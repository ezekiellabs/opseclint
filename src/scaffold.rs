//! Gap-to-rule scaffolding. Turns a modeled action (a knowledge-base entry) into
//! a starter Sigma rule whose `detection:` mirrors how opseclint matches that
//! action, so a `--coverage-gaps` blind spot can be closed with a real rule
//! instead of a blank page. The generated rule is a *scaffold*: the detection
//! logic, tags, description, and references are real, while a few fields (id,
//! author, the ATT&CK tactic tag) are placeholders to refine before upstreaming.

use std::collections::HashSet;

use crate::kb::Platform;
use crate::model::{KbEntry, KnowledgeBase, Severity};

/// Resolve knowledge-base entries for a list of rule ids, de-duplicated and in
/// first-seen order.
pub fn entries_by_ids<'a>(kb: &'a KnowledgeBase, ids: &[&str]) -> Vec<&'a KbEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for &id in ids {
        if seen.insert(id)
            && let Some(entry) = kb.entries.iter().find(|e| e.id == id)
        {
            out.push(entry);
        }
    }
    out
}

/// Join scaffolds for several entries into a multi-document Sigma YAML stream.
pub fn rules_for(entries: &[&KbEntry], platform: Platform, date: &str) -> String {
    entries
        .iter()
        .map(|e| rule_for(e, platform, date))
        .collect::<Vec<_>>()
        .join("---\n")
}

/// Generate a single starter Sigma rule (YAML) for a knowledge-base entry.
pub fn rule_for(entry: &KbEntry, platform: Platform, date: &str) -> String {
    let mut out = String::new();
    out.push_str("# opseclint scaffold — a starter rule mirroring how opseclint matches this\n");
    out.push_str("# action. Refine the TODO fields (and tighten the detection) before\n");
    out.push_str("# submitting upstream to SigmaHQ.\n");
    out.push_str(&format!(
        "title: '{}'\n",
        yaml_sq(&scaffold_title(&entry.description))
    ));
    out.push_str(&format!(
        "id: {}   # generated placeholder — regenerate with uuidgen\n",
        placeholder_uuid(&entry.id)
    ));
    out.push_str("status: experimental\n");
    out.push_str("description: |\n");
    out.push_str(&format!("    {}\n", entry.description));
    out.push_str("references:\n");
    for t in &entry.techniques {
        out.push_str(&format!(
            "    - https://attack.mitre.org/techniques/{}/\n",
            t.id.replace('.', "/")
        ));
    }
    out.push_str("author: 'TODO: your name'\n");
    out.push_str(&format!("date: {date}\n"));
    out.push_str("tags:\n");
    for t in &entry.techniques {
        out.push_str(&format!("    - attack.{}\n", t.id.to_lowercase()));
    }
    out.push_str("    # TODO: add the ATT&CK tactic tag, e.g. attack.defense-evasion\n");
    out.push_str("logsource:\n");
    out.push_str("    category: process_creation\n");
    out.push_str(&format!("    product: {}\n", platform.sigma_product()));
    out.push_str("detection:\n");
    out.push_str("    selection:\n");
    out.push_str(&build_selection(entry, platform));
    out.push_str("    condition: selection\n");
    out.push_str("falsepositives:\n");
    out.push_str("    - Unknown\n");
    out.push_str(&format!("level: {}\n", level_for(entry.noise)));
    out
}

/// Build the `selection:` block from the entry's matcher, mirroring opseclint's
/// own matching: an exact `program` -> `Image|endswith`, and the `args` / `line`
/// literals -> `CommandLine|contains`. Multiple CommandLine terms are ANDed via
/// `contains|all`.
fn build_selection(entry: &KbEntry, platform: Platform) -> String {
    let matcher = entry.compiled_matcher();
    let mut s = String::new();
    if let Some(cmd) = matcher.program_literal() {
        // Mirror how opseclint synthesizes the Image field per platform.
        let image = match platform {
            Platform::WindowsSysmon => format!("\\{}.exe", yaml_sq(cmd)),
            _ => format!("/{}", yaml_sq(cmd)),
        };
        s.push_str(&format!("        Image|endswith: '{image}'\n"));
    }
    let terms = matcher.commandline_terms();
    match terms.as_slice() {
        [] => {}
        [only] => s.push_str(&format!(
            "        CommandLine|contains: '{}'\n",
            yaml_sq(only)
        )),
        many => {
            s.push_str("        CommandLine|contains|all:\n");
            for term in many {
                s.push_str(&format!("            - '{}'\n", yaml_sq(term)));
            }
        }
    }
    if s.is_empty() {
        s.push_str("        # TODO: no matchable field on this entry; define the selection\n");
    }
    s
}

/// Escape a value for a YAML single-quoted scalar.
fn yaml_sq(s: &str) -> String {
    s.replace('\'', "''")
}

/// A concise title from the entry description (the part before an em dash).
fn scaffold_title(desc: &str) -> String {
    let base = desc.split('—').next().unwrap_or(desc).trim();
    let mut chars = base.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => "Opseclint scaffold".to_string(),
    }
}

/// Map detectability (0-100 noise) to a Sigma severity level.
fn level_for(noise: u8) -> &'static str {
    // Reuse opseclint's own severity buckets so the scaffold level matches the
    // tool's interpretation (Sigma also supports `critical`).
    match Severity::from_noise(noise) {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// A deterministic, RFC-4122-shaped v4 UUID derived from a seed, so a scaffold's
/// id is stable per action (regenerate with uuidgen before upstreaming).
fn placeholder_uuid(seed: &str) -> String {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&fnv1a(seed.as_bytes()).to_be_bytes());
    let mut salted = seed.as_bytes().to_vec();
    salted.extend_from_slice(b"::opseclint-scaffold");
    b[8..].copy_from_slice(&fnv1a(&salted).to_be_bytes());
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in data {
        h ^= byte as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Today's date (UTC) as `YYYY-MM-DD`, for the scaffold's `date` field.
pub fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert days-since-Unix-epoch to a (year, month, day) civil date.
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kb;
    use crate::model::Technique;

    fn linux_kb() -> KnowledgeBase {
        kb::load(kb::Platform::LinuxAuditd).unwrap()
    }

    fn entry<'a>(kb: &'a KnowledgeBase, id: &str) -> &'a KbEntry {
        kb.entries.iter().find(|e| e.id == id).unwrap()
    }

    #[test]
    fn scaffold_is_valid_sigma_yaml_for_a_command_entry() {
        let kb = linux_kb();
        // docker-sock is a raw entry; use a command entry for the Image assertion.
        let e = entry(&kb, "clear-syslog-rm");
        let yaml = rule_for(e, kb::Platform::LinuxAuditd, "2026-07-29");
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(v["status"].as_str(), Some("experimental"));
        assert_eq!(
            v["logsource"]["category"].as_str(),
            Some("process_creation")
        );
        assert_eq!(v["logsource"]["product"].as_str(), Some("linux"));
        assert_eq!(v["detection"]["condition"].as_str(), Some("selection"));
        let sel = &v["detection"]["selection"];
        assert_eq!(sel["Image|endswith"].as_str(), Some("/rm"));
        assert_eq!(sel["CommandLine|contains"].as_str(), Some("/var/log"));
        // A valid-shaped v4 UUID (36 chars, version nibble '4').
        let id = v["id"].as_str().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
        // Real ATT&CK reference + technique tag.
        assert!(yaml.contains("https://attack.mitre.org/techniques/T1070/002/"));
        assert!(yaml.contains("attack.t1070.002"));
    }

    #[test]
    fn scaffold_handles_raw_only_entry() {
        let kb = linux_kb();
        let e = entry(&kb, "reverse-shell-devtcp"); // raw_contains: /dev/tcp
        let yaml = rule_for(e, kb::Platform::LinuxAuditd, "2026-07-29");
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let sel = &v["detection"]["selection"];
        assert!(sel.get("Image|endswith").is_none());
        assert_eq!(sel["CommandLine|contains"].as_str(), Some("/dev/tcp"));
    }

    #[test]
    fn scaffold_id_is_deterministic_and_multidoc_joins() {
        let kb = linux_kb();
        let e = entry(&kb, "clear-syslog-rm");
        let a = rule_for(e, kb::Platform::LinuxAuditd, "2026-07-29");
        let b = rule_for(e, kb::Platform::LinuxAuditd, "2026-07-29");
        assert_eq!(a, b, "same entry must scaffold identically");

        let stream = rules_for(
            &[
                entry(&kb, "clear-syslog-rm"),
                entry(&kb, "reverse-shell-devtcp"),
            ],
            kb::Platform::LinuxAuditd,
            "2026-07-29",
        );
        // Two documents, joined by a YAML document separator.
        assert!(stream.contains("\n---\n"));
        assert_eq!(stream.matches("status: experimental").count(), 2);
    }

    #[test]
    fn civil_date_is_correct() {
        // 2026-07-29 is 20663 days after the Unix epoch.
        assert_eq!(civil_from_days(20_663), (2026, 7, 29));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn scaffold_windows_uses_backslash_exe_image() {
        let kb = kb::load(kb::Platform::WindowsSysmon).unwrap();
        let e = entry(&kb, "certutil-download");
        let yaml = rule_for(e, kb::Platform::WindowsSysmon, "2026-07-29");
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(v["logsource"]["product"].as_str(), Some("windows"));
        assert_eq!(
            v["detection"]["selection"]["Image|endswith"].as_str(),
            Some("\\certutil.exe")
        );
    }

    #[test]
    fn scaffold_title_with_colon_stays_valid_yaml() {
        // A colon+space would break an unquoted YAML title; it must be quoted.
        let e = KbEntry {
            id: "synthetic".into(),
            matcher: None,
            command: None,
            args_contains: None,
            raw_contains: Some("lsass".into()),
            description: "Dump credentials: full LSASS memory — credential access".into(),
            techniques: vec![Technique {
                id: "T1003.001".into(),
                name: "LSASS Memory".into(),
            }],
            telemetry: vec![],
            detections: vec![],
            noise: 80,
        };
        let yaml = rule_for(&e, kb::Platform::WindowsSysmon, "2026-07-29");
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            v["title"].as_str(),
            Some("Dump credentials: full LSASS memory")
        );
        assert_eq!(v["level"].as_str(), Some("critical")); // noise 80 -> Critical
    }
}
