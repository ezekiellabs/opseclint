//! Gap-to-rule scaffolding. Turns a modeled action (a knowledge-base entry) into
//! a starter Sigma rule whose `detection:` mirrors how opseclint matches that
//! action, so a `--coverage-gaps` blind spot can be closed with a real rule
//! instead of a blank page. The generated rule is a *scaffold*: the detection
//! logic, tags, description, and references are real, while a few fields (id,
//! author, the ATT&CK tactic tag) are placeholders to refine before upstreaming.

use std::collections::HashSet;

use opseclint_core::kb::Platform;
use opseclint_core::matcher::SigmaEventSelection;
use opseclint_core::model::{KbEntry, KnowledgeBase, Severity};

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

/// Every scaffold document for `entries`, in order.
pub fn documents_for(entries: &[&KbEntry], platform: Platform, date: &str) -> Vec<String> {
    entries
        .iter()
        .flat_map(|e| documents_for_entry(e, platform, date))
        .collect()
}

/// Generate the starter Sigma rule(s) (YAML) for a knowledge-base entry.
///
/// An entry's command axes and its `event` axis describe records in different
/// log sources, and one Sigma rule cannot span two. So an entry carrying both
/// scaffolds **two** documents — a `process_creation` rule and a rule over the
/// event class — rather than one rule with half the entry silently dropped.
/// Never empty.
pub fn documents_for_entry(entry: &KbEntry, platform: Platform, date: &str) -> Vec<String> {
    let command = build_selection(entry, platform);
    let event = entry.matcher.sigma_event_selection();
    let mut docs: Vec<String> = Vec::new();

    // The command document. Also the home of the "nothing to match on" TODO,
    // which is now reachable only for a matcher whose command axes lower to
    // nothing *and* which has no `event` axis either — a purely-negated `line`,
    // say. An entry recognized only by an event scaffolds the event document
    // instead of an empty `selection:`, which is not valid Sigma.
    if command.is_some() || event.is_none() {
        let selection = command.unwrap_or_else(|| {
            "        # TODO: no matchable field on this entry; define the selection\n".to_string()
        });
        docs.push(render(
            entry,
            platform,
            date,
            &Document {
                title_suffix: String::new(),
                id_seed: entry.id.clone(),
                category: "process_creation",
                detection: format!("    selection:\n{selection}"),
                condition: "selection".to_string(),
            },
        ));
    }

    if let Some(ev) = &event {
        let (detection, condition) = build_event_detection(ev);
        docs.push(render(
            entry,
            platform,
            date,
            &Document {
                title_suffix: format!(" ({} event)", ev.class.as_str()),
                id_seed: format!("{}#{}", entry.id, ev.class.as_str()),
                category: ev.class.sigma_category(),
                detection,
                condition,
            },
        ));
    }

    docs
}

/// What differs between the documents scaffolded for one entry. Everything else
/// — the description, references, tags, level — describes the action rather than
/// the log source, so both documents carry it identically.
struct Document {
    /// Appended to the title, so two rules for one action read apart.
    title_suffix: String,
    /// Seeds the placeholder id, so the two documents never collide.
    id_seed: String,
    /// The `logsource.category` this document declares.
    category: &'static str,
    /// The body under `detection:`, selection keys included.
    detection: String,
    /// The `condition:` over those selections.
    condition: String,
}

/// Render one Sigma document for an entry.
fn render(entry: &KbEntry, platform: Platform, date: &str, doc: &Document) -> String {
    let mut out = String::new();
    out.push_str("# opseclint scaffold — a starter rule mirroring how opseclint matches this\n");
    out.push_str("# action. Refine the TODO fields (and tighten the detection) before\n");
    out.push_str("# submitting upstream to SigmaHQ.\n");
    out.push_str(&format!(
        "title: '{}'\n",
        yaml_sq(&format!(
            "{}{}",
            scaffold_title(&entry.description),
            doc.title_suffix
        ))
    ));
    out.push_str(&format!(
        "id: {}   # generated placeholder — regenerate with uuidgen\n",
        placeholder_uuid(&doc.id_seed)
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
    out.push_str(&format!("    category: {}\n", doc.category));
    out.push_str(&format!("    product: {}\n", platform.sigma_product()));
    out.push_str("detection:\n");
    out.push_str(&doc.detection);
    out.push_str(&format!("    condition: {}\n", doc.condition));
    out.push_str("falsepositives:\n");
    out.push_str("    - Unknown\n");
    out.push_str(&format!("level: {}\n", level_for(entry.noise)));
    out
}

/// Build the `selection:` block from the entry's matcher, mirroring opseclint's
/// own matching: `program` -> `Image|endswith` (a list for an any-of program),
/// the `args` / `line` literals -> `CommandLine|contains` (an OR-list for an
/// `any`-of-`contains` group, `contains|all` for ANDed terms), and any `regex`
/// leaf -> `CommandLine|re`. Alternation/nesting a flat selection can't mirror is
/// flagged with a NOTE rather than silently narrowed. `None` when the command
/// axes lower to nothing at all — an entry recognized only by its `event` axis.
fn build_selection(entry: &KbEntry, platform: Platform) -> Option<String> {
    let sel = entry.matcher.sigma_selection();
    let mut s = String::new();

    // program -> Image|endswith (scalar for one, list for an any-of program).
    let image = |p: &str| match platform {
        Platform::WindowsSysmon => format!("\\{}.exe", yaml_sq(p)),
        _ => format!("/{}", yaml_sq(p)),
    };
    push_field(&mut s, "Image|endswith", &sel.image_endswith, false, image);

    // CommandLine|contains: an OR-list for the any-group, else scalar / |all.
    let ident = |v: &str| yaml_sq(v);
    if sel.contains_all.is_empty() && !sel.contains_any.is_empty() {
        push_field(
            &mut s,
            "CommandLine|contains",
            &sel.contains_any,
            false,
            ident,
        );
    } else {
        push_field(
            &mut s,
            "CommandLine|contains",
            &sel.contains_all,
            true,
            ident,
        );
    }

    // CommandLine|re: scalar for one pattern, list for many.
    push_field(&mut s, "CommandLine|re", &sel.regexes, false, ident);

    // A NOTE on its own is not a selection: with no field lowered there is
    // nothing here to scaffold from the command axes.
    if s.is_empty() {
        return None;
    }
    if sel.simplified {
        s.insert_str(
            0,
            "        # NOTE: this matcher uses alternation/nesting the scaffold can't fully\n\
             \x20       # mirror; review the selection (some alternatives may be missing).\n",
        );
    }
    Some(s)
}

/// Build the `detection:` body and `condition:` for an entry's `event` axis:
/// each lowered block becomes a `selection:` (then `selection_1:`, …) and the
/// condition ORs them, because one flat Sigma map cannot express a disjunction
/// spanning different keys.
fn build_event_detection(ev: &SigmaEventSelection) -> (String, String) {
    let mut body = String::new();
    for note in &ev.notes {
        push_comment(&mut body, 4, note);
    }

    let mut names = Vec::new();
    for (i, block) in ev.blocks.iter().enumerate() {
        let name = if i == 0 {
            "selection".to_string()
        } else {
            format!("selection_{i}")
        };
        body.push_str(&format!("    {name}:\n"));
        for f in &block.fields {
            let key = format!("{}{}", f.field, f.modifier);
            let scalar = |v: &str| event_scalar(v, f.modifier);
            match f.values.as_slice() {
                [] => {}
                [only] => body.push_str(&format!("        {key}: {}\n", scalar(only))),
                many => {
                    // Several values under one key: a sequence, which Sigma ORs
                    // — unless they were ANDed, which `|all` says.
                    let key = if f.all_of { format!("{key}|all") } else { key };
                    body.push_str(&format!("        {key}:\n"));
                    for v in many {
                        body.push_str(&format!("            - {}\n", scalar(v)));
                    }
                }
            }
        }
        names.push(name);
    }
    (body, names.join(" or "))
}

/// An event field's value as a Sigma scalar. An unmodified all-digit value goes
/// out bare so a port reads as the integer backends expect of `DestinationPort`;
/// everything else is single-quoted, which is what keeps a registry path's
/// backslashes literal.
fn event_scalar(value: &str, modifier: &str) -> String {
    let numeric = modifier.is_empty()
        && !value.is_empty()
        && value.len() <= 19
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'));
    if numeric {
        value.to_string()
    } else {
        format!("'{}'", yaml_sq(value))
    }
}

/// Emit a `# NOTE:` comment at `indent` spaces, wrapped so the YAML stays
/// readable at the width the rest of the scaffold is written to.
fn push_comment(out: &mut String, indent: usize, note: &str) {
    let pad = " ".repeat(indent);
    let mut line = format!("{pad}# NOTE:");
    for word in note.split_whitespace() {
        if line.len() + 1 + word.len() > 78 {
            out.push_str(&line);
            out.push('\n');
            line = format!("{pad}#");
        }
        line.push(' ');
        line.push_str(word);
    }
    out.push_str(&line);
    out.push('\n');
}

/// Emit a Sigma selection field: nothing for an empty list, a scalar for one
/// value, and a YAML sequence for several — appending `|all` to the key when the
/// several values are ANDed (`and_list`) rather than ORed.
fn push_field(
    out: &mut String,
    key: &str,
    values: &[String],
    and_list: bool,
    fmt: impl Fn(&str) -> String,
) {
    match values {
        [] => {}
        [only] => out.push_str(&format!("        {key}: '{}'\n", fmt(only))),
        many => {
            let key = if and_list {
                format!("{key}|all")
            } else {
                key.to_string()
            };
            out.push_str(&format!("        {key}:\n"));
            for v in many {
                out.push_str(&format!("            - '{}'\n", fmt(v)));
            }
        }
    }
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
    use opseclint_core::kb;
    use opseclint_core::matcher::{LinePred, Matcher};
    use opseclint_core::model::Technique;

    fn linux_kb() -> KnowledgeBase {
        kb::load(kb::Platform::LinuxAuditd).unwrap()
    }

    fn entry<'a>(kb: &'a KnowledgeBase, id: &str) -> &'a KbEntry {
        kb.entries.iter().find(|e| e.id == id).unwrap()
    }

    /// The single document an entry scaffolds. Doubles as a guard that an entry
    /// without an `event` axis still scaffolds exactly one rule, and keeps the
    /// result parseable — `serde_norway` rejects a multi-document stream.
    fn rule_for(entry: &KbEntry, platform: Platform, date: &str) -> String {
        let mut docs = documents_for_entry(entry, platform, date);
        assert_eq!(docs.len(), 1, "expected one document, got {}", docs.len());
        docs.remove(0)
    }

    /// Parse one document of a scaffold.
    fn doc(yaml: &str) -> serde_norway::Value {
        serde_norway::from_str(yaml).expect("scaffold parses as Sigma YAML")
    }

    #[test]
    fn scaffold_is_valid_sigma_yaml_for_a_command_entry() {
        let kb = linux_kb();
        // docker-sock is a raw entry; use a command entry for the Image assertion.
        let e = entry(&kb, "clear-syslog-rm");
        let yaml = rule_for(e, kb::Platform::LinuxAuditd, "2026-07-29");
        let v: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();

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
        let v: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
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

        let stream = documents_for(
            &[
                entry(&kb, "clear-syslog-rm"),
                entry(&kb, "reverse-shell-devtcp"),
            ],
            kb::Platform::LinuxAuditd,
            "2026-07-29",
        )
        .join("---\n");
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
        let v: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
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
            matcher: Matcher {
                program: None,
                args: None,
                line: Some(LinePred::Contains("lsass".into())),
                event: None,
            },
            example: None,
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
        let v: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        assert_eq!(
            v["title"].as_str(),
            Some("Dump credentials: full LSASS memory")
        );
        assert_eq!(v["level"].as_str(), Some("critical")); // noise 80 -> Critical
    }

    #[test]
    fn scaffold_maps_a_regex_leaf_to_commandline_re() {
        // A `regex` leaf lowers to a Sigma `CommandLine|re` selection, and the
        // `any` of contains around it lowers to a CommandLine OR-list carrying
        // *both* alternatives (not just the first).
        let kb = kb::load(kb::Platform::WindowsSysmon).unwrap();
        let e = entry(&kb, "powershell-hidden");
        let yaml = rule_for(e, kb::Platform::WindowsSysmon, "2026-07-29");
        let v: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let sel = &v["detection"]["selection"];
        assert!(
            sel["CommandLine|re"].as_str().is_some(),
            "expected a CommandLine|re selection, got:\n{yaml}"
        );
        let contains: Vec<&str> = sel["CommandLine|contains"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert!(
            contains.contains(&"powershell") && contains.contains(&"pwsh"),
            "{yaml}"
        );
    }

    #[test]
    fn scaffold_lowers_program_any_of_to_an_image_list() {
        // `net-user` matches `net`/`net1`; the scaffold keeps both as an
        // `Image|endswith` OR-list.
        let kb = kb::load(kb::Platform::WindowsSysmon).unwrap();
        let yaml = rule_for(
            entry(&kb, "net-user"),
            kb::Platform::WindowsSysmon,
            "2026-07-29",
        );
        let v: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let imgs: Vec<&str> = v["detection"]["selection"]["Image|endswith"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(imgs, vec!["\\net.exe", "\\net1.exe"]);
    }

    #[test]
    fn scaffold_lowers_line_any_to_a_contains_or_list() {
        // `sudo-l` matches `sudo -l` OR `sudo --list`; both survive scaffolding.
        let kb = kb::load(kb::Platform::LinuxAuditd).unwrap();
        let yaml = rule_for(
            entry(&kb, "sudo-l"),
            kb::Platform::LinuxAuditd,
            "2026-07-29",
        );
        let v: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let contains: Vec<&str> = v["detection"]["selection"]["CommandLine|contains"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(contains, vec!["sudo -l", "sudo --list"]);
    }

    #[test]
    fn scaffold_flags_a_dropped_negation_with_a_note() {
        // `private-key-rsa` excludes `id_rsa.pub` via `not`, which a positive
        // selection can't express — the scaffold must carry the review NOTE.
        let kb = kb::load(kb::Platform::LinuxAuditd).unwrap();
        let yaml = rule_for(
            entry(&kb, "private-key-rsa"),
            kb::Platform::LinuxAuditd,
            "2026-07-29",
        );
        assert!(
            yaml.contains("# NOTE:"),
            "expected a review NOTE, got:\n{yaml}"
        );
        // The generated rule is still valid YAML.
        serde_norway::from_str::<serde_norway::Value>(&yaml).unwrap();
    }

    #[test]
    fn scaffold_lists_multiple_regexes_as_a_yaml_sequence() {
        // Two regexes must become one `CommandLine|re` key holding a list — never
        // a repeated key (invalid / lossy YAML).
        let matcher: Matcher = serde_json::from_str(
            r#"{ "line": { "all": [{ "regex": "aa" }, { "regex": "bb" }] } }"#,
        )
        .unwrap();
        let e = KbEntry {
            id: "multi".into(),
            matcher,
            example: Some("aa bb".into()),
            description: "two regexes".into(),
            techniques: vec![Technique {
                id: "T1059".into(),
                name: "n".into(),
            }],
            telemetry: vec![],
            detections: vec![],
            noise: 50,
        };
        let yaml = rule_for(&e, kb::Platform::LinuxAuditd, "2026-07-29");
        let v: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let re = &v["detection"]["selection"]["CommandLine|re"];
        assert_eq!(re.as_sequence().map(|s| s.len()), Some(2), "got:\n{yaml}");
    }

    // --- the `event` axis ---------------------------------------------------

    fn macos_kb() -> KnowledgeBase {
        kb::load(kb::Platform::MacosEs).unwrap()
    }

    fn windows_kb() -> KnowledgeBase {
        kb::load(kb::Platform::WindowsSysmon).unwrap()
    }

    /// The documents an entry scaffolds, on its own platform.
    fn docs_for(kb: &KnowledgeBase, id: &str, platform: Platform) -> Vec<String> {
        documents_for_entry(entry(kb, id), platform, "2026-07-29")
    }

    #[test]
    fn scaffold_emits_a_document_per_log_source_for_a_dual_axis_entry() {
        // `cloud-imds` matches a command *and* a network record. One Sigma rule
        // cannot span two logsources, so neither dimension may be dropped.
        let kb = linux_kb();
        let docs = docs_for(&kb, "cloud-imds", Platform::LinuxAuditd);
        assert_eq!(docs.len(), 2);

        let (cmd, ev) = (doc(&docs[0]), doc(&docs[1]));
        assert_eq!(
            cmd["logsource"]["category"].as_str(),
            Some("process_creation")
        );
        assert_eq!(
            ev["logsource"]["category"].as_str(),
            Some("network_connection")
        );
        // Both carry the platform, and describe the same action.
        assert_eq!(ev["logsource"]["product"].as_str(), Some("linux"));
        assert_eq!(cmd["description"], ev["description"]);
        assert_eq!(cmd["level"], ev["level"]);
        // Distinct ids, so pasting both into a ruleset does not collide, and
        // distinct titles, so a reviewer can tell them apart.
        assert_ne!(cmd["id"], ev["id"]);
        let id = ev["id"].as_str().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(
            ev["title"].as_str().unwrap().ends_with(" (network event)"),
            "got {:?}",
            ev["title"]
        );
    }

    #[test]
    fn scaffold_event_class_picks_the_logsource_category() {
        let (linux, macos, windows) = (linux_kb(), macos_kb(), windows_kb());
        let category = |kb: &KnowledgeBase, id: &str, p: Platform| {
            let docs = docs_for(kb, id, p);
            doc(docs.last().expect("an event document"))["logsource"]["category"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(
            category(&linux, "cloud-imds", Platform::LinuxAuditd),
            "network_connection"
        );
        assert_eq!(
            category(&macos, "tcc-tamper", Platform::MacosEs),
            "file_event"
        );
        assert_eq!(
            category(&windows, "run-key-persist", Platform::WindowsSysmon),
            "registry_set"
        );
    }

    #[test]
    fn scaffold_ands_several_event_fields_in_one_selection() {
        let kb = linux_kb();
        let v = doc(&docs_for(&kb, "cloud-imds", Platform::LinuxAuditd)[1]);
        let sel = &v["detection"]["selection"];
        assert_eq!(sel["DestinationIp"].as_str(), Some("169.254.169.254"));
        // A port is a number to every Sigma backend, so it is not quoted.
        assert_eq!(sel["DestinationPort"].as_u64(), Some(80));
        assert_eq!(v["detection"]["condition"].as_str(), Some("selection"));
    }

    #[test]
    fn scaffold_event_alternation_becomes_sibling_selections() {
        // `sudoers-tamper` alternates over two *different* modifiers on one
        // field, which one flat map cannot OR — so it becomes two selections
        // rather than one narrowed to a single branch.
        //
        // The drop-in directory leads because the entry's first `any` branch is
        // also what its representative record is derived from, and that is the
        // record SigmaHQ's own sudoers rule watches. Branch order is otherwise
        // immaterial to matching; here it decides what gets probed.
        let kb = linux_kb();
        let v = doc(&docs_for(&kb, "sudoers-tamper", Platform::LinuxAuditd)[1]);
        assert_eq!(
            v["detection"]["selection"]["TargetFilename|startswith"].as_str(),
            Some("/etc/sudoers.d")
        );
        assert_eq!(
            v["detection"]["selection_1"]["TargetFilename"].as_str(),
            Some("/etc/sudoers")
        );
        assert_eq!(
            v["detection"]["condition"].as_str(),
            Some("selection or selection_1")
        );
    }

    #[test]
    fn scaffold_folds_a_same_key_event_alternation_into_a_value_list() {
        // `emond-persist` alternates two `path_under` leaves on one field. Sigma
        // reads a sequence under one key as an OR, so this stays one selection.
        let kb = macos_kb();
        let v = doc(&docs_for(&kb, "emond-persist", Platform::MacosEs)[1]);
        let paths = v["detection"]["selection"]["TargetFilename|startswith"]
            .as_sequence()
            .expect("a value list");
        assert_eq!(paths.len(), 2);
        assert_eq!(v["detection"]["condition"].as_str(), Some("selection"));
    }

    #[test]
    fn scaffold_keeps_a_nested_event_alternation_in_one_selection() {
        // `winlogon-persist` is `all[contains, any[suffix, suffix]]`. Both
        // branches share a key, so the nesting needs no second selection.
        let kb = windows_kb();
        let v = doc(&docs_for(&kb, "winlogon-persist", Platform::WindowsSysmon)[1]);
        let sel = &v["detection"]["selection"];
        assert_eq!(
            sel["TargetObject|contains"].as_str(),
            Some("\\Winlogon\\"),
            "registry backslashes must survive the round trip"
        );
        let ends = sel["TargetObject|endswith"]
            .as_sequence()
            .expect("a value list");
        assert_eq!(ends.len(), 2);
        assert_eq!(ends[0].as_str(), Some("\\Shell"));
        assert_eq!(v["detection"]["condition"].as_str(), Some("selection"));
    }

    #[test]
    fn scaffold_keeps_two_modifiers_on_one_event_field_as_separate_keys() {
        // `launch-agent-persist` ANDs `contains` and `suffix` on one field: two
        // distinct Sigma keys, so no `|all` and no second selection.
        let kb = macos_kb();
        let yaml = &docs_for(&kb, "launch-agent-persist", Platform::MacosEs)[1];
        let sel = &doc(yaml)["detection"]["selection"];
        assert_eq!(
            sel["TargetFilename|contains"].as_str(),
            Some("/LaunchAgents/")
        );
        assert_eq!(sel["TargetFilename|endswith"].as_str(), Some(".plist"));
        assert!(!yaml.contains("|all"), "got:\n{yaml}");
    }

    #[test]
    fn scaffold_flags_a_widened_event_leaf() {
        // `word` and `path_under` have no Sigma equivalent. Each widens, and the
        // rule has to say so — the same contract `sel.simplified` already holds.
        let kb = linux_kb();
        let widened = &docs_for(&kb, "authorized-keys", Platform::LinuxAuditd)[1];
        assert!(widened.contains("# NOTE:") && widened.contains("`word: authorized_keys`"));
        assert_eq!(
            doc(widened)["detection"]["selection"]["TargetFilename|contains"].as_str(),
            Some("authorized_keys")
        );

        let under = &docs_for(&kb, "sudoers-tamper", Platform::LinuxAuditd)[1];
        assert!(under.contains("# NOTE:") && under.contains("path_under"));
    }

    #[test]
    fn an_event_only_entry_scaffolds_no_empty_selection() {
        // The shape the hardcoded logsource made unrepresentable: no command
        // axis at all. It must scaffold the event rule and nothing else, rather
        // than a `process_creation` rule with an empty `selection:`.
        let matcher: Matcher = serde_json::from_str(
            r#"{ "event": { "class": "file", "field": "TargetFilename", "eq": "/etc/x" } }"#,
        )
        .unwrap();
        let e = KbEntry {
            id: "event-only".into(),
            matcher,
            example: None,
            description: "writes to /etc/x — persistence".into(),
            techniques: vec![Technique {
                id: "T1543".into(),
                name: "n".into(),
            }],
            telemetry: vec![],
            detections: vec![],
            noise: 50,
        };
        let docs = documents_for_entry(&e, Platform::LinuxAuditd, "2026-07-29");
        assert_eq!(docs.len(), 1);
        assert!(!docs[0].contains("process_creation"), "got:\n{}", docs[0]);
        assert!(!docs[0].contains("no matchable field"), "got:\n{}", docs[0]);
        let v = doc(&docs[0]);
        assert_eq!(v["logsource"]["category"].as_str(), Some("file_event"));
        assert_eq!(
            v["detection"]["selection"]["TargetFilename"].as_str(),
            Some("/etc/x")
        );
    }

    /// Whether every selection `condition` names resolves to a block that the
    /// document actually defines.
    fn condition_names_defined_blocks(v: &serde_norway::Value) -> bool {
        let detection = v["detection"].as_mapping().expect("a detection map");
        let condition = v["detection"]["condition"]
            .as_str()
            .expect("a condition string");
        condition.split(" or ").all(|name| {
            detection.contains_key(serde_norway::Value::from(name.trim()))
                && name.trim() != "condition"
        })
    }

    #[test]
    fn every_entry_scaffolds_documents_that_parse_as_sigma() {
        // The corpus-wide guard: whatever an entry's shape, each document it
        // scaffolds has to be a rule someone could paste into a ruleset — a
        // valid YAML document, in a real logsource, with a non-empty selection
        // its condition actually names.
        let categories = [
            "process_creation",
            "network_connection",
            "file_event",
            "registry_set",
        ];
        for (kb, platform) in [
            (linux_kb(), Platform::LinuxAuditd),
            (macos_kb(), Platform::MacosEs),
            (windows_kb(), Platform::WindowsSysmon),
        ] {
            for e in &kb.entries {
                let docs = documents_for_entry(e, platform, "2026-07-29");
                assert!(!docs.is_empty(), "entry `{}` scaffolded nothing", e.id);
                for yaml in &docs {
                    let v: serde_norway::Value = serde_norway::from_str(yaml)
                        .unwrap_or_else(|err| panic!("entry `{}`: {err}\n{yaml}", e.id));
                    let category = v["logsource"]["category"].as_str().unwrap_or_default();
                    assert!(
                        categories.contains(&category),
                        "entry `{}` scaffolded logsource `{category}`",
                        e.id
                    );
                    assert!(
                        v["detection"]["selection"].as_mapping().is_some_and(|m| {
                            // An entry with nothing to match on carries the TODO
                            // instead, which YAML reads as a null selection.
                            !m.is_empty()
                        }) || yaml.contains("no matchable field"),
                        "entry `{}` scaffolded an empty selection:\n{yaml}",
                        e.id
                    );
                    assert!(
                        condition_names_defined_blocks(&v),
                        "entry `{}` has a condition naming no block:\n{yaml}",
                        e.id
                    );
                }
            }
        }
    }
}
