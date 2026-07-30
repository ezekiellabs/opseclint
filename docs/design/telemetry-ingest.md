# Reference: ingesting real telemetry

**Status:** current (first cut — Windows Sysmon Event ID 1, JSON)
**Scope:** how opseclint maps recorded host telemetry back to the knowledge base.

opseclint's original direction is *predictive*: given a command, resolve the
telemetry a sensor **would** emit and the detections that **would** fire. The
`--telemetry` input flips that direction — it ingests the events a sensor
**actually recorded** and maps each back to KB entries → techniques, telemetry,
detections, and a detectability score. It answers "given what the sensor did
record, which techniques and coverage does this represent?" — the observed-mode
complement to the predictive report and to `--sigma` / `--verify-detections`.

Like the rest of opseclint, this describes **detectability** only. It is an
observation front-end — "here's what the sensor saw" — and encodes no evasion.

## The seam it reuses

`sigma_eval::synthesize` already models a command line as the event a
process-creation sensor emits:

```
Command{program, args, raw}
  → { CommandLine: raw, Image: /<prog> | \<prog>.exe, OriginalFileName: prog }
```

Real Sysmon **Event ID 1 (Process Create)** telemetry carries exactly those
fields. So ingestion does not add a new matching layer — it parses each record
back into a `Command` and drives the *existing* matcher and analyzer:

```
telemetry record → reduce to Command{program, args, raw}
                 → analyzer::match_unit (the same core analyze() uses)
                 → Finding (technique / telemetry / detections / noise)
```

`analyze()` (text) and `analyze_telemetry()` (records) share one matching core,
so the observed and predicted verdicts for the same command line agree by
construction (guarded by a test).

## The reduction (Sysmon EID 1)

For each event object:

- **`raw`** ← the recorded `CommandLine` (falling back to `Image` when a Process
  Create event carries no command line).
- **`commands`** ← `parser::parse_line(raw)` — reusing the shell parser's
  tokenization, wrapper stripping, quote handling, and compound-line splitting.
- **program** of the primary command is then overridden with
  `basename(Image)`: `Image` is the authoritative executable path, normalized
  with the same rule the KB's `program` axis keys on
  (`C:\…\certutil.exe` → `certutil`).

### Accepted shapes

Real exporters differ; the parser accepts:

- a top-level **JSON array** of event objects,
- a single **JSON object**, and
- **JSONL** (one object per line).

Fields are read case-insensitively and gathered from the common nesting
containers — flat (native Sysmon JSON), `EventData`, Elastic's
`winlog.event_data`, and the EVTX→JSON `{"@Name": "Image", "#text": "…"}` array
shape.

### What counts as a process creation

A record is ingested when its event id is `1`, or — when no event id is present
(some Sysmon-only EID 1 exports omit it) — when it carries a `CommandLine`.
Requiring the command line in the id-less case keeps a network (EID 3) or file
(EID 11) record, which carries an `Image` but no `CommandLine`, from being
misread as a process launch. Non-process records are **skipped and counted**,
and the count is reported to the user — never silently dropped.

## Scope and what comes next

The first cut is deliberately one format, end-to-end:

- **Process-creation events only.** The KB matches commands, so process creation
  is the natural target. Other event classes (network / file / registry) tie
  into the `edr.rs` event-class taxonomy and are out of scope for now.
- **Command reduction, not a richer event.** Each record reduces to a
  `Command`, which makes the matcher, report, score, `--json` / `--sarif` /
  `--navigator` / `--edr`, and `--diff` all work unchanged. The real event's
  extra fields (`ParentImage`, `User`, `IntegrityLevel`, …) are not yet
  consulted.

The planned next increment threads those extra fields into a `sigma_eval`
evaluation path so that `--telemetry … --sigma` can decide whether the expected
detection fires on the *real* event — collapsing the `INDETERMINATE` verdicts
that arise today only because `synthesize` cannot invent a `ParentImage` or
`User`. auditd (`EXECVE`/`SYSCALL`) and macOS/ESF then follow as further formats
behind the same `--telemetry` input path.
