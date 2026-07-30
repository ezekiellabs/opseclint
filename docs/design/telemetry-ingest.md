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

## Evaluating detections on the real event

The command reduction drives *matching*, but a record carries more than a
command line. `flatten_fields` keeps the whole event — canonically named
(`ParentImage`, `User`, `IntegrityLevel`, …) — and it rides along on each
`Finding` as `observed_event`. When `--telemetry` is paired with `--sigma` (or
feeds `--coverage-gaps`), rule evaluation uses
[`sigma_eval::evaluate_observed`](../../src/sigma_eval.rs) instead of the
predictive `evaluate`: the recorded fields are overlaid on the synthesized base,
so a rule keyed on a field a command line cannot supply resolves against the
real event.

The effect is that verdicts which are `INDETERMINATE` in predictive mode become
definite. For a certutil download whose recorded `ParentImage` is `WINWORD.EXE`,
a rule selecting on that parent reports:

```
predictive (text):        indeterminate (needs ParentImage)
observed (real event):    fires
```

Evaluation stays honest: a field the record genuinely lacks is still
`INDETERMINATE`, and an unsupported Sigma modifier (`re`, `cidr`, `base64`) is
still `Unknown` — the real event resolves only the fields it actually carries.

## Scope and what comes next

The cut is deliberately one format:

- **Process-creation events only.** The KB matches commands, so process creation
  is the natural target. Other event classes (network / file / registry) tie
  into the `edr.rs` event-class taxonomy and are out of scope for now.

auditd (`EXECVE`/`SYSCALL`) and macOS/ESF follow as further formats behind the
same `--telemetry` input path, reusing this same reduction and observed-event
evaluation.
