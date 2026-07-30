# Reference: ingesting real telemetry

**Status:** current (Windows Sysmon EID 1 JSON; Linux auditd `execve`; macOS ESF `NOTIFY_EXEC`)
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

## The reduction (Linux auditd)

auditd records one `execve` as **several single-line records sharing an event
id** — `SYSCALL` (the call, `exe`, ids), `EXECVE` (the argv), `CWD` (the working
directory), `PROCTITLE` (a hex cmdline). They may interleave with other events
in the log, so ingestion first **reassembles** them:

```
audit(1700000000.101:801)  →  { SYSCALL, EXECVE, CWD, PROCTITLE }
```

grouping every parsed record by the `<ts>:<serial>` inside `audit(…)`, in
first-seen order. An event is a process launch when it carries an **`EXECVE`**
record — the kernel emits `EXECVE` only for `execve`/`execveat`, which makes this
arch-independent (no matching on syscall number `59` vs `221`). Every other event
class (a `connect`, an `open`) has no `EXECVE` and is **skipped and counted**.

For a qualifying event the reduction fills the same canonical field map the
Sysmon path produces, so `execution_from_fields` — the shared reducer — and all
downstream analysis are identical:

- **`CommandLine`** ← the `EXECVE` argv, rebuilt by joining `a0`, `a1`, … in
  order. Each value is **decoded**: auditd double-quotes values, or hex-encodes
  them when they contain spaces/quotes/control characters (`a0=6C73` → `ls`).
  Decoding is applied only to string fields, never numeric ones, so `pid=5678`
  is never mistaken for hex. Because auditd hands us the *exact* argv but the
  shared reducer re-tokenizes the joined line, each element is **re-quoted** when
  it holds anything the shell parser would act on (whitespace, a quote, a `;` /
  `|` / `&`), so an argument that legitimately contains a space stays one token
  instead of splitting into several.
- **`Image`** ← the `SYSCALL` `exe` path (also decoded); its `basename` becomes
  the primary command's program.
- **`CurrentDirectory`** ← the `CWD` record — a field the command line can't
  supply, carried for observed Sigma evaluation.
- **`tty`** / **`key`** ← the `SYSCALL` controlling tty and audit-rule tag — extra
  context a rule may key on, carried only when the record includes it (a `(none)`
  tty is a placeholder and is dropped).

Two fields are **deliberately not mapped**, because doing so would fabricate a
wrong answer rather than an honest "can't tell":

- **`ParentImage`** — auditd records only a numeric `ppid`, not the parent's
  path. Parent-keyed rules stay `INDETERMINATE`.
- **`User`** — auditd records a numeric `uid`; mapping `0` onto the name-based
  `User` field would make a rule expecting `root` report a definite `no-fire`.
  Left absent, such a rule stays `INDETERMINATE` (honest) instead — **unless**
  `--users <passwd-file>` supplies the uid→name mapping, in which case `User` is
  resolved from it (`parse_passwd`). The resolution is opt-in precisely so the
  default never guesses: no mapping ⇒ no `User` ⇒ honest indeterminate.

Reassembling oversized args split across `aN_len` + `aN[0]…` chunks is a known
limitation; the common single-token `aN` shape is handled.

## The reduction (macOS Endpoint Security)

macOS emits one **`ES_EVENT_TYPE_NOTIFY_EXEC`** per launch. Exported with Apple's
built-in `eslogger exec`, each is a self-contained JSON object (a top-level array,
a single object, or JSONL, read by the same reader the Sysmon path uses — no
reassembly). A record
is an execution when it carries an `event.exec` object; any other event class
(`event.open`, `event.fork`) is **skipped and counted**.

The ESF exec model is the key to the mapping. `event.exec.target` is the *new*
process, while the message's top-level `process` is the caller that invoked
`exec`:

- **`Image`** ← `event.exec.target.executable.path`; its `basename` is the
  program.
- **`CommandLine`** ← `event.exec.args`, joined with the same argv re-quoting the
  auditd path uses (ESF also hands us exact argv).
- **`CurrentDirectory`** ← `event.exec.cwd.path`.
- **`ParentImage`** ← `process.executable.path`, the calling process's image.
- **`signing_id`** / **`team_id`** / **`is_platform_binary`** ← the new image's
  code-signing context. These are carried under their `eslogger` field names and
  are what macOS detections key on to flag unsigned or third-party binaries
  (`is_platform_binary: 'false'`) — a fact only a real Endpoint Security event
  supplies, so such a rule is indeterminate predictively and resolves here.

That parent mapping is what sets ESF apart: unlike auditd (a numeric `ppid` only),
ESF names the calling process, so `ParentImage`-keyed detections **resolve**
against ingested macOS telemetry. `User` is still left unmapped — the audit token
carries a numeric uid, the same name-vs-number hazard as auditd.

## Evaluating detections on the real event

The command reduction drives *matching*, but a record carries more than a
command line. Each format's reduction keeps the whole event field map — keyed by
the canonical field names a Sigma rule references (`ParentImage`,
`IntegrityLevel`, `CurrentDirectory`, …) — and it rides along on each `Finding`
as `observed_event`. When `--telemetry` is paired with `--sigma` (or feeds
`--coverage-gaps`), rule evaluation uses
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

## Correlating non-execution events

A real export interleaves process launches with the network, file, and registry
events those processes cause. opseclint reduces only executions into analyzable
units, but it does not throw the rest away: each non-execution record names the
process that emitted it (its **pid**), so it can be **correlated back** to the
execution and surfaced as *confirmed* secondary telemetry.

This turns a prediction into an observation. Where predictive mode says "certutil
*would* emit an outbound connection", correlation adds the recorded proof:

```
├ ◈ Sysmon EID 3 (network) from certutil.exe          ← predicted
├ ◉ observed: network connection to 192.0.2.10:443     ← confirmed, from EID 3
├ ◉ observed: file created C:\Users\analyst\a.exe      ← confirmed, from EID 11
```

Each execution `Observation` carries its `pid`; non-execution records are parsed
into `(pid, SideEffect{class, detail})` pairs and attached to the matching
observation (`correlate_side_effects`), then ride onto every `Finding` as
`observed_side_effects` and render as green `◉ observed:` lines. An event whose
causing process is not in the same file is dropped — correlation never guesses.

**Currently wired for Sysmon** (EID 3 network → `DestinationIp:DestinationPort`,
EID 11 → `TargetFilename`, EID 13 → `TargetObject`), the canonical case: a flat
`ProcessId` and named destination/target fields. The same framework extends to
auditd (correlate by `pid`, decode `SOCKADDR` `saddr`) and ESF (the audit-token
pid, `NOTIFY_OPEN`) as follow-ons. Pid reuse is the known caveat — correlation is
scoped to a single ingest file; tightening it with event timestamps / process
start time is a future refinement.

## Scope and what comes next

- **Process-execution events only.** The KB matches commands, so process launches
  are the natural target across all three formats. Other event classes (network /
  file / registry) tie into the `edr.rs` event-class taxonomy and are out of
  scope for now — they are skipped and counted.

With Sysmon, auditd, and ESF, the three platforms opseclint models each have a
process-execution ingest path. Natural extensions from here are non-execution
event classes (file / network / registry) mapped through `edr.rs`, and richer
per-format field coverage (e.g. resolving numeric uids to names when a record
carries the mapping) — each additive behind the same reduction and observed-event
evaluation.
