# Changelog

All notable changes to opseclint are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`--telemetry <FILE>`** — ingest recorded host telemetry (the events a sensor
  actually logged) and map it back to techniques, detectability, and coverage —
  the observed-mode complement to opseclint's predictive analysis. Three formats
  are supported (`--format`): Windows **Sysmon Event ID 1** (Process Create), as
  a JSON array of events or JSONL (`sysmon`) — flat, `EventData`-nested, and
  Elastic `winlog.event_data` shapes are all accepted; Linux **auditd** `execve`
  events, as raw `audit.log` text (`auditd`) — the multi-line `SYSCALL` /
  `EXECVE` / `CWD` records of one event are reassembled by their `audit(…)` id,
  the argv rebuilt from the `EXECVE` fields (quoted and hex-encoded values
  decoded), and the program taken from the `exe` path; and macOS **Endpoint
  Security** `NOTIFY_EXEC` events, as `eslogger exec` JSON (`esf`) — the image,
  argv, and working directory from `event.exec.target`, and a real `ParentImage`
  from the calling process. Each record reduces to the
  same `Command` the analyzer already understands, so `--json` / `--sarif` /
  `--navigator` / `--edr` all work on ingested events, and observed verdicts
  agree with predicted ones by construction. Non-execution records are skipped
  and counted. When paired with `--sigma`, detections are evaluated against the
  **real recorded event**: a rule keyed on a field a command line can't supply
  (`ParentImage`, `IntegrityLevel`, `CurrentDirectory`, macOS code-signing fields
  like `is_platform_binary`, …) resolves to `fires` / `no-fire` instead of
  `indeterminate` — the payoff of ingesting real telemetry. Each format carries
  the extra context it records: ESF the calling parent and the new image's
  code-signing (`signing_id` / `team_id` / `is_platform_binary`), auditd the
  controlling `tty` and audit-rule `key`. Non-execution records (Sysmon EID 3 /
  11 / 13) are **correlated by process id** back to the execution that emitted
  them and shown as confirmed secondary telemetry — a green `◉ observed:` line
  (e.g. `network connection to 192.0.2.10:443`) turning predicted telemetry into
  recorded proof.
  See [`docs/design/telemetry-ingest.md`](docs/design/telemetry-ingest.md).

- **`--users <FILE>`** — a `passwd`-format file mapping numeric uids to names, so
  ingested auditd telemetry resolves the `User` field (uid `0` → `root`), letting
  `User`-keyed detections resolve. Opt-in by design: without it a numeric uid is
  left unresolved rather than guessed, so a rule expecting `root` stays
  `indeterminate` instead of getting a wrong `no-fire`.

- **Standalone non-execution matching** — a non-execution event with no captured
  causing execution (e.g. a registry Run-key set by an uncaptured process) is now
  matched directly against a new `event` axis on the KB matcher (tests an event
  `class` and a field, e.g. a registry `TargetObject`). An entry can carry both a
  command `line` axis and an `event` axis, so it recognizes its action whether
  seen as a command or a standalone event; the Windows `run-key-persist` entry is
  seeded this way. Events that correlate to an execution attach as its side-effect
  and are not also matched standalone. Linux/macOS event-scoped entries follow.

- **`--verify-detections`** — prove the knowledge base's own Sigma detection
  claims against a real ruleset. For every entry that cites a Sigma detection,
  opseclint synthesizes a representative command and checks whether a genuine
  SigmaHQ rule for the entry's technique(s) actually fires, classifying each as
  `verified` / `unverified` / `indeterminate` / `no-rule`. Audits the KB itself
  (no input needed); honors `--json` (snapshot) and `--diff` (regression). A new
  CI job runs it per platform against a fresh SigmaHQ checkout as a regression
  gate: `--ci` fails when a previously-verified detection stops firing (diff
  mode) or when any claimed detection is contradicted (standalone). Baselines
  live in `.ci/verified-<platform>.json`.

- **`--scaffold`** — generate a starter Sigma rule for each modeled action,
  with detection logic mirroring how opseclint matches it. Paired with
  `--coverage-gaps`, it scaffolds only the blind-spot actions, closing the
  loop from a coverage gap to a rule that would fire on it.

- **`--navigator`** — emit an ATT&CK Navigator layer (JSON) of the techniques an
  input surfaces, scored by detectability, for import at the MITRE ATT&CK
  Navigator to visualize coverage on the matrix.

- **Known-benign corpus test** — asserts a curated corpus of everyday commands
  per platform (navigation, dev/build tooling, log reads) produces zero
  findings, guarding against knowledge-base false positives.

- **Structured matcher `regex` leaf** — knowledge-base entries can now key on a
  regular expression (in `args`, `line`, or a positional/`joined` leaf) when the
  fixed leaves can't express the shape. Patterns compile at load (invalid = load
  error) and match case-insensitively; an entry that uses one must supply an
  `example` command, which also drives verification and scaffolding (`--scaffold`
  lowers it to a Sigma `CommandLine|re`). Used to fold the whole PowerShell
  `-WindowStyle Hidden` abbreviation family into one `powershell-hidden` rule.

### Fixed

- **EDR classifier re-audit** — after the knowledge base was deepened, the
  telemetry → EDR event-class classifier had drifted: 41 telemetry lines matched
  no class, and four Active Directory entries (`dcsync`, `kerberoast-getuserspns`,
  `asreproast`, `golden-ticket`) silently fell back to the `process_creation`
  default despite being Kerberos/replication **authentication** events (`4768`,
  `4769`, `4662`, TGS/AS-REQ, DRSUAPI). Extended the class patterns to cover the
  new telemetry vocabulary (Kerberos/AD auth, LDAP/DNS/tunnel network activity,
  `ptrace`/`init_module`/`getxattr`, systemd timers, etc.) with no reclassification
  of already-correct lines, so `--edr` now maps every entry to its true event
  class. Added a guard test asserting no entry with telemetry falls back to the
  default, so future KB growth can't silently regress the mapping.

- **`clear-syslog` false positive** — the Linux log-tampering rule keyed on a
  bare `/var/log` substring, so ordinary reads and navigation (`cd /var/log`,
  `tail -f /var/log/syslog`, `ls /var/log`) were flagged as anti-forensic log
  clearing. Scoped it to actual clearing commands (`rm`/`truncate`/`shred`
  targeting `/var/log`); `journalctl --vacuum` remains covered separately.

## [1.1.0] - 2026-07-27

### Added - 1.1.0

- **Startup banner** — running `opseclint` with no input on an interactive
  terminal now prints a brief banner and usage hint instead of blocking on a
  stdin read that never arrives.

- **Coverage diff (`--diff`)** — compare the current analysis against a report
  saved earlier with `--json` and render the delta: findings added, removed, or
  whose detectability / Sigma verdict shifted. Collapsed per rule (survives line
  shifts), honors `--json` for a machine-readable delta, and pairs with `--sigma`
  to catch a rule flipping a finding from `no-fire` to `fires`. With `--ci`, exits
  non-zero when peak detectability rose above the baseline.
- **`--coverage-gaps` now honors `--json` and `--diff`.** `--coverage-gaps --json`
  saves a coverage run; `--coverage-gaps --diff <saved.json>` diffs blind spots
  between two rulesets, reporting which gaps **closed** and which **opened**, and
  fails `--ci` when coverage regressed.
- **Deepened the Linux and Windows knowledge bases** — Linux 62 → 81 and Windows
  62 → 83 entries, adding modern attack surface the seed KBs missed. Linux gains
  cloud/container/Kubernetes coverage (instance-metadata credential theft, service-
  account tokens, `kubectl exec`/`get`, `nsenter` and `/proc/1/root` host escape),
  process injection (`gdb`/ptrace), persistence (`rc.local`, systemd timers),
  tunneling/exfil (proxychains, SSH SOCKS, dnscat, `rclone`/`aws s3`), and evasion
  (timestomp, `HISTFILE` tamper, GTFOBins shell escapes, `dd` wipe). Windows gains
  LOLBins (`msiexec`, InstallUtil, CMSTP, MSBuild, WSH/VBScript), UAC and AMSI
  bypasses, persistence (WMI event subscription, accessibility hijack, IFEO,
  Winlogon), credential access (`cmdkey`, `findstr`), security-software discovery,
  RDP enablement, `netsh portproxy` tunneling, and recovery inhibition
  (`wmic shadowcopy delete`, `wbadmin`).
- **EDR telemetry mappings (`--edr`)** — an opt-in flag that maps each finding's
  native host telemetry to the concrete sensor event or hunting table the major
  EDRs surface it as: CrowdStrike Falcon (`event_simpleName`), Microsoft Defender
  for Endpoint (Advanced Hunting tables), SentinelOne (Deep Visibility event
  types), and Elastic Defend (ECS `event.category`/`event.type`). Pass vendor or
  omit the value for all four. Mapping is driven by a telemetry event-class
  classifier plus an embedded `data/edr-telemetry.json` table, so new KB entries
  gain EDR coverage without per-entry authoring. Standard output is unchanged when
  the flag is absent; the `edr` field is added to JSON only when requested.
- **Deepened the macOS/Endpoint Security knowledge base** from 28 to 66 entries,
  reaching breadth parity with the Linux and Windows rulesets. New coverage spans
  process/network discovery (`ps`, `netstat`, `lsof -i`, `arp`), credential access
  (SSH private keys, `grep` for secrets, `dscl` ShadowHashData dumping, Safari/Chrome
  credential stores, `osascript` GUI phishing), scheduled-task and logon persistence
  (`crontab`, emond, periodic scripts, LoginHook, `authorized_keys`, `.zshrc`, hidden
  users), defense evasion (`DYLD_INSERT_LIBRARIES` hijacking, `socketfilterfw`/`pfctl`
  firewall tampering, `chflags`, `chmod +x`, `base64 -d`), collection/exfil (`tar`,
  `ditto`, `scp`), and lateral movement (`ssh`, ARD `kickstart`, Screen Sharing).

## [1.0.0] - 2026-07-23

### Added - 1.0.0

- **Sigma rule-logic evaluator** (`--check-rule`) — evaluate command against
  rule's actual `detection:`/`condition:` logic with three-valued (Kleene) logic:
  `FIRES` / `NO-FIRE` / `INDETERMINATE`.
- **`--coverage-gaps`** — flags actions whose ATT&CK techniques have rules in the
  `--sigma` ruleset but where none would actually fire (the purple-team blind
  spots). Exits non-zero with `--ci` when any gap is found.
- **Verdicts inline in `--sigma`** — each enriched rule is evaluated against the
  matched command and annotated `fires` / `no-fire` / `indeterminate`.
- **Tokyo Night** themed terminal output across the report, coverage, and
  rule-check views.
- Container image on GHCR and a Marketplace-ready GitHub Action.

### Changed - 1.0.0

- Unified the Sigma metadata index and the detection-logic index into a single
  cached `SigmaIndex`; `--coverage-gaps` now benefits from the on-disk cache too.
- CLI: `--help` is grouped into sections, and mutually-exclusive modes now error
  clearly instead of silently taking precedence.

## [0.1.2] - 2026-07-23

### Added - 0.1.2

- Published to [crates.io](https://crates.io/crates/opseclint) (`cargo install opseclint`).
- A GitHub Action (`action.yml`) and a `scratch`-based GHCR container image.

### Fixed - 0.1.2

- Sync `Cargo.lock` so the tag-triggered `cargo publish` workflow succeeds.

## [0.1.1] - 2026-07-23

### Added - 0.1.1

- crates.io metadata and a tag-triggered publish workflow.

## [0.1.0] - 2026-07-22

### Added - 0.1.0

- Initial release. Detection-coverage analyzer for **Linux/auditd**,
  **Windows/Sysmon**, and **macOS/Endpoint Security**.
- ~150 modeled post-exploitation actions mapping to ATT&CK techniques, the host
  telemetry they emit, representative Sigma-style detections, and a 0–100
  detectability score.
- Human / JSON / SARIF output; a `--ci` gate; `--sigma` enrichment from a real
  SigmaHQ checkout with an on-disk cache; a `--platform` selector.

[Unreleased]: https://github.com/ezekiellabs/opseclint/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/ezekiellabs/opseclint/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ezekiellabs/opseclint/compare/v0.1.2...v1.0.0
[0.1.2]: https://github.com/ezekiellabs/opseclint/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ezekiellabs/opseclint/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ezekiellabs/opseclint/releases/tag/v0.1.0
