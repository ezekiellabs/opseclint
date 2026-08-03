# Changelog

All notable changes to opseclint are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`sync-packaging.sh` now substitutes the version only where it is declared to
  live**, instead of replacing it everywhere and excluding the collisions. The
  old approach accumulated four exclusions — a GNU-only `sed` address range, an
  ERE quantifier, the winget `ManifestVersion`, and the schema version quoted in
  prose — every one of which shipped before being caught. An allowlist inverts
  the failure mode from "silently changed something that was not ours" to
  "silently changed too little", and unlike the former that is detectable: after
  each bump the script asserts no line outside a known foreign-version line
  still carries the old version, naming the file and line if one does.

### Fixed

- **`sync-packaging.sh` could corrupt the winget manifests.** The version bump
  replaced every occurrence of the crate's version in each manifest, and the
  winget files carry a second version-shaped string that means something else
  entirely — `ManifestVersion` and the `$schema` URL, which track the *winget
  schema*, not opseclint. The schema was `1.6.0` and this crate is on its way
  there: releasing 1.6.0 and then bumping to 1.7.0 would have silently rewritten
  all three manifests to reference a schema version that does not exist. Those
  two lines are now held back from the substitution.
- winget manifests migrated from schema `1.6.0` to **`1.12.0`**, which is what
  `microsoft/winget-pkgs` now asks new submissions to conform to. Every field
  1.12.0 requires was already present, so this is a version-string change only.

### Added

- **`--verify-detections` now reports *why* an entry is indeterminate**, not just
  that it is. `INDETERMINATE` had several distinct causes collapsed into one
  status, so the count said only "the evaluator abstained a lot" — not whether
  that was fixable, or by what. Each entry now carries the modifier tokens the
  evaluator does not implement, the fields a rule keys on that a command line
  cannot supply, rules that could not be lowered to logic at all, and
  field-absent (`null`) assertions — reported per entry in `--json` and as a
  ranked breakdown in the human summary. The distinction matters because the
  causes are entirely different work: modifiers are evaluator features, missing
  fields are telemetry the tool would have to be handed.

### Fixed

- The three tag-triggered workflows matched `v*`, which also matches the moving
  major tag (`v1`) that `release.yml` now re-points at each release. Pushing
  that pointer therefore ran the full release pipeline: it built and published a
  GitHub Release literally named **v1**, which became `releases/latest` and
  displaced the real one — breaking every consumer that resolves "latest",
  including this repository's own composite action (`action.yml` asks
  `/releases/latest` for a tag and derives the asset name from it) and Scoop's
  `checkver`. It also re-ran `cargo publish` against an already-published
  version. All three now match `v*.*.*`, so a major-tag push is inert.
- Packaging manifests (Homebrew, Scoop, AUR, winget) were still pinned to the
  v1.1.0 artifacts and hashes while the crate was at 1.2.0 — every one of the
  four staged channels would have installed the wrong version or failed its
  checksum. All are now on v1.2.0. The AUR `PKGBUILD` also shipped a
  `you@example.com` maintainer placeholder; it now names the real maintainer.
  The Homebrew formula interpolates `#{version}` into its URLs and test
  assertion, so a future bump touches only `version` and the three `sha256`
  lines.
- Documentation that contradicted the shipped tool. `SECURITY.md` claimed
  opseclint was pre-1.0 and now carries a real supported-versions table.
  `docs/design/rule-logic-evaluator.md` was still marked **proposed** although
  it shipped in v1.0.0, and its non-goals listed `ParentImage` / `User` as
  unresolvable without noting that v1.2.0's `--telemetry` and `--users` resolve
  them from a recorded event; the section is now scoped to predictive mode. The
  README's GitHub Action example referenced `ezekiellabs/opseclint@v1` — a tag
  that does not exist — and taught `codeql-action/upload-sarif@v3` while CI uses
  `@v4`; both are corrected. Stale `v0.1.0` version placeholders in the bug
  report template and `action.yml` now name the current release.
- The README pointed readers at an empty issue tracker for "the full list". It
  now links the changelog, coverage requests, and Discussions, and the 13/13
  checked Roadmap is a `What's shipped` list plus an honest `Next` section.
- `.gitignore` covered only `/target`, leaving the SigmaHQ ruleset clones that
  the README and CI both create (`sigma/`, `sigma-rules/`) and `*.sarif` output
  untracked in the working tree.
- `LICENSE` named a different copyright holder than the organization's other
  repositories; standardized on Ezekiel Labs.
- The release workflow ran `softprops/action-gh-release` from **all four**
  matrix build jobs against the same tag, with no `needs:` and no concurrency
  guard. The four concurrent create-release calls race, and a loser creates a
  stray *untagged draft* release next to the real one — reproducibly, on every
  release. `build` now uploads artifacts and a single `publish` job creates the
  release from them.

### Added

- `scripts/sync-packaging.sh` — one implementation of "where the version lives",
  used three ways: `--check` (offline parity against `Cargo.toml`), `--bump`
  (move every version string), and `<version>` (fetch the published artifacts
  and fill in real hashes). Because the fixer and the checker are the same code,
  they cannot disagree.
- CI gate asserting `packaging/` matches `Cargo.toml`, and a post-publish
  release job that recomputes the four artifact hashes and fails if `packaging/`
  does not carry them. The first is offline and cheap; the second runs at the
  only moment the real hashes exist.
- The release workflow now re-points the major tag (`v1`) at each release, so
  the `ezekiellabs/opseclint@v1` pin that the README and Marketplace advertise
  resolves. Pre-release tags are skipped.

## [1.2.0] - 2026-07-31

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

[Unreleased]: https://github.com/ezekiellabs/opseclint/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/ezekiellabs/opseclint/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ezekiellabs/opseclint/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ezekiellabs/opseclint/compare/v0.1.2...v1.0.0
[0.1.2]: https://github.com/ezekiellabs/opseclint/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ezekiellabs/opseclint/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ezekiellabs/opseclint/releases/tag/v0.1.0
