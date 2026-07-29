# Changelog

All notable changes to opseclint are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Known-benign corpus test** — asserts a curated corpus of everyday commands
  per platform (navigation, dev/build tooling, log reads) produces zero
  findings, guarding against knowledge-base false positives.

### Fixed

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
