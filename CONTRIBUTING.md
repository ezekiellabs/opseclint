# Contributing to opseclint

Thanks for your interest! The most valuable contributions are **new detection
coverage** and **fixes to false positives/negatives** — most of which are data
changes, not code.

## Development setup

opseclint is a single Rust crate (edition 2024, stable toolchain).

```bash
cargo build
cargo test
```

Before opening a PR, run the same gates CI enforces:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

`main` is protected: open a pull request and let CI (`build & test` and
`sigma live enrichment`) go green before merging.

## Adding detection coverage (the common case)

Coverage lives in the per-platform knowledge bases:

- `data/knowledge.json` — Linux / auditd
- `data/knowledge-windows.json` — Windows / Sysmon
- `data/knowledge-macos.json` — macOS / Endpoint Security

Each entry maps a command (or a raw pattern) to ATT&CK technique(s), the
telemetry it emits, representative Sigma-style detections, and a detectability
score:

```json
{
  "id": "short-kebab-id",
  "command": "curl",
  "args_contains": "urlcache",
  "description": "One line: what a defender would observe.",
  "techniques": [{ "id": "T1105", "name": "Ingress Tool Transfer" }],
  "telemetry": ["the concrete host event(s) this produces"],
  "detections": [{ "source": "Sigma", "rule": "...", "confidence": "high" }],
  "noise": 60
}
```

An entry matches either by `command` (with optional `args_contains` /
`raw_contains` refinements) or by `raw_contains` alone. Keep `id`s unique within
a file, and add a matching test in `src/analyzer.rs` when you introduce a
notable technique.

## Guidelines

- Cite real ATT&CK technique IDs; keep detection references representative and
  honest about confidence.
- Tune `noise` (0–100) to reflect how strongly an action surfaces in telemetry,
  not how "bad" it is.
- **Scope:** opseclint describes *detectability* — what a defender would see. It
  does **not** recommend evasions. Pull requests that add "how to be quieter /
  defeat this detection" guidance are out of scope and won't be merged.
- For user-facing changes, add a line under `## [Unreleased]` in
  [CHANGELOG.md](CHANGELOG.md).

## Reporting bugs and requesting coverage

Use the issue templates (Bug report / Coverage request). For security issues,
see [SECURITY.md](SECURITY.md). For questions and ideas, use
[Discussions](https://github.com/ezekiellabs/opseclint/discussions).
