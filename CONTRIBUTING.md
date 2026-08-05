# Contributing to opseclint

Thanks for your interest! The most valuable contributions are **new detection
coverage** and **fixes to false positives/negatives** — most of which are data
changes, not code.

## Development setup

opseclint is a Cargo workspace of three crates (edition 2024, stable toolchain):

- **`crates/opseclint-core`** — the knowledge base and everything that computes
  over it: the `match` engine, the Sigma evaluator, telemetry ingest, the EDR
  mapping. Published as a library so other tools build on this data rather than
  fork it.
- **`crates/opseclint`** — the CLI: argument parsing, the rendered report, and
  the knowledge-base tooling (`--scaffold`, `--verify-detections`,
  `--coverage-gaps`).
- **`crates/opseclint-mcp`** — an MCP server over the same core, for agents.

The two binaries are core's *consumers*, not its owners. New coverage and
matching logic almost always belong in core; anything about how a result is
*presented* belongs in whichever consumer presents it.

A note on the MCP crate specifically: its result types exist to keep an
abstention from being read as a negative, and the tests in `server.rs` under
"the uncertainty contract" hold that property. Treat those as load-bearing —
if a change makes one fail, the fix is almost never to relax the test.

```bash
cargo build
cargo test
```

Both crates build and test together from the workspace root. `opseclint-core`
must also stand on its own without the CLI's dependencies, which CI checks with
`cargo test -p opseclint-core` — that build has no `clap` feature, so a stray
`use clap::…` in core fails there while passing a workspace build.

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

- `crates/opseclint-core/data/knowledge.json` — Linux / auditd
- `crates/opseclint-core/data/knowledge-windows.json` — Windows / Sysmon
- `crates/opseclint-core/data/knowledge-macos.json` — macOS / Endpoint Security

Each entry maps an action to ATT&CK technique(s), the telemetry it emits,
representative Sigma-style detections, and a detectability score. Matching is
driven by a structured `match` predicate:

```json
{
  "id": "short-kebab-id",
  "match": { "program": "certutil", "args": { "contains": "urlcache" } },
  "description": "One line: what a defender would observe.",
  "techniques": [{ "id": "T1105", "name": "Ingress Tool Transfer" }],
  "telemetry": ["the concrete host event(s) this produces"],
  "detections": [{ "source": "Sigma", "rule": "...", "confidence": "high" }],
  "noise": 60
}
```

`match` has four optional axes — `program` (the resolved basename), `args` (a
predicate tree over the arguments), `line` (the whole raw line), and `event` (a
non-execution record's fields, for telemetry with no command line) — with leaves
like `contains`, `flag`, `word`, `path_under`, `any`/`all`/`not`, and `regex`.
Prefer the boundary-aware leaves (`word`, `path_under`) over a bare `contains` to
avoid false positives, and reach for `regex` only when the fixed leaves can't
express the shape (an entry that uses `regex` must also carry an `example`). The
full reference is [docs/design/match-schema.md](docs/design/match-schema.md).

If the action also shows up as a standalone sensor event — a file written, a
connection made — give the entry an `event` axis alongside its command axis, so
one entry recognizes it either way rather than splitting into two.

Keep `id`s unique within a file, and add a matching test in
`crates/opseclint-core/src/analyzer.rs` when you introduce a notable technique.

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
