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

### Writing an `example`

Without one, the command an entry is verified against is derived from its
matcher's own literals — which is often a fragment no real rule matches, so the
claim reads contradicted rather than untested. Author an `example` when that
happens. Four rules, each of which has bitten:

- **Write what an operator would type**, not a string built to satisfy a rule.
  A claim is that a real rule catches the *action*; an example reverse-engineered
  from the rule proves only that the rule matches itself.
- **The first command on the line must be the entry's own program.** Verification
  parses only the first command, while the self-consistency guard matches any
  command on the line — so `foo | bar` can satisfy both while proving nothing
  about `foo`. A pipeline is fine when the rule keys on the whole line and the
  entry's program leads it.
- **An `event` axis is probed by the *first* branch of an `any`.** A command
  `example` cannot stand in for a record, so when a file or registry rule will
  not fire, the lever is the order of the predicate — not the example. Branch
  order does not affect matching.
- **A rule keyed on an absolute `Image:` path cannot fire.** `Image` is
  synthesized from the program basename, so `Image: '/usr/bin/mdfind'` is a
  definite *false* against `/mdfind`. No example reaches it; the claim should be
  withdrawn instead.

`--verify-detections` names the rules that answered no under each `UNVERIFIED`
entry, which is where to start: read those rules, not the whole ruleset.

## Detection-verification baselines

A detection claim in the knowledge base is an assertion about the outside world,
so CI proves it rather than trusting it. `--verify-detections` synthesizes a
representative command (and, for an `event` axis, a representative record) for
every entry carrying a Sigma claim, then checks whether a genuine SigmaHQ rule
for that technique actually fires on it. The verdicts are committed as
`.ci/verified-<platform>.json`, and the `verify detections` job runs two checks
against them. The first is relative: it fails if a verdict gets worse than its
baseline, if a change adds a claim the ruleset refutes, or if the count of
refuted claims rises. A newly added entry has no baseline row to fall from, so
it is checked on its own terms rather than skipped — landing a claim no rule
substantiates is the same defect as breaking one that used to hold.

The second is absolute, and needs no baseline: **no entry may claim a Sigma
detection that no rule fires on.** All three platforms read zero, and this is
what holds them there — the relative check compares against a committed file,
so regenerating that file would otherwise launder a refuted claim into the
baseline. If your entry cannot reach a real rule, make no claim: omit
`detections` entirely. That is a finding, not a gap left unfilled, and
`--coverage-gaps` and `--scaffold` are what it feeds.

That comparison only means something if both sides are fixed, so CI checks out
the exact SigmaHQ commit named in [`.ci/sigma-ref`](.ci/sigma-ref) rather than
whatever `main` happens to be. Each baseline also records the revision it was
computed from, in its own `sigma_ref` field, so a baseline still says what it
came from when you diff against it locally months later.

The pin and the baselines are one fact stored twice, and
`scripts/sync-sigma.sh --check` (offline, on every pull request) fails if they
disagree. Move them together — never hand-edit either:

```bash
scripts/sync-sigma.sh --ref              # what is pinned right now
scripts/sync-sigma.sh --bump latest      # or a specific 40-hex commit id
```

`--bump` prints what the new revision does to the existing baselines *before*
overwriting them; that delta is what belongs in the pull-request description,
because the JSON diff alone cannot tell an upstream improvement apart from a
silently accepted regression.

You should not normally need to bump the pin yourself. The scheduled
`sigma drift` workflow runs the same comparison against upstream `main`, and a
red run there is the prompt to review the delta and move the pin.

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
