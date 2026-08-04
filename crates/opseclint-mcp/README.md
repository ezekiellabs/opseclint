# opseclint-mcp

[![Crates.io](https://img.shields.io/crates/v/opseclint-mcp.svg?style=flat-square)](https://crates.io/crates/opseclint-mcp)
[![MIT License](https://img.shields.io/crates/l/opseclint-mcp.svg?style=flat-square)](../../LICENSE)

An [MCP](https://modelcontextprotocol.io) server over
[opseclint](https://github.com/ezekiellabs/opseclint)'s detection knowledge
base. *"what would a defender see?"* — for agents.

Agents are being pointed at security work with no ground truth. They
hallucinate detections and confidently misjudge what is observable. This puts a
real knowledge base and a real rule evaluator behind four tools, so the answer
comes from data rather than from recall.

## Install

```sh
cargo install opseclint-mcp
```

Then point a client at the binary:

```json
{
  "mcpServers": {
    "opseclint": { "command": "opseclint-mcp" }
  }
}
```

It speaks MCP over stdio. Every knowledge base is compiled in, so the server
makes no network calls and reads no files — including for
`evaluate_sigma_rule`, which takes rule text inline rather than a directory
path. An MCP server takes instructions from a model; the safest one has nothing
to reach for.

## Tools

| Tool | Answers |
| --- | --- |
| `analyze_command` | What does this command emit, which ATT&CK techniques does it implement, and what would detect it? |
| `lookup_technique` | What implements T1059.001, and what telemetry does that produce? |
| `evaluate_sigma_rule` | Would this specific Sigma rule fire on this command — `fires`, `no_fire`, or `indeterminate`? |
| `describe_coverage` | What does opseclint actually model, and what does it not? |

## The part that matters

Agents amplify whatever they are given, which makes opseclint's abstain-honestly
property load-bearing here in a way it never was in a terminal. Two failure
modes drove the design of every result in this crate:

**`indeterminate` is not `no`.** Rule evaluation is three-valued. A rule keyed
on a field a command line cannot carry — `ParentImage`, a hash, a registry
value — comes back `indeterminate`, meaning *the input could not answer the
question*. Collapsed to a boolean it becomes "would not fire", which reads as
evidence of stealth and is nothing of the kind. So no field in any result is a
boolean about whether something was detected; the verdict is a three-variant
enum, and the one boolean nearby, `verdict_is_conclusive`, is about the
verdict's standing and is `false` exactly when the answer is unavailable.

**An empty result is a statement about coverage, not about the command.** The
knowledge base models a bounded set of actions. No finding means nothing modeled
matched — never that the action is invisible. `describe_coverage` exists so that
distinction is always resolvable, and every empty result says so and points at
it.

Every result carries a `summary` in prose and a `limits` list naming what the
answer does not establish. Neither can force an agent to reason well; what they
do is make the uncertainty impossible to drop *silently*.

## Scope

This describes *detectability* only — what a defender would see. It does not
provide evasion guidance and will not help make an action quieter. That is the
same commitment the CLI ships under, and it is enforced in the server
instructions the client receives at connect time.

## License

MIT. See [LICENSE](../../LICENSE).
