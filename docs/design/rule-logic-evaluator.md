# Design: Sigma rule-logic evaluator

**Status:** current (shipped in v1.0.0 as `--check-rule` and `--coverage-gaps`)
**Scope:** upgrade `--sigma` from technique-tag matching to real detection-logic
evaluation, and add coverage-gap analysis.

## Motivation

Today `--sigma` links a finding to Sigma rules that share an ATT&CK technique
tag. That is coarse: it says "a rule exists for this technique", not "this rule
would fire on this command."

The upgrade evaluates a parsed command against a rule's actual
`detection:`/`condition:` logic. The central obstacle is also the central idea:
Sigma rules match **event fields** (`CommandLine`, `Image`, `ParentImage`,
`TargetFilename`, …), while opseclint has a **command string**, not a full
process event. The evaluator therefore does two things:

1. **Synthesizes a pseudo-event** from the parsed command — the fields it can
   legitimately know.
2. **Evaluates the rule with three-valued (Kleene) logic** — `FIRES` /
   `NO-FIRE` / `INDETERMINATE` — where `INDETERMINATE` means the rule keys on a
   field opseclint cannot see (e.g. `ParentImage`, a hash, a registry value).

Abstaining honestly (`INDETERMINATE`) is a feature: it keeps the tool truthful
about the limits of static analysis, and it is exactly what makes the
coverage-gap number trustworthy.

## Non-goals (predictive mode)

These bound what can be resolved from a **command line alone**. Since v1.2.0,
`--telemetry` supplies `ParentImage`, `IntegrityLevel`, `CurrentDirectory`, and
(with `--users`) `User` from a **recorded** event, so those fields resolve to
`fires` / `no-fire` in observed mode rather than reading `INDETERMINATE`. See
[telemetry-ingest.md](telemetry-ingest.md).

- Fields opseclint cannot synthesize from a command line (`ParentImage`,
  `User`, `Hashes`, registry and network fields) → these branches evaluate to
  `Unknown` and surface as `INDETERMINATE`.
- Modifiers `re`, `cidr`, `base64`/`base64offset`, `windash` → treated as
  `Unknown` (documented), implemented later. Still open.
- Aggregations (`| count() > N`, `near`, `timeframe`) and correlation rules →
  out of scope; opseclint evaluates a single command, not an event stream.

## Design

### Event synthesis

```rust
struct Event { fields: HashMap<String, String>, available: HashSet<String> }
fn synthesize(cmd: &Command, platform: Platform) -> Event;
```

| Sigma field                       | Source                                             | Available |
|-----------------------------------|----------------------------------------------------|-----------|
| `CommandLine`                     | `cmd.raw`                                           | yes       |
| `Image` / `OriginalFileName`      | resolved program path (+ platform extension)       | yes       |
| `TargetFilename`                  | path-shaped args (try each; any match ⇒ hit)       | when present |
| `ParentImage`, `User`, `Hashes`, registry/network | —                                  | no → drives `INDETERMINATE` |

A `FieldMatch` on a field not in `available` evaluates to `Unknown`.

With `--telemetry`, the event is **ingested rather than synthesized**, so the
last row's fields are populated from what the sensor actually recorded and
`available` grows accordingly — the same evaluator, given a real event.

### Data model (`src/sigma_eval.rs`)

```rust
enum Modifier { Contains, StartsWith, EndsWith, All } // v2: Re, Cidr, Base64, Windash

struct FieldMatch { field: String, mods: Vec<Modifier>, values: Vec<String> }
// values: OR across values, unless `All` (then AND)

enum Search {
    Fields(Vec<FieldMatch>),          // map form: AND across fields
    OneOfMaps(Vec<Vec<FieldMatch>>),  // list-of-maps: OR
    Keywords(Vec<String>),            // bare list: matched against CommandLine
}

enum Cond {
    Id(String),
    And(Box<Cond>, Box<Cond>),
    Or(Box<Cond>, Box<Cond>),
    Not(Box<Cond>),
    OneOf(String),  // glob pattern like "selection*" or "them"
    AllOf(String),
}

struct DetectionRule {
    id: String, title: String, level: String,
    category: Option<String>, product: Option<String>,
    searches: HashMap<String, Search>,
    condition: Cond,
}
```

`SigmaRuleRaw` gains `detection` (parsed from `serde_yaml::Value`) and
`logsource.category`. Parsed `DetectionRule`s live in `SigmaIndex` and the
on-disk cache (bump the cache fingerprint/version so stale caches rebuild).

### Three-valued evaluation

`FieldMatch → {True, False, Unknown}` (`Unknown` iff the field is unavailable).

- **Search (AND of fields):** any `False` ⇒ False; else any `Unknown` ⇒ Unknown;
  else True.
- **`and`:** any `False` ⇒ False; else any `Unknown` ⇒ Unknown; else True.
- **`or`:** any `True` ⇒ True; else any `Unknown` ⇒ Unknown; else False.
- **`not`:** swap True/False; `Unknown` ⇒ Unknown.
- **`N of selection*` / `all of them`:** desugar to OR / AND over the matching
  identifiers, same tables.

Final verdict: `True → FIRES`, `False → NO-FIRE`, `Unknown → INDETERMINATE`
(attach the list of missing fields so the report can explain the abstention).

### Field-match semantics

- Default string comparison is **case-insensitive** (per the Sigma spec).
- Plain values with `*` / `?` are treated as globs.
- `contains` / `startswith` / `endswith` / `all` as defined by Sigma.
- A value list is OR unless the field carries the `all` modifier.

### Condition parser

A small recursive-descent / Pratt parser (~120 lines). Tokens: identifiers,
`and` / `or` / `not`, parentheses, `N of`, `all`, `them`, and `*` in identifier
patterns. Fully unit-testable in isolation from the rest of the tool.

## Output and new capabilities

- Each enriched detection gains a **verdict**: `fires`, `no-fire`, or
  `indeterminate: needs <field>`.
- **`--coverage-gaps`**: list actions whose techniques have rules but where
  **zero rules FIRE** — the blind spots. This is the purple-team headline
  feature and falls out of the evaluator for free.
- SARIF / JSON carry the verdict so CI can gate on "N uncovered actions".

## Implementation plan

**First slice (one PR):**

1. `Search::Fields` with `contains` / `endswith` / equals; `CommandLine` +
   `Image` synthesis; ternary evaluation; `and` / `or` / `not` / `1 of` /
   `all of` conditions.
2. Test fixtures containing real `detection:` / `condition:` blocks.
3. Tests:
   - `CommandLine|contains: '/etc/shadow'` **FIRES** on `cat /etc/shadow`.
   - a rule keyed on `ParentImage` → **INDETERMINATE** (reports the missing
     field).
   - `selection and not filter`, where the filter excludes the command →
     **NO-FIRE**.

**Later:** `re` / `cidr` / `base64` modifiers, `TargetFilename` synthesis,
`--coverage-gaps` output, verdicts in SARIF, richer event synthesis.

## Risks and honesty

- **Lossy synthesis.** opseclint has a command, not a host event. The evaluator
  must abstain (`INDETERMINATE`) rather than claim a rule fires when it cannot
  confirm the fields. This is deliberate: a static analyzer will never confirm a
  `ParentImage` rule, and saying so plainly is what makes the coverage number
  trustworthy.
- **Sigma spec breadth.** Pin to a documented supported subset; log unsupported
  constructs instead of silently mis-evaluating them.

## Non-goals restated

opseclint describes **detectability**. Evaluating which rules fire does not
change that: there is still no evasion guidance. If anything, precise rule
evaluation makes the defensive framing sharper.
