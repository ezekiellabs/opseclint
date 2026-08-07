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

That only holds if `INDETERMINATE` means one thing. Rules are selected by ATT&CK
technique tag, and a technique's rules span event classes — `ps_script`,
`file_event`, `registry_set`, `proxy`. Those were never addressed to a command
line, so counting them as abstentions inflated the number with questions we were
not asked. Since the logsource pass, a candidate whose `logsource.category` is
an explicit non-process class is **set aside** rather than evaluated, and an
entry whose candidates are *all* set aside reports `NOT-APPLICABLE`. Only an
explicit foreign category disqualifies a rule; a rule with no category is still
evaluated, because we cannot show it inapplicable.

The distinction is about the event *class*, not the fields. A `process_creation`
rule keyed on `Hashes` or `Description` stays evaluable and correctly reads
indeterminate — Sysmon Event ID 1 carries those, so richer telemetry really
could resolve it.

The same argument fixes which rules get asked in the first place. Rules for a
technique are ranked by severity then title and truncated for display, because a
widely-tagged technique carries more rules than a report can show. That cap must
not reach a verdict: it would exclude a rule on nothing but its first letter, and
`NO-FIRE` / `GAP` would then mean "none of the five we looked at" while claiming
to mean "none". `SigmaIndex::candidate_rules` returns the full set and is what
verification and coverage evaluate; `rules_for` keeps the cap and is used only
where rules are rendered.

## Non-goals (predictive mode)

These bound what can be resolved from a **command line alone**. Since v1.2.0,
`--telemetry` supplies `ParentImage`, `IntegrityLevel`, `CurrentDirectory`, and
(with `--users`) `User` from a **recorded** event, so those fields resolve to
`fires` / `no-fire` in observed mode rather than reading `INDETERMINATE`. See
[telemetry-ingest.md](telemetry-ingest.md).

- Fields opseclint cannot synthesize from a command line (`ParentImage`,
  `User`, `Hashes`, registry and network fields) → these branches evaluate to
  `Unknown` and surface as `INDETERMINATE`.
- Modifiers `re`, `cidr`, `base64offset`, `windash` → **implemented**. A `re`
  pattern the `regex` crate cannot compile, and a malformed network under
  `cidr`, still evaluate to `Unknown` and name the modifier — the degradation
  is an abstention, never a `no-fire`.
- Modifiers `base64` (unused upstream today), `utf16`/`utf16le`/`wide`,
  `fieldref`, `expand`, and the numeric comparisons → treated as `Unknown`
  (documented), implemented later. Leaving the encoding modifiers unsupported
  is what keeps `base64offset` honest: an unknown token in a chain gates the
  whole field match, so a UTF-16 rule can never be answered with ASCII needles.
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

### Data model (`crates/opseclint-core/src/sigma_eval.rs`)

```rust
// Modifiers split by role: a transform rewrites the value, an op compares it.
// `contains|windash` is a transform *then* a comparison, which a single flat
// modifier set cannot express.
enum Transform { Windash, Base64Offset }
enum MatchOp { Glob, Contains, StartsWith, EndsWith, Re(Vec<Regex>), Cidr(Vec<Net>) }

struct FieldMatch {
    field: String,
    values: Vec<String>,        // as authored
    needles: Vec<Vec<String>>,  // one group per value: its transform expansion
    op: MatchOp,
    all: bool,
}
// OR within a needle group, OR across groups — unless `all`, then AND across
// groups. Keeping the grouping is what makes `all|windash` mean "every
// authored flag, in any dash form" rather than "every variant of every flag".

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

`sigma_eval::parse_documents` splits a rule file — which may hold several
`---`-separated documents — and reduces each to an owned `RuleDoc`: `id`,
`title`, `level`, `logsource.category`, `tags`, and the parsed `DetectionRule`.
YAML types stop at that boundary, so `sigma.rs` builds its index without naming
a YAML crate. Parsed `DetectionRule`s live in `SigmaIndex` and the on-disk cache
(bump the cache fingerprint/version so stale caches rebuild).

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
