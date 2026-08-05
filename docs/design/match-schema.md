# Reference: the `match` schema

**Status:** current
**Scope:** how a knowledge-base entry decides whether it applies to a line.

Every entry in `crates/opseclint-core/data/knowledge*.json` carries a required `match` object — a small
structured predicate over a parsed command and its raw line, or over a recorded
non-execution event. It replaced the old
`command` / `args_contains` / `raw_contains` substring fields. The engine lives
in [`crates/opseclint-core/src/matcher.rs`](../../crates/opseclint-core/src/matcher.rs).

`match` describes **detectability** only ("what would a defender see?"). It never
encodes evasion.

## The axes

A matcher has four optional parts — three over a command, one over an event:

| Key | Matches against | Meaning |
|-----|-----------------|---------|
| `program` | the resolved program basename | who ran (wrappers like `sudo`/`env` are stripped first, `certutil.exe` → `certutil`) |
| `args`    | the argument vector | a predicate tree over the args |
| `line`    | the whole raw line | markers that span tokens (redirects, pipes, socket paths) |
| `event`   | a non-execution record's fields | a network / file / registry event, with no command line involved |

- If `program` is present, the entry is **command-scoped**: some command on the
  line must satisfy `program` (and `args` / `line` if given).
- If `program` is absent, the entry is **line-scoped**: the raw line must
  satisfy `line`.
- `event` is **orthogonal** to all three. It is never consulted for a command
  line, and the command axes are never consulted for an event. An entry may
  carry both, and most should: that is how one entry recognizes its action
  whether it arrives as a command or as a standalone sensor event.

All matching is case-insensitive.

## `program`

```jsonc
"program": "curl"                     // exact basename
"program": { "any": ["nc", "ncat"] }  // any of these
```

## `args` — a predicate tree over the argument vector

Leaf predicates are **existential over the arguments** ("some argument satisfies
this"). The combinators compose predicates, not arguments.

Combinators: `all`, `any`, `not`.

Leaves:

| Leaf | True when some argument… | Example |
|------|--------------------------|---------|
| `flag` | equals this token exactly | `{ "flag": "-e" }` |
| `eq` | equals this string | `{ "eq": "/bin/sh" }` |
| `contains` | contains this substring | `{ "contains": "urlcache" }` |
| `prefix` / `suffix` | starts / ends with this | `{ "prefix": "if=/dev/" }` |
| `word` | contains this token on word boundaries | `{ "word": "id_rsa" }` |
| `path_under` | is a path equal to / nested under this dir (segment-aware) | `{ "path_under": "/var/log" }` |
| `at` | the argument at a fixed index satisfies a leaf | `{ "at": { "index": 0, "value": { "prefix": "if=/dev/" } } }` |
| `joined` | a leaf holds against all args joined by spaces (for a phrase spanning tokens) | `{ "joined": { "contains": "process call create" } }` |
| `regex` | matches this regular expression | `{ "regex": "^if=/dev/sd[a-z]$" }` |

## `line` — a predicate over the raw line

Combinators `all` / `any` / `not`, and the leaves `contains`, `word`, `prefix`,
`suffix`, `regex`.

## `event` — a predicate over a non-execution record

Some telemetry has no command line: a registry Run key set by a GUI, a file
written by a service, a connection whose causing process was never captured.
`--telemetry` reduces those to standalone events, and the `event` axis is what
recognizes them. See
[`telemetry-ingest.md`](telemetry-ingest.md) for how each sensor produces them.

An `event` predicate names the record's `class` and then tests its fields:

| Key | Meaning |
|-----|---------|
| `class` | `network`, `file`, or `registry`. Required; an unrecognized value is a load error. |
| `field` | the record field to test, e.g. `TargetObject`. Matched case-insensitively. |

Combinators `all` / `any` / `not` compose predicates as they do on the other
axes, and each leaf names the field it tests, so one entry can require several
fields at once:

| Leaf | True when the field… |
|------|----------------------|
| `eq` | equals this string |
| `contains` | contains this substring |
| `prefix` / `suffix` | starts / ends with this |
| `word` | contains this token on word boundaries |
| `path_under` | is a path equal to / nested under this dir (segment-aware) |
| `regex` | matches this regular expression |

```jsonc
// one field — the whole predicate hoisted to the top
"event": { "class": "registry", "field": "TargetObject", "contains": "\\CurrentVersion\\Run" }

// several fields, ANDed: the address *and* the port
"event": { "class": "network", "all": [
  { "field": "DestinationIp",   "eq": "169.254.169.254" },
  { "field": "DestinationPort", "eq": "80" } ] }
```

Fields are keyed by their canonical Sysmon names on every platform —
`DestinationIp`, `DestinationPort`, `TargetFilename`, `TargetObject` — so an
entry is written once rather than once per sensor vocabulary. auditd `SOCKADDR`
and `PATH` records and macOS ESF `NOTIFY_OPEN` / `NOTIFY_CREATE` /
`NOTIFY_CONNECT` all reduce into the same names.

Prefer the boundary-aware leaves here for the same reason as on the command
axes — event fields are usually paths, where a bare `contains` over-matches most.

## `regex` and the `example` field

Reach for `regex` only when the fixed leaves can't express the shape — an
abbreviation family, an alternation of shells, a structured token. Patterns are
**compiled at knowledge-base load** (an invalid pattern is a load error, not a
silent no-match) and matched **case-insensitively**, like the other leaves.

Because a pattern can't be reversed into a concrete command, **any entry whose
`match` uses a `regex` leaf must also carry a top-level `example`** — a
representative command line the entry should match. It drives the
self-consistency guard, the `--verify-detections` synthetic event, and the
`--scaffold` output; load-time validation rejects a regex entry that lacks one.
(`example` is also accepted on non-regex entries, where it overrides the
literal-derived representative.)

```jsonc
{
  "id": "powershell-hidden",
  "match": { "line": { "all": [
    { "any": [{ "contains": "powershell" }, { "contains": "pwsh" }] },
    { "regex": "-w(?:indowstyle|indowsty|indow|ind|in|i)?\\s+(?:hidden|1)\\b" }
  ] } },
  "example": "powershell -w hidden -enc ZQBjAGgAbwA=",
  "…": "…"
}
```

`--scaffold` lowers a `regex` leaf to a Sigma `CommandLine|re:` selection.

## Why `word` and `path_under` exist

Plain `contains` over-matches. These segment/boundary-aware leaves are how the
knowledge bases avoid false positives:

- `path_under: "/var/log"` matches `rm -rf /var/log/nginx` and `rm -rf /var/log`,
  but **not** `rm -rf /var/logistics` (a substring `contains` would).
- `word: "id_rsa"` matches `cp ~/.ssh/id_rsa …`, but **not**
  `vim id_rsa_backup_notes.txt`.

## Worked examples

```jsonc
// program only
{ "match": { "program": "curl" } }

// program + path-aware arg (kills the /var/log substring FP)
{ "match": { "program": "rm", "args": { "path_under": "/var/log" } } }

// any-of program + flag + alternation (nc/ncat reverse shell)
{ "match": { "program": { "any": ["nc", "ncat"] },
             "args": { "all": [ { "flag": "-e" },
                                { "any": [ { "eq": "/bin/sh" }, { "eq": "/bin/bash" } ] } ] } } }

// multi-word argument phrase spanning tokens
{ "match": { "program": "wmic", "args": { "joined": { "contains": "process call create" } } } }

// raw line, word-boundary aware, excluding the public key
{ "match": { "line": { "all": [ { "word": "id_rsa" },
                                { "not": { "contains": "id_rsa.pub" } } ] } } }

// raw substring (marker spans tokens)
{ "match": { "line": { "contains": "/dev/tcp" } } }

// one action, recognized as a command *or* as a standalone file event
{ "match": { "line": { "contains": "ld.so.preload" },
             "event": { "class": "file", "field": "TargetFilename",
                        "eq": "/etc/ld.so.preload" } } }

// several event fields at once (the link-local metadata endpoint)
{ "match": { "line": { "contains": "169.254.169.254" },
             "event": { "class": "network", "all": [
               { "field": "DestinationIp",   "eq": "169.254.169.254" },
               { "field": "DestinationPort", "eq": "80" } ] } } }
```

## Self-consistency invariant

A test (`every_entry_matches_its_own_representative` in `crates/opseclint-core/src/analyzer.rs`)
derives a representative command from each entry — its `example` if present, else
one built from the `match` literals — and asserts the entry fires on it. If you
write a matcher whose own representative can't match it, that test fails — which
is the usual sign of a typo (e.g. a per-arg `contains` for a phrase that should
be `joined`, or a `regex` whose `example` doesn't actually satisfy the pattern).

Each axis is checked on its own terms, and an entry carrying both must satisfy
both — they are different claims about the same action, and neither implies the
other. For an `event` axis the representative is a synthetic *record*: a class
and a field map built from the predicate's literals, run through the same
standalone-matching path real telemetry takes. Where several leaves constrain one
field they are composed into a single value rather than overwriting each other,
so `contains "/LaunchAgents/"` plus `suffix ".plist"` yields a value satisfying
both.

`example` has no event counterpart, because a command line cannot stand in for a
record. Instead the representative must be derivable from the predicate itself:
an `event` axis that is a bare `regex`, or purely negated, has nothing positive
to build from and is **rejected at load**. Pair the pattern with a literal leaf.
