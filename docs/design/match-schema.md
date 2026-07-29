# Reference: the `match` schema

**Status:** current
**Scope:** how a knowledge-base entry decides whether it applies to a line.

Every entry in `data/knowledge*.json` carries a required `match` object — a small
structured predicate over a parsed command and its raw line. It replaced the old
`command` / `args_contains` / `raw_contains` substring fields. The engine lives
in [`src/matcher.rs`](../../src/matcher.rs).

`match` describes **detectability** only ("what would a defender see?"). It never
encodes evasion.

## The three axes

A matcher has three optional parts:

| Key | Matches against | Meaning |
|-----|-----------------|---------|
| `program` | the resolved program basename | who ran (wrappers like `sudo`/`env` are stripped first, `certutil.exe` → `certutil`) |
| `args`    | the argument vector | a predicate tree over the args |
| `line`    | the whole raw line | markers that span tokens (redirects, pipes, socket paths) |

- If `program` is present, the entry is **command-scoped**: some command on the
  line must satisfy `program` (and `args` / `line` if given).
- If `program` is absent, the entry is **line-scoped**: the raw line must
  satisfy `line`.

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

## `line` — a predicate over the raw line

Combinators `all` / `any` / `not`, and the leaves `contains`, `word`, `prefix`,
`suffix`.

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
```

## Self-consistency invariant

A test (`every_entry_matches_its_own_representative` in `src/analyzer.rs`)
derives an example command from each entry's `match` and asserts the entry fires
on it. If you write a matcher whose own example can't match it, that test fails —
which is the usual sign of a typo (e.g. a per-arg `contains` for a phrase that
should be `joined`).
