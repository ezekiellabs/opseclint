# Changelog

All notable changes to opseclint are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **No knowledge-base entry, on any platform, claims a Sigma rule that no rule
  can satisfy.** Windows reached that state in v1.4.0; Linux and macOS carried
  40 refuted claims between them, and both are now at zero — 23 / 23 / 21
  verified against the ruleset pinned in `.ci/sigma-ref`. CI enforces it
  absolutely rather than relatively: alongside the baseline comparison, a
  second baseline-free `--verify-detections --ci` run per platform fails if
  *any* claim is unverified. The relative check compares against a committed
  file, so regenerating that file could otherwise launder a refuted claim into
  the baseline; the absolute one is the term that survives a rewrite.
- **The macOS knowledge base: 28 refuted claims adjudicated, 14 verified (7 →
  21), 14 withdrawn.** Twelve were artifacts of the probe and now carry the
  canonical operator form of the action — `arp -a`, `crontab /tmp/.cache.cron`,
  `dscl . -list /Groups`, `dscl . -create /Users/svc IsHidden 1`,
  `security dump-keychain -d`, `sw_vers -productVersion`, `system_profiler
  SPHardwareDataType`, `xattr -d com.apple.quarantine`, the two `osascript -e`
  forms, and a PlistBuddy `RunAtLoad` write for each of the LaunchAgent and
  LaunchDaemon entries. `emond-persist` needed no example: like
  `sudoers-tamper` on Linux, its `event` axis alternates over two directories
  and the representative record is derived from the *first*, so the branches
  are swapped to probe `/private/var/db/emondClients`, which SigmaHQ's rule
  watches. `curl` keeps its claim but stops overstating it — only the
  download-piped-to-`osacompile` chain reaches a rule, and the claim now says
  which and admits plain `curl` is uncovered.
- **A rule keyed on an absolute `Image:` path cannot be verified predictively,
  and four macOS claims are withdrawn because of it.** `Image` is synthesized
  from the program basename, so `Image: '/usr/sbin/screencapture'` compares
  against `/screencapture` and resolves to a definite *false* — which is why
  those entries read `UNVERIFIED` rather than `INDETERMINATE`. No example can
  move them: `screencapture`, `mdfind`, `spctl-status` and
  `gatekeeper-disable`. This is opseclint's ceiling, not a knowledge-base
  defect, and it is recorded as such rather than papered over.
- **Ten further macOS claims are withdrawn** because the ruleset genuinely
  carries nothing for the action: `base64-decode`, `keychain-find`,
  `periodic-persist`, `tar-archive`, `ditto-archive`, `python-http-server`,
  `scp-exfil`, `reverse-shell-devtcp` (T1059.004 has no macOS rule at all),
  `clipboard-capture` (SigmaHQ's `pbpaste` rule lives under
  `rules-threat-hunting/`, which the gate does not index), and `netcat`. The
  last is worth naming: *MacOS Network Service Scanning* would fire, but it is
  tagged T1046, and asserting that of a bare `nc` invocation is false — its
  filter is also the single letter `l`, so a hostname like `scanner.local`
  suppresses it. Reaching it would mean building a command line around a rule
  quirk instead of describing the action.

- **No Linux knowledge-base entry claims a Sigma rule that no rule can
  satisfy.** The twelve remaining `UNVERIFIED` claims were adjudicated one at a
  time against the ruleset pinned in `.ci/sigma-ref`; eight now verify (15 →
  23) and four were withdrawn. Five were artifacts of the probe rather than of
  the claim, the same shape the Windows pass found: `--verify-detections`
  evaluates an entry's representative line, derived from the matcher's own
  literals when no `example` is authored, so `arp`, `base64`, `scp`, `wget` and
  `python3 -c` were each put to a real rule as a bare program name with none of
  the arguments the rule keys on — a definite *false*, read as contradicted
  rather than untested. Each now carries a realistic operator command.
  `python-c` also says what it covers: only the base64-decoding form reaches a
  rule, so the claim names it and stops implying every `-c` invocation is
  caught.
- **`sudoers-tamper` verifies without changing what it matches.** Its `event`
  axis alternates over `/etc/sudoers` and the `/etc/sudoers.d` drop-in
  directory, and a representative record is derived from the *first* branch —
  so the probe was the file, while SigmaHQ's *Persistence Via Sudoers.d Files*
  watches the directory. The two branches are swapped. Matching is unchanged in
  both directions; only the record the entry is checked with moves, which is
  the whole difference between a claim that can be tested and one that cannot.
- **`login-discovery` named the wrong technique, not a missing rule.** It
  claimed a T1087.001 rule for `last`, and SigmaHQ's local-account rule covers
  `/lastlog` — a different binary reading a different file. The rule that does
  cover `/last` is *System Network Connections Discovery - Linux*, under T1049.
  That technique is true of the action independent of the rule — `last` reads
  wtmp, which records the remote origin of each login — so it is added
  alongside T1087.001 rather than replacing it, the same bar `av-discovery` and
  `winlogon-persist` were held to. Account enumeration is still what the entry
  is for.
- **`bash-history-tamper` now models the form the ruleset can actually see.**
  Its only candidate is a keyword rule, and opseclint matches Sigma keywords
  literally, so every wildcard-bearing keyword in it — `rm *sh_history`,
  `shred *sh_history`, `cat /dev/null >*sh_history` — is unreachable. None of
  the keywords that *are* reachable mention `.bash_history`, so no single
  command could satisfy both the entry's matcher and the rule. The matcher is
  widened to the shell-builtin forms (`history -c`, `history -w`,
  `export HISTFILESIZE=0`, `shopt -ou history`), which is a coverage gain in its
  own right: clearing history through the builtin is the common case and was
  unmodeled. The wildcard limitation is opseclint's, and remains.
- **Four Linux claims are withdrawn**, because the pinned ruleset carries
  nothing that can fire on the action and inventing a command to reach one
  would be worse than claiming nothing. `crontab-l` — the T1053.003 process
  rule requires `/tmp/`, which describes installing a job rather than listing
  one with `-l`, and the remaining rule is a `service: cron` keyword rule over a
  cron *daemon log line*. `ss` — the single T1049 rule enumerates `/who`, `/w`,
  `/last`, `/lsof` and `/netstat`; SigmaHQ covers the deprecated tool and not
  its replacement. `python-http-server` — T1105's rules are keyed on `/curl`,
  `/wget` and scp keywords, T1567's are network, DNS and proxy rules.
  `usermod-group` — T1098 carries an `/esxcli` rule and a keyword rule over
  auth.log prose. Each keeps its matcher, techniques, telemetry and score, and
  now surfaces under `--coverage-gaps` and `--scaffold` instead. A
  `withdrawn_*_sigma_claims_stay_withdrawn` table per platform records the
  reason and fails if a claim reappears; `ifeo-debugger`'s existing guard folds
  into the Windows table.
- `netstat` verified all along, against *System Network Connections Discovery -
  Linux* — but its claim named a rule title that does not exist. Corrected in
  passing: a claim that names no real rule is the same defect whether or not
  the entry happens to verify.

### Added

- **Nineteen more entries recognize their action as a standalone sensor event.**
  v1.4.0 built the whole non-execution path — ingest on all three formats,
  standalone matching, verification against a derived record, per-log-source
  scaffolding — and wired 13 of 233 entries to it, so in practice a file or
  registry record with no command line matched almost nothing. Entries whose
  `telemetry` already named a concrete record now carry the `event` axis that
  says so: SSH private keys and `authorized_keys`, the Kubernetes
  service-account token, `/etc/rc.local`, systemd `.timer` units, `~/.bashrc`,
  the Docker socket, `/proc/1/root`, the `at` spool, `/sys/fs/selinux/enforce`,
  macOS browser credential stores, `/etc/periodic`, cron tabs, and the RDP and
  fodhelper registry values on Windows. On six auditd `PATH` records carrying no
  command line at all, the same input went from **0 findings to 6**.

  Chosen for whether the record *identifies the action on its own*: a write to
  `/etc/rc.local` does, an outbound connection on tcp/22 does not, so `scp` and
  `ssh` keep to the command axis rather than each claiming every SSH session in
  a capture. The leaves are boundary-aware for the same reason — `suffix:
  "/id_rsa"` carries the exclusion the command axis spells out with a `not`,
  since a path ending in `id_rsa.pub` cannot end in `/id_rsa`, and a test pins
  it.

  No verdict moves and no claim is added. One measurable change: ten registry
  rules that `uac-bypass-fodhelper` had been setting aside as a class it did not
  model are now genuinely evaluated against its record (`inapplicable_rules` 26
  → 16). Each of these entries also scaffolds its second rule now, under the
  class's own logsource.

### Fixed

- **The detection-verification gate could not see a claim that was never
  substantiated.** `--verify-detections --diff --ci` compared a run against its
  committed baseline and failed only when an entry that read `VERIFIED` stopped
  reading so. A claim *added* by a change has no baseline row at all, so the
  lookup missed it and it merged silently; `NO-RULE → UNVERIFIED` and
  `INDETERMINATE → UNVERIFIED` were equally invisible, because neither side was
  ever `VERIFIED`. The gate now compares verdicts by rank, so any worsening
  counts, and reports a claim with no baseline row as its own class — listed
  whatever its status, because a new entry means the committed baseline is
  stale, but failing the build only when the ruleset refutes it. A count
  ratchet backs both, matching the shape `--coverage-gaps` already uses.
  Deleting a refuted claim stays the one way out that the gate does not punish:
  withdrawing a detection no rule substantiates is the remedy for an
  `UNVERIFIED` entry, so a vanished entry is still a regression only when it
  was `VERIFIED`. `UNVERIFIED → NO-RULE` is deliberately *not* reported as an
  improvement either — re-pointing an entry at a technique nothing covers
  lowers the count without proving anything, and labelling that `VERIFIED`
  would be a lie. The scheduled `sigma drift` workflow is unaffected: it varies
  the ruleset and not the knowledge base, so both sides always share an id set
  and the new class is always empty there.

## [1.4.0] - 2026-08-17

### Added

- **The detection-verification gate runs against a pinned SigmaHQ revision.**
  CI cloned upstream `main`, then failed the build if a claim that was
  `VERIFIED` in `.ci/verified-<platform>.json` had stopped firing. Both halves
  of that comparison were free to move, so the gate was not reproducible: a
  past run could not be re-created, and an unrelated pull request could go red
  because SigmaHQ merged a rule overnight. The revision is now named in
  `.ci/sigma-ref` and checked out exactly, and each baseline records the
  revision it was computed from in a new `sigma_ref` field, set by
  `--sigma-ref`. That field is deliberately not inferred from the checkout —
  `--sigma` may point at any directory, and a guessed provenance committed into
  a baseline is worse than none — and it is omitted rather than written as
  `null` when no ref is given, so "unknown" and "recorded" never look alike.
  Older baselines without the field still load, and `--diff` still compares
  `status` by `id`: a ruleset mismatch is reported as a note, never a failure,
  because comparing a pinned baseline against a different ruleset is precisely
  what the drift check below does on purpose. `scripts/sync-sigma.sh` moves the
  pin and all three baselines together and refuses to let them drift apart —
  `--check` is an offline string comparison, so it is cheap enough to require
  on every pull request, the same trade `sync-packaging.sh` already makes.
  Pinning changed no verdict: linux, windows and macos read 15 / 23 / 7
  verified against `3c0d3518`, exactly as before, over the same 251 / 2220 /
  124 rules.
- **A scheduled `sigma drift` workflow watches upstream.** Pinning buys
  reproducibility at the cost of hiding that the pin has gone stale, so the
  same three comparisons run weekly against SigmaHQ `main`, off the
  pull-request path entirely. A red run there means the pin needs review, not
  that someone's change broke something — which is the one thing the old
  arrangement could never say.
- **`--verify-detections` can verify a `file_event` / `registry_set` claim.** A
  candidate rule whose logsource is not process-execution was set aside
  unevaluated, and an entry whose candidates were *all* set aside reported
  `NOT-APPLICABLE` — the claim was never tested, and no amount of ruleset
  improvement could move it, because the rule was never asked. That was correct
  when the only synthetic event was a command line. It is not any more: an entry
  carrying an `event` axis derives a representative *record* too, so a rule put
  to an entry that models the same class of record is now evaluated against it.
  Four claims that were permanently unverifiable are now tested —
  `sudoers-tamper`, `emond-persist`, `ifeo-debugger`, `winlogon-persist` — and
  `cron-persist` verifies against SigmaHQ's *New Cron File Created*. The
  original hazard stays shut: the gate is the rule's category matching the
  entry's own event class, so a `registry_set` rule is never answered with a
  file record, and an entry with no `event` axis is classified exactly as
  before. Event rules are evaluated against the record alone, with no command
  line synthesized underneath it, so a file rule keying on `CommandLine`
  abstains rather than firing on evidence from another log source — the cost
  being that a rule keyed on the writing process reads `INDETERMINATE` on
  `Image`, the same honest abstention `ParentImage` produces on the process
  side. One firing rule verifies an entry whichever log source it asked about:
  the claim is that a real rule catches the action, not that every record the
  entry models is separately covered.
- A `path_under` event leaf derives a file *inside* the directory as its
  representative, not the directory itself. Both satisfy the leaf, so the
  self-consistency guard passed either way — but `--verify-detections` puts that
  same record to real Sigma rules, and a rule watching a drop-in directory keys
  on `startswith '/etc/cron.d/'`, which `/etc/cron.d` does not satisfy. A
  representative has to stand for the action to a third party, not only to
  opseclint's own matcher; deriving the bare base made every `path_under` entry
  read as contradicted the moment its rule was actually asked.

- **Non-execution telemetry on Linux and macOS.** `--telemetry` reads auditd
  `SOCKADDR` and `PATH` records, and macOS ESF `NOTIFY_OPEN` / `NOTIFY_CREATE` /
  `NOTIFY_WRITE` / `NOTIFY_CONNECT`, as network and file events. Each is
  correlated by process id to the execution that caused it and shown as a
  confirmed `◉ observed:` line,
  or — with no captured causing execution — matched standalone against the
  knowledge base's `event` axis. Previously only Sysmon produced these, so on
  the other two platforms the `event` axis had nothing to match against at all.
- **`--scaffold` lowers the `event` axis.** An action modeled on both a command
  and a sensor record now scaffolds two Sigma rules — the `process_creation` one
  it always did, plus one under the event class's own logsource
  (`network_connection` / `file_event` / `registry_set`) — and an entry
  recognized only by an event scaffolds just the second, instead of an empty
  `selection:` under the wrong log source. Previously the logsource was
  hardcoded, so `cloud-imds` scaffolded a `process_creation` rule keyed on a
  command-line substring while the `DestinationIp` / `DestinationPort` pair the
  knowledge base already held went unmentioned. Sigma's own map semantics carry
  most of the lowering: leaves ANDed by an `all` become keys in one selection,
  and an `any` whose branches share a field and a modifier becomes one key with
  a value sequence, so `winlogon-persist`'s nested alternation stays a single
  idiomatic selection. Only an alternation spanning different keys needs sibling
  selections and a composed `condition`. `word` and `path_under` have no Sigma
  equivalent and stand in as `|contains` and `|startswith` — broader than
  opseclint's own match, never narrower — and say so in a `# NOTE:`.
- **The `event` axis is a predicate tree.** `all` / `any` / `not` over per-field
  leaves (`contains`, `eq`, `prefix`, `suffix`, `word`, `path_under`, `regex`),
  reaching parity with the `args` and `line` axes. An entry can now require
  several fields at once — a destination address *and* a port — which the
  previous one-field shape could not express. The single-field form is the
  degenerate case of the same grammar, so existing entries are unchanged.
- **Event-scoped knowledge-base coverage for Linux and macOS.** `shadow-read`,
  `cron-persist`, `ld-preload`, `authorized-keys` and `cloud-imds` on Linux;
  `launch-agent-persist`, `launch-daemon-persist` and `tcc-tamper` on macOS.
  Each carries an `event` axis alongside its command axis, so one entry
  recognizes its action whether it arrives as a command or as a sensor event.
- Sigma modifiers `windash`, `re`, `base64offset` and `cidr` are now evaluated
  rather than abstained on. `windash` and `base64offset` expand a value into
  candidate needles; `re` and `cidr` replace the default comparison.
- Three Windows knowledge-base claims that previously read `INDETERMINATE` are
  now verified against the live SigmaHQ ruleset: `findstr-creds`,
  `gpp-cpassword` and `ipconfig`.
- **No Windows knowledge-base entry claims a Sigma rule that no rule can
  satisfy.** The last ten `UNVERIFIED` claims were adjudicated one at a time;
  nine now verify (13 → 22) and the tenth was withdrawn. Seven were probe
  artifacts: `--verify-detections` evaluates an entry's representative line,
  which is derived from the matcher's own literals when no `example` is
  authored, and `attrib +h` or `shadowcopy delete` carries no program — so an
  `Image|endswith` test resolves to a definite *false* and the claim reads
  contradicted rather than untested. `accessibility-sethc`, `attrib-hidden`,
  `bcdedit-recovery`, `regsvr32-squiblydoo`, `run-key-persist`,
  `wbadmin-delete` and `wmic-shadow-delete` now carry a realistic `example`.
  Two more claims became `UNVERIFIED` afterwards — not a regression, but the
  first time they were testable at all (see the `--verify-detections` entry
  above) — and both have since been adjudicated the same way; `unverified` on
  Windows now reads 0 against the SigmaHQ revision pinned in `.ci/sigma-ref`,
  which CI checks out and enforces.
- **`winlogon-persist` verifies.** It claimed a `registry_set` rule for the
  Winlogon `Shell` / `Userinit` values, and the T1547.004 registry rule covers
  `Winlogon\Notify\logon` with a `.dll` payload instead. But the entry is also a
  registry *modification*, which it did not say: with `T1112` listed and a
  realistic `reg.exe add` `example` authored, SigmaHQ's *Reg Add Suspicious
  Paths* fires on it, and the claim now names the `proc_creation` rule that
  really answers (22 → 23 verified). The technique was added because it is true
  of the action, the same bar `cmdkey-creds` and `av-discovery` were held to —
  not because it reached a rule. `T1547.001` would also have reached one, and
  was rejected: MITRE assigns `Winlogon\Shell` and `Userinit` to T1547.004
  explicitly, so listing it would have put a false technique into the report,
  the `--navigator` layer and the MCP technique lookup.

### Changed

- **YAML parsing moved off the archived `serde_yaml`** (which resolved to
  `0.9.34+deprecated`) and onto the maintained `serde_norway` fork of that same
  release. The parsing path is identical, so no rule parses differently than it
  did before: `rules_indexed` holds at 251 (linux), 2220 (windows) and 124
  (macos) against the live SigmaHQ ruleset, with every `--verify-detections`
  verdict unchanged. `--sigma` and `--check-rule` are back on a dependency that
  still receives fixes.
- **YAML types are confined to `sigma_eval`.** `sigma.rs` used to navigate a raw
  YAML value to pull a rule's metadata out; it now consumes an owned `RuleDoc`
  per document from `sigma_eval::parse_documents` and names no YAML type. A
  future parser change is a one-file change.
- The Sigma fixture tests assert exact rule counts instead of a `>= 2` floor. A
  parser that silently skipped documents — the failure mode a YAML migration
  actually has, since an unreadable document is skipped rather than reported —
  would have shrunk the ruleset without failing anything.
- A field match is cached as its source key plus raw values and re-lowered on
  load, so nothing derived is persisted. Stale caches are invalidated
  automatically.
- An `event` axis is now held to the same self-consistency invariant as the
  command axes: a representative record derived from the predicate's own
  literals must fire the entry. An `event` predicate with nothing positive to
  derive from — a bare `regex`, or pure negation — is rejected at load, as is an
  unrecognized `class`. Event field names are matched case-insensitively, which
  values already were.
- **Four Windows detection claims were wrong rather than untested.**
  `av-discovery` and `cmdkey-creds` are covered by real rules that SigmaHQ tags
  under a technique the entries did not carry — `Potential Product Class
  Reconnaissance Via Wmic.EXE` under T1047, `Potential Reconnaissance For Cached
  Credentials Via Cmdkey.EXE` under T1003.005 — so the rule was never a
  candidate. Both techniques are now listed, and `av-discovery`, which named a
  security-software-discovery rule SigmaHQ does not carry for this action, now
  names the wmic reconnaissance rule that does answer it.
  `wbadmin-delete` claimed backup deletion at `high` confidence,
  but every wbadmin rule requires `backup` in the command line, so the
  catalog-only form it also matches fires nothing: the claim now says so and
  reads `medium`. `netstat` claimed a network-connection-discovery rule that
  does not exist — SigmaHQ has no `netstat.exe` process-creation rule under
  T1049 — and the claim is withdrawn. An entry with no `detections` is now a
  deliberate statement that nothing covers the action, reported by
  `--coverage-gaps` and scaffoldable with `--scaffold`; claiming a detection
  that does not exist is worse than claiming none.
- **`ifeo-debugger`'s claim is withdrawn.** It named a `registry_set` rule for
  the IFEO `Debugger` value, and SigmaHQ tags no rule for that value under
  T1546.012: the two rules that carry the technique cover `GlobalFlag` and
  `SilentProcessExit`, and no `process_creation` rule carries it at all, so no
  `example` could reach one. The rules that do fire on a `Debugger` write are
  accessibility-scoped under T1546.008 — the coverage `accessibility-sethc`
  already claims and verifies, which this entry does not lose.
  What remains is a real blind spot rather than a probe artifact, so the entry
  keeps its matcher, techniques and telemetry and drops only the claim.
  One rule does cover the action — *CurrentVersion NT Autorun Keys
  Modification* lists `\Image File Execution Options` — but it is tagged
  T1547.001, which MITRE assigns to Run keys and the Startup folder, and
  SigmaHQ's own rule body points at the GlobalFlags rule for IFEO. Re-tagging
  the entry to reach it would have been a false mapping, and it would have
  bought nothing: that rule's `filter_main_null` asserts `Details: null`, which
  gates to `Unknown` before the record is read, so `not 1 of filter_main_*` is
  never definitely true and the rule cannot fire on any record. A test now pins
  both halves — the abstention, and the withdrawal, which the baseline diff
  cannot catch on its own because it only flags a `VERIFIED` entry losing its
  status.
- `docs/design/match-schema.md` documents the `event` axis, which it had never
  mentioned despite being the canonical `match` reference, and
  `docs/design/telemetry-ingest.md` no longer contradicts itself about whether
  non-execution classes are in scope.

### Notes

- The degradation contract is unchanged and now covers the new modifiers: an
  `re` pattern that will not compile, or a malformed network under `cidr`,
  evaluates to `INDETERMINATE` and names the modifier. It never evaluates to
  `no-fire` — an evaluator that cannot read a rule has not shown the rule would
  not fire.
- `base64`, `utf16`/`utf16le`/`wide`, `fieldref` and `expand` remain
  unsupported on purpose. An unrecognized token anywhere in a modifier chain
  still gates the whole field match, which is what stops a UTF-16 rule being
  answered with ASCII needles.

## [1.3.0] - 2026-08-04

### Added

- **`opseclint-mcp`: the knowledge base as an MCP server.** A third crate,
  producing a second binary that speaks [MCP](https://modelcontextprotocol.io)
  over stdio on top of `opseclint-core`. Four tools: `analyze_command`,
  `lookup_technique`, `evaluate_sigma_rule`, and `describe_coverage`.

  Agents are being pointed at security work right now with no ground truth —
  they hallucinate detections and confidently misjudge what is observable. This
  puts a real knowledge base and a real evaluator behind the question.

  **The interesting part is not the plumbing, it is the result shape.** Agents
  amplify whatever they are given, which turns opseclint's abstain-honestly
  property from a nice trait into a load-bearing one: an `INDETERMINATE` that an
  agent silently rounds to "not detected" manufactures evidence of stealth out
  of an honest abstention, and is worse than no answer at all. So the results
  are designed against that specifically. No field in any result is a boolean
  about whether something was detected — the verdict is a three-variant enum,
  and the one boolean nearby (`verdict_is_conclusive`) is about the verdict's
  *standing*, with `false` as its unsafe-to-ignore value. Every result carries a
  prose `summary` first in declaration order, so it leads the JSON a client
  renders as text, and a `limits` list naming what the answer does not
  establish. An empty result says "no *modeled* action matched" and points at
  `describe_coverage`, which exists so that "nothing matched" is always
  distinguishable from "not modeled". The contract is also delivered in the
  server's `instructions`, which reach the client before any tool is called.

  None of this can make an agent reason well. What it does is make the
  uncertainty impossible to drop *silently*: reporting certainty here requires
  having discarded a field that said otherwise in plain words. The tests under
  "the uncertainty contract" in `server.rs` hold the property, including the
  converse — that a real `no_fire` stays conclusive, since a server that
  abstained on everything would be equally useless.

  The server makes no network calls and reads no files. `evaluate_sigma_rule`
  takes rule text inline rather than a directory path: an MCP server takes
  instructions from a model, and the safest one has nothing to reach for.

  Built on `rmcp` 3.1, the official Rust MCP SDK. Release archives carry both
  binaries, and every package manifest installs both: `brew install`,
  `scoop install`, the AUR package, and `winget install` all put `opseclint-mcp`
  on your path alongside `opseclint`. It is also on crates.io —
  `cargo install opseclint-mcp`.

- **`opseclint-core`: the knowledge base and evaluator, as a library.** The repo
  becomes a Cargo workspace — three crates by the end of this release, counting
  `opseclint-mcp` above. `crates/opseclint-core` holds everything that computes
  — the platform knowledge bases, the `match` engine, the parser, the analyzer,
  the Sigma evaluator, telemetry ingest, and the EDR mapping — and
  `crates/opseclint` is the CLI over it: argument parsing, the rendered report,
  and the knowledge-base tooling (`--scaffold`, `--verify-detections`,
  `--coverage-gaps`).

  The point is that the binary is now core's *first consumer* rather than its
  owner. Until now the knowledge base was reachable only by running the CLI and
  parsing its output, which meant the second tool built on this data would have
  had to fork it — and two copies of a knowledge base is how a toolkit dies.

  No behavior changes: same output, same flags, same 164 tests. The library
  carries the same commitment the CLI ships under, and one of them matters more
  through an API than through a report a human reads — `sigma_eval` is
  three-valued, and `INDETERMINATE` is a verdict, not a soft no. A consumer that
  rounds it to "not detected" converts a careful abstention into a false claim
  of stealth.

  For consumers: `cargo add opseclint-core`. `clap::ValueEnum` on `Platform`,
  `telemetry::Format`, and `edr::Vendor` now sits behind an off-by-default
  `clap` feature, so a library user does not inherit an argument parser;
  `Severity::color()` moved to the binary, where terminal palettes belong.

  The public surface was narrowed before publishing rather than after, since
  every name in it becomes a semver commitment the moment 1.3.0 ships.
  `parser::preprocess`, `parser::Unit`, `parser::command_substitutions`, and
  `sigma_eval::parse_rule_value` are now `pub(crate)` — implementation details
  of `analyzer::analyze` and the rule parser, not entry points. The last of
  those also takes `serde_yaml::Value` out of the public API, which matters
  because serde_yaml 0.9 is deprecated and would otherwise have been a
  breaking-change liability in a signature we had promised to keep.

  `opseclint-core` is `#![warn(missing_docs)]` and CI builds docs with
  `-D warnings`. Every public item — 63 items and 84 fields — carries
  documentation. That is worth the effort in a knowledge-base crate
  specifically: a field named `noise` or a variant named `Indeterminate` means
  something precise, and a consumer who guesses gets a plausible wrong answer
  instead of a compile error.

### Changed

- **`kb::load` returns `KbError` instead of `serde_json::Error`.** The old
  signature routed semantic validation failures through
  `serde_json::Error::custom`, so a caller could not tell "this JSON is not a
  knowledge base" from "this knowledge base is malformed" — the two are
  different problems with different fixes. `KbError::Parse` and
  `KbError::Invalid` separate them, and it implements `std::error::Error` with
  `source()`, so it composes with `anyhow`, `thiserror`, and `?`. The CLI's
  output is unchanged; it only ever printed `Display`.
- **`--verify-detections` and `--coverage-gaps` no longer count rules that were
  never addressed to a command line.** Candidate rules are selected by ATT&CK
  technique tag, and a technique's rules span event classes — `ps_script`,
  `file_event`, `registry_set`, `proxy`. Those cannot fire on a synthesized
  process-execution event no matter what the evaluator implements, so counting
  them as `INDETERMINATE` conflated "I might answer this given more data" with
  "this question was not for me". A rule whose `logsource.category` is an
  explicit non-process class is now set aside, and an entry whose candidates are
  all set aside reports a new `NOT-APPLICABLE` status. Only an explicit foreign
  category disqualifies a rule; one with no category is still evaluated.

  Measured against live SigmaHQ, the honest consequence is that the numbers get
  **worse where it counts**. Indeterminate falls (windows 69 → 47, linux 30 →
  20, macos 7 → 2), but most of that moves to **unverified** — windows 3 → 21,
  linux 15 → 20, macos 24 → 27. Those were always claims the ruleset does not
  substantiate; they were hidden behind an abstention that included rules which
  could never have fired. Verified counts are unchanged on all three platforms,
  and the verified *entry sets* are identical, so no claim was resting on an
  inapplicable rule.
- **`sync-packaging.sh` now substitutes the version only where it is declared to
  live**, instead of replacing it everywhere and excluding the collisions. The
  old approach accumulated four exclusions — a GNU-only `sed` address range, an
  ERE quantifier, the winget `ManifestVersion`, and the schema version quoted in
  prose — every one of which shipped before being caught. An allowlist inverts
  the failure mode from "silently changed something that was not ours" to
  "silently changed too little", and unlike the former that is detectable: after
  each bump the script asserts no line outside a known foreign-version line
  still carries the old version, naming the file and line if one does.

### Fixed

- **A display cap was deciding verdicts.** `SigmaIndex::rules_for` truncated its
  result to five rules per technique — the right call for a terminal report,
  where a widely-tagged technique would otherwise drown a finding. But
  `--verify-detections` and `--coverage-gaps` drew their candidates from the same
  function, so both reasoned over at most five rules, ranked by severity and then
  *alphabetically by title*. A rule could be excluded from a verdict on nothing
  but its first letter.

  It was not hypothetical. `Shadow Copies Deletion Using Operating Systems
  Utilities` is the SigmaHQ rule for T1490 and fires on
  `vssadmin.exe delete shadows /all /quiet`; it sorts under **S**, behind four
  same-level T1490 rules beginning A, B, C and D, and was never evaluated. Four
  Windows entries were reported as contradicted claims because of it. The same
  cut could report a coverage gap when the rule that fires happened to sort
  sixth — a false blind spot in the tool's headline feature.

  `candidate_rules` now returns the full set and is what verification and
  coverage analyze; `rules_for` keeps the cap and is used only where rules are
  rendered. Regenerated against SigmaHQ `master` @ `1aacbed`, verified rises
  windows 3 → 10 and linux 10 → 14, with unverified falling 21 → 10 and 20 → 12.
  macOS is unchanged, because no macOS technique in the knowledge base carries
  more than five rules — which is why this survived three releases.
- **`sync-packaging.sh` could corrupt the winget manifests.** The version bump
  replaced every occurrence of the crate's version in each manifest, and the
  winget files carry a second version-shaped string that means something else
  entirely — `ManifestVersion` and the `$schema` URL, which track the *winget
  schema*, not opseclint. The schema was `1.6.0` and this crate is on its way
  there: releasing 1.6.0 and then bumping to 1.7.0 would have silently rewritten
  all three manifests to reference a schema version that does not exist. Those
  two lines are now held back from the substitution.
- winget manifests migrated from schema `1.6.0` to **`1.12.0`**, which is what
  `microsoft/winget-pkgs` now asks new submissions to conform to. Every field
  1.12.0 requires was already present, so this is a version-string change only.

### Added

- **`--verify-detections` now reports *why* an entry is indeterminate**, not just
  that it is. `INDETERMINATE` had several distinct causes collapsed into one
  status, so the count said only "the evaluator abstained a lot" — not whether
  that was fixable, or by what. Each entry now carries the modifier tokens the
  evaluator does not implement, the fields a rule keys on that a command line
  cannot supply, rules that could not be lowered to logic at all, and
  field-absent (`null`) assertions — reported per entry in `--json` and as a
  ranked breakdown in the human summary. The distinction matters because the
  causes are entirely different work: modifiers are evaluator features, missing
  fields are telemetry the tool would have to be handed.

### Fixed

- The three tag-triggered workflows matched `v*`, which also matches the moving
  major tag (`v1`) that `release.yml` now re-points at each release. Pushing
  that pointer therefore ran the full release pipeline: it built and published a
  GitHub Release literally named **v1**, which became `releases/latest` and
  displaced the real one — breaking every consumer that resolves "latest",
  including this repository's own composite action (`action.yml` asks
  `/releases/latest` for a tag and derives the asset name from it) and Scoop's
  `checkver`. It also re-ran `cargo publish` against an already-published
  version. All three now match `v*.*.*`, so a major-tag push is inert.
- Packaging manifests (Homebrew, Scoop, AUR, winget) were still pinned to the
  v1.1.0 artifacts and hashes while the crate was at 1.2.0 — every one of the
  four staged channels would have installed the wrong version or failed its
  checksum. All are now on v1.2.0. The AUR `PKGBUILD` also shipped a
  `you@example.com` maintainer placeholder; it now names the real maintainer.
  The Homebrew formula interpolates `#{version}` into its URLs and test
  assertion, so a future bump touches only `version` and the three `sha256`
  lines.
- Documentation that contradicted the shipped tool. `SECURITY.md` claimed
  opseclint was pre-1.0 and now carries a real supported-versions table.
  `docs/design/rule-logic-evaluator.md` was still marked **proposed** although
  it shipped in v1.0.0, and its non-goals listed `ParentImage` / `User` as
  unresolvable without noting that v1.2.0's `--telemetry` and `--users` resolve
  them from a recorded event; the section is now scoped to predictive mode. The
  README's GitHub Action example referenced `ezekiellabs/opseclint@v1` — a tag
  that does not exist — and taught `codeql-action/upload-sarif@v3` while CI uses
  `@v4`; both are corrected. Stale `v0.1.0` version placeholders in the bug
  report template and `action.yml` now name the current release.
- The README pointed readers at an empty issue tracker for "the full list". It
  now links the changelog, coverage requests, and Discussions, and the 13/13
  checked Roadmap is a `What's shipped` list plus an honest `Next` section.
- `.gitignore` covered only `/target`, leaving the SigmaHQ ruleset clones that
  the README and CI both create (`sigma/`, `sigma-rules/`) and `*.sarif` output
  untracked in the working tree.
- `LICENSE` named a different copyright holder than the organization's other
  repositories; standardized on Ezekiel Labs.
- The release workflow ran `softprops/action-gh-release` from **all four**
  matrix build jobs against the same tag, with no `needs:` and no concurrency
  guard. The four concurrent create-release calls race, and a loser creates a
  stray *untagged draft* release next to the real one — reproducibly, on every
  release. `build` now uploads artifacts and a single `publish` job creates the
  release from them.

### Added

- `scripts/sync-packaging.sh` — one implementation of "where the version lives",
  used three ways: `--check` (offline parity against `Cargo.toml`), `--bump`
  (move every version string), and `<version>` (fetch the published artifacts
  and fill in real hashes). Because the fixer and the checker are the same code,
  they cannot disagree.
- CI gate asserting `packaging/` matches `Cargo.toml`, and a post-publish
  release job that recomputes the four artifact hashes and fails if `packaging/`
  does not carry them. The first is offline and cheap; the second runs at the
  only moment the real hashes exist.
- The release workflow now re-points the major tag (`v1`) at each release, so
  the `ezekiellabs/opseclint@v1` pin that the README and Marketplace advertise
  resolves. Pre-release tags are skipped.

## [1.2.0] - 2026-07-31

### Added

- **`--telemetry <FILE>`** — ingest recorded host telemetry (the events a sensor
  actually logged) and map it back to techniques, detectability, and coverage —
  the observed-mode complement to opseclint's predictive analysis. Three formats
  are supported (`--format`): Windows **Sysmon Event ID 1** (Process Create), as
  a JSON array of events or JSONL (`sysmon`) — flat, `EventData`-nested, and
  Elastic `winlog.event_data` shapes are all accepted; Linux **auditd** `execve`
  events, as raw `audit.log` text (`auditd`) — the multi-line `SYSCALL` /
  `EXECVE` / `CWD` records of one event are reassembled by their `audit(…)` id,
  the argv rebuilt from the `EXECVE` fields (quoted and hex-encoded values
  decoded), and the program taken from the `exe` path; and macOS **Endpoint
  Security** `NOTIFY_EXEC` events, as `eslogger exec` JSON (`esf`) — the image,
  argv, and working directory from `event.exec.target`, and a real `ParentImage`
  from the calling process. Each record reduces to the
  same `Command` the analyzer already understands, so `--json` / `--sarif` /
  `--navigator` / `--edr` all work on ingested events, and observed verdicts
  agree with predicted ones by construction. Non-execution records are skipped
  and counted. When paired with `--sigma`, detections are evaluated against the
  **real recorded event**: a rule keyed on a field a command line can't supply
  (`ParentImage`, `IntegrityLevel`, `CurrentDirectory`, macOS code-signing fields
  like `is_platform_binary`, …) resolves to `fires` / `no-fire` instead of
  `indeterminate` — the payoff of ingesting real telemetry. Each format carries
  the extra context it records: ESF the calling parent and the new image's
  code-signing (`signing_id` / `team_id` / `is_platform_binary`), auditd the
  controlling `tty` and audit-rule `key`. Non-execution records (Sysmon EID 3 /
  11 / 13) are **correlated by process id** back to the execution that emitted
  them and shown as confirmed secondary telemetry — a green `◉ observed:` line
  (e.g. `network connection to 192.0.2.10:443`) turning predicted telemetry into
  recorded proof.
  See [`docs/design/telemetry-ingest.md`](docs/design/telemetry-ingest.md).

- **`--users <FILE>`** — a `passwd`-format file mapping numeric uids to names, so
  ingested auditd telemetry resolves the `User` field (uid `0` → `root`), letting
  `User`-keyed detections resolve. Opt-in by design: without it a numeric uid is
  left unresolved rather than guessed, so a rule expecting `root` stays
  `indeterminate` instead of getting a wrong `no-fire`.

- **Standalone non-execution matching** — a non-execution event with no captured
  causing execution (e.g. a registry Run-key set by an uncaptured process) is now
  matched directly against a new `event` axis on the KB matcher (tests an event
  `class` and a field, e.g. a registry `TargetObject`). An entry can carry both a
  command `line` axis and an `event` axis, so it recognizes its action whether
  seen as a command or a standalone event; the Windows `run-key-persist` entry is
  seeded this way. Events that correlate to an execution attach as its side-effect
  and are not also matched standalone. Linux/macOS event-scoped entries follow.

- **`--verify-detections`** — prove the knowledge base's own Sigma detection
  claims against a real ruleset. For every entry that cites a Sigma detection,
  opseclint synthesizes a representative command and checks whether a genuine
  SigmaHQ rule for the entry's technique(s) actually fires, classifying each as
  `verified` / `unverified` / `indeterminate` / `no-rule`. Audits the KB itself
  (no input needed); honors `--json` (snapshot) and `--diff` (regression). A new
  CI job runs it per platform against a fresh SigmaHQ checkout as a regression
  gate: `--ci` fails when a previously-verified detection stops firing (diff
  mode) or when any claimed detection is contradicted (standalone). Baselines
  live in `.ci/verified-<platform>.json`.

- **`--scaffold`** — generate a starter Sigma rule for each modeled action,
  with detection logic mirroring how opseclint matches it. Paired with
  `--coverage-gaps`, it scaffolds only the blind-spot actions, closing the
  loop from a coverage gap to a rule that would fire on it.

- **`--navigator`** — emit an ATT&CK Navigator layer (JSON) of the techniques an
  input surfaces, scored by detectability, for import at the MITRE ATT&CK
  Navigator to visualize coverage on the matrix.

- **Known-benign corpus test** — asserts a curated corpus of everyday commands
  per platform (navigation, dev/build tooling, log reads) produces zero
  findings, guarding against knowledge-base false positives.

- **Structured matcher `regex` leaf** — knowledge-base entries can now key on a
  regular expression (in `args`, `line`, or a positional/`joined` leaf) when the
  fixed leaves can't express the shape. Patterns compile at load (invalid = load
  error) and match case-insensitively; an entry that uses one must supply an
  `example` command, which also drives verification and scaffolding (`--scaffold`
  lowers it to a Sigma `CommandLine|re`). Used to fold the whole PowerShell
  `-WindowStyle Hidden` abbreviation family into one `powershell-hidden` rule.

### Fixed

- **EDR classifier re-audit** — after the knowledge base was deepened, the
  telemetry → EDR event-class classifier had drifted: 41 telemetry lines matched
  no class, and four Active Directory entries (`dcsync`, `kerberoast-getuserspns`,
  `asreproast`, `golden-ticket`) silently fell back to the `process_creation`
  default despite being Kerberos/replication **authentication** events (`4768`,
  `4769`, `4662`, TGS/AS-REQ, DRSUAPI). Extended the class patterns to cover the
  new telemetry vocabulary (Kerberos/AD auth, LDAP/DNS/tunnel network activity,
  `ptrace`/`init_module`/`getxattr`, systemd timers, etc.) with no reclassification
  of already-correct lines, so `--edr` now maps every entry to its true event
  class. Added a guard test asserting no entry with telemetry falls back to the
  default, so future KB growth can't silently regress the mapping.

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

[Unreleased]: https://github.com/ezekiellabs/opseclint/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/ezekiellabs/opseclint/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/ezekiellabs/opseclint/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/ezekiellabs/opseclint/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ezekiellabs/opseclint/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ezekiellabs/opseclint/compare/v0.1.2...v1.0.0
[0.1.2]: https://github.com/ezekiellabs/opseclint/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ezekiellabs/opseclint/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ezekiellabs/opseclint/releases/tag/v0.1.0
