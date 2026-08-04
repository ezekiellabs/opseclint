//! Coverage diff: compare the current analysis against a previously saved
//! `--json` report and render what changed — findings added, removed, or whose
//! detectability / Sigma verdict shifted. It answers "did this change make me
//! louder or quieter?" across a ruleset or playbook revision.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::theme::{self, Painter};
use opseclint_core::model::{Detection, Report, Severity};

const WIDTH: usize = 60;

/// One rule's collapsed coverage state, across every line it matched.
#[derive(Debug, Clone, Serialize)]
pub struct DiffEntry {
    pub rule_id: String,
    pub description: String,
    pub techniques: Vec<String>,
    pub noise: u8,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
}

/// A rule present in both reports whose detectability or verdict moved.
#[derive(Debug, Clone, Serialize)]
pub struct Changed {
    pub before: DiffEntry,
    pub after: DiffEntry,
}

/// The full delta between a baseline and the current report.
#[derive(Debug, Clone, Serialize)]
pub struct Delta {
    pub platform: String,
    /// Set to the baseline's platform when it differs from the current one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_mismatch: Option<String>,
    pub added: Vec<DiffEntry>,
    pub removed: Vec<DiffEntry>,
    pub changed: Vec<Changed>,
    pub baseline_findings: usize,
    pub current_findings: usize,
    pub baseline_max_noise: u8,
    pub current_max_noise: u8,
}

impl Delta {
    /// True when the current run's peak detectability rose above the baseline —
    /// consistent with the tool's headline "loudest action" metric and the
    /// standard `--ci` gate. Drives both the trend word and the diff CI gate.
    pub fn is_louder(&self) -> bool {
        self.current_max_noise > self.baseline_max_noise
    }

    /// True when peak detectability fell below the baseline.
    pub fn is_quieter(&self) -> bool {
        self.current_max_noise < self.baseline_max_noise
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

fn verdict_rank(v: &str) -> u8 {
    match v.split_whitespace().next().unwrap_or("") {
        "fires" => 3,
        "indeterminate" => 2,
        "no-fire" => 1,
        _ => 0,
    }
}

/// The strongest verdict among a finding's detections (fires > indeterminate >
/// no-fire), normalized to its leading word. `None` when no rule was evaluated.
fn summarize_verdict(dets: &[Detection]) -> Option<String> {
    dets.iter()
        .filter_map(|d| d.verdict.as_deref())
        .max_by_key(|v| verdict_rank(v))
        .map(|v| v.split_whitespace().next().unwrap_or(v).to_string())
}

/// Collapse per-line findings into one entry per rule, keeping the loudest.
fn collapse(report: &Report) -> BTreeMap<String, DiffEntry> {
    let mut map: BTreeMap<String, DiffEntry> = BTreeMap::new();
    for f in &report.findings {
        let entry = DiffEntry {
            rule_id: f.rule_id.clone(),
            description: f.description.clone(),
            techniques: f.techniques.iter().map(|t| t.id.clone()).collect(),
            noise: f.noise,
            severity: f.severity,
            verdict: summarize_verdict(&f.detections),
        };
        map.entry(f.rule_id.clone())
            .and_modify(|e| {
                if entry.noise > e.noise {
                    *e = entry.clone();
                }
            })
            .or_insert(entry);
    }
    map
}

/// Compute the coverage delta of `current` relative to `baseline`.
pub fn compute(baseline: &Report, current: &Report) -> Delta {
    let base = collapse(baseline);
    let curr = collapse(current);

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (id, c) in &curr {
        match base.get(id) {
            None => added.push(c.clone()),
            Some(b) if b.noise != c.noise || b.verdict != c.verdict => changed.push(Changed {
                before: b.clone(),
                after: c.clone(),
            }),
            Some(_) => {}
        }
    }
    let mut removed: Vec<DiffEntry> = base
        .iter()
        .filter(|(id, _)| !curr.contains_key(*id))
        .map(|(_, b)| b.clone())
        .collect();

    // Loudest-first for display.
    let by_noise =
        |a: &DiffEntry, b: &DiffEntry| b.noise.cmp(&a.noise).then(a.rule_id.cmp(&b.rule_id));
    added.sort_by(by_noise);
    removed.sort_by(by_noise);
    changed.sort_by(|a, b| by_noise(&a.after, &b.after));

    Delta {
        platform: current.platform.clone(),
        platform_mismatch: (baseline.platform != current.platform)
            .then(|| baseline.platform.clone()),
        added,
        removed,
        changed,
        baseline_findings: baseline.findings.len(),
        current_findings: current.findings.len(),
        baseline_max_noise: baseline.max_noise,
        current_max_noise: current.max_noise,
    }
}

fn techs(p: &Painter, ids: &[String]) -> String {
    if ids.is_empty() {
        return String::new();
    }
    format!("  {}", p.paint(theme::PURPLE, &ids.join(", ")))
}

/// Render the delta for a terminal in the Tokyo Night palette.
pub fn render_human(delta: &Delta, color: bool) -> String {
    let p = Painter::new(color);
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{}{}",
        p.bold(theme::BLUE, "opseclint"),
        p.paint(
            theme::COMMENT,
            &format!(" · coverage diff · {}", delta.platform)
        )
    );
    if let Some(base_plat) = &delta.platform_mismatch {
        let _ = writeln!(
            out,
            "{}",
            p.paint(
                theme::YELLOW,
                &format!(
                    "  ! baseline platform was {base_plat}, current is {} — comparison may be misleading",
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
                "baseline {} finding(s) · current {} finding(s)",
                delta.baseline_findings, delta.current_findings
            )
        )
    );
    let _ = writeln!(out, "{}", p.rule(WIDTH));

    if delta.is_empty() {
        let _ = writeln!(out, " {}", p.paint(theme::FG_DIM, "No coverage change."));
    }

    for e in &delta.added {
        let _ = writeln!(
            out,
            " {}  {}{}",
            p.paint(
                theme::GREEN,
                &format!("+ {:<8} {:>2}", e.severity.label(), e.noise)
            ),
            p.paint(theme::FG, &e.description),
            techs(&p, &e.techniques),
        );
    }
    for e in &delta.removed {
        let _ = writeln!(
            out,
            " {}  {}{}",
            p.paint(
                theme::RED,
                &format!("- {:<8} {:>2}", e.severity.label(), e.noise)
            ),
            p.paint(theme::FG_DIM, &e.description),
            techs(&p, &e.techniques),
        );
    }
    for c in &delta.changed {
        let (b, a) = (&c.before, &c.after);
        let mut delta_str = String::new();
        if b.noise != a.noise {
            let _ = write!(
                delta_str,
                "{} {} {}",
                p.paint(
                    theme::COMMENT,
                    &format!("{} {}", b.severity.label(), b.noise)
                ),
                p.paint(theme::COMMENT, "→"),
                p.paint(
                    theme::severity_color(a.severity),
                    &format!("{} {}", a.severity.label(), a.noise)
                ),
            );
        }
        if b.verdict != a.verdict {
            let fmt = |v: &Option<String>| v.clone().unwrap_or_else(|| "—".to_string());
            if !delta_str.is_empty() {
                delta_str.push_str(&p.paint(theme::COMMENT, " · "));
            }
            let _ = write!(
                delta_str,
                "{} {} {}",
                p.paint(theme::COMMENT, &fmt(&b.verdict)),
                p.paint(theme::COMMENT, "→"),
                p.paint(theme::CYAN, &fmt(&a.verdict)),
            );
        }
        let _ = writeln!(
            out,
            " {}  {}  {}{}",
            p.paint(theme::YELLOW, "~ CHANGED "),
            p.paint(theme::FG, &a.description),
            delta_str,
            techs(&p, &a.techniques),
        );
    }

    let _ = writeln!(out, "{}", p.rule(WIDTH));
    let trend = if delta.is_louder() {
        p.paint(theme::ORANGE, "louder")
    } else if delta.is_quieter() {
        p.paint(theme::GREEN, "quieter")
    } else {
        p.paint(theme::COMMENT, "peak unchanged")
    };
    let _ = writeln!(
        out,
        " {}  {} · {} · {} · max noise {} → {} · {}",
        p.bold(theme::FG, "summary"),
        p.paint(theme::GREEN, &format!("+{}", delta.added.len())),
        p.paint(theme::RED, &format!("-{}", delta.removed.len())),
        p.paint(theme::YELLOW, &format!("~{}", delta.changed.len())),
        delta.baseline_max_noise,
        delta.current_max_noise,
        trend,
    );
    out
}

/// Render the delta as pretty JSON.
pub fn render_json(delta: &Delta) -> String {
    serde_json::to_string_pretty(delta).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opseclint_core::model::{Finding, Technique};

    fn finding(rule: &str, noise: u8, verdict: Option<&str>) -> Finding {
        Finding {
            line: 1,
            source: "opseclint".into(),
            rule_id: rule.into(),
            description: format!("desc {rule}"),
            techniques: vec![Technique {
                id: "T1059".into(),
                name: "n".into(),
            }],
            telemetry: vec![],
            detections: verdict
                .map(|v| {
                    vec![Detection {
                        source: "Sigma".into(),
                        rule: "r".into(),
                        confidence: "high".into(),
                        verdict: Some(v.into()),
                    }]
                })
                .unwrap_or_default(),
            edr: vec![],
            noise,
            severity: Severity::from_noise(noise),
            matched_command: None,
            observed_event: None,
            observed_side_effects: Vec::new(),
        }
    }

    fn report(platform: &str, findings: Vec<Finding>) -> Report {
        let max_noise = findings.iter().map(|f| f.noise).max().unwrap_or(0);
        Report {
            platform: platform.into(),
            note: String::new(),
            findings,
            max_noise,
            lines_analyzed: 1,
        }
    }

    #[test]
    fn detects_added_removed_and_changed() {
        let base = report(
            "linux-auditd",
            vec![finding("a", 40, None), finding("b", 60, None)],
        );
        // a: noise bumped 40 -> 55; b: removed; c: added.
        let curr = report(
            "linux-auditd",
            vec![finding("a", 55, None), finding("c", 70, None)],
        );
        let d = compute(&base, &curr);
        assert_eq!(
            d.added
                .iter()
                .map(|e| e.rule_id.as_str())
                .collect::<Vec<_>>(),
            ["c"]
        );
        assert_eq!(
            d.removed
                .iter()
                .map(|e| e.rule_id.as_str())
                .collect::<Vec<_>>(),
            ["b"]
        );
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].after.rule_id, "a");
        assert!(d.is_louder()); // new finding + higher max noise
    }

    #[test]
    fn verdict_flip_is_a_change_even_at_same_noise() {
        let base = report("linux-auditd", vec![finding("a", 50, Some("no-fire"))]);
        let curr = report("linux-auditd", vec![finding("a", 50, Some("fires"))]);
        let d = compute(&base, &curr);
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].before.verdict.as_deref(), Some("no-fire"));
        assert_eq!(d.changed[0].after.verdict.as_deref(), Some("fires"));
    }

    #[test]
    fn removing_the_loudest_action_reads_as_quieter() {
        let base = report(
            "linux-auditd",
            vec![finding("shell", 82, None), finding("recon", 45, None)],
        );
        let curr = report("linux-auditd", vec![finding("recon", 45, None)]);
        let d = compute(&base, &curr);
        assert!(d.is_quieter());
        assert!(!d.is_louder());
        assert_eq!(d.removed.len(), 1);
    }

    #[test]
    fn identical_reports_have_no_delta() {
        let r = report("linux-auditd", vec![finding("a", 50, None)]);
        let d = compute(&r, &r);
        assert!(d.is_empty());
        assert!(!d.is_louder());
    }

    #[test]
    fn platform_mismatch_is_flagged() {
        let base = report("windows-sysmon", vec![]);
        let curr = report("linux-auditd", vec![]);
        let d = compute(&base, &curr);
        assert_eq!(d.platform_mismatch.as_deref(), Some("windows-sysmon"));
    }
}
