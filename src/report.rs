//! Rendering: a human-readable terminal report and a machine-readable JSON
//! form for CI consumption.

use std::fmt::Write as _;

use crate::model::{Report, Severity};
use crate::theme::{self, Painter};

const WIDTH: usize = 60;
const INDENT: &str = "                "; // 16 spaces, aligns sub-lines

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Render the report for a terminal in the Tokyo Night palette. `color` toggles
/// ANSI escapes.
pub fn render_human(report: &Report, color: bool) -> String {
    let p = Painter::new(color);
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{}{}",
        p.bold(theme::BLUE, "opseclint"),
        p.paint(
            theme::COMMENT,
            &format!(" · detection-coverage · {}", report.platform)
        )
    );

    if report.findings.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            p.paint(
                theme::COMMENT,
                &format!(
                    "{} line{} · 0 findings",
                    report.lines_analyzed,
                    plural(report.lines_analyzed)
                )
            )
        );
        let _ = writeln!(
            out,
            "\n  {}",
            p.paint(
                theme::FG_DIM,
                "No modeled actions matched — which is not proof of stealth, only that"
            )
        );
        let _ = writeln!(
            out,
            "  {}",
            p.paint(
                theme::FG_DIM,
                "nothing in the knowledge base matched this input."
            )
        );
        return out;
    }

    let sev = report.max_severity();
    let _ = writeln!(
        out,
        "{}{}",
        p.paint(
            theme::COMMENT,
            &format!(
                "{} line{} · {} finding{} · loudest ",
                report.lines_analyzed,
                plural(report.lines_analyzed),
                report.findings.len(),
                plural(report.findings.len())
            )
        ),
        p.paint(
            sev.color(),
            &format!("● {} ({})", sev.label(), report.max_noise)
        )
    );
    let _ = writeln!(out, "{}", p.rule(WIDTH));

    for f in &report.findings {
        let s = f.severity;
        let _ = writeln!(
            out,
            " {}  {}  {}",
            p.paint(s.color(), &format!("● {:<8} {:>2}", s.label(), f.noise)),
            p.paint(theme::COMMENT, &format!("L{}", f.line)),
            p.paint(theme::FG, &f.description),
        );

        // Build sub-lines, then draw the tree (├ for all but the last, └ last).
        let mut subs: Vec<String> = Vec::new();
        if !f.techniques.is_empty() {
            let techs = f
                .techniques
                .iter()
                .map(|t| {
                    format!(
                        "{} {}",
                        p.paint(theme::PURPLE, &t.id),
                        p.paint(theme::FG_DIM, &t.name)
                    )
                })
                .collect::<Vec<_>>()
                .join(&p.paint(theme::COMMENT, " · "));
            subs.push(techs);
        }
        for tel in &f.telemetry {
            subs.push(p.paint(theme::COMMENT, &format!("◈ {tel}")));
        }
        for d in &f.detections {
            let mut line = p.paint(theme::CYAN, &format!("◆ {}: {}", d.source, d.rule));
            if let Some(v) = &d.verdict {
                let vcol = if v.starts_with("fires") {
                    theme::GREEN
                } else if v.starts_with("indeterminate") {
                    theme::YELLOW
                } else {
                    theme::COMMENT
                };
                line.push_str(&format!(" {}", p.paint(vcol, v)));
            }
            line.push_str(&format!(
                " {}",
                p.paint(theme::COMMENT, &format!("({})", d.confidence))
            ));
            subs.push(line);
        }
        for m in &f.edr {
            subs.push(format!(
                "{} {}",
                p.paint(theme::BLUE, &format!("◎ {}:", m.vendor)),
                p.paint(theme::FG_DIM, &m.events.join(" · ")),
            ));
        }

        let last = subs.len().saturating_sub(1);
        for (i, sub) in subs.iter().enumerate() {
            let glyph = if i == last { "└" } else { "├" };
            let _ = writeln!(out, "{INDENT}{} {sub}", p.paint(theme::COMMENT, glyph));
        }
    }

    let _ = writeln!(out, "{}", p.rule(WIDTH));
    let _ = writeln!(
        out,
        " {}  {}",
        p.bold(theme::FG, "summary"),
        p.paint(
            sev.color(),
            &format!("● {} ({})", sev.label(), report.max_noise)
        )
    );
    if !report.note.is_empty() {
        let _ = writeln!(out, "\n{}", p.paint(theme::COMMENT, &report.note));
    }
    out
}

/// Render the report as pretty JSON.
pub fn render_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// Human-readable one-liner for a severity, used in CI gate messages.
pub fn severity_word(sev: Severity) -> &'static str {
    sev.label()
}
