//! opseclint: A detection-coverage analyzer for Linux/auditd,
//! Windows/Sysmon, and macOS/Endpoint Security.
//!
//! Point it at a command, a script, or a playbook and it statically resolves
//! each action to the ATT&CK technique(s) it implements, the host telemetry it
//! emits, and the detections that would fire. With a detectability score.
//! It answers "what would a defender see?", to help red/purple teams and
//! detection engineers reason about coverage. It does not recommend evasions.

mod analyzer;
mod coverage;
mod kb;
mod model;
mod parser;
mod report;
mod sarif;
mod sigma;
mod sigma_eval;
mod theme;

use std::io::{IsTerminal, Read};
use std::process::ExitCode;

use clap::Parser;

/// Detection-coverage analyzer: shell actions -> ATT&CK -> telemetry -> detections.
#[derive(Parser, Debug)]
#[command(name = "opseclint", version, about, long_about = None)]
struct Cli {
    /// Path to a script or playbook to analyze. Reads stdin if omitted and
    /// --command is not given.
    path: Option<String>,

    /// Analyze a single command string instead of a file.
    #[arg(short, long)]
    command: Option<String>,

    /// Target platform / telemetry model.
    #[arg(long, value_enum, default_value = "linux-auditd")]
    platform: kb::Platform,

    /// Only report findings at or above this detectability score (0-100).
    #[arg(long, default_value_t = 0, help_heading = "Filtering")]
    min: u8,

    /// Emit machine-readable JSON instead of a terminal report.
    #[arg(long, help_heading = "Output")]
    json: bool,

    /// Emit SARIF 2.1.0 (for GitHub code scanning / SARIF-aware tools).
    #[arg(long, conflicts_with = "json", help_heading = "Output")]
    sarif: bool,

    /// Force-disable ANSI color (color is auto-disabled when not a TTY).
    #[arg(long, help_heading = "Output")]
    no_color: bool,

    /// CI gate: exit non-zero if any finding's detectability is >= --threshold
    /// (or, with --coverage-gaps, if any gap is found).
    #[arg(long, help_heading = "CI gate")]
    ci: bool,

    /// Detectability threshold used by --ci (0-100).
    #[arg(long, default_value_t = 50, help_heading = "CI gate")]
    threshold: u8,

    /// Enrich findings with real rules from a SigmaHQ checkout (directory of
    /// Sigma YAML). Matched by ATT&CK technique; platform-relevant rules only.
    #[arg(long, value_name = "DIR", help_heading = "Sigma")]
    sigma: Option<String>,

    /// Disable the on-disk Sigma index cache (always re-parse the ruleset).
    #[arg(long, help_heading = "Sigma")]
    no_sigma_cache: bool,

    /// Evaluate the input against a single Sigma rule's detection logic and
    /// print, per command, whether it FIRES / NO-FIRE / INDETERMINATE.
    #[arg(
        long,
        value_name = "RULE.yml",
        conflicts_with_all = ["json", "sarif", "coverage_gaps"],
        help_heading = "Modes"
    )]
    check_rule: Option<String>,

    /// Report coverage gaps: actions whose techniques have rules in --sigma but
    /// where none actually fire. Requires --sigma.
    #[arg(
        long,
        requires = "sigma",
        conflicts_with_all = ["json", "sarif"],
        help_heading = "Modes"
    )]
    coverage_gaps: bool,
}

fn read_input(cli: &Cli) -> std::io::Result<String> {
    if let Some(cmd) = &cli.command {
        return Ok(cmd.clone());
    }
    if let Some(path) = &cli.path {
        return std::fs::read_to_string(path);
    }
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// Evaluate every command in `input` against a single Sigma rule file.
fn run_check_rule(cli: &Cli, rule_path: &str, input: &str) -> ExitCode {
    let yaml = match std::fs::read_to_string(rule_path) {
        Ok(y) => y,
        Err(e) => {
            eprintln!("opseclint: could not read rule '{rule_path}': {e}");
            return ExitCode::from(2);
        }
    };
    let Some(rule) = sigma_eval::parse_rule(&yaml) else {
        eprintln!("opseclint: could not parse a Sigma detection from '{rule_path}'");
        return ExitCode::from(2);
    };

    let color = !cli.no_color && std::io::stdout().is_terminal();
    let p = theme::Painter::new(color);
    println!(
        "{}{}",
        p.bold(theme::BLUE, "opseclint"),
        p.paint(
            theme::COMMENT,
            &format!(" · rule check · {} ({})", rule.title, rule.id)
        )
    );
    println!("{}", p.rule(60));

    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for cmd in parser::parse_line(line) {
            let v = sigma_eval::evaluate(&rule, &cmd, cli.platform);
            let (glyph, col, label) = match v.outcome {
                sigma_eval::Outcome::Fires => ("✓", theme::GREEN, "FIRES        "),
                sigma_eval::Outcome::NoFire => ("·", theme::COMMENT, "NO-FIRE      "),
                sigma_eval::Outcome::Indeterminate => ("?", theme::YELLOW, "INDETERMINATE"),
            };
            println!(
                " {} {}  {}  {}",
                p.paint(col, glyph),
                p.paint(col, label),
                p.paint(theme::COMMENT, &format!("L{}", idx + 1)),
                p.paint(theme::FG, &cmd.program),
            );
            if v.outcome == sigma_eval::Outcome::Indeterminate && !v.missing_fields.is_empty() {
                println!(
                    "        {}",
                    p.paint(
                        theme::COMMENT,
                        &format!("needs {}", v.missing_fields.join(", "))
                    )
                );
            }
        }
    }

    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let kb = match kb::load(cli.platform) {
        Ok(kb) => kb,
        Err(e) => {
            eprintln!("opseclint: failed to load knowledge base: {e}");
            return ExitCode::from(2);
        }
    };

    let input = match read_input(&cli) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("opseclint: failed to read input: {e}");
            return ExitCode::from(2);
        }
    };

    // --check-rule is a distinct mode: evaluate detection logic, not coverage.
    if let Some(rule_path) = &cli.check_rule {
        return run_check_rule(&cli, rule_path, &input);
    }

    let mut report = analyzer::analyze(&input, &kb);
    if cli.min > 0 {
        report.findings.retain(|f| f.noise >= cli.min);
    }

    // --coverage-gaps is its own output mode (evaluate rule logic, not enrich).
    if cli.coverage_gaps {
        let dir = cli.sigma.as_deref().expect("clap requires --sigma");
        let index = match sigma::load_cached(
            std::path::Path::new(dir),
            cli.platform.sigma_product(),
            !cli.no_sigma_cache,
        ) {
            Ok((i, _from_cache)) => i,
            Err(e) => {
                eprintln!("opseclint: could not read sigma dir '{dir}': {e}");
                return ExitCode::from(2);
            }
        };
        let results = coverage::analyze(&report, &index, cli.platform);
        let color = !cli.no_color && std::io::stdout().is_terminal();
        print!(
            "{}",
            coverage::render(&results, &report.platform, index.rules_indexed, color)
        );
        // In --ci mode, fail the run when blind spots exist.
        if cli.ci && coverage::gap_count(&results) > 0 {
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    if let Some(dir) = &cli.sigma {
        let product = cli.platform.sigma_product();
        match sigma::load_cached(std::path::Path::new(dir), product, !cli.no_sigma_cache) {
            Ok((index, from_cache)) => {
                let enriched = sigma::enrich(&mut report, &index, cli.platform);
                if !cli.json && !cli.sarif {
                    eprintln!(
                        "opseclint: sigma — {} rule(s) from {} file(s){}; enriched {} finding(s)",
                        index.rules_indexed,
                        index.files_scanned,
                        if from_cache { " [cached]" } else { "" },
                        enriched
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "opseclint: could not read sigma dir '{dir}': {e} (using seed references)"
                );
            }
        }
    }

    if cli.sarif {
        let source_uri = cli.path.clone().unwrap_or_else(|| {
            if cli.command.is_some() {
                "<command>"
            } else {
                "stdin"
            }
            .to_string()
        });
        println!("{}", sarif::render(&report, &source_uri));
    } else if cli.json {
        println!("{}", report::render_json(&report));
    } else {
        let color = !cli.no_color && std::io::stdout().is_terminal();
        print!("{}", report::render_human(&report, color));
    }

    if cli.ci && report.max_noise >= cli.threshold {
        if !cli.json {
            eprintln!(
                "\nopseclint: CI gate failed — loudest action {} (>= threshold {})",
                report::severity_word(report.max_severity()),
                cli.threshold
            );
        }
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}
