//! opseclint: A detection-coverage analyzer for Linux/auditd,
//! Windows/Sysmon, and macOS/Endpoint Security.
//!
//! Point it at a command, a script, or a playbook and it statically resolves
//! each action to the ATT&CK technique(s) it implements, the host telemetry it
//! emits, and the detections that would fire. With a detectability score.
//! It answers "what would a defender see?", to help red/purple teams and
//! detection engineers reason about coverage. It does not recommend evasions.

//! The analysis itself lives in `opseclint-core`; this crate is the CLI over
//! it — argument parsing, the rendered report, and the knowledge-base tooling
//! (`--scaffold`, `--verify-detections`, `--coverage-gaps`) that maintains it.

mod coverage;
mod diff;
mod navigator;
mod report;
mod sarif;
mod scaffold;
mod theme;
mod verify;

use opseclint_core::{analyzer, edr, kb, model, parser, sigma, sigma_eval, telemetry};

use std::io::{IsTerminal, Read, Write};
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

    /// Ingest recorded host telemetry (the events a sensor actually logged) and
    /// map it back to techniques, detectability, and coverage — the complement
    /// to the predictive mode. Currently Windows Sysmon Event ID 1 (Process
    /// Create), as a JSON array of events or JSONL. Honors --json / --sarif /
    /// --navigator / --edr like any other input.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["command", "path", "check_rule", "verify_detections"],
        help_heading = "Ingest"
    )]
    telemetry: Option<String>,

    /// Format of the --telemetry file.
    #[arg(long, value_enum, default_value = "sysmon", help_heading = "Ingest")]
    format: telemetry::Format,

    /// `passwd`-format file mapping numeric uids to names, so ingested telemetry
    /// with a numeric uid (auditd) resolves the `User` field. Without it, a
    /// numeric uid is left unresolved rather than guessed.
    #[arg(long, value_name = "FILE", help_heading = "Ingest")]
    users: Option<String>,

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

    /// Emit an ATT&CK Navigator layer (JSON) of the techniques surfaced, scored
    /// by detectability. Import at mitre-attack.github.io/attack-navigator.
    #[arg(long, conflicts_with_all = ["json", "sarif", "diff", "coverage_gaps", "check_rule"], help_heading = "Output")]
    navigator: bool,

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

    /// Map each finding's telemetry to the sensor events major EDRs surface.
    /// Give a vendor (crowdstrike, defender, sentinelone, elastic) or omit the
    /// value for all four.
    #[arg(
        long,
        value_enum,
        value_name = "VENDOR",
        num_args = 0..=1,
        default_missing_value = "all",
        help_heading = "EDR"
    )]
    edr: Option<edr::Vendor>,

    /// Enrich findings with real rules from a SigmaHQ checkout (directory of
    /// Sigma YAML). Matched by ATT&CK technique; platform-relevant rules only.
    #[arg(long, value_name = "DIR", help_heading = "Sigma")]
    sigma: Option<String>,

    /// Disable the on-disk Sigma index cache (always re-parse the ruleset).
    #[arg(long, help_heading = "Sigma")]
    no_sigma_cache: bool,

    /// Record the ruleset revision this run was computed against (typically a
    /// SigmaHQ commit SHA), stamping it into `--verify-detections --json` so a
    /// saved baseline says which ruleset produced it. Deliberately not derived
    /// from the checkout: `--sigma` may point at any directory, and a guessed
    /// provenance committed into a baseline is worse than none at all.
    /// Scoped to --verify-detections, which is the only mode that records it:
    /// anywhere else the flag would parse, be ignored, and leave the caller
    /// believing a provenance had been captured. (That mode already requires
    /// --sigma, so this is the stricter of the two constraints, not a weaker
    /// one.)
    #[arg(
        long,
        value_name = "REF",
        requires = "verify_detections",
        help_heading = "Sigma"
    )]
    sigma_ref: Option<String>,

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
    /// where none actually fire. Requires --sigma. Honors --json and --diff.
    #[arg(
        long,
        requires = "sigma",
        conflicts_with = "sarif",
        help_heading = "Modes"
    )]
    coverage_gaps: bool,

    /// Scaffold a starter Sigma rule for each modeled action (multi-doc YAML to
    /// stdout). With --coverage-gaps, scaffolds only the blind-spot actions,
    /// closing the loop from a coverage gap to a rule that would fire on it.
    #[arg(
        long,
        conflicts_with_all = ["json", "sarif", "navigator", "check_rule", "diff"],
        help_heading = "Modes"
    )]
    scaffold: bool,

    /// Verify the knowledge base's own Sigma detection claims against a real
    /// ruleset (--sigma): for each entry claiming a Sigma detection, check that
    /// a genuine rule for its technique(s) actually fires. Audits the KB itself,
    /// so it needs no input. Honors --json (snapshot) and --diff (regression);
    /// with --ci, fails on unverified claims — or, with --diff, on regressions.
    #[arg(
        long,
        requires = "sigma",
        conflicts_with_all = ["sarif", "coverage_gaps", "check_rule", "navigator", "scaffold"],
        help_heading = "Modes"
    )]
    verify_detections: bool,

    /// Compare this run against a previously saved --json report and show the
    /// coverage delta. On its own, diffs findings (added / removed / changed);
    /// with --coverage-gaps, diffs blind spots (closed / opened). Honors --json.
    #[arg(
        long,
        value_name = "BASELINE.json",
        conflicts_with_all = ["sarif", "check_rule"],
        help_heading = "Modes"
    )]
    diff: Option<String>,
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

/// Emit scaffolded Sigma rules (YAML) for `entries` to stdout, with a stderr note.
fn emit_scaffold(entries: &[&model::KbEntry], platform: kb::Platform) {
    if entries.is_empty() {
        eprintln!("opseclint: no actions to scaffold");
        return;
    }
    let docs = scaffold::documents_for(entries, platform, &scaffold::today());
    print!("{}", docs.join("---\n"));
    // Flush stdout before the stderr note so combined streams stay ordered.
    let _ = std::io::stdout().flush();
    // An action modeled on both a command axis and an `event` axis scaffolds a
    // rule per log source, so rules and actions are no longer the same count.
    eprintln!(
        "opseclint: scaffolded {} starter rule(s) for {} action(s)",
        docs.len(),
        entries.len()
    );
}

/// Verify the knowledge base's Sigma detection claims against a real ruleset.
/// Audits the KB itself (no input required); a claimed detection that a genuine
/// rule for the entry's technique(s) does not fire on is surfaced as unverified.
fn run_verify(cli: &Cli) -> ExitCode {
    let kb = match kb::load(cli.platform) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("opseclint: failed to load knowledge base: {e}");
            return ExitCode::from(2);
        }
    };
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
    let mut current = verify::verify(&kb, &index, cli.platform);
    current.sigma_ref = cli.sigma_ref.clone();
    let color = !cli.no_color && std::io::stdout().is_terminal();

    // --diff: regression gate against a saved snapshot.
    if let Some(baseline_path) = &cli.diff {
        let baseline: verify::VerifyReport = match std::fs::read_to_string(baseline_path)
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "opseclint: could not read baseline '{baseline_path}': {e} \
                     (expected a file saved with --verify-detections --json)"
                );
                return ExitCode::from(2);
            }
        };
        if baseline.platform != current.platform {
            eprintln!(
                "opseclint: baseline platform '{}' does not match --platform '{}' \
                 (pass the matching .ci/verified-<platform>.json)",
                baseline.platform, current.platform
            );
            return ExitCode::from(2);
        }
        // A ruleset mismatch is a note, never a failure. Comparing a pinned
        // baseline against a *different* ruleset is exactly what the scheduled
        // drift check does on purpose, and failing here would replace its
        // findings with a configuration error. What keeps the two in step on
        // the pull-request path is scripts/sync-sigma.sh --check, which makes a
        // mismatched pair impossible to commit in the first place.
        if let (Some(base_ref), Some(curr_ref)) =
            (baseline.sigma_ref.as_deref(), current.sigma_ref.as_deref())
            && base_ref != curr_ref
        {
            eprintln!(
                "opseclint: note — the baseline was computed against ruleset {base_ref}, \
                 this run against {curr_ref}. A regression below may be upstream drift \
                 rather than a knowledge-base change."
            );
        }
        let delta = verify::compute_delta(&baseline, &current);
        if cli.json {
            println!("{}", verify::render_delta_json(&delta));
        } else {
            print!("{}", verify::render_delta(&delta, color));
        }
        if cli.ci && delta.has_regressed() {
            if !cli.json {
                eprintln!(
                    "\nopseclint: CI gate failed — a verified detection regressed from the baseline"
                );
            }
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    if cli.json {
        println!("{}", verify::render_json(&current));
    } else {
        print!("{}", verify::render(&current, color));
    }
    // Without a baseline, --ci fails when any claimed detection is contradicted
    // (a real rule for the technique exists but none fire on the command).
    let unverified = current.count(verify::Status::Unverified);
    if cli.ci && unverified > 0 {
        if !cli.json {
            eprintln!(
                "\nopseclint: CI gate failed — {unverified} claimed detection(s) do not fire"
            );
        }
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // --verify-detections audits the knowledge base itself; it needs no input,
    // so handle it before the no-input banner would otherwise short-circuit.
    if cli.verify_detections {
        return run_verify(&cli);
    }

    // With no input on an interactive terminal, greet with the banner instead
    // of blocking on a stdin read that will never arrive. Require both stdin and
    // stdout to be a TTY so a redirected `opseclint > out.txt` doesn't capture it.
    if cli.command.is_none()
        && cli.path.is_none()
        && cli.telemetry.is_none()
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
    {
        print!("{}", theme::banner(!cli.no_color));
        return ExitCode::SUCCESS;
    }

    let kb = match kb::load(cli.platform) {
        Ok(kb) => kb,
        Err(e) => {
            eprintln!("opseclint: failed to load knowledge base: {e}");
            return ExitCode::from(2);
        }
    };

    // Build the report from one of two input directions: ingested real
    // telemetry (--telemetry) or predicted from text (a file / command / stdin).
    let mut report = if let Some(tel_path) = &cli.telemetry {
        let text = match std::fs::read_to_string(tel_path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("opseclint: failed to read telemetry '{tel_path}': {e}");
                return ExitCode::from(2);
            }
        };
        let users = match &cli.users {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(t) => telemetry::parse_passwd(&t),
                Err(e) => {
                    eprintln!("opseclint: failed to read --users '{path}': {e}");
                    return ExitCode::from(2);
                }
            },
            None => Default::default(),
        };
        let ingest = match telemetry::parse_with_users(&text, cli.format, &users) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("opseclint: could not parse telemetry '{tel_path}': {e}");
                return ExitCode::from(2);
            }
        };
        if !cli.json && !cli.sarif && !cli.navigator {
            let skipped = if ingest.skipped > 0 {
                format!(", {} non-execution record(s) skipped", ingest.skipped)
            } else {
                String::new()
            };
            let standalone = if !ingest.event_observations.is_empty() {
                // These are the standalone *candidates* evaluated against the
                // event axis — not a count of findings, some may match nothing.
                format!(
                    " ({} evaluated as standalone event(s))",
                    ingest.event_observations.len()
                )
            } else {
                String::new()
            };
            eprintln!(
                "opseclint: telemetry — {} process-execution event(s) ingested{skipped}{standalone}",
                ingest.observations.len()
            );
        }
        analyzer::analyze_telemetry(&ingest, &kb)
    } else {
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

        analyzer::analyze(&input, &kb)
    };
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

        // --coverage-gaps + --scaffold: emit a starter rule for each blind spot.
        if cli.scaffold {
            let gap_ids: Vec<&str> = results
                .iter()
                .filter(|r| r.coverage == coverage::Coverage::Gap)
                .map(|r| r.rule_id.as_str())
                .collect();
            emit_scaffold(&scaffold::entries_by_ids(&kb, &gap_ids), cli.platform);
            return ExitCode::SUCCESS;
        }
        let color = !cli.no_color && std::io::stdout().is_terminal();
        let current = coverage::CoverageReport {
            platform: report.platform.clone(),
            rules_indexed: index.rules_indexed,
            results,
        };

        // --coverage-gaps + --diff: compare blind spots against a saved run.
        if let Some(baseline_path) = &cli.diff {
            let baseline: coverage::CoverageReport = match std::fs::read_to_string(baseline_path)
                .map_err(|e| e.to_string())
                .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "opseclint: could not read baseline '{baseline_path}': {e} \
                         (expected a file saved with --coverage-gaps --json)"
                    );
                    return ExitCode::from(2);
                }
            };
            let delta = coverage::compute_delta(&baseline, &current);
            if cli.json {
                println!("{}", coverage::render_delta_json(&delta));
            } else {
                print!("{}", coverage::render_delta(&delta, color));
            }
            if cli.ci && delta.has_regressed() {
                if !cli.json {
                    eprintln!("\nopseclint: CI gate failed — coverage regressed from the baseline");
                }
                return ExitCode::from(1);
            }
            return ExitCode::SUCCESS;
        }

        if cli.json {
            println!("{}", coverage::render_json(&current));
        } else {
            print!(
                "{}",
                coverage::render(
                    &current.results,
                    &current.platform,
                    current.rules_indexed,
                    color
                )
            );
        }
        // In --ci mode, fail the run when blind spots exist.
        if cli.ci && coverage::gap_count(&current.results) > 0 {
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    // --scaffold on its own: a starter rule for every modeled action found.
    if cli.scaffold {
        let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
        emit_scaffold(&scaffold::entries_by_ids(&kb, &ids), cli.platform);
        return ExitCode::SUCCESS;
    }

    if let Some(dir) = &cli.sigma {
        let product = cli.platform.sigma_product();
        match sigma::load_cached(std::path::Path::new(dir), product, !cli.no_sigma_cache) {
            Ok((index, from_cache)) => {
                let enriched = sigma::enrich(&mut report, &index, cli.platform);
                if !cli.json && !cli.sarif && !cli.navigator {
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

    // EDR telemetry mapping is additive enrichment on the standard report.
    if let Some(vendor) = cli.edr {
        let note = edr::annotate(&mut report, &[vendor]);
        if !cli.json && !cli.sarif && !cli.navigator {
            eprintln!("opseclint: edr — {note}");
        }
    }

    // --diff is its own output mode: compare against a saved report and render
    // the coverage delta instead of the standard report.
    if let Some(baseline_path) = &cli.diff {
        let baseline: model::Report = match std::fs::read_to_string(baseline_path)
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "opseclint: could not read baseline report '{baseline_path}': {e} \
                     (expected a file saved with --json)"
                );
                return ExitCode::from(2);
            }
        };
        let delta = diff::compute(&baseline, &report);
        if cli.json {
            println!("{}", diff::render_json(&delta));
        } else {
            let color = !cli.no_color && std::io::stdout().is_terminal();
            print!("{}", diff::render_human(&delta, color));
        }
        // In --ci mode, fail when the change made the input louder.
        if cli.ci && delta.is_louder() {
            if !cli.json {
                eprintln!("\nopseclint: CI gate failed — coverage is louder than the baseline");
            }
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    if cli.navigator {
        println!("{}", navigator::render(&report));
    } else if cli.sarif {
        let source_uri = cli
            .path
            .clone()
            .or_else(|| cli.telemetry.clone())
            .unwrap_or_else(|| {
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
