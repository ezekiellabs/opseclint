//! The shapes tool results take, and the reasoning behind them.
//!
//! # Why these types exist instead of returning opseclint-core's own
//!
//! An agent is not a person reading a terminal. It reads a JSON blob, keeps a
//! sentence or two, and discards the rest — and whatever it discards, it will
//! later answer questions as though it had never existed. That makes the
//! *shape* of a result load-bearing in a way it is not for the CLI, so these
//! types are designed against three specific failure modes:
//!
//! 1. **An abstention read as a negative.** `sigma_eval` is three-valued, and
//!    `INDETERMINATE` means *the input could not answer this*. Flattened to a
//!    boolean it becomes "would not fire", which reads as evidence of stealth
//!    and is nothing of the kind. So: no field anywhere in this module is a
//!    boolean about whether something was detected. The verdict is an enum with
//!    three variants, and the only boolean nearby —
//!    [`EvaluateOutput::verdict_is_conclusive`] — is *about the verdict's
//!    standing*, and its unsafe-to-ignore value is `false`.
//!
//! 2. **An empty result read as "nothing to see".** No finding means no
//!    *modeled* action matched. The knowledge base covers a bounded set, so an
//!    empty `findings` is a statement about coverage, not about the command.
//!    Every empty result therefore populates [`limits`](AnalyzeOutput::limits)
//!    saying so, and points at `describe_coverage`.
//!
//! 3. **The caveat being the part that gets dropped.** Every result leads with
//!    a `summary` field that states its own limits in prose. It is first in
//!    declaration order on purpose: serde preserves that order, so it is the
//!    first thing in the JSON a client renders as text, not a footnote below
//!    two hundred lines of findings.
//!
//! None of this can force an agent to reason well. What it can do is make the
//! uncertainty impossible to drop *silently* — an agent that reports certainty
//! here has to have discarded a field that said otherwise in plain words.

use rmcp::schemars::{self, JsonSchema};
use serde::Serialize;

use opseclint_core::{Platform, sigma_eval::Outcome};

/// The platform a request targets. Mirrors [`opseclint_core::Platform`] with
/// the serialization and schema derives an MCP tool argument needs, which keeps
/// `schemars` out of the core library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PlatformArg {
    /// Linux hosts with auditd / EDR syscall telemetry.
    Linux,
    /// Windows hosts with Sysmon / Security-log telemetry.
    Windows,
    /// macOS hosts with Endpoint Security (ESF) / unified-log telemetry.
    Macos,
}

impl PlatformArg {
    /// Every platform, in the order results should present them.
    pub const ALL: [PlatformArg; 3] =
        [PlatformArg::Linux, PlatformArg::Windows, PlatformArg::Macos];

    /// The core platform this selects.
    pub fn core(self) -> Platform {
        match self {
            PlatformArg::Linux => Platform::LinuxAuditd,
            PlatformArg::Windows => Platform::WindowsSysmon,
            PlatformArg::Macos => Platform::MacosEs,
        }
    }

    /// The full platform/telemetry-model label, e.g. `linux-auditd`.
    pub fn label(self) -> &'static str {
        match self {
            PlatformArg::Linux => "linux-auditd",
            PlatformArg::Windows => "windows-sysmon",
            PlatformArg::Macos => "macos-es",
        }
    }
}

/// An ATT&CK technique reference.
#[derive(Debug, Serialize, JsonSchema)]
pub struct TechniqueOut {
    /// The ATT&CK technique id, including any sub-technique: `T1059.001`.
    pub id: String,
    /// The technique's ATT&CK name.
    pub name: String,
}

/// A detection the knowledge base claims would fire on an action.
#[derive(Debug, Serialize, JsonSchema)]
pub struct DetectionOut {
    /// Where the detection comes from — `Sigma`, a vendor, an internal ruleset.
    pub source: String,
    /// The rule's name or title.
    pub rule: String,
    /// The knowledge base's authored confidence that this covers the action:
    /// `high`, `medium`, or `low`. A judgement, not a measurement — it has not
    /// been evaluated against any real ruleset. Use `evaluate_sigma_rule` with
    /// a rule you actually deploy to get a measured verdict.
    pub confidence: String,
}

/// One matched action.
#[derive(Debug, Serialize, JsonSchema)]
pub struct FindingOut {
    /// 1-based line of the input this came from.
    pub line: usize,
    /// The source text that produced it.
    pub source: String,
    /// The knowledge-base entry id that matched.
    pub action: String,
    /// What a defender would observe.
    pub description: String,
    /// The ATT&CK technique(s) this action implements.
    pub techniques: Vec<TechniqueOut>,
    /// The concrete host events this action produces on this platform.
    pub telemetry: Vec<String>,
    /// Detections the knowledge base claims for it. See
    /// [`DetectionOut::confidence`] — these are authored claims, not verdicts.
    pub detections: Vec<DetectionOut>,
    /// 0-100: how strongly this action surfaces in defensive telemetry. Higher
    /// = louder. **Not** a severity or a risk score — a quiet action is not a
    /// safe one, and a loud one is not a dangerous one.
    pub detectability: u8,
    /// The band `detectability` falls in: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
    pub detectability_band: String,
}

/// The result of `analyze_command`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct AnalyzeOutput {
    /// A prose statement of what this result does and does not establish. Read
    /// it before the findings, and carry it into any summary you produce.
    pub summary: String,
    /// The platform analyzed against.
    pub platform: String,
    /// How many logical lines were analyzed, including ones that matched
    /// nothing — the denominator that makes the finding count meaningful.
    pub lines_analyzed: usize,
    /// Every modeled action that matched, loudest first. Empty means no
    /// *modeled* action matched; see `limits`.
    pub findings: Vec<FindingOut>,
    /// What this answer does not establish. Never omitted, and empty only when
    /// there is genuinely nothing unresolved.
    pub limits: Vec<String>,
    /// The knowledge base's own caveat about what it assumes the host collects.
    pub knowledge_base_note: String,
}

/// The three-valued verdict of evaluating a rule. Deliberately not a boolean:
/// see the module docs.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerdictOut {
    /// The rule's condition is satisfied: it would fire on this input.
    Fires,
    /// The rule's condition is definitively not satisfied, on fields the input
    /// does supply. A real negative.
    NoFire,
    /// **Not a negative.** The rule could not be decided from this input. See
    /// `undetermined_because` for what was missing. Reporting this as "not
    /// detected" is a false claim of stealth.
    Indeterminate,
}

impl From<Outcome> for VerdictOut {
    fn from(o: Outcome) -> Self {
        match o {
            Outcome::Fires => VerdictOut::Fires,
            Outcome::NoFire => VerdictOut::NoFire,
            Outcome::Indeterminate => VerdictOut::Indeterminate,
        }
    }
}

/// Why a verdict came out `indeterminate`, split by what would fix it. The two
/// causes are different work: one is telemetry the caller would have to supply,
/// the other is evaluator features nobody has written yet.
#[derive(Debug, Serialize, JsonSchema)]
pub struct UndeterminedBecause {
    /// Fields the rule keys on that a command line cannot supply
    /// (`ParentImage`, `User`, `IntegrityLevel`, a hash, a registry value).
    /// Supply a real recorded event and these resolve.
    pub missing_fields: Vec<String>,
    /// Sigma modifiers this evaluator does not implement (`base64offset`,
    /// `windash`, …). No input fixes these.
    pub blocking_modifiers: Vec<String>,
    /// The rule asserts a field is *absent* (`field: null`), which cannot be
    /// confirmed from a command line.
    pub asserts_field_absent: bool,
}

/// The result of `evaluate_sigma_rule`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct EvaluateOutput {
    /// A prose statement of the verdict and its standing. Read it first.
    pub summary: String,
    /// The evaluated rule's UUID.
    pub rule_id: String,
    /// The evaluated rule's title.
    pub rule_title: String,
    /// The three-valued verdict. See [`VerdictOut`] before reducing it.
    pub verdict: VerdictOut,
    /// `false` exactly when `verdict` is `indeterminate`. Provided so the
    /// abstention is checkable in one field — if you branch on anything here,
    /// branch on this, and treat `false` as "no answer", never as "no".
    pub verdict_is_conclusive: bool,
    /// Present only when the verdict is `indeterminate`.
    pub undetermined_because: Option<UndeterminedBecause>,
    /// What this answer does not establish.
    pub limits: Vec<String>,
}

/// One modeled action, as returned by a technique lookup.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ActionOut {
    /// The knowledge-base entry id.
    pub action: String,
    /// What a defender would observe.
    pub description: String,
    /// A representative command line this action matches.
    pub example: Option<String>,
    /// The concrete host events it produces.
    pub telemetry: Vec<String>,
    /// Detections the knowledge base claims. Authored claims, not verdicts.
    pub detections: Vec<DetectionOut>,
    /// 0-100 detectability. See [`FindingOut::detectability`].
    pub detectability: u8,
}

/// What one platform's knowledge base has for a technique.
#[derive(Debug, Serialize, JsonSchema)]
pub struct PlatformMatches {
    /// The platform/telemetry model, e.g. `windows-sysmon`.
    pub platform: String,
    /// Modeled actions implementing the requested technique. Empty means this
    /// platform's base models none — which is a fact about the base, not about
    /// the technique's detectability.
    pub actions: Vec<ActionOut>,
}

/// The result of `lookup_technique`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct LookupOutput {
    /// A prose statement of what was found and what that means. Read it first.
    pub summary: String,
    /// The technique id as requested.
    pub technique_id: String,
    /// Per-platform results, in a stable order.
    pub platforms: Vec<PlatformMatches>,
    /// What this answer does not establish.
    pub limits: Vec<String>,
}

/// What one platform's knowledge base models.
#[derive(Debug, Serialize, JsonSchema)]
pub struct PlatformCoverage {
    /// The platform/telemetry model, e.g. `linux-auditd`.
    pub platform: String,
    /// How many actions this base models.
    pub modeled_actions: usize,
    /// Every ATT&CK technique id any modeled action implements, sorted and
    /// deduplicated. A technique absent from this list has no coverage here.
    pub techniques: Vec<String>,
    /// The base's own caveat about what it assumes the host collects.
    pub note: String,
}

/// The result of `describe_coverage`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CoverageOutput {
    /// A prose statement of what this covers and what it does not. Read first.
    pub summary: String,
    /// Per-platform coverage, in a stable order.
    pub platforms: Vec<PlatformCoverage>,
    /// What this answer does not establish.
    pub limits: Vec<String>,
}

/// The sentence appended to every result that reports on predicted (rather than
/// observed) telemetry. Stated once here so it cannot drift between tools.
pub const PREDICTIVE_LIMIT: &str = "This is a static prediction from a command line, not a record of what a sensor logged. It describes what a correctly configured host would emit — not what this host actually collects.";

/// The sentence every empty result carries.
pub fn no_match_limit(platform: &str, modeled: usize) -> String {
    format!(
        "No modeled action matched. The {platform} knowledge base models {modeled} actions; an absent finding means this input is outside that set, and is NOT evidence that the action is invisible or undetected. Call describe_coverage to see what is modeled."
    )
}
