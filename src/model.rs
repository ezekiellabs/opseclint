//! Core data types: the knowledge base schema (deserialized from
//! `data/knowledge.json`) and the runtime analysis results.

use serde::{Deserialize, Serialize};

/// A single ATT&CK technique reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
}

/// A representative detection signal (e.g. a Sigma rule the action would trip).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub source: String,
    pub rule: String,
    pub confidence: String,
    /// When enriched from a real ruleset, whether the rule would actually fire
    /// on the matched command: `fires`, `no-fire`, or `indeterminate (…)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
}

/// One entry in the knowledge base: a rule that maps a shell action to the
/// techniques it implements, the telemetry it emits, and the detections that
/// would fire. An entry matches either by `command` (with optional
/// `args_contains` / `raw_contains` refinements) or by `raw_contains` alone.
#[derive(Debug, Clone, Deserialize)]
pub struct KbEntry {
    pub id: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args_contains: Option<String>,
    #[serde(default)]
    pub raw_contains: Option<String>,
    pub description: String,
    pub techniques: Vec<Technique>,
    #[serde(default)]
    pub telemetry: Vec<String>,
    #[serde(default)]
    pub detections: Vec<Detection>,
    /// Detectability on a 0-100 scale: how likely this action is to surface in
    /// defensive telemetry. Higher = louder.
    pub noise: u8,
}

/// The deserialized knowledge base.
#[derive(Debug, Clone, Deserialize)]
pub struct KnowledgeBase {
    pub platform: String,
    #[serde(default)]
    pub note: String,
    pub entries: Vec<KbEntry>,
}

/// Detectability bucket derived from a numeric noise score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_noise(noise: u8) -> Self {
        match noise {
            0..=24 => Severity::Low,
            25..=49 => Severity::Medium,
            50..=74 => Severity::High,
            _ => Severity::Critical,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Tokyo Night ANSI color code for terminal rendering.
    pub fn color(self) -> &'static str {
        match self {
            Severity::Low => crate::theme::CYAN,
            Severity::Medium => crate::theme::YELLOW,
            Severity::High => crate::theme::ORANGE,
            Severity::Critical => crate::theme::RED,
        }
    }
}

/// The sensor events one EDR product would surface for a finding, derived by
/// classifying its native telemetry into event classes (see `edr.rs`).
#[derive(Debug, Clone, Serialize)]
pub struct EdrMapping {
    /// Human-readable vendor label, e.g. "CrowdStrike Falcon".
    pub vendor: String,
    /// Sensor events / hunting tables for this vendor, deduplicated.
    pub events: Vec<String>,
}

/// A single detection-coverage finding tied to a source line.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub line: usize,
    pub source: String,
    pub rule_id: String,
    pub description: String,
    pub techniques: Vec<Technique>,
    pub telemetry: Vec<String>,
    pub detections: Vec<Detection>,
    /// EDR sensor-event mappings, populated only when `--edr` is requested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edr: Vec<EdrMapping>,
    pub noise: u8,
    pub severity: Severity,
    /// The command this finding was matched from, kept for rule-logic
    /// evaluation (coverage gaps). Not serialized.
    #[serde(skip)]
    pub matched_command: Option<crate::parser::Command>,
}

/// The full report for an analyzed input.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub platform: String,
    pub note: String,
    pub findings: Vec<Finding>,
    pub max_noise: u8,
    pub lines_analyzed: usize,
}

impl Report {
    pub fn max_severity(&self) -> Severity {
        Severity::from_noise(self.max_noise)
    }
}
