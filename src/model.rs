//! Core data types: the knowledge base schema (deserialized from
//! `data/knowledge.json`) and the runtime analysis results.

use serde::{Deserialize, Serialize};

use crate::matcher::Matcher;

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

/// A non-execution event (network / file / registry) correlated back — by
/// process id — to the execution that caused it, confirming a piece of the
/// telemetry the entry predicts. `class` is a short tag (`network` / `file` /
/// `registry`); `detail` is the human phrase rendered under the finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideEffect {
    pub class: String,
    pub detail: String,
}

/// One entry in the knowledge base: a rule that maps a shell action to the
/// techniques it implements, the telemetry it emits, and the detections that
/// would fire.
///
/// Matching is driven by the structured [`Matcher`] under the required `match`
/// key. (The legacy substring fields `command` / `args_contains` /
/// `raw_contains` were removed once every knowledge base finished migrating.)
#[derive(Debug, Clone, Deserialize)]
pub struct KbEntry {
    pub id: String,
    /// The structured matcher that decides whether this entry applies to a line.
    #[serde(rename = "match")]
    pub matcher: Matcher,
    /// A representative command line this entry should match, used to synthesize
    /// an example event for `--verify-detections` / `--scaffold` and to drive the
    /// self-consistency guard. Required for entries whose matcher uses a `regex`
    /// leaf (a pattern cannot be reversed into a literal); optional otherwise,
    /// where it overrides the literal-derived representative.
    #[serde(default)]
    pub example: Option<String>,
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

impl KbEntry {
    /// A representative command line this entry matches: the author-supplied
    /// `example` when present, otherwise one derived from the matcher's literals.
    /// `None` only for a bare matcher with neither — which the self-consistency
    /// guard rejects.
    pub fn representative_line(&self) -> Option<String> {
        self.example
            .clone()
            .or_else(|| self.matcher.representative_line())
    }
}

/// The deserialized knowledge base.
#[derive(Debug, Clone, Deserialize)]
pub struct KnowledgeBase {
    pub platform: String,
    #[serde(default)]
    pub note: String,
    pub entries: Vec<KbEntry>,
}

impl KnowledgeBase {
    /// Enforce cross-field invariants after deserialization: an entry whose
    /// matcher uses a `regex` leaf must supply an `example` (a pattern cannot be
    /// reversed into a representative for verification/scaffolding).
    pub fn validate(&self) -> Result<(), String> {
        for e in &self.entries {
            if e.matcher.has_regex() && e.example.is_none() {
                return Err(format!(
                    "entry `{}` uses a regex leaf but has no `example`",
                    e.id
                ));
            }
        }
        Ok(())
    }
}

/// Detectability bucket derived from a numeric noise score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrMapping {
    /// Human-readable vendor label, e.g. "CrowdStrike Falcon".
    pub vendor: String,
    /// Sensor events / hunting tables for this vendor, deduplicated.
    pub events: Vec<String>,
}

/// A single detection-coverage finding tied to a source line.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Non-execution events (network / file / registry) correlated by process id
    /// to the execution this finding came from — confirmed secondary telemetry.
    /// Populated only for ingested telemetry; empty for predictive analysis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_side_effects: Vec<SideEffect>,
    pub noise: u8,
    pub severity: Severity,
    /// The command this finding was matched from, kept for rule-logic
    /// evaluation (coverage gaps). Not serialized.
    #[serde(skip)]
    pub matched_command: Option<crate::parser::Command>,
    /// The real recorded event fields when this finding came from ingested
    /// telemetry, so Sigma evaluation can consult fields a command line cannot
    /// supply (`ParentImage`, `User`, `IntegrityLevel`, …). `None` for predictive
    /// (text) analysis. Shared (`Arc`) so the several findings a single record
    /// produces point at one event map rather than each deep-cloning it. Not
    /// serialized.
    #[serde(skip)]
    pub observed_event: Option<std::sync::Arc<std::collections::HashMap<String, String>>>,
}

/// The full report for an analyzed input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub platform: String,
    #[serde(default)]
    pub note: String,
    pub findings: Vec<Finding>,
    pub max_noise: u8,
    #[serde(default)]
    pub lines_analyzed: usize,
}

impl Report {
    pub fn max_severity(&self) -> Severity {
        Severity::from_noise(self.max_noise)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kb_with(matcher_json: &str, example: Option<&str>) -> KnowledgeBase {
        let matcher: Matcher = serde_json::from_str(matcher_json).expect("matcher parses");
        KnowledgeBase {
            platform: "linux".into(),
            note: String::new(),
            entries: vec![KbEntry {
                id: "x".into(),
                matcher,
                example: example.map(str::to_string),
                description: "d".into(),
                techniques: vec![],
                telemetry: vec![],
                detections: vec![],
                noise: 10,
            }],
        }
    }

    #[test]
    fn validate_requires_example_for_regex_entries() {
        // A regex entry without an example is rejected...
        assert!(
            kb_with(r#"{ "line": { "regex": "foo" } }"#, None)
                .validate()
                .is_err()
        );
        // ...with one it is accepted, and non-regex entries never need one.
        assert!(
            kb_with(r#"{ "line": { "regex": "foo" } }"#, Some("foobar"))
                .validate()
                .is_ok()
        );
        assert!(
            kb_with(r#"{ "line": { "contains": "foo" } }"#, None)
                .validate()
                .is_ok()
        );
    }
}
