//! Core data types: the knowledge base schema (deserialized from
//! `data/knowledge.json`) and the runtime analysis results.

use serde::{Deserialize, Serialize};

use crate::matcher::Matcher;

/// A single ATT&CK technique reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    /// The ATT&CK technique id, including any sub-technique: `T1059.001`.
    pub id: String,
    /// The technique's ATT&CK name, e.g. `PowerShell`.
    pub name: String,
}

/// A representative detection signal (e.g. a Sigma rule the action would trip).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Where the detection comes from — `Sigma`, a vendor, an internal ruleset.
    pub source: String,
    /// The rule's name or title. Representative of published logic rather than a
    /// literal rule id, unless the finding was enriched from a real ruleset.
    pub rule: String,
    /// How confident the knowledge base is that this detection covers the
    /// action: `high`, `medium`, or `low`. An authored judgement, not a measured
    /// one — [`verdict`](Detection::verdict) is the measured field.
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
    /// Short event-class tag: `network`, `file`, or `registry`.
    pub class: String,
    /// The human-readable phrase describing what was observed.
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
    /// Stable kebab-case identifier, unique within its knowledge base. Surfaces
    /// as a finding's [`rule_id`](Finding::rule_id).
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
    /// One line describing what a defender would observe — written from the
    /// defender's side, not the operator's.
    pub description: String,
    /// The ATT&CK technique(s) this action implements.
    pub techniques: Vec<Technique>,
    /// The concrete host events this action produces, in the platform's own
    /// vocabulary (`Sysmon EID 1`, `auditd execve`, `ESF NOTIFY_EXEC`, …).
    #[serde(default)]
    pub telemetry: Vec<String>,
    /// Representative detections that would fire. Authored claims — run
    /// `--verify-detections` against a real ruleset to find out which hold.
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
    /// The platform this base models, as a display string.
    pub platform: String,
    /// The base's own caveat: what it assumes about the host's collection, and
    /// what it does not claim. Carried into every [`Report`] so the caveat
    /// travels with the result instead of living in documentation.
    #[serde(default)]
    pub note: String,
    /// Every modeled action, in file order.
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
            if let Some(event) = &e.matcher.event {
                event
                    .validate()
                    .map_err(|m| format!("entry `{}`: {m}", e.id))?;
                // The `event` counterpart of the regex/`example` rule above. A
                // command `example` cannot stand in for an event, so instead of
                // widening the entry schema the representative must be derivable
                // from the predicate's own literals — otherwise the entry could
                // never be checked against itself.
                if e.matcher.representative_event().is_none() {
                    return Err(format!(
                        "entry `{}` has an `event` axis with no derivable representative \
                         (a bare `regex` or a purely-negated predicate); pair it with a literal leaf",
                        e.id
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Detectability bucket derived from a numeric noise score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Noise 0-24: little or nothing distinctive reaches the sensor.
    Low,
    /// Noise 25-49: observable, but unlikely to stand out on its own.
    Medium,
    /// Noise 50-74: distinctive telemetry a tuned ruleset should catch.
    High,
    /// Noise 75-100: loud, and widely covered by published detections.
    Critical,
}

impl Severity {
    /// The bucket a 0-100 detectability score falls in.
    pub fn from_noise(noise: u8) -> Self {
        match noise {
            0..=24 => Severity::Low,
            25..=49 => Severity::Medium,
            50..=74 => Severity::High,
            _ => Severity::Critical,
        }
    }

    /// The uppercase display label: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
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
    /// 1-based line of the input this finding came from. For ingested
    /// telemetry, the 1-based record number instead.
    pub line: usize,
    /// The source text that produced the finding — the command line as written.
    pub source: String,
    /// The [`KbEntry::id`] that matched.
    pub rule_id: String,
    /// What a defender would observe, from the matched entry.
    pub description: String,
    /// The ATT&CK technique(s) this action implements.
    pub techniques: Vec<Technique>,
    /// The concrete host events this action produces.
    pub telemetry: Vec<String>,
    /// Detections that would fire. Authored claims from the knowledge base
    /// unless the report was enriched from a real ruleset, in which case each
    /// carries a [`verdict`](Detection::verdict).
    pub detections: Vec<Detection>,
    /// EDR sensor-event mappings, populated only when `--edr` is requested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edr: Vec<EdrMapping>,
    /// Non-execution events (network / file / registry) correlated by process id
    /// to the execution this finding came from — confirmed secondary telemetry.
    /// Populated only for ingested telemetry; empty for predictive analysis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_side_effects: Vec<SideEffect>,
    /// Detectability on a 0-100 scale: how strongly this action surfaces in
    /// defensive telemetry. Higher = louder. Not a severity or a risk score —
    /// a quiet action is not a safe one.
    pub noise: u8,
    /// The bucket [`noise`](Finding::noise) falls in.
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
    /// The platform analyzed against, from [`KnowledgeBase::platform`].
    pub platform: String,
    /// The knowledge base's caveat about what it assumes and does not claim,
    /// carried through from [`KnowledgeBase::note`]. Surface it alongside the
    /// findings: it is what keeps an empty `findings` from reading as proof
    /// that nothing would be seen.
    #[serde(default)]
    pub note: String,
    /// Every match, deduplicated per line and ranked loudest-first.
    ///
    /// An empty vector means no *modeled* action matched — the knowledge base
    /// covers a bounded set, so this is not evidence that the input is
    /// invisible.
    pub findings: Vec<Finding>,
    /// The loudest [`Finding::noise`] in the report, or 0 when there are none.
    pub max_noise: u8,
    /// How many logical lines were analyzed, including ones that matched
    /// nothing — the denominator that makes a finding count meaningful.
    #[serde(default)]
    pub lines_analyzed: usize,
}

impl Report {
    /// The bucket of the loudest finding in this report.
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

    #[test]
    fn validate_requires_a_derivable_event_representative() {
        // A bare `regex` event predicate cannot be reversed into a field value, so
        // the entry could never be checked against itself.
        assert!(
            kb_with(
                r#"{ "event": { "class": "file", "field": "TargetFilename", "regex": "^/etc/" } }"#,
                None
            )
            .validate()
            .is_err()
        );
        // A purely-negated predicate is underivable for the same reason.
        assert!(
            kb_with(
                r#"{ "event": { "class": "file",
                                "not": { "field": "TargetFilename", "eq": "/etc/shadow" } } }"#,
                None
            )
            .validate()
            .is_err()
        );
        // Pairing the pattern with a literal makes it derivable, and accepted.
        assert!(
            kb_with(
                r#"{ "event": { "class": "file", "all": [
                    { "field": "TargetFilename", "prefix": "/etc/" },
                    { "field": "TargetFilename", "regex": "^/etc/" } ] } }"#,
                None
            )
            .validate()
            .is_ok()
        );
    }
}
