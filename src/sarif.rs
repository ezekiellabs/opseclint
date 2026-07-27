//! SARIF 2.1.0 output, so opseclint findings can be uploaded to GitHub code
//! scanning (the Security tab) or consumed by any SARIF-aware tool.

use serde::Serialize;

use crate::model::{Report, Severity};

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFO_URI: &str = "https://github.com/ezekiellabs/opseclint";

#[derive(Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
struct Driver {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct Rule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: Text,
    #[serde(rename = "fullDescription")]
    full_description: Text,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    properties: RuleProps,
}

#[derive(Serialize)]
struct RuleProps {
    tags: Vec<String>,
    #[serde(rename = "security-severity")]
    security_severity: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: Text,
    locations: Vec<Location>,
}

#[derive(Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: usize,
}

#[derive(Serialize)]
struct Text {
    text: String,
}

/// SARIF `level`: note/warning/error. GitHub derives the High/Medium/Low label
/// from the numeric `security-severity` property; `level` drives alert kind.
fn level_for(sev: Severity) -> &'static str {
    match sev {
        Severity::Low | Severity::Medium => "note",
        Severity::High => "warning",
        Severity::Critical => "error",
    }
}

/// ATT&CK technique URL, e.g. `T1003.008` -> `.../techniques/T1003/008`.
fn attack_url(technique_id: &str) -> String {
    format!(
        "https://attack.mitre.org/techniques/{}",
        technique_id.replace('.', "/")
    )
}

/// Build a SARIF log from a report. `source_uri` is the path attributed to the
/// findings (the analyzed file, or a placeholder for stdin / -c input).
pub fn build(report: &Report, source_uri: &str) -> SarifLog {
    // One rule per distinct fired rule id, in first-seen order.
    let mut rules: Vec<Rule> = Vec::new();
    let mut results: Vec<SarifResult> = Vec::new();

    for f in &report.findings {
        if !rules.iter().any(|r| r.id == f.rule_id) {
            let mut tags = vec!["security".to_string(), "att&ck".to_string()];
            tags.extend(f.techniques.iter().map(|t| t.id.clone()));
            let technique_line = f
                .techniques
                .iter()
                .map(|t| format!("{} {}", t.id, t.name))
                .collect::<Vec<_>>()
                .join("; ");
            rules.push(Rule {
                id: f.rule_id.clone(),
                name: f.rule_id.clone(),
                short_description: Text {
                    text: f.description.clone(),
                },
                full_description: Text {
                    text: if technique_line.is_empty() {
                        f.description.clone()
                    } else {
                        format!("{} (ATT&CK: {})", f.description, technique_line)
                    },
                },
                help_uri: f.techniques.first().map(|t| attack_url(&t.id)),
                properties: RuleProps {
                    tags,
                    security_severity: format!("{:.1}", f.noise as f32 / 10.0),
                },
            });
        }

        let mut msg = f.description.clone();
        for t in &f.techniques {
            msg.push_str(&format!("\nATT&CK: {} {}", t.id, t.name));
        }
        for d in &f.detections {
            msg.push_str(&format!(
                "\nDetection: {}: {} ({} confidence)",
                d.source, d.rule, d.confidence
            ));
        }
        msg.push_str(&format!(
            "\nDetectability: {} ({})",
            f.noise,
            f.severity.label()
        ));

        results.push(SarifResult {
            rule_id: f.rule_id.clone(),
            level: level_for(f.severity),
            message: Text { text: msg },
            locations: vec![Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation {
                        uri: source_uri.to_string(),
                    },
                    region: Region {
                        start_line: f.line.max(1),
                    },
                },
            }],
        });
    }

    SarifLog {
        schema: SCHEMA,
        version: "2.1.0",
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "opseclint",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: INFO_URI,
                    rules,
                },
            },
            results,
        }],
    }
}

/// Render a report as a SARIF 2.1.0 JSON string.
pub fn render(report: &Report, source_uri: &str) -> String {
    serde_json::to_string_pretty(&build(report, source_uri))
        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyzer, kb};

    #[test]
    fn sarif_is_valid_json_with_expected_shape() {
        let kb = kb::load(kb::Platform::LinuxAuditd).unwrap();
        let report = analyzer::analyze("cat /etc/shadow", &kb);
        let out = render(&report, "examples/recon.sh");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();

        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "opseclint");
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "shadow-read");
        assert_eq!(result["level"], "error");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "examples/recon.sh"
        );
    }
}
