//! Knowledge-base loading and matching. Each platform's KB is embedded at
//! compile time so the tool ships as a single self-contained binary.

use clap::ValueEnum;

use crate::model::KnowledgeBase;

const EMBEDDED_LINUX: &str = include_str!("../data/knowledge.json");
const EMBEDDED_WINDOWS: &str = include_str!("../data/knowledge-windows.json");
const EMBEDDED_MACOS: &str = include_str!("../data/knowledge-macos.json");

/// The host platform / telemetry model an analysis targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Platform {
    /// Linux hosts with auditd / EDR syscall telemetry.
    #[value(name = "linux-auditd", alias = "linux")]
    LinuxAuditd,
    /// Windows hosts with Sysmon / Security-log telemetry.
    #[value(name = "windows-sysmon", alias = "windows")]
    WindowsSysmon,
    /// macOS hosts with Endpoint Security (ESF) / unified-log telemetry.
    #[value(name = "macos-es", alias = "macos")]
    MacosEs,
}

impl Platform {
    /// The Sigma `logsource.product` value to filter rules by for this platform.
    pub fn sigma_product(self) -> &'static str {
        match self {
            Platform::LinuxAuditd => "linux",
            Platform::WindowsSysmon => "windows",
            Platform::MacosEs => "macos",
        }
    }
}

/// Load the embedded knowledge base for a platform.
pub fn load(platform: Platform) -> Result<KnowledgeBase, serde_json::Error> {
    let raw = match platform {
        Platform::LinuxAuditd => EMBEDDED_LINUX,
        Platform::WindowsSysmon => EMBEDDED_WINDOWS,
        Platform::MacosEs => EMBEDDED_MACOS,
    };
    serde_json::from_str(raw)
}
