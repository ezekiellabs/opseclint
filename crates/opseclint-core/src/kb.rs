//! Knowledge-base loading and matching. Each platform's KB is embedded at
//! compile time so the tool ships as a single self-contained binary.

use crate::model::KnowledgeBase;

const EMBEDDED_LINUX: &str = include_str!("../data/knowledge.json");
const EMBEDDED_WINDOWS: &str = include_str!("../data/knowledge-windows.json");
const EMBEDDED_MACOS: &str = include_str!("../data/knowledge-macos.json");

/// The host platform / telemetry model an analysis targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Platform {
    /// Linux hosts with auditd / EDR syscall telemetry.
    #[cfg_attr(feature = "clap", value(name = "linux-auditd", alias = "linux"))]
    LinuxAuditd,
    /// Windows hosts with Sysmon / Security-log telemetry.
    #[cfg_attr(feature = "clap", value(name = "windows-sysmon", alias = "windows"))]
    WindowsSysmon,
    /// macOS hosts with Endpoint Security (ESF) / unified-log telemetry.
    #[cfg_attr(feature = "clap", value(name = "macos-es", alias = "macos"))]
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

/// Why a knowledge base failed to load.
///
/// The two cases are different kinds of wrong and a caller may want to treat
/// them differently: [`Parse`](KbError::Parse) means the JSON does not describe
/// a knowledge base at all, while [`Invalid`](KbError::Invalid) means it
/// deserialized fine but breaks an invariant the analysis relies on. Neither is
/// reachable from [`load`] with the embedded bases — those are validated by the
/// test suite — but both are reachable once you deserialize a
/// [`KnowledgeBase`] of your own and call [`KnowledgeBase::validate`].
#[derive(Debug)]
pub enum KbError {
    /// The JSON could not be deserialized into a [`KnowledgeBase`].
    Parse(serde_json::Error),
    /// The knowledge base deserialized but violates a cross-field invariant.
    /// Carries the offending entry's id and what it broke.
    Invalid(String),
}

impl std::fmt::Display for KbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KbError::Parse(e) => write!(f, "malformed knowledge base: {e}"),
            KbError::Invalid(m) => write!(f, "invalid knowledge base: {m}"),
        }
    }
}

impl std::error::Error for KbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KbError::Parse(e) => Some(e),
            KbError::Invalid(_) => None,
        }
    }
}

impl From<serde_json::Error> for KbError {
    fn from(e: serde_json::Error) -> Self {
        KbError::Parse(e)
    }
}

/// Load the embedded knowledge base for a platform.
///
/// Deserialization is followed by a semantic validation pass (see
/// [`KnowledgeBase::validate`]). No I/O: every platform's base is embedded at
/// compile time, so this is a parse of a `&'static str` and cannot fail for any
/// reason outside this crate.
pub fn load(platform: Platform) -> Result<KnowledgeBase, KbError> {
    let raw = match platform {
        Platform::LinuxAuditd => EMBEDDED_LINUX,
        Platform::WindowsSysmon => EMBEDDED_WINDOWS,
        Platform::MacosEs => EMBEDDED_MACOS,
    };
    let kb: KnowledgeBase = serde_json::from_str(raw)?;
    kb.validate().map_err(KbError::Invalid)?;
    Ok(kb)
}
