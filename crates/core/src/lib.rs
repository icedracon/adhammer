//! Shared domain model: SIDs, GUIDs, collected AD objects, findings, risk config.
//! Everything above this crate (checks, graph, report) speaks in these types.

pub mod finding;
pub mod object;
pub mod redact;
pub mod sanitize;
pub mod scope;
pub mod secret_write;
pub mod sid;
pub mod snapshot;
pub mod speed;

/// Build-time provenance (git commit + date), captured by `build.rs`.
pub mod build {
    include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

    /// One-line version + provenance, e.g. `1.5.2 (abc123def456, 2026-09-18)`.
    pub fn long_version() -> String {
        format!("{} ({GIT_SHA}, {COMMIT_DATE})", env!("CARGO_PKG_VERSION"))
    }
}

pub use finding::{
    AttackResult, Category, Evidence, Finding, Mitre, NextCommand, Severity, WireDirection,
    WireExchange, WireLayer,
};
pub use object::AdObject;
pub use redact::{Redacted, SecretBytes, SecretString};
pub use sanitize::sanitize_terminal_output;
pub use scope::{
    Capability, CapabilityKind, CheckClass, CheckId, EngagementScope, FindingStatus, NextAction,
    ScopeError, ScopeTarget, SecretHandle,
};
pub use secret_write::{write_secret_artifact, SecretArtifact};
pub use sid::{Guid, Sid};
pub use snapshot::{SearchOp, Snapshot};
