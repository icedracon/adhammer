//! Shared domain model: SIDs, GUIDs, collected AD objects, findings, risk config.
//! Everything above this crate (checks, graph, report) speaks in these types.
//!
//! 1.5.3 audit F3: this crate cannot be `forbid(unsafe_code)` because
//! `secret_write.rs` holds the Windows FFI path (`CreateFileW` + `LocalFree` +
//! `from_raw_handle`) that owns the atomic O_CREAT|O_EXCL secure-file-write.
//! Every non-`core` library crate in the workspace is `forbid(unsafe_code)`
//! and this crate's `unsafe` is confined to that one Windows-only function.

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
    /// On a crates.io build (no `.git/` in the registry tarball), both fields are
    /// literal `"unknown"` — drop the suffix entirely instead of printing
    /// `1.6.0 (unknown, unknown)`, which reads as broken metadata.
    pub fn long_version() -> String {
        let base = env!("CARGO_PKG_VERSION");
        if GIT_SHA == "unknown" && COMMIT_DATE == "unknown" {
            base.to_string()
        } else {
            format!("{base} ({GIT_SHA}, {COMMIT_DATE})")
        }
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
