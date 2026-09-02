//! Shared domain model: SIDs, GUIDs, collected AD objects, findings, risk config.
//! Everything above this crate (checks, graph, report) speaks in these types.

pub mod finding;
pub mod object;
pub mod redact;
pub mod sanitize;
pub mod sid;
pub mod snapshot;

pub use finding::{
    AttackResult, Category, Evidence, Finding, Mitre, Severity, WireDirection, WireExchange,
    WireLayer,
};
pub use object::AdObject;
pub use redact::{Redacted, SecretBytes, SecretString};
pub use sanitize::sanitize_terminal_output;
pub use sid::{Guid, Sid};
pub use snapshot::{SearchOp, Snapshot};
