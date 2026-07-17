//! Shared domain model: SIDs, GUIDs, collected AD objects, findings, risk config.
//! Everything above this crate (checks, graph, report) speaks in these types.

pub mod sid;
pub mod object;
pub mod finding;
pub mod snapshot;

pub use finding::{Category, Finding, Mitre, Severity};
pub use object::AdObject;
pub use sid::{Guid, Sid};
pub use snapshot::Snapshot;
