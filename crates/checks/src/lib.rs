//! The rule engine. Each `Check` reads the immutable `Snapshot` (+ the prebuilt
//! `ControlGraph` for path-based rules) and emits `Finding`s. Registry order defines
//! nothing — findings are scored and sorted downstream.
//!
//! Representative rules are implemented in full; the rest are registered stubs with a
//! TODO so the category coverage is visible and wiring is done.

use adhammer_core::snapshot::Snapshot;
use adhammer_core::Finding;
use adhammer_graph::ControlGraph;

pub mod util;
pub mod privileged;
pub mod privileged_extra;
pub mod stale;
pub mod anomalies;
pub mod anomalies_extra;
pub mod adcs;
pub mod trusts;

/// A single rule. Kept object-safe so the registry is `Vec<Box<dyn Check>>`.
pub trait Check {
    fn id(&self) -> &'static str;
    fn run(&self, snap: &Snapshot, graph: &ControlGraph) -> Vec<Finding>;
}

/// Build the default rule set. Add new rules here.
pub fn registry() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(privileged::AsrepRoastable),
        Box::new(privileged::KerberoastableAdmin),
        Box::new(privileged::UnconstrainedDelegation),
        Box::new(privileged::DcsyncPath),
        Box::new(privileged::ShadowCredentialsPath),
        Box::new(privileged_extra::SensitiveGroups),
        Box::new(privileged_extra::GmsaReadableByBroad),
        Box::new(privileged_extra::SidHistory),
        Box::new(privileged_extra::RbcdConfigured),
        Box::new(privileged_extra::LapsCoverage),
        Box::new(privileged_extra::PasswordNotRequired),
        Box::new(anomalies::MachineAccountQuota),
        Box::new(anomalies::KrbtgtPasswordAge),
        Box::new(anomalies::ReversibleEncryption),
        Box::new(anomalies::Rc4Kerberos),
        Box::new(anomalies::BadSuccessor),
        Box::new(anomalies_extra::WeakPasswordPolicy),
        Box::new(anomalies_extra::DsHeuristics),
        Box::new(anomalies_extra::PreWindows2000Compat),
        Box::new(anomalies_extra::ProtectedUsersUnused),
        Box::new(anomalies_extra::GuestEnabled),
        Box::new(adcs::VulnerableCertTemplates),
        Box::new(trusts::SidFilteringDisabled),
        Box::new(trusts::SelectiveAuthDisabled),
        Box::new(trusts::TgtDelegationAcrossTrust),
        Box::new(trusts::Rc4Trust),
        Box::new(trusts::TransitiveExternalTrust),
        Box::new(stale::InactiveAccounts),
        Box::new(stale::UnsupportedOs),
        Box::new(stale::PasswordNeverChanged),
        Box::new(stale::StaleComputers),
        Box::new(stale::MachinePasswordAge),
        Box::new(stale::DuplicateSpn),
    ]
}

/// Run every rule and flatten. `graph` is built once by the caller.
pub fn run_all(snap: &Snapshot, graph: &ControlGraph) -> Vec<Finding> {
    let mut out: Vec<Finding> = registry().iter().flat_map(|c| c.run(snap, graph)).collect();
    out.sort_by(|a, b| b.score().cmp(&a.score()));
    out
}
