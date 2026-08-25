//! The rule engine. Each `Check` reads the immutable `Snapshot` (+ the prebuilt
//! `ControlGraph` for path-based rules) and emits `Finding`s.

use adhammer_core::snapshot::Snapshot;
use adhammer_core::Finding;
use adhammer_graph::ControlGraph;

pub mod adcs;
pub mod anomalies;
pub mod anomalies_extra;
pub mod esc_registry;
pub mod hygiene;
pub mod privileged;
pub mod privileged_extra;
pub mod rules;
pub mod stale;
pub mod trusts;
pub mod util;

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
        Box::new(privileged_extra::ConstrainedDelegation),
        Box::new(privileged_extra::KerberoastableUsers),
        Box::new(privileged_extra::AdminsDelegatable),
        Box::new(privileged_extra::KeyCredentialOnAdmin),
        Box::new(privileged_extra::BroadInTier0Group),
        Box::new(privileged_extra::KeyAdminsPopulated),
        Box::new(privileged_extra::AdminNotProtected),
        Box::new(privileged_extra::ForeignPrincipalInPrivGroup),
        Box::new(privileged_extra::ComputerInPrivGroup),
        Box::new(privileged_extra::ConstrainedToDc),
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
        Box::new(anomalies_extra::PasswordInDescription),
        Box::new(anomalies_extra::WeakFineGrainedPolicy),
        Box::new(anomalies_extra::CleartextSecretAttr),
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
        Box::new(stale::LapsExpired),
        Box::new(stale::DuplicateSpn),
        Box::new(hygiene::PrivilegedPasswordNeverExpires),
        Box::new(hygiene::DesOnlyAccounts),
        Box::new(hygiene::ObsoleteFunctionalLevel),
        Box::new(hygiene::DisabledPrivileged),
        Box::new(hygiene::NeverLoggedOn),
        Box::new(hygiene::PrimaryGroupPrivileged),
        Box::new(hygiene::DormantPrivileged),
        Box::new(hygiene::DefaultAdministratorActive),
    ]
}

/// Run every rule and flatten. `graph` is built once by the caller.
pub fn run_all(snap: &Snapshot, graph: &ControlGraph) -> Vec<Finding> {
    let mut out: Vec<Finding> = registry().iter().flat_map(|c| c.run(snap, graph)).collect();
    out.sort_by_key(|f| std::cmp::Reverse(f.score()));
    out
}

/// Run every rule and report per-check coverage: `(check id, findings it produced)`, in
/// `registry()` order. An empty Vec means the check ran and the target is **not** vulnerable to
/// that vector — the completeness signal a pentest report needs ("checked X, clean"), so the
/// operator sees where there IS a bug and where there is NOT, not only the positive hits.
pub fn run_all_with_coverage(
    snap: &Snapshot,
    graph: &ControlGraph,
) -> Vec<(&'static str, Vec<Finding>)> {
    registry()
        .iter()
        .map(|c| (c.id(), c.run(snap, graph)))
        .collect()
}
