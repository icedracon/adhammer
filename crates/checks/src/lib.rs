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

/// Machine-readable roll-up of every check ID in the registry. Used by the coverage-
/// meta CI gate in `adhammer-report` (WS-CTRLMAP, 1.4.7) to assert every registered
/// check has a `CheckMeta` entry with `control_areas` + `kill_chain_phase` populated.
pub fn registry_ids() -> Vec<&'static str> {
    registry().iter().map(|c| c.id()).collect()
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
        Box::new(privileged_extra::GpoCreatorOwners),
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
        Box::new(anomalies_extra::DomainReversiblePwd),
        Box::new(adcs::VulnerableCertTemplates),
        Box::new(adcs::WeakCertTemplateCrypto),
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

/// WS-WPT session 3c: for every finding that doesn't already carry a wire exchange (i.e. every
/// LDAP-passive check — 50 of the 58), synthesize one from the collector's recorded SearchOp.
/// Active-probe checks (session 4) that already set `exchange` are left alone. One-place transform,
/// so every current + future LDAP-passive check gets wire proof for free without any per-check
/// code change.
///
/// **Session 4 (gate-strict) refinement**: some checks emit findings with formatted-string
/// `affected` labels ("Schema Admins (N members)", "N computer objects", …) rather than DNs.
/// For those, fall back to the domain root's search — which every scan captures — so the
/// finding still shows the LDAP conversation that made it visible, not just adhammer's word.
fn attach_wire_proof(snap: &Snapshot, findings: &mut [Finding]) {
    // Fall-back wire: the domain-root sub search. Every scan runs it; every LDAP-passive
    // finding is downstream of it. Empty when the collector wasn't instrumented (uninstrumented
    // legacy path — leaves findings without exchange, same as before).
    let fallback = snap.wire_for_dn(&snap.domain.domain_dn);
    for f in findings.iter_mut() {
        if !f.exchange.is_empty() {
            continue;
        }
        if let Some(dn) = f.affected.first() {
            let wires = snap.wire_for_dn(dn);
            if !wires.is_empty() {
                f.exchange = wires;
                continue;
            }
        }
        if !fallback.is_empty() {
            f.exchange = fallback.clone();
        }
    }
}

/// Run every rule and flatten. `graph` is built once by the caller.
pub fn run_all(snap: &Snapshot, graph: &ControlGraph) -> Vec<Finding> {
    let mut out: Vec<Finding> = registry().iter().flat_map(|c| c.run(snap, graph)).collect();
    attach_wire_proof(snap, &mut out);
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
    run_all_with_coverage_filtered(snap, graph, &CheckFilter::default())
}

/// **1.4.8 WS-SCAN-ONLY-FILTER**: select a subset of the registry to run. Empty `only` means
/// "all checks" (default). `skip` is applied after `only`. Unknown ids in either list are
/// warned about via `tracing::warn!` and silently ignored — callers get the filter behavior
/// they asked for even if a typo slips in. Preserves `registry()` iteration order for
/// deterministic coverage-row ordering.
///
/// Enables the 0-vuln **hardened-bill-of-health** banner to be live-rendered: pick a set of
/// checks known to be clean on the target DC → `Report::is_clean_bill()` returns true → the
/// green banner appears in HTML.
#[derive(Default, Clone, Debug)]
pub struct CheckFilter {
    pub only: Vec<String>,
    pub skip: Vec<String>,
}

impl CheckFilter {
    /// True when this check id should run under the current filter.
    fn allows(&self, id: &str) -> bool {
        if !self.only.is_empty() && !self.only.iter().any(|s| s == id) {
            return false;
        }
        if self.skip.iter().any(|s| s == id) {
            return false;
        }
        true
    }
}

pub fn run_all_with_coverage_filtered(
    snap: &Snapshot,
    graph: &ControlGraph,
    filter: &CheckFilter,
) -> Vec<(&'static str, Vec<Finding>)> {
    let all_ids: std::collections::HashSet<&'static str> =
        registry().iter().map(|c| c.id()).collect();
    for id in filter.only.iter().chain(filter.skip.iter()) {
        if !all_ids.contains(id.as_str()) {
            tracing::warn!(id, "check id not in registry — ignored by --only/--skip");
        }
    }
    registry()
        .iter()
        .filter(|c| filter.allows(c.id()))
        .map(|c| {
            let mut fs = c.run(snap, graph);
            attach_wire_proof(snap, &mut fs);
            (c.id(), fs)
        })
        .collect()
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    #[test]
    fn default_filter_allows_every_id() {
        let f = CheckFilter::default();
        assert!(f.allows("P-KerberoastAdmin"));
        assert!(f.allows("A-Esc15-ms-crtd"));
        assert!(f.allows("anything-else"));
    }

    #[test]
    fn only_narrows_to_named_ids() {
        let f = CheckFilter {
            only: vec!["P-GmsaRead".into(), "P-SidHistory".into()],
            skip: vec![],
        };
        assert!(f.allows("P-GmsaRead"));
        assert!(f.allows("P-SidHistory"));
        assert!(!f.allows("P-KerberoastAdmin"));
        assert!(!f.allows("A-Esc15-ms-crtd"));
    }

    #[test]
    fn skip_removes_named_ids() {
        let f = CheckFilter {
            only: vec![],
            skip: vec!["P-KerberoastAdmin".into()],
        };
        assert!(!f.allows("P-KerberoastAdmin"));
        assert!(f.allows("P-GmsaRead"));
    }

    #[test]
    fn skip_takes_precedence_over_only() {
        // Composed: --only A,B --skip A → runs only B.
        let f = CheckFilter {
            only: vec!["A".into(), "B".into()],
            skip: vec!["A".into()],
        };
        assert!(!f.allows("A"));
        assert!(f.allows("B"));
        assert!(!f.allows("C"));
    }

    #[test]
    fn only_narrows_but_does_not_gate_on_registry_membership() {
        // `allows()` is a pure string predicate — registry membership is enforced by
        // `run_all_with_coverage_filtered` iterating `registry()`. So an unknown id in
        // `only` matches itself in `allows()` (nothing else); the run is empty because
        // no registered check has that id. This is deliberate: the CLI logs a warn once
        // for the unknown id (see run_all_with_coverage_filtered), the operator sees
        // an empty run instead of a surprising unfiltered scan.
        let f = CheckFilter {
            only: vec!["Z-DoesNotExist".into()],
            skip: vec![],
        };
        assert!(f.allows("Z-DoesNotExist")); // string membership: yes
        assert!(!f.allows("P-KerberoastAdmin")); // not in `only` → filtered out
    }
}
