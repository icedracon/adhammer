//! Category: Privileged Accounts. Delegation, roastable admins, and the two
//! graph-backed rules (DCSync, Shadow Credentials) that consume the control-path layer.

use super::Check;
use adhammer_core::finding::{mitre, Category, Severity};
use adhammer_core::object::uac;
use adhammer_core::snapshot::Snapshot;
use adhammer_core::Finding;
use adhammer_graph::ControlGraph;

pub struct AsrepRoastable;
impl Check for AsrepRoastable {
    fn id(&self) -> &'static str {
        "P-AsrepRoast"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("user")
            .filter(|o| o.uac() & uac::DONT_REQ_PREAUTH != 0 && o.uac() & uac::ACCOUNTDISABLE == 0)
            .map(|o| o.dn.clone())
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Accounts do not require Kerberos pre-authentication".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::ASREP_ROAST],
            weight_bonus: hits.len() as u32 * 5,
            affected: hits,
            detail: "DONT_REQ_PREAUTH set: an unauthenticated attacker can request an AS-REP and crack it offline.".into(),
            remediation: "Remove the 'Do not require Kerberos preauthentication' flag; enforce AES; long passwords for any account that must keep it.".into(),
        }]
    }
}

pub struct KerberoastableAdmin;
impl Check for KerberoastableAdmin {
    fn id(&self) -> &'static str {
        "P-KerberoastAdmin"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("user")
            .filter(|o| {
                !o.all("servicePrincipalName").is_empty()
                    && o.int("adminCount") == Some(1)
                    && o.uac() & uac::ACCOUNTDISABLE == 0
            })
            .map(|o| o.dn.clone())
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Privileged accounts are Kerberoastable (SPN + adminCount=1)".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Critical,
            mitre: vec![mitre::KERBEROASTING],
            weight_bonus: hits.len() as u32 * 10,
            affected: hits,
            detail: "Accounts holding an SPN can have a TGS requested by any authenticated user and cracked offline; these are also privileged.".into(),
            remediation: "Convert to gMSA, or set a 25+ char random password and force AES-only encryption.".into(),
        }]
    }
}

pub struct UnconstrainedDelegation;
impl Check for UnconstrainedDelegation {
    fn id(&self) -> &'static str {
        "P-UnconstrainedDelegation"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .objects
            .iter()
            .filter(|o| {
                o.uac() & uac::TRUSTED_FOR_DELEGATION != 0
                    // exclude domain controllers (expected); crude filter by primaryGroupID 516
                    && o.int("primaryGroupID") != Some(516)
            })
            .map(|o| o.dn.clone())
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Unconstrained delegation on non-DC principals".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Critical,
            mitre: vec![mitre::SILVER_TICKET],
            weight_bonus: hits.len() as u32 * 10,
            affected: hits,
            detail: "TRUSTED_FOR_DELEGATION lets the host cache TGTs of any user that authenticates to it — coercible into DC compromise.".into(),
            remediation: "Remove unconstrained delegation; use constrained delegation with protocol transition only where required; add Tier-0 accounts to Protected Users.".into(),
        }]
    }
}

/// Graph-backed: any non-Tier-0 principal with a cheap path (DCSync edge or ≤1 hop)
/// into Tier-0 is reported as an attack path.
pub struct DcsyncPath;
impl Check for DcsyncPath {
    fn id(&self) -> &'static str {
        "P-DcsyncPath"
    }
    fn run(&self, _snap: &Snapshot, g: &ControlGraph) -> Vec<Finding> {
        let paths = g.paths_to_tier0();
        let close: Vec<String> = paths
            .iter()
            .filter(|p| p.cost <= 1)
            .map(|p| format!("{} → {} (cost {})", p.principal, p.target, p.cost))
            .collect();
        if close.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Non-privileged principals hold a direct control path to Tier-0".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Critical,
            mitre: vec![mitre::DCSYNC, mitre::VALID_ACCOUNTS],
            weight_bonus: close.len() as u32 * 8,
            affected: close,
            detail: "Control-path graph found principals one dangerous ACL edge away from Domain/Enterprise Admins or the domain head (DCSync-capable).".into(),
            remediation: "Audit and remove the offending ACEs (WriteDacl/GenericAll/Replication rights); re-apply the AdminSDHolder template.".into(),
        }]
    }
}

pub struct ShadowCredentialsPath;
impl Check for ShadowCredentialsPath {
    fn id(&self) -> &'static str {
        "P-ShadowCred"
    }
    fn run(&self, _snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        // TODO: filter graph edges of kind AddKeyCredential terminating on Tier-0.
        vec![]
    }
}
