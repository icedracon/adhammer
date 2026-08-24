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
            impact: Some("An unauthenticated attacker requests an AS-REP for the account, cracks the encrypted timestamp offline, and logs in as the user. Common initial foothold — with weak passwords this is minutes; combined with any downstream privesc it becomes domain compromise.".into()),
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
            impact: Some("Any domain user requests a TGS for the account, cracks the encrypted portion offline, recovers the admin's plaintext password. Direct tier-0 compromise — the account is already privileged, so no further privesc is needed.".into()),
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
            impact: Some("Attacker with control of this host coerces a DC to authenticate to it (via any RPC coercion vector), then extracts the DC's TGT from LSASS. That TGT does DCSync → krbtgt hash → golden ticket → indefinite domain persistence.".into()),
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
            .map(|p| format!("{} (cost {})", p.render(), p.cost))
            .collect();
        if close.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Direct control path to Tier-0 detected".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Critical,
            mitre: vec![mitre::DCSYNC, mitre::VALID_ACCOUNTS],
            weight_bonus: close.len() as u32 * 8,
            affected: close,
            detail: "Control-path graph found principals one dangerous ACL edge away from Domain/Enterprise Admins or the domain head (DCSync-capable).".into(),
            impact: Some("Any compromised principal in the listed path can write the ACL, gain DCSync/GenericAll on Tier-0, extract the krbtgt hash, and forge a golden ticket. Cost=1 means one dangerous action away, not one hop of pivoting.".into()),
            remediation: "Review the listed principals and remove unexpected ACEs (WriteDacl/GenericAll/Replication rights); re-apply the AdminSDHolder template where appropriate.".into(),
        }]
    }
}

pub struct ShadowCredentialsPath;
impl Check for ShadowCredentialsPath {
    fn id(&self) -> &'static str {
        "P-ShadowCred"
    }
    fn run(&self, _snap: &Snapshot, g: &ControlGraph) -> Vec<Finding> {
        use adhammer_graph::ControlPrimitive;
        let hits: Vec<String> = g
            .direct_edges_to_tier0(ControlPrimitive::AddKeyCredential.into())
            .into_iter()
            .map(|(src, dst)| format!("{src} → {dst} (msDS-KeyCredentialLink write)"))
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Shadow Credentials path to Tier-0 detected".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Critical,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 10,
            affected: hits,
            detail: "Write access to msDS-KeyCredentialLink on a Tier-0 object lets an attacker register a key and PKINIT as that principal.".into(),
            impact: Some("Attacker writes msDS-KeyCredentialLink on the Tier-0 target, then PKINITs with the freshly-generated cert to obtain a TGT as that principal. Full impersonation of a Domain Admin without ever learning their password.".into()),
            remediation: "Remove unexpected WriteProperty on msDS-KeyCredentialLink and audit AdminSDHolder inheritance on privileged accounts.".into(),
        }]
    }
}
