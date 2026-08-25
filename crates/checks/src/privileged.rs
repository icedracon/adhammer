//! Category: Privileged Accounts. Delegation, roastable admins, and the two
//! graph-backed rules (DCSync, Shadow Credentials) that consume the control-path layer.

use super::Check;
use adhammer_core::finding::{mitre, Category, Evidence, Severity};
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
        let hits: Vec<(String, u32)> = snap
            .iter_class("user")
            .filter(|o| o.uac() & uac::DONT_REQ_PREAUTH != 0 && o.uac() & uac::ACCOUNTDISABLE == 0)
            .map(|o| (o.dn.clone(), o.uac()))
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        // Ground-truth evidence: the raw userAccountControl of each account, showing the
        // DONT_REQ_PREAUTH (0x400000) bit actually set — verifiable by hand against the DC.
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(dn, u)| {
                Evidence::new(
                    format!("LDAP {dn}:userAccountControl"),
                    format!("0x{u:08X} (DONT_REQ_PREAUTH 0x400000 set)"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "Accounts do not require Kerberos pre-authentication".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::ASREP_ROAST],
            weight_bonus: hits.len() as u32 * 5,
            affected: hits.iter().map(|(dn, _)| dn.clone()).collect(),
            evidence,
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
        let hits: Vec<(String, String)> = snap
            .iter_class("user")
            .filter(|o| {
                !o.all("servicePrincipalName").is_empty()
                    && o.int("adminCount") == Some(1)
                    && o.uac() & uac::ACCOUNTDISABLE == 0
            })
            .map(|o| (o.dn.clone(), o.all("servicePrincipalName").join(", ")))
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        // Ground-truth evidence: the actual SPN(s) + adminCount=1 that make each account both
        // roastable and privileged.
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(dn, spns)| {
                Evidence::new(
                    format!("LDAP {dn}:servicePrincipalName + adminCount"),
                    format!("adminCount=1; SPN: {spns}"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "Privileged accounts are Kerberoastable (SPN + adminCount=1)".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Critical,
            mitre: vec![mitre::KERBEROASTING],
            weight_bonus: hits.len() as u32 * 10,
            affected: hits.iter().map(|(dn, _)| dn.clone()).collect(),
            evidence,
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
        let hits: Vec<(String, u32)> = snap
            .objects
            .iter()
            .filter(|o| {
                o.uac() & uac::TRUSTED_FOR_DELEGATION != 0
                    // exclude domain controllers (expected); crude filter by primaryGroupID 516
                    && o.int("primaryGroupID") != Some(516)
            })
            .map(|o| (o.dn.clone(), o.uac()))
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        // Ground-truth evidence: the raw userAccountControl of each principal, showing the
        // TRUSTED_FOR_DELEGATION (0x80000) bit actually set — verifiable by hand against the DC.
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(dn, u)| {
                Evidence::new(
                    format!("LDAP {dn}:userAccountControl"),
                    format!("0x{u:08X} (TRUSTED_FOR_DELEGATION 0x80000 set)"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "Unconstrained delegation on non-DC principals".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Critical,
            mitre: vec![mitre::SILVER_TICKET],
            weight_bonus: hits.len() as u32 * 10,
            affected: hits.iter().map(|(dn, _)| dn.clone()).collect(),
            evidence,
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
        let close: Vec<&adhammer_graph::AttackPath> =
            paths.iter().filter(|p| p.cost <= 1).collect();
        if close.is_empty() {
            return vec![];
        }
        // Ground-truth evidence: the actual control-path ACL edge(s) that grant each path —
        // the specific `principal =[EdgeKind]=> target` hop(s) the graph walked (WriteDacl /
        // GenericAll / replication rights), so the verdict points at the ACE, not just the fact.
        let evidence: Vec<Evidence> = close
            .iter()
            .take(25)
            .map(|p| {
                let edges = p
                    .steps
                    .iter()
                    .map(|s| format!("{} =[{}]=> {}", s.from, s.edge, s.to))
                    .collect::<Vec<_>>()
                    .join("; ");
                Evidence::new(
                    format!(
                        "ControlGraph path {} → {} (cost {})",
                        p.principal, p.target, p.cost
                    ),
                    if edges.is_empty() {
                        format!("direct control: {} → {}", p.principal, p.target)
                    } else {
                        edges
                    },
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "Direct control path to Tier-0 detected".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Critical,
            mitre: vec![mitre::DCSYNC, mitre::VALID_ACCOUNTS],
            weight_bonus: close.len() as u32 * 8,
            affected: close
                .iter()
                .map(|p| format!("{} (cost {})", p.render(), p.cost))
                .collect(),
            evidence,
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
        let edges: Vec<(String, String)> =
            g.direct_edges_to_tier0(ControlPrimitive::AddKeyCredential.into());
        if edges.is_empty() {
            return vec![];
        }
        // Ground-truth evidence: the actual control-path edge that grants the path — a
        // WriteProperty on the Tier-0 target's msDS-KeyCredentialLink attribute held by the
        // source principal, which is exactly what makes the Shadow Credentials attack possible.
        let evidence: Vec<Evidence> = edges
            .iter()
            .take(25)
            .map(|(src, dst)| {
                Evidence::new(
                    format!("ControlGraph edge {src} → {dst}"),
                    format!(
                        "AddKeyCredential: WriteProperty on {dst}:msDS-KeyCredentialLink held by {src}"
                    ),
                )
            })
            .collect();
        let hits: Vec<String> = edges
            .iter()
            .map(|(src, dst)| format!("{src} → {dst} (msDS-KeyCredentialLink write)"))
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "Shadow Credentials path to Tier-0 detected".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Critical,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 10,
            affected: hits,
            evidence,
            detail: "Write access to msDS-KeyCredentialLink on a Tier-0 object lets an attacker register a key and PKINIT as that principal.".into(),
            impact: Some("Attacker writes msDS-KeyCredentialLink on the Tier-0 target, then PKINITs with the freshly-generated cert to obtain a TGT as that principal. Full impersonation of a Domain Admin without ever learning their password.".into()),
            remediation: "Remove unexpected WriteProperty on msDS-KeyCredentialLink and audit AdminSDHolder inheritance on privileged accounts.".into(),
        }]
    }
}
