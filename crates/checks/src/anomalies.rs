//! Category: Anomalies. The heaviest bucket — Kerberos hygiene, krbtgt, MAQ,
//! reversible encryption, and the fresh Server 2025 badSuccessor (dMSA) vector.

use super::Check;
use adhammer_core::finding::{mitre, Category, Severity};
use adhammer_core::object::uac;
use adhammer_core::sid::rid;
use adhammer_core::snapshot::Snapshot;
use adhammer_core::Finding;
use adhammer_graph::ControlGraph;

/// FILETIME ticks since 1601 → days before `now` (approx, for age heuristics).
const TICKS_PER_DAY: i64 = 864_000_000_000;
// 1601→2026 offset in days, good enough for "older than N days" comparisons.
const FILETIME_2026_DAYS: i64 = 155_000;

pub struct MachineAccountQuota;
impl Check for MachineAccountQuota {
    fn id(&self) -> &'static str {
        "A-MachineAccountQuota"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let maq = snap.domain.machine_account_quota.unwrap_or(10);
        if maq <= 0 {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("ms-DS-MachineAccountQuota = {maq} (any user can join computers)"),
            category: Category::Anomalies,
            severity: if maq >= 10 { Severity::Medium } else { Severity::Low },
            mitre: vec![mitre::VALID_ACCOUNTS],
            affected: vec![snap.domain.domain_dn.clone()],
            detail: "A non-zero quota lets any authenticated user create computer accounts — a prerequisite for RBCD and noPac (CVE-2021-42278/87) style attacks.".into(),
            remediation: "Set ms-DS-MachineAccountQuota to 0 and delegate computer-join to a dedicated group.".into(),
            weight_bonus: 0,
        }]
    }
}

pub struct KrbtgtPasswordAge;
impl Check for KrbtgtPasswordAge {
    fn id(&self) -> &'static str {
        "A-KrbtgtAge"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let Some(krbtgt) = snap.by_rid(rid::KRBTGT) else { return vec![] };
        let Some(pls) = krbtgt.filetime("pwdLastSet") else { return vec![] };
        let age_days = FILETIME_2026_DAYS - (pls / TICKS_PER_DAY);
        if age_days < 180 {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("krbtgt password not rotated in ~{age_days} days"),
            category: Category::Anomalies,
            severity: if age_days > 365 { Severity::High } else { Severity::Medium },
            mitre: vec![mitre::GOLDEN_TICKET],
            affected: vec![krbtgt.dn.clone()],
            detail: "A stale krbtgt key means any previously forged Golden Ticket remains valid; rotation invalidates them.".into(),
            remediation: "Rotate the krbtgt password twice (with >10h between rotations) using the Microsoft reset script.".into(),
            weight_bonus: 0,
        }]
    }
}

pub struct ReversibleEncryption;
impl Check for ReversibleEncryption {
    fn id(&self) -> &'static str {
        "A-ReversibleEncryption"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        const ENCRYPTED_TEXT_PWD_ALLOWED: u32 = 0x0080;
        let hits: Vec<String> = snap
            .iter_class("user")
            .filter(|o| {
                o.uac() & ENCRYPTED_TEXT_PWD_ALLOWED != 0 && o.uac() & uac::ACCOUNTDISABLE == 0
            })
            .map(|o| o.dn.clone())
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Accounts store passwords with reversible encryption".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 5,
            affected: hits,
            detail: "Reversible encryption stores a recoverable cleartext-equivalent of the password in the directory.".into(),
            remediation: "Clear the flag and force a password reset for affected accounts.".into(),
        }]
    }
}

pub struct Rc4Kerberos;
impl Check for Rc4Kerberos {
    fn id(&self) -> &'static str {
        "A-Rc4Kerberos"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        // msDS-SupportedEncryptionTypes: bit 0x4 = RC4, 0x8|0x10 = AES. Missing/0 ⇒ RC4 default.
        let hits: Vec<String> = snap
            .iter_class("user")
            .filter(|o| !o.all("servicePrincipalName").is_empty())
            .filter(|o| {
                let et = o.int("msDS-SupportedEncryptionTypes").unwrap_or(0);
                et == 0 || (et & 0x4 != 0 && et & 0x18 == 0)
            })
            .map(|o| o.dn.clone())
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Service accounts negotiate RC4 Kerberos encryption".into(),
            category: Category::Anomalies,
            severity: Severity::Medium,
            mitre: vec![mitre::KERBEROASTING],
            weight_bonus: 0,
            affected: hits,
            detail: "RC4 (etype 23) TGS tickets crack far faster than AES; missing msDS-SupportedEncryptionTypes falls back to RC4.".into(),
            remediation: "Set msDS-SupportedEncryptionTypes to AES128+AES256 (0x18) on service accounts and DCs.".into(),
        }]
    }
}

/// badSuccessor (2025): a Server 2025 delegated Managed Service Account (dMSA) whose
/// creation/attribute-write is delegated to a low-priv principal → full privilege takeover.
/// Detectable purely via LDAP: presence of dMSA objects + who controls the parent OU.
pub struct BadSuccessor;
impl Check for BadSuccessor {
    fn id(&self) -> &'static str {
        "A-BadSuccessor"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let dmsas: Vec<String> = snap
            .iter_class("msDS-DelegatedManagedServiceAccount")
            .map(|o| o.dn.clone())
            .collect();
        if dmsas.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Delegated Managed Service Accounts present (badSuccessor exposure)".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            affected: dmsas,
            detail: "Server 2025 dMSA objects can be abused (badSuccessor) when create/write over the containing OU is delegated to non-Tier-0 principals, yielding privilege takeover.".into(),
            remediation: "Restrict CreateChild/Write on OUs that can host dMSA objects to Tier-0; audit msDS-ManagedAccountPrecededByLink.".into(),
            weight_bonus: 0,
        }]
    }
}
