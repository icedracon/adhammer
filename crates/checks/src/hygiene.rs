//! Hygiene checks — cheap, pure-LDAP rules over already-collected attributes, closing the
//! coverage gap against PingCastle's StaleObjects/Anomalies buckets. High signal, no new protocol
//! work: privileged-account hygiene (never-expiring / dormant / default-admin / stealth-primary-
//! group), weak crypto (DES-only), disabled-but-privileged residue, and obsolete functional level.

use super::Check;
use adhammer_core::finding::{mitre, Category, Severity};
use adhammer_core::object::{uac, AdObject};
use adhammer_core::snapshot::Snapshot;
use adhammer_core::Finding;
use adhammer_graph::ControlGraph;

const TICKS_PER_DAY: i64 = 864_000_000_000;
const FILETIME_2026_DAYS: i64 = 155_000;

/// Age in days of a FILETIME attribute; None if unset/zero.
fn age_days(o: &AdObject, attr: &str) -> Option<i64> {
    match o.filetime(attr) {
        Some(t) if t > 0 => Some(FILETIME_2026_DAYS - t / TICKS_PER_DAY),
        _ => None,
    }
}

/// True for an enabled, adminCount-stamped (Tier-0-adjacent) principal.
fn is_privileged(o: &AdObject) -> bool {
    o.int("adminCount") == Some(1)
}

/// A-PrivPwdNeverExpires: privileged accounts whose password never expires — a long-lived,
/// high-value credential that survives rotation policy and breach exposure.
pub struct PrivilegedPasswordNeverExpires;
impl Check for PrivilegedPasswordNeverExpires {
    fn id(&self) -> &'static str {
        "A-PrivPwdNeverExpires"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("user")
            .filter(|o| !o.has_class("computer"))
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE == 0)
            .filter(|o| is_privileged(o) && o.uac() & uac::DONT_EXPIRE_PASSWORD != 0)
            .map(|o| o.dn.clone())
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("{} privileged accounts with non-expiring passwords", hits.len()),
            category: Category::Anomalies,
            severity: Severity::Medium,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 2,
            affected: hits,
            detail: "A privileged account with DONT_EXPIRE_PASSWORD keeps the same credential indefinitely — ideal for offline cracking, reuse, and breach persistence.".into(),
            remediation: "Remove DONT_EXPIRE_PASSWORD from privileged accounts; migrate service accounts to gMSA.".into(),
        }]
    }
}

/// A-DesOnly: accounts restricted to DES Kerberos keys — trivially crackable, and a classic
/// downgrade for offline attacks (roastable at DES strength).
pub struct DesOnlyAccounts;
impl Check for DesOnlyAccounts {
    fn id(&self) -> &'static str {
        "A-DesOnly"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("user")
            .filter(|o| o.uac() & uac::USE_DES_KEY_ONLY != 0)
            .map(|o| o.dn.clone())
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("{} accounts restricted to DES Kerberos keys", hits.len()),
            category: Category::Anomalies,
            severity: Severity::Medium,
            mitre: vec![mitre::KERBEROASTING],
            weight_bonus: hits.len() as u32 * 3,
            affected: hits,
            detail: "USE_DES_KEY_ONLY forces 56-bit DES tickets, which are crackable in minutes and enable AS-REP/Kerberoast downgrade.".into(),
            remediation: "Clear USE_DES_KEY_ONLY and enforce AES-only (msDS-SupportedEncryptionTypes).".into(),
        }]
    }
}

/// A-FunctionalLevel: domain functional level below Windows Server 2016 (behavior-version 7),
/// gating modern hardening (PAM, LAPS-native, credential-guard-friendly Kerberos).
pub struct ObsoleteFunctionalLevel;
impl Check for ObsoleteFunctionalLevel {
    fn id(&self) -> &'static str {
        "A-FunctionalLevel"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let Some(dom) = snap.objects.iter().find(|o| o.has_class("domainDNS")) else {
            return vec![];
        };
        let Some(level) = dom.int("msDS-Behavior-Version") else {
            return vec![];
        };
        if level >= 7 {
            return vec![];
        }
        let name = match level {
            0 => "2000",
            2 => "2003",
            3 => "2008",
            4 => "2008 R2",
            5 => "2012",
            6 => "2012 R2",
            _ => "pre-2016",
        };
        vec![Finding {
            id: self.id().into(),
            title: format!("Domain functional level is Windows Server {name} (< 2016)"),
            category: Category::Anomalies,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec![dom.dn.clone()],
            detail: "An older functional level blocks modern security features (PAM/shadow-principals, tighter Kerberos, native LAPS enforcement).".into(),
            remediation: "Retire legacy DCs and raise the domain/forest functional level to 2016+.".into(),
        }]
    }
}

/// S-DisabledInPrivGroup: disabled accounts still carrying adminCount=1 — AdminSDHolder keeps
/// their ACL locked as Tier-0 even though they're off, a re-enable-to-privesc foothold.
pub struct DisabledPrivileged;
impl Check for DisabledPrivileged {
    fn id(&self) -> &'static str {
        "S-DisabledInPrivGroup"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("user")
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE != 0 && is_privileged(o))
            .map(|o| o.dn.clone())
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("{} disabled accounts still stamped privileged (adminCount=1)", hits.len()),
            category: Category::StaleObjects,
            severity: Severity::Medium,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32,
            affected: hits,
            detail: "A disabled but adminCount=1 account keeps its AdminSDHolder-protected ACL; anyone who can re-enable it (or its password) gains a Tier-0 identity.".into(),
            remediation: "Remove stale privileged accounts, or clear adminCount and re-baseline the ACL after removing them from protected groups.".into(),
        }]
    }
}

/// S-NeverLoggedOn: enabled accounts that have never authenticated yet were created long ago —
/// provisioned-and-forgotten credentials with default/weak passwords.
pub struct NeverLoggedOn;
impl Check for NeverLoggedOn {
    fn id(&self) -> &'static str {
        "S-NeverLoggedOn"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        const OLD_DAYS: i64 = 90;
        let count = snap
            .iter_class("user")
            .filter(|o| !o.has_class("computer"))
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE == 0)
            .filter(|o| age_days(o, "lastLogonTimestamp").is_none())
            .filter(|o| age_days(o, "whenCreated").is_some_and(|d| d > OLD_DAYS))
            .count();
        if count == 0 {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("{count} enabled accounts created > {OLD_DAYS}d ago that never logged on"),
            category: Category::StaleObjects,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec![format!("{count} user objects")],
            detail: "Provisioned-but-unused accounts often keep their initial (weak/shared) password and are prime password-spray targets.".into(),
            remediation: "Disable or delete accounts that were never used within a grace window of creation.".into(),
        }]
    }
}

/// P-PrimaryGroupPriv: a user whose primaryGroupID points at a privileged group. Primary-group
/// membership does not appear in the group's `member` list, so it hides Domain-Admin-equivalent
/// access from casual review and from tools that only walk `member`.
pub struct PrimaryGroupPrivileged;
impl Check for PrimaryGroupPrivileged {
    fn id(&self) -> &'static str {
        "P-PrimaryGroupPriv"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        // Domain/Schema/Enterprise Admins + Group Policy Creator Owners RIDs.
        const PRIV_RIDS: [i64; 4] = [512, 518, 519, 520];
        let hits: Vec<String> = snap
            .iter_class("user")
            .filter(|o| !o.has_class("computer"))
            .filter(|o| o.int("primaryGroupID").is_some_and(|r| PRIV_RIDS.contains(&r)))
            .map(|o| format!("{} (primaryGroupID={})", o.dn, o.int("primaryGroupID").unwrap_or(0)))
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("{} accounts privileged via primaryGroupID (hidden membership)", hits.len()),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 5,
            affected: hits,
            detail: "Setting primaryGroupID to a privileged group grants that group's rights without appearing in its member attribute — a stealth Domain-Admin persistence technique.".into(),
            remediation: "Reset primaryGroupID to 513 (Domain Users) and investigate how it was changed.".into(),
        }]
    }
}

/// P-DormantPrivileged: privileged accounts that have not authenticated recently — powerful
/// credentials nobody is watching, ideal for quiet takeover.
pub struct DormantPrivileged;
impl Check for DormantPrivileged {
    fn id(&self) -> &'static str {
        "P-DormantPrivileged"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        const DORMANT_DAYS: i64 = 90;
        let hits: Vec<String> = snap
            .iter_class("user")
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE == 0 && is_privileged(o))
            .filter(|o| age_days(o, "lastLogonTimestamp").is_some_and(|d| d > DORMANT_DAYS))
            .map(|o| o.dn.clone())
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("{} privileged accounts dormant > {DORMANT_DAYS} days", hits.len()),
            category: Category::PrivilegedAccounts,
            severity: Severity::Medium,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 3,
            affected: hits,
            detail: "An unused but privileged account draws no attention if compromised; dormant Tier-0 credentials are a favored persistence target.".into(),
            remediation: "Disable dormant privileged accounts; require just-in-time elevation for admin duties.".into(),
        }]
    }
}

/// P-DefaultAdminActive: the built-in Administrator (RID 500) authenticating recently — it should
/// be a sealed break-glass account, so day-to-day use means a shared, un-attributable credential.
pub struct DefaultAdministratorActive;
impl Check for DefaultAdministratorActive {
    fn id(&self) -> &'static str {
        "P-DefaultAdminActive"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        const RECENT_DAYS: i64 = 30;
        let Some(admin) = snap.by_rid(500) else {
            return vec![];
        };
        if !age_days(admin, "lastLogonTimestamp").is_some_and(|d| d <= RECENT_DAYS) {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Built-in Administrator (RID 500) is in active use".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec![admin.dn.clone()],
            detail: "The built-in Administrator should be a sealed break-glass account; routine use means a shared credential with no individual attribution and full Tier-0 rights.".into(),
            remediation: "Reserve RID 500 for break-glass, use named admin accounts, and enable auditing/alerting on its logons.".into(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_core::snapshot::{DomainInfo, Snapshot};
    use std::collections::HashMap as Map;

    fn user(dn: &str, attrs: &[(&str, &str)]) -> AdObject {
        let mut a: Map<String, Vec<String>> = Map::new();
        a.insert("objectClass".into(), vec!["user".into(), "person".into()]);
        for (k, v) in attrs {
            a.entry((*k).into()).or_default().push((*v).to_string());
        }
        AdObject { dn: dn.into(), attrs: a, bin: Map::new() }
    }

    #[test]
    fn priv_never_expires_fires_only_for_admincount() {
        let snap = Snapshot::new(
            DomainInfo::default(),
            vec![
                // privileged + non-expiring + enabled → fires
                user("CN=svc_sql,DC=x", &[("adminCount", "1"), ("userAccountControl", "66048")]),
                // non-expiring but NOT privileged → ignored
                user("CN=bob,DC=x", &[("userAccountControl", "66048")]),
            ],
        );
        let g = ControlGraph::build(&snap);
        let f = PrivilegedPasswordNeverExpires.run(&snap, &g);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].affected.len(), 1);
        assert!(f[0].affected[0].contains("svc_sql"));
    }

    #[test]
    fn primary_group_privilege_detected() {
        let snap = Snapshot::new(
            DomainInfo::default(),
            vec![
                user("CN=stealth,DC=x", &[("primaryGroupID", "512")]), // Domain Admins → fires
                user("CN=normal,DC=x", &[("primaryGroupID", "513")]),  // Domain Users → ok
            ],
        );
        let g = ControlGraph::build(&snap);
        let f = PrimaryGroupPrivileged.run(&snap, &g);
        assert_eq!(f.len(), 1);
        assert!(f[0].affected[0].contains("stealth"));
    }

    #[test]
    fn disabled_privileged_flagged() {
        let snap = Snapshot::new(
            DomainInfo::default(),
            // disabled (0x2) + adminCount=1 → 0x10002 = 65538
            vec![user("CN=old_da,DC=x", &[("adminCount", "1"), ("userAccountControl", "65538")])],
        );
        let g = ControlGraph::build(&snap);
        assert_eq!(DisabledPrivileged.run(&snap, &g).len(), 1);
    }

    #[test]
    fn des_only_flagged() {
        // USE_DES_KEY_ONLY = 0x200000, + NORMAL_ACCOUNT 0x200 = 0x200200 = 2097664
        let snap = Snapshot::new(
            DomainInfo::default(),
            vec![user("CN=legacy,DC=x", &[("userAccountControl", "2097664")])],
        );
        let g = ControlGraph::build(&snap);
        assert_eq!(DesOnlyAccounts.run(&snap, &g).len(), 1);
    }
}
