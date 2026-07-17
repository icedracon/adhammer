//! Category: Stale Objects. Pure-LDAP, cheap. Inactive principals and unsupported OS.

use super::Check;
use adhammer_core::finding::{mitre, Category, Severity};
use adhammer_core::object::{uac, AdObject};
use adhammer_core::snapshot::Snapshot;
use adhammer_core::Finding;
use adhammer_graph::ControlGraph;
use std::collections::HashMap;

const TICKS_PER_DAY: i64 = 864_000_000_000;
const FILETIME_2026_DAYS: i64 = 155_000;
const INACTIVE_DAYS: i64 = 180;

/// Age in days of a FILETIME attribute (pwdLastSet, lastLogonTimestamp); None if unset.
fn age_days(o: &AdObject, attr: &str) -> Option<i64> {
    match o.filetime(attr) {
        Some(t) if t > 0 => Some(FILETIME_2026_DAYS - t / TICKS_PER_DAY),
        _ => None,
    }
}

pub struct InactiveAccounts;
impl Check for InactiveAccounts {
    fn id(&self) -> &'static str {
        "S-Inactive"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let count = snap
            .iter_class("user")
            .filter(|o| {
                match o.filetime("lastLogonTimestamp") {
                    Some(t) if t > 0 => FILETIME_2026_DAYS - t / TICKS_PER_DAY > INACTIVE_DAYS,
                    _ => false,
                }
            })
            .count();
        if count == 0 {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("{count} accounts inactive > {INACTIVE_DAYS} days"),
            category: Category::StaleObjects,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            affected: vec![format!("{count} user objects")],
            detail: "Dormant accounts expand the attack surface and are prime targets for password spray / takeover.".into(),
            remediation: "Disable or remove accounts unused beyond the inactivity threshold.".into(),
            weight_bonus: 0,
        }]
    }
}

pub struct UnsupportedOs;
impl Check for UnsupportedOs {
    fn id(&self) -> &'static str {
        "S-UnsupportedOs"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("computer")
            .filter(|o| {
                o.one("operatingSystem").map_or(false, |os| {
                    ["2000", "2003", "2008", "XP", "Windows 7", "Vista", "2012"]
                        .iter()
                        .any(|old| os.contains(old))
                })
            })
            .map(|o| format!("{} [{}]", o.dn, o.one("operatingSystem").unwrap_or("")))
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Unsupported / end-of-life operating systems in the domain".into(),
            category: Category::StaleObjects,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 3,
            affected: hits,
            detail: "EOL Windows versions receive no security patches and often force weak protocols (NTLMv1, SMBv1).".into(),
            remediation: "Decommission or isolate; where unavoidable, apply ESU and segment the network.".into(),
        }]
    }
}

/// Enabled user accounts whose password has not changed in over two years.
pub struct PasswordNeverChanged;
impl Check for PasswordNeverChanged {
    fn id(&self) -> &'static str {
        "S-OldPassword"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        const STALE_PW_DAYS: i64 = 730;
        let count = snap
            .iter_class("user")
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE == 0)
            .filter(|o| age_days(o, "pwdLastSet").map_or(false, |d| d > STALE_PW_DAYS))
            .count();
        if count == 0 {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("{count} accounts with passwords older than {STALE_PW_DAYS} days"),
            category: Category::StaleObjects,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec![format!("{count} user objects")],
            detail: "Long-lived passwords are more likely to be cracked, reused, or already exposed in breaches.".into(),
            remediation: "Enforce password rotation and investigate accounts exempt from expiry.".into(),
        }]
    }
}

/// Enabled computer objects that have not authenticated in over the inactivity window.
pub struct StaleComputers;
impl Check for StaleComputers {
    fn id(&self) -> &'static str {
        "S-StaleComputers"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let count = snap
            .iter_class("computer")
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE == 0)
            .filter(|o| age_days(o, "lastLogonTimestamp").map_or(false, |d| d > INACTIVE_DAYS))
            .count();
        if count == 0 {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("{count} computers inactive > {INACTIVE_DAYS} days"),
            category: Category::StaleObjects,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec![format!("{count} computer objects")],
            detail: "Dormant computer accounts remain valid Kerberos principals and expand the attack surface (e.g. resurrected-machine attacks).".into(),
            remediation: "Disable and remove computer accounts unused beyond the threshold.".into(),
        }]
    }
}

/// Computer accounts whose machine password has not rotated in far longer than the
/// default 30-day interval — a dead host, or a persistence ("golden computer") signal.
pub struct MachinePasswordAge;
impl Check for MachinePasswordAge {
    fn id(&self) -> &'static str {
        "S-MachinePwAge"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        const STALE_MACHINE_PW_DAYS: i64 = 180;
        let hits: Vec<String> = snap
            .iter_class("computer")
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE == 0)
            .filter(|o| age_days(o, "pwdLastSet").map_or(false, |d| d > STALE_MACHINE_PW_DAYS))
            .map(|o| o.dn.clone())
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: format!("{} computers with machine password older than 180 days", hits.len()),
            category: Category::StaleObjects,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: hits,
            detail: "The machine password normally rotates every ~30 days; a much older one indicates a dead computer or a manually pinned credential usable for persistence.".into(),
            remediation: "Remove dead computer accounts; investigate any live host that stopped rotating its password.".into(),
        }]
    }
}

/// The same SPN registered on more than one account — breaks authentication and can
/// indicate a stealthy Kerberoast/persistence setup.
pub struct DuplicateSpn;
impl Check for DuplicateSpn {
    fn id(&self) -> &'static str {
        "S-DuplicateSpn"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let mut owners: HashMap<String, Vec<String>> = HashMap::new();
        for o in &snap.objects {
            for spn in o.all("servicePrincipalName") {
                owners.entry(spn.to_ascii_lowercase()).or_default().push(o.dn.clone());
            }
        }
        let mut affected: Vec<String> = owners
            .into_iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(spn, v)| format!("{spn} → {}", v.join(", ")))
            .collect();
        if affected.is_empty() {
            return vec![];
        }
        affected.sort();
        vec![Finding {
            id: self.id().into(),
            title: format!("{} duplicate SPN registrations", affected.len()),
            category: Category::StaleObjects,
            severity: Severity::Medium,
            mitre: vec![mitre::KERBEROASTING],
            weight_bonus: affected.len() as u32 * 3,
            affected,
            detail: "A service principal name registered on multiple accounts causes Kerberos auth failures and can hide a rogue account shadowing a real service.".into(),
            remediation: "Remove the duplicate SPN from the incorrect account (setspn -D).".into(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_core::snapshot::{DomainInfo, Snapshot};
    use std::collections::HashMap as Map;

    fn acct(dn: &str, spns: &[&str]) -> AdObject {
        let mut a: Map<String, Vec<String>> = Map::new();
        a.insert("objectClass".into(), vec!["user".into()]);
        a.insert(
            "servicePrincipalName".into(),
            spns.iter().map(|s| (*s).to_string()).collect(),
        );
        AdObject { dn: dn.into(), attrs: a, bin: Map::new() }
    }

    #[test]
    fn detects_duplicate_spn() {
        let snap = Snapshot::new(
            DomainInfo::default(),
            vec![
                acct("CN=svc1,DC=x", &["MSSQLSvc/db.corp:1433"]),
                acct("CN=svc2,DC=x", &["MSSQLSvc/db.corp:1433"]),
                acct("CN=svc3,DC=x", &["HTTP/web.corp"]),
            ],
        );
        let g = ControlGraph::build(&snap);
        let f = DuplicateSpn.run(&snap, &g);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].affected.len(), 1); // only the MSSQLSvc SPN is duplicated
    }
}
