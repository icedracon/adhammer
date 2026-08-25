//! Category: Stale Objects. Pure-LDAP, cheap. Inactive principals and unsupported OS.

use super::Check;
use adhammer_core::finding::{mitre, Category, Evidence, Severity};
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
        // Capture the raw lastLogonTimestamp FILETIME per stale account as ground-truth evidence.
        let hits: Vec<(String, i64, i64)> = snap
            .iter_class("user")
            .filter_map(|o| match o.filetime("lastLogonTimestamp") {
                Some(t) if t > 0 => {
                    let d = FILETIME_2026_DAYS - t / TICKS_PER_DAY;
                    (d > INACTIVE_DAYS).then_some((o.dn.clone(), t, d))
                }
                _ => None,
            })
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        let count = hits.len();
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(dn, raw, d)| {
                Evidence::new(
                    format!("LDAP {dn}:lastLogonTimestamp"),
                    format!("{raw} ({d}d ago, > {INACTIVE_DAYS}d inactivity threshold)"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: format!("{count} accounts inactive > {INACTIVE_DAYS} days"),
            category: Category::StaleObjects,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            affected: vec![format!("{count} user objects")],
            evidence,
            detail: "Dormant accounts expand the attack surface and are prime targets for password spray / takeover.".into(),
            impact: Some("Stale accounts with valid credentials are the easiest lateral-movement path. They're rarely monitored, their passwords are old (crackable), and they may hold group memberships whose relevance the owners have forgotten.".into()),
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
        // Keep the matched operatingSystem string per host — the exact banner the DC returned.
        let hits: Vec<(String, String)> = snap
            .iter_class("computer")
            .filter_map(|o| {
                o.one("operatingSystem")
                    .filter(|os| {
                        ["2000", "2003", "2008", "XP", "Windows 7", "Vista", "2012"]
                            .iter()
                            .any(|old| os.contains(old))
                    })
                    .map(|os| (o.dn.clone(), os.to_string()))
            })
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(dn, os)| {
                Evidence::new(
                    format!("LDAP {dn}:operatingSystem"),
                    format!("\"{os}\" (end-of-life / unsupported)"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "Unsupported / end-of-life operating systems in the domain".into(),
            category: Category::StaleObjects,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 3,
            affected: hits.iter().map(|(dn, os)| format!("{dn} [{os}]")).collect(),
            evidence,
            detail: "EOL Windows versions receive no security patches and often force weak protocols (NTLMv1, SMBv1).".into(),
            impact: Some("EoL OSes miss every security patch since their EoL date. Local privilege escalation via known unpatched CVEs, protocol downgrade (SMBv1, RC4-only), and no support for modern Kerberos/RPC hardening.".into()),
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
        // Capture the raw pwdLastSet FILETIME per enabled account with a stale password.
        let hits: Vec<(String, i64, i64)> = snap
            .iter_class("user")
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE == 0)
            .filter_map(|o| {
                age_days(o, "pwdLastSet")
                    .filter(|d| *d > STALE_PW_DAYS)
                    .map(|d| (o.dn.clone(), o.filetime("pwdLastSet").unwrap_or(0), d))
            })
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        let count = hits.len();
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(dn, raw, d)| {
                Evidence::new(
                    format!("LDAP {dn}:pwdLastSet"),
                    format!("{raw} ({d}d ago, > {STALE_PW_DAYS}d)"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: format!("{count} accounts with passwords older than {STALE_PW_DAYS} days"),
            category: Category::StaleObjects,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec![format!("{count} user objects")],
            evidence,
            detail: "Long-lived passwords are more likely to be cracked, reused, or already exposed in breaches.".into(),
            impact: Some("Passwords that never change accumulate risk. Old cracked passwords remain valid; the account may have been compromised years ago and the attacker retains persistence via credential rotation on their side, not yours.".into()),
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
        // Capture the raw lastLogonTimestamp FILETIME per enabled, dormant computer.
        let hits: Vec<(String, i64, i64)> = snap
            .iter_class("computer")
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE == 0)
            .filter_map(|o| {
                age_days(o, "lastLogonTimestamp")
                    .filter(|d| *d > INACTIVE_DAYS)
                    .map(|d| {
                        (
                            o.dn.clone(),
                            o.filetime("lastLogonTimestamp").unwrap_or(0),
                            d,
                        )
                    })
            })
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        let count = hits.len();
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(dn, raw, d)| {
                Evidence::new(
                    format!("LDAP {dn}:lastLogonTimestamp"),
                    format!("{raw} ({d}d ago, > {INACTIVE_DAYS}d inactivity threshold)"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: format!("{count} computers inactive > {INACTIVE_DAYS} days"),
            category: Category::StaleObjects,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec![format!("{count} computer objects")],
            evidence,
            detail: "Dormant computer accounts remain valid Kerberos principals and expand the attack surface (e.g. resurrected-machine attacks).".into(),
            impact: Some("Dormant computer objects still hold their machine password + delegation rights. An attacker who resurrects one (physical box or by writing to the object) gets a machine-account foothold with the historical trust.".into()),
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
        // Capture the raw pwdLastSet FILETIME per computer whose machine password never rotated.
        let hits: Vec<(String, i64, i64)> = snap
            .iter_class("computer")
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE == 0)
            .filter_map(|o| {
                age_days(o, "pwdLastSet")
                    .filter(|d| *d > STALE_MACHINE_PW_DAYS)
                    .map(|d| (o.dn.clone(), o.filetime("pwdLastSet").unwrap_or(0), d))
            })
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(dn, raw, d)| {
                Evidence::new(
                    format!("LDAP {dn}:pwdLastSet"),
                    format!("{raw} ({d}d ago, > {STALE_MACHINE_PW_DAYS}d, ~30d rotation expected)"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: format!("{} computers with machine password older than 180 days", hits.len()),
            category: Category::StaleObjects,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: hits.iter().map(|(dn, _, _)| dn.clone()).collect(),
            evidence,
            detail: "The machine password normally rotates every ~30 days; a much older one indicates a dead computer or a manually pinned credential usable for persistence.".into(),
            impact: Some("Machine password rotation limits the useful lifetime of a captured NTLM hash / Kerberos machine key. 180+ day-old machine password = any historical LSASS dump or NTDS extract that included this machine still works today.".into()),
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
                owners
                    .entry(spn.to_ascii_lowercase())
                    .or_default()
                    .push(o.dn.clone());
            }
        }
        // Keep the SPN → owning-DNs mapping so each duplicate registration is its own evidence row.
        let mut dups: Vec<(String, Vec<String>)> =
            owners.into_iter().filter(|(_, v)| v.len() > 1).collect();
        if dups.is_empty() {
            return vec![];
        }
        dups.sort();
        let evidence: Vec<Evidence> = dups
            .iter()
            .take(25)
            .map(|(spn, v)| {
                Evidence::new(
                    format!("LDAP servicePrincipalName={spn}"),
                    format!("registered on {} accounts: {}", v.len(), v.join(", ")),
                )
            })
            .collect();
        let affected: Vec<String> = dups
            .iter()
            .map(|(spn, v)| format!("{spn} → {}", v.join(", ")))
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: format!("{} duplicate SPN registrations", affected.len()),
            category: Category::StaleObjects,
            severity: Severity::Medium,
            mitre: vec![mitre::KERBEROASTING],
            weight_bonus: affected.len() as u32 * 3,
            affected,
            evidence,
            detail: "A service principal name registered on multiple accounts causes Kerberos auth failures and can hide a rogue account shadowing a real service.".into(),
            impact: Some("Two accounts registering the same SPN causes the KDC to pick unpredictably. An attacker can register a duplicate SPN on a controlled account, then any Kerberos auth to that SPN yields a ticket the attacker's account can decrypt: silent MitM.".into()),
            remediation: "Remove the duplicate SPN from the incorrect account (setspn -D).".into(),
        }]
    }
}

/// A LAPS-managed computer whose password expiration time is in the past — LAPS has stopped
/// rotating, so the local-admin password is stale (and may already be known). (WS-COVERAGE, 1.4.3.)
pub struct LapsExpired;
impl Check for LapsExpired {
    fn id(&self) -> &'static str {
        "S-LapsExpired"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for o in snap.iter_class("computer") {
            let attr = if o.filetime("msLAPS-PasswordExpirationTime").is_some() {
                "msLAPS-PasswordExpirationTime"
            } else {
                "ms-Mcs-AdmPwdExpirationTime"
            };
            // overdue > 1 day; < 10 years guards against an unset/epoch-0 value reading as expired.
            if let Some(overdue) = age_days(o, attr) {
                if (2..3650).contains(&overdue) {
                    affected.push(o.dn.clone());
                    if evidence.len() < 25 {
                        evidence.push(Evidence::new(
                            format!("LDAP {}:{attr}", o.dn),
                            format!("expiration was {overdue} day(s) ago (LAPS not rotating)"),
                        ));
                    }
                }
            }
        }
        if affected.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "LAPS password expired (not rotating)".into(),
            category: Category::StaleObjects,
            severity: Severity::Medium,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 3,
            affected,
            evidence,
            detail: "The LAPS password expiration time is in the past, so LAPS is failing to rotate the local-admin password — a stale credential that may already be known or dumped.".into(),
            impact: Some("A local-admin password that stopped rotating is a durable, reusable credential for lateral movement — if it leaked once, it still works.".into()),
            remediation: "Fix LAPS rotation (GPO / scheduled task / permissions) and force an immediate reset on the affected hosts.".into(),
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
        AdObject {
            dn: dn.into(),
            attrs: a,
            bin: Map::new(),
        }
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
