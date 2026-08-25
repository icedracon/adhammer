//! Category: Privileged Accounts — the LDAP-decidable batch beyond delegation/roasting:
//! sensitive group membership, gMSA read ACL, SID history, RBCD, LAPS coverage, and
//! accounts that require no password.

use super::Check;
use crate::util::{builtin_sid, domain_sid_with_rid, is_broad};
use adhammer_core::finding::{mitre, Category, Evidence, Severity};
use adhammer_core::object::uac;
use adhammer_core::sid::Sid;
use adhammer_core::snapshot::Snapshot;
use adhammer_core::{AdObject, Finding};
use adhammer_graph::ControlGraph;

/// How to locate a well-known group (RID is locale-independent; name is a fallback).
enum GroupRef {
    Domain(u32),
    Builtin(u32),
    ByName(&'static str),
}

fn resolve<'a>(snap: &'a Snapshot, g: &GroupRef) -> Option<&'a AdObject> {
    match g {
        GroupRef::Domain(rid) => snap
            .domain
            .domain_sid
            .as_ref()
            .and_then(|d| snap.by_sid(&domain_sid_with_rid(d, *rid))),
        GroupRef::Builtin(rid) => snap.by_sid(&builtin_sid(*rid)),
        GroupRef::ByName(n) => snap.by_sam(n),
    }
}

/// Membership in high-impact groups that are frequently forgotten. Account/Backup/Print
/// Operators and DnsAdmins are effectively Tier-0; Schema Admins should be empty.
pub struct SensitiveGroups;
impl Check for SensitiveGroups {
    fn id(&self) -> &'static str {
        "P-SensitiveGroups"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let groups = [
            ("Schema Admins", GroupRef::Domain(518)),
            ("Account Operators", GroupRef::Builtin(548)),
            ("Backup Operators", GroupRef::Builtin(551)),
            ("Print Operators", GroupRef::Builtin(550)),
            ("Server Operators", GroupRef::Builtin(549)),
            ("DnsAdmins", GroupRef::ByName("DnsAdmins")),
        ];
        let hits: Vec<(&'static str, String, Vec<String>)> = groups
            .iter()
            .filter_map(|(label, spec)| {
                let grp = resolve(snap, spec)?;
                let members = grp.all("member");
                (!members.is_empty()).then(|| (*label, grp.dn.clone(), members.to_vec()))
            })
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        let affected: Vec<String> = hits
            .iter()
            .map(|(label, _, members)| format!("{label} ({} members)", members.len()))
            .collect();
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(label, dn, members)| {
                Evidence::new(
                    format!("LDAP {dn}:member"),
                    format!(
                        "{label}: {} member(s), e.g. {}",
                        members.len(),
                        members.first().map(String::as_str).unwrap_or("<none>")
                    ),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "Populated sensitive / Tier-0-equivalent groups".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 5,
            affected,
            evidence,
            detail: "Members of Account/Backup/Print/Server Operators and DnsAdmins can escalate to Domain Admin; Schema Admins should be empty outside schema changes.".into(),
            impact: Some("Members of these groups (Backup Operators, Server Operators, Print Operators, Account Operators, DnsAdmins, etc.) can escalate to Domain Admin via well-documented paths (SeBackupPrivilege dumps SAM, DnsAdmin ServerLevelPluginDll, etc.). Any account here should be treated as Tier-0.".into()),
            remediation: "Empty these groups; use just-in-time membership for the rare legitimate operation.".into(),
        }]
    }
}

/// gMSA whose password can be read by a broad principal (ReadGMSAPassword).
pub struct GmsaReadableByBroad;
impl Check for GmsaReadableByBroad {
    fn id(&self) -> &'static str {
        "P-GmsaRead"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let dsid = snap.domain.domain_sid.as_ref();
        let hits: Vec<(String, String)> = snap
            .iter_class("msDS-GroupManagedServiceAccount")
            .filter_map(|o| {
                let raw = o.bin1("msDS-GroupMSAMembership")?;
                let sd = windows_sddl::parse(raw).ok()?;
                let trustee = sd
                    .dacl
                    .iter()
                    .flat_map(|d| &d.aces)
                    .filter(|a| a.is_allow())
                    .find(|a| is_broad(&a.trustee, dsid))?;
                Some((o.dn.clone(), trustee.trustee.to_string()))
            })
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(dn, sid)| {
                Evidence::new(
                    format!("LDAP {dn}:msDS-GroupMSAMembership"),
                    format!("allow ACE grants password retrieval to broad principal {sid}"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "gMSA password readable by a broad principal".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 8,
            affected: hits.iter().map(|(dn, _)| dn.clone()).collect(),
            evidence,
            detail: "msDS-GroupMSAMembership grants password retrieval to a low-privilege group; any member can recover the gMSA's credentials.".into(),
            impact: Some("The gMSA password is DPAPI-NG-wrapped and readable by any principal in msDS-GroupMSAMembership. A broad principal here means an unprivileged attacker recovers the gMSA's password, then impersonates the service, often a Tier-0 helper.".into()),
            remediation: "Restrict PrincipalsAllowedToRetrieveManagedPassword to specific hardened hosts.".into(),
        }]
    }
}

/// sIDHistory populated — flagged High when it carries a privileged SID (injected escalation).
pub struct SidHistory;
impl Check for SidHistory {
    fn id(&self) -> &'static str {
        "P-SidHistory"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let mut privileged: Vec<(String, Sid)> = Vec::new();
        let mut any: Vec<(String, String)> = Vec::new();
        for o in &snap.objects {
            let sids: Vec<Sid> = o
                .bin_all("sIDHistory")
                .iter()
                .filter_map(|b| Sid::from_bytes(b))
                .collect();
            if sids.is_empty() {
                continue;
            }
            if let Some(p) = sids.iter().find(|s| is_privileged_sid(s)) {
                privileged.push((o.dn.clone(), p.clone()));
            } else {
                let joined = sids
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                any.push((o.dn.clone(), joined));
            }
        }
        let mut out = Vec::new();
        if !privileged.is_empty() {
            let evidence: Vec<Evidence> = privileged
                .iter()
                .take(25)
                .map(|(dn, sid)| {
                    let val = match sid.rid() {
                        Some(r) => format!("{sid} (privileged well-known RID {r})"),
                        None => format!("{sid} (privileged well-known SID)"),
                    };
                    Evidence::new(format!("LDAP {dn}:sIDHistory"), val)
                })
                .collect();
            out.push(Finding {
                id: "P-SidHistoryPriv".into(),
                title: "sIDHistory contains a privileged SID (escalation)".into(),
                category: Category::PrivilegedAccounts,
                severity: Severity::Critical,
                mitre: vec![mitre::VALID_ACCOUNTS],
                weight_bonus: privileged.len() as u32 * 10,
                affected: privileged.iter().map(|(dn, _)| dn.clone()).collect(),
                evidence,
                detail: "The account's sIDHistory injects a privileged RID (e.g. 512/519), granting that privilege transparently — a classic persistence / migration abuse.".into(),
                impact: Some("The Kerberos PAC includes sIDHistory SIDs as group memberships. If the account is ever authenticated, it acts with the listed privileged group's rights: silent, permanent escalation invisible in memberOf.".into()),
                remediation: "Remove privileged SIDs from sIDHistory; investigate how they were added.".into(),
            });
        }
        if !any.is_empty() {
            let evidence: Vec<Evidence> = any
                .iter()
                .take(25)
                .map(|(dn, sids)| {
                    Evidence::new(
                        format!("LDAP {dn}:sIDHistory"),
                        format!("sIDHistory = {sids}"),
                    )
                })
                .collect();
            out.push(Finding {
                id: "P-SidHistoryAny".into(),
                title: "Accounts carry sIDHistory".into(),
                category: Category::PrivilegedAccounts,
                severity: Severity::Low,
                mitre: vec![mitre::VALID_ACCOUNTS],
                weight_bonus: 0,
                affected: any.iter().map(|(dn, _)| dn.clone()).collect(),
                evidence,
                detail: "sIDHistory outside an active migration is unusual and expands effective access; review for legitimacy.".into(),
                impact: Some("The Kerberos PAC includes sIDHistory SIDs as group memberships. If the account is ever authenticated, it acts with the listed privileged group's rights: silent, permanent escalation invisible in memberOf.".into()),
                remediation: "Clear sIDHistory once migrations complete.".into(),
            });
        }
        out
    }
}

/// Resource-Based Constrained Delegation configured on an object; High when the allowed
/// principal is broad/low-privilege (attacker-controllable takeover of the object).
pub struct RbcdConfigured;
impl Check for RbcdConfigured {
    fn id(&self) -> &'static str {
        "P-Rbcd"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let dsid = snap.domain.domain_sid.as_ref();
        let mut low_priv: Vec<(String, String)> = Vec::new();
        for o in &snap.objects {
            let Some(raw) = o.bin1("msDS-AllowedToActOnBehalfOfOtherIdentity") else {
                continue;
            };
            let Ok(sd) = windows_sddl::parse(raw) else {
                continue;
            };
            let broad = sd
                .dacl
                .iter()
                .flat_map(|d| &d.aces)
                .filter(|a| a.is_allow())
                .find(|a| is_broad(&a.trustee, dsid));
            if let Some(ace) = broad {
                low_priv.push((o.dn.clone(), ace.trustee.to_string()));
            }
        }
        if low_priv.is_empty() {
            return vec![];
        }
        let evidence: Vec<Evidence> = low_priv
            .iter()
            .take(25)
            .map(|(dn, sid)| {
                Evidence::new(
                    format!("LDAP {dn}:msDS-AllowedToActOnBehalfOfOtherIdentity"),
                    format!("allow ACE grants S4U2Proxy to broad principal {sid}"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "RBCD allows a broad principal to act on the object".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: low_priv.len() as u32 * 8,
            affected: low_priv.iter().map(|(dn, _)| dn.clone()).collect(),
            evidence,
            detail: "msDS-AllowedToActOnBehalfOfOtherIdentity grants a low-privilege principal S4U2Proxy rights, allowing impersonation of any user to the object.".into(),
            impact: Some("The listed target's msDS-AllowedToActOnBehalfOfOtherIdentity grants a broad principal (or one they control) the ability to S4U2Self+S4U2Proxy as any user against the target's services: silent full impersonation.".into()),
            remediation: "Remove the RBCD entry or restrict it to a specific, trusted service account.".into(),
        }]
    }
}

/// Enabled, non-DC computers without any LAPS expiration attribute ⇒ no managed local
/// admin password rotation.
pub struct LapsCoverage;
impl Check for LapsCoverage {
    fn id(&self) -> &'static str {
        "P-LapsCoverage"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let missing: Vec<String> = snap
            .iter_class("computer")
            .filter(|o| o.uac() & uac::ACCOUNTDISABLE == 0 && o.int("primaryGroupID") != Some(516))
            .filter(|o| {
                o.one("ms-Mcs-AdmPwdExpirationTime").is_none()
                    && o.one("msLAPS-PasswordExpirationTime").is_none()
            })
            .map(|o| o.dn.clone())
            .collect();
        if missing.is_empty() {
            return vec![];
        }
        let evidence: Vec<Evidence> = missing
            .iter()
            .take(25)
            .map(|dn| {
                Evidence::new(
                    format!(
                        "LDAP {dn}:ms-Mcs-AdmPwdExpirationTime + msLAPS-PasswordExpirationTime"
                    ),
                    "both LAPS expiration attributes absent (no managed local-admin password)"
                        .to_string(),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: format!("{} computers without LAPS coverage", missing.len()),
            category: Category::PrivilegedAccounts,
            severity: Severity::Medium,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec![format!("{} computer objects", missing.len())],
            evidence,
            detail: "Machines with no LAPS-managed local administrator password are prone to shared/static local admin creds enabling lateral movement.".into(),
            impact: Some("Local admin passwords are either shared across the fleet (lateral movement pivot in one hop) or unmanaged/weak. A single-machine compromise cascades domain-wide via reused local-admin credentials.".into()),
            remediation: "Deploy Windows LAPS domain-wide and confirm expiration attributes populate.".into(),
        }]
    }
}

/// Accounts flagged PASSWD_NOTREQD — may authenticate with an empty password.
pub struct PasswordNotRequired;
impl Check for PasswordNotRequired {
    fn id(&self) -> &'static str {
        "P-PasswdNotReqd"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<(String, u32)> = snap
            .iter_class("user")
            .filter(|o| o.uac() & uac::PASSWD_NOTREQD != 0 && o.uac() & uac::ACCOUNTDISABLE == 0)
            .map(|o| (o.dn.clone(), o.uac()))
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(dn, u)| {
                Evidence::new(
                    format!("LDAP {dn}:userAccountControl"),
                    format!("0x{u:08X} (PASSWD_NOTREQD 0x20 set)"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "Accounts with PASSWD_NOTREQD set".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Medium,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 3,
            affected: hits.iter().map(|(dn, _)| dn.clone()).collect(),
            evidence,
            detail: "PASSWD_NOTREQD lets the account be set to (or keep) an empty password, bypassing the password policy.".into(),
            impact: Some("The account can authenticate with an empty password. Any spray/enumeration script tries blank first: one authenticated shell inside the domain, often on a service account with more rights than expected.".into()),
            remediation: "Clear the flag and enforce a password reset.".into(),
        }]
    }
}

/// Privileged well-known SIDs used to grade sIDHistory injection.
fn is_privileged_sid(sid: &Sid) -> bool {
    // BUILTIN Administrators + operators: S-1-5-32-{544,548,549,550,551,552}
    if sid.identifier_authority == 5 && sid.sub_authorities.first() == Some(&32) {
        if let Some(r) = sid.rid() {
            if matches!(r, 544 | 548 | 549 | 550 | 551 | 552) {
                return true;
            }
        }
    }
    // Domain: Administrator 500, krbtgt 502, Domain/Schema/Enterprise Admins etc.
    matches!(
        sid.rid(),
        Some(500 | 502 | 512 | 516 | 518 | 519 | 520 | 521)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_core::snapshot::{DomainInfo, Snapshot};
    use std::collections::HashMap;

    fn user_with_sidhistory(rid_hist: u32, domain: &Sid) -> AdObject {
        let mut a: HashMap<String, Vec<String>> = HashMap::new();
        a.insert("objectClass".into(), vec!["user".into()]);
        let mut sh = domain.sub_authorities.clone();
        sh.push(rid_hist);
        let hist = Sid {
            revision: 1,
            identifier_authority: 5,
            sub_authorities: sh,
        };
        // serialize the SID back to bytes for the binary attribute
        let mut bytes = vec![hist.revision, hist.sub_authorities.len() as u8];
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, hist.identifier_authority as u8]);
        for s in &hist.sub_authorities {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        let mut bin: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        bin.insert("sIDHistory".into(), vec![bytes]);
        AdObject {
            dn: "CN=migrated,DC=corp,DC=local".into(),
            attrs: a,
            bin,
        }
    }

    #[test]
    fn privileged_sidhistory_is_critical() {
        let domain = Sid::parse("S-1-5-21-1-2-3").unwrap();
        let snap = Snapshot::new(
            DomainInfo {
                domain_sid: Some(domain.clone()),
                ..Default::default()
            },
            vec![user_with_sidhistory(512, &domain)], // Domain Admins RID
        );
        let g = ControlGraph::build(&snap);
        let f = SidHistory.run(&snap, &g);
        assert!(f.iter().any(|x| x.id == "P-SidHistoryPriv"));
    }
}
