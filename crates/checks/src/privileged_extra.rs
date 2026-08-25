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

/// Classic constrained delegation: an account with `msDS-AllowedToDelegateTo` can obtain service
/// tickets to the listed SPNs as ANY user (S4U2Proxy) — a lateral-movement / privesc surface.
/// (WS-COVERAGE, 1.4.3.)
pub struct ConstrainedDelegation;
impl Check for ConstrainedDelegation {
    fn id(&self) -> &'static str {
        "P-ConstrainedDelegation"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for o in snap.objects.iter() {
            let targets = o.all("msDS-AllowedToDelegateTo");
            if !targets.is_empty() {
                affected.push(o.dn.clone());
                if evidence.len() < 25 {
                    evidence.push(Evidence::new(
                        format!("LDAP {}:msDS-AllowedToDelegateTo", o.dn),
                        targets.join(", "),
                    ));
                }
            }
        }
        if affected.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Constrained delegation configured (msDS-AllowedToDelegateTo)".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 5,
            affected,
            evidence,
            detail: "The account can request service tickets to the listed SPNs as ANY user (S4U2Proxy). If its credentials or a protocol-transition path are compromised, it impersonates privileged users to those services.".into(),
            impact: Some("Attacker who controls this account runs S4U2Self+S4U2Proxy to impersonate a Domain Admin to the target service — lateral movement or Tier-0 access without the target's password.".into()),
            remediation: "Scope delegation tightly; prefer resource-based constrained delegation; mark sensitive accounts 'account is sensitive and cannot be delegated' / add to Protected Users.".into(),
        }]
    }
}

/// Any enabled user account holding an SPN is Kerberoastable — the full offline-crack surface,
/// broader than the admin-only `P-KerberoastAdmin`. (WS-COVERAGE, 1.4.3.)
pub struct KerberoastableUsers;
impl Check for KerberoastableUsers {
    fn id(&self) -> &'static str {
        "P-KerberoastableUser"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for o in snap.iter_class("user") {
            let spns = o.all("servicePrincipalName");
            // krbtgt carries an SPN by design and isn't roastable in practice.
            let is_krbtgt = o
                .one("sAMAccountName")
                .is_some_and(|s| s.eq_ignore_ascii_case("krbtgt"));
            if !spns.is_empty() && o.uac() & uac::ACCOUNTDISABLE == 0 && !is_krbtgt {
                affected.push(o.dn.clone());
                if evidence.len() < 25 {
                    evidence.push(Evidence::new(
                        format!("LDAP {}:servicePrincipalName", o.dn),
                        spns.join(", "),
                    ));
                }
            }
        }
        if affected.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Kerberoastable service accounts (user + SPN)".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Medium,
            mitre: vec![mitre::KERBEROASTING],
            weight_bonus: affected.len() as u32 * 2,
            affected,
            evidence,
            detail: "Any authenticated user can request a TGS for these SPN-holding accounts and crack the encrypted portion offline to recover the account's password.".into(),
            impact: Some("Attacker Kerberoasts the account, cracks a weak password offline in minutes-to-hours, and logs in as the service account — often a foothold for further privilege escalation.".into()),
            remediation: "Use gMSA or 25+ char random passwords, enforce AES-only, and remove unused SPNs.".into(),
        }]
    }
}

/// Privileged (adminCount=1) accounts NOT flagged "account is sensitive and cannot be delegated"
/// (UAC NOT_DELEGATED 0x100000) — their TGTs can be captured by an unconstrained-delegation host or
/// abused via constrained delegation. (WS-COVERAGE, 1.4.3.)
pub struct AdminsDelegatable;
impl Check for AdminsDelegatable {
    fn id(&self) -> &'static str {
        "P-AdminDelegatable"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        const NOT_DELEGATED: u32 = 0x0010_0000;
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for o in snap.iter_class("user") {
            if o.int("adminCount") == Some(1)
                && o.uac() & uac::ACCOUNTDISABLE == 0
                && o.uac() & NOT_DELEGATED == 0
            {
                affected.push(o.dn.clone());
                if evidence.len() < 25 {
                    evidence.push(Evidence::new(
                        format!("LDAP {}:userAccountControl", o.dn),
                        format!(
                            "0x{:08X} (adminCount=1; NOT_DELEGATED 0x100000 clear)",
                            o.uac()
                        ),
                    ));
                }
            }
        }
        if affected.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Privileged accounts are delegatable (missing 'sensitive, cannot be delegated')".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Medium,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 3,
            affected,
            evidence,
            detail: "The account's TGT can be delegated. An unconstrained-delegation host that the account authenticates to caches its TGT; a constrained/RBCD path can impersonate it.".into(),
            impact: Some("Attacker coerces the admin to authenticate to a delegation-enabled host, captures the TGT, and replays it — Tier-0 access without the password.".into()),
            remediation: "Set 'account is sensitive and cannot be delegated' (UAC NOT_DELEGATED) on Tier-0 accounts, or add them to Protected Users.".into(),
        }]
    }
}

/// A privileged (adminCount=1) account carrying `msDS-KeyCredentialLink` (an NGC key). Legitimate
/// for Windows Hello for Business, but an unexpected key on a Tier-0 account is a PKINIT backdoor an
/// attacker may have planted (Shadow Credentials persistence). (WS-COVERAGE, 1.4.3.)
pub struct KeyCredentialOnAdmin;
impl Check for KeyCredentialOnAdmin {
    fn id(&self) -> &'static str {
        "P-KeyCredentialOnAdmin"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for o in snap.iter_class("user") {
            let keys = o.all("msDS-KeyCredentialLink");
            if !keys.is_empty() && o.int("adminCount") == Some(1) {
                affected.push(o.dn.clone());
                if evidence.len() < 25 {
                    evidence.push(Evidence::new(
                        format!("LDAP {}:msDS-KeyCredentialLink", o.dn),
                        format!(
                            "{} NGC key(s) present on an adminCount=1 account",
                            keys.len()
                        ),
                    ));
                }
            }
        }
        if affected.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Key credential (NGC) on a privileged account (possible Shadow Credentials)".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::CERT_ABUSE],
            weight_bonus: affected.len() as u32 * 5,
            affected,
            evidence,
            detail: "msDS-KeyCredentialLink is set on a Tier-0 account. If not a deliberate Windows Hello for Business enrollment, it is a planted PKINIT key granting silent authentication as the account.".into(),
            impact: Some("An attacker who planted the key PKINITs as the admin at will — a passwordless, password-reset-surviving backdoor into Tier-0.".into()),
            remediation: "Verify every KeyCredentialLink on privileged accounts; remove unexpected NGC keys; restrict who can write msDS-KeyCredentialLink on Tier-0 objects.".into(),
        }]
    }
}

/// A broad principal (Everyone / Authenticated Users / Domain Users / Domain Computers) that is a
/// DIRECT member of a Tier-0 group (Domain/Enterprise/Schema Admins, Administrators) — every
/// authenticated user is effectively Domain Admin. (WS-COVERAGE, 1.4.3.)
pub struct BroadInTier0Group;
impl Check for BroadInTier0Group {
    fn id(&self) -> &'static str {
        "P-BroadInTier0"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let dsid = snap.domain.domain_sid.as_ref();
        let groups = [
            ("Domain Admins", GroupRef::Domain(512)),
            ("Enterprise Admins", GroupRef::Domain(519)),
            ("Schema Admins", GroupRef::Domain(518)),
            ("Administrators", GroupRef::Builtin(544)),
        ];
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for (label, spec) in &groups {
            let Some(grp) = resolve(snap, spec) else {
                continue;
            };
            for member_dn in grp.all("member") {
                let Some(m) = snap.by_dn(member_dn) else {
                    continue;
                };
                let Some(sid) = m.bin1("objectSid").and_then(Sid::from_bytes) else {
                    continue;
                };
                if is_broad(&sid, dsid) {
                    affected.push(format!("{member_dn} in {label}"));
                    if evidence.len() < 25 {
                        evidence.push(Evidence::new(
                            format!("LDAP {}:member", grp.dn),
                            format!(
                                "broad principal {sid} ({member_dn}) is a direct member of {label}"
                            ),
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
            title: "Broad principal directly in a Tier-0 group".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Critical,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 20,
            affected,
            evidence,
            detail: "A low-privilege / everyone-scoped principal is a direct member of Domain/Enterprise/Schema Admins or Administrators — every authenticated user inherits Tier-0.".into(),
            impact: Some("Any authenticated user is already Domain Admin — DCSync the krbtgt, forge a golden ticket, own the forest. No escalation needed.".into()),
            remediation: "Remove the broad principal from the Tier-0 group immediately; audit how and when it was added.".into(),
        }]
    }
}

/// Key Admins (RID 526) / Enterprise Key Admins (RID 527) with any members. These groups can write
/// `msDS-KeyCredentialLink` on user and computer objects domain-wide — i.e. register a Shadow
/// Credential and PKINIT as ANY principal. They are missing from the classic operator-group sweep
/// yet are effectively Tier-0. (WS-COVERAGE, 1.4.3.)
pub struct KeyAdminsPopulated;
impl Check for KeyAdminsPopulated {
    fn id(&self) -> &'static str {
        "P-KeyAdmins"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let groups = [
            ("Key Admins", GroupRef::Domain(526)),
            ("Enterprise Key Admins", GroupRef::Domain(527)),
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
            .map(|(label, _, m)| format!("{label} ({} members)", m.len()))
            .collect();
        let evidence: Vec<Evidence> = hits
            .iter()
            .take(25)
            .map(|(label, dn, m)| {
                Evidence::new(
                    format!("LDAP {dn}:member"),
                    format!(
                        "{label}: {} member(s), e.g. {}",
                        m.len(),
                        m.first().map(String::as_str).unwrap_or("<none>")
                    ),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "Populated Key Admins / Enterprise Key Admins".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::CERT_ABUSE],
            weight_bonus: affected.len() as u32 * 8,
            affected,
            evidence,
            detail: "Members of Key Admins / Enterprise Key Admins can write msDS-KeyCredentialLink on directory objects, letting them register an NGC key and PKINIT as the target — a domain-wide Shadow Credentials primitive.".into(),
            impact: Some("A member adds a key credential to any account (including a Domain Admin) and authenticates via PKINIT as that principal — passwordless impersonation without touching the target's password.".into()),
            remediation: "Empty these groups unless Windows Hello for Business enrollment genuinely requires them; use just-in-time membership and treat any member as Tier-0.".into(),
        }]
    }
}

/// Privileged (adminCount=1) enabled accounts that are NOT in the Protected Users group, *when that
/// group is already in use* (non-empty). Complementary to `A-ProtectedUsers` (which fires only when
/// the group is entirely empty): here the org adopted Protected Users but left some admins out, so
/// those specific accounts keep RC4 TGTs, delegation, and NTLM exposure. (WS-COVERAGE, 1.4.3.)
pub struct AdminNotProtected;
impl Check for AdminNotProtected {
    fn id(&self) -> &'static str {
        "P-AdminNotProtected"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let Some(dsid) = snap.domain.domain_sid.as_ref() else {
            return vec![];
        };
        let Some(pu) = snap.by_sid(&domain_sid_with_rid(dsid, 525)) else {
            return vec![];
        };
        // Only meaningful once Protected Users is actually populated — otherwise A-ProtectedUsers owns it.
        let members: std::collections::HashSet<String> = pu
            .all("member")
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .collect();
        if members.is_empty() {
            return vec![];
        }
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for o in snap.iter_class("user") {
            if o.int("adminCount") == Some(1)
                && o.uac() & uac::ACCOUNTDISABLE == 0
                && !members.contains(&o.dn.to_ascii_lowercase())
            {
                affected.push(o.dn.clone());
                if evidence.len() < 25 {
                    evidence.push(Evidence::new(
                        format!("LDAP {}:memberOf/adminCount", o.dn),
                        format!(
                            "adminCount=1, enabled; absent from Protected Users ({} member(s))",
                            members.len()
                        ),
                    ));
                }
            }
        }
        if affected.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Privileged accounts missing from Protected Users".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 2,
            affected,
            evidence,
            detail: "The domain uses Protected Users, but these adminCount=1 accounts are not members — they keep the credential-theft exposures Protected Users would remove (RC4 TGTs, delegation, NTLM, long ticket lifetime).".into(),
            impact: Some("These specific admins remain Kerberoast/PtH/delegation-exposed while the org believes Protected Users covers its Tier-0 — an easily-overlooked gap that leaves the highest-value accounts unhardened.".into()),
            remediation: "Add every Tier-0 account to Protected Users after validating compatibility (no RC4-only services, no required delegation).".into(),
        }]
    }
}

/// The Tier-0 + operator group set, resolved once per check that sweeps privileged membership.
fn tier0_and_operator_groups() -> [(&'static str, GroupRef); 10] {
    [
        ("Domain Admins", GroupRef::Domain(512)),
        ("Enterprise Admins", GroupRef::Domain(519)),
        ("Schema Admins", GroupRef::Domain(518)),
        ("Administrators", GroupRef::Builtin(544)),
        ("Account Operators", GroupRef::Builtin(548)),
        ("Backup Operators", GroupRef::Builtin(551)),
        ("Print Operators", GroupRef::Builtin(550)),
        ("Server Operators", GroupRef::Builtin(549)),
        ("Key Admins", GroupRef::Domain(526)),
        ("Enterprise Key Admins", GroupRef::Domain(527)),
    ]
}

/// A foreign-forest / cross-domain principal that is a direct member of a Tier-0 or operator group.
/// These come in via `CN=ForeignSecurityPrincipals` (a trusted-forest SID) and are easy to miss in a
/// single-domain audit, yet grant that external principal privileged access here. (WS-COVERAGE, 1.4.3.)
pub struct ForeignPrincipalInPrivGroup;
impl Check for ForeignPrincipalInPrivGroup {
    fn id(&self) -> &'static str {
        "P-ForeignInPriv"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for (label, spec) in tier0_and_operator_groups() {
            let Some(grp) = resolve(snap, &spec) else {
                continue;
            };
            for member_dn in grp.all("member") {
                let is_fsp_dn = member_dn
                    .to_ascii_lowercase()
                    .contains(",cn=foreignsecurityprincipals,");
                let is_fsp_class = snap
                    .by_dn(member_dn)
                    .is_some_and(|m| m.has_class("foreignSecurityPrincipal"));
                if is_fsp_dn || is_fsp_class {
                    affected.push(format!("{member_dn} in {label}"));
                    if evidence.len() < 25 {
                        evidence.push(Evidence::new(
                            format!("LDAP {}:member", grp.dn),
                            format!("foreign security principal {member_dn} is a direct member of {label}"),
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
            title: "Foreign/cross-forest principal in a privileged group".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 5,
            affected,
            evidence,
            detail: "A principal from a trusted forest/domain (ForeignSecurityPrincipal) holds direct membership in a Tier-0 or operator group, extending privileged access across the trust boundary.".into(),
            impact: Some("Whoever controls that external account has privileged rights in this domain. Compromise or abuse in the trusted forest becomes compromise here, across a boundary most audits don't cross.".into()),
            remediation: "Review every ForeignSecurityPrincipal in privileged groups; remove unless the cross-forest grant is explicitly required and the source forest is equally trusted.".into(),
        }]
    }
}

/// A computer account (`computer` class or a `$`-suffixed sAMAccountName) that is a direct member of
/// Domain/Enterprise/Schema Admins or Administrators. Legitimate cluster/management setups rarely
/// need this; more often it is RBCD staging or attacker persistence. (WS-COVERAGE, 1.4.3.)
pub struct ComputerInPrivGroup;
impl Check for ComputerInPrivGroup {
    fn id(&self) -> &'static str {
        "P-ComputerInPriv"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let groups = [
            ("Domain Admins", GroupRef::Domain(512)),
            ("Enterprise Admins", GroupRef::Domain(519)),
            ("Schema Admins", GroupRef::Domain(518)),
            ("Administrators", GroupRef::Builtin(544)),
        ];
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for (label, spec) in &groups {
            let Some(grp) = resolve(snap, spec) else {
                continue;
            };
            for member_dn in grp.all("member") {
                let Some(m) = snap.by_dn(member_dn) else {
                    continue;
                };
                let is_computer = m.has_class("computer")
                    || m.one("sAMAccountName").is_some_and(|s| s.ends_with('$'));
                if is_computer {
                    affected.push(format!("{member_dn} in {label}"));
                    if evidence.len() < 25 {
                        let sam = m.one("sAMAccountName").unwrap_or("<unknown>");
                        evidence.push(Evidence::new(
                            format!("LDAP {}:member", grp.dn),
                            format!("computer account {sam} ({member_dn}) is a direct member of {label}"),
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
            title: "Computer account in a Tier-0 group".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 6,
            affected,
            evidence,
            detail: "A machine account is a direct member of a Tier-0 group. Anyone who controls that machine (local SYSTEM, or an RBCD/coercion path to its TGT) inherits Domain Admin.".into(),
            impact: Some("Compromising the machine — or coercing/relaying its computer-account authentication — yields Tier-0. Attackers also add a controlled machine account here for stealthy, reboot-surviving persistence.".into()),
            remediation: "Remove computer accounts from Tier-0 groups; grant the needed rights to a dedicated, monitored service account or via a resource-specific delegation instead.".into(),
        }]
    }
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

    fn sid_bytes(s: &Sid) -> Vec<u8> {
        let mut b = vec![s.revision, s.sub_authorities.len() as u8];
        b.extend_from_slice(&[0, 0, 0, 0, 0, s.identifier_authority as u8]);
        for sub in &s.sub_authorities {
            b.extend_from_slice(&sub.to_le_bytes());
        }
        b
    }

    fn group(dn: &str, rid: u32, members: &[&str], domain: &Sid) -> AdObject {
        let sid = domain_sid_with_rid(domain, rid);
        let mut a: HashMap<String, Vec<String>> = HashMap::new();
        a.insert("objectClass".into(), vec!["group".into()]);
        a.insert(
            "member".into(),
            members.iter().map(|m| m.to_string()).collect(),
        );
        let mut bin: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        bin.insert("objectSid".into(), vec![sid_bytes(&sid)]);
        AdObject {
            dn: dn.into(),
            attrs: a,
            bin,
        }
    }

    #[test]
    fn key_admins_populated_flags() {
        let domain = Sid::parse("S-1-5-21-1-2-3").unwrap();
        let ka = group(
            "CN=Key Admins,DC=corp,DC=local",
            526,
            &["CN=bob,DC=corp,DC=local"],
            &domain,
        );
        let snap = Snapshot::new(
            DomainInfo {
                domain_sid: Some(domain.clone()),
                ..Default::default()
            },
            vec![ka],
        );
        let g = ControlGraph::build(&snap);
        assert!(KeyAdminsPopulated
            .run(&snap, &g)
            .iter()
            .any(|x| x.id == "P-KeyAdmins"));
    }

    #[test]
    fn admin_not_protected_flags_when_pu_used() {
        let domain = Sid::parse("S-1-5-21-1-2-3").unwrap();
        let pu = group(
            "CN=Protected Users,DC=corp,DC=local",
            525,
            &["CN=carol,DC=corp,DC=local"],
            &domain,
        );
        let mut admin_attrs: HashMap<String, Vec<String>> = HashMap::new();
        admin_attrs.insert("objectClass".into(), vec!["user".into()]);
        admin_attrs.insert("adminCount".into(), vec!["1".into()]);
        admin_attrs.insert("userAccountControl".into(), vec!["512".into()]);
        let admin = AdObject {
            dn: "CN=svc-admin,DC=corp,DC=local".into(),
            attrs: admin_attrs,
            bin: HashMap::new(),
        };
        let snap = Snapshot::new(
            DomainInfo {
                domain_sid: Some(domain.clone()),
                ..Default::default()
            },
            vec![pu, admin],
        );
        let g = ControlGraph::build(&snap);
        assert!(AdminNotProtected
            .run(&snap, &g)
            .iter()
            .any(|x| x.id == "P-AdminNotProtected"));
        // clean when Protected Users is empty (A-ProtectedUsers owns that case)
        let domain2 = Sid::parse("S-1-5-21-9-9-9").unwrap();
        let empty_pu = group("CN=Protected Users,DC=x,DC=y", 525, &[], &domain2);
        let snap2 = Snapshot::new(
            DomainInfo {
                domain_sid: Some(domain2),
                ..Default::default()
            },
            vec![empty_pu],
        );
        assert!(AdminNotProtected.run(&snap2, &g).is_empty());
    }

    #[test]
    fn foreign_principal_in_priv_flags() {
        let domain = Sid::parse("S-1-5-21-1-2-3").unwrap();
        let da = group(
            "CN=Domain Admins,DC=corp,DC=local",
            512,
            &["CN=S-1-5-21-9-9-9-500,CN=ForeignSecurityPrincipals,DC=corp,DC=local"],
            &domain,
        );
        let snap = Snapshot::new(
            DomainInfo {
                domain_sid: Some(domain.clone()),
                ..Default::default()
            },
            vec![da],
        );
        let g = ControlGraph::build(&snap);
        assert!(ForeignPrincipalInPrivGroup
            .run(&snap, &g)
            .iter()
            .any(|x| x.id == "P-ForeignInPriv"));
    }

    #[test]
    fn computer_in_priv_flags() {
        let domain = Sid::parse("S-1-5-21-1-2-3").unwrap();
        let da = group(
            "CN=Domain Admins,DC=corp,DC=local",
            512,
            &["CN=WS01,DC=corp,DC=local"],
            &domain,
        );
        let mut c: HashMap<String, Vec<String>> = HashMap::new();
        c.insert("objectClass".into(), vec!["computer".into()]);
        c.insert("sAMAccountName".into(), vec!["WS01$".into()]);
        let comp = AdObject {
            dn: "CN=WS01,DC=corp,DC=local".into(),
            attrs: c,
            bin: HashMap::new(),
        };
        let snap = Snapshot::new(
            DomainInfo {
                domain_sid: Some(domain.clone()),
                ..Default::default()
            },
            vec![da, comp],
        );
        let g = ControlGraph::build(&snap);
        assert!(ComputerInPrivGroup
            .run(&snap, &g)
            .iter()
            .any(|x| x.id == "P-ComputerInPriv"));
    }
}
