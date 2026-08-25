//! Category: Anomalies — LDAP-decidable domain hygiene beyond the Kerberos/ADCS rules:
//! password policy, anonymous LDAP (dSHeuristics), Pre-Windows-2000 Compatible Access,
//! Protected Users usage, and an enabled Guest account.
//!
//! Note: LM/NTLM auth level and LDAP/SMB signing enforcement live in the DC registry /
//! default-domain GPO, not in LDAP — those belong to the (future) SMB/SYSVOL collector.

use super::Check;
use crate::util::{builtin_sid, domain_sid_with_rid, is_broad};
use adhammer_core::finding::{mitre, Category, Evidence, Severity};
use adhammer_core::object::uac;
use adhammer_core::sid::{rid, Sid};
use adhammer_core::snapshot::Snapshot;
use adhammer_core::Finding;
use adhammer_graph::ControlGraph;

/// Weak domain password policy (length, complexity, lockout, expiry) from the domain head.
pub struct WeakPasswordPolicy;
impl Check for WeakPasswordPolicy {
    fn id(&self) -> &'static str {
        "A-PasswordPolicy"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let Some(dom) = snap.by_dn(&snap.domain.domain_dn) else {
            return vec![];
        };
        let mut issues = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        let dn = &snap.domain.domain_dn;

        if let Some(len) = dom.int("minPwdLength") {
            if len < 8 {
                issues.push(format!("minimum password length is {len} (< 8)"));
                evidence.push(Evidence::new(
                    format!("LDAP {dn}:minPwdLength"),
                    format!("minPwdLength={len} (<8)"),
                ));
            }
        }
        // pwdProperties bit 0x1 = DOMAIN_PASSWORD_COMPLEX.
        if let Some(props) = dom.int("pwdProperties") {
            if props & 0x1 == 0 {
                issues.push("password complexity disabled".into());
                evidence.push(Evidence::new(
                    format!("LDAP {dn}:pwdProperties"),
                    format!("pwdProperties=0x{props:08X} (DOMAIN_PASSWORD_COMPLEX 0x1 clear)"),
                ));
            }
        }
        if dom.int("lockoutThreshold") == Some(0) {
            issues.push("account lockout disabled (password spray possible)".into());
            evidence.push(Evidence::new(
                format!("LDAP {dn}:lockoutThreshold"),
                "lockoutThreshold=0 (account lockout disabled)",
            ));
        }
        // maxPwdAge is a negative 100ns interval; 0 = passwords never expire.
        if dom.int("maxPwdAge") == Some(0) {
            issues.push("passwords never expire".into());
            evidence.push(Evidence::new(
                format!("LDAP {dn}:maxPwdAge"),
                "maxPwdAge=0 (passwords never expire)",
            ));
        }
        if issues.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Weak domain password policy".into(),
            category: Category::Anomalies,
            severity: Severity::Medium,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: issues.len() as u32 * 3,
            affected: issues,
            evidence,
            detail: "The default domain password policy allows weak or long-lived credentials, easing brute-force and spray attacks.".into(),
            impact: Some("Short minimum length + low complexity means accounts are crackable in hours from a single Kerberoast or AS-REP capture, and password-spray attacks succeed against multiple accounts before lockout fires.".into()),
            remediation: "Enforce length >= 14, complexity on, a lockout threshold, and finite maximum password age.".into(),
        }]
    }
}

/// Anonymous LDAP operations and AdminSDHolder exclusions via dSHeuristics.
pub struct DsHeuristics;
impl Check for DsHeuristics {
    fn id(&self) -> &'static str {
        "A-DsHeuristics"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let Some((h_dn, h)) = snap
            .objects
            .iter()
            .find_map(|o| o.one("dSHeuristics").map(|v| (o.dn.clone(), v.to_string())))
        else {
            return vec![];
        };
        let chars: Vec<char> = h.chars().collect();
        let mut out = Vec::new();

        // 7th character == '2' ⇒ fLDAPBlockAnonOps disabled ⇒ anonymous LDAP allowed.
        if chars.get(6) == Some(&'2') {
            out.push(Finding {
                id: "A-AnonLdap".into(),
                title: "Anonymous LDAP operations enabled (dSHeuristics)".into(),
                category: Category::Anomalies,
                severity: Severity::High,
                mitre: vec![mitre::VALID_ACCOUNTS],
                weight_bonus: 0,
                affected: vec![format!("dSHeuristics = {h}")],
                evidence: vec![Evidence::new(
                    format!("LDAP {h_dn}:dSHeuristics"),
                    format!("dSHeuristics=\"{h}\" (7th char '2' — fLDAPBlockAnonOps disabled)"),
                )],
                detail: "The 7th dSHeuristics character is '2', permitting unauthenticated LDAP reads of the directory.".into(),
                impact: Some("Unauthenticated attackers can enumerate the domain (users, groups, SPNs, policy) without a single credential, accelerating every subsequent attack path: Kerberoasting, targeting, deprovisioned-account reuse.".into()),
                remediation: "Clear the anonymous-operations flag (set the 7th dSHeuristics character to 0).".into(),
            });
        }
        // 16th character (dwAdminSDExMask) non-zero ⇒ groups excluded from AdminSDHolder.
        if matches!(chars.get(15), Some(c) if *c != '0') {
            out.push(Finding {
                id: "A-AdminSdExclusion".into(),
                title: "AdminSDHolder protection excludes some groups (dSHeuristics)".into(),
                category: Category::Anomalies,
                severity: Severity::Medium,
                mitre: vec![mitre::VALID_ACCOUNTS],
                weight_bonus: 0,
                affected: vec![format!("dSHeuristics = {h}")],
                evidence: vec![Evidence::new(
                    format!("LDAP {h_dn}:dSHeuristics"),
                    format!(
                        "dSHeuristics=\"{h}\" (16th char '{}' — dwAdminSDExMask set)",
                        chars.get(15).copied().unwrap_or('0')
                    ),
                )],
                detail: "dwAdminSDExMask is set, excluding operator groups from AdminSDHolder ACL propagation and weakening their protection.".into(),
                impact: Some("Unauthenticated attackers can enumerate the domain (users, groups, SPNs, policy) without a single credential, accelerating every subsequent attack path: Kerberoasting, targeting, deprovisioned-account reuse.".into()),
                remediation: "Reset the 16th dSHeuristics character to 0 unless the exclusion is justified.".into(),
            });
        }
        out
    }
}

/// Pre-Windows 2000 Compatible Access (S-1-5-32-554) containing a broad principal ⇒
/// anonymous/low-priv read of sensitive attributes.
pub struct PreWindows2000Compat;
impl Check for PreWindows2000Compat {
    fn id(&self) -> &'static str {
        "A-PreWin2000"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let dsid = snap.domain.domain_sid.as_ref();
        let Some(grp) = snap.by_sid(&builtin_sid(554)) else {
            return vec![];
        };
        let broad_members: Vec<(String, Sid)> = grp
            .all("member")
            .iter()
            .filter_map(|dn| {
                snap.by_dn(dn)
                    .and_then(|m| m.bin1("objectSid"))
                    .and_then(Sid::from_bytes)
                    .filter(|s| is_broad(s, dsid))
                    .map(|s| (dn.clone(), s))
            })
            .collect();
        if broad_members.is_empty() {
            return vec![];
        }
        let evidence: Vec<Evidence> = broad_members
            .iter()
            .take(25)
            .map(|(dn, s)| {
                Evidence::new(
                    format!("LDAP {dn}:objectSid"),
                    format!("{s} (broad principal, member of Pre-Windows 2000 Compatible Access S-1-5-32-554)"),
                )
            })
            .collect();
        vec![Finding {
            id: self.id().into(),
            title: "Pre-Windows 2000 Compatible Access contains a broad principal".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: broad_members.iter().map(|(dn, _)| dn.clone()).collect(),
            evidence,
            detail: "Everyone / Authenticated Users in this group grants near-anonymous read of sensitive attributes across the domain.".into(),
            impact: Some("Broad membership grants pre-auth anonymous read across the domain and can enable computer-account creation for RBCD chains.".into()),
            remediation: "Remove Everyone/Authenticated Users from Pre-Windows 2000 Compatible Access.".into(),
        }]
    }
}

/// Domain has privileged accounts but the Protected Users group (RID 525) is empty.
pub struct ProtectedUsersUnused;
impl Check for ProtectedUsersUnused {
    fn id(&self) -> &'static str {
        "A-ProtectedUsers"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let Some(dsid) = snap.domain.domain_sid.as_ref() else {
            return vec![];
        };
        let Some(grp) = snap.by_sid(&domain_sid_with_rid(dsid, 525)) else {
            return vec![];
        };
        if !grp.all("member").is_empty() {
            return vec![];
        }
        // Only meaningful if there are privileged accounts to protect.
        let Some(da_grp) = snap.by_sid(&domain_sid_with_rid(dsid, rid::DOMAIN_ADMINS)) else {
            return vec![];
        };
        let da_count = da_grp.all("member").len();
        if da_count == 0 {
            return vec![];
        }
        let evidence = vec![
            Evidence::new(
                format!("LDAP {}:member", grp.dn),
                "member=<empty> (Protected Users, RID 525, has 0 members)",
            ),
            Evidence::new(
                format!("LDAP {}:member", da_grp.dn),
                format!(
                    "Domain Admins member count = {da_count} (Tier-0 accounts exist to protect)"
                ),
            ),
        ];
        vec![Finding {
            id: self.id().into(),
            title: "Protected Users group is empty".into(),
            category: Category::Anomalies,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec!["Protected Users (0 members)".into()],
            evidence,
            detail: "Privileged accounts are not placed in Protected Users, so they remain exposed to credential theft (no RC4, no delegation, forced short TGT lifetime).".into(),
            impact: Some("Protected Users hardens membership against most credential-theft (no RC4 TGT, no unconstrained delegation, no NTLM). Empty = Tier-0 accounts remain vulnerable to Kerberoasting, PtH, and delegation abuse.".into()),
            remediation: "Add Tier-0 accounts to Protected Users after validating compatibility.".into(),
        }]
    }
}

/// The built-in Guest account (RID 501) is enabled.
pub struct GuestEnabled;
impl Check for GuestEnabled {
    fn id(&self) -> &'static str {
        "A-GuestEnabled"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let Some(guest) = snap.by_rid(rid::GUEST) else {
            return vec![];
        };
        if guest.uac() & uac::ACCOUNTDISABLE != 0 {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Built-in Guest account is enabled".into(),
            category: Category::Anomalies,
            severity: Severity::Medium,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec![guest.dn.clone()],
            evidence: vec![Evidence::new(
                format!("LDAP {}:userAccountControl", guest.dn),
                format!(
                    "0x{:08X} (ACCOUNTDISABLE 0x2 clear — Guest RID 501 enabled)",
                    guest.uac()
                ),
            )],
            detail:
                "An enabled Guest account provides an anonymous foothold and is rarely required."
                    .into(),
            impact: Some("Guest has no password and no auditing. An attacker with LAN access enumerates via SMB anonymous session, and any resource with Everyone/Authenticated permissions is reachable via a Guest logon.".into()),
            remediation: "Disable the Guest account.".into(),
        }]
    }
}

/// A user account whose `description` / `info` carries a password-like string — a classic place
/// admins stash service-account creds in cleartext, readable by ANY authenticated user over LDAP.
/// (WS-COVERAGE, 1.4.3.)
pub struct PasswordInDescription;
impl Check for PasswordInDescription {
    fn id(&self) -> &'static str {
        "A-PasswordInDescription"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for o in snap.iter_class("user") {
            for attr in ["description", "info"] {
                if let Some(v) = o.one(attr) {
                    if looks_like_password(v) {
                        affected.push(o.dn.clone());
                        if evidence.len() < 25 {
                            evidence.push(Evidence::new(format!("LDAP {}:{attr}", o.dn), v));
                        }
                        break;
                    }
                }
            }
        }
        if affected.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Password-like string in a user's description/info".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 5,
            affected,
            evidence,
            detail: "An account's description/info attribute holds a password-like value — cleartext \
                     credentials any authenticated user can read over LDAP."
                .into(),
            impact: Some("Any domain user reads the attribute and obtains the credential directly — no cracking, instant access as that account.".into()),
            remediation: "Remove secrets from description/info; rotate the exposed password; store credentials in a vault.".into(),
        }]
    }
}

/// Heuristic: a `pass`/`pwd` hint, or a spaceless 8-64 char string mixing ≥3 character classes.
fn looks_like_password(s: &str) -> bool {
    let s = s.trim();
    let lower = s.to_ascii_lowercase();
    if lower.contains("pass")
        || lower.contains("pwd")
        || lower.contains("pw:")
        || lower.contains("pw=")
    {
        return true;
    }
    let len = s.chars().count();
    if !(8..=64).contains(&len) || s.contains(' ') {
        return false;
    }
    let classes = [
        s.chars().any(|c| c.is_ascii_lowercase()),
        s.chars().any(|c| c.is_ascii_uppercase()),
        s.chars().any(|c| c.is_ascii_digit()),
        s.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    classes >= 3
}

/// A Fine-Grained Password Policy (PSO, `msDS-PasswordSettings`) with weak settings — the default
/// domain policy check misses these per-group overrides. (WS-COVERAGE, 1.4.3.)
pub struct WeakFineGrainedPolicy;
impl Check for WeakFineGrainedPolicy {
    fn id(&self) -> &'static str {
        "A-WeakFgpp"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for o in snap.iter_class("msDS-PasswordSettings") {
            let minlen = o.int("msDS-MinimumPasswordLength");
            let lockout = o.int("msDS-LockoutThreshold");
            let weak = minlen.is_some_and(|l| l < 8) || lockout == Some(0);
            if weak {
                let name = o.one("cn").or_else(|| o.one("name")).unwrap_or(&o.dn);
                affected.push(name.to_string());
                if evidence.len() < 25 {
                    evidence.push(Evidence::new(
                        format!(
                            "LDAP {}:msDS-MinimumPasswordLength/msDS-LockoutThreshold",
                            o.dn
                        ),
                        format!(
                            "msDS-MinimumPasswordLength={}, msDS-LockoutThreshold={}",
                            minlen
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "unset".into()),
                            lockout
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "unset".into()),
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
            title: "Weak Fine-Grained Password Policy (PSO)".into(),
            category: Category::Anomalies,
            severity: Severity::Medium,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 3,
            affected,
            evidence,
            detail: "A Password Settings Object overrides the domain policy for its target group with a short minimum length and/or no lockout — accounts under it are easier to spray or crack.".into(),
            impact: Some("Accounts governed by this PSO get weaker protection than the domain default — a targeted spray against that group succeeds where the domain policy would have blocked it.".into()),
            remediation: "Set the PSO to length >= 14, complexity on, and a lockout threshold; verify its msDS-PSOAppliesTo target.".into(),
        }]
    }
}

/// A directory object with a populated `userPassword` / `unixUserPassword` attribute — some
/// provisioning tools (inetOrgPerson sync, Identity Management for Unix / SFU) stash a
/// cleartext-or-crypt password there, and it is readable by ANY authenticated user over LDAP.
/// Distinct from `A-PasswordInDescription` (which scans description/info). (WS-COVERAGE, 1.4.3.)
pub struct CleartextSecretAttr;
impl Check for CleartextSecretAttr {
    fn id(&self) -> &'static str {
        "A-CleartextSecret"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        for o in &snap.objects {
            for attr in ["userPassword", "unixUserPassword"] {
                // The value may arrive as a string or as an octet-string binary attribute.
                let str_val = o.one(attr).filter(|s| !s.is_empty());
                let bin_len = o.bin1(attr).map(|b| b.len()).filter(|n| *n > 0);
                if str_val.is_none() && bin_len.is_none() {
                    continue;
                }
                affected.push(o.dn.clone());
                if evidence.len() < 25 {
                    // Proof: the attribute is set and LDAP-readable. Show length + a short printable
                    // prefix so a client can confirm by hand without the full secret in the report.
                    let detail = match (str_val, bin_len) {
                        (Some(v), _) => {
                            let n = v.chars().count();
                            let prefix: String = v.chars().take(2).collect();
                            format!("{attr} set, {n} char(s), starts \"{prefix}…\" — LDAP-readable")
                        }
                        (None, Some(n)) => {
                            format!("{attr} set, {n} byte(s) octet-string — LDAP-readable")
                        }
                        _ => unreachable!(),
                    };
                    evidence.push(Evidence::new(format!("LDAP {}:{attr}", o.dn), detail));
                }
                break;
            }
        }
        if affected.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Password stored in userPassword/unixUserPassword".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: affected.len() as u32 * 5,
            affected,
            evidence,
            detail: "An object carries a password in userPassword/unixUserPassword — a cleartext or \
                     reversibly-encoded credential that any authenticated user can read over LDAP."
                .into(),
            impact: Some("Any domain user reads the attribute and recovers the credential directly — no cracking. Common with directory-sync/SFU accounts that are also service accounts.".into()),
            remediation: "Clear userPassword/unixUserPassword; rotate the exposed credential; store secrets in a vault, never in a readable LDAP attribute.".into(),
        }]
    }
}

/// The domain default policy stores every user's password with reversible encryption
/// (`pwdProperties` bit DOMAIN_PASSWORD_STORE_CLEARTEXT 0x10). Distinct from the per-account
/// `A-ReversibleEncryption` (UAC 0x80) — this forces a recoverable cleartext-equivalent for the
/// WHOLE domain. (WS-COVERAGE, 1.4.3.)
pub struct DomainReversiblePwd;
impl Check for DomainReversiblePwd {
    fn id(&self) -> &'static str {
        "A-DomainReversiblePwd"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        const DOMAIN_PASSWORD_STORE_CLEARTEXT: i64 = 0x10;
        let Some(dom) = snap.by_dn(&snap.domain.domain_dn) else {
            return vec![];
        };
        let Some(props) = dom.int("pwdProperties") else {
            return vec![];
        };
        if props & DOMAIN_PASSWORD_STORE_CLEARTEXT == 0 {
            return vec![];
        }
        let dn = &snap.domain.domain_dn;
        vec![Finding {
            id: self.id().into(),
            title: "Domain policy stores all passwords with reversible encryption".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 20,
            affected: vec![dn.clone()],
            evidence: vec![Evidence::new(
                format!("LDAP {dn}:pwdProperties"),
                format!("0x{props:08X} (DOMAIN_PASSWORD_STORE_CLEARTEXT 0x10 set)"),
            )],
            detail: "The domain's pwdProperties has DOMAIN_PASSWORD_STORE_CLEARTEXT set — every account's password is stored reversibly encrypted in NTDS, a domain-wide cleartext-equivalent exposure.".into(),
            impact: Some("Anyone who dumps NTDS.dit (DCSync or offline extract) recovers EVERY user's plaintext password directly — no cracking. Worst-case credential exposure, and it applies to the whole domain rather than one account.".into()),
            remediation: "Clear DOMAIN_PASSWORD_STORE_CLEARTEXT (0x10) from the default domain policy's pwdProperties, then force a domain-wide password reset.".into(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_core::object::AdObject;
    use adhammer_core::snapshot::{DomainInfo, Snapshot};
    use std::collections::HashMap;

    fn obj(class: &str, attrs: &[(&str, &str)]) -> AdObject {
        let mut a: HashMap<String, Vec<String>> = HashMap::new();
        a.insert("objectClass".into(), vec![class.into()]);
        for (k, v) in attrs {
            a.insert((*k).into(), vec![(*v).into()]);
        }
        AdObject {
            dn: format!("CN={class},DC=corp,DC=local"),
            attrs: a,
            bin: HashMap::new(),
        }
    }

    #[test]
    fn anon_ldap_detected_from_dsheuristics() {
        // 7th char = '2'
        let ds = obj("nTDSService", &[("dSHeuristics", "0000002")]);
        let snap = Snapshot::new(DomainInfo::default(), vec![ds]);
        let g = ControlGraph::build(&snap);
        let f = DsHeuristics.run(&snap, &g);
        assert!(f.iter().any(|x| x.id == "A-AnonLdap"));
    }

    #[test]
    fn weak_policy_flags_no_lockout() {
        let mut dom = obj(
            "domainDNS",
            &[("lockoutThreshold", "0"), ("minPwdLength", "7")],
        );
        dom.dn = "DC=corp,DC=local".into();
        let snap = Snapshot::new(
            DomainInfo {
                domain_dn: "DC=corp,DC=local".into(),
                ..Default::default()
            },
            vec![dom],
        );
        let g = ControlGraph::build(&snap);
        let f = WeakPasswordPolicy.run(&snap, &g);
        assert!(f
            .iter()
            .any(|x| x.id == "A-PasswordPolicy" && x.affected.len() == 2));
    }

    #[test]
    fn cleartext_secret_flags_userpassword() {
        let u = obj("user", &[("userPassword", "Sup3rSecret!")]);
        let snap = Snapshot::new(DomainInfo::default(), vec![u]);
        let g = ControlGraph::build(&snap);
        let f = CleartextSecretAttr.run(&snap, &g);
        assert!(f.iter().any(|x| x.id == "A-CleartextSecret"));
        // clean when the attribute is absent
        let clean = obj("user", &[("sAMAccountName", "bob")]);
        let snap2 = Snapshot::new(DomainInfo::default(), vec![clean]);
        assert!(CleartextSecretAttr.run(&snap2, &g).is_empty());
    }

    #[test]
    fn domain_reversible_pwd_flags_store_cleartext_bit() {
        // pwdProperties 0x11 = complexity + STORE_CLEARTEXT
        let mut dom = obj("domainDNS", &[("pwdProperties", "17")]);
        dom.dn = "DC=corp,DC=local".into();
        let snap = Snapshot::new(
            DomainInfo {
                domain_dn: "DC=corp,DC=local".into(),
                ..Default::default()
            },
            vec![dom],
        );
        let g = ControlGraph::build(&snap);
        assert!(DomainReversiblePwd
            .run(&snap, &g)
            .iter()
            .any(|x| x.id == "A-DomainReversiblePwd"));
        // clean when the bit is clear (0x1 = complexity only)
        let mut dom2 = obj("domainDNS", &[("pwdProperties", "1")]);
        dom2.dn = "DC=corp,DC=local".into();
        let snap2 = Snapshot::new(
            DomainInfo {
                domain_dn: "DC=corp,DC=local".into(),
                ..Default::default()
            },
            vec![dom2],
        );
        assert!(DomainReversiblePwd.run(&snap2, &g).is_empty());
    }
}
