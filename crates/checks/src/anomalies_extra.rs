//! Category: Anomalies — LDAP-decidable domain hygiene beyond the Kerberos/ADCS rules:
//! password policy, anonymous LDAP (dSHeuristics), Pre-Windows-2000 Compatible Access,
//! Protected Users usage, and an enabled Guest account.
//!
//! Note: LM/NTLM auth level and LDAP/SMB signing enforcement live in the DC registry /
//! default-domain GPO, not in LDAP — those belong to the (future) SMB/SYSVOL collector.

use super::Check;
use crate::util::{builtin_sid, domain_sid_with_rid, is_broad};
use adhammer_core::finding::{mitre, Category, Severity};
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
        let Some(dom) = snap.by_dn(&snap.domain.domain_dn) else { return vec![] };
        let mut issues = Vec::new();

        if let Some(len) = dom.int("minPwdLength") {
            if len < 8 {
                issues.push(format!("minimum password length is {len} (< 8)"));
            }
        }
        // pwdProperties bit 0x1 = DOMAIN_PASSWORD_COMPLEX.
        if let Some(props) = dom.int("pwdProperties") {
            if props & 0x1 == 0 {
                issues.push("password complexity disabled".into());
            }
        }
        if dom.int("lockoutThreshold") == Some(0) {
            issues.push("account lockout disabled (password spray possible)".into());
        }
        // maxPwdAge is a negative 100ns interval; 0 = passwords never expire.
        if dom.int("maxPwdAge") == Some(0) {
            issues.push("passwords never expire".into());
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
            detail: "The default domain password policy allows weak or long-lived credentials, easing brute-force and spray attacks.".into(),
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
        let Some(h) = snap.objects.iter().find_map(|o| o.one("dSHeuristics")) else { return vec![] };
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
                detail: "The 7th dSHeuristics character is '2', permitting unauthenticated LDAP reads of the directory.".into(),
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
                detail: "dwAdminSDExMask is set, excluding operator groups from AdminSDHolder ACL propagation and weakening their protection.".into(),
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
        let Some(grp) = snap.by_sid(&builtin_sid(554)) else { return vec![] };
        let broad_members: Vec<String> = grp
            .all("member")
            .iter()
            .filter(|dn| {
                snap.by_dn(dn)
                    .and_then(|m| m.bin1("objectSid"))
                    .and_then(Sid::from_bytes)
                    .map(|s| is_broad(&s, dsid))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        if broad_members.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Pre-Windows 2000 Compatible Access contains a broad principal".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: broad_members,
            detail: "Everyone / Authenticated Users in this group grants near-anonymous read of sensitive attributes across the domain.".into(),
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
        let Some(dsid) = snap.domain.domain_sid.as_ref() else { return vec![] };
        let Some(grp) = snap.by_sid(&domain_sid_with_rid(dsid, 525)) else { return vec![] };
        if !grp.all("member").is_empty() {
            return vec![];
        }
        // Only meaningful if there are privileged accounts to protect.
        let has_admins = snap
            .by_sid(&domain_sid_with_rid(dsid, rid::DOMAIN_ADMINS))
            .map(|g| !g.all("member").is_empty())
            .unwrap_or(false);
        if !has_admins {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Protected Users group is empty".into(),
            category: Category::Anomalies,
            severity: Severity::Low,
            mitre: vec![mitre::VALID_ACCOUNTS],
            weight_bonus: 0,
            affected: vec!["Protected Users (0 members)".into()],
            detail: "Privileged accounts are not placed in Protected Users, so they remain exposed to credential theft (no RC4, no delegation, forced short TGT lifetime).".into(),
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
        let Some(guest) = snap.by_rid(rid::GUEST) else { return vec![] };
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
            detail: "An enabled Guest account provides an anonymous foothold and is rarely required.".into(),
            remediation: "Disable the Guest account.".into(),
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
        AdObject { dn: format!("CN={class},DC=corp,DC=local"), attrs: a, bin: HashMap::new() }
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
        let mut dom = obj("domainDNS", &[("lockoutThreshold", "0"), ("minPwdLength", "7")]);
        dom.dn = "DC=corp,DC=local".into();
        let snap = Snapshot::new(
            DomainInfo { domain_dn: "DC=corp,DC=local".into(), ..Default::default() },
            vec![dom],
        );
        let g = ControlGraph::build(&snap);
        let f = WeakPasswordPolicy.run(&snap, &g);
        assert!(f.iter().any(|x| x.id == "A-PasswordPolicy" && x.affected.len() == 2));
    }
}
