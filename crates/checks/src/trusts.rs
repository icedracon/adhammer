//! Category: Trusts. Pure-LDAP: `trustedDomain` objects live in `CN=System` under the
//! domain NC, so they arrive in the same sweep. All findings are decided from the
//! `trustAttributes` / `trustDirection` bitfields (MS-ADTS §6.1.6).

use super::Check;
use adhammer_core::finding::{mitre, Category, Severity};
use adhammer_core::object::AdObject;
use adhammer_core::snapshot::Snapshot;
use adhammer_core::Finding;
use adhammer_graph::ControlGraph;

// trustAttributes bits.
const TA_NON_TRANSITIVE: i64 = 0x0000_0001;
const TA_QUARANTINED_DOMAIN: i64 = 0x0000_0004; // SID filtering ENABLED
const TA_FOREST_TRANSITIVE: i64 = 0x0000_0008;
const TA_CROSS_ORGANIZATION: i64 = 0x0000_0010; // selective authentication
const TA_WITHIN_FOREST: i64 = 0x0000_0020;
const TA_TREAT_AS_EXTERNAL: i64 = 0x0000_0040;
const TA_USES_RC4: i64 = 0x0000_0080;
const TA_NO_TGT_DELEGATION: i64 = 0x0000_0200;

// trustDirection.
const TD_INBOUND: i64 = 0x1;
const TD_OUTBOUND: i64 = 0x2;

struct Trust {
    partner: String,
    attrs: i64,
    direction: i64,
}

impl Trust {
    fn from(o: &AdObject) -> Self {
        Trust {
            partner: o
                .one("trustPartner")
                .or_else(|| o.one("flatName"))
                .or_else(|| o.one("cn"))
                .unwrap_or(&o.dn)
                .to_string(),
            attrs: o.int("trustAttributes").unwrap_or(0),
            direction: o.int("trustDirection").unwrap_or(0),
        }
    }
    fn has(&self, bit: i64) -> bool {
        self.attrs & bit != 0
    }
    fn within_forest(&self) -> bool {
        self.has(TA_WITHIN_FOREST)
    }
    /// Trust is exploitable inbound: foreign principals can authenticate into us
    /// (we are the trusting/resource side).
    fn inbound_facing(&self) -> bool {
        self.direction & TD_INBOUND != 0 || self.direction & TD_OUTBOUND != 0
    }
}

/// SID filtering (quarantine) not enforced on an external / forest trust ⇒ SID history
/// injection lets the trusted side forge membership in our privileged groups.
pub struct SidFilteringDisabled;
impl Check for SidFilteringDisabled {
    fn id(&self) -> &'static str {
        "T-SidFiltering"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("trustedDomain")
            .map(Trust::from)
            .filter(|t| {
                !t.within_forest() // intra-forest trusts are implicitly trusted
                    && t.inbound_facing()
                    && (!t.has(TA_QUARANTINED_DOMAIN) || t.has(TA_TREAT_AS_EXTERNAL))
            })
            .map(|t| t.partner)
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "SID filtering not enforced on external/forest trust".into(),
            category: Category::Trusts,
            severity: Severity::High,
            mitre: vec![mitre::TRUST_MOD, mitre::VALID_ACCOUNTS],
            weight_bonus: hits.len() as u32 * 8,
            affected: hits,
            detail: "Without quarantine (SID filtering), a compromised trusted domain can inject SID history for our privileged RIDs (e.g. 512) and authenticate as Domain Admin.".into(),
            remediation: "Enable SID filtering: netdom trust /quarantine:Yes (external) or /enablesidhistory:No (forest); avoid TREAT_AS_EXTERNAL.".into(),
        }]
    }
}

/// Selective authentication not set: any principal from the trusted domain can
/// authenticate to any resource, instead of only where explicitly allowed.
pub struct SelectiveAuthDisabled;
impl Check for SelectiveAuthDisabled {
    fn id(&self) -> &'static str {
        "T-SelectiveAuth"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("trustedDomain")
            .map(Trust::from)
            .filter(|t| !t.within_forest() && t.inbound_facing() && !t.has(TA_CROSS_ORGANIZATION))
            .map(|t| t.partner)
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Selective authentication disabled on external/forest trust".into(),
            category: Category::Trusts,
            severity: Severity::Medium,
            mitre: vec![mitre::TRUST_MOD],
            weight_bonus: hits.len() as u32 * 3,
            affected: hits,
            detail: "Domain-wide (forest-wide) authentication lets every principal in the trusted domain authenticate to every resource, widening lateral movement.".into(),
            remediation: "Enable selective authentication and grant 'Allowed to authenticate' only where required.".into(),
        }]
    }
}

/// Forest trust that still permits TGT delegation across the boundary ⇒ unconstrained
/// delegation on the far side can capture our users' TGTs.
pub struct TgtDelegationAcrossTrust;
impl Check for TgtDelegationAcrossTrust {
    fn id(&self) -> &'static str {
        "T-TgtDelegation"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("trustedDomain")
            .map(Trust::from)
            .filter(|t| t.has(TA_FOREST_TRANSITIVE) && !t.has(TA_NO_TGT_DELEGATION))
            .map(|t| t.partner)
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "TGT delegation allowed across forest trust".into(),
            category: Category::Trusts,
            severity: Severity::Medium,
            mitre: vec![mitre::TRUST_MOD],
            weight_bonus: hits.len() as u32 * 5,
            affected: hits,
            detail: "The forest trust does not set the no-TGT-delegation flag; an unconstrained-delegation host in the trusted forest can capture forwarded TGTs of our users.".into(),
            remediation: "Set the CROSS_ORGANIZATION_NO_TGT_DELEGATION flag on the trust (netdom trust /EnableTGTDelegation:No).".into(),
        }]
    }
}

/// Trust negotiated with RC4 rather than AES.
pub struct Rc4Trust;
impl Check for Rc4Trust {
    fn id(&self) -> &'static str {
        "T-Rc4Trust"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("trustedDomain")
            .map(Trust::from)
            .filter(|t| t.has(TA_USES_RC4))
            .map(|t| t.partner)
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Trust uses RC4 encryption".into(),
            category: Category::Trusts,
            severity: Severity::Low,
            mitre: vec![mitre::TRUST_MOD],
            weight_bonus: 0,
            affected: hits,
            detail: "The trust key negotiates RC4; inter-realm TGTs are then RC4-encrypted and easier to forge/crack.".into(),
            remediation: "Enable AES on the trust and rotate the trust password.".into(),
        }]
    }
}

/// Non-transitive is generally *safer*; this rule instead flags the dangerous inverse —
/// a transitive external trust, which extends implicit trust to unknown third domains.
pub struct TransitiveExternalTrust;
impl Check for TransitiveExternalTrust {
    fn id(&self) -> &'static str {
        "T-TransitiveExternal"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let hits: Vec<String> = snap
            .iter_class("trustedDomain")
            .map(Trust::from)
            .filter(|t| !t.within_forest() && !t.has(TA_FOREST_TRANSITIVE) && !t.has(TA_NON_TRANSITIVE))
            .map(|t| t.partner)
            .collect();
        if hits.is_empty() {
            return vec![];
        }
        vec![Finding {
            id: self.id().into(),
            title: "Transitive external trust".into(),
            category: Category::Trusts,
            severity: Severity::Low,
            mitre: vec![mitre::TRUST_MOD],
            weight_bonus: 0,
            affected: hits,
            detail: "A transitive external trust can chain implicit trust to domains beyond the direct partner, expanding the reachable attack surface.".into(),
            remediation: "Make external trusts non-transitive unless a transitive path is explicitly required.".into(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_core::snapshot::{DomainInfo, Snapshot};
    use std::collections::HashMap;

    fn trust(attrs: i64, direction: i64) -> AdObject {
        let mut a: HashMap<String, Vec<String>> = HashMap::new();
        a.insert("objectClass".into(), vec!["trustedDomain".into()]);
        a.insert("trustPartner".into(), vec!["evil.example".into()]);
        a.insert("trustAttributes".into(), vec![attrs.to_string()]);
        a.insert("trustDirection".into(), vec![direction.to_string()]);
        AdObject { dn: "CN=evil.example,CN=System,DC=corp,DC=local".into(), attrs: a, bin: HashMap::new() }
    }

    #[test]
    fn external_trust_without_quarantine_flags_sid_filtering() {
        // external (no WITHIN_FOREST), bidirectional, quarantine OFF
        let snap = Snapshot::new(DomainInfo::default(), vec![trust(0, 3)]);
        let g = ControlGraph::build(&snap);
        assert!(SidFilteringDisabled.run(&snap, &g).iter().any(|f| f.id == "T-SidFiltering"));
    }

    #[test]
    fn quarantined_trust_is_clean() {
        let snap = Snapshot::new(DomainInfo::default(), vec![trust(TA_QUARANTINED_DOMAIN, 3)]);
        let g = ControlGraph::build(&snap);
        assert!(SidFilteringDisabled.run(&snap, &g).is_empty());
    }

    #[test]
    fn within_forest_trust_ignored() {
        let snap = Snapshot::new(DomainInfo::default(), vec![trust(TA_WITHIN_FOREST, 3)]);
        let g = ControlGraph::build(&snap);
        assert!(SidFilteringDisabled.run(&snap, &g).is_empty());
    }
}
