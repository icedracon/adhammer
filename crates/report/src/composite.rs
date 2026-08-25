//! Composite attack-chain narrative — cross-references the flat finding list
//! post-scan and emits English chains ("Coercion + ESC8 → DA cert", …) so a
//! reader sees the actual playable path, not just the individual weaknesses.
//!
//! Initial 4-chain set uses only finding IDs that fire in adhammer today (see
//! `crates/checks/` + `cli/src/attacks/scan.rs`). Extend when the underlying
//! detection lands — a chain that requires an ID no check emits stays silently
//! `present: false` and does not surface in reports.

use adhammer_core::Finding;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct CompositeChain {
    pub title: &'static str,
    /// Finding-id prefixes required for this chain to be present. A precondition
    /// matches if ANY finding's `id` starts with the prefix — lets us match
    /// `A-Esc1` and `A-Esc1-ms-crtd` (the two ESC1 detectors) with one entry.
    pub requires: Vec<&'static str>,
    pub impact: &'static str,
    pub present: bool,
}

/// Detect every composite chain against `findings`. Returns the full rule set
/// (present + absent) so downstream consumers can render "chains checked / N
/// present" counts. Reports show only `present == true` in the narrative.
pub fn detect(findings: &[Finding]) -> Vec<CompositeChain> {
    let has = |prefix: &str| findings.iter().any(|f| f.id.starts_with(prefix));
    let mut chains = rule_set();
    for c in &mut chains {
        c.present = c.requires.iter().all(|p| has(p));
    }
    chains
}

fn rule_set() -> Vec<CompositeChain> {
    vec![
        CompositeChain {
            title: "Coercion + ADCS ESC8",
            requires: vec!["A-Esc8"],
            impact: "relay coerced DC NTLM to the CA's HTTP web-enrollment → DA machine cert → PKINIT for the DC TGT → DCSync.",
            present: false,
        },
        CompositeChain {
            title: "ESC1 template enrollable by any user",
            requires: vec!["A-Esc1"],
            impact: "enroll a cert with SAN = arbitrary UPN → PKINIT for that user's TGT (typically DA).",
            present: false,
        },
        CompositeChain {
            title: "MAQ > 0 + ADCS ESC8",
            requires: vec!["A-MachineAccountQuota", "A-Esc8"],
            impact: "create rogue machine (MAQ let-through) → coerce it → relay its NTLM to CA web-enrollment → DA cert → PKINIT.",
            present: false,
        },
        CompositeChain {
            title: "DCSync path + writable Shadow Credentials",
            requires: vec!["P-DcsyncPath", "P-ShadowCred"],
            impact: "plant KeyCredentialLink on the DCSync-capable principal → PKINIT for its TGT → DCSync the whole domain.",
            present: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_core::finding::{Category, Severity};

    fn f(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            title: id.to_string(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![],
            affected: vec![],
            evidence: Vec::new(),
            detail: String::new(),
            impact: None,
            remediation: String::new(),
            weight_bonus: 0,
        }
    }

    #[test]
    fn coercion_esc8_present_when_a_esc8_fires() {
        let findings = vec![f("A-Esc8")];
        let chains = detect(&findings);
        assert!(chains
            .iter()
            .any(|c| c.title == "Coercion + ADCS ESC8" && c.present));
        assert!(chains
            .iter()
            .any(|c| c.title == "ESC1 template enrollable by any user" && !c.present));
    }

    #[test]
    fn maq_and_esc8_needs_both() {
        assert!(!detect(&[f("A-MachineAccountQuota")])
            .iter()
            .any(|c| c.title == "MAQ > 0 + ADCS ESC8" && c.present));
        assert!(detect(&[f("A-MachineAccountQuota"), f("A-Esc8")])
            .iter()
            .any(|c| c.title == "MAQ > 0 + ADCS ESC8" && c.present));
    }

    #[test]
    fn esc1_prefix_match_covers_both_ids() {
        assert!(detect(&[f("A-Esc1")])
            .iter()
            .any(|c| c.title == "ESC1 template enrollable by any user" && c.present));
        assert!(detect(&[f("A-Esc1-ms-crtd")])
            .iter()
            .any(|c| c.title == "ESC1 template enrollable by any user" && c.present));
    }

    #[test]
    fn dcsync_shadowcred_composite() {
        let ok = vec![f("P-DcsyncPath"), f("P-ShadowCred")];
        assert!(detect(&ok)
            .iter()
            .any(|c| c.title == "DCSync path + writable Shadow Credentials" && c.present));
    }

    #[test]
    fn empty_findings_no_chain_present() {
        assert!(detect(&[]).iter().all(|c| !c.present));
    }
}
