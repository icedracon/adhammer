//! ESC1-15 rule pack backed by [`ms_crtd::detect_esc`].
//!
//! adhammer's original [`crate::adcs::VulnerableCertTemplates`] check inspects
//! `AdObject` fields directly and enforces adhammer's "broad principal" ACL
//! model on top. This module runs the *offline* ms-crtd taxonomy in parallel —
//! for callers holding a `Vec<CertTemplate>` (from
//! `adhammer_collector::sources::adcs::templates_from`) that don't want to
//! re-run the ACL walk. The two produce complementary outputs and both feed
//! the same `Finding` sink.

use adhammer_core::finding::{mitre, Category, Severity};
use adhammer_core::Finding;
use ms_crtd::{detect_esc, CertTemplate, EscFinding};

/// Turn one ms-crtd `EscFinding` into an adhammer `Finding`.
fn to_finding(f: &EscFinding) -> Finding {
    match f {
        EscFinding::Esc1 {
            template,
            client_auth_eku,
            spn_supplied,
        } => Finding {
            id: "A-Esc1-ms-crtd".into(),
            title: "ESC1: enrollee-supplies-subject template with auth EKU (ms-crtd)".into(),
            category: Category::Anomalies,
            severity: Severity::Critical,
            mitre: vec![mitre::CERT_ABUSE, mitre::VALID_ACCOUNTS],
            affected: vec![template.clone()],
            detail: format!(
                "ms-crtd detected an ESC1-shaped template: client_auth_eku={client_auth_eku}, \
                 SAN-suppliable={spn_supplied}. Any principal that can enroll can request a cert \
                 for an arbitrary UPN and authenticate as that principal.",
            ),
            impact: Some("Attacker requests a cert from this template with SAN=Administrator@corp.local, then PKINITs the resulting cert to get an Administrator TGT. Full domain compromise from any authenticated user, no password crack required.".into()),
            remediation: "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT/SAN, require manager approval, \
                          or restrict enrollment to a trusted group."
                .into(),
            weight_bonus: 0,
        },
        EscFinding::Esc2 { template, .. } => Finding {
            id: "A-Esc2-ms-crtd".into(),
            title: "ESC2: Any-Purpose / SubCA template (ms-crtd)".into(),
            category: Category::Anomalies,
            severity: Severity::Critical,
            mitre: vec![mitre::CERT_ABUSE],
            affected: vec![template.clone()],
            detail: "Template exposes Any-Purpose (or no) EKU — issued cert is usable for \
                     domain authentication."
                .into(),
            impact: Some("Attacker enrolls a cert whose Any-Purpose EKU covers Client-Auth, then PKINITs it. Same outcome as ESC1: DA TGT from any low-priv account.".into()),
            remediation: "Constrain EKU set; require approval; restrict enrollment.".into(),
            weight_bonus: 0,
        },
        EscFinding::Esc3 { template, .. } => Finding {
            id: "A-Esc3-ms-crtd".into(),
            title: "ESC3: Enrollment Agent template (ms-crtd)".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![mitre::CERT_ABUSE],
            affected: vec![template.clone()],
            detail: "Template carries Certificate-Request-Agent EKU — holders can enroll on \
                     behalf of arbitrary principals."
                .into(),
            impact: Some("Attacker enrolls an Enrollment-Agent cert, then uses it to request a Client-Auth cert on behalf of any target user (e.g. Administrator) and PKINITs the result.".into()),
            remediation: "Restrict enrollment-agent templates to a dedicated group; require \
                          approval; scope with application policies."
                .into(),
            weight_bonus: 0,
        },
        EscFinding::Esc6 {
            ca_name,
            template_names,
            ..
        } => Finding {
            id: "A-Esc6-ms-crtd".into(),
            title: "ESC6: CA-side EDITF_ATTRIBUTESUBJECTALTNAME2 (ms-crtd)".into(),
            category: Category::Anomalies,
            severity: Severity::Critical,
            mitre: vec![mitre::CERT_ABUSE],
            affected: {
                let mut v = vec![ca_name.clone()];
                v.extend(template_names.iter().cloned());
                v
            },
            detail: format!(
                "CA `{ca_name}` has EDITF_ATTRIBUTESUBJECTALTNAME2 set — every listed template \
                 becomes SAN-injectable regardless of its own name-flag."
            ),
            impact: Some("The CA-wide flag forces every published template to honor caller-supplied SAN, effectively ESC1 on every enrollable template on this CA regardless of per-template config.".into()),
            remediation: "Clear EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA (certutil -setreg \
                          policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2) and restart the CA."
                .into(),
            weight_bonus: 0,
        },
        EscFinding::Esc9 { template } => Finding {
            id: "A-Esc9-ms-crtd".into(),
            title: "ESC9: NO_SECURITY_EXTENSION on auth-capable template (ms-crtd)".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![mitre::CERT_ABUSE],
            affected: vec![template.clone()],
            detail: "CT_FLAG_NO_SECURITY_EXTENSION drops the SID binding — weak certificate \
                     mapping opens UPN-alias impersonation."
                .into(),
            impact: Some("Cert issued without the SID security extension pairs with any weak altSecurityIdentities mapping (ESC14) or works against pre-KB5014754 DCs to impersonate the target account.".into()),
            remediation:
                "Clear the flag; enforce Full strong certificate mapping on DCs (KB5014754).".into(),
            weight_bonus: 0,
        },
        EscFinding::Esc13 {
            template,
            policy_oids,
        } => Finding {
            id: "A-Esc13-ms-crtd".into(),
            title: "ESC13: issuance-policy template linked to a group (ms-crtd)".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![mitre::CERT_ABUSE],
            affected: vec![template.clone()],
            detail: format!(
                "Template carries {} issuance policy OID(s) that may be group-linked, granting \
                 the certificate holder the linked group's rights.",
                policy_oids.len()
            ),
            impact: Some("Attacker enrolls the template, holds a cert whose issuance-policy OID grants membership in the linked (privileged) group at PKINIT time, obtaining a TGT that carries that group's rights.".into()),
            remediation: "Audit msPKI-Certificate-Policy OID→group links; restrict enrollment."
                .into(),
            weight_bonus: 0,
        },
        EscFinding::Esc15 { template } => Finding {
            id: "A-Esc15-ms-crtd".into(),
            title: "ESC15 / EKUwu: schema-v1 template enrollable (ms-crtd)".into(),
            category: Category::Anomalies,
            severity: Severity::Critical,
            mitre: vec![mitre::CERT_ABUSE],
            affected: vec![template.clone()],
            detail: "CVE-2024-49019: schema-v1 template lets the requester inject arbitrary \
                     application policies into the CSR."
                .into(),
            impact: Some("CVE-2024-49019 exploitation: attacker enrolls a v1 template requesting Client-Auth in the application policies, receives a cert usable for PKINIT, gets a TGT as any target account.".into()),
            remediation: "Upgrade v1 templates to v2+, require approval, apply CVE-2024-49019 \
                          patch."
                .into(),
            weight_bonus: 0,
        },
    }
}

/// Run [`ms_crtd::detect_esc`] over every template and lower the results into
/// adhammer `Finding`s.
pub fn detect_all(templates: &[CertTemplate]) -> Vec<Finding> {
    let mut out = Vec::new();
    for t in templates {
        for f in detect_esc(t) {
            out.push(to_finding(&f));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_crtd::flags::NameFlag;
    use ms_crtd::model::CertTemplate;
    use ms_crtd::oid::Oid;

    fn esc1_template() -> CertTemplate {
        CertTemplate {
            name: "VulnUser".into(),
            oid: Oid::new("1.3.6.1.4.1.311.21.8.1.42"),
            schema_version: 2,
            enrollment_flag: ms_crtd::flags::EnrollmentFlag::empty(),
            name_flag: NameFlag::ENROLLEE_SUPPLIES_SUBJECT,
            private_key_flag: ms_crtd::flags::PrivateKeyFlag::empty(),
            ekus: vec![Oid::new("1.3.6.1.5.5.7.3.2")],
            min_ra_signatures: 0,
            raw_security_descriptor: None,
        }
    }

    #[test]
    fn esc1_lowers_to_finding_with_expected_shape() {
        let ts = vec![esc1_template()];
        let findings = detect_all(&ts);
        assert!(!findings.is_empty(), "expected at least one finding");
        let esc1 = findings
            .iter()
            .find(|f| f.id == "A-Esc1-ms-crtd")
            .expect("ESC1 finding");
        assert_eq!(esc1.severity, Severity::Critical);
        assert_eq!(esc1.affected, vec!["VulnUser"]);
        assert!(esc1.mitre.iter().any(|m| m.id == mitre::CERT_ABUSE.id));
    }

    #[test]
    fn empty_input_emits_no_findings() {
        assert!(detect_all(&[]).is_empty());
    }
}
