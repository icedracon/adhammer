//! Category: Anomalies / AD CS. The ESC classes decidable from LDAP alone: template flags +
//! EKUs + object `nTSecurityDescriptor` (ESC1/2/3/4/9/13/15), CA-object ACLs (ESC5), and weak
//! explicit certificate mappings (ESC14). ESC8 is detected actively (`enum adcs` web-enroll
//! probe). Still out of passive scope — need a CA/DC registry or active-RPC read: ESC6
//! (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC7 (CA ManageCA/ManageCertificates ACL), ESC10 (DC cert
//! mapping enforcement), ESC11 (unencrypted ICPR), ESC16 (globally disabled security extension).
//!
//! The template ACL parse reuses the self-rolled SDDL crate; "low-priv can enroll/write"
//! is decided against the broad principals (Authenticated Users, Domain Users/Computers,
//! Everyone, BUILTIN\Users).

use super::Check;
use adhammer_core::finding::{mitre, Category, Evidence, Severity};
use adhammer_core::sid::Sid;
use adhammer_core::snapshot::Snapshot;
use adhammer_core::{AdObject, Finding};
use adhammer_graph::ControlGraph;
use std::collections::HashSet;
use windows_sddl::{rights, AccessMask};

// Extended Key Usage OIDs that grant domain authentication.
const EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const EKU_SMARTCARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
const EKU_PKINIT_CLIENT: &str = "1.3.6.1.5.5.2.3.4";
const EKU_ANY_PURPOSE: &str = "2.5.29.37.0";
const EKU_ENROLLMENT_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";

// msPKI-Certificate-Name-Flag
const CT_ENROLLEE_SUPPLIES_SUBJECT: i64 = 0x0000_0001;
// msPKI-Enrollment-Flag
const CT_PEND_ALL_REQUESTS: i64 = 0x0000_0002; // manager approval
const CT_NO_SECURITY_EXTENSION: i64 = 0x0008_0000; // ESC9

/// Parsed view of one certificate template.
struct Template {
    name: String,
    ekus: Vec<String>,
    name_flag: i64,
    enroll_flag: i64,
    ra_signature: i64,
    schema_version: i64,
    issuance_policies: bool,
}

impl Template {
    fn from(o: &AdObject) -> Self {
        Template {
            name: o
                .one("cn")
                .or_else(|| o.one("name"))
                .unwrap_or(&o.dn)
                .to_string(),
            ekus: o.all("pKIExtendedKeyUsage").to_vec(),
            name_flag: o.int("msPKI-Certificate-Name-Flag").unwrap_or(0),
            enroll_flag: o.int("msPKI-Enrollment-Flag").unwrap_or(0),
            ra_signature: o.int("msPKI-RA-Signature").unwrap_or(0),
            schema_version: o.int("msPKI-Template-Schema-Version").unwrap_or(1),
            issuance_policies: !o.all("msPKI-Certificate-Policy").is_empty(),
        }
    }

    /// EKU that lets the resulting cert authenticate as the subject.
    fn auth_eku(&self) -> bool {
        self.ekus.is_empty()
            || self.ekus.iter().any(|e| {
                e == EKU_CLIENT_AUTH
                    || e == EKU_SMARTCARD_LOGON
                    || e == EKU_PKINIT_CLIENT
                    || e == EKU_ANY_PURPOSE
            })
    }
    fn any_purpose(&self) -> bool {
        self.ekus.is_empty() || self.ekus.iter().any(|e| e == EKU_ANY_PURPOSE)
    }
    fn enrollment_agent(&self) -> bool {
        self.ekus.iter().any(|e| e == EKU_ENROLLMENT_AGENT)
    }
    fn supplies_subject(&self) -> bool {
        self.name_flag & CT_ENROLLEE_SUPPLIES_SUBJECT != 0
    }
    fn manager_approval(&self) -> bool {
        self.enroll_flag & CT_PEND_ALL_REQUESTS != 0
    }
    fn no_security_extension(&self) -> bool {
        self.enroll_flag & CT_NO_SECURITY_EXTENSION != 0
    }
}

/// One rule object that emits a finding per ESC class (affected = list of templates).
pub struct VulnerableCertTemplates;

impl Check for VulnerableCertTemplates {
    fn id(&self) -> &'static str {
        "A-AdcsEsc"
    }

    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let dsid = snap.domain.domain_sid.as_ref();
        let published = published_templates(snap);
        let filter_published = !published.is_empty();

        let mut esc1 = Vec::new();
        let mut esc2 = Vec::new();
        let mut esc3 = Vec::new();
        let mut esc4 = Vec::new();
        let mut esc5 = Vec::new();
        let mut esc9 = Vec::new();
        let mut esc13 = Vec::new();
        let mut esc14 = Vec::new();
        let mut esc15 = Vec::new();

        for o in snap.iter_class("pKICertificateTemplate") {
            let t = Template::from(o);
            if filter_published && !published.contains(&t.name.to_ascii_lowercase()) {
                continue; // unpublished templates aren't enrollable
            }
            let (can_enroll, can_write) = broad_rights(o, dsid);
            let ekus = if t.ekus.is_empty() {
                "<none>".to_string()
            } else {
                t.ekus.join(", ")
            };

            // ESC4: any low-priv principal can modify the template ⇒ they can make it ESC1.
            if can_write {
                esc4.push((
                    t.name.clone(),
                    Evidence::new(
                        format!("LDAP {}:nTSecurityDescriptor", o.dn),
                        "broad principal (Authenticated Users / Domain Users / Everyone) holds Write/GenericAll on the template ACL".to_string(),
                    ),
                ));
            }
            if !can_enroll {
                continue; // remaining ESCs need low-priv enrollment
            }
            let enroll_why = "broad principal holds Enroll on the template ACL";
            let approved = t.manager_approval() || t.ra_signature > 0;

            if t.supplies_subject() && t.auth_eku() && !approved {
                esc1.push((
                    t.name.clone(),
                    Evidence::new(
                        format!("LDAP {}", o.dn),
                        format!(
                            "msPKI-Certificate-Name-Flag=0x{:X} (ENROLLEE_SUPPLIES_SUBJECT); \
                             pKIExtendedKeyUsage=[{ekus}] (auth EKU); \
                             msPKI-Enrollment-Flag=0x{:X}/RA-Signature={} (no approval); enroll: {enroll_why}",
                            t.name_flag, t.enroll_flag, t.ra_signature
                        ),
                    ),
                ));
            }
            if t.any_purpose() && !approved {
                esc2.push((
                    t.name.clone(),
                    Evidence::new(
                        format!("LDAP {}:pKIExtendedKeyUsage", o.dn),
                        format!(
                            "[{ekus}] (Any-Purpose / no-EKU); \
                             msPKI-Enrollment-Flag=0x{:X}/RA-Signature={} (no approval); enroll: {enroll_why}",
                            t.enroll_flag, t.ra_signature
                        ),
                    ),
                ));
            }
            if t.enrollment_agent() && !t.manager_approval() {
                esc3.push((
                    t.name.clone(),
                    Evidence::new(
                        format!("LDAP {}:pKIExtendedKeyUsage", o.dn),
                        format!(
                            "[{ekus}] (Certificate-Request-Agent {EKU_ENROLLMENT_AGENT}); \
                             msPKI-Enrollment-Flag=0x{:X} (no manager approval); enroll: {enroll_why}",
                            t.enroll_flag
                        ),
                    ),
                ));
            }
            if t.no_security_extension() && t.auth_eku() {
                esc9.push((
                    t.name.clone(),
                    Evidence::new(
                        format!("LDAP {}:msPKI-Enrollment-Flag", o.dn),
                        format!(
                            "0x{:X} (CT_FLAG_NO_SECURITY_EXTENSION 0x80000 set); \
                             pKIExtendedKeyUsage=[{ekus}] (auth EKU); enroll: {enroll_why}",
                            t.enroll_flag
                        ),
                    ),
                ));
            }
            if t.issuance_policies && t.auth_eku() {
                let policies = o.all("msPKI-Certificate-Policy").join(", ");
                esc13.push((
                    t.name.clone(),
                    Evidence::new(
                        format!("LDAP {}:msPKI-Certificate-Policy", o.dn),
                        format!(
                            "[{policies}] (issuance policy present); \
                             pKIExtendedKeyUsage=[{ekus}] (auth EKU); enroll: {enroll_why}"
                        ),
                    ),
                ));
            }
            // ESC15 / EKUwu (CVE-2024-49019): a schema-v1 template enrollable by low-priv lets the
            // requester inject arbitrary application policies (e.g. Client Authentication) in the
            // CSR — the template's own EKU is irrelevant, so any enrollable v1 template qualifies.
            if t.schema_version == 1 && !approved {
                esc15.push((
                    t.name.clone(),
                    Evidence::new(
                        format!("LDAP {}:msPKI-Template-Schema-Version", o.dn),
                        format!(
                            "1 (schema v1 — arbitrary application-policy injection); \
                             msPKI-Enrollment-Flag=0x{:X}/RA-Signature={} (no approval); enroll: {enroll_why}",
                            t.enroll_flag, t.ra_signature
                        ),
                    ),
                ));
            }
        }

        // ESC5: a broad principal holds Write/Owner/DACL control over a CA object itself
        // (pKIEnrollmentService / certificationAuthority) — they can republish templates, add
        // EKUs, or otherwise reconfigure the PKI. Reuses the template ACL walk.
        for o in snap
            .iter_class("pKIEnrollmentService")
            .chain(snap.iter_class("certificationAuthority"))
        {
            if broad_rights(o, dsid).1 {
                let name = o
                    .one("cn")
                    .or_else(|| o.one("name"))
                    .unwrap_or(&o.dn)
                    .to_string();
                esc5.push((
                    name,
                    Evidence::new(
                        format!("LDAP {}:nTSecurityDescriptor", o.dn),
                        "broad principal holds Write/WriteDacl/WriteOwner on the CA object"
                            .to_string(),
                    ),
                ));
            }
        }

        // ESC14: a *weak* explicit certificate mapping (altSecurityIdentities) — an X509 mapping
        // that isn't pinned by issuer+serial / key id / public-key hash (i.e. Subject-only,
        // Issuer+Subject, or RFC822/email) can be satisfied by an attacker-obtained certificate.
        for o in &snap.objects {
            for m in o.all("altSecurityIdentities") {
                if is_weak_x509_mapping(m) {
                    let who = o
                        .one("sAMAccountName")
                        .or_else(|| o.one("cn"))
                        .unwrap_or(&o.dn);
                    esc14.push((
                        who.to_string(),
                        Evidence::new(
                            format!("LDAP {}:altSecurityIdentities", o.dn),
                            m.to_string(),
                        ),
                    ));
                }
            }
        }

        let mut out = Vec::new();
        push(&mut out, "A-Esc1", "ESC1: enrollee-supplies-subject template with auth EKU, enrollable by low-priv", Severity::Critical, esc1,
            "The template lets the requester specify the SAN and issues a client-auth cert without approval — any low-priv user can request a cert as a Domain Admin.",
            Some("Attacker requests a cert from this template with SAN = Administrator@corp.local, then PKINITs the resulting cert to get an Administrator TGT. Full domain compromise from any authenticated user, no password crack required."),
            "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, require manager approval, or restrict enrollment to a trusted group.");
        push(&mut out, "A-Esc2", "ESC2: Any-Purpose / SubCA template enrollable by low-priv", Severity::Critical, esc2,
            "An Any-Purpose (or no-EKU) template without approval can issue a cert usable for any purpose, including authentication.",
            Some("Attacker enrolls a cert whose Any-Purpose EKU covers Client-Auth, then PKINITs it. Equivalent to ESC1 outcome — DA TGT from any low-priv account."),
            "Constrain the EKU set and require approval; restrict enrollment.");
        push(&mut out, "A-Esc3", "ESC3: Enrollment Agent template enrollable by low-priv", Severity::High, esc3,
            "A Certificate Request Agent template lets the holder enroll on behalf of other users, escalating to any principal.",
            Some("Attacker enrolls an Enrollment-Agent cert, then uses it to request a Client-Auth cert on behalf of any target user (e.g. Administrator) and PKINITs → target's TGT."),
            "Restrict enrollment-agent templates to a dedicated group and require approval.");
        push(&mut out, "A-Esc4", "ESC4: certificate template ACL writable by low-priv", Severity::Critical, esc4,
            "A low-privileged principal holds Write/WriteDacl/WriteOwner/GenericAll (or ownership) over the template and can reconfigure it into ESC1.",
            Some("Attacker writes the template's flags to enable ENROLLEE_SUPPLIES_SUBJECT + Client-Auth EKU, self-enrolls with SAN=Administrator, PKINITs. ESC1 on demand."),
            "Remove the offending ACEs; template write access belongs to Tier-0 only.");
        push(&mut out, "A-Esc5", "ESC5: CA object ACL writable by low-priv", Severity::Critical, esc5,
            "A low-privileged principal can write/own the CA's AD object (pKIEnrollmentService / certificationAuthority) and can republish templates or reconfigure the PKI into an escalation.",
            Some("Attacker publishes a rogue template on the CA (equivalent to ESC1 shape) or reconfigures the CA to accept any subject. Domain-wide escalation via any subsequent enrollment."),
            "Restrict Write/WriteDacl/WriteOwner on the Enrollment Services + CA objects to Tier-0.");
        push(&mut out, "A-Esc14", "ESC14: weak explicit certificate mapping (altSecurityIdentities)", Severity::High, esc14,
            "The account carries a weak X509 mapping (Subject-only / Issuer+Subject / RFC822) that a certificate the attacker can obtain will satisfy, allowing impersonation.",
            Some("Attacker obtains ANY cert whose subject or RFC822 name matches the weak mapping (from any trusted issuer, including one they compromise or install) and PKINITs as the mapped account. Silent impersonation without the account's password."),
            "Use only strong mappings (Issuer+Serial, SKI, SHA1-PublicKey) and enforce Full strong certificate binding (KB5014754).");
        push(&mut out, "A-Esc15", "ESC15 / EKUwu: schema-v1 template enrollable by low-priv", Severity::Critical, esc15,
            "CVE-2024-49019: a version-1 template lets the enrollee inject arbitrary application policies (e.g. Client Authentication) in the request, so an enrollable v1 template yields an auth cert regardless of its own EKU.",
            Some("Attacker enrolls a v1 template requesting Client-Auth in the application policies, receives a cert usable for PKINIT, gets a TGT as any target account (SAN-supplied). CVE-2024-49019 exploitation."),
            "Upgrade v1 templates to v2+, require manager approval, or restrict enrollment; apply the CVE-2024-49019 patch.");
        push(&mut out, "A-Esc9", "ESC9: no-security-extension template with auth EKU", Severity::High, esc9,
            "CT_FLAG_NO_SECURITY_EXTENSION disables the SID binding, enabling weak certificate mapping / impersonation.",
            Some("Cert issued without the SID security extension can be paired with a weak altSecurityIdentities mapping (ESC14) or used against pre-KB5014754 DCs to impersonate the target account."),
            "Clear the flag and enforce strong (Full) certificate mapping on DCs (KB5014754).");
        push(&mut out, "A-Esc13", "ESC13: issuance-policy template linked to a privileged group", Severity::High, esc13,
            "The template carries an issuance policy OID that may be group-linked, granting the certificate holder the linked group's rights.",
            Some("Attacker enrolls the template, holds a cert whose issuance-policy OID grants membership in the linked (privileged) group at PKINIT time, obtaining a TGT that carries that group's rights."),
            "Audit msPKI-Certificate-Policy OID-to-group links; restrict enrollment.");
        out
    }
}

/// True if the template uses an elliptic-curve key algorithm — for ECC, a 256/384-bit key is
/// strong, so it must NOT be flagged against the 2048-bit RSA minimum.
fn is_ecc_template(o: &AdObject) -> bool {
    if let Some(a) = o.one("msPKI-Asymmetric-Algorithm") {
        let a = a.to_ascii_uppercase();
        if a.starts_with("EC") || a.contains("ECD") || a.contains("ECDSA") {
            return true;
        }
    }
    o.all("pKIDefaultCSPs").iter().any(|c| {
        let c = c.to_ascii_uppercase();
        c.contains("ECD") || c.contains("ECDSA") || c.contains("ELLIPTIC")
    })
}

/// Weak-crypto certificate templates: an RSA template whose `msPKI-Minimal-Key-Size` is below 2048
/// bits issues certificates a modern attacker can forge or factor, undermining every use of the
/// template (auth, signing, TLS). Pure-LDAP hygiene, orthogonal to the ESC enrollment classes.
/// (WS-COVERAGE, 1.4.3.)
pub struct WeakCertTemplateCrypto;
impl Check for WeakCertTemplateCrypto {
    fn id(&self) -> &'static str {
        "A-WeakCertKeySize"
    }
    fn run(&self, snap: &Snapshot, _g: &ControlGraph) -> Vec<Finding> {
        let published = published_templates(snap);
        let filter_published = !published.is_empty();
        let mut affected: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        let mut min_size = 2048;
        for o in snap.iter_class("pKICertificateTemplate") {
            let name = o.one("cn").or_else(|| o.one("name")).unwrap_or(&o.dn);
            if filter_published && !published.contains(&name.to_ascii_lowercase()) {
                continue;
            }
            let Some(ksize) = o.int("msPKI-Minimal-Key-Size") else {
                continue;
            };
            if ksize <= 0 || ksize >= 2048 || is_ecc_template(o) {
                continue;
            }
            min_size = min_size.min(ksize);
            affected.push(name.to_string());
            if evidence.len() < 25 {
                let algo = o
                    .one("msPKI-Asymmetric-Algorithm")
                    .unwrap_or("RSA (default)");
                evidence.push(Evidence::new(
                    format!("LDAP {}:msPKI-Minimal-Key-Size", o.dn),
                    format!("{ksize}-bit {algo} (< 2048-bit minimum)"),
                ));
            }
        }
        if affected.is_empty() {
            return vec![];
        }
        // A 512-bit template is forgeable today; 1024 is deprecated. Grade by the weakest seen.
        let severity = if min_size < 1024 {
            Severity::High
        } else {
            Severity::Medium
        };
        vec![Finding {
            id: self.id().into(),
            title: "Certificate template uses a weak RSA key size (< 2048)".into(),
            category: Category::Anomalies,
            severity,
            mitre: vec![mitre::CERT_ABUSE],
            weight_bonus: affected.len() as u32 * 4,
            exchange: Vec::new(),
            affected,
            evidence,
            detail: "A certificate template mandates an RSA key smaller than 2048 bits. Certificates it issues are weak: 1024-bit is deprecated and 512-bit is factorable, so a forged or factored key defeats whatever the cert authorizes.".into(),
            impact: Some("An attacker who factors/forges a certificate from this template impersonates its subject (auth cert → PKINIT as the user, or a signing cert accepted as legitimate). Weak keys also let a downgrade weaken otherwise-strong PKI.".into()),
            remediation: "Raise the template's Minimum Key Size to ≥ 2048 (RSA) or migrate to ECC P-256+, then re-issue affected certificates.".into(),
        }]
    }
}

/// Templates actually published by at least one CA (`certificateTemplates` on the
/// pKIEnrollmentService object). Lowercased names.
fn published_templates(snap: &Snapshot) -> HashSet<String> {
    snap.iter_class("pKIEnrollmentService")
        .flat_map(|ca| ca.all("certificateTemplates"))
        .map(|n| n.to_ascii_lowercase())
        .collect()
}

/// A weak X509 `altSecurityIdentities` mapping — one not pinned by issuer+serial, subject key
/// id, or public-key hash. Kerberos/UPN mappings and the strong X509 forms return false.
fn is_weak_x509_mapping(m: &str) -> bool {
    let up = m.trim().to_ascii_uppercase();
    if !up.starts_with("X509:") {
        return false; // Kerberos:/UPN mappings aren't ESC14
    }
    // Strong: <SR> issuer+serial, <SKI> subject-key-id, <SHA1-PUKEY> public-key hash.
    !(up.contains("<SR>") || up.contains("<SKI>") || up.contains("<SHA1-PUKEY>"))
}

use crate::util::is_broad;

/// Decide whether a *broad* principal can enroll in, or modify, the template,
/// by walking the template's `nTSecurityDescriptor`.
fn broad_rights(o: &AdObject, dsid: Option<&Sid>) -> (bool, bool) {
    let Some(raw) = o.bin1("nTSecurityDescriptor") else {
        return (false, false);
    };
    let Ok(sd) = windows_sddl::parse(raw) else {
        return (false, false);
    };

    let mut can_enroll = false;
    let mut can_write = false;

    if sd.owner.as_ref().is_some_and(|ow| is_broad(ow, dsid)) {
        can_write = true; // owner can rewrite the DACL
    }

    for ace in sd
        .dacl
        .iter()
        .flat_map(|d| &d.aces)
        .filter(|a| a.is_allow())
    {
        if !is_broad(&ace.trustee, dsid) {
            continue;
        }
        let m = ace.mask;

        // Enrollment = the Certificate-Enrollment extended right, or all-rights.
        if m.contains(AccessMask::GENERIC_ALL) {
            can_enroll = true;
        }
        if m.contains(AccessMask::CONTROL_ACCESS) {
            match &ace.object_type {
                None => can_enroll = true, // all extended rights
                Some(g) if rights::is_enrollment_right(g) => can_enroll = true,
                _ => {}
            }
        }

        // Write / takeover of the template object itself (ESC4).
        if m.intersects(
            AccessMask::WRITE_DAC
                | AccessMask::WRITE_OWNER
                | AccessMask::GENERIC_ALL
                | AccessMask::GENERIC_WRITE,
        ) {
            can_write = true;
        }
        if m.contains(AccessMask::WRITE_PROP) && ace.object_type.is_none() {
            can_write = true; // write-any-property
        }
    }
    (can_enroll, can_write)
}

#[allow(clippy::too_many_arguments)]
fn push(
    out: &mut Vec<Finding>,
    id: &str,
    title: &str,
    severity: Severity,
    hits: Vec<(String, Evidence)>,
    detail: &str,
    impact: Option<&str>,
    remediation: &str,
) {
    if hits.is_empty() {
        return;
    }
    let bonus = hits.len() as u32 * 10;
    // Ground-truth evidence: each vulnerable template/object carries the exact attribute values
    // that triggered its ESC class (built at the detection site).
    let affected: Vec<String> = hits.iter().map(|(n, _)| n.clone()).collect();
    let evidence: Vec<Evidence> = hits.into_iter().map(|(_, e)| e).take(25).collect();
    out.push(Finding {
        id: id.into(),
        title: title.into(),
        category: Category::Anomalies,
        severity,
        mitre: vec![mitre::CERT_ABUSE],
        affected,
        evidence,
        detail: detail.into(),
        impact: impact.map(|s| s.to_string()),
        remediation: remediation.into(),
        weight_bonus: bonus,
        exchange: Vec::new(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_core::snapshot::{DomainInfo, Snapshot};
    use adhammer_graph::ControlGraph;
    use std::collections::HashMap;

    /// Build a self-relative SECURITY_DESCRIPTOR whose DACL grants the
    /// Certificate-Enrollment extended right to Authenticated Users (S-1-5-11).
    fn esc_enroll_sd() -> Vec<u8> {
        // Certificate-Enrollment GUID {0e10c968-...} in on-wire (mixed-endian) bytes.
        let guid: [u8; 16] = [
            0x68, 0xc9, 0x10, 0x0e, 0xfb, 0x78, 0xd2, 0x11, 0x90, 0xd4, 0x00, 0xc0, 0x4f, 0x79,
            0xdc, 0x55,
        ];
        // S-1-5-11: rev=1, subauth_count=1, authority=5 (BE), subauth[0]=11 (LE).
        let sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];

        let mut ace = vec![0x05u8, 0x00]; // ACCESS_ALLOWED_OBJECT_ACE, no flags
        let ace_size = (4 + 4 + 4 + 16 + sid.len()) as u16;
        ace.extend_from_slice(&ace_size.to_le_bytes());
        ace.extend_from_slice(&0x0000_0100u32.to_le_bytes()); // ADS_RIGHT_DS_CONTROL_ACCESS
        ace.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // ACE_OBJECT_TYPE_PRESENT
        ace.extend_from_slice(&guid);
        ace.extend_from_slice(&sid);

        let mut dacl = vec![0x04u8, 0x00]; // ACL_REVISION_DS
        let dacl_size = (8 + ace.len()) as u16;
        dacl.extend_from_slice(&dacl_size.to_le_bytes());
        dacl.extend_from_slice(&1u16.to_le_bytes()); // AceCount
        dacl.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
        dacl.extend_from_slice(&ace);

        let mut sd = vec![1u8, 0]; // Revision, Sbz1
        sd.extend_from_slice(&0x8004u16.to_le_bytes()); // SELF_RELATIVE | DACL_PRESENT
        sd.extend_from_slice(&0u32.to_le_bytes()); // owner off
        sd.extend_from_slice(&0u32.to_le_bytes()); // group off
        sd.extend_from_slice(&0u32.to_le_bytes()); // sacl off
        sd.extend_from_slice(&20u32.to_le_bytes()); // dacl off
        sd.extend_from_slice(&dacl);
        sd
    }

    fn esc1_template() -> AdObject {
        let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
        attrs.insert("objectClass".into(), vec!["pKICertificateTemplate".into()]);
        attrs.insert("cn".into(), vec!["VulnUser".into()]);
        attrs.insert("pKIExtendedKeyUsage".into(), vec![EKU_CLIENT_AUTH.into()]);
        attrs.insert("msPKI-Certificate-Name-Flag".into(), vec!["1".into()]); // ENROLLEE_SUPPLIES_SUBJECT
        attrs.insert("msPKI-Enrollment-Flag".into(), vec!["0".into()]); // no manager approval
        attrs.insert("msPKI-RA-Signature".into(), vec!["0".into()]);
        let mut bin: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        bin.insert("nTSecurityDescriptor".into(), vec![esc_enroll_sd()]);
        AdObject {
            dn: "CN=VulnUser,CN=Certificate Templates,...".into(),
            attrs,
            bin,
        }
    }

    #[test]
    fn detects_esc1_end_to_end() {
        let snap = Snapshot::new(DomainInfo::default(), vec![esc1_template()]);
        let graph = ControlGraph::build(&snap);
        let findings = VulnerableCertTemplates.run(&snap, &graph);
        assert!(
            findings.iter().any(|f| f.id == "A-Esc1"),
            "expected ESC1 finding, got {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn weak_vs_strong_x509_mappings() {
        // Weak: subject-only, issuer+subject, RFC822/email.
        assert!(is_weak_x509_mapping("X509:<S>CN=admin"));
        assert!(is_weak_x509_mapping("X509:<I>DC=corp<S>CN=admin"));
        assert!(is_weak_x509_mapping("X509:<RFC822>admin@corp.local"));
        // Strong: issuer+serial, SKI, public-key hash.
        assert!(!is_weak_x509_mapping("X509:<I>DC=corp<SR>1200000000AABB"));
        assert!(!is_weak_x509_mapping("X509:<SKI>1a2b3c"));
        assert!(!is_weak_x509_mapping("X509:<SHA1-PUKEY>deadbeef"));
        // Not an X509 mapping at all.
        assert!(!is_weak_x509_mapping("Kerberos:admin@CORP.LOCAL"));
    }

    #[test]
    fn detects_esc15_v1_template() {
        let mut t = esc1_template();
        // A schema-v1 template, enrollable, no approval → EKUwu/ESC15 regardless of its EKU.
        t.attrs
            .insert("msPKI-Template-Schema-Version".into(), vec!["1".into()]);
        t.attrs.insert("pKIExtendedKeyUsage".into(), vec![]); // even with no client-auth EKU
        let snap = Snapshot::new(DomainInfo::default(), vec![t]);
        let graph = ControlGraph::build(&snap);
        let findings = VulnerableCertTemplates.run(&snap, &graph);
        assert!(
            findings.iter().any(|f| f.id == "A-Esc15"),
            "expected ESC15 for an enrollable v1 template"
        );
    }

    #[test]
    fn ignores_template_with_manager_approval() {
        let mut t = esc1_template();
        t.attrs
            .insert("msPKI-Enrollment-Flag".into(), vec!["2".into()]); // PEND_ALL_REQUESTS
        let snap = Snapshot::new(DomainInfo::default(), vec![t]);
        let graph = ControlGraph::build(&snap);
        let findings = VulnerableCertTemplates.run(&snap, &graph);
        assert!(
            !findings.iter().any(|f| f.id == "A-Esc1"),
            "manager approval should suppress ESC1"
        );
    }

    fn template_keysize(name: &str, ksize: &str, algo: Option<&str>) -> AdObject {
        let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
        attrs.insert("objectClass".into(), vec!["pKICertificateTemplate".into()]);
        attrs.insert("cn".into(), vec![name.into()]);
        attrs.insert("msPKI-Minimal-Key-Size".into(), vec![ksize.into()]);
        if let Some(a) = algo {
            attrs.insert("msPKI-Asymmetric-Algorithm".into(), vec![a.into()]);
        }
        AdObject {
            dn: format!("CN={name},CN=Certificate Templates,..."),
            attrs,
            bin: HashMap::new(),
        }
    }

    #[test]
    fn weak_rsa_flagged_ecc_and_strong_ignored() {
        let weak = template_keysize("WeakRsa", "1024", None); // RSA default, < 2048 → flag
        let ecc = template_keysize("EccOk", "256", Some("ECDH_P256")); // 256-bit ECC → strong
        let strong = template_keysize("StrongRsa", "4096", None); // ≥ 2048 → fine
        let snap = Snapshot::new(DomainInfo::default(), vec![weak, ecc, strong]);
        let graph = ControlGraph::build(&snap);
        let f = WeakCertTemplateCrypto.run(&snap, &graph);
        assert!(f.iter().any(|x| x.id == "A-WeakCertKeySize"));
        let hit = f.iter().find(|x| x.id == "A-WeakCertKeySize").unwrap();
        assert_eq!(hit.affected, vec!["WeakRsa".to_string()]);
        assert_eq!(hit.severity, Severity::Medium); // 1024 → Medium, not < 1024
    }

    #[test]
    fn factorable_512bit_is_high() {
        let weak = template_keysize("Rsa512", "512", Some("RSA"));
        let snap = Snapshot::new(DomainInfo::default(), vec![weak]);
        let graph = ControlGraph::build(&snap);
        let f = WeakCertTemplateCrypto.run(&snap, &graph);
        assert!(f
            .iter()
            .any(|x| x.id == "A-WeakCertKeySize" && x.severity == Severity::High));
    }
}
