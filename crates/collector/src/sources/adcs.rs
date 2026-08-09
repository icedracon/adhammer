//! Typed pKICertificateTemplate / pKIEnrollmentService view over the LDAP
//! attributes already stored in [`AdObject`].
//!
//! The heavy lifting (flag decoding, EKU OID collection, SAN-supply logic,
//! ESC1-15 rule shape) lives in `ms-crtd`. This adapter is the thin bridge
//! from adhammer's generic `AdObject` bag to `ms_crtd::Attrs`
//! (`BTreeMap<String, Vec<Vec<u8>>>`, lowercase-keyed).
//!
//! No live-DC I/O — consumers hand in an already-collected `AdObject` (or a
//! `Snapshot`) and get back typed values.

use adhammer_core::AdObject;
use ms_crtd::{
    parse_enrollment_service_ldap, parse_template_ldap, Attrs, CertTemplate, EnrollmentService,
};
use std::collections::BTreeMap;

/// Convert an `AdObject`'s attribute bag into the shape `ms_crtd` wants.
///
/// String values are re-encoded as UTF-8 bytes; binary values pass through
/// verbatim. Keys are lowercased so `ms_crtd::parse::get` finds them.
fn attrs_of(o: &AdObject) -> Attrs {
    let mut out: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
    for (k, vals) in &o.attrs {
        out.entry(k.to_ascii_lowercase())
            .or_default()
            .extend(vals.iter().map(|s| s.as_bytes().to_vec()));
    }
    for (k, vals) in &o.bin {
        out.entry(k.to_ascii_lowercase())
            .or_default()
            .extend(vals.iter().cloned());
    }
    out
}

/// Parse one `pKICertificateTemplate` object into a `CertTemplate`.
pub fn template_from(o: &AdObject) -> Result<CertTemplate, ms_crtd::Error> {
    parse_template_ldap(&attrs_of(o))
}

/// Parse one `pKIEnrollmentService` (CA) object.
pub fn enrollment_service_from(o: &AdObject) -> Result<EnrollmentService, ms_crtd::Error> {
    parse_enrollment_service_ldap(&attrs_of(o))
}

/// Walk every `pKICertificateTemplate` in the collected objects and return the
/// successfully-parsed ones. Objects that fail to parse are dropped silently —
/// mirroring the check engine's tolerance for partial CA container reads
/// (missing attrs are common on DCs the bind identity can't fully see).
pub fn templates_from<'a, I>(objects: I) -> Vec<CertTemplate>
where
    I: IntoIterator<Item = &'a AdObject>,
{
    objects
        .into_iter()
        .filter(|o| o.has_class("pKICertificateTemplate"))
        .filter_map(|o| template_from(o).ok())
        .collect()
}

/// Enumerate every `pKIEnrollmentService` (CA) in the collected objects.
pub fn enrollment_services_from<'a, I>(objects: I) -> Vec<EnrollmentService>
where
    I: IntoIterator<Item = &'a AdObject>,
{
    objects
        .into_iter()
        .filter(|o| o.has_class("pKIEnrollmentService"))
        .filter_map(|o| enrollment_service_from(o).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn v1(s: &str) -> Vec<String> {
        vec![s.into()]
    }

    /// A minimal ESC1-shaped template: enrollee-supplies-subject + Client Auth EKU,
    /// no manager approval. This is the same shape `ms_crtd::detect_esc` flags as
    /// ESC1 — the point of the test is to prove the AdObject → CertTemplate wire
    /// preserves the fields that decision looks at.
    fn esc1_ad_object() -> AdObject {
        let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
        attrs.insert("objectClass".into(), v1("pKICertificateTemplate"));
        attrs.insert("cn".into(), v1("VulnUser"));
        attrs.insert(
            "msPKI-Cert-Template-OID".into(),
            v1("1.3.6.1.4.1.311.21.8.1.42"),
        );
        attrs.insert("msPKI-Template-Schema-Version".into(), v1("2"));
        // ENROLLEE_SUPPLIES_SUBJECT (bit 0)
        attrs.insert("msPKI-Certificate-Name-Flag".into(), v1("1"));
        // no PEND_ALL_REQUESTS
        attrs.insert("msPKI-Enrollment-Flag".into(), v1("0"));
        attrs.insert("msPKI-RA-Signature".into(), v1("0"));
        // Client Authentication EKU
        attrs.insert("pKIExtendedKeyUsage".into(), v1("1.3.6.1.5.5.7.3.2"));
        AdObject {
            dn: "CN=VulnUser,CN=Templates,CN=Public Key Services,\
                 CN=Services,CN=Configuration,DC=corp,DC=local"
                .into(),
            attrs,
            bin: HashMap::new(),
        }
    }

    #[test]
    fn wires_ad_object_into_cert_template() {
        let o = esc1_ad_object();
        let t = template_from(&o).expect("parse");
        assert_eq!(t.name, "VulnUser");
        assert_eq!(t.schema_version, 2);
        assert_eq!(t.min_ra_signatures, 0);
        assert!(t.enrollee_supplies_subject());
        assert!(t.is_authentication_capable());
        assert!(!t.requires_manager_approval());
    }

    #[test]
    fn ms_crtd_detect_esc_flags_esc1_off_the_wire() {
        let o = esc1_ad_object();
        let t = template_from(&o).expect("parse");
        let findings = ms_crtd::detect_esc(&t);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, ms_crtd::EscFinding::Esc1 { template, .. } if template == "VulnUser")),
            "expected ESC1 finding on VulnUser, got {:?}",
            findings
        );
    }

    #[test]
    fn templates_from_filters_by_object_class() {
        let template = esc1_ad_object();
        let other = AdObject {
            dn: "CN=User,CN=Users,DC=corp,DC=local".into(),
            attrs: {
                let mut m: HashMap<String, Vec<String>> = HashMap::new();
                m.insert("objectClass".into(), v1("user"));
                m
            },
            bin: HashMap::new(),
        };
        let all = vec![&template, &other];
        let ts = templates_from(all);
        assert_eq!(ts.len(), 1);
        assert_eq!(ts[0].name, "VulnUser");
    }
}
