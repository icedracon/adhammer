//! Registry-only AD CS ESC detections, decided from CA/DC registry values read over MS-RRP
//! (`dcerpc::rrp`). These are the ESC classes LDAP can't see:
//!
//! - **ESC6**  — CA `EditFlags` has `EDITF_ATTRIBUTESUBJECTALTNAME2` → requester-supplied SAN on
//!   *any* template.
//! - **ESC11** — CA `InterfaceFlags` lacks `IF_ENFORCEENCRYPTICERTREQUEST` → ICPR accepts
//!   unencrypted requests (relayable).
//! - **ESC16** — CA `DisableExtensionList` contains the szOID_NTDS_CA_SECURITY_EXT → the SID
//!   security extension is globally disabled.
//! - **ESC10** — DC `Kdc\StrongCertificateBindingEnforcement` < 2 (Disabled/Compatibility) →
//!   weak Kerberos certificate mapping.
//!
//! The read path (SMB → `\winreg` → open key → query value) lives in `dcerpc::rrp`; this module
//! owns the *decision* — turning a raw registry value into an ESC verdict — and is unit-tested
//! independently of the network.

/// CA `EditFlags` bit: the CA honors a requester-supplied subjectAltName on any template.
pub const EDITF_ATTRIBUTESUBJECTALTNAME2: u32 = 0x0004_0000;
/// CA `InterfaceFlags` bit: the ICertRequest RPC interface requires packet privacy (encryption).
pub const IF_ENFORCEENCRYPTICERTREQUEST: u32 = 0x0000_0200;
/// The SID security-extension OID that ESC16 disables.
pub const SZOID_NTDS_CA_SECURITY_EXT: &str = "1.3.6.1.4.1.311.25.2";

/// One registry-derived ESC finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscHit {
    pub id: &'static str,
    pub title: &'static str,
    pub detail: String,
}

/// ESC6: `EditFlags & EDITF_ATTRIBUTESUBJECTALTNAME2`.
pub fn esc6(edit_flags: u32) -> Option<EscHit> {
    (edit_flags & EDITF_ATTRIBUTESUBJECTALTNAME2 != 0).then(|| EscHit {
        id: "A-Esc6",
        title: "ESC6: CA honors requester-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)",
        detail: format!(
            "CA EditFlags = 0x{edit_flags:08x} has EDITF_ATTRIBUTESUBJECTALTNAME2 set — any \
             enrollable template can be requested with an arbitrary SAN, so a low-priv user can \
             obtain a cert as a Domain Admin. Remediation: clear the flag \
             (`certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`) and restart the CA."
        ),
    })
}

/// ESC11: `InterfaceFlags` *lacks* `IF_ENFORCEENCRYPTICERTREQUEST`.
pub fn esc11(interface_flags: u32) -> Option<EscHit> {
    (interface_flags & IF_ENFORCEENCRYPTICERTREQUEST == 0).then(|| EscHit {
        id: "A-Esc11",
        title: "ESC11: CA ICertRequest does not enforce RPC encryption",
        detail: format!(
            "CA InterfaceFlags = 0x{interface_flags:08x} lacks IF_ENFORCEENCRYPTICERTREQUEST — the \
             ICPR endpoint accepts unencrypted requests, so a coerced machine's NTLM can be relayed \
             to it for a cert. Remediation: set IF_ENFORCEENCRYPTICERTREQUEST and restart the CA."
        ),
    })
}

/// ESC16: `DisableExtensionList` (REG_MULTI_SZ, one OID per line) contains the security-ext OID.
pub fn esc16(disable_extension_list: &str) -> Option<EscHit> {
    disable_extension_list
        .lines()
        .any(|l| l.trim() == SZOID_NTDS_CA_SECURITY_EXT)
        .then(|| EscHit {
            id: "A-Esc16",
            title: "ESC16: CA globally disables the SID security extension",
            detail: format!(
                "CA DisableExtensionList contains {SZOID_NTDS_CA_SECURITY_EXT} — every issued cert \
                 omits the SID binding, enabling weak certificate mapping / impersonation. \
                 Remediation: remove the OID from DisableExtensionList and enforce strong mapping."
            ),
        })
}

/// ESC10: DC `StrongCertificateBindingEnforcement`. 2 = Full (enforced), 1 = Compatibility,
/// 0 = Disabled. Anything below 2 is exploitable.
pub fn esc10(strong_binding: u32) -> Option<EscHit> {
    (strong_binding < 2).then(|| EscHit {
        id: "A-Esc10",
        title: "ESC10: DC Kerberos certificate mapping not strongly enforced",
        detail: format!(
            "Kdc\\StrongCertificateBindingEnforcement = {strong_binding} ({}). A UPN/SAN cert can be \
             mapped to a privileged account. Remediation: set it to 2 (Full) — KB5014754.",
            match strong_binding {
                0 => "Disabled",
                1 => "Compatibility",
                _ => "?",
            }
        ),
    })
}

/// ESC10 when the value is *absent*. The default is version-dependent: Compatibility (weak) on
/// Server 2016–2022 until the Feb-2025 enforcement, Full (safe) on Server 2025 / enforced builds.
/// Flag it honestly rather than silently assuming "safe".
pub fn esc10_absent() -> EscHit {
    EscHit {
        id: "A-Esc10",
        title: "ESC10: DC StrongCertificateBindingEnforcement is not set (default is version-dependent)",
        detail:
            "Kdc\\StrongCertificateBindingEnforcement is absent. Its default is Compatibility \
             (exploitable) on Server 2016–2022 prior to the Feb-2025 enforcement, and Full (safe) \
             on Server 2025 / enforced builds. Verify the DC's patch level; set it explicitly to 2 \
             (Full) — KB5014754."
                .into(),
    }
}

/// On a CA `Security` descriptor the low ACCESS_MASK bits are CA-specific rights (certsrv.h):
/// bit 0 = ManageCA (CA administrator), bit 1 = ManageCertificates (certificate manager/officer).
/// These are the two rights ESC7 abuses (an officer can issue/approve a request → ESC7 → ESC1-style
/// escalation; a CA admin can flip EDITF_ATTRIBUTESUBJECTALTNAME2 → ESC6).
pub const CA_MANAGE_CA: u32 = 0x0000_0001;
pub const CA_MANAGE_CERTIFICATES: u32 = 0x0000_0002;

/// SIDs that legitimately hold CA control (Tier-0). ManageCA/ManageCertificates held by these is the
/// default and benign, so it must not raise ESC7.
fn is_tier0(sid: &windows_sddl::Sid) -> bool {
    let s = sid.to_string();
    // BUILTIN\Administrators, LocalSystem, Enterprise DCs.
    if s == "S-1-5-32-544" || s == "S-1-5-18" || s == "S-1-5-9" {
        return true;
    }
    // Domain groups by RID: Domain/Enterprise/Schema Admins, Domain Controllers, Administrator.
    matches!(sid.rid(), Some(500 | 512 | 516 | 518 | 519))
        && sid.identifier_authority == 5
        && sid.sub_authorities.first() == Some(&21)
}

/// ESC7 decision over a parsed CA security descriptor: any non-Tier-0 principal granted ManageCA
/// or ManageCertificates. One hit per offending trustee.
fn esc7_from_sd(sd: &windows_sddl::SecurityDescriptor) -> Vec<EscHit> {
    let Some(dacl) = &sd.dacl else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    for ace in &dacl.aces {
        if !ace.is_allow() || is_tier0(&ace.trustee) {
            continue;
        }
        let m = ace.mask.bits();
        let ca = m & CA_MANAGE_CA != 0;
        let certs = m & CA_MANAGE_CERTIFICATES != 0;
        if !ca && !certs {
            continue;
        }
        let right = match (ca, certs) {
            (true, true) => "ManageCA + ManageCertificates",
            (true, false) => "ManageCA",
            _ => "ManageCertificates",
        };
        hits.push(EscHit {
            id: "A-Esc7",
            title: "ESC7: non-admin principal holds CA management rights",
            detail: format!(
                "{} is granted {right} on the CA. ManageCertificates lets it approve a pending \
                 request (issue a cert on any template → ESC1-style impersonation); ManageCA lets \
                 it set EDITF_ATTRIBUTESUBJECTALTNAME2 (→ ESC6) or add itself as an officer. \
                 Remediation: remove the ACE — restrict CA Administrators/Certificate Managers to Tier-0.",
                ace.trustee
            ),
        });
    }
    hits
}

/// ESC7 from the raw `Security` REG_BINARY under the CA config key.
pub fn esc7(sd_bytes: &[u8]) -> Vec<EscHit> {
    match windows_sddl::parse(sd_bytes) {
        Ok(sd) => esc7_from_sd(&sd),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sddl::{AccessMask, Ace, AceType, Acl, SecurityDescriptor, Sid};

    fn sd_with(trustee: &str, mask: u32) -> SecurityDescriptor {
        SecurityDescriptor {
            owner: None,
            group: None,
            dacl: Some(Acl {
                aces: vec![Ace {
                    ace_type: AceType::AccessAllowed,
                    flags: 0,
                    mask: AccessMask::from_bits_truncate(mask),
                    trustee: Sid::parse(trustee).unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                }],
            }),
        }
    }

    #[test]
    fn esc7_fires_for_nonadmin_manageca() {
        // low-priv domain user with ManageCA
        let sd = sd_with("S-1-5-21-1-2-3-1105", CA_MANAGE_CA);
        let h = esc7_from_sd(&sd);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].id, "A-Esc7");
        assert!(h[0].detail.contains("ManageCA"));
    }

    #[test]
    fn esc7_ignores_tier0_and_enroll_only() {
        // Domain Admins with both rights → benign
        assert!(esc7_from_sd(&sd_with(
            "S-1-5-21-1-2-3-512",
            CA_MANAGE_CA | CA_MANAGE_CERTIFICATES
        ))
        .is_empty());
        // BUILTIN\Administrators → benign
        assert!(esc7_from_sd(&sd_with("S-1-5-32-544", CA_MANAGE_CA)).is_empty());
        // Authenticated Users with Enroll (0x200, not a management bit) → benign
        assert!(esc7_from_sd(&sd_with("S-1-5-11", 0x200)).is_empty());
    }

    #[test]
    fn esc6_fires_only_on_the_bit() {
        assert!(esc6(0x0004_0000).is_some());
        assert!(esc6(0x0014_0014).is_some()); // bit present among others
        assert!(esc6(0x0000_0000).is_none());
        assert!(esc6(0x0002_0000).is_none()); // a different bit
    }

    #[test]
    fn esc11_fires_when_encryption_not_enforced() {
        assert!(esc11(0x0000_0000).is_some()); // no enforcement bit
        assert!(esc11(0x0000_0040).is_some()); // some other flag, still no privacy
        assert!(esc11(0x0000_0200).is_none()); // enforced → safe
        assert!(esc11(0x0000_0240).is_none());
    }

    #[test]
    fn esc16_matches_the_security_ext_oid() {
        assert!(esc16("1.3.6.1.4.1.311.25.2").is_some());
        assert!(esc16("1.2.3.4\n1.3.6.1.4.1.311.25.2\n5.6.7").is_some());
        assert!(esc16("1.2.3.4\n5.6.7").is_none());
        assert!(esc16("").is_none());
    }

    #[test]
    fn esc10_below_full_is_weak() {
        assert!(esc10(0).is_some());
        assert!(esc10(1).is_some());
        assert!(esc10(2).is_none()); // Full enforcement → safe
    }
}
