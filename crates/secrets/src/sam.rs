//! Offline SAM secrets: derive the system bootkey from the SYSTEM hive, then decrypt the local
//! account NT hashes out of the SAM hive. Implements both the legacy RC4 path and the modern
//! (Windows 10 / Server 2016+, incl. Server 2025) AES-128-CBC path, mirroring impacket's
//! secretsdump LOCAL logic.

use crate::hive::Hive;
use aes::cipher::{BlockDecrypt, KeyInit};
use des::Des;
use md5::{Digest, Md5};
use rc4::{Rc4, StreamCipher};

const AQWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
const ANUM: &[u8] = b"0123456789012345678901234567890123456789\0";
const NTPASSWORD: &[u8] = b"NTPASSWORD\0";
const EMPTY_NT: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

/// One decrypted local account.
pub struct SamAccount {
    pub rid: u32,
    pub username: String,
    pub nt: String, // 32-hex NT hash
}

impl SamAccount {
    /// secretsdump line: `user:rid:lmhash:nthash:::` (LM left as the empty-string hash).
    pub fn secretsdump_line(&self) -> String {
        format!(
            "{}:{}:aad3b435b51404eeaad3b435b51404ee:{}:::",
            self.username, self.rid, self.nt
        )
    }
}

/// Derive the 16-byte bootkey ("syskey") from the SYSTEM hive: concatenate the class names of
/// the four Lsa subkeys (JD/Skew1/GBG/Data — 8 hex chars each) and apply the fixed permutation.
pub fn bootkey(system: &Hive) -> Option<[u8; 16]> {
    let cs = system.value_u32("Select", "Current").unwrap_or(1);
    let lsa = format!("ControlSet{cs:03}\\Control\\Lsa");

    let mut hex = String::new();
    for key in ["JD", "Skew1", "GBG", "Data"] {
        let class = system.key_class(&format!("{lsa}\\{key}"))?;
        // The class is stored as UTF-16LE text — 8 hex digits per key.
        let s: String = class
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]) as u8 as char)
            .collect();
        hex.push_str(&s);
    }
    let scrambled = hex::decode(hex.trim_matches(char::from(0))).ok()?;
    if scrambled.len() != 16 {
        return None;
    }
    const P: [usize; 16] = [
        0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7,
    ];
    let mut bk = [0u8; 16];
    for i in 0..16 {
        bk[i] = scrambled[P[i]];
    }
    Some(bk)
}

/// The revision of the SAM key material (2 = RC4, 3 = AES) plus the derived hashed bootkey.
struct HashedBootKey {
    revision: u8,
    key: [u8; 16],
}

fn hashed_bootkey(sam: &Hive, bootkey: &[u8; 16]) -> Option<HashedBootKey> {
    let f = sam.value("SAM\\Domains\\Account", "F")?;
    // Need through f[0xA0] (kd[24..56]) on the RC4 path; a shorter/crafted F must return None,
    // not panic on the slice (this parser runs on attacker/analyst-supplied hives).
    if f.len() < 0xA0 {
        return None;
    }
    let kd = &f[0x68..];
    let revision = kd[0];
    match revision {
        // Revision 1 (≤ Server 2012 R2) and 2 share the RC4 SAM_KEY_DATA structure + derivation;
        // revision 3 (Server 2016+) is AES.
        1 | 2 => {
            // SAM_KEY_DATA: Revision(4) Length(4) Salt(16) Key(16) CheckSum(16).
            let salt = &kd[8..24];
            let enc = &kd[24..56]; // Key(16) + CheckSum(16)
            let mut md = Md5::new();
            md.update(salt);
            md.update(AQWERTY);
            md.update(bootkey);
            md.update(ANUM);
            let rc4key = md.finalize();
            let mut buf = enc.to_vec();
            Rc4::new(&rc4key).apply_keystream(&mut buf);
            let mut key = [0u8; 16];
            key.copy_from_slice(&buf[..16]);
            Some(HashedBootKey { revision, key })
        }
        3 => {
            // SAM_KEY_DATA_AES: Revision(4) Length(4) ChecksumLen(4) DataLen(4) Salt(16) Data(..).
            let salt: [u8; 16] = kd[16..32].try_into().ok()?;
            let data = &kd[32..];
            let dec = aes128_cbc_decrypt(bootkey, &salt, data);
            let mut key = [0u8; 16];
            key.copy_from_slice(dec.get(..16)?);
            Some(HashedBootKey { revision, key })
        }
        _ => None,
    }
}

/// Decrypt all local accounts from a SAM hive given the SYSTEM bootkey.
pub fn dump(system: &Hive, sam: &Hive) -> Option<Vec<SamAccount>> {
    let bk = bootkey(system)?;
    let hbk = hashed_bootkey(sam, &bk)?;
    let mut out = Vec::new();
    for name in sam.subkey_names("SAM\\Domains\\Account\\Users") {
        let Ok(rid) = u32::from_str_radix(&name, 16) else {
            continue;
        }; // subkeys are hex RIDs; skip "Names"
        let Some(v) = sam.value(&format!("SAM\\Domains\\Account\\Users\\{name}"), "V") else {
            continue;
        };
        if let Some(acct) = decrypt_user(&v, rid, &hbk) {
            out.push(acct);
        }
    }
    out.sort_by_key(|a| a.rid);
    Some(out)
}

fn le32(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize
}

fn decrypt_user(v: &[u8], rid: u32, hbk: &HashedBootKey) -> Option<SamAccount> {
    if v.len() < 0xCC {
        return None;
    }
    // Offset table entries are relative to 0xCC.
    let name_off = le32(v, 0x0c) + 0xCC;
    let name_len = le32(v, 0x10);
    let nt_off = le32(v, 0xa8) + 0xCC;
    let nt_len = le32(v, 0xac);

    let username = v.get(name_off..name_off + name_len).map(|b| {
        let units: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    })?;

    let nt = if nt_len < 20 {
        EMPTY_NT.to_string() // no hash stored → empty-password hash
    } else {
        let blob = v.get(nt_off..nt_off + nt_len)?;
        hex::encode(decrypt_hash(blob, rid, hbk)?)
    };
    Some(SamAccount { rid, username, nt })
}

/// Decrypt one 16-byte hash from its V-structure blob (RC4 or AES form) → NT hash bytes.
fn decrypt_hash(blob: &[u8], rid: u32, hbk: &HashedBootKey) -> Option<[u8; 16]> {
    let raw = if hbk.revision == 3 {
        // SAM_HASH_AES: PekID(2) Revision(2) DataOffset(4) Salt(16) Hash(..).
        if blob.len() < 24 {
            return Some(hex_to_16(EMPTY_NT));
        }
        let salt: [u8; 16] = blob[8..24].try_into().ok()?;
        let enc = &blob[24..];
        if enc.is_empty() {
            return Some(hex_to_16(EMPTY_NT));
        }
        let dec = aes128_cbc_decrypt(&hbk.key, &salt, enc);
        let mut h = [0u8; 16];
        h.copy_from_slice(dec.get(..16)?);
        return Some(h); // AES path yields the NT hash directly — no per-RID DES.
    } else {
        // SAM_HASH: PekID(2) Revision(2) Hash(16).
        if blob.len() < 20 {
            return Some(hex_to_16(EMPTY_NT));
        }
        let enc = &blob[4..20];
        let mut md = Md5::new();
        md.update(hbk.key);
        md.update(rid.to_le_bytes());
        md.update(NTPASSWORD);
        let rc4key = md.finalize();
        let mut buf = enc.to_vec();
        Rc4::new(&rc4key).apply_keystream(&mut buf);
        buf
    };
    // RC4 path: strip the per-RID DES layer.
    Some(remove_des_layer(&raw, rid))
}

fn hex_to_16(s: &str) -> [u8; 16] {
    let mut h = [0u8; 16];
    h.copy_from_slice(&hex::decode(s).unwrap());
    h
}

/// Manual AES-128-CBC decrypt (no padding); decrypts whole 16-byte blocks, ignores any tail.
fn aes128_cbc_decrypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = aes::Aes128::new(key[..16].into());
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for block in data.chunks_exact(16) {
        let mut b = [0u8; 16];
        b.copy_from_slice(block);
        let ct = b;
        cipher.decrypt_block((&mut b).into());
        for i in 0..16 {
            b[i] ^= prev[i];
        }
        out.extend_from_slice(&b);
        prev = ct;
    }
    out
}

/// Reverse the two-half DES obfuscation keyed by the RID (SAM RC4 path).
fn remove_des_layer(data: &[u8], rid: u32) -> [u8; 16] {
    let (k1, k2) = rid_to_des_keys(rid);
    let mut out = [0u8; 16];
    des_decrypt_block(&k1, &data[0..8], &mut out[0..8]);
    des_decrypt_block(&k2, &data[8..16], &mut out[8..16]);
    out
}

fn des_decrypt_block(key: &[u8; 8], input: &[u8], output: &mut [u8]) {
    let cipher = Des::new(key.into());
    let mut b = [0u8; 8];
    b.copy_from_slice(input);
    cipher.decrypt_block((&mut b).into());
    output.copy_from_slice(&b);
}

fn rid_to_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let r = rid.to_le_bytes();
    let s1 = [r[0], r[1], r[2], r[3], r[0], r[1], r[2]];
    let s2 = [r[3], r[0], r[1], r[2], r[3], r[0], r[1]];
    (str_to_des_key(&s1), str_to_des_key(&s2))
}

/// Expand 7 bytes into an 8-byte DES key (7 bits/byte, parity bit unused).
fn str_to_des_key(s: &[u8; 7]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = s[0] >> 1;
    k[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2);
    k[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3);
    k[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4);
    k[4] = ((s[3] & 0x0f) << 3) | (s[4] >> 5);
    k[5] = ((s[4] & 0x1f) << 2) | (s[5] >> 6);
    k[6] = ((s[5] & 0x3f) << 1) | (s[6] >> 7);
    k[7] = s[6] & 0x7f;
    for b in &mut k {
        *b <<= 1; // DES uses the top 7 bits; the LSB is parity (ignored).
    }
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_to_key_known_vector() {
        // Classic "KGS!@#$%" LM key-schedule vector: rid does not apply, but str_to_key is the
        // same expansion used everywhere; check a simple deterministic transform.
        let k = str_to_des_key(&[0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(k, [0u8; 8]);
    }

    #[test]
    fn aes_cbc_roundtrips() {
        use aes::cipher::BlockEncrypt;
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let pt = [0x33u8; 16];
        // encrypt one block manually then CBC-decrypt.
        let cipher = aes::Aes128::new((&key).into());
        let mut b = [0u8; 16];
        for i in 0..16 {
            b[i] = pt[i] ^ iv[i];
        }
        cipher.encrypt_block((&mut b).into());
        let dec = aes128_cbc_decrypt(&key, &iv, &b);
        assert_eq!(&dec[..], &pt[..]);
    }

    #[test]
    fn empty_nt_hash_constant() {
        assert_eq!(EMPTY_NT.len(), 32);
    }
}
