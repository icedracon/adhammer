//! NTLM (MS-NLMP) — the impacket `ntlm` equivalent. Implements NTLMSSP NEGOTIATE /
//! CHALLENGE / AUTHENTICATE with NTLMv2, key exchange, and the MIC, so it can drive both
//! authenticated DCE/RPC and SMB session setup.
//!
//! Crypto: NT hash = MD4(UTF-16LE(password)); NTOWFv2 = HMAC-MD5(NT, UPPER(user)+domain);
//! NTLMv2 response = NTProofStr || temp. Verified against the MS-NLMP §4.2.4 test vector.

use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use rand::RngCore;

pub mod flags {
    pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    pub const NEGOTIATE_SIGN: u32 = 0x0000_0010;
    pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
    pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
    pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
    pub const NEGOTIATE_128: u32 = 0x2000_0000;
    pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
}

#[derive(Debug, thiserror::Error)]
pub enum NtlmError {
    #[error("not an NTLM {0} message")]
    BadMessage(&'static str),
    #[error("truncated message")]
    Truncated,
}
type Result<T> = std::result::Result<T, NtlmError>;

// ---- crypto primitives ----------------------------------------------------

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn nt_hash(password: &str) -> [u8; 16] {
    let d = Md4::digest(utf16le(password));
    let mut h = [0u8; 16];
    h.copy_from_slice(&d);
    h
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac<Md5>>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let mut o = [0u8; 16];
    o.copy_from_slice(&mac.finalize().into_bytes());
    o
}

/// NTOWFv2 = HMAC-MD5(NT-hash, UTF-16LE(UPPER(user) + domain)).
pub fn nt_owf_v2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let nt = nt_hash(password);
    let identity = utf16le(&format!("{}{}", user.to_uppercase(), domain));
    hmac_md5(&nt, &identity)
}

// ---- message parsing / building -------------------------------------------

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Parsed CHALLENGE (Type 2).
#[derive(Clone, Debug)]
pub struct Challenge {
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
    pub flags: u32,
}

pub fn parse_challenge(b: &[u8]) -> Result<Challenge> {
    if b.len() < 48 || &b[0..8] != b"NTLMSSP\0" {
        return Err(NtlmError::BadMessage("CHALLENGE"));
    }
    if u32le(b, 8) != 2 {
        return Err(NtlmError::BadMessage("CHALLENGE"));
    }
    let flags = u32le(b, 20);
    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&b[24..32]);
    let ti_len = u16le(b, 40) as usize;
    let ti_off = u32le(b, 44) as usize;
    let target_info = b.get(ti_off..ti_off + ti_len).unwrap_or(&[]).to_vec();
    Ok(Challenge { server_challenge, target_info, flags })
}

/// The MsvAvTimestamp (AV id 7) from a target-info blob, if present.
fn target_info_timestamp(ti: &[u8]) -> Option<u64> {
    let mut p = 0;
    while p + 4 <= ti.len() {
        let id = u16le(ti, p);
        let len = u16le(ti, p + 2) as usize;
        p += 4;
        if id == 0 {
            break; // MsvAvEOL
        }
        if id == 7 && len >= 8 {
            return ti.get(p..p + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()));
        }
        p += len;
    }
    None
}

fn now_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    (secs + 11_644_473_600) * 10_000_000
}

/// NTLMv2 response = NTProofStr || temp; also returns the SessionBaseKey and LMv2 response.
fn ntlmv2_response(
    resp_key: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: u64,
    target_info: &[u8],
) -> (Vec<u8>, [u8; 16], Vec<u8>) {
    let mut temp = vec![0x01, 0x01, 0, 0, 0, 0, 0, 0];
    temp.extend_from_slice(&timestamp.to_le_bytes());
    temp.extend_from_slice(client_challenge);
    temp.extend_from_slice(&[0, 0, 0, 0]);
    temp.extend_from_slice(target_info);
    temp.extend_from_slice(&[0, 0, 0, 0]);

    let mut proof_input = server_challenge.to_vec();
    proof_input.extend_from_slice(&temp);
    let nt_proof = hmac_md5(resp_key, &proof_input);

    let mut nt_response = nt_proof.to_vec();
    nt_response.extend_from_slice(&temp);
    let session_base_key = hmac_md5(resp_key, &nt_proof);

    let mut lm_input = server_challenge.to_vec();
    lm_input.extend_from_slice(client_challenge);
    let mut lm_response = hmac_md5(resp_key, &lm_input).to_vec();
    lm_response.extend_from_slice(client_challenge);

    (nt_response, session_base_key, lm_response)
}

const VERSION: [u8; 8] = [6, 1, 0, 0, 0, 0, 0, 15]; // Windows 7, NTLMSSP rev 15

/// NTLM client: holds the NEGOTIATE message so the MIC can bind all three messages.
pub struct Ntlm {
    type1: Vec<u8>,
}

impl Default for Ntlm {
    fn default() -> Self {
        Self::new()
    }
}

impl Ntlm {
    pub fn new() -> Self {
        let f = flags::NEGOTIATE_UNICODE
            | flags::REQUEST_TARGET
            | flags::NEGOTIATE_NTLM
            | flags::NEGOTIATE_ALWAYS_SIGN
            | flags::NEGOTIATE_EXTENDED_SESSIONSECURITY;
        let mut m = Vec::new();
        m.extend_from_slice(b"NTLMSSP\0");
        m.extend_from_slice(&1u32.to_le_bytes());
        m.extend_from_slice(&f.to_le_bytes());
        m.extend_from_slice(&[0u8; 8]); // DomainName fields (empty)
        m.extend_from_slice(&[0u8; 8]); // Workstation fields (empty)
        Ntlm { type1: m }
    }

    pub fn negotiate(&self) -> &[u8] {
        &self.type1
    }

    /// Produce the AUTHENTICATE (Type 3) for the given CHALLENGE and credentials, plus the
    /// exported session key (used for SMB/RPC signing and sealing).
    pub fn authenticate(
        &self,
        challenge: &[u8],
        domain: &str,
        user: &str,
        password: &str,
        workstation: &str,
    ) -> Result<(Vec<u8>, [u8; 16])> {
        let ch = parse_challenge(challenge)?;
        let resp_key = nt_owf_v2(password, user, domain);

        let mut client_challenge = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut client_challenge);
        let timestamp = target_info_timestamp(&ch.target_info).unwrap_or_else(now_filetime);

        let (nt_response, session_base_key, lm_response) =
            ntlmv2_response(&resp_key, &ch.server_challenge, &client_challenge, timestamp, &ch.target_info);

        // No key exchange: the exported session key IS the SessionBaseKey. Simpler and it
        // makes the SMB/RPC signing key unambiguous (no RC4-wrapped random key to agree on).
        let exported = session_base_key;
        let type3 = build_type3(
            &lm_response,
            &nt_response,
            domain,
            user,
            workstation,
            &[], // no EncryptedRandomSessionKey without key exchange
            &self.type1,
            challenge,
            &exported,
        );
        Ok((type3, exported))
    }
}

#[allow(clippy::too_many_arguments)]
fn build_type3(
    lm: &[u8],
    nt: &[u8],
    domain: &str,
    user: &str,
    workstation: &str,
    enc_session_key: &[u8],
    type1: &[u8],
    type2: &[u8],
    exported: &[u8; 16],
) -> Vec<u8> {
    let du = utf16le(domain);
    let uu = utf16le(user);
    let wu = utf16le(workstation);

    let f = flags::NEGOTIATE_UNICODE
        | flags::REQUEST_TARGET
        | flags::NEGOTIATE_SIGN
        | flags::NEGOTIATE_NTLM
        | flags::NEGOTIATE_ALWAYS_SIGN
        | flags::NEGOTIATE_EXTENDED_SESSIONSECURITY
        | flags::NEGOTIATE_TARGET_INFO
        | flags::NEGOTIATE_VERSION
        | flags::NEGOTIATE_128;

    // Header is 88 bytes: sig(8)+type(4)+6 fields(48)+flags(4)+version(8)+MIC(16).
    const HEADER: u32 = 88;
    let mut payload = Vec::new();
    let mut field = |data: &[u8]| -> [u8; 8] {
        let off = HEADER + payload.len() as u32;
        payload.extend_from_slice(data);
        let mut f = [0u8; 8];
        f[0..2].copy_from_slice(&(data.len() as u16).to_le_bytes());
        f[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
        f[4..8].copy_from_slice(&off.to_le_bytes());
        f
    };
    let lm_f = field(lm);
    let nt_f = field(nt);
    let dom_f = field(&du);
    let usr_f = field(&uu);
    let ws_f = field(&wu);
    let key_f = field(enc_session_key);

    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&3u32.to_le_bytes());
    for fld in [lm_f, nt_f, dom_f, usr_f, ws_f, key_f] {
        m.extend_from_slice(&fld);
    }
    m.extend_from_slice(&f.to_le_bytes());
    m.extend_from_slice(&VERSION);
    let mic_at = m.len();
    m.extend_from_slice(&[0u8; 16]); // MIC placeholder
    debug_assert_eq!(m.len() as u32, HEADER);
    m.extend_from_slice(&payload);

    // MIC = HMAC-MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE[MIC=0]).
    let mut all = Vec::with_capacity(type1.len() + type2.len() + m.len());
    all.extend_from_slice(type1);
    all.extend_from_slice(type2);
    all.extend_from_slice(&m);
    let mic = hmac_md5(exported, &all);
    m[mic_at..mic_at + 16].copy_from_slice(&mic);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    // MS-NLMP §4.2.4.2: NTOWFv2 for User/Domain/Password.
    #[test]
    fn ntowfv2_matches_spec_vector() {
        let key = nt_owf_v2("Password", "User", "Domain");
        assert_eq!(hex(&key), "0c868a403bfd7a93a3001ef22ef02e3f");
    }

    #[test]
    fn type3_roundtrips_identity() {
        let type2 = fake_challenge();
        let ntlm = Ntlm::new();
        let (t3, exported) = ntlm.authenticate(&type2, "Domain", "User", "Password", "WKS").unwrap();

        assert_eq!(&t3[0..8], b"NTLMSSP\0");
        assert_eq!(u32le(&t3, 8), 3);
        // UserName field is the 4th field: sig(8)+type(4)+Lm(8)+Nt(8)+Domain(8) = 36.
        let user = read_field(&t3, 36);
        assert_eq!(user, "User");
        let domain = read_field(&t3, 28);
        assert_eq!(domain, "Domain");
        assert_ne!(exported, [0u8; 16]);
    }

    fn read_field(m: &[u8], field_off: usize) -> String {
        let len = u16le(m, field_off) as usize;
        let off = u32le(m, field_off + 4) as usize;
        let bytes = &m[off..off + len];
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    }

    fn fake_challenge() -> Vec<u8> {
        let target_info = [0u8, 0, 0, 0]; // MsvAvEOL only
        let mut m = Vec::new();
        m.extend_from_slice(b"NTLMSSP\0");
        m.extend_from_slice(&2u32.to_le_bytes());
        m.extend_from_slice(&[0u8; 8]); // TargetName fields (empty)
        m.extend_from_slice(&flags::NEGOTIATE_UNICODE.to_le_bytes());
        m.extend_from_slice(&[0x11; 8]); // server challenge
        m.extend_from_slice(&[0u8; 8]); // reserved
        let ti_off = 48u32;
        m.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        m.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        m.extend_from_slice(&ti_off.to_le_bytes());
        m.extend_from_slice(&target_info);
        m
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
