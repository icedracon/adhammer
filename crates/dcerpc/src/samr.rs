//! SAMR (MS-SAMR) — the Security Account Manager Remote protocol: enumerate domains,
//! users, groups, and (via aliases) local administrators. Exposed only over the
//! `\PIPE\samr` named pipe, so it rides an authenticated SMB transport (the next layer);
//! the interface identity and NDR request marshaling live here.

use crate::ndr::{NdrDecoder, NdrEncoder};
use crate::transport::SmbPipe;
use crate::{Result, RpcError, Syntax};
use adhammer_core::sid::Sid;
use adhammer_smb::SmbClient;

/// The SAMR interface (v1.0).
pub fn samr_syntax() -> Syntax {
    Syntax::new("12345778-1234-abcd-ef00-0123456789ac", 1, 0)
}

pub mod opnum {
    pub const CONNECT: u16 = 0;
    pub const CLOSE_HANDLE: u16 = 1;
    pub const LOOKUP_DOMAIN: u16 = 5;
    pub const ENUM_DOMAINS: u16 = 6;
    pub const OPEN_DOMAIN: u16 = 7;
    pub const ENUM_USERS: u16 = 13;
    pub const CONNECT2: u16 = 57;
    pub const CONNECT5: u16 = 64;
}

/// A 20-byte RPC context handle (attributes u32 + 16-byte GUID) returned by open calls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SamrHandle(pub [u8; 20]);

impl SamrHandle {
    pub fn decode(d: &mut NdrDecoder) -> Result<Self> {
        let _attrs = d.u32()?;
        let uuid = d.uuid()?;
        let mut h = [0u8; 20];
        h[..4].copy_from_slice(&_attrs.to_le_bytes());
        h[4..].copy_from_slice(&uuid);
        Ok(SamrHandle(h))
    }
    pub fn encode(&self, e: &mut NdrEncoder) {
        e.bytes(&self.0);
    }
}

/// SamrConnect2(IN [unique,string] ServerName, IN ACCESS_MASK DesiredAccess) → handle.
pub fn encode_connect2(server: &str, desired_access: u32) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.referent(); // non-null unique pointer to ServerName
    e.conformant_varying_wstr(server);
    e.u32(desired_access);
    e.into_bytes()
}

/// SamrEnumerateDomainsInSamServer(IN handle, IN/OUT EnumerationContext, IN PreferedMaximumLength).
pub fn encode_enum_domains(server_handle: &SamrHandle, resume: u32, pref_max: u32) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    server_handle.encode(&mut e);
    e.u32(resume);
    e.u32(pref_max);
    e.into_bytes()
}

/// Decode a SamrEnumerateDomainsInSamServer response: (resume handle, [(rid, name)]).
///
/// Layout: EnumerationContext(u32), Buffer ptr → { EntriesRead(u32), array ptr →
/// max_count(u32), N × { RelativeId(u32), RPC_UNICODE_STRING{len,max,buf-ptr} } }, then
/// each non-null name as a conformant-varying wchar array.
pub fn decode_enum_domains(stub: &[u8]) -> Result<(u32, Vec<(u32, String)>)> {
    let mut d = NdrDecoder::new(stub);
    let resume = d.u32()?;
    let buffer_ref = d.u32()?;
    if buffer_ref == 0 {
        return Ok((resume, Vec::new()));
    }
    let entries = d.u32()? as usize;
    let _array_ref = d.u32()?;
    let _max_count = d.u32()?;

    let mut fixed = Vec::with_capacity(entries);
    for _ in 0..entries {
        let rid = d.u32()?;
        let _name_len = d.u16()?;
        let _name_max = d.u16()?;
        let name_ref = d.u32()?;
        fixed.push((rid, name_ref));
    }

    let mut out = Vec::with_capacity(entries);
    for (rid, name_ref) in fixed {
        let name = if name_ref != 0 { d.conformant_varying_wstr()? } else { String::new() };
        out.push((rid, name));
    }
    Ok((resume, out))
}

// ---- RPC_SID marshaling ---------------------------------------------------

/// Encode an RPC_SID (conformant array size hoisted): max_count, revision, count,
/// 6-byte big-endian authority, then the sub-authorities.
fn encode_sid(e: &mut NdrEncoder, sid: &Sid) {
    e.u32(sid.sub_authorities.len() as u32); // max_count
    e.u8(sid.revision);
    e.u8(sid.sub_authorities.len() as u8);
    let a = sid.identifier_authority;
    e.bytes(&[(a >> 40) as u8, (a >> 32) as u8, (a >> 24) as u8, (a >> 16) as u8, (a >> 8) as u8, a as u8]);
    for s in &sid.sub_authorities {
        e.u32(*s);
    }
}

fn decode_sid(d: &mut NdrDecoder) -> Result<Sid> {
    let _max = d.u32()?;
    let revision = d.u8()?;
    let count = d.u8()? as usize;
    let auth = d.read_bytes(6)?;
    let identifier_authority = auth.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
    let mut sub_authorities = Vec::with_capacity(count);
    for _ in 0..count {
        sub_authorities.push(d.u32()?);
    }
    Ok(Sid { revision, identifier_authority, sub_authorities })
}

/// SamrLookupDomainInSamServer(IN handle, IN RPC_UNICODE_STRING name) → domain SID.
pub fn encode_lookup_domain(server: &SamrHandle, name: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    server.encode(&mut e);
    let units: Vec<u16> = name.encode_utf16().collect();
    let blen = (units.len() * 2) as u16;
    e.u16(blen); // Length
    e.u16(blen); // MaximumLength
    e.referent(); // Buffer pointer
    e.u32(units.len() as u32); // max_count (counted, no NUL)
    e.u32(0); // offset
    e.u32(units.len() as u32); // actual_count
    for u in units {
        e.u16(u);
    }
    e.into_bytes()
}

pub fn decode_lookup_domain(stub: &[u8]) -> Result<Sid> {
    let mut d = NdrDecoder::new(stub);
    let sid_ref = d.u32()?;
    if sid_ref == 0 {
        return Err(RpcError::Protocol("SamrLookupDomain returned no SID".into()));
    }
    decode_sid(&mut d)
}

/// SamrOpenDomain(IN handle, IN access, IN RPC_SID domain) → domain handle.
pub fn encode_open_domain(server: &SamrHandle, desired_access: u32, sid: &Sid) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    server.encode(&mut e);
    e.u32(desired_access);
    // DomainId is a top-level [ref] pointer → NDR emits the pointee directly, no referent id.
    encode_sid(&mut e, sid);
    e.into_bytes()
}

/// SamrEnumerateUsersInDomain(IN handle, IN/OUT ctx, IN UserAccountControl, IN prefMax).
/// The response reuses the SAMPR_RID_ENUMERATION shape → `decode_enum_domains`.
pub fn encode_enum_users(domain: &SamrHandle, resume: u32, uac_filter: u32, pref_max: u32) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    domain.encode(&mut e);
    e.u32(resume);
    e.u32(uac_filter);
    e.u32(pref_max);
    e.into_bytes()
}

/// High-level SAMR client bound over an SMB named pipe (`\PIPE\samr`).
pub struct SamrClient<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> SamrClient<'a> {
    /// Bind the SAMR interface over an already-open `samr` pipe.
    pub async fn bind(client: &'a mut SmbClient, file_id: [u8; 16]) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind(samr_syntax()).await?;
        Ok(SamrClient { pipe })
    }

    /// SamrConnect2 → server handle.
    pub async fn connect(&mut self, server: &str) -> Result<SamrHandle> {
        let stub = encode_connect2(server, access::MAXIMUM_ALLOWED);
        let resp = self.pipe.call(opnum::CONNECT2, &stub).await?;
        let mut d = NdrDecoder::new(&resp);
        SamrHandle::decode(&mut d)
    }

    /// Enumerate the SAM domains (typically "Builtin" and the account domain).
    pub async fn enumerate_domains(&mut self, server: &SamrHandle) -> Result<Vec<String>> {
        let stub = encode_enum_domains(server, 0, 0x1000);
        let resp = self.pipe.call(opnum::ENUM_DOMAINS, &stub).await?;
        let (_resume, list) = decode_enum_domains(&resp)?;
        Ok(list.into_iter().map(|(_, name)| name).collect())
    }

    /// SamrLookupDomainInSamServer → the SID of a named domain.
    pub async fn lookup_domain(&mut self, server: &SamrHandle, name: &str) -> Result<Sid> {
        let resp = self.pipe.call(opnum::LOOKUP_DOMAIN, &encode_lookup_domain(server, name)).await?;
        decode_lookup_domain(&resp)
    }

    /// SamrOpenDomain → a handle to the domain identified by `sid`.
    pub async fn open_domain(&mut self, server: &SamrHandle, sid: &Sid) -> Result<SamrHandle> {
        let stub = encode_open_domain(server, access::MAXIMUM_ALLOWED, sid);
        let resp = self.pipe.call(opnum::OPEN_DOMAIN, &stub).await?;
        let mut d = NdrDecoder::new(&resp);
        SamrHandle::decode(&mut d)
    }

    /// SamrEnumerateUsersInDomain → [(rid, sAMAccountName)] for the open domain.
    pub async fn enumerate_users(&mut self, domain: &SamrHandle) -> Result<Vec<(u32, String)>> {
        // SamrEnumerateUsersInDomain is paged: it returns up to PreferedMaximumLength of
        // entries plus an EnumerationContext, and NTSTATUS STATUS_MORE_ENTRIES (0x105) while
        // more remain. Loop on the resume handle until the domain is exhausted.
        const STATUS_MORE_ENTRIES: u32 = 0x0000_0105;
        let mut all = Vec::new();
        let mut resume = 0u32;
        loop {
            let stub = encode_enum_users(domain, resume, 0, 0x1000);
            let resp = self.pipe.call(opnum::ENUM_USERS, &stub).await?;
            let (next, list) = decode_enum_domains(&resp)?;
            let got = list.len();
            all.extend(list);
            // The operation's return NTSTATUS is the trailing 4 bytes of the stub.
            let status = resp
                .get(resp.len().wrapping_sub(4)..)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            if status != STATUS_MORE_ENTRIES || got == 0 || next == resume {
                break; // done, or no forward progress (guard against a stuck context)
            }
            resume = next;
        }
        Ok(all)
    }

    /// End-to-end: connect, pick the account domain (the non-"Builtin" one), and list its
    /// users — the SAMR enumeration LDAP can't fully reproduce.
    pub async fn enumerate_all_users(&mut self, server_name: &str) -> Result<Vec<(u32, String)>> {
        let server = self.connect(server_name).await?;
        let domains = self.enumerate_domains(&server).await?;
        let account = domains.into_iter().find(|d| !d.eq_ignore_ascii_case("Builtin"));
        let Some(account) = account else { return Ok(Vec::new()) };
        let sid = self.lookup_domain(&server, &account).await?;
        let domain_handle = self.open_domain(&server, &sid).await?;
        self.enumerate_users(&domain_handle).await
    }
}

/// Common SAM access masks.
pub mod access {
    pub const SAM_SERVER_ENUMERATE_DOMAINS: u32 = 0x0000_0010;
    pub const SAM_SERVER_LOOKUP_DOMAIN: u32 = 0x0000_0020;
    pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect2_marshals_server_and_access() {
        let stub = encode_connect2("\\\\dc01", access::MAXIMUM_ALLOWED);
        // referent(4) + max/off/act(12) + "\\dc01"+NUL = 7 wchar*2(14) = 30,
        // align(4) → pad 2, then access u32 = 36.
        assert_eq!(stub.len(), 36);
        assert_eq!(&stub[32..36], &access::MAXIMUM_ALLOWED.to_le_bytes());
        // referent id is non-zero.
        assert_ne!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 0);
    }

    #[test]
    fn enum_domains_layout() {
        let stub = encode_enum_domains(&SamrHandle([0; 20]), 0, 0x1000);
        assert_eq!(stub.len(), 20 + 4 + 4);
        assert_eq!(&stub[24..28], &0x1000u32.to_le_bytes());
    }

    /// Encode a synthetic SamrEnumerateDomains response and decode it back — proves the
    /// nested-pointer / conformant-array decoder without a live DC.
    fn encode_enum_response(domains: &[&str]) -> Vec<u8> {
        let mut e = NdrEncoder::new();
        e.u32(0); // EnumerationContext
        e.referent(); // Buffer pointer
        e.u32(domains.len() as u32); // EntriesRead
        e.referent(); // array pointer
        e.u32(domains.len() as u32); // conformant max_count
        for name in domains {
            let ul = (name.encode_utf16().count() * 2) as u16;
            e.u32(0); // RelativeId
            e.u16(ul); // Name.Length
            e.u16(ul); // Name.MaximumLength
            e.referent(); // Name.Buffer pointer
        }
        for name in domains {
            let units: Vec<u16> = name.encode_utf16().collect();
            let n = units.len() as u32;
            e.u32(n); // max_count (no NUL, like real SAMR)
            e.u32(0); // offset
            e.u32(n); // actual_count
            for u in units {
                e.u16(u);
            }
        }
        e.u32(domains.len() as u32); // CountReturned
        e.u32(0); // NTSTATUS
        e.into_bytes()
    }

    #[test]
    fn enum_domains_decode_roundtrip() {
        let stub = encode_enum_response(&["Builtin", "CORP"]);
        let (resume, list) = decode_enum_domains(&stub).unwrap();
        assert_eq!(resume, 0);
        let names: Vec<&str> = list.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(names, vec!["Builtin", "CORP"]);
    }

    #[test]
    fn sid_marshaling_roundtrips_through_lookup_response() {
        let sid = Sid::parse("S-1-5-21-1111111111-2222222222-3333333333").unwrap();
        // Synthesize a SamrLookupDomain response: SID pointer (non-null) + SID.
        let mut e = NdrEncoder::new();
        e.referent();
        encode_sid(&mut e, &sid);
        let stub = e.into_bytes();
        assert_eq!(decode_lookup_domain(&stub).unwrap(), sid);
    }

    #[test]
    fn enum_users_request_layout() {
        let stub = encode_enum_users(&SamrHandle([0; 20]), 0, 0, 0x1000);
        assert_eq!(stub.len(), 20 + 4 + 4 + 4);
        assert_eq!(&stub[28..32], &0x1000u32.to_le_bytes());
    }
}
