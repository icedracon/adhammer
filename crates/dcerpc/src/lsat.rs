//! LSAT / LSARPC (MS-LSAT) — SID ⇄ name translation over the `\lsarpc` named pipe.
//! Rides the same SMB DCE/RPC transport as SAMR. Implements OpenPolicy2 + LookupNames
//! (name → SID), the classic recon primitive that also enables RID cycling.

use crate::ndr::{NdrDecoder, NdrEncoder};
use crate::samr::SamrHandle; // 20-byte RPC context handle, reused
use crate::transport::SmbPipe;
use crate::{Result, Syntax};
use adhammer_core::sid::Sid;
use adhammer_smb::SmbClient;

/// The LSARPC interface (v0.0). Note the UUID differs from SAMR only in the last nibble.
pub fn lsat_syntax() -> Syntax {
    Syntax::new("12345778-1234-abcd-ef00-0123456789ab", 0, 0)
}

pub mod opnum {
    pub const CLOSE: u16 = 0;
    pub const LOOKUP_NAMES: u16 = 14;
    pub const OPEN_POLICY2: u16 = 44;
}

const POLICY_MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// LsarOpenPolicy2(SystemName=NULL, ObjectAttributes, DesiredAccess) → policy handle.
pub fn encode_open_policy2() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.null_ptr(); // SystemName [unique,string] = NULL
    // LSAPR_OBJECT_ATTRIBUTES: Length + 5 null/zero fields (24 bytes)
    e.u32(24); // Length
    e.null_ptr(); // RootDirectory
    e.null_ptr(); // ObjectName
    e.u32(0); // Attributes
    e.null_ptr(); // SecurityDescriptor
    e.null_ptr(); // SecurityQualityOfService
    e.u32(POLICY_MAXIMUM_ALLOWED); // DesiredAccess
    e.into_bytes()
}

/// LsarLookupNames(policy, Count=1, Names, TranslatedSids, LookupLevel, MappedCount).
pub fn encode_lookup_names(policy: &SamrHandle, name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let blen = (units.len() * 2) as u16;
    let mut e = NdrEncoder::new();
    policy.encode(&mut e); // PolicyHandle (20)
    e.u32(1); // Count
    // Names: [ref] pointer to conformant array of RPC_UNICODE_STRING (no top-level referent)
    e.u32(1); // max_count
    e.u16(blen); // Name[0].Length
    e.u16(blen); // Name[0].MaximumLength
    e.referent(); // Name[0].Buffer pointer
    // deferred: the buffer (counted conformant-varying, no NUL)
    e.u32(units.len() as u32);
    e.u32(0);
    e.u32(units.len() as u32);
    for u in units {
        e.u16(u);
    }
    // TranslatedSids [in,out]: Entries = 0, Sids = NULL
    e.u32(0);
    e.null_ptr();
    // LookupLevel = LsapLookupWksta (1)
    e.u16(1);
    // MappedCount [in,out] ulong = 0
    e.u32(0);
    e.into_bytes()
}

fn decode_rpc_sid(d: &mut NdrDecoder) -> Result<Sid> {
    let _max = d.u32()?;
    let revision = d.u8()?;
    let count = d.u8()? as usize;
    let auth = d.read_bytes(6)?;
    let identifier_authority = auth.iter().fold(0u64, |a, &b| (a << 8) | b as u64);
    let mut sub = Vec::with_capacity(count);
    for _ in 0..count {
        sub.push(d.u32()?);
    }
    Ok(Sid { revision, identifier_authority, sub_authorities: sub })
}

/// Decode a LookupNames response into the resolved SID for the (single) queried name.
pub fn decode_lookup_names(stub: &[u8]) -> Result<Option<Sid>> {
    let mut d = NdrDecoder::new(stub);

    // ReferencedDomains: [out] pointer to LSAPR_REFERENCED_DOMAIN_LIST
    let dom_ref = d.u32()?;
    let mut domain_sids: Vec<Option<Sid>> = Vec::new();
    if dom_ref != 0 {
        let entries = d.u32()? as usize;
        let domains_ref = d.u32()?;
        let _max_entries = d.u32()?;
        if domains_ref != 0 {
            let _max = d.u32()?;
            // fixed parts: each LSAPR_TRUST_INFORMATION { Name{len,maxlen,buf-ptr}, Sid-ptr }
            let mut fixed = Vec::with_capacity(entries);
            for _ in 0..entries {
                let _len = d.u16()?;
                let _maxlen = d.u16()?;
                let name_ref = d.u32()?;
                let sid_ref = d.u32()?;
                fixed.push((name_ref, sid_ref));
            }
            // deferred: for each, Name buffer then SID
            for (name_ref, sid_ref) in fixed {
                if name_ref != 0 {
                    let _ = d.conformant_varying_wstr()?;
                }
                domain_sids.push(if sid_ref != 0 { Some(decode_rpc_sid(&mut d)?) } else { None });
            }
        }
    }

    // TranslatedSids: LSAPR_TRANSLATED_SIDS { Entries, Sids-ptr }
    let ts_entries = d.u32()? as usize;
    let sids_ref = d.u32()?;
    if sids_ref == 0 || ts_entries == 0 {
        return Ok(None);
    }
    let _max = d.u32()?;
    // first LSAPR_TRANSLATED_SID { Use(u16), RelativeId(u32), DomainIndex(i32) }
    let use_ = d.u16()?;
    let rid = d.u32()?;
    let domain_index = d.u32()? as i32;

    // SidTypeUnknown = 8 ⇒ not mapped
    if use_ == 8 || domain_index < 0 {
        return Ok(None);
    }
    let Some(Some(dom)) = domain_sids.get(domain_index as usize).cloned() else {
        return Ok(None);
    };
    let mut sub = dom.sub_authorities.clone();
    sub.push(rid);
    Ok(Some(Sid { revision: dom.revision, identifier_authority: dom.identifier_authority, sub_authorities: sub }))
}

/// High-level LSAT client bound over `\lsarpc`.
pub struct LsatClient<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> LsatClient<'a> {
    pub async fn bind(client: &'a mut SmbClient, file_id: [u8; 16]) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind(lsat_syntax()).await?;
        Ok(LsatClient { pipe })
    }

    pub async fn open_policy(&mut self) -> Result<SamrHandle> {
        let resp = self.pipe.call(opnum::OPEN_POLICY2, &encode_open_policy2()).await?;
        let mut d = NdrDecoder::new(&resp);
        SamrHandle::decode(&mut d)
    }

    /// Resolve a name (e.g. "Administrator" or "TESTLAB\\svc_sql") to its SID.
    pub async fn lookup_name(&mut self, policy: &SamrHandle, name: &str) -> Result<Option<Sid>> {
        let resp = self.pipe.call(opnum::LOOKUP_NAMES, &encode_lookup_names(policy, name)).await?;
        decode_lookup_names(&resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_policy2_stub_shape() {
        let stub = encode_open_policy2();
        // SystemName null(4) + ObjectAttributes(24) + DesiredAccess(4) = 32
        assert_eq!(stub.len(), 32);
        assert_eq!(&stub[28..32], &POLICY_MAXIMUM_ALLOWED.to_le_bytes());
    }

    #[test]
    fn lookup_names_marshals_count_and_name() {
        let stub = encode_lookup_names(&SamrHandle([0; 20]), "Administrator");
        assert_eq!(u32::from_le_bytes(stub[20..24].try_into().unwrap()), 1); // Count
    }
}
