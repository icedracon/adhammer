//! SMB2 request bodies and response parsers (MS-SMB2 §2.2). Offsets in the on-wire
//! `*Offset` fields are measured from the start of the SMB2 header (i.e. `64 + body_off`).

use crate::{Result, SmbError};

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
fn u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

// ---- NEGOTIATE (§2.2.3) ---------------------------------------------------

/// Offer dialect 2.1.0 with a random client GUID.
pub fn negotiate(client_guid: &[u8; 16]) -> Vec<u8> {
    // Offer SMB 2.0.2 (Server 2008/R2) and 2.1.0. The server picks the highest it supports and
    // negotiates *down*, so this reaches 2008 through 2025 (2012/2016/2019/2022/2025 all accept
    // 2.1.0 — validated live against Server 2025). Both sign with HMAC-SHA256.
    //
    // SMB 3.0.x (AES-CMAC) support exists in header.rs (sign_v3 / kdf_signing_key) and the
    // client branches on the negotiated dialect, but 3.x is not offered yet — it's only needed
    // for servers hardened to refuse SMB2 entirely, and the CMAC path isn't validated.
    let dialects: [u16; 2] = [0x0202, 0x0210];
    let mut b = Vec::new();
    b.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&(dialects.len() as u16).to_le_bytes()); // DialectCount
    b.extend_from_slice(&0x0001u16.to_le_bytes()); // SecurityMode = SIGNING_ENABLED
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(client_guid);
    b.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime
    for dialect in dialects {
        b.extend_from_slice(&dialect.to_le_bytes());
    }
    b
}

// ---- SESSION_SETUP (§2.2.5 / §2.2.6) --------------------------------------

/// The security buffer holds a raw NTLMSSP token.
pub fn session_setup(token: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
    b.push(0); // Flags
    b.push(0x01); // SecurityMode = SIGNING_ENABLED
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&0u32.to_le_bytes()); // Channel
    let sec_off = 64u16 + 24; // header + fixed part
    b.extend_from_slice(&sec_off.to_le_bytes()); // SecurityBufferOffset
    b.extend_from_slice(&(token.len() as u16).to_le_bytes()); // SecurityBufferLength
    b.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    b.extend_from_slice(token);
    b
}

/// Extract the security buffer (server NTLM token) from a SESSION_SETUP response.
pub fn session_setup_token(msg: &[u8]) -> Result<Vec<u8>> {
    // body starts at 64; StructureSize(2), SessionFlags(2), SecBufOffset(2), SecBufLength(2)
    let body = msg.get(64..).ok_or(SmbError::Truncated)?;
    let off = u16(body, 4) as usize; // from SMB header start
    let len = u16(body, 6) as usize;
    msg.get(off..off + len).map(|s| s.to_vec()).ok_or(SmbError::Truncated)
}

// ---- TREE_CONNECT (§2.2.9) ------------------------------------------------

pub fn tree_connect(path: &str) -> Vec<u8> {
    let name = utf16le(path);
    let mut b = Vec::new();
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved/Flags
    let path_off = 64u16 + 8;
    b.extend_from_slice(&path_off.to_le_bytes()); // PathOffset
    b.extend_from_slice(&(name.len() as u16).to_le_bytes()); // PathLength
    b.extend_from_slice(&name);
    b
}

// ---- CREATE (§2.2.13 / §2.2.14) -------------------------------------------

/// Open a named pipe (e.g. "samr") on the IPC$ tree.
pub fn create_pipe(name: &str) -> Vec<u8> {
    let n = utf16le(name);
    let mut b = Vec::new();
    b.extend_from_slice(&57u16.to_le_bytes()); // StructureSize
    b.push(0); // SecurityFlags
    b.push(0); // RequestedOplockLevel
    b.extend_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel = Impersonation
    b.extend_from_slice(&0u64.to_le_bytes()); // SmbCreateFlags
    b.extend_from_slice(&0u64.to_le_bytes()); // Reserved
    b.extend_from_slice(&0x0012_0089u32.to_le_bytes()); // DesiredAccess (read+write pipe)
    b.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
    b.extend_from_slice(&0x0000_0007u32.to_le_bytes()); // ShareAccess = R|W|D
    b.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // CreateDisposition = OPEN
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateOptions
    let name_off = 64u16 + 56;
    b.extend_from_slice(&name_off.to_le_bytes()); // NameOffset
    b.extend_from_slice(&(n.len() as u16).to_le_bytes()); // NameLength
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
    b.extend_from_slice(&n);
    b
}

/// FileId (16 bytes) from a CREATE response.
pub fn create_file_id(msg: &[u8]) -> Result<[u8; 16]> {
    // FileId sits at body offset 64 → absolute 128.
    msg.get(128..144).map(|s| s.try_into().unwrap()).ok_or(SmbError::Truncated)
}

// ---- IOCTL (§2.2.31 / §2.2.32) --------------------------------------------

pub const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;

/// Send `input` through the pipe and read the response in one round trip.
pub fn ioctl_transceive(file_id: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&57u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&FSCTL_PIPE_TRANSCEIVE.to_le_bytes()); // CtlCode
    b.extend_from_slice(file_id);
    let input_off = 64u32 + 56;
    b.extend_from_slice(&input_off.to_le_bytes()); // InputOffset
    b.extend_from_slice(&(input.len() as u32).to_le_bytes()); // InputCount
    b.extend_from_slice(&0u32.to_le_bytes()); // MaxInputResponse
    b.extend_from_slice(&input_off.to_le_bytes()); // OutputOffset
    b.extend_from_slice(&0u32.to_le_bytes()); // OutputCount
    b.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // MaxOutputResponse (64 KiB — SMB2.1 max transact)
    b.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // Flags = IS_FSCTL
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    b.extend_from_slice(input);
    b
}

/// Extract the pipe output (RPC response bytes) from an IOCTL response.
pub fn ioctl_output(msg: &[u8]) -> Result<Vec<u8>> {
    // response body: StructureSize(2) Reserved(2) CtlCode(4) FileId(16)
    // InputOffset(4) InputCount(4) OutputOffset(4) OutputCount(4) ...
    let body = msg.get(64..).ok_or(SmbError::Truncated)?;
    let out_off = u32(body, 32) as usize; // from SMB header start
    let out_len = u32(body, 36) as usize;
    msg.get(out_off..out_off + out_len).map(|s| s.to_vec()).ok_or(SmbError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_offers_dialect_210() {
        let b = negotiate(&[0; 16]);
        assert_eq!(u16(&b, 0), 36); // StructureSize
        assert_eq!(u16(&b, 2), 2); // DialectCount (2.0.2 + 2.1.0)
        // dialects at 36 (fixed part) — after 4+2+2+4+16+8 = 36
        assert_eq!(u16(&b, 36), 0x0202);
        assert_eq!(u16(&b, 38), 0x0210);
    }

    #[test]
    fn create_pipe_name_offset_correct() {
        let b = create_pipe("samr");
        assert_eq!(u16(&b, 0), 57);
        assert_eq!(u16(&b, 44), 64 + 56); // NameOffset field
        assert_eq!(u16(&b, 46), 8); // "samr" = 4 wchar * 2
    }

    #[test]
    fn ioctl_uses_transceive_ctlcode() {
        let b = ioctl_transceive(&[0; 16], &[1, 2, 3]);
        assert_eq!(u32(&b, 4), FSCTL_PIPE_TRANSCEIVE);
        assert_eq!(u32(&b, 28), 3); // InputCount
    }
}
