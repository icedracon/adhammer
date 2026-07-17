//! SMB2 sync header (MS-SMB2 §2.2.1.2) — fixed 64 bytes, little-endian.

use crate::{Result, SmbError};

pub mod cmd {
    pub const NEGOTIATE: u16 = 0x0000;
    pub const SESSION_SETUP: u16 = 0x0001;
    pub const TREE_CONNECT: u16 = 0x0003;
    pub const CREATE: u16 = 0x0005;
    pub const CLOSE: u16 = 0x0006;
    pub const IOCTL: u16 = 0x000B;
}

pub const FLAGS_SIGNED: u32 = 0x0000_0008;
const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// Build a 64-byte sync header with the signature field zeroed.
#[allow(clippy::too_many_arguments)]
pub fn build(command: u16, message_id: u64, session_id: u64, tree_id: u32, signed: bool) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[0..4].copy_from_slice(&PROTOCOL_ID);
    h[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
    h[6..8].copy_from_slice(&1u16.to_le_bytes()); // CreditCharge
    // 8..12 Status/ChannelSequence = 0
    h[12..14].copy_from_slice(&command.to_le_bytes());
    h[14..16].copy_from_slice(&1u16.to_le_bytes()); // CreditRequest
    let flags = if signed { FLAGS_SIGNED } else { 0 };
    h[16..20].copy_from_slice(&flags.to_le_bytes());
    // 20..24 NextCommand = 0
    h[24..32].copy_from_slice(&message_id.to_le_bytes());
    // 32..36 Reserved (ProcessId)
    h[36..40].copy_from_slice(&tree_id.to_le_bytes());
    h[40..48].copy_from_slice(&session_id.to_le_bytes());
    // 48..64 Signature = 0
    h
}

/// Parsed fields we consume from a response header.
#[derive(Clone, Copy, Debug)]
pub struct Parsed {
    pub command: u16,
    pub status: u32,
    pub session_id: u64,
    pub tree_id: u32,
}

pub fn parse(buf: &[u8]) -> Result<Parsed> {
    if buf.len() < 64 {
        return Err(SmbError::Truncated);
    }
    if buf[0..4] != PROTOCOL_ID {
        return Err(SmbError::BadProtocol);
    }
    Ok(Parsed {
        status: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        command: u16::from_le_bytes(buf[12..14].try_into().unwrap()),
        tree_id: u32::from_le_bytes(buf[36..40].try_into().unwrap()),
        session_id: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
    })
}

/// SMB 2.x signing: HMAC-SHA256(session_key, message-with-zeroed-sig-and-SIGNED-flag),
/// truncated to 16 bytes, written back into the Signature field.
pub fn sign(message: &mut [u8], key: &[u8; 16]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    for b in &mut message[48..64] {
        *b = 0;
    }
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("hmac key");
    mac.update(message);
    let sig = mac.finalize().into_bytes();
    message[48..64].copy_from_slice(&sig[..16]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_64_bytes_and_parses() {
        let h = build(cmd::NEGOTIATE, 3, 0xAABB, 0x11, true);
        assert_eq!(h.len(), 64);
        let p = parse(&h).unwrap();
        assert_eq!(p.command, cmd::NEGOTIATE);
        assert_eq!(p.session_id, 0xAABB);
        assert_eq!(p.tree_id, 0x11);
        assert_eq!(u32::from_le_bytes(h[16..20].try_into().unwrap()), FLAGS_SIGNED);
    }
}
