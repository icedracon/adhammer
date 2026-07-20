//! Endpoint Mapper (MS-RPCE §2.2.1.2 / C706 EPM) — resolves an interface UUID to the
//! dynamic TCP port a service listens on. Reachable on TCP/135 without authentication, so
//! it is the first end-to-end exercise of the whole stack: bind + NDR + request/response.
//!
//! `ept_map` (opnum 3) exchanges "protocol towers": a tower describes a full protocol
//! stack (interface, NDR, RPC-CO, TCP, IP). We send a tower with port 0 for the target
//! interface and read the returned tower's port.

use crate::ndr::{NdrDecoder, NdrEncoder};
use crate::transport::RpcTcp;
use crate::{ndr_transfer_syntax, Result, RpcError, Syntax};

pub const EPM_OPNUM_MAP: u16 = 3;

/// The Endpoint Mapper interface (v3.0).
pub fn epm_syntax() -> Syntax {
    Syntax::new("e1af8308-5d1f-11c9-91a4-08002b14a0fa", 3, 0)
}

// Tower floor protocol identifiers (C706).
const PROT_UUID: u8 = 0x0D; // UUID-derived (interface / transfer syntax)
const PROT_RPC_CO: u8 = 0x0B; // connection-oriented RPC
const PROT_TCP: u8 = 0x07;
const PROT_IP: u8 = 0x09;

fn floor(t: &mut Vec<u8>, lhs: &[u8], rhs: &[u8]) {
    t.extend_from_slice(&(lhs.len() as u16).to_le_bytes());
    t.extend_from_slice(lhs);
    t.extend_from_slice(&(rhs.len() as u16).to_le_bytes());
    t.extend_from_slice(rhs);
}

/// Build a 5-floor tower for `target`, advertising the given TCP `port` (0 in a request).
pub fn build_tower_with_port(target: Syntax, port: u16) -> Vec<u8> {
    let ndr = ndr_transfer_syntax();
    let mut t = Vec::new();
    t.extend_from_slice(&5u16.to_le_bytes()); // number of floors

    // Floor 1: interface UUID + version.
    let mut lhs = vec![PROT_UUID];
    lhs.extend_from_slice(&target.uuid);
    lhs.extend_from_slice(&target.ver_major.to_le_bytes());
    floor(&mut t, &lhs, &target.ver_minor.to_le_bytes());

    // Floor 2: NDR transfer syntax.
    let mut lhs = vec![PROT_UUID];
    lhs.extend_from_slice(&ndr.uuid);
    lhs.extend_from_slice(&ndr.ver_major.to_le_bytes());
    floor(&mut t, &lhs, &ndr.ver_minor.to_le_bytes());

    // Floor 3: RPC connection-oriented.
    floor(&mut t, &[PROT_RPC_CO], &0u16.to_le_bytes());
    // Floor 4: TCP port (big-endian).
    floor(&mut t, &[PROT_TCP], &port.to_be_bytes());
    // Floor 5: IP host (big-endian, 0.0.0.0).
    floor(&mut t, &[PROT_IP], &0u32.to_be_bytes());
    t
}

/// Tower for an `ept_map` request (port 0 = "tell me the port").
pub fn build_tower(target: Syntax) -> Vec<u8> {
    build_tower_with_port(target, 0)
}

/// Extract the TCP port from a tower's floor 4.
pub fn parse_tower_port(tower: &[u8]) -> Option<u16> {
    if tower.len() < 2 {
        return None;
    }
    let floors = u16::from_le_bytes([tower[0], tower[1]]);
    let mut p = 2usize;
    for _ in 0..floors {
        let lhs_len = u16::from_le_bytes([*tower.get(p)?, *tower.get(p + 1)?]) as usize;
        p += 2;
        let lhs = tower.get(p..p + lhs_len)?;
        p += lhs_len;
        let rhs_len = u16::from_le_bytes([*tower.get(p)?, *tower.get(p + 1)?]) as usize;
        p += 2;
        let rhs = tower.get(p..p + rhs_len)?;
        p += rhs_len;
        if lhs.first() == Some(&PROT_TCP) && rhs.len() >= 2 {
            return Some(u16::from_be_bytes([rhs[0], rhs[1]]));
        }
    }
    None
}

/// Marshal an `ept_map` request for `target`.
pub fn encode_map(target: Syntax) -> Vec<u8> {
    let tower = build_tower(target);
    let mut e = NdrEncoder::new();
    e.null_ptr(); // obj: NULL unique pointer
    e.referent(); // map_tower: non-null unique pointer
    // twr_t: conformant array size is hoisted to the front of the struct.
    e.u32(tower.len() as u32); // max_count
    e.u32(tower.len() as u32); // tower_length
    e.bytes(&tower);
    while e.len() % 4 != 0 {
        e.u8(0); // pad the conformant byte array to 4
    }
    e.bytes(&[0u8; 20]); // entry_handle (context handle, zeroed on first call)
    e.u32(1); // max_towers
    e.into_bytes()
}

/// Parse an `ept_map` response and return the first mapped TCP port.
pub fn decode_map_response(stub: &[u8]) -> Result<u16> {
    let mut d = NdrDecoder::new(stub);
    let _entry_handle = d.read_bytes(20)?;
    let num_towers = d.u32()?;
    if num_towers == 0 {
        return Err(RpcError::Protocol("EPM returned no towers".into()));
    }
    // ITowers conformant-varying array of tower pointers: max_count, offset, actual_count,
    // then one referent id per tower (the array data begins directly, with no wrapping ptr).
    let _max = d.u32()?;
    let _offset = d.u32()?;
    let actual = d.u32()?;
    for _ in 0..actual {
        let _ref = d.u32()?; // per-tower referent id
    }
    // First tower (twr_t): conformant max_count, then tower_length, then the octet string.
    let _mc = d.u32()?;
    let tower_len = d.u32()? as usize;
    let tower = d.read_bytes(tower_len)?;
    parse_tower_port(tower).ok_or(RpcError::Protocol("no TCP floor in tower".into()))
}

/// End-to-end: bind EPM over TCP/135 and resolve `target`'s dynamic port.
pub async fn resolve_port(host: &str, target: Syntax) -> Result<u16> {
    let mut rpc = RpcTcp::connect(&format!("{host}:135")).await?;
    rpc.bind(epm_syntax()).await?;
    let resp = rpc.call(EPM_OPNUM_MAP, &encode_map(target)).await?;
    decode_map_response(&resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samr() -> Syntax {
        Syntax::new("12345778-1234-abcd-ef00-0123456789ac", 1, 0)
    }

    #[test]
    fn tower_has_five_floors_and_zero_port() {
        let t = build_tower(samr());
        assert_eq!(u16::from_le_bytes([t[0], t[1]]), 5);
        assert_eq!(parse_tower_port(&t), Some(0));
    }

    #[test]
    fn port_roundtrips_through_tower() {
        let t = build_tower_with_port(samr(), 49155);
        assert_eq!(parse_tower_port(&t), Some(49155));
    }

    #[test]
    fn decode_map_response_extracts_port() {
        let tower = build_tower_with_port(samr(), 49664);
        let mut s = Vec::new();
        s.extend_from_slice(&[0u8; 20]); // entry_handle
        s.extend_from_slice(&1u32.to_le_bytes()); // num_towers
        s.extend_from_slice(&1u32.to_le_bytes()); // ITowers max_count (array data, no wrapping ptr)
        s.extend_from_slice(&0u32.to_le_bytes()); // offset
        s.extend_from_slice(&1u32.to_le_bytes()); // actual_count
        s.extend_from_slice(&0x0002_0004u32.to_le_bytes()); // tower referent
        s.extend_from_slice(&(tower.len() as u32).to_le_bytes()); // conformant max_count
        s.extend_from_slice(&(tower.len() as u32).to_le_bytes()); // tower_length
        s.extend_from_slice(&tower);
        s.extend_from_slice(&0u32.to_le_bytes()); // status

        assert_eq!(decode_map_response(&s).unwrap(), 49664);
    }
}
