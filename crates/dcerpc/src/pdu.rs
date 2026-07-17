//! Connection-oriented DCE/RPC PDUs (MS-RPCE §2.2.6, DCE 1.1 §12.6). Little-endian DREP.

use crate::{ndr_transfer_syntax, Result, RpcError, Syntax};

pub mod ptype {
    pub const REQUEST: u8 = 0;
    pub const RESPONSE: u8 = 2;
    pub const FAULT: u8 = 3;
    pub const BIND: u8 = 11;
    pub const BIND_ACK: u8 = 12;
    pub const BIND_NAK: u8 = 13;
}

const PFC_FIRST_FRAG: u8 = 0x01;
const PFC_LAST_FRAG: u8 = 0x02;
const DREP_LE: [u8; 4] = [0x10, 0x00, 0x00, 0x00]; // little-endian, ASCII, IEEE float

/// 16-byte common header with `frag_length` patched in after the body is known.
fn header(ptype: u8, frag_length: u16, call_id: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(16);
    h.push(5); // rpc_vers
    h.push(0); // rpc_vers_minor
    h.push(ptype);
    h.push(PFC_FIRST_FRAG | PFC_LAST_FRAG);
    h.extend_from_slice(&DREP_LE);
    h.extend_from_slice(&frag_length.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    h.extend_from_slice(&call_id.to_le_bytes());
    h
}

/// Build a BIND PDU offering one presentation context (abstract syntax + NDR transfer).
pub fn build_bind(call_id: u32, abstract_syntax: Syntax) -> Vec<u8> {
    let ndr = ndr_transfer_syntax();
    let mut body = Vec::new();
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
    // p_cont_list
    body.push(1); // n_context_elem
    body.push(0); // reserved
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    // context element 0
    body.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    body.push(1); // n_transfer_syn
    body.push(0); // reserved
    // abstract syntax
    body.extend_from_slice(&abstract_syntax.uuid);
    body.extend_from_slice(&abstract_syntax.ver_major.to_le_bytes());
    body.extend_from_slice(&abstract_syntax.ver_minor.to_le_bytes());
    // transfer syntax (NDR)
    body.extend_from_slice(&ndr.uuid);
    body.extend_from_slice(&ndr.ver_major.to_le_bytes());
    body.extend_from_slice(&ndr.ver_minor.to_le_bytes());

    let frag_length = (16 + body.len()) as u16;
    let mut pdu = header(ptype::BIND, frag_length, call_id);
    pdu.extend_from_slice(&body);
    pdu
}

/// Build a REQUEST PDU carrying an NDR-marshaled stub for `opnum`.
pub fn build_request(call_id: u32, p_cont_id: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + stub.len());
    body.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
    body.extend_from_slice(&p_cont_id.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(stub);

    let frag_length = (16 + body.len()) as u16;
    let mut pdu = header(ptype::REQUEST, frag_length, call_id);
    pdu.extend_from_slice(&body);
    pdu
}

/// Parsed common header.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub ptype: u8,
    pub frag_length: u16,
    pub call_id: u32,
}

pub fn parse_header(buf: &[u8]) -> Result<Header> {
    if buf.len() < 16 {
        return Err(RpcError::Underrun { need: 16, pos: 0 });
    }
    if buf[0] != 5 {
        return Err(RpcError::Protocol(format!("rpc_vers {} != 5", buf[0])));
    }
    Ok(Header {
        ptype: buf[2],
        frag_length: u16::from_le_bytes([buf[8], buf[9]]),
        call_id: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
    })
}

/// Confirm a BIND_ACK (or surface a BIND_NAK). We do not parse per-context results here;
/// a NAK is fatal and an ACK is sufficient to proceed.
pub fn expect_bind_ack(buf: &[u8]) -> Result<()> {
    let h = parse_header(buf)?;
    match h.ptype {
        ptype::BIND_ACK => Ok(()),
        ptype::BIND_NAK => Err(RpcError::BindRejected),
        other => Err(RpcError::UnexpectedPdu(other)),
    }
}

/// Extract the stub data from a RESPONSE PDU, or translate a FAULT into an error.
/// Response layout: 16-byte header + alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1).
pub fn parse_response(buf: &[u8]) -> Result<Vec<u8>> {
    let h = parse_header(buf)?;
    match h.ptype {
        ptype::RESPONSE => {
            let start = 24.min(buf.len());
            let end = (h.frag_length as usize).min(buf.len());
            Ok(buf[start..end].to_vec())
        }
        ptype::FAULT => {
            // fault: header + alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1) + status(4)
            let status = buf
                .get(24..28)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            Err(RpcError::Fault(status))
        }
        other => Err(RpcError::UnexpectedPdu(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_header_shape() {
        let samr = Syntax::new("12345778-1234-abcd-ef00-0123456789ac", 1, 0);
        let pdu = build_bind(1, samr);
        assert_eq!(pdu[0], 5); // rpc_vers
        assert_eq!(pdu[2], ptype::BIND);
        assert_eq!(pdu[3], PFC_FIRST_FRAG | PFC_LAST_FRAG);
        let frag = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
        assert_eq!(frag, pdu.len());
        let h = parse_header(&pdu).unwrap();
        assert_eq!(h.ptype, ptype::BIND);
        assert_eq!(h.call_id, 1);
    }

    #[test]
    fn request_carries_opnum_and_stub() {
        let stub = [0xDE, 0xAD, 0xBE, 0xEF];
        let pdu = build_request(7, 0, 0x0005, &stub);
        assert_eq!(pdu[2], ptype::REQUEST);
        // opnum sits at header(16) + alloc_hint(4) + p_cont_id(2) = offset 22
        assert_eq!(u16::from_le_bytes([pdu[22], pdu[23]]), 0x0005);
        assert_eq!(&pdu[24..28], &stub);
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
    }

    #[test]
    fn parse_response_extracts_stub() {
        // Fake a RESPONSE: 24-byte prefix then stub.
        let mut pdu = build_request(1, 0, 0, &[]); // reuse header shape
        pdu[2] = ptype::RESPONSE;
        pdu.truncate(16);
        pdu.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // alloc_hint+cont+cancel+reserved
        pdu.extend_from_slice(&[0x11, 0x22]); // stub
        let frag = pdu.len() as u16;
        pdu[8..10].copy_from_slice(&frag.to_le_bytes());
        assert_eq!(parse_response(&pdu).unwrap(), vec![0x11, 0x22]);
    }
}
