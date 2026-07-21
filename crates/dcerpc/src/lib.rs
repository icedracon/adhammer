//! A minimal DCE/RPC (MS-RPCE) stack in Rust — the impacket `dcerpc.v5` equivalent.
//!
//! Layers, bottom-up:
//!   `ndr`       — NDR (Network Data Representation) transfer-syntax marshaling.
//!   `pdu`       — connection-oriented RPC PDUs (bind / bind_ack / request / response / fault).
//!   `transport` — ncacn_ip_tcp (RPC directly over TCP).
//!   `epm`       — endpoint mapper (ept_map): interface UUID → dynamic port.
//!   `samr`      — the SAMR interface (UUID/opnums/structs); rides a named-pipe transport.
//!
//! Interface UUIDs are parsed from their canonical strings via `adhammer_core::sid::Guid`,
//! whose byte layout already matches the DCE UUID on-wire encoding.

pub mod ndr;
pub mod pdu;
pub mod transport;
pub mod epm;
pub mod samr;
pub mod lsat;
pub mod efsr;
pub mod rprn;
pub mod drsuapi;

use adhammer_core::sid::Guid;

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("buffer underrun: need {need} at {pos}")]
    Underrun { need: usize, pos: usize },
    #[error("unexpected PDU type {0:#04x}")]
    UnexpectedPdu(u8),
    #[error("RPC fault, status {0:#010x}")]
    Fault(u32),
    #[error("bind rejected")]
    BindRejected,
    #[error("protocol: {0}")]
    Protocol(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RpcError>;

/// A DCE/RPC abstract syntax: interface UUID + version.
#[derive(Clone, Copy, Debug)]
pub struct Syntax {
    pub uuid: [u8; 16],
    pub ver_major: u16,
    pub ver_minor: u16,
}

impl Syntax {
    /// Build from the canonical UUID string, e.g. "12345778-1234-abcd-ef00-0123456789ac".
    pub fn new(uuid: &str, ver_major: u16, ver_minor: u16) -> Self {
        Syntax { uuid: Guid::parse(uuid).expect("valid interface UUID").0, ver_major, ver_minor }
    }
}

/// The NDR transfer syntax (v2.0) every bind offers.
pub fn ndr_transfer_syntax() -> Syntax {
    Syntax::new("8a885d04-1ceb-11c9-9fe8-08002b104860", 2, 0)
}
