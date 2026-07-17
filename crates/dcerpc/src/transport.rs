//! ncacn_ip_tcp — connection-oriented RPC directly over TCP. Drives one bound interface:
//! bind once, then issue requests and read the (single-fragment) responses.

use crate::{pdu, Result, RpcError, Syntax};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct RpcTcp {
    stream: TcpStream,
    call_id: u32,
}

impl RpcTcp {
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(RpcTcp { stream, call_id: 1 })
    }

    async fn send(&mut self, buf: &[u8]) -> Result<()> {
        self.stream.write_all(buf).await?;
        Ok(())
    }

    /// Read exactly one PDU (16-byte header, then `frag_length - 16` more bytes).
    async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut head = [0u8; 16];
        self.stream.read_exact(&mut head).await?;
        let frag = u16::from_le_bytes([head[8], head[9]]) as usize;
        if frag < 16 {
            return Err(RpcError::Protocol(format!("frag_length {frag} < 16")));
        }
        let mut rest = vec![0u8; frag - 16];
        self.stream.read_exact(&mut rest).await?;
        let mut pdu = head.to_vec();
        pdu.append(&mut rest);
        Ok(pdu)
    }

    /// Bind the given abstract syntax (interface) over this connection.
    pub async fn bind(&mut self, syntax: Syntax) -> Result<()> {
        let bind = pdu::build_bind(self.call_id, syntax);
        self.call_id += 1;
        self.send(&bind).await?;
        let resp = self.recv().await?;
        pdu::expect_bind_ack(&resp)
    }

    /// Issue one request for `opnum` with an NDR stub; return the response stub bytes.
    pub async fn call(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        let req = pdu::build_request(self.call_id, 0, opnum, stub);
        self.call_id += 1;
        self.send(&req).await?;
        let resp = self.recv().await?;
        pdu::parse_response(&resp)
    }
}

/// DCE/RPC over an SMB2 named pipe: each bind/request is one FSCTL_PIPE_TRANSCEIVE.
/// Borrows an authenticated, tree-connected `SmbClient` and an open pipe FileId.
pub struct SmbPipe<'a> {
    client: &'a mut adhammer_smb::SmbClient,
    file_id: [u8; 16],
    call_id: u32,
}

impl<'a> SmbPipe<'a> {
    pub fn new(client: &'a mut adhammer_smb::SmbClient, file_id: [u8; 16]) -> Self {
        SmbPipe { client, file_id, call_id: 1 }
    }

    async fn transact(&mut self, pdu_bytes: &[u8]) -> Result<Vec<u8>> {
        self.client
            .transact(&self.file_id, pdu_bytes)
            .await
            .map_err(|e| RpcError::Protocol(format!("smb transact: {e}")))
    }

    pub async fn bind(&mut self, syntax: Syntax) -> Result<()> {
        let bind = pdu::build_bind(self.call_id, syntax);
        self.call_id += 1;
        let resp = self.transact(&bind).await?;
        pdu::expect_bind_ack(&resp)
    }

    pub async fn call(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        let req = pdu::build_request(self.call_id, 0, opnum, stub);
        self.call_id += 1;
        let resp = self.transact(&req).await?;
        pdu::parse_response(&resp)
    }
}
