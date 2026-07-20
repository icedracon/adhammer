//! ncacn_ip_tcp — connection-oriented RPC directly over TCP. Drives one bound interface:
//! bind once, then issue requests and read the (single-fragment) responses.

use crate::{pdu, Result, RpcError, Syntax};
use adhammer_ntlm::{Ntlm, SealState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct RpcTcp {
    stream: TcpStream,
    call_id: u32,
    seal: Option<SealState>,
}

impl RpcTcp {
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(RpcTcp { stream, call_id: 1, seal: None })
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

    /// Authenticated bind with NTLMSSP sign+seal (auth_level PKT_PRIVACY). Runs the three-leg
    /// handshake (BIND → BIND_ACK/CHALLENGE → AUTH3) and arms the [`SealState`] so subsequent
    /// [`call_sealed`](Self::call_sealed) requests are encrypted. Required for DRSUAPI, which a
    /// DC refuses to answer on an unsealed channel.
    pub async fn bind_sealed(
        &mut self,
        syntax: Syntax,
        domain: &str,
        user: &str,
        password: &str,
        workstation: &str,
    ) -> Result<()> {
        let ntlm = Ntlm::new_sealed();
        let bind = pdu::build_bind_auth(self.call_id, syntax, ntlm.negotiate());
        self.call_id += 1;
        self.send(&bind).await?;
        let ack = self.recv().await?;
        pdu::expect_bind_ack(&ack)?;
        let challenge = pdu::extract_auth_value(&ack)?;
        let (type3, exported) = ntlm
            .authenticate(&challenge, domain, user, password, workstation)
            .map_err(|e| RpcError::Protocol(format!("ntlm authenticate: {e}")))?;
        let auth3 = pdu::build_auth3(self.call_id, &type3);
        self.call_id += 1;
        self.send(&auth3).await?; // AUTH3 is unacknowledged
        self.seal = Some(SealState::new(&exported));
        Ok(())
    }

    /// Issue a sign+sealed request over an authenticated ([`bind_sealed`](Self::bind_sealed))
    /// session; the stub is RC4-sealed and the response is verified and decrypted.
    pub async fn call_sealed(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        let seal = self.seal.as_mut().ok_or_else(|| RpcError::Protocol("session not sealed".into()))?;
        // Pad the stub so the sec_trailer is 4-byte aligned (MS-RPCE §2.2.2.11).
        let pad_len = ((4 - (stub.len() % 4)) % 4) as u8;
        let mut plain = stub.to_vec();
        plain.extend(std::iter::repeat(0u8).take(pad_len as usize));
        let (sealed, signature) = seal.seal(&plain);
        let req = pdu::build_request_sealed(self.call_id, 0, opnum, &sealed, pad_len, &signature, stub.len() as u32);
        self.call_id += 1;
        self.send(&req).await?;
        let resp = self.recv().await?;
        let (sealed_resp, signature, resp_pad) = pdu::split_sealed_response(&resp)?;
        let seal = self.seal.as_mut().unwrap();
        let mut plain = seal
            .unseal(&sealed_resp, &signature)
            .map_err(|e| RpcError::Protocol(format!("unseal response: {e}")))?;
        plain.truncate(plain.len().saturating_sub(resp_pad as usize));
        Ok(plain)
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
