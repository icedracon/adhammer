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
    session_key: Option<[u8; 16]>,
}

impl RpcTcp {
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(RpcTcp {
            stream,
            call_id: 1,
            seal: None,
            session_key: None,
        })
    }

    /// The negotiated NTLM exported session key — the base key for DRSUAPI secret decryption.
    pub fn session_key(&self) -> Option<[u8; 16]> {
        self.session_key
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
        // The BIND and its AUTH3 completion share one call_id (they are one negotiation).
        let bind_call_id = self.call_id;
        self.call_id += 1;
        let bind = pdu::build_bind_auth(bind_call_id, syntax, ntlm.negotiate());
        self.send(&bind).await?;
        let ack = self.recv().await?;
        pdu::expect_bind_ack(&ack)?;
        let challenge = pdu::extract_auth_value(&ack)?;
        let (type3, exported) = ntlm
            .authenticate(&challenge, domain, user, password, workstation)
            .map_err(|e| RpcError::Protocol(format!("ntlm authenticate: {e}")))?;
        let auth3 = pdu::build_auth3(bind_call_id, &type3);
        self.send(&auth3).await?; // AUTH3 is unacknowledged
        self.session_key = Some(exported);
        self.seal = Some(SealState::new(&exported));
        Ok(())
    }

    /// Issue a sign+sealed request over an authenticated ([`bind_sealed`](Self::bind_sealed))
    /// session. The MAC covers the whole PDU minus the trailing 16-byte signature (over the
    /// plaintext stub); only the stub is encrypted. The response is verified and decrypted.
    pub async fn call_sealed(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        const STUB_OFF: usize = 24; // header(16) + alloc_hint(4) + cont_id(2) + opnum(2)
        let pad_len = ((4 - (stub.len() % 4)) % 4) as u8;
        let mut stub_padded = stub.to_vec();
        stub_padded.extend(std::iter::repeat(0u8).take(pad_len as usize));

        // Assemble the PDU with a plaintext stub and a zeroed signature, then MAC the whole
        // thing (minus the signature) and encrypt the stub in place.
        let mut req = pdu::build_request_sealed(
            self.call_id,
            0,
            opnum,
            &stub_padded,
            pad_len,
            &[0u8; 16],
            stub.len() as u32,
        );
        self.call_id += 1;
        let n = req.len();
        let sign_over = req[..n - 16].to_vec();
        let seal = self
            .seal
            .as_mut()
            .ok_or_else(|| RpcError::Protocol("session not sealed".into()))?;
        let (sealed, signature) = seal.seal_pdu(&sign_over, &stub_padded);
        req[STUB_OFF..STUB_OFF + stub_padded.len()].copy_from_slice(&sealed);
        req[n - 16..].copy_from_slice(&signature);
        self.send(&req).await?;

        // A large object (e.g. DCSync of a DC/computer) spans multiple sealed RESPONSE fragments.
        // Each fragment is independently RC4-sealed and HMAC-signed with the incrementing receive
        // sequence; the RC4 keystream is continuous, so unseal each in order and concatenate the
        // plaintext stubs until PFC_LAST_FRAG.
        const PFC_LAST_FRAG: u8 = 0x02;
        let mut plain = Vec::new();
        loop {
            let resp = self.recv().await?;
            let h = pdu::parse_header(&resp)?;
            if h.ptype == pdu::ptype::FAULT {
                let status = resp
                    .get(24..28)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                return Err(RpcError::Fault(status));
            }
            if h.ptype != pdu::ptype::RESPONSE {
                return Err(RpcError::UnexpectedPdu(h.ptype));
            }
            let pfc = resp[3];
            let auth_length = u16::from_le_bytes([resp[10], resp[11]]) as usize;
            let frag = (h.frag_length as usize).min(resp.len());
            let sec_trailer_start = frag - 8 - auth_length;
            let resp_pad = resp[sec_trailer_start + 2] as usize;
            let sig = resp[frag - auth_length..frag].to_vec();
            let pdu_no_sig = &resp[..frag - auth_length];
            let seal = self.seal.as_mut().unwrap();
            let mut chunk = seal
                .unseal_pdu(pdu_no_sig, STUB_OFF, sec_trailer_start - STUB_OFF, &sig)
                .map_err(|e| RpcError::Protocol(format!("unseal response: {e}")))?;
            chunk.truncate(chunk.len().saturating_sub(resp_pad));
            plain.extend_from_slice(&chunk);
            if pfc & PFC_LAST_FRAG != 0 {
                break;
            }
        }
        Ok(plain)
    }
}

/// DCE/RPC over an SMB2 named pipe: each bind/request is one FSCTL_PIPE_TRANSCEIVE.
/// Borrows an authenticated, tree-connected `SmbClient` and an open pipe FileId.
pub struct SmbPipe<'a> {
    client: &'a mut adhammer_smb::SmbClient,
    file_id: [u8; 16],
    call_id: u32,
    seal: Option<SealState>,
}

impl<'a> SmbPipe<'a> {
    pub fn new(client: &'a mut adhammer_smb::SmbClient, file_id: [u8; 16]) -> Self {
        SmbPipe {
            client,
            file_id,
            call_id: 1,
            seal: None,
        }
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

    /// Bind with NTLMSSP sign+seal (RPC packet privacy) over the pipe — required by interfaces
    /// that reject plaintext RPC (Task Scheduler, the CA's ICertPassage, …). The BIND rides a
    /// transceive; the unacknowledged AUTH3 is a fire-and-forget pipe WRITE.
    pub async fn bind_sealed(
        &mut self,
        syntax: Syntax,
        domain: &str,
        user: &str,
        password: &str,
        workstation: &str,
    ) -> Result<()> {
        let ntlm = Ntlm::new_sealed();
        let bind_call_id = self.call_id;
        self.call_id += 1;
        let bind = pdu::build_bind_auth(bind_call_id, syntax, ntlm.negotiate());
        let ack = self.transact(&bind).await?;
        pdu::expect_bind_ack(&ack)?;
        let challenge = pdu::extract_auth_value(&ack)?;
        let (type3, exported) = ntlm
            .authenticate(&challenge, domain, user, password, workstation)
            .map_err(|e| RpcError::Protocol(format!("ntlm authenticate: {e}")))?;
        let auth3 = pdu::build_auth3(bind_call_id, &type3);
        self.client
            .write_pipe(&self.file_id, &auth3)
            .await
            .map_err(|e| RpcError::Protocol(format!("auth3 write: {e}")))?;
        self.seal = Some(SealState::new(&exported));
        Ok(())
    }

    /// Sign+sealed request over the pipe (single-fragment response — adequate for the small
    /// replies these interfaces return). Mirrors [`RpcTcp::call_sealed`].
    pub async fn call_sealed(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        const STUB_OFF: usize = 24;
        let pad_len = ((4 - (stub.len() % 4)) % 4) as u8;
        let mut stub_padded = stub.to_vec();
        stub_padded.extend(std::iter::repeat(0u8).take(pad_len as usize));
        let mut req = pdu::build_request_sealed(
            self.call_id,
            0,
            opnum,
            &stub_padded,
            pad_len,
            &[0u8; 16],
            stub.len() as u32,
        );
        self.call_id += 1;
        let n = req.len();
        let sign_over = req[..n - 16].to_vec();
        let seal = self
            .seal
            .as_mut()
            .ok_or_else(|| RpcError::Protocol("pipe not sealed".into()))?;
        let (sealed, signature) = seal.seal_pdu(&sign_over, &stub_padded);
        req[STUB_OFF..STUB_OFF + stub_padded.len()].copy_from_slice(&sealed);
        req[n - 16..].copy_from_slice(&signature);
        // A large reply (e.g. an issued certificate) spans several sealed RESPONSE fragments.
        // The first arrives in the transceive output; the rest must be drained from the pipe
        // with SMB READs. Unseal each fragment exactly once (the receive keystream + sequence
        // advance per fragment) as it becomes complete, until PFC_LAST_FRAG.
        const PFC_LAST_FRAG: u8 = 0x02;
        let mut raw = self.transact(&req).await?;
        let mut plain = Vec::new();
        let mut off = 0usize;
        loop {
            let mut hit_last = false;
            while off + 16 <= raw.len() {
                let h = pdu::parse_header(&raw[off..])?;
                if h.ptype == pdu::ptype::FAULT {
                    let status = raw
                        .get(off + 24..off + 28)
                        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                        .unwrap_or(0);
                    return Err(RpcError::Fault(status));
                }
                if h.ptype != pdu::ptype::RESPONSE {
                    return Err(RpcError::UnexpectedPdu(h.ptype));
                }
                let frag = h.frag_length as usize;
                if frag < 24 || off + frag > raw.len() {
                    break; // fragment not fully received yet
                }
                let pdu = &raw[off..off + frag];
                let pfc = pdu[3];
                let auth_length = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
                let sec_trailer_start = frag - 8 - auth_length;
                let resp_pad = pdu[sec_trailer_start + 2] as usize;
                let sig = pdu[frag - auth_length..frag].to_vec();
                let pdu_no_sig = &pdu[..frag - auth_length];
                let seal = self.seal.as_mut().unwrap();
                let mut chunk = seal
                    .unseal_pdu(pdu_no_sig, STUB_OFF, sec_trailer_start - STUB_OFF, &sig)
                    .map_err(|e| RpcError::Protocol(format!("unseal response: {e}")))?;
                chunk.truncate(chunk.len().saturating_sub(resp_pad));
                plain.extend_from_slice(&chunk);
                off += frag;
                if pfc & PFC_LAST_FRAG != 0 {
                    hit_last = true;
                    break;
                }
            }
            if hit_last {
                break;
            }
            let more = self
                .client
                .read_pipe(&self.file_id, 0x0001_0000)
                .await
                .map_err(|e| RpcError::Protocol(format!("pipe read: {e}")))?;
            if more.is_empty() {
                break; // no more data available
            }
            raw.extend_from_slice(&more);
        }
        Ok(plain)
    }
}
