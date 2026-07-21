//! SmbClient — drives the SMB2 exchange up to a usable named-pipe transport for RPC.
//! Flow: connect → negotiate → session-setup (NTLM, two round trips) → tree-connect IPC$
//! → create(pipe) → transact(). Post-authentication messages are signed.

use crate::header::{self, cmd};
use crate::transport::SmbTransport;
use crate::{msg, Result, SmbError};
use adhammer_ntlm::Ntlm;
use rand::RngCore;

pub struct SmbClient {
    transport: SmbTransport,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    sign_key: Option<[u8; 16]>,
    dialect: u16,
}

impl SmbClient {
    pub async fn connect(host: &str) -> Result<Self> {
        Ok(SmbClient {
            transport: SmbTransport::connect(host).await?,
            message_id: 0,
            session_id: 0,
            tree_id: 0,
            sign_key: None,
            dialect: 0,
        })
    }

    /// Send one command, returning the full response message (header + body).
    async fn call(&mut self, command: u16, body: &[u8]) -> Result<Vec<u8>> {
        let mut m = header::build(command, self.message_id, self.session_id, self.tree_id, self.sign_key.is_some());
        m.extend_from_slice(body);
        if let Some(key) = &self.sign_key {
            if self.dialect >= 0x0300 {
                header::sign_v3(&mut m, key); // 3.0.x → AES-CMAC
            } else {
                header::sign(&mut m, key); // 2.x → HMAC-SHA256
            }
        }
        self.message_id += 1;
        self.transport.send(&m).await?;
        let mut resp = self.transport.recv().await?;
        // A server may answer asynchronously: an interim STATUS_PENDING response, then the
        // real one on the same message id. Keep reading until the completion arrives.
        while header::parse(&resp).map(|p| p.status).unwrap_or(crate::status::SUCCESS)
            == crate::status::PENDING
        {
            resp = self.transport.recv().await?;
        }
        Ok(resp)
    }

    fn ok(resp: &[u8], expect: u16) -> Result<header::Parsed> {
        let p = header::parse(resp)?;
        if p.status != crate::status::SUCCESS {
            return Err(SmbError::Status(p.status, expect));
        }
        Ok(p)
    }

    /// Unauthenticated NEGOTIATE probe: returns (dialect revision, signing_required). Signing
    /// NOT required marks a host as an NTLM-relay target. Cheap — no session setup.
    pub async fn probe_signing(&mut self) -> Result<(u16, bool)> {
        let mut guid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut guid);
        let resp = self.call(cmd::NEGOTIATE, &msg::negotiate(&guid)).await?;
        Self::ok(&resp, cmd::NEGOTIATE)?;
        // NEGOTIATE response body @64: StructureSize(2), SecurityMode(2), DialectRevision(2).
        let security_mode = u16::from_le_bytes([resp[66], resp[67]]);
        let dialect = u16::from_le_bytes([resp[68], resp[69]]);
        Ok((dialect, security_mode & 0x0002 != 0)) // 0x2 = SMB2_NEGOTIATE_SIGNING_REQUIRED
    }

    /// Negotiate + NTLM session setup with the given credentials.
    pub async fn login(&mut self, host: &str, domain: &str, user: &str, password: &str) -> Result<()> {
        // NEGOTIATE
        let mut guid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut guid);
        let resp = self.call(cmd::NEGOTIATE, &msg::negotiate(&guid)).await?;
        Self::ok(&resp, cmd::NEGOTIATE)?;
        // DialectRevision is at response body offset 4 → absolute 68; it selects the signing algo.
        self.dialect = u16::from_le_bytes([resp[68], resp[69]]);

        // SESSION_SETUP #1: NTLM NEGOTIATE wrapped in SPNEGO negTokenInit.
        let ntlm = Ntlm::new();
        let init = crate::spnego::negotiate_init(ntlm.negotiate());
        let resp = self.call(cmd::SESSION_SETUP, &msg::session_setup(&init)).await?;
        let p = header::parse(&resp)?;
        if p.status != crate::status::MORE_PROCESSING_REQUIRED {
            return Err(SmbError::Status(p.status, cmd::SESSION_SETUP));
        }
        self.session_id = p.session_id;

        // The server CHALLENGE (Type 2) is embedded in a SPNEGO negTokenResp.
        let blob = msg::session_setup_token(&resp)?;
        let challenge = crate::spnego::find_ntlm(&blob).ok_or(SmbError::BadToken)?;

        // Build AUTHENTICATE; the exported session key becomes our signing key.
        let (type3, session_key) = ntlm
            .authenticate(challenge, domain, user, password, host)
            .map_err(|e| SmbError::Ntlm(e.to_string()))?;

        // Derive the signing key: 2.x uses the session key directly, 3.0.x derives an
        // AES-CMAC key from it (SP800-108 KDF).
        let key = if self.dialect >= 0x0300 {
            header::kdf_signing_key(&session_key)
        } else {
            session_key
        };
        // SESSION_SETUP #2: AUTHENTICATE (Type 3). SMB 3.x requires the final session setup to
        // be signed with the new key; 2.x leaves it unsigned (matching Windows).
        if self.dialect >= 0x0300 {
            self.sign_key = Some(key);
        }
        let token = crate::spnego::negotiate_resp(&type3);
        let resp = self.call(cmd::SESSION_SETUP, &msg::session_setup(&token)).await?;
        Self::ok(&resp, cmd::SESSION_SETUP)?;
        self.sign_key = Some(key); // sign everything from here on
        Ok(())
    }

    /// Connect to a share, e.g. `\\dc01\IPC$`.
    pub async fn tree_connect(&mut self, unc: &str) -> Result<()> {
        let resp = self.call(cmd::TREE_CONNECT, &msg::tree_connect(unc)).await?;
        let p = Self::ok(&resp, cmd::TREE_CONNECT)?;
        self.tree_id = p.tree_id;
        Ok(())
    }

    /// Open a named pipe on the connected tree and return its FileId.
    pub async fn open_pipe(&mut self, name: &str) -> Result<[u8; 16]> {
        let resp = self.call(cmd::CREATE, &msg::create_pipe(name)).await?;
        Self::ok(&resp, cmd::CREATE)?;
        msg::create_file_id(&resp)
    }

    /// One RPC round trip over the pipe (FSCTL_PIPE_TRANSCEIVE): send `data`, return output.
    pub async fn transact(&mut self, file_id: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        let resp = self.call(cmd::IOCTL, &msg::ioctl_transceive(file_id, data)).await?;
        Self::ok(&resp, cmd::IOCTL)?;
        msg::ioctl_output(&resp)
    }
}
