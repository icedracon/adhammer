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
}

impl SmbClient {
    pub async fn connect(host: &str) -> Result<Self> {
        Ok(SmbClient {
            transport: SmbTransport::connect(host).await?,
            message_id: 0,
            session_id: 0,
            tree_id: 0,
            sign_key: None,
        })
    }

    /// Send one command, returning the full response message (header + body).
    async fn call(&mut self, command: u16, body: &[u8]) -> Result<Vec<u8>> {
        let mut m = header::build(command, self.message_id, self.session_id, self.tree_id, self.sign_key.is_some());
        m.extend_from_slice(body);
        if let Some(key) = &self.sign_key {
            header::sign(&mut m, key);
        }
        self.message_id += 1;
        self.transport.send(&m).await?;
        self.transport.recv().await
    }

    fn ok(resp: &[u8], expect: u16) -> Result<header::Parsed> {
        let p = header::parse(resp)?;
        if p.status != crate::status::SUCCESS {
            return Err(SmbError::Status(p.status, expect));
        }
        Ok(p)
    }

    /// Negotiate + NTLM session setup with the given credentials.
    pub async fn login(&mut self, host: &str, domain: &str, user: &str, password: &str) -> Result<()> {
        // NEGOTIATE
        let mut guid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut guid);
        let resp = self.call(cmd::NEGOTIATE, &msg::negotiate(&guid)).await?;
        Self::ok(&resp, cmd::NEGOTIATE)?;

        // SESSION_SETUP #1: send NTLM NEGOTIATE, expect MORE_PROCESSING_REQUIRED + CHALLENGE.
        let ntlm = Ntlm::new();
        let resp = self.call(cmd::SESSION_SETUP, &msg::session_setup(ntlm.negotiate())).await?;
        let p = header::parse(&resp)?;
        if p.status != crate::status::MORE_PROCESSING_REQUIRED {
            return Err(SmbError::Status(p.status, cmd::SESSION_SETUP));
        }
        self.session_id = p.session_id;
        let challenge = msg::session_setup_token(&resp)?;

        // Build AUTHENTICATE; the exported session key becomes our signing key.
        let (type3, session_key) = ntlm
            .authenticate(&challenge, domain, user, password, host)
            .map_err(|e| SmbError::Ntlm(e.to_string()))?;

        // SESSION_SETUP #2: send NTLM AUTHENTICATE (this request is itself signed once we
        // have the key, matching Windows behaviour).
        self.sign_key = Some(session_key);
        let resp = self.call(cmd::SESSION_SETUP, &msg::session_setup(&type3)).await?;
        Self::ok(&resp, cmd::SESSION_SETUP)?;
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
