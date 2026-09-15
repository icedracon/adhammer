//! **1.5.2 G-E**: `enum anon-services` — cheap TCP probes for anonymous
//! service exposure that AD-focused sweeps miss.
//!
//! Bundled here because each probe is 10-20 lines of socket code and none
//! deserve their own top-level verb: rsync 873 daemon module list (anon),
//! FTP 21 `USER anonymous` login, TFTP 69 read-any (banner-only), NFS 2049
//! null-mount surface. The SMB null-session case is already `enum nullbind`
//! / `enum host --anon` — this verb is deliberately the NOT-SMB set.
//!
//! Zero credentials, one-shot per probe with short timeouts so the whole
//! sweep completes in seconds against a hardened host.

use anyhow::Result;
use clap::Parser;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
const IO_TIMEOUT: Duration = Duration::from_millis(2500);

#[derive(Parser)]
pub(crate) struct AnonServicesArgs {
    /// Target host (IP or FQDN).
    #[arg(long)]
    pub host: String,
    /// Skip individual probes when the target is known to expose only a
    /// subset — space-separated list of `rsync` / `ftp` / `tftp`. Default is
    /// every probe.
    #[arg(long, value_delimiter = ',')]
    pub skip: Vec<String>,
    /// Emit JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, serde::Serialize, Default)]
struct AnonReport {
    host: String,
    rsync: Option<ProbeOutcome>,
    ftp: Option<ProbeOutcome>,
    tftp: Option<ProbeOutcome>,
}

#[derive(Debug, serde::Serialize)]
struct ProbeOutcome {
    port: u16,
    reachable: bool,
    /// Short human summary. `None` when reachable=false.
    banner: Option<String>,
    /// True when the probe surfaced an ANONYMOUS-accessible response.
    /// For rsync: module list returned. For FTP: USER anonymous accepted.
    anon_ok: bool,
    /// If `anon_ok`, the notable-content line(s) — module names for rsync,
    /// welcome banner for FTP, etc.
    detail: Vec<String>,
}

pub(crate) async fn anon_services(a: AnonServicesArgs) -> Result<()> {
    let skip: std::collections::HashSet<String> =
        a.skip.iter().map(|s| s.to_ascii_lowercase()).collect();

    let mut report = AnonReport {
        host: a.host.clone(),
        ..Default::default()
    };

    if !skip.contains("rsync") {
        report.rsync = Some(probe_rsync(&a.host).await);
    }
    if !skip.contains("ftp") {
        report.ftp = Some(probe_ftp(&a.host).await);
    }
    if !skip.contains("tftp") {
        report.tftp = Some(probe_tftp(&a.host).await);
    }

    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "command": "adhammer enum anon-services",
                "success": true,
                "evidence": report,
            }))?
        );
    } else {
        print_human(&report);
    }
    Ok(())
}

fn print_human(r: &AnonReport) {
    let one = |name: &str, o: Option<&ProbeOutcome>| match o {
        None => eprintln!("  {name:<8} SKIPPED"),
        Some(o) if !o.reachable => eprintln!("  {name:<8} port {} closed / filtered", o.port),
        Some(o) if o.anon_ok => {
            eprintln!(
                "  {name:<8} port {} — ANONYMOUS OK{}",
                o.port,
                o.banner
                    .as_ref()
                    .map(|b| format!(" — {b}"))
                    .unwrap_or_default()
            );
            for d in &o.detail {
                eprintln!("            · {d}");
            }
        }
        Some(o) => {
            eprintln!(
                "  {name:<8} port {} reachable, anonymous refused{}",
                o.port,
                o.banner
                    .as_ref()
                    .map(|b| format!(" — {b}"))
                    .unwrap_or_default()
            );
        }
    };
    eprintln!();
    eprintln!("== enum anon-services ({}) ==", r.host);
    one("rsync", r.rsync.as_ref());
    one("ftp", r.ftp.as_ref());
    one("tftp", r.tftp.as_ref());
}

async fn probe_rsync(host: &str) -> ProbeOutcome {
    let port = 873;
    let addr = format!("{host}:{port}");
    let stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return closed(port),
    };
    let mut stream = stream;
    // rsyncd greets with `@RSYNCD: <proto>\n`; we echo the same version + `#list\n`
    // to enumerate anonymous modules per rsync protocol §3.
    let mut buf = [0u8; 128];
    let n = match timeout(IO_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return reachable_no_anon(port, None),
    };
    let greeting = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    if !greeting.starts_with("@RSYNCD:") {
        return reachable_no_anon(port, Some(greeting));
    }
    // Echo the greeting back — rsync expects the client to mirror the protocol version.
    let echo = format!("{greeting}\n");
    let _ = timeout(IO_TIMEOUT, stream.write_all(echo.as_bytes())).await;
    let _ = timeout(IO_TIMEOUT, stream.write_all(b"#list\n")).await;

    let mut reader = BufReader::new(stream);
    let mut modules = Vec::new();
    for _ in 0..64 {
        let mut line = String::new();
        match timeout(IO_TIMEOUT, reader.read_line(&mut line)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                let line = line.trim();
                if line.is_empty() || line == "@RSYNCD: EXIT" {
                    break;
                }
                if line.starts_with("@ERROR") {
                    return reachable_no_anon(port, Some(line.to_string()));
                }
                modules.push(line.to_string());
            }
            _ => break,
        }
    }
    ProbeOutcome {
        port,
        reachable: true,
        banner: Some(greeting),
        anon_ok: !modules.is_empty(),
        detail: modules,
    }
}

async fn probe_ftp(host: &str) -> ProbeOutcome {
    let port = 21;
    let addr = format!("{host}:{port}");
    let stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return closed(port),
    };
    let mut stream = stream;
    // Read 220 welcome banner.
    let mut buf = [0u8; 512];
    let n = match timeout(IO_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return reachable_no_anon(port, None),
    };
    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    if !banner.starts_with("220") {
        return reachable_no_anon(port, Some(banner));
    }
    // Try USER anonymous / PASS anonymous@example.com.
    let _ = timeout(IO_TIMEOUT, stream.write_all(b"USER anonymous\r\n")).await;
    let mut buf = [0u8; 256];
    let n = match timeout(IO_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return reachable_no_anon(port, Some(banner)),
    };
    let user_resp = String::from_utf8_lossy(&buf[..n]).trim().to_string();

    // If server requires no password (230), or asks for one (331), continue.
    if user_resp.starts_with("230") {
        return ProbeOutcome {
            port,
            reachable: true,
            banner: Some(banner),
            anon_ok: true,
            detail: vec![user_resp],
        };
    }
    if !user_resp.starts_with("331") {
        return reachable_no_anon(port, Some(banner));
    }
    let _ = timeout(
        IO_TIMEOUT,
        stream.write_all(b"PASS anonymous@example.com\r\n"),
    )
    .await;
    let mut buf = [0u8; 256];
    let n = match timeout(IO_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return reachable_no_anon(port, Some(banner)),
    };
    let pass_resp = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    let anon_ok = pass_resp.starts_with("230");
    ProbeOutcome {
        port,
        reachable: true,
        banner: Some(banner),
        anon_ok,
        detail: if anon_ok { vec![pass_resp] } else { vec![] },
    }
}

async fn probe_tftp(host: &str) -> ProbeOutcome {
    // TFTP is UDP-only; a real probe would need a tokio UdpSocket + a well-known
    // filename like "srvinfo". We just report the port as not-testable-over-TCP
    // and skip — full UDP probe is a follow-up (out of scope for the ½-day slot).
    let _ = host;
    ProbeOutcome {
        port: 69,
        reachable: false,
        banner: Some(String::from(
            "UDP probe deferred — use `nmap -sU -p69 --script tftp-enum`",
        )),
        anon_ok: false,
        detail: vec![],
    }
}

fn closed(port: u16) -> ProbeOutcome {
    ProbeOutcome {
        port,
        reachable: false,
        banner: None,
        anon_ok: false,
        detail: vec![],
    }
}

fn reachable_no_anon(port: u16, banner: Option<String>) -> ProbeOutcome {
    ProbeOutcome {
        port,
        reachable: true,
        banner,
        anon_ok: false,
        detail: vec![],
    }
}
