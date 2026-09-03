//! `enum web` — HTTP(S) fingerprint of a host's AD-relevant web surface.
//!
//! WS-WEB-FP (1.5.0). A no-cred first-touch probe of the web endpoints
//! that matter on an AD estate: AD CS Web Enrollment (`/certsrv/` — the
//! ESC8 relay surface), RD Web Access, ADFS sign-in + federation
//! metadata, Exchange OWA / EWS, and the SCCM client endpoint. One GET
//! per endpoint over HTTP/80 and HTTPS/443; the status line, `Server`
//! header, and `WWW-Authenticate` header classify each hit.
//!
//! A cleartext-HTTP `WWW-Authenticate: NTLM` on `/certsrv/` is the ESC8
//! tell — coerce a machine, relay its NTLM there, get a machine cert.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ui;

#[derive(Parser)]
pub(crate) struct WebArgs {
    /// Target host / IP to fingerprint (repeatable).
    #[arg(long = "host", required = true)]
    pub hosts: Vec<String>,
    /// Per-request timeout in seconds.
    #[arg(long, default_value = "5")]
    pub timeout: u64,
    /// Emit JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

/// AD-relevant endpoints, each with a short technology tag.
const ENDPOINTS: &[(&str, &str)] = &[
    ("/", "root (Server banner)"),
    ("/certsrv/", "AD CS Web Enrollment"),
    (
        "/certsrv/certfnsh.asp",
        "AD CS enrollment (ESC8 if NTLM/cleartext)",
    ),
    ("/certsrv/certrqxt.asp", "AD CS request page"),
    ("/RDWeb/", "RD Web Access"),
    ("/RDWeb/Pages/en-US/login.aspx", "RD Web Access login"),
    ("/adfs/ls/", "ADFS sign-in"),
    (
        "/FederationMetadata/2007-06/FederationMetadata.xml",
        "ADFS federation metadata",
    ),
    ("/EWS/Exchange.asmx", "Exchange Web Services"),
    ("/owa/", "Outlook Web Access"),
    ("/Autodiscover/Autodiscover.xml", "Exchange Autodiscover"),
    ("/ccm_system/", "SCCM client"),
    ("/aspnet_client/", "IIS / ASP.NET"),
];

struct WebHit {
    scheme: &'static str,
    port: u16,
    path: String,
    tech: &'static str,
    status: String,
    server: Option<String>,
    www_authenticate: Option<String>,
}

#[derive(Debug)]
struct AcceptAny;
impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _s: &ServerName<'_>,
        _o: &[u8],
        _n: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn http_request(host: &str, path: &str) -> String {
    // HTTP/1.0 + explicit close so the server ends the body without us
    // parsing Content-Length / chunked; we only need the head anyway.
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: adhammer\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
}

/// Parse the head of an HTTP response into (status-line, Server, WWW-Authenticate).
fn parse_head(resp: &str) -> Option<(String, Option<String>, Option<String>)> {
    let mut lines = resp.lines();
    let status = lines.next()?.trim().to_string();
    if !status.starts_with("HTTP/") {
        return None;
    }
    let mut server = None;
    let mut auth = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("server:") {
            server = Some(line[line.len() - v.len()..].trim().to_string());
        } else if lower.starts_with("www-authenticate:") {
            let v = line
                .split_once(':')
                .map(|(_, v)| v)
                .unwrap_or("")
                .trim()
                .to_string();
            // Multiple WWW-Authenticate lines (NTLM + Negotiate) — join.
            auth = Some(match auth {
                Some(prev) => format!("{prev}, {v}"),
                None => v,
            });
        }
    }
    Some((status, server, auth))
}

async fn probe_http(
    host: &str,
    port: u16,
    path: &str,
    timeout: u64,
) -> Option<(String, Option<String>, Option<String>)> {
    let dur = std::time::Duration::from_secs(timeout);
    let mut s = tokio::time::timeout(dur, TcpStream::connect((host, port)))
        .await
        .ok()?
        .ok()?;
    s.write_all(http_request(host, path).as_bytes())
        .await
        .ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(dur, s.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_head(&String::from_utf8_lossy(&buf[..n]))
}

async fn probe_https(
    host: &str,
    port: u16,
    path: &str,
    timeout: u64,
) -> Option<(String, Option<String>, Option<String>)> {
    let dur = std::time::Duration::from_secs(timeout);
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::time::timeout(dur, TcpStream::connect((host, port)))
        .await
        .ok()?
        .ok()?;
    let sn = ServerName::try_from(host.to_string()).ok()?;
    let mut stream = tokio::time::timeout(dur, connector.connect(sn, tcp))
        .await
        .ok()?
        .ok()?;
    stream
        .write_all(http_request(host, path).as_bytes())
        .await
        .ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(dur, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_head(&String::from_utf8_lossy(&buf[..n]))
}

pub(crate) async fn webenum(a: WebArgs) -> Result<()> {
    let mut all: Vec<(String, Vec<WebHit>)> = Vec::new();
    for host in &a.hosts {
        let sp = ui::Spinner::start(format!("fingerprinting web surface on {host}"));
        let mut hits = Vec::new();
        for (path, tech) in ENDPOINTS {
            // HTTP/80 — skip re-probing "/" tech-tag duplication is fine.
            if let Some((status, server, auth)) = probe_http(host, 80, path, a.timeout).await {
                hits.push(WebHit {
                    scheme: "http",
                    port: 80,
                    path: (*path).to_string(),
                    tech,
                    status,
                    server,
                    www_authenticate: auth,
                });
            }
            if let Some((status, server, auth)) = probe_https(host, 443, path, a.timeout).await {
                hits.push(WebHit {
                    scheme: "https",
                    port: 443,
                    path: (*path).to_string(),
                    tech,
                    status,
                    server,
                    www_authenticate: auth,
                });
            }
        }
        sp.done(&format!("{}: {} endpoint hit(s)", host, hits.len()));
        all.push((host.clone(), hits));
    }

    if a.json {
        print_json(&all);
    } else {
        print_human(&all);
    }
    Ok(())
}

fn san(s: &str) -> String {
    adhammer_core::sanitize_terminal_output(s)
}

fn print_human(all: &[(String, Vec<WebHit>)]) {
    for (host, hits) in all {
        println!("\n== {} ==", san(host));
        if hits.is_empty() {
            println!("  no AD web endpoints responded on 80/443");
            continue;
        }
        for h in hits {
            let mut line = format!(
                "  {}://{}:{}{}  {}  [{}]",
                h.scheme,
                san(host),
                h.port,
                san(&h.path),
                san(&h.status),
                h.tech
            );
            if let Some(sv) = &h.server {
                line.push_str(&format!("  server={}", san(sv)));
            }
            if let Some(auth) = &h.www_authenticate {
                line.push_str(&format!("  www-authenticate={}", san(auth)));
                if h.scheme == "http"
                    && auth.to_ascii_lowercase().contains("ntlm")
                    && h.path.starts_with("/certsrv")
                {
                    line.push_str("  ** ESC8 relay surface (NTLM over cleartext) **");
                }
            }
            println!("{line}");
        }
    }
}

fn print_json(all: &[(String, Vec<WebHit>)]) {
    let esc = |s: &str| {
        let clean = san(s);
        let mut q = String::from("\"");
        for c in clean.chars() {
            match c {
                '"' => q.push_str("\\\""),
                '\\' => q.push_str("\\\\"),
                c if (c as u32) < 0x20 => q.push_str(&format!("\\u{:04x}", c as u32)),
                c => q.push(c),
            }
        }
        q.push('"');
        q
    };
    let mut out = String::from("{\"hosts\":[");
    for (i, (host, hits)) in all.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{{\"host\":{},\"endpoints\":[", esc(host)));
        for (j, h) in hits.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"url\":{},\"tech\":{},\"status\":{},\"server\":{},\"www_authenticate\":{}}}",
                esc(&format!("{}://{}:{}{}", h.scheme, host, h.port, h.path)),
                esc(h.tech),
                esc(&h.status),
                h.server
                    .as_deref()
                    .map(esc)
                    .unwrap_or_else(|| "null".into()),
                h.www_authenticate
                    .as_deref()
                    .map(esc)
                    .unwrap_or_else(|| "null".into()),
            ));
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    println!("{out}");
}

#[cfg(test)]
mod tests {
    use super::parse_head;

    #[test]
    fn parses_status_server_and_joins_www_authenticate() {
        let resp = "HTTP/1.1 401 Unauthorized\r\n\
            Server: Microsoft-IIS/10.0\r\n\
            WWW-Authenticate: Negotiate\r\n\
            WWW-Authenticate: NTLM\r\n\
            Content-Length: 0\r\n\r\n";
        let (status, server, auth) = parse_head(resp).unwrap();
        assert_eq!(status, "HTTP/1.1 401 Unauthorized");
        assert_eq!(server.as_deref(), Some("Microsoft-IIS/10.0"));
        assert_eq!(auth.as_deref(), Some("Negotiate, NTLM"));
    }

    #[test]
    fn no_auth_header_is_none() {
        let resp = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html>";
        let (status, server, auth) = parse_head(resp).unwrap();
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(server.as_deref(), Some("nginx"));
        assert!(auth.is_none());
    }

    #[test]
    fn non_http_first_line_rejected() {
        assert!(parse_head("SSH-2.0-OpenSSH_9.0\r\n").is_none());
        assert!(parse_head("").is_none());
    }
}
