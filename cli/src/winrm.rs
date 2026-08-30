//! WinRM (WS-Management) command execution over 5985/HTTP with NTLM authentication and
//! MS-NLMP message encryption ("SPNEGO session-encrypted" multipart). No external WinRM/HTTP
//! stack — raw TCP + the `ntlmssp` crate (NTLMv2 + RC4 seal/sign, the same primitives that seal
//! DCE/RPC). WinRM is often the only lateral-exec path a hardened estate leaves open, and it is
//! quieter than SVCCTL (no 7045 service-install event).
//!
//! Flow: NTLM type1 → 401+type2 → type3 (carrying the first encrypted request) → WS-Man
//! Create shell → Command → Receive (loop for output) → Signal terminate → Delete shell.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ntlmssp::{Ntlm, SealState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SHELL_URI: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
const ENC_CT: &str = "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"";

/// Credential material for the NTLM bind.
pub enum Secret {
    Password(String),
    NtHash([u8; 16]),
}

/// A monotonically-unique WS-Man MessageID (`uuid:...`). Uniqueness, not randomness, is what
/// the protocol needs, so a counter mixed with the clock is sufficient.
fn msg_id() -> String {
    static CTR: AtomicU64 = AtomicU64::new(1);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(n);
    format!(
        "uuid:{:08X}-{:04X}-4{:03X}-8{:03X}-{:012X}",
        (t >> 32) as u32,
        (t >> 16) as u16,
        (n as u16) & 0x0FFF,
        (n as u16) & 0x0FFF,
        t & 0xFFFF_FFFF_FFFF
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Text of the first element whose opening tag contains `open_contains`.
fn tag_text<'a>(xml: &'a str, open_contains: &str, close_tag: &str) -> Option<&'a str> {
    let start = xml.find(open_contains)?;
    let gt = xml[start..].find('>')? + start + 1;
    let end = xml[gt..].find(close_tag)? + gt;
    Some(xml[gt..end].trim())
}

pub struct WinRm {
    stream: TcpStream,
    seal: SealState,
    endpoint: String, // http://host:port/wsman
    host_hdr: String, // host:port
}

impl WinRm {
    /// Open a connection and complete NTLM auth, carrying the shell-Create as the first
    /// encrypted request so the exchange is a single round of POSTs.
    pub async fn connect(
        host: &str,
        port: u16,
        domain: &str,
        user: &str,
        secret: &Secret,
    ) -> Result<(Self, String)> {
        let mut stream = smb2_client::socks::dial(host, port)
            .await
            .with_context(|| format!("connect {host}:{port}"))?;
        let host_hdr = format!("{host}:{port}");
        let endpoint = format!("http://{host_hdr}/wsman");

        // Step 1: NTLM negotiate (type1), empty body → expect 401 + challenge (type2).
        let ntlm = Ntlm::new_sealed();
        let auth1 = format!("Negotiate {}", STANDARD.encode(ntlm.negotiate()));
        let (code, headers, _) = http_request(&mut stream, &host_hdr, Some(&auth1), None).await?;
        if code != 401 {
            bail!("WinRM: expected 401 challenge, got HTTP {code} (auth not Negotiate/NTLM?)");
        }
        let challenge = extract_negotiate(&headers)
            .context("no Negotiate challenge in 401 (server may not allow NTLM)")?;

        // Step 2: type3 + the exported session key → seal state for message encryption.
        let (type3, exported) = match secret {
            Secret::Password(p) => ntlm.authenticate(&challenge, domain, user, p, "adhammer"),
            Secret::NtHash(h) => ntlm.authenticate_hash(&challenge, domain, user, h, "adhammer"),
        }
        .map_err(|e| anyhow::anyhow!("NTLM authenticate: {e}"))?;
        let mut seal = SealState::new(&exported);
        let auth3 = format!("Negotiate {}", STANDARD.encode(&type3));

        // First authenticated request (encrypted): create the shell.
        let create = Self::create_shell_soap(&endpoint);
        let (ct, body) = wrap_encrypted(&mut seal, &create);
        let (code, _h, resp) =
            http_request(&mut stream, &host_hdr, Some(&auth3), Some((&ct, &body))).await?;
        if code != 200 {
            let txt = String::from_utf8_lossy(&resp);
            bail!(
                "WinRM: shell create failed (HTTP {code}): {}",
                txt.chars().take(300).collect::<String>()
            );
        }
        let xml = unwrap_encrypted(&mut seal, &resp)?;
        let shell_id = tag_text(&xml, "ShellId>", "</")
            .or_else(|| tag_text(&xml, "Selector Name=\"ShellId\">", "</"))
            .context("no ShellId in Create response")?
            .to_string();

        Ok((
            WinRm {
                stream,
                seal,
                endpoint,
                host_hdr,
            },
            shell_id,
        ))
    }

    /// Run one command in the shell and return (stdout, stderr, exit_code).
    pub async fn run(&mut self, shell_id: &str, command: &str) -> Result<(String, String, i32)> {
        let cmd_soap = self.command_soap(shell_id, command);
        let xml = self.send(&cmd_soap).await?;
        let command_id = tag_text(&xml, "CommandId>", "</")
            .context("no CommandId in Command response")?
            .to_string();

        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit = 0i32;
        // Receive loop: pull output streams until the command reports Done.
        for _ in 0..600 {
            let recv = self.receive_soap(shell_id, &command_id);
            let xml = self.send(&recv).await?;
            for (name, data) in streams(&xml) {
                if let Ok(bytes) = STANDARD.decode(data) {
                    let s = String::from_utf8_lossy(&bytes);
                    if name == "stderr" {
                        stderr.push_str(&s);
                    } else {
                        stdout.push_str(&s);
                    }
                }
            }
            if xml.contains("/CommandState/Done") || xml.contains("State/Done") {
                if let Some(code) = tag_text(&xml, "ExitCode>", "</") {
                    exit = code.trim().parse().unwrap_or(0);
                }
                break;
            }
        }

        // Best-effort cleanup: terminate the command, delete the shell.
        let _ = self.send(&self.signal_soap(shell_id, &command_id)).await;
        let _ = self.send(&self.delete_soap(shell_id)).await;
        Ok((stdout, stderr, exit))
    }

    /// Encrypt + POST a SOAP request on the authenticated connection, return the decrypted XML.
    async fn send(&mut self, soap: &str) -> Result<String> {
        let (ct, body) = wrap_encrypted(&mut self.seal, soap);
        let (code, _h, resp) =
            http_request(&mut self.stream, &self.host_hdr, None, Some((&ct, &body))).await?;
        if code != 200 {
            let txt = unwrap_encrypted(&mut self.seal, &resp)
                .unwrap_or_else(|_| String::from_utf8_lossy(&resp).into_owned());
            bail!(
                "WinRM: HTTP {code}: {}",
                txt.chars().take(400).collect::<String>()
            );
        }
        unwrap_encrypted(&mut self.seal, &resp)
    }

    fn header(&self, action: &str, extra: &str) -> String {
        format!(
            r#"<wsa:To>{to}</wsa:To><wsman:ResourceURI s:mustUnderstand="true">{uri}</wsman:ResourceURI><wsa:ReplyTo><wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo><wsa:Action s:mustUnderstand="true">{action}</wsa:Action><wsman:MaxEnvelopeSize s:mustUnderstand="true">153600</wsman:MaxEnvelopeSize><wsa:MessageID>{mid}</wsa:MessageID><wsman:Locale xml:lang="en-US" s:mustUnderstand="false"/><wsman:OperationTimeout>PT60S</wsman:OperationTimeout>{extra}"#,
            to = self.endpoint,
            uri = SHELL_URI,
            action = action,
            mid = msg_id(),
            extra = extra,
        )
    }

    fn envelope(&self, header: &str, body: &str) -> String {
        format!(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header>{header}</s:Header><s:Body>{body}</s:Body></s:Envelope>"#
        )
    }

    fn create_shell_soap(endpoint: &str) -> String {
        // Standalone (no &self yet): build the Create directly.
        let header = format!(
            r#"<wsa:To>{to}</wsa:To><wsman:ResourceURI s:mustUnderstand="true">{uri}</wsman:ResourceURI><wsa:ReplyTo><wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo><wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</wsa:Action><wsman:MaxEnvelopeSize s:mustUnderstand="true">153600</wsman:MaxEnvelopeSize><wsa:MessageID>{mid}</wsa:MessageID><wsman:Locale xml:lang="en-US" s:mustUnderstand="false"/><wsman:OptionSet><wsman:Option Name="WINRS_NOPROFILE">FALSE</wsman:Option><wsman:Option Name="WINRS_CODEPAGE">437</wsman:Option></wsman:OptionSet><wsman:OperationTimeout>PT60S</wsman:OperationTimeout>"#,
            to = endpoint,
            uri = SHELL_URI,
            mid = msg_id(),
        );
        format!(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header>{header}</s:Header><s:Body><rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell></s:Body></s:Envelope>"#
        )
    }

    fn command_soap(&self, shell_id: &str, command: &str) -> String {
        let extra = format!(
            r#"<wsman:SelectorSet><wsman:Selector Name="ShellId">{s}</wsman:Selector></wsman:SelectorSet><wsman:OptionSet><wsman:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</wsman:Option><wsman:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</wsman:Option></wsman:OptionSet>"#,
            s = shell_id
        );
        let header = self.header(
            "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
            &extra,
        );
        // Run through cmd.exe so arbitrary command lines (pipes, builtins) work.
        let body = format!(
            r#"<rsp:CommandLine><rsp:Command>cmd.exe</rsp:Command><rsp:Arguments>/c {}</rsp:Arguments></rsp:CommandLine>"#,
            xml_escape(command)
        );
        self.envelope(&header, &body)
    }

    fn receive_soap(&self, shell_id: &str, command_id: &str) -> String {
        let extra = format!(
            r#"<wsman:SelectorSet><wsman:Selector Name="ShellId">{s}</wsman:Selector></wsman:SelectorSet>"#,
            s = shell_id
        );
        let header = self.header(
            "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
            &extra,
        );
        let body = format!(
            r#"<rsp:Receive><rsp:DesiredStream CommandId="{c}">stdout stderr</rsp:DesiredStream></rsp:Receive>"#,
            c = command_id
        );
        self.envelope(&header, &body)
    }

    fn signal_soap(&self, shell_id: &str, command_id: &str) -> String {
        let extra = format!(
            r#"<wsman:SelectorSet><wsman:Selector Name="ShellId">{s}</wsman:Selector></wsman:SelectorSet>"#,
            s = shell_id
        );
        let header = self.header(
            "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
            &extra,
        );
        let body = format!(
            r#"<rsp:Signal CommandId="{c}"><rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code></rsp:Signal>"#,
            c = command_id
        );
        self.envelope(&header, &body)
    }

    fn delete_soap(&self, shell_id: &str) -> String {
        let extra = format!(
            r#"<wsman:SelectorSet><wsman:Selector Name="ShellId">{s}</wsman:Selector></wsman:SelectorSet>"#,
            s = shell_id
        );
        let header = self.header(
            "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
            &extra,
        );
        self.envelope(&header, "")
    }
}

/// All `<rsp:Stream Name="...">base64</rsp:Stream>` payloads (skips empty/end-of-stream markers).
fn streams(xml: &str) -> Vec<(String, &str)> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<rsp:Stream ") {
        rest = &rest[i..];
        let Some(gt) = rest.find('>') else { break };
        let attrs = &rest[..gt];
        let name = if attrs.contains("Name=\"stderr\"") {
            "stderr"
        } else {
            "stdout"
        };
        let Some(end) = rest[gt + 1..].find("</rsp:Stream>") else {
            break;
        };
        let data = &rest[gt + 1..gt + 1 + end];
        if !data.is_empty() {
            out.push((name.to_string(), data));
        }
        rest = &rest[gt + 1 + end..];
    }
    out
}

/// Wrap a SOAP message as an MS-NLMP session-encrypted multipart body (RC4-sealed + signed).
fn wrap_encrypted(seal: &mut SealState, soap: &str) -> (String, Vec<u8>) {
    let plain = soap.as_bytes();
    // WinRM signs and seals the whole message: sign_over == stub == plaintext.
    let (sealed, sig) = seal.seal_pdu(plain, plain);
    let mut enc = Vec::with_capacity(4 + 16 + sealed.len());
    enc.extend_from_slice(&(sig.len() as u32).to_le_bytes()); // signature length = 16
    enc.extend_from_slice(&sig);
    enc.extend_from_slice(&sealed);

    let mut body = Vec::new();
    body.extend_from_slice(b"--Encrypted Boundary\r\n");
    body.extend_from_slice(b"\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n");
    body.extend_from_slice(
        format!(
            "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={}\r\n",
            plain.len()
        )
        .as_bytes(),
    );
    body.extend_from_slice(b"--Encrypted Boundary\r\n");
    body.extend_from_slice(b"\tContent-Type: application/octet-stream\r\n");
    body.extend_from_slice(&enc);
    body.extend_from_slice(b"--Encrypted Boundary--\r\n");
    (ENC_CT.to_string(), body)
}

/// Reverse of [`wrap_encrypted`]: pull the octet-stream part, split off the signature, decrypt.
fn unwrap_encrypted(seal: &mut SealState, resp: &[u8]) -> Result<String> {
    let marker = b"application/octet-stream\r\n";
    let pos = find_sub(resp, marker).context("no octet-stream part in encrypted response")?;
    let mut enc = &resp[pos + marker.len()..];
    // Strip the trailing multipart boundary if present.
    if let Some(b) = find_sub(enc, b"--Encrypted Boundary") {
        enc = &enc[..b];
    }
    if enc.len() < 4 {
        bail!("encrypted part too short");
    }
    let sig_len = u32::from_le_bytes([enc[0], enc[1], enc[2], enc[3]]) as usize;
    if enc.len() < 4 + sig_len {
        bail!("encrypted part shorter than signature");
    }
    let signature = &enc[4..4 + sig_len];
    let sealed = &enc[4 + sig_len..];
    let plain = seal
        .unseal_pdu(sealed, 0, sealed.len(), signature)
        .map_err(|e| anyhow::anyhow!("WinRM unseal: {e}"))?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Send one HTTP/1.1 POST /wsman and read one full response → (status, headers, body).
async fn http_request(
    stream: &mut TcpStream,
    host_hdr: &str,
    auth: Option<&str>,
    body: Option<(&str, &[u8])>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let (ct, payload): (&str, &[u8]) = match body {
        Some((ct, b)) => (ct, b),
        None => ("application/soap+xml;charset=UTF-8", &[]),
    };
    let mut req = format!(
        "POST /wsman HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: Keep-Alive\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n",
        payload.len()
    );
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    if !payload.is_empty() {
        stream.write_all(payload).await?;
    }
    stream.flush().await?;
    read_http_response(stream).await
}

/// Per-op deadline for a single WinRM HTTP response read (headers + body).
/// A hostile WinRM endpoint that dribbles bytes could otherwise hang the
/// operator's session indefinitely. 60 s matches the WSMan
/// `OperationTimeout` we send in the SOAP envelope + a little margin for
/// TCP jitter.
const WINRM_HTTP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Read a complete HTTP/1.1 response (Content-Length or chunked), leaving the stream positioned
/// for the next keep-alive request. **1.4.8 hostile-server DoS defence:**
/// the whole read is capped at [`WINRM_HTTP_READ_TIMEOUT`].
async fn read_http_response(
    stream: &mut TcpStream,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    tokio::time::timeout(WINRM_HTTP_READ_TIMEOUT, read_http_response_inner(stream))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "WinRM HTTP read timed out after {}s (hostile-server DoS defence)",
                WINRM_HTTP_READ_TIMEOUT.as_secs()
            )
        })?
}

async fn read_http_response_inner(
    stream: &mut TcpStream,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    // Read until end of headers.
    let hdr_end = loop {
        if let Some(p) = find_sub(&buf, b"\r\n\r\n") {
            break p + 4;
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("connection closed before headers");
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..hdr_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .context("no HTTP status code")?;
    let mut headers = Vec::new();
    let mut content_len: Option<usize> = None;
    let mut chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.parse().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_lowercase().contains("chunked")
            {
                chunked = true;
            }
            headers.push((k, v));
        }
    }

    let mut body = buf.split_off(hdr_end);
    if chunked {
        // Standard HTTP/1.1 chunked decoder: <hex-size>CRLF <data> CRLF … 0 CRLF CRLF.
        let mut decoded = Vec::new();
        loop {
            let line_end = loop {
                if let Some(p) = find_sub(&body, b"\r\n") {
                    break p;
                }
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    bail!("closed mid chunk-size line");
                }
                body.extend_from_slice(&tmp[..n]);
            };
            let size_str = String::from_utf8_lossy(&body[..line_end]);
            let size =
                usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0").trim(), 16)
                    .unwrap_or(0);
            let need = line_end + 2 + size + 2; // size line + CRLF + data + trailing CRLF
            while body.len() < need {
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            if size == 0 {
                break;
            }
            let data_end = (line_end + 2 + size).min(body.len());
            decoded.extend_from_slice(&body[line_end + 2..data_end]);
            body.drain(..need.min(body.len())); // consume this chunk's framing
        }
        Ok((code, headers, decoded))
    } else {
        let len = content_len.unwrap_or(0);
        while body.len() < len {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(len);
        Ok((code, headers, body))
    }
}

/// Pull the base64 challenge out of a `WWW-Authenticate: Negotiate <b64>` header.
fn extract_negotiate(headers: &[(String, String)]) -> Option<Vec<u8>> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("www-authenticate") {
            if let Some(b64) = v.split_whitespace().nth(1) {
                if let Ok(bytes) = STANDARD.decode(b64) {
                    return Some(bytes);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_xml_metachars() {
        assert_eq!(
            xml_escape(r#"a & b < c > "d""#),
            "a &amp; b &lt; c &gt; &quot;d&quot;"
        );
    }

    #[test]
    fn extracts_tag_text() {
        let xml = "<rsp:ShellId>ABC-123</rsp:ShellId><x:ExitCode>1</x:ExitCode>";
        assert_eq!(tag_text(xml, "ShellId>", "</"), Some("ABC-123"));
        assert_eq!(tag_text(xml, "ExitCode>", "</"), Some("1"));
        assert_eq!(tag_text(xml, "Nope>", "</"), None);
    }

    #[test]
    fn parses_output_streams() {
        let xml = r#"<rsp:Stream Name="stdout" CommandId="c">aGVsbG8=</rsp:Stream><rsp:Stream Name="stderr" CommandId="c">ZXJy</rsp:Stream><rsp:Stream Name="stdout" CommandId="c" End="true"></rsp:Stream>"#;
        let s = streams(xml);
        assert_eq!(s.len(), 2, "empty end-of-stream marker should be skipped");
        assert_eq!(s[0], ("stdout".to_string(), "aGVsbG8="));
        assert_eq!(s[1], ("stderr".to_string(), "ZXJy"));
    }

    #[test]
    fn message_ids_are_unique_and_shaped() {
        let a = msg_id();
        let b = msg_id();
        assert_ne!(a, b);
        assert!(a.starts_with("uuid:"));
        assert_eq!(a.matches('-').count(), 4, "UUID must have 5 groups");
    }

    #[test]
    fn find_sub_locates_bytes() {
        assert_eq!(find_sub(b"abcdef", b"cd"), Some(2));
        assert_eq!(find_sub(b"abcdef", b"xy"), None);
    }
}
