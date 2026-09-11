//! `ldap` — direct LDAP primitives that bypass the collector (ldap3).
//!
//! First inhabitant: `ldap auth` (F1b) — **SASL EXTERNAL bind over
//! LDAPS-with-client-cert (schannel auth).** The workspace default LDAP
//! client (ldap3) does not expose a rustls client-cert setter, so this verb
//! sets up rustls itself (tokio-rustls + rustls-native-certs, already in
//! tree), does the TLS handshake with a client cert, and sends a minimal
//! `BindRequest { name="", auth=SASL{mech="EXTERNAL", cred=""} }`. The DC
//! authenticates the client via the cert subject (Windows key-trust /
//! altSecurityIdentities mapping) and returns the LDAP `resultCode` +
//! `diagnosticMessage` in the `BindResponse`.
//!
//! Success = the DC accepted the cert as auth for a principal. This verb is
//! a **bind test** — it does not integrate into the collector's session store
//! (adding cert-bind to the collector needs a bigger ldap3-fork or
//! native-tls-backend switch; that's the follow-up workstream). Chain with a
//! `[hint]` toward `attack laps` / `attack dcsync` / `attack secretsdump`
//! run under a subsequent password- or ccache-based auth.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::ui;

#[derive(Subcommand)]
pub(crate) enum LdapCmd {
    /// F1b — LDAPS bind via TLS client certificate (SASL EXTERNAL). Supply the
    /// key + cert as `--pfx <bundle> [--pfx-password]` OR `--key <pem>
    /// --cert <path>`. On success the DC's `BindResponse` `resultCode` is
    /// printed with the diagnostic message; on cert mapping failure the DC's
    /// `data <hex>` sub-code is surfaced.
    Auth(AuthArgs),
}

#[derive(Parser)]
pub(crate) struct AuthArgs {
    /// DC hostname (or IP) — must match the cert's SAN when the DC verifies
    /// hostname on the client leg (some do; some don't).
    #[arg(long)]
    pub host: String,
    /// LDAPS port. Default 636.
    #[arg(long, default_value_t = 636u16)]
    pub port: u16,

    /// PKCS#12 bundle (`.pfx` / `.p12`). Mutually exclusive with `--key`.
    #[arg(long, value_name = "PATH", conflicts_with = "key")]
    pub pfx: Option<String>,
    /// PFX password (blank for unencrypted).
    #[arg(long, default_value = "")]
    pub pfx_password: adhammer_core::SecretString,
    /// PKCS#8 PEM private key. Mutually exclusive with `--pfx`.
    #[arg(long, value_name = "PATH", conflicts_with = "pfx")]
    pub key: Option<String>,
    /// Paired cert (DER or PEM). Required with `--key`.
    #[arg(long, value_name = "PATH")]
    pub cert: Option<String>,

    /// Skip TLS server-cert verification (lab / self-signed DC certs).
    #[arg(long)]
    pub insecure: bool,
}

pub(crate) async fn auth(a: AuthArgs) -> Result<()> {
    let mut checklist = ui::StageChecklist::new([
        "load client cert + key",
        "TLS handshake (client-cert)",
        "LDAP SASL EXTERNAL bind",
        "parse BindResponse",
    ]);
    let result = auth_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("LDAP schannel bind"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("LDAP schannel bind (failed)");
        }
    }
    result
}

async fn auth_impl(a: AuthArgs, cl: &mut ui::StageChecklist) -> Result<()> {
    // 1. Resolve identity: PFX (decode inline) OR PEM+CRT (read + parse).
    let (key_pem, cert_der) = if let Some(pfx_path) = a.pfx.as_deref() {
        let pw = crate::resolve_secret(&a.pfx_password, "ADHAMMER_PFX_PASSWORD")?;
        crate::attacks::kerb::decode_pfx_bundle_for_reuse(pfx_path, pw.expose_secret())
            .with_context(|| format!("decode PFX bundle {pfx_path}"))?
    } else {
        let key_path = a
            .key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("supply --pfx or --key <pem>"))?;
        let cert_path = a
            .cert
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("supply --cert alongside --key"))?;
        let key_pem =
            std::fs::read_to_string(key_path).with_context(|| format!("read --key {key_path}"))?;
        if !key_pem.contains("-----BEGIN") {
            bail!("--key {key_path} is not a PEM private key");
        }
        let cert_der = crate::attacks::kerb::read_cert_der(cert_path)?;
        (key_pem, cert_der)
    };
    cl.record_ok(
        "load client cert + key",
        format!("cert {}B DER, key {}B PEM", cert_der.len(), key_pem.len()),
    );

    // 2. Build rustls client config. Cert = single-entry chain (leaf). Key
    // is PKCS#8; use rustls_pki_types + pkcs8 to feed rustls.
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    let cert_chain = vec![CertificateDer::from(cert_der.clone())];
    // Extract the raw PKCS#8 DER out of the PEM body.
    let key_der_bytes =
        pem_body_to_der(&key_pem, "PRIVATE KEY").context("re-decode PKCS#8 key PEM")?;
    let priv_key: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_bytes));

    let mut builder = rustls::ClientConfig::builder();
    let config = if a.insecure {
        // Match the collector's --insecure semantics: skip cert + hostname verify.
        // WS-INSECURE (1.5.1 F1b): reuse the collector's verifier pattern.
        Arc::new(
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_client_auth_cert(cert_chain, priv_key)
                .context("rustls with_client_auth_cert (insecure)")?,
        )
    } else {
        let mut roots = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for c in native.certs {
            roots.add(c).ok();
        }
        builder = rustls::ClientConfig::builder();
        Arc::new(
            builder
                .with_root_certificates(roots)
                .with_client_auth_cert(cert_chain, priv_key)
                .context("rustls with_client_auth_cert")?,
        )
    };

    // 3. TCP + TLS handshake.
    let tcp = tokio::net::TcpStream::connect((a.host.as_str(), a.port))
        .await
        .with_context(|| format!("connect {}:{}", a.host, a.port))?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let server_name = ServerName::try_from(a.host.clone())
        .map_err(|e| anyhow::anyhow!("bad SNI hostname {}: {e}", a.host))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake to {}:{}", a.host, a.port))?;
    cl.record_ok(
        "TLS handshake (client-cert)",
        format!("→ {}:{}", a.host, a.port),
    );

    // 4. Send BindRequest with SASL EXTERNAL.
    let bind_msg = encode_bind_sasl_external(1);
    tls.write_all(&bind_msg)
        .await
        .context("send LDAP BindRequest")?;
    tls.flush().await.ok();
    cl.record_ok(
        "LDAP SASL EXTERNAL bind",
        format!("sent {} bytes", bind_msg.len()),
    );

    // 5. Read BindResponse. LDAP messages are DER-encoded SEQUENCE; read the
    // outer header (tag + length) to size the read.
    let (result_code, matched_dn, diag) = read_bind_response(&mut tls).await?;
    cl.record_ok("parse BindResponse", format!("resultCode={result_code}"));

    if result_code == 0 {
        println!("[+] LDAP schannel bind OK — DC accepted the cert.");
        if !matched_dn.is_empty() {
            println!("    matchedDN: {matched_dn}");
        }
        if !diag.is_empty() {
            println!("    diagnostic: {diag}");
        }
        println!("    (bind test only — this verb does not persist a session; chain into e.g. `attack laps --user <mapped-principal>` under a password- or ccache-based auth.)");
        Ok(())
    } else {
        let name = ldap_result_code_name(result_code);
        println!("[-] LDAP bind FAILED: resultCode={result_code} ({name})");
        if !matched_dn.is_empty() {
            println!("    matchedDN: {matched_dn}");
        }
        if !diag.is_empty() {
            println!("    diagnostic: {diag}");
        }
        bail!("LDAP bind rejected by DC (result={result_code})");
    }
}

/// Encode a `BindRequest` with `SASL EXTERNAL` (empty credentials) as a full
/// LDAPMessage. `mid` = messageID.
fn encode_bind_sasl_external(mid: u32) -> Vec<u8> {
    // SASL choice body: [3] IMPLICIT SEQUENCE { mechanism, credentials }
    // We encode the mechanism as OCTET STRING and credentials as OCTET STRING
    // per RFC 4511 §4.2 (`SaslCredentials`).
    let mech = b"EXTERNAL";
    let mut sasl = Vec::new();
    tlv(&mut sasl, 0x04, mech); // OCTET STRING mechanism
    tlv(&mut sasl, 0x04, &[]); // OCTET STRING credentials (empty)

    let mut bind_body = Vec::new();
    tlv(&mut bind_body, 0x02, &[0x03]); // INTEGER version=3
    tlv(&mut bind_body, 0x04, &[]); // OCTET STRING name=""
                                    // [3] SASL choice — CONTEXT 3, constructed.
    tlv(&mut bind_body, 0xA3, &sasl);

    let mut msg = Vec::new();
    tlv_uint(&mut msg, mid); // INTEGER messageID
                             // [APPLICATION 0] BindRequest — tag 0x60, constructed.
    tlv(&mut msg, 0x60, &bind_body);

    let mut wrapped = Vec::new();
    tlv(&mut wrapped, 0x30, &msg); // outer SEQUENCE (LDAPMessage)
    wrapped
}

/// Append TLV (tag, DER length, value) to `out`.
fn tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    encode_len(out, body.len());
    out.extend_from_slice(body);
}

/// Append INTEGER TLV holding a small unsigned integer (0..=u32::MAX).
fn tlv_uint(out: &mut Vec<u8>, v: u32) {
    // Serialize minimum-length big-endian, with a leading 0 byte if the MSB is set.
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(out, 0x02, &bytes);
}

fn encode_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let be = (n as u64).to_be_bytes();
        let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
        let body = &be[first..];
        out.push(0x80 | body.len() as u8);
        out.extend_from_slice(body);
    }
}

/// Read + parse a BindResponse from `s`. Returns (resultCode, matchedDN, diagnosticMessage).
async fn read_bind_response<S>(s: &mut S) -> Result<(u32, String, String)>
where
    S: AsyncReadExt + Unpin,
{
    // Outer SEQUENCE header.
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr)
        .await
        .context("read LDAPMessage tag")?;
    if hdr[0] != 0x30 {
        bail!("expected LDAPMessage SEQUENCE (0x30), got {:#04x}", hdr[0]);
    }
    let outer_len = read_len(s, hdr[1]).await?;
    let mut body = vec![0u8; outer_len];
    s.read_exact(&mut body)
        .await
        .context("read LDAPMessage body")?;

    // Walk: INTEGER messageID, [APPLICATION 1] BindResponse.
    let mut off = 0usize;
    let (_mid, mid_end) = read_tlv(&body, off, 0x02)?;
    off = mid_end;
    let (br_body, _) = read_tlv_body(&body, off, 0x61)?; // BindResponse tag = APPLICATION 1

    // BindResponse ::= LDAPResult:
    //   ENUMERATED resultCode
    //   OCTET STRING matchedDN
    //   OCTET STRING diagnosticMessage
    //   [3] referral OPTIONAL (ignored)
    let mut i = 0usize;
    let (rc_bytes, rc_end) = read_tlv(&br_body, i, 0x0A)?;
    let result_code = be_uint(rc_bytes);
    i = rc_end;
    let (md_bytes, md_end) = read_tlv(&br_body, i, 0x04)?;
    let matched_dn = String::from_utf8_lossy(md_bytes).to_string();
    i = md_end;
    let (dm_bytes, _) = read_tlv(&br_body, i, 0x04)?;
    let diag = String::from_utf8_lossy(dm_bytes).to_string();
    Ok((result_code, matched_dn, diag))
}

async fn read_len<S>(s: &mut S, first: u8) -> Result<usize>
where
    S: AsyncReadExt + Unpin,
{
    if first < 0x80 {
        return Ok(first as usize);
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 {
        bail!("bad DER long-form length octet {first:#04x}");
    }
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf[..n])
        .await
        .context("read DER long-form length body")?;
    let mut v = 0usize;
    for b in &buf[..n] {
        v = (v << 8) | (*b as usize);
    }
    Ok(v)
}

fn read_tlv(bytes: &[u8], off: usize, want_tag: u8) -> Result<(&[u8], usize)> {
    if off + 2 > bytes.len() {
        bail!("truncated TLV at {off}");
    }
    let tag = bytes[off];
    if tag != want_tag {
        bail!("expected tag {want_tag:#04x} at {off}, got {tag:#04x}");
    }
    let (len, len_bytes) = parse_len(&bytes[off + 1..])?;
    let start = off + 1 + len_bytes;
    if start + len > bytes.len() {
        bail!("TLV len {len} at {off} runs past body");
    }
    Ok((&bytes[start..start + len], start + len))
}

fn read_tlv_body(bytes: &[u8], off: usize, want_tag: u8) -> Result<(Vec<u8>, usize)> {
    let (b, next) = read_tlv(bytes, off, want_tag)?;
    Ok((b.to_vec(), next))
}

fn parse_len(bytes: &[u8]) -> Result<(usize, usize)> {
    if bytes.is_empty() {
        bail!("empty DER length");
    }
    let first = bytes[0];
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 || bytes.len() < 1 + n {
        bail!("bad DER long-form length {first:#04x}");
    }
    let mut v = 0usize;
    for b in &bytes[1..=n] {
        v = (v << 8) | (*b as usize);
    }
    Ok((v, 1 + n))
}

fn be_uint(bytes: &[u8]) -> u32 {
    let mut v = 0u32;
    for b in bytes {
        v = (v << 8) | (*b as u32);
    }
    v
}

fn ldap_result_code_name(rc: u32) -> &'static str {
    match rc {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        7 => "authMethodNotSupported",
        8 => "strongerAuthRequired",
        13 => "confidentialityRequired",
        14 => "saslBindInProgress",
        48 => "inappropriateAuthentication",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        _ => "?",
    }
}

/// Strip PEM headers/footers and base64-decode a body labeled `expect_label`.
fn pem_body_to_der(pem: &str, expect_label: &str) -> Result<Vec<u8>> {
    let mut in_body = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN") {
            if !t.contains(expect_label) {
                // The PKCS#8 crate emits `BEGIN PRIVATE KEY`; RSA emits
                // `BEGIN RSA PRIVATE KEY`. We only recognise PKCS#8 here —
                // the p12 → pkcs8 pipeline in kerb.rs always produces this.
                bail!(
                    "PEM header does not name {expect_label}: {t}\n\
                     (F1b expects a PKCS#8 key; convert via pkcs8 crate or openssl if needed)"
                );
            }
            in_body = true;
            continue;
        }
        if t.starts_with("-----END") {
            break;
        }
        if in_body {
            b64.push_str(t);
        }
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("base64-decode PKCS#8 body: {e}"))
}

/// rustls verifier that accepts any server cert (matches collector's --insecure semantics).
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_sasl_external_encodes_recognisable_shape() {
        let m = encode_bind_sasl_external(1);
        // Outer SEQUENCE.
        assert_eq!(m[0], 0x30);
        // messageID INTEGER 1 appears somewhere in the body.
        assert!(m.windows(3).any(|w| w == [0x02, 0x01, 0x01]));
        // BindRequest tag [APPLICATION 0] = 0x60.
        assert!(m.contains(&0x60));
        // SASL choice tag [3] = 0xA3.
        assert!(m.contains(&0xA3));
        // Mechanism string "EXTERNAL".
        assert!(m.windows(8).any(|w| w == b"EXTERNAL"));
    }

    #[test]
    fn encode_len_short_form() {
        let mut out = Vec::new();
        encode_len(&mut out, 5);
        assert_eq!(out, vec![5]);
    }

    #[test]
    fn encode_len_long_form() {
        let mut out = Vec::new();
        encode_len(&mut out, 300);
        assert_eq!(out[0], 0x82);
        assert_eq!(out[1], 0x01);
        assert_eq!(out[2], 0x2C);
    }

    #[test]
    fn parse_len_round_trips() {
        for n in [0usize, 1, 127, 128, 255, 256, 1000, 65535, 65536, 1_000_000] {
            let mut out = Vec::new();
            encode_len(&mut out, n);
            let (parsed, _) = parse_len(&out).unwrap();
            assert_eq!(parsed, n, "round-trip for {n}");
        }
    }

    #[test]
    fn ldap_result_code_names_the_common_ones() {
        assert_eq!(ldap_result_code_name(0), "success");
        assert_eq!(ldap_result_code_name(49), "invalidCredentials");
        assert_eq!(ldap_result_code_name(999), "?");
    }
}
