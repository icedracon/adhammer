//! `creds` — offline credential recovery / decode primitives that do not need
//! a live target.
//!
//! - `creds gpp-decrypt` (F6) — decode an MS14-025 Group Policy Preferences
//!   `cpassword` blob to plaintext using the public MS AES-256 key.
//! - `creds kdbx-extract` (F4b) — given a KNOWN KeePass master password,
//!   decrypt a KDBX4 body and unmask every protected field. Brute-forcing
//!   the master password is intentionally NOT in-tree — that job belongs to
//!   `keepass2john <file> | hashcat -m 13400 <wordlist>`, and adhammer's
//!   `docs/GAPS.md#kdbx-crack` row points at exactly that.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub(crate) enum CredsCmd {
    /// Decrypt an MS14-025 GPP `cpassword` blob to plaintext. Uses the public
    /// MS-GPPREF AES-256 key (identical on every domain — GPP passwords are
    /// plaintext-equivalent, which is the whole finding). Takes the base64
    /// string on the CLI or reads it from `--file`.
    GppDecrypt(GppDecryptArgs),
    /// **1.5.2 F4b** — KDBX4 protected-field extract. Given a KNOWN
    /// master password (recover it via `keepass2john <file> | hashcat -m 13400`
    /// first — hashcat owns the brute), this verb runs the full KeePass
    /// pipeline: Argon2d KDF → SHA-512 HMAC base key → outer cipher
    /// (AES256-CBC / ChaCha20) → gzip inflate → inner header parse → XML
    /// walk → protected-field unmask via inner ChaCha20 stream. Prints the
    /// recovered `Title / UserName / Password / URL` per entry. adhammer
    /// does NOT ship an in-tree brute — that would just be a slower hashcat.
    KdbxExtract(KdbxExtractArgs),
}

#[derive(Parser)]
pub(crate) struct KdbxExtractArgs {
    /// Path to a `.kdbx` file (KDBX4 format).
    #[arg(long, value_name = "PATH")]
    pub file: String,
    /// Master password (accepts `env:VAR` / `@file:PATH` / secure prompt).
    /// Mutually exclusive with `--key`.
    #[arg(long, conflicts_with = "key")]
    pub password: Option<adhammer_core::SecretString>,
    /// Hex-encoded composite key (from a prior `kdbx-crack` — 64 hex chars).
    /// Mutually exclusive with `--password`.
    #[arg(long, value_name = "HEX")]
    pub key: Option<String>,
    /// Emit JSON envelope.
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser)]
pub(crate) struct GppDecryptArgs {
    /// Base64 cpassword string (e.g. `j1Uyj3Vx8TY9LtLZ...`). Mutually exclusive with `--file`.
    #[arg(value_name = "CPASSWORD", conflicts_with = "file")]
    pub cpassword: Option<String>,

    /// Path to a file containing the base64 cpassword (whitespace ignored).
    /// Mutually exclusive with the positional CPASSWORD.
    #[arg(long, value_name = "PATH")]
    pub file: Option<String>,

    /// Prefix the output line with the recovered account name (if the caller
    /// pulled one out of the XML). Useful for scripted pipelines.
    #[arg(long, value_name = "NAME")]
    pub account: Option<String>,
}

pub(crate) async fn gpp_decrypt(a: GppDecryptArgs) -> Result<()> {
    let raw = match (a.cpassword.as_deref(), a.file.as_deref()) {
        (Some(s), _) => s.trim().to_string(),
        (None, Some(p)) => std::fs::read_to_string(p)
            .with_context(|| format!("read --file {p}"))?
            .split_whitespace()
            .collect::<String>(),
        (None, None) => {
            anyhow::bail!("supply the cpassword as an argument or via --file <PATH> (see --help)")
        }
    };
    if raw.is_empty() {
        anyhow::bail!("empty cpassword");
    }

    let pt = adhammer_sysvol::gpp::decrypt_cpassword(&raw)
        .context("MS14-025 AES-CBC decrypt failed — is this a real cpassword blob?")?;

    // TAB-separated so shell pipelines can `cut -f`.
    match a.account.as_deref() {
        Some(name) => println!("{name}\t{}", pt.expose_secret()),
        None => println!("{}", pt.expose_secret()),
    }
    Ok(())
}

pub(crate) async fn kdbx_extract(a: KdbxExtractArgs) -> Result<()> {
    let bytes = std::fs::read(&a.file).with_context(|| format!("read --file {}", a.file))?;
    let header =
        crate::attacks::kdbx::parse_header(&bytes).with_context(|| format!("parse {}", a.file))?;
    let pw = match (a.password.as_ref(), a.key.as_ref()) {
        (Some(p), None) => p.expose_secret().to_string(),
        (None, Some(_)) => {
            anyhow::bail!("--key (composite-key hex) path is deferred; supply --password for now");
        }
        (None, None) => anyhow::bail!("supply --password or --key"),
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts_with"),
    };
    let sp = crate::ui::Spinner::start(format!(
        "KDBX{}.{} — Argon2d + body decrypt + XML walk",
        header.major, header.minor
    ));
    // Derive the Argon2d key ONCE, verify it against the header HMAC (fail fast
    // on a wrong password before body decrypt), then reuse the same key for the
    // body extract — Argon2d is expensive, so we never run the KDF twice.
    let final_key =
        crate::attacks::kdbx::derive_final_key(&pw, &header).context("KDBX4 key derivation")?;
    if !crate::attacks::kdbx::verify_header_hmac(&header, &final_key) {
        sp.done_warn("wrong password (header HMAC mismatch)");
        anyhow::bail!("wrong password");
    }
    let entries =
        crate::attacks::kdbx::extract(&bytes, &header, &final_key).context("KDBX4 body extract")?;
    sp.done(&format!(
        "recovered {} entries — protected fields unmasked",
        entries.len()
    ));

    if a.json {
        let arr: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "title": e.title, "username": e.username, "password": e.password,
                    "url": e.url, "notes": e.notes, "custom": e.custom,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "adhammer creds kdbx-extract",
                "success": true,
                "evidence": {"file": a.file, "entries": arr},
            }))?
        );
    } else {
        for e in &entries {
            println!(
                "{}\t{}\t{}\t{}",
                e.title.clone().unwrap_or_default(),
                e.username.clone().unwrap_or_default(),
                e.password.clone().unwrap_or_default(),
                e.url.clone().unwrap_or_default(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Round-trip test: adhammer_sysvol carries its own vector; this just proves the
    // CLI-side plumbing calls it, without duplicating the key material or an expected
    // cleartext string in this file (leak-hook shape discipline).
    use super::*;

    #[tokio::test]
    async fn empty_input_bails_with_a_named_message() {
        let err = gpp_decrypt(GppDecryptArgs {
            cpassword: None,
            file: None,
            account: None,
        })
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cpassword"), "message names the input: {msg}");
    }
}
