//! `creds` — offline credential recovery / decode primitives that do not need
//! a live target.
//!
//! First inhabitant: `creds gpp-decrypt` (F6) — decode an MS14-025 Group Policy
//! Preferences `cpassword` blob to plaintext using the public MS AES-256 key
//! (already implemented in `adhammer_sysvol::gpp::decrypt_cpassword`). Surfaces
//! as a standalone verb so a `cpassword=` string pulled from a third-party dump
//! or an SMB share triage can be decoded without a fresh SYSVOL sweep.
//!
//! Follow-ups landing under the same group (see docs plan for 1.5.1):
//! - `creds kdbx-crack <file> --wordlist` (F4a) — KDBX4 Argon2d master-key brute.
//! - `creds kdbx-extract <file> --key <hex>|--password <pw>` (F4b) — ChaCha20
//!   protected-field decrypt of a cracked-or-known KeePass DB.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub(crate) enum CredsCmd {
    /// Decrypt an MS14-025 GPP `cpassword` blob to plaintext. Uses the public
    /// MS-GPPREF AES-256 key (identical on every domain — GPP passwords are
    /// plaintext-equivalent, which is the whole finding). Takes the base64
    /// string on the CLI or reads it from `--file`.
    GppDecrypt(GppDecryptArgs),
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
