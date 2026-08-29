//! `enum krb-users` — Kerberos user enumeration via pre-auth-less AS-REQ.
//!
//! **1.4.8-A WS-KERBRUTE.** No credentials needed. Sends a raw AS-REQ per
//! candidate name and classifies the KDC's response per RFC 4120 §7.5.9:
//!
//! - `KDC_ERR_PREAUTH_REQUIRED` (25) → **user exists** (normal path — pre-auth
//!   enforced, no AS-REP without PA-ENC-TIMESTAMP)
//! - `KDC_ERR_PREAUTH_FAILED` (24) → **user exists** (KDC recorded a prior
//!   bad-pw attempt against this same name, still leaks existence)
//! - `KDC_ERR_CLIENT_REVOKED` (18) → **user exists** but disabled/locked
//! - AS-REP returned → **user exists AND is AS-REP-roastable** (account has
//!   `DONT_REQ_PREAUTH`); operator can pipe to `attack roast` for the hash
//! - `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6) → **user does NOT exist**
//! - anything else → shown with the raw KDC error code
//!
//! Two input modes: `--user <sam>` for a single name, or `--userlist <path>`
//! for a newline-separated file. Comments (`#`) and blank lines skipped.

use adhammer_kerberos::{kerbrute_probe, KerbruteOutcome};
use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct KrbArgs {
    /// Kerberos realm, e.g. `TESTLAB.LOCAL`. Case matters per RFC 4120.
    #[arg(long)]
    pub realm: String,
    /// KDC host (usually the DC). `host` or `host:port`; default port 88.
    #[arg(long)]
    pub kdc: String,
    /// Probe a single username. Mutually exclusive with `--userlist`.
    #[arg(long, conflicts_with = "userlist")]
    pub user: Option<String>,
    /// Newline-separated file of candidate sAMAccountNames. `#` comments and
    /// blank lines are skipped. Mutually exclusive with `--user`.
    #[arg(long, value_name = "PATH", conflicts_with = "user")]
    pub userlist: Option<String>,
}

pub(crate) async fn krbenum(a: KrbArgs) -> Result<()> {
    let names = load_names(&a)?;
    if names.is_empty() {
        bail!("no usernames supplied — pass --user <sam> or --userlist <path>");
    }

    let mut checklist =
        crate::ui::StageChecklist::new(["resolve inputs", "probe KDC", "classify + report"]);
    checklist.record_ok("resolve inputs", format!("{} candidate(s)", names.len()));

    let mut exists = 0usize;
    let mut roastable = 0usize;
    let mut locked = 0usize;
    let mut missing = 0usize;
    let mut other = 0usize;
    let mut errors = 0usize;

    for name in &names {
        match kerbrute_probe(name, &a.realm, &a.kdc).await {
            Ok(KerbruteOutcome::Exists) => {
                exists += 1;
                println!("[+] EXISTS      {}@{}", name, a.realm);
            }
            Ok(KerbruteOutcome::Roastable) => {
                roastable += 1;
                println!(
                    "[!] ROASTABLE   {}@{}   → adhammer attack roast --user {} --realm {} --kdc {}",
                    name, a.realm, name, a.realm, a.kdc
                );
            }
            Ok(KerbruteOutcome::Locked) => {
                locked += 1;
                println!(
                    "[+] LOCKED      {}@{}   (exists, disabled/revoked)",
                    name, a.realm
                );
            }
            Ok(KerbruteOutcome::Missing) => {
                missing += 1;
                // Suppress by default — noisy on large lists. Comment-in for verbose runs.
                tracing::debug!(name, "user does not exist");
            }
            Ok(KerbruteOutcome::Other(code)) => {
                other += 1;
                println!(
                    "[?] OTHER       {}@{}   KDC error code {}",
                    name, a.realm, code
                );
            }
            Err(e) => {
                errors += 1;
                tracing::warn!(name, "kerbrute probe error: {e:#}");
            }
        }
    }
    checklist.record_ok(
        "probe KDC",
        format!(
            "{} probed → {} exists · {} roastable · {} locked · {} missing · {} other · {} err",
            names.len(),
            exists,
            roastable,
            locked,
            missing,
            other,
            errors
        ),
    );
    checklist.record_ok(
        "classify + report",
        format!("{} confirmed present", exists + roastable + locked),
    );
    checklist.render("enum krb-users stages");
    Ok(())
}

fn load_names(a: &KrbArgs) -> Result<Vec<String>> {
    if let Some(u) = &a.user {
        return Ok(vec![u.trim().to_string()]);
    }
    let path = a
        .userlist
        .as_ref()
        .expect("clap enforces --user or --userlist");
    let text = std::fs::read_to_string(path).with_context(|| format!("read --userlist {path}"))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}
