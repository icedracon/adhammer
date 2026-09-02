//! WS-F — SCCM / SCOM enumeration over LDAP (IronEye competitive absorb).
//!
//! Read-only walks of the System Center footprint that AD publishes:
//!  * `enum sccm` — `CN=System Management,CN=System,<base>`: Management Points,
//!    `mSSMSManagementPoint` objects, site codes, device MPs.
//!  * `enum scom` — `CN=OperationsManager,<base>` (custom schema extension, present only
//!    when SCOM is installed): management servers / gateways / agents.
//!
//! An absent container is reported as "not present" (a clean result), never an error —
//! most directories publish neither. No writes; this is the enumeration foundation for the
//! 1.4.5 SCCM attack chapter (NAA credential extraction).

use adhammer_collector::{Collector, LdapConfig};
use anyhow::Result;
use clap::Parser;

use crate::ui;

#[derive(Parser)]
pub(crate) struct SysCenterArgs {
    /// LDAP URL, e.g. ldaps://dc:636
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub user: String,
    #[arg(long, default_value = "")]
    pub password: adhammer_core::SecretString,
    #[arg(long)]
    pub insecure: bool,
}

async fn connect(a: &mut SysCenterArgs) -> Result<Collector> {
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
        allow_plaintext_bind: false,
    };
    Collector::connect(&cfg).await
}

/// `enum sccm` — enumerate the SCCM footprint under `CN=System Management`.
pub(crate) async fn sccmenum(mut a: SysCenterArgs) -> Result<()> {
    let sp = ui::Spinner::start("connecting + reading CN=System Management");
    let mut c = connect(&mut a).await?;
    let base = format!("CN=System Management,CN=System,{}", c.base_dn());
    let attrs = vec![
        "cn",
        "name",
        "dNSHostName",
        "mSSMSMPName",
        "mSSMSSiteCode",
        "mSSMSDefaultMP",
        "mSSMSDeviceManagementPoint",
        "objectClass",
    ];
    let objs = match c.search_subtree(&base, "(objectClass=*)", attrs).await {
        Ok(v) => v,
        Err(_) => {
            sp.done("CN=System Management not present");
            ui::warn("SCCM System Management container absent → SCCM not published here (clean)");
            return Ok(());
        }
    };
    sp.done(&format!("{} object(s) under System Management", objs.len()));
    let mut mps = 0usize;
    for o in &objs {
        let is_mp = o
            .all("objectClass")
            .iter()
            .any(|k| k.eq_ignore_ascii_case("mSSMSManagementPoint"))
            || o.one("mSSMSMPName").is_some();
        if is_mp {
            mps += 1;
        }
        let host = o
            .one("dNSHostName")
            .or_else(|| o.one("mSSMSMPName"))
            .unwrap_or("-");
        let site = o.one("mSSMSSiteCode").unwrap_or("-");
        let tag = if is_mp { "  [Management Point]" } else { "" };
        println!("  {:<46} host={host:<22} site={site}{tag}", trim_dn(&o.dn));
    }
    ui::ok(&format!(
        "SCCM: {} object(s), {mps} Management Point(s)",
        objs.len()
    ));
    if mps > 0 {
        ui::warn(
            "SCCM present → NAA credential + policy-request surface (foundation for the 1.4.5 SCCM chapter)",
        );
    }
    Ok(())
}

/// `enum scom` — enumerate the SCOM footprint under `CN=OperationsManager` (if the schema is present).
pub(crate) async fn scomenum(mut a: SysCenterArgs) -> Result<()> {
    let sp = ui::Spinner::start("connecting + reading CN=OperationsManager");
    let mut c = connect(&mut a).await?;
    let base = format!("CN=OperationsManager,{}", c.base_dn());
    let attrs = vec!["cn", "name", "dNSHostName", "objectClass"];
    let objs = match c.search_subtree(&base, "(objectClass=*)", attrs).await {
        Ok(v) => v,
        Err(_) => {
            sp.done("CN=OperationsManager not present");
            ui::warn("SCOM container absent → SCOM not installed / schema not extended (clean)");
            return Ok(());
        }
    };
    sp.done(&format!("{} object(s) under OperationsManager", objs.len()));
    for o in &objs {
        let host = o.one("dNSHostName").unwrap_or("-");
        println!("  {:<48} host={host}", trim_dn(&o.dn));
    }
    ui::ok(&format!(
        "SCOM: {} object(s) under CN=OperationsManager",
        objs.len()
    ));
    Ok(())
}

/// Compact a DN to its leaf RDN chain (drop the `DC=` domain tail) for readable output.
fn trim_dn(dn: &str) -> String {
    let leaves: Vec<&str> = dn
        .split(',')
        .take_while(|p| !p.trim().to_ascii_uppercase().starts_with("DC="))
        .collect();
    if leaves.is_empty() {
        dn.to_string()
    } else {
        leaves.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dn_trim_drops_domain_tail() {
        assert_eq!(
            trim_dn("CN=SMS-MP,CN=System Management,CN=System,DC=corp,DC=local"),
            "CN=SMS-MP,CN=System Management,CN=System"
        );
        assert_eq!(trim_dn("DC=corp,DC=local"), "DC=corp,DC=local");
    }
}
