//! ADIDNS enumeration over LDAP (adidnsdump-equivalent).

use anyhow::Result;
use clap::Parser;

use crate::ui;

#[derive(Parser)]
pub(crate) struct DnsArgs {
    /// LDAP URL, e.g. ldap://dc:389 or ldaps://dc:636
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub user: String,
    #[arg(long, default_value = "")]
    pub password: adhammer_core::SecretString,
    #[arg(long)]
    pub insecure: bool,
}

/// Enumerate AD-integrated DNS over LDAP (adidnsdump-equivalent): list every zone + record from
/// the DomainDnsZones/ForestDnsZones partitions, and flag wildcard nodes — a wildcard (or any
/// writable node) turns ADIDNS into a mitm6 / WPAD name-hijack primitive.
pub(crate) async fn dnsenum(mut a: DnsArgs) -> Result<()> {
    use adhammer_collector::{Collector, LdapConfig};
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    let sp = ui::Spinner::start("connecting + reading ADIDNS zones");
    let mut c = Collector::connect(&cfg).await?;
    let zones = c.read_adidns().await?;
    sp.done(&format!("{} ADIDNS zone(s) read", zones.len()));
    if zones.is_empty() {
        ui::warn("no ADIDNS zones readable");
        return Ok(());
    }
    let (mut total, mut wildcards) = (0usize, 0usize);
    for z in &zones {
        ui::header(&format!("{} ({} records)", z.name, z.records.len()));
        for r in &z.records {
            total += 1;
            let wild = r.node == "*";
            if wild {
                wildcards += 1;
            }
            let mut tags = String::new();
            if wild {
                tags.push_str(&format!("  {}", ui::accent("◄ WILDCARD")));
            }
            if r.tombstoned {
                tags.push_str(&format!("  {}", ui::dim("(tombstoned)")));
            }
            println!(
                "  {:<28} {} {}{}",
                r.node,
                ui::dim(&format!("{:<6}", r.rtype)),
                r.data,
                tags
            );
        }
    }
    ui::ok(&format!(
        "ADIDNS: {} zone(s), {total} record(s), {wildcards} wildcard(s)",
        zones.len()
    ));
    if wildcards > 0 {
        ui::warn("wildcard record present → ADIDNS/mitm6-style name-hijack surface");
    }
    Ok(())
}
