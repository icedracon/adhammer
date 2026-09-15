//! **1.5.2 H-F**: `enum ldap-info` — no-cred anonymous RootDSE fingerprint.
//!
//! Every AD DC serves RootDSE anonymously by design (RFC 4511 §4.4). This
//! verb makes that one probe a first-class first-touch command: SASL mechs
//! offered, functional levels, whether the DC is synchronized to a replica,
//! how many extended controls it supports, and the `ldapServiceName` that
//! reveals the realm short-name and the DC computer account.
//!
//! Zero credentials, zero side effects. Fast fallback when
//! `scan --anonymous` is more surface than the engagement needs.
//! Complements [`crate::doctor`] (transport-level checks) with
//! LDAP-content facts. Heavy lifting lives in
//! [`adhammer_collector::read_rootdse_rich`].

use adhammer_collector::{read_rootdse_rich, RootDseRich};
use anyhow::Result;
use clap::Parser;
use serde_json::json;

#[derive(Parser)]
pub(crate) struct LdapInfoArgs {
    /// LDAP(S) URL of the target DC, e.g. `ldaps://dc.corp.local` or
    /// `ldap://10.0.0.10`. LDAPS on 636 is preferred; 389 works when the DC
    /// still accepts anonymous simple binds (RootDSE stays readable either way
    /// on standard AD deployments).
    #[arg(long)]
    pub url: String,
    /// Accept a self-signed / hostname-mismatched TLS certificate — the lab
    /// / self-signed CA path. Same flag semantics as `doctor --insecure`.
    #[arg(long)]
    pub insecure: bool,
    /// Emit JSON instead of the human summary. `AttackResult`-shaped envelope
    /// with the full RootDSE payload under `evidence`.
    #[arg(long)]
    pub json: bool,
}

pub(crate) async fn ldap_info(a: LdapInfoArgs) -> Result<()> {
    let sp = crate::ui::Spinner::start(format!("anonymous RootDSE probe → {}", a.url));

    let dse = match read_rootdse_rich(&a.url, a.insecure).await {
        Ok(d) => d,
        Err(e) => {
            sp.done_warn(&format!("RootDSE probe failed: {e}"));
            return Err(e);
        }
    };

    sp.done(&format!(
        "RootDSE served — realm {}",
        dse.realm_short.as_deref().unwrap_or("<unknown>")
    ));

    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "command": "adhammer enum ldap-info",
                "success": true,
                "evidence": dse,
            }))?
        );
    } else {
        print_human(&dse);
        eprintln!();
        eprintln!(
            "next: authenticated preflight — `adhammer doctor --url {url} --user <u> --password env:ADHAMMER_PASSWORD`",
            url = a.url
        );
    }
    Ok(())
}

fn print_human(d: &RootDseRich) {
    let line = |k: &str, v: &str| {
        if !v.is_empty() {
            eprintln!("  {k:<26} {v}");
        }
    };
    eprintln!();
    eprintln!("== RootDSE ==");
    line("dnsHostName", d.dns_host.as_deref().unwrap_or(""));
    line(
        "ldapServiceName",
        d.ldap_service_name.as_deref().unwrap_or(""),
    );
    line("realm (derived)", d.realm_short.as_deref().unwrap_or(""));
    line(
        "DC account (derived)",
        d.dc_account.as_deref().unwrap_or(""),
    );
    line(
        "defaultNamingContext",
        d.default_nc.as_deref().unwrap_or(""),
    );
    line(
        "rootDomainNamingContext",
        d.root_domain_nc.as_deref().unwrap_or(""),
    );
    line(
        "configurationNamingContext",
        d.configuration_nc.as_deref().unwrap_or(""),
    );
    line("isSynchronized", d.is_synchronized.as_deref().unwrap_or(""));
    line(
        "isGlobalCatalogReady",
        d.is_global_catalog_ready.as_deref().unwrap_or(""),
    );
    line(
        "domainFunctionality",
        d.domain_functionality.as_deref().unwrap_or(""),
    );
    line(
        "forestFunctionality",
        d.forest_functionality.as_deref().unwrap_or(""),
    );
    line(
        "dcFunctionality",
        d.domain_controller_functionality.as_deref().unwrap_or(""),
    );
    line(
        "highestCommittedUSN",
        d.highest_committed_usn.as_deref().unwrap_or(""),
    );
    line("currentTime", d.current_time.as_deref().unwrap_or(""));
    eprintln!(
        "  supportedControl           {} OID(s)",
        d.supported_controls
    );
    eprintln!(
        "  supportedCapabilities      {} OID(s)",
        d.supported_capabilities
    );
    eprintln!(
        "  supportedLDAPVersion       {}",
        d.supported_ldap_version.join(", ")
    );
    if !d.sasl.is_empty() {
        eprintln!("  supportedSASLMechanisms    {}", d.sasl.join(", "));
    }
    if !d.naming_contexts.is_empty() {
        eprintln!("  namingContexts ({}):", d.naming_contexts.len());
        for nc in &d.naming_contexts {
            eprintln!("    · {nc}");
        }
    }
}
