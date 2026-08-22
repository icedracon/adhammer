//! `check adcs` — run the ms-crtd ESC1-15 rule pack over `pKICertificateTemplate`
//! objects collected from LDAP. Complements `scan` — no ACL walk, just the
//! template-shape checks straight out of `ms-crtd::detect_esc`.

use adhammer_collector::{Collector, LdapConfig};
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct CheckAdcsArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::LdapAuth,
    /// Emit findings as JSON (default: human-readable).
    #[arg(long)]
    pub json: bool,
}

/// `check adcs` — pull every `pKICertificateTemplate` from the domain, run the
/// `ms-crtd` ESC1-15 rule pack over the typed view, and emit adhammer `Finding`s.
/// Offline pass — no ACL walk, no CA registry probe, no active enrollment; the
/// exhaustive ESC pipeline is `adhammer scan` (which fires the parallel
/// `A-AdcsEsc` rule alongside the graph-based paths).
pub(crate) async fn check_adcs(a: CheckAdcsArgs) -> Result<()> {
    let cfg = LdapConfig {
        url: a.auth.url.clone(),
        bind_dn: a.auth.user.clone(),
        password: a.auth.password.clone(),
        base_dn: None,
        insecure: a.auth.insecure,
        gssapi: false,
    };
    let snap = Collector::connect(&cfg).await?.collect().await?;
    let templates =
        adhammer_collector::sources::adcs::templates_from(snap.objects.iter().collect::<Vec<_>>());
    let findings = adhammer_checks::rules::esc::detect_all(&templates);
    if a.json {
        let j = serde_json::to_string_pretty(&findings)?;
        println!("{j}");
    } else {
        println!(
            "== check adcs (ms-crtd ESC rule pack) — {} template(s) scanned, {} finding(s) ==",
            templates.len(),
            findings.len()
        );
        for f in &findings {
            println!(
                "[{:?}] {} — {}\n  affected: {}\n  {}\n",
                f.severity,
                f.id,
                f.title,
                f.affected.join(", "),
                f.detail
            );
        }
    }
    Ok(())
}
