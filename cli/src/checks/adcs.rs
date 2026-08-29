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
///
/// **1.4.8 WS-CHECK-STAGES**: wraps the impl in a `StageChecklist` so the
/// end-of-run card breaks the pipeline into `ldap connect → collect templates →
/// rule pack → render`, matching the shape every `attack` verb already renders
/// per 1.4.6. Silent in `--json` mode (machine consumers get the raw JSON
/// envelope only, no diagnostic chrome).
pub(crate) async fn check_adcs(a: CheckAdcsArgs) -> Result<()> {
    let mut checklist = crate::ui::StageChecklist::new([
        "ldap connect",
        "collect templates",
        "rule pack (ESC1-15)",
        "render findings",
    ]);
    let result = check_adcs_impl(a, &mut checklist).await;
    // StageChecklist prints to stderr; JSON findings (if `--json`) go to stdout.
    // Rendering both is safe — captures that redirect only `>` (stdout) stay clean.
    match &result {
        Ok(()) => checklist.render("check adcs stages"),
        Err(_) => checklist.render("check adcs stages (failed)"),
    }
    result
}

async fn check_adcs_impl(
    a: CheckAdcsArgs,
    checklist: &mut crate::ui::StageChecklist,
) -> Result<()> {
    let json = a.json;
    let cfg = LdapConfig {
        url: a.auth.url.clone(),
        bind_dn: a.auth.user.clone(),
        password: a.auth.password.clone(),
        base_dn: None,
        insecure: a.auth.insecure,
        gssapi: false,
    };
    let collector = match Collector::connect(&cfg).await {
        Ok(c) => c,
        Err(e) => {
            checklist.mark_current_failed(format!("{e:#}"));
            return Err(e.into());
        }
    };
    checklist.record_ok("ldap connect", a.auth.url.clone());

    let snap = match collector.collect().await {
        Ok(s) => s,
        Err(e) => {
            checklist.mark_current_failed(format!("{e:#}"));
            return Err(e.into());
        }
    };
    let templates =
        adhammer_collector::sources::adcs::templates_from(snap.objects.iter().collect::<Vec<_>>());
    checklist.record_ok(
        "collect templates",
        format!("{} template(s)", templates.len()),
    );

    let findings = adhammer_checks::rules::esc::detect_all(&templates);
    checklist.record_ok(
        "rule pack (ESC1-15)",
        format!("{} finding(s)", findings.len()),
    );

    if json {
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
    checklist.record_ok("render findings", if json { "json" } else { "text" });
    Ok(())
}
