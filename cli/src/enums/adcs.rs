//! AD CS enterprise-CA enumeration + active ESC8 web-enrollment probe.

use anyhow::Result;

use crate::enums::dns::DnsArgs;
use crate::enums::net::esc8_probe;
use crate::ui;

/// Enumerate enterprise CAs and actively check each for ESC8 web-enrollment exposure. ESC8 is
/// relay-only, so it can't be decided from the passive LDAP snapshot — this probes the CA host.
pub(crate) async fn adcsenum(a: DnsArgs) -> Result<()> {
    use adhammer_collector::{Collector, LdapConfig};
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
        allow_plaintext_bind: false,
    };
    let sp = ui::Spinner::start("enumerating enterprise CAs");
    let mut c = Collector::connect(&cfg).await?;
    let cas = c.read_cas().await?;
    sp.done(&format!("{} enterprise CA(s) found", cas.len()));
    if cas.is_empty() {
        ui::warn("no enterprise CA found in the forest");
        return Ok(());
    }
    ui::header("AD CS — Certification Authorities");
    let mut esc8 = 0usize;
    for (name, host) in &cas {
        ui::field(
            &format!("CA {name}"),
            &format!("host {}", if host.is_empty() { "?" } else { host }),
        );
        if host.is_empty() {
            continue;
        }
        let sp = ui::Spinner::start(format!("probing {host} web enrollment (ESC8)"));
        let hit = esc8_probe(host).await;
        match hit {
            Some(p) => {
                esc8 += 1;
                sp.done_warn(&p.finding_text);
            }
            None => sp.done(&format!(
                "{host}: ESC8 web enrollment not exposed over http/80"
            )),
        }
    }
    if esc8 > 0 {
        ui::warn(&format!(
            "AD CS: {esc8} ESC8 web-enrollment exposure(s) across {} CA(s)",
            cas.len()
        ));
    } else {
        ui::ok(&format!(
            "AD CS: {} CA(s), no ESC8 web-enrollment exposure",
            cas.len()
        ));
    }
    ui::info("ESC11 (unencrypted ICPR) detection: follow-up — needs a CA config read");
    Ok(())
}
