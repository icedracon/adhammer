//! `adhammer doctor` — pure-diagnostic preflight (WS-UX-DOCTOR, 1.5.1 Track A).
//!
//! Zero attack surface. Kills the recurring first-touch support class ("os error
//! 104 / data 52e / which port?") with a ✓/✗ checklist and a **named fix per
//! failure**: DNS SRV DC discovery, TCP reachability of the AD ports, and — only
//! when creds are supplied — a bind attempt whose failure is classified.
//!
//! It deliberately does NOT conclude channel-binding enforcement from `data 52e`
//! alone (52e is invalid-credentials on AD; CBT/signing rejection surfaces separately).
//!
//! **Honest as an automation gate (1.5.1 review fixes):** every probe records a
//! status of `ok` / `warn` / `fail` / `skipped`; the process exits non-zero when a
//! required probe fails *or* when nothing was actually checked ("inconclusive" is not
//! "ready"). TCP probes go through the same SOCKS pivot as the rest of the tool (so
//! `--socks` reachability is truthful), and `--timeout` bounds the bind too — a hostile
//! server can no longer hang the diagnostic. `--json` emits the machine result.

use std::time::Duration;

use anyhow::{bail, Result};
use clap::Parser;
use serde::Serialize;

use crate::attacks::scan_anonymous::dns_srv;
use crate::diag::{bind_fix, classify_bind};
use crate::ui;

#[derive(Parser)]
pub(crate) struct DoctorArgs {
    /// AD / Kerberos realm (e.g. corp.local) — enables DNS SRV discovery of DCs.
    /// `--realm` is a visible alias for operators coming from a Kerberos-world muscle memory
    /// (the doc line uses both terms; SmbAuth/LdapAuth used `--domain` first so we stay
    /// consistent — both names work here).
    #[arg(long, visible_alias = "realm")]
    pub domain: Option<String>,
    /// DC host or IP to probe (also used as the DNS server for SRV lookups).
    #[arg(long)]
    pub dc: Option<String>,
    /// LDAP URL to test a bind against (e.g. ldaps://dc.corp.local:636).
    /// Defaults to `ldaps://<dc>:636` when `--dc` is given.
    #[arg(long)]
    pub url: Option<String>,
    /// Bind username (sAMAccountName or UPN). With `--password`, doctor classifies the bind.
    #[arg(long)]
    pub user: Option<String>,
    /// Bind password. Prefer `@file:/path` or `$ADHAMMER_PASSWORD`.
    #[arg(long)]
    pub password: Option<adhammer_core::SecretString>,
    /// Skip TLS verification for a lab LDAPS bind.
    #[arg(long)]
    pub insecure: bool,
    /// Allow a plaintext-LDAP (389) bind when classifying creds (lab only; sends the
    /// password unencrypted). Mirrors the scan flag so doctor's own fix advice is actionable.
    #[arg(long)]
    pub allow_plaintext_ldap: bool,
    /// Per-probe timeout, seconds. Bounds every probe **and** the bind.
    #[arg(long, default_value_t = 3)]
    pub timeout: u64,
    /// Emit the preflight result as JSON (checks + verdict) instead of the human checklist.
    #[arg(long)]
    pub json: bool,
}

const PORTS: &[(u16, &str)] = &[
    (88, "Kerberos"),
    (389, "LDAP"),
    (445, "SMB"),
    (636, "LDAPS"),
    (3268, "Global Catalog"),
];

/// Outcome of one preflight probe. `Skipped` is explicitly distinct from `Ok` — it means
/// "not checked", never "ready".
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Warn,
    Fail,
    Skipped,
}

#[derive(Serialize)]
struct Check {
    name: String,
    status: Status,
    detail: String,
}

#[derive(Serialize)]
struct DoctorReport {
    checks: Vec<Check>,
    /// Number of probes that actually ran (ok|warn|fail — not skipped).
    ran: usize,
    /// Number of required probes that failed.
    failed: usize,
    /// `"ready"` | `"issues"` | `"inconclusive"`.
    verdict: &'static str,
}

/// TCP reachability **through the active SOCKS pivot** (if `--socks` was set) — the same
/// dialer the rest of the tool uses, so the result reflects the real connection path.
async fn tcp_reach(host: &str, port: u16, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, smb2_client::socks::dial(host, port)).await,
        Ok(Ok(_))
    )
}

/// Extract the host from an `ldap(s)://host[:port][/...]` URL.
fn host_of_url(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let hostport = rest.split('/').next()?;
    let host = hostport
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(hostport);
    (!host.is_empty()).then(|| host.to_string())
}

pub(crate) async fn doctor(a: DoctorArgs) -> Result<()> {
    let to = Duration::from_secs(a.timeout.max(1));
    let mut checks: Vec<Check> = Vec::new();
    let mut rec = |name: &str, status: Status, detail: String| {
        checks.push(Check {
            name: name.to_string(),
            status,
            detail,
        });
    };

    // 1. DNS SRV DC discovery.
    let mut srv_dc: Option<String> = None;
    match (&a.domain, &a.dc) {
        (Some(domain), Some(dc)) => {
            let qname = format!("_ldap._tcp.dc._msdcs.{domain}");
            match dns_srv(dc, &qname).await {
                Some(recs) if !recs.is_empty() => {
                    srv_dc = Some(recs[0].3.trim_end_matches('.').to_string());
                    rec(
                        "dns-srv",
                        Status::Ok,
                        format!("{} DC record(s) for {domain} (via {dc})", recs.len()),
                    );
                }
                _ => rec(
                    "dns-srv",
                    Status::Fail,
                    format!("no {qname} from {dc} — fix: point --dc at a DNS server hosting the AD zone"),
                ),
            }
        }
        (Some(_), None) => rec(
            "dns-srv",
            Status::Skipped,
            "pass --dc <dns-server> (usually the DC) to resolve SRV records".into(),
        ),
        _ => rec(
            "dns-srv",
            Status::Skipped,
            "pass --domain <realm> and --dc <host> to check DC discovery".into(),
        ),
    }

    let target =
        a.dc.clone()
            .or_else(|| srv_dc.clone())
            .or_else(|| a.url.as_deref().and_then(host_of_url));

    // 2. TCP reachability of the AD ports (through the SOCKS pivot if set).
    if let Some(host) = &target {
        for (port, label) in PORTS {
            let name = format!("tcp-{port}");
            if tcp_reach(host, *port, to).await {
                rec(
                    &name,
                    Status::Ok,
                    format!("{host}:{port} ({label}) reachable"),
                );
            } else if *port == 636 {
                rec(&name, Status::Warn, format!(
                    "{host}:636 (LDAPS) closed — fix: --url ldap://{host}:389 --allow-plaintext-ldap (lab) or enroll a DC cert"
                ));
            } else if *port == 3268 {
                rec(
                    &name,
                    Status::Warn,
                    format!("{host}:3268 (Global Catalog) closed — normal on a non-GC DC"),
                );
            } else {
                rec(&name, Status::Fail, format!(
                    "{host}:{port} ({label}) unreachable — fix: check firewall / that the DC role is running"
                ));
            }
        }
    } else {
        rec(
            "tcp",
            Status::Skipped,
            "no target — pass --dc or --url".into(),
        );
    }

    // 3. Optional bind classification — only with creds. Read-only; bounded by --timeout.
    let url = a
        .url
        .clone()
        .or_else(|| a.dc.as_ref().map(|d| format!("ldaps://{d}:636")));
    match (url, &a.user, &a.password) {
        (Some(url), Some(user), Some(password)) => {
            let cfg = adhammer_collector::LdapConfig {
                url,
                bind_dn: user.clone(),
                password: password.clone(),
                base_dn: None,
                insecure: a.insecure,
                gssapi: false,
                allow_plaintext_bind: a.allow_plaintext_ldap,
            };
            match tokio::time::timeout(to, adhammer_collector::Collector::connect(&cfg)).await {
                Ok(Ok(_)) => rec(
                    "ldap-bind",
                    Status::Ok,
                    "success (credentials + transport accepted)".into(),
                ),
                Ok(Err(e)) => {
                    let verdict = classify_bind(&format!("{e:#}"));
                    rec(
                        "ldap-bind",
                        Status::Fail,
                        format!("{verdict:?} — {}", bind_fix(&verdict)),
                    );
                }
                Err(_) => rec(
                    "ldap-bind",
                    Status::Fail,
                    format!("timed out after {}s — a healthy DC binds fast; raise --timeout or suspect a stalling/filtered server", to.as_secs()),
                ),
            }
        }
        _ => rec(
            "ldap-bind",
            Status::Skipped,
            "pass --url (or --dc) + --user + --password to classify a bind".into(),
        ),
    }

    // Tally: `ran` counts non-skipped probes; a required failure OR nothing-checked is non-zero exit.
    let ran = checks
        .iter()
        .filter(|c| c.status != Status::Skipped)
        .count();
    let failed = checks.iter().filter(|c| c.status == Status::Fail).count();
    let verdict = if failed > 0 {
        "issues"
    } else if ran == 0 {
        "inconclusive"
    } else {
        "ready"
    };
    let report = DoctorReport {
        checks,
        ran,
        failed,
        verdict,
    };

    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        ui::header("adhammer doctor — preflight");
        for c in &report.checks {
            let line = format!("{}: {}", c.name, c.detail);
            match c.status {
                Status::Ok => ui::ok(&line),
                Status::Warn => ui::warn(&line),
                Status::Fail => ui::bad(&line),
                Status::Skipped => ui::note(&format!("{} skipped — {}", c.name, c.detail)),
            }
        }
        match verdict {
            "ready" => ui::ok("preflight clean — the target looks ready for scan/enum"),
            "issues" => {
                ui::warn("preflight found issues — address the fix lines above before scanning")
            }
            _ => ui::warn(
                "preflight inconclusive — nothing was actually checked (pass a target + creds)",
            ),
        }
    }

    // Automation gate: exit 0 only on a real "ready"; non-zero on issues or inconclusive.
    match verdict {
        "ready" => Ok(()),
        "issues" => bail!("doctor: preflight found {failed} failing check(s)"),
        _ => bail!("doctor: preflight inconclusive — nothing was checked"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_url_parses() {
        assert_eq!(
            host_of_url("ldaps://dc.corp.local:636").as_deref(),
            Some("dc.corp.local")
        );
        assert_eq!(host_of_url("ldap://10.0.0.1").as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn verdict_tally() {
        // ran>0 + no fail => ready; any fail => issues; all skipped => inconclusive.
        let ok = [Status::Ok, Status::Warn, Status::Skipped];
        let ran = ok.iter().filter(|s| **s != Status::Skipped).count();
        let failed = ok.iter().filter(|s| **s == Status::Fail).count();
        assert_eq!((ran, failed), (2, 0));
        let allskip = [Status::Skipped, Status::Skipped];
        assert_eq!(allskip.iter().filter(|s| **s != Status::Skipped).count(), 0);
    }
}
