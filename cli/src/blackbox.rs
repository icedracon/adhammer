//! `adhammer run` — no-credential black-box Phase-0 discovery.
//!
//! WS-FOUNDATION-BLACKBOX-CLI (1.5.0). Turns the hand-rolled DNS resolver
//! (`adhammer_collector::discover_dns`) into an operator-reachable verb:
//! declare the authorized scope + the realm(s) to discover, and get the
//! domain controllers / KDCs / global catalogs the domain's DNS advertises
//! — before any credential lands.
//!
//! Scope discipline is enforced: the operator must declare at least one
//! in-scope include (`--range` / `--host` / `--hostname`); discovered SRV
//! targets outside it (or matching an `--exclude`, which wins across
//! identity forms per BF-3) are dropped, not probed.
//!
//! `--web` composes the `enum web` fingerprint onto every discovered DC
//! IP — the "one binary ties the no-cred flow together" step (DNS
//! discovery → web surface in one command). Consent (`--allow-impact` /
//! `--allow-spoof`) and budget (`--max-hosts` / `--max-duration-secs`)
//! flags land when Impact/PostCred verbs join the chain; DNS discovery
//! + web fingerprint are Discovery-class and always permitted in scope.

use std::net::IpAddr;

use adhammer_core::{EngagementScope, ScopeError, ScopeTarget};
use anyhow::{bail, Context, Result};
use clap::Parser;
use ipnet::IpNet;

#[derive(Parser)]
pub(crate) struct RunArgs {
    /// AD realm to discover via DNS SRV (repeatable). e.g. `--domain corp.local`
    #[arg(long = "domain", required = true)]
    pub domains: Vec<String>,
    /// In-scope CIDR — an authorized network range (repeatable). e.g. `--range 10.0.0.0/24`
    #[arg(long = "range")]
    pub ranges: Vec<String>,
    /// In-scope single host IP (repeatable).
    #[arg(long = "host")]
    pub hosts: Vec<IpAddr>,
    /// In-scope hostname (repeatable).
    #[arg(long = "hostname")]
    pub hostnames: Vec<String>,
    /// Exclude a CIDR / IP / hostname (repeatable). Excludes win over includes,
    /// across every identity form the discovery resolves (BF-3).
    #[arg(long = "exclude")]
    pub excludes: Vec<String>,
    /// DNS server to query (repeatable). Default: system resolvers
    /// (`/etc/resolv.conf` on Unix). On Windows, pass at least one.
    #[arg(long = "dns-server")]
    pub dns_servers: Vec<IpAddr>,
    /// Chain an HTTP(S) web-surface fingerprint on every discovered DC IP
    /// (composes `enum web` into the no-cred flow — flags ESC8 relay
    /// surface, RD Web, ADFS, OWA/EWS, SCCM).
    #[arg(long)]
    pub web: bool,
    /// Per-request timeout (seconds) for the chained web fingerprint.
    #[arg(long, default_value = "5")]
    pub web_timeout: u64,
    /// Emit JSON instead of the human-readable summary.
    #[arg(long)]
    pub json: bool,
}

/// Parse a `--range` / `--exclude` token that may be a CIDR, a bare IP
/// (treated as a /32 or /128 host), or a hostname.
fn parse_scope_token(tok: &str) -> Result<ScopeTarget, ScopeError> {
    if let Ok(net) = tok.parse::<IpNet>() {
        return Ok(ScopeTarget::Cidr { net });
    }
    if let Ok(addr) = tok.parse::<IpAddr>() {
        return Ok(ScopeTarget::Host { addr });
    }
    let target = ScopeTarget::Hostname {
        name: tok.to_string(),
    };
    target.validate()?;
    Ok(target)
}

pub(crate) async fn run(a: RunArgs) -> Result<()> {
    // Build the include set from every scope-bearing flag.
    let mut includes: Vec<ScopeTarget> = Vec::new();
    for r in &a.ranges {
        let net: IpNet = r
            .parse()
            .with_context(|| format!("invalid --range CIDR: {r}"))?;
        includes.push(ScopeTarget::Cidr { net });
    }
    for h in &a.hosts {
        includes.push(ScopeTarget::Host { addr: *h });
    }
    for name in &a.hostnames {
        let t = ScopeTarget::Hostname {
            name: name.to_string(),
        };
        t.validate()
            .with_context(|| format!("invalid --hostname: {name}"))?;
        includes.push(t);
    }
    if includes.is_empty() {
        bail!(
            "no authorized scope declared — pass at least one of \
             --range <cidr>, --host <ip>, or --hostname <name>. \
             Discovery only probes targets you explicitly allow."
        );
    }

    let mut excludes: Vec<ScopeTarget> = Vec::new();
    for e in &a.excludes {
        excludes.push(parse_scope_token(e).with_context(|| format!("invalid --exclude: {e}"))?);
    }

    let domain_hints = a.domains.clone();
    let scope = EngagementScope {
        includes,
        excludes,
        domain_hints,
    };
    scope.validate().context("engagement scope is invalid")?;

    // Nameservers: explicit --dns-server list, else system resolvers.
    let nameservers: Vec<IpAddr> = if a.dns_servers.is_empty() {
        adhammer_collector::system_nameservers()
    } else {
        a.dns_servers.clone()
    };
    if nameservers.is_empty() {
        bail!(
            "no DNS server available — pass --dns-server <ip> (system resolver \
             auto-detection is Unix-only for now; on Windows supply it explicitly)"
        );
    }

    let sp = crate::ui::Spinner::start("resolving AD SRV records (no-cred DNS discovery)");
    let discoveries = adhammer_collector::discover_dns(&scope, &nameservers).await?;
    let total_dc: usize = discoveries.iter().map(|d| d.ldap_dc.len()).sum();
    sp.done(&format!(
        "{} domain(s) probed · {} DC SRV target(s) in scope",
        discoveries.len(),
        total_dc
    ));

    if a.json {
        print_json(&discoveries);
    } else {
        print_human(&discoveries);
    }

    // Composition: chain the web-surface fingerprint on every unique
    // discovered DC IP (the "one binary ties the flow together" step).
    if a.web {
        let mut seen = std::collections::BTreeSet::new();
        for d in &discoveries {
            for t in d
                .ldap_dc
                .iter()
                .chain(&d.kerberos_kdc)
                .chain(&d.global_catalog)
            {
                for addr in &t.addrs {
                    seen.insert(*addr);
                }
            }
        }
        if seen.is_empty() {
            crate::ui::warn("--web: no discovered DC IPs to fingerprint");
        } else {
            println!("\n=== web surface on discovered DCs ===");
            for ip in seen {
                let host = ip.to_string();
                let sp = crate::ui::Spinner::start(format!("web fingerprint {host}"));
                let hits = crate::enums::web::fingerprint_host(&host, a.web_timeout).await;
                sp.done(&format!("{host}: {} endpoint hit(s)", hits.len()));
                for h in &hits {
                    // Only surface interesting (non-404) hits in the compact view.
                    if h.status.contains("404") {
                        continue;
                    }
                    let esc = if crate::enums::web::is_esc8(h) {
                        "  ** ESC8 relay surface **"
                    } else {
                        ""
                    };
                    println!(
                        "    {}://{}:{}{}  {}  [{}]{}",
                        h.scheme,
                        host,
                        h.port,
                        adhammer_core::sanitize_terminal_output(&h.path),
                        adhammer_core::sanitize_terminal_output(&h.status),
                        h.tech,
                        esc
                    );
                }
            }
        }
    }
    Ok(())
}

fn print_human(discoveries: &[adhammer_collector::DnsDiscovery]) {
    if discoveries.is_empty() {
        crate::ui::warn(
            "no domains resolved — check --domain spelling + --dns-server reachability",
        );
        return;
    }
    for d in discoveries {
        println!(
            "\n== {} ==",
            adhammer_core::sanitize_terminal_output(&d.domain)
        );
        print_family("LDAP DC  (_ldap._tcp.dc._msdcs)", &d.ldap_dc);
        print_family("KDC      (_kerberos._tcp)", &d.kerberos_kdc);
        print_family("GC       (_gc._tcp)", &d.global_catalog);
        if !d.reverse.is_empty() {
            println!("  reverse DNS:");
            for r in &d.reverse {
                let names = r
                    .names
                    .iter()
                    .map(|n| adhammer_core::sanitize_terminal_output(n))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("    {}  ->  {}", r.addr, names);
            }
        }
    }
    println!(
        "\nnext: point authenticated verbs at a DC above once creds land \
         (e.g. `adhammer scan --url ldaps://<dc>:636 ...`), or run the \
         anonymous first-touch `adhammer scan --anonymous --url ldap://<dc>:389`."
    );
}

fn print_family(label: &str, targets: &[adhammer_collector::DnsServiceTarget]) {
    if targets.is_empty() {
        return;
    }
    println!("  {label}:");
    for t in targets {
        let addrs = if t.addrs.is_empty() {
            "(no A/AAAA)".to_string()
        } else {
            t.addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "    {}:{}  prio={} weight={}  [{}]",
            adhammer_core::sanitize_terminal_output(&t.hostname),
            t.port,
            t.priority,
            t.weight,
            addrs
        );
    }
}

fn print_json(discoveries: &[adhammer_collector::DnsDiscovery]) {
    // Hand-built JSON to avoid a serde derive on the collector types +
    // keep the wire shape stable + operator-obvious. Values are DNS-
    // derived, so run each through the terminal sanitizer before quoting.
    let mut out = String::from("{\"domains\":[");
    for (i, d) in discoveries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"domain\":{},\"ldap_dc\":{},\"kerberos_kdc\":{},\"global_catalog\":{},\"reverse\":{}}}",
            json_str(&d.domain),
            json_targets(&d.ldap_dc),
            json_targets(&d.kerberos_kdc),
            json_targets(&d.global_catalog),
            json_reverse(&d.reverse),
        ));
    }
    out.push_str("]}");
    println!("{out}");
}

fn json_str(s: &str) -> String {
    // Sanitize DNS-derived text, then JSON-escape quotes/backslashes/controls.
    let clean = adhammer_core::sanitize_terminal_output(s);
    let mut q = String::with_capacity(clean.len() + 2);
    q.push('"');
    for c in clean.chars() {
        match c {
            '"' => q.push_str("\\\""),
            '\\' => q.push_str("\\\\"),
            c if (c as u32) < 0x20 => q.push_str(&format!("\\u{:04x}", c as u32)),
            c => q.push(c),
        }
    }
    q.push('"');
    q
}

fn json_targets(targets: &[adhammer_collector::DnsServiceTarget]) -> String {
    let mut s = String::from("[");
    for (i, t) in targets.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let addrs = t
            .addrs
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(",");
        s.push_str(&format!(
            "{{\"hostname\":{},\"port\":{},\"priority\":{},\"weight\":{},\"addrs\":[{}]}}",
            json_str(&t.hostname),
            t.port,
            t.priority,
            t.weight,
            addrs
        ));
    }
    s.push(']');
    s
}

fn json_reverse(reverse: &[adhammer_collector::ReverseDnsRecord]) -> String {
    let mut s = String::from("[");
    for (i, r) in reverse.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let names = r
            .names
            .iter()
            .map(|n| json_str(n))
            .collect::<Vec<_>>()
            .join(",");
        s.push_str(&format!(
            "{{\"addr\":\"{}\",\"names\":[{}]}}",
            r.addr, names
        ));
    }
    s.push(']');
    s
}
