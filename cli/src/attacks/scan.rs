//! `scan` — flagship passive audit: LDAP collect → control-path graph → checks →
//! scored report. Owns `ScanArgs` (embedded by `DcshadowArgs`, reused as-is by
//! `attack roast` and `attack unconstrained`) and the `config(&ScanArgs)` LDAP-
//! config helper.

use adhammer_collector::{Collector, LdapConfig};
use adhammer_graph::ControlGraph;
use adhammer_report::{Report, RiskConfig};
use anyhow::{Context, Result};
use clap::Parser;

use crate::enums::net::esc8_probe;
use crate::{esc_registry, ui};

#[derive(Parser)]
pub(crate) struct ScanArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::LdapAuth,
    /// Base DN (defaults to RootDSE defaultNamingContext)
    #[arg(long)]
    pub base_dn: Option<String>,
    /// Output format for `scan`: `json` (default) or `html`. When `--out <path>` is
    /// set the format is auto-inferred from the file extension (`.json` / `.html` /
    /// `.zip` → BloodHound-CE bundle); this flag overrides that inference.
    #[arg(long, default_value = "json", value_parser = ["json", "html"])]
    pub format: String,
    /// Write the report to `<path>` instead of stdout. Format is inferred from the
    /// extension: `.json` → JSON, `.html` → HTML, `.zip` → BloodHound-CE ingest
    /// bundle. Pass `--format` to override the inference. Tracing / diagnostics
    /// still go to stderr, so stdout stays capture-clean for scripting.
    #[arg(long)]
    pub out: Option<String>,
    /// KDC `host[:port]` for `roast` to actually AS-REP roast (omit = list candidates only)
    #[arg(long)]
    pub kdc: Option<String>,
    /// SYSVOL path for `scan` to hunt GPP cpasswords, e.g. \\corp.local\SYSVOL
    #[arg(long)]
    pub sysvol: Option<String>,
    /// SASL GSSAPI bind (signed LDAP over 389 via ambient Kerberos; needs `--features gssapi`)
    #[arg(long)]
    pub gssapi: bool,
    /// **Deprecated in favour of `--out <path.zip>`.** Also export the collected
    /// domain as a BloodHound .zip at this path (BloodHound CE v5 ingest JSON).
    /// Will be removed in 1.5.0.
    #[arg(long)]
    pub bloodhound: Option<String>,
}

pub(crate) fn config(a: &ScanArgs) -> LdapConfig {
    LdapConfig {
        url: a.auth.url.clone(),
        bind_dn: a.auth.user.clone(),
        password: a.auth.password.clone(),
        base_dn: a.base_dn.clone(),
        insecure: a.auth.insecure,
        gssapi: a.gssapi,
    }
}

async fn esc_registry_probe(
    host: &str,
    domain: &str,
    user: &str,
    password: &str,
    ca_names: &[String],
) -> Result<Vec<adhammer_core::Finding>> {
    use dcerpc::rrp::RegistryClient;
    use smb2_client::SmbClient;

    let mut smb = SmbClient::connect(host).await?;
    smb.login(host, domain, user, password).await?;
    smb.tree_connect(&format!("\\\\{host}\\IPC$")).await?;
    let mut reg = RegistryClient::connect(&mut smb, domain, user, password, host).await?;

    let mut all = Vec::new();
    for ca in ca_names {
        all.extend(esc_registry::probe_esc_registry(&mut reg, ca).await);
    }
    Ok(all)
}

pub(crate) async fn scan(a: ScanArgs) -> Result<()> {
    let sp = ui::Spinner::start("collecting AD objects over LDAP");
    let snap = Collector::connect(&config(&a)).await?.collect().await?;
    sp.done(&format!("{} AD object(s) collected", snap.objects.len()));
    tracing::info!(objects = snap.objects.len(), "collected");

    let graph = ControlGraph::build(&snap);
    let stats = graph.stats();
    let paths = graph.paths_to_tier0();
    let mut findings = adhammer_checks::run_all(&snap, &graph);
    {
        let crit = findings
            .iter()
            .filter(|f| matches!(f.severity, adhammer_core::finding::Severity::Critical))
            .count();
        ui::ok(&format!(
            "{} finding(s) ({crit} critical) · {} control-path(s) to Tier-0",
            findings.len(),
            paths.len()
        ));
    }

    // The cheapest routes, hop by hop, with the command that walks each hop. A hop with no
    // executor is printed as such rather than silently skipped.
    for p in paths.iter().take(5) {
        eprintln!("\n[>] {} (cost {})", p.render(), p.cost);
        for (i, s) in p.steps.iter().enumerate() {
            match &s.command {
                Some(c) => eprintln!("    {}. {:<26} {}", i + 1, s.edge, c),
                None => eprintln!("    {}. {:<26} (detection only)", i + 1, s.edge),
            }
            eprintln!("       fix: {}", s.mitigation);
        }
    }

    // Optional BloodHound export (BloodHound CE v5 ingest .zip) alongside the report.
    // Two paths: the DEPRECATED --bloodhound flag (kept working through 1.4.x for one
    // release cycle) and the new --out=<path>.zip auto-inference. --bloodhound wins if
    // both are set so scripts that already know their zip path don't silently overwrite.
    if let Some(path) = &a.bloodhound {
        eprintln!(
            "[!] `--bloodhound <path>` is DEPRECATED and will be removed in 1.5.0. Use \
             `--out <path.zip>` instead — the .zip extension routes to the BloodHound-CE bundle \
             writer automatically."
        );
        let p = std::path::Path::new(path);
        let n = adhammer_bloodhound::export_zip(&snap, p)?;
        eprintln!("[+] BloodHound export: {} JSON files → {}", n, p.display());
    } else if let Some(path) = &a.out {
        // --out routing: infer BloodHound bundle from a .zip extension. Non-.zip
        // extensions defer to the report-render path below (json / html).
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ext == "zip" {
            let p = std::path::Path::new(path);
            let n = adhammer_bloodhound::export_zip(&snap, p)?;
            eprintln!("[+] BloodHound export: {} JSON files → {}", n, p.display());
        }
    }

    // ESC registry probe: ESC6/7/10/11/16 via MS-RRP over the DC's Remote Registry.
    // Runs automatically when a CA is discovered in the LDAP snapshot. Best-effort — if the
    // Remote Registry service is stopped the scan still completes with passive findings only.
    {
        let ca_names: Vec<String> = snap
            .iter_class("pKIEnrollmentService")
            .filter_map(|o| o.one("cn").or_else(|| o.one("name")).map(|s| s.to_string()))
            .collect();
        if !ca_names.is_empty() {
            let host = a
                .auth
                .url
                .split("://")
                .nth(1)
                .unwrap_or(&a.auth.url)
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .to_string();
            let domain = snap.domain.netbios.clone().unwrap_or_else(|| {
                snap.domain
                    .domain_dn
                    .split(',')
                    .find_map(|p| {
                        p.trim()
                            .strip_prefix("DC=")
                            .or_else(|| p.trim().strip_prefix("dc="))
                    })
                    .unwrap_or("")
                    .to_uppercase()
            });
            let user = a
                .auth
                .user
                .split('@')
                .next()
                .and_then(|s| s.split('\\').next_back())
                .unwrap_or(&a.auth.user)
                .to_string();
            let sp = ui::Spinner::start("ESC registry probe (MS-RRP)");
            match esc_registry_probe(&host, &domain, &user, &a.auth.password, &ca_names).await {
                Ok(esc_findings) => {
                    let n = esc_findings.len();
                    findings.extend(esc_findings);
                    if n > 0 {
                        sp.done(&format!(
                            "{n} registry-based ESC finding(s) (ESC6/7/10/11/16)"
                        ));
                    } else {
                        sp.done("no registry-based ESC exposure");
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("0xc00000ac") || msg.contains("winreg") {
                        sp.done_warn(
                            "Remote Registry unavailable — ESC6/7/10/11/16 skipped (passive checks unaffected)",
                        );
                    } else {
                        sp.done_warn(&format!("ESC registry probe failed: {e:#}"));
                    }
                }
            }
        }
    }

    // ESC8 web-enrollment probe: check each CA host for HTTP NTLM relay exposure.
    {
        let ca_hosts: Vec<String> = snap
            .iter_class("pKIEnrollmentService")
            .filter_map(|o| o.one("dNSHostName").map(|s| s.to_string()))
            .filter(|h| !h.is_empty())
            .collect();
        for host in &ca_hosts {
            if let Some(_detail) = esc8_probe(host).await {
                findings.push(adhammer_core::Finding {
                    id: "A-Esc8".into(),
                    title: format!(
                        "ESC8: web enrollment at http://{host}/certsrv exposes NTLM (relayable)"
                    ),
                    category: adhammer_core::finding::Category::Anomalies,
                    severity: adhammer_core::finding::Severity::Critical,
                    mitre: vec![adhammer_core::finding::mitre::CERT_ABUSE],
                    affected: vec![host.clone()],
                    detail: format!(
                        "The CA at {host} exposes HTTP web enrollment with NTLM authentication \
                         over cleartext — a coerced machine's NTLM can be relayed for a cert, \
                         then PKINIT'd for that machine's TGT."
                    ),
                    impact: Some(
                        "Attacker coerces a DC (PetitPotam/PrinterBug), relays its NTLM to \
                         the web enrollment endpoint, obtains a machine cert, PKINITs for the \
                         DC's TGT, then DCSync. Full domain compromise from any authenticated user."
                            .into(),
                    ),
                    remediation:
                        "Disable HTTP web enrollment or require HTTPS + Extended Protection (EPA); \
                         enforce SMB/LDAP signing to blunt the relay."
                            .into(),
                    weight_bonus: 30,
                });
            }
        }
    }

    // Optional SYSVOL sweep: GPP cpasswords (MS14-025) + default-policy signing/NTLM.
    if let Some(sysvol) = &a.sysvol {
        let root = std::path::Path::new(sysvol);
        let hits = adhammer_sysvol::scan(root);
        tracing::info!(gpp = hits.len(), "sysvol GPP swept");
        if let Some(f) = adhammer_sysvol::finding(&hits) {
            findings.insert(0, f);
        }
        let policy = adhammer_sysvol::gptmpl::scan_policy(root);
        findings.extend(adhammer_sysvol::gptmpl::policy_findings(&policy));
    }

    let report = Report::build(
        &snap.domain.domain_dn,
        findings,
        paths,
        stats,
        &RiskConfig::default(),
    );

    // Resolve output format + destination.
    //
    // Order of precedence:
    //   1. --format explicit                        → wins over any inference
    //   2. --out=<path>.{json,html,zip} inference   → picks format from extension
    //   3. default --format json                    → stdout
    //
    // .zip via --out is already handled above (BloodHound-CE bundle). Here we only
    // route the JSON/HTML report body.
    let explicit_format = std::env::args().any(|a| a == "--format");
    let format = if explicit_format {
        a.format.clone()
    } else if let Some(path) = &a.out {
        match std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref()
        {
            Some("html") => "html".to_string(),
            Some("zip") => {
                // .zip already written; nothing to serialise here.
                return Ok(());
            }
            _ => "json".to_string(),
        }
    } else {
        a.format.clone()
    };

    let body = match format.as_str() {
        "html" => report.to_html(),
        _ => report.to_json(),
    };

    match &a.out {
        Some(path) if path != "-" => {
            std::fs::write(path, &body).with_context(|| format!("write scan report → {path}"))?;
            eprintln!(
                "[+] {} report written → {} ({} bytes)",
                format,
                path,
                body.len()
            );
        }
        _ => {
            println!("{body}");
        }
    }
    Ok(())
}
