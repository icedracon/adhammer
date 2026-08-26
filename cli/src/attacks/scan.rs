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
    /// Output format for `scan`: `json` (default), `html`, `md`, or `txt`.
    /// When `--out <path>` is set the format is auto-inferred from the file
    /// extension (`.json` / `.html` / `.md` / `.txt` / `.zip` → BloodHound-CE
    /// bundle); this flag overrides that inference.
    #[arg(long, default_value = "json", value_parser = ["json", "html", "md", "txt"])]
    pub format: String,
    /// Write the report to `<path>` instead of stdout. Format is inferred from
    /// the extension: `.json` → JSON, `.html` → HTML, `.md` → Markdown,
    /// `.txt` → plaintext summary, `.zip` → BloodHound-CE ingest bundle. Pass
    /// `--format` to override the inference. Tracing / diagnostics still go
    /// to stderr, so stdout stays capture-clean for scripting.
    #[arg(long)]
    pub out: Option<String>,
    /// Write ALL four report formats (json + md + html + txt summary) into
    /// `<dir>` in a single pass: `report.json`, `report.md`, `report.html`,
    /// `report-summary.txt`. Complements `--out <path>` (single-file); pass
    /// only one of the two.
    #[arg(long, value_name = "DIR")]
    pub out_all: Option<String>,
    /// Number of findings included in the plaintext `report-summary.txt`
    /// (highest-scored first). Only affects the plaintext emitter.
    #[arg(long, default_value_t = 10)]
    pub top_n: usize,
    /// Anonymous fingerprint mode — skip the authenticated LDAP collection and
    /// run port scan + RootDSE fingerprint + null-session SMB probe + SRV
    /// enumeration against the target. Useful as the first-touch step in an
    /// engagement before creds are available. No `--user` / `--password` is
    /// consulted; `--url` still selects the target host.
    #[arg(long)]
    pub anonymous: bool,
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
    /// WS-19: compare this scan against a prior scan's JSON report at `<path>` and tag findings
    /// NEW / RESOLVED / SEVERITY-CHANGED (keyed by rule id + affected object). Adds a
    /// `baseline_diff` object to the JSON report and a "Baseline diff" section to md/html/txt.
    /// A missing or unparsable baseline is a warning, not a hard error — the scan still emits.
    #[arg(long, value_name = "PRIOR_JSON")]
    pub baseline: Option<String>,
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

pub(crate) async fn esc_registry_probe(
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
    if a.anonymous {
        return scan_anonymous(a).await;
    }

    let sp = ui::Spinner::start("collecting AD objects over LDAP");
    let snap = Collector::connect(&config(&a)).await?.collect().await?;
    sp.done(&format!("{} AD object(s) collected", snap.objects.len()));
    tracing::info!(objects = snap.objects.len(), "collected");

    let graph = ControlGraph::build(&snap);
    let stats = graph.stats();
    let paths = graph.paths_to_tier0();
    // WS-R2: run every check with per-check coverage so the report can show the whole audit
    // surface (tripped vs clean), then flatten to the scored finding list the rest expects.
    let coverage_raw = adhammer_checks::run_all_with_coverage(&snap, &graph);
    let coverage: Vec<(&'static str, usize)> = coverage_raw
        .iter()
        .map(|(id, fs)| (*id, fs.len()))
        .collect();
    let mut findings: Vec<_> = coverage_raw.into_iter().flat_map(|(_, fs)| fs).collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.score()));
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
            if let Some(probe) = esc8_probe(host).await {
                findings.push(adhammer_core::Finding {
                    id: "A-Esc8".into(),
                    title: format!(
                        "ESC8: web enrollment at http://{host}/certsrv exposes NTLM (relayable)"
                    ),
                    category: adhammer_core::finding::Category::Anomalies,
                    severity: adhammer_core::finding::Severity::Critical,
                    mitre: vec![adhammer_core::finding::mitre::CERT_ABUSE],
                    affected: vec![host.clone()],
                    evidence: vec![adhammer_core::Evidence::new(
                        format!("HTTP {host}/certsrv (ESC8 probe)"),
                        probe.finding_text.clone(),
                    )],
                    // WS-WPT session 4: the actual GET/response transcript that produced this finding.
                    exchange: probe.wire,
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

    let mut report = Report::build(
        &snap.domain.domain_dn,
        findings,
        paths,
        stats,
        &RiskConfig::default(),
    )
    .with_coverage(coverage);

    // WS-19: baseline diff. Read a prior scan's JSON and tag NEW / RESOLVED / SEVERITY-CHANGED.
    // Best-effort: a missing/unparsable baseline warns to stderr and the scan still emits.
    if let Some(path) = &a.baseline {
        match std::fs::read_to_string(path) {
            Ok(prior) => {
                match adhammer_report::BaselineDiff::compute(&prior, &report.findings, path) {
                    Ok(diff) => {
                        ui::ok(&format!(
                        "baseline diff vs {path}: +{} new / -{} resolved / ~{} severity-changed",
                        diff.summary.new, diff.summary.resolved, diff.summary.severity_changed
                    ));
                        report.baseline_diff = Some(diff);
                    }
                    Err(e) => eprintln!("[!] baseline diff skipped: {e}"),
                }
            }
            Err(e) => eprintln!("[!] baseline read failed ({path}): {e}"),
        }
    }

    // WS-9 (1.4.1): --out-all writes all four report formats into a directory,
    // in one pass. Preserves --out (single-file) semantics; the two flags are
    // mutually exclusive at runtime — --out-all wins if both are given.
    if let Some(dir) = &a.out_all {
        return write_out_all(&report, dir, a.top_n);
    }

    // Resolve output format + destination.
    //
    // Order of precedence:
    //   1. --format explicit                              → wins over any inference
    //   2. --out=<path>.{json,html,md,txt,zip} inference  → picks format from extension
    //   3. default --format json                          → stdout
    //
    // .zip via --out is already handled above (BloodHound-CE bundle). Here we route
    // the JSON / HTML / Markdown / plaintext report bodies.
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
            Some("md") | Some("markdown") => "md".to_string(),
            Some("txt") | Some("text") => "txt".to_string(),
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
        "md" => report.to_markdown(),
        "txt" => report.to_text_summary(a.top_n),
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

/// WS-9: dump all four formats into `dir`. Filenames match AyDee's convention:
/// `report.{json,md,html}` + `report-summary.txt`.
fn write_out_all(report: &Report, dir: &str, top_n: usize) -> Result<()> {
    let d = std::path::Path::new(dir);
    std::fs::create_dir_all(d).with_context(|| format!("create --out-all dir {dir}"))?;
    let quads = [
        ("report.json", report.to_json()),
        ("report.md", report.to_markdown()),
        ("report.html", report.to_html()),
        ("report-summary.txt", report.to_text_summary(top_n)),
    ];
    for (name, body) in &quads {
        let path = d.join(name);
        std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
        eprintln!("[+] {} written ({} bytes)", path.display(), body.len());
    }
    Ok(())
}

/// WS-11: `--anonymous` — port scan + RootDSE + null-session SMB + SRV lookup.
/// Emits a smaller anonymous-mode report through the same JSON/HTML/MD/TXT
/// renderers, so the output-format flags (`--out`, `--out-all`, `--format`)
/// behave identically to the authenticated path.
async fn scan_anonymous(a: ScanArgs) -> Result<()> {
    let sp = ui::Spinner::start("anonymous fingerprint (port scan + RootDSE + SMB + SRV)");
    let anon = crate::attacks::scan_anonymous::run(&a.auth.url, a.auth.insecure).await?;
    sp.done(&format!(
        "{} anonymous finding(s) from external fingerprint",
        anon.findings.len()
    ));

    let domain_label = if anon.domain.is_empty() {
        format!("{} (anonymous)", anon.host)
    } else {
        format!("{} (anonymous — domain {})", anon.host, anon.domain)
    };

    let report = Report::build(
        &domain_label,
        anon.findings,
        Vec::new(),
        (0, 0),
        &RiskConfig::default(),
    );

    if let Some(dir) = &a.out_all {
        return write_out_all(&report, dir, a.top_n);
    }

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
            Some("md") | Some("markdown") => "md".to_string(),
            Some("txt") | Some("text") => "txt".to_string(),
            _ => "json".to_string(),
        }
    } else {
        a.format.clone()
    };

    let body = match format.as_str() {
        "html" => report.to_html(),
        "md" => report.to_markdown(),
        "txt" => report.to_text_summary(a.top_n),
        _ => report.to_json(),
    };

    match &a.out {
        Some(path) if path != "-" => {
            std::fs::write(path, &body)
                .with_context(|| format!("write anonymous report → {path}"))?;
            eprintln!(
                "[+] anonymous {} report written → {} ({} bytes)",
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
