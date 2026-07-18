//! ADhammer — passive Active Directory security assessment (PingCastle-class), in Rust.
//! Pipeline: LDAP collect → build control-path graph → run checks → score → report.

use adhammer_collector::{Collector, LdapConfig};
use adhammer_graph::ControlGraph;
use adhammer_report::{Report, RiskConfig};
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "adhammer", version, about = "Passive AD security assessment in Rust")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Collect from LDAP and produce a scored report.
    Scan(ScanArgs),
    /// List Kerberos roasting candidates from a live collection (no cracking).
    Roast(ScanArgs),
    /// Enumerate domain users over SAMR (SMB named-pipe RPC) — exercises the full stack.
    Samr(SamrArgs),
}

#[derive(Parser)]
struct SamrArgs {
    /// DC host or IP
    #[arg(long)]
    host: String,
    /// NetBIOS domain, e.g. TESTLAB
    #[arg(long)]
    domain: String,
    /// Username (sAMAccountName)
    #[arg(long)]
    user: String,
    /// Password
    #[arg(long)]
    password: String,
}

#[derive(Parser)]
struct ScanArgs {
    /// LDAP URL, e.g. ldap://dc.corp.local:389 or ldaps://dc.corp.local:636
    #[arg(long)]
    url: String,
    /// Bind identity: user@realm, DOMAIN\\user, or full DN
    #[arg(long)]
    user: String,
    /// Bind password
    #[arg(long)]
    password: String,
    /// Base DN (defaults to RootDSE defaultNamingContext)
    #[arg(long)]
    base_dn: Option<String>,
    /// Output format for `scan`
    #[arg(long, default_value = "json")]
    format: String,
    /// KDC host[:port] for `roast` to actually AS-REP roast (omit = list candidates only)
    #[arg(long)]
    kdc: Option<String>,
    /// SYSVOL path for `scan` to hunt GPP cpasswords, e.g. \\corp.local\SYSVOL
    #[arg(long)]
    sysvol: Option<String>,
    /// Skip TLS certificate verification (LDAPS against a self-signed / lab DC)
    #[arg(long)]
    insecure: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();

    match cli.cmd {
        Command::Scan(a) => scan(a).await,
        Command::Roast(a) => roast(a).await,
        Command::Samr(a) => samr(a).await,
    }
}

/// Full impacket-style path: SMB2 negotiate → NTLM session → IPC$ → \samr pipe →
/// DCE/RPC bind → SamrConnect → enumerate domain users.
async fn samr(a: SamrArgs) -> Result<()> {
    use adhammer_dcerpc::samr::SamrClient;
    use adhammer_smb::SmbClient;

    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    tracing::info!("SMB session established");
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let pipe = smb.open_pipe("samr").await?;
    tracing::info!("\\samr pipe open");

    let mut client = SamrClient::bind(&mut smb, pipe).await?;
    let users = client.enumerate_all_users(&format!("\\\\{}", a.host)).await?;
    println!("== SAMR users ({}) ==", users.len());
    for (rid, name) in users {
        println!("  {rid}\t{name}");
    }
    Ok(())
}

fn config(a: &ScanArgs) -> LdapConfig {
    LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: a.base_dn.clone(),
        insecure: a.insecure,
    }
}

async fn scan(a: ScanArgs) -> Result<()> {
    let snap = Collector::connect(&config(&a)).await?.collect().await?;
    tracing::info!(objects = snap.objects.len(), "collected");

    let graph = ControlGraph::build(&snap);
    let stats = graph.stats();
    let paths = graph.paths_to_tier0();
    let mut findings = adhammer_checks::run_all(&snap, &graph);

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

    match a.format.as_str() {
        "html" => println!("{}", report.to_html()),
        _ => println!("{}", report.to_json()),
    }
    Ok(())
}

async fn roast(a: ScanArgs) -> Result<()> {
    let snap = Collector::connect(&config(&a)).await?.collect().await?;
    let realm = snap
        .domain
        .domain_dn
        .split(',')
        .filter_map(|p| p.strip_prefix("DC="))
        .collect::<Vec<_>>()
        .join(".")
        .to_uppercase();
    let (kerberoast, asrep) = adhammer_kerberos::candidates(&snap, &realm);

    println!("== Kerberoastable ({}) ==", kerberoast.len());
    match &a.kdc {
        None => {
            for c in &kerberoast {
                println!("  {}  spn={}", c.sam, c.spn.as_deref().unwrap_or("-"));
            }
        }
        Some(kdc) if !kerberoast.is_empty() => {
            // One authenticated TGT, then a TGS-REQ per SPN.
            match adhammer_kerberos::get_tgt(&a.user, &a.password, &realm, kdc).await {
                Err(e) => eprintln!("  TGT acquisition failed: {e}"),
                Ok(tgt) => {
                    for c in &kerberoast {
                        let spn = c.spn.as_deref().unwrap_or_default();
                        match adhammer_kerberos::roast_spn(&tgt, &c.sam, spn, kdc).await {
                            Ok(hash) => println!("{hash}"),
                            Err(e) => eprintln!("  {}: {e}", c.sam),
                        }
                    }
                }
            }
        }
        Some(_) => {}
    }

    println!("== AS-REP roastable ({}) ==", asrep.len());
    match &a.kdc {
        None => {
            for c in &asrep {
                println!("  {}", c.sam);
            }
            if !asrep.is_empty() {
                eprintln!("(pass --kdc <host> to fetch hashcat 18200 hashes)");
            }
        }
        Some(kdc) => {
            for c in &asrep {
                match adhammer_kerberos::asrep_roast(c, kdc).await {
                    Ok(hash) => println!("{hash}"),
                    Err(e) => eprintln!("  {}: {e}", c.sam),
                }
            }
        }
    }
    Ok(())
}
