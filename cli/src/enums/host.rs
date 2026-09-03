//! `enum host --anon` — unified no-cred host posture over ONE null session.
//!
//! WS-BB-HOST (1.5.0). The enum4linux-ng-shape single-shot: open one anonymous
//! SMB session (`login_null`) and, over that single session, probe every classic
//! anon-reachable surface — SAMR users (`\samr`), sessions (`\srvsvc`
//! NetSessionEnum), logged-on users (`\wkssvc`), LSA policy (`\lsarpc`), and
//! shares (`\srvsvc` NetrShareEnum). One authentication, one posture report.
//!
//! This is the composition core: [`probe_host`] returns the [`HostPosture`]
//! struct that both this verb and `run --deep` render, so the anon host-probe
//! logic lives in exactly one place. Each surface is tried independently; a
//! per-interface refusal is recorded, never aborts the sweep — the pattern of
//! what a DC exposes vs. refuses IS the finding.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct HostArgs {
    /// Target DC / host (IP or name).
    #[arg(long)]
    pub host: String,
    /// Probe over an anonymous (null) session — required; no credentials used.
    #[arg(long)]
    pub anon: bool,
    /// Emit JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

/// One share row (netname / STYPE label / admin-flag / remark), pre-rendered
/// from `dcerpc::srvsvc::Share` so the collector types stay out of the CLI.
pub(crate) struct ShareRow {
    pub netname: String,
    pub stype: String,
    pub special: bool,
    pub remark: String,
}

/// Everything one anonymous session could learn about a host. `None` on a
/// surface means "tried and refused" (a note records why); `Some` means the
/// interface answered — i.e. it is exposed anonymously.
#[derive(Default)]
pub(crate) struct HostPosture {
    pub reachable: bool,
    pub null_session: bool,
    pub samr_users: Option<Vec<(u32, String)>>,
    pub srvsvc_sessions: Option<usize>,
    pub wkssvc_users: Option<usize>,
    pub lsarpc_ok: bool,
    pub shares: Option<Vec<ShareRow>>,
    pub notes: Vec<String>,
}

impl HostPosture {
    /// True if *any* surface answered anonymously (used to headline the sweep).
    pub fn anon_exposed(&self) -> bool {
        self.samr_users.is_some()
            || self.srvsvc_sessions.is_some()
            || self.wkssvc_users.is_some()
            || self.lsarpc_ok
            || self.shares.is_some()
    }
    /// Count of non-admin shares listable anonymously (the higher-signal subset).
    pub fn non_admin_shares(&self) -> usize {
        self.shares
            .as_ref()
            .map(|v| v.iter().filter(|s| !s.special).count())
            .unwrap_or(0)
    }
}

/// Probe every anon surface over one `login_null` session. Never errors on a
/// refused interface — refusals are recorded in `notes` and left as `None`.
pub(crate) async fn probe_host(host: &str) -> HostPosture {
    use adhammer_core::sanitize_terminal_output as san;
    use smb2_client::SmbClient;

    let mut p = HostPosture::default();

    let mut smb = match SmbClient::connect(host).await {
        Ok(s) => s,
        Err(e) => {
            p.notes.push(format!("connect: {e}"));
            return p;
        }
    };
    p.reachable = true;

    if let Err(e) = smb.login_null(host).await {
        p.notes.push(format!("null session refused: {e}"));
        return p;
    }
    p.null_session = true;

    if let Err(e) = smb.tree_connect(&format!("\\\\{host}\\IPC$")).await {
        p.notes.push(format!("IPC$ tree-connect: {e}"));
        return p;
    }

    // \samr — user enumeration.
    match smb.open_pipe("samr").await {
        Ok(pipe) => match dcerpc::samr::SamrClient::bind(&mut smb, pipe).await {
            Ok(mut c) => match c.enumerate_all_users(&format!("\\\\{host}")).await {
                Ok(users) => {
                    p.samr_users = Some(users.into_iter().map(|(rid, n)| (rid, san(&n))).collect())
                }
                Err(e) => p.notes.push(format!("samr enum: {e}")),
            },
            Err(e) => p.notes.push(format!("samr bind: {e}")),
        },
        Err(e) => p.notes.push(format!("samr pipe: {e}")),
    }

    // \srvsvc — NetSessionEnum + NetrShareEnum over one bind.
    match smb.open_pipe("srvsvc").await {
        Ok(pipe) => match dcerpc::srvsvc::SrvsvcClient::bind(&mut smb, pipe).await {
            Ok(mut c) => {
                match c.enum_sessions().await {
                    Ok((sessions, _)) => p.srvsvc_sessions = Some(sessions.len()),
                    Err(e) => p.notes.push(format!("srvsvc NetSessionEnum: {e}")),
                }
                match c.enum_shares().await {
                    Ok((shares, ret)) if !(ret != 0 && shares.is_empty()) => {
                        p.shares = Some(
                            shares
                                .into_iter()
                                .map(|s| ShareRow {
                                    netname: san(&s.netname),
                                    stype: s.stype_label().to_string(),
                                    special: s.is_special(),
                                    remark: san(&s.remark),
                                })
                                .collect(),
                        );
                    }
                    Ok((_, ret)) => p.notes.push(format!("srvsvc NetrShareEnum rc={ret:#010x}")),
                    Err(e) => p.notes.push(format!("srvsvc NetrShareEnum: {e}")),
                }
            }
            Err(e) => p.notes.push(format!("srvsvc bind: {e}")),
        },
        Err(e) => p.notes.push(format!("srvsvc pipe: {e}")),
    }

    // \wkssvc — NetrWkstaUserEnum.
    match smb.open_pipe("wkssvc").await {
        Ok(pipe) => match dcerpc::wkssvc::WkstaUserClient::bind(&mut smb, pipe).await {
            Ok(mut c) => match c.enum_users().await {
                Ok((users, _)) => p.wkssvc_users = Some(users.len()),
                Err(e) => p.notes.push(format!("wkssvc NetrWkstaUserEnum: {e}")),
            },
            Err(e) => p.notes.push(format!("wkssvc bind: {e}")),
        },
        Err(e) => p.notes.push(format!("wkssvc pipe: {e}")),
    }

    // \lsarpc — LsarOpenPolicy.
    match smb.open_pipe("lsarpc").await {
        Ok(pipe) => match dcerpc::lsat::LsatClient::bind(&mut smb, pipe).await {
            Ok(mut c) => match c.open_policy().await {
                Ok(_) => p.lsarpc_ok = true,
                Err(e) => p.notes.push(format!("lsarpc LsarOpenPolicy: {e}")),
            },
            Err(e) => p.notes.push(format!("lsarpc bind: {e}")),
        },
        Err(e) => p.notes.push(format!("lsarpc pipe: {e}")),
    }

    p
}

pub(crate) async fn host(a: HostArgs) -> Result<()> {
    if !a.anon {
        anyhow::bail!("pass --anon: only anonymous (no-cred) host probing is wired in 1.5.0");
    }
    let sp = crate::ui::Spinner::start(format!("anonymous host posture → {}", a.host));
    let p = probe_host(&a.host).await;
    if !p.reachable {
        sp.done_warn(&format!("{}: SMB (445) not reachable", a.host));
    } else if !p.null_session {
        sp.done(&format!("{}: null session refused (hardened)", a.host));
    } else {
        sp.done(&format!(
            "{}: null session OK · anon surface {}",
            a.host,
            if p.anon_exposed() {
                "partially exposed"
            } else {
                "all refused (hardened)"
            }
        ));
    }
    if a.json {
        println!("{}", posture_json(&a.host, &p));
    } else {
        print_posture(&p, "  ");
    }
    Ok(())
}

/// Render a posture block with the given indent. Shared by `enum host` and
/// `run --deep` (which indents each DC's block under a per-host header).
pub(crate) fn print_posture(p: &HostPosture, ind: &str) {
    use adhammer_core::sanitize_terminal_output as san;
    if !p.reachable {
        println!("{ind}SMB (445) not reachable");
    } else if !p.null_session {
        println!("{ind}null session refused — hardened against anonymous SMB.");
    } else {
        println!("{ind}null session established.");
        match &p.samr_users {
            Some(u) => println!(
                "{ind}\\samr    users            → {} [ANON EXPOSED]",
                u.len()
            ),
            None => println!("{ind}\\samr    users            → refused"),
        }
        match p.srvsvc_sessions {
            Some(n) => println!("{ind}\\srvsvc  NetSessionEnum   → {n} [ANON EXPOSED]"),
            None => println!("{ind}\\srvsvc  NetSessionEnum   → refused"),
        }
        match &p.shares {
            Some(rows) => {
                println!(
                    "{ind}\\srvsvc  NetrShareEnum    → {} share(s) [ANON EXPOSED]",
                    rows.len()
                );
                for s in rows {
                    let tag = if s.special { " [admin$]" } else { "" };
                    let rem = if s.remark.is_empty() {
                        String::new()
                    } else {
                        format!("  — {}", s.remark)
                    };
                    println!("{ind}    {:<16} {}{tag}{rem}", san(&s.netname), s.stype);
                }
            }
            None => println!("{ind}\\srvsvc  NetrShareEnum    → refused"),
        }
        match p.wkssvc_users {
            Some(n) => println!("{ind}\\wkssvc  WkstaUserEnum    → {n} [ANON EXPOSED]"),
            None => println!("{ind}\\wkssvc  WkstaUserEnum    → refused"),
        }
        println!(
            "{ind}\\lsarpc  LsarOpenPolicy   → {}",
            if p.lsarpc_ok {
                "OK [ANON EXPOSED]"
            } else {
                "refused"
            }
        );
        if let Some(u) = &p.samr_users {
            if !u.is_empty() {
                println!("{ind}users:");
                for (rid, name) in u {
                    println!("{ind}    {rid}\t{name}");
                }
            }
        }
        let na = p.non_admin_shares();
        if na > 0 {
            println!(
                "{ind}** {na} non-admin share(s) listable anonymously — DC permits null-session \
                 NetrShareEnum (RestrictNullSessAccess=0)."
            );
        }
    }
    if !p.notes.is_empty() {
        println!("{ind}detail:");
        for n in &p.notes {
            println!("{ind}    - {}", san(n));
        }
    }
}

pub(crate) fn posture_json(host: &str, p: &HostPosture) -> String {
    let users = match &p.samr_users {
        Some(u) => u
            .iter()
            .map(|(rid, n)| format!("{{\"rid\":{rid},\"name\":\"{}\"}}", jesc(n)))
            .collect::<Vec<_>>()
            .join(","),
        None => String::new(),
    };
    let shares = match &p.shares {
        Some(rows) => rows
            .iter()
            .map(|s| {
                format!(
                    "{{\"netname\":\"{}\",\"type\":\"{}\",\"special\":{},\"remark\":\"{}\"}}",
                    jesc(&s.netname),
                    jesc(&s.stype),
                    s.special,
                    jesc(&s.remark)
                )
            })
            .collect::<Vec<_>>()
            .join(","),
        None => String::new(),
    };
    let notes = p
        .notes
        .iter()
        .map(|n| format!("\"{}\"", jesc(n)))
        .collect::<Vec<_>>()
        .join(",");
    let num = |o: Option<usize>| o.map(|n| n.to_string()).unwrap_or_else(|| "null".into());
    format!(
        "{{\"host\":\"{}\",\"reachable\":{},\"null_session\":{},\"anon_exposed\":{},\
         \"samr_users\":[{}],\"srvsvc_sessions\":{},\"wkssvc_users\":{},\"lsarpc_policy\":{},\
         \"shares\":[{}],\"notes\":[{}]}}",
        jesc(host),
        p.reachable,
        p.null_session,
        p.anon_exposed(),
        users,
        num(p.srvsvc_sessions),
        num(p.wkssvc_users),
        p.lsarpc_ok,
        shares,
        notes
    )
}

fn jesc(s: &str) -> String {
    let clean = adhammer_core::sanitize_terminal_output(s);
    let mut out = String::with_capacity(clean.len());
    for c in clean.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
