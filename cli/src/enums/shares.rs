//! `enum shares` — SMB share enumeration (smbclient -L shape).
//!
//! Two modes now (1.5.2 Task L):
//! - **`--anon`**: no-cred anonymous share enumeration (WS-BB-SHARES, 1.5.0).
//!   Binds `\srvsvc` over `login_null` and calls `NetrShareEnum` level 1
//!   (SHARE_INFO_1: netname / type / remark). A hardened DC refuses the null
//!   session, the `\srvsvc` bind, or the enum itself — reported as a finding
//!   rather than an error.
//! - **`--user` / `--password` / `--domain`**: authenticated share enum.
//!   Uses SMB NTLMSSP to log in, then the same NetrShareEnum path. Reveals
//!   the full share table (SYSVOL / NETLOGON / admin$ / any custom shares
//!   the caller has ACL for).

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct SharesArgs {
    /// Target DC / host (IP or name).
    #[arg(long)]
    pub host: String,
    /// Enumerate over an anonymous (null) session — mutually exclusive with `--user`.
    #[arg(long, conflicts_with = "user")]
    pub anon: bool,
    /// Authenticated SMB user (sAMAccountName). Requires `--password` and
    /// `--domain`.
    #[arg(long, requires = "password", requires = "domain")]
    pub user: Option<String>,
    /// SMB password. Accepts `env:VAR` / `@file:PATH` / secure prompt.
    #[arg(long)]
    pub password: Option<adhammer_core::SecretString>,
    /// NetBIOS or DNS domain for the authenticated bind.
    #[arg(long)]
    pub domain: Option<String>,
    /// Emit JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

struct ShareRow {
    netname: String,
    stype: String,
    special: bool,
    remark: String,
}

#[derive(Default)]
struct SharesReport {
    reachable: bool,
    null_session: bool,
    shares: Option<Vec<ShareRow>>,
    notes: Vec<String>,
}

pub(crate) async fn shares(mut a: SharesArgs) -> Result<()> {
    use smb2_client::SmbClient;

    if !a.anon && a.user.is_none() {
        anyhow::bail!(
            "pass --anon for a null-session enum OR --user/--password/--domain for an \
             authenticated enum"
        );
    }
    let authed_mode = a.user.is_some();
    // Resolve @file:/env: for the password when in authed mode (Task L).
    if authed_mode {
        if let Some(pw) = a.password.take() {
            a.password = Some(crate::resolve_secret(&pw, "ADHAMMER_PASSWORD")?);
        }
    }

    let sp = crate::ui::Spinner::start(format!(
        "{} share enum → {}",
        if authed_mode {
            "authenticated"
        } else {
            "anonymous"
        },
        a.host
    ));
    let mut rep = SharesReport::default();

    let mut smb = match SmbClient::connect(&a.host).await {
        Ok(s) => s,
        Err(e) => {
            sp.done_warn(&format!("SMB connect failed: {e}"));
            rep.notes.push(format!("connect: {e}"));
            return emit(&a, &rep);
        }
    };
    rep.reachable = true;

    if authed_mode {
        let user = a.user.as_deref().unwrap();
        let domain = a.domain.as_deref().unwrap();
        let pw = a.password.as_ref().unwrap().expose_secret();
        if let Err(e) = smb.login(&a.host, domain, user, pw).await {
            sp.done_warn(&format!("SMB auth failed: {e}"));
            rep.notes.push(format!("SMB login: {e}"));
            return emit(&a, &rep);
        }
        rep.null_session = false; // authed, but keep the field name for JSON stability
    } else if let Err(e) = smb.login_null(&a.host).await {
        sp.done(&format!("{}: anonymous session refused (hardened)", a.host));
        rep.notes.push(format!("null session refused: {e}"));
        return emit(&a, &rep);
    } else {
        rep.null_session = true;
    }

    if let Err(e) = smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await {
        sp.done(&format!("{}: IPC$ refused (hardened)", a.host));
        rep.notes.push(format!("IPC$ tree-connect: {e}"));
        return emit(&a, &rep);
    }

    let pipe = match smb.open_pipe("srvsvc").await {
        Ok(p) => p,
        Err(e) => {
            sp.done(&format!("{}: \\srvsvc refused (hardened)", a.host));
            rep.notes.push(format!("srvsvc pipe: {e}"));
            return emit(&a, &rep);
        }
    };

    let mut client = match dcerpc::srvsvc::SrvsvcClient::bind(&mut smb, pipe).await {
        Ok(c) => c,
        Err(e) => {
            sp.done(&format!("{}: \\srvsvc bind refused (hardened)", a.host));
            rep.notes.push(format!("srvsvc bind: {e}"));
            return emit(&a, &rep);
        }
    };

    match client.enum_shares().await {
        Ok((shares, ret)) => {
            if ret != 0 && shares.is_empty() {
                sp.done(&format!("{}: NetrShareEnum refused (rc={ret:#x})", a.host));
                rep.notes
                    .push(format!("NetrShareEnum returned rc={ret:#010x}"));
                return emit(&a, &rep);
            }
            let rows: Vec<ShareRow> = shares
                .into_iter()
                .map(|s| ShareRow {
                    netname: s.netname.clone(),
                    stype: s.stype_label().to_string(),
                    special: s.is_special(),
                    remark: s.remark.clone(),
                })
                .collect();
            let mode_tag = if a.user.is_some() {
                "authenticated"
            } else {
                "anonymous"
            };
            let anon_tag = if a.user.is_none() {
                " [ANON EXPOSED]"
            } else {
                ""
            };
            sp.done(&format!(
                "{}: {} share enum OK — {} share(s){}",
                a.host,
                mode_tag,
                rows.len(),
                anon_tag
            ));
            rep.shares = Some(rows);
            emit(&a, &rep)
        }
        Err(e) => {
            sp.done(&format!("{}: NetrShareEnum refused (hardened)", a.host));
            rep.notes.push(format!("NetrShareEnum: {e}"));
            emit(&a, &rep)
        }
    }
}

fn emit(a: &SharesArgs, r: &SharesReport) -> Result<()> {
    use adhammer_core::sanitize_terminal_output as san;
    if a.json {
        let shares = match &r.shares {
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
        let notes = r
            .notes
            .iter()
            .map(|n| format!("\"{}\"", jesc(n)))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\"host\":\"{}\",\"reachable\":{},\"null_session\":{},\"anon_exposed\":{},\"shares\":[{}],\"notes\":[{}]}}",
            jesc(&a.host),
            r.reachable,
            r.null_session,
            r.shares.is_some(),
            shares,
            notes
        );
        return Ok(());
    }

    let mode_tag = if a.user.is_some() {
        "authenticated"
    } else {
        "anonymous"
    };
    println!("\n== {} — {mode_tag} shares ==", san(&a.host));
    if !r.reachable {
        println!("  SMB (445) not reachable");
    } else if a.user.is_none() && !r.null_session {
        println!("  null session refused — DC hardened against anonymous SMB.");
    } else if let Some(rows) = &r.shares {
        let session_desc = if a.user.is_some() {
            format!("{mode_tag} session established")
        } else {
            String::from("null session established")
        };
        println!(
            "  {session_desc} · NetrShareEnum → {} share(s):",
            rows.len()
        );
        let non_admin = rows.iter().filter(|s| !s.special).count();
        for s in rows {
            let tag = if s.special { " [admin$]" } else { "" };
            let remark = if s.remark.is_empty() {
                String::new()
            } else {
                format!("  — {}", san(&s.remark))
            };
            println!("    {:<16} {}{tag}{remark}", san(&s.netname), s.stype);
        }
        if a.user.is_none() && non_admin > 0 {
            println!(
                "\n  ** {non_admin} non-admin share(s) listable anonymously [ANON EXPOSED] — \
                 this DC permits null-session NetrShareEnum. Harden: RestrictNullSessAccess=1."
            );
        }
    } else {
        println!(
            "  anonymous share enumeration refused — DC hardened against null-session srvsvc."
        );
    }
    if !r.notes.is_empty() {
        println!("  detail:");
        for n in &r.notes {
            println!("    - {}", san(n));
        }
    }
    Ok(())
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
