//! `enum shares --anon` — no-cred anonymous share enumeration (smbclient -L shape).
//!
//! WS-BB-SHARES (1.5.0). Over one anonymous SMB session (`login_null`), binds
//! `\srvsvc` and calls `NetrShareEnum` level 1 (`SHARE_INFO_1`: netname / type /
//! remark) — the classic no-cred share listing. On a legacy DC this returns the
//! full share table (SYSVOL, NETLOGON, admin `$` shares); on a hardened DC (2019+
//! default) the null session, the `\srvsvc` bind, or the enum itself is refused,
//! and that refusal is reported as the finding rather than erroring out.
//!
//! `--anon` is required and explicit: it records in the invocation that the enum
//! used zero credentials, and reserves the bare `enum shares` name for a future
//! authenticated mode.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct SharesArgs {
    /// Target DC / host (IP or name).
    #[arg(long)]
    pub host: String,
    /// Enumerate over an anonymous (null) session — required; no credentials used.
    #[arg(long)]
    pub anon: bool,
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

pub(crate) async fn shares(a: SharesArgs) -> Result<()> {
    use smb2_client::SmbClient;

    if !a.anon {
        anyhow::bail!("pass --anon: only anonymous (no-cred) share enumeration is wired in 1.5.0");
    }

    let sp = crate::ui::Spinner::start(format!("anonymous share enum → {}", a.host));
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

    if let Err(e) = smb.login_null(&a.host).await {
        sp.done(&format!("{}: anonymous session refused (hardened)", a.host));
        rep.notes.push(format!("null session refused: {e}"));
        return emit(&a, &rep);
    }
    rep.null_session = true;

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
            sp.done(&format!(
                "{}: anonymous share enum OK — {} share(s) [ANON EXPOSED]",
                a.host,
                rows.len()
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

    println!("\n== {} — anonymous shares ==", san(&a.host));
    if !r.reachable {
        println!("  SMB (445) not reachable");
    } else if !r.null_session {
        println!("  null session refused — DC hardened against anonymous SMB.");
    } else if let Some(rows) = &r.shares {
        println!(
            "  null session established · NetrShareEnum → {} share(s):",
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
        if non_admin > 0 {
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
