//! `enum rpc --null` — no-cred anonymous RPC surface probe (rpcclient shape).
//!
//! WS-BB-RPCNULL (1.5.0). Over one anonymous SMB session (`login_null`),
//! probes the classic anon-reachable RPC interfaces: `\srvsvc`
//! (NetSessionEnum), `\wkssvc` (NetrWkstaUserEnum), and `\lsarpc`
//! (LsarOpenPolicy). Each interface is tried independently; a per-pipe
//! refusal is reported as a hardened-posture line rather than aborting
//! the whole probe. On a legacy `RestrictAnonymous=0` DC these return
//! live session / logged-on-user data; on a hardened DC (2019+ default)
//! each is refused and the verb records where.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct RpcNullArgs {
    /// Target DC / host (IP or name).
    #[arg(long)]
    pub host: String,
    /// Emit JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Default)]
struct RpcNullReport {
    reachable: bool,
    null_session: bool,
    srvsvc_sessions: Option<usize>,
    wkssvc_users: Option<usize>,
    lsarpc_policy: Option<bool>,
    notes: Vec<String>,
}

pub(crate) async fn rpcnull(a: RpcNullArgs) -> Result<()> {
    use smb2_client::SmbClient;

    let sp = crate::ui::Spinner::start(format!("anonymous RPC probe → {}", a.host));
    let mut rep = RpcNullReport::default();

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

    if smb
        .tree_connect(&format!("\\\\{}\\IPC$", a.host))
        .await
        .is_err()
    {
        rep.notes.push("IPC$ tree-connect refused".into());
        sp.done(&format!("{}: IPC$ refused (hardened)", a.host));
        return emit(&a, &rep);
    }

    // \srvsvc — NetSessionEnum.
    match smb.open_pipe("srvsvc").await {
        Ok(pipe) => match dcerpc::srvsvc::SrvsvcClient::bind(&mut smb, pipe).await {
            Ok(mut c) => match c.enum_sessions().await {
                Ok((sessions, _)) => rep.srvsvc_sessions = Some(sessions.len()),
                Err(e) => rep
                    .notes
                    .push(format!("srvsvc NetSessionEnum refused: {e}")),
            },
            Err(e) => rep.notes.push(format!("srvsvc bind refused: {e}")),
        },
        Err(e) => rep.notes.push(format!("srvsvc pipe refused: {e}")),
    }

    // \wkssvc — NetrWkstaUserEnum.
    match smb.open_pipe("wkssvc").await {
        Ok(pipe) => match dcerpc::wkssvc::WkstaUserClient::bind(&mut smb, pipe).await {
            Ok(mut c) => match c.enum_users().await {
                Ok((users, _)) => rep.wkssvc_users = Some(users.len()),
                Err(e) => rep
                    .notes
                    .push(format!("wkssvc NetrWkstaUserEnum refused: {e}")),
            },
            Err(e) => rep.notes.push(format!("wkssvc bind refused: {e}")),
        },
        Err(e) => rep.notes.push(format!("wkssvc pipe refused: {e}")),
    }

    // \lsarpc — LsarOpenPolicy (proves LSA reachable anonymously).
    match smb.open_pipe("lsarpc").await {
        Ok(pipe) => match dcerpc::lsat::LsatClient::bind(&mut smb, pipe).await {
            Ok(mut c) => match c.open_policy().await {
                Ok(_) => rep.lsarpc_policy = Some(true),
                Err(e) => rep
                    .notes
                    .push(format!("lsarpc LsarOpenPolicy refused: {e}")),
            },
            Err(e) => rep.notes.push(format!("lsarpc bind refused: {e}")),
        },
        Err(e) => rep.notes.push(format!("lsarpc pipe refused: {e}")),
    }

    let any = rep.srvsvc_sessions.is_some()
        || rep.wkssvc_users.is_some()
        || rep.lsarpc_policy == Some(true);
    sp.done(&format!(
        "{}: null session OK · anon RPC {}",
        a.host,
        if any {
            "partially exposed"
        } else {
            "all refused (hardened)"
        }
    ));
    emit(&a, &rep)
}

fn emit(a: &RpcNullArgs, r: &RpcNullReport) -> Result<()> {
    use adhammer_core::sanitize_terminal_output as san;
    if a.json {
        let notes = r
            .notes
            .iter()
            .map(|n| format!("\"{}\"", jesc(n)))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\"host\":\"{}\",\"reachable\":{},\"null_session\":{},\"srvsvc_sessions\":{},\"wkssvc_users\":{},\"lsarpc_policy\":{},\"notes\":[{}]}}",
            jesc(&a.host),
            r.reachable,
            r.null_session,
            r.srvsvc_sessions.map(|n| n.to_string()).unwrap_or_else(|| "null".into()),
            r.wkssvc_users.map(|n| n.to_string()).unwrap_or_else(|| "null".into()),
            r.lsarpc_policy.map(|b| b.to_string()).unwrap_or_else(|| "null".into()),
            notes
        );
        return Ok(());
    }

    println!("\n== {} — anonymous RPC ==", san(&a.host));
    if !r.reachable {
        println!("  SMB (445) not reachable");
    } else if !r.null_session {
        println!("  null session refused — DC hardened against anonymous SMB.");
    } else {
        println!("  null session established.");
        match r.srvsvc_sessions {
            Some(n) => println!("  \\srvsvc  NetSessionEnum   → {n} session(s) [ANON EXPOSED]"),
            None => println!("  \\srvsvc  NetSessionEnum   → refused"),
        }
        match r.wkssvc_users {
            Some(n) => println!("  \\wkssvc  WkstaUserEnum    → {n} user(s) [ANON EXPOSED]"),
            None => println!("  \\wkssvc  WkstaUserEnum    → refused"),
        }
        match r.lsarpc_policy {
            Some(true) => println!("  \\lsarpc  LsarOpenPolicy   → OK [ANON EXPOSED]"),
            _ => println!("  \\lsarpc  LsarOpenPolicy   → refused"),
        }
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
