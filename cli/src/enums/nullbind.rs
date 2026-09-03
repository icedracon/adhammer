//! `enum nullbind` — no-cred SMB null-session enumeration (enum4linux-ng shape).
//!
//! WS-FOUNDATION-NULLBIND (1.5.0). Opens an anonymous SMB session to the
//! target's IPC$, then walks SAMR over the `\samr` named pipe to list the
//! domain(s) and their users/RIDs — with zero credentials.
//!
//! On a DC that still permits anonymous IPC$ (legacy / `RestrictAnonymous
//! = 0`) this returns the domain user list. On a hardened DC (2019+
//! default) the null session is refused at `SESSION_SETUP` or the SAMR
//! bind — that refusal is itself the finding: the box is hardened against
//! anonymous enumeration, which the verb reports cleanly rather than
//! erroring out.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct NullbindArgs {
    /// Target DC / host (IP or name).
    #[arg(long)]
    pub host: String,
    /// Emit JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

pub(crate) async fn nullbind(a: NullbindArgs) -> Result<()> {
    use adhammer_core::sanitize_terminal_output as san;
    use smb2_client::SmbClient;

    let sp = crate::ui::Spinner::start(format!("anonymous SMB null session → {}", a.host));

    let mut smb = match SmbClient::connect(&a.host).await {
        Ok(s) => s,
        Err(e) => {
            sp.done_warn(&format!("SMB connect failed: {e}"));
            return emit(&a, NullResult::connect_failed(&e.to_string()));
        }
    };

    if let Err(e) = smb.login_null(&a.host).await {
        // Refusal is the expected hardened-DC outcome — report, don't error.
        sp.done(&format!("{}: anonymous session refused (hardened)", a.host));
        return emit(&a, NullResult::refused(&e.to_string()));
    }

    if let Err(e) = smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await {
        sp.done(&format!("{}: IPC$ tree-connect refused (hardened)", a.host));
        return emit(&a, NullResult::refused(&format!("IPC$ tree-connect: {e}")));
    }

    let pipe = match smb.open_pipe("samr").await {
        Ok(p) => p,
        Err(e) => {
            sp.done(&format!("{}: \\samr pipe refused (hardened)", a.host));
            return emit(&a, NullResult::refused(&format!("\\samr open: {e}")));
        }
    };

    let mut client = match dcerpc::samr::SamrClient::bind(&mut smb, pipe).await {
        Ok(c) => c,
        Err(e) => {
            sp.done(&format!("{}: SAMR bind refused (hardened)", a.host));
            return emit(&a, NullResult::refused(&format!("SAMR bind: {e}")));
        }
    };

    match client.enumerate_all_users(&format!("\\\\{}", a.host)).await {
        Ok(users) => {
            sp.done(&format!(
                "{}: anonymous SAMR enum OK — {} user(s)",
                a.host,
                users.len()
            ));
            let users: Vec<(u32, String)> = users
                .into_iter()
                .map(|(rid, name)| (rid, san(&name)))
                .collect();
            emit(&a, NullResult::users(users))
        }
        Err(e) => {
            sp.done(&format!("{}: SAMR user-enum refused (hardened)", a.host));
            emit(&a, NullResult::refused(&format!("SamrEnumerateUsers: {e}")))
        }
    }
}

enum NullResult {
    Users(Vec<(u32, String)>),
    Refused(String),
    ConnectFailed(String),
}

impl NullResult {
    fn users(u: Vec<(u32, String)>) -> Self {
        NullResult::Users(u)
    }
    fn refused(why: &str) -> Self {
        NullResult::Refused(why.to_string())
    }
    fn connect_failed(why: &str) -> Self {
        NullResult::ConnectFailed(why.to_string())
    }
}

fn emit(a: &NullbindArgs, r: NullResult) -> Result<()> {
    use adhammer_core::sanitize_terminal_output as san;
    if a.json {
        let body = match &r {
            NullResult::Users(users) => {
                let list = users
                    .iter()
                    .map(|(rid, name)| {
                        format!("{{\"rid\":{rid},\"name\":\"{}\"}}", json_escape(name))
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "{{\"host\":\"{}\",\"anonymous\":true,\"users\":[{list}]}}",
                    json_escape(&a.host)
                )
            }
            NullResult::Refused(why) => format!(
                "{{\"host\":\"{}\",\"anonymous\":false,\"hardened\":true,\"detail\":\"{}\"}}",
                json_escape(&a.host),
                json_escape(why)
            ),
            NullResult::ConnectFailed(why) => format!(
                "{{\"host\":\"{}\",\"reachable\":false,\"detail\":\"{}\"}}",
                json_escape(&a.host),
                json_escape(why)
            ),
        };
        println!("{body}");
        return Ok(());
    }

    match &r {
        NullResult::Users(users) => {
            println!(
                "\n== {} — anonymous SAMR ({} users) ==",
                san(&a.host),
                users.len()
            );
            for (rid, name) in users {
                println!("  {rid}\t{name}");
            }
            println!(
                "\n** anonymous enumeration succeeded — this DC permits null-session SAMR \
                 (RestrictAnonymous=0). Harden: set RestrictAnonymous=1 + RestrictAnonymousSAM=1."
            );
        }
        NullResult::Refused(why) => {
            println!("\n== {} ==", san(&a.host));
            println!("  anonymous SMB enumeration refused — DC is hardened against null sessions.");
            println!("  detail: {}", san(why));
            println!("  (this is the SECURE posture — no action needed.)");
        }
        NullResult::ConnectFailed(why) => {
            println!("\n== {} ==", san(&a.host));
            println!("  SMB (445) not reachable: {}", san(why));
        }
    }
    Ok(())
}

fn json_escape(s: &str) -> String {
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
