//! Host session enumeration — SRVSVC / WKSSVC / HKU.

use anyhow::Result;
use clap::Parser;

use crate::{resolve_secret, smb_login};

#[derive(Parser)]
pub(crate) struct SessionsArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::SmbAuth,
    /// Pass-the-hash: NT hash (32 hex, or LM:NT) instead of --password
    #[arg(long)]
    pub nt_hash: Option<adhammer_core::SecretString>,
    /// Include machine-account (`$`-suffixed) principals in the output. Default is off —
    /// on a DC these flood the list with the DC's own machine-account service sessions.
    #[arg(long)]
    pub include_machine: bool,
}

/// `enum sessions` — enumerate a host's logon sessions over SRVSVC (session hunting). Each row is
/// a (user, client computer) pair; a privileged user here marks the host as a credential-theft
/// target, i.e. a `HasSession` edge into that user.
pub(crate) async fn sessions(mut a: SessionsArgs) -> Result<()> {
    use dcerpc::srvsvc::SrvsvcClient;
    use smb2_client::SmbClient;

    a.auth.password = resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;
    let mut smb = SmbClient::connect(&a.auth.host).await?;
    smb_login(
        &mut smb,
        &a.auth.host,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.nt_hash,
    )
    .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.auth.host))
        .await?;
    let pipe = smb.open_pipe("srvsvc").await?;
    let mut srv = SrvsvcClient::bind(&mut smb, pipe).await?;
    let (list, ret) = srv.enum_sessions().await?;
    if ret != 0 {
        eprintln!("[!] NetrSessionEnum returned 0x{ret:08x} (access denied? need local admin on many hosts)");
    }
    if list.is_empty() {
        eprintln!("[-] no sessions returned on {}", a.auth.host);
    } else {
        eprintln!("[+] {} session(s) on {}:", list.len(), a.auth.host);
        for s in &list {
            let from = if s.client.is_empty() { "?" } else { &s.client };
            println!("    {:<24} from {from}", s.user);
        }
    }
    Ok(())
}

pub(crate) async fn wkssvc_enum(mut a: SessionsArgs) -> Result<()> {
    use dcerpc::wkssvc::WkstaUserClient;
    use smb2_client::SmbClient;
    use std::collections::BTreeMap;

    a.auth.password = resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;
    let mut smb = SmbClient::connect(&a.auth.host).await?;
    smb_login(
        &mut smb,
        &a.auth.host,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.nt_hash,
    )
    .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.auth.host))
        .await?;
    let pipe = smb.open_pipe("wkssvc").await?;
    let mut wks = WkstaUserClient::bind(&mut smb, pipe).await?;
    let (list, ret) = wks.enum_users().await?;
    if ret != 0 {
        eprintln!("[!] NetrWkstaUserEnum returned {ret} (need local admin)");
    }
    let raw = list.len();
    // Dedup on (user, domain, logon_server) — one Windows box typically emits many LSA
    // sessions per principal (one per service / logon type), which for HasSession-style
    // graph building is noise. Machine accounts (`$`-suffixed) are filtered unless
    // --include-machine, since on a DC they're the flood.
    let mut grouped: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut machine_hidden = 0usize;
    for u in &list {
        if !a.include_machine && u.username.ends_with('$') {
            machine_hidden += 1;
            continue;
        }
        *grouped
            .entry((
                u.username.clone(),
                u.logon_domain.clone(),
                u.logon_server.clone(),
            ))
            .or_default() += 1;
    }
    if grouped.is_empty() {
        eprintln!(
            "[-] no logged-on users on {} (raw={raw}, machine-hidden={machine_hidden})",
            a.auth.host
        );
        if machine_hidden > 0 && !a.include_machine {
            eprintln!("    pass --include-machine to show machine-account sessions");
        }
    } else {
        eprintln!(
            "[+] {} unique principal(s) on {} (raw={raw}, machine-hidden={machine_hidden}):",
            grouped.len(),
            a.auth.host
        );
        for ((user, domain, server), count) in &grouped {
            let mark = if *count > 1 {
                format!(" ×{count}")
            } else {
                String::new()
            };
            let srv = if server.is_empty() { "(none)" } else { server };
            println!("    {domain}\\{user:<24} server={srv}{mark}");
        }
    }
    Ok(())
}

pub(crate) async fn hku_enum(mut a: SessionsArgs) -> Result<()> {
    use dcerpc::rrp::RegistryClient;
    use smb2_client::SmbClient;

    a.auth.password = resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;
    let mut smb = SmbClient::connect(&a.auth.host).await?;
    smb_login(
        &mut smb,
        &a.auth.host,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.nt_hash,
    )
    .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.auth.host))
        .await?;
    let mut reg = match RegistryClient::connect(
        &mut smb,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.auth.host,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("0xc00000ac") || msg.contains("open \\winreg") {
                anyhow::bail!(
                    "Remote Registry service is stopped on {} — start it or use `enum wkssvc` / `enum sessions` instead",
                    a.auth.host
                );
            }
            return Err(e.into());
        }
    };
    let sids = reg.logged_on_sids().await?;
    if sids.is_empty() {
        eprintln!("[-] no logged-on SIDs via HKU on {}", a.auth.host);
    } else {
        eprintln!(
            "[+] {} logged-on SID(s) via HKU on {}:",
            sids.len(),
            a.auth.host
        );
        for s in &sids {
            println!("    {}", s.sid);
        }
    }
    Ok(())
}
