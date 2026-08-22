//! DC posture — LDAP signing / channel binding + Spooler (relay/coercion enablers) via MS-RRP + pipes.

use anyhow::Result;
use clap::Parser;

use crate::ui;

#[derive(Parser)]
pub(crate) struct PostureArgs {
    /// DC host or IP.
    #[arg(long)]
    pub host: String,
    /// NetBIOS domain, e.g. CORP.
    #[arg(long)]
    pub domain: String,
    #[arg(long)]
    pub user: String,
    #[arg(long)]
    pub password: String,
}

pub(crate) async fn posture_scan(a: PostureArgs) -> Result<()> {
    use crate::host_posture::{ldap_channel_binding, ldap_signing, spooler_running};
    use dcerpc::rrp::RegistryClient;
    use smb2_client::SmbClient;

    let sp = ui::Spinner::start(format!("{} — SMB auth + \\winreg", a.host));
    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    // Read the NTDS relay-posture values, scoped so the RRP client releases the SMB session.
    let ntds = "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters";
    let (signing, cbt) = {
        let mut reg = RegistryClient::connect(&mut smb, &a.domain, &a.user, &a.password, &a.host)
            .await
            .map_err(|e| {
                // 0xC00000AC = STATUS_ILLEGAL_FUNCTION → \winreg pipe not exposed, i.e. the
                // Remote Registry service is stopped/disabled. Very common on hardened DCs
                // and on fresh Server 2022/2025 installs.
                let msg = e.to_string();
                if msg.contains("0xc00000ac") || msg.contains("open \\winreg") {
                    anyhow::anyhow!(
                        "\\winreg unreachable on {} — the Remote Registry service is stopped or \
                         disabled (STATUS_ILLEGAL_FUNCTION 0xC00000AC). Start it on the DC \
                         (`Set-Service RemoteRegistry -StartupType Automatic; Start-Service RemoteRegistry`) \
                         then rerun. Spooler-only posture still runs without it — but the LDAP \
                         signing / channel binding values require registry read.",
                        a.host
                    )
                } else {
                    e.into()
                }
            })?;
        let s = reg
            .read_value(ntds, "LDAPServerIntegrity")
            .await
            .ok()
            .and_then(|v| v.as_dword());
        let c = reg
            .read_value(ntds, "LdapEnforceChannelBinding")
            .await
            .ok()
            .and_then(|v| v.as_dword());
        (s, c)
    };
    // Spooler running? The \spoolss pipe answering means the service is up.
    let spooler_open = smb.open_pipe("spoolss").await.is_ok();
    sp.done("posture read");

    ui::header(&format!("DC posture — {}", a.host));
    let mut hits = Vec::new();
    hits.extend(ldap_signing(signing));
    hits.extend(ldap_channel_binding(cbt));
    hits.extend(spooler_running(spooler_open));

    if hits.is_empty() {
        ui::ok("LDAP signing + channel binding enforced, no Spooler on the DC — no relay/coercion posture exposure");
    } else {
        for h in &hits {
            ui::warn(&format!("[{}] {} — {}", h.severity, h.id, h.title));
            ui::field("detail", &h.detail);
        }
        ui::warn(&format!(
            "{} relay/coercion posture exposure(s) on {}",
            hits.len(),
            a.host
        ));
    }
    Ok(())
}
