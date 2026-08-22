//! Registry-only AD CS ESC checks (ESC6/10/11/16) over MS-RRP subcommand.
//!
//! **Naming note:** this module (`crate::enums::esc_registry`) hosts the
//! `enum esc` subcommand handler. It shares its base name with the older
//! `crate::esc_registry` module (top-level), which is the thin transport
//! wrapper around `adhammer_checks::esc_registry`. References to the
//! decision-layer helpers below go through `crate::esc_registry::*`, NOT
//! the sibling module.

use anyhow::Result;
use clap::Parser;

use crate::ui;

#[derive(Parser)]
pub(crate) struct EscArgs {
    /// CA host. ESC10 is read from this host's Kdc key too, so point it at a DC-hosted CA.
    #[arg(long)]
    pub host: String,
    /// NetBIOS domain, e.g. CORP.
    #[arg(long)]
    pub domain: String,
    #[arg(long)]
    pub user: String,
    #[arg(long)]
    pub password: String,
    /// CA name (the `Configuration\<CA>` registry key), e.g. corp-CA.
    #[arg(long)]
    pub ca: String,
}

/// Registry-only AD CS ESC checks (ESC6/10/11/16) over MS-RRP: authenticate over SMB, open
/// `\winreg`, read the CA/DC registry values, and decide each ESC. Needs the target's Remote
/// Registry service reachable.
pub(crate) async fn esc_registry_scan(a: EscArgs) -> Result<()> {
    use crate::esc_registry::{esc10, esc11, esc16, esc6, esc7};
    use dcerpc::rrp::RegistryClient;
    use smb2_client::SmbClient;

    let sp = ui::Spinner::start(format!("{} — SMB auth + \\winreg", a.host));
    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let mut reg = RegistryClient::connect(&mut smb, &a.domain, &a.user, &a.password, &a.host)
        .await
        .map_err(|e| {
            // 0xC00000AC = STATUS_ILLEGAL_FUNCTION → \winreg pipe not exposed, i.e. the
            // Remote Registry service is stopped/disabled. Very common on hardened DCs.
            let msg = e.to_string();
            if msg.contains("0xc00000ac") || msg.contains("open \\winreg") {
                anyhow::anyhow!(
                    "\\winreg unreachable on {} — the Remote Registry service is stopped or \
                     disabled (STATUS_ILLEGAL_FUNCTION 0xC00000AC). Start it on the CA host \
                     (`Set-Service RemoteRegistry -StartupType Automatic; Start-Service RemoteRegistry`) \
                     then rerun. ESC1/2/3/4/9/13 don't need this — only ESC6/10/11/16 read \
                     registry state.",
                    a.host
                )
            } else {
                e.into()
            }
        })?;
    sp.done("Remote Registry reachable");

    ui::header(&format!("AD CS registry ESC checks — CA {}", a.ca));
    let ca = format!(
        "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{}",
        a.ca
    );
    let mut hits = Vec::new();

    // InterfaceFlags sits directly under the CA config key. If absent, the default lacks
    // IF_ENFORCEENCRYPTICERTREQUEST (relayable), so treat a missing value as 0 rather than skipping.
    let iflags = reg
        .read_value(&ca, "InterfaceFlags")
        .await
        .ok()
        .and_then(|v| v.as_dword())
        .unwrap_or(0);
    hits.extend(esc11(iflags));

    // EditFlags and DisableExtensionList live under the *active policy module* subkey, whose name
    // is the `Active` REG_SZ under `<CA>\PolicyModules` (e.g. CertificateAuthority_MicrosoftDefault.Policy).
    let pm_root = format!("{ca}\\PolicyModules");
    let policy = reg
        .read_value(&pm_root, "Active")
        .await
        .map(|v| v.as_string())
        .unwrap_or_else(|_| "CertificateAuthority_MicrosoftDefault.Policy".into());
    let policy_key = format!("{pm_root}\\{policy}");
    if let Ok(v) = reg.read_value(&policy_key, "EditFlags").await {
        if let Some(d) = v.as_dword() {
            hits.extend(esc6(d));
        }
    }
    if let Ok(v) = reg.read_value(&policy_key, "DisableExtensionList").await {
        hits.extend(esc16(&v.as_string()));
    }
    // ESC7 — the CA `Security` REG_BINARY is a SECURITY_DESCRIPTOR; flag non-Tier-0 ManageCA/Certs.
    if let Ok(v) = reg.read_value(&ca, "Security").await {
        hits.extend(esc7(&v.data));
    }
    // ESC10 lives on the DC's Kdc key and only applies to a DC. Confirm DC-ness via NTDS first so an
    // absent value on a CA-only host isn't mis-flagged; on a real DC, an absent value is NOT
    // automatically safe (weak default on 2016–2022), so flag it with that caveat.
    let is_dc = reg
        .read_value(
            "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
            "DSA Working Directory",
        )
        .await
        .is_ok()
        || reg
            .read_value(
                "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                "Machine DN Name",
            )
            .await
            .is_ok();
    if is_dc {
        match reg
            .read_value(
                "SYSTEM\\CurrentControlSet\\Services\\Kdc",
                "StrongCertificateBindingEnforcement",
            )
            .await
        {
            Ok(v) => match v.as_dword() {
                Some(d) => hits.extend(esc10(d)),
                None => hits.push(crate::esc_registry::esc10_absent()),
            },
            Err(_) => hits.push(crate::esc_registry::esc10_absent()),
        }
    }

    if hits.is_empty() {
        ui::ok("no registry-based ESC (ESC6/10/11/16) exposure found");
    } else {
        for h in &hits {
            ui::warn(&format!("{} — {}", h.id, h.title));
            ui::field("detail", &h.detail);
        }
        ui::warn(&format!(
            "{} registry-based ESC exposure(s) on {}",
            hits.len(),
            a.host
        ));
    }
    Ok(())
}
