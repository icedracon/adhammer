//! **1.5.2 G-D**: `check wdigest` — DC/host `UseLogonCredential=1` finding.
//!
//! Windows caches cleartext passwords in LSASS when the WDigest security
//! provider is turned on and `UseLogonCredential` (DWORD, `HKLM\SYSTEM\
//! CurrentControlSet\Control\SecurityProviders\WDigest`) is set to `1`.
//! Since Windows 8.1 / Server 2012 R2 the value has been absent by default
//! (equivalent to 0 = off); explicit `1` is the finding — LSASS dumps yield
//! plaintext creds. This check reads the value over MS-RRP
//! (SMB → `\PIPE\winreg`) and reports a Critical finding when it is truthy.

use adhammer_core::finding::{Category, Evidence, Finding, Mitre, Severity};
use anyhow::Result;
use clap::Parser;
use dcerpc::rrp::RegistryClient;
use serde_json::json;
use smb2_client::SmbClient;

const T1003_001: Mitre = Mitre {
    id: "T1003.001",
    name: "OS Credential Dumping: LSASS Memory",
};

#[derive(Parser)]
pub(crate) struct CheckWdigestArgs {
    /// Target host (IP or FQDN). Any domain-joined Windows host works — DCs,
    /// member servers, workstations. The MS-RRP `\PIPE\winreg` interface is
    /// what LSASS.exe protects; local Administrator (or an account in the
    /// remote-registry-service ACL) is required.
    #[arg(long)]
    pub host: String,
    /// NetBIOS domain name for SMB auth.
    #[arg(long)]
    pub domain: String,
    /// SMB user (should have local admin on the target for remote registry).
    #[arg(long)]
    pub user: String,
    /// SMB password. Accepts `env:VAR` / `@file:PATH` / secure prompt.
    #[arg(long)]
    pub password: adhammer_core::SecretString,
    /// Emit JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

pub(crate) async fn check_wdigest(a: CheckWdigestArgs) -> Result<()> {
    let sp = crate::ui::Spinner::start(format!("MS-RRP WDigest probe → {}", a.host));

    let pw = a.password.expose().clone();
    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &pw).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let mut reg = match RegistryClient::connect(&mut smb, &a.domain, &a.user, &pw, &a.host).await {
        Ok(r) => r,
        Err(e) => {
            // Server 2016+ ships with the Remote Registry service disabled by
            // default; `open \winreg` returns STATUS_ILLEGAL_FUNCTION
            // (0xC00000AC). Report as a `Skipped` outcome — that IS the
            // observation, not a tool bug.
            let msg = e.to_string();
            let unavailable = msg.contains("0xc00000ac")
                || msg.contains("0xC00000AC")
                || msg.to_ascii_lowercase().contains("open \\winreg");
            if unavailable {
                sp.done(&format!(
                    "{}: Remote Registry unavailable (`\\PIPE\\winreg` refused) — check skipped",
                    a.host
                ));
                if a.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "command": "adhammer check wdigest",
                            "success": true,
                            "evidence": {
                                "host": a.host,
                                "state": "skipped_no_remote_registry",
                                "wire": msg,
                            },
                        }))?
                    );
                }
                return Ok(());
            }
            return Err(e.into());
        }
    };

    let key = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";
    let read = reg.read_value(key, "UseLogonCredential").await;
    let (state, wire_text) = match &read {
        Ok(v) => {
            let dw = v.as_dword().unwrap_or(0);
            (WdigestState::from_dword(dw), format!("DWORD 0x{dw:08x}"))
        }
        Err(e) => {
            let msg = e.to_string();
            let low = msg.to_ascii_lowercase();
            // `win32 2` = ERROR_FILE_NOT_FOUND — the WDigest value doesn't exist,
            // i.e. the safe OS default. dcerpc/rrp 0.2.x surfaces it as
            // `BaseRegQueryValue failed (win32 2)`; also match the raw name.
            let absent = low.contains("not found")
                || msg.contains("ERROR_FILE_NOT_FOUND")
                || msg.contains("win32 2")
                || low.contains("basereg") && low.contains("(win32 2)");
            if absent {
                (WdigestState::AbsentSafe, format!("value absent: {msg}"))
            } else {
                sp.done_warn(&format!("read failed: {msg}"));
                return Err(anyhow::anyhow!("WDigest read: {msg}"));
            }
        }
    };

    sp.done(&format!("{}: {}", a.host, state.summary()));

    let finding = state.to_finding(&a.host, &wire_text, key);

    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "command": "adhammer check wdigest",
                "success": true,
                "evidence": {
                    "host": a.host,
                    "state": state.tag(),
                    "wire": wire_text,
                    "finding": finding.as_ref().map(finding_to_json),
                },
            }))?
        );
    } else {
        eprintln!();
        eprintln!("== check wdigest ({}) ==", a.host);
        eprintln!("  UseLogonCredential = {}", state.summary());
        if let Some(f) = &finding {
            eprintln!("  [{:?}] {}", f.severity, f.title);
            eprintln!("    detail: {}", f.detail);
            if let Some(i) = &f.impact {
                eprintln!("    impact: {i}");
            }
            for ev in &f.evidence {
                eprintln!("    proof:  {} = {}", ev.source, ev.value);
            }
        }
    }
    Ok(())
}

enum WdigestState {
    Enabled,
    ExplicitlyDisabled,
    AbsentSafe,
}

impl WdigestState {
    fn from_dword(dw: u32) -> Self {
        if dw == 0 {
            Self::ExplicitlyDisabled
        } else {
            Self::Enabled
        }
    }

    fn summary(&self) -> &'static str {
        match self {
            Self::Enabled => "1 (enabled — LSASS caches cleartext)",
            Self::ExplicitlyDisabled => "0 (explicitly disabled)",
            Self::AbsentSafe => "absent (OS default, safe)",
        }
    }

    fn tag(&self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::ExplicitlyDisabled => "explicitly_disabled",
            Self::AbsentSafe => "absent_safe",
        }
    }

    fn to_finding(&self, host: &str, wire_text: &str, key: &str) -> Option<Finding> {
        if !matches!(self, Self::Enabled) {
            return None;
        }
        Some(Finding {
            id: String::from("C-WDigestEnabled"),
            title: format!("WDigest UseLogonCredential=1 on {host} — LSASS caches cleartext"),
            severity: Severity::Critical,
            category: Category::Anomalies,
            mitre: vec![T1003_001],
            affected: vec![host.to_string()],
            evidence: vec![Evidence::new(
                format!("MS-RRP HKLM\\{key}\\UseLogonCredential"),
                wire_text.to_string(),
            )],
            detail: format!(
                "HKLM\\{key}\\UseLogonCredential is DWORD 1 — the WDigest provider caches \
                 cleartext passwords for every interactive logon since the value was set. \
                 Default since Windows 8.1 / Server 2012 R2 is absent/0."
            ),
            impact: Some(String::from(
                "Cleartext-credential harvesting via mimikatz-style LSASS dumps. Any \
                 subsequent interactive / RemoteInteractive / RunAs logon on this host leaks \
                 its password in memory.",
            )),
            remediation: String::from(
                "Remove UseLogonCredential (or set it to DWORD 0) via GPO or \
                 `reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest \
                 /v UseLogonCredential /f`, then reboot / log off to clear cached creds.",
            ),
            weight_bonus: 0,
            exchange: vec![],
        })
    }
}

fn finding_to_json(f: &Finding) -> serde_json::Value {
    json!({
        "id": f.id,
        "title": f.title,
        "severity": format!("{:?}", f.severity),
        "affected": f.affected,
        "detail": f.detail,
        "impact": f.impact,
        "remediation": f.remediation,
        "mitre": f.mitre.iter().map(|m| json!({"id": m.id, "name": m.name})).collect::<Vec<_>>(),
    })
}
