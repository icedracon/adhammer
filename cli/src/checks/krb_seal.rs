//! `check krb-seal` — live-DC probe of the WS-4-P2 AES256-CTS-HMAC-SHA1-96 sealer.
//!
//! Flow:
//! 1. AS-REQ + AS-REP: get a TGT for the caller.
//! 2. TGS-REQ + TGS-REP: get two service tickets for `cifs/<dc>` — one drives SMB
//!    signing, the other feeds a second AP-REQ that the DCE-RPC pipe bind consumes.
//! 3. SMB2 NEGOTIATE + SESSION_SETUP (Kerberos): opens the authenticated session.
//! 4. TREE_CONNECT `\\<dc>\IPC$` + OPEN `\PIPE\lsarpc`.
//! 5. DCE-RPC BIND on the pipe with `auth_type=GSS_KERBEROS`, `auth_level=PKT_PRIVACY`;
//!    hand the pipe a `Box<KrbSealer>` built from the RPC ticket's 32-byte AES256
//!    subkey and expect a BIND_ACK.
//! 6. Optionally issue one `call_sealed_kerberos` (LSA `OpenPolicy2` = opnum 44) and
//!    print whether the DC accepted or faulted.
//!
//! This is the honest first probe against a real DC. The current sealer honors dcerpc's
//! 28-byte `AES_SHA1_AUTH_VALUE_LEN` contract, which is **not** byte-compatible with the
//! MS-KILE RRC-rotated ~60-byte wire layout; the OpenPolicy2 leg will almost certainly
//! fault, and the fault code (or the exact BIND-ACK/BIND-NAK reason) is the datum we
//! need to iterate on. Success up through step 5 alone is worth reporting.

use anyhow::{Context, Result};
use clap::Parser;

use crate::ui;

#[derive(Parser)]
pub(crate) struct CheckKrbSealArgs {
    /// DC hostname or IP for the TCP + SMB target. Can be either — the workstation
    /// just needs to route to it.
    #[arg(long)]
    pub host: String,
    /// SPN hostname override (goes into `cifs/<spn_host>`). Defaults to `--host`.
    /// Set this when `--host` is an IP the workstation reaches directly, but the DC's
    /// SPNs use its DNS name (mismatch → `KRB_AP_ERR_TKT_INV` from the KDC).
    #[arg(long)]
    pub spn_host: Option<String>,
    /// NetBIOS domain, e.g. TESTLAB.
    #[arg(long)]
    pub domain: String,
    /// Kerberos realm, e.g. TESTLAB.LOCAL. Case-sensitive per RFC 4120.
    #[arg(long)]
    pub realm: String,
    /// KDC host — usually the same as `--host` on a single-DC lab. Separate flag so
    /// tests against a member server can point Kerberos at the DC while probing the
    /// member's own pipes.
    #[arg(long)]
    pub kdc: String,
    /// Bind username (sAMAccountName, no domain prefix).
    #[arg(long)]
    pub user: String,
    /// Bind password. Empty string treated as "use ADHAMMER_PASSWORD env".
    #[arg(long, default_value = "")]
    pub password: String,
    /// After BIND_ACK, attempt one `LsarOpenPolicy2` opnum 44 call. The current
    /// sealer's wire format is scaffolding; expect this to fault. The fault code is
    /// what we need to iterate to a byte-compatible wire layout in Session 4.
    #[arg(long)]
    pub try_call: bool,
}

pub(crate) async fn check_krb_seal(mut a: CheckKrbSealArgs) -> Result<()> {
    let mut checklist = ui::StageChecklist::new([
        "resolve password",
        "asktgt (AS-REP)",
        "TGS for cifs/<host> ×2",
        "SMB session-setup (Kerberos)",
        "tree-connect IPC$ + open lsarpc",
        "DCE-RPC BIND sealed Kerberos",
        "LsarOpenPolicy2 (opnum 44)",
    ]);
    let result = run(&mut a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("krb-seal stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("krb-seal stages (failed)");
        }
    }
    result
}

async fn run(a: &mut CheckKrbSealArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    use adhammer_kerberos::rpc_sealer::AesCts96Sealer;
    use adhammer_kerberos::{
        build_ap_req_gss, build_ap_req_gss_aes256, get_service_ticket, get_tgt,
    };
    use dcerpc::transport::SmbPipe;
    use dcerpc::Syntax;

    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    checklist.record_ok("resolve password", "resolved");

    // Step 1: get a TGT (Tgt struct with session key + ticket, not a ccache blob).
    let tgt = get_tgt(&a.user, &a.password, &a.realm, &a.kdc)
        .await
        .with_context(|| format!("get_tgt for {}@{}", a.user, a.realm))?;
    // (Tgt::crealm is private — use the realm we passed in for the display.)
    checklist.record_ok("asktgt (AS-REP)", format!("TGT for {}@{}", a.user, a.realm));

    // Step 2: two service tickets for cifs/<spn_host>. One drives SMB, the other the pipe
    // bind. Two separate tickets avoid Windows' AP-REQ replay-cache rejecting the second
    // (same cname+sname+ctime tuple treated as a replay).
    let spn_host = a.spn_host.clone().unwrap_or_else(|| a.host.clone());
    let spn = format!("cifs/{spn_host}");
    let st_smb = get_service_ticket(&tgt, &spn, &a.kdc)
        .await
        .with_context(|| format!("TGS for {spn} (SMB leg)"))?;
    let st_rpc = get_service_ticket(&tgt, &spn, &a.kdc)
        .await
        .with_context(|| format!("TGS for {spn} (RPC leg)"))?;
    checklist.record_ok(
        "TGS for cifs/<host> ×2",
        format!("two AES256 service tickets for {spn}"),
    );

    // Step 3: SMB session-setup with Kerberos. build_ap_req_gss emits an AES128 subkey
    // that becomes the SMB session key — that's what login_kerberos expects (16 bytes).
    let (spnego_smb, subkey_smb) =
        build_ap_req_gss(&st_smb).context("build AP-REQ for SMB session-setup")?;
    let mut smb = smb2_client::SmbClient::connect(&a.host)
        .await
        .with_context(|| format!("SMB TCP connect to {}:445", a.host))?;
    smb.login_kerberos(&spnego_smb, &subkey_smb)
        .await
        .context("SMB2 SESSION_SETUP with Kerberos AP-REQ")?;
    checklist.record_ok(
        "SMB session-setup (Kerberos)",
        "SESSION_SETUP OK with AES128 subkey",
    );

    // Step 4: IPC$ + \PIPE\lsarpc.
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host))
        .await
        .context("SMB2 TREE_CONNECT \\IPC$")?;
    let pipe_id = smb
        .open_pipe("lsarpc")
        .await
        .context("SMB2 OPEN \\PIPE\\lsarpc")?;
    checklist.record_ok(
        "tree-connect IPC$ + open lsarpc",
        "pipe file handle acquired",
    );

    // Step 5: sealed Kerberos BIND on the pipe with the RPC ticket's 32-byte AES256 subkey.
    let (spnego_rpc, subkey_rpc) =
        build_ap_req_gss_aes256(&st_rpc).context("build AES256 AP-REQ for RPC bind")?;
    let sealer = Box::new(AesCts96Sealer::new_initiator(subkey_rpc, false));
    let mut pipe = SmbPipe::new(&mut smb, pipe_id);
    // LSARPC abstract syntax (MS-LSAT / MS-LSAD) — this is the interface \PIPE\lsarpc serves.
    // {12345778-1234-abcd-ef00-0123456789ab} v0.0 — the well-known LSA interface UUID.
    let lsarpc = Syntax {
        uuid: [
            0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab,
        ],
        ver_major: 0,
        ver_minor: 0,
    };
    pipe.bind_sealed_kerberos(lsarpc, &spnego_rpc, sealer)
        .await
        .context("DCE-RPC BIND with sealed Kerberos")?;
    checklist.record_ok("DCE-RPC BIND sealed Kerberos", "BIND_ACK received");

    // Step 6: optional first sealed call.
    if a.try_call {
        // LsarOpenPolicy2 (opnum 44) — minimal argument shape: NDR-marshaled
        // ObjectAttributes(empty) + DesiredAccessMask. Adjust after live probe.
        // For scaffolding, send an empty stub and let the server tell us what
        // it expected — the error path is the datum, not the success path.
        match pipe.call_sealed_kerberos(44, &[]).await {
            Ok(resp) => {
                checklist.record_ok(
                    "LsarOpenPolicy2 (opnum 44)",
                    format!("{} byte response — decoding TBD", resp.len()),
                );
                println!("[+] sealed call round-trip: {} bytes returned", resp.len());
            }
            Err(e) => {
                // Expected on first probe — wire format mismatch. Bubble the error
                // so the outer wrapper records the failure stage; that's the whole
                // point of this check (we're gathering the fault code).
                anyhow::bail!("call_sealed_kerberos faulted: {e}");
            }
        }
    } else {
        checklist.record_skipped(
            "LsarOpenPolicy2 (opnum 44)",
            "pass --try-call to send one sealed request",
        );
    }
    Ok(())
}
