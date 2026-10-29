//! **1.4.8-B WS-DELEGATION-CAPTURE (PARTIAL — recon-only).** Unconstrained-
//! delegation recon — LDAP-only sweep for hosts carrying the
//! `TRUSTED_FOR_DELEGATION` UAC bit (0x80000). Also surfaces constrained-with-
//! protocol-transition accounts. Reuses `crate::attacks::scan::ScanArgs` since
//! the collector bind is identical to `scan`.
//!
//! **What's missing for full capture-and-forwarded-TGT-extract**: the abuse
//! recipe below prints step 2 as "Capture the incoming Kerberos AP-REQ on
//! this host" — that's not yet implemented. It needs (a) a TCP listener on
//! the port the coerced DC will authenticate to, (b) parsing the incoming
//! AP-REQ + Authenticator, (c) extracting the forwarded TGT from the
//! Authenticator when the GSS-KRB5 Delegation flag is set. Deferred as a
//! follow-up workstream — until it lands, this verb documents the abuse
//! path so an operator can chain manually with existing tools.

use anyhow::Result;

use adhammer_collector::Collector;

use crate::attacks::scan::{config, ScanArgs};
use crate::ui;
use crate::ui::OutcomeKind;

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

    let dc_label = dc_baseline.to_string();
    let risky_label = risky.len().to_string();
    ui::verb_banner(
        "attack unconstrained",
        &[
            ("scope", "LDAP-only recon"),
            ("dc-baseline", dc_label.as_str()),
            ("risky-non-dc", risky_label.as_str()),
        ],
    );
    if risky.is_empty() {
        ui::note("(none — only DCs carry TRUSTED_FOR_DELEGATION, which is expected)");
    } else {
        let rows: Vec<Vec<String>> = risky
            .iter()
            .map(|(sam, dn)| vec![(*sam).to_string(), (*dn).to_string()])
            .collect();
        ui::table(&["sAMAccountName", "DN"], &rows);
        ui::note("");
        ui::note("Abuse recipe (once you control one of these hosts):");
        ui::note("  1. attack coerce --host <DC> --pipe efsrpc  --listener <this-host>");
        ui::note("     (or --pipe spoolss|netdfs|fssagentrpc)");
        ui::note("  2. Capture the incoming Kerberos AP-REQ on this host.");
        ui::note("  3. Extract the forwarded TGT from the Authenticator (GSS-KRB5 Deleg flag).");
        ui::note("  4. attack dcsync --user krbtgt   (or golden-ticket forge)");
    }

    if !proto_transition.is_empty() {
        ui::note("");
        ui::info(&format!(
            "Constrained delegation w/ protocol transition ({}) — S4U2Self abuse",
            proto_transition.len()
        ));
        let rows: Vec<Vec<String>> = proto_transition
            .iter()
            .map(|(sam, dn)| vec![(*sam).to_string(), (*dn).to_string()])
            .collect();
        ui::table(&["sAMAccountName", "DN"], &rows);
        ui::note("→ attack constrained --host <this-host> --target <spn>");
    }

    // Close with a boxed summary so operators find the recon boundary in scrollback.
    let status = if risky.is_empty() && proto_transition.is_empty() {
        OutcomeKind::Clean
    } else {
        OutcomeKind::Validated
    };
    ui::summary_box("domain delegation posture", status, &[], None);
    Ok(())
}
