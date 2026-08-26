//! Wire probe for the registry-only AD CS ESC checks. The decision layer lives in
//! [`adhammer_checks::esc_registry`] — this module is a thin transport wrapper that reads
//! CA / DC registry values over MS-RRP (via `dcerpc::rrp`) and hands them to the pure
//! decision functions.
//!
//! Re-exports every item from `adhammer_checks::esc_registry` so existing callers
//! (`main.rs`, `interactive.rs`) can keep using `crate::esc_registry::*` paths — the
//! move was purely a decision-layer extraction, not a public-API break.

pub use adhammer_checks::esc_registry::*;

/// WS-WPT session 4b: one recorded MS-RRP read — the key path, the value name asked for, and a
/// short human-readable summary of what came back (or the error). Attached as a two-frame
/// `WireExchange` to the ESC finding it produced, so the report shows the exact registry probe.
fn rrp_wire(key: &str, value: &str, result_summary: &str) -> Vec<adhammer_core::WireExchange> {
    use adhammer_core::{WireExchange, WireLayer};
    vec![
        WireExchange::sent(
            WireLayer::Rrp,
            format!("OpenBaseKey(HKLM) + RegQueryValue key={key} value={value}"),
        ),
        WireExchange::recv(WireLayer::Rrp, result_summary.to_string()),
    ]
}

/// Run every registry-only ESC probe over an already-connected `RegistryClient` and return
/// findings for ESC6/7/10/11/16.
pub async fn probe_esc_registry(
    reg: &mut dcerpc::rrp::RegistryClient<'_>,
    ca_name: &str,
) -> Vec<adhammer_core::Finding> {
    let ca = format!("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca_name}");
    // WS-WPT: build hits with the (ESC id → wire) association per probe read.
    let mut hits: Vec<(EscHit, Vec<adhammer_core::WireExchange>)> = Vec::new();

    let iflags_read = reg.read_value(&ca, "InterfaceFlags").await;
    let iflags = iflags_read
        .as_ref()
        .ok()
        .and_then(|v| v.as_dword())
        .unwrap_or(0);
    let iflags_wire = rrp_wire(
        &ca,
        "InterfaceFlags",
        &match iflags_read {
            Ok(_) => format!("DWORD 0x{iflags:08x}"),
            Err(ref e) => format!("read failed: {e}"),
        },
    );
    if let Some(h) = esc11(iflags) {
        hits.push((h, iflags_wire.clone()));
    }

    let pm_root = format!("{ca}\\PolicyModules");
    let policy_read = reg.read_value(&pm_root, "Active").await;
    let policy = policy_read
        .as_ref()
        .map(|v| v.as_string())
        .unwrap_or_else(|_| "CertificateAuthority_MicrosoftDefault.Policy".into());
    let policy_key = format!("{pm_root}\\{policy}");
    if let Ok(v) = reg.read_value(&policy_key, "EditFlags").await {
        if let Some(d) = v.as_dword() {
            let wire = rrp_wire(&policy_key, "EditFlags", &format!("DWORD 0x{d:08x}"));
            if let Some(h) = esc6(d) {
                hits.push((h, wire));
            }
        }
    }
    if let Ok(v) = reg.read_value(&policy_key, "DisableExtensionList").await {
        let s = v.as_string();
        let n = s.lines().count();
        let wire = rrp_wire(
            &policy_key,
            "DisableExtensionList",
            &format!(
                "REG_MULTI_SZ ({n} entr{})",
                if n == 1 { "y" } else { "ies" }
            ),
        );
        if let Some(h) = esc16(&s) {
            hits.push((h, wire));
        }
    }
    if let Ok(v) = reg.read_value(&ca, "Security").await {
        let n = v.data.len();
        let wire = rrp_wire(&ca, "Security", &format!("BINARY SD ({n} bytes)"));
        for h in esc7(&v.data) {
            hits.push((h, wire.clone()));
        }
    }

    let is_dc = reg
        .read_value(
            "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
            "DSA Working Directory",
        )
        .await
        .is_ok()
        || reg
            .read_value(
                "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                "Machine DN Name",
            )
            .await
            .is_ok();
    if is_dc {
        let kdc_key = "SYSTEM\\CurrentControlSet\\Services\\Kdc";
        match reg
            .read_value(kdc_key, "StrongCertificateBindingEnforcement")
            .await
        {
            Ok(v) => match v.as_dword() {
                Some(d) => {
                    let wire = rrp_wire(
                        kdc_key,
                        "StrongCertificateBindingEnforcement",
                        &format!("DWORD {d}"),
                    );
                    if let Some(h) = esc10(d) {
                        hits.push((h, wire));
                    }
                }
                None => {
                    let wire = rrp_wire(
                        kdc_key,
                        "StrongCertificateBindingEnforcement",
                        "unexpected type (not a DWORD)",
                    );
                    hits.push((esc10_absent(), wire));
                }
            },
            Err(e) => {
                let wire = rrp_wire(
                    kdc_key,
                    "StrongCertificateBindingEnforcement",
                    &format!("read failed: {e}"),
                );
                hits.push((esc10_absent(), wire));
            }
        }
    }

    // The pure decision layer can't know which CA/DC produced the reading, so registry-ESC
    // findings (esp. DC-posture ones like ESC10) come back with an empty `affected`. Attach the
    // probed CA/DC name here so every finding points at a concrete object instead of nothing.
    hits.into_iter()
        .map(|(h, wire)| {
            let mut f = h.into_finding();
            if f.affected.is_empty() {
                f.affected.push(ca_name.to_string());
            }
            f.exchange = wire;
            f
        })
        .collect()
}
