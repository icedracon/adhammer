//! Wire probe for the registry-only AD CS ESC checks. The decision layer lives in
//! [`adhammer_checks::esc_registry`] — this module is a thin transport wrapper that reads
//! CA / DC registry values over MS-RRP (via `dcerpc::rrp`) and hands them to the pure
//! decision functions.
//!
//! Re-exports every item from `adhammer_checks::esc_registry` so existing callers
//! (`main.rs`, `interactive.rs`) can keep using `crate::esc_registry::*` paths — the
//! move was purely a decision-layer extraction, not a public-API break.

pub use adhammer_checks::esc_registry::*;

/// Run every registry-only ESC probe over an already-connected `RegistryClient` and return
/// findings for ESC6/7/10/11/16.
pub async fn probe_esc_registry(
    reg: &mut dcerpc::rrp::RegistryClient<'_>,
    ca_name: &str,
) -> Vec<adhammer_core::Finding> {
    let ca = format!("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca_name}");
    let mut hits: Vec<EscHit> = Vec::new();

    let iflags = reg
        .read_value(&ca, "InterfaceFlags")
        .await
        .ok()
        .and_then(|v| v.as_dword())
        .unwrap_or(0);
    hits.extend(esc11(iflags));

    let pm_root = format!("{ca}\\PolicyModules");
    let policy = reg
        .read_value(&pm_root, "Active")
        .await
        .map(|v| v.as_string())
        .unwrap_or_else(|_| "CertificateAuthority_MicrosoftDefault.Policy".into());
    let policy_key = format!("{pm_root}\\{policy}");
    if let Ok(v) = reg.read_value(&policy_key, "EditFlags").await {
        if let Some(d) = v.as_dword() {
            hits.extend(esc6(d));
        }
    }
    if let Ok(v) = reg.read_value(&policy_key, "DisableExtensionList").await {
        hits.extend(esc16(&v.as_string()));
    }
    if let Ok(v) = reg.read_value(&ca, "Security").await {
        hits.extend(esc7(&v.data));
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
        match reg
            .read_value(
                "SYSTEM\\CurrentControlSet\\Services\\Kdc",
                "StrongCertificateBindingEnforcement",
            )
            .await
        {
            Ok(v) => match v.as_dword() {
                Some(d) => hits.extend(esc10(d)),
                None => hits.push(esc10_absent()),
            },
            Err(_) => hits.push(esc10_absent()),
        }
    }

    hits.into_iter().map(|h| h.into_finding()).collect()
}
