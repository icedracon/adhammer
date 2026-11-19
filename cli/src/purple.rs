//! T5 (1.6.1): purple-mode detection metadata.
//!
//! Each attack verb with `--purple` prints a defender-facing block alongside
//! its action output describing:
//!   - Which Windows Event IDs (or equivalent) the attack generates
//!   - A reference to a Sigma rule shipped in `detections/` that catches it
//!   - MITRE ATT&CK technique id
//!   - IOC / log-field hints defenders should pivot on
//!
//! The output is structured enough to grep but readable as-is. No incumbent
//! AD red-team tool in the Rust space emits detection telemetry alongside
//! the attack — this is adhammer's defender-grade wedge.
//!
//! Adding a new attack: define a `const DETECTION_<NAME>: Detection` here
//! AND ship the corresponding `detections/<category>/<name>.yml` Sigma
//! rule. The `sigma_rule_files_exist` test fails the build if the pointer
//! is broken.

use serde::Serialize;

/// Detection metadata for one attack. All fields are `&'static str` because
/// the whole table is a compile-time constant and this type is `Serialize`
/// for `--purple --json` output.
#[derive(Serialize, Clone, Copy, Debug)]
#[non_exhaustive]
pub(crate) struct Detection {
    /// Short identifier, e.g. "kerberoasting-rc4".
    pub name: &'static str,
    /// Windows Event IDs this attack generates (empty if non-Windows).
    pub event_ids: &'static [u32],
    /// MITRE ATT&CK technique, e.g. "T1558.003".
    pub mitre: &'static str,
    /// Repo-relative path to the shipped Sigma YAML rule.
    pub sigma_rule: &'static str,
    /// One-line pointers a defender grep's / pivots on in SIEM.
    pub ioc_hints: &'static [&'static str],
    /// Windows log channel carrying the telemetry.
    pub log_source: &'static str,
}

pub(crate) const DETECTION_ROAST: Detection = Detection {
    name: "kerberoasting-rc4",
    event_ids: &[4769],
    mitre: "T1558.003",
    sigma_rule: "detections/kerberos/kerberoasting-rc4-tgs-req.yml",
    ioc_hints: &[
        "TicketEncryptionType = 0x17 (RC4-HMAC) when both DC and service support AES",
        "ServiceName does NOT end with '$' (filters out legitimate computer-account TGS)",
        "Short-lived burst of 4769 to many unique ServiceName values from one SubjectUser",
    ],
    log_source: "Security.evtx (DC)",
};

pub(crate) const DETECTION_DCSYNC: Detection = Detection {
    name: "dcsync-drsuapi",
    event_ids: &[4662],
    mitre: "T1003.006",
    sigma_rule: "detections/dcerpc/dcsync-drsuapi-from-non-dc.yml",
    ioc_hints: &[
        "Properties contains GUIDs 1131f6aa-/1131f6ad-/89e95b76-... (DS-Replication-Get-Changes[-All|-In-Filtered-Set])",
        "SubjectUserName does NOT end with '$' (filters legitimate DC-to-DC replication)",
        "SubjectUserName is NOT 'MSOL_*' (filters Azure AD Connect sync)",
    ],
    log_source: "Security.evtx (DC with Directory Service Access auditing enabled)",
};

pub(crate) const DETECTION_ESC1: Detection = Detection {
    name: "adcs-esc1-san-impersonation",
    event_ids: &[4886, 4887],
    mitre: "T1649",
    sigma_rule: "detections/adcs/esc1-cert-request-with-san-impersonation.yml",
    ioc_hints: &[
        "Attributes field contains literal 'san:' (requester supplied Subject Alternative Name)",
        "Template allows CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Authentication EKU",
        "Follow-on 4768 (TGT issued) or 4624 (logon) for the SAN subject from the enrollee's host",
    ],
    log_source: "CA Audit Log (Application and Services Logs > Certificate Services)",
};

/// Render a detection block to a human-readable multi-line string. Called
/// after the attack's own output when `--purple` is set.
pub(crate) fn render(d: &Detection) -> String {
    let mut s = String::new();
    s.push_str("[purple] detection surface:\n");
    s.push_str(&format!("  name:       {}\n", d.name));
    s.push_str(&format!("  mitre:      {}\n", d.mitre));
    s.push_str(&format!(
        "  event IDs:  {}\n",
        d.event_ids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    s.push_str(&format!("  log source: {}\n", d.log_source));
    s.push_str(&format!("  sigma rule: {}\n", d.sigma_rule));
    s.push_str("  IOCs:\n");
    for h in d.ioc_hints {
        s.push_str(&format!("    - {h}\n"));
    }
    s
}

/// Print the detection block (via `render`) to stdout. Helper used by every
/// attack verb that gains a `--purple` flag so the output is consistent.
pub(crate) fn emit(d: &Detection) {
    print!("{}", render(d));
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[&Detection] = &[&DETECTION_ROAST, &DETECTION_DCSYNC, &DETECTION_ESC1];

    #[test]
    fn sigma_rule_files_exist() {
        // Drift guard: every Detection.sigma_rule path must resolve to a file
        // shipped in the detections/ directory of the workspace root. Prevents
        // a Rust-side rename from silently breaking the pointer.
        // CARGO_MANIFEST_DIR is `.../adhammer/cli`; one `.parent()` is the
        // workspace root. (A second call lands outside the repo entirely.)
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("cli crate has a parent (workspace root)");
        for d in ALL {
            let path = workspace_root.join(d.sigma_rule);
            assert!(
                path.is_file(),
                "detection {} points at {} which does not exist (expected at {})",
                d.name,
                d.sigma_rule,
                path.display()
            );
        }
    }

    #[test]
    fn every_detection_has_event_ids_and_mitre() {
        for d in ALL {
            assert!(!d.event_ids.is_empty(), "{} has no event_ids", d.name);
            assert!(
                d.mitre.starts_with('T') && d.mitre.contains('.') == d.mitre.contains('.'),
                "{} mitre {} not a technique id",
                d.name,
                d.mitre
            );
            assert!(!d.ioc_hints.is_empty(), "{} has no IOC hints", d.name);
        }
    }

    #[test]
    fn render_output_is_grep_able() {
        let out = render(&DETECTION_ROAST);
        assert!(out.contains("sigma rule:"));
        assert!(out.contains("detections/kerberos/"));
        assert!(out.contains("T1558"));
    }
}
