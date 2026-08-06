//! SYSVOL analysis — a thin adapter over the standalone [`gpo`] crate, mapping its neutral
//! GPP / GptTmpl results onto ADhammer [`Finding`]s. All parsing, crypto, and policy logic
//! lives in `gpo`; this crate only owns the ADhammer-specific finding shapes.

use adhammer_core::finding::{mitre, Category, Severity};
use adhammer_core::Finding;

pub use gpo::gpp::{scan, GppHit};

/// Roll the recovered GPP credentials into a single Critical finding.
pub fn finding(hits: &[GppHit]) -> Option<Finding> {
    if hits.is_empty() {
        return None;
    }
    let affected = hits
        .iter()
        .map(|h| {
            format!(
                "{} [{}] :: {}",
                h.user.as_deref().unwrap_or("<no user>"),
                h.password,
                h.file.display()
            )
        })
        .collect::<Vec<_>>();
    Some(Finding {
        id: "A-GppPassword".into(),
        title: "Recoverable GPP cpassword in SYSVOL (MS14-025)".into(),
        category: Category::Anomalies,
        severity: Severity::Critical,
        mitre: vec![mitre::VALID_ACCOUNTS],
        weight_bonus: hits.len() as u32 * 10,
        affected,
        detail: "Group Policy Preferences store passwords encrypted with a Microsoft-published AES key; any authenticated user who can read SYSVOL can decrypt them.".into(),
        remediation: "Remove the offending GPP XML files, rotate the exposed credentials, and stop using GPP to set passwords (KB2962486).".into(),
    })
}

/// GptTmpl.inf security-template analysis.
pub mod gptmpl {
    use super::*;
    pub use gpo::gptmpl::{parse_registry_values, scan_policy};

    fn map_sev(s: gpo::Severity) -> Severity {
        match s {
            gpo::Severity::Low => Severity::Low,
            gpo::Severity::Medium => Severity::Medium,
            gpo::Severity::High => Severity::High,
            gpo::Severity::Critical => Severity::Critical,
        }
    }

    /// Map the GptTmpl policy issues onto ADhammer findings (Anomalies / Valid-Accounts).
    pub fn policy_findings(map: &std::collections::HashMap<String, String>) -> Vec<Finding> {
        gpo::gptmpl::policy_issues(map)
            .into_iter()
            .map(|i| Finding {
                id: i.id.into(),
                title: i.title.into(),
                category: Category::Anomalies,
                severity: map_sev(i.severity),
                mitre: vec![mitre::VALID_ACCOUNTS],
                weight_bonus: 0,
                affected: vec![i.evidence],
                detail: i.detail.into(),
                remediation: i.remediation.into(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpp_finding_maps_to_critical() {
        let hits = vec![GppHit {
            file: "Groups.xml".into(),
            user: Some("svc_admin".into()),
            password: "Local*P4ssword!".into(),
        }];
        let f = finding(&hits).unwrap();
        assert_eq!(f.id, "A-GppPassword");
        assert!(matches!(f.severity, Severity::Critical));
        assert_eq!(f.weight_bonus, 10);
        assert!(finding(&[]).is_none());
    }

    #[test]
    fn gptmpl_issues_map_to_findings() {
        let inf = "[Registry Values]\n\
            MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,1\n\
            MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,1\n";
        let map = gptmpl::parse_registry_values(inf);
        let f = gptmpl::policy_findings(&map);
        assert!(f.iter().any(|x| x.id == "A-NtlmV1"));
        assert!(f.iter().any(|x| x.id == "A-LdapSigning"));
    }
}
