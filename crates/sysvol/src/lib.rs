//! SYSVOL collection — Group Policy Preferences (GPP) cpassword recovery (MS14-025).
//!
//! On Windows the SYSVOL share is reachable as a UNC path (`\\domain\SYSVOL\...`) through
//! the OS SMB redirector, so we walk it with ordinary filesystem I/O — no Rust SMB stack,
//! no FFI. GPP XML files embed a `cpassword` attribute encrypted with an AES-256 key that
//! Microsoft *published*, making every such password trivially recoverable. We decrypt it
//! and report the file, the target account, and the plaintext.

use adhammer_core::finding::{mitre, Category, Severity};
use adhammer_core::Finding;
use std::path::{Path, PathBuf};

pub mod gpp;
pub mod gptmpl;

/// One recovered GPP credential.
#[derive(Clone, Debug)]
pub struct GppHit {
    pub file: PathBuf,
    pub user: Option<String>,
    pub password: String,
}

/// Recursively scan a SYSVOL path for GPP XML files carrying a `cpassword`.
/// `root` is typically `\\<domain-fqdn>\SYSVOL` on a domain-joined host.
pub fn scan(root: &Path) -> Vec<GppHit> {
    let mut hits = Vec::new();
    walk(root, &mut hits);
    hits
}

fn walk(dir: &Path, out: &mut Vec<GppHit>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(?dir, %e, "skip unreadable dir");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("xml")) {
            if let Ok(content) = std::fs::read_to_string(&path) {
                for (b64, user) in gpp::extract_cpasswords(&content) {
                    match gpp::decrypt_cpassword(&b64) {
                        Ok(password) => out.push(GppHit { file: path.clone(), user, password }),
                        Err(e) => tracing::warn!(?path, %e, "cpassword decrypt failed"),
                    }
                }
            }
        }
    }
}

/// Roll the recovered credentials into a single Critical finding.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_walks_tree_and_recovers_password() {
        let dir = std::env::temp_dir().join(format!("adhammer_sysvol_{}", std::process::id()));
        let deep = dir.join("Policies/{GUID}/Machine/Preferences/Groups");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(
            deep.join("Groups.xml"),
            r#"<Groups><User><Properties userName="svc_admin"
               cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"/></User></Groups>"#,
        )
        .unwrap();

        let hits = scan(&dir);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].user.as_deref(), Some("svc_admin"));
        assert_eq!(hits[0].password, "Local*P4ssword!");
        assert!(finding(&hits).is_some());
    }
}
