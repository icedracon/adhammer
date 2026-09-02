//! SYSVOL collection — Group Policy Preferences (GPP) cpassword recovery (MS14-025).
//!
//! On Windows the SYSVOL share is reachable as a UNC path (`\\domain\SYSVOL\...`) through
//! the OS SMB redirector, so we walk it with ordinary filesystem I/O — no Rust SMB stack,
//! no FFI. GPP XML files embed a `cpassword` attribute encrypted with an AES-256 key that
//! Microsoft *published*, making every such password trivially recoverable. We decrypt it
//! and report the file, the target account, and the plaintext.

// Clippy 1.98 suggests `as_chunks::<N>()`; these wire parsers intentionally keep
// `chunks_exact(N)` next to their runtime field widths. See `adhammer_secrets`.
#![allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]

use adhammer_core::finding::{mitre, Category, Evidence, Severity};
use adhammer_core::secret_write::{write_secret_artifact, SecretArtifact};
use adhammer_core::{Finding, SecretString};
use std::path::{Path, PathBuf};

pub mod gpp;
pub mod gptmpl;

/// One recovered GPP credential.
///
/// WS-SECRET-BOUNDARY (1.5.0): `password` is a `SecretString`, so a stray
/// `tracing::debug!("{hit:?}")` or `println!("{}", hit.password)` cannot
/// leak the plaintext — `Debug`/`Display` both print `"***"`. Sites that
/// intentionally consume the plaintext (dump-to-secure-file, feeding an
/// operator-supplied hashcat pipeline) must call `.expose_secret()`, which
/// makes them greppable for security review.
#[derive(Clone, Debug)]
pub struct GppHit {
    pub file: PathBuf,
    pub user: Option<String>,
    pub password: SecretString,
}

/// WS-LDAP-INTEGRITY (1.5.0) — SYSVOL DoS-defence budgets. Real SYSVOL
/// trees have depths well under 10 and GPP XML files well under 100 KiB.
/// Ceiling values here are ~2 orders of magnitude above realistic
/// production shapes so a hostile / broken SYSVOL server (or an fs-loop
/// mounted at the walk root) cannot consume unbounded memory. See BF-7.
const SYSVOL_MAX_WALK_DEPTH: usize = 32;
const SYSVOL_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB
const SYSVOL_MAX_HITS: usize = 10_000;

/// Recursively scan a SYSVOL path for GPP XML files carrying a `cpassword`.
/// `root` is typically `\\<domain-fqdn>\SYSVOL` on a domain-joined host.
///
/// Walk stops early on any of: [`SYSVOL_MAX_WALK_DEPTH`] recursion
/// depth reached, [`SYSVOL_MAX_HITS`] recovered credentials, or a file
/// larger than [`SYSVOL_MAX_FILE_BYTES`] (that file is skipped, walk
/// continues). All three refusals are logged at `warn` so an operator
/// sees the truncation without a silent short-return.
pub fn scan(root: &Path) -> Vec<GppHit> {
    let mut hits = Vec::new();
    walk(root, 0, &mut hits);
    hits
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<GppHit>) {
    if depth > SYSVOL_MAX_WALK_DEPTH {
        tracing::warn!(
            ?dir,
            depth,
            "sysvol walk depth cap {SYSVOL_MAX_WALK_DEPTH} reached — stopping this subtree"
        );
        return;
    }
    if out.len() >= SYSVOL_MAX_HITS {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(?dir, %e, "skip unreadable dir");
            return;
        }
    };
    for entry in entries.flatten() {
        if out.len() >= SYSVOL_MAX_HITS {
            tracing::warn!("sysvol hit cap {SYSVOL_MAX_HITS} reached — stopping the walk");
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            walk(&path, depth + 1, out);
        } else if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("xml"))
        {
            let size = std::fs::metadata(&path)
                .map(|m| m.len())
                .unwrap_or(u64::MAX);
            if size > SYSVOL_MAX_FILE_BYTES {
                tracing::warn!(
                    ?path,
                    size,
                    "sysvol file exceeds {SYSVOL_MAX_FILE_BYTES}-byte cap — skipping"
                );
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&path) {
                for (b64, user) in gpp::extract_cpasswords(&content) {
                    match gpp::decrypt_cpassword(&b64) {
                        Ok(password) => out.push(GppHit {
                            file: path.clone(),
                            user,
                            password,
                        }),
                        Err(e) => tracing::warn!(?path, %e, "cpassword decrypt failed"),
                    }
                }
            }
        }
    }
}

/// Roll the recovered credentials into a single Critical finding.
///
/// WS-SECRET-BOUNDARY (1.5.0): the returned `Finding` never carries the
/// recovered plaintext. `affected` lists user + file only; `evidence` cites
/// the file + attests the decrypt succeeded without printing the value.
/// Operators who need the plaintext call [`write_dump`] to land it in a
/// 0600 secure-artifact file. This closes BF-2 from the 1.5.0 audit —
/// prior versions embedded `h.password` directly into `affected` and
/// `evidence.value`, which then reached every report renderer.
pub fn finding(hits: &[GppHit]) -> Option<Finding> {
    if hits.is_empty() {
        return None;
    }
    let affected = hits
        .iter()
        .map(|h| {
            format!(
                "{} :: {}",
                h.user.as_deref().unwrap_or("<no user>"),
                h.file.display()
            )
        })
        .collect::<Vec<_>>();
    // Ground-truth evidence: the file + a statement that the MS14-025 AES
    // key produced a valid decrypt for this cpassword. The plaintext itself
    // is redacted here; call `write_dump` to obtain it under a 0600 file.
    let evidence: Vec<Evidence> = hits
        .iter()
        .take(25)
        .map(|h| {
            Evidence::new(
                format!("SYSVOL GPP {}", h.file.display()),
                format!(
                    "cpassword decrypts under the MS14-025 AES key (user {}); \
                     plaintext redacted here — use `--gpp-dump-out <path>` to \
                     land the recovered secret in a 0600 artifact file.",
                    h.user.as_deref().unwrap_or("<no user>"),
                ),
            )
        })
        .collect();
    // WS-WPT session 4c: per-file SMB read frames (cap 25) — the report shows the exact SYSVOL
    // paths the scan opened, not just a claim of "GPP cpasswords found."
    let exchange: Vec<adhammer_core::WireExchange> = hits
        .iter()
        .take(25)
        .flat_map(|h| {
            [
                adhammer_core::WireExchange::sent(
                    adhammer_core::WireLayer::Smb,
                    format!("SMB2 CREATE + READ {}", h.file.display()),
                ),
                adhammer_core::WireExchange::recv(
                    adhammer_core::WireLayer::Smb,
                    format!(
                        "file present · GPP XML with cpassword blob (user={})",
                        h.user.as_deref().unwrap_or("<no user>")
                    ),
                ),
            ]
        })
        .collect();
    Some(Finding {
        id: "A-GppPassword".into(),
        title: "Recoverable GPP cpassword in SYSVOL (MS14-025)".into(),
        category: Category::Anomalies,
        severity: Severity::Critical,
        mitre: vec![mitre::VALID_ACCOUNTS],
        weight_bonus: hits.len() as u32 * 10,
        exchange,
        affected,
        evidence,
        detail: "Group Policy Preferences store passwords encrypted with a Microsoft-published AES key; any authenticated user who can read SYSVOL can decrypt them.".into(),
        // WS-PROOF-70 was gated on the check registry; sysvol emits Findings outside `registry()`,
        // so it can drift without CI catching it. Fill impact here — the same "no finding without
        // impact" contract applies to every emitter.
        impact: Some(
            "Any authenticated domain user reads SYSVOL, decrypts the GPP cpassword with the \
             Microsoft-published AES key (MS14-025), and logs in as the target account — often a \
             local admin baked into a preferences deployment. Trivial credential theft from a \
             read-only foothold.".into(),
        ),
        remediation: "Remove the offending GPP XML files, rotate the exposed credentials, and stop using GPP to set passwords (KB2962486).".into(),
    })
}

/// WS-SECRET-BOUNDARY (1.5.0): dump recovered GPP plaintext to a 0600
/// secure-artifact file. This is the ONLY path in the crate that exposes
/// the plaintext; `finding()` above stripped it from the reporting surface.
///
/// Format: one line per hit as `<file>\t<user>\t<plaintext>\n`. Fields are
/// tab-separated so awk/cut can split; embedded tabs in a file path (rare
/// on SYSVOL) are preserved as-is. Trailing newline on every line so `cat`
/// output is well-formed.
///
/// The file is created O_EXCL 0600; the call fails if `path` already
/// exists. Callers who intend to append across scans should route through
/// a per-scan output directory rather than a single fixed file.
pub fn write_dump(hits: &[GppHit], path: &Path) -> std::io::Result<()> {
    let mut buf = String::new();
    for h in hits {
        buf.push_str(&h.file.display().to_string());
        buf.push('\t');
        buf.push_str(h.user.as_deref().unwrap_or("<no user>"));
        buf.push('\t');
        // The one authorized `.expose_secret()` call in the crate; every
        // other consumer stays print-hidden.
        buf.push_str(h.password.expose_secret());
        buf.push('\n');
    }
    write_secret_artifact(path, SecretArtifact::GppDump, buf.as_bytes())
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
        assert_eq!(hits[0].password.expose_secret(), "Local*P4ssword!");
        assert!(finding(&hits).is_some());
    }

    /// WS-SECRET-BOUNDARY (1.5.0). Regression for BF-2: prior versions
    /// embedded the recovered plaintext into `affected[]` and
    /// `evidence.value`, so it reached every report renderer verbatim. This
    /// test asserts that no field of the emitted Finding contains the
    /// canonical MS14-025 test-vector plaintext.
    #[test]
    fn finding_never_carries_recovered_plaintext() {
        let hit = GppHit {
            file: std::path::PathBuf::from("SYSVOL/policy/Groups.xml"),
            user: Some("svc_admin".into()),
            password: SecretString::from("Local*P4ssword!"),
        };
        let f = finding(std::slice::from_ref(&hit)).expect("finding emitted");

        let leak_probe = "Local*P4ssword!";
        for a in &f.affected {
            assert!(
                !a.contains(leak_probe),
                "affected line leaks plaintext: {a}"
            );
        }
        for e in &f.evidence {
            assert!(
                !e.source.contains(leak_probe),
                "evidence.source leaks plaintext: {}",
                e.source
            );
            assert!(
                !e.value.contains(leak_probe),
                "evidence.value leaks plaintext: {}",
                e.value
            );
        }
        assert!(!f.detail.contains(leak_probe));
        assert!(!f.remediation.contains(leak_probe));
        if let Some(ref im) = f.impact {
            assert!(!im.contains(leak_probe));
        }
    }

    /// WS-LDAP-INTEGRITY (1.5.0) — BF-7 sysvol budgets. A file larger than
    /// [`SYSVOL_MAX_FILE_BYTES`] must be skipped, and the walk must keep
    /// going for the other files in the same directory.
    #[test]
    fn walk_skips_oversized_xml_but_keeps_processing_siblings() {
        let dir =
            std::env::temp_dir().join(format!("adhammer_sysvol_budget_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Sibling under the cap — must be processed and produce a hit.
        std::fs::write(
            dir.join("small.xml"),
            r#"<Groups><User><Properties userName="svc_admin"
               cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"/></User></Groups>"#,
        )
        .unwrap();
        // Oversized sibling — must be skipped with a warn, walk continues.
        let big = "A".repeat(SYSVOL_MAX_FILE_BYTES as usize + 1024);
        std::fs::write(dir.join("big.xml"), big.as_bytes()).unwrap();

        let hits = scan(&dir);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(hits.len(), 1, "small.xml must still produce a hit");
        assert_eq!(hits[0].user.as_deref(), Some("svc_admin"));
    }

    /// WS-LDAP-INTEGRITY (1.5.0). Recursive-loop / hostile-depth defence.
    #[test]
    fn walk_stops_at_max_depth() {
        let root =
            std::env::temp_dir().join(format!("adhammer_sysvol_depth_{}", std::process::id()));
        // Build a tree deeper than SYSVOL_MAX_WALK_DEPTH so the guard fires.
        let mut deep = root.clone();
        for _ in 0..(SYSVOL_MAX_WALK_DEPTH + 4) {
            deep.push("nested");
        }
        std::fs::create_dir_all(&deep).unwrap();
        // Place a cpassword under a depth WELL past the cap; must NOT be
        // found (proves the guard actually stopped the recursion).
        std::fs::write(
            deep.join("Groups.xml"),
            r#"<Groups><User><Properties userName="svc_admin"
               cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"/></User></Groups>"#,
        )
        .unwrap();

        let hits = scan(&root);
        std::fs::remove_dir_all(&root).ok();

        assert!(
            hits.is_empty(),
            "walk_stops_at_max_depth guard leaked past cap; got {} hits",
            hits.len()
        );
    }

    /// WS-SECRET-BOUNDARY (1.5.0). `write_dump` is the ONE exposure site;
    /// verifies it lands the tab-separated line with the plaintext to disk.
    #[test]
    fn write_dump_lands_tab_separated_plaintext() {
        let hit = GppHit {
            file: std::path::PathBuf::from("SYSVOL/policy/Groups.xml"),
            user: Some("svc_admin".into()),
            password: SecretString::from("Local*P4ssword!"),
        };
        let out =
            std::env::temp_dir().join(format!("adhammer_gpp_dump_{}.tsv", std::process::id()));
        let _ = std::fs::remove_file(&out);
        write_dump(std::slice::from_ref(&hit), &out).unwrap();
        let back = std::fs::read_to_string(&out).unwrap();
        std::fs::remove_file(&out).ok();
        assert!(back.contains("Local*P4ssword!"));
        assert!(back.contains("svc_admin"));
        assert!(back.contains("Groups.xml"));
    }
}
