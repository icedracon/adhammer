//! Unified target-string classification + resolution helpers.
//!
//! Attack subcommands accept a `--target` string that may arrive as:
//!   - a security identifier (`S-1-5-21-…-1000`),
//!   - a distinguished name (`CN=Alice,OU=Users,DC=corp,DC=local`), or
//!   - a bare sAMAccountName (`alice`, `DC01$`).
//!
//! Before ux-2 each handler branched on `s.starts_with("S-")` or similar
//! ad-hoc. This module centralises the classification and the two common
//! resolutions we need (→ SID, → DN) so a single fix updates every attack.

use adhammer_core::sid::Sid;
use adhammer_collector::Collector;
use anyhow::{Context, Result};

/// Which kind of principal identifier a raw `--target` string represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetKind {
    /// `S-1-5-21-…-<rid>` — SID literal, no LDAP round-trip needed.
    Sid,
    /// `CN=…,DC=…` — LDAP distinguished name, pass through unchanged for DN-taking APIs.
    Dn,
    /// Anything else — treat as a sAMAccountName and LDAP-search for it.
    Sam,
}

/// Classify a `--target` / `--value` string without touching LDAP.
///
/// The heuristic is deliberately narrow to avoid mis-classifying edge cases:
///   - starts with `S-1-` → `Sid` (Windows well-known SID prefix)
///   - contains `=` AND a comma-separated `DC=` component → `Dn`
///   - everything else → `Sam`
pub(crate) fn classify(s: &str) -> TargetKind {
    if s.starts_with("S-1-") {
        TargetKind::Sid
    } else if s.contains('=') && s.split(',').any(|c| c.trim_start().starts_with("DC=")) {
        TargetKind::Dn
    } else {
        TargetKind::Sam
    }
}

/// Resolve any target-string to a [`Sid`].
///
/// * `Sid` inputs parse directly (no LDAP call).
/// * `Sam` inputs LDAP-search via `Collector::resolve_sid`.
/// * `Dn` inputs LDAP-search via `Collector::resolve_sid` too — the
///   collector's search will accept the DN's first RDN as a filter fallback;
///   if that fails, the user gets a clear "no such object" error.
pub(crate) async fn to_sid(c: &mut Collector, s: &str) -> Result<Sid> {
    match classify(s) {
        TargetKind::Sid => Sid::parse(s).context(format!("bad SID literal: {s}")),
        TargetKind::Sam | TargetKind::Dn => c
            .resolve_sid(s)
            .await
            .with_context(|| format!("resolve --target {s:?} to SID")),
    }
}

/// Resolve any target-string to a distinguished name.
///
/// * `Dn` inputs pass through unchanged.
/// * `Sam` inputs LDAP-search via `Collector::resolve_dn`.
/// * `Sid` inputs LDAP-search via `Collector::resolve_dn` — matches on the
///   `objectSid` attribute in the collector's filter builder.
pub(crate) async fn to_dn(c: &mut Collector, s: &str) -> Result<String> {
    match classify(s) {
        TargetKind::Dn => Ok(s.to_string()),
        TargetKind::Sam | TargetKind::Sid => c
            .resolve_dn(s)
            .await
            .with_context(|| format!("resolve --target {s:?} to DN")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_prefix_detected() {
        assert_eq!(classify("S-1-5-21-1-2-3-1000"), TargetKind::Sid);
        assert_eq!(classify("S-1-5-32-544"), TargetKind::Sid);
    }

    #[test]
    fn dn_with_dc_components_detected() {
        assert_eq!(
            classify("CN=Alice,OU=Users,DC=corp,DC=local"),
            TargetKind::Dn
        );
        assert_eq!(classify("CN=DC01$,OU=Domain Controllers,DC=lab,DC=local"), TargetKind::Dn);
    }

    #[test]
    fn bare_sam_falls_through() {
        assert_eq!(classify("alice"), TargetKind::Sam);
        assert_eq!(classify("DC01$"), TargetKind::Sam);
        assert_eq!(classify("svc_sql"), TargetKind::Sam);
    }

    #[test]
    fn cn_only_without_dc_is_not_a_dn() {
        // A stray `CN=foo` (no ,DC=…) is more likely a typo than a real DN;
        // treat as Sam so the LDAP search gives a helpful "no such user" error
        // instead of silently trying to LDAP-modify a malformed DN.
        assert_eq!(classify("CN=foo"), TargetKind::Sam);
    }

    #[test]
    fn ambiguous_looking_sid_gate() {
        // Only S-1- prefix counts as a SID literal. Anything else (S-2-…, S-foo)
        // falls through to Sam so LDAP resolution is attempted.
        assert_eq!(classify("S-2-5-21-1-2-3"), TargetKind::Sam);
        assert_eq!(classify("S-foo"), TargetKind::Sam);
    }
}
