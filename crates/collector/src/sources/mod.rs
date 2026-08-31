//! Typed source-of-truth adapters that sit on top of the raw LDAP collector.
//!
//! `Collector` (in `lib.rs`) hands out `Vec<AdObject>` — flat DN+attrs bags. That
//! shape is deliberately generic so the check engine can walk it, but every
//! consumer that wants a *domain-specific* view has to re-decode the same flag
//! bits and OID lists. This module wraps those decoders behind small, typed APIs
//! backed by published protocol crates:
//!
//! * [`adcs`] — pKICertificateTemplate → [`ms_crtd::CertTemplate`]
//! * `gkdi` (feature `experimental-gkdi`) — pre-alpha GKDI seed-key derivation
//!
//! Each source is opt-in and shares nothing with the others; they exist so
//! individual crates (checks, cli) can pull a single adapter without inheriting
//! the whole collector's transitive weight.

pub mod adcs;
#[cfg(feature = "experimental-gkdi")]
pub mod gkdi;

/// Distinguishes the two `Source`s so a caller can enumerate what an adapter
/// can produce without importing the concrete types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// AD-CS certificate template + enrollment-service view (`ms-crtd`).
    Adcs,
    /// Group Key Distribution seed-key tree walk (`ms-gkdi`).
    #[cfg(feature = "experimental-gkdi")]
    Gkdi,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Adcs => "adcs",
            #[cfg(feature = "experimental-gkdi")]
            SourceKind::Gkdi => "gkdi",
        }
    }
}
