//! Opt-in RustHound-CE (`g0h4n/RustHound-CE`) collector adapter — 1.5.2 additive
//! integration. Compiled ONLY under `--features rusthound-ce`; the default build
//! never links RH-CE and every stable ADhammer contract stays byte-identical.
//!
//! Contract (per `docs/PLAN_1.5.2.md`):
//! - We reuse the ADhammer `Collector`'s already-bound `ldap3::Ldap` session.
//! - We do NOT re-authenticate. `Options.username`/`password` stay empty; the
//!   session's bind identity is what RH-CE runs under.
//! - Collection method is fixed to `LdapOnly` in this first cut. ESC8 probes
//!   and `fqdn_resolver` extras stay off — they were the plan's out-of-scope
//!   items.
//! - The output ZIP is written under `output_dir`. RH-CE picks the filename.
//! - The existing `adhammer-bloodhound` `export_files` / `export_zip` remain
//!   the default exporter; this is a co-exporter, not a replacement.

use rusthound_ce::args::{CollectionMethod, Options};

/// Options surfaced to the ADhammer caller. Keeps the plan's "cooperation, not
/// competition" contract: what varies is small and named, everything RH-CE
/// takes from the session or from `LdapOnly` defaults.
#[derive(Debug, Clone)]
pub struct AdapterOptions {
    /// DNS realm (`corp.example`). RH-CE uses this to name the ZIP and to
    /// resolve principals to short domain form.
    pub domain: String,
    /// Directory where RH-CE writes the ZIP. Absolute path recommended.
    pub output_dir: String,
    /// Optional DC FQDN (`dc01.corp.example`); helps RH-CE derive SIDs and
    /// domain-controllers node kind. `None` = RH-CE derives from the session.
    pub ldap_fqdn: Option<String>,
    /// Verbosity forwarded to RH-CE's `log` sink. `log::LevelFilter::Info` is
    /// a reasonable default for a foreground scan; `Warn` for quieter output.
    pub verbose: log::LevelFilter,
}

impl AdapterOptions {
    /// Reasonable defaults for a co-run alongside `adhammer scan`.
    pub fn new(domain: impl Into<String>, output_dir: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            output_dir: output_dir.into(),
            ldap_fqdn: None,
            verbose: log::LevelFilter::Info,
        }
    }

    fn to_rh_options(&self) -> Options {
        Options {
            domain: self.domain.clone(),
            username: None,
            password: None,
            ldapfqdn: self.ldap_fqdn.clone(),
            ip: None,
            port: None,
            name_server: String::from("not set"),
            path: self.output_dir.clone(),
            collection_method: CollectionMethod::LdapOnly,
            ldaps: true,
            dns_tcp: false,
            fqdn_resolver: false,
            hashes: None,
            kerberos: false,
            pfx: None,
            pfx_pass: None,
            crt: None,
            key: None,
            zip: true,
            verbose: self.verbose,
            ldap_filter: String::from("(objectClass=*)"),
            cache: false,
            cache_buffer_size: 1000,
            resume: false,
        }
    }
}

/// Run RustHound-CE's `LdapOnly` collection over the caller's already-bound
/// `&mut ldap3::Ldap` session and return the on-disk path of the emitted ZIP.
///
/// This does not touch ADhammer's own snapshot / findings / control-path
/// graph — it is a co-exporter. Errors from RH-CE bubble up unchanged; the
/// LDAP session is NOT closed on error and remains reusable.
///
/// H-E polish (1.5.2 v2):
/// - Ensures `output_dir` exists (RH-CE's `Options.path` field is a directory;
///   it does NOT create it and will fail confusingly at ZIP-write time).
/// - Returns the RH-CE-picked ZIP path unchanged so the CLI verb can render
///   it and stat its size for the operator.
pub async fn run_over_shared_session(
    ldap: &mut ldap3::Ldap,
    opts: &AdapterOptions,
) -> Result<String, Box<dyn std::error::Error>> {
    if !std::path::Path::new(&opts.output_dir).exists() {
        std::fs::create_dir_all(&opts.output_dir)?;
    }
    let rh_opts = opts.to_rh_options();
    rusthound_ce::api::run_collection(ldap, &rh_opts).await
}

/// Best-effort ZIP-size lookup for the checklist / JSON receipt. Returns
/// `None` if the file is gone by the time we stat (RH-CE writes atomically
/// so this only trips when the caller passed us a bad path).
pub fn zip_size_bytes(zip_path: &str) -> Option<u64> {
    std::fs::metadata(zip_path).ok().map(|m| m.len())
}
