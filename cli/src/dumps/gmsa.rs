//! Dump gMSA `msDS-ManagedPassword` blobs.
//!
//! TODO wire onto ms-gkdi for the LAPS-v2 style seed-key derivation; for now
//! falls back to `attack gmsa` (which speaks the SEALED LDAP path directly).

use anyhow::Result;
use clap::Parser;

use crate::attacks;

#[derive(Parser)]
pub(crate) struct DumpGmsaArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::LdapAuth,
    /// gMSA sAMAccountName (e.g. `gmsa_web$`).
    #[arg(long)]
    pub target: String,
}

/// `dump gmsa` — read a gMSA's `msDS-ManagedPassword` blob. Same status as
/// `dump laps`: the seed-key derivation lives in `sources::gkdi`, but the
/// LDAP-attribute-fetch path already handles gMSA end-to-end via
/// `attack gmsa` (`msDS-ManagedPassword` over a sealed LDAP channel).
pub(crate) async fn dump_gmsa(a: DumpGmsaArgs) -> Result<()> {
    eprintln!(
        "[!] `dump gmsa` is DEPRECATED and will be removed in 1.5.0 — use `attack gmsa` (same \
         functionality, one command per capability)."
    );
    attacks::gmsa::gmsa(attacks::gmsa::GmsaArgs {
        url: a.auth.url,
        user: a.auth.user,
        password: a.auth.password,
        insecure: a.auth.insecure,
        target: a.target,
    })
    .await
}
