//! Dump LAPS local-admin passwords.
//!
//! Wire path over the `ms-gkdi` seed-key derivation is TODO — this subcommand
//! today reuses the existing `attack laps` code path over dpapi-ng and prints
//! a hint for the ms-gkdi-only route.

use anyhow::Result;
use clap::Parser;

use crate::attacks;

#[derive(Parser)]
pub(crate) struct DumpLapsArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::LdapAuth,
    /// Target sAMAccountName, e.g. `WIN11$`. Omit to dump every readable entry.
    #[arg(long)]
    pub target: Option<String>,
    /// DC host / KDC for the GKDI GetKey call (defaults to the URL host).
    #[arg(long)]
    pub dc: Option<String>,
}

pub(crate) async fn dump_laps(a: DumpLapsArgs) -> Result<()> {
    eprintln!(
        "[!] `dump laps` is DEPRECATED and will be removed in 1.5.0 — use `attack laps` (same \
         functionality, one command per capability). The GKDI-first offline-derive path lives in \
         `adhammer_collector::sources::gkdi` for callers who want the library primitive."
    );
    let _ = a.dc; // reserved for the ms-gkdi path
    attacks::laps::laps(attacks::laps::LapsArgs {
        target: a.target,
        url: a.auth.url,
        user: a.auth.user,
        password: a.auth.password,
        insecure: a.auth.insecure,
    })
    .await
}
