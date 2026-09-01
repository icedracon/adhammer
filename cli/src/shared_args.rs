//! Shape-family shared arg structs — flattened into subcommand Args via
//! `#[command(flatten)]`. Introduced in ux-0 to remove ~300 lines of
//! duplicated `--host/--domain/--user/--password` declarations across
//! ~20 subcommands. clap's flatten keeps every `--<flag>` on the CLI
//! surface byte-for-byte identical.

use clap::Args;

/// SMB/DCERPC-based auth — the most common shape across `attack coerce`,
/// `attack dcsync`, `attack exec/wmiexec/atexec`, `enum posture`, etc.
#[derive(Args, Clone, Debug)]
pub(crate) struct SmbAuth {
    /// Target host (DC / member / relay victim) — DNS name or IP.
    #[arg(long)]
    pub host: String,
    /// NetBIOS domain, e.g. CORP.
    #[arg(long)]
    pub domain: String,
    /// Bind username (sAMAccountName, no domain prefix).
    #[arg(long)]
    pub user: String,
    /// Bind password. Prefer `@file:/path/to/pw` or `$ADHAMMER_PASSWORD`.
    #[arg(long, default_value = "")]
    pub password: adhammer_core::SecretString,
}

/// LDAPS-based auth — for `scan`, `check adcs`, `dump laps/gmsa`.
///
/// `user` defaults to `""` so `scan --anonymous` (WS-11, 1.4.1) parses without
/// requiring the bind identity. Authenticated subcommands still fail loudly at
/// bind time if the caller forgot to pass `--user`.
#[derive(Args, Clone, Debug)]
pub(crate) struct LdapAuth {
    /// LDAP URL, e.g. `ldaps://dc.corp.local:636`.
    #[arg(long)]
    pub url: String,
    /// Bind username. Optional in anonymous-mode subcommands.
    #[arg(long, default_value = "")]
    pub user: String,
    /// Bind password. Prefer `@file:/path/to/pw` or `$ADHAMMER_PASSWORD`.
    #[arg(long, default_value = "")]
    pub password: adhammer_core::SecretString,
    /// Skip TLS verification for lab LDAPS.
    #[arg(long)]
    pub insecure: bool,
}

/// Optional-variant auth — for handlers where the fields may be resolved
/// from elsewhere (e.g. `attack abuse --action pkinit` gets credentials
/// from a Kerberos ccache rather than argv).
#[derive(Args, Clone, Debug)]
pub(crate) struct OptAuth {
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub user: Option<String>,
    #[arg(long)]
    pub password: Option<adhammer_core::SecretString>,
    #[arg(long)]
    pub insecure: bool,
}
