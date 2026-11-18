//! Shape-family shared arg structs — flattened into subcommand Args via
//! `#[command(flatten)]`. Introduced in ux-0 to remove ~300 lines of
//! duplicated `--host/--domain/--user/--password` declarations across
//! ~20 subcommands. clap's flatten keeps every `--<flag>` on the CLI
//! surface byte-for-byte identical.

use clap::{Args, ValueEnum};

/// CLI-facing choice of LDAP bind method. Maps to
/// [`adhammer_collector::AuthMethod`] via `From`. Named `Kerberos` rather
/// than `Gssapi` on the CLI surface because operators ask for Kerberos by name.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum AuthMethodArg {
    /// Try simple_bind first; on LDAP_STRONG_AUTH_REQUIRED (CBT=2
    /// rejection), transparently retry with NTLM so ldap3 attaches the
    /// tls-server-end-point channel binding token. Default.
    #[default]
    Auto,
    /// Force plaintext simple_bind (inside TLS). Bypasses CBT; accepted only
    /// by non-hardened DCs. Useful to confirm a DC's CBT policy.
    Simple,
    /// Force SASL GSS-SPNEGO NTLM bind. CBT auto-applied on TLS. Avoids the
    /// simple_bind probe that would otherwise appear in the DC event log.
    Ntlm,
    /// Force SASL GSSAPI Kerberos bind. CBT auto-applied on TLS. Requires an
    /// adhammer build with `--features gssapi`.
    Kerberos,
}

impl From<AuthMethodArg> for adhammer_collector::AuthMethod {
    fn from(v: AuthMethodArg) -> Self {
        match v {
            AuthMethodArg::Auto => adhammer_collector::AuthMethod::Auto,
            AuthMethodArg::Simple => adhammer_collector::AuthMethod::Simple,
            AuthMethodArg::Ntlm => adhammer_collector::AuthMethod::Ntlm,
            AuthMethodArg::Kerberos => adhammer_collector::AuthMethod::Gssapi,
        }
    }
}

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

/// LDAPS-based auth — for `scan`, `check adcs`, `attack laps/gmsa`.
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
    /// **1.5.1 G-19**: allow an unencrypted LDAP bind (cleartext credentials on
    /// the wire). Off by default — LDAPS or a signed/GSSAPI bind is required
    /// unless this is set. For lab DCs without a certificate; the collector still
    /// prompts for consent before it downgrades to plaintext.
    #[arg(long)]
    pub allow_plaintext_ldap: bool,
    /// **1.6.1 T1.2**: LDAP bind method. Default `auto` tries simple_bind
    /// first and transparently falls back to NTLM on CBT=2 rejection. For
    /// stealth against hardened DCs that log every rejected bind, prefer
    /// `ntlm` to skip the simple_bind probe entirely.
    #[arg(long, value_enum, default_value_t = AuthMethodArg::Auto)]
    pub auth_method: AuthMethodArg,
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
    /// **1.5.1 G-19**: allow an unencrypted LDAP bind (cleartext credentials on
    /// the wire). Off by default; the collector still prompts for consent before
    /// downgrading to plaintext.
    #[arg(long)]
    pub allow_plaintext_ldap: bool,
}
