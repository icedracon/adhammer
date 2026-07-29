//! Saved engagement profile — written on first `adhammer` run, reused with `--old`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::ScanArgs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// DNS domain, e.g. `corp.local`
    pub domain: String,
    /// Domain controller hostname or IP, e.g. `dc.corp.local`
    pub dc: String,
    /// Bind username (sAMAccountName or DOMAIN\\user)
    pub username: String,
    pub password: String,
    /// Optional NT hash (32 hex) for pass-the-hash on the SMB-based actions.
    #[serde(default)]
    pub nt_hash: Option<String>,
    /// Skip TLS verification for lab LDAPS
    #[serde(default)]
    pub insecure: bool,
}

impl Session {
    pub fn realm(&self) -> String {
        self.domain.to_uppercase()
    }

    pub fn netbios(&self) -> String {
        self.domain
            .split('.')
            .next()
            .unwrap_or(self.domain.as_str())
            .to_uppercase()
    }

    pub fn ldap_url(&self) -> String {
        format!("ldaps://{}:636", self.dc)
    }

    pub fn scan_args(&self) -> ScanArgs {
        ScanArgs {
            url: self.ldap_url(),
            user: self.username.clone(),
            password: self.password.clone(),
            base_dn: None,
            format: "json".to_string(),
            kdc: Some(self.dc.clone()),
            sysvol: None,
            insecure: self.insecure,
            gssapi: false,
            bloodhound: None,
        }
    }
}

fn config_path() -> Result<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var("APPDATA").context("APPDATA not set")?
    } else {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .context("HOME not set")?
            .parse::<PathBuf>()
            .context("bad home path")?
            .join(".config")
            .to_string_lossy()
            .into_owned()
    };
    Ok(PathBuf::from(base).join("adhammer").join("session.json"))
}

pub fn load() -> Result<Session> {
    let path = config_path()?;
    let data = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "no saved session at {} — run `adhammer` first",
            path.display()
        )
    })?;
    serde_json::from_str(&data).context("parse saved session")
}

pub fn save(session: &Session) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(session)?;
    std::fs::write(&path, &data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    eprintln!("[*] session saved to {}", path.display());
    Ok(())
}

pub fn exists() -> bool {
    config_path().map(|p| p.is_file()).unwrap_or(false)
}

/// Delete the saved session file (creds) from disk. Idempotent — a missing file is not an error.
pub fn wipe() -> Result<()> {
    let path = config_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => eprintln!("[*] session wiped: {}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("[*] no saved session to wipe ({})", path.display())
        }
        Err(e) => return Err(e).context("wipe session"),
    }
    Ok(())
}
