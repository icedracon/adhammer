//! Saved engagement profile — written on first `adhammer` run, reused with `--old`.
//! On Windows the session file is DPAPI-encrypted (CryptProtectData) so creds at rest
//! are bound to the current user's login session. On Unix it's chmod 600.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::attacks::scan::ScanArgs;

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
            auth: crate::shared_args::LdapAuth {
                url: self.ldap_url(),
                user: self.username.clone(),
                password: self.password.clone(),
                insecure: self.insecure,
            },
            base_dn: None,
            format: "json".to_string(),
            kdc: Some(self.dc.clone()),
            sysvol: None,
            gssapi: false,
            bloodhound: None,
            out: None,
            out_all: None,
            top_n: 10,
            anonymous: false,
            baseline: None,
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
    let raw = std::fs::read(&path).with_context(|| {
        format!(
            "no saved session at {} — run `adhammer` first",
            path.display()
        )
    })?;
    let json = dpapi::decrypt_if_wrapped(&raw)?;
    serde_json::from_slice(&json).context("parse saved session")
}

pub fn save(session: &Session) -> Result<()> {
    save_inner(
        session,
        std::env::var_os("ADHAMMER_ALLOW_PLAIN_SESSION").is_some(),
    )
}

pub fn save_allow_cleartext(session: &Session) -> Result<()> {
    save_inner(session, true)
}

pub fn would_save_cleartext() -> bool {
    dpapi::is_cleartext_wrapper()
}

fn save_inner(session: &Session, allow_cleartext: bool) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(session)?;
    let blob = dpapi::encrypt(json.as_bytes())?;

    // Refuse-by-default when the payload came through the cleartext DPAPI
    // fallback (non-Windows, non-keyring host). Silent plaintext writes of
    // credential material are the exact opposite of what an operator expects
    // from a "DPAPI-encrypted session" flag. Override via env for lab work.
    if dpapi::is_cleartext_wrapper() && !allow_cleartext {
        anyhow::bail!(
            "session save refused: DPAPI is unavailable on this platform so the file would \
             be written in cleartext. Set ADHAMMER_ALLOW_PLAIN_SESSION=1 to allow it (lab only), \
             or use --no-save to keep credentials off disk."
        );
    }

    // Atomic 0600 create: `open` with mode 0600 + O_CREAT|O_EXCL on Unix
    // closes the TOCTOU window between `write` and `set_permissions` where
    // the file existed at 0644 (umask default) and another local user could
    // read the ciphertext (DPAPI or otherwise). On Windows the DPAPI blob is
    // already user-bound so mode bits are irrelevant; on non-Windows we get
    // proper 0600 from the outset.
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        // Remove any pre-existing file so create_new() succeeds; this ensures we
        // never inherit a file another user could have created at 0666.
        let _ = std::fs::remove_file(&path);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("open {} 0600", path.display()))?;
        f.write_all(&blob)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, &blob)?;
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

mod dpapi {
    use anyhow::Result;
    // `Context` is only used by the Windows CryptProtectData / CryptUnprotectData path;
    // importing it unconditionally trips `-D unused-imports` on non-Windows CI hosts.
    #[cfg(windows)]
    use anyhow::Context as _;

    const MAGIC: &[u8; 4] = b"ADHS";

    #[cfg(windows)]
    mod win {
        use std::ptr;

        #[repr(C)]
        struct DataBlob {
            cb_data: u32,
            pb_data: *mut u8,
        }

        extern "system" {
            fn CryptProtectData(
                data_in: *const DataBlob,
                description: *const u16,
                entropy: *const DataBlob,
                reserved: *mut u8,
                prompt: *mut u8,
                flags: u32,
                data_out: *mut DataBlob,
            ) -> i32;

            fn CryptUnprotectData(
                data_in: *const DataBlob,
                description: *mut *mut u16,
                entropy: *const DataBlob,
                reserved: *mut u8,
                prompt: *mut u8,
                flags: u32,
                data_out: *mut DataBlob,
            ) -> i32;

            fn LocalFree(mem: *mut u8) -> *mut u8;
        }

        pub fn protect(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
            let input = DataBlob {
                cb_data: plaintext.len() as u32,
                pb_data: plaintext.as_ptr() as *mut u8,
            };
            let mut output = DataBlob {
                cb_data: 0,
                pb_data: ptr::null_mut(),
            };
            let ok = unsafe {
                CryptProtectData(
                    &input,
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    &mut output,
                )
            };
            if ok == 0 {
                anyhow::bail!("CryptProtectData failed (GetLastError)");
            }
            let enc =
                unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize) }
                    .to_vec();
            unsafe { LocalFree(output.pb_data) };
            Ok(enc)
        }

        pub fn unprotect(ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
            let input = DataBlob {
                cb_data: ciphertext.len() as u32,
                pb_data: ciphertext.as_ptr() as *mut u8,
            };
            let mut output = DataBlob {
                cb_data: 0,
                pb_data: ptr::null_mut(),
            };
            let ok = unsafe {
                CryptUnprotectData(
                    &input,
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    &mut output,
                )
            };
            if ok == 0 {
                anyhow::bail!(
                    "CryptUnprotectData failed — session file may belong to another user"
                );
            }
            let dec =
                unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize) }
                    .to_vec();
            unsafe { LocalFree(output.pb_data) };
            Ok(dec)
        }
    }

    pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(windows)]
        {
            let enc = win::protect(plaintext).context("DPAPI encrypt")?;
            let mut out = Vec::with_capacity(4 + enc.len());
            out.extend_from_slice(MAGIC);
            out.extend_from_slice(&enc);
            Ok(out)
        }
        #[cfg(not(windows))]
        {
            eprintln!("[!] session creds stored unencrypted (DPAPI unavailable on this OS)");
            Ok(plaintext.to_vec())
        }
    }

    pub fn decrypt_if_wrapped(data: &[u8]) -> Result<Vec<u8>> {
        if data.starts_with(MAGIC) {
            #[cfg(windows)]
            {
                return win::unprotect(&data[4..]).context("DPAPI decrypt");
            }
            #[cfg(not(windows))]
            {
                anyhow::bail!(
                    "session file is DPAPI-encrypted (created on Windows) — cannot decrypt on this OS"
                );
            }
        }
        Ok(data.to_vec())
    }

    /// `true` when this build's `encrypt()` would write cleartext (no real
    /// key-wrapping backend). Consumed by `session::save()` to refuse-by-default
    /// on hosts where "DPAPI-encrypted" is a marketing lie. Set
    /// `ADHAMMER_ALLOW_PLAIN_SESSION=1` to opt in anyway (lab use).
    pub fn is_cleartext_wrapper() -> bool {
        #[cfg(windows)]
        {
            false
        }
        #[cfg(not(windows))]
        {
            true
        }
    }
}
