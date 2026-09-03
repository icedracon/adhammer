//! Atomic secure-file-write helper for secret artifacts.
//!
//! WS-SECRET-BOUNDARY (1.4.10): every secret ADhammer writes to disk (recovered
//! GPP plaintext, Kerberos ccache, hashcat-input, DPAPI master-key material,
//! LAPS clear passwords, keytabs) must land with narrow permissions so that
//! another local principal — a low-priv service account on a shared jump-box,
//! a coworker on a shared workstation, or a compromised sibling process —
//! cannot read it in the window between `write` and a later `chmod`. The
//! historical `session.rs` DPAPI path already uses the O_CREAT|O_EXCL+0600
//! pattern; this module lifts that pattern out so every secret writer can
//! call one function.
//!
//! ## Contract
//!
//! - **Unix**: `OpenOptions::create_new(true).mode(0o600)`. TOCTOU-safe:
//!   the mode is set BEFORE the file exists at any wider mode; `create_new`
//!   fails atomically if the path already exists (so we never overwrite a
//!   file another user placed there).
//! - **Windows**: `CreateFileW(CREATE_NEW)` receives a protected DACL at
//!   creation time. The owner, LocalSystem, and local Administrators have
//!   full control; inherited parent-directory ACEs are disabled. This closes
//!   both the permissive-parent and post-create ACL race windows.
//!
//! ## Non-goals
//! - This helper does NOT encrypt content. Encryption is a caller-choice
//!   layer (DPAPI on Windows for session state; explicit passphrase-based
//!   sealing elsewhere). This helper enforces PERMISSIONS, not
//!   CONFIDENTIALITY.
//! - This helper does NOT sync directory metadata after write. That is a
//!   durability concern (partial-write on power loss) and is handled by
//!   `fsync`-on-file which we do call; the directory-fsync durability
//!   promise is separately documented as "not guaranteed."

use std::io::Write as _;
use std::path::Path;

/// Kind of secret being written — surfaces in error messages so an operator
/// can tell which artifact failed to land. Also documents the taxonomy of
/// on-disk secrets a caller may produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretArtifact {
    /// Kerberos credential cache (MIT ccache v4 or Heimdal).
    Ccache,
    /// Hashcat-format input (`user:$krb5tgs$...` etc.) — plaintext hashes
    /// but their presence on disk still enables offline cracking.
    HashcatInput,
    /// Recovered GPP plaintext dump (MS14-025 harvest).
    GppDump,
    /// Domain DPAPI master key material.
    DpapiMasterKey,
    /// LAPS-legacy or LAPS-v2 cleartext password.
    LapsPassword,
    /// Keytab file.
    Keytab,
    /// Private key material (PEM, DER, or another unencrypted key encoding).
    PrivateKey,
    /// Other; caller supplies a &'static label for the error path.
    Other(&'static str),
}

impl SecretArtifact {
    fn label(self) -> &'static str {
        match self {
            SecretArtifact::Ccache => "ccache",
            SecretArtifact::HashcatInput => "hashcat-input",
            SecretArtifact::GppDump => "gpp-dump",
            SecretArtifact::DpapiMasterKey => "dpapi-master-key",
            SecretArtifact::LapsPassword => "laps-password",
            SecretArtifact::Keytab => "keytab",
            SecretArtifact::PrivateKey => "private-key",
            SecretArtifact::Other(s) => s,
        }
    }
}

/// Write `bytes` to `path` at 0600 (Unix) / O_EXCL default (Windows), atomically.
///
/// Fails if `path` already exists — callers who intend to overwrite must
/// unlink first. This is deliberate: silent overwrite of a secret file
/// erases evidence of a prior successful attack step; the caller states
/// intent explicitly.
///
pub fn write_secret_artifact(
    path: &Path,
    kind: SecretArtifact,
    bytes: &[u8],
) -> std::io::Result<()> {
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| annotate(e, kind, path))?
    };

    #[cfg(windows)]
    let mut f = create_windows_secret_file(path).map_err(|e| annotate(e, kind, path))?;

    #[cfg(not(any(unix, windows)))]
    let mut f = std::fs::File::create_new(path).map_err(|e| annotate(e, kind, path))?;

    f.write_all(bytes).map_err(|e| annotate(e, kind, path))?;
    f.sync_all().map_err(|e| annotate(e, kind, path))?;
    Ok(())
}

#[cfg(windows)]
fn create_windows_secret_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::{LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL};

    // Protected DACL: owner rights + LocalSystem + local Administrators only.
    // The descriptor is supplied to CreateFileW, so the file never exists
    // with a permissive inherited DACL.
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)\0"
        .encode_utf16()
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide_path = windows_api_path(path)?;
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn windows_api_path(path: &Path) -> std::io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt as _;

    let absolute = std::path::absolute(path)?;
    let wide: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    const VERBATIM: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const DEVICE: &[u16] = &[b'\\' as u16, b'\\' as u16, b'.' as u16, b'\\' as u16];
    const UNC: &[u16] = &[b'\\' as u16, b'\\' as u16];

    if wide.starts_with(DEVICE) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "device-namespace paths are not valid secret artifact files",
        ));
    }

    let mut api_path = Vec::with_capacity(wide.len() + 8);
    if wide.starts_with(VERBATIM) {
        // Accept only verbatim drive and UNC filesystem paths. Reject namespaces
        // such as GLOBALROOT that can escape ordinary filesystem expectations.
        let tail = &wide[VERBATIM.len()..];
        let is_drive = tail.len() >= 3 && tail[1] == b':' as u16 && tail[2] == b'\\' as u16;
        let is_unc = tail.starts_with(&[b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16]);
        if !is_drive && !is_unc {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "non-filesystem verbatim paths are not valid secret artifact files",
            ));
        }
        api_path.extend_from_slice(&wide);
    } else if wide.starts_with(UNC) {
        api_path.extend("\\\\?\\UNC\\".encode_utf16());
        api_path.extend_from_slice(&wide[UNC.len()..]);
    } else {
        api_path.extend("\\\\?\\".encode_utf16());
        api_path.extend_from_slice(&wide);
    }
    api_path.push(0);
    Ok(api_path)
}

fn annotate(e: std::io::Error, kind: SecretArtifact, path: &Path) -> std::io::Error {
    std::io::Error::new(
        e.kind(),
        format!(
            "write_secret_artifact({}, {}): {}",
            kind.label(),
            path.display(),
            e
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("adhammer_secret_write_tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn writes_bytes_and_reads_back() {
        let p = tmp_path("basic.bin");
        let _ = std::fs::remove_file(&p);
        write_secret_artifact(&p, SecretArtifact::Ccache, b"hello secret").unwrap();
        let mut f = std::fs::File::open(&p).unwrap();
        let mut back = Vec::new();
        f.read_to_end(&mut back).unwrap();
        assert_eq!(back, b"hello secret");
    }

    #[cfg(unix)]
    #[test]
    fn unix_file_has_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp_path("perm.bin");
        let _ = std::fs::remove_file(&p);
        write_secret_artifact(&p, SecretArtifact::GppDump, b"top secret").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    #[test]
    fn refuses_to_overwrite_existing_file() {
        let p = tmp_path("no_overwrite.bin");
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, b"pre-existing").unwrap();
        let err = write_secret_artifact(&p, SecretArtifact::GppDump, b"replacement")
            .expect_err("existing secret artifact must never be replaced");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&p).unwrap(), b"pre-existing");
    }

    #[test]
    fn artifact_label_stable() {
        assert_eq!(SecretArtifact::Ccache.label(), "ccache");
        assert_eq!(SecretArtifact::GppDump.label(), "gpp-dump");
        assert_eq!(
            SecretArtifact::Other("custom-label").label(),
            "custom-label"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_has_protected_dacl() {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SE_DACL_PROTECTED,
        };

        let p = tmp_path("protected-dacl.bin");
        let _ = std::fs::remove_file(&p);
        write_secret_artifact(&p, SecretArtifact::PrivateKey, b"private").unwrap();
        let wide: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0, "GetNamedSecurityInfoW failed: {status}");
        let mut control = 0u16;
        let mut revision = 0u32;
        let ok = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
        unsafe {
            LocalFree(descriptor);
        }
        assert_ne!(ok, 0, "GetSecurityDescriptorControl failed");
        assert_ne!(
            control & SE_DACL_PROTECTED,
            0,
            "DACL must reject inheritance"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_long_path_is_supported() {
        let mut dir = std::env::temp_dir().join("adhammer_secret_write_long_path");
        for n in 0..8 {
            dir.push(format!("segment-{n:02}-abcdefghijklmnopqrstuvwxyz"));
        }
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("secret.bin");
        assert!(p.as_os_str().len() > 260);
        let _ = std::fs::remove_file(&p);
        write_secret_artifact(&p, SecretArtifact::PrivateKey, b"private").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"private");
    }
}
