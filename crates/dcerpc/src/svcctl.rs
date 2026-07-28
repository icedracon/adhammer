//! SVCCTL (MS-SCMR) — the Service Control Manager Remote protocol. This is the psexec
//! primitive: open the SCM, create a service whose binary path is an arbitrary command,
//! start it (the command runs as LocalSystem; the SCM reports a start "timeout" because a
//! command is not a real service — expected), then delete the service. Rides the same
//! authenticated `\PIPE\svcctl` SMB transport the SAMR/LSAT clients use.
//!
//! Blind command execution only (no output capture yet — that needs an SMB read on `C$`).

use crate::ndr::{NdrDecoder, NdrEncoder};
use crate::transport::SmbPipe;
use crate::{Result, RpcError, Syntax};
use adhammer_smb::SmbClient;

/// The Service Control Manager Remote interface (v2.0).
pub fn svcctl_syntax() -> Syntax {
    Syntax::new("367abb81-9844-35f1-ad32-98f038001003", 2, 0)
}

pub mod opnum {
    pub const CLOSE_SERVICE_HANDLE: u16 = 0;
    pub const DELETE_SERVICE: u16 = 2;
    pub const CREATE_SERVICE_W: u16 = 12;
    pub const OPEN_SC_MANAGER_W: u16 = 15;
    pub const START_SERVICE_W: u16 = 19;
}

// Access masks and service parameters (MS-SCMR §2.2 / winsvc.h).
const SC_MANAGER_ALL_ACCESS: u32 = 0x000F_003F;
const SERVICE_ALL_ACCESS: u32 = 0x000F_01FF;
const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
const SERVICE_DEMAND_START: u32 = 0x0000_0003;
const SERVICE_ERROR_IGNORE: u32 = 0x0000_0000;

// Win32 error codes we treat as "the command ran" — the SCM never sees a real service.
const ERROR_SERVICE_REQUEST_TIMEOUT: u32 = 1053;
const ERROR_SERVICE_NO_THREAD: u32 = 1054;
const ERROR_EXCEPTION_IN_SERVICE: u32 = 1064;
const ERROR_PROCESS_ABORTED: u32 = 1067;

/// A 20-byte SC_RPC_HANDLE (attributes u32 + 16-byte context uuid).
#[derive(Clone, Copy, Debug, Default)]
pub struct ScHandle(pub [u8; 20]);

impl ScHandle {
    fn decode(d: &mut NdrDecoder) -> Result<Self> {
        let attrs = d.u32()?;
        let uuid = d.uuid()?;
        let mut h = [0u8; 20];
        h[..4].copy_from_slice(&attrs.to_le_bytes());
        h[4..].copy_from_slice(&uuid);
        Ok(ScHandle(h))
    }
    fn encode(&self, e: &mut NdrEncoder) {
        e.bytes(&self.0);
    }
    fn is_null(&self) -> bool {
        self.0 == [0u8; 20]
    }
}

/// ROpenSCManagerW(NULL machine, NULL database, access) → SCM handle.
fn encode_open_scm(access: u32) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.null_ptr(); // lpMachineName (local)
    e.null_ptr(); // lpDatabaseName (defaults to ServicesActive)
    e.u32(access);
    e.into_bytes()
}

/// RCreateServiceW: create a WIN32_OWN_PROCESS demand-start service whose binary is `binpath`.
/// All optional pointers (display name, tag id, dependencies, account, password) are NULL, so
/// the service runs as LocalSystem.
///
/// The two mandatory strings (`lpServiceName`, `lpBinaryPathName`) are `[string] wchar_t*` and
/// marshal as inline conformant-varying `WSTR`s — no referent ID, no deferral. The optional
/// pointers (`LPWSTR`/`LPDWORD`/`LPBYTE`) are unique pointers → a referent ID (0 here = NULL),
/// with no deferred pointee since all are NULL. So the whole stub is one inline stream.
fn encode_create_service(scm: &ScHandle, name: &str, binpath: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    scm.encode(&mut e); // hSCManager (context handle, 20 bytes)
    e.conformant_varying_wstr(name); // lpServiceName (inline WSTR)
    e.align(4);
    e.null_ptr(); // lpDisplayName    (NULL)
    e.u32(SERVICE_ALL_ACCESS); // dwDesiredAccess
    e.u32(SERVICE_WIN32_OWN_PROCESS); // dwServiceType
    e.u32(SERVICE_DEMAND_START); // dwStartType
    e.u32(SERVICE_ERROR_IGNORE); // dwErrorControl
    e.conformant_varying_wstr(binpath); // lpBinaryPathName (inline WSTR)
    e.align(4);
    e.null_ptr(); // lpLoadOrderGroup (NULL)
    e.null_ptr(); // lpdwTagId        (NULL)
    e.null_ptr(); // lpDependencies   (NULL)
    e.u32(0); // dwDependSize
    e.null_ptr(); // lpServiceStartName (NULL → LocalSystem)
    e.null_ptr(); // lpPassword       (NULL)
    e.u32(0); // dwPwSize
    e.into_bytes()
}

/// RStartServiceW(handle, argc=0, argv=NULL).
fn encode_start_service(svc: &ScHandle) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    svc.encode(&mut e);
    e.u32(0); // argc
    e.null_ptr(); // argv
    e.into_bytes()
}

fn encode_handle_only(h: &ScHandle) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    h.encode(&mut e);
    e.into_bytes()
}

/// The trailing NDR return value (a Win32 error) of an SCM call.
fn tail_return(stub: &[u8]) -> u32 {
    if stub.len() < 4 {
        return u32::MAX;
    }
    u32::from_le_bytes(stub[stub.len() - 4..].try_into().unwrap())
}

/// High-level SVCCTL client bound over an SMB `\PIPE\svcctl`.
pub struct SvcctlClient<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> SvcctlClient<'a> {
    pub async fn bind(client: &'a mut SmbClient, file_id: [u8; 16]) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind(svcctl_syntax()).await?;
        Ok(SvcctlClient { pipe })
    }

    async fn open_scm(&mut self) -> Result<ScHandle> {
        let resp = self
            .pipe
            .call(
                opnum::OPEN_SC_MANAGER_W,
                &encode_open_scm(SC_MANAGER_ALL_ACCESS),
            )
            .await?;
        let mut d = NdrDecoder::new(&resp);
        let handle = ScHandle::decode(&mut d)?;
        let ret = d.u32().unwrap_or(u32::MAX);
        if ret != 0 || handle.is_null() {
            return Err(RpcError::Protocol(format!(
                "ROpenSCManagerW failed (win32 {ret})"
            )));
        }
        Ok(handle)
    }

    async fn create_service(
        &mut self,
        scm: &ScHandle,
        name: &str,
        binpath: &str,
    ) -> Result<ScHandle> {
        let resp = self
            .pipe
            .call(
                opnum::CREATE_SERVICE_W,
                &encode_create_service(scm, name, binpath),
            )
            .await?;
        let ret = tail_return(&resp);
        if ret != 0 {
            return Err(RpcError::Protocol(format!(
                "RCreateServiceW failed (win32 {ret})"
            )));
        }
        // [out] lpdwTagId (unique) then [out] lpServiceHandle (20) then return. Skip the tag.
        let mut d = NdrDecoder::new(&resp);
        let tag_ref = d.u32()?;
        if tag_ref != 0 {
            let _ = d.u32(); // tag value
        }
        ScHandle::decode(&mut d)
    }

    /// Start the service (the command executes); SCM start-timeout/exception = command ran.
    async fn start_service(&mut self, svc: &ScHandle) -> Result<u32> {
        let resp = self
            .pipe
            .call(opnum::START_SERVICE_W, &encode_start_service(svc))
            .await?;
        Ok(tail_return(&resp))
    }

    async fn delete_service(&mut self, svc: &ScHandle) -> Result<u32> {
        let resp = self
            .pipe
            .call(opnum::DELETE_SERVICE, &encode_handle_only(svc))
            .await?;
        Ok(tail_return(&resp))
    }

    async fn close_handle(&mut self, h: &ScHandle) {
        let _ = self
            .pipe
            .call(opnum::CLOSE_SERVICE_HANDLE, &encode_handle_only(h))
            .await;
    }
}

/// The result of a remote exec: the SCM outcome plus captured stdout/stderr (if any).
pub struct ExecResult {
    pub service: String,
    pub start_win32: u32,
    pub ran: bool,
    pub cleaned: bool,
    pub output: Option<String>,
}

/// psexec-style command execution over SVCCTL. Creates a service whose binary detaches the real
/// work (`start "" /b`, so it survives the SCM tearing the service down), redirects its output
/// to a temp file on the target, starts it as LocalSystem, deletes the service, then reads the
/// output back over `C$` (delete-on-close). The service and temp file are always cleaned up.
///
/// `host` is the target used for the `\\host\C$` output read.
pub async fn exec(client: &mut SmbClient, host: &str, command: &str) -> Result<ExecResult> {
    let tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let name = format!("ADh{tag:08x}");
    let out_rel = format!("Windows\\Temp\\ADh{tag:08x}.out"); // relative to C$ root
    let out_win = format!("C:\\{out_rel}"); // absolute path for the redirect
                                            // Detach the real work so it outlives the SCM teardown; redirect stdout+stderr to the file.
    let full = format!("{command} > {out_win} 2>&1");
    let binpath = format!("%COMSPEC% /Q /c start \"\" /b %COMSPEC% /Q /c \"{full}\"");

    // --- create/start/delete the service over \svcctl (IPC$) ---
    let start_ret = create_start_delete(client, &name, &binpath).await?;
    let cleaned = true;
    let ran = matches!(
        start_ret,
        0 | ERROR_SERVICE_REQUEST_TIMEOUT
            | ERROR_SERVICE_NO_THREAD
            | ERROR_EXCEPTION_IN_SERVICE
            | ERROR_PROCESS_ABORTED
    );

    // --- read the captured output off C$ (retries while the async child writes) ---
    let output = if ran {
        match client.tree_connect(&format!("\\\\{host}\\C$")).await {
            Ok(()) => match client.read_file_delete(&out_rel).await {
                Ok(bytes) if !bytes.is_empty() => Some(
                    String::from_utf8_lossy(&bytes)
                        .replace('\r', "")
                        .trim_end()
                        .to_string(),
                ),
                Ok(_) => Some(String::new()),
                Err(e) => {
                    tracing::warn!("output read failed: {e}");
                    None
                }
            },
            Err(e) => {
                tracing::warn!("C$ tree-connect failed: {e}");
                None
            }
        }
    } else {
        None
    };

    Ok(ExecResult {
        service: name,
        start_win32: start_ret,
        ran,
        cleaned,
        output,
    })
}

/// Run a command as LocalSystem over SVCCTL without capturing output — for side-effect commands
/// (e.g. `reg save`) whose result is a file the caller reads separately. Returns the SCM start
/// code. Requires the client to be tree-connected to IPC$. Detaches via `start "" /b`.
pub async fn run(client: &mut SmbClient, command: &str) -> Result<u32> {
    let tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let name = format!("ADh{tag:08x}");
    let binpath = format!("%COMSPEC% /Q /c start \"\" /b %COMSPEC% /Q /c \"{command}\"");
    create_start_delete(client, &name, &binpath).await
}

/// Create → start → delete a transient service with the given binary path; returns the start code.
async fn create_start_delete(client: &mut SmbClient, name: &str, binpath: &str) -> Result<u32> {
    let file_id = client
        .open_pipe("svcctl")
        .await
        .map_err(|e| RpcError::Protocol(format!("open \\svcctl: {e}")))?;
    let mut scm = SvcctlClient::bind(client, file_id).await?;
    let scm_handle = scm.open_scm().await?;
    let svc = scm.create_service(&scm_handle, name, binpath).await?;
    let start_ret = scm.start_service(&svc).await?;
    let del_ret = scm.delete_service(&svc).await?;
    scm.close_handle(&svc).await;
    scm.close_handle(&scm_handle).await;
    if del_ret != 0 {
        tracing::warn!("RDeleteService returned win32 {del_ret}");
    }
    Ok(start_ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_service_stub_shape() {
        // handle(20) + inline WSTR("X\0": max/off/act + 2 wchars = 16) then the scalar block.
        let scm = ScHandle([0x11; 20]);
        let stub = encode_create_service(&scm, "X", "cmd /c whoami");
        assert_eq!(&stub[..20], &[0x11u8; 20]);
        let d = |o: usize| u32::from_le_bytes(stub[o..o + 4].try_into().unwrap());
        assert_eq!(d(20), 2, "lpServiceName WSTR max_count = 2 (X\\0)");
        assert_eq!(d(24), 0, "offset = 0");
        assert_eq!(d(28), 2, "actual_count = 2");
        // chars at 32..36 ('X',0), then lpDisplayName NULL at 36, then the access dwords.
        assert_eq!(d(36), 0, "lpDisplayName must be NULL");
        assert_eq!(d(40), SERVICE_ALL_ACCESS);
        assert_eq!(d(44), SERVICE_WIN32_OWN_PROCESS);
        assert_eq!(d(48), SERVICE_DEMAND_START);
        assert_eq!(d(52), SERVICE_ERROR_IGNORE);
        assert_eq!(
            d(56),
            13 + 1,
            "lpBinaryPathName WSTR max_count = 14 (cmd /c whoami\\0)"
        );
    }

    #[test]
    fn open_scm_stub_is_two_nulls_plus_access() {
        let stub = encode_open_scm(SC_MANAGER_ALL_ACCESS);
        assert_eq!(stub, vec![0, 0, 0, 0, 0, 0, 0, 0, 0x3f, 0x00, 0x0f, 0x00]);
    }
}
