//! ADhammer local secrets — offline registry-hive parsing and SAM hash decryption.
//!
//! Feed it `SYSTEM` and `SAM` hives (retrieved with `reg save` + an SMB `C$` read); it derives
//! the bootkey and returns each local account's NT hash in secretsdump format. LSA secrets and
//! cached domain credentials (DCC2) from the `SECURITY` hive are a planned follow-on.

pub mod hive;
pub mod lsa;
pub mod rrp;
pub mod sam;

pub use hive::Hive;
pub use lsa::{CachedCred, LsaDump, LsaSecret};
pub use rrp::bootkey_via_rrp;
pub use sam::{dump, SamAccount};

/// Parse SYSTEM + SAM hive bytes and return the decrypted local accounts.
pub fn local_dump(system: &[u8], sam_bytes: &[u8]) -> Result<Vec<SamAccount>, String> {
    let system = Hive::parse(system.to_vec()).ok_or("SYSTEM hive: bad regf header")?;
    let sam = Hive::parse(sam_bytes.to_vec()).ok_or("SAM hive: bad regf header")?;
    if !system.is_valid() || !sam.is_valid() {
        return Err("hive root cell is not a key node".into());
    }
    dump(&system, &sam)
        .ok_or_else(|| "could not derive bootkey / SAM key (unexpected hive layout)".into())
}

/// Fast-path SAM decrypt: bootkey came from RRP (no SYSTEM hive fetch), SAM still from hive.
pub fn local_dump_with_bootkey(
    sam_bytes: &[u8],
    bootkey: &[u8; 16],
) -> Result<Vec<SamAccount>, String> {
    let sam = Hive::parse(sam_bytes.to_vec()).ok_or("SAM hive: bad regf header")?;
    if !sam.is_valid() {
        return Err("SAM hive root cell is not a key node".into());
    }
    sam::dump_with_bootkey(&sam, bootkey)
        .ok_or_else(|| "SAM decrypt failed (bad bootkey or unexpected layout)".into())
}

/// Parse SYSTEM + SECURITY hive bytes and return LSA secrets + cached domain credentials.
pub fn local_lsa(system: &[u8], security_bytes: &[u8]) -> Result<LsaDump, String> {
    let system = Hive::parse(system.to_vec()).ok_or("SYSTEM hive: bad regf header")?;
    let security = Hive::parse(security_bytes.to_vec()).ok_or("SECURITY hive: bad regf header")?;
    lsa::dump(&system, &security)
        .ok_or_else(|| "could not derive LSA key (unexpected hive layout)".into())
}

/// Fast-path LSA decrypt: bootkey came from RRP (no SYSTEM hive fetch), SECURITY still from hive.
pub fn local_lsa_with_bootkey(
    security_bytes: &[u8],
    bootkey: &[u8; 16],
) -> Result<LsaDump, String> {
    let security = Hive::parse(security_bytes.to_vec()).ok_or("SECURITY hive: bad regf header")?;
    lsa::dump_with_bootkey(&security, bootkey)
        .ok_or_else(|| "LSA decrypt failed (bad bootkey or unexpected layout)".into())
}
