//! SID / GUID types. The parsing/formatting lives in the standalone [`windows_sddl`] crate
//! (extracted from this repo); we re-export it here so the whole workspace shares one `Sid`/`Guid`
//! type, and keep the AD-specific well-known RID table alongside.

pub use windows_sddl::{Guid, Sid};

/// Well-known RIDs (relative to the domain SID unless noted).
pub mod rid {
    pub const ADMINISTRATOR: u32 = 500;
    pub const GUEST: u32 = 501;
    pub const KRBTGT: u32 = 502;
    pub const DOMAIN_ADMINS: u32 = 512;
    pub const DOMAIN_CONTROLLERS: u32 = 516;
    pub const SCHEMA_ADMINS: u32 = 518;
    pub const ENTERPRISE_ADMINS: u32 = 519;
    pub const ADMINISTRATORS_BUILTIN: u32 = 544; // under S-1-5-32
}
