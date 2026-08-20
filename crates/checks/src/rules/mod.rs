//! Additional rule packs that sit alongside the top-level hygiene checks in this
//! crate. Each submodule owns one taxonomy — the file layout keeps large mappings
//! (`ms_crtd::EscFinding` → `Finding`, future SDDL / GKDI packs) from crowding `lib.rs`.

pub mod esc;
