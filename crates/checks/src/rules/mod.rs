//! Additional rule packs that sit alongside the top-level PingCastle-style
//! checks in this crate. Each submodule owns one taxonomy — the file layout
//! keeps large third-party mappings (`ms_crtd::EscFinding` → `Finding`,
//! future SDDL / GKDI packs) from crowding `lib.rs`.

pub mod esc;
