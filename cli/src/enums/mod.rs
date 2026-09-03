//! Read-only enumeration subcommands — one file per group.
//!
//! Each module owns its `Args` struct (referenced from the `EnumCmd` enum
//! in `main.rs` via `enums::<name>::<Name>Args`) and its `async fn` entry
//! point (dispatched from the same enum's match arm). Interactive-mode
//! callers in `crate::interactive` reference these directly.
//!
//! The split from `main.rs` landed in arch-0 (batch 4, post-1.3.10) to keep
//! each handler independently reviewable. See `.agents/arch-0-plan.md`.

pub(crate) mod adcs;
pub(crate) mod dns;
pub(crate) mod esc_registry;
pub(crate) mod krb;
pub(crate) mod net;
pub(crate) mod nullbind;
pub(crate) mod posture;
pub(crate) mod rpcnull;
pub(crate) mod sccm;
pub(crate) mod sessions;
pub(crate) mod web;
