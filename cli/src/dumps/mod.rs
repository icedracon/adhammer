//! Offline credential/secret extraction subcommands.
//!
//! Each module owns its `Args` struct (referenced from the `DumpCmd` enum in
//! `main.rs` via `dumps::<name>::<Name>Args`) and its `async fn` entry point
//! (dispatched from the same enum's match arm).
//!
//! The split from `main.rs` landed in arch-0 (batch 4, post-1.3.10).

pub(crate) mod gmsa;
pub(crate) mod laps;
