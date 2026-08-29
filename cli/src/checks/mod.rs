//! Offline single-purpose check subcommands — subsets of `scan` for one
//! taxonomy at a time.
//!
//! Each module owns its `Args` struct (referenced from the `CheckCmd` enum
//! in `main.rs` via `checks::<name>::<Name>Args`) and its `async fn` entry
//! point (dispatched from the same enum's match arm).
//!
//! The split from `main.rs` landed in arch-0 (batch 4, post-1.3.10).

pub(crate) mod adcs;
