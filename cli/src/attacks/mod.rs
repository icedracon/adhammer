//! Active attack handlers — one file per subcommand.
//!
//! Each module owns its `Args` struct (referenced from the top-level `Cli`
//! enum in `main.rs` via `attacks::<name>::<Name>Args`) and its `async fn`
//! entry point (dispatched from the same enum's match arm). Interactive-mode
//! callers in `crate::interactive` reference these directly.
//!
//! The split from `main.rs` landed in arch-0 (post-1.3.10) to keep each
//! handler independently reviewable. See `.agents/arch-0-plan.md`.

pub(crate) mod abuse;
pub(crate) mod asktgt;
pub(crate) mod badsuccessor;
pub(crate) mod coerce;
pub(crate) mod esc4;
pub(crate) mod gmsa;
pub(crate) mod golden;
pub(crate) mod laps;
pub(crate) mod lsa;
pub(crate) mod rbcd;
pub(crate) mod samr;
pub(crate) mod shadowcred;
pub(crate) mod silver;
pub(crate) mod spray;
pub(crate) mod unconstrained;
pub(crate) mod zerologon;
