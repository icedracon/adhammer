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
pub(crate) mod adcs_relay;
pub(crate) mod asktgt;
pub(crate) mod badsuccessor;
pub(crate) mod coerce;
pub(crate) mod dcsync;
pub(crate) mod diamond;
pub(crate) mod dns;
pub(crate) mod esc1;
pub(crate) mod esc4;
pub(crate) mod exec_pack;
pub(crate) mod gmsa;
pub(crate) mod golden;
pub(crate) mod icpr_esc1;
pub(crate) mod laps;
pub(crate) mod lsa;
pub(crate) mod mssql;
pub(crate) mod ptt;
pub(crate) mod rbcd;
pub(crate) mod relay;
pub(crate) mod roast;
pub(crate) mod samr;
pub(crate) mod scan;
pub(crate) mod scan_anonymous;
pub(crate) mod secretsdump;
pub(crate) mod shadowcred;
pub(crate) mod silver;
pub(crate) mod spray;
pub(crate) mod unconstrained;
pub(crate) mod winrm_exec;
pub(crate) mod zerologon;
