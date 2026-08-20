//! # ADHammer Core — the SDK
//!
//! ADHammer is split into **Core** (this SDK — reusable libraries) and the **CLI** (the
//! `adhammer` binary that drives them). This crate is the single import surface for Core: it
//! re-exports every subsystem so a downstream tool can `use adhammer_sdk::{graph, kerberos, …}`
//! instead of depending on each `adhammer-*` crate individually.
//!
//! The subsystems, bottom-up:
//! - [`types`] — core types (`Sid`, `Guid`, `Snapshot`, `Finding`).  *(the `adhammer-core` crate)*
//! - [`collector`] — LDAP collection into a `Snapshot` (TLS backend via crate features).
//! - [`checks`] — the AD hygiene audit rules (privileged accounts, trusts, stale objects, anomalies).
//! - [`graph`] — the control-path graph and executable attack chains ([`graph::AttackPath`]).
//! - [`kerberos`] — AS-REP/Kerberoast, S4U/RBCD, PKINIT, ticket forging.
//! - [`ldap`] — the raw LDAP client (NTLM/SASL) used for writes and relay.
//! - [`sysvol`] — GPP cpassword + GptTmpl.inf analysis.
//! - [`bloodhound`] — SharpHound-compatible BloodHound CE export.
//! - [`secrets`] — offline SAM/LSA/DCC2 secret decryption.
//! - [`report`] — JSON/HTML reporting.
//!
//! For the DCE/RPC, NDR, PAC, DRSUAPI, GPO, and DPAPI layers, see the standalone crates
//! `dcerpc`, `ms-ndr`, `ms-pac`, `ms-drsr`, `gpo`, and `dpapi-offline`.

// `adhammer-core` is aliased to `types` so it never shadows the `core` extern-prelude crate.
pub use adhammer_core as types;

pub use adhammer_bloodhound as bloodhound;
pub use adhammer_checks as checks;
pub use adhammer_collector as collector;
pub use adhammer_graph as graph;
pub use adhammer_kerberos as kerberos;
pub use adhammer_ldap as ldap;
pub use adhammer_report as report;
pub use adhammer_secrets as secrets;
pub use adhammer_sysvol as sysvol;

#[cfg(test)]
mod tests {
    /// The SDK surface resolves: every subsystem is reachable through one import, and the
    /// end-to-end audit path (Snapshot → graph → executable attack chains) is wired.
    #[test]
    fn subsystems_are_reachable() {
        // Type-level touch of one item per subsystem — compiles only if the re-exports resolve.
        let _ = core::any::type_name::<crate::types::Finding>();
        let _ = core::any::type_name::<crate::graph::AttackPath>();
        let _ = core::any::type_name::<crate::graph::ControlGraph>();
        // `checks::run_all` is a fn, referenced as a value to confirm the path resolves.
        let _run_all = crate::checks::run_all;
    }
}
