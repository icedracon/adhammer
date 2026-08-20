//! BloodHound export — turn a collected [`Snapshot`] into BloodHound CE v5 ingest JSON that the
//! BloodHound UI ingests, so the in-process control-path graph becomes explorable in the tool
//! every AD team already uses. Targets the BloodHound Community Edition v5 ingest format: one file per
//! node type (`users`/`computers`/`groups`/`domains`/`ous`/`gpos`/`containers`), each a
//! `{"data":[…],"meta":{…}}` document, packaged into a single `.zip`.
//!
//! Node identity: SIDs for security principals, GUIDs for OUs/GPOs/containers. Edges come from
//! group membership (`Members`) and from ACEs parsed out of `nTSecurityDescriptor` — the same
//! rights the control-path graph walks, mapped to BloodHound `RightName`s.

use adhammer_core::sid::{Guid, Sid};
use adhammer_core::snapshot::Snapshot;
use adhammer_core::AdObject;
use serde_json::{json, Value};
use std::collections::HashMap;
use windows_sddl::rights;
use windows_sddl::{AccessMask, AceType};

const VERSION: u32 = 5;

/// The object types BloodHound distinguishes, as they appear in JSON.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    User,
    Computer,
    Group,
    Domain,
    Ou,
    Gpo,
    Container,
    Base,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::User => "User",
            Kind::Computer => "Computer",
            Kind::Group => "Group",
            Kind::Domain => "Domain",
            Kind::Ou => "OU",
            Kind::Gpo => "GPO",
            Kind::Container => "Container",
            Kind::Base => "Base",
        }
    }
}

fn kind_of(o: &AdObject) -> Kind {
    if o.has_class("computer") {
        Kind::Computer
    } else if o.has_class("group") {
        Kind::Group
    } else if o.has_class("domainDNS") {
        Kind::Domain
    } else if o.has_class("groupPolicyContainer") {
        Kind::Gpo
    } else if o.has_class("organizationalUnit") {
        Kind::Ou
    } else if o.has_class("user") {
        Kind::User
    } else if o.has_class("container") {
        Kind::Container
    } else {
        Kind::Base
    }
}

/// DC=corp,DC=local → "corp.local".
fn dn_to_fqdn(dn: &str) -> String {
    dn.split(',')
        .filter_map(|p| p.trim().strip_prefix("DC="))
        .collect::<Vec<_>>()
        .join(".")
}

fn guid_upper(o: &AdObject) -> Option<String> {
    o.bin1("objectGUID")
        .and_then(Guid::from_bytes)
        .map(|g| g.to_string().to_uppercase())
}

/// The BloodHound identity for an object: SID (principals) or GUID (OU/GPO/container).
fn object_id(o: &AdObject, kind: Kind) -> Option<String> {
    match kind {
        Kind::User | Kind::Computer | Kind::Group | Kind::Domain => o
            .bin1("objectSid")
            .and_then(Sid::from_bytes)
            .map(|s| s.to_string().to_uppercase()),
        _ => guid_upper(o),
    }
}

struct Ctx {
    domain_fqdn_upper: String,
    domain_sid: String,
    /// SID → node type, for resolving ACE trustees and group members.
    type_by_sid: HashMap<String, Kind>,
    /// member DN → (id, type), for group `Members` and containment.
    id_by_dn: HashMap<String, (String, Kind)>,
}

/// Build the full set of BloodHound JSON files (filename, bytes) for a snapshot.
pub fn export_files(snap: &Snapshot) -> Vec<(String, Vec<u8>)> {
    let fqdn = dn_to_fqdn(&snap.domain.domain_dn);
    let domain_sid = snap
        .domain
        .domain_sid
        .as_ref()
        .map(|s| s.to_string().to_uppercase())
        .unwrap_or_default();

    let mut ctx = Ctx {
        domain_fqdn_upper: fqdn.to_uppercase(),
        domain_sid,
        type_by_sid: HashMap::new(),
        id_by_dn: HashMap::new(),
    };
    for o in &snap.objects {
        let k = kind_of(o);
        if let Some(sid) = o.bin1("objectSid").and_then(Sid::from_bytes) {
            ctx.type_by_sid.insert(sid.to_string().to_uppercase(), k);
        }
        if let Some(id) = object_id(o, k) {
            ctx.id_by_dn.insert(o.dn.to_uppercase(), (id, k));
        }
    }

    let mut buckets: HashMap<&'static str, Vec<Value>> = HashMap::new();
    for name in [
        "users",
        "computers",
        "groups",
        "domains",
        "ous",
        "gpos",
        "containers",
    ] {
        buckets.insert(name, Vec::new());
    }

    for o in &snap.objects {
        let kind = kind_of(o);
        let Some(id) = object_id(o, kind) else {
            continue;
        };
        let node = build_node(&ctx, o, kind, &id);
        let bucket = match kind {
            Kind::User => "users",
            Kind::Computer => "computers",
            Kind::Group => "groups",
            Kind::Domain => "domains",
            Kind::Ou => "ous",
            Kind::Gpo => "gpos",
            Kind::Container | Kind::Base => "containers",
        };
        buckets.get_mut(bucket).unwrap().push(node);
    }

    buckets
        .into_iter()
        .map(|(typ, data)| {
            let doc = json!({
                "data": data,
                "meta": { "methods": 0, "type": typ, "count": data.len(), "version": VERSION }
            });
            (
                format!("{}_{typ}.json", ctx.domain_fqdn_upper.to_lowercase()),
                serde_json::to_vec(&doc).unwrap(),
            )
        })
        .collect()
}

/// Export a snapshot to a single BloodHound `.zip` at `path`.
pub fn export_zip(snap: &Snapshot, path: &std::path::Path) -> std::io::Result<usize> {
    let files = export_files(snap);
    let n = files.len();
    let zip = zip_store(&files);
    std::fs::write(path, zip)?;
    Ok(n)
}

fn build_node(ctx: &Ctx, o: &AdObject, kind: Kind, id: &str) -> Value {
    let mut props = base_properties(ctx, o, kind);
    let aces = build_aces(ctx, o);
    let owner_ace = owner_ace(ctx, o);

    let mut node = json!({
        "ObjectIdentifier": id,
        "Aces": [],
        "IsDeleted": false,
        "IsACLProtected": false,
    });
    // Owner first (BloodHound convention), then the DACL-derived ACEs.
    let mut ace_list = Vec::new();
    ace_list.extend(owner_ace);
    ace_list.extend(aces);
    node["Aces"] = Value::Array(ace_list);

    match kind {
        Kind::User => {
            props["hasspn"] = json!(!o.all("servicePrincipalName").is_empty());
            node["Properties"] = props;
            node["PrimaryGroupSID"] = json!(primary_group_sid(ctx, o));
            node["HasSIDHistory"] = json!(sid_history(o));
            node["SPNTargets"] = json!([]);
            node["AllowedToDelegate"] = json!([]);
        }
        Kind::Computer => {
            node["Properties"] = props;
            node["PrimaryGroupSID"] = json!(primary_group_sid(ctx, o));
            node["HasSIDHistory"] = json!(sid_history(o));
            node["AllowedToDelegate"] = json!([]);
            node["AllowedToAct"] = json!([]);
            node["DumpSMSAPassword"] = json!([]);
            for coll in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
                node[coll] = json!({"Results": [], "Collected": false, "FailureReason": null});
            }
            for coll in [
                "LocalAdmins",
                "RemoteDesktopUsers",
                "DcomUsers",
                "PSRemoteUsers",
            ] {
                node[coll] = json!({"Results": [], "Collected": false, "FailureReason": null});
            }
            node["Status"] = Value::Null;
        }
        Kind::Group => {
            node["Properties"] = props;
            node["Members"] = json!(group_members(ctx, o));
        }
        Kind::Domain => {
            node["Properties"] = props;
            node["Trusts"] = json!([]);
            node["Links"] = json!([]);
            node["ChildObjects"] = json!([]);
            node["GPOChanges"] = json!({
                "LocalAdmins": [], "RemoteDesktopUsers": [], "DcomUsers": [],
                "PSRemoteUsers": [], "AffectedComputers": []
            });
        }
        Kind::Ou => {
            node["Properties"] = props;
            node["Links"] = json!([]);
            node["ChildObjects"] = json!([]);
            node["GPOChanges"] = json!({
                "LocalAdmins": [], "RemoteDesktopUsers": [], "DcomUsers": [],
                "PSRemoteUsers": [], "AffectedComputers": []
            });
        }
        Kind::Gpo => {
            node["Properties"] = props;
        }
        Kind::Container | Kind::Base => {
            node["Properties"] = props;
            node["ChildObjects"] = json!([]);
        }
    }
    node
}

fn base_properties(ctx: &Ctx, o: &AdObject, kind: Kind) -> Value {
    let dn = o.dn.to_uppercase();
    let name = display_name(ctx, o, kind);
    let mut p = json!({
        "domain": ctx.domain_fqdn_upper,
        "domainsid": ctx.domain_sid,
        "name": name,
        "distinguishedname": dn,
        "whencreated": o.int("whenCreated").unwrap_or(0),
    });
    if let Some(desc) = o.one("description") {
        p["description"] = json!(desc);
    }
    let admincount = o.int("adminCount").unwrap_or(0) != 0;
    p["admincount"] = json!(admincount);
    p["highvalue"] = json!(is_high_value(ctx, o, kind));

    if matches!(kind, Kind::User | Kind::Computer) {
        let uac = o.uac();
        p["enabled"] = json!(uac & adhammer_core::object::uac::ACCOUNTDISABLE == 0);
        p["unconstraineddelegation"] =
            json!(uac & adhammer_core::object::uac::TRUSTED_FOR_DELEGATION != 0);
        p["trustedtoauth"] =
            json!(uac & adhammer_core::object::uac::TRUSTED_TO_AUTH_FOR_DELEGATION != 0);
        p["pwdlastset"] = json!(filetime_to_unix(o.filetime("pwdLastSet")));
        p["lastlogontimestamp"] = json!(filetime_to_unix(o.filetime("lastLogonTimestamp")));
        p["samaccountname"] = json!(o.one("sAMAccountName").unwrap_or_default());
        if let Some(spns) = o.attrs.get("servicePrincipalName") {
            p["serviceprincipalnames"] = json!(spns);
        }
    }
    if kind == Kind::User {
        let uac = o.uac();
        p["dontreqpreauth"] = json!(uac & adhammer_core::object::uac::DONT_REQ_PREAUTH != 0);
        p["passwordnotreqd"] = json!(uac & adhammer_core::object::uac::PASSWD_NOTREQD != 0);
        p["sensitive"] = json!(uac & adhammer_core::object::uac::NOT_DELEGATED != 0);
        if let Some(upn) = o.one("userPrincipalName") {
            p["email"] = json!(upn);
        }
    }
    if kind == Kind::Computer {
        p["operatingsystem"] = json!(o.one("operatingSystem").unwrap_or_default());
    }
    p
}

/// BloodHound `name`: PRINCIPAL@DOMAIN for users/groups, HOST.DOMAIN for computers, the FQDN
/// for the domain itself, otherwise the object's CN@DOMAIN.
fn display_name(ctx: &Ctx, o: &AdObject, kind: Kind) -> String {
    let dom = &ctx.domain_fqdn_upper;
    match kind {
        Kind::Domain => dom.clone(),
        Kind::Computer => {
            let host = o
                .one("dNSHostName")
                .map(str::to_string)
                .or_else(|| {
                    o.one("sAMAccountName")
                        .map(|s| s.trim_end_matches('$').to_string())
                })
                .unwrap_or_default()
                .to_uppercase();
            if host.contains('.') {
                host
            } else {
                format!("{host}.{dom}")
            }
        }
        _ => {
            let sam = o
                .one("sAMAccountName")
                .map(str::to_string)
                .or_else(|| o.one("cn").map(str::to_string))
                .or_else(|| o.one("name").map(str::to_string))
                .unwrap_or_default()
                .to_uppercase();
            format!("{sam}@{dom}")
        }
    }
}

fn is_high_value(ctx: &Ctx, o: &AdObject, kind: Kind) -> bool {
    // Well-known Tier-0 RIDs / groups (Domain Admins 512, Enterprise Admins 519, etc.).
    if kind == Kind::Group {
        if let Some(sid) = o.bin1("objectSid").and_then(Sid::from_bytes) {
            if let Some(rid) = sid.rid() {
                if matches!(rid, 512 | 516 | 518 | 519 | 520)
                    && sid.to_string().to_uppercase().starts_with(&ctx.domain_sid)
                {
                    return true;
                }
            }
            // BUILTIN\Administrators S-1-5-32-544
            if sid.to_string() == "S-1-5-32-544" {
                return true;
            }
        }
    }
    false
}

fn primary_group_sid(ctx: &Ctx, o: &AdObject) -> Option<String> {
    o.int("primaryGroupID")
        .map(|rid| format!("{}-{}", ctx.domain_sid, rid))
}

fn sid_history(o: &AdObject) -> Vec<Value> {
    o.bin_all("sIDHistory")
        .iter()
        .filter_map(|b| Sid::from_bytes(b))
        .map(|s| {
            let id = s.to_string().to_uppercase();
            json!({"ObjectIdentifier": id, "ObjectType": "User"})
        })
        .collect()
}

fn group_members(ctx: &Ctx, o: &AdObject) -> Vec<Value> {
    o.all("member")
        .iter()
        .filter_map(|dn| ctx.id_by_dn.get(&dn.to_uppercase()))
        .map(|(id, k)| json!({"ObjectIdentifier": id, "ObjectType": k.as_str()}))
        .collect()
}

fn principal_type(ctx: &Ctx, sid: &Sid) -> &'static str {
    ctx.type_by_sid
        .get(&sid.to_string().to_uppercase())
        .copied()
        .unwrap_or(Kind::Base)
        .as_str()
}

/// The object owner, as an `Owns` ACE (BloodHound models ownership as an edge).
fn owner_ace(ctx: &Ctx, o: &AdObject) -> Vec<Value> {
    let Some(raw) = o.bin1("nTSecurityDescriptor") else {
        return vec![];
    };
    let Ok(sd) = windows_sddl::parse(raw) else {
        return vec![];
    };
    let Some(owner) = sd.owner else { return vec![] };
    if owner.is_well_known() {
        return vec![];
    }
    vec![ace(
        &owner.to_string().to_uppercase(),
        principal_type(ctx, &owner),
        "Owns",
        false,
    )]
}

/// Parse the DACL into BloodHound ACEs (allow-only, non-well-known trustees).
fn build_aces(ctx: &Ctx, o: &AdObject) -> Vec<Value> {
    let Some(raw) = o.bin1("nTSecurityDescriptor") else {
        return vec![];
    };
    let Ok(sd) = windows_sddl::parse(raw) else {
        return vec![];
    };
    let mut out = Vec::new();
    for a in sd.dacl.iter().flat_map(|d| &d.aces) {
        if a.ace_type == AceType::AccessDenied || a.ace_type == AceType::AccessDeniedObject {
            continue;
        }
        if a.trustee.is_well_known() {
            continue;
        }
        let inherited = a.flags & 0x10 != 0; // INHERITED_ACE
        let sid = a.trustee.to_string().to_uppercase();
        let ptype = principal_type(ctx, &a.trustee);
        for right in ace_rights(a) {
            out.push(ace(&sid, ptype, right, inherited));
        }
    }
    out
}

fn ace(principal: &str, ptype: &str, right: &str, inherited: bool) -> Value {
    json!({
        "PrincipalSID": principal,
        "PrincipalType": ptype,
        "RightName": right,
        "IsInherited": inherited,
    })
}

/// Map an ACE's access mask + object-type GUID to BloodHound `RightName`s.
fn ace_rights(a: &windows_sddl::Ace) -> Vec<&'static str> {
    let m = a.mask;
    let mut v = Vec::new();
    if m.contains(AccessMask::GENERIC_ALL) {
        return vec!["GenericAll"];
    }
    if m.contains(AccessMask::WRITE_DAC) {
        v.push("WriteDacl");
    }
    if m.contains(AccessMask::WRITE_OWNER) {
        v.push("WriteOwner");
    }
    if m.contains(AccessMask::GENERIC_WRITE) {
        v.push("GenericWrite");
    }
    if m.contains(AccessMask::CONTROL_ACCESS) {
        match &a.object_type {
            None => v.push("AllExtendedRights"),
            Some(g) if rights::FORCE_CHANGE_PASSWORD.matches(g) => v.push("ForceChangePassword"),
            Some(g) if rights::REPL_GET_CHANGES.matches(g) => v.push("GetChanges"),
            Some(g) if rights::REPL_GET_CHANGES_ALL.matches(g) => v.push("GetChangesAll"),
            Some(_) => {}
        }
    }
    if m.contains(AccessMask::WRITE_PROP) {
        match &a.object_type {
            None => {
                if !v.contains(&"GenericWrite") {
                    v.push("GenericWrite");
                }
            }
            Some(g) if rights::MEMBER_ATTR.matches(g) => v.push("AddMember"),
            Some(g) if rights::KEY_CREDENTIAL_LINK.matches(g) => v.push("AddKeyCredentialLink"),
            Some(g) if rights::RBCD_ATTR.matches(g) => v.push("AddAllowedToAct"),
            Some(_) => {}
        }
    }
    v
}

/// Windows FILETIME (100 ns ticks since 1601) → Unix seconds; -1 for never/absent.
fn filetime_to_unix(ft: Option<i64>) -> i64 {
    match ft {
        Some(t) if t > 0 => t / 10_000_000 - 11_644_473_600,
        _ => -1,
    }
}

// ---- Minimal STORED (uncompressed) ZIP writer -----------------------------------------------
// BloodHound accepts stored zips; a from-scratch writer keeps the dependency footprint at zero.

fn zip_store(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut offsets = Vec::new();

    for (name, data) in files {
        let crc = crc32(data);
        let off = out.len() as u32;
        offsets.push(off);
        let name_b = name.as_bytes();
        // Local file header.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method = stored
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed size
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed size
        out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_b);
        out.extend_from_slice(data);
    }

    for ((name, data), off) in files.iter().zip(offsets) {
        let crc = crc32(data);
        let name_b = name.as_bytes();
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method
        central.extend_from_slice(&0u16.to_le_bytes()); // time
        central.extend_from_slice(&0u16.to_le_bytes()); // date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&off.to_le_bytes());
        central.extend_from_slice(name_b);
    }

    let central_off = out.len() as u32;
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    // End of central directory.
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_known_vector() {
        // CRC-32 of "123456789" is 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn zip_has_signatures() {
        let z = zip_store(&[("a.json".into(), b"{}".to_vec())]);
        assert_eq!(&z[0..4], &0x0403_4b50u32.to_le_bytes()); // local header
                                                             // EOCD signature appears near the end.
        assert!(z.windows(4).any(|w| w == 0x0605_4b50u32.to_le_bytes()));
    }

    #[test]
    fn fqdn_from_dn() {
        assert_eq!(dn_to_fqdn("DC=corp,DC=local"), "corp.local");
    }

    #[test]
    fn filetime_conversion() {
        assert_eq!(filetime_to_unix(None), -1);
        assert_eq!(filetime_to_unix(Some(0)), -1);
        // 2021-01-01T00:00:00Z = 1609459200 unix = (1609459200 + 11644473600) * 1e7 filetime.
        assert_eq!(
            filetime_to_unix(Some(132_539_328_000_000_000)),
            1_609_459_200
        );
    }
}
