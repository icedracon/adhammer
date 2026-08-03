//! Path reconstruction: a route to Tier-0 has to come back as the hops it actually walks,
//! each with the command that walks it.

use adhammer_core::sid::Sid;
use adhammer_core::snapshot::{DomainInfo, Snapshot};
use adhammer_core::AdObject;
use adhammer_graph::{ControlGraph, ControlPrimitive};
use std::collections::HashMap;

const DOMAIN: &str = "S-1-5-21-188340184-197284216-3369952227";

fn sid(s: &str) -> Sid {
    Sid::parse(s).expect("test SID parses")
}

fn obj(dn: &str, sid_str: &str, class: &str, attrs: &[(&str, &str)]) -> AdObject {
    let mut a: HashMap<String, Vec<String>> = HashMap::new();
    a.insert("objectClass".into(), vec![class.into()]);
    for (k, v) in attrs {
        a.entry((*k).into()).or_default().push((*v).to_string());
    }
    let mut bin: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    bin.insert("objectSid".into(), vec![sid(sid_str).to_bytes()]);
    AdObject {
        dn: dn.into(),
        attrs: a,
        bin,
    }
}

/// A security descriptor granting `trustee` one object-scoped right.
fn sd_with_ace(trustee: &str, mask: u32, object_type: Option<&str>) -> Vec<u8> {
    use windows_sddl::sid::Guid;
    let trustee = sid(trustee).to_bytes();
    let owner = sid("S-1-5-32-544").to_bytes();

    let mut ace = Vec::new();
    match object_type {
        Some(g) => {
            ace.push(0x05); // ACCESS_ALLOWED_OBJECT_ACE
            ace.push(0x00);
            let guid = Guid::parse(g).unwrap();
            let body_len = (4 + 4 + 4 + 16 + trustee.len()) as u16;
            ace.extend_from_slice(&(body_len + 4).to_le_bytes());
            ace.extend_from_slice(&mask.to_le_bytes());
            ace.extend_from_slice(&1u32.to_le_bytes()); // ACE_OBJECT_TYPE_PRESENT
            ace.extend_from_slice(&guid.0);
            ace.extend_from_slice(&trustee);
        }
        None => {
            ace.push(0x00); // ACCESS_ALLOWED_ACE
            ace.push(0x00);
            ace.extend_from_slice(&((4 + 4 + trustee.len()) as u16).to_le_bytes());
            ace.extend_from_slice(&mask.to_le_bytes());
            ace.extend_from_slice(&trustee);
        }
    }

    let mut dacl = vec![0x02u8, 0x00];
    dacl.extend_from_slice(&((8 + ace.len()) as u16).to_le_bytes());
    dacl.extend_from_slice(&1u16.to_le_bytes());
    dacl.extend_from_slice(&0u16.to_le_bytes());
    dacl.extend_from_slice(&ace);

    let owner_off = 20u32;
    let group_off = 20 + owner.len() as u32;
    let dacl_off = group_off + owner.len() as u32;
    let mut sd = vec![1u8, 0];
    sd.extend_from_slice(&0x8004u16.to_le_bytes());
    sd.extend_from_slice(&owner_off.to_le_bytes());
    sd.extend_from_slice(&group_off.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&dacl_off.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd.extend_from_slice(&owner);
    sd.extend_from_slice(&dacl);
    sd
}

fn domain() -> DomainInfo {
    DomainInfo {
        domain_dn: "DC=testlab,DC=local".into(),
        domain_sid: Some(sid(DOMAIN)),
        ..Default::default()
    }
}

/// bob --GenericAll--> svc --MemberOf--> Domain Admins
fn two_hop_snapshot() -> Snapshot {
    let bob = obj("CN=bob,DC=x", &format!("{DOMAIN}-1105"), "user", &[]);
    let da = obj(
        "CN=Domain Admins,DC=x",
        &format!("{DOMAIN}-512"),
        "group",
        &[],
    );

    let mut svc = obj(
        "CN=svc_sql,DC=x",
        &format!("{DOMAIN}-1106"),
        "user",
        &[("memberOf", "CN=Domain Admins,DC=x")],
    );
    svc.bin.insert(
        "nTSecurityDescriptor".into(),
        vec![sd_with_ace(&format!("{DOMAIN}-1105"), 0x1000_0000, None)],
    );

    Snapshot::new(domain(), vec![bob, svc, da])
}

#[test]
fn a_path_carries_the_hops_it_walks() {
    let g = ControlGraph::build(&two_hop_snapshot());
    let paths = g.paths_to_tier0();

    let bob = paths
        .iter()
        .find(|p| p.principal_sid.ends_with("-1105"))
        .expect("bob reaches Tier-0");

    assert_eq!(bob.steps.len(), 2, "{}", bob.render());
    assert_eq!(bob.steps[0].edge, "GenericAll");
    assert_eq!(bob.steps[1].edge, "MemberOf");
    // Every hop chains: the target of one is the source of the next.
    assert_eq!(bob.steps[0].to, bob.steps[1].from);
    assert_eq!(bob.steps[1].to, bob.target);
    assert_eq!(bob.cost, 1); // GenericAll 1 + MemberOf 0
}

#[test]
fn each_hop_carries_a_command_or_says_it_has_none() {
    let g = ControlGraph::build(&two_hop_snapshot());
    let p = g
        .paths_to_tier0()
        .into_iter()
        .find(|p| p.steps.len() == 2)
        .expect("two-hop path");

    // GenericAll is executable today…
    let cmd = p.steps[0].command.as_deref().expect("GenericAll executes");
    assert!(cmd.starts_with("adhammer attack abuse"), "{cmd}");
    assert!(cmd.contains(&p.steps[0].to), "command names the target");
    // …MemberOf is not an action, so it has no executor.
    assert!(p.steps[1].command.is_none());
    assert!(!p.fully_executable());
}

#[test]
fn every_hop_carries_impact_and_a_fix() {
    let g = ControlGraph::build(&two_hop_snapshot());
    for p in g.paths_to_tier0() {
        for s in &p.steps {
            assert!(!s.impact.is_empty(), "{} has no impact line", s.edge);
            assert!(!s.mitigation.is_empty(), "{} has no fix line", s.edge);
        }
    }
}

#[test]
fn render_shows_the_whole_route() {
    let g = ControlGraph::build(&two_hop_snapshot());
    let p = g
        .paths_to_tier0()
        .into_iter()
        .find(|p| p.steps.len() == 2)
        .unwrap();
    let r = p.render();
    assert!(r.contains("[GenericAll]"), "{r}");
    assert!(r.contains("[MemberOf]"), "{r}");
    assert!(r.ends_with(&p.target), "{r}");
}

#[test]
fn sid_history_is_an_edge() {
    let da = obj(
        "CN=Domain Admins,DC=x",
        &format!("{DOMAIN}-512"),
        "group",
        &[],
    );
    let migrated = obj(
        "CN=oldadmin,DC=x",
        &format!("{DOMAIN}-1200"),
        "user",
        &[("sIDHistory", &format!("{DOMAIN}-512"))],
    );
    let g = ControlGraph::build(&Snapshot::new(domain(), vec![migrated, da]));

    let p = g
        .paths_to_tier0()
        .into_iter()
        .find(|p| p.principal_sid.ends_with("-1200"))
        .expect("sIDHistory reaches Tier-0");
    assert_eq!(p.steps.len(), 1);
    assert_eq!(p.steps[0].edge, "SidHistory");
    assert_eq!(p.cost, 0, "sIDHistory is already effective access");
}

#[test]
fn unconstrained_delegation_reaches_every_dc() {
    // A member server trusted for delegation: coerce a DC to it and the DC's TGT is yours.
    let host = obj(
        "CN=WEB01,DC=x",
        &format!("{DOMAIN}-1300"),
        "computer",
        &[("userAccountControl", "524288")], // TRUSTED_FOR_DELEGATION
    );
    let dc = obj(
        "CN=DC01,DC=x",
        &format!("{DOMAIN}-1000"),
        "computer",
        &[("userAccountControl", "532480")], // SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION
    );
    let dcs_group = obj(
        "CN=Domain Controllers,DC=x",
        &format!("{DOMAIN}-516"),
        "group",
        &[],
    );
    let g = ControlGraph::build(&Snapshot::new(domain(), vec![host, dc, dcs_group]));

    let (_, edges) = g.stats();
    assert!(edges > 0, "the delegation edge exists");
    assert!(!g
        .direct_edges_to_tier0(adhammer_graph::EdgeKind::UnconstrainedDelegation)
        .is_empty());
}

#[test]
fn constrained_delegation_follows_the_spn_to_its_host() {
    let dc = obj(
        "CN=DC01,DC=x",
        &format!("{DOMAIN}-1000"),
        "computer",
        &[
            ("userAccountControl", "532480"),
            ("servicePrincipalName", "CIFS/dc01.testlab.local"),
            ("sAMAccountName", "DC01$"),
        ],
    );
    let svc = obj(
        "CN=svc_web,DC=x",
        &format!("{DOMAIN}-1400"),
        "user",
        &[("msDS-AllowedToDelegateTo", "CIFS/dc01.testlab.local")],
    );
    let g = ControlGraph::build(&Snapshot::new(domain(), vec![svc, dc]));

    let hits = g.direct_edges_to_tier0(adhammer_graph::EdgeKind::AllowedToDelegate);
    assert_eq!(hits.len(), 1, "svc_web delegates to the DC");
}

#[test]
fn an_isolated_principal_has_no_path() {
    let lonely = obj("CN=nobody,DC=x", &format!("{DOMAIN}-1500"), "user", &[]);
    let da = obj(
        "CN=Domain Admins,DC=x",
        &format!("{DOMAIN}-512"),
        "group",
        &[],
    );
    let g = ControlGraph::build(&Snapshot::new(domain(), vec![lonely, da]));
    assert!(g.paths_to_tier0().is_empty());
}

#[test]
fn executor_templates_substitute_both_endpoints() {
    let e = adhammer_graph::EdgeKind::Acl(ControlPrimitive::AddMember);
    let c = e.command("bob", "Domain Admins").unwrap();
    assert_eq!(
        c,
        "adhammer attack abuse --add-member --group Domain Admins --member bob"
    );
    assert!(adhammer_graph::EdgeKind::MemberOf
        .command("a", "b")
        .is_none());
}
