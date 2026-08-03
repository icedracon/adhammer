//! Control-path graph (the BloodHound-style layer, in-process on petgraph).
//!
//! Nodes are security principals; a directed edge `A -> B` means "A holds a primitive
//! that lets it control B". We seed Tier-0 (Domain/Enterprise Admins, DC computers,
//! the domain head) and do a reverse traversal to find every principal that can reach it.
//! Each edge carries a weight; the cheapest path is the attacker's likely route.

use adhammer_core::sid::Sid;
use adhammer_core::snapshot::Snapshot;
use adhammer_core::AdObject;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use std::collections::HashMap;

pub use ad_acl::{ControlPrimitive, SchemaMap};

/// Edge label. ACL-derived edges are [`ad_acl::ControlPrimitive`]s; `MemberOf` is the one
/// edge that comes from group membership rather than from a security descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    MemberOf,
    Acl(ControlPrimitive),
}

impl EdgeKind {
    /// Lower = cheaper for the attacker = more dangerous.
    pub fn weight(self) -> u32 {
        match self {
            EdgeKind::MemberOf => 0,
            EdgeKind::Acl(p) => p.cost(),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            EdgeKind::MemberOf => "MemberOf",
            EdgeKind::Acl(p) => p.name(),
        }
    }

    /// What traversing this edge gets the attacker (empty for `MemberOf`).
    pub fn impact(self) -> &'static str {
        match self {
            EdgeKind::MemberOf => "inherits every privilege of the group",
            EdgeKind::Acl(p) => p.impact(),
        }
    }

    /// How a defender removes this edge.
    pub fn mitigation(self) -> &'static str {
        match self {
            EdgeKind::MemberOf => "remove the principal from the group",
            EdgeKind::Acl(p) => p.mitigation(),
        }
    }
}

impl From<ControlPrimitive> for EdgeKind {
    fn from(p: ControlPrimitive) -> Self {
        EdgeKind::Acl(p)
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub sid: Sid,
    pub label: String,
    pub tier0: bool,
}

pub struct ControlGraph {
    g: DiGraph<Node, EdgeKind>,
    by_sid: HashMap<String, NodeIndex>,
}

impl ControlGraph {
    pub fn build(snap: &Snapshot) -> Self {
        Self::build_with(snap, &SchemaMap::new())
    }

    /// [`ControlGraph::build`] with a forest schema map, so ACEs on LAPS / gMSA / dMSA
    /// attributes — whose GUIDs differ per forest — become edges too.
    pub fn build_with(snap: &Snapshot, schema: &SchemaMap) -> Self {
        let mut cg = ControlGraph {
            g: DiGraph::new(),
            by_sid: HashMap::new(),
        };

        // 1. one node per principal that has a SID.
        for o in &snap.objects {
            if let Some(sid) = o.bin1("objectSid").and_then(Sid::from_bytes) {
                let tier0 = is_tier0(snap, &sid);
                cg.ensure(sid, label_of(o), tier0);
            }
        }

        // 2. edges.
        for o in &snap.objects {
            let Some(dst) = o.bin1("objectSid").and_then(Sid::from_bytes) else {
                continue;
            };
            cg.add_membership_edges(snap, o, &dst);
            cg.add_acl_edges(o, &dst, schema);
            cg.add_rbcd_edge(o, &dst);
        }
        cg
    }

    fn ensure(&mut self, sid: Sid, label: String, tier0: bool) -> NodeIndex {
        if let Some(&ix) = self.by_sid.get(&sid.to_string()) {
            if tier0 {
                self.g[ix].tier0 = true;
            }
            return ix;
        }
        let key = sid.to_string();
        let ix = self.g.add_node(Node { sid, label, tier0 });
        self.by_sid.insert(key, ix);
        ix
    }

    fn node_for(&mut self, sid: Sid) -> NodeIndex {
        self.ensure(sid.clone(), sid.to_string(), false)
    }

    fn add_membership_edges(&mut self, snap: &Snapshot, o: &AdObject, self_sid: &Sid) {
        // memberOf: this principal -> group. Edge means "member can act as group".
        let me = self.node_for(self_sid.clone());
        for group_dn in o.all("memberOf") {
            if let Some(g) = snap
                .by_dn(group_dn)
                .and_then(|g| g.bin1("objectSid"))
                .and_then(Sid::from_bytes)
            {
                let gx = self.node_for(g);
                self.g.add_edge(me, gx, EdgeKind::MemberOf);
            }
        }
    }

    fn add_rbcd_edge(&mut self, o: &AdObject, self_sid: &Sid) {
        // msDS-AllowedToActOnBehalfOfOtherIdentity is itself an SD; anyone in it can act on `self`.
        if let Some(raw) = o.bin1("msDS-AllowedToActOnBehalfOfOtherIdentity") {
            if let Ok(sd) = windows_sddl::parse(raw) {
                let target = self.node_for(self_sid.clone());
                for ace in sd
                    .dacl
                    .iter()
                    .flat_map(|d| &d.aces)
                    .filter(|a| a.is_allow())
                {
                    let src = self.node_for(ace.trustee.clone());
                    self.g
                        .add_edge(src, target, ControlPrimitive::WriteRbcd.into());
                }
            }
        }
    }

    fn add_acl_edges(&mut self, o: &AdObject, self_sid: &Sid, schema: &SchemaMap) {
        let Some(raw) = o.bin1("nTSecurityDescriptor") else {
            return;
        };
        let Ok(sd) = windows_sddl::parse(raw) else {
            return;
        };
        let target = self.node_for(self_sid.clone());

        // `ad_acl` owns the ACE→primitive semantics (deny ACEs yield nothing); we only
        // decide which trustees are worth a node.
        for grant in ad_acl::grants_with(&sd, schema) {
            if grant.trustee_is_well_known() {
                continue;
            }
            let src = self.node_for(grant.trustee.clone());
            self.g.add_edge(src, target, grant.primitive.into());
        }
    }

    /// Every principal that can reach any Tier-0 node, with the cheapest path cost.
    pub fn paths_to_tier0(&self) -> Vec<AttackPath> {
        use petgraph::algo::dijkstra;
        // Reverse the graph: shortest path *into* a tier0 node = attacker route.
        let rev = petgraph::visit::Reversed(&self.g);
        let mut out = Vec::new();
        for tix in self.g.node_indices().filter(|&i| self.g[i].tier0) {
            let dist = dijkstra(rev, tix, None, |e| e.weight().weight());
            for (src, cost) in dist {
                if src == tix || self.g[src].tier0 {
                    continue;
                }
                out.push(AttackPath {
                    principal: self.g[src].label.clone(),
                    principal_sid: self.g[src].sid.to_string(),
                    target: self.g[tix].label.clone(),
                    cost,
                });
            }
        }
        out.sort_by_key(|p| p.cost);
        out
    }

    pub fn stats(&self) -> (usize, usize) {
        (self.g.node_count(), self.g.edge_count())
    }

    /// Direct `kind` edges from a non-Tier-0 principal into a Tier-0 node.
    pub fn direct_edges_to_tier0(&self, kind: EdgeKind) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for e in self.g.edge_indices() {
            if self.g[e] != kind {
                continue;
            }
            let (src, dst) = self.g.edge_endpoints(e).unwrap();
            if self.g[dst].tier0 && !self.g[src].tier0 {
                out.push((self.g[src].label.clone(), self.g[dst].label.clone()));
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AttackPath {
    pub principal: String,
    pub principal_sid: String,
    pub target: String,
    pub cost: u32,
}

fn is_tier0(snap: &Snapshot, sid: &Sid) -> bool {
    use adhammer_core::sid::rid;
    let Some(rid) = sid.rid() else { return false };
    // domain-relative privileged RIDs
    if matches!(
        rid,
        rid::DOMAIN_ADMINS
            | rid::ENTERPRISE_ADMINS
            | rid::SCHEMA_ADMINS
            | rid::ADMINISTRATOR
            | rid::KRBTGT
            | rid::DOMAIN_CONTROLLERS
    ) {
        // ensure it belongs to this domain (or is builtin admins)
        if let Some(dsid) = &snap.domain.domain_sid {
            let prefix = &sid.sub_authorities[..sid.sub_authorities.len().saturating_sub(1)];
            if prefix == &dsid.sub_authorities[..] {
                return true;
            }
        }
    }
    // BUILTIN\Administrators  S-1-5-32-544
    sid.identifier_authority == 5
        && sid.sub_authorities.first() == Some(&32)
        && sid.rid() == Some(rid::ADMINISTRATORS_BUILTIN)
}

fn label_of(o: &AdObject) -> String {
    o.one("sAMAccountName")
        .map(String::from)
        .unwrap_or_else(|| o.dn.clone())
}
