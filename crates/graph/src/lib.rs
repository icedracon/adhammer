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

/// Edge label. ACL-derived edges are [`ad_acl::ControlPrimitive`]s; the rest come from object
/// attributes rather than from a security descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    /// Group membership.
    MemberOf,
    /// Derived from an ACE on the target's security descriptor.
    Acl(ControlPrimitive),
    /// `msDS-AllowedToDelegateTo` names a service on the target — constrained delegation
    /// with protocol transition impersonates any user to it.
    AllowedToDelegate,
    /// The source runs with `TRUSTED_FOR_DELEGATION`: coerce the target to authenticate to
    /// it and its TGT lands in the source's cache.
    UnconstrainedDelegation,
    /// The source carries the target's SID in `sIDHistory` — it already *is* the target as
    /// far as access checks are concerned.
    SidHistory,
}

impl EdgeKind {
    /// Lower = cheaper for the attacker = more dangerous.
    pub fn weight(self) -> u32 {
        match self {
            EdgeKind::MemberOf | EdgeKind::SidHistory => 0,
            EdgeKind::Acl(p) => p.cost(),
            EdgeKind::AllowedToDelegate | EdgeKind::UnconstrainedDelegation => 2,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            EdgeKind::MemberOf => "MemberOf",
            EdgeKind::Acl(p) => p.name(),
            EdgeKind::AllowedToDelegate => "AllowedToDelegate",
            EdgeKind::UnconstrainedDelegation => "UnconstrainedDelegation",
            EdgeKind::SidHistory => "SidHistory",
        }
    }

    /// What traversing this edge gets the attacker.
    pub fn impact(self) -> &'static str {
        match self {
            EdgeKind::MemberOf => "inherits every privilege of the group",
            EdgeKind::Acl(p) => p.impact(),
            EdgeKind::AllowedToDelegate => {
                "S4U2Self+S4U2Proxy impersonates any user to the allowed service"
            }
            EdgeKind::UnconstrainedDelegation => {
                "coerce the target to authenticate here and its TGT is captured, then replayed"
            }
            EdgeKind::SidHistory => "access checks already grant the target's rights",
        }
    }

    /// How a defender removes this edge.
    pub fn mitigation(self) -> &'static str {
        match self {
            EdgeKind::MemberOf => "remove the principal from the group",
            EdgeKind::Acl(p) => p.mitigation(),
            EdgeKind::AllowedToDelegate => {
                "clear msDS-AllowedToDelegateTo; mark Tier-0 accounts sensitive and non-delegatable"
            }
            EdgeKind::UnconstrainedDelegation => {
                "clear TRUSTED_FOR_DELEGATION, put Tier-0 in Protected Users, block the coercion RPCs"
            }
            EdgeKind::SidHistory => "clean sIDHistory after the migration and enable SID filtering",
        }
    }

    /// The `adhammer` command that walks this edge, as a template over `{from}` and `{to}`.
    ///
    /// `None` means the tool can *find* this edge but cannot yet *walk* it — which is exactly
    /// the roadmap: an edge without an executor is an attack still owed.
    pub fn executor(self) -> Option<&'static str> {
        use ControlPrimitive as P;
        Some(match self {
            EdgeKind::MemberOf | EdgeKind::SidHistory => return None,
            EdgeKind::AllowedToDelegate => "attack constrained --target {to}",
            EdgeKind::UnconstrainedDelegation => return None, // planned: attack unconstrained
            EdgeKind::Acl(p) => match p {
                P::DcsyncGetChangesAll | P::AllExtendedRights => "attack dcsync --user krbtgt",
                P::AddMember | P::AddSelfToGroup => {
                    "attack abuse --add-member --group {to} --member {from}"
                }
                P::ForceChangePassword => "attack abuse --set-password --target {to}",
                P::WriteRbcd | P::GenericAll | P::GenericWrite | P::WriteDacl | P::Owns => {
                    "attack abuse --write-rbcd --target {to} && attack rbcd --target {to}"
                }
                P::WriteSpn => "attack abuse --add-spn --target {to} && attack roast",
                P::ReadGmsaPassword => "attack gmsa --account {to}",
                P::ReadLapsPassword => "attack laps --computer {to}",
                P::Enroll => "attack esc1 --template {to}",
                // Found by `enum`, not yet executable: shadow credentials outside the relay
                // path, BadSuccessor, template rewrite, the rest.
                _ => return None,
            },
        })
    }

    /// [`EdgeKind::executor`] with the endpoints filled in.
    pub fn command(self, from: &str, to: &str) -> Option<String> {
        self.executor()
            .map(|t| format!("adhammer {}", t.replace("{from}", from).replace("{to}", to)))
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
            cg.add_delegation_edges(snap, o, &dst);
            cg.add_sid_history_edges(snap, o, &dst);
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

        // Primary group membership is *not* in memberOf — it is a bare RID on the account.
        // Hiding privilege there is a known trick, so the edge has to be drawn from it too.
        if let Some(rid) = o.one("primaryGroupID").and_then(|s| s.parse::<u32>().ok()) {
            if let Some(dsid) = &snap.domain.domain_sid {
                let mut group = dsid.clone();
                group.sub_authorities.push(rid);
                if group != *self_sid {
                    let gx = self.node_for(group);
                    self.g.add_edge(me, gx, EdgeKind::MemberOf);
                }
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

    /// Delegation, both flavours. Neither lives in a security descriptor, so neither shows up
    /// in the ACL pass — which is why an ACL-only graph misses the shortest routes to a DC.
    fn add_delegation_edges(&mut self, snap: &Snapshot, o: &AdObject, self_sid: &Sid) {
        use adhammer_core::object::uac;

        // Constrained: this account may impersonate anyone to the named services.
        let me = self.node_for(self_sid.clone());
        for spn in o.all("msDS-AllowedToDelegateTo") {
            if let Some(target) = spn_host_sid(snap, spn) {
                let tx = self.node_for(target);
                self.g.add_edge(me, tx, EdgeKind::AllowedToDelegate);
            }
        }

        // Unconstrained: anything coerced into authenticating here leaves its TGT behind.
        // The DCs are the payoff, so that is the edge worth drawing.
        if o.uac() & uac::TRUSTED_FOR_DELEGATION != 0 {
            let dcs: Vec<Sid> = snap
                .objects
                .iter()
                .filter(|c| is_domain_controller(c))
                .filter_map(|c| c.bin1("objectSid").and_then(Sid::from_bytes))
                .filter(|s| s != self_sid)
                .collect();
            for dc in dcs {
                let dx = self.node_for(dc);
                self.g.add_edge(me, dx, EdgeKind::UnconstrainedDelegation);
            }
        }
    }

    /// `sIDHistory` — the holder already carries the other principal's access.
    fn add_sid_history_edges(&mut self, snap: &Snapshot, o: &AdObject, self_sid: &Sid) {
        let raws: Vec<Sid> = o
            .all("sIDHistory")
            .iter()
            .filter_map(|s| Sid::parse(s))
            .filter(|s| snap.by_sid(s).is_some())
            .collect();
        if raws.is_empty() {
            return;
        }
        let me = self.node_for(self_sid.clone());
        for sid in raws {
            let tx = self.node_for(sid);
            self.g.add_edge(me, tx, EdgeKind::SidHistory);
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

    /// Every principal that can reach any Tier-0 node, with the cheapest route and the exact
    /// steps it walks.
    ///
    /// Dijkstra runs *backwards* from each Tier-0 node over incoming edges, so the recorded
    /// predecessor is the next hop forwards — reversing it yields the attacker's route.
    pub fn paths_to_tier0(&self) -> Vec<AttackPath> {
        use petgraph::Direction::Incoming;
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        let mut out = Vec::new();
        for tix in self.g.node_indices().filter(|&i| self.g[i].tier0) {
            // next[x] = (node after x on the way to tix, edge x -> that node)
            let mut next: HashMap<NodeIndex, (NodeIndex, EdgeKind)> = HashMap::new();
            let mut dist: HashMap<NodeIndex, u32> = HashMap::new();
            let mut heap = BinaryHeap::new();

            dist.insert(tix, 0);
            heap.push(Reverse((0u32, tix.index())));

            while let Some(Reverse((cost, raw))) = heap.pop() {
                let node = NodeIndex::new(raw);
                if cost > *dist.get(&node).unwrap_or(&u32::MAX) {
                    continue;
                }
                for e in self.g.edges_directed(node, Incoming) {
                    let src = e.source();
                    let kind = *e.weight();
                    let nc = cost.saturating_add(kind.weight());
                    if nc < *dist.get(&src).unwrap_or(&u32::MAX) {
                        dist.insert(src, nc);
                        next.insert(src, (node, kind));
                        heap.push(Reverse((nc, src.index())));
                    }
                }
            }

            for (src, cost) in dist {
                if src == tix || self.g[src].tier0 {
                    continue;
                }
                out.push(AttackPath {
                    principal: self.g[src].label.clone(),
                    principal_sid: self.g[src].sid.to_string(),
                    target: self.g[tix].label.clone(),
                    cost,
                    steps: self.walk(src, tix, &next),
                });
            }
        }
        out.sort_by(|a, b| a.cost.cmp(&b.cost).then(a.principal.cmp(&b.principal)));
        out
    }

    /// Follow the `next` map from `src` to `dst`, turning each hop into a [`Step`].
    fn walk(
        &self,
        src: NodeIndex,
        dst: NodeIndex,
        next: &HashMap<NodeIndex, (NodeIndex, EdgeKind)>,
    ) -> Vec<Step> {
        let mut steps = Vec::new();
        let mut cur = src;
        // The map is acyclic by construction; the node bound is a belt-and-braces stop.
        while cur != dst && steps.len() < self.g.node_count() {
            let Some(&(to, edge)) = next.get(&cur) else {
                break;
            };
            let from_label = self.g[cur].label.clone();
            let to_label = self.g[to].label.clone();
            steps.push(Step {
                command: edge.command(&from_label, &to_label),
                from: from_label,
                from_sid: self.g[cur].sid.to_string(),
                edge: edge.name(),
                to: to_label,
                to_sid: self.g[to].sid.to_string(),
                impact: edge.impact(),
                mitigation: edge.mitigation(),
            });
            cur = to;
        }
        steps
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

/// One hop of an attack path, with everything a report needs about it: what it is, what it
/// buys the attacker, the command that walks it, and how a defender removes it.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Step {
    pub from: String,
    pub from_sid: String,
    /// Edge label, e.g. `AddKeyCredential`.
    pub edge: &'static str,
    pub to: String,
    pub to_sid: String,
    pub impact: &'static str,
    pub mitigation: &'static str,
    /// The `adhammer` invocation for this hop, or `None` when the tool can find the edge but
    /// cannot yet walk it.
    pub command: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AttackPath {
    pub principal: String,
    pub principal_sid: String,
    pub target: String,
    pub cost: u32,
    /// The route from `principal` to `target`, hop by hop.
    pub steps: Vec<Step>,
}

impl AttackPath {
    /// `user → [AddKeyCredential] → svc → [MemberOf] → Domain Admins`
    pub fn render(&self) -> String {
        if self.steps.is_empty() {
            return format!("{} → {}", self.principal, self.target);
        }
        let mut s = self.principal.clone();
        for st in &self.steps {
            s.push_str(&format!(" → [{}] → {}", st.edge, st.to));
        }
        s
    }

    /// `true` if every hop has an executor — the whole route can be walked by the tool.
    pub fn fully_executable(&self) -> bool {
        !self.steps.is_empty() && self.steps.iter().all(|s| s.command.is_some())
    }
}

/// `HOST/dc01.testlab.local:1234/whatever` → the SID of the account that owns that SPN.
fn spn_host_sid(snap: &Snapshot, spn: &str) -> Option<Sid> {
    // The host part is the second field, minus any port or instance suffix.
    let host = spn
        .split('/')
        .nth(1)?
        .split(':')
        .next()?
        .to_ascii_lowercase();
    let short = host.split('.').next().unwrap_or(&host);

    snap.objects
        .iter()
        .find(|o| {
            o.all("servicePrincipalName")
                .iter()
                .any(|s| s.eq_ignore_ascii_case(spn))
        })
        .or_else(|| snap.by_sam(&format!("{short}$")))
        .and_then(|o| o.bin1("objectSid"))
        .and_then(Sid::from_bytes)
}

/// A domain controller: a computer whose `userAccountControl` carries the SERVER_TRUST_ACCOUNT
/// bit, which is what makes it a DC rather than a member server.
fn is_domain_controller(o: &AdObject) -> bool {
    const SERVER_TRUST_ACCOUNT: u32 = 0x0000_2000;
    o.uac() & SERVER_TRUST_ACCOUNT != 0
}

fn is_tier0(snap: &Snapshot, sid: &Sid) -> bool {
    use adhammer_core::sid::rid;

    // A domain controller's *computer account* is Tier-0 by definition — it holds the
    // replication rights. Its RID is an ordinary one, so the RID table below never catches it.
    if snap.by_sid(sid).is_some_and(is_domain_controller) {
        return true;
    }

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
