//! WS-R1 — deterministic, self-contained SVG of the control-path subgraph.
//!
//! Renders the attacker's cheapest routes to Tier-0 (`Report::top_paths`) as a layered
//! node-link diagram: principals are boxes, control primitives are labeled edges, Tier-0
//! sinks are ringed red, and hops adhammer can execute are drawn in green. The layout is
//! computed here (longest-path layering) with **no RNG and no clock**, so the same snapshot
//! always yields byte-identical SVG. It inlines into the HTML report with **zero external
//! requests** — no `d3`, no CDN — keeping the report one portable, offline file.

use crate::html_escape;
use adhammer_graph::AttackPath;
use std::collections::{BTreeMap, BTreeSet};

const COL_W: i64 = 224;
const ROW_H: i64 = 66;
const NODE_W: i64 = 172;
const NODE_H: i64 = 34;
const MARGIN: i64 = 30;
/// Cap the drawn subgraph so the SVG stays legible; excess (cheapest-last) paths are noted.
const MAX_NODES: usize = 50;

struct Pos {
    x: i64,
    y: i64,
}

/// Render `paths` (already the top-N attack routes) as an inline `<svg>`. Empty input →
/// empty string (caller omits the panel).
pub fn attack_graph_svg(paths: &[AttackPath]) -> String {
    if paths.is_empty() {
        return String::new();
    }

    // Cheapest first — the routes an operator cares about, and the ones we keep if the node
    // budget forces truncation.
    let mut ordered: Vec<&AttackPath> = paths.iter().collect();
    ordered.sort_by(|a, b| {
        a.cost
            .cmp(&b.cost)
            .then_with(|| a.principal.cmp(&b.principal))
    });

    let mut label: BTreeMap<String, String> = BTreeMap::new();
    let mut depth: BTreeMap<String, usize> = BTreeMap::new();
    let mut sinks: BTreeSet<String> = BTreeSet::new();
    // (from_sid, to_sid, edge) -> executable (adhammer can walk this hop)
    let mut edges: BTreeMap<(String, String, String), bool> = BTreeMap::new();
    let mut truncated = 0usize;

    for (idx, p) in ordered.iter().enumerate() {
        // Node budget: stop before a path would blow the legibility cap (always keep ≥1).
        if !label.is_empty() && label.len() + path_new_sid_count(p, &label) > MAX_NODES {
            truncated = ordered.len() - idx;
            break;
        }

        label
            .entry(p.principal_sid.clone())
            .or_insert_with(|| p.principal.clone());
        depth.entry(p.principal_sid.clone()).or_insert(0);

        for (i, s) in p.steps.iter().enumerate() {
            label
                .entry(s.from_sid.clone())
                .or_insert_with(|| s.from.clone());
            label
                .entry(s.to_sid.clone())
                .or_insert_with(|| s.to.clone());
            // Longest-path layering: a node sits at the deepest hop index it is seen at, so
            // Tier-0 sinks land rightmost and edges read left-to-right.
            let d_from = depth.entry(s.from_sid.clone()).or_insert(0);
            *d_from = (*d_from).max(i);
            let d_to = depth.entry(s.to_sid.clone()).or_insert(0);
            *d_to = (*d_to).max(i + 1);
            edges.insert(
                (s.from_sid.clone(), s.to_sid.clone(), s.edge.to_string()),
                s.command.is_some(),
            );
            if i + 1 == p.steps.len() {
                sinks.insert(s.to_sid.clone());
            }
        }
    }

    // A node with no incoming edge is an entry principal (source).
    let to_sids: BTreeSet<String> = edges.keys().map(|(_, t, _)| t.clone()).collect();

    // Group by layer, sort within a layer by SID (deterministic row order).
    let mut layers: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for (sid, d) in &depth {
        layers.entry(*d).or_default().push(sid.clone());
    }
    let mut pos: BTreeMap<String, Pos> = BTreeMap::new();
    let mut max_rows = 1usize;
    for (d, sids) in &mut layers {
        sids.sort();
        max_rows = max_rows.max(sids.len());
        for (row, sid) in sids.iter().enumerate() {
            pos.insert(
                sid.clone(),
                Pos {
                    x: MARGIN + (*d as i64) * COL_W,
                    y: MARGIN + (row as i64) * ROW_H,
                },
            );
        }
    }
    let max_layer = layers.keys().copied().max().unwrap_or(0) as i64;
    let width = MARGIN + max_layer * COL_W + NODE_W + MARGIN;
    let note_room = if truncated > 0 { ROW_H } else { 0 };
    let height = MARGIN + (max_rows as i64) * ROW_H + note_room;

    let mut svg = format!(
        "<svg class=graph viewBox=\"0 0 {width} {height}\" xmlns=\"http://www.w3.org/2000/svg\" \
         role=img aria-label=\"control-path graph\">\
         <defs><marker id=ah viewBox=\"0 0 10 10\" refX=9 refY=5 markerWidth=7 markerHeight=7 \
         orient=auto-start-reverse><path d=\"M0,0 L10,5 L0,10 z\" class=arrow/></marker></defs>"
    );

    // Edges first, so opaque node boxes draw on top of the line ends.
    for ((from, to, elabel), exec) in &edges {
        let (Some(pf), Some(pt)) = (pos.get(from), pos.get(to)) else {
            continue;
        };
        let x1 = pf.x + NODE_W;
        let y1 = pf.y + NODE_H / 2;
        let x2 = pt.x;
        let y2 = pt.y + NODE_H / 2;
        let mx = (x1 + x2) / 2;
        let my = (y1 + y2) / 2 - 4;
        let cls = if *exec { "edge edge-exec" } else { "edge" };
        let ftxt = label.get(from).map(String::as_str).unwrap_or(from);
        let ttxt = label.get(to).map(String::as_str).unwrap_or(to);
        svg.push_str(&format!(
            "<line x1={x1} y1={y1} x2={x2} y2={y2} class=\"{cls}\" marker-end=\"url(#ah)\">\
             <title>{ft} \u{2192} [{el}] \u{2192} {tt}</title></line>\
             <text x={mx} y={my} class=edge-label>{el}</text>",
            el = html_escape(elabel),
            ft = html_escape(ftxt),
            tt = html_escape(ttxt),
        ));
    }

    // Nodes on top.
    for (sid, p) in &pos {
        let cls = if sinks.contains(sid) {
            "node-sink"
        } else if !to_sids.contains(sid) {
            "node-source"
        } else {
            "node-inter"
        };
        let full = label.get(sid).map(String::as_str).unwrap_or(sid);
        svg.push_str(&format!(
            "<g class=\"node {cls}\"><rect x={x} y={y} width={w} height={h} rx=8/>\
             <text x={tx} y={ty}>{lbl}</text><title>{full}</title></g>",
            x = p.x,
            y = p.y,
            w = NODE_W,
            h = NODE_H,
            tx = p.x + NODE_W / 2,
            ty = p.y + NODE_H / 2 + 4,
            lbl = html_escape(&trunc(full, 20)),
            full = html_escape(full),
        ));
    }

    if truncated > 0 {
        svg.push_str(&format!(
            "<text x={x} y={y} class=graph-note>+{truncated} lower-priority path(s) not drawn</text>",
            x = MARGIN,
            y = height - 10,
        ));
    }
    svg.push_str("</svg>");
    svg
}

/// How many SIDs this path would add that `seen` does not already have — the budget check.
fn path_new_sid_count(p: &AttackPath, seen: &BTreeMap<String, String>) -> usize {
    let mut fresh: BTreeSet<&str> = BTreeSet::new();
    if !seen.contains_key(&p.principal_sid) {
        fresh.insert(p.principal_sid.as_str());
    }
    for s in &p.steps {
        if !seen.contains_key(&s.from_sid) {
            fresh.insert(s.from_sid.as_str());
        }
        if !seen.contains_key(&s.to_sid) {
            fresh.insert(s.to_sid.as_str());
        }
    }
    fresh.len()
}

/// Truncate a label to `n` chars with an ellipsis (node boxes are fixed width).
fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_graph::{AttackPath, Step};

    fn step(from: &str, fsid: &str, edge: &'static str, to: &str, tsid: &str, exec: bool) -> Step {
        Step {
            from: from.into(),
            from_sid: fsid.into(),
            edge,
            to: to.into(),
            to_sid: tsid.into(),
            impact: "",
            mitigation: "",
            command: exec.then(|| "adhammer attack dcsync --user krbtgt".to_string()),
        }
    }

    fn fixture() -> Vec<AttackPath> {
        vec![
            AttackPath {
                principal: "bob".into(),
                principal_sid: "S-1-5-21-1-1-1101".into(),
                target: "Domain Admins".into(),
                cost: 1,
                steps: vec![
                    step(
                        "bob",
                        "S-1-5-21-1-1-1101",
                        "GenericAll",
                        "svc",
                        "S-1-5-21-1-1-1102",
                        false,
                    ),
                    step(
                        "svc",
                        "S-1-5-21-1-1-1102",
                        "MemberOf",
                        "Domain Admins",
                        "S-1-5-21-1-1-512",
                        true,
                    ),
                ],
            },
            AttackPath {
                principal: "alice".into(),
                principal_sid: "S-1-5-21-1-1-1103".into(),
                target: "Domain Admins".into(),
                cost: 0,
                steps: vec![step(
                    "alice",
                    "S-1-5-21-1-1-1103",
                    "AddKeyCredential",
                    "Domain Admins",
                    "S-1-5-21-1-1-512",
                    true,
                )],
            },
        ]
    }

    #[test]
    fn renders_nodes_edges_and_tier0_ring() {
        let svg = attack_graph_svg(&fixture());
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        // node labels present
        for lbl in ["bob", "alice", "svc", "Domain Admins"] {
            assert!(svg.contains(lbl), "missing node label {lbl}");
        }
        // edge labels present
        for e in ["GenericAll", "MemberOf", "AddKeyCredential"] {
            assert!(svg.contains(e), "missing edge label {e}");
        }
        // Tier-0 sink gets the ring class; executable hops get the exec class.
        assert!(svg.contains("node-sink"));
        assert!(svg.contains("node-source"));
        assert!(svg.contains("edge-exec"));
        // self-contained: no external references
        assert!(!svg.contains("http://") || svg.contains("www.w3.org/2000/svg"));
        assert!(!svg.contains("<script"));
    }

    #[test]
    fn deterministic_byte_stable() {
        let a = attack_graph_svg(&fixture());
        let b = attack_graph_svg(&fixture());
        assert_eq!(a, b, "same input must produce byte-identical SVG");
    }

    #[test]
    fn empty_paths_empty_svg() {
        assert_eq!(attack_graph_svg(&[]), "");
    }
}
