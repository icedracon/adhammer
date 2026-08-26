//! WS-BHG — BloodHound-style principal graph, inline in the HTML report.
//!
//! Extends WS-R1 (`graph_svg.rs`, attack-paths only) with the *full* principal graph — every user,
//! group, computer that has an edge into or out of a Tier-0 node, plus the edges themselves labeled
//! with their control primitive (`memberOf`, `WriteDacl`, `GenericAll`, `AddKeyCredential`, `DCSync`,
//! …). The operator sees the same shape a BloodHound analyst would open BH-CE for, without leaving
//! the ADhammer report.
//!
//! **Determinism (byte-stable diffs)**: no RNG, no clock. Nodes are sorted by SID; layout is a
//! concentric radial around a horizontal row of Tier-0 nodes. Same snapshot ⇒ same SVG bytes ⇒
//! two scans diff cleanly.
//!
//! **Self-contained**: no `d3`, no CDN, no external asset. The report stays one portable file.
//! Node metadata (SID, tier, direct-neighbor count) is exposed via SVG `<title>` tooltips so a
//! reader hovers a node to see its identity without JS interaction.
//!
//! **Scope guardrail**: pruned to Tier-0 nodes + their direct neighbors, capped at
//! `MAX_NODES = 250`. A 50k-user directory rendered fully would produce a report no one opens.

use crate::html_escape;
use adhammer_graph::ControlGraph;
use std::collections::{BTreeMap, BTreeSet};

/// Hard cap on rendered principals. Rest of the directory is not drawn but still counted below.
const MAX_NODES: usize = 250;
/// Public doc-string of the node cap so the report panel copy stays in sync with the code.
pub const MAX_NODES_DOCS: usize = MAX_NODES;

/// Layout constants — all deterministic pixel math, no floats where an integer suffices.
const CANVAS_W: i64 = 960;
const CANVAS_H: i64 = 540;
const CENTER_Y: i64 = CANVAS_H / 2;
const T0_RADIUS_SPACING: i64 = 260;
const NEIGHBOR_RADIUS: i64 = 130;
const NODE_R: i64 = 14;

struct BhNode {
    sid: String,
    label: String,
    tier0: bool,
    /// (x, y) after layout.
    x: i64,
    y: i64,
}

struct BhEdge {
    from_sid: String,
    to_sid: String,
    kind: &'static str,
}

/// Render a full principal graph for the HTML report. Empty string when the graph has ≤1 node
/// (nothing to show).
pub fn to_svg(g: &ControlGraph) -> String {
    // 1. Collect Tier-0 nodes (sorted by SID for determinism).
    let mut tier0_sids: BTreeSet<String> = BTreeSet::new();
    for (sid, _label, tier0) in g.nodes_view() {
        if tier0 {
            tier0_sids.insert(sid.to_string());
        }
    }
    if tier0_sids.is_empty() {
        return String::new();
    }

    // 2. Collect direct neighbors of any Tier-0 node — the "who-holds-control-over-Tier-0" view.
    let mut keep: BTreeSet<String> = tier0_sids.clone();
    for (from, to, _kind) in g.edges_view() {
        let (fs, ts) = (from.to_string(), to.to_string());
        if tier0_sids.contains(&fs) {
            keep.insert(ts.clone());
        }
        if tier0_sids.contains(&ts) {
            keep.insert(fs);
        }
        if keep.len() >= MAX_NODES {
            break;
        }
    }

    // 3. Materialize kept nodes + label lookup (all sorted by SID).
    let mut label_by_sid: BTreeMap<String, (String, bool)> = BTreeMap::new();
    for (sid, label, tier0) in g.nodes_view() {
        let s = sid.to_string();
        if keep.contains(&s) {
            label_by_sid.insert(s, (label.to_string(), tier0));
        }
    }

    // 4. Deterministic layout: Tier-0 nodes across a horizontal middle row; each neighbor placed
    //    on a fixed-radius circle around its first Tier-0 anchor. Neighbors shared across Tier-0
    //    nodes anchor to the one with the smallest SID (stable ordering).
    let tier0_ordered: Vec<String> = tier0_sids.into_iter().collect();
    let n_t0 = tier0_ordered.len();
    let step = if n_t0 > 1 {
        T0_RADIUS_SPACING.min((CANVAS_W - 200) / (n_t0 as i64 - 1).max(1))
    } else {
        0
    };
    let start_x = (CANVAS_W - step * (n_t0 as i64 - 1).max(0)) / 2;

    // Assign each kept non-Tier-0 node to a Tier-0 anchor (its lowest-SID Tier-0 neighbor).
    let mut anchor_of: BTreeMap<String, String> = BTreeMap::new();
    for (from, to, _kind) in g.edges_view() {
        let (fs, ts) = (from.to_string(), to.to_string());
        // If `to` is Tier-0 and `from` is a kept non-Tier-0, from anchors on to.
        if label_by_sid.get(&ts).is_some_and(|(_, t0)| *t0)
            && label_by_sid.get(&fs).is_some_and(|(_, t0)| !*t0)
        {
            let ts_c = ts.clone();
            anchor_of
                .entry(fs.clone())
                .and_modify(|prev| {
                    if ts_c < *prev {
                        prev.clone_from(&ts_c);
                    }
                })
                .or_insert(ts_c);
        }
        // Symmetric: from Tier-0 to non-Tier-0 (rare but possible for OwnedBy/RBCD directions).
        let (fs, ts) = (from.to_string(), to.to_string());
        if label_by_sid.get(&fs).is_some_and(|(_, t0)| *t0)
            && label_by_sid.get(&ts).is_some_and(|(_, t0)| !*t0)
        {
            let fs_c = fs.clone();
            anchor_of
                .entry(ts.clone())
                .and_modify(|prev| {
                    if fs_c < *prev {
                        prev.clone_from(&fs_c);
                    }
                })
                .or_insert(fs_c);
        }
    }

    let t0_pos: BTreeMap<String, (i64, i64)> = tier0_ordered
        .iter()
        .enumerate()
        .map(|(i, s)| (s.clone(), (start_x + step * i as i64, CENTER_Y)))
        .collect();

    // Count neighbors per Tier-0 for angular spacing.
    let mut neighbors_by_anchor: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (sid, anchor) in &anchor_of {
        neighbors_by_anchor
            .entry(anchor.clone())
            .or_default()
            .push(sid.clone());
    }
    for v in neighbors_by_anchor.values_mut() {
        v.sort();
    }

    // Build the drawn nodes with positions.
    let mut nodes: Vec<BhNode> = Vec::new();
    for (sid, (x, y)) in &t0_pos {
        if let Some((label, tier0)) = label_by_sid.get(sid) {
            nodes.push(BhNode {
                sid: sid.clone(),
                label: label.clone(),
                tier0: *tier0,
                x: *x,
                y: *y,
            });
        }
    }
    for (anchor, ns) in &neighbors_by_anchor {
        let Some(&(ax, ay)) = t0_pos.get(anchor) else {
            continue;
        };
        let count = ns.len() as i64;
        for (i, sid) in ns.iter().enumerate() {
            // Deterministic angle: full circle around anchor, index-based.
            let angle_ppm = ((i as i64).saturating_mul(1_000_000)).saturating_div(count.max(1));
            let (dx, dy) = polar_int(NEIGHBOR_RADIUS, angle_ppm);
            let label = label_by_sid
                .get(sid)
                .map(|(l, _)| l.clone())
                .unwrap_or_else(|| sid.clone());
            let tier0 = label_by_sid.get(sid).is_some_and(|(_, t0)| *t0);
            nodes.push(BhNode {
                sid: sid.clone(),
                label,
                tier0,
                x: ax + dx,
                y: ay + dy,
            });
        }
    }

    // 5. Kept edges — sorted for determinism, only where both endpoints are drawn.
    let mut edges: Vec<BhEdge> = Vec::new();
    let drawn_sids: BTreeSet<String> = nodes.iter().map(|n| n.sid.clone()).collect();
    for (from, to, kind) in g.edges_view() {
        let (fs, ts) = (from.to_string(), to.to_string());
        if drawn_sids.contains(&fs) && drawn_sids.contains(&ts) {
            edges.push(BhEdge {
                from_sid: fs,
                to_sid: ts,
                kind,
            });
        }
    }
    edges.sort_by(|a, b| (&a.from_sid, &a.to_sid, a.kind).cmp(&(&b.from_sid, &b.to_sid, b.kind)));

    render_svg(&nodes, &edges, g)
}

/// Deterministic (int-only) polar → cartesian for `angle_ppm` in millionths of a full turn.
/// Uses a 32-point cosine LUT so no `f64` sneaks into the SVG bytes.
fn polar_int(radius: i64, angle_ppm: i64) -> (i64, i64) {
    // 32-slice LUT — cos/sin values × 1000 for degree 0..360 stepped by 11.25°.
    const COS: [i64; 33] = [
        1000, 981, 924, 831, 707, 556, 383, 195, 0, -195, -383, -556, -707, -831, -924, -981,
        -1000, -981, -924, -831, -707, -556, -383, -195, 0, 195, 383, 556, 707, 831, 924, 981,
        1000,
    ];
    let idx = ((angle_ppm.rem_euclid(1_000_000) as i128) * 32 / 1_000_000) as usize;
    let cos = COS[idx];
    let sin = COS[(idx + 24) % 32]; // sin(θ) = cos(θ - 90°); shift 24/32 slices back = -90°
    (radius * cos / 1000, radius * sin / 1000)
}

fn render_svg(nodes: &[BhNode], edges: &[BhEdge], g: &ControlGraph) -> String {
    let (total_n, total_e) = g.stats();
    let drawn_n = nodes.len();
    let drawn_e = edges.len();
    let mut svg = String::with_capacity(4096 + nodes.len() * 200 + edges.len() * 120);
    svg.push_str(&format!(
        "<svg class=\"bh-graph\" role=\"img\" aria-label=\"Principal graph\" \
         viewBox=\"0 0 {CANVAS_W} {CANVAS_H}\" xmlns=\"http://www.w3.org/2000/svg\">"
    ));
    // Arrowhead marker — one, reused.
    svg.push_str(
        "<defs><marker id=\"bh-arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" \
         markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\">\
         <path d=\"M0,0 L10,5 L0,10 z\" fill=\"currentColor\"/></marker></defs>",
    );

    // WS-BHG-INTERACT (1.4.6): wrap the drawn scene in a translatable/scalable group so the
    // interaction JS can pan (mouse drag) and zoom (wheel) without touching individual nodes.
    // The <g id="bh-scene"> transform is set by JS on load; static SVG (no JS) renders identity.
    svg.push_str("<g id=\"bh-scene\">");

    // Edges first (drawn under nodes). Deterministic ordering ensures byte-stable output.
    // Each edge carries data-from / data-to so the click-highlight code can find its endpoints.
    for e in edges {
        let (Some(a), Some(b)) = (
            nodes.iter().find(|n| n.sid == e.from_sid),
            nodes.iter().find(|n| n.sid == e.to_sid),
        ) else {
            continue;
        };
        svg.push_str(&format!(
            "<line class=\"bh-edge\" data-from=\"{fs}\" data-to=\"{ts}\" \
             x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" \
             marker-end=\"url(#bh-arrow)\"><title>{}</title></line>",
            a.x,
            a.y,
            b.x,
            b.y,
            html_escape(&format!("{} → {} : {}", a.label, b.label, e.kind)),
            fs = html_escape(&e.from_sid),
            ts = html_escape(&e.to_sid),
        ));
    }
    // Nodes on top. data-sid drives the click-highlight code below.
    for n in nodes {
        let cls = if n.tier0 { "bh-node bh-t0" } else { "bh-node" };
        let short = n.label.chars().take(14).collect::<String>()
            + if n.label.chars().count() > 14 {
                "…"
            } else {
                ""
            };
        svg.push_str(&format!(
            "<g class=\"{cls}\" data-sid=\"{sid}\" transform=\"translate({},{})\" tabindex=\"0\"><title>{}</title>\
             <circle r=\"{NODE_R}\"></circle>\
             <text text-anchor=\"middle\" y=\"{}\">{}</text></g>",
            n.x,
            n.y,
            html_escape(&format!("{} · {} · tier0={}", n.label, n.sid, n.tier0)),
            NODE_R + 14,
            html_escape(&short),
            sid = html_escape(&n.sid),
        ));
    }

    // Close the pan/zoom-able scene wrapper.
    svg.push_str("</g>");

    // Footer text sits OUTSIDE #bh-scene so it doesn't zoom/pan with the graph.
    let pruned = total_n.saturating_sub(drawn_n);
    let footer = if pruned == 0 {
        format!("full principal graph — {drawn_n} nodes, {drawn_e} edges")
    } else {
        format!(
            "showing {drawn_n}/{total_n} nodes (Tier-0 + direct neighbors) · {drawn_e}/{total_e} edges — pruned {pruned} for legibility"
        )
    };
    svg.push_str(&format!(
        "<text class=\"bh-footer\" x=\"{}\" y=\"{}\" text-anchor=\"middle\">{}</text>",
        CANVAS_W / 2,
        CANVAS_H - 8,
        html_escape(&footer)
    ));

    // WS-BHG-INTERACT: inline pan/zoom/click handler. Kept small (~1 KB minified-ish), no deps.
    // Static SVG (JS off) still renders + hovers work; interaction is progressive-enhancement.
    svg.push_str("<script><![CDATA[");
    svg.push_str(INTERACT_JS);
    svg.push_str("]]></script>");
    svg.push_str("</svg>");
    svg
}

/// WS-BHG-INTERACT (1.4.6 follow-up): the inline JS for pan (mouse drag), zoom (mouse wheel),
/// and click-to-highlight-neighbors on the principal graph. Self-contained, no deps, byte-stable
/// (no timestamp or randomness in the source). ~1 KB uncompressed.
///
/// Design:
/// - Pan: mousedown on the SVG background sets a drag origin; mousemove updates
///   `translate(tx,ty)` on `#bh-scene`.
/// - Zoom: wheel on the SVG multiplies a `scale` (clamped 0.4..4.0); origin at cursor for
///   natural focused zoom.
/// - Click node: dims every unrelated node + edge by adding a `bh-dim` class; clicking blank
///   background clears the selection. Neighbor lookup uses the `data-sid` on nodes and
///   `data-from` / `data-to` on edges (both emitted by the Rust renderer).
///
/// Keyboard: Escape clears the selection. Focus rings on nodes work because we emit
/// `tabindex="0"` on each node group.
const INTERACT_JS: &str = r#"
(function(){
  var svg = document.currentScript && document.currentScript.ownerSVGElement;
  if (!svg) return;
  var scene = svg.querySelector('#bh-scene');
  if (!scene) return;
  var tx = 0, ty = 0, s = 1;
  var drag = null;
  function apply(){ scene.setAttribute('transform', 'translate(' + tx + ',' + ty + ') scale(' + s + ')'); }
  svg.addEventListener('mousedown', function(e){
    if (e.button !== 0) return;
    if (e.target.closest('.bh-node')) return; // node click, not pan
    drag = { x: e.clientX, y: e.clientY, tx: tx, ty: ty };
    svg.style.cursor = 'grabbing';
  });
  window.addEventListener('mousemove', function(e){
    if (!drag) return;
    tx = drag.tx + (e.clientX - drag.x);
    ty = drag.ty + (e.clientY - drag.y);
    apply();
  });
  window.addEventListener('mouseup', function(){
    drag = null;
    svg.style.cursor = '';
  });
  svg.addEventListener('wheel', function(e){
    e.preventDefault();
    var factor = e.deltaY < 0 ? 1.15 : (1/1.15);
    var ns = Math.max(0.4, Math.min(4.0, s * factor));
    // Zoom about cursor: keep the point under the cursor stationary.
    var rect = svg.getBoundingClientRect();
    var vb = svg.viewBox.baseVal;
    var cx = (e.clientX - rect.left) / rect.width * vb.width;
    var cy = (e.clientY - rect.top) / rect.height * vb.height;
    tx = cx - (cx - tx) * (ns / s);
    ty = cy - (cy - ty) * (ns / s);
    s = ns;
    apply();
  }, { passive: false });
  function clearSel(){
    scene.querySelectorAll('.bh-dim').forEach(function(el){ el.classList.remove('bh-dim'); });
  }
  scene.addEventListener('click', function(e){
    var g = e.target.closest('.bh-node');
    if (!g) { clearSel(); return; }
    var sid = g.getAttribute('data-sid');
    var neighbors = new Set([sid]);
    scene.querySelectorAll('.bh-edge').forEach(function(edge){
      var f = edge.getAttribute('data-from'), t = edge.getAttribute('data-to');
      if (f === sid) neighbors.add(t);
      if (t === sid) neighbors.add(f);
    });
    scene.querySelectorAll('.bh-node').forEach(function(n){
      if (neighbors.has(n.getAttribute('data-sid'))) n.classList.remove('bh-dim');
      else n.classList.add('bh-dim');
    });
    scene.querySelectorAll('.bh-edge').forEach(function(edge){
      var f = edge.getAttribute('data-from'), t = edge.getAttribute('data-to');
      if (f === sid || t === sid) edge.classList.remove('bh-dim');
      else edge.classList.add('bh-dim');
    });
  });
  window.addEventListener('keydown', function(e){ if (e.key === 'Escape') clearSel(); });
})();
"#;

/// The CSS block that themes the graph SVG. Included once by `to_html()` next to the existing
/// `graph_svg` styles; reuses the report's design tokens (WS-THEME) so light/dark just work.
pub fn css() -> &'static str {
    ".bh-wrap{width:100%;max-width:100%;overflow-x:auto;margin-top:12px}\
     .bh-graph{width:100%;height:auto;background:var(--panel-2);border:1px solid var(--line);border-radius:8px;color:var(--muted)}\
     .bh-edge{stroke:var(--muted);stroke-width:1.4;opacity:0.6;color:var(--muted)}\
     .bh-node circle{fill:var(--blue);stroke:var(--line);stroke-width:1.5}\
     .bh-node.bh-t0 circle{fill:var(--red);stroke:var(--red);stroke-width:2}\
     .bh-node text{fill:var(--text);font:11px ui-monospace,SFMono-Regular,Consolas,monospace;pointer-events:none}\
     .bh-footer{fill:var(--muted);font:11px Inter,system-ui,sans-serif}"
}

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_core::snapshot::{DomainInfo, Snapshot};

    fn empty_snap() -> Snapshot {
        Snapshot::new(DomainInfo::default(), vec![])
    }

    #[test]
    fn empty_graph_renders_empty() {
        let g = ControlGraph::build(&empty_snap());
        assert!(to_svg(&g).is_empty(), "empty graph should render nothing");
    }

    #[test]
    fn polar_lut_is_deterministic_and_symmetric() {
        // 0° → +x radius, 0y.
        assert_eq!(polar_int(100, 0), (100, 0));
        // 250_000 ppm = quarter turn = +y (SVG y-down is fine; determinism is what matters).
        let (x, y) = polar_int(100, 250_000);
        assert!(x.abs() < 5, "x near 0 at quarter turn, got {x}");
        assert!((y - 100).abs() < 5, "y near +100 at quarter turn, got {y}");
    }

    #[test]
    fn css_uses_theme_tokens() {
        let css = css();
        assert!(css.contains("var(--panel-2)"));
        assert!(css.contains("var(--text)"));
        assert!(css.contains("var(--red)"), "Tier-0 nodes need red accent");
    }

    #[test]
    fn interact_js_is_self_contained_and_covers_pan_zoom_click() {
        // WS-BHG-INTERACT: the pan/zoom/click JS is inline in the SVG. Sanity that the code
        // was actually inlined and doesn't require any external dep or a CDN.
        let js = INTERACT_JS;
        // Pan handlers
        assert!(js.contains("mousedown"));
        assert!(js.contains("mousemove"));
        assert!(js.contains("mouseup"));
        // Zoom handler
        assert!(js.contains("wheel"));
        // Click-highlight: dims neighbors, keyboard Esc clears
        assert!(js.contains("bh-dim"));
        assert!(js.contains("Escape"));
        // Rule enforcement: no external references
        assert!(!js.contains("http://"), "no external URLs allowed");
        assert!(!js.contains("https://"), "no external URLs allowed");
        assert!(
            !js.to_ascii_lowercase().contains("cdn"),
            "no CDN references"
        );
    }
}
