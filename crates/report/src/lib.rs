//! Scoring + output. Aggregates findings into a per-category risk score (configurable
//! weights) and emits JSON / HTML / Markdown / plain-text reports. No external template
//! engine — keeps the dependency surface small.

use adhammer_core::finding::{Category, Severity};
use adhammer_core::Finding;
use adhammer_graph::AttackPath;
use serde::Serialize;
use std::collections::BTreeMap;

pub mod baseline;
pub mod composite;
pub mod graph_bh;
pub mod graph_svg;
pub use baseline::BaselineDiff;
pub use composite::CompositeChain;

/// Configurable multipliers per category (diploma "risk scoring engine").
#[derive(Clone, Debug)]
pub struct RiskConfig {
    pub category_weight: BTreeMap<&'static str, f64>,
}

impl Default for RiskConfig {
    fn default() -> Self {
        let mut m = BTreeMap::new();
        m.insert("PrivilegedAccounts", 1.5);
        m.insert("Trusts", 1.2);
        m.insert("Anomalies", 1.0);
        m.insert("StaleObjects", 0.5);
        RiskConfig { category_weight: m }
    }
}

fn cat_key(c: Category) -> &'static str {
    match c {
        Category::PrivilegedAccounts => "PrivilegedAccounts",
        Category::Trusts => "Trusts",
        Category::StaleObjects => "StaleObjects",
        Category::Anomalies => "Anomalies",
    }
}

mod check_meta;
pub use check_meta::describe as describe_check;
// 1.4.7 WS-CTRLMAP: re-export the taxonomy declarations so downstream tooling (CLI
// `coverage --standard areas|kill-chain` subcommand, WS-CLEAN-REPORT methodology
// assertion, third-party consumers) can enumerate the valid tag universe.
pub use check_meta::{CONTROL_AREAS, KILL_CHAIN_PHASES};

/// WS-R2: one row of the coverage matrix — a registry check id and how many findings it
/// produced this run (0 = the check ran and the directory is **clean** for that vector).
/// Turns "here are the hits" into "here is everything we checked, and the result of each."
///
/// **1.4.6 addition** (`title`/`hypothetical_impact`/`remediation`/`mitre`): every row (tripped
/// AND clean) carries the check's description so an operator can verify "this check DID look
/// for X, saw nothing, so nothing is really there" — rather than wondering whether the check
/// is buggy. When tripped, the fields mirror the first emitted Finding. When clean, they come
/// from `crate::check_meta::describe(id)` static fallback.
#[derive(Serialize, Clone, Debug)]
pub struct CheckCoverage {
    pub id: String,
    pub findings: usize,
    /// Short human-readable title. Empty string if unknown.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// If this check *were* to trip on this directory, what would the impact be?
    /// Empty string if unknown.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hypothetical_impact: String,
    /// Remediation guidance. Empty string if unknown.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remediation: String,
    /// MITRE ATT&CK technique IDs this check maps to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre: Vec<String>,
    /// **1.4.7 WS-CTRLMAP** — in-house AD-pentest control-area codes (`ADP-NN`; see
    /// `docs/CONTROL_AREAS.md`). Sourced from the static taxonomy table, not the
    /// individual finding — a check belongs to the same control areas whether it
    /// tripped or not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub control_areas: Vec<String>,
    /// **1.4.7 WS-CTRLMAP** — generic offensive kill-chain phase (`enumeration |
    /// initial-access | privilege-escalation | lateral-movement | persistence |
    /// domain-dominance`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kill_chain_phase: String,
}

#[derive(Serialize)]
pub struct Report {
    pub domain: String,
    pub total_score: u64,
    pub category_scores: BTreeMap<&'static str, u64>,
    pub findings: Vec<Finding>,
    pub top_paths: Vec<AttackPath>,
    pub graph_nodes: usize,
    pub graph_edges: usize,
    /// English cross-references between findings — "Coercion + ESC8 → DA cert".
    /// Every rule appears (present + absent) so a machine reader can tell the
    /// difference between "chain didn't match" and "chain wasn't checked".
    pub composite_chains: Vec<CompositeChain>,
    /// WS-19: comparison against a prior scan (NEW / RESOLVED / SEVERITY-CHANGED), present only
    /// when the caller passed `--baseline`. Absent from JSON otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_diff: Option<BaselineDiff>,
    /// WS-R2: per-check coverage roster (every registry check + its finding count). Empty
    /// unless the caller supplied it via [`Report::with_coverage`]; omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage: Vec<CheckCoverage>,
    /// WS-BHG (1.4.6): pre-rendered BloodHound-style principal-graph SVG string. Skipped from JSON
    /// (SVG is an HTML artifact — the JSON caller should re-render locally if it wants a picture).
    /// Callers hand it in via [`Report::with_bh_svg`], since `Report` does not carry a
    /// `ControlGraph` reference (that lives one crate up and is not `Serialize`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bh_svg: String,
}

impl Report {
    pub fn build(
        domain: &str,
        findings: Vec<Finding>,
        paths: Vec<AttackPath>,
        graph_stats: (usize, usize),
        cfg: &RiskConfig,
    ) -> Self {
        let mut category_scores: BTreeMap<&'static str, u64> = BTreeMap::new();
        for f in &findings {
            let w = cfg
                .category_weight
                .get(cat_key(f.category))
                .copied()
                .unwrap_or(1.0);
            let s = (f.score() as f64 * w).round() as u64;
            *category_scores.entry(cat_key(f.category)).or_insert(0) += s;
        }
        let total_score = category_scores.values().sum();
        let composite_chains = composite::detect(&findings);
        Report {
            domain: domain.into(),
            total_score,
            category_scores,
            findings,
            top_paths: paths.into_iter().take(25).collect(),
            graph_nodes: graph_stats.0,
            graph_edges: graph_stats.1,
            composite_chains,
            baseline_diff: None,
            coverage: Vec::new(),
            bh_svg: String::new(),
        }
    }

    /// WS-BHG: attach a pre-rendered BloodHound-style principal-graph SVG. Builder shape mirrors
    /// [`Self::with_coverage`]. Caller renders via `adhammer_report::graph_bh::to_svg(&control_graph)`.
    pub fn with_bh_svg(mut self, svg: String) -> Self {
        self.bh_svg = svg;
        self
    }

    /// WS-R2: attach the per-check coverage roster from `run_all_with_coverage`
    /// (`(check_id, findings_count)`), so the report shows every check that ran — tripped
    /// or clean — not only the positive hits. Additive builder, mirrors [`Self::with_baseline`].
    ///
    /// **1.4.6**: each row's `title` / `hypothetical_impact` / `remediation` / `mitre` is filled
    /// from either (a) the check's first emitted Finding if tripped, or (b) a static describe()
    /// fallback for clean rows. Lets an operator inspect what a clean check *would* have flagged
    /// so they can rule out check-code bugs — "not tripping" vs "check is buggy".
    pub fn with_coverage(mut self, cov: Vec<(&'static str, usize)>) -> Self {
        self.coverage = cov
            .into_iter()
            .map(|(id, findings)| {
                // 1.4.7 WS-CTRLMAP: control_areas + kill_chain_phase come from the static
                // taxonomy table regardless of tripped/clean state — they are check-registry
                // attributes, not finding attributes, so they don't change per-run.
                let taxonomy = describe_check(id);
                let control_areas: Vec<String> = taxonomy
                    .control_areas
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                let kill_chain_phase = taxonomy.kill_chain_phase.to_string();
                // If tripped, mirror the first Finding's title/impact/mitre/remediation.
                if findings > 0 {
                    if let Some(f) = self.findings.iter().find(|f| f.id == id) {
                        return CheckCoverage {
                            id: id.to_string(),
                            findings,
                            title: f.title.clone(),
                            hypothetical_impact: f.impact.clone().unwrap_or_default(),
                            remediation: f.remediation.clone(),
                            mitre: f.mitre.iter().map(|m| m.id.to_string()).collect(),
                            control_areas,
                            kill_chain_phase,
                        };
                    }
                }
                // Clean row (or tripped but the Finding wasn't in self.findings — shouldn't
                // happen): fall back to the static describe() lookup for the description
                // fields too.
                CheckCoverage {
                    id: id.to_string(),
                    findings,
                    title: taxonomy.title.into(),
                    hypothetical_impact: taxonomy.hypothetical_impact.into(),
                    remediation: taxonomy.remediation.into(),
                    mitre: taxonomy.mitre.iter().map(|s| s.to_string()).collect(),
                    control_areas,
                    kill_chain_phase,
                }
            })
            .collect();
        self
    }

    /// **1.4.7 WS-CTRLMAP**: roll up the coverage matrix by control area →
    /// `(area, checks_tripped, checks_clean)`. Sorted by area code. Empty when the
    /// caller didn't attach a coverage roster.
    pub fn coverage_by_area(&self) -> Vec<(String, usize, usize)> {
        use std::collections::BTreeMap;
        let mut acc: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for row in &self.coverage {
            for area in &row.control_areas {
                let entry = acc.entry(area.clone()).or_insert((0, 0));
                if row.findings > 0 {
                    entry.0 += 1;
                } else {
                    entry.1 += 1;
                }
            }
        }
        acc.into_iter().map(|(k, (t, c))| (k, t, c)).collect()
    }

    /// **1.4.7 WS-CTRLMAP**: roll up the coverage matrix by kill-chain phase →
    /// `(phase, checks_tripped, checks_clean)`. Phase order matches
    /// [`check_meta::KILL_CHAIN_PHASES`] (attacker-lifecycle order).
    pub fn coverage_by_phase(&self) -> Vec<(String, usize, usize)> {
        use std::collections::HashMap;
        let mut acc: HashMap<String, (usize, usize)> = HashMap::new();
        for row in &self.coverage {
            if row.kill_chain_phase.is_empty() {
                continue;
            }
            let entry = acc.entry(row.kill_chain_phase.clone()).or_insert((0, 0));
            if row.findings > 0 {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
        // Emit in canonical KILL_CHAIN_PHASES order (attacker lifecycle), not alphabetical.
        check_meta::KILL_CHAIN_PHASES
            .iter()
            .filter_map(|p| acc.remove(*p).map(|(t, c)| (p.to_string(), t, c)))
            .collect()
    }

    /// WS-19: attach a baseline comparison computed from a prior scan's JSON. `label` is recorded
    /// in the diff (usually the baseline file path). On a parse error the report is returned
    /// unchanged and the error is handed back so the caller can warn without aborting the scan.
    pub fn with_baseline(mut self, baseline_json: &str, label: &str) -> Result<Self, String> {
        self.baseline_diff = Some(BaselineDiff::compute(baseline_json, &self.findings, label)?);
        Ok(self)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    /// **1.4.7 WS-CLEAN-REPORT**: `true` when zero findings surfaced. Used to gate the
    /// green "hardened bill of health" assurance banner in the HTML/MD renderers — a
    /// hardened DC should render as an affirmative assurance document, not an empty
    /// findings page that reads identical to a broken/incomplete scan.
    pub fn is_clean_bill(&self) -> bool {
        self.findings.is_empty()
    }

    /// **1.4.7 WS-CLEAN-REPORT**: sha256 fingerprint of the report content. Hashes the
    /// canonical JSON serialization (which is deterministic via `serde_json` +
    /// `BTreeMap` for the score buckets + `&'static` static taxonomy tables), so two
    /// runs against the same domain state hash to the same value — matches WS-BHG's
    /// byte-stable-SVG discipline.
    ///
    /// Enables audit workflows: "here's the sha256 of the assessment we ran on
    /// 2026-01-15", diff by hash across baselines, spot-check that a shared report
    /// hasn't been tampered with.
    pub fn content_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let json = self.to_json();
        let digest = Sha256::digest(json.as_bytes());
        // Lowercase hex, no separator — matches every other hash surface in the report.
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Self-contained operator-facing HTML report for passive scan output.
    pub fn to_html(&self) -> String {
        let total_findings = self.findings.len();
        let chain_count = self.composite_chains.iter().filter(|c| c.present).count();
        let path_count = self.top_paths.len();
        let critical = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = self
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Low | Severity::Info))
            .count();
        format!(
            "<!doctype html><meta charset=utf-8><title>ADhammer report — {dom}</title>\
             <style>\
             :root{{color-scheme:light dark;--bg:#f7f8fc;--panel:#ffffff;--panel-2:#eef1f7;--line:#d8dde8;--text:#1a1f2c;--muted:#5a6577;--green:#0f7a4d;--amber:#996100;--red:#c62838;--blue:#1e5aa6;--code-bg:#eef1f7;--hop-bg:rgba(238,241,247,0.55);}}\
             @media (prefers-color-scheme: dark){{:root:not([data-theme=\"light\"]){{color-scheme:dark;--bg:#0b1020;--panel:#131a2c;--panel-2:#10172a;--line:#2c3657;--text:#e8edf7;--muted:#98a4c7;--green:#5be49b;--amber:#ffcf66;--red:#ff6b7f;--blue:#7cc9ff;--code-bg:#0d1323;--hop-bg:rgba(11,16,32,0.45);}}}}\
             :root[data-theme=\"dark\"]{{color-scheme:dark;--bg:#0b1020;--panel:#131a2c;--panel-2:#10172a;--line:#2c3657;--text:#e8edf7;--muted:#98a4c7;--green:#5be49b;--amber:#ffcf66;--red:#ff6b7f;--blue:#7cc9ff;--code-bg:#0d1323;--hop-bg:rgba(11,16,32,0.45);}}\
             *{{box-sizing:border-box}}\
             body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 Inter,Segoe UI,system-ui,sans-serif}}\
             .wrap{{max-width:1240px;margin:0 auto;padding:32px 24px 56px}}\
             h1,h2,h3,p{{margin:0}}\
             code,pre{{font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace}}\
             code{{background:var(--code-bg);padding:3px 6px;border-radius:6px}}\
             section{{margin-top:28px}}\
             .hero{{margin-bottom:10px}}\
             .hero p{{margin-top:12px;color:var(--muted);max-width:900px}}\
             .hero-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap}}\
             .subtitle{{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.04em}}\
             .stats,.sev-grid,.score-grid{{display:grid;gap:12px}}\
             .stats{{grid-template-columns:repeat(5,minmax(140px,1fr));margin:20px 0}}\
             .sev-grid{{grid-template-columns:repeat(4,minmax(140px,1fr));margin:0 0 6px}}\
             .score-grid{{grid-template-columns:repeat(auto-fit,minmax(180px,1fr));margin-top:12px}}\
             .stat,.sev-card,.score-card,.panel,.finding,.path,.chain{{background:var(--panel);border:1px solid var(--line);border-radius:8px}}\
             .stat,.sev-card,.score-card{{padding:14px 16px}}\
             .stat b,.sev-card b,.score-card b{{display:block;font-size:25px;line-height:1.1}}\
             .stat span,.sev-card span,.score-card span{{color:var(--muted);font-size:12px;text-transform:uppercase}}\
             .sev-critical{{border-color:rgba(255,107,127,.45)}} .sev-high{{border-color:rgba(255,207,102,.45)}} .sev-medium{{border-color:rgba(124,201,255,.45)}}\
             .sev-low{{border-color:rgba(152,164,199,.35)}}\
             .panel{{padding:18px 20px}}\
             .panel h2{{margin-bottom:12px}}\
             .panel p{{color:var(--muted)}}\
             .chip{{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border-radius:999px;font-size:12px;font-weight:700;border:1px solid var(--line);background:var(--panel-2);margin-right:8px}}\
             .chip-critical{{color:var(--red);border-color:var(--red)}}\
             .chip-high{{color:var(--amber);border-color:var(--amber)}}\
             .chip-medium{{color:var(--blue);border-color:var(--blue)}}\
             .chip-low,.chip-info{{color:var(--muted)}}\
             .chip-good{{color:var(--green);border-color:rgba(91,228,155,.5)}}\
             .chip-warn{{color:var(--amber);border-color:rgba(255,207,102,.55)}}\
             .muted{{color:var(--muted)}}\
             .finding{{padding:18px 20px;margin:0 0 16px}}\
             .finding-head{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px}}\
             .finding h3{{margin-bottom:10px}}\
             .meta{{display:grid;grid-template-columns:130px 1fr;gap:10px;margin:8px 0}}\
             .meta .k{{color:var(--muted);font-weight:600}}\
             .list{{margin:0;padding-left:18px;color:var(--text)}}\
             .list li{{margin:4px 0}}\
             .path{{padding:18px 20px;margin:0 0 16px}}\
             .path-head{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;margin-bottom:10px}}\
             .route{{font-weight:700;font-size:16px}}\
             .hop{{margin:12px 0 0;padding:12px 14px;border-left:3px solid var(--line);background:var(--hop-bg);border-radius:0 8px 8px 0}}\
             .hop-top{{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;flex-wrap:wrap}}\
             .cmd{{display:block;margin-top:10px;padding:10px 12px;background:var(--code-bg);border:1px solid var(--line);border-radius:8px;overflow:auto}}\
             .theme-toggle{{position:fixed;top:16px;right:16px;z-index:100;background:var(--panel);border:1px solid var(--line);color:var(--text);border-radius:999px;padding:6px 12px;cursor:pointer;font:12px Inter,system-ui,sans-serif;box-shadow:0 2px 6px rgba(0,0,0,0.12);user-select:none}}\
             .theme-toggle:hover{{border-color:var(--muted)}}\
             .todo{{color:var(--amber);font-style:italic;margin-top:10px}}\
             .fix{{margin-top:10px;color:var(--green)}}\
             .chain{{padding:14px 16px;margin:0 0 12px}}\
             .chain p{{margin-top:6px;color:var(--muted)}}\
             @media (max-width:900px){{.stats{{grid-template-columns:repeat(2,minmax(140px,1fr))}} .sev-grid{{grid-template-columns:repeat(2,minmax(140px,1fr))}} .meta{{grid-template-columns:1fr}} .wrap{{padding:24px 18px 42px}}}}\
             .graph-wrap{{overflow-x:auto;padding:6px 2px;margin-top:12px}}\
             .bh-wrap{{width:100%;max-width:100%;overflow-x:auto;margin-top:12px}}\
             .bh-graph{{width:100%;height:auto;background:var(--panel-2);border:1px solid var(--line);border-radius:8px;color:var(--muted)}}\
             .bh-edge{{stroke:var(--muted);stroke-width:1.4;opacity:0.6;color:var(--muted)}}\
             .bh-node circle{{fill:var(--blue);stroke:var(--line);stroke-width:1.5}}\
             .bh-node.bh-t0 circle{{fill:var(--red);stroke:var(--red);stroke-width:2}}\
             .bh-node text{{fill:var(--text);font:11px ui-monospace,SFMono-Regular,Consolas,monospace;pointer-events:none}}\
             .bh-node{{cursor:pointer}}\
             .bh-graph{{cursor:grab}}\
             .bh-dim{{opacity:0.15;transition:opacity 120ms}}\
             .bh-node:not(.bh-dim),.bh-edge:not(.bh-dim){{transition:opacity 120ms}}\
             .bh-footer{{fill:var(--muted);font:11px Inter,system-ui,sans-serif}}\
             svg.graph{{min-width:100%;height:auto;display:block}}\
             .node rect{{fill:var(--panel-2);stroke:var(--line);stroke-width:1.5}}\
             .node text{{fill:var(--text);font:600 12px Inter,system-ui,sans-serif;text-anchor:middle;dominant-baseline:middle}}\
             .node-source rect{{stroke:var(--blue)}}\
             .node-inter rect{{stroke:var(--amber)}}\
             .node-sink rect{{stroke:var(--red);stroke-width:2.5}}\
             .edge{{stroke:var(--line);stroke-width:1.3;fill:none}}\
             .edge-exec{{stroke:var(--green);stroke-width:2.4}}\
             .edge-label{{fill:var(--muted);font:11px ui-monospace,Consolas,monospace;text-anchor:middle}}\
             .arrow{{fill:var(--muted)}}\
             .graph-note{{fill:var(--muted);font:12px Inter,system-ui,sans-serif}}\
             .cov-wrap{{overflow-x:auto;margin-top:12px}}\
             .cov{{border-collapse:collapse;width:100%;font-size:13px}}\
             .cov th,.cov td{{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)}}\
             .cov th{{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.04em}}\
             </style>\
             <button type=button class=theme-toggle id=theme-toggle aria-label=\"Toggle light/dark theme\" title=\"Toggle theme\">\u{2600}\u{FE0F} / \u{1F319}</button>\
             <script>\
             (function(){{try{{var k='adhammer-theme';var s=localStorage.getItem(k);if(s==='light'||s==='dark'){{document.documentElement.setAttribute('data-theme',s);}}var b=document.getElementById('theme-toggle');if(!b)return;b.addEventListener('click',function(){{var d=document.documentElement;var cur=d.getAttribute('data-theme');var mp=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches;var isDark=cur==='dark'||(!cur&&mp);var next=isDark?'light':'dark';d.setAttribute('data-theme',next);try{{localStorage.setItem(k,next);}}catch(e){{}}}});}}catch(e){{}}}})();\
             </script>\
             <div class=wrap>\
             <div class=hero>\
               <div class=hero-head>\
                 <div>\
                   <div class=subtitle>ADhammer passive audit report</div>\
                   <h1>{dom}</h1>\
                 </div>\
                 <div class=subtitle>{date}</div>\
               </div>\
               <p>This report summarizes supported passive findings, control-path analysis, and attack-chain correlation from the current directory snapshot. Findings are grouped for fast operator review, with attack paths and mitigations kept copy-paste close.</p>\
             </div>\
             <div class=stats>\
               <div class=stat><b>{findings}</b><span>Total findings</span></div>\
               <div class=stat><b>{score}</b><span>Risk score</span></div>\
               <div class=stat><b>{nodes}</b><span>Graph nodes</span></div>\
               <div class=stat><b>{paths_count}</b><span>Attack paths</span></div>\
               <div class=stat><b>{chains_count}</b><span>Attack chains</span></div>\
             </div>\
             <div class=sev-grid>\
               <div class=\"sev-card sev-critical\"><b>{critical}</b><span>Critical</span></div>\
               <div class=\"sev-card sev-high\"><b>{high}</b><span>High</span></div>\
               <div class=\"sev-card sev-medium\"><b>{medium}</b><span>Medium</span></div>\
               <div class=\"sev-card sev-low\"><b>{low}</b><span>Low / Info</span></div>\
             </div>\
             {baseline}\
             {assurance}\
             <section class=panel><h2>Risk by category</h2><div class=score-grid>{scores}</div></section>\
             {coverage_areas}\
             {coverage_phases}\
             {coverage}\
             {chains}\
             <section class=panel><h2>Findings</h2><p>Each card shows why the condition matters, what it affects, and the shortest remediation text needed to brief an operator or stakeholder.</p></section>\
             {findings_html}\
             {graph}\
             {bh_graph}\
             {paths}\
             {hash_footer}\
             </div>",
            dom = html_escape(&self.domain),
            date = current_utc_date(),
            findings = total_findings,
            score = self.total_score,
            nodes = self.graph_nodes,
            paths_count = path_count,
            chains_count = chain_count,
            critical = critical,
            high = high,
            medium = medium,
            low = low,
            baseline = self.baseline_html(),
            assurance = self.assurance_banner_html(),
            scores = self.category_scores_html(),
            coverage_areas = self.coverage_areas_html(),
            coverage_phases = self.coverage_phases_html(),
            coverage = self.coverage_html(),
            chains = self.chains_html(),
            findings_html = self.findings_html(),
            graph = self.graph_svg_panel(),
            bh_graph = self.bh_graph_panel(),
            paths = self.paths_html(),
            hash_footer = self.hash_footer_html(),
        )
    }

    /// WS-BHG: the "Principal graph" panel — inline BloodHound-style SVG of every principal that
    /// has an edge into/out of a Tier-0 node. Empty string when the caller didn't attach one.
    fn bh_graph_panel(&self) -> String {
        if self.bh_svg.is_empty() {
            return String::new();
        }
        format!(
            "<section class=panel><h2>Principal graph</h2>\
             <p>Every principal with a direct control-edge into or out of a Tier-0 node — \
             <span style=\"color:var(--red)\">Tier-0</span> in a horizontal row, neighbors on \
             concentric rings. Hover any node for its SID; hover an edge for the control primitive. \
             Pruned to the first {} — the footer shows total vs. drawn.</p>\
             <div class=bh-wrap>{}</div></section>",
            graph_bh::MAX_NODES_DOCS,
            self.bh_svg
        )
    }

    /// WS-R1: the "Attack graph" panel — an inline, self-contained SVG of the cheapest
    /// control paths to Tier-0 (see [`graph_svg`]). Empty string when there are no paths.
    fn graph_svg_panel(&self) -> String {
        let svg = graph_svg::attack_graph_svg(&self.top_paths);
        if svg.is_empty() {
            return String::new();
        }
        format!(
            "<section class=panel><h2>Attack graph</h2>\
             <p>The cheapest control paths to Tier-0, drawn as a graph — \
             <span style=\"color:var(--blue)\">entry principal</span>, \
             <span style=\"color:var(--amber)\">pivot</span>, \
             <span style=\"color:var(--red)\">Tier-0 target</span>; \
             <span style=\"color:var(--green)\">green</span> edges are hops adhammer can execute. \
             Hover an edge for the hop.</p>\
             <div class=graph-wrap>{svg}</div></section>"
        )
    }

    /// **1.4.7 WS-CLEAN-REPORT**: green "hardened bill of health" banner shown only when
    /// the scan produced zero findings. Turns an otherwise-empty findings page into an
    /// affirmative assurance document — the target passed every tested control area.
    /// Includes counts sourced from the WS-CTRLMAP roll-ups so a reader can immediately
    /// see how much surface was actually exercised, not just "0 findings" in isolation.
    fn assurance_banner_html(&self) -> String {
        if !self.is_clean_bill() {
            return String::new();
        }
        let areas = self.coverage_by_area().len();
        let phases = self.coverage_by_phase().len();
        let checks = self.coverage.len();
        // Preconditions-not-met heuristic: any coverage row whose remediation says
        // Remote Registry / not present / not deployed → the check couldn't fully
        // exercise its target. Surfaced honestly next to the assurance claim so a
        // reader isn't misled about surface that wasn't reached.
        let skipped_hint = self
            .coverage
            .iter()
            .filter(|c| {
                c.findings == 0
                    && (c.remediation.contains("Remote Registry")
                        || c.title.contains("not present")
                        || c.title.contains("not installed"))
            })
            .count();
        let skipped_line = if skipped_hint > 0 {
            format!(
                " <span class=muted>({skipped_hint} check(s) could not fully exercise their target — see the coverage matrix)</span>"
            )
        } else {
            String::new()
        };
        format!(
            "<section class=panel style=\"border:1px solid var(--green);background:linear-gradient(180deg,rgba(15,122,77,0.10),transparent 60%)\">\
             <h2 style=\"color:var(--green)\">&#10003; No vulnerabilities identified</h2>\
             <p><b>{checks}</b> passive checks ran across <b>{areas}</b> in-house control area(s) \
             (<code>ADP-NN</code>; see <code>docs/CONTROL_AREAS.md</code>) and <b>{phases}</b> \
             attacker-lifecycle phase(s). No condition tripped.{skipped_line}</p>\
             <p class=muted>This is an assurance statement about what ADhammer's static + \
             live-probe checks looked for on this run — not a claim of complete AD security. \
             Kerberos + LDAP transport hardening, attack-graph paths to Tier-0, and control-area \
             coverage are all in scope; runtime EDR, network segmentation, and human-process \
             controls are not.</p></section>"
        )
    }

    /// **1.4.7 WS-CLEAN-REPORT**: audit-trail footer with the report's content hash +
    /// domain label. Always rendered — supports diffing across baselines, spot-checking
    /// a shared report for tampering, and archive search by hash. Deterministic per
    /// [`Self::content_hash`].
    fn hash_footer_html(&self) -> String {
        format!(
            "<section class=panel style=\"border-style:dashed\">\
             <h2>Report fingerprint</h2>\
             <p class=muted>Deterministic sha256 of the canonical JSON serialization — same domain \
             state on repeat scans yields the same fingerprint. Useful as an audit-trail identifier \
             or a baseline-diff key.</p>\
             <p><code>domain</code>: <code>{}</code></p>\
             <p><code>sha256</code>: <code>{}</code></p></section>",
            html_escape(&self.domain),
            self.content_hash(),
        )
    }

    /// **1.4.7 WS-CTRLMAP**: HTML "Control-area coverage" panel — the in-house AD-pentest
    /// taxonomy (`ADP-01..ADP-30`; see `docs/CONTROL_AREAS.md`) rolled up as `(area, tripped,
    /// clean)`. Executive-level summary above the 58-row detail matrix — answers the
    /// question "which control areas did this assessment exercise, and how did the target
    /// score in each?" without any third-party methodology labels.
    fn coverage_areas_html(&self) -> String {
        let rollup = self.coverage_by_area();
        if rollup.is_empty() {
            return String::new();
        }
        let total_areas = rollup.len();
        let clean_areas = rollup.iter().filter(|(_, t, _)| *t == 0).count();
        let rows: String = rollup
            .iter()
            .map(|(area, t, c)| {
                let (cls, status) = if *t == 0 {
                    ("chip-good", format!("clean · {c} check(s)"))
                } else {
                    ("chip-warn", format!("{t} tripped · {c} clean"))
                };
                format!(
                    "<tr><td><code>{}</code></td><td><span class=\"chip {}\">{}</span></td></tr>",
                    html_escape(area),
                    cls,
                    html_escape(&status),
                )
            })
            .collect();
        format!(
            "<section class=panel><h2>Control-area coverage</h2>\
             <p>The <b>{total_areas}</b> AD-pentest control areas this assessment exercised — \
             <b>{clean_areas}</b> came back fully clean. Codes are the in-house <code>ADP-NN</code> \
             taxonomy (see <code>docs/CONTROL_AREAS.md</code>); each check in the matrix below \
             carries one or more area tags, and this table rolls them up.</p>\
             <div class=cov-wrap><table class=cov><thead><tr><th>Area</th><th>Result</th></tr></thead>\
             <tbody>{rows}</tbody></table></div></section>"
        )
    }

    /// **1.4.7 WS-CTRLMAP**: HTML "Kill-chain coverage" panel — generic offensive lifecycle
    /// (enumeration → initial-access → privilege-escalation → lateral-movement → persistence
    /// → domain-dominance). Rolled up as `(phase, tripped, clean)` in attacker-lifecycle
    /// order, not alphabetical.
    fn coverage_phases_html(&self) -> String {
        let rollup = self.coverage_by_phase();
        if rollup.is_empty() {
            return String::new();
        }
        let rows: String = rollup
            .iter()
            .map(|(phase, t, c)| {
                let (cls, status) = if *t == 0 {
                    ("chip-good", format!("clean · {c} check(s)"))
                } else {
                    ("chip-warn", format!("{t} tripped · {c} clean"))
                };
                format!(
                    "<tr><td><code>{}</code></td><td><span class=\"chip {}\">{}</span></td></tr>",
                    html_escape(phase),
                    cls,
                    html_escape(&status),
                )
            })
            .collect();
        format!(
            "<section class=panel><h2>Kill-chain coverage</h2>\
             <p>Coverage by attacker-lifecycle phase — generic offensive terminology, no cert-body \
             framing. Rows are in canonical lifecycle order (enumeration first, domain-dominance \
             last), so a reader can walk down the phases the way an attacker would.</p>\
             <div class=cov-wrap><table class=cov><thead><tr><th>Phase</th><th>Result</th></tr></thead>\
             <tbody>{rows}</tbody></table></div></section>"
        )
    }

    /// WS-R2 + 1.4.6 WS-COVERAGE-META: HTML "Check coverage" panel — the full registry roster
    /// (tripped vs clean). Each row is expandable via `<details>` to show the check's title,
    /// hypothetical impact ("what would happen if this had tripped"), remediation, and MITRE
    /// techniques — populated from the tripped Finding (if any) or from
    /// [`crate::describe_check`] fallback for clean rows.
    fn coverage_html(&self) -> String {
        if self.coverage.is_empty() {
            return String::new();
        }
        let total = self.coverage.len();
        let tripped = self.coverage.iter().filter(|c| c.findings > 0).count();
        let clean = total - tripped;
        let rows: String = self
            .coverage
            .iter()
            .map(|c| {
                let (cls, status, proof_cell) = if c.findings > 0 {
                    (
                        "chip-warn",
                        format!("{} finding(s)", c.findings),
                        "<span class=\"chip chip-good\" title=\"every finding has evidence + impact — enforced by CI\">&#10003; proof</span>",
                    )
                } else {
                    (
                        "chip-good",
                        "clean".to_string(),
                        "<span class=muted>—</span>",
                    )
                };
                // Build the expandable card body — title + hypothetical impact + remediation +
                // MITRE. Skip fields that are empty so unknown check IDs (in the fallback table)
                // gracefully render just the ID row.
                let mut card = String::new();
                if !c.title.is_empty() {
                    card.push_str(&format!(
                        "<div class=cov-title>{}</div>",
                        html_escape(&c.title)
                    ));
                }
                let impact_label = if c.findings > 0 { "Impact" } else { "Hypothetical impact (what would happen if this had tripped)" };
                if !c.hypothetical_impact.is_empty() {
                    card.push_str(&format!(
                        "<div class=cov-field><b>{impact_label}:</b> {}</div>",
                        html_escape(&c.hypothetical_impact)
                    ));
                }
                if !c.remediation.is_empty() {
                    card.push_str(&format!(
                        "<div class=cov-field><b>Remediation:</b> {}</div>",
                        html_escape(&c.remediation)
                    ));
                }
                if !c.mitre.is_empty() {
                    let chips: String = c
                        .mitre
                        .iter()
                        .map(|m| format!("<span class=\"chip chip-info\">{}</span>", html_escape(m)))
                        .collect();
                    card.push_str(&format!("<div class=cov-field><b>MITRE:</b> {chips}</div>"));
                }
                let details = if card.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<tr class=cov-details><td colspan=3><details><summary>Details</summary><div class=cov-card>{card}</div></details></td></tr>"
                    )
                };
                format!(
                    "<tr><td><code>{}</code></td><td><span class=\"chip {}\">{}</span></td><td>{}</td></tr>{}",
                    html_escape(&c.id),
                    cls,
                    html_escape(&status),
                    proof_cell,
                    details,
                )
            })
            .collect();
        format!(
            "<section class=panel><h2>Check coverage</h2>\
             <p>All <b>{total}</b> passive checks ran — <b>{tripped}</b> tripped, <b>{clean}</b> clean. \
             Click <em>Details</em> on any row to see what the check was looking for and its hypothetical \
             impact, so a clean row is verifiable (not just \"the check didn't trip — maybe it's buggy\"). \
             Every tripped row carries a ground-truth <b>proof</b> block; WS-PROOF-70 enforces this at CI time.</p>\
             <div class=cov-wrap><table class=cov><thead><tr><th>Check</th><th>Result</th><th>Proof</th></tr></thead>\
             <tbody>{rows}</tbody></table></div></section>"
        )
    }

    /// WS-R2: Markdown "Check coverage" section (empty when no coverage was supplied).
    fn coverage_md(&self) -> String {
        if self.coverage.is_empty() {
            return String::new();
        }
        let tripped = self.coverage.iter().filter(|c| c.findings > 0).count();
        let clean = self.coverage.len() - tripped;
        let mut out = format!(
            "## Check coverage\n\nAll {} passive checks ran — **{} tripped**, **{} clean**. Every \
             tripped check carries ground-truth **proof** — enforced at build time (WS-PROOF-70).\n\n\
             | Check | Result | Proof |\n|---|---|---|\n",
            self.coverage.len(),
            tripped,
            clean
        );
        for c in &self.coverage {
            let (status, proof) = if c.findings > 0 {
                (format!("{} finding(s)", c.findings), "✓")
            } else {
                ("clean".to_string(), "—")
            };
            out.push_str(&format!("| `{}` | {} | {} |\n", c.id, status, proof));
        }
        out.push('\n');
        out
    }

    /// WS-19: a `[NEW] ` / `[SEV CHANGED] ` prefix for a finding whose id moved vs the baseline.
    fn baseline_tag(&self, id: &str) -> &'static str {
        if let Some(d) = &self.baseline_diff {
            if d.new_ids().contains(id) {
                return "[NEW] ";
            }
            if d.sevchanged_ids().contains(id) {
                return "[SEV CHANGED] ";
            }
        }
        ""
    }

    /// WS-19: Markdown "Baseline diff" block (empty string when no baseline was supplied).
    fn baseline_md(&self) -> String {
        let Some(d) = &self.baseline_diff else {
            return String::new();
        };
        let mut out = format!(
            "## Baseline diff\n\nCompared against `{}` — **{} new**, **{} resolved**, **{} severity-changed**, {} unchanged.\n\n",
            collapse_ws(&d.baseline),
            d.summary.new,
            d.summary.resolved,
            d.summary.severity_changed,
            d.summary.unchanged,
        );
        for e in d.new.iter().take(50) {
            out.push_str(&format!(
                "- [NEW] {} — {} ({})\n",
                e.id, e.object, e.severity
            ));
        }
        for e in d.severity_changed.iter().take(50) {
            out.push_str(&format!(
                "- [SEV {}→{}] {} — {}\n",
                e.from, e.to, e.id, e.object
            ));
        }
        for e in d.resolved.iter().take(50) {
            out.push_str(&format!(
                "- [RESOLVED] {} — {} ({})\n",
                e.id, e.object, e.severity
            ));
        }
        out.push('\n');
        out
    }

    /// WS-19: HTML "Baseline diff" panel (empty when no baseline was supplied).
    fn baseline_html(&self) -> String {
        let Some(d) = &self.baseline_diff else {
            return String::new();
        };
        let row = |items: String| -> String { format!("<ul class=list>{items}</ul>") };
        let new_rows: String = d
            .new
            .iter()
            .take(50)
            .map(|e| {
                format!(
                    "<li><code>{}</code> {} <span class=muted>({})</span></li>",
                    html_escape(&e.id),
                    html_escape(&e.object),
                    html_escape(&e.severity)
                )
            })
            .collect();
        let chg_rows: String = d
            .severity_changed
            .iter()
            .take(50)
            .map(|e| {
                format!(
                    "<li><code>{}</code> {} <span class=muted>{}→{}</span></li>",
                    html_escape(&e.id),
                    html_escape(&e.object),
                    html_escape(&e.from),
                    html_escape(&e.to)
                )
            })
            .collect();
        let res_rows: String = d
            .resolved
            .iter()
            .take(50)
            .map(|e| {
                format!(
                    "<li><code>{}</code> {} <span class=muted>({})</span></li>",
                    html_escape(&e.id),
                    html_escape(&e.object),
                    html_escape(&e.severity)
                )
            })
            .collect();
        format!(
            "<section class=panel><h2>Baseline diff</h2>\
             <p>Compared against <code>{base}</code>: \
             <span class=\"chip chip-high\">{n} new</span>\
             <span class=\"chip chip-good\">{r} resolved</span>\
             <span class=\"chip chip-medium\">{c} severity-changed</span>\
             <span class=chip>{u} unchanged</span></p>\
             {new_block}{chg_block}{res_block}</section>",
            base = html_escape(&d.baseline),
            n = d.summary.new,
            r = d.summary.resolved,
            c = d.summary.severity_changed,
            u = d.summary.unchanged,
            new_block = if new_rows.is_empty() {
                String::new()
            } else {
                format!("<h3>New</h3>{}", row(new_rows))
            },
            chg_block = if chg_rows.is_empty() {
                String::new()
            } else {
                format!("<h3>Severity changed</h3>{}", row(chg_rows))
            },
            res_block = if res_rows.is_empty() {
                String::new()
            } else {
                format!("<h3>Resolved</h3>{}", row(res_rows))
            },
        )
    }

    fn category_scores_html(&self) -> String {
        if self.category_scores.is_empty() {
            return "<div class=score-card><b>0</b><span>No category scores</span></div>".into();
        }
        let mut out = String::new();
        for (category, score) in &self.category_scores {
            out.push_str(&format!(
                "<div class=score-card><b>{}</b><span>{}</span></div>",
                score,
                html_escape(category)
            ));
        }
        out
    }

    fn findings_html(&self) -> String {
        let mut out = String::new();
        for sev in SEV_ORDER {
            let batch: Vec<_> = self
                .findings
                .iter()
                .filter(|f| f.severity == *sev)
                .collect();
            if batch.is_empty() {
                continue;
            }
            out.push_str(&format!(
                "<section><div class=panel><h2>{}</h2><p>{} finding(s) in this band.</p></div></section>",
                sev_name(*sev),
                batch.len()
            ));
            for f in batch {
                let mitre = if f.mitre.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<div class=meta><div class=k>MITRE</div><div>{}</div></div>",
                        html_escape(
                            &f.mitre
                                .iter()
                                .map(|m| format!("{} {}", m.id, m.name))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    )
                };
                let impact = f
                    .impact
                    .as_ref()
                    .map(|s| {
                        format!(
                            "<div class=meta><div class=k>Impact</div><div>{}</div></div>",
                            html_escape(s)
                        )
                    })
                    .unwrap_or_default();
                out.push_str(&format!(
                    "<article class=finding>\
                       <div class=finding-head>\
                         <span class=\"chip chip-{sev_class}\">{sev}</span>\
                         <span class=chip>{id}</span>\
                         <span class=chip>{category}</span>\
                         <span class=\"chip {affected_chip}\">{affected_count} affected</span>\
                         {baseline_chip}\
                       </div>\
                       <h3>{title}</h3>\
                       <div class=meta><div class=k>Why</div><div>{detail}</div></div>\
                       {evidence}\
                       {wire}\
                       {mitre}\
                       <div class=meta><div class=k>Affected</div><div>{affected}</div></div>\
                       {impact}\
                       <div class=meta><div class=k>Remediation</div><div>{remediation}</div></div>\
                     </article>",
                    sev_class = sev_class(f.severity),
                    sev = html_escape(sev_name(f.severity)),
                    id = html_escape(&f.id),
                    category = html_escape(cat_label(f.category)),
                    affected_chip = if f.affected.is_empty() {
                        "muted"
                    } else {
                        "chip-good"
                    },
                    baseline_chip = {
                        let t = self.baseline_tag(&f.id);
                        if t.is_empty() {
                            String::new()
                        } else {
                            format!("<span class=\"chip chip-warn\">{}</span>", html_escape(t.trim()))
                        }
                    },
                    affected_count = f.affected.len(),
                    title = html_escape(&f.title),
                    detail = html_escape(&f.detail),
                    evidence = if f.evidence.is_empty() {
                        String::new()
                    } else {
                        let rows: String = f
                            .evidence
                            .iter()
                            .map(|e| {
                                format!(
                                    "<div class=ev><code>{}</code> = <code>{}</code></div>",
                                    html_escape(&e.source),
                                    html_escape(&e.value)
                                )
                            })
                            .collect();
                        format!("<div class=meta><div class=k>Evidence (ground truth)</div><div>{rows}</div></div>")
                    },
                    wire = wire_html(&f.exchange),
                    mitre = mitre,
                    affected = affected_html(&f.affected),
                    impact = impact,
                    remediation = html_escape(&f.remediation),
                ));
            }
        }
        out
    }

    /// The kill-chain section: each route to Tier-0 hop by hop, with the command that walks
    /// the hop and the change that removes it.
    fn paths_html(&self) -> String {
        if self.top_paths.is_empty() {
            return String::new();
        }
        let mut out = String::from(
            "<section><div class=panel><h2>Attack paths to Tier-0</h2><p>These are the cheapest control paths in the graph. Every hop keeps the suggested command or clearly says when executor support is still missing.</p></div></section>",
        );
        for p in &self.top_paths {
            out.push_str(&format!(
                "<article class=path><div class=path-head><div><div class=route>{route}</div><div class=muted>cost {cost}</div></div><div>{exec}</div></div>",
                route = html_escape(&p.render()),
                cost = p.cost,
                exec = if p.fully_executable() {
                    "<span class=\"chip chip-good\">every hop executable</span>"
                } else {
                    "<span class=\"chip chip-warn\">manual/context gaps remain</span>"
                },
            ));
            for (i, s) in p.steps.iter().enumerate() {
                let cmd = match &s.command {
                    Some(c) => format!("<code class=cmd>{}</code>", html_escape(c)),
                    None => "<div class=todo>no executor yet — detection only</div>".into(),
                };
                out.push_str(&format!(
                    "<div class=hop><div class=hop-top><b>{n}. {edge}</b><span class=muted>{from} -> {to}</span></div><div>{impact}</div>{cmd}\
                     <div class=fix>fix: {fix}</div></div>",
                    n = i + 1,
                    edge = s.edge,
                    from = html_escape(&s.from),
                    to = html_escape(&s.to),
                    impact = html_escape(s.impact),
                    cmd = cmd,
                    fix = html_escape(s.mitigation),
                ));
            }
            out.push_str("</article>");
        }
        out
    }

    fn chains_html(&self) -> String {
        let present: Vec<_> = self.composite_chains.iter().filter(|c| c.present).collect();
        if present.is_empty() {
            return String::new();
        }
        let mut out = String::from(
            "<section><div class=panel><h2>Attack chains</h2><p>Composite chains highlight combinations that raise impact beyond any single finding on its own.</p></div></section>",
        );
        for c in present {
            out.push_str(&format!(
                "<article class=chain><div><span class=\"chip chip-critical\">Chain</span><b>{title}</b></div><p>{impact}</p></article>",
                title = html_escape(c.title),
                impact = html_escape(c.impact),
            ));
        }
        out
    }

    /// Offline-read Markdown: H1 = domain + scan date, TOC, per-severity sections.
    /// No emoji, no color escapes.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let now = current_utc_date();
        out.push_str(&format!(
            "# ADhammer report — {} ({})\n\n",
            self.domain, now
        ));

        out.push_str(&format!(
            "Total risk score: **{}** — graph: {} nodes / {} edges — findings: {}\n\n",
            self.total_score,
            self.graph_nodes,
            self.graph_edges,
            self.findings.len(),
        ));

        // WS-19: baseline diff summary right under the header, before the TOC.
        out.push_str(&self.baseline_md());
        // WS-R2: full-registry coverage roster (tripped vs clean).
        out.push_str(&self.coverage_md());

        // Table of contents.
        out.push_str("## Contents\n\n");
        let present_chains = self.composite_chains.iter().any(|c| c.present);
        if present_chains {
            out.push_str("- [Attack chains](#attack-chains)\n");
        }
        for sev in SEV_ORDER {
            if self.findings.iter().any(|f| f.severity == *sev) {
                let name = sev_name(*sev);
                out.push_str(&format!(
                    "- [{name}](#{anchor})\n",
                    anchor = name.to_ascii_lowercase()
                ));
            }
        }
        out.push('\n');

        // Composite chains block, if any present.
        if present_chains {
            out.push_str("## Attack chains\n\n");
            for c in self.composite_chains.iter().filter(|c| c.present) {
                out.push_str(&format!("- **{}** — {}\n", c.title, c.impact));
            }
            out.push('\n');
        }

        // Per-severity sections.
        for sev in SEV_ORDER {
            let batch: Vec<_> = self
                .findings
                .iter()
                .filter(|f| f.severity == *sev)
                .collect();
            if batch.is_empty() {
                continue;
            }
            let name = sev_name(*sev);
            out.push_str(&format!("## {name}\n\n"));
            for f in batch {
                out.push_str(&format!(
                    "### {}{} — {}\n\n",
                    self.baseline_tag(&f.id),
                    f.id,
                    f.title
                ));
                if !f.mitre.is_empty() {
                    let tags: Vec<String> = f
                        .mitre
                        .iter()
                        .map(|m| format!("{} {}", m.id, m.name))
                        .collect();
                    out.push_str(&format!("- MITRE: {}\n", tags.join(", ")));
                }
                if !f.affected.is_empty() {
                    let list = f
                        .affected
                        .iter()
                        .take(20)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    let more = if f.affected.len() > 20 {
                        format!(" (and {} more)", f.affected.len() - 20)
                    } else {
                        String::new()
                    };
                    out.push_str(&format!("- Affected: {list}{more}\n"));
                }
                out.push_str(&format!("- Detail: {}\n", collapse_ws(&f.detail)));
                if !f.evidence.is_empty() {
                    out.push_str("- Evidence (ground truth):\n");
                    for e in f.evidence.iter().take(25) {
                        out.push_str(&format!(
                            "  - `{}` = `{}`\n",
                            collapse_ws(&e.source),
                            collapse_ws(&e.value)
                        ));
                    }
                }
                out.push_str(&wire_md(&f.exchange));
                if let Some(impact) = &f.impact {
                    out.push_str(&format!("- Impact: {}\n", collapse_ws(impact)));
                }
                out.push_str(&format!(
                    "- Remediation: {}\n\n",
                    collapse_ws(&f.remediation)
                ));
            }
        }
        out
    }

    /// Plaintext summary: header, top-N one-liners, footer. `n` controls how
    /// many findings the summary lists (highest severity first).
    pub fn to_text_summary(&self, n: usize) -> String {
        let mut out = String::new();
        let date = current_utc_date();
        out.push_str(&format!("ADhammer summary — {} ({})\n", self.domain, date));
        out.push_str(&format!(
            "Total findings: {} — risk score {}\n",
            self.findings.len(),
            self.total_score
        ));

        // Severity histogram.
        let mut parts = Vec::new();
        for sev in SEV_ORDER {
            let c = self.findings.iter().filter(|f| f.severity == *sev).count();
            if c > 0 {
                parts.push(format!("{}={}", sev_name(*sev), c));
            }
        }
        if !parts.is_empty() {
            out.push_str(&format!("By severity: {}\n", parts.join("  ")));
        }
        if !self.coverage.is_empty() {
            let tripped = self.coverage.iter().filter(|c| c.findings > 0).count();
            out.push_str(&format!(
                "Coverage: {} checks run, {} tripped, {} clean\n",
                self.coverage.len(),
                tripped,
                self.coverage.len() - tripped
            ));
        }

        let chain_hits: Vec<_> = self.composite_chains.iter().filter(|c| c.present).collect();
        out.push_str(&format!("Chains: {} present\n", chain_hits.len()));
        for c in &chain_hits {
            out.push_str(&format!("  - {} -> {}\n", c.title, c.impact));
        }

        if let Some(d) = &self.baseline_diff {
            out.push_str(&format!(
                "Baseline ({}): +{} new / -{} resolved / ~{} severity-changed\n",
                collapse_ws(&d.baseline),
                d.summary.new,
                d.summary.resolved,
                d.summary.severity_changed,
            ));
        }

        out.push('\n');
        out.push_str(&format!("Top {} findings\n", n.min(self.findings.len())));
        let mut sorted: Vec<&Finding> = self.findings.iter().collect();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.score()));
        for f in sorted.iter().take(n) {
            let obj = f
                .affected
                .first()
                .map(String::as_str)
                .unwrap_or("(no object)");
            out.push_str(&format!(
                "  [{sev}] {title} - {obj}\n",
                sev = sev_short(f.severity),
                title = collapse_ws(&f.title),
                obj = obj,
            ));
            // WS-PROOF-70 part 2: every tripped finding shows its impact + first ground-truth
            // evidence, capped so the summary stays legible.
            if let Some(impact) = f.impact.as_deref() {
                out.push_str(&format!(
                    "         impact: {}\n",
                    cap_line(&collapse_ws(impact), 160)
                ));
            }
            if let Some(e) = f.evidence.first() {
                out.push_str(&format!(
                    "         proof : {} = {}\n",
                    cap_line(&collapse_ws(&e.source), 60),
                    cap_line(&collapse_ws(&e.value), 96)
                ));
            }
            // WS-WPT session 2: one-line wire-exchange summary under each finding when present.
            if let Some(line) = wire_txt_line(&f.exchange) {
                out.push_str(&format!("         wire  : {}\n", cap_line(&line, 160)));
            }
        }

        out.push('\n');
        out.push_str("See report.md / report.html for full detail.\n");
        out
    }
}

const SEV_ORDER: &[Severity] = &[
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

fn sev_name(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn sev_short(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED ",
        Severity::Low => "LOW ",
        Severity::Info => "INFO",
    }
}

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn cat_label(c: Category) -> &'static str {
    match c {
        Category::PrivilegedAccounts => "Privileged Accounts",
        Category::Trusts => "Trusts",
        Category::StaleObjects => "Stale Objects",
        Category::Anomalies => "Anomalies",
    }
}

fn affected_html(values: &[String]) -> String {
    if values.is_empty() {
        return "<span class=muted>none recorded</span>".into();
    }
    if values.len() <= 6 {
        let mut out = String::from("<ul class=list>");
        for value in values {
            out.push_str(&format!("<li>{}</li>", html_escape(value)));
        }
        out.push_str("</ul>");
        return out;
    }

    let mut out = String::new();
    let summary = format!("{} objects / principals", values.len());
    out.push_str(&format!(
        "<details><summary>{}</summary><ul class=list>",
        html_escape(&summary)
    ));
    for value in values {
        out.push_str(&format!("<li>{}</li>", html_escape(value)));
    }
    out.push_str("</ul></details>");
    out
}

pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn collapse_ws(s: &str) -> String {
    // Squash internal newlines/tabs so MD list items and TXT lines stay single-line.
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// WS-WPT session 2: HTML render for a finding's wire-exchange transcript. Returns "" when the
/// exchange is empty (renders as nothing — keeps the finding card compact for pre-WPT checks).
/// Rendered as an expandable `<details>` block so the report stays scannable but full transcripts
/// are one click away.
fn wire_html(exchange: &[adhammer_core::WireExchange]) -> String {
    if exchange.is_empty() {
        return String::new();
    }
    let rows: String = exchange
        .iter()
        .map(|w| {
            let arrow = match w.direction {
                adhammer_core::WireDirection::Sent => "→",
                adhammer_core::WireDirection::Recv => "←",
            };
            let opnum = w
                .opnum
                .map(|n| format!(" <span class=muted>opnum={n}</span>"))
                .unwrap_or_default();
            let hex = w
                .raw_hex
                .as_ref()
                .map(|h| format!("<div class=wire-hex><code>{}</code></div>", html_escape(h)))
                .unwrap_or_default();
            format!(
                "<div class=wire-frame><span class=chip>{layer:?}</span> <b>{arrow}</b> <code>{summary}</code>{opnum}{hex}</div>",
                layer = w.layer,
                arrow = arrow,
                summary = html_escape(&w.summary),
                opnum = opnum,
                hex = hex,
            )
        })
        .collect();
    format!(
        "<div class=meta><div class=k>Wire exchange</div><div><details class=wire><summary>{} frame(s) — click to expand</summary>{rows}</details></div></div>",
        exchange.len(),
    )
}

/// WS-WPT session 2: Markdown lines for the wire exchange under a finding. Empty string when
/// the finding has no exchange (pre-WPT checks). One `- wire: ...` bullet per frame.
fn wire_md(exchange: &[adhammer_core::WireExchange]) -> String {
    if exchange.is_empty() {
        return String::new();
    }
    let mut out = String::from("- Wire exchange:\n");
    for w in exchange {
        let arrow = match w.direction {
            adhammer_core::WireDirection::Sent => "→",
            adhammer_core::WireDirection::Recv => "←",
        };
        let opnum = w.opnum.map(|n| format!(" [opnum {n}]")).unwrap_or_default();
        out.push_str(&format!(
            "  - `{:?}` {arrow} {}{opnum}\n",
            w.layer,
            collapse_ws(&w.summary),
        ));
        if let Some(hex) = &w.raw_hex {
            out.push_str(&format!(
                "    - raw (hex, capped): `{}`\n",
                collapse_ws(hex)
            ));
        }
    }
    out
}

/// WS-WPT session 2: single one-liner for the text summary — "wire: LAYER → summary".
/// Empty when the finding has no exchange. Capped by the caller.
fn wire_txt_line(exchange: &[adhammer_core::WireExchange]) -> Option<String> {
    let first = exchange.first()?;
    let arrow = match first.direction {
        adhammer_core::WireDirection::Sent => "→",
        adhammer_core::WireDirection::Recv => "←",
    };
    Some(format!(
        "{:?} {} {}",
        first.layer,
        arrow,
        collapse_ws(&first.summary)
    ))
}

/// Truncate `s` to at most `max` chars (char-boundary safe), appending `…` when it was cut.
fn cap_line(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Best-effort UTC calendar date (`YYYY-MM-DD`) — no chrono dep; direct epoch math.
/// Falls back to `unknown-date` on a wall clock that predates the Unix epoch.
fn current_utc_date() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "unknown-date".into();
    };
    let days = (dur.as_secs() / 86_400) as i64;
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Civil-from-days algorithm (Howard Hinnant) — converts days-since-epoch to
/// proleptic-Gregorian (year, month, day). Handles pre/post 1970 uniformly.
fn days_to_ymd(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m as u32, d as u32)
}

/// Info-level guard so the compiler keeps Severity in scope for consumers.
pub const _MIN_SEVERITY: Severity = Severity::Info;

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_core::finding::{mitre, Category, Severity};

    fn mk_finding(id: &str, sev: Severity, title: &str) -> Finding {
        Finding {
            id: id.to_string(),
            title: title.to_string(),
            category: Category::Anomalies,
            severity: sev,
            mitre: vec![mitre::CERT_ABUSE],
            affected: vec!["CN=DC01,OU=Domain Controllers,DC=corp,DC=local".into()],
            evidence: Vec::new(),
            detail: "detected in test fixture".into(),
            impact: Some("test impact".into()),
            remediation: "test remediation".into(),
            weight_bonus: 0,
            exchange: Vec::new(),
        }
    }

    fn empty_report(findings: Vec<Finding>) -> Report {
        Report::build(
            "DC=corp,DC=local",
            findings,
            vec![],
            (0, 0),
            &RiskConfig::default(),
        )
    }

    #[test]
    fn coverage_matrix_renders_tripped_and_clean() {
        // WS-R2: a report with a coverage roster shows every check — tripped and clean —
        // in JSON, HTML, Markdown, and the text summary.
        let r = empty_report(vec![mk_finding(
            "A-Esc15",
            Severity::Critical,
            "tripped one",
        )])
        .with_coverage(vec![("A-Esc15", 1), ("A-CleanCheck", 0)]);
        let json = r.to_json();
        assert!(
            json.contains("\"coverage\""),
            "JSON carries a coverage array"
        );
        assert!(json.contains("A-CleanCheck"), "clean check listed in JSON");
        let html = r.to_html();
        assert!(html.contains("Check coverage"));
        assert!(html.contains("A-Esc15") && html.contains("A-CleanCheck"));
        assert!(html.contains("clean"), "clean status rendered in HTML");
        let md = r.to_markdown();
        assert!(md.contains("## Check coverage"));
        assert!(md.contains("| `A-CleanCheck` | clean |"));
        let txt = r.to_text_summary(10);
        assert!(txt.contains("Coverage: 2 checks run, 1 tripped, 1 clean"));
    }

    #[test]
    fn no_coverage_omits_section() {
        // Empty coverage → no section, no JSON field (skip_serializing_if).
        let r = empty_report(vec![mk_finding("A-X", Severity::Low, "x")]);
        assert!(!r.to_json().contains("\"coverage\""));
        assert!(!r.to_html().contains("Check coverage"));
        assert!(!r.to_markdown().contains("## Check coverage"));
    }

    #[test]
    fn html_includes_attack_graph_when_paths_present() {
        // WS-R1: the HTML report embeds the inline SVG graph panel when there are paths.
        use adhammer_graph::{AttackPath, Step};
        let path = AttackPath {
            principal: "bob".into(),
            principal_sid: "S-1-5-21-9-9-1101".into(),
            target: "Domain Admins".into(),
            cost: 1,
            steps: vec![Step {
                from: "bob".into(),
                from_sid: "S-1-5-21-9-9-1101".into(),
                edge: "GenericAll",
                to: "Domain Admins".into(),
                to_sid: "S-1-5-21-9-9-512".into(),
                impact: "",
                mitigation: "",
                command: Some("adhammer attack dcsync --user krbtgt".into()),
            }],
        };
        let r = Report::build(
            "DC=corp,DC=local",
            vec![],
            vec![path],
            (2, 1),
            &RiskConfig::default(),
        );
        let html = r.to_html();
        assert!(html.contains("Attack graph"));
        assert!(html.contains("<svg class=graph"));
    }

    #[test]
    fn html_carries_light_and_dark_theme_layers() {
        // The report ships a token-layered palette so it can render in both
        // light (default `:root`) and dark (`@media (prefers-color-scheme: dark)` +
        // `[data-theme="dark"]` override) — plus a toggle button + inline JS that flips the
        // `data-theme` attribute and remembers the choice in `localStorage`. Everything
        // self-contained: no CDN, no external CSS, matches the report's no-external-requests rule.
        let html = empty_report(vec![]).to_html();
        // Bare :root defines LIGHT (default). Any consumer with prefers-color-scheme unset gets it.
        assert!(
            html.contains(":root{color-scheme:light dark;--bg:#f7f8fc"),
            "light palette must be on bare :root as the default"
        );
        // prefers-color-scheme: dark path.
        assert!(
            html.contains("@media (prefers-color-scheme: dark)"),
            "dark palette must live under prefers-color-scheme"
        );
        // Explicit override selector for the toggle.
        assert!(
            html.contains(":root[data-theme=\"dark\"]"),
            "toggle must have a matching selector"
        );
        // Toggle UI + JS + localStorage.
        assert!(html.contains("class=theme-toggle"), "toggle button missing");
        assert!(
            html.contains("adhammer-theme"),
            "localStorage key for theme persistence missing"
        );
        // Tokens the JS/CSS both need — the sanity that no hardcoded hex remained on hop/code/cmd.
        assert!(html.contains("--code-bg") && html.contains("--hop-bg"));
        assert!(
            !html.contains("background:#0d1323"),
            "hardcoded code bg must be token-driven"
        );
    }

    #[test]
    fn baseline_diff_renders_and_tags_findings() {
        // WS-19: a report with a baseline attached tags NEW findings and carries a baseline_diff.
        let prior =
            empty_report(vec![mk_finding("A-Old", Severity::High, "was here before")]).to_json();
        let r = empty_report(vec![mk_finding("A-Fresh", Severity::Critical, "brand new")])
            .with_baseline(&prior, "prior.json")
            .unwrap();
        let md = r.to_markdown();
        assert!(md.contains("## Baseline diff"));
        assert!(md.contains("### [NEW] A-Fresh — brand new"));
        let json = r.to_json();
        assert!(json.contains("\"baseline_diff\""));
        assert!(json.contains("\"A-Old\"")); // resolved
        let txt = r.to_text_summary(10);
        assert!(txt.contains("Baseline (prior.json): +1 new / -1 resolved"));
        assert!(r.to_html().contains("Baseline diff"));
    }

    #[test]
    fn markdown_has_toc_and_severity_sections() {
        let r = empty_report(vec![
            mk_finding("P-DcsyncPath", Severity::Critical, "DCSync path present"),
            mk_finding("A-Esc1", Severity::High, "ESC1 template enrollable"),
        ]);
        let md = r.to_markdown();
        assert!(md.starts_with("# ADhammer report"));
        assert!(md.contains("## Contents"));
        assert!(md.contains("## Critical"));
        assert!(md.contains("## High"));
        assert!(md.contains("### P-DcsyncPath — DCSync path present"));
        assert!(md.contains("MITRE:"));
        assert!(md.contains("Remediation:"));
    }

    #[test]
    fn markdown_renders_ground_truth_evidence() {
        // WS-PROOF: a finding's structured Evidence must surface as verifiable rows in the report.
        let f = mk_finding("A-Rc4Kerberos", Severity::Medium, "RC4 Kerberos").with_evidence(
            "LDAP CN=svc,DC=corp:msDS-SupportedEncryptionTypes",
            "0x4 (RC4 only)",
        );
        let md = empty_report(vec![f]).to_markdown();
        assert!(md.contains("Evidence (ground truth):"));
        assert!(md.contains("msDS-SupportedEncryptionTypes"));
        assert!(md.contains("0x4 (RC4 only)"));
    }

    #[test]
    fn markdown_renders_present_chains() {
        let r = empty_report(vec![mk_finding(
            "A-Esc8",
            Severity::Critical,
            "ESC8 web enrollment",
        )]);
        let md = r.to_markdown();
        assert!(md.contains("## Attack chains"));
        assert!(md.contains("Coercion + ADCS ESC8"));
    }

    #[test]
    fn plaintext_summary_header_and_top_n() {
        let r = empty_report(vec![
            mk_finding("A-Esc8", Severity::Critical, "ESC8 present"),
            mk_finding("A-Foo", Severity::Low, "low finding"),
        ]);
        let txt = r.to_text_summary(10);
        assert!(txt.contains("ADhammer summary"));
        assert!(txt.contains("Total findings: 2"));
        assert!(txt.contains("Critical=1"));
        assert!(txt.contains("Low=1"));
        assert!(txt.contains("[CRIT]"));
        assert!(txt.contains("Chains: 1 present"));
        assert!(txt.contains("See report.md"));
    }

    #[test]
    fn wire_exchange_renders_in_html_md_and_txt() {
        // WS-WPT session 2: a finding with WireExchange renders in every text format.
        use adhammer_core::{WireExchange, WireLayer};
        let f = mk_finding("A-Rc4Kerberos", Severity::Medium, "RC4 Kerberos")
            .with_evidence(
                "LDAP CN=svc,DC=corp:msDS-SupportedEncryptionTypes",
                "0x4 (RC4 only)",
            )
            .with_wire(WireExchange::sent(
                WireLayer::Ldap,
                "search base=DC=corp filter=(&(objectClass=user)(servicePrincipalName=*))",
            ))
            .with_wires([WireExchange::recv(
                WireLayer::Ldap,
                "3 entries — 1 with msDS-SupportedEncryptionTypes=0x4",
            )]);
        let r = empty_report(vec![f]);

        let html = r.to_html();
        assert!(
            html.contains("Wire exchange"),
            "html missing wire block\n{html}"
        );
        assert!(
            html.contains("<details class=wire"),
            "html wire not <details>"
        );

        let md = r.to_markdown();
        assert!(
            md.contains("- Wire exchange:"),
            "md missing wire section\n{md}"
        );
        assert!(md.contains("`Ldap`"), "md wire missing layer label\n{md}");

        let txt = r.to_text_summary(5);
        assert!(txt.contains("wire  :"), "txt missing wire line\n{txt}");
    }

    #[test]
    fn plaintext_summary_carries_proof_and_impact_lines() {
        // WS-PROOF-70 part 2: every top-N finding shows impact + first evidence in the txt summary.
        let f = mk_finding("A-Rc4Kerberos", Severity::Medium, "RC4 Kerberos").with_evidence(
            "LDAP CN=svc,DC=corp:msDS-SupportedEncryptionTypes",
            "0x4 (RC4 only)",
        );
        let txt = empty_report(vec![f]).to_text_summary(5);
        assert!(
            txt.contains("impact:"),
            "expected 'impact:' line under finding\nfull txt:\n{txt}"
        );
        assert!(
            txt.contains("proof :"),
            "expected 'proof :' line under finding\nfull txt:\n{txt}"
        );
        assert!(txt.contains("msDS-SupportedEncryptionTypes"));
    }

    #[test]
    fn plaintext_summary_respects_n_cap() {
        let findings: Vec<Finding> = (0..15)
            .map(|i| mk_finding(&format!("A-F{i}"), Severity::Medium, &format!("f{i}")))
            .collect();
        let txt = empty_report(findings).to_text_summary(3);
        assert_eq!(txt.matches("[MED ]").count(), 3);
    }

    #[test]
    fn composite_chains_present_in_json() {
        let r = empty_report(vec![mk_finding("A-Esc8", Severity::Critical, "ESC8")]);
        let json = r.to_json();
        assert!(json.contains("\"composite_chains\""));
        assert!(json.contains("Coercion + ADCS ESC8"));
    }

    #[test]
    fn html_shows_attack_chains_when_present() {
        let r = empty_report(vec![mk_finding("A-Esc8", Severity::Critical, "ESC8")]);
        let html = r.to_html();
        assert!(html.contains("Attack chains"));
        assert!(html.contains("Coercion + ADCS ESC8"));
    }

    #[test]
    fn days_to_ymd_basic_calendar_math() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        assert_eq!(days_to_ymd(365), (1971, 1, 1)); // 1970 non-leap
        assert_eq!(days_to_ymd(59), (1970, 3, 1)); // 1970 has no leap day
        assert_eq!(days_to_ymd(365 + 365 + 31 + 29), (1972, 3, 1)); // 1972 leap
    }

    // ---- 1.4.7 WS-CLEAN-REPORT tests ----

    #[test]
    fn clean_bill_reports_no_findings() {
        let r = empty_report(vec![]).with_coverage(vec![
            ("A-Esc15", 0),
            ("P-KerberoastAdmin", 0),
            ("A-PasswordPolicy", 0),
        ]);
        assert!(r.is_clean_bill(), "empty findings = clean bill");
        let html = r.to_html();
        // Green assurance banner MUST appear.
        assert!(
            html.contains("No vulnerabilities identified"),
            "clean-bill HTML must render the green assurance banner"
        );
        // Counts sourced from WS-CTRLMAP roll-ups appear.
        assert!(
            html.contains("in-house control area"),
            "banner must reference the control-area taxonomy"
        );
        assert!(
            html.contains("attacker-lifecycle phase"),
            "banner must reference kill-chain phases"
        );
    }

    #[test]
    fn dirty_report_hides_assurance_banner() {
        let r = empty_report(vec![mk_finding("A-Esc15", Severity::Critical, "ESC15")])
            .with_coverage(vec![("A-Esc15", 1)]);
        assert!(!r.is_clean_bill(), "any finding = not a clean bill");
        let html = r.to_html();
        // Green banner MUST NOT appear on a dirty report — that would be misleading.
        assert!(
            !html.contains("No vulnerabilities identified"),
            "dirty report must not render the green banner"
        );
    }

    #[test]
    fn content_hash_is_deterministic_across_runs() {
        // Two reports built from the same inputs must hash identically — supports the
        // audit-trail workflow ("baseline sha256 vs current sha256 = same? no drift").
        let r1 = empty_report(vec![mk_finding("A-Esc15", Severity::Critical, "ESC15")])
            .with_coverage(vec![("A-Esc15", 1), ("P-KerberoastAdmin", 0)]);
        let r2 = empty_report(vec![mk_finding("A-Esc15", Severity::Critical, "ESC15")])
            .with_coverage(vec![("A-Esc15", 1), ("P-KerberoastAdmin", 0)]);
        let h1 = r1.content_hash();
        let h2 = r2.content_hash();
        assert_eq!(h1, h2, "identical inputs must hash identically");
        // Hash is a 64-hex-char sha256.
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn content_hash_differs_on_finding_change() {
        let r1 = empty_report(vec![mk_finding("A-Esc15", Severity::Critical, "ESC15")]);
        let r2 = empty_report(vec![mk_finding(
            "A-Esc15",
            Severity::High, // <-- severity change
            "ESC15",
        )]);
        assert_ne!(
            r1.content_hash(),
            r2.content_hash(),
            "changing severity must change the fingerprint"
        );
    }

    #[test]
    fn hash_footer_is_always_present_in_html() {
        // Renders on both clean and dirty reports — supports diffing either.
        let dirty =
            empty_report(vec![mk_finding("A-Esc15", Severity::Critical, "ESC15")]).to_html();
        let clean = empty_report(vec![]).to_html();
        assert!(dirty.contains("Report fingerprint"));
        assert!(dirty.contains("sha256"));
        assert!(clean.contains("Report fingerprint"));
        assert!(clean.contains("sha256"));
    }
}
