//! Scoring + output. Aggregates findings into a per-category risk score (configurable
//! weights) and emits JSON or a standalone HTML report. No external template engine —
//! keeps the dependency surface small.

use adhammer_core::finding::{Category, Severity};
use adhammer_core::Finding;
use adhammer_graph::AttackPath;
use serde::Serialize;
use std::collections::BTreeMap;

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

#[derive(Serialize)]
pub struct Report {
    pub domain: String,
    pub total_score: u64,
    pub category_scores: BTreeMap<&'static str, u64>,
    pub findings: Vec<Finding>,
    pub top_paths: Vec<AttackPath>,
    pub graph_nodes: usize,
    pub graph_edges: usize,
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
        Report {
            domain: domain.into(),
            total_score,
            category_scores,
            findings,
            top_paths: paths.into_iter().take(25).collect(),
            graph_nodes: graph_stats.0,
            graph_edges: graph_stats.1,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    /// Minimal self-contained HTML — enough for the diploma appendix; style later.
    pub fn to_html(&self) -> String {
        let mut rows = String::new();
        for f in &self.findings {
            rows.push_str(&format!(
                "<tr><td>{sev:?}</td><td>{id}</td><td>{cat:?}</td><td>{title}</td><td>{n}</td></tr>",
                sev = f.severity,
                id = f.id,
                cat = f.category,
                title = html_escape(&f.title),
                n = f.affected.len(),
            ));
        }
        format!(
            "<!doctype html><meta charset=utf-8><title>ADhammer — {dom}</title>\
             <style>body{{font:14px system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}\
             td,th{{border:1px solid #ccc;padding:4px 8px;text-align:left}}\
             h1 small{{color:#888}}\
             .path{{border:1px solid #ccc;margin:1rem 0;padding:.5rem 1rem}}\
             .route{{font-weight:600}}\
             .hop{{margin:.5rem 0 .5rem 1rem;border-left:3px solid #ddd;padding-left:.75rem}}\
             .cmd{{font-family:ui-monospace,Consolas,monospace;background:#f4f4f4;padding:2px 6px;display:inline-block}}\
             .todo{{color:#a60;font-style:italic}}\
             .fix{{color:#060}}</style>\
             <h1>ADhammer report <small>{dom}</small></h1>\
             <p>Total risk score: <b>{score}</b> — graph: {nodes} nodes / {edges} edges</p>\
             <table><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Finding</th><th>#</th></tr>{rows}</table>\
             {paths}",
            dom = html_escape(&self.domain),
            score = self.total_score,
            nodes = self.graph_nodes,
            edges = self.graph_edges,
            rows = rows,
            paths = self.paths_html(),
        )
    }

    /// The kill-chain section: each route to Tier-0 hop by hop, with the command that walks
    /// the hop and the change that removes it.
    fn paths_html(&self) -> String {
        if self.top_paths.is_empty() {
            return String::new();
        }
        let mut out = String::from("<h2>Attack paths to Tier-0</h2>");
        for p in &self.top_paths {
            out.push_str(&format!(
                "<div class=path><div class=route>{route}</div>\
                 <div>cost {cost}{exec}</div>",
                route = html_escape(&p.render()),
                cost = p.cost,
                exec = if p.fully_executable() {
                    " · every hop is executable"
                } else {
                    ""
                },
            ));
            for (i, s) in p.steps.iter().enumerate() {
                let cmd = match &s.command {
                    Some(c) => format!("<div class=cmd>{}</div>", html_escape(c)),
                    None => "<div class=todo>no executor yet — detection only</div>".into(),
                };
                out.push_str(&format!(
                    "<div class=hop><b>{n}. {edge}</b> — {from} → {to}<br>{impact}<br>{cmd}\
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
            out.push_str("</div>");
        }
        out
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Info-level guard so the compiler keeps Severity in scope for consumers.
pub const _MIN_SEVERITY: Severity = Severity::Info;
