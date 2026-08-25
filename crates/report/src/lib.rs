//! Scoring + output. Aggregates findings into a per-category risk score (configurable
//! weights) and emits JSON / HTML / Markdown / plain-text reports. No external template
//! engine — keeps the dependency surface small.

use adhammer_core::finding::{Category, Severity};
use adhammer_core::Finding;
use adhammer_graph::AttackPath;
use serde::Serialize;
use std::collections::BTreeMap;

pub mod composite;
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
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
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
             :root{{color-scheme:dark;--bg:#0b1020;--panel:#131a2c;--panel-2:#10172a;--line:#2c3657;--text:#e8edf7;--muted:#98a4c7;--green:#5be49b;--amber:#ffcf66;--red:#ff6b7f;--blue:#7cc9ff;}}\
             *{{box-sizing:border-box}}\
             body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 Inter,Segoe UI,system-ui,sans-serif}}\
             .wrap{{max-width:1240px;margin:0 auto;padding:32px 24px 56px}}\
             h1,h2,h3,p{{margin:0}}\
             code,pre{{font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace}}\
             code{{background:#0d1323;padding:3px 6px;border-radius:6px}}\
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
             .hop{{margin:12px 0 0;padding:12px 14px;border-left:3px solid var(--line);background:rgba(11,16,32,.45);border-radius:0 8px 8px 0}}\
             .hop-top{{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;flex-wrap:wrap}}\
             .cmd{{display:block;margin-top:10px;padding:10px 12px;background:#0d1323;border:1px solid var(--line);border-radius:8px;overflow:auto}}\
             .todo{{color:var(--amber);font-style:italic;margin-top:10px}}\
             .fix{{margin-top:10px;color:var(--green)}}\
             .chain{{padding:14px 16px;margin:0 0 12px}}\
             .chain p{{margin-top:6px;color:var(--muted)}}\
             @media (max-width:900px){{.stats{{grid-template-columns:repeat(2,minmax(140px,1fr))}} .sev-grid{{grid-template-columns:repeat(2,minmax(140px,1fr))}} .meta{{grid-template-columns:1fr}} .wrap{{padding:24px 18px 42px}}}}\
             </style>\
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
             <section class=panel><h2>Risk by category</h2><div class=score-grid>{scores}</div></section>\
             {chains}\
             <section class=panel><h2>Findings</h2><p>Each card shows why the condition matters, what it affects, and the shortest remediation text needed to brief an operator or stakeholder.</p></section>\
             {findings_html}\
             {paths}\
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
            scores = self.category_scores_html(),
            chains = self.chains_html(),
            findings_html = self.findings_html(),
            paths = self.paths_html(),
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
                       </div>\
                       <h3>{title}</h3>\
                       <div class=meta><div class=k>Why</div><div>{detail}</div></div>\
                       {evidence}\
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
                out.push_str(&format!("### {} — {}\n\n", f.id, f.title));
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

        let chain_hits: Vec<_> = self.composite_chains.iter().filter(|c| c.present).collect();
        out.push_str(&format!("Chains: {} present\n", chain_hits.len()));
        for c in &chain_hits {
            out.push_str(&format!("  - {} -> {}\n", c.title, c.impact));
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

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn collapse_ws(s: &str) -> String {
    // Squash internal newlines/tabs so MD list items and TXT lines stay single-line.
    s.split_whitespace().collect::<Vec<_>>().join(" ")
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
}
