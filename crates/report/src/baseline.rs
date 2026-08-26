//! WS-19 — baseline diff. Compare the current findings against a prior scan's JSON and tag each
//! `(rule id, affected object)` pair as NEW / RESOLVED / SEVERITY-CHANGED. Consumes only the fields
//! a report is guaranteed to carry (`findings[].{id,severity,affected}`), so it round-trips against
//! any adhammer JSON without coupling to the full `Finding` shape.

use adhammer_core::finding::Severity;
use adhammer_core::Finding;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The variant name serde emits for a severity — must match the JSON on disk exactly so a prior
/// scan's `"High"` compares equal to a current `Severity::High`.
fn sev_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

#[derive(Deserialize)]
struct PriorFinding {
    id: String,
    severity: String,
    #[serde(default)]
    affected: Vec<String>,
}

#[derive(Deserialize)]
struct PriorReport {
    #[serde(default)]
    findings: Vec<PriorFinding>,
}

/// One `(id, object)` pair that appeared or disappeared between the two scans.
#[derive(Serialize, Debug, Clone)]
pub struct DiffEntry {
    pub id: String,
    pub object: String,
    pub severity: String,
}

/// An `(id, object)` pair present in both scans whose severity moved.
#[derive(Serialize, Debug, Clone)]
pub struct SevChange {
    pub id: String,
    pub object: String,
    pub from: String,
    pub to: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct DiffSummary {
    pub new: usize,
    pub resolved: usize,
    pub severity_changed: usize,
    pub unchanged: usize,
}

/// The full baseline comparison, serialized into the report JSON as `baseline_diff`.
#[derive(Serialize, Debug, Clone)]
pub struct BaselineDiff {
    /// Label for the baseline the current scan was compared against (usually the file path).
    pub baseline: String,
    pub summary: DiffSummary,
    pub new: Vec<DiffEntry>,
    pub resolved: Vec<DiffEntry>,
    pub severity_changed: Vec<SevChange>,
}

impl BaselineDiff {
    /// Diff `current` findings against a prior scan's JSON text. Keys on `(id, affected object)`;
    /// a finding with no affected objects keys on `(id, "")`. Returns `Err` if the baseline JSON
    /// can't be parsed as a report with a `findings` array.
    pub fn compute(baseline_json: &str, current: &[Finding], label: &str) -> Result<Self, String> {
        let prior: PriorReport =
            serde_json::from_str(baseline_json).map_err(|e| format!("parse baseline: {e}"))?;

        let mut base: BTreeMap<(String, String), String> = BTreeMap::new();
        for f in prior.findings {
            if f.affected.is_empty() {
                base.insert((f.id.clone(), String::new()), f.severity.clone());
            } else {
                for o in f.affected {
                    base.insert((f.id.clone(), o), f.severity.clone());
                }
            }
        }

        let mut cur: BTreeMap<(String, String), String> = BTreeMap::new();
        for f in current {
            let sev = sev_str(f.severity).to_string();
            if f.affected.is_empty() {
                cur.insert((f.id.clone(), String::new()), sev.clone());
            } else {
                for o in &f.affected {
                    cur.insert((f.id.clone(), o.clone()), sev.clone());
                }
            }
        }

        let mut new = Vec::new();
        let mut severity_changed = Vec::new();
        let mut unchanged = 0usize;
        for ((id, object), sev) in &cur {
            match base.get(&(id.clone(), object.clone())) {
                None => new.push(DiffEntry {
                    id: id.clone(),
                    object: object.clone(),
                    severity: sev.clone(),
                }),
                Some(prev) if prev != sev => severity_changed.push(SevChange {
                    id: id.clone(),
                    object: object.clone(),
                    from: prev.clone(),
                    to: sev.clone(),
                }),
                Some(_) => unchanged += 1,
            }
        }
        let mut resolved = Vec::new();
        for ((id, object), sev) in &base {
            if !cur.contains_key(&(id.clone(), object.clone())) {
                resolved.push(DiffEntry {
                    id: id.clone(),
                    object: object.clone(),
                    severity: sev.clone(),
                });
            }
        }

        Ok(BaselineDiff {
            baseline: label.to_string(),
            summary: DiffSummary {
                new: new.len(),
                resolved: resolved.len(),
                severity_changed: severity_changed.len(),
                unchanged,
            },
            new,
            resolved,
            severity_changed,
        })
    }

    /// Rule ids that are *entirely* new (no `(id, *)` pair existed in the baseline) — used to tag
    /// whole findings `[NEW]` in the rendered report.
    pub fn new_ids(&self) -> BTreeSet<&str> {
        let mut resolved_or_changed: BTreeSet<&str> = BTreeSet::new();
        resolved_or_changed.extend(self.resolved.iter().map(|e| e.id.as_str()));
        resolved_or_changed.extend(self.severity_changed.iter().map(|e| e.id.as_str()));
        self.new
            .iter()
            .map(|e| e.id.as_str())
            .filter(|id| !resolved_or_changed.contains(id))
            .collect()
    }

    /// Rule ids with at least one severity change — tags a finding `[SEV CHANGED]`.
    pub fn sevchanged_ids(&self) -> BTreeSet<&str> {
        self.severity_changed
            .iter()
            .map(|e| e.id.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adhammer_core::finding::{Category, Severity};

    fn finding(id: &str, sev: Severity, affected: &[&str]) -> Finding {
        Finding {
            id: id.into(),
            title: id.into(),
            category: Category::Anomalies,
            severity: sev,
            mitre: vec![],
            affected: affected.iter().map(|s| s.to_string()).collect(),
            detail: String::new(),
            evidence: vec![],
            impact: None,
            remediation: String::new(),
            weight_bonus: 0,
            exchange: Vec::new(),
        }
    }

    fn baseline_json(findings: &[Finding]) -> String {
        // Mimic the report JSON shape the diff parses (only findings[].{id,severity,affected}).
        let items: Vec<String> = findings
            .iter()
            .map(|f| {
                let objs: Vec<String> = f.affected.iter().map(|o| format!("{o:?}")).collect();
                format!(
                    "{{\"id\":{:?},\"severity\":{:?},\"affected\":[{}]}}",
                    f.id,
                    sev_str(f.severity),
                    objs.join(",")
                )
            })
            .collect();
        format!("{{\"findings\":[{}]}}", items.join(","))
    }

    #[test]
    fn detects_new_resolved_and_severity_change() {
        let base = baseline_json(&[
            finding("A-Old", Severity::High, &["CN=a"]),
            finding("A-Shift", Severity::Low, &["CN=b"]),
        ]);
        let current = vec![
            finding("A-Shift", Severity::High, &["CN=b"]), // Low -> High
            finding("A-Fresh", Severity::Critical, &["CN=c"]),
        ];
        let d = BaselineDiff::compute(&base, &current, "prior.json").unwrap();
        assert_eq!(d.summary.new, 1);
        assert_eq!(d.summary.resolved, 1);
        assert_eq!(d.summary.severity_changed, 1);
        assert!(d.new.iter().any(|e| e.id == "A-Fresh"));
        assert!(d.resolved.iter().any(|e| e.id == "A-Old"));
        assert!(d
            .severity_changed
            .iter()
            .any(|e| e.id == "A-Shift" && e.from == "Low" && e.to == "High"));
        assert!(d.new_ids().contains("A-Fresh"));
        assert!(d.sevchanged_ids().contains("A-Shift"));
    }

    #[test]
    fn identical_scan_is_all_unchanged() {
        let f = vec![finding("A-Same", Severity::Medium, &["CN=x", "CN=y"])];
        let base = baseline_json(&f);
        let d = BaselineDiff::compute(&base, &f, "prior.json").unwrap();
        assert_eq!(d.summary.new, 0);
        assert_eq!(d.summary.resolved, 0);
        assert_eq!(d.summary.severity_changed, 0);
        assert_eq!(d.summary.unchanged, 2);
    }

    #[test]
    fn bad_json_errs() {
        assert!(BaselineDiff::compute("not json", &[], "x").is_err());
    }
}
