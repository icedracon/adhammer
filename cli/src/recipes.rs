//! T8 (1.6.1): typed quickstart/playbook recipes.
//!
//! Previously the `--examples` output was a hand-maintained `&'static str`
//! blob (see `QUICKSTART` in `main.rs`). This module defines the same recipes
//! as structured [`Recipe`] / [`Step`] values so they can be rendered as
//! either human text (default) or JSON (`--examples-json`), consumed by
//! tooling that wants to walk the catalog programmatically.
//!
//! The `QUICKSTART` const in `main.rs` stays — clap's `after_help` wants a
//! `&'static str` and the drift-guard test [`quickstart_text_matches_recipes`]
//! pins the const to the rendered-from-recipes text so they can never
//! silently diverge.
//!
//! When adding a new quickstart recipe: add it here AND update the matching
//! block in `QUICKSTART`. The drift test will fail the build until they agree.

use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub(crate) struct Step {
    /// Shell command the operator would copy-paste as-is.
    pub command: &'static str,
}

#[derive(Serialize, Clone, Debug)]
pub(crate) struct Recipe {
    /// Short slug — stable identifier, machine-friendly.
    pub name: &'static str,
    /// One-line human description matching the quickstart banner.
    pub description: &'static str,
    /// Ordered steps. Most recipes are single-step; `run --web --deep` style
    /// variants count as separate steps of the same recipe.
    pub steps: &'static [Step],
}

/// The quickstart catalog. Kept intentionally small (3 recipes) — this is the
/// zero-to-first-win set, not the full attack playbook. For the exhaustive
/// catalog see README.md under `## CLI methods`.
pub(crate) const RECIPES: &[Recipe] = &[
    Recipe {
        name: "blackbox",
        description: "Black-box (no creds) — discover + posture in one command",
        steps: &[
            Step { command: "adhammer run --domain corp.local --range 10.0.0.0/24" },
            Step { command: "adhammer run --domain corp.local --range 10.0.0.0/24 --web --deep" },
        ],
    },
    Recipe {
        name: "authenticated",
        description: "Authenticated — preflight, then a full scan to an HTML report",
        steps: &[
            Step { command: "adhammer doctor --url ldaps://dc.corp.local --user alice" },
            Step { command: "adhammer scan --url ldaps://dc.corp.local --user alice --out report.html" },
        ],
    },
    Recipe {
        name: "one-attack",
        description: "One attack — every finding prints its own copy-paste next command",
        steps: &[
            Step { command: "adhammer attack roast --url ldaps://dc.corp.local --user alice --kdc dc.corp.local" },
        ],
    },
];

/// Render RECIPES as the human text that matches the existing QUICKSTART const.
/// Used only by the drift-guard test — the live `--examples` path uses the
/// hand-maintained `QUICKSTART` string in `main.rs` so clap's `after_help`
/// can take a `&'static str` without a one-time heap allocation.
#[cfg(test)]
pub(crate) fn render_quickstart_text() -> String {
    let mut s = String::new();
    s.push_str(
        "QUICKSTART — copy-paste recipes (swap corp.local / dc.corp.local / alice for yours)\n\n",
    );
    for (idx, r) in RECIPES.iter().enumerate() {
        s.push_str("  ");
        s.push_str(r.description);
        s.push_str(":\n\n");
        for step in r.steps {
            s.push_str("    ");
            s.push_str(step.command);
            s.push('\n');
        }
        if idx + 1 < RECIPES.len() {
            s.push('\n');
        }
    }
    s.push_str("\n  Any verb: `adhammer <verb> --help`.\n");
    s
}

/// Render RECIPES as pretty JSON for machine consumption.
pub(crate) fn render_quickstart_json() -> String {
    serde_json::to_string_pretty(RECIPES).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_text_matches_hand_coded_quickstart() {
        // Drift guard: the hand-coded QUICKSTART const in main.rs must equal
        // what the typed recipes render to. If a future contributor edits one
        // without the other, this test fails the build.
        assert_eq!(render_quickstart_text(), crate::QUICKSTART);
    }

    #[test]
    fn render_json_is_parseable() {
        let out = render_quickstart_json();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), RECIPES.len());
    }

    #[test]
    fn every_recipe_has_a_step() {
        for r in RECIPES {
            assert!(!r.steps.is_empty(), "recipe {} has zero steps", r.name);
        }
    }
}
