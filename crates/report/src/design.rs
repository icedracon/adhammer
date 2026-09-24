//! Shared, self-contained visual system for every ADhammer HTML report.
//!
//! The CLI guided report and the passive report renderer both consume these
//! assets so new report capabilities cannot silently drift into a second,
//! visually incompatible HTML implementation.

/// Shared report CSS. Kept local and embedded so opening a report never makes
/// a network request or leaks a target/domain name to a CDN.
pub const PREMIUM_REPORT_CSS: &str = include_str!("../templates/premium_report.css");

/// Shared progressive-enhancement runtime. Core content remains readable when
/// JavaScript is disabled; this adds navigation, filtering, copy actions and
/// the real attack-path hero visual.
pub const PREMIUM_REPORT_JS: &str = include_str!("../templates/premium_report.js");
