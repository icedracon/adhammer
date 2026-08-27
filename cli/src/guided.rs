//! Guided exploitation: scan → correlate findings → for each weakness ask the operator
//! "validate + capture a PoC?" → run the matching attack → collect evidence → write a report.
//!
//! Declined and non-auto-validatable findings still land in the report (documented, not
//! exercised), so the deliverable is the complete picture. Terminal output is colored via `ui`;
//! the primary report is Markdown with the exact command + captured proof per validated finding,
//! plus sidecar JSON / HTML / text artifacts for automation, screenshots, and client handoff.

use crate::ui;
use adhammer_checks::run_all_with_coverage;
use adhammer_collector::{Collector, LdapConfig};
use adhammer_core::finding::{Category, Finding, Severity};
use adhammer_core::snapshot::Snapshot;
use adhammer_graph::ControlGraph;
use adhammer_report::CheckCoverage;
use anyhow::{Context, Result};
use dialoguer::{Confirm, Input};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

const PREMIUM_GUIDED_REPORT_TEMPLATE: &str =
    include_str!("../templates/premium_guided_report.html");

pub struct GuidedArgs {
    pub url: String,
    pub user: String,
    pub password: String,
    pub insecure: bool,
    pub host: Option<String>,
    pub domain: Option<String>,
    pub realm: Option<String>,
    pub kdc: Option<String>,
    pub out: String,
    /// Validate every finding without prompting (unattended runs).
    pub yes: bool,
    /// Skip the per-finding **Impact:** attack-chain narrative in the saved report artifacts.
    /// The interactive card still shows it either way.
    pub no_impact: bool,
}

/// Everything a validator needs to build an attack invocation.
struct Ctx {
    url: String,
    user: String,
    password: String,
    insecure: bool,
    host: String,
    domain: String,
    realm: String,
    kdc: String,
    ca: Option<String>,
}

impl Ctx {
    /// Bare sAMAccountName for RPC/SMB validators (DRSUAPI, AD CS): the LDAP bind identity may be
    /// a UPN (`user@realm`) or `DOMAIN\user`, but NTLM/Kerberos over SMB wants the plain name plus
    /// a separate `--domain`.
    fn sam_user(&self) -> String {
        if let Some((_, s)) = self.user.split_once('\\') {
            s.to_string()
        } else if let Some((s, _)) = self.user.split_once('@') {
            s.to_string()
        } else {
            self.user.clone()
        }
    }
}

enum Outcome {
    Validated { cmd: String, evidence: String },
    Attempted { cmd: String, evidence: String },
    Declined,
    Potential,
}

enum ExportChoice {
    FullBundle,
    SummaryOnly,
    Skip,
}

/// Flags whose value is credential material — value is replaced with
/// `<redacted>` before the argv shows up in the Markdown report the operator
/// hands to the client. Both `--flag value` and `--flag=value` forms handled.
const REDACT_FLAGS: &[&str] = &[
    "--password",
    "--nt-hash",
    "--account-password",
    "--krbtgt-aes256",
    "--service-aes256",
    "--aes256",
    "--aes128",
    "--restore",
    "--restore-password",
    "--rc4",
    "--ccache-password",
    "--key",
    "--key-pem",
];

/// Build a redacted `adhammer <argv>` display string safe to write into the
/// report. The real argv is still passed intact to the child process; only the
/// human-readable copy is scrubbed.
fn redacted_cmd(argv: &[String]) -> String {
    let mut out: Vec<String> = Vec::with_capacity(argv.len());
    let mut skip_next = false;
    for a in argv {
        if skip_next {
            out.push("<redacted>".to_string());
            skip_next = false;
            continue;
        }
        if let Some((flag, _)) = a.split_once('=') {
            if REDACT_FLAGS.contains(&flag) {
                out.push(format!("{flag}=<redacted>"));
                continue;
            }
        }
        if REDACT_FLAGS.contains(&a.as_str()) {
            out.push(a.clone());
            skip_next = true;
            continue;
        }
        out.push(a.clone());
    }
    format!("adhammer {}", out.join(" "))
}

#[cfg(test)]
mod redact_tests {
    use super::redacted_cmd;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn redacts_password_value_token() {
        let got = redacted_cmd(&v(&["attack", "spray", "--password", "Hunter2!"]));
        assert!(!got.contains("Hunter2!"));
        assert!(got.contains("--password <redacted>"));
    }

    #[test]
    fn redacts_inline_equals_form() {
        let got = redacted_cmd(&v(&["attack", "dcsync", "--nt-hash=aad3b435b51404ee"]));
        assert!(!got.contains("aad3b435b51404ee"));
        assert!(got.contains("--nt-hash=<redacted>"));
    }

    #[test]
    fn redacts_aes256_and_krbtgt_material() {
        let got = redacted_cmd(&v(&[
            "attack",
            "golden",
            "--krbtgt-aes256",
            "8a8415e2a4b4a89bda80b458c4d73da2",
            "--user",
            "Administrator",
        ]));
        assert!(!got.contains("8a8415e2"));
        assert!(got.contains("--user Administrator"));
    }

    #[test]
    fn leaves_non_sensitive_flags_alone() {
        let got = redacted_cmd(&v(&[
            "scan",
            "--url",
            "ldaps://dc.corp:636",
            "--user",
            "alice",
        ]));
        assert!(got.contains("--url ldaps://dc.corp:636"));
        assert!(got.contains("--user alice"));
    }
}

/// Public entry point — thin wrapper that owns the per-run [`ui::StageChecklist`] and
/// always renders the stages panel at end-of-run (success OR failure), so the operator
/// sees the full pipeline as a ✓/✗/NOT-ATTEMPTED checklist rather than a single opaque
/// error line. The heavy lifting lives in [`guided_impl`].
pub async fn guided(a: GuidedArgs) -> Result<()> {
    let mut checklist = ui::StageChecklist::new([
        "LDAP bind",
        "collect AD objects",
        "control-path graph",
        "security checks",
        "validate + PoC",
        "export bundle",
    ]);
    let result = guided_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("Stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .to_string();
            checklist.mark_current_failed(brief);
            checklist.render("Stages (failed)");
        }
    }
    result
}

async fn guided_impl(mut a: GuidedArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };

    let connect_host = a.host.clone().unwrap_or_else(|| url_host(&a.url));
    show_connection_summary(&connect_host, &a.user, a.insecure);

    // Step-by-step narration so the operator always sees what adhammer is doing right now.
    let bind_phase = ui::Phase::start(&format!(
        "step 1/4 - binding to {connect_host} as {}",
        a.user
    ));
    let mut c = connect_with_step_by_step(&cfg, &connect_host).await?;
    bind_phase.finish(ui::OutcomeKind::Validated, "LDAP bind established");
    checklist.record_ok("LDAP bind", format!("{connect_host} — established"));

    let collect_phase =
        ui::Phase::start("step 2/4 - collecting AD objects (users, groups, computers, GPOs, ACLs)");
    let sp = ui::Spinner::start("collecting AD objects (users, groups, computers, GPOs, ACLs)");
    let ca = c
        .read_cas()
        .await
        .ok()
        .and_then(|v| v.into_iter().next().map(|(n, _)| n));
    let snap = c.collect().await?;
    sp.done(&format!("{} objects collected", snap.objects.len()));
    collect_phase.finish(
        ui::OutcomeKind::Validated,
        &format!("{} directory object(s) collected", snap.objects.len()),
    );
    checklist.record_ok(
        "collect AD objects",
        format!("{} object(s)", snap.objects.len()),
    );

    let graph_phase = ui::Phase::start("step 3/4 - building control-path graph to Tier-0");
    let graph = ControlGraph::build(&snap);
    let paths = graph.paths_to_tier0();
    graph_phase.finish(
        ui::OutcomeKind::Validated,
        &format!("{} control-path(s) to Tier-0", paths.len()),
    );
    checklist.record_ok(
        "control-path graph",
        format!("{} path(s) to Tier-0", paths.len()),
    );

    let checks_phase = ui::Phase::start("step 4/4 - running supported security checks");
    // WS-0b: coverage roster in the guided/auto artifact — same call `scan` uses (WS-R2),
    // so the exported bundle carries the 58-check matrix (not just the tripped findings).
    let cov_raw = run_all_with_coverage(&snap, &graph);
    let coverage: Vec<CheckCoverage> = cov_raw
        .iter()
        .map(|(id, fs)| {
            // Populate title/impact/remediation/mitre from the first Finding when tripped,
            // fall back to describe_check() for clean rows (1.4.6 WS-COVERAGE-META).
            if let Some(f) = fs.first() {
                CheckCoverage {
                    id: (*id).to_string(),
                    findings: fs.len(),
                    title: f.title.clone(),
                    hypothetical_impact: f.impact.clone().unwrap_or_default(),
                    remediation: f.remediation.clone(),
                    mitre: f.mitre.iter().map(|m| m.id.to_string()).collect(),
                }
            } else {
                let m = adhammer_report::describe_check(id);
                CheckCoverage {
                    id: (*id).to_string(),
                    findings: 0,
                    title: m.title.into(),
                    hypothetical_impact: m.hypothetical_impact.into(),
                    remediation: m.remediation.into(),
                    mitre: m.mitre.iter().map(|s| s.to_string()).collect(),
                }
            }
        })
        .collect();
    let mut findings: Vec<Finding> = cov_raw.into_iter().flat_map(|(_, fs)| fs).collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.score()));
    let tripped = coverage.iter().filter(|c| c.findings > 0).count();
    let checks_summary = format!(
        "{} finding(s) · {} checks ran · {} tripped · {} clean",
        findings.len(),
        coverage.len(),
        tripped,
        coverage.len() - tripped
    );
    checklist.record_ok("security checks", checks_summary);
    checks_phase.finish(
        ui::OutcomeKind::Validated,
        &format!(
            "{} passive finding(s) — {} checks ran, {} tripped, {} clean",
            findings.len(),
            coverage.len(),
            tripped,
            coverage.len() - tripped
        ),
    );

    let ctx = Ctx {
        url: a.url.clone(),
        user: a.user.clone(),
        password: a.password.clone(),
        insecure: a.insecure,
        host: a.host.clone().unwrap_or_else(|| url_host(&a.url)),
        domain: a
            .domain
            .clone()
            .or_else(|| snap.domain.netbios.clone())
            .unwrap_or_else(|| netbios_from_dn(&snap.domain.domain_dn)),
        realm: a
            .realm
            .clone()
            .unwrap_or_else(|| dns_from_dn(&snap.domain.domain_dn).to_uppercase()),
        kdc: a
            .kdc
            .clone()
            .unwrap_or_else(|| a.host.clone().unwrap_or_else(|| url_host(&a.url))),
        ca,
    };

    // ESC registry misconfig probe (ESC6/7/10/11/16 via MS-RRP over SMB) — parity with `scan`, so
    // Auto runs EVERY detection, not just the LDAP-passive set. Non-fatal: the CA may be
    // unreachable, and a failed probe must never abort the guided run.
    if let Some(ca) = ctx.ca.clone() {
        let sp = ui::Spinner::start("probing CA registry for ESC6/7/10/11/16 (MS-RRP)");
        match crate::attacks::scan::esc_registry_probe(
            &ctx.host,
            &ctx.domain,
            &ctx.sam_user(),
            &ctx.password,
            std::slice::from_ref(&ca),
        )
        .await
        {
            Ok(mut esc) if !esc.is_empty() => {
                let n = esc.len();
                findings.append(&mut esc);
                findings.sort_by_key(|f| std::cmp::Reverse(f.score()));
                sp.done(&format!("{n} ESC registry finding(s)"));
            }
            Ok(_) => sp.done("CA registry clean (no ESC6/7/10/11/16)"),
            Err(e) => sp.done_warn(&format!("ESC registry probe skipped: {e}")),
        }
    }

    // Full severity-grouped summary of EVERY bug found (not just the validatable subset), so the
    // operator sees the complete picture before choosing which to demonstrate impact for.
    show_findings_summary(&findings, &ctx.realm);
    if findings.is_empty() {
        show_clean_state(&ctx.realm);
    }
    if a.yes {
        ui::info("--yes: validating every finding with an available PoC");
        if !a.no_impact {
            ui::info("--yes also includes every finding's Impact narrative in the saved artifacts");
        }
    }

    let exe = std::env::current_exe().context("locate adhammer binary")?;
    let mut results: Vec<(Finding, Outcome)> = Vec::new();
    // Findings whose Impact attack-chain narrative the operator asked to include in the report.
    let mut impact_yes: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Which findings have an automated validator (can be exercised for a real PoC).
    let validatable: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| validator(f, &ctx).is_some())
        .map(|(i, _)| i)
        .collect();

    // Batch impact selection: print a short numbered list of the validatable findings and let the
    // operator pick which to validate + demonstrate impact for in ONE step (instead of a y/n per
    // finding). `--yes` selects all; `--no-impact` / no-validatable / non-interactive selects none.
    let selected: std::collections::HashSet<usize> = if a.yes {
        validatable.iter().copied().collect()
    } else if validatable.is_empty() {
        std::collections::HashSet::new()
    } else {
        ui::header_err(&format!(
            "Scan found {} finding(s) — pick which to validate + demonstrate impact",
            findings.len()
        ));
        ui::note("Only supported findings with an automated validator are listed below.");
        for (n, &i) in validatable.iter().enumerate() {
            let f = &findings[i];
            let proof = proof_kind_for(f);
            let plan = validator(f, &ctx)
                .map(|(label, _, _)| label)
                .unwrap_or_default();
            eprintln!(
                "  {:>2}. {} {} {}",
                n + 1,
                sev_emoji(f.severity),
                severity_sticker(f.severity),
                ui::accent_err(&f.title),
            );
            ui::field_story_err(&ui::sticker("PROOF", ui::Tone::Good), proof, ui::Pace::Fast);
            ui::field_story_err(
                &ui::sticker("METHOD", ui::Tone::Accent),
                &plan,
                ui::Pace::Normal,
            );
            if let Some(impact) = &f.impact {
                ui::field_story_err(
                    &ui::sticker("IMPACT", ui::Tone::Warn),
                    impact,
                    ui::Pace::Important,
                );
            }
            if let Some(note) = validator_context_note(f, &ctx) {
                ui::field_story_err(
                    &ui::sticker("CONTEXT", ui::Tone::Dim),
                    &note,
                    ui::Pace::Normal,
                );
            }
            ui::hold_for(match f.severity {
                Severity::Critical => ui::Pace::Important,
                Severity::High => ui::Pace::Normal,
                Severity::Medium | Severity::Low | Severity::Info => ui::Pace::Fast,
            });
        }
        let unvalidatable = findings.len() - validatable.len();
        if unvalidatable > 0 {
            eprintln!(
                "  {}",
                ui::dim(&format!(
                    "(+{unvalidatable} without an automated validator — documented in the report)"
                ))
            );
        }
        let raw: String = Input::new()
            .with_prompt("Demonstrate impact for? [all / e.g. 1,3 / none]")
            .allow_empty(true)
            .default("all".to_string())
            .interact_text()
            .unwrap_or_else(|_| "none".to_string());
        parse_impact_selection(&raw, &validatable)
    };

    for (i, f) in findings.into_iter().enumerate() {
        let selected_here = selected.contains(&i);
        let outcome = match validator(&f, &ctx) {
            // No automated validator, or not chosen → documented in the report, but SILENT on
            // screen so the terminal stays focused on the impacts that actually ran + their proof.
            None => Outcome::Potential,
            Some((label, argv, marker)) => {
                if !selected_here {
                    Outcome::Declined
                } else {
                    // Only the findings the operator picked get the full card + impact + proof.
                    print_card(&f);
                    if !a.no_impact {
                        if let Some(imp) = &f.impact {
                            impact_yes.insert(f.id.clone());
                            ui::field_story_err(
                                &ui::sticker("IMPACT", ui::Tone::Warn),
                                imp,
                                ui::Pace::Important,
                            );
                        }
                    }
                    let sp = ui::Spinner::start(format!("running {label}"));
                    let cmd = redacted_cmd(&argv);
                    match Command::new(&exe).args(&argv).output() {
                        Ok(o) => {
                            // Confirm the *specific* proof is present, not just exit 0 — e.g. an
                            // actual `$krb5tgs$` hash, an ISSUED cert. Check the full (untruncated)
                            // output so evidence truncation can't cause a false negative.
                            let full = full_out(&o.stdout, &o.stderr);
                            let confirmed =
                                o.status.success() && (marker.is_empty() || full.contains(marker));
                            let ev = truncate(&full);
                            if confirmed {
                                sp.done("validated — PoC captured");
                                ui::proof_block(proof_kind_for(&f), &ev);
                                Outcome::Validated { cmd, evidence: ev }
                            } else {
                                sp.done_warn("attempted — proof not found (see report)");
                                ui::proof_block(proof_kind_for(&f), &ev);
                                Outcome::Attempted { cmd, evidence: ev }
                            }
                        }
                        Err(e) => {
                            sp.done_warn(&format!("failed to run validator: {e}"));
                            Outcome::Attempted {
                                cmd,
                                evidence: format!("failed to spawn: {e}"),
                            }
                        }
                    }
                }
            }
        };
        results.push((f, outcome));
    }

    // Opportunistic active checks that aren't part of the passive scan (network/ADCS). Each runs
    // a read/probe and only becomes a report finding when a weakness is actually confirmed.
    eprintln!();
    ui::header_err("Active checks (beyond the passive scan)");

    // LAPS local-admin read across the estate.
    {
        let mut argv = vec!["attack".to_string(), "laps".into()];
        argv.extend(ldap_args(&ctx));
        if a.yes || confirm("read LAPS local-admin passwords across the estate?") {
            let sp = ui::Spinner::start("LAPS local-admin read");
            let cmd = redacted_cmd(&argv);
            match Command::new(&exe).args(&argv).output() {
                Ok(o) => {
                    let full = full_out(&o.stdout, &o.stderr);
                    // Success = at least one recovered credential row (HOST$<TAB>account<TAB>pw).
                    let hit =
                        o.status.success() && full.lines().any(|l| l.matches('\t').count() >= 2);
                    if hit {
                        sp.done("validated — LAPS credentials recovered");
                        let ev = truncate(&full);
                        ui::proof_block("password", &ev);
                        results.push((laps_finding(), Outcome::Validated { cmd, evidence: ev }));
                    } else {
                        sp.done("no LAPS password readable — not exposed");
                    }
                }
                Err(e) => sp.done_warn(&format!("could not run: {e}")),
            }
        }
    }

    // AD CS ESC8 web-enrollment relay exposure.
    {
        let mut argv = vec!["enum".to_string(), "adcs".into()];
        argv.extend(ldap_args(&ctx));
        if a.yes || confirm("probe the CA(s) for ESC8 web-enrollment relay exposure?") {
            let sp = ui::Spinner::start("ADCS ESC8 web-enrollment probe");
            let cmd = redacted_cmd(&argv);
            match Command::new(&exe).args(&argv).output() {
                Ok(o) => {
                    let full = full_out(&o.stdout, &o.stderr);
                    let hit = o.status.success() && full.contains("exposes NTLM");
                    if hit {
                        sp.done("validated — ESC8 web enrollment exposed");
                        let ev = truncate(&full);
                        ui::proof_block("web enrollment proof", &ev);
                        results.push((esc8_finding(), Outcome::Validated { cmd, evidence: ev }));
                    } else {
                        sp.done("no ESC8 web-enrollment exposure");
                    }
                }
                Err(e) => sp.done_warn(&format!("could not run: {e}")),
            }
        }
    }

    // DC posture — LDAP signing / channel binding + Print Spooler (NTLM-relay + coercion enablers).
    {
        let argv = vec![
            "enum".to_string(),
            "posture".into(),
            "--host".into(),
            ctx.host.clone(),
            "--domain".into(),
            ctx.domain.clone(),
            "--user".into(),
            ctx.sam_user(),
            "--password".into(),
            ctx.password.clone(),
        ];
        if a.yes
            || confirm(
                "probe DC posture (LDAP signing / channel binding / Spooler = relay enablers)?",
            )
        {
            let sp = ui::Spinner::start("DC posture probe (MS-RRP + \\spoolss)");
            let cmd = redacted_cmd(&argv);
            match Command::new(&exe).args(&argv).output() {
                Ok(o) => {
                    let full = full_out(&o.stdout, &o.stderr);
                    let exposed = o.status.success()
                        && (full.contains("relayable")
                            || full.contains("Spooler")
                            || full.contains("not enforced"));
                    if exposed {
                        sp.done("validated — DC posture exposes relay/coercion enablers");
                        let ev = truncate(&full);
                        ui::proof_block("DC posture proof", &ev);
                        results.push((posture_finding(), Outcome::Validated { cmd, evidence: ev }));
                    } else {
                        sp.done("DC posture hardened (signing + channel binding, no Spooler)");
                    }
                }
                Err(e) => sp.done_warn(&format!("could not run: {e}")),
            }
        }
    }

    let artifacts = artifact_paths(&a.out);
    let report = build_report(&snap, &results, &impact_yes, &coverage);
    let json = build_json_report(&snap, &results, &impact_yes, &coverage);
    let html = build_html_report(&snap, &results, &impact_yes, &coverage);
    let txt = build_text_report(&snap, &results, &coverage);
    let export_choice = if a.yes {
        ExportChoice::FullBundle
    } else {
        prompt_export_choice()?
    };
    // Record the validate + PoC stage from the actual results tally (validated / declined /
    // potential). Skipped when the operator picked no findings AND nothing was auto-run.
    let (validated_n, attempted_n, declined_n, potential_n) = tally(&results);
    if validated_n + attempted_n + declined_n > 0 {
        checklist.record_ok(
            "validate + PoC",
            format!(
                "{validated_n} validated · {attempted_n} attempted · {declined_n} declined · {potential_n} potential"
            ),
        );
    } else {
        checklist.record_skipped("validate + PoC", "no findings selected for validation");
    }

    let exported = write_artifacts(export_choice, &artifacts, &report, &json, &html, &txt)?;
    if exported.is_empty() {
        checklist.record_skipped("export bundle", "export declined at prompt");
    } else {
        let paths: Vec<String> = exported.iter().map(|(k, _)| (*k).to_string()).collect();
        checklist.record_ok("export bundle", paths.join(" + "));
    }
    show_finish_card(&results, &impact_yes, &exported);
    Ok(())
}

/// Absolute, human-readable path (joins the CWD for a relative path) — so the operator can find
/// the report file. Avoids `std::fs::canonicalize`, which returns the ugly `\\?\` prefix on Windows.
fn abs_display(p: &Path) -> String {
    let ap = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    ap.display().to_string()
}

/// Map a finding to the attack that proves it (label + argv for the adhammer subcommand), or
/// `None` when there's no automated validator yet.
/// The shared `--url --user --password [--insecure]` block for LDAP-bound attacks.
fn ldap_args(c: &Ctx) -> Vec<String> {
    let mut v = vec![
        "--url".into(),
        c.url.clone(),
        "--user".into(),
        c.user.clone(),
        "--password".into(),
        c.password.clone(),
    ];
    if c.insecure {
        v.push("--insecure".into());
    }
    v
}

fn validator(f: &Finding, c: &Ctx) -> Option<(String, Vec<String>, &'static str)> {
    let ldap = || ldap_args(c);
    match f.id.as_str() {
        "P-AsrepRoast" | "P-KerberoastAdmin" | "P-KerberoastableUser" => {
            let mut v = vec!["attack".into(), "roast".into()];
            v.extend(ldap());
            v.extend(["--kdc".into(), c.kdc.clone()]);
            // The specific proof differs: an AS-REP finding needs a $krb5asrep$ hash, a
            // Kerberoast one needs $krb5tgs$ — exit 0 alone isn't proof either fired.
            let marker = if f.id == "P-AsrepRoast" {
                "$krb5asrep$"
            } else {
                "$krb5tgs$"
            };
            Some(("Kerberoast / AS-REP roast".into(), v, marker))
        }
        "P-GmsaRead" => {
            let target = affected_sam(f)?;
            let mut v = vec!["attack".into(), "gmsa".into()];
            v.extend(ldap());
            v.extend(["--target".into(), target]);
            Some(("gMSA managed-password read".into(), v, "NT hash recovered"))
        }
        "P-DcsyncPath" => {
            let v = vec![
                "attack".into(),
                "dcsync".into(),
                "--host".into(),
                c.host.clone(),
                "--domain".into(),
                c.domain.clone(),
                "--user".into(),
                c.sam_user(),
                "--password".into(),
                c.password.clone(),
                "--target".into(),
                "krbtgt".into(),
            ];
            Some(("DCSync (replicate krbtgt secret)".into(), v, "krbtgt:"))
        }
        "A-Esc1" => {
            let ca = c.ca.clone()?; // need a known CA
            let template = f.affected.first()?.clone();
            let v = vec![
                "attack".into(),
                "esc1".into(),
                "--host".into(),
                c.host.clone(),
                "--domain".into(),
                c.domain.clone(),
                "--user".into(),
                c.sam_user(),
                "--password".into(),
                c.password.clone(),
                "--ca".into(),
                ca,
                "--template".into(),
                template,
                "--upn".into(),
                format!("{}@{}", c.sam_user(), c.realm.to_lowercase()),
            ];
            Some((
                "AD CS ESC1 (enroll a cert as the target)".into(),
                v,
                "ISSUED",
            ))
        }
        _ => None,
    }
}

/// Parse a batch impact selection — `"all"` / `"none"` / `"1,3 5"` — into the set of finding
/// indices (into the full `findings` vec) the operator chose. `slots[list_position] = finding_idx`.
/// Empty / `none` / unparseable selects nothing; `all` selects every validatable finding.
fn parse_impact_selection(raw: &str, slots: &[usize]) -> std::collections::HashSet<usize> {
    let raw = raw.trim().to_lowercase();
    if raw.is_empty() || raw == "none" || raw == "n" || raw == "0" {
        return std::collections::HashSet::new();
    }
    if raw == "all" || raw == "a" || raw == "*" {
        return slots.iter().copied().collect();
    }
    raw.split([',', ' '])
        .filter_map(|tok| tok.trim().parse::<usize>().ok())
        .filter(|&n| (1..=slots.len()).contains(&n))
        .map(|n| slots[n - 1])
        .collect()
}

fn show_connection_summary(host: &str, user: &str, insecure: bool) {
    ui::header_err("Connection summary");
    ui::field_story_err("host", host, ui::Pace::Fast);
    ui::field_story_err("user", user, ui::Pace::Fast);
    ui::field_story_err(
        "ldaps",
        if insecure {
            "certificate verification skipped (lab mode)"
        } else {
            "certificate verification enabled"
        },
        ui::Pace::Normal,
    );
    ui::note_story(
        "Important moments will linger a bit longer; routine metadata moves faster.",
        ui::Pace::Important,
    );
    ui::hold_for(ui::Pace::Important);
}

fn show_clean_state(realm: &str) {
    ui::header_err("Clean pass");
    ui::field_story_err("realm", realm, ui::Pace::Fast);
    ui::field_story_err(
        "checked",
        "LDAP collection, control paths, supported passive checks",
        ui::Pace::Normal,
    );
    ui::field_story_err(
        "next",
        "Optional deeper actions remain: LAPS read, AD CS ESC8 probe, or export a clean summary",
        ui::Pace::Important,
    );
    ui::hold_for(ui::Pace::Important);
}

/// Severity-grouped roll-up of every finding — "Found N · Critical: a · b; High: c …" — so the
/// operator sees the whole picture (all passive + active detections), not only the validatable
/// ones, before the impact prompt.
fn show_findings_summary(findings: &[Finding], realm: &str) {
    if findings.is_empty() {
        ui::outcome(
            ui::OutcomeKind::Clean,
            &format!("no findings on {realm} — clean for every check run"),
        );
        return;
    }
    ui::header_err(&format!("Found {} finding(s) on {realm}", findings.len()));
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let names: Vec<&str> = findings
            .iter()
            .filter(|f| f.severity == sev)
            .map(|f| f.title.as_str())
            .collect();
        if names.is_empty() {
            continue;
        }
        eprintln!(
            "  {} {} ({}): {}",
            sev_emoji(sev),
            severity_sticker(sev),
            names.len(),
            names.join(" · ")
        );
        ui::beat_for(match sev {
            Severity::Critical => ui::Pace::Critical,
            Severity::High => ui::Pace::Important,
            Severity::Medium => ui::Pace::Normal,
            Severity::Low | Severity::Info => ui::Pace::Fast,
        });
    }
    ui::hold_for(ui::Pace::Important);
}

fn severity_sticker(s: Severity) -> String {
    match s {
        Severity::Critical => ui::sticker("CRITICAL", ui::Tone::Bad),
        Severity::High => ui::sticker("HIGH", ui::Tone::Warn),
        Severity::Medium => ui::sticker("MEDIUM", ui::Tone::Accent),
        Severity::Low => ui::sticker("LOW", ui::Tone::Dim),
        Severity::Info => ui::sticker("INFO", ui::Tone::Dim),
    }
}

/// A colored severity "sticker" for the findings list.
fn sev_emoji(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
        Severity::Info => "⚪",
    }
}

fn confirm(prompt: &str) -> bool {
    Confirm::new()
        .with_prompt(format!("  {prompt}"))
        .default(false)
        .interact()
        .unwrap_or(false)
}

fn proof_kind_for(f: &Finding) -> &'static str {
    match f.id.as_str() {
        "P-AsrepRoast" => "hash",
        "P-KerberoastAdmin" => "ticket hash",
        "P-DcsyncPath" => "replicated secret",
        "P-RbcdPath" | "P-ConstrainedDelegation" => "service ticket",
        "A-Esc1" => "certificate",
        "X-LapsRead" => "password",
        "X-Esc8" => "web enrollment proof",
        _ => "proof",
    }
}

fn validator_context_note(f: &Finding, c: &Ctx) -> Option<String> {
    match f.id.as_str() {
        "A-Esc1" if c.ca.is_none() => Some("needs CA context before validation".into()),
        "P-DcsyncPath" => Some("requires replication rights with current bind identity".into()),
        "P-RbcdPath" | "P-ConstrainedDelegation" => {
            Some("needs a controlled account and delegation path".into())
        }
        _ => None,
    }
}

/// Synthetic finding for a confirmed LAPS local-admin read (not a passive-scan rule).
fn laps_finding() -> Finding {
    Finding {
        id: "X-LapsRead".into(),
        title: "LAPS local-admin password readable".into(),
        category: Category::PrivilegedAccounts,
        severity: Severity::Critical,
        mitre: vec![adhammer_core::finding::mitre::VALID_ACCOUNTS],
        affected: vec![],
        // Proof is the captured `attack laps` output (the recovered password), shown + saved by the guided flow.
        evidence: Vec::new(),
        detail: "A LAPS-managed local administrator password was readable with the current identity — instant local admin, reusable for lateral movement.".into(),
        impact: None,
        remediation: "Restrict read access to ms-Mcs-AdmPwd / msLAPS-Password to tier-appropriate admins; deploy encrypted (DPAPI-NG) LAPS.".into(),
        weight_bonus: 0,
        exchange: Vec::new(),
    }
}

/// Synthetic finding for a confirmed ESC8 web-enrollment relay exposure.
fn esc8_finding() -> Finding {
    Finding {
        id: "X-Esc8".into(),
        title: "AD CS ESC8 — web-enrollment relay exposure".into(),
        category: Category::Anomalies,
        severity: Severity::Critical,
        mitre: vec![adhammer_core::finding::mitre::CERT_ABUSE],
        affected: vec![],
        // Proof is the captured `enum adcs` ESC8 probe output, shown + saved by the guided flow.
        evidence: Vec::new(),
        detail: "A CA exposes HTTP web enrollment with NTLM over cleartext — a coerced machine's NTLM can be relayed to it for a cert, then PKINIT for that machine's TGT.".into(),
        impact: None,
        remediation: "Disable HTTP web enrollment or require HTTPS + Extended Protection (EPA); enforce SMB/LDAP signing to blunt the relay.".into(),
        weight_bonus: 0,
        exchange: Vec::new(),
    }
}

/// Synthetic finding for confirmed DC relay/coercion posture exposure (from the `enum posture` probe).
fn posture_finding() -> Finding {
    Finding {
        id: "X-Posture".into(),
        title: "DC relay/coercion posture exposure (LDAP signing / channel binding / Spooler)".into(),
        category: Category::Anomalies,
        severity: Severity::High,
        mitre: vec![adhammer_core::finding::mitre::COERCION],
        affected: vec![],
        // Proof is the captured `enum posture` output, shown + saved by the guided flow.
        evidence: Vec::new(),
        detail: "The DC does not fully enforce LDAP signing / channel binding, and/or the Print Spooler is reachable — the exact preconditions for NTLM relay + coercion (PetitPotam/PrinterBug -> relay -> ADCS/LDAP).".into(),
        impact: None,
        remediation: "Require LDAP signing and enforce LDAP channel binding (EPA) on every DC; disable the Print Spooler service on DCs.".into(),
        weight_bonus: 0,
        exchange: Vec::new(),
    }
}

/// First affected entry that looks like a sAMAccountName (`name$` or a bare name, not a SID/DN).
fn affected_sam(f: &Finding) -> Option<String> {
    f.affected
        .iter()
        .map(|a| a.split([' ', '\t']).next().unwrap_or(a).trim().to_string())
        .find(|s| !s.is_empty() && !s.starts_with("S-1-") && !s.contains('='))
}

/// Full combined stdout+stderr (untruncated) — the success-marker is checked against this so
/// evidence truncation can never cause a false negative.
fn full_out(stdout: &[u8], stderr: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(stdout).into_owned();
    let e = String::from_utf8_lossy(stderr);
    if !e.trim().is_empty() {
        s.push('\n');
        s.push_str(&e);
    }
    s.trim().to_string()
}

/// Truncate captured evidence for the report (char-boundary-safe).
fn truncate(s: &str) -> String {
    if s.len() <= 6000 {
        return s.to_string();
    }
    let mut end = 6000;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n… (truncated)", &s[..end])
}

fn tally(r: &[(Finding, Outcome)]) -> (usize, usize, usize, usize) {
    let mut t = (0, 0, 0, 0);
    for (_, o) in r {
        match o {
            Outcome::Validated { .. } => t.0 += 1,
            Outcome::Attempted { .. } => t.1 += 1,
            Outcome::Declined => t.2 += 1,
            Outcome::Potential => t.3 += 1,
        }
    }
    t
}

// ---- presentation ---------------------------------------------------------------------

fn sev_tag(s: Severity) -> String {
    match s {
        Severity::Critical => ui::red_err("[CRITICAL]"),
        Severity::High => ui::yellow_err("[HIGH]"),
        Severity::Medium => ui::accent_err("[MEDIUM]"),
        Severity::Low => ui::sticker("LOW", ui::Tone::Dim),
        Severity::Info => ui::sticker("INFO", ui::Tone::Dim),
    }
}

fn cat_str(c: Category) -> &'static str {
    match c {
        Category::PrivilegedAccounts => "Privileged Accounts",
        Category::Trusts => "Trusts",
        Category::StaleObjects => "Stale Objects",
        Category::Anomalies => "Anomalies",
    }
}

fn mitre_str(f: &Finding) -> String {
    f.mitre
        .iter()
        .map(|m| format!("{} {}", m.id, m.name))
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_card(f: &Finding) {
    eprintln!();
    eprintln!("{} {}", sev_tag(f.severity), ui::accent_err(&f.title));
    ui::beat_for(match f.severity {
        Severity::Critical => ui::Pace::Important,
        Severity::High => ui::Pace::Normal,
        Severity::Medium | Severity::Low | Severity::Info => ui::Pace::Fast,
    });
    ui::field_story_err("id", &f.id, ui::Pace::Fast);
    ui::field_story_err("category", cat_str(f.category), ui::Pace::Fast);
    if !f.mitre.is_empty() {
        ui::field_story_err(
            &ui::sticker("MITRE", ui::Tone::Accent),
            &mitre_str(f),
            ui::Pace::Fast,
        );
    }
    if !f.affected.is_empty() {
        let n = f.affected.len();
        let shown = f
            .affected
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let extra = if n > 4 {
            format!(" (+{} more)", n - 4)
        } else {
            String::new()
        };
        ui::field_story_err(
            &ui::sticker("AFFECTED", ui::Tone::Warn),
            &format!("{shown}{extra}"),
            ui::Pace::Normal,
        );
    }
    ui::field_story_err(
        &ui::sticker("WHY", ui::Tone::Dim),
        &f.detail,
        ui::Pace::Important,
    );
    if !f.evidence.is_empty() {
        let shown: String = f
            .evidence
            .iter()
            .take(4)
            .map(|e| format!("{} = {}", e.source, e.value))
            .collect::<Vec<_>>()
            .join("   ·   ");
        let extra = if f.evidence.len() > 4 {
            format!(" (+{} more in report)", f.evidence.len() - 4)
        } else {
            String::new()
        };
        ui::field_story_err(
            &ui::sticker("PROOF", ui::Tone::Accent),
            &format!("{shown}{extra}"),
            ui::Pace::Normal,
        );
    }
    ui::hold_for(match f.severity {
        Severity::Critical => ui::Pace::Critical,
        Severity::High => ui::Pace::Important,
        Severity::Medium | Severity::Low | Severity::Info => ui::Pace::Normal,
    });
    // Impact is intentionally NOT printed here — it's shown per-finding via a
    // "want impact? (y/n)" prompt in the guided loop, so operators can pick which
    // findings to annotate before the terminal fills with narrative.
}

// ---- report ---------------------------------------------------------------------------

fn build_report(
    snap: &Snapshot,
    results: &[(Finding, Outcome)],
    impact_ids: &std::collections::HashSet<String>,
    coverage: &[CheckCoverage],
) -> String {
    let (v, at, d, p) = tally(results);
    let mut s = String::new();
    s.push_str("# ADhammer — guided assessment report\n\n");
    s.push_str(&format!("**Domain:** `{}`\n\n", snap.domain.domain_dn));
    s.push_str(&coverage_md_block(coverage));
    s.push_str(&format!(
        "**Summary:** {} finding(s) — **{v} validated (PoC)**, {at} attempted, {d} declined, {p} potential.\n\n",
        results.len()
    ));
    s.push_str("> Validated findings carry a reproducible PoC (exact command + captured output). ");
    s.push_str("Declined/potential findings are documented but were not exercised.\n\n");
    s.push_str("---\n\n");

    for (f, o) in results {
        let status = match o {
            Outcome::Validated { .. } => "✅ VALIDATED (PoC)",
            Outcome::Attempted { .. } => "⚠️ ATTEMPTED (not confirmed)",
            Outcome::Declined => "◻️ DECLINED (not exercised)",
            Outcome::Potential => "◽ POTENTIAL (no auto-validator)",
        };
        s.push_str(&format!(
            "## [{}] {} — {}\n\n",
            sev_word(f.severity),
            f.id,
            f.title
        ));
        s.push_str(&format!("- **Status:** {status}\n"));
        s.push_str(&format!("- **Category:** {}\n", cat_str(f.category)));
        if !f.mitre.is_empty() {
            s.push_str(&format!("- **MITRE ATT&CK:** {}\n", mitre_str(f)));
        }
        if !f.affected.is_empty() {
            s.push_str(&format!("- **Affected:** {}\n", f.affected.join(", ")));
        }
        s.push_str(&format!("- **Why:** {}\n", f.detail));
        // Only include the Impact line if the operator answered YES to the per-finding
        // prompt during the interactive walk.
        if impact_ids.contains(&f.id) {
            if let Some(imp) = &f.impact {
                s.push_str(&format!("- **Impact:** {imp}\n"));
            }
        }
        s.push_str(&format!("- **Remediation:** {}\n\n", f.remediation));
        match o {
            Outcome::Validated { cmd, evidence } | Outcome::Attempted { cmd, evidence } => {
                s.push_str("**PoC**\n\n");
                s.push_str(&format!("```\n$ {cmd}\n```\n\n"));
                s.push_str("<details><summary>captured output</summary>\n\n");
                s.push_str(&format!("```\n{evidence}\n```\n\n</details>\n\n"));
            }
            _ => {}
        }
        s.push_str("---\n\n");
    }
    s.push_str("_Generated by ADhammer — authorized testing / research only._\n");
    s
}

fn sev_word(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

#[derive(Serialize)]
struct GuidedArtifactReport {
    domain: String,
    summary: GuidedArtifactSummary,
    findings: Vec<GuidedArtifactFinding>,
    /// WS-0b: the 58-check coverage matrix (same shape as `scan`'s WS-R2 output), so the exported
    /// artifact carries "checked X, clean" not just the tripped findings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    coverage: Vec<CheckCoverage>,
}

/// WS-0b: shared coverage-matrix renderers so the guided/auto artifacts mirror the primary
/// `scan` report shape (`coverage_md` / `coverage_html` in `crates/report`).
fn coverage_md_block(cov: &[CheckCoverage]) -> String {
    if cov.is_empty() {
        return String::new();
    }
    let tripped = cov.iter().filter(|c| c.findings > 0).count();
    let clean = cov.len() - tripped;
    let mut out = format!(
        "## Check coverage\n\nAll {} passive checks ran — **{} tripped**, **{} clean**.\n\n| Check | Result |\n|---|---|\n",
        cov.len(), tripped, clean
    );
    for c in cov {
        let status = if c.findings > 0 {
            format!("{} finding(s)", c.findings)
        } else {
            "clean".to_string()
        };
        out.push_str(&format!("| `{}` | {} |\n", c.id, status));
    }
    out.push('\n');
    out
}

fn coverage_html_block(cov: &[CheckCoverage]) -> String {
    if cov.is_empty() {
        return String::new();
    }
    let tripped = cov.iter().filter(|c| c.findings > 0).count();
    let clean = cov.len() - tripped;
    let mut rows = String::new();
    for c in cov {
        let (klass, status) = if c.findings > 0 {
            ("tripped", format!("{} finding(s)", c.findings))
        } else {
            ("clean", "clean".to_string())
        };
        rows.push_str(&format!(
            "<tr class=\"cov-{klass}\"><td><code>{}</code></td><td>{status}</td></tr>",
            c.id.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        ));
    }
    format!(
        "<section class=\"panel\"><h2>Check coverage</h2>\
         <p>All {} passive checks ran — <b>{} tripped</b>, <b>{} clean</b>.</p>\
         <table class=\"cov\"><thead><tr><th>Check</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table>\
         </section>",
        cov.len(), tripped, clean
    )
}

fn coverage_text_line(cov: &[CheckCoverage]) -> String {
    if cov.is_empty() {
        return String::new();
    }
    let tripped = cov.iter().filter(|c| c.findings > 0).count();
    format!(
        "Coverage: {} checks ran, {} tripped, {} clean\n",
        cov.len(),
        tripped,
        cov.len() - tripped
    )
}

#[derive(Serialize)]
struct GuidedArtifactSummary {
    total: usize,
    validated: usize,
    attempted: usize,
    declined: usize,
    potential: usize,
}

#[derive(Serialize)]
struct GuidedArtifactFinding {
    id: String,
    title: String,
    severity: &'static str,
    category: &'static str,
    status: &'static str,
    mitre: Vec<String>,
    affected: Vec<String>,
    why: String,
    impact: Option<String>,
    remediation: String,
    command: Option<String>,
    evidence: Option<String>,
}

struct ArtifactPaths {
    markdown: PathBuf,
    json: PathBuf,
    html: PathBuf,
    text: PathBuf,
}

fn prompt_export_choice() -> Result<ExportChoice> {
    eprintln!();
    ui::header_err("Export");
    ui::menu_legend();
    eprintln!("  * 1. Export full bundle (HTML + JSON + Markdown + summary)");
    eprintln!("    2. Export summary only");
    eprintln!("    3. Skip export");
    let raw: String = Input::new()
        .with_prompt("Export choice [1-3, Enter=1]")
        .allow_empty(true)
        .interact_text()
        .unwrap_or_else(|_| "1".to_string());
    Ok(match raw.trim() {
        "" | "1" => ExportChoice::FullBundle,
        "2" => ExportChoice::SummaryOnly,
        "3" => ExportChoice::Skip,
        _ => ExportChoice::FullBundle,
    })
}

fn write_artifacts(
    choice: ExportChoice,
    artifacts: &ArtifactPaths,
    markdown: &str,
    json: &str,
    html: &str,
    text: &str,
) -> Result<Vec<(&'static str, String)>> {
    let mut exported = Vec::new();
    match choice {
        ExportChoice::FullBundle => {
            std::fs::write(&artifacts.markdown, markdown)
                .with_context(|| format!("write report {}", artifacts.markdown.display()))?;
            std::fs::write(&artifacts.json, json)
                .with_context(|| format!("write report {}", artifacts.json.display()))?;
            std::fs::write(&artifacts.html, html)
                .with_context(|| format!("write report {}", artifacts.html.display()))?;
            std::fs::write(&artifacts.text, text)
                .with_context(|| format!("write report {}", artifacts.text.display()))?;
            exported.push(("html", abs_display(&artifacts.html)));
            exported.push(("json", abs_display(&artifacts.json)));
            exported.push(("markdown", abs_display(&artifacts.markdown)));
            exported.push(("summary", abs_display(&artifacts.text)));
        }
        ExportChoice::SummaryOnly => {
            std::fs::write(&artifacts.text, text)
                .with_context(|| format!("write report {}", artifacts.text.display()))?;
            exported.push(("summary", abs_display(&artifacts.text)));
        }
        ExportChoice::Skip => {}
    }
    for (label, path) in &exported {
        ui::artifact(label, path);
    }
    if exported.is_empty() {
        ui::outcome(ui::OutcomeKind::Skipped, "export skipped");
    }
    Ok(exported)
}

fn show_finish_card(
    results: &[(Finding, Outcome)],
    impact_ids: &std::collections::HashSet<String>,
    exported: &[(&'static str, String)],
) {
    let (validated, attempted, declined, potential) = tally(results);
    let strongest = results
        .iter()
        .filter(|(_, outcome)| matches!(outcome, Outcome::Validated { .. }))
        .find_map(|(finding, _)| {
            impact_ids.contains(&finding.id).then(|| {
                finding
                    .impact
                    .as_ref()
                    .unwrap_or(&finding.title)
                    .to_string()
            })
        })
        .unwrap_or_else(|| {
            results
                .iter()
                .find(|(_, outcome)| matches!(outcome, Outcome::Validated { .. }))
                .map(|(finding, _)| finding.title.clone())
                .unwrap_or_else(|| "No impact validated in this run".to_string())
        });
    let export_line = if exported.is_empty() {
        "none".to_string()
    } else {
        exported
            .iter()
            .map(|(label, _)| (*label).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    ui::finish_card(
        "Run complete",
        &[
            ("validated", validated.to_string()),
            ("attempted", attempted.to_string()),
            ("declined", declined.to_string()),
            ("potential", potential.to_string()),
            ("strongest", strongest),
            ("exports", export_line),
            (
                "next",
                if validated > 0 {
                    "Open the HTML or summary artifact, then capture any manual follow-up needed for the validated path."
                        .to_string()
                } else {
                    "Review the clean/attempted paths, then decide whether to run a deeper single attack or export the summary."
                        .to_string()
                },
            ),
        ],
    );
}

fn artifact_paths(out: &str) -> ArtifactPaths {
    let markdown = PathBuf::from(out);
    ArtifactPaths {
        json: sibling_with_extension(&markdown, "json"),
        html: sibling_with_extension(&markdown, "html"),
        text: sibling_summary_path(&markdown),
        markdown,
    }
}

fn sibling_with_extension(path: &Path, ext: &str) -> PathBuf {
    let mut out = path.to_path_buf();
    out.set_extension(ext);
    out
}

fn sibling_summary_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("adhammer-report");
    parent.join(format!("{stem}-summary.txt"))
}

fn build_json_report(
    snap: &Snapshot,
    results: &[(Finding, Outcome)],
    impact_ids: &std::collections::HashSet<String>,
    coverage: &[CheckCoverage],
) -> String {
    let (validated, attempted, declined, potential) = tally(results);
    let findings = results
        .iter()
        .map(|(f, o)| GuidedArtifactFinding {
            id: f.id.clone(),
            title: f.title.clone(),
            severity: sev_word(f.severity),
            category: cat_str(f.category),
            status: outcome_label(o),
            mitre: f
                .mitre
                .iter()
                .map(|m| format!("{} {}", m.id, m.name))
                .collect(),
            affected: f.affected.clone(),
            why: f.detail.clone(),
            impact: if impact_ids.contains(&f.id) {
                f.impact.clone()
            } else {
                None
            },
            remediation: f.remediation.clone(),
            command: outcome_command(o),
            evidence: outcome_evidence(o),
        })
        .collect();
    let report = GuidedArtifactReport {
        domain: snap.domain.domain_dn.clone(),
        summary: GuidedArtifactSummary {
            total: results.len(),
            validated,
            attempted,
            declined,
            potential,
        },
        findings,
        coverage: coverage.to_vec(),
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
}

fn build_html_report(
    snap: &Snapshot,
    results: &[(Finding, Outcome)],
    impact_ids: &std::collections::HashSet<String>,
    coverage: &[CheckCoverage],
) -> String {
    let (validated, attempted, declined, potential) = tally(results);
    let domain_dns = dns_from_dn(&snap.domain.domain_dn);
    let domain_label = if domain_dns.is_empty() {
        snap.domain.domain_dn.as_str()
    } else {
        domain_dns.as_str()
    };
    let proof_rows = results
        .iter()
        .filter(|(_, o)| matches!(o, Outcome::Validated { .. } | Outcome::Attempted { .. }))
        .count();
    let validation_ratio = if results.is_empty() {
        0
    } else {
        ((validated + attempted + declined) * 100) / results.len()
    };
    let mut highlights = String::new();
    for (f, o) in results.iter().filter(|(f, o)| {
        impact_ids.contains(&f.id)
            && matches!(o, Outcome::Validated { .. } | Outcome::Attempted { .. })
    }) {
        let proof_tag = match o {
            Outcome::Validated { .. } => "validated",
            Outcome::Attempted { .. } => "attempted",
            Outcome::Declined | Outcome::Potential => "",
        };
        let impact = f.impact.as_deref().unwrap_or(&f.detail);
        highlights.push_str(&format!(
            "<article class=\"highlight highlight-{proof_tag}\">\
               <div class=\"badge-row\">\
                 <span class=\"badge sev sev-{sev}\">{sev_word}</span>\
                 <span class=\"badge outcome outcome-{proof_tag}\">{proof_tag}</span>\
                 <span class=\"badge ghost\">{id}</span>\
               </div>\
               <h3>{title}</h3>\
               <p>{impact}</p>\
             </article>",
            sev = sev_word(f.severity).to_ascii_lowercase(),
            sev_word = html_escape(sev_word(f.severity)),
            proof_tag = html_escape(proof_tag),
            id = html_escape(&f.id),
            title = html_escape(&f.title),
            impact = html_escape(impact),
        ));
    }
    if highlights.is_empty() {
        highlights = "<article class=\"highlight empty\"><h3>No validated impact recorded yet</h3><p>This run captured the passive findings and left the remaining items as potential, declined, or waiting for operator validation.</p></article>".into();
    }

    let mut body = String::new();
    body.push_str(&coverage_html_block(coverage));
    for (f, o) in results {
        let impact = if impact_ids.contains(&f.id) {
            f.impact
                .as_ref()
                .map(|s| {
                    format!(
                        "<div class=\"field\"><div class=\"k\">Impact</div><div class=\"v\">{}</div></div>",
                        html_escape(s)
                    )
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        let mitre = if f.mitre.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"field\"><div class=\"k\">MITRE</div><div class=\"v\">{}</div></div>",
                html_escape(&mitre_str(f))
            )
        };
        let affected = format!(
            "<div class=\"field\"><div class=\"k\">Affected</div><div class=\"v\">{}</div></div>",
            affected_html(&f.affected)
        );
        let proof = match o {
            Outcome::Validated { cmd, evidence } | Outcome::Attempted { cmd, evidence } => format!(
                "<section class=\"proof\">\
                   <div class=\"field\"><div class=\"k\">Command</div><div class=\"v\"><code>{}</code></div></div>\
                   <details><summary>Captured proof</summary><pre>{}</pre></details>\
                 </section>",
                html_escape(cmd),
                html_escape(evidence)
            ),
            _ => String::new(),
        };
        body.push_str(&format!(
            "<article class=\"finding finding-{sev}\">\
               <div class=\"head\">\
                 <div class=\"badge-row\">\
                   <span class=\"badge sev sev-{sev}\">{sev_word}</span>\
                   <span class=\"badge outcome outcome-{outcome}\">{outcome}</span>\
                   <span class=\"badge ghost\">{id}</span>\
                   <span class=\"badge ghost\">{category}</span>\
                 </div>\
                 <h2>{title}</h2>\
               </div>\
               <div class=\"field-grid\">\
                 {mitre}\
                 {affected}\
                 <div class=\"field\"><div class=\"k\">Why</div><div class=\"v\">{detail}</div></div>\
                 {impact}\
                 <div class=\"field\"><div class=\"k\">Remediation</div><div class=\"v\">{remediation}</div></div>\
               </div>\
               {proof}\
             </article>",
            sev = sev_word(f.severity).to_ascii_lowercase(),
            sev_word = html_escape(sev_word(f.severity)),
            outcome = html_escape(outcome_label(o)),
            id = html_escape(&f.id),
            category = html_escape(cat_str(f.category)),
            title = html_escape(&f.title),
            mitre = mitre,
            affected = affected,
            detail = html_escape(&f.detail),
            impact = impact,
            remediation = html_escape(&f.remediation),
            proof = proof,
        ));
    }
    let indexed = results.len();
    let exposed = results
        .iter()
        .map(|(f, _)| f.affected.len())
        .max()
        .unwrap_or(0);
    let crown_actions = if results.iter().any(|(f, _)| f.id == "P-DcsyncPath") {
        1
    } else if validated > 0 {
        2
    } else {
        0
    };
    let risk_hint = if results
        .iter()
        .any(|(f, o)| f.severity == Severity::Critical && matches!(o, Outcome::Validated { .. }))
    {
        "validated Tier-0 path"
    } else if results
        .iter()
        .any(|(f, _)| f.severity == Severity::Critical)
    {
        "critical exposure"
    } else if validated > 0 {
        "proof captured"
    } else if results.iter().any(|(f, _)| f.severity == Severity::High) {
        "high-risk findings"
    } else {
        "operator review"
    };
    PREMIUM_GUIDED_REPORT_TEMPLATE
        .replace("__DOMAIN__", &html_escape(domain_label))
        .replace(
            "__INTRO__",
            &html_escape("This report captures the supported findings observed during this ADhammer engagement, the validation paths the operator chose to run, and the proof gathered for each confirmed path. It is designed to read cleanly as a client-facing pentest deliverable while keeping commands and evidence close for technical review."),
        )
        .replace("__STATUS__", "scan complete")
        .replace("__INDEXED__", &indexed.to_string())
        .replace("__RISK_HINT__", risk_hint)
        .replace("__HUD_VALIDATED__", &format!("{validated:02}"))
        .replace("__HUD_EXPOSED__", &format!("{exposed:02}"))
        .replace("__HUD_ACTIONS__", &format!("{crown_actions:02}"))
        .replace("__STAT_TOTAL__", &results.len().to_string())
        .replace("__STAT_VALIDATED__", &validated.to_string())
        .replace("__STAT_ATTEMPTED__", &attempted.to_string())
        .replace("__STAT_DECLINED__", &declined.to_string())
        .replace("__STAT_POTENTIAL__", &potential.to_string())
        .replace("__STAT_RATIO__", &format!("{validation_ratio}%"))
        .replace(
            "__VALIDATED_COPY__",
            &html_escape("The strongest operator-ready moments from this run. These are the findings where ADhammer captured proof or at least completed an operator-visible validation attempt."),
        )
        .replace("__PROOF_ROWS__", &proof_rows.to_string())
        .replace("__HIGHLIGHTS__", &highlights)
        .replace(
            "__FINDINGS_COPY__",
            &html_escape("Each finding keeps the same reading order: what was observed, why it matters, impact when validation was selected, remediation, and proof when a validation path ran."),
        )
        .replace("__BODY__", &body)
        .replace(
            "__FOOTER__",
            &html_escape(&format!("{} · generated {}", domain_label, current_utc_date())),
        )
}

fn current_utc_date() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "unknown-date".to_string();
    };
    let days = (dur.as_secs() / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    format!("{year:04}-{m:02}-{d:02}")
}

fn build_text_report(
    snap: &Snapshot,
    results: &[(Finding, Outcome)],
    coverage: &[CheckCoverage],
) -> String {
    let (validated, attempted, declined, potential) = tally(results);
    let mut out = String::new();
    out.push_str(&format!(
        "ADhammer guided summary — {}\n\n",
        snap.domain.domain_dn
    ));
    out.push_str(&coverage_text_line(coverage));
    out.push_str(&format!(
        "Findings: {} total | {} validated | {} attempted | {} declined | {} potential\n\n",
        results.len(),
        validated,
        attempted,
        declined,
        potential
    ));
    for (f, o) in results {
        out.push_str(&format!(
            "[{}] {} — {}\n  status: {}\n",
            sev_word(f.severity),
            f.id,
            f.title,
            outcome_label(o)
        ));
    }
    out
}

fn outcome_label(o: &Outcome) -> &'static str {
    match o {
        Outcome::Validated { .. } => "validated",
        Outcome::Attempted { .. } => "attempted",
        Outcome::Declined => "declined",
        Outcome::Potential => "potential",
    }
}

fn outcome_command(o: &Outcome) -> Option<String> {
    match o {
        Outcome::Validated { cmd, .. } | Outcome::Attempted { cmd, .. } => Some(cmd.clone()),
        Outcome::Declined | Outcome::Potential => None,
    }
}

fn outcome_evidence(o: &Outcome) -> Option<String> {
    match o {
        Outcome::Validated { evidence, .. } | Outcome::Attempted { evidence, .. } => {
            Some(evidence.clone())
        }
        Outcome::Declined | Outcome::Potential => None,
    }
}

fn affected_html(values: &[String]) -> String {
    if values.is_empty() {
        return "<span class=\"muted\">none recorded</span>".into();
    }
    if values.len() <= 5 {
        let mut out = String::from("<ul class=\"list\">");
        for value in values {
            out.push_str(&format!("<li>{}</li>", html_escape(value)));
        }
        out.push_str("</ul>");
        return out;
    }

    let mut out = format!(
        "<details><summary>{} objects / principals</summary><ul class=\"list\">",
        values.len()
    );
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
        .replace('"', "&quot;")
}

// ---- small derivations ----------------------------------------------------------------

fn url_host(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Break an LDAP URL into (host, port, is_tls). Handles both `ldap://host:389` and
/// `ldaps://host:636`, defaulting the port to 389/636 when the URL omits it. Used by the
/// step-by-step connect diagnostic so the operator sees the exact target we're probing.
fn parse_url_target(url: &str) -> (String, u16, bool) {
    let is_tls = url.starts_with("ldaps://");
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let hostport = after_scheme.split('/').next().unwrap_or("");
    let mut parts = hostport.splitn(2, ':');
    let host = parts.next().unwrap_or("").to_string();
    let port = parts
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(if is_tls { 636 } else { 389 });
    (host, port, is_tls)
}

/// Wrap `Collector::connect` with step-by-step narration so a failure names the exact
/// stage that broke (TCP reachability vs LDAP bind) and prints an actionable "cause"
/// line — instead of a single opaque "I/O error: Connection reset by peer" the operator
/// can't diagnose. The first stage (TCP with a 5s timeout) separates "port closed / host
/// down / firewall" from "bind negotiation refused"; the second wraps the ldap3 connect
/// and pipes the anyhow chain through `diagnose_connection_error` for a specific hint.
async fn connect_with_step_by_step(cfg: &LdapConfig, host_hint: &str) -> Result<Collector> {
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let (parsed_host, port, is_tls) = parse_url_target(&cfg.url);
    let host = if parsed_host.is_empty() {
        host_hint.to_string()
    } else {
        parsed_host
    };
    let endpoint = format!("{host}:{port}");

    // Attempt summary — surface every knob so a failure is diagnosable without asking.
    ui::field_err("url", &cfg.url);
    ui::field_err("endpoint", &endpoint);
    ui::field_err("bind", &cfg.bind_dn);
    ui::field_err("tls", if is_tls { "yes (ldaps)" } else { "no (ldap)" });
    ui::field_err(
        "cert-verify",
        if cfg.insecure {
            "skipped (--insecure)"
        } else {
            "enforced (default; add --insecure for lab CAs)"
        },
    );
    ui::field_err(
        "sasl",
        if cfg.gssapi {
            "GSSAPI/Kerberos"
        } else {
            "simple (BIND w/ password)"
        },
    );

    // Stage 1: raw TCP — clarifies "port closed / firewall / down" vs "bind refused".
    let tcp = ui::Spinner::start(format!("stage 1/2 TCP connect {endpoint}"));
    match timeout(Duration::from_secs(5), TcpStream::connect(&endpoint)).await {
        Ok(Ok(_)) => tcp.done(&format!("TCP {endpoint} reachable")),
        Ok(Err(e)) => {
            tcp.done(&format!("TCP {endpoint} REFUSED"));
            return Err(anyhow::anyhow!(
                "TCP connect to {endpoint} failed: {e}\n  → cause: port closed / service not listening / firewall drop\n  → next: `nc -vz {host} {port}` from this host to confirm; if closed, verify DC service state or open the port"
            ));
        }
        Err(_) => {
            tcp.done(&format!("TCP {endpoint} TIMEOUT (>5s)"));
            return Err(anyhow::anyhow!(
                "TCP connect to {endpoint} timed out (5s)\n  → cause: firewall dropping packets, or a routing/NAT issue between this host and the DC\n  → next: `ping {host}` (or `traceroute {host}`) — if ping fails, it's the network path; if ping works but the port times out, it's a firewall rule"
            ));
        }
    }

    // Stage 2: full LDAP bind (TLS handshake + BIND + optional SASL). Only reached when
    // the TCP handshake proved the endpoint accepts connections at all.
    let bind = ui::Spinner::start("stage 2/2 LDAP bind (TLS handshake + BIND)");
    match Collector::connect(cfg).await {
        Ok(c) => {
            bind.done("LDAP bind established");
            Ok(c)
        }
        Err(e) => {
            bind.done("LDAP bind FAILED");
            let reason = format!("{e:#}");
            let diag = crate::interactive::diagnose_connection_error(&reason).unwrap_or(
                "unknown failure at the LDAP layer — verify --user format (DOMAIN\\user or user@REALM), the password, and (for LDAPS) the cert trust chain (or add --insecure for a lab CA)",
            );
            Err(anyhow::anyhow!("{reason}\n  → cause: {diag}"))
        }
    }
}

fn dns_from_dn(dn: &str) -> String {
    dn.split(',')
        .filter_map(|p| {
            let p = p.trim();
            p.strip_prefix("DC=").or_else(|| p.strip_prefix("dc="))
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn netbios_from_dn(dn: &str) -> String {
    dn.split(',')
        .find_map(|p| {
            let p = p.trim();
            p.strip_prefix("DC=").or_else(|| p.strip_prefix("dc="))
        })
        .unwrap_or("")
        .to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivations() {
        assert_eq!(url_host("ldaps://192.168.10.1:636"), "192.168.10.1");
        assert_eq!(dns_from_dn("DC=testlab,DC=local"), "testlab.local");
        assert_eq!(netbios_from_dn("DC=testlab,DC=local"), "TESTLAB");
    }

    #[test]
    fn parse_url_target_covers_scheme_and_default_ports() {
        // Explicit port.
        assert_eq!(
            parse_url_target("ldaps://dc.corp:636"),
            ("dc.corp".to_string(), 636, true)
        );
        assert_eq!(
            parse_url_target("ldap://dc.corp:389"),
            ("dc.corp".to_string(), 389, false)
        );
        // Default ports when omitted.
        assert_eq!(
            parse_url_target("ldaps://dc.corp"),
            ("dc.corp".to_string(), 636, true)
        );
        assert_eq!(
            parse_url_target("ldap://dc.corp"),
            ("dc.corp".to_string(), 389, false)
        );
        // Trailing path shouldn't confuse the parser.
        assert_eq!(
            parse_url_target("ldaps://dc.corp:636/dc=corp,dc=local"),
            ("dc.corp".to_string(), 636, true)
        );
        // IPv4 endpoint on non-standard port (the operator override case).
        assert_eq!(
            parse_url_target("ldap://10.0.0.1:1389"),
            ("10.0.0.1".to_string(), 1389, false)
        );
    }

    fn f(id: &str, affected: &[&str]) -> Finding {
        Finding {
            id: id.into(),
            title: "t".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![],
            affected: affected.iter().map(|s| s.to_string()).collect(),
            evidence: Vec::new(),
            detail: "d".into(),
            impact: None,
            remediation: "r".into(),
            weight_bonus: 0,
            exchange: Vec::new(),
        }
    }

    #[test]
    fn affected_sam_skips_sid_and_dn() {
        assert_eq!(
            affected_sam(&f("x", &["S-1-5-21-1-2-3-513", "svc_sql$", "CN=x,DC=y"])).as_deref(),
            Some("svc_sql$")
        );
    }

    #[test]
    fn roast_and_dcsync_have_validators() {
        let c = Ctx {
            url: "ldaps://dc:636".into(),
            user: "administrator".into(),
            password: "p".into(),
            insecure: true,
            host: "dc".into(),
            domain: "CORP".into(),
            realm: "CORP.LOCAL".into(),
            kdc: "dc".into(),
            ca: None,
        };
        assert!(validator(&f("P-KerberoastAdmin", &[]), &c).is_some());
        assert!(validator(&f("P-DcsyncPath", &[]), &c).is_some());
        assert!(validator(&f("A-Esc1", &["User"]), &c).is_none()); // no CA known → no validator
        assert!(validator(&f("S-Inactive", &[]), &c).is_none());
    }

    #[test]
    fn sam_user_strips_upn_and_netbios_prefix() {
        let mk = |u: &str| Ctx {
            url: "ldaps://dc:636".into(),
            user: u.into(),
            password: "p".into(),
            insecure: true,
            host: "dc".into(),
            domain: "CORP".into(),
            realm: "CORP.LOCAL".into(),
            kdc: "dc".into(),
            ca: None,
        };
        assert_eq!(mk("administrator@corp.local").sam_user(), "administrator");
        assert_eq!(mk("CORP\\administrator").sam_user(), "administrator");
        assert_eq!(mk("administrator").sam_user(), "administrator");
    }
}
