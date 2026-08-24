//! Guided exploitation: scan → correlate findings → for each weakness ask the operator
//! "validate + capture a PoC?" → run the matching attack → collect evidence → write a report.
//!
//! Declined and non-auto-validatable findings still land in the report (documented, not
//! exercised), so the deliverable is the complete picture. Terminal output is colored via `ui`;
//! the primary report is Markdown with the exact command + captured proof per validated finding,
//! plus sidecar JSON / HTML / text artifacts for automation and screenshots.

use crate::ui;
use adhammer_checks::run_all;
use adhammer_collector::{Collector, LdapConfig};
use adhammer_core::finding::{Category, Finding, Severity};
use adhammer_core::snapshot::Snapshot;
use adhammer_graph::ControlGraph;
use anyhow::{Context, Result};
use dialoguer::{Confirm, Input};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

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

pub async fn guided(mut a: GuidedArgs) -> Result<()> {
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };

    // Step-by-step narration so the operator always sees what adhammer is doing right now.
    ui::info(&format!(
        "step 1/4 · binding to {} as {}",
        a.host.clone().unwrap_or_else(|| url_host(&a.url)),
        a.user
    ));
    let mut c = Collector::connect(&cfg).await?;
    ui::ok("LDAP bind established");

    let sp = ui::Spinner::start(
        "step 2/4 · collecting AD objects (users · groups · computers · GPOs · ACLs)",
    );
    let ca = c
        .read_cas()
        .await
        .ok()
        .and_then(|v| v.into_iter().next().map(|(n, _)| n));
    let snap = c.collect().await?;
    sp.done(&format!("{} objects collected", snap.objects.len()));

    ui::info("step 3/4 · building control-path graph → Tier-0");
    let graph = ControlGraph::build(&snap);
    let paths = graph.paths_to_tier0();
    ui::ok(&format!("{} control-path(s) to Tier-0", paths.len()));

    ui::info("step 4/4 · running security checks");
    let mut findings = run_all(&snap, &graph); // already sorted by score, desc
    ui::ok(&format!("{} passive finding(s)", findings.len()));

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
        ui::header(&format!(
            "Scan found {} finding(s) — pick which to validate + demonstrate impact",
            findings.len()
        ));
        for (n, &i) in validatable.iter().enumerate() {
            let f = &findings[i];
            println!(
                "  {:>2}. {} {} {}  {}",
                n + 1,
                sev_emoji(f.severity),
                sev_tag(f.severity),
                ui::accent(&f.title),
                ui::dim(&format!("· {}", cat_str(f.category))),
            );
        }
        let unvalidatable = findings.len() - validatable.len();
        if unvalidatable > 0 {
            println!(
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
                            ui::field("impact", imp);
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
                                show_proof(&ev);
                                Outcome::Validated { cmd, evidence: ev }
                            } else {
                                sp.done_warn("attempted — proof not found (see report)");
                                show_proof(&ev);
                                Outcome::Attempted { cmd, evidence: ev }
                            }
                        }
                        Err(e) => {
                            sp.done_warn(&format!("could not run: {e}"));
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
    println!();
    ui::header("Active checks (beyond the passive scan)");

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
                        show_proof(&ev);
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
                        show_proof(&ev);
                        results.push((esc8_finding(), Outcome::Validated { cmd, evidence: ev }));
                    } else {
                        sp.done("no ESC8 web-enrollment exposure");
                    }
                }
                Err(e) => sp.done_warn(&format!("could not run: {e}")),
            }
        }
    }

    let (v, at, d, p) = tally(&results);
    println!();
    println!(
        "{}   {}   {}   {}",
        ui::green(&format!("✓ {v} validated")),
        ui::yellow(&format!("▲ {at} attempted")),
        ui::dim(&format!("◻ {d} declined")),
        ui::dim(&format!("◽ {p} potential"))
    );
    let artifacts = artifact_paths(&a.out);
    let report = build_report(&snap, &results, &impact_yes);
    let json = build_json_report(&snap, &results, &impact_yes);
    let html = build_html_report(&snap, &results, &impact_yes);
    let txt = build_text_report(&snap, &results);
    std::fs::write(&artifacts.markdown, report)
        .with_context(|| format!("write report {}", artifacts.markdown.display()))?;
    std::fs::write(&artifacts.json, json)
        .with_context(|| format!("write report {}", artifacts.json.display()))?;
    std::fs::write(&artifacts.html, html)
        .with_context(|| format!("write report {}", artifacts.html.display()))?;
    std::fs::write(&artifacts.text, txt)
        .with_context(|| format!("write report {}", artifacts.text.display()))?;
    println!();
    ui::ok("report bundle written — open the HTML in a browser:");
    ui::field("html", &abs_display(&artifacts.html));
    ui::field("json", &abs_display(&artifacts.json));
    ui::field("markdown", &abs_display(&artifacts.markdown));
    ui::field("summary", &abs_display(&artifacts.text));
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
        "P-AsrepRoast" | "P-KerberoastAdmin" => {
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

/// Severity-grouped roll-up of every finding — "Found N · Critical: a · b; High: c …" — so the
/// operator sees the whole picture (all passive + active detections), not only the validatable
/// ones, before the impact prompt.
fn show_findings_summary(findings: &[Finding], realm: &str) {
    if findings.is_empty() {
        ui::ok(&format!(
            "no findings on {realm} — clean for every check run"
        ));
        return;
    }
    ui::header(&format!("Found {} finding(s) on {realm}", findings.len()));
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
        println!(
            "  {} {} ({}): {}",
            sev_emoji(sev),
            sev_label(sev),
            names.len(),
            names.join(" · ")
        );
    }
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
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

/// Print the captured proof (ticket / hash / cert / shell output) inline under a validated finding,
/// so the operator sees the actual evidence — not just "PoC captured". Capped for the terminal; the
/// full evidence still lands in every report artifact.
fn show_proof(ev: &str) {
    let ev = ev.trim();
    if ev.is_empty() {
        return;
    }
    const MAX_LINES: usize = 12;
    const MAX_LEN: usize = 160;
    let lines: Vec<&str> = ev.lines().collect();
    println!("     {}", ui::dim("── proof ──"));
    for line in lines.iter().take(MAX_LINES) {
        let n = line.chars().count();
        let shown = if n > MAX_LEN {
            let head: String = line.chars().take(MAX_LEN).collect();
            format!("{head}…[+{} chars]", n - MAX_LEN)
        } else {
            (*line).to_string()
        };
        println!("     {}", ui::dim(&shown));
    }
    if lines.len() > MAX_LINES {
        println!(
            "     {}",
            ui::dim(&format!(
                "… (+{} more line(s) — full proof in the report)",
                lines.len() - MAX_LINES
            ))
        );
    }
}

fn confirm(prompt: &str) -> bool {
    Confirm::new()
        .with_prompt(format!("  {prompt}"))
        .default(false)
        .interact()
        .unwrap_or(false)
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
        detail: "A LAPS-managed local administrator password was readable with the current identity — instant local admin, reusable for lateral movement.".into(),
        impact: None,
        remediation: "Restrict read access to ms-Mcs-AdmPwd / msLAPS-Password to tier-appropriate admins; deploy encrypted (DPAPI-NG) LAPS.".into(),
        weight_bonus: 0,
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
        detail: "A CA exposes HTTP web enrollment with NTLM over cleartext — a coerced machine's NTLM can be relayed to it for a cert, then PKINIT for that machine's TGT.".into(),
        impact: None,
        remediation: "Disable HTTP web enrollment or require HTTPS + Extended Protection (EPA); enforce SMB/LDAP signing to blunt the relay.".into(),
        weight_bonus: 0,
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
        Severity::Critical => ui::red("[CRITICAL]"),
        Severity::High => ui::yellow("[HIGH]"),
        Severity::Medium => ui::accent("[MEDIUM]"),
        Severity::Low => ui::dim("[LOW]"),
        Severity::Info => ui::dim("[INFO]"),
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
    println!();
    println!("{} {}", sev_tag(f.severity), ui::accent(&f.title));
    ui::field("id", &f.id);
    ui::field("category", cat_str(f.category));
    if !f.mitre.is_empty() {
        ui::field("mitre", &mitre_str(f));
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
        ui::field("affected", &format!("{shown}{extra}"));
    }
    ui::field("why", &f.detail);
    // Impact is intentionally NOT printed here — it's shown per-finding via a
    // "want impact? (y/n)" prompt in the guided loop, so operators can pick which
    // findings to annotate before the terminal fills with narrative.
}

// ---- report ---------------------------------------------------------------------------

fn build_report(
    snap: &Snapshot,
    results: &[(Finding, Outcome)],
    impact_ids: &std::collections::HashSet<String>,
) -> String {
    let (v, at, d, p) = tally(results);
    let mut s = String::new();
    s.push_str("# ADhammer — guided assessment report\n\n");
    s.push_str(&format!("**Domain:** `{}`\n\n", snap.domain.domain_dn));
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
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
}

fn build_html_report(
    snap: &Snapshot,
    results: &[(Finding, Outcome)],
    impact_ids: &std::collections::HashSet<String>,
) -> String {
    let (validated, attempted, declined, potential) = tally(results);
    let mut body = String::new();
    for (f, o) in results {
        let impact = if impact_ids.contains(&f.id) {
            f.impact
                .as_ref()
                .map(|s| {
                    format!(
                        "<div class=\"meta\"><span class=\"k\">Impact</span><span class=\"v\">{}</span></div>",
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
                "<div class=\"meta\"><span class=\"k\">MITRE</span><span class=\"v\">{}</span></div>",
                html_escape(&mitre_str(f))
            )
        };
        let affected = if f.affected.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"meta\"><span class=\"k\">Affected</span><span class=\"v\">{}</span></div>",
                html_escape(&f.affected.join(", "))
            )
        };
        let proof = match o {
            Outcome::Validated { cmd, evidence } | Outcome::Attempted { cmd, evidence } => format!(
                "<div class=\"proof\"><div class=\"meta\"><span class=\"k\">Command</span><code>{}</code></div>\
                 <details><summary>Captured output</summary><pre>{}</pre></details></div>",
                html_escape(cmd),
                html_escape(evidence)
            ),
            _ => String::new(),
        };
        body.push_str(&format!(
            "<section class=\"finding\">\
               <div class=\"head\">\
                 <span class=\"sev sev-{}\">{}</span>\
                 <span class=\"status\">{}</span>\
               </div>\
               <h2>{} <small>{}</small></h2>\
               <div class=\"meta\"><span class=\"k\">Category</span><span class=\"v\">{}</span></div>\
               {}{}\
               <div class=\"meta\"><span class=\"k\">Why</span><span class=\"v\">{}</span></div>\
               {}\
               <div class=\"meta\"><span class=\"k\">Remediation</span><span class=\"v\">{}</span></div>\
               {}\
             </section>",
            sev_word(f.severity).to_ascii_lowercase(),
            html_escape(sev_word(f.severity)),
            html_escape(outcome_label(o)),
            html_escape(&f.title),
            html_escape(&f.id),
            html_escape(cat_str(f.category)),
            mitre,
            affected,
            html_escape(&f.detail),
            impact,
            html_escape(&f.remediation),
            proof,
        ));
    }
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>ADhammer guided report — {domain}</title>\
         <style>\
           :root {{ color-scheme: dark; --bg:#0b1020; --panel:#131a2c; --line:#2c3657; --text:#e8edf7; --muted:#98a4c7; --green:#5be49b; --amber:#ffcf66; --red:#ff6b7f; --blue:#7cc9ff; }}\
           * {{ box-sizing:border-box; }} body {{ margin:0; padding:32px; background:var(--bg); color:var(--text); font:15px/1.55 Inter,Segoe UI,system-ui,sans-serif; }}\
           h1,h2 {{ margin:0; }} .hero {{ margin-bottom:24px; }} .hero p {{ color:var(--muted); max-width:900px; }}\
           .stats {{ display:grid; grid-template-columns:repeat(5,minmax(120px,1fr)); gap:12px; margin:18px 0 28px; }}\
           .stat {{ background:var(--panel); border:1px solid var(--line); padding:14px 16px; border-radius:8px; }}\
           .stat b {{ display:block; font-size:24px; }} .stat span {{ color:var(--muted); font-size:12px; text-transform:uppercase; }}\
           .finding {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:18px 20px; margin:0 0 18px; }}\
           .head {{ display:flex; gap:10px; align-items:center; margin-bottom:10px; }} .sev,.status {{ padding:2px 8px; border-radius:999px; font-size:12px; font-weight:700; }}\
           .sev-critical {{ color:var(--red); border:1px solid var(--red); }} .sev-high {{ color:var(--amber); border:1px solid var(--amber); }} .sev-medium {{ color:var(--blue); border:1px solid var(--blue); }} .sev-low,.sev-info {{ color:var(--muted); border:1px solid var(--line); }}\
           .status {{ background:#10172a; border:1px solid var(--line); color:var(--muted); }}\
           h2 small {{ color:var(--muted); font-size:13px; font-weight:600; margin-left:8px; }}\
           .meta {{ display:grid; grid-template-columns:120px 1fr; gap:10px; margin:8px 0; }} .k {{ color:var(--muted); font-weight:600; }}\
           code,pre {{ font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace; }} code {{ background:#0d1323; padding:4px 6px; border-radius:6px; }}\
           pre {{ white-space:pre-wrap; background:#0d1323; border:1px solid var(--line); border-radius:8px; padding:14px; overflow:auto; }}\
           details summary {{ cursor:pointer; color:var(--blue); margin:8px 0 0; }}\
         </style>\
         <div class=\"hero\">\
           <h1>ADhammer guided report</h1>\
           <p>Domain <code>{domain}</code>. Guided mode ran the passive audit, then recorded which findings were validated, attempted, declined, or left potential.</p>\
           <div class=\"stats\">\
             <div class=\"stat\"><b>{total}</b><span>Total findings</span></div>\
             <div class=\"stat\"><b>{validated}</b><span>Validated</span></div>\
             <div class=\"stat\"><b>{attempted}</b><span>Attempted</span></div>\
             <div class=\"stat\"><b>{declined}</b><span>Declined</span></div>\
             <div class=\"stat\"><b>{potential}</b><span>Potential</span></div>\
           </div>\
         </div>{body}",
        domain = html_escape(&snap.domain.domain_dn),
        total = results.len(),
        validated = validated,
        attempted = attempted,
        declined = declined,
        potential = potential,
        body = body,
    )
}

fn build_text_report(snap: &Snapshot, results: &[(Finding, Outcome)]) -> String {
    let (validated, attempted, declined, potential) = tally(results);
    let mut out = String::new();
    out.push_str(&format!(
        "ADhammer guided summary — {}\n\n",
        snap.domain.domain_dn
    ));
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

    fn f(id: &str, affected: &[&str]) -> Finding {
        Finding {
            id: id.into(),
            title: "t".into(),
            category: Category::PrivilegedAccounts,
            severity: Severity::High,
            mitre: vec![],
            affected: affected.iter().map(|s| s.to_string()).collect(),
            detail: "d".into(),
            impact: None,
            remediation: "r".into(),
            weight_bonus: 0,
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
