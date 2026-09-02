//! Live safe integration tests against a real DC. All are `#[ignore]`d so the normal
//! `cargo test` stays hermetic; run them explicitly against a lab:
//!
//!   ADH_DC=10.0.0.1 ADH_DOMAIN=CORP ADH_REALM=CORP.LOCAL \
//!   ADH_USER=Administrator ADH_PASS='...' cargo test -p adhammer --test live_safe -- --ignored --test-threads=1
//!
//! Optional per-test gates: `ADH_CA` (enum esc), `ADH_NETBIOS` (zerologon detect).

mod common;

use common::{dc, domain, env, pass, realm, run, user};

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
fn enum_esc_registry_checks() {
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
    let pw = pass();
    if pw.is_empty() {
        return;
    }
    let out = std::env::temp_dir().join("adh_asktgt.ccache");
    let Some(o) = run(&[
        "attack",
        "asktgt",
        "--user",
        &user(),
        "--realm",
        &realm(),
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
