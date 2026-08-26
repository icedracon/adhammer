//! WS-PROOF-70 gate — **every finding any check emits carries `evidence` AND `impact`**.
//!
//! Fires the whole `registry()` against a "kitchen sink" snapshot crafted to trigger a broad
//! cross-section of rules, then walks every emitted `Finding` and asserts:
//!   - `!f.evidence.is_empty()`  (ground-truth artifact present)
//!   - `f.impact` is `Some(non-empty-string)`  (attack-chain narrative present)
//!
//! Any violation names the offending check id and finding title. **Adding a new check without an
//! Evidence + impact fails this test → CI blocks the PR** — the "for every future check" promise
//! from `.agents/adhammer-1.4.6-plan.md::WS-PROOF-70` made enforceable in code.

use adhammer_checks::run_all_with_coverage;
use adhammer_core::finding::Finding;
use adhammer_core::object::AdObject;
use adhammer_core::sid::Sid;
use adhammer_core::snapshot::{DomainInfo, Snapshot};
use adhammer_graph::ControlGraph;
use std::collections::HashMap;

/// Serialize a SID back to on-wire bytes so `snap.by_sid` finds it.
fn sid_bytes(s: &Sid) -> Vec<u8> {
    let mut b = vec![s.revision, s.sub_authorities.len() as u8];
    b.extend_from_slice(&[0, 0, 0, 0, 0, s.identifier_authority as u8]);
    for sub in &s.sub_authorities {
        b.extend_from_slice(&sub.to_le_bytes());
    }
    b
}

fn mk_obj(dn: &str, class: &str, attrs: &[(&str, &str)]) -> AdObject {
    let mut a: HashMap<String, Vec<String>> = HashMap::new();
    a.insert("objectClass".into(), vec![class.into()]);
    for (k, v) in attrs {
        a.entry((*k).into()).or_default().push((*v).into());
    }
    AdObject {
        dn: dn.into(),
        attrs: a,
        bin: HashMap::new(),
    }
}

fn mk_obj_with_sid(dn: &str, class: &str, attrs: &[(&str, &str)], sid: &Sid) -> AdObject {
    let mut o = mk_obj(dn, class, attrs);
    o.bin.insert("objectSid".into(), vec![sid_bytes(sid)]);
    o
}

fn kitchen_sink_snapshot() -> Snapshot {
    let domain_sid = Sid::parse("S-1-5-21-1-2-3").unwrap();
    let domain_dn = "DC=corp,DC=local".to_string();

    // Domain head — trips WeakPasswordPolicy + DomainReversiblePwd.
    let mut dom = mk_obj(
        &domain_dn,
        "domainDNS",
        &[
            ("minPwdLength", "7"),
            ("lockoutThreshold", "0"),
            ("maxPwdAge", "0"),
            ("pwdProperties", "0x10"), // DOMAIN_PASSWORD_STORE_CLEARTEXT
        ],
    );
    dom.dn = domain_dn.clone();

    // Trip DsHeuristics::AnonLdap — 7th char = '2'.
    let ds = mk_obj(
        "CN=Directory Service,CN=Configuration",
        "nTDSService",
        &[("dSHeuristics", "0000002")],
    );

    // User trippers — each crafted to hit one specific check.
    let asrep = mk_obj(
        "CN=lowpre,CN=Users,DC=corp,DC=local",
        "user",
        &[
            ("userAccountControl", "4194816"),
            ("sAMAccountName", "lowpre"),
        ], // 0x400200 (DONT_REQ_PREAUTH + NORMAL)
    );
    let roast_user = mk_obj(
        "CN=svc_sql,CN=Users,DC=corp,DC=local",
        "user",
        &[
            ("userAccountControl", "512"),
            ("sAMAccountName", "svc_sql"),
            ("servicePrincipalName", "MSSQLSvc/db01.corp.local:1433"),
        ],
    );
    let pwd_in_desc = mk_obj(
        "CN=bob,CN=Users,DC=corp,DC=local",
        "user",
        &[
            ("userAccountControl", "512"),
            ("sAMAccountName", "bob"),
            ("description", "svc pw: Summer2025!"),
        ],
    );
    let mut cleartext = mk_obj(
        "CN=alice,CN=Users,DC=corp,DC=local",
        "user",
        &[
            ("userAccountControl", "512"),
            ("sAMAccountName", "alice"),
            ("userPassword", "PlainSecret123!"),
        ],
    );
    cleartext
        .bin
        .insert("objectSid".into(), vec![sid_bytes(&domain_sid)]); // won't hurt, unused
    let reversible = mk_obj(
        "CN=carol,CN=Users,DC=corp,DC=local",
        "user",
        &[
            ("userAccountControl", "640"), // 0x80 | 0x200
            ("sAMAccountName", "carol"),
        ],
    );
    let pwd_notreqd = mk_obj(
        "CN=dave,CN=Users,DC=corp,DC=local",
        "user",
        &[
            ("userAccountControl", "544"), // 0x20 | 0x200
            ("sAMAccountName", "dave"),
        ],
    );
    let admin_delegatable = mk_obj(
        "CN=eve,CN=Users,DC=corp,DC=local",
        "user",
        &[
            ("userAccountControl", "512"),
            ("sAMAccountName", "eve"),
            ("adminCount", "1"),
        ],
    );
    let key_cred_admin = mk_obj(
        "CN=frank,CN=Users,DC=corp,DC=local",
        "user",
        &[
            ("userAccountControl", "512"),
            ("sAMAccountName", "frank"),
            ("adminCount", "1"),
            ("msDS-KeyCredentialLink", "B:32:0000...deadbeef:CN=whatever"),
        ],
    );
    let unconstrained = mk_obj(
        "CN=srv01,CN=Computers,DC=corp,DC=local",
        "computer",
        &[
            ("userAccountControl", "528384"), // 0x81000 (TRUSTED_FOR_DELEGATION + WORKSTATION_TRUST)
            ("sAMAccountName", "srv01$"),
            ("primaryGroupID", "515"),
        ],
    );
    let constrained_to_dc = mk_obj(
        "CN=svc-web,CN=Users,DC=corp,DC=local",
        "user",
        &[
            ("userAccountControl", "512"),
            ("sAMAccountName", "svc-web"),
            ("msDS-AllowedToDelegateTo", "cifs/dc01.corp.local"),
        ],
    );
    let dc = mk_obj(
        "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
        "computer",
        &[
            ("userAccountControl", "532480"), // 0x82000 SERVER_TRUST + WORKSTATION
            ("sAMAccountName", "DC01$"),
            ("dNSHostName", "dc01.corp.local"),
            ("primaryGroupID", "516"),
        ],
    );

    // Populated Domain Admins (RID 512) — required by ProtectedUsersUnused precondition.
    let mut da_subs = domain_sid.sub_authorities.clone();
    da_subs.push(512);
    let da_sid = Sid {
        revision: 1,
        identifier_authority: 5,
        sub_authorities: da_subs,
    };
    let mut da = mk_obj_with_sid(
        "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "group",
        &[("sAMAccountName", "Domain Admins")],
        &da_sid,
    );
    da.attrs.insert(
        "member".into(),
        vec!["CN=eve,CN=Users,DC=corp,DC=local".into()],
    );

    // Empty Protected Users (RID 525) → trips ProtectedUsersUnused.
    let mut pu_subs = domain_sid.sub_authorities.clone();
    pu_subs.push(525);
    let pu_sid = Sid {
        revision: 1,
        identifier_authority: 5,
        sub_authorities: pu_subs,
    };
    let pu = mk_obj_with_sid(
        "CN=Protected Users,CN=Users,DC=corp,DC=local",
        "group",
        &[("sAMAccountName", "Protected Users")],
        &pu_sid,
    );

    // Populated Schema Admins (RID 518) → trips SensitiveGroups.
    let mut sa_subs = domain_sid.sub_authorities.clone();
    sa_subs.push(518);
    let sa_sid = Sid {
        revision: 1,
        identifier_authority: 5,
        sub_authorities: sa_subs,
    };
    let mut sa = mk_obj_with_sid(
        "CN=Schema Admins,CN=Users,DC=corp,DC=local",
        "group",
        &[("sAMAccountName", "Schema Admins")],
        &sa_sid,
    );
    sa.attrs.insert(
        "member".into(),
        vec!["CN=eve,CN=Users,DC=corp,DC=local".into()],
    );

    // Trip BadSuccessor — a dMSA present in the directory.
    let dmsa = mk_obj(
        "CN=testDMSA,CN=Managed Service Accounts,DC=corp,DC=local",
        "msDS-DelegatedManagedServiceAccount",
        &[("sAMAccountName", "testDMSA$")],
    );

    Snapshot::new(
        DomainInfo {
            domain_dn: domain_dn.clone(),
            domain_sid: Some(domain_sid),
            netbios: Some("CORP".into()),
            functional_level: Some(7),
            machine_account_quota: Some(10),
        },
        vec![
            dom,
            ds,
            asrep,
            roast_user,
            pwd_in_desc,
            cleartext,
            reversible,
            pwd_notreqd,
            admin_delegatable,
            key_cred_admin,
            unconstrained,
            constrained_to_dc,
            dc,
            da,
            pu,
            sa,
            dmsa,
        ],
    )
}

/// The single assertion. If it panics, the failure message tells you WHICH check emitted a
/// finding without evidence or impact — no scrolling stack traces.
fn assert_provable(check_id: &'static str, f: &Finding) {
    assert!(
        !f.evidence.is_empty(),
        "WS-PROOF-70 violation: check `{}` emitted finding `{}` (\"{}\") with EMPTY evidence — every finding must carry ground-truth `Evidence`.",
        check_id, f.id, f.title,
    );
    let impact_ok = f.impact.as_deref().is_some_and(|s| !s.trim().is_empty());
    assert!(
        impact_ok,
        "WS-PROOF-70 violation: check `{}` emitted finding `{}` (\"{}\") with EMPTY/absent impact — every finding must carry an attack-chain narrative.",
        check_id, f.id, f.title,
    );
}

#[test]
fn every_finding_carries_evidence_and_impact() {
    let snap = kitchen_sink_snapshot();
    let graph = ControlGraph::build(&snap);
    let coverage = run_all_with_coverage(&snap, &graph);
    let mut total_findings = 0usize;
    let mut tripped_checks = 0usize;
    for (check_id, findings) in &coverage {
        if !findings.is_empty() {
            tripped_checks += 1;
        }
        for f in findings {
            total_findings += 1;
            assert_provable(check_id, f);
        }
    }
    // Sanity: the kitchen-sink is broad enough that at least a dozen checks trip. If this drops
    // below the guard, someone stripped fixture entries — refresh, don't lower the bar.
    assert!(
        tripped_checks >= 12,
        "kitchen-sink fixture only tripped {tripped_checks} checks; the fixture is too thin to stress WS-PROOF-70 (was expecting ≥12). Refresh the fixture.",
    );
    assert!(
        total_findings >= 12,
        "kitchen-sink fixture only produced {total_findings} findings; the fixture is too thin to stress WS-PROOF-70 (was expecting ≥12).",
    );
}
