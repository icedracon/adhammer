//! End-to-end SDK smoke test: build an empty Snapshot, run the checks, print the score.
//!
//! Demonstrates the intended library-shape: `use adhammer_sdk::{types, graph, checks}` and you
//! have the whole audit pipeline. Run with `cargo run -p adhammer-sdk --example audit_snapshot`.

use adhammer_sdk::{checks, graph, types::snapshot::DomainInfo, types::Snapshot};

fn main() {
    // A minimal empty domain — enough to prove the pipeline runs; no LDAP contacted.
    let domain = DomainInfo {
        domain_dn: "DC=corp,DC=local".into(),
        domain_sid: None,
        netbios: None,
        functional_level: None,
        machine_account_quota: None,
    };
    let snap = Snapshot::new(domain, Vec::new());

    let g = graph::ControlGraph::build(&snap);
    let findings = checks::run_all(&snap, &g);
    let (n, e) = g.stats();

    println!(
        "adhammer-sdk pipeline: {} object(s), graph {}n/{}e, {} finding(s)",
        snap.objects.len(),
        n,
        e,
        findings.len()
    );
    println!("(empty snapshot: expected 0 objects, 0 nodes/edges, 0 findings)");
    assert_eq!(snap.objects.len(), 0);
    println!("SDK smoke test OK.");
}
