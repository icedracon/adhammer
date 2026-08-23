//! `scan --anonymous` — first-touch fingerprint. No creds, no ACL walk. Emits
//! a smaller anonymous-mode report built from four passive sources:
//!
//! 1. Port scan against the target host (common AD-adjacent ports).
//! 2. Anonymous LDAP RootDSE bind (defaultNamingContext / dnsHostName /
//!    supportedControl / supportedSASLMechanisms — always readable on AD).
//! 3. Null-session SMB negotiate against the target (signing posture).
//! 4. SRV enumeration for `_ldap._tcp.dc._msdcs.<domain>` via raw UDP DNS
//!    against the target host (which is almost always also a DNS server on AD).
//!
//! Runs alongside the authenticated `scan` path — the flag simply routes
//! `scan()` into `run()` before `Collector::connect`.

use anyhow::{anyhow, Result};

use adhammer_collector::{dns_from_nc, read_rootdse_anonymous};
use adhammer_core::finding::{Category, Severity};
use adhammer_core::Finding;

/// Bundle of results collected in anonymous mode. Fed into the report crate as
/// a `Vec<Finding>` so downstream JSON/HTML/MD/TXT rendering is unchanged.
pub struct AnonymousReport {
    pub host: String,
    pub domain: String,
    pub findings: Vec<Finding>,
}

pub async fn run(url: &str, insecure: bool) -> Result<AnonymousReport> {
    let host = host_of(url)?;

    let mut findings = Vec::new();

    // 1. Port scan.
    let open = port_scan(&host).await;
    if !open.is_empty() {
        let list = open
            .iter()
            .map(|(p, s)| format!("{p}/{s}"))
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding {
            id: "F-OpenPorts".into(),
            title: format!("{} open service(s) on target", open.len()),
            category: Category::Anomalies,
            severity: Severity::Info,
            mitre: vec![],
            affected: vec![host.clone()],
            detail: format!("open: {list}"),
            impact: None,
            remediation: "External attack surface — restrict inbound to management scope.".into(),
            weight_bonus: 0,
        });
    }

    // 2. Anonymous LDAP RootDSE.
    let mut domain = String::new();
    match read_rootdse_anonymous(url, insecure).await {
        Ok(rd) => {
            domain = dns_from_nc(&rd.default_nc);
            let mut detail = format!(
                "defaultNamingContext={} · dnsHostName={} · serverName={} · controls={} · SASL={}",
                rd.default_nc,
                rd.dns_host,
                rd.server_name,
                rd.controls_count,
                rd.sasl.join(",")
            );
            if rd.anon_subtree_hit > 0 {
                detail.push_str(&format!(
                    " · WARNING: anonymous subtree returned {} object(s) (legacy 2003/2008 exposure)",
                    rd.anon_subtree_hit
                ));
            }
            let sev = if rd.anon_subtree_hit > 0 {
                Severity::High
            } else {
                Severity::Info
            };
            findings.push(Finding {
                id: "F-RootDSE".into(),
                title: "RootDSE fingerprint (anonymous LDAP bind)".into(),
                category: Category::Anomalies,
                severity: sev,
                mitre: vec![],
                affected: vec![host.clone()],
                detail,
                impact: (rd.anon_subtree_hit > 0).then(|| {
                    "Anonymous readers can enumerate directory objects — pre-auth recon material."
                        .into()
                }),
                remediation:
                    "Set dSHeuristics 7th char to 0 (default) to disable anonymous subtree read."
                        .into(),
                weight_bonus: 0,
            });
        }
        Err(e) => tracing::warn!(%e, "RootDSE anonymous read failed"),
    }

    // 3. Null-session SMB negotiate.
    if let Ok(mut c) = smb2_client::SmbClient::connect(&host).await {
        if let Ok((d, req)) = c.probe_signing().await {
            let sev = if req { Severity::Info } else { Severity::High };
            let title = if req {
                "SMB signing REQUIRED".to_string()
            } else {
                "SMB signing NOT required — NTLM-relay target".to_string()
            };
            findings.push(Finding {
                id: "F-SmbSigning".into(),
                title,
                category: Category::Anomalies,
                severity: sev,
                mitre: vec![],
                affected: vec![host.clone()],
                detail: format!("negotiate SecurityMode=0x{d:04x}, required={req}"),
                impact: (!req).then(|| {
                    "Coerced auth (PetitPotam / PrinterBug) can be relayed to this host for SMB code execution.".into()
                }),
                remediation: "Enforce SMB signing on every server and DC via GPO.".into(),
                weight_bonus: 0,
            });
        }
    }

    // 4. SRV enumeration for `_ldap._tcp.dc._msdcs.<domain>` — only if we
    //    got a domain from RootDSE.
    if !domain.is_empty() {
        let q = format!("_ldap._tcp.dc._msdcs.{domain}");
        if let Some(hits) = dns_srv(&host, &q).await {
            if !hits.is_empty() {
                let detail = hits
                    .iter()
                    .map(|(pri, w, port, tgt)| format!("{tgt}:{port} (prio={pri} weight={w})"))
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push(Finding {
                    id: "F-SrvLdap".into(),
                    title: format!("{} DC record(s) via SRV lookup", hits.len()),
                    category: Category::Anomalies,
                    severity: Severity::Info,
                    mitre: vec![],
                    affected: vec![q.clone()],
                    detail,
                    impact: None,
                    remediation:
                        "SRV records are required for AD site-aware routing — informational."
                            .into(),
                    weight_bonus: 0,
                });
            }
        }
    }

    Ok(AnonymousReport {
        host,
        domain,
        findings,
    })
}

/// Pull the host portion out of an `ldap://` / `ldaps://` URL, stripping any
/// user@ prefix and :port suffix.
fn host_of(url: &str) -> Result<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host_only = after_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    if host_only.is_empty() {
        return Err(anyhow!("could not parse target host from --url {url}"));
    }
    Ok(host_only.to_string())
}

const PORTS: &[(u16, &str)] = &[
    (53, "dns"),
    (88, "kerberos"),
    (135, "msrpc"),
    (139, "netbios"),
    (389, "ldap"),
    (445, "smb"),
    (464, "kpasswd"),
    (636, "ldaps"),
    (3268, "gc"),
    (3269, "gc-s"),
    (5985, "winrm"),
    (5986, "winrm-s"),
];

async fn port_scan(host: &str) -> Vec<(u16, &'static str)> {
    use tokio::time::{timeout, Duration};
    let mut set = tokio::task::JoinSet::new();
    for &(p, s) in PORTS {
        let h = host.to_string();
        set.spawn(async move {
            match timeout(Duration::from_millis(800), smb2_client::socks::dial(&h, p)).await {
                Ok(Ok(_)) => Some((p, s)),
                _ => None,
            }
        });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some(v)) = r {
            out.push(v);
        }
    }
    out.sort_by_key(|(p, _)| *p);
    out
}

/// Raw UDP DNS SRV query — no dep. Returns `(priority, weight, port, target)`
/// tuples, or None if the request failed or was refused.
///
/// Also consumed by `adhammer setup krb5` (WS-12, 1.4.1) to auto-discover the
/// KDC via `_kerberos._tcp.<realm>` before writing the krb5.conf.
pub(crate) async fn dns_srv(
    dns_host: &str,
    qname: &str,
) -> Option<Vec<(u16, u16, u16, String)>> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect((dns_host, 53)).await.ok()?;
    let mut q: Vec<u8> = vec![0x13, 0x39, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in qname.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // SRV=33, IN
    sock.send(&q).await.ok()?;
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(std::time::Duration::from_millis(1200), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_dns_srv(&buf[..n])
}

/// Parse SRV rdata. Handles DNS name compression via `read_name`. Best-effort:
/// stops at the first malformed record.
fn parse_dns_srv(msg: &[u8]) -> Option<Vec<(u16, u16, u16, String)>> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if an == 0 {
        return Some(vec![]);
    }
    let mut off = 12usize;
    for _ in 0..qd {
        off = skip_name(msg, off)?;
        off = off.checked_add(4)?; // qtype+qclass
    }
    let mut out = Vec::new();
    for _ in 0..an {
        off = skip_name(msg, off)?; // NAME
        if off + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        off += 10;
        if off + rdlen > msg.len() {
            break;
        }
        if rtype == 33 && rdlen >= 6 {
            // SRV
            let pri = u16::from_be_bytes([msg[off], msg[off + 1]]);
            let w = u16::from_be_bytes([msg[off + 2], msg[off + 3]]);
            let port = u16::from_be_bytes([msg[off + 4], msg[off + 5]]);
            if let Some(name) = read_name(msg, off + 6) {
                out.push((pri, w, port, name));
            }
        }
        off += rdlen;
    }
    Some(out)
}

fn skip_name(msg: &[u8], mut off: usize) -> Option<usize> {
    while off < msg.len() {
        let l = msg[off];
        if l == 0 {
            return Some(off + 1);
        }
        if l & 0xc0 == 0xc0 {
            return Some(off + 2);
        }
        off += 1 + l as usize;
    }
    None
}

fn read_name(msg: &[u8], start: usize) -> Option<String> {
    let mut off = start;
    let mut hops = 0usize;
    let mut labels = Vec::new();
    while off < msg.len() {
        let l = msg[off];
        if l == 0 {
            return Some(labels.join("."));
        }
        if l & 0xc0 == 0xc0 {
            let next = ((l as usize & 0x3f) << 8) | msg.get(off + 1).copied()? as usize;
            hops += 1;
            if hops > 8 {
                return None;
            }
            off = next;
            continue;
        }
        let end = off + 1 + l as usize;
        if end > msg.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&msg[off + 1..end]).into_owned());
        off = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_ldaps() {
        assert_eq!(
            host_of("ldaps://dc.corp.local:636").unwrap(),
            "dc.corp.local"
        );
        assert_eq!(host_of("ldap://user@1.2.3.4/").unwrap(), "1.2.3.4");
        assert_eq!(host_of("ldap://10.0.0.1").unwrap(), "10.0.0.1");
    }
}
