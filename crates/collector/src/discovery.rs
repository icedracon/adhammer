//! DNS-first no-credential discovery for the 1.5.0 black-box flow.
//!
//! WS-FOUNDATION-DNS-HANDROLL (1.5.0). Resolves AD-relevant SRV records
//! from `EngagementScope::domain_hints`, resolves their hostnames to IPs,
//! filters through scope, and collects best-effort PTR names — all over a
//! hand-rolled DNS client (`dns_wire` codec + tokio UDP/TCP transport),
//! with NO third-party resolver dependency (D2 lock, docs/PLAN_1.5.0.md).
//!
//! The orchestration (`discover_dns_with`, SRV family walk, scope filter,
//! PTR collection, ordering) is transport-agnostic behind the `DnsLookup`
//! trait; only `HandRolledDnsLookup` touches sockets. Tests drive a fake
//! `DnsLookup` so the logic is verifiable without a live DNS server.

use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use adhammer_core::EngagementScope;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::dns_wire::{self, QType, RecordData};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsServiceTarget {
    pub hostname: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    pub addrs: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SrvAnswer {
    hostname: String,
    port: u16,
    priority: u16,
    weight: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseDnsRecord {
    pub addr: IpAddr,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DnsDiscovery {
    pub domain: String,
    pub ldap_dc: Vec<DnsServiceTarget>,
    pub kerberos_kdc: Vec<DnsServiceTarget>,
    pub global_catalog: Vec<DnsServiceTarget>,
    pub reverse: Vec<ReverseDnsRecord>,
}

/// Default per-query timeout for the hand-rolled resolver.
pub const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve AD SRV families for every `domain_hint` in `scope`, using
/// `nameservers` (port 53 assumed) as the DNS servers. Returns one
/// `DnsDiscovery` per domain hint. An empty `nameservers` list, empty
/// `domain_hints`, or a resolver with nothing to reach yields an empty
/// result rather than an error — discovery is best-effort.
pub async fn discover_dns(
    scope: &EngagementScope,
    nameservers: &[IpAddr],
) -> Result<Vec<DnsDiscovery>> {
    scope.validate()?;
    if scope.domain_hints.is_empty() || nameservers.is_empty() {
        return Ok(Vec::new());
    }
    let lookup = HandRolledDnsLookup::new(nameservers.to_vec(), DEFAULT_DNS_TIMEOUT);
    discover_dns_with(&lookup, scope).await
}

/// Best-effort system nameserver discovery. Unix: parse
/// `/etc/resolv.conf`. Windows + others: returns empty — the caller
/// (CLI verb) must supply an explicit `--dns-server` there until the
/// platform adapter enumeration lands. Never errors.
pub fn system_nameservers() -> Vec<IpAddr> {
    #[cfg(unix)]
    {
        let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver ") {
                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                    out.push(ip);
                }
            }
        }
        out
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

async fn discover_dns_with(
    lookup: &impl DnsLookup,
    scope: &EngagementScope,
) -> Result<Vec<DnsDiscovery>> {
    scope.validate()?;
    if scope.domain_hints.is_empty() {
        return Ok(Vec::new());
    }

    let mut discoveries = Vec::new();
    for domain in &scope.domain_hints {
        let domain = trim_dns_name(domain);
        let ldap_dc =
            discover_srv_family(lookup, scope, &format!("_ldap._tcp.dc._msdcs.{domain}")).await?;
        let kerberos_kdc =
            discover_srv_family(lookup, scope, &format!("_kerberos._tcp.{domain}")).await?;
        let global_catalog =
            discover_srv_family(lookup, scope, &format!("_gc._tcp.{domain}")).await?;
        let reverse = reverse_dns_for_targets(
            lookup,
            ldap_dc
                .iter()
                .chain(kerberos_kdc.iter())
                .chain(global_catalog.iter()),
        )
        .await;

        discoveries.push(DnsDiscovery {
            domain,
            ldap_dc,
            kerberos_kdc,
            global_catalog,
            reverse,
        });
    }

    Ok(discoveries)
}

async fn discover_srv_family(
    lookup: &impl DnsLookup,
    scope: &EngagementScope,
    qname: &str,
) -> Result<Vec<DnsServiceTarget>> {
    let answers = match lookup.srv_lookup(qname).await {
        Ok(answers) => answers,
        Err(_) => return Ok(Vec::new()),
    };

    let mut targets = Vec::new();
    for answer in answers {
        let hostname = trim_dns_name(&answer.hostname);
        let addrs = lookup.lookup_ip(&hostname).await;
        if !target_in_scope(scope, &hostname, &addrs) {
            continue;
        }
        targets.push(DnsServiceTarget {
            hostname,
            port: answer.port,
            priority: answer.priority,
            weight: answer.weight,
            addrs,
        });
    }

    targets.sort_by(|lhs, rhs| {
        (lhs.priority, lhs.weight, lhs.port, lhs.hostname.as_str()).cmp(&(
            rhs.priority,
            rhs.weight,
            rhs.port,
            rhs.hostname.as_str(),
        ))
    });
    Ok(targets)
}

async fn reverse_dns_for_targets<'a>(
    lookup: &impl DnsLookup,
    targets: impl IntoIterator<Item = &'a DnsServiceTarget>,
) -> Vec<ReverseDnsRecord> {
    let mut uniq = BTreeSet::new();
    for target in targets {
        for addr in &target.addrs {
            uniq.insert(*addr);
        }
    }

    let mut out = Vec::new();
    for addr in uniq {
        let mut names = lookup
            .reverse_lookup(addr)
            .await
            .into_iter()
            .map(|name| trim_dns_name(&name))
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        out.push(ReverseDnsRecord { addr, names });
    }
    out
}

/// BF-3 (1.4.10) scope API: excludes win across identity forms. A target
/// is in scope if EITHER its hostname or any resolved IP is allowed, and
/// neither is excluded — `EngagementScope::allows` enforces both.
fn target_in_scope(scope: &EngagementScope, hostname: &str, addrs: &[IpAddr]) -> bool {
    if addrs.is_empty() {
        return scope.allows(None, Some(hostname));
    }
    addrs
        .iter()
        .copied()
        .any(|addr| scope.allows(Some(addr), Some(hostname)))
}

fn trim_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Reverse-DNS query name for an address: `a.b.c.d.in-addr.arpa` (v4) or
/// nibble-reversed `...ip6.arpa` (v6).
fn reverse_qname(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

trait DnsLookup {
    fn srv_lookup<'a>(&'a self, qname: &'a str) -> BoxFuture<'a, Result<Vec<SrvAnswer>>>;
    fn lookup_ip<'a>(&'a self, hostname: &'a str) -> BoxFuture<'a, Vec<IpAddr>>;
    fn reverse_lookup<'a>(&'a self, addr: IpAddr) -> BoxFuture<'a, Vec<String>>;
}

/// Weak transaction-id source. A black-box operator queries the target's
/// own DNS point-to-point, so blind-spoofing resistance is not the threat
/// model here; a monotonic counter seeded by the process start nanos is
/// enough to correlate replies and reject obviously stale ones.
fn next_txn_id() -> u16 {
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0);
    seed ^ COUNTER.fetch_add(0x9e37, Ordering::Relaxed)
}

/// Hand-rolled DNS client over the `dns_wire` codec.
pub struct HandRolledDnsLookup {
    servers: Vec<SocketAddr>,
    timeout: Duration,
}

impl HandRolledDnsLookup {
    pub fn new(nameservers: Vec<IpAddr>, timeout: Duration) -> Self {
        Self {
            servers: nameservers
                .into_iter()
                .map(|ip| SocketAddr::new(ip, 53))
                .collect(),
            timeout,
        }
    }

    /// Query each configured server in turn; first parseable NOERROR-ish
    /// response wins. Returns None if every server times out / errors.
    async fn query(&self, qname: &str, qtype: QType) -> Option<dns_wire::DnsResponse> {
        for server in &self.servers {
            if let Some(resp) = self.query_one(*server, qname, qtype).await {
                return Some(resp);
            }
        }
        None
    }

    async fn query_one(
        &self,
        server: SocketAddr,
        qname: &str,
        qtype: QType,
    ) -> Option<dns_wire::DnsResponse> {
        let id = next_txn_id();
        let query = dns_wire::encode_query(id, qname, qtype);

        let bind: SocketAddr = if server.is_ipv6() {
            "[::]:0".parse().ok()?
        } else {
            "0.0.0.0:0".parse().ok()?
        };
        let sock = UdpSocket::bind(bind).await.ok()?;
        sock.connect(server).await.ok()?;
        sock.send(&query).await.ok()?;

        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(self.timeout, sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        let resp = dns_wire::parse_response(&buf[..n]).ok()?;
        if resp.id != id {
            return None; // stale / spoofed reply
        }
        if resp.truncated {
            return self.query_tcp(server, &query, id).await;
        }
        Some(resp)
    }

    async fn query_tcp(
        &self,
        server: SocketAddr,
        query: &[u8],
        id: u16,
    ) -> Option<dns_wire::DnsResponse> {
        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(server))
            .await
            .ok()?
            .ok()?;
        // TCP DNS framing: 2-byte big-endian length prefix.
        let len = u16::try_from(query.len()).ok()?;
        stream.write_all(&len.to_be_bytes()).await.ok()?;
        stream.write_all(query).await.ok()?;
        stream.flush().await.ok()?;

        let mut lenbuf = [0u8; 2];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut lenbuf))
            .await
            .ok()?
            .ok()?;
        let rlen = u16::from_be_bytes(lenbuf) as usize;
        if rlen == 0 || rlen > 65_535 {
            return None;
        }
        let mut body = vec![0u8; rlen];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut body))
            .await
            .ok()?
            .ok()?;
        let resp = dns_wire::parse_response(&body).ok()?;
        if resp.id != id {
            return None;
        }
        Some(resp)
    }
}

impl DnsLookup for HandRolledDnsLookup {
    fn srv_lookup<'a>(&'a self, qname: &'a str) -> BoxFuture<'a, Result<Vec<SrvAnswer>>> {
        Box::pin(async move {
            let Some(resp) = self.query(qname, QType::Srv).await else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for rr in resp.answers {
                if let RecordData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                } = rr.data
                {
                    out.push(SrvAnswer {
                        hostname: trim_dns_name(&target),
                        port,
                        priority,
                        weight,
                    });
                }
            }
            Ok(out)
        })
    }

    fn lookup_ip<'a>(&'a self, hostname: &'a str) -> BoxFuture<'a, Vec<IpAddr>> {
        Box::pin(async move {
            let mut addrs = Vec::new();
            for qtype in [QType::A, QType::Aaaa] {
                if let Some(resp) = self.query(hostname, qtype).await {
                    for rr in resp.answers {
                        match rr.data {
                            RecordData::A(v4) => addrs.push(IpAddr::V4(v4)),
                            RecordData::Aaaa(v6) => addrs.push(IpAddr::V6(v6)),
                            _ => {}
                        }
                    }
                }
            }
            addrs.sort();
            addrs.dedup();
            addrs
        })
    }

    fn reverse_lookup<'a>(&'a self, addr: IpAddr) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let qname = reverse_qname(addr);
            let Some(resp) = self.query(&qname, QType::Ptr).await else {
                return Vec::new();
            };
            let mut names: Vec<String> = resp
                .answers
                .into_iter()
                .filter_map(|rr| match rr.data {
                    RecordData::Ptr(name) => Some(trim_dns_name(&name)),
                    _ => None,
                })
                .collect();
            names.sort();
            names.dedup();
            names
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        discover_dns_with, reverse_qname, target_in_scope, trim_dns_name, BoxFuture, DnsLookup,
        SrvAnswer,
    };
    use adhammer_core::{EngagementScope, ScopeTarget};
    use anyhow::Result;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[derive(Default)]
    struct FakeDnsLookup {
        srv: HashMap<String, Vec<SrvAnswer>>,
        ip: HashMap<String, Vec<IpAddr>>,
        ptr: HashMap<IpAddr, Vec<String>>,
    }

    impl DnsLookup for FakeDnsLookup {
        fn srv_lookup<'a>(&'a self, qname: &'a str) -> BoxFuture<'a, Result<Vec<SrvAnswer>>> {
            let value = self.srv.get(qname).cloned().unwrap_or_default();
            Box::pin(async move { Ok(value) })
        }

        fn lookup_ip<'a>(&'a self, hostname: &'a str) -> BoxFuture<'a, Vec<IpAddr>> {
            let value = self.ip.get(hostname).cloned().unwrap_or_default();
            Box::pin(async move { value })
        }

        fn reverse_lookup<'a>(&'a self, addr: IpAddr) -> BoxFuture<'a, Vec<String>> {
            let mut value = self.ptr.get(&addr).cloned().unwrap_or_default();
            value.sort();
            value.dedup();
            Box::pin(async move { value })
        }
    }

    #[test]
    fn trim_dns_name_normalizes_case_and_root_dot() {
        assert_eq!(trim_dns_name("DC01.CORP.LOCAL."), "dc01.corp.local");
        assert_eq!(trim_dns_name("dc01"), "dc01");
    }

    #[test]
    fn reverse_qname_v4_and_v6() {
        assert_eq!(
            reverse_qname(IpAddr::from_str("10.0.0.10").unwrap()),
            "10.0.0.10.in-addr.arpa"
        );
        let v6 = reverse_qname(IpAddr::from_str("2001:db8::1").unwrap());
        assert!(v6.ends_with("ip6.arpa"));
        assert!(v6.starts_with("1.0.0.0"));
    }

    #[test]
    fn scope_accepts_matching_hostname_or_ip() {
        let host_scope = EngagementScope::new(vec![ScopeTarget::Hostname {
            name: "dc01.corp.local".into(),
        }])
        .unwrap();
        assert!(target_in_scope(&host_scope, "DC01.CORP.LOCAL.", &[]));

        let ip_scope = EngagementScope::new(vec![ScopeTarget::Cidr {
            net: "10.0.0.0/24".parse().unwrap(),
        }])
        .unwrap();
        assert!(target_in_scope(
            &ip_scope,
            "dc01.corp.local",
            &[IpAddr::from_str("10.0.0.42").unwrap()]
        ));
        assert!(!target_in_scope(
            &ip_scope,
            "dc01.corp.local",
            &[IpAddr::from_str("10.0.1.42").unwrap()]
        ));
    }

    /// BF-3 regression at the discovery layer: a hostname-excluded target
    /// is refused even when its resolved IP is inside an included CIDR.
    #[test]
    fn scope_exclude_by_hostname_blocks_included_ip() {
        let scope = EngagementScope {
            includes: vec![ScopeTarget::Cidr {
                net: "10.0.0.0/24".parse().unwrap(),
            }],
            excludes: vec![ScopeTarget::Hostname {
                name: "dc01.corp.local".into(),
            }],
            domain_hints: vec![],
        };
        scope.validate().unwrap();
        assert!(!target_in_scope(
            &scope,
            "dc01.corp.local",
            &[IpAddr::from_str("10.0.0.10").unwrap()]
        ));
        assert!(target_in_scope(
            &scope,
            "dc02.corp.local",
            &[IpAddr::from_str("10.0.0.11").unwrap()]
        ));
    }

    #[tokio::test]
    async fn discover_dns_returns_empty_without_domain_hints() {
        let scope = EngagementScope::new(vec![ScopeTarget::Cidr {
            net: "10.0.0.0/24".parse().unwrap(),
        }])
        .unwrap();
        let result = discover_dns_with(&FakeDnsLookup::default(), &scope)
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn discover_dns_filters_out_of_scope_targets_and_collects_ptrs() {
        let mut fake = FakeDnsLookup::default();
        fake.srv.insert(
            "_ldap._tcp.dc._msdcs.corp.local".into(),
            vec![
                SrvAnswer {
                    hostname: "dc01.corp.local.".into(),
                    port: 389,
                    priority: 0,
                    weight: 100,
                },
                SrvAnswer {
                    hostname: "dc02.corp.local.".into(),
                    port: 389,
                    priority: 10,
                    weight: 50,
                },
            ],
        );
        fake.srv.insert(
            "_kerberos._tcp.corp.local".into(),
            vec![SrvAnswer {
                hostname: "dc01.corp.local.".into(),
                port: 88,
                priority: 0,
                weight: 100,
            }],
        );
        fake.srv.insert(
            "_gc._tcp.corp.local".into(),
            vec![SrvAnswer {
                hostname: "gc01.corp.local.".into(),
                port: 3268,
                priority: 5,
                weight: 0,
            }],
        );
        fake.ip.insert(
            "dc01.corp.local".into(),
            vec![IpAddr::from_str("10.0.0.10").unwrap()],
        );
        fake.ip.insert(
            "dc02.corp.local".into(),
            vec![IpAddr::from_str("10.0.1.10").unwrap()],
        );
        fake.ip.insert(
            "gc01.corp.local".into(),
            vec![IpAddr::from_str("10.0.0.20").unwrap()],
        );
        fake.ptr.insert(
            IpAddr::from_str("10.0.0.10").unwrap(),
            vec!["DC01.CORP.LOCAL.".into()],
        );
        fake.ptr.insert(
            IpAddr::from_str("10.0.0.20").unwrap(),
            vec!["gc01.corp.local.".into(), "gc01.corp.local.".into()],
        );

        let scope = EngagementScope {
            includes: vec![ScopeTarget::Cidr {
                net: "10.0.0.0/24".parse().unwrap(),
            }],
            excludes: vec![],
            domain_hints: vec!["corp.local".into()],
        };

        let result = discover_dns_with(&fake, &scope).await.unwrap();
        assert_eq!(result.len(), 1);
        let discovery = &result[0];
        assert_eq!(discovery.domain, "corp.local");
        assert_eq!(discovery.ldap_dc.len(), 1);
        assert_eq!(discovery.ldap_dc[0].hostname, "dc01.corp.local");
        assert_eq!(discovery.kerberos_kdc.len(), 1);
        assert_eq!(discovery.global_catalog.len(), 1);
        assert_eq!(discovery.reverse.len(), 2);
        assert_eq!(discovery.reverse[0].names, vec!["dc01.corp.local"]);
        assert_eq!(discovery.reverse[1].names, vec!["gc01.corp.local"]);
    }

    #[tokio::test]
    async fn discover_dns_accepts_hostname_scoped_targets_without_ip_hits() {
        let mut fake = FakeDnsLookup::default();
        fake.srv.insert(
            "_ldap._tcp.dc._msdcs.corp.local".into(),
            vec![SrvAnswer {
                hostname: "dc01.corp.local.".into(),
                port: 389,
                priority: 0,
                weight: 100,
            }],
        );

        let scope = EngagementScope {
            includes: vec![ScopeTarget::Hostname {
                name: "dc01.corp.local".into(),
            }],
            excludes: vec![],
            domain_hints: vec!["corp.local".into()],
        };

        let result = discover_dns_with(&fake, &scope).await.unwrap();
        assert_eq!(result[0].ldap_dc.len(), 1);
        assert!(result[0].ldap_dc[0].addrs.is_empty());
    }
}
