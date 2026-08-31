//! LDAP collection layer. Pulls the object classes the checks + graph need, in paged
//! sweeps over the domain NC *and* the Configuration NC (where AD CS templates + CAs
//! live), and normalizes them into `core::Snapshot`. Binary attrs (objectSid,
//! nTSecurityDescriptor, objectGUID, RBCD) are requested raw so we parse them ourselves.

use adhammer_core::object::AdObject;
use adhammer_core::sid::Sid;
use adhammer_core::snapshot::{DomainInfo, Snapshot};
use anyhow::{Context, Result};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::collections::{HashMap, HashSet};

pub mod dns_record;
pub mod sources;

/// LDAP_SERVER_SD_FLAGS_OID — ask the server for only OWNER|GROUP|DACL of
/// nTSecurityDescriptor (0x7), omitting the SACL. Without this, a non-admin bind gets an
/// empty security descriptor, so DACL-based checks (ESC, control paths) see nothing.
fn sd_flags_control() -> RawControl {
    RawControl {
        ctype: "1.2.840.113556.1.4.801".into(),
        crit: false,
        val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x07]), // SEQUENCE { INTEGER 7 }
    }
}

/// Attributes we always want. `nTSecurityDescriptor` comes back with owner/group/dacl
/// even without SeSecurityPrivilege. AD CS template attrs are harmless on other objects.
const ATTRS: &[&str] = &[
    "objectClass",
    "cn",
    "sAMAccountName",
    "distinguishedName",
    "objectSid",
    "objectGUID",
    "userAccountControl",
    "servicePrincipalName",
    "adminCount",
    "memberOf",
    "member",
    "pwdLastSet",
    "lastLogonTimestamp",
    "whenCreated",
    "operatingSystem",
    "msDS-SupportedEncryptionTypes",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-KeyCredentialLink",
    "nTSecurityDescriptor",
    "trustAttributes",
    "trustDirection",
    "trustType",
    "trustPartner",
    "flatName",
    "securityIdentifier",
    "whenChanged",
    "msDS-MachineAccountQuota",
    "msDS-Behavior-Version",
    "primaryGroupID",
    "sIDHistory",
    // gMSA read-password ACL + LAPS coverage
    "msDS-GroupMSAMembership",
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-PasswordExpirationTime",
    // AD CS: certificate templates + enrollment services (CAs)
    "displayName",
    "dNSHostName",
    "certificateTemplates",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature",
    "pKIExtendedKeyUsage",
    "msPKI-Certificate-Application-Policy",
    "msPKI-Certificate-Policy",
    "msPKI-Template-Schema-Version",
    "msPKI-Cert-Template-OID",
    // ESC14: explicit certificate mappings (weak X509 mapping strings).
    "altSecurityIdentities",
    // domain password policy + Directory Service heuristics (anonymous LDAP etc.)
    "minPwdLength",
    "pwdProperties",
    "maxPwdAge",
    "minPwdAge",
    "lockoutThreshold",
    "lockoutDuration",
    "dSHeuristics",
];

/// Object classes to pull from the Public Key Services container under the config NC.
const PKI_FILTER: &str =
    "(|(objectClass=pKICertificateTemplate)(objectClass=pKIEnrollmentService)(objectClass=certificationAuthority))";

pub struct LdapConfig {
    pub url: String,     // ldap://dc.corp.local:389  or ldaps://...
    pub bind_dn: String, // CORP\\user  or user@corp.local  or full DN
    pub password: String,
    pub base_dn: Option<String>, // default: RootDSE defaultNamingContext
    pub insecure: bool,          // skip TLS cert verification (labs / self-signed DC certs)
    pub gssapi: bool,            // SASL GSSAPI bind (signed LDAP over 389, ambient Kerberos)
}

/// The server FQDN from an LDAP URL, for the GSSAPI service principal (ldap/<fqdn>).
#[cfg(feature = "gssapi")]
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

/// A no-default-features build intentionally supports plain `ldap://` only. Reject LDAPS before
/// dialing so the absence of a TLS backend is explicit rather than an opaque ldap3 error.
fn ensure_tls_configuration(_url: &str, _insecure: bool) -> Result<()> {
    #[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
    {
        let scheme = _url
            .split_once("://")
            .map(|(scheme, _)| scheme)
            .unwrap_or_default();
        if scheme.eq_ignore_ascii_case("ldaps") {
            anyhow::bail!(
                "LDAPS is disabled in this build; enable `tls-rustls` (default) or `tls-native`"
            );
        }
        if _insecure {
            anyhow::bail!(
                "--insecure requires a TLS backend; enable `tls-rustls` (default) or `tls-native`"
            );
        }
    }
    Ok(())
}

#[cfg(all(feature = "tls-native", feature = "tls-rustls"))]
compile_error!(
    "`tls-rustls` and `tls-native` are mutually exclusive; select exactly one LDAPS backend"
);

/// `--insecure` LDAPS settings that skip certificate + hostname verification (self-signed /
/// legacy DC certs, or an IP/tunnel endpoint that can't match the cert CN).
///
/// tls-native path: a custom connector setting BOTH danger flags — ldap3's own `no_tls_verify`
/// skips certs but not hostnames, and native-TLS (OpenSSL/Schannel) also accepts the SHA-1
/// handshake signatures rustls refuses, reaching legacy DCs rustls cannot.
#[cfg(feature = "tls-native")]
fn insecure_settings() -> Result<ldap3::LdapConnSettings> {
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .context("build native-tls connector")?;
    Ok(ldap3::LdapConnSettings::new().set_connector(connector))
}

/// rustls path: ldap3's built-in `NoCertVerification` skips both cert and hostname checks.
#[cfg(all(feature = "tls-rustls", not(feature = "tls-native")))]
fn insecure_settings() -> Result<ldap3::LdapConnSettings> {
    Ok(ldap3::LdapConnSettings::new().set_no_tls_verify(true))
}

/// `--insecure` changes TLS certificate validation and has no meaning in a plain-LDAP-only build.
#[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
fn insecure_settings() -> Result<ldap3::LdapConnSettings> {
    anyhow::bail!(
        "--insecure requires a TLS backend; enable `tls-rustls` (default) or `tls-native`"
    )
}

pub struct Collector {
    ldap: ldap3::Ldap,
    base_dn: String,
    config_dn: String,
}

/// One ADIDNS record parsed from a `dnsRecord` blob.
#[derive(Debug, Clone)]
pub struct DnsRecordEntry {
    /// Node relative name: `@` = zone apex, `*` = wildcard.
    pub node: String,
    /// Record type mnemonic (A, AAAA, CNAME, NS, SRV, …).
    pub rtype: String,
    /// Rendered record data.
    pub data: String,
    /// True if the node is DNS-tombstoned (deleted-but-present).
    pub tombstoned: bool,
}

/// An AD-integrated DNS zone and its nodes.
#[derive(Debug, Clone)]
pub struct DnsZone {
    pub name: String,
    pub records: Vec<DnsRecordEntry>,
}

/// One computer's recovered LAPS local-administrator password.
#[derive(Debug, Clone)]
pub struct LapsEntry {
    /// Computer sAMAccountName, e.g. `WIN11$`.
    pub sam: String,
    pub dn: String,
    /// Managed local account name (`Administrator`, or the `n` field of Windows LAPS).
    pub account: String,
    /// Cleartext password. `None` when only the DPAPI-NG-encrypted blob is present.
    pub password: Option<String>,
    /// Expiration (raw FILETIME string as returned by AD), best-effort.
    pub expires: Option<String>,
    /// Which attribute the value came from.
    pub source: &'static str,
    /// Raw bytes of `msLAPS-EncryptedPassword` when that is the source — the DPAPI-NG blob
    /// (LAPS header + CMS EnvelopedData). Empty for cleartext sources.
    pub encrypted_blob: Option<Vec<u8>>,
}

/// When a global SOCKS5 proxy is set, ldap3 (which owns its own TCP connect and can't be
/// handed a pre-dialed socket) is pointed at a local one-shot forwarder that tunnels the
/// connection to the DC through the proxy. Returns the rewritten `127.0.0.1:<port>` URL, or
/// `None` when no proxy is active (ldap3 connects directly).
async fn socks_forward_url(url: &str, insecure: bool) -> Result<Option<String>> {
    if smb2_client::socks::proxy().is_none() {
        return Ok(None);
    }
    let scheme = if url.starts_with("ldaps://") {
        "ldaps"
    } else {
        "ldap"
    };
    let default_port: u16 = if scheme == "ldaps" { 636 } else { 389 };
    let hostport = url.split("://").nth(1).unwrap_or(url);
    let hostport = hostport.split('/').next().unwrap_or(hostport);
    let host = hostport.split(':').next().unwrap_or("").to_string();
    let port: u16 = hostport
        .rsplit(':')
        .next()
        .filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && *p != hostport)
        .and_then(|p| p.parse().ok())
        .unwrap_or(default_port);
    // LDAPS over the tunnel presents the DC's cert to a client that dialed 127.0.0.1, so the
    // hostname can never match — this only works with the cert-skipping connector.
    if scheme == "ldaps" && !insecure {
        anyhow::bail!(
            "LDAPS through --socks needs --insecure (the DC cert can't match the local tunnel \
             endpoint); re-run with --insecure or use an ldap:// URL"
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind local LDAP→SOCKS forwarder")?;
    let local = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let host = host.clone();
            tokio::spawn(async move {
                if let Ok(mut outbound) = smb2_client::socks::dial(&host, port).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    Ok(Some(format!("{scheme}://127.0.0.1:{local}")))
}

impl Collector {
    pub async fn connect(cfg: &LdapConfig) -> Result<Self> {
        ensure_tls_configuration(&cfg.url, cfg.insecure)?;
        // Route ldap3's connect through the SOCKS pivot when one is configured.
        let dial_url = socks_forward_url(&cfg.url, cfg.insecure)
            .await?
            .unwrap_or_else(|| cfg.url.clone());
        let (conn, mut ldap) = if cfg.insecure {
            LdapConnAsync::with_settings(insecure_settings()?, &dial_url)
                .await
                .context("ldap connect")?
        } else {
            LdapConnAsync::new(&dial_url)
                .await
                .context("ldap connect")?
        };
        ldap3::drive!(conn);

        // A bare sAMAccountName (e.g. `administrator`) is rejected by a real DC's simple_bind
        // (rc=49, data 52e) — it wants a UPN or `DOMAIN\user`. RootDSE is readable anonymously
        // on AD, so read the naming context first and qualify a bare name to `user@domain`.
        // Best-effort: if the pre-bind read is refused, fall back to binding as-given + reading
        // RootDSE afterwards (the original order).
        let pre = if cfg.gssapi {
            None
        } else {
            root_ncs(&mut ldap).await.ok()
        };
        let domain = pre.as_ref().map(|(nc, _)| dns_from_nc(nc));
        Self::bind(&mut ldap, cfg, domain.as_deref()).await?;

        let (default_nc, config_nc) = match pre {
            Some(v) => v,
            None => root_ncs(&mut ldap).await?,
        };
        let base_dn = cfg.base_dn.clone().unwrap_or(default_nc);
        Ok(Collector {
            ldap,
            base_dn,
            config_dn: config_nc,
        })
    }

    async fn bind(ldap: &mut ldap3::Ldap, cfg: &LdapConfig, domain: Option<&str>) -> Result<()> {
        if cfg.gssapi {
            #[cfg(feature = "gssapi")]
            {
                let fqdn = url_host(&cfg.url);
                ldap.sasl_gssapi_bind(&fqdn)
                    .await?
                    .success()
                    .context("GSSAPI bind failed")?;
                return Ok(());
            }
            #[cfg(not(feature = "gssapi"))]
            anyhow::bail!("--gssapi requires a build with `--features gssapi`");
        }
        let bind_dn = qualify_bind(&cfg.bind_dn, domain);
        ldap.simple_bind(&bind_dn, &cfg.password)
            .await?
            .success()
            .with_context(|| {
                format!("bind failed as `{bind_dn}` — check the password, or pass `DOMAIN\\user` / `user@domain`")
            })?;
        Ok(())
    }

    /// Paged subtree search over the domain NC, then over the AD CS container.
    /// A missing Public Key Services container (no ADCS) is tolerated, not fatal.
    pub async fn collect(mut self) -> Result<Snapshot> {
        let mut objects = Vec::new();
        // WS-WPT session 3b: record every LDAP search the collector runs + which DNs it
        // populated, so LDAP-passive checks can synthesize a wire-exchange proof from the
        // same source of truth. Fully additive — legacy callers just see the same Snapshot.
        let mut searches: Vec<adhammer_core::SearchOp> = Vec::new();
        let mut dn_links: Vec<(String, usize)> = Vec::new();

        let base = self.base_dn.clone();
        self.search_into(
            &base,
            "(objectClass=*)",
            &mut objects,
            &mut searches,
            &mut dn_links,
        )
        .await?;

        let pki_base = format!("CN=Public Key Services,CN=Services,{}", self.config_dn);
        if let Err(e) = self
            .search_into(
                &pki_base,
                PKI_FILTER,
                &mut objects,
                &mut searches,
                &mut dn_links,
            )
            .await
        {
            tracing::warn!(%e, "AD CS container not collected (no PKI, or access denied)");
        }

        let ds = format!(
            "CN=Directory Service,CN=Windows NT,CN=Services,{}",
            self.config_dn
        );
        if let Err(e) = self
            .search_base_into(&ds, &mut objects, &mut searches, &mut dn_links)
            .await
        {
            tracing::warn!(%e, "Directory Service object not collected");
        }

        let domain = self.domain_info(&objects);
        let mut snap = Snapshot::new(domain, objects);
        for op in searches {
            snap.record_search(op);
        }
        for (dn, idx) in dn_links {
            snap.link_dn_to_search(&dn, idx);
        }
        Ok(snap)
    }

    /// Base-scope read of a single object (e.g. the Directory Service heuristics object).
    async fn search_base_into(
        &mut self,
        base: &str,
        out: &mut Vec<AdObject>,
        searches: &mut Vec<adhammer_core::SearchOp>,
        dn_links: &mut Vec<(String, usize)>,
    ) -> Result<()> {
        let search_idx = searches.len();
        self.ldap.with_controls(sd_flags_control());
        let (rs, _) = self
            .ldap
            .search(base, Scope::Base, "(objectClass=*)", ATTRS.to_vec())
            .await?
            .success()?;
        let mut count = 0usize;
        for e in rs {
            let obj = to_object(SearchEntry::construct(e));
            dn_links.push((obj.dn.clone(), search_idx));
            out.push(obj);
            count += 1;
        }
        searches.push(adhammer_core::SearchOp {
            base_dn: base.into(),
            filter: "(objectClass=*)".into(),
            attrs: ATTRS.iter().map(|s| (*s).into()).collect(),
            returned_count: count,
            scope: "base".into(),
        });
        Ok(())
    }

    async fn search_into(
        &mut self,
        base: &str,
        filter: &str,
        out: &mut Vec<AdObject>,
        searches: &mut Vec<adhammer_core::SearchOp>,
        dn_links: &mut Vec<(String, usize)>,
    ) -> Result<()> {
        let search_idx = searches.len();
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(1000)),
        ];
        self.ldap.with_controls(sd_flags_control());
        let mut stream = self
            .ldap
            .streaming_search_with(adapters, base, Scope::Subtree, filter, ATTRS.to_vec())
            .await?;
        let mut count = 0usize;
        // Per-entry deadline (hostile-server DoS defence). ldap3's own
        // connection-level timeout doesn't cap the per-record dribble of a
        // paged / referral-heavy LDAP server, so wrap each `stream.next()`
        // in a 60 s ceiling. Real DCs return each entry in single-digit ms;
        // a well-behaved paged response of 100 k objects finishes in
        // seconds. 60 s per entry is roughly four orders of magnitude above
        // that and still catches a hostile / broken server that dribbles.
        const LDAP_PER_ENTRY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
        loop {
            let maybe_entry = tokio::time::timeout(LDAP_PER_ENTRY_TIMEOUT, stream.next())
                .await
                .map_err(|elapsed| ldap3::LdapError::Timeout { elapsed })??;
            let Some(entry) = maybe_entry else { break };
            let obj = to_object(SearchEntry::construct(entry));
            dn_links.push((obj.dn.clone(), search_idx));
            out.push(obj);
            count += 1;
        }
        stream.finish().await.success().ok();
        searches.push(adhammer_core::SearchOp {
            base_dn: base.into(),
            filter: filter.into(),
            attrs: ATTRS.iter().map(|s| (*s).into()).collect(),
            returned_count: count,
            scope: "sub".into(),
        });
        Ok(())
    }

    /// Resolve a sAMAccountName to its DN.
    /// Read a single binary attribute (e.g. `msDS-ManagedPassword`) off the object whose
    /// sAMAccountName matches `sam`. Requires a sealed/TLS bind and the read right.
    pub async fn read_attr_bin(&mut self, sam: &str, attr: &str) -> Result<Option<Vec<u8>>> {
        let base = self.base_dn.clone();
        let (rs, _) = self
            .ldap
            .search(
                &base,
                Scope::Subtree,
                &format!("(sAMAccountName={sam})"),
                vec![attr],
            )
            .await?
            .success()?;
        let Some(entry) = rs.into_iter().next() else {
            return Ok(None);
        };
        let se = SearchEntry::construct(entry);
        Ok(se.bin_attrs.get(attr).and_then(|v| v.first()).cloned())
    }

    /// Read LAPS local-admin passwords. With `target` set, reads that one computer; otherwise
    /// sweeps every computer whose LAPS attribute is readable by the bind identity. Covers both
    /// legacy Microsoft LAPS (`ms-Mcs-AdmPwd`, cleartext) and Windows LAPS (`msLAPS-Password`,
    /// a JSON blob) — the DPAPI-NG-encrypted `msLAPS-EncryptedPassword` is surfaced but not
    /// decrypted. Like gMSA, the cleartext is only returned over a sealed/TLS bind.
    pub async fn read_laps(&mut self, target: Option<&str>) -> Result<Vec<LapsEntry>> {
        let base = self.base_dn.clone();
        let filter = match target {
            Some(sam) => format!("(&(objectCategory=computer)(sAMAccountName={sam}))"),
            None => "(&(objectCategory=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))".to_string(),
        };
        let attrs = vec![
            "sAMAccountName",
            "distinguishedName",
            "ms-Mcs-AdmPwd",
            "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-Password",
            "msLAPS-PasswordExpirationTime",
            "msLAPS-EncryptedPassword",
        ];
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(1000)),
        ];
        let mut stream = self
            .ldap
            .streaming_search_with(adapters, &base, Scope::Subtree, &filter, attrs)
            .await?;
        let mut out = Vec::new();
        while let Some(entry) = stream.next().await? {
            if let Some(e) = laps_from_entry(&SearchEntry::construct(entry)) {
                out.push(e);
            }
        }
        stream.finish().await.success().ok();
        Ok(out)
    }

    /// Enumerate AD-integrated DNS (ADIDNS) — every `dnsNode` across the `DomainDnsZones` and
    /// `ForestDnsZones` application partitions plus the legacy `System` container — and parse the
    /// `dnsRecord` blobs (MS-DNSP). This is the adidnsdump-equivalent: any authenticated user can
    /// usually read the whole zone, and a writable/wildcard node is a name-hijack (mitm6/WPAD)
    /// primitive. Missing partitions are tolerated, not fatal.
    pub async fn read_adidns(&mut self) -> Result<Vec<DnsZone>> {
        let bases = [
            format!("DC=DomainDnsZones,{}", self.base_dn),
            format!("DC=ForestDnsZones,{}", self.base_dn),
            format!("CN=MicrosoftDNS,CN=System,{}", self.base_dn),
        ];
        let mut zones: std::collections::BTreeMap<String, DnsZone> = Default::default();
        for base in bases {
            let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
                Box::new(EntriesOnly::new()),
                Box::new(PagedResults::new(1000)),
            ];
            let mut stream = match self
                .ldap
                .streaming_search_with(
                    adapters,
                    &base,
                    Scope::Subtree,
                    "(objectClass=dnsNode)",
                    vec!["dc", "dnsRecord", "dNSTombstoned"],
                )
                .await
            {
                Ok(s) => s,
                Err(_) => continue, // partition not present on this DC
            };
            while let Ok(Some(entry)) = stream.next().await {
                let se = SearchEntry::construct(entry);
                let zone_name = zone_from_dn(&se.dn);
                let node = se
                    .attrs
                    .get("dc")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| "@".into());
                let node_tomb = se
                    .attrs
                    .get("dNSTombstoned")
                    .and_then(|v| v.first())
                    .map(|s| s.eq_ignore_ascii_case("TRUE"))
                    .unwrap_or(false);
                let zone = zones.entry(zone_name.clone()).or_insert_with(|| DnsZone {
                    name: zone_name.clone(),
                    records: Vec::new(),
                });
                if let Some(blobs) = se.bin_attrs.get("dnsRecord") {
                    for b in blobs {
                        if let Some((rtype, data, rec_tomb)) = parse_dns_record(b) {
                            zone.records.push(DnsRecordEntry {
                                node: node.clone(),
                                rtype,
                                data,
                                tombstoned: node_tomb || rec_tomb,
                            });
                        }
                    }
                }
            }
            let _ = stream.finish().await; // NoSuchObject on a missing partition is expected
        }
        Ok(zones.into_values().collect())
    }

    /// Enumerate the enterprise CAs (`pKIEnrollmentService` under the Configuration NC) as
    /// (CA name, DNS host). The host is where ESC8 web-enrollment / ESC11 ICPR live.
    pub async fn read_cas(&mut self) -> Result<Vec<(String, String)>> {
        let base = format!(
            "CN=Enrollment Services,CN=Public Key Services,CN=Services,{}",
            self.config_dn
        );
        let (rs, _) = match self
            .ldap
            .search(
                &base,
                Scope::Subtree,
                "(objectClass=pKIEnrollmentService)",
                vec!["cn", "name", "dNSHostName"],
            )
            .await
        {
            Ok(r) => r.success()?,
            Err(_) => return Ok(Vec::new()), // no AD CS in the forest
        };
        let mut out = Vec::new();
        for e in rs {
            let se = SearchEntry::construct(e);
            let name = se
                .attrs
                .get("cn")
                .or_else(|| se.attrs.get("name"))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let host = se
                .attrs
                .get("dNSHostName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            out.push((name, host));
        }
        Ok(out)
    }

    pub async fn resolve_dn(&mut self, sam: &str) -> Result<String> {
        let base = self.base_dn.clone();
        let (rs, _) = self
            .ldap
            .search(
                &base,
                Scope::Subtree,
                &format!("(sAMAccountName={sam})"),
                vec!["distinguishedName"],
            )
            .await?
            .success()?;
        let e = rs.into_iter().next().context("object not found")?;
        Ok(SearchEntry::construct(e).dn)
    }

    /// Add a value to a (multi-valued) attribute — e.g. a servicePrincipalName (targeted
    /// Kerberoast) or a group `member`. Requires write rights on the object.
    pub async fn add_value(&mut self, dn: &str, attr: &str, value: &str) -> Result<()> {
        use ldap3::Mod;
        let m: Mod<Vec<u8>> = Mod::Add(
            attr.as_bytes().to_vec(),
            HashSet::from([value.as_bytes().to_vec()]),
        );
        self.ldap
            .modify(dn, vec![m])
            .await?
            .success()
            .context("modify (add) failed")?;
        Ok(())
    }

    /// Resolve a sAMAccountName to its SID.
    pub async fn resolve_sid(&mut self, sam: &str) -> Result<Sid> {
        let base = self.base_dn.clone();
        let (rs, _) = self
            .ldap
            .search(
                &base,
                Scope::Subtree,
                &format!("(sAMAccountName={sam})"),
                vec!["objectSid"],
            )
            .await?
            .success()?;
        let e = rs.into_iter().next().context("object not found")?;
        let se = SearchEntry::construct(e);
        se.bin_attrs
            .get("objectSid")
            .and_then(|v| v.first())
            .and_then(|b| Sid::from_bytes(b))
            .context("no objectSid")
    }

    /// Replace a binary attribute (e.g. write msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD).
    pub async fn write_binary(&mut self, dn: &str, attr: &str, value: Vec<u8>) -> Result<()> {
        use ldap3::Mod;
        let m: Mod<Vec<u8>> = Mod::Replace(attr.as_bytes().to_vec(), HashSet::from([value]));
        self.ldap
            .modify(dn, vec![m])
            .await?
            .success()
            .context("binary modify failed")?;
        Ok(())
    }

    /// Read a single binary attribute off `dn` (base scope). Uses SD_FLAGS so
    /// `nTSecurityDescriptor` comes back with OWNER|GROUP|DACL populated for
    /// callers that need to round-trip an SD (WriteOwner / WriteDacl).
    pub async fn read_binary(&mut self, dn: &str, attr: &str) -> Result<Option<Vec<u8>>> {
        self.ldap.with_controls(sd_flags_control());
        let (rs, _) = self
            .ldap
            .search(dn, Scope::Base, "(objectClass=*)", vec![attr])
            .await?
            .success()?;
        let Some(entry) = rs.into_iter().next() else {
            return Ok(None);
        };
        let se = SearchEntry::construct(entry);
        Ok(se
            .bin_attrs
            .get(attr)
            .and_then(|v| v.first())
            .cloned()
            .or_else(|| {
                // Some servers echo text-encoded values (e.g. gPLink) via `attrs`
                // rather than `bin_attrs`; fall back to that path.
                se.attrs
                    .get(attr)
                    .and_then(|v| v.first())
                    .map(|s| s.as_bytes().to_vec())
            }))
    }

    /// Read a single text attribute off `dn` (base scope). Returns `None` when
    /// the attribute is absent.
    pub async fn read_text(&mut self, dn: &str, attr: &str) -> Result<Option<String>> {
        let (rs, _) = self
            .ldap
            .search(dn, Scope::Base, "(objectClass=*)", vec![attr])
            .await?
            .success()?;
        let Some(entry) = rs.into_iter().next() else {
            return Ok(None);
        };
        let se = SearchEntry::construct(entry);
        Ok(se.attrs.get(attr).and_then(|v| v.first()).cloned())
    }

    /// Replace a text (single-value string) attribute — the counterpart of
    /// [`write_binary`] used for scalar attrs like `primaryGroupID` or `gPLink`.
    pub async fn modify_replace(&mut self, dn: &str, attr: &str, value: &str) -> Result<()> {
        use ldap3::Mod;
        let m: Mod<Vec<u8>> = Mod::Replace(
            attr.as_bytes().to_vec(),
            HashSet::from([value.as_bytes().to_vec()]),
        );
        self.ldap
            .modify(dn, vec![m])
            .await?
            .success()
            .context("modify (replace) failed")?;
        Ok(())
    }

    /// Read all values of a multi-valued text attribute — `msDS-KeyCredentialLink`
    /// entries (DN-Binary syntax, ASCII), `servicePrincipalName`, `member`, etc.
    /// Returns an empty `Vec` when the attribute is absent.
    pub async fn read_multi_text(&mut self, dn: &str, attr: &str) -> Result<Vec<String>> {
        let (rs, _) = self
            .ldap
            .search(dn, Scope::Base, "(objectClass=*)", vec![attr])
            .await?
            .success()?;
        let Some(entry) = rs.into_iter().next() else {
            return Ok(Vec::new());
        };
        let se = SearchEntry::construct(entry);
        if let Some(v) = se.attrs.get(attr) {
            return Ok(v.clone());
        }
        // ldap3 sometimes classifies mixed-ASCII values as bin_attrs; fall back.
        if let Some(v) = se.bin_attrs.get(attr) {
            return Ok(v
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect());
        }
        Ok(Vec::new())
    }

    /// Replace a multi-valued attribute with the given text values. An empty slice
    /// clears the attribute entirely (LDAP `Replace` with no values = delete all).
    pub async fn replace_multi_text(
        &mut self,
        dn: &str,
        attr: &str,
        values: &[String],
    ) -> Result<()> {
        use ldap3::Mod;
        let set: HashSet<Vec<u8>> = values.iter().map(|v| v.as_bytes().to_vec()).collect();
        let m: Mod<Vec<u8>> = Mod::Replace(attr.as_bytes().to_vec(), set);
        self.ldap
            .modify(dn, vec![m])
            .await?
            .success()
            .context("modify (replace multi) failed")?;
        Ok(())
    }

    /// The base DN this collector is bound at (root of the domain NC).
    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }

    /// Generic subtree search under `base` — used by targeted enumerators (SCCM/SCOM).
    /// Each hit comes back as an `AdObject` (`.one()` / `.all()` accessors). A missing
    /// container surfaces as an LDAP error the caller can treat as "not present / clean".
    pub async fn search_subtree(
        &mut self,
        base: &str,
        filter: &str,
        attrs: Vec<&str>,
    ) -> Result<Vec<AdObject>> {
        let (rs, _) = self
            .ldap
            .search(base, Scope::Subtree, filter, attrs)
            .await?
            .success()?;
        Ok(rs
            .into_iter()
            .map(|e| to_object(SearchEntry::construct(e)))
            .collect())
    }

    /// Read the two flag attributes of an AD CS certificate template. Returns
    /// (`msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`) as signed 32-bit values —
    /// AD stores them as text integers that can be negative when the sign bit is set.
    pub async fn read_template_flags(&mut self, dn: &str) -> Result<(i64, i64)> {
        let (rs, _) = self
            .ldap
            .search(
                dn,
                Scope::Base,
                "(objectClass=*)",
                vec!["msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag"],
            )
            .await?
            .success()?;
        let e = rs.into_iter().next().context("template not found")?;
        let se = SearchEntry::construct(e);
        let read = |attr: &str| -> Result<i64> {
            se.attrs
                .get(attr)
                .and_then(|v| v.first())
                .context(attr.to_string())?
                .parse::<i64>()
                .with_context(|| format!("{attr} parse"))
        };
        Ok((
            read("msPKI-Certificate-Name-Flag")?,
            read("msPKI-Enrollment-Flag")?,
        ))
    }

    /// Create a new LDAP object. `attrs` is a list of `(attribute, [values…])` pairs including
    /// `objectClass`. Used by BadSuccessor (dMSA creation) and dcshadow-style rogue-DC prep.
    pub async fn add_object(&mut self, dn: &str, attrs: Vec<(&str, Vec<Vec<u8>>)>) -> Result<()> {
        let list: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = attrs
            .into_iter()
            .map(|(a, vs)| {
                (
                    a.as_bytes().to_vec(),
                    vs.into_iter().collect::<HashSet<_>>(),
                )
            })
            .collect();
        self.ldap
            .add(dn, list)
            .await?
            .success()
            .context("LDAP add failed")?;
        Ok(())
    }

    /// Delete an LDAP object by DN. Callers that want idempotent delete
    /// (DCShadow cleanup) must swallow NoSuchObject themselves.
    pub async fn delete_object(&mut self, dn: &str) -> Result<()> {
        self.ldap
            .delete(dn)
            .await?
            .success()
            .with_context(|| format!("LDAP delete of {dn} failed"))?;
        Ok(())
    }

    /// Force-set an account password (ForceChangePassword / GenericAll abuse). unicodePwd
    /// is a quoted UTF-16LE string; the DC requires the connection to be encrypted (LDAPS).
    pub async fn set_password(&mut self, dn: &str, password: &str) -> Result<()> {
        use ldap3::Mod;
        let quoted = format!("\"{password}\"");
        let utf16: Vec<u8> = quoted.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let m: Mod<Vec<u8>> = Mod::Replace(b"unicodePwd".to_vec(), HashSet::from([utf16]));
        self.ldap
            .modify(dn, vec![m])
            .await?
            .success()
            .context("password set failed (needs LDAPS + rights)")?;
        Ok(())
    }

    fn domain_info(&self, objects: &[AdObject]) -> DomainInfo {
        let head = objects
            .iter()
            .find(|o| o.dn.eq_ignore_ascii_case(&self.base_dn));
        let domain_sid = head
            .and_then(|o| o.bin1("objectSid"))
            .and_then(Sid::from_bytes);
        DomainInfo {
            domain_dn: self.base_dn.clone(),
            domain_sid,
            netbios: None,
            functional_level: head.and_then(|o| o.int("msDS-Behavior-Version")),
            machine_account_quota: head.and_then(|o| o.int("msDS-MachineAccountQuota")),
        }
    }
}

/// Result of an anonymous RootDSE fingerprint (`scan --anonymous`). All strings
/// come from RootDSE attributes that AD returns without a bound identity.
#[derive(Debug, Clone, Default)]
pub struct RootDseAnon {
    pub default_nc: String,
    pub dns_host: String,
    pub server_name: String,
    pub controls_count: usize,
    pub sasl: Vec<String>,
    /// Non-zero only on legacy 2003/2008 DCs with dSHeuristics permitting
    /// anonymous subtree read — modern AD returns access-denied here.
    pub anon_subtree_hit: usize,
}

/// Anonymous simple_bind + RootDSE read + opportunistic subtree probe. Never
/// touches `--user` / `--password`. Fails fast if the DC refuses the anonymous
/// bind (rare on AD; RootDSE is anonymously readable by design).
pub async fn read_rootdse_anonymous(url: &str, insecure: bool) -> Result<RootDseAnon> {
    ensure_tls_configuration(url, insecure)?;
    let (conn, mut ldap) = if insecure {
        LdapConnAsync::with_settings(insecure_settings()?, url).await
    } else {
        LdapConnAsync::new(url).await
    }
    .context("anonymous ldap connect")?;
    ldap3::drive!(conn);
    // Empty bind_dn + empty password = anonymous simple_bind.
    ldap.simple_bind("", "").await.context("anonymous bind")?;
    let (rs, _) = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec![
                "defaultNamingContext",
                "dnsHostName",
                "serverName",
                "supportedControl",
                "supportedSASLMechanisms",
            ],
        )
        .await
        .context("RootDSE search")?
        .success()
        .context("RootDSE result")?;
    let e = rs.into_iter().next().context("empty RootDSE")?;
    let se = SearchEntry::construct(e);
    let one = |k: &str| se.attrs.get(k).and_then(|v| v.first()).cloned();

    let mut out = RootDseAnon {
        default_nc: one("defaultNamingContext").unwrap_or_default(),
        dns_host: one("dnsHostName").unwrap_or_default(),
        server_name: one("serverName").unwrap_or_default(),
        controls_count: se
            .attrs
            .get("supportedControl")
            .map(|v| v.len())
            .unwrap_or(0),
        sasl: se
            .attrs
            .get("supportedSASLMechanisms")
            .cloned()
            .unwrap_or_default(),
        anon_subtree_hit: 0,
    };

    // Legacy exposure probe: on 2003/2008 the anonymous simple_bind can still
    // subtree-read the domain if dSHeuristics allowed it. Modern DCs return an
    // empty result set or access-denied; both leave anon_subtree_hit = 0.
    if !out.default_nc.is_empty() {
        if let Ok(res) = ldap
            .search(
                &out.default_nc,
                Scope::Subtree,
                "(objectClass=*)",
                vec!["dn"],
            )
            .await
        {
            if let Ok((rs, _)) = res.success() {
                out.anon_subtree_hit = rs.len();
            }
        }
    }
    Ok(out)
}

#[cfg(all(test, not(any(feature = "tls-native", feature = "tls-rustls"))))]
mod no_tls_feature_tests {
    use super::{ensure_tls_configuration, insecure_settings};

    #[test]
    fn plain_ldap_remains_available_without_tls_features() {
        ensure_tls_configuration("ldap://dc.example.test", false).unwrap();
    }

    #[test]
    fn ldaps_is_rejected_before_dial_without_tls_features() {
        let err = ensure_tls_configuration("LdApS://dc.example.test", false).unwrap_err();
        assert!(err.to_string().contains("enable `tls-rustls`"));
    }

    #[test]
    fn insecure_is_rejected_without_tls_features() {
        let config_err = ensure_tls_configuration("ldap://dc.example.test", true).unwrap_err();
        assert!(config_err.to_string().contains("--insecure requires"));

        let err = match insecure_settings() {
            Err(err) => err,
            Ok(_) => panic!("plain-LDAP build unexpectedly accepted --insecure"),
        };
        assert!(err.to_string().contains("--insecure requires"));
    }
}

/// Derive the DNS domain from a naming context DN: `DC=testlab,DC=local` → `testlab.local`.
pub fn dns_from_nc(nc: &str) -> String {
    nc.split(',')
        .filter_map(|p| {
            let p = p.trim();
            p.strip_prefix("DC=").or_else(|| p.strip_prefix("dc="))
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Qualify a bind identity. A bare sAMAccountName gets turned into a UPN (`user@domain`) so
/// simple_bind succeeds on a real DC; anything already qualified (`DOMAIN\user`, a UPN, or a
/// full DN containing `=`) is passed through untouched. A `DOMAIN/user` typo (forward slash) is
/// normalized to `DOMAIN\user` — a forward slash is never valid in a sAMAccountName, so this can
/// only be the NETBIOS separator mistyped, and mis-qualifying it to a UPN yields a confusing
/// `data 52e` bind failure.
fn qualify_bind(name: &str, domain: Option<&str>) -> String {
    let name = name.replace('/', "\\");
    if name.contains('\\') || name.contains('@') || name.contains('=') {
        return name;
    }
    match domain {
        Some(d) if !d.is_empty() => format!("{name}@{d}"),
        _ => name,
    }
}

/// Extract one string field from a flat Windows-LAPS JSON blob (`{"n":..,"t":..,"p":..}`),
/// handling the standard JSON backslash escapes in the value.
fn json_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let after = &json[json.find(&needle)? + needle.len()..];
    let open = after.find('"')?; // the value's opening quote (after the `:`)
    let mut chars = after[open + 1..].chars();
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                other => out.push(other), // \" \\ \/ → literal
            },
            '"' => return Some(out),
            other => out.push(other),
        }
    }
    None
}

/// Build a `LapsEntry` from a computer object, preferring Windows LAPS over legacy, and
/// surfacing an encrypted-only blob as a non-cleartext entry. Returns `None` if no LAPS
/// attribute is present (e.g. a targeted read of a host without LAPS).
fn laps_from_entry(se: &SearchEntry) -> Option<LapsEntry> {
    let sam = se
        .attrs
        .get("sAMAccountName")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();
    let dn = se.dn.clone();

    if let Some(js) = se.attrs.get("msLAPS-Password").and_then(|v| v.first()) {
        return Some(LapsEntry {
            sam,
            dn,
            account: json_field(js, "n").unwrap_or_else(|| "Administrator".into()),
            password: json_field(js, "p"),
            expires: se
                .attrs
                .get("msLAPS-PasswordExpirationTime")
                .and_then(|v| v.first())
                .cloned(),
            source: "msLAPS-Password",
            encrypted_blob: None,
        });
    }
    if let Some(pw) = se.attrs.get("ms-Mcs-AdmPwd").and_then(|v| v.first()) {
        return Some(LapsEntry {
            sam,
            dn,
            account: "Administrator".into(),
            password: Some(pw.clone()),
            expires: se
                .attrs
                .get("ms-Mcs-AdmPwdExpirationTime")
                .and_then(|v| v.first())
                .cloned(),
            source: "ms-Mcs-AdmPwd",
            encrypted_blob: None,
        });
    }
    if let Some(blob) = se
        .bin_attrs
        .get("msLAPS-EncryptedPassword")
        .and_then(|v| v.first())
    {
        return Some(LapsEntry {
            sam,
            dn,
            account: String::new(),
            password: None,
            expires: None,
            source: "msLAPS-EncryptedPassword",
            encrypted_blob: Some(blob.clone()),
        });
    }
    None
}

/// The DNS zone name for a `dnsNode` DN: the last `DC=` component before `,CN=MicrosoftDNS`.
/// `DC=www,DC=corp.local,CN=MicrosoftDNS,…` → `corp.local`.
fn zone_from_dn(dn: &str) -> String {
    let head = dn.split(",CN=MicrosoftDNS").next().unwrap_or(dn);
    head.split(',')
        .filter_map(|p| {
            let p = p.trim();
            p.strip_prefix("DC=").or_else(|| p.strip_prefix("dc="))
        })
        .next_back()
        .unwrap_or("")
        .to_string()
}

/// A `DNS_COUNT_NAME` (MS-DNSP 2.2.2.2.2): total-length byte, label-count byte, then
/// length-prefixed labels. Rendered dotted; the root is `.`.
fn dns_count_name(d: &[u8]) -> Option<String> {
    if d.len() < 2 {
        return Some(".".into());
    }
    let labels_n = d[1] as usize;
    let mut pos = 2;
    let mut labels = Vec::with_capacity(labels_n);
    for _ in 0..labels_n {
        let len = *d.get(pos)? as usize;
        pos += 1;
        let s = d.get(pos..pos + len)?;
        pos += len;
        labels.push(String::from_utf8_lossy(s).into_owned());
    }
    Some(if labels.is_empty() {
        ".".into()
    } else {
        labels.join(".")
    })
}

/// Parse one `DNS_RPC_RECORD` (MS-DNSP 2.2.2.2.1): 24-byte fixed header (DataLength, Type,
/// version/rank/flags, serial, TTL, reserved, timestamp) then type-specific data. Returns
/// (type mnemonic, rendered value, is-tombstone). Unknown types render as a hex dump.
fn parse_dns_record(b: &[u8]) -> Option<(String, String, bool)> {
    if b.len() < 24 {
        return None;
    }
    let dlen = u16::from_le_bytes([b[0], b[1]]) as usize;
    let rtype = u16::from_le_bytes([b[2], b[3]]);
    let data = b.get(24..24 + dlen)?;
    let render = |t: &str, s: String| Some((t.to_string(), s, false));
    match rtype {
        0 => Some(("TOMBSTONE".into(), String::new(), true)),
        1 if data.len() >= 4 => render(
            "A",
            format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]),
        ),
        2 => render("NS", dns_count_name(data)?),
        5 => render("CNAME", dns_count_name(data)?),
        6 if data.len() >= 24 => {
            let serial = u32::from_be_bytes(data[0..4].try_into().ok()?);
            let primary = dns_count_name(&data[20..])?;
            render("SOA", format!("serial={serial} primary={primary}"))
        }
        12 => render("PTR", dns_count_name(data)?),
        15 if data.len() >= 2 => {
            let pref = u16::from_be_bytes([data[0], data[1]]);
            render("MX", format!("{pref} {}", dns_count_name(&data[2..])?))
        }
        16 => {
            let mut pos = 0;
            let mut parts = Vec::new();
            while pos < data.len() {
                let len = data[pos] as usize;
                pos += 1;
                if let Some(s) = data.get(pos..pos + len) {
                    parts.push(String::from_utf8_lossy(s).into_owned());
                }
                pos += len;
            }
            render("TXT", parts.join(" "))
        }
        28 if data.len() >= 16 => {
            let groups: Vec<String> = data[..16]
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            render("AAAA", groups.join(":"))
        }
        33 if data.len() >= 6 => {
            let pri = u16::from_be_bytes([data[0], data[1]]);
            let wt = u16::from_be_bytes([data[2], data[3]]);
            let port = u16::from_be_bytes([data[4], data[5]]);
            render(
                "SRV",
                format!("{pri} {wt} {port} {}", dns_count_name(&data[6..])?),
            )
        }
        n => {
            let hex: String = data.iter().map(|x| format!("{x:02x}")).collect();
            render(&format!("TYPE{n}"), hex)
        }
    }
}

/// Read defaultNamingContext + configurationNamingContext from RootDSE.
async fn root_ncs(ldap: &mut ldap3::Ldap) -> Result<(String, String)> {
    let (rs, _) = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["defaultNamingContext", "configurationNamingContext"],
        )
        .await?
        .success()?;
    let e = rs.into_iter().next().context("empty RootDSE")?;
    let se = SearchEntry::construct(e);
    let default_nc = se
        .attrs
        .get("defaultNamingContext")
        .and_then(|v| v.first())
        .cloned()
        .context("no defaultNamingContext")?;
    let config_nc = se
        .attrs
        .get("configurationNamingContext")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| format!("CN=Configuration,{default_nc}"));
    Ok((default_nc, config_nc))
}

fn to_object(se: SearchEntry) -> AdObject {
    let bin: HashMap<String, Vec<Vec<u8>>> = se.bin_attrs.into_iter().collect();
    AdObject {
        dn: se.dn,
        attrs: se.attrs,
        bin,
    }
}

#[cfg(test)]
mod tests {
    use super::{dns_from_nc, json_field, laps_from_entry, qualify_bind};
    use ldap3::SearchEntry;
    use std::collections::HashMap;

    fn entry(dn: &str, attrs: &[(&str, &str)], bin: &[&str]) -> SearchEntry {
        SearchEntry {
            dn: dn.to_string(),
            attrs: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
                .collect(),
            bin_attrs: bin
                .iter()
                .map(|k| (k.to_string(), vec![vec![0u8, 1, 2, 3]]))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn wlaps_json_field_extract() {
        let js = r#"{"n":"Administrator","t":"1db0000000","p":"Str0ng!\"pw\\x"}"#;
        assert_eq!(json_field(js, "n").as_deref(), Some("Administrator"));
        // password with an escaped quote and backslash must round-trip.
        assert_eq!(json_field(js, "p").as_deref(), Some("Str0ng!\"pw\\x"));
        assert_eq!(json_field(js, "missing"), None);
    }

    #[test]
    fn laps_prefers_windows_json() {
        let js = r#"{"n":"LAPSAdmin","t":"1db","p":"WinLapsPw1"}"#;
        let e = laps_from_entry(&entry(
            "CN=WIN11,OU=X,DC=t,DC=l",
            &[("sAMAccountName", "WIN11$"), ("msLAPS-Password", js)],
            &[],
        ))
        .unwrap();
        assert_eq!(e.sam, "WIN11$");
        assert_eq!(e.account, "LAPSAdmin");
        assert_eq!(e.password.as_deref(), Some("WinLapsPw1"));
        assert_eq!(e.source, "msLAPS-Password");
    }

    #[test]
    fn laps_legacy_cleartext() {
        let e = laps_from_entry(&entry(
            "CN=SRV,DC=t,DC=l",
            &[("sAMAccountName", "SRV$"), ("ms-Mcs-AdmPwd", "L3gacyPw!")],
            &[],
        ))
        .unwrap();
        assert_eq!(e.account, "Administrator");
        assert_eq!(e.password.as_deref(), Some("L3gacyPw!"));
        assert_eq!(e.source, "ms-Mcs-AdmPwd");
    }

    #[test]
    fn laps_encrypted_blob_has_no_cleartext() {
        let e = laps_from_entry(&entry(
            "CN=DC,DC=t,DC=l",
            &[("sAMAccountName", "DC$")],
            &["msLAPS-EncryptedPassword"],
        ))
        .unwrap();
        assert!(e.password.is_none());
        assert_eq!(e.source, "msLAPS-EncryptedPassword");
    }

    #[test]
    fn laps_absent_returns_none() {
        assert!(
            laps_from_entry(&entry("CN=X,DC=t,DC=l", &[("sAMAccountName", "X$")], &[])).is_none()
        );
    }

    // ---- ADIDNS ----------------------------------------------------------
    use super::{dns_count_name, parse_dns_record, zone_from_dn};

    /// Build a DNS_RPC_RECORD: 24-byte header (DataLength, Type, …) + data.
    fn dns_rec(rtype: u16, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(data.len() as u16).to_le_bytes()); // DataLength
        b.extend_from_slice(&rtype.to_le_bytes()); // Type
        b.extend_from_slice(&[0u8; 20]); // version/rank/flags/serial/ttl/reserved/timestamp
        b.extend_from_slice(data);
        b
    }

    #[test]
    fn zone_name_from_dnsnode_dn() {
        assert_eq!(
            zone_from_dn("DC=www,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local"),
            "corp.local"
        );
        assert_eq!(
            zone_from_dn("DC=_ldap._tcp,DC=corp.local,CN=MicrosoftDNS,CN=System,DC=corp,DC=local"),
            "corp.local"
        );
    }

    #[test]
    fn parse_a_record() {
        let (t, v, tomb) = parse_dns_record(&dns_rec(1, &[192, 168, 10, 5])).unwrap();
        assert_eq!((t.as_str(), v.as_str(), tomb), ("A", "192.168.10.5", false));
    }

    #[test]
    fn parse_cname_count_name() {
        // DNS_COUNT_NAME for "dc.corp.local": total-len, label-count=3, then 3 labels.
        let mut d = vec![0u8, 3]; // [0]=total (unused by parser), [1]=label count
        for label in ["dc", "corp", "local"] {
            d.push(label.len() as u8);
            d.extend_from_slice(label.as_bytes());
        }
        let (t, v, _) = parse_dns_record(&dns_rec(5, &d)).unwrap();
        assert_eq!(t, "CNAME");
        assert_eq!(v, "dc.corp.local");
        assert_eq!(dns_count_name(&d).unwrap(), "dc.corp.local");
    }

    #[test]
    fn parse_tombstone_and_unknown() {
        let (t, _, tomb) = parse_dns_record(&dns_rec(0, &[])).unwrap();
        assert_eq!((t.as_str(), tomb), ("TOMBSTONE", true));
        let (t2, v2, _) = parse_dns_record(&dns_rec(99, &[0xde, 0xad])).unwrap();
        assert_eq!(t2, "TYPE99");
        assert_eq!(v2, "dead"); // 2 bytes → 4 hex chars
    }

    #[test]
    fn short_record_rejected() {
        assert!(parse_dns_record(&[0u8; 10]).is_none());
    }

    #[test]
    fn nc_to_dns() {
        assert_eq!(dns_from_nc("DC=testlab,DC=local"), "testlab.local");
        assert_eq!(dns_from_nc("dc=corp,dc=example,dc=com"), "corp.example.com");
        assert_eq!(dns_from_nc("CN=x,DC=a,DC=b"), "a.b"); // ignores non-DC RDNs
    }

    #[test]
    fn bare_name_becomes_upn() {
        assert_eq!(
            qualify_bind("administrator", Some("testlab.local")),
            "administrator@testlab.local"
        );
    }

    #[test]
    fn forward_slash_typo_normalized_to_backslash() {
        // `DOMAIN/user` (forward slash) must bind as `DOMAIN\user`, not mis-qualify to a UPN.
        let d = Some("testlab.local");
        assert_eq!(qualify_bind("TESTLAB/labuser", d), "TESTLAB\\labuser");
        assert_eq!(qualify_bind("TESTLAB/labuser", None), "TESTLAB\\labuser");
    }

    #[test]
    fn qualified_names_pass_through() {
        let d = Some("testlab.local");
        assert_eq!(
            qualify_bind("TESTLAB\\Administrator", d),
            "TESTLAB\\Administrator"
        );
        assert_eq!(qualify_bind("admin@other.com", d), "admin@other.com");
        assert_eq!(
            qualify_bind("CN=Admin,DC=testlab,DC=local", d),
            "CN=Admin,DC=testlab,DC=local"
        );
    }

    #[test]
    fn no_domain_leaves_bare_name() {
        assert_eq!(qualify_bind("administrator", None), "administrator");
        assert_eq!(qualify_bind("administrator", Some("")), "administrator");
    }
}
