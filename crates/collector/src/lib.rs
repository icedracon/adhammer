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

#[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
compile_error!("enable a TLS backend: `tls-rustls` (default) or `tls-native`");

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

        let base = self.base_dn.clone();
        self.search_into(&base, "(objectClass=*)", &mut objects)
            .await?;

        let pki_base = format!("CN=Public Key Services,CN=Services,{}", self.config_dn);
        if let Err(e) = self.search_into(&pki_base, PKI_FILTER, &mut objects).await {
            tracing::warn!(%e, "AD CS container not collected (no PKI, or access denied)");
        }

        let ds = format!(
            "CN=Directory Service,CN=Windows NT,CN=Services,{}",
            self.config_dn
        );
        if let Err(e) = self.search_base_into(&ds, &mut objects).await {
            tracing::warn!(%e, "Directory Service object not collected");
        }

        let domain = self.domain_info(&objects);
        Ok(Snapshot::new(domain, objects))
    }

    /// Base-scope read of a single object (e.g. the Directory Service heuristics object).
    async fn search_base_into(&mut self, base: &str, out: &mut Vec<AdObject>) -> Result<()> {
        self.ldap.with_controls(sd_flags_control());
        let (rs, _) = self
            .ldap
            .search(base, Scope::Base, "(objectClass=*)", ATTRS.to_vec())
            .await?
            .success()?;
        for e in rs {
            out.push(to_object(SearchEntry::construct(e)));
        }
        Ok(())
    }

    async fn search_into(
        &mut self,
        base: &str,
        filter: &str,
        out: &mut Vec<AdObject>,
    ) -> Result<()> {
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(1000)),
        ];
        self.ldap.with_controls(sd_flags_control());
        let mut stream = self
            .ldap
            .streaming_search_with(adapters, base, Scope::Subtree, filter, ATTRS.to_vec())
            .await?;
        while let Some(entry) = stream.next().await? {
            out.push(to_object(SearchEntry::construct(entry)));
        }
        stream.finish().await.success().ok();
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

/// Derive the DNS domain from a naming context DN: `DC=testlab,DC=local` → `testlab.local`.
fn dns_from_nc(nc: &str) -> String {
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
/// full DN containing `=`) is passed through untouched.
fn qualify_bind(name: &str, domain: Option<&str>) -> String {
    if name.contains('\\') || name.contains('@') || name.contains('=') {
        return name.to_string();
    }
    match domain {
        Some(d) if !d.is_empty() => format!("{name}@{d}"),
        _ => name.to_string(),
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
        });
    }
    if se.bin_attrs.contains_key("msLAPS-EncryptedPassword") {
        return Some(LapsEntry {
            sam,
            dn,
            account: String::new(),
            password: None,
            expires: None,
            source: "msLAPS-EncryptedPassword",
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
