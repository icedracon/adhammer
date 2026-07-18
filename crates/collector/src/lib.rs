//! LDAP collection layer. Pulls the object classes the checks + graph need, in paged
//! sweeps over the domain NC *and* the Configuration NC (where AD CS templates + CAs
//! live), and normalizes them into `core::Snapshot`. Binary attrs (objectSid,
//! nTSecurityDescriptor, objectGUID, RBCD) are requested raw so we parse them ourselves.

use adhammer_core::object::AdObject;
use adhammer_core::sid::Sid;
use adhammer_core::snapshot::{DomainInfo, Snapshot};
use anyhow::{Context, Result};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::collections::HashMap;

/// Attributes we always want. `nTSecurityDescriptor` comes back with owner/group/dacl
/// even without SeSecurityPrivilege. AD CS template attrs are harmless on other objects.
const ATTRS: &[&str] = &[
    "objectClass", "cn", "sAMAccountName", "distinguishedName", "objectSid", "objectGUID",
    "userAccountControl", "servicePrincipalName", "adminCount", "memberOf", "member",
    "pwdLastSet", "lastLogonTimestamp", "whenCreated", "operatingSystem",
    "msDS-SupportedEncryptionTypes", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-KeyCredentialLink", "nTSecurityDescriptor",
    "trustAttributes", "trustDirection", "trustType", "trustPartner", "flatName",
    "securityIdentifier", "whenChanged",
    "msDS-MachineAccountQuota", "msDS-Behavior-Version", "primaryGroupID", "sIDHistory",
    // gMSA read-password ACL + LAPS coverage
    "msDS-GroupMSAMembership", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime",
    // AD CS: certificate templates + enrollment services (CAs)
    "displayName", "dNSHostName", "certificateTemplates",
    "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
    "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
    "msPKI-Certificate-Policy", "msPKI-Template-Schema-Version",
    // domain password policy + Directory Service heuristics (anonymous LDAP etc.)
    "minPwdLength", "pwdProperties", "maxPwdAge", "minPwdAge", "lockoutThreshold",
    "lockoutDuration", "dSHeuristics",
];

/// Object classes to pull from the Public Key Services container under the config NC.
const PKI_FILTER: &str =
    "(|(objectClass=pKICertificateTemplate)(objectClass=pKIEnrollmentService)(objectClass=certificationAuthority))";

pub struct LdapConfig {
    pub url: String,      // ldap://dc.corp.local:389  or ldaps://...
    pub bind_dn: String,  // CORP\\user  or user@corp.local  or full DN
    pub password: String,
    pub base_dn: Option<String>, // default: RootDSE defaultNamingContext
    pub insecure: bool,   // skip TLS cert verification (labs / self-signed DC certs)
}

/// Accept any server certificate — lab use only, for self-signed DC certs over LDAPS.
struct NoCertVerify;
impl rustls::client::ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn insecure_tls() -> std::sync::Arc<rustls::ClientConfig> {
    let cfg = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerify))
        .with_no_client_auth();
    std::sync::Arc::new(cfg)
}

pub struct Collector {
    ldap: ldap3::Ldap,
    base_dn: String,
    config_dn: String,
}

impl Collector {
    pub async fn connect(cfg: &LdapConfig) -> Result<Self> {
        let (conn, mut ldap) = if cfg.insecure {
            let settings = ldap3::LdapConnSettings::new().set_config(insecure_tls());
            LdapConnAsync::with_settings(settings, &cfg.url).await.context("ldap connect")?
        } else {
            LdapConnAsync::new(&cfg.url).await.context("ldap connect")?
        };
        ldap3::drive!(conn);
        ldap.simple_bind(&cfg.bind_dn, &cfg.password)
            .await?
            .success()
            .context("bind failed")?;

        let (default_nc, config_nc) = root_ncs(&mut ldap).await?;
        let base_dn = cfg.base_dn.clone().unwrap_or(default_nc);
        Ok(Collector { ldap, base_dn, config_dn: config_nc })
    }

    /// Paged subtree search over the domain NC, then over the AD CS container.
    /// A missing Public Key Services container (no ADCS) is tolerated, not fatal.
    pub async fn collect(mut self) -> Result<Snapshot> {
        let mut objects = Vec::new();

        let base = self.base_dn.clone();
        self.search_into(&base, "(objectClass=*)", &mut objects).await?;

        let pki_base = format!("CN=Public Key Services,CN=Services,{}", self.config_dn);
        if let Err(e) = self.search_into(&pki_base, PKI_FILTER, &mut objects).await {
            tracing::warn!(%e, "AD CS container not collected (no PKI, or access denied)");
        }

        let ds = format!("CN=Directory Service,CN=Windows NT,CN=Services,{}", self.config_dn);
        if let Err(e) = self.search_base_into(&ds, &mut objects).await {
            tracing::warn!(%e, "Directory Service object not collected");
        }

        let domain = self.domain_info(&objects);
        Ok(Snapshot::new(domain, objects))
    }

    /// Base-scope read of a single object (e.g. the Directory Service heuristics object).
    async fn search_base_into(&mut self, base: &str, out: &mut Vec<AdObject>) -> Result<()> {
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

    async fn search_into(&mut self, base: &str, filter: &str, out: &mut Vec<AdObject>) -> Result<()> {
        let adapters: Vec<Box<dyn Adapter<_, _>>> =
            vec![Box::new(EntriesOnly::new()), Box::new(PagedResults::new(1000))];
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

    fn domain_info(&self, objects: &[AdObject]) -> DomainInfo {
        let head = objects.iter().find(|o| o.dn.eq_ignore_ascii_case(&self.base_dn));
        let domain_sid = head.and_then(|o| o.bin1("objectSid")).and_then(Sid::from_bytes);
        DomainInfo {
            domain_dn: self.base_dn.clone(),
            domain_sid,
            netbios: None,
            functional_level: head.and_then(|o| o.int("msDS-Behavior-Version")),
            machine_account_quota: head.and_then(|o| o.int("msDS-MachineAccountQuota")),
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
    AdObject { dn: se.dn, attrs: se.attrs, bin }
}
