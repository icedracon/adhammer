//! Engagement scope and no-cred assessment control-plane types.
//!
//! WS-FOUNDATION-INTEGRATE (1.4.10 foundation, capability in 1.5.0). These types describe what the operator
//! is allowed to touch, what a check reports, and which capability a later
//! phase may consume. Protocol-agnostic — the network implementation lives
//! elsewhere.
//!
//! ## Excludes-win-across-identity (BF-3 fix)
//!
//! Prior draft only checked one identity form at a time: `contains_ip`
//! walked IP-shaped excludes, `contains_hostname` walked hostname-shaped
//! excludes. A target excluded by name could still be reached by IP (and
//! vice versa). The [`EngagementScope::allows`] entry point now takes an
//! optional IP + optional hostname pair and refuses if EITHER form matches
//! ANY exclude — regardless of which axis the exclude was declared on.
//! Runners that resolve DNS before scope-check pass both forms so an
//! exclude on `dc01.corp.local` blocks the query for `10.0.0.10` too.

use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A machine-readable assessment scope.
///
/// The operator provides an include list and an optional exclude list.
/// Includes must be non-empty. Excludes always win over includes, across
/// every identity form the caller can provide.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngagementScope {
    pub includes: Vec<ScopeTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excludes: Vec<ScopeTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_hints: Vec<String>,
}

impl EngagementScope {
    pub fn new(includes: Vec<ScopeTarget>) -> Result<Self, ScopeError> {
        let scope = Self {
            includes,
            excludes: Vec::new(),
            domain_hints: Vec::new(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ScopeError> {
        if self.includes.is_empty() {
            return Err(ScopeError::EmptyIncludes);
        }
        for target in self.includes.iter().chain(self.excludes.iter()) {
            target.validate()?;
        }
        for hint in &self.domain_hints {
            if normalize_name(hint).is_none() {
                return Err(ScopeError::InvalidDomainHint(hint.clone()));
            }
        }
        Ok(())
    }

    /// Single-axis include check for an IP. See [`Self::allows`] for the
    /// full excludes-win-across-identity contract; call `allows` unless you
    /// deliberately want to bypass the cross-form exclude check (rare).
    fn ip_in_includes(&self, ip: IpAddr) -> bool {
        self.includes.iter().any(|target| target.matches_ip(ip))
    }

    /// Single-axis include check for a hostname.
    fn hostname_in_includes(&self, hostname: &str) -> bool {
        self.includes
            .iter()
            .any(|target| target.matches_hostname(hostname))
    }

    /// BF-3: exclude match on ANY provided identity form. If the caller
    /// supplies both `ip` and `hostname`, either alone matching an exclude
    /// vetoes the target.
    fn any_exclude_matches(&self, ip: Option<IpAddr>, hostname: Option<&str>) -> bool {
        if let Some(ip) = ip {
            if self.excludes.iter().any(|target| target.matches_ip(ip)) {
                return true;
            }
        }
        if let Some(hostname) = hostname {
            if self
                .excludes
                .iter()
                .any(|target| target.matches_hostname(hostname))
            {
                return true;
            }
        }
        false
    }

    /// BF-3 fix. Returns `true` iff:
    ///   1. at least one of `ip` / `hostname` appears in the include list; AND
    ///   2. NEITHER `ip` nor `hostname` appears in ANY exclude.
    ///
    /// Callers that only know one identity form supply `None` for the other;
    /// the exclude check runs against only the known form. Runners that
    /// resolve DNS before scope-check should call this with both forms so
    /// an exclude on `dc01.corp.local` also blocks `10.0.0.10`.
    pub fn allows(&self, ip: Option<IpAddr>, hostname: Option<&str>) -> bool {
        let in_includes = match (ip, hostname) {
            (None, None) => return false,
            (Some(ip), None) => self.ip_in_includes(ip),
            (None, Some(h)) => self.hostname_in_includes(h),
            (Some(ip), Some(h)) => self.ip_in_includes(ip) || self.hostname_in_includes(h),
        };
        if !in_includes {
            return false;
        }
        !self.any_exclude_matches(ip, hostname)
    }

    /// Convenience: allows-check for an IP-only target.
    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        self.allows(Some(ip), None)
    }

    /// Convenience: allows-check for a hostname-only target.
    pub fn allows_hostname(&self, hostname: &str) -> bool {
        self.allows(None, Some(hostname))
    }
}

/// One target shape allowed in an engagement scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ScopeTarget {
    Host { addr: IpAddr },
    Cidr { net: IpNet },
    Hostname { name: String },
}

impl ScopeTarget {
    pub fn validate(&self) -> Result<(), ScopeError> {
        match self {
            ScopeTarget::Host { .. } | ScopeTarget::Cidr { .. } => Ok(()),
            ScopeTarget::Hostname { name } => {
                if normalize_name(name).is_some() {
                    Ok(())
                } else {
                    Err(ScopeError::InvalidHostname(name.clone()))
                }
            }
        }
    }

    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match self {
            ScopeTarget::Host { addr } => *addr == ip,
            ScopeTarget::Cidr { net } => net.contains(&ip),
            ScopeTarget::Hostname { .. } => false,
        }
    }

    pub fn matches_hostname(&self, hostname: &str) -> bool {
        match self {
            ScopeTarget::Hostname { name } => {
                let lhs = normalize_name(name);
                let rhs = normalize_name(hostname);
                lhs.is_some() && lhs == rhs
            }
            ScopeTarget::Host { .. } | ScopeTarget::Cidr { .. } => false,
        }
    }
}

/// Stable check identifier for the black-box runner and report output.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CheckId(String);

impl CheckId {
    pub fn new(value: impl Into<String>) -> Result<Self, ScopeError> {
        let value = value.into();
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ScopeError::InvalidCheckId(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// High-level class of a check for operator policy and reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckClass {
    Discovery,
    Impact,
    PostCred,
}

/// Coarse result vocabulary for a single check execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingStatus {
    Found,
    NotFound,
    Blocked,
    NotApplicable,
    Error,
}

/// Opaque handle used to reference a secret without rendering the secret itself.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretHandle(String);

impl SecretHandle {
    pub fn new(value: impl Into<String>) -> Result<Self, ScopeError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ScopeError::InvalidSecretHandle(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A capability recovered during a run that can unlock later checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub kind: CapabilityKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CheckId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretHandle>,
}

/// Capability category, intentionally coarse for the first implementation pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityKind {
    AnonymousLdap,
    SmbNullSession,
    Password,
    MachineAccount,
    KerberosTicket,
    Certificate,
}

/// A recommended next action emitted by a check or report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextAction {
    pub check: CheckId,
    pub class: CheckClass,
    pub summary: String,
    #[serde(default)]
    pub requires_consent: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("engagement scope must include at least one target")]
    EmptyIncludes,
    #[error("invalid hostname in scope: {0}")]
    InvalidHostname(String),
    #[error("invalid domain hint in scope: {0}")]
    InvalidDomainHint(String),
    #[error("invalid check id: {0}")]
    InvalidCheckId(String),
    #[error("invalid secret handle: {0}")]
    InvalidSecretHandle(String),
}

fn normalize_name(name: &str) -> Option<String> {
    let trimmed = name.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_')
    {
        return None;
    }
    if trimmed.starts_with('.') || trimmed.ends_with('.') || trimmed.contains("..") {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn empty_includes_rejected() {
        let err = EngagementScope::new(Vec::new()).unwrap_err();
        assert_eq!(err, ScopeError::EmptyIncludes);
    }

    #[test]
    fn cidr_contains_ip() {
        let scope = EngagementScope::new(vec![ScopeTarget::Cidr {
            net: IpNet::from_str("10.0.0.0/24").unwrap(),
        }])
        .unwrap();
        assert!(scope.allows_ip(IpAddr::from_str("10.0.0.42").unwrap()));
        assert!(!scope.allows_ip(IpAddr::from_str("10.0.1.42").unwrap()));
    }

    #[test]
    fn exclude_overrides_include() {
        let scope = EngagementScope {
            includes: vec![ScopeTarget::Cidr {
                net: IpNet::from_str("10.0.0.0/24").unwrap(),
            }],
            excludes: vec![ScopeTarget::Host {
                addr: IpAddr::from_str("10.0.0.42").unwrap(),
            }],
            domain_hints: Vec::new(),
        };
        scope.validate().unwrap();
        assert!(!scope.allows_ip(IpAddr::from_str("10.0.0.42").unwrap()));
        assert!(scope.allows_ip(IpAddr::from_str("10.0.0.43").unwrap()));
    }

    #[test]
    fn hostname_matching_is_case_insensitive() {
        let scope = EngagementScope::new(vec![ScopeTarget::Hostname {
            name: "DC01.Corp.Local".into(),
        }])
        .unwrap();
        assert!(scope.allows_hostname("dc01.corp.local"));
        assert!(scope.allows_hostname("DC01.CORP.LOCAL."));
        assert!(!scope.allows_hostname("dc02.corp.local"));
    }

    /// BF-3 regression. Prior draft: excluding a hostname did NOT block
    /// the corresponding IP. `allows(Some(ip), Some(hostname))` must
    /// refuse if EITHER the ip or the hostname is excluded.
    #[test]
    fn hostname_exclude_blocks_ip_lookup_via_allows() {
        let scope = EngagementScope {
            includes: vec![ScopeTarget::Cidr {
                net: IpNet::from_str("10.0.0.0/24").unwrap(),
            }],
            excludes: vec![ScopeTarget::Hostname {
                name: "dc01.corp.local".into(),
            }],
            domain_hints: Vec::new(),
        };
        scope.validate().unwrap();
        let ip = IpAddr::from_str("10.0.0.10").unwrap();
        // Ip-only lookup — no hostname context, so the hostname exclude
        // cannot fire. Caller loses the cross-form protection when they
        // pass only one axis; documented on `allows`.
        assert!(scope.allows(Some(ip), None));
        // Once the caller supplies BOTH forms, the hostname exclude wins.
        assert!(!scope.allows(Some(ip), Some("dc01.corp.local")));
    }

    /// BF-3 regression: reverse of the above — an IP exclude blocks the
    /// query even when the include shape is a hostname.
    #[test]
    fn ip_exclude_blocks_hostname_lookup_via_allows() {
        let scope = EngagementScope {
            includes: vec![ScopeTarget::Hostname {
                name: "dc01.corp.local".into(),
            }],
            excludes: vec![ScopeTarget::Host {
                addr: IpAddr::from_str("10.0.0.10").unwrap(),
            }],
            domain_hints: Vec::new(),
        };
        scope.validate().unwrap();
        let ip = IpAddr::from_str("10.0.0.10").unwrap();
        // Hostname-only lookup: passes (no ip context to hit the exclude).
        assert!(scope.allows(None, Some("dc01.corp.local")));
        // With ip context: exclude wins.
        assert!(!scope.allows(Some(ip), Some("dc01.corp.local")));
    }

    #[test]
    fn allows_with_no_identity_forms_returns_false() {
        let scope = EngagementScope::new(vec![ScopeTarget::Host {
            addr: IpAddr::from_str("10.0.0.1").unwrap(),
        }])
        .unwrap();
        assert!(!scope.allows(None, None));
    }

    #[test]
    fn scope_round_trips_through_json() {
        let scope = EngagementScope {
            includes: vec![
                ScopeTarget::Cidr {
                    net: IpNet::from_str("192.168.10.0/24").unwrap(),
                },
                ScopeTarget::Hostname {
                    name: "dc01.lab.local".into(),
                },
            ],
            excludes: vec![ScopeTarget::Host {
                addr: IpAddr::from_str("192.168.10.1").unwrap(),
            }],
            domain_hints: vec!["lab.local".into()],
        };
        let json = serde_json::to_string(&scope).unwrap();
        let decoded: EngagementScope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, scope);
        assert!(decoded.allows_hostname("DC01.LAB.LOCAL"));
    }

    #[test]
    fn invalid_names_rejected() {
        let err = EngagementScope::new(vec![ScopeTarget::Hostname {
            name: "bad host".into(),
        }])
        .unwrap_err();
        assert_eq!(err, ScopeError::InvalidHostname("bad host".into()));

        let scope = EngagementScope {
            includes: vec![ScopeTarget::Host {
                addr: IpAddr::from_str("127.0.0.1").unwrap(),
            }],
            excludes: Vec::new(),
            domain_hints: vec!["corp local".into()],
        };
        let err = scope.validate().unwrap_err();
        assert_eq!(err, ScopeError::InvalidDomainHint("corp local".into()));
    }

    #[test]
    fn check_id_requires_lowercase_kebab_case() {
        assert_eq!(CheckId::new("dns-enum").unwrap().as_str(), "dns-enum");
        let err = CheckId::new("DnsEnum").unwrap_err();
        assert_eq!(err, ScopeError::InvalidCheckId("DnsEnum".into()));
    }

    #[test]
    fn secret_handle_must_not_be_empty() {
        let err = SecretHandle::new("").unwrap_err();
        assert_eq!(err, ScopeError::InvalidSecretHandle(String::new()));
    }
}
