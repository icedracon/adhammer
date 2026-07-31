//! Host/DC posture checks decided from the registry (over MS-RRP) and live pipe reachability —
//! the NTLM-relay and coercion enablers that a pure-LDAP snapshot can't see:
//!
//! - **LDAP signing** — `NTDS\Parameters\LDAPServerIntegrity`. 2 = required; anything else (incl.
//!   the value being absent) means the DC accepts unsigned LDAP binds → **relayable** (the exact
//!   precondition `attack relay` needs).
//! - **LDAP channel binding** — `NTDS\Parameters\LdapEnforceChannelBinding`. 0/absent = never
//!   enforced → NTLM relay to **LDAPS** works too; 1 = only when the client asks (still bypassable);
//!   2 = always (safe).
//! - **Print Spooler on a DC** — the `\spoolss` pipe answering means the Spooler service is running
//!   on the DC: PrinterBug coercion (`attack coerce --pipe spoolss`) + PrintNightmare surface.
//!
//! Decision logic is pure and unit-tested; the CLI (`enum posture`) supplies the read values.

/// One posture finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureHit {
    pub id: &'static str,
    pub severity: &'static str,
    pub title: &'static str,
    pub detail: String,
}

/// `LDAPServerIntegrity`: 2 = require signing; 1 = none; absent ⇒ historically "not required".
/// Fires whenever the DC does not *require* signing (relayable).
pub fn ldap_signing(integrity: Option<u32>) -> Option<PostureHit> {
    if integrity == Some(2) {
        return None;
    }
    let state = match integrity {
        Some(v) => format!("LDAPServerIntegrity = {v}"),
        None => "LDAPServerIntegrity unset (default: signing not required)".to_string(),
    };
    Some(PostureHit {
        id: "A-LdapSigning",
        severity: "HIGH",
        title: "DC does not require LDAP signing (NTLM-relayable)",
        detail: format!(
            "{state} — the DC accepts unsigned LDAP binds, so a coerced/poisoned machine's NTLM can \
             be relayed to LDAP (e.g. to write a Shadow Credential / RBCD on a Tier-0 object). \
             Remediation: set the 'Domain controller: LDAP server signing requirements' policy to \
             'Require signing' (LDAPServerIntegrity = 2)."
        ),
    })
}

/// `LdapEnforceChannelBinding`: 2 = always, 1 = when supported, 0/absent = never. Fires unless 2;
/// 0/absent is HIGH (LDAPS relay works), 1 is MEDIUM (bypassable by clients that don't offer CBT).
pub fn ldap_channel_binding(cbt: Option<u32>) -> Option<PostureHit> {
    match cbt {
        Some(2) => None,
        Some(1) => Some(PostureHit {
            id: "A-LdapChannelBinding",
            severity: "MEDIUM",
            title: "LDAP channel binding only enforced 'when supported' (partially relayable)",
            detail: "LdapEnforceChannelBinding = 1 — clients that don't present a channel-binding \
                     token are still accepted, so an NTLM relay to LDAPS can succeed. Remediation: \
                     set it to 2 (always)."
                .to_string(),
        }),
        _ => {
            let state = match cbt {
                Some(v) => format!("LdapEnforceChannelBinding = {v}"),
                None => "LdapEnforceChannelBinding unset (default: not enforced)".to_string(),
            };
            Some(PostureHit {
                id: "A-LdapChannelBinding",
                severity: "HIGH",
                title: "DC does not enforce LDAP channel binding (LDAPS NTLM-relayable)",
                detail: format!(
                    "{state} — NTLM can be relayed to LDAPS despite TLS. Remediation: set \
                     LdapEnforceChannelBinding = 2 (KB4520412)."
                ),
            })
        }
    }
}

/// Print Spooler reachable on the DC (the `\spoolss` pipe answered).
pub fn spooler_running(pipe_open: bool) -> Option<PostureHit> {
    pipe_open.then(|| PostureHit {
        id: "A-SpoolerOnDc",
        severity: "MEDIUM",
        title: "Print Spooler is running on the domain controller",
        detail: "The \\spoolss pipe is reachable — the Spooler exposes PrinterBug (MS-RPRN \
                 RpcRemoteFindFirstPrinterChangeNotificationEx) for authentication coercion and the \
                 PrintNightmare (CVE-2021-1675 / CVE-2021-34527) RCE/LPE surface. Remediation: \
                 disable the Print Spooler service on domain controllers."
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldap_signing_fires_unless_required() {
        assert!(ldap_signing(Some(1)).is_some()); // none
        assert!(ldap_signing(None).is_some()); // unset ⇒ not required
        assert!(ldap_signing(Some(0)).is_some());
        assert!(ldap_signing(Some(2)).is_none()); // required ⇒ safe
    }

    #[test]
    fn channel_binding_severity_by_value() {
        assert_eq!(ldap_channel_binding(None).unwrap().severity, "HIGH");
        assert_eq!(ldap_channel_binding(Some(0)).unwrap().severity, "HIGH");
        assert_eq!(ldap_channel_binding(Some(1)).unwrap().severity, "MEDIUM");
        assert!(ldap_channel_binding(Some(2)).is_none());
    }

    #[test]
    fn spooler_only_when_open() {
        assert!(spooler_running(true).is_some());
        assert!(spooler_running(false).is_none());
    }
}
