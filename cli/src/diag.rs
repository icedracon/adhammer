//! WS-UX-ERRORS (1.5.1): the shared error→fix classifier. `doctor` uses it for its
//! bind verdict; `main` uses [`fix_hint`] to append a named remediation to ANY verb's
//! failure, so a tool that dumps an opaque error becomes one that teaches the fix.
//!
//! Pure + unit-tested. Conservative: [`fix_hint`] returns `None` for errors it does not
//! confidently recognize, so it never bolts a misleading hint onto an unrelated failure.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BindVerdict {
    Success,
    InvalidCredentials,
    AccountState(&'static str),
    StrongerAuthRequired,
    Unreachable,
    Other,
}

/// Map an LDAP bind error string to a verdict. Pure — the unit-tested core.
///
/// `data 52e` is classified as invalid-credentials, NOT channel-binding: on AD, 52e
/// means bad user/password, and CBT/signing rejection surfaces separately as rc=8
/// (`strongerAuthRequired`), `data 80090346`, or a confidentiality/signing message.
pub(crate) fn classify_bind(err: &str) -> BindVerdict {
    let e = err.to_ascii_lowercase();
    let has = |needle: &str| e.contains(needle);

    if has("data 52e") {
        return BindVerdict::InvalidCredentials;
    }
    for (code, msg) in [
        ("data 525", "user not found"),
        ("data 530", "logon-hours restriction"),
        ("data 531", "workstation restriction"),
        ("data 532", "password expired"),
        ("data 533", "account disabled"),
        ("data 701", "account expired"),
        ("data 773", "must change password"),
        ("data 775", "account locked out"),
    ] {
        if has(code) {
            return BindVerdict::AccountState(msg);
        }
    }
    if has("80090346")
        || has("strongerauth")
        || has("stronger auth")
        || has("confidentiality")
        || has("channel binding")
        || has("signing")
        || has("result code: 8")
        || has("rc=8")
    {
        return BindVerdict::StrongerAuthRequired;
    }
    if has("connection refused")
        || has("timed out")
        || has("timeout")
        || has("os error 10061")
        || has("os error 104")
        || has("reset by peer")
        || has("no route")
        || has("unreachable")
    {
        return BindVerdict::Unreachable;
    }
    if e.is_empty() {
        return BindVerdict::Success;
    }
    BindVerdict::Other
}

pub(crate) fn bind_fix(v: &BindVerdict) -> &'static str {
    match v {
        BindVerdict::Success => "bind OK",
        BindVerdict::InvalidCredentials => {
            "check --user (try DOMAIN\\user or a UPN) and --password; 52e is bad \
             credentials, not (by itself) channel binding"
        }
        BindVerdict::AccountState(s) => s,
        BindVerdict::StrongerAuthRequired => {
            "DC enforces LDAP signing / channel binding — use ldaps:// (636) or a \
             GSSAPI-signed bind (--gssapi), not plaintext 389"
        }
        BindVerdict::Unreachable => {
            "host/port unreachable — check the --url host, firewall, and that the DC is up"
        }
        BindVerdict::Other => {
            "unrecognized bind error — re-run with -vv for the raw LDAP diagnostic"
        }
    }
}

/// WS-UX-ERRORS: classify ANY verb's error string into a one-line named fix, or `None`
/// when unrecognized. `main` appends this as anyhow context so the fix is the headline
/// and the raw error the cause. Ordered most-specific first.
pub(crate) fn fix_hint(err: &str) -> Option<&'static str> {
    let e = err.to_ascii_lowercase();
    let has = |n: &str| e.contains(n);

    // LDAP bind (reuse the classifier) — only the actionable verdicts.
    match classify_bind(err) {
        BindVerdict::InvalidCredentials => return Some(bind_fix(&BindVerdict::InvalidCredentials)),
        BindVerdict::AccountState(s) => return Some(s),
        BindVerdict::StrongerAuthRequired => {
            return Some(bind_fix(&BindVerdict::StrongerAuthRequired))
        }
        _ => {}
    }

    // Kerberos.
    if has("skew") || has("krb_ap_err_skew") || has("clock") {
        return Some("Kerberos clock skew — sync the host clock to the DC (ntpdate/w32tm); AD tolerates ~5 min");
    }
    if has("preauth") || has("kdc_err_preauth") {
        return Some("Kerberos pre-auth required/failed — check the password/hash and that the account exists");
    }
    if has("kdc_err_c_principal_unknown") || has("client not found in kerberos database") {
        return Some(
            "principal unknown to the KDC — check the username and realm (case-sensitive REALM)",
        );
    }
    if has("kdc_err_s_principal_unknown") || has("server not found in kerberos database") {
        return Some("SPN unknown to the KDC — check the target service principal name");
    }

    // SMB.
    if has("status_access_denied") {
        return Some("SMB access denied — the account lacks rights on the target/share; try a privileged user");
    }
    if has("status_logon_failure") {
        return Some("SMB logon failed — check --user/--password/--domain (NETBIOS or FQDN)");
    }
    if has("status_pipe_not_available") || has("status_object_name_not_found") {
        return Some("named pipe/RPC endpoint not available — the service may be stopped or the opnum blocked");
    }

    // DNS / discovery.
    if has("failed to lookup") || has("name or service not known") || has("no such host") {
        return Some("DNS resolution failed — use the DC IP for --url/--host, or point resolv.conf at the AD DNS");
    }

    // TLS.
    if has("certificate") || has("self-signed") || has("tls") && has("verify") {
        return Some("TLS verification failed — pass --insecure for a lab self-signed DC cert, or trust the CA");
    }

    // Generic connection (last — broadest).
    if has("connection refused")
        || has("timed out")
        || has("timeout")
        || has("os error 10061")
        || has("os error 104")
        || has("reset by peer")
        || has("no route")
        || has("unreachable")
    {
        return Some(
            "host/port unreachable — check the target host, firewall, and that the DC role is up",
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_52e_is_invalid_credentials_not_cbt() {
        assert_eq!(
            classify_bind("80090308: LdapErr: DSID-0C09..., comment: AcceptSecurityContext error, data 52e, v4563"),
            BindVerdict::InvalidCredentials
        );
    }

    #[test]
    fn data_80090346_is_stronger_auth() {
        assert_eq!(
            classify_bind("comment: AcceptSecurityContext error, data 80090346, v4563"),
            BindVerdict::StrongerAuthRequired
        );
    }

    #[test]
    fn result_code_8_is_stronger_auth() {
        assert_eq!(
            classify_bind("ldap result code: 8 (strongerAuthRequired)"),
            BindVerdict::StrongerAuthRequired
        );
    }

    #[test]
    fn disabled_account_is_account_state() {
        assert_eq!(
            classify_bind("AcceptSecurityContext error, data 533, v4563"),
            BindVerdict::AccountState("account disabled")
        );
    }

    #[test]
    fn connection_refused_is_unreachable() {
        assert_eq!(
            classify_bind("Connection refused (os error 111)"),
            BindVerdict::Unreachable
        );
    }

    // ── fix_hint across the top failure classes (WS-UX-ERRORS DoD) ──
    #[test]
    fn fix_hint_names_the_fix_for_top_classes() {
        assert!(fix_hint("data 52e").unwrap().contains("DOMAIN\\user"));
        assert!(fix_hint("data 533").unwrap().contains("disabled"));
        assert!(fix_hint("data 80090346")
            .unwrap()
            .contains("channel binding"));
        assert!(fix_hint("KRB_AP_ERR_SKEW: clock skew too great")
            .unwrap()
            .contains("clock"));
        assert!(fix_hint("KDC_ERR_PREAUTH_FAILED")
            .unwrap()
            .contains("pre-auth"));
        assert!(fix_hint("STATUS_ACCESS_DENIED")
            .unwrap()
            .contains("access denied"));
        assert!(fix_hint("STATUS_LOGON_FAILURE").unwrap().contains("logon"));
        assert!(fix_hint("failed to lookup address information")
            .unwrap()
            .contains("DNS"));
        assert!(fix_hint("self-signed certificate in chain")
            .unwrap()
            .contains("--insecure"));
        assert!(fix_hint("Connection refused (os error 111)")
            .unwrap()
            .contains("unreachable"));
    }

    #[test]
    fn fix_hint_is_none_for_unrecognized() {
        assert!(fix_hint("some totally unrelated internal error xyz").is_none());
        assert!(fix_hint("").is_none());
    }
}
