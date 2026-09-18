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
    // 1.5.2 UX-B widening: catch strong-auth / channel-binding refusals BEFORE
    // the generic rc=49 fallthrough. WS2019/2022 DCs default to rejecting
    // plaintext simple binds and often surface as rc=8 without the sub-status
    // text; some paths return the bare "strongerAuthRequired" name only.
    // NOTE: "signing" alone is too generic (SMB signing errors and some doctor
    // remediation strings also contain the word). Require LDAP context for
    // that match so an SMB path never gets routed to the LDAP-signing hint.
    if has("80090346")
        || has("strongerauth")
        || has("stronger auth")
        || has("confidentiality")
        || has("channel binding")
        || (has("signing") && (has("ldap") || has("simple_bind") || has("simple bind")))
        || has("result code: 8")
        || has("rc=8")
        || has("rc: 8,")
        || has("(strongerauthrequired)")
    {
        return BindVerdict::StrongerAuthRequired;
    }
    // 1.5.2 UX-B widening: generic InvalidCredentials — some paths surface only
    // the LDAP result code (49) without the Windows sub-status "data 52e" text.
    // Kept BELOW the specific sub-status matches so we still get the precise
    // hint when the wire carries it.
    if has("result code: 49")
        || has("rc: 49,")
        || has("rc=49")
        || has("(invalidcredentials)")
        || has("supplied credential is invalid")
    {
        return BindVerdict::InvalidCredentials;
    }
    if has("connection refused")
        || has("timed out")
        || has("timeout")
        || has("os error 10061") // WSAECONNREFUSED (Windows)
        || has("os error 111")   // ECONNREFUSED (Linux)
        || has("no route")
        || has("unreachable")
    {
        return BindVerdict::Unreachable;
    }
    // NOTE: `reset by peer` / `os error 104` (ECONNRESET) is deliberately NOT here.
    // A peer that resets is reachable — the reset is a TLS-handshake refusal or
    // signing-policy kill. fix_hint() handles that class separately with its own
    // remedy; a doctor call surfaces it via BindVerdict::Other → the raw diagnostic.
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
            "unrecognized bind error — re-run with -vv to log the raw LDAP wire result \
             (`ldap-bind wire result` line), then file an issue with that line"
        }
    }
}

/// Match "kdc error N" at a word boundary — the character AFTER the number (if any) must
/// be a non-digit. Prevents "KDC error 6" from spuriously matching "KDC error 68". `e` is
/// already lowercased by `fix_hint`.
fn kdc_code(e: &str, code: u16) -> bool {
    let needle = format!("kdc error {code}");
    let mut start = 0;
    while let Some(pos) = e[start..].find(&needle) {
        let abs = start + pos;
        let end = abs + needle.len();
        let after = e.as_bytes().get(end).copied();
        // Boundary: end-of-string, or the next char is NOT an ASCII digit.
        if !after.is_some_and(|b| b.is_ascii_digit()) {
            return true;
        }
        start = end;
    }
    false
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

    // DNS / discovery. Narrowed: "failed to lookup" alone would also catch things like
    // "failed to lookup sAMAccountName" (an LDAP search miss). tokio's DNS error is
    // specifically "failed to lookup address information" — require the "address" token
    // together with "failed to lookup" so the LDAP-lookup case falls through.
    if (has("failed to lookup") && has("address"))
        || has("name or service not known")
        || has("no such host")
    {
        return Some("DNS resolution failed — use the DC IP for --url/--host, or point resolv.conf at the AD DNS");
    }

    // Kerberos numeric KDC error codes (adhammer's `bail!("AS-REQ rejected, KDC error N")`
    // format). Without this the operator gets a bare number and no fix advice. `kdc_code`
    // matches at a word boundary so `kdc error 6` cannot spuriously match `kdc error 68`.
    if kdc_code(&e, 68) {
        return Some("KDC error 68 (KDC_ERR_WRONG_REALM) — wrong realm; the referral in the reply names the correct realm to retry against");
    }
    if kdc_code(&e, 25) {
        return Some("KDC error 25 (KDC_ERR_PREAUTH_REQUIRED) — the account requires pre-auth (normal); this stops AS-REP roasting but the account is valid");
    }
    if kdc_code(&e, 24) {
        return Some("KDC error 24 (KDC_ERR_PREAUTH_FAILED) — the supplied password/hash is WRONG for the account, but the account itself exists");
    }
    if kdc_code(&e, 23) {
        return Some("KDC error 23 (KDC_ERR_KEY_EXPIRED) — the account's password expired; reset it before roasting");
    }
    if kdc_code(&e, 18) {
        return Some("KDC error 18 (KDC_ERR_CLIENT_REVOKED) — the account is disabled/locked; check with `enum krb-users` or SAMR");
    }
    if kdc_code(&e, 14) {
        return Some("KDC error 14 (KDC_ERR_ETYPE_NOSUPP) — the account's etypes don't include AES; enable AES on the account, or accept RC4 downgrade with --rc4");
    }
    if kdc_code(&e, 7) {
        return Some("KDC error 7 (KDC_ERR_S_PRINCIPAL_UNKNOWN) — the target SPN is not in AD; check --spn / --target-spn (needs an FQDN, not an IP)");
    }
    if kdc_code(&e, 6) {
        return Some("KDC error 6 (KDC_ERR_C_PRINCIPAL_UNKNOWN) — user not found in the realm; check --user spelling and case-sensitive --realm");
    }

    // AD CS enrollment refusals — the wire message includes the word "certificate",
    // so must be classified BEFORE the TLS branch or the wrong hint fires.
    if has("denied by policy module") || has("template that is not supported") {
        return Some(
            "AD CS refused the CSR — the CA has not (re-)published this template. On the DC: \
             `certutil -SetCATemplates +<name>` then `Restart-Service CertSvc`",
        );
    }
    // PKINIT KDC-side rejection: RFC 4556 §3.2.3 KDC_ERR_CERTIFICATE_MISMATCH (66) —
    // the cert was issued, but the KDC's account-mapping policy refused it
    // (KB5014754 Full Enforcement, live since Feb 2025).
    if has("error_code 66") || has("kdc_err_certificate_mismatch") {
        return Some(
            "PKINIT blocked by KB5014754 strong cert mapping — the cert issued fine but the KDC \
             refuses to map it to an account without a SID/SecurityIdentifier extension. Try a \
             pre-KB5014754 DC or add the SID mapping via certipy-style OID 1.3.6.1.4.1.311.25.2",
        );
    }

    // Adhammer's own plaintext-bind safety guard: the raw remedy already lives in the
    // guard message ("switch to ldaps://, pass --gssapi, or set allow_plaintext_bind=true"),
    // but its wording contains "certificate" and used to trip the TLS matcher. Classify
    // it explicitly so the operator sees the *actual* remedy, not `--insecure`.
    if has("refusing to send an authenticated ldap simple_bind over plaintext") {
        return Some(
            "LDAP requires an integrity-checked bind — use `ldaps://…:636 --insecure` for a \
             lab cert, `--gssapi` for SASL-sealed LDAP/389, or `--allow-plaintext-ldap` if \
             the DC really has no LDAPS cert (cleartext credentials on the wire)",
        );
    }

    // TCP reset — the peer accepted the handshake and then killed the flow. This is NOT
    // unreachable (nc -zv succeeds), so it must be classified BEFORE the generic
    // reachability branch. On ldaps:// it's almost always a TLS-handshake refusal (the
    // DC's Schannel policy rejects our ciphersuite/protocol, or requires channel binding
    // / client cert). On ldap:// it can be an LDAP signing kill.
    if has("connection reset by peer")
        || has("os error 104")     // ECONNRESET (Linux/musl)
        || has("os error 10054")   // WSAECONNRESET (Windows)
        || has("wsaeconnreset")
    {
        return Some(
            "TCP reset — the port is OPEN but the peer killed the flow. For ldaps://: \
             the DC's Schannel policy rejected the handshake (try `--tls-native` for \
             OpenSSL/Schannel ciphers, or check the DC's SCH_USE_STRONG_CRYPTO and \
             ciphersuite policy). For ldap://: the DC is enforcing LDAP signing.",
        );
    }

    // TLS. Narrowed: don't fire on generic "certificate" text — a wire like
    // "Denied by Policy Module: certificate template …" matched the old rule.
    let tls_context = has("verify") || has("self-signed") || has("unknown ca") || has("chain");
    if (has("tls") || has("certificate")) && tls_context {
        return Some("TLS verification failed — pass --insecure for a lab self-signed DC cert, or trust the CA");
    }

    // Generic connection (last — broadest). Reset-by-peer is handled above so it does
    // not fall in here as "unreachable" (a peer that resets is by definition reachable).
    if has("connection refused")
        || has("timed out")
        || has("timeout")
        || has("os error 10061") // WSAECONNREFUSED
        || has("os error 111")   // ECONNREFUSED (Linux)
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

    // 1.5.2 UX-B regression tests — seeded from the 2026-09-14 testlab.local
    // live-fire where the classifier whiffed and returned "Other" on wire
    // responses that carried enough info to name the cause.
    #[test]
    fn bare_rc49_is_invalid_credentials_ux_b() {
        // Seen from ldap3 wrapping a rc:49 response with no Windows sub-status.
        assert_eq!(
            classify_bind("LdapResult { rc: 49, matched: \"\", text: \"\", refs: [] }"),
            BindVerdict::InvalidCredentials
        );
    }

    #[test]
    fn strongerauthrequired_name_only_is_stronger_auth_ux_b() {
        // Some ldap3 paths render the name without the numeric code.
        assert_eq!(
            classify_bind("LDAP bind failed: (strongerAuthRequired)"),
            BindVerdict::StrongerAuthRequired
        );
    }

    #[test]
    fn supplied_credential_is_invalid_ux_b() {
        // Native S.DS.Protocols-shape wrapped errors surface this phrase; the
        // classifier should now name it InvalidCredentials rather than Other.
        assert_eq!(
            classify_bind(
                "bind failed as `administrator@testlab.local` — The supplied credential is invalid"
            ),
            BindVerdict::InvalidCredentials
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

    #[test]
    fn adcs_policy_refusal_does_not_misclassify_as_tls() {
        // Live 2025 DC wire: `Denied by Policy Module 0x80094800, The request was for a
        // certificate template that is not supported ...` — the word "certificate" used to
        // trip the TLS hint. The AD CS branch now precedes it.
        let h = fix_hint(
            "Denied by Policy Module  0x80094800, The request was for a certificate template \
             that is not supported by the Active Directory Certificate Services policy: ESC1Vuln",
        )
        .unwrap();
        assert!(h.contains("AD CS"), "got: {h}");
        assert!(h.contains("SetCATemplates"), "got: {h}");
        assert!(!h.contains("TLS"), "wrong branch: {h}");
    }

    #[test]
    fn pkinit_error_66_maps_to_kb5014754() {
        // RFC 4556 §3.2.3 — KDC_ERR_CERTIFICATE_MISMATCH. Live wire on Server 2025:
        // `KDC rejected PKINIT AS-REQ: unhandled error_code 66 ''`
        let h = fix_hint("KDC rejected PKINIT AS-REQ: unhandled error_code 66 ''").unwrap();
        assert!(h.contains("KB5014754"), "got: {h}");
        assert!(h.contains("SID"), "got: {h}");
    }

    #[test]
    fn genuine_tls_error_still_classifies() {
        // Genuine TLS problem — the narrowed matcher must still fire.
        let h =
            fix_hint("tls handshake: certificate verify failed: self-signed certificate").unwrap();
        assert!(h.contains("TLS verification failed"), "got: {h}");
    }

    #[test]
    fn plaintext_bind_refusal_names_actual_remedy_not_tls() {
        // 2026-09-18 live-fire on armbusinessbank.local — the safety guard's OWN wording
        // contained "certificate" and used to trip the TLS branch, so operators saw
        // "pass --insecure" (a no-op here). The dedicated branch names the real remedy.
        let h = fix_hint(
            "refusing to send an authenticated LDAP simple_bind over plaintext \
             \"ldap://armbusinessbank.local:389\": switch to `ldaps://`, pass `--gssapi`, \
             or set `allow_plaintext_bind = true` on the LdapConfig if this is a lab DC \
             without an LDAPS certificate.",
        )
        .unwrap();
        assert!(h.contains("integrity-checked bind"), "got: {h}");
        assert!(h.contains("--gssapi"), "got: {h}");
        assert!(h.contains("--allow-plaintext-ldap"), "got: {h}");
        assert!(!h.starts_with("TLS verification"), "wrong branch: {h}");
    }

    #[test]
    fn tcp_reset_is_not_unreachable() {
        // 2026-09-18 live-fire on armbusinessbank.local:636 — `nc -zv` proved the port
        // was open, yet the tool said "host/port unreachable". A peer that RESETS is
        // by definition reachable; the reset is a TLS-handshake / signing policy kill.
        let h = fix_hint(
            "ldap connect: I/O error: Connection reset by peer (os error 104): \
             Connection reset by peer (os error 104)",
        )
        .unwrap();
        assert!(h.contains("TCP reset"), "got: {h}");
        assert!(h.contains("Schannel") || h.contains("signing"), "got: {h}");
        assert!(!h.contains("unreachable"), "wrong branch: {h}");
    }

    #[test]
    fn connection_refused_still_maps_to_unreachable() {
        // Regression guard: pruning "reset by peer" from the unreachable branch must
        // NOT break the honest-unreachable case.
        let h = fix_hint("Connection refused (os error 111)").unwrap();
        assert!(h.contains("unreachable"), "got: {h}");
    }

    #[test]
    fn ldap_search_lookup_miss_is_not_dns() {
        // A search that returns no entries can bubble up as "failed to lookup <attr>" —
        // that must NOT be routed to the DNS branch. Tightened matcher requires "address".
        let h = fix_hint("failed to lookup sAMAccountName=svc_missing");
        assert!(
            h.map(|s| !s.contains("DNS resolution failed"))
                .unwrap_or(true),
            "LDAP lookup miss must not misclassify as DNS: {h:?}"
        );
    }

    #[test]
    fn dns_getaddrinfo_still_classifies() {
        // The genuine tokio DNS failure (uniquely says "failed to lookup address ...")
        // must still fire the DNS hint after the tightening.
        let h = fix_hint(
            "io error: failed to lookup address information: nodename nor servname provided",
        )
        .unwrap();
        assert!(h.contains("DNS resolution failed"), "got: {h}");
    }

    #[test]
    fn smb_signing_error_not_routed_to_ldap_signing_hint() {
        // If the SMB stack ever emits a message containing "signing" (documented
        // remediation strings do, per `crates/graph/src/lib.rs`), the LDAP
        // StrongerAuthRequired hint must NOT fire on it. Tightened matcher requires
        // LDAP context.
        let smb_msg = "smb signing verification failed on RESPONSE packet";
        assert_ne!(
            classify_bind(smb_msg),
            BindVerdict::StrongerAuthRequired,
            "SMB signing errors must not be routed to LDAP StrongerAuthRequired"
        );
    }

    #[test]
    fn genuine_ldap_signing_still_classifies() {
        // A genuine LDAP signing rejection (contains both "signing" AND LDAP context)
        // must still be caught after the tightening.
        assert_eq!(
            classify_bind("ldap bind refused: signing/sealing required"),
            BindVerdict::StrongerAuthRequired
        );
        assert_eq!(
            classify_bind("simple_bind rejected because signing is required"),
            BindVerdict::StrongerAuthRequired
        );
    }

    #[test]
    fn kdc_numeric_error_codes_are_translated() {
        // Adhammer's kerberos crate emits bare `bail!("AS-REQ rejected, KDC error N")`
        // (see crates/kerberos/src/tgs.rs:354). Without this the operator gets a
        // number with no context. Cover the tell-tale codes.
        let cases = [
            (6, "KDC_ERR_C_PRINCIPAL_UNKNOWN"),
            (7, "KDC_ERR_S_PRINCIPAL_UNKNOWN"),
            (14, "KDC_ERR_ETYPE_NOSUPP"),
            (18, "KDC_ERR_CLIENT_REVOKED"),
            (23, "KDC_ERR_KEY_EXPIRED"),
            (24, "KDC_ERR_PREAUTH_FAILED"),
            (25, "KDC_ERR_PREAUTH_REQUIRED"),
            (68, "KDC_ERR_WRONG_REALM"),
        ];
        for (code, name) in cases {
            let msg = format!("AS-REQ rejected, KDC error {code}");
            let h = fix_hint(&msg).unwrap_or_else(|| panic!("no hint for KDC error {code}"));
            assert!(
                h.contains(name),
                "KDC error {code} hint should name {name} — got: {h}"
            );
        }
    }
}
