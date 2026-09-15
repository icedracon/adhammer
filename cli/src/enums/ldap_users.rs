//! **1.5.2 Stream 7 / niche-adds**: `enum ldap-users` — anonymous LDAP
//! user enumeration.
//!
//! Some DCs (mis-configured or Pre-Win2000 legacy) allow the anonymous
//! bind to walk `(objectClass=user)` under the domain naming context.
//! When they do, this verb dumps sAMAccountName + userAccountControl +
//! description in one go — a fast first-touch enum when `enum ldap-info`
//! confirms the RootDSE is readable and the operator wants to check
//! whether user objects are also readable without a credential.
//!
//! Zero credentials, zero side effects. If the anonymous bind is
//! rejected or the search returns 0 objects (the modern default), the
//! verb exits with a clean "no anonymous listing" message pointing the
//! operator at `attack spray --users @wordlist` for the cred-testing
//! path instead.

use adhammer_collector::{Collector, LdapConfig};
use anyhow::Result;
use clap::Parser;
use serde_json::json;

#[derive(Parser)]
pub(crate) struct LdapUsersArgs {
    /// LDAP(S) URL of the target DC, e.g. `ldaps://dc.corp.local`.
    #[arg(long)]
    pub url: String,
    /// Accept a self-signed / hostname-mismatched TLS certificate.
    #[arg(long)]
    pub insecure: bool,
    /// Anonymous bind (no --user / --password). Required for this verb.
    /// Named explicitly to match the `enum shares --anon` /
    /// `enum host --anon` idiom.
    #[arg(long)]
    pub anon: bool,
    /// Emit JSON instead of the tabular summary.
    #[arg(long)]
    pub json: bool,
}

pub(crate) async fn ldap_users(a: LdapUsersArgs) -> Result<()> {
    if !a.anon {
        anyhow::bail!("`enum ldap-users` currently only supports the anonymous path — pass --anon");
    }
    let sp = crate::ui::Spinner::start(format!("anonymous LDAP user enum → {}", a.url));

    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: String::new(),
        password: adhammer_core::SecretString::from(""),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
        allow_plaintext_bind: true, // anonymous bind is by definition unencrypted-safe
    };
    let mut c = match Collector::connect(&cfg).await {
        Ok(c) => c,
        Err(e) => {
            sp.done_warn(&format!("anonymous bind rejected: {e}"));
            eprintln!(
                "[hint] no anonymous listing on this DC — use `attack spray --realm <R> \
                 --kdc <dc> --users @wordlist.txt` for the cred-testing path"
            );
            return Err(e);
        }
    };
    let base = c.base_dn().to_string();

    let entries = c
        .search_subtree(
            &base,
            "(&(objectClass=user)(!(objectClass=computer)))",
            vec!["sAMAccountName", "userAccountControl", "description"],
        )
        .await;
    let entries = match entries {
        Ok(e) => e,
        Err(e) => {
            sp.done_warn(&format!("anonymous search rejected: {e}"));
            eprintln!(
                "[hint] anonymous bind succeeded but subtree search blocked — try \
                 `enum ldap-info --url {}` for RootDSE facts (always anonymous-readable)",
                a.url
            );
            return Err(e);
        }
    };

    sp.done(&format!("{} user object(s) returned", entries.len()));

    if entries.is_empty() {
        eprintln!(
            "[i] no user objects returned via anonymous bind (the modern default). \
             The DC accepts an anonymous bind but hides user objects behind `dsHeuristics`."
        );
        return Ok(());
    }

    if a.json {
        let payload: Vec<_> = entries
            .iter()
            .map(|o| {
                json!({
                    "sam": o.one("sAMAccountName").unwrap_or(""),
                    "uac": o.uac(),
                    "description": o.one("description").unwrap_or(""),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "command": "adhammer enum ldap-users --anon",
                "success": true,
                "count": entries.len(),
                "evidence": payload,
            }))?
        );
    } else {
        println!("{:<30} {:<12} description", "sAMAccountName", "UAC");
        for o in &entries {
            println!(
                "{:<30} 0x{:08x}   {}",
                o.one("sAMAccountName").unwrap_or("<no sam>"),
                o.uac(),
                o.one("description").unwrap_or(""),
            );
        }
        eprintln!();
        eprintln!(
            "next: password spray — `adhammer attack spray --realm <R> --kdc <dc> \
             --users {}.users --password env:ADHAMMER_PASSWORD`",
            base.split(',')
                .filter_map(|p| p.strip_prefix("DC="))
                .collect::<Vec<_>>()
                .join(".")
        );
    }
    Ok(())
}
