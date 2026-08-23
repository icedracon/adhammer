//! `adhammer setup` — one-shot onboarding helpers that produce local artifacts
//! (no wire actions against the target). WS-12 (1.4.1) shipped `setup krb5`, an
//! interactive `krb5.conf` generator so first-time-Kerberos operators can go
//! straight to `attack asktgt` without hand-editing config.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::ui;

#[derive(Subcommand)]
pub(crate) enum SetupCmd {
    /// Emit a working `krb5.conf` for the target realm — auto-discovers the KDC via SRV
    /// lookup when `--dc` is not passed, prompts interactively for anything missing.
    Krb5(SetupKrb5Args),
}

#[derive(Parser, Debug)]
pub(crate) struct SetupKrb5Args {
    /// Kerberos realm (AD DNS domain — case-insensitive, will be upper-cased
    /// wherever the config expects a realm). Prompted when omitted.
    #[arg(long)]
    pub realm: Option<String>,
    /// KDC / DC host or IP. When omitted, tries SRV `_kerberos._tcp.<realm>`
    /// against the OS resolver (`/etc/resolv.conf` on Unix, 8.8.8.8 / 1.1.1.1
    /// fallback on Windows). Falls back to a prompt if no SRV answers.
    #[arg(long)]
    pub dc: Option<String>,
    /// Output path. Default: `~/.krb5.conf` (Unix) or `%APPDATA%\krb5.conf` (Windows).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Overwrite an existing file at the target path.
    #[arg(long)]
    pub force: bool,
}

pub(crate) mod krb5 {
    use super::*;
    use dialoguer::theme::ColorfulTheme;
    use dialoguer::Input;

    pub(crate) async fn run(a: SetupKrb5Args) -> Result<()> {
        let realm = match a.realm {
            Some(r) if !r.trim().is_empty() => r.trim().to_string(),
            _ => Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Kerberos realm (e.g. corp.local)")
                .interact_text()
                .context("prompt realm")?,
        };
        let realm_upper = realm.to_uppercase();
        let realm_lower = realm.to_lowercase();

        let dc = match a.dc {
            Some(d) if !d.trim().is_empty() => d.trim().to_string(),
            _ => {
                let query = format!("_kerberos._tcp.{realm_lower}");
                match discover_kdc(&query).await {
                    Some(host) => {
                        ui::info(&format!("resolved KDC via SRV `{query}` → {host}"));
                        host
                    }
                    None => Input::<String>::with_theme(&ColorfulTheme::default())
                        .with_prompt(format!("KDC host/IP (SRV lookup for {query} failed)"))
                        .interact_text()
                        .context("prompt KDC")?,
                }
            }
        };

        let out = a.out.unwrap_or_else(default_out_path);
        if out.is_file() && !a.force {
            anyhow::bail!("{} exists — pass --force to overwrite", out.display());
        }

        let contents = super::render_krb5_conf(&realm_upper, &realm_lower, &dc);

        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create parent dir {}", parent.display()))?;
            }
        }
        std::fs::write(&out, &contents).with_context(|| format!("write {}", out.display()))?;
        println!("[+] wrote krb5.conf to {}", out.display());
        if cfg!(windows) {
            println!("[i] setx KRB5_CONFIG \"{}\"", out.display());
        } else {
            println!("[i] export KRB5_CONFIG=\"{}\"", out.display());
        }
        Ok(())
    }
}

/// Render a minimal but working krb5.conf. Kept as a free function (not inside `mod krb5`)
/// so unit tests can exercise the string surface without spinning up dialoguer prompts.
pub(crate) fn render_krb5_conf(realm_upper: &str, realm_lower: &str, dc: &str) -> String {
    // udp_preference_limit = 1 forces TCP to the KDC — AS-REP payloads with a full PAC blow
    // past the 1500-byte UDP MTU on real domains and the operator gets cryptic "message too
    // long" without it.
    format!(
        "[libdefaults]\n  \
default_realm = {realm_upper}\n  \
dns_lookup_realm = true\n  \
dns_lookup_kdc = true\n  \
forwardable = true\n  \
udp_preference_limit = 1\n\n\
[realms]\n  \
{realm_upper} = {{\n    \
kdc = {dc}\n    \
admin_server = {dc}\n    \
default_domain = {realm_lower}\n  \
}}\n\n\
[domain_realm]\n  \
.{realm_lower} = {realm_upper}\n  \
{realm_lower} = {realm_upper}\n"
    )
}

fn default_out_path() -> PathBuf {
    if cfg!(windows) {
        match std::env::var("APPDATA") {
            Ok(v) => PathBuf::from(v).join("krb5.conf"),
            Err(_) => PathBuf::from("krb5.conf"),
        }
    } else {
        match std::env::var("HOME") {
            Ok(v) => PathBuf::from(v).join(".krb5.conf"),
            Err(_) => PathBuf::from(".krb5.conf"),
        }
    }
}

/// Best-effort SRV lookup for `_kerberos._tcp.<realm>` against the OS resolvers. Returns
/// the lowest-priority SRV target on success. Never fails hard — the caller falls back
/// to a prompt.
async fn discover_kdc(qname: &str) -> Option<String> {
    for srv in default_resolvers() {
        if let Some(mut hits) = crate::attacks::scan_anonymous::dns_srv(&srv, qname).await {
            if hits.is_empty() {
                continue;
            }
            hits.sort_by_key(|(pri, _, _, _)| *pri);
            let (_, _, _port, target) = hits.into_iter().next()?;
            return Some(target.trim_end_matches('.').to_string());
        }
    }
    None
}

fn default_resolvers() -> Vec<String> {
    #[cfg(unix)]
    {
        if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
            let mut out = Vec::new();
            for line in text.lines() {
                let l = line.trim();
                if let Some(rest) = l.strip_prefix("nameserver ") {
                    out.push(rest.trim().to_string());
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
}

#[cfg(test)]
mod tests {
    use super::render_krb5_conf;

    #[test]
    fn renders_all_required_sections() {
        let out = render_krb5_conf("TESTLAB.LOCAL", "testlab.local", "172.29.247.82");
        assert!(out.contains("[libdefaults]"));
        assert!(out.contains("[realms]"));
        assert!(out.contains("[domain_realm]"));
        assert!(out.contains("default_realm = TESTLAB.LOCAL"));
        assert!(out.contains("kdc = 172.29.247.82"));
        assert!(out.contains("admin_server = 172.29.247.82"));
        assert!(out.contains("default_domain = testlab.local"));
        assert!(out.contains(".testlab.local = TESTLAB.LOCAL"));
        assert!(out.contains("testlab.local = TESTLAB.LOCAL"));
        // udp_preference_limit=1 forces TCP → PAC-sized AS-REPs work over the wire.
        assert!(out.contains("udp_preference_limit = 1"));
    }
}
