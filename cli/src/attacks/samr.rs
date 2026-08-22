//! SAMR enumeration: SMB2 → NTLM → \samr pipe → SamrConnect → enumerate
//! domain users (read-only, no writes).

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct SamrArgs {
    /// DC host or IP
    #[arg(long)]
    pub host: String,
    /// NetBIOS domain, e.g. CORP
    #[arg(long)]
    pub domain: String,
    /// Username (sAMAccountName)
    #[arg(long)]
    pub user: String,
    /// Password
    #[arg(long, default_value = "")]
    pub password: String,
    /// Pass-the-hash: NT hash (32 hex, or LM:NT) instead of --password
    #[arg(long)]
    pub nt_hash: Option<String>,
}

/// Full path: SMB2 negotiate → NTLM session → IPC$ → \samr pipe →
/// DCE/RPC bind → SamrConnect → enumerate domain users.
pub(crate) async fn samr(a: SamrArgs) -> Result<()> {
    use dcerpc::samr::SamrClient;
    use smb2_client::SmbClient;

    let mut smb = SmbClient::connect(&a.host).await?;
    crate::smb_login(
        &mut smb,
        &a.host,
        &a.domain,
        &a.user,
        &a.password,
        &a.nt_hash,
    )
    .await?;
    tracing::info!("SMB session established");
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let pipe = smb.open_pipe("samr").await?;
    tracing::info!("\\samr pipe open");

    let mut client = SamrClient::bind(&mut smb, pipe).await?;
    let users = client
        .enumerate_all_users(&format!("\\\\{}", a.host))
        .await?;
    println!("== SAMR users ({}) ==", users.len());
    for (rid, name) in users {
        println!("  {rid}\t{name}");
    }
    Ok(())
}
