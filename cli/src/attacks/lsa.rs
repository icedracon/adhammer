//! LSAT name→SID resolution over \lsarpc: SMB2 → NTLM → DCE/RPC →
//! LsarOpenPolicy2 → LsarLookupNames.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct LsaArgs {
    #[arg(long)]
    pub host: String,
    #[arg(long)]
    pub domain: String,
    #[arg(long)]
    pub user: String,
    #[arg(long, default_value = "")]
    pub password: String,
    /// Pass-the-hash: NT hash (32 hex, or LM:NT) instead of --password
    #[arg(long)]
    pub nt_hash: Option<String>,
    /// Name to resolve to a SID, e.g. Administrator
    #[arg(long)]
    pub name: String,
}

/// LSAT name→SID over \lsarpc (SMB2 → NTLM → DCE/RPC → LsarOpenPolicy2 → LsarLookupNames).
pub(crate) async fn lsa(a: LsaArgs) -> Result<()> {
    use dcerpc::lsat::LsatClient;
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
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.host)).await?;
    let pipe = smb.open_pipe("lsarpc").await?;

    let mut client = LsatClient::bind(&mut smb, pipe).await?;
    let policy = client.open_policy().await?;
    match client.lookup_name(&policy, &a.name).await? {
        Some(sid) => println!("{} => {sid}", a.name),
        None => println!("{} => (not mapped)", a.name),
    }
    Ok(())
}
