//! LAPS local-admin password read over LDAPS. Handles both legacy
//! `ms-Mcs-AdmPwd` cleartext and modern `msLAPS-EncryptedPassword` blobs
//! (MS-GKDI GetKey → DPAPI-NG unwrap).

use anyhow::Result;
use clap::Parser;

use crate::ui;

#[derive(Parser)]
pub(crate) struct LapsArgs {
    /// LDAP URL (LDAPS required — the password is only returned over a sealed channel)
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub user: String,
    #[arg(long, default_value = "")]
    pub password: adhammer_core::SecretString,
    #[arg(long)]
    pub insecure: bool,
    /// Computer sAMAccountName to read (e.g. WIN11$). Omit to dump every LAPS password you can read.
    #[arg(long)]
    pub target: Option<String>,
}

/// Decrypt a raw `msLAPS-EncryptedPassword` blob via MS-GKDI `GetKey` against the DC. Returns
/// (account name, cleartext password) on success. The GKDI RPC is sealed — the DC only hands
/// out the group key if the bind identity is authorized to read the LAPS password.
async fn decrypt_encrypted_laps(
    dc_host: &str,
    domain: &str,
    user: &str,
    password: &str,
    laps_attr_value: &[u8],
) -> Result<(String, String)> {
    use dpapi_ng::{decrypt, laps_password_from_json, rpc, LapsBlob};

    let laps = LapsBlob::parse(laps_attr_value)
        .map_err(|e| anyhow::anyhow!("parse LAPS header: {e:?}"))?;
    let protected = laps
        .protected()
        .map_err(|e| anyhow::anyhow!("parse CMS ProtectedBlob: {e:?}"))?;
    let id = &protected.key_identifier;
    let envelope = rpc::get_key(
        dc_host,
        domain,
        user,
        password,
        &[], // empty target SD — DC uses the requestor's context (dploot/netexec default)
        Some(id.root_key_id),
        id.l0,
        id.l1,
        id.l2,
    )
    .await
    .map_err(|e| anyhow::anyhow!("GKDI GetKey: {e}"))?;
    let plaintext_utf16 =
        decrypt(&protected, &envelope).map_err(|e| anyhow::anyhow!("DPAPI-NG decrypt: {e:?}"))?;
    // Windows LAPS stores `{"n":"<account>","t":"<hex>","p":"<pw>"}` as UTF-16LE.
    let pw = laps_password_from_json(&plaintext_utf16)
        .ok_or_else(|| anyhow::anyhow!("decrypted blob has no 'p' field"))?;
    let account = {
        let json = String::from_utf16_lossy(
            &plaintext_utf16
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        json.find("\"n\"")
            .and_then(|at| json[at + 3..].find('"').map(|s| at + 3 + s + 1))
            .and_then(|s| json[s..].find('"').map(|e| json[s..s + e].to_string()))
            .unwrap_or_else(|| "Administrator".into())
    };
    Ok((account, pw))
}

/// Read LAPS local-administrator passwords over LDAPS — one host (`--target WIN11$`) or every
/// computer whose LAPS attribute the bind identity can read. Wraps `laps_impl` with a rich
/// per-stage checklist so the operator sees where the pipeline stopped (bad channel, no entries
/// readable, GKDI GetKey denied).
pub(crate) async fn laps(a: LapsArgs) -> Result<()> {
    let mut checklist = ui::StageChecklist::new([
        "resolve password",
        "sealed LDAP bind (LDAPS)",
        "read LAPS attributes",
        "decrypt / emit passwords",
    ]);
    let result = laps_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("LAPS stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("LAPS stages (failed)");
        }
    }
    result
}

async fn laps_impl(mut a: LapsArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
    checklist.record_ok(
        "resolve password",
        if a.password.is_empty() {
            "empty"
        } else {
            "resolved"
        },
    );
    use adhammer_collector::{Collector, LdapConfig};
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
        allow_plaintext_bind: false,
    };
    let sp = ui::Spinner::start("reading LAPS passwords over LDAPS");
    let mut c = Collector::connect(&cfg).await?;
    checklist.record_ok("sealed LDAP bind (LDAPS)", format!("→ {}", a.url));
    let entries = c.read_laps(a.target.as_deref()).await?;
    sp.done(&format!("{} LAPS entr(y/ies) returned", entries.len()));
    checklist.record_ok(
        "read LAPS attributes",
        format!(
            "{} entr{}",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" }
        ),
    );
    if entries.is_empty() {
        anyhow::bail!(
            "no LAPS password readable (no LAPS deployed, or the bind identity lacks the read right — try a specific --target <HOST$>)"
        );
    }

    // For encrypted LAPS we need a KDC hostname + a DOMAIN\user bind for the sealed GKDI
    // GetKey RPC. Both are derived from the LDAP config we already have.
    let dc_host = a
        .url
        .trim_start_matches("ldaps://")
        .trim_start_matches("ldap://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    let (domain, user) = a
        .user
        .split_once('\\')
        .map(|(d, u)| (d.to_string(), u.to_string()))
        .unwrap_or_else(|| (String::new(), a.user.clone()));

    let mut cleartext = 0usize;
    for e in &entries {
        if let Some(pw) = &e.password {
            cleartext += 1;
            let exp = e
                .expires
                .as_deref()
                .map(|x| format!("  expires={x}"))
                .unwrap_or_default();
            // TAB-separated: HOST$  account  password  [expires]
            println!("{}\t{}\t{}{}", e.sam, e.account, pw, exp);
            continue;
        }
        // Encrypted-LAPS path: msLAPS-EncryptedPassword → LAPS header → CMS ProtectedBlob →
        // MS-GKDI GetKey for the blob's KeyIdentifier → derive L2 key → open the blob.
        let Some(bytes) = &e.encrypted_blob else {
            eprintln!(
                "[!] {}: no cleartext and no encrypted blob to work with",
                e.sam
            );
            continue;
        };
        match decrypt_encrypted_laps(&dc_host, &domain, &user, &a.password, bytes).await {
            Ok((account, pw)) => {
                cleartext += 1;
                println!("{}\t{}\t{}", e.sam, account, pw);
            }
            Err(err) => eprintln!(
                "[!] {} DPAPI-NG decrypt failed: {err} (bind identity may lack the GKDI read right)",
                e.sam
            ),
        }
    }
    checklist.record_ok(
        "decrypt / emit passwords",
        format!("{cleartext} cleartext recovered"),
    );
    ui::ok(&format!(
        "LAPS: {cleartext} cleartext local-admin password(s) recovered"
    ));
    Ok(())
}
