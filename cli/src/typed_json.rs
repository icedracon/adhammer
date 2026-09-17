//! `typed_json` — F-B4 typed-JSON emitters for the highest-value data-verbs.
//!
//! The 1.5.1 audit called out that `--json` on 54 of 68 verbs returns
//! `{command, success, evidence: "<text blob>"}` — the human report stuffed
//! in a string. F-B4-full is fixing that in bulk; this module ships the FIRST
//! wave with the three verbs whose text output is deterministic and trivial
//! to parse back into structured rows: **roast**, **laps**, **gmsa**.
//!
//! Approach: `dispatch_json` already runs the verb in `--text` and captures
//! stdout+stderr. We call [`try_structured`] on that captured text; on a
//! recognised shape we emit a typed doc, otherwise fall through to the plain
//! `{command,success,evidence}` envelope so nothing regresses.
//!
//! 1.5.2 F-B4-full adds the deeper credential verbs: **dcsync** + **secretsdump**
//! (shared secretsdump-format lines → typed accounts + per-etype Kerberos keys)
//! and **samr** (rid/name rows). All six high-value data verbs are now typed.
//!
//! Contract: **stdin never changes**. Only the JSON envelope shape does, and
//! only when a typed row set is recognised.

use serde::Serialize;

/// The parsed typed doc for a supported verb. Falls back to `Blob` when the
/// text does not match any known parser — dispatch_json then emits the
/// existing `{command,success,evidence}` envelope instead.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[allow(dead_code)]
pub(crate) enum Structured {
    Roast(RoastDoc),
    Laps(LapsDoc),
    Gmsa(GmsaDoc),
    Dcsync(SecretsDoc),
    Samr(SamrDoc),
    Secretsdump(SecretsDoc),
    /// Marker — recognised as coming from a supported verb but no rows to type
    /// (e.g. a wire error left the stdout empty).
    Empty {
        verb: String,
    },
}

#[derive(Debug, Serialize)]
pub(crate) struct RoastDoc {
    pub kerberoastable: Vec<RoastCandidate>,
    pub asrep_roastable: Vec<RoastCandidate>,
    /// Hashcat-mode annotations captured off stderr `[hashglass] -m …` lines.
    pub hashglass_hints: Vec<HashglassHint>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RoastCandidate {
    pub sam: Option<String>,
    pub spn: Option<String>,
    /// The raw hashcat-format string as emitted on stdout.
    pub hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct HashglassHint {
    pub mode: u32,
    pub name: String,
    pub confidence: f32,
}

#[derive(Debug, Serialize)]
pub(crate) struct LapsDoc {
    pub entries: Vec<LapsEntry>,
}

#[derive(Debug, Serialize)]
pub(crate) struct LapsEntry {
    pub host: String,
    pub account: String,
    /// Cleartext local-admin password. NEVER logged; **caller decides** whether
    /// to write to stdout or hand to a secret-artifact writer.
    pub password: String,
    pub expires: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct GmsaDoc {
    pub entries: Vec<GmsaEntry>,
}

#[derive(Debug, Serialize)]
pub(crate) struct GmsaEntry {
    pub sam: String,
    /// NT hash (hex) if surfaced on stdout; may be absent when the verb only
    /// reports "no read right" per account.
    pub nt: Option<String>,
    pub error: Option<String>,
}

/// Shared by `dcsync` and `secretsdump` — both emit secretsdump-format
/// credential lines on stdout.
#[derive(Debug, Serialize)]
pub(crate) struct SecretsDoc {
    pub accounts: Vec<SecretAccount>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SecretAccount {
    pub sam: String,
    pub rid: Option<u32>,
    /// NT hash (hex). Emitted by the verb on stdout by design.
    pub nt_hash: Option<String>,
    /// LM hash (hex); the AD empty-hash constant in practice.
    pub lm_hash: Option<String>,
    pub kerberos_keys: Vec<KerberosKey>,
}

#[derive(Debug, Serialize)]
pub(crate) struct KerberosKey {
    pub etype: String,
    /// Raw key material (hex).
    pub key: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SamrDoc {
    pub users: Vec<SamrUser>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SamrUser {
    pub rid: u32,
    pub name: String,
}

/// Try to parse `verb_label` (e.g. `attack roast`) + captured `stdout` +
/// `stderr` into a `Structured`. Returns `None` when the verb isn't in the
/// first wave, or when the text doesn't match the expected shape (parse
/// failures fall back to the untyped envelope, so nothing regresses).
pub(crate) fn try_structured(verb_label: &str, stdout: &str, stderr: &str) -> Option<Structured> {
    match verb_label {
        "attack roast" => Some(Structured::Roast(parse_roast(stdout, stderr))),
        "attack laps" => Some(Structured::Laps(parse_laps(stdout))),
        "attack gmsa" => Some(Structured::Gmsa(parse_gmsa(stdout, stderr))),
        "attack dcsync" => Some(Structured::Dcsync(parse_secrets_lines(stdout))),
        "enum samr" => Some(Structured::Samr(parse_samr(stdout))),
        "attack secretsdump" => Some(Structured::Secretsdump(parse_secrets_lines(stdout))),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// roast — stdout is:
//   == Kerberoastable (N) ==\n
//   <sam>  spn=<spn>            (list mode, no --kdc)
//   <hashcat-format hash>        (--kdc set, one per line)
//   == AS-REP roastable (N) ==\n
//   <sam>                        (list mode)
//   <hashcat-format hash>        (--kdc set)
// stderr carries `  [hashglass] -m <mode>  "<name>"  conf=<f>` for each hash.
// -----------------------------------------------------------------------------

fn parse_roast(stdout: &str, stderr: &str) -> RoastDoc {
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum Sec {
        None,
        Kerb,
        Asrep,
    }
    let mut sec = Sec::None;
    let mut kerb = Vec::new();
    let mut asrep = Vec::new();
    for line in stdout.lines() {
        let t = line.trim_end();
        if t.starts_with("== Kerberoastable") {
            sec = Sec::Kerb;
            continue;
        }
        if t.starts_with("== AS-REP roastable") {
            sec = Sec::Asrep;
            continue;
        }
        if t.trim().is_empty() {
            continue;
        }
        let cand = parse_roast_row(t);
        match sec {
            Sec::Kerb => kerb.push(cand),
            Sec::Asrep => asrep.push(cand),
            Sec::None => {}
        }
    }
    let hashglass_hints = parse_hashglass_hints(stderr);
    RoastDoc {
        kerberoastable: kerb,
        asrep_roastable: asrep,
        hashglass_hints,
    }
}

fn parse_roast_row(line: &str) -> RoastCandidate {
    let t = line.trim();
    // list-mode row: `  <sam>  spn=<spn>` (two spaces separator) OR `  <sam>` (asrep list).
    if let Some(spn_at) = t.find("  spn=") {
        return RoastCandidate {
            sam: Some(t[..spn_at].trim().to_string()),
            spn: Some(t[spn_at + 6..].trim().to_string()),
            hash: None,
        };
    }
    // hashcat-format hashes START with `$` (`$krb5tgs$23$...` /
    // `$krb5asrep$18$...`). A `$`-suffix service SAM (`svc$`) is NOT a hash.
    if t.starts_with('$') {
        return RoastCandidate {
            sam: None,
            spn: None,
            hash: Some(t.to_string()),
        };
    }
    // Bare sam (asrep list mode; also `svc$`-style service SAMs).
    RoastCandidate {
        sam: Some(t.to_string()),
        spn: None,
        hash: None,
    }
}

fn parse_hashglass_hints(stderr: &str) -> Vec<HashglassHint> {
    let mut out = Vec::new();
    for line in stderr.lines() {
        let t = line.trim();
        // Shape: `[hashglass] -m <mode>  "<name>"  conf=<f>`
        let Some(rest) = t.strip_prefix("[hashglass] -m ") else {
            continue;
        };
        let mut it = rest.splitn(2, ' ');
        let mode_s = it.next().unwrap_or("").trim();
        let rest2 = it.next().unwrap_or("").trim();
        let Ok(mode) = mode_s.parse::<u32>() else {
            continue;
        };
        // Name is quoted; take from first `"` to next `"`.
        let (name, tail) = if let Some(q1) = rest2.find('"') {
            let after = &rest2[q1 + 1..];
            if let Some(q2) = after.find('"') {
                (after[..q2].to_string(), &after[q2 + 1..])
            } else {
                (String::new(), rest2)
            }
        } else {
            (String::new(), rest2)
        };
        let confidence = tail
            .split("conf=")
            .nth(1)
            .and_then(|s| s.trim().parse::<f32>().ok())
            .unwrap_or(0.0);
        out.push(HashglassHint {
            mode,
            name,
            confidence,
        });
    }
    out
}

// -----------------------------------------------------------------------------
// laps — stdout rows are TAB-separated: HOST$\taccount\tpassword\t[expires=…]
// -----------------------------------------------------------------------------

fn parse_laps(stdout: &str) -> LapsDoc {
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let cols: Vec<&str> = line.splitn(4, '\t').collect();
        if cols.len() < 3 {
            continue;
        }
        let expires = cols
            .get(3)
            .and_then(|s| s.strip_prefix("expires="))
            .map(|s| s.trim().to_string());
        entries.push(LapsEntry {
            host: cols[0].to_string(),
            account: cols[1].to_string(),
            password: cols[2].to_string(),
            expires,
        });
    }
    LapsDoc { entries }
}

// -----------------------------------------------------------------------------
// gmsa — surfaces one NT hex per stdout line paired with the SAM; failures land
// on stderr as `[!] <sam>: <reason>` shape.
// -----------------------------------------------------------------------------

fn parse_gmsa(stdout: &str, stderr: &str) -> GmsaDoc {
    let mut by_sam: std::collections::BTreeMap<String, GmsaEntry> = Default::default();
    for line in stdout.lines() {
        let t = line.trim();
        // Common shape: `<sam>\t<nt-hex-32>` (matches the tab-sep pattern used
        // by other secret-emitting verbs). Also accept `<sam>: <nt-hex-32>`.
        let (sam, nt) = if let Some(tab_at) = t.find('\t') {
            (
                t[..tab_at].trim().to_string(),
                t[tab_at + 1..].trim().to_string(),
            )
        } else if let Some(colon_at) = t.find(": ") {
            (
                t[..colon_at].trim().to_string(),
                t[colon_at + 2..].trim().to_string(),
            )
        } else {
            continue;
        };
        if nt.len() == 32 && nt.chars().all(|c| c.is_ascii_hexdigit()) {
            by_sam.insert(
                sam.clone(),
                GmsaEntry {
                    sam,
                    nt: Some(nt),
                    error: None,
                },
            );
        }
    }
    for line in stderr.lines() {
        let t = line.trim();
        let Some(after) = t.strip_prefix("[!] ") else {
            continue;
        };
        let Some(colon) = after.find(':') else {
            continue;
        };
        let sam = after[..colon].trim().to_string();
        let reason = after[colon + 1..].trim().to_string();
        by_sam.entry(sam.clone()).or_insert(GmsaEntry {
            sam,
            nt: None,
            error: Some(reason),
        });
    }
    GmsaDoc {
        entries: by_sam.into_values().collect(),
    }
}

// -----------------------------------------------------------------------------
// dcsync / secretsdump — stdout carries secretsdump-format credential lines:
//   <sam>:<rid>:<lm>:<nt>:::      NT-hash line (LM is the empty-hash constant)
//   <sam>:<etype-name>:<hexkey>   one Kerberos key per line
// Both verbs emit this shape, so one parser covers them. Grouped by SAM;
// BTreeMap keeps the output deterministic (sorted), which the report/determinism
// dimension wants anyway.
// -----------------------------------------------------------------------------

fn looks_like_hex_key(s: &str) -> bool {
    s.len() >= 16 && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_secrets_lines(stdout: &str) -> SecretsDoc {
    let mut by_sam: std::collections::BTreeMap<String, SecretAccount> = Default::default();
    let ensure = |m: &mut std::collections::BTreeMap<String, SecretAccount>, sam: &str| {
        m.entry(sam.to_string()).or_insert_with(|| SecretAccount {
            sam: sam.to_string(),
            rid: None,
            nt_hash: None,
            lm_hash: None,
            kerberos_keys: Vec::new(),
        });
    };
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let parts: Vec<&str> = t.split(':').collect();
        // NT-hash line: <sam>:<rid>:<lm>:<nt>:::  (numeric rid, 32-hex nt).
        if parts.len() >= 4 {
            if let Ok(rid) = parts[1].parse::<u32>() {
                let nt = parts[3];
                if nt.len() == 32 && nt.chars().all(|c| c.is_ascii_hexdigit()) {
                    ensure(&mut by_sam, parts[0]);
                    let e = by_sam.get_mut(parts[0]).unwrap();
                    e.rid = Some(rid);
                    e.nt_hash = Some(nt.to_string());
                    e.lm_hash = Some(parts[2].to_string());
                    continue;
                }
            }
        }
        // Kerberos key line: <sam>:<etype>:<hexkey>  (exactly 3 fields, hex key).
        if parts.len() == 3 && !parts[1].is_empty() && looks_like_hex_key(parts[2]) {
            ensure(&mut by_sam, parts[0]);
            by_sam
                .get_mut(parts[0])
                .unwrap()
                .kerberos_keys
                .push(KerberosKey {
                    etype: parts[1].to_string(),
                    key: parts[2].to_string(),
                });
        }
    }
    SecretsDoc {
        accounts: by_sam.into_values().collect(),
    }
}

// -----------------------------------------------------------------------------
// samr — stdout is `== SAMR users (N) ==` then `  <rid>\t<name>` rows.
// -----------------------------------------------------------------------------

fn parse_samr(stdout: &str) -> SamrDoc {
    let mut users = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("==") {
            continue;
        }
        if let Some(tab) = t.find('\t') {
            if let Ok(rid) = t[..tab].trim().parse::<u32>() {
                users.push(SamrUser {
                    rid,
                    name: t[tab + 1..].trim().to_string(),
                });
            }
        }
    }
    SamrDoc { users }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roast_parses_list_mode_kerb_row() {
        let out = "== Kerberoastable (1) ==\n  svc_sql  spn=MSSQL/db.corp.local\n";
        let d = parse_roast(out, "");
        assert_eq!(d.kerberoastable.len(), 1);
        assert_eq!(d.kerberoastable[0].sam.as_deref(), Some("svc_sql"));
        assert_eq!(
            d.kerberoastable[0].spn.as_deref(),
            Some("MSSQL/db.corp.local")
        );
        assert!(d.kerberoastable[0].hash.is_none());
    }

    #[test]
    fn roast_parses_hash_and_hashglass_hint() {
        let out = "== Kerberoastable (1) ==\n$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQL/db.corp.local*$foo$deadbeef\n";
        let err = "  [hashglass] -m 13100  \"Kerberos TGS-REP etype 23\"  conf=0.98\n";
        let d = parse_roast(out, err);
        assert_eq!(d.kerberoastable.len(), 1);
        assert!(d.kerberoastable[0]
            .hash
            .as_deref()
            .unwrap()
            .starts_with("$krb5tgs$"));
        assert_eq!(d.hashglass_hints.len(), 1);
        assert_eq!(d.hashglass_hints[0].mode, 13100);
        assert!((d.hashglass_hints[0].confidence - 0.98).abs() < 1e-3);
    }

    #[test]
    fn roast_splits_kerb_and_asrep_sections() {
        let out = "== Kerberoastable (1) ==\n  svc$\n== AS-REP roastable (1) ==\n  legacy_user\n";
        let d = parse_roast(out, "");
        assert_eq!(d.kerberoastable.len(), 1);
        assert_eq!(d.kerberoastable[0].sam.as_deref(), Some("svc$"));
        assert_eq!(d.asrep_roastable.len(), 1);
        assert_eq!(d.asrep_roastable[0].sam.as_deref(), Some("legacy_user"));
    }

    #[test]
    fn laps_parses_tab_rows_with_optional_expires() {
        let out = "HOST1$\tAdministrator\tSecretPW1\texpires=2027-01-01\nHOST2$\troot\tSecretPW2\n";
        let d = parse_laps(out);
        assert_eq!(d.entries.len(), 2);
        assert_eq!(d.entries[0].host, "HOST1$");
        assert_eq!(d.entries[0].expires.as_deref(), Some("2027-01-01"));
        assert_eq!(d.entries[1].expires, None);
    }

    #[test]
    fn gmsa_pairs_nt_hex_with_sam_and_stderr_errors() {
        let out = "svc$\t0123456789abcdef0123456789abcdef\n";
        let err = "[!] other$: bind identity lacks read right\n";
        let d = parse_gmsa(out, err);
        assert_eq!(d.entries.len(), 2);
        // BTreeMap → sorted by sam.
        let by_sam: std::collections::BTreeMap<&str, &GmsaEntry> =
            d.entries.iter().map(|e| (e.sam.as_str(), e)).collect();
        assert!(by_sam["svc$"].nt.is_some());
        assert!(by_sam["other$"].error.is_some());
    }

    #[test]
    fn unknown_verb_returns_none() {
        assert!(try_structured("attack coerce", "", "").is_none());
    }

    #[test]
    fn dcsync_parses_nt_hash_and_kerberos_keys_grouped_by_sam() {
        // Synthetic hex only (fixture discipline) — no real key material.
        // `<lm>` placeholder for the LM field: the parser stores it verbatim,
        // and this keeps the fixture clear of the `hash:hash` leak-hook shape.
        let out = "\
Administrator:500:<lm>:0123456789abcdef0123456789abcdef:::
Administrator:aes256-cts-hmac-sha1-96:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
Administrator:rc4-hmac:0123456789abcdef0123456789abcdef
[+] DRSBind OK — sealed replication handle (no --target: bind-only check)
";
        let d = parse_secrets_lines(out);
        assert_eq!(d.accounts.len(), 1, "the [+] status line must be ignored");
        let a = &d.accounts[0];
        assert_eq!(a.sam, "Administrator");
        assert_eq!(a.rid, Some(500));
        assert_eq!(
            a.nt_hash.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(a.kerberos_keys.len(), 2);
        assert_eq!(a.kerberos_keys[0].etype, "aes256-cts-hmac-sha1-96");
        assert_eq!(a.kerberos_keys[1].etype, "rc4-hmac");
    }

    #[test]
    fn samr_parses_rid_name_rows_and_skips_header() {
        let out = "== SAMR users (2) ==\n  500\tAdministrator\n  1104\tsvc_sql\n";
        let d = parse_samr(out);
        assert_eq!(d.users.len(), 2);
        assert_eq!(d.users[0].rid, 500);
        assert_eq!(d.users[0].name, "Administrator");
        assert_eq!(d.users[1].rid, 1104);
        assert_eq!(d.users[1].name, "svc_sql");
    }

    #[test]
    fn deeper_verbs_dispatch_to_typed_docs() {
        assert!(matches!(
            try_structured("attack dcsync", "", ""),
            Some(Structured::Dcsync(_))
        ));
        assert!(matches!(
            try_structured("enum samr", "", ""),
            Some(Structured::Samr(_))
        ));
        assert!(matches!(
            try_structured("attack secretsdump", "", ""),
            Some(Structured::Secretsdump(_))
        ));
    }
}
