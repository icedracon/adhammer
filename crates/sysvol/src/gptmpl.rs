//! Security-template parsing from SYSVOL: the `[Registry Values]` of GptTmpl.inf carries
//! LM/NTLM level and SMB/LDAP/Netlogon signing settings that are *not* exposed via LDAP.
//!
//! To stay precise we only read the two fixed-GUID default policies — Default Domain
//! Policy and Default Domain Controllers Policy — so we never false-positive on an
//! unlinked or test GPO. GptTmpl.inf is normally UTF-16LE with a BOM.

use adhammer_core::finding::{mitre, Category, Severity};
use adhammer_core::Finding;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const DEFAULT_DOMAIN_POLICY: &str = "31B2F340-016D-11D2-945F-00C04FB984F9";
const DEFAULT_DC_POLICY: &str = "6AC1786C-016F-11D2-945F-00C04FB984F9";

/// Merge `[Registry Values]` from the two default-policy GptTmpl.inf files.
pub fn scan_policy(root: &Path) -> HashMap<String, String> {
    let mut files = Vec::new();
    collect_named(root, "gpttmpl.inf", &mut files);

    let mut map = HashMap::new();
    for f in files {
        let upper = f.to_string_lossy().to_uppercase();
        if upper.contains(DEFAULT_DOMAIN_POLICY) || upper.contains(DEFAULT_DC_POLICY) {
            if let Some(text) = read_text(&f) {
                for (k, v) in parse_registry_values(&text) {
                    map.insert(k, v);
                }
            }
        }
    }
    map
}

fn collect_named(dir: &Path, name_lc: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_named(&p, name_lc, out);
        } else if p.file_name().is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(name_lc)) {
            out.push(p);
        }
    }
}

/// Read a file that may be UTF-16LE (BOM), UTF-8 (BOM), or plain UTF-8.
fn read_text(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> =
            bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&units))
    } else if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        Some(String::from_utf8_lossy(&bytes[3..]).into_owned())
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// Parse the `[Registry Values]` section into `full\reg\path (lowercased) -> value`,
/// where the value is the part after the `type,` prefix (e.g. `4,1` -> `1`).
pub fn parse_registry_values(inf: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut in_section = false;
    for line in inf.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_section = t.eq_ignore_ascii_case("[Registry Values]");
            continue;
        }
        if !in_section || t.is_empty() {
            continue;
        }
        if let Some((k, v)) = t.split_once('=') {
            let value = v.split_once(',').map(|(_, val)| val).unwrap_or(v).trim().trim_matches('"');
            map.insert(k.trim().to_ascii_lowercase(), value.to_string());
        }
    }
    map
}

fn get<'a>(map: &'a HashMap<String, String>, suffix: &str) -> Option<&'a str> {
    map.iter().find(|(k, _)| k.ends_with(suffix)).map(|(_, v)| v.as_str())
}

fn int(map: &HashMap<String, String>, suffix: &str) -> Option<i64> {
    get(map, suffix).and_then(|v| v.parse().ok())
}

/// Derive findings from the merged default-policy registry values.
pub fn policy_findings(map: &HashMap<String, String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let f = |id: &str, title: String, sev, detail: &str, rem: &str, val: String| Finding {
        id: id.into(),
        title,
        category: Category::Anomalies,
        severity: sev,
        mitre: vec![mitre::VALID_ACCOUNTS],
        weight_bonus: 0,
        affected: vec![val],
        detail: detail.into(),
        remediation: rem.into(),
    };

    // LmCompatibilityLevel: 5 = NTLMv2 only. <3 permits LM/NTLMv1.
    if let Some(l) = int(map, r"\lsa\lmcompatibilitylevel") {
        if l < 3 {
            out.push(f("A-NtlmV1", "LM/NTLMv1 authentication permitted".into(), Severity::High,
                "LmCompatibilityLevel < 3 lets clients/DCs accept LM and NTLMv1, which are trivially crackable and relayable.",
                "Set LmCompatibilityLevel to 5 (send NTLMv2 only, refuse LM & NTLM).", format!("LmCompatibilityLevel = {l}")));
        } else if l < 5 {
            out.push(f("A-NtlmWeak", "NTLM not restricted to NTLMv2-only".into(), Severity::Medium,
                "LmCompatibilityLevel < 5 still accepts downgraded NTLM in some paths.",
                "Set LmCompatibilityLevel to 5.", format!("LmCompatibilityLevel = {l}")));
        }
    }
    // LDAPServerIntegrity: 2 = require signing.
    if let Some(v) = int(map, r"\ntds\parameters\ldapserverintegrity") {
        if v < 2 {
            out.push(f("A-LdapSigning", "LDAP server signing not required".into(), Severity::High,
                "LDAPServerIntegrity < 2 allows unsigned LDAP binds, enabling NTLM relay to LDAP (e.g. to AD CS / RBCD).",
                "Set 'Domain controller: LDAP server signing requirements' to Require signing (LDAPServerIntegrity=2).",
                format!("LDAPServerIntegrity = {v}")));
        }
    }
    // SMB server signing.
    if int(map, r"lanmanserver\parameters\requiresecuritysignature") == Some(0) {
        out.push(f("A-SmbSigning", "SMB signing not required (server)".into(), Severity::High,
            "RequireSecuritySignature=0 lets attackers relay/tamper with SMB, a prerequisite for many NTLM-relay chains.",
            "Require SMB signing on servers (and DCs) via the default policy.", "LanManServer RequireSecuritySignature = 0".into()));
    }
    // NoLMHash: 1 = do not store LM hash.
    if int(map, r"\lsa\nolmhash") == Some(0) {
        out.push(f("A-LmHashStored", "LM hashes stored in the directory".into(), Severity::Medium,
            "NoLMHash=0 stores weak LM hashes for account passwords, crackable near-instantly.",
            "Set 'Network security: Do not store LAN Manager hash value' (NoLMHash=1) and reset passwords.",
            "NoLMHash = 0".into()));
    }
    // Netlogon secure channel (Zerologon-adjacent).
    if int(map, r"netlogon\parameters\requiresignorseal") == Some(0) {
        out.push(f("A-NetlogonSeal", "Netlogon secure channel signing/sealing not enforced".into(), Severity::High,
            "RequireSignOrSeal=0 weakens the Netlogon secure channel, part of the exposure surface around CVE-2020-1472 (Zerologon).",
            "Require Netlogon secure channel signing/sealing and apply DC enforcement updates.", "Netlogon RequireSignOrSeal = 0".into()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_flags_weak_settings() {
        let inf = "[Unicode]\nUnicode=yes\n[Registry Values]\n\
            MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,1\n\
            MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,1\n\
            MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,1\n";
        let map = parse_registry_values(inf);
        let f = policy_findings(&map);
        assert!(f.iter().any(|x| x.id == "A-NtlmV1"));        // level 1 < 3
        assert!(f.iter().any(|x| x.id == "A-LdapSigning"));   // integrity 1 < 2
        assert!(!f.iter().any(|x| x.id == "A-LmHashStored")); // NoLMHash=1 is secure
    }
}
