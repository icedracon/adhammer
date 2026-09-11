//! The output vocabulary: a Finding is one rule firing, tagged with a hygiene
//! category, a severity, and one or more MITRE ATT&CK techniques.

use serde::Serialize;

/// The four top-level AD hygiene categories a Finding rolls up under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Category {
    PrivilegedAccounts,
    Trusts,
    StaleObjects,
    Anomalies,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    /// Base weight fed into the risk engine (overridable via config).
    pub fn base_weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 5,
            Severity::Medium => 15,
            Severity::High => 30,
            Severity::Critical => 50,
        }
    }
}

/// MITRE ATT&CK technique reference, e.g. ("T1558.003", "Kerberoasting").
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Mitre {
    pub id: &'static str,
    pub name: &'static str,
}

/// Common techniques, referenced by checks so the mapping lives in one place.
pub mod mitre {
    use super::Mitre;
    pub const KERBEROASTING: Mitre = Mitre {
        id: "T1558.003",
        name: "Kerberoasting",
    };
    pub const ASREP_ROAST: Mitre = Mitre {
        id: "T1558.004",
        name: "AS-REP Roasting",
    };
    pub const GOLDEN_TICKET: Mitre = Mitre {
        id: "T1558.001",
        name: "Golden Ticket",
    };
    pub const SILVER_TICKET: Mitre = Mitre {
        id: "T1558.002",
        name: "Silver Ticket",
    };
    pub const DCSYNC: Mitre = Mitre {
        id: "T1003.006",
        name: "DCSync",
    };
    pub const DCSHADOW: Mitre = Mitre {
        id: "T1207",
        name: "Rogue Domain Controller",
    };
    pub const GPO_MOD: Mitre = Mitre {
        id: "T1484.001",
        name: "Group Policy Modification",
    };
    pub const TRUST_MOD: Mitre = Mitre {
        id: "T1484.002",
        name: "Domain Trust Modification",
    };
    pub const CERT_ABUSE: Mitre = Mitre {
        id: "T1649",
        name: "Steal or Forge Auth Certificates",
    };
    pub const VALID_ACCOUNTS: Mitre = Mitre {
        id: "T1078",
        name: "Valid Accounts",
    };
    pub const COERCION: Mitre = Mitre {
        id: "T1187",
        name: "Forced Authentication",
    };
}

/// A single piece of **ground-truth evidence** substantiating a finding (WS-PROOF): the actual
/// server/client artifact — an LDAP attribute value, an MS-RRP registry key, a SAMR field, a wire
/// status code — that a reviewer can verify **by hand, independent of adhammer's verdict**. This is
/// the difference between "you have X" (our word) and "the server returned Y, which is X" (proof).
#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    /// Where it came from, expressed so a reviewer can reproduce it — e.g.
    /// `LDAP CN=svc_sql,…:msDS-SupportedEncryptionTypes`,
    /// `MS-RRP HKLM\SYSTEM\CurrentControlSet\…\StrongCertificateBindingEnforcement`,
    /// `SAMR DOMAIN_PASSWORD_INFORMATION.MinPasswordLength`.
    pub source: String,
    /// The raw value exactly as the server/client returned it (decoded/hex as needed for legibility).
    pub value: String,
}

impl Evidence {
    pub fn new(source: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            value: value.into(),
        }
    }
}

/// WS-WPT (1.4.6): the wire layer a [`WireExchange`] belongs to. The one enum every check that
/// hits the network tags its recorded exchange with, so the report can group/filter by layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WireLayer {
    Ldap,
    Rrp,
    Smb,
    Kerberos,
    Rpc,
    Http,
}

/// WS-WPT (1.4.6): direction of a single frame in a [`WireExchange`] — `Sent` = adhammer → server,
/// `Recv` = server → adhammer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WireDirection {
    Sent,
    Recv,
}

/// WS-WPT (1.4.6): **the wire exchange that produced a finding** — request/response transcript
/// alongside the interpreted [`Evidence`]. Where `Evidence` says "the server returned Y", `WireExchange`
/// shows the *actual conversation*: adhammer sent request X, DC replied Y, that reply means vuln
/// because Z.
///
/// Renderers show this in an expandable per-finding block. Kept lightweight — a single
/// human-readable `summary` line is enough for most checks (LDAP search filter + result count);
/// `raw_hex` is optional and **capped at 512 bytes** by the recorder to bound report size against
/// a hostile server.
#[derive(Clone, Debug, Serialize)]
pub struct WireExchange {
    /// Which wire protocol this frame belongs to.
    pub layer: WireLayer,
    /// Sent (client → server) or Recv (server → client). Frame ordering in `Vec<WireExchange>`
    /// is the caller's responsibility; a typical exchange is `[Sent, Recv]`.
    pub direction: WireDirection,
    /// RPC opnum where applicable (SCMR CreateServiceW, DRSUAPI GetNCChanges, RRP OpenBaseKey…),
    /// otherwise `None` (e.g. LDAP searches, HTTP GETs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opnum: Option<u16>,
    /// One-line human-readable summary: `"LDAP search base=... filter=... → N entries"`,
    /// `"HTTP GET /certsrv → 401 WWW-Authenticate: Negotiate, NTLM"`, etc.
    pub summary: String,
    /// Optional raw bytes (hex) — capped by the recorder. Absent when a summary suffices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_hex: Option<String>,
}

impl WireExchange {
    /// A `Sent` frame with just a summary (no raw hex, no opnum). The most common shape.
    pub fn sent(layer: WireLayer, summary: impl Into<String>) -> Self {
        Self {
            layer,
            direction: WireDirection::Sent,
            opnum: None,
            summary: summary.into(),
            raw_hex: None,
        }
    }

    /// A `Recv` frame with just a summary.
    pub fn recv(layer: WireLayer, summary: impl Into<String>) -> Self {
        Self {
            layer,
            direction: WireDirection::Recv,
            opnum: None,
            summary: summary.into(),
            raw_hex: None,
        }
    }

    /// Attach an opnum (chainable).
    pub fn with_opnum(mut self, opnum: u16) -> Self {
        self.opnum = Some(opnum);
        self
    }

    /// Attach raw bytes as hex; truncated to `MAX_RAW_HEX_BYTES` before hex-encoding so the
    /// hex string is at most `MAX_RAW_HEX_BYTES * 2` chars — bounded-alloc discipline against
    /// a hostile server.
    pub fn with_raw_bytes(mut self, bytes: &[u8]) -> Self {
        const MAX_RAW_HEX_BYTES: usize = 512;
        let take = bytes.len().min(MAX_RAW_HEX_BYTES);
        let mut hex = String::with_capacity(take * 2);
        for b in &bytes[..take] {
            use std::fmt::Write;
            let _ = write!(&mut hex, "{b:02x}");
        }
        if bytes.len() > MAX_RAW_HEX_BYTES {
            hex.push('…');
        }
        self.raw_hex = Some(hex);
        self
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: String, // stable rule id, e.g. "P-KerberoastAdmin"
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub mitre: Vec<Mitre>,
    /// DNs / SIDs the finding points at.
    pub affected: Vec<String>,
    /// What was observed (evidence-level: raw stat, matched attribute, etc.).
    pub detail: String,
    /// Ground-truth evidence (WS-PROOF): the raw server/client artifacts that prove this finding,
    /// each verifiable by hand. Empty only for not-yet-evidenced legacy rules; the 1.4.3 goal is
    /// every finding carries ≥1. Reports/UIs render it under a distinct "Evidence" heading.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// WS-WPT (1.4.6): the wire-level exchange(s) that produced this finding — the actual
    /// request/response transcript, one step deeper than [`Self::evidence`]. Empty for passive
    /// checks that only read a pre-collected snapshot without recording provenance yet (WS-WPT
    /// sessions 3–4 fill this in for all 58 registry checks + all active probes). Renderers show
    /// an expandable "Wire exchange" block per finding when present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exchange: Vec<WireExchange>,
    /// Attack-chain narrative: if an attacker acted on this finding, what would happen?
    /// 1-2 sentences. Optional so downstream Finding producers can leave it blank; UIs
    /// render it under a distinct "Impact" heading and reports omit the section if `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    pub remediation: String,
    /// Extra weight beyond the severity base (e.g. per-object scaling).
    #[serde(default)]
    pub weight_bonus: u32,
}

impl Finding {
    /// Chainable setter for [`Self::impact`] — used by rule constructors that want to
    /// annotate the attack-chain narrative alongside the raw evidence.
    pub fn with_impact(mut self, impact: impl Into<String>) -> Self {
        self.impact = Some(impact.into());
        self
    }

    /// Attach one piece of ground-truth evidence (chainable) — see [`Evidence`].
    pub fn with_evidence(mut self, source: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.push(Evidence::new(source, value));
        self
    }

    /// Attach several evidence rows at once (chainable).
    pub fn with_evidences(mut self, ev: impl IntoIterator<Item = Evidence>) -> Self {
        self.evidence.extend(ev);
        self
    }

    /// WS-WPT: attach one [`WireExchange`] frame (chainable). Typical use is two calls in a row —
    /// once for the sent request, once for the received reply — from the check that captured them.
    pub fn with_wire(mut self, ex: WireExchange) -> Self {
        self.exchange.push(ex);
        self
    }

    /// WS-WPT: attach several exchange frames at once (chainable). Order is preserved.
    pub fn with_wires(mut self, ex: impl IntoIterator<Item = WireExchange>) -> Self {
        self.exchange.extend(ex);
        self
    }

    /// WS-UX-NEXTACTION (1.5.1): the operator's copy-pasteable next command for this
    /// finding, if there is a natural follow-up verb. This is the single mapper every
    /// renderer (CLI footer, report block, `--json`) routes through, so guidance stays
    /// uniform. `<placeholder>` slots (`<dc>`, `<user>`, `<domain>`, `<your-ip>`) are
    /// filled by the operator; finding-specific args (template/victim name) are pulled
    /// from the first affected object when it is a short, safe value. Returns `None` for
    /// findings with no direct actioning verb (the renderer then prints nothing).
    pub fn next_command(&self) -> Option<NextCommand> {
        let id = self.id.to_ascii_lowercase();
        // SECURITY: the suggested command is copy-pasted into a shell. Only substitute an
        // affected name (attacker-controlled via LDAP `cn`/`name`) if it is shell-safe —
        // otherwise a CN like `x;rm -rf /` or `$(…)` would ride into the command. Unsafe or
        // absent → a clearly-a-placeholder token the operator fills in. (HTML escaping does
        // not help here; this is a shell context.)
        let named = self
            .affected
            .first()
            .map(|a| leaf_name(a))
            .filter(|s| is_shell_safe(s) && s.len() <= 64);
        let tmpl = named.clone().unwrap_or_else(|| "<template>".into());
        let victim = named.unwrap_or_else(|| "<victim>".into());
        let mk = |label: &str, command: String, requires_consent: bool| {
            Some(NextCommand {
                label: label.to_string(),
                command,
                requires_consent,
            })
        };

        // AD CS ESC ids: match the EXACT ESC number, not a substring — otherwise `esc1`
        // also catches `esc10`/`esc11`/`esc15`/`esc16` and mis-suggests the ESC1 attack.
        if let Some(n) = esc_number(&id) {
            return match n {
                1 => mk(
                    "escalate via ESC1 (spoofed-UPN enrollment)",
                    format!("adhammer attack icpr-esc1 --url ldaps://<dc> --user <user> --template {tmpl}"),
                    true,
                ),
                4 => mk(
                    "weaponize the template (ESC4 -> ESC1)",
                    format!("adhammer attack esc4 --url ldaps://<dc> --user <user> --template {tmpl}"),
                    true,
                ),
                8 => mk(
                    "relay to AD CS Web Enrollment (ESC8)",
                    "adhammer attack relay --target adcs --listener <your-ip>".into(),
                    true,
                ),
                11 => mk(
                    "relay to ICPR (ESC11)",
                    "adhammer attack relay --target icpr --listener <your-ip>".into(),
                    true,
                ),
                _ => mk(
                    "enumerate the AD CS attack surface",
                    "adhammer enum adcs --url ldaps://<dc> --user <user>".into(),
                    false,
                ),
            };
        }
        if id.contains("adcsesc") {
            return mk(
                "enumerate the AD CS attack surface",
                "adhammer enum adcs --url ldaps://<dc> --user <user>".into(),
                false,
            );
        }
        if id.contains("kerberoast") || id.contains("roast") || id.contains("asrep") {
            return mk(
                "roast the exposed accounts",
                "adhammer attack roast --url ldaps://<dc> --user <user> --kdc <dc>".into(),
                false,
            );
        }
        if id.contains("krbtgt") {
            return mk(
                "dump krbtgt for a golden ticket",
                "adhammer attack dcsync --host <dc> --domain <domain> --user <user> --target krbtgt"
                    .into(),
                true,
            );
        }
        if id.contains("unconstrained") || id.contains("delegation") {
            return mk(
                "hunt unconstrained-delegation hosts",
                "adhammer attack unconstrained --url ldaps://<dc> --user <user>".into(),
                false,
            );
        }
        if id.contains("badsuccessor") {
            return mk(
                "abuse dMSA (BadSuccessor)",
                format!("adhammer attack badsuccessor --url ldaps://<dc> --user <user> --victim {victim}"),
                true,
            );
        }
        if id.contains("laps") || id.contains("admpwd") {
            return mk(
                "read LAPS local-admin passwords",
                "adhammer attack laps --url ldaps://<dc> --user <user>".into(),
                false,
            );
        }
        if id.contains("gmsa") {
            return mk(
                "read the gMSA managed password",
                "adhammer attack gmsa --url ldaps://<dc> --user <user>".into(),
                false,
            );
        }
        if id.contains("signing") || id.contains("channelbinding") || id.contains("coerce") {
            return mk(
                "coerce the DC to your listener",
                "adhammer attack coerce --host <dc> --domain <domain> --user <user> --listener <your-ip>"
                    .into(),
                true,
            );
        }
        None
    }
}

/// Extract the leaf value of a DN (`CN=Foo,OU=..` -> `Foo`); otherwise the trimmed input.
fn leaf_name(s: &str) -> String {
    if let Some(first) = s.split(',').next() {
        if let Some((_, v)) = first.split_once('=') {
            return v.trim().to_string();
        }
    }
    s.trim().to_string()
}

/// Whether a token is safe to drop verbatim into a copy-paste shell command: ASCII
/// letters/digits and `.`/`-`/`_` only. Rejects spaces, quotes, and every shell
/// metacharacter, so an attacker-controlled LDAP name cannot inject into the suggestion.
fn is_shell_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// The exact ESC number in an AD CS finding id (`a-esc15` -> 15), or `None`. Matches the
/// digits immediately after `esc`, so `esc1` and `esc11`/`esc15` are distinct.
fn esc_number(id: &str) -> Option<u32> {
    let pos = id.find("esc")?;
    let digits: String = id[pos + 3..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// WS-UX-NEXTACTION (1.5.1): a copy-pasteable next command suggested for a [`Finding`].
///
/// Distinct from [`crate::NextAction`] (which models *engine check-chaining* via
/// `check`/`class`): this is operator ergonomics — "you found X, here is the exact
/// command to act on it" — the single biggest lever turning ADhammer's 90-verb surface
/// from a maze into a guided kill-chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NextCommand {
    /// One-line human label, e.g. "escalate via ESC1".
    pub label: String,
    /// The runnable command, with `<placeholder>` slots the operator fills in.
    pub command: String,
    /// True when the command performs a state-changing / offensive action needing consent.
    pub requires_consent: bool,
}

impl NextCommand {
    /// The CLI footer line rendered beneath a finding (`  -> next: <command>`).
    pub fn cli_line(&self) -> String {
        format!("  \u{2192} next: {}", self.command)
    }
}

impl Finding {
    pub fn score(&self) -> u32 {
        self.severity.base_weight() + self.weight_bonus
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AttackResult {
    pub command: String,
    pub success: bool,
    pub evidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn wire_exchange_builders_shape_sent_and_recv() {
        let sent = WireExchange::sent(WireLayer::Ldap, "LDAP search filter=(objectClass=user)")
            .with_opnum(3);
        assert_eq!(sent.direction, WireDirection::Sent);
        assert_eq!(sent.layer, WireLayer::Ldap);
        assert_eq!(sent.opnum, Some(3));
        assert!(sent.raw_hex.is_none());

        let recv = WireExchange::recv(WireLayer::Http, "HTTP/1.1 401 Unauthorized");
        assert_eq!(recv.direction, WireDirection::Recv);
        assert!(recv.opnum.is_none());
    }

    #[test]
    fn wire_raw_bytes_are_capped_against_hostile_server() {
        // Bounded-alloc discipline: 4KB in, ≤ 512 bytes retained; hex includes an ellipsis marker.
        let big = vec![0xABu8; 4096];
        let ex = WireExchange::recv(WireLayer::Rpc, "big blob").with_raw_bytes(&big);
        let hex = ex.raw_hex.expect("raw_hex populated");
        assert!(hex.ends_with('…'), "hex truncated with ellipsis marker");
        // 512 bytes × 2 hex chars + '…' = 1025 chars max
        assert!(
            hex.chars().count() <= 1025,
            "hex string {} chars — cap not enforced",
            hex.chars().count()
        );
    }

    #[test]
    fn finding_with_wire_and_with_wires_extend_the_field() {
        let f = Finding {
            id: "T".into(),
            title: "t".into(),
            category: Category::Anomalies,
            severity: Severity::Low,
            mitre: vec![],
            affected: vec![],
            detail: String::new(),
            evidence: vec![],
            exchange: vec![],
            impact: None,
            remediation: String::new(),
            weight_bonus: 0,
        }
        .with_wire(WireExchange::sent(WireLayer::Ldap, "s1"))
        .with_wires([
            WireExchange::recv(WireLayer::Ldap, "r1"),
            WireExchange::sent(WireLayer::Rrp, "s2").with_opnum(15),
        ]);
        assert_eq!(f.exchange.len(), 3);
        assert_eq!(f.exchange[2].opnum, Some(15));
    }
}

#[cfg(test)]
mod next_command_tests {
    use super::*;

    fn f(id: &str, affected: Vec<String>) -> Finding {
        Finding {
            id: id.into(),
            title: "t".into(),
            category: Category::Anomalies,
            severity: Severity::High,
            mitre: vec![],
            affected,
            detail: "d".into(),
            evidence: vec![],
            exchange: vec![],
            impact: None,
            remediation: "r".into(),
            weight_bonus: 0,
        }
    }

    #[test]
    fn esc1_maps_to_icpr_esc1_with_template_from_affected() {
        let nc = f("A-Esc1", vec!["CN=WeakTpl,CN=Certificate Templates".into()])
            .next_command()
            .expect("esc1 has a next command");
        assert!(nc.command.contains("attack icpr-esc1"), "{}", nc.command);
        assert!(nc.command.contains("--template WeakTpl"), "{}", nc.command);
        assert!(nc.requires_consent);
    }

    #[test]
    fn esc1_without_affected_uses_placeholder() {
        let nc = f("A-Esc1", vec![]).next_command().unwrap();
        assert!(
            nc.command.contains("--template <template>"),
            "{}",
            nc.command
        );
    }

    #[test]
    fn headline_classes_map_to_real_verbs() {
        assert!(f("P-KerberoastAdmin", vec![])
            .next_command()
            .unwrap()
            .command
            .contains("attack roast"));
        assert!({
            let c = f("A-KrbtgtAge", vec![]).next_command().unwrap().command;
            c.contains("attack dcsync") && c.contains("--target krbtgt")
        });
        assert!(f("P-UnconstrainedDelegation", vec![])
            .next_command()
            .unwrap()
            .command
            .contains("attack unconstrained"));
        assert!(f("A-BadSuccessor", vec!["CN=targetuser,CN=Users".into()])
            .next_command()
            .unwrap()
            .command
            .contains("--victim targetuser"));
        // Generic ESC falls back to enumeration, not a specific weaponization.
        assert_eq!(
            f("A-Esc9", vec![]).next_command().unwrap().command,
            "adhammer enum adcs --url ldaps://<dc> --user <user>"
        );
    }

    #[test]
    fn findings_without_a_verb_return_none() {
        assert!(f("A-FunctionalLevel", vec![]).next_command().is_none());
        assert!(f("A-PasswordPolicy", vec![]).next_command().is_none());
    }

    #[test]
    fn cli_line_is_the_uniform_footer() {
        let nc = f("A-Esc4", vec![]).next_command().unwrap();
        assert!(nc
            .cli_line()
            .starts_with("  \u{2192} next: adhammer attack esc4"));
    }

    #[test]
    fn esc_number_is_exact_not_substring() {
        // esc1 -> icpr-esc1; esc11 -> relay icpr; esc15/esc16 -> enum adcs (NOT icpr-esc1).
        assert!(f("A-Esc1", vec![])
            .next_command()
            .unwrap()
            .command
            .contains("attack icpr-esc1"));
        assert!(f("A-Esc11", vec![])
            .next_command()
            .unwrap()
            .command
            .contains("relay --target icpr"));
        for id in ["A-Esc15", "A-Esc16", "A-Esc10"] {
            let c = f(id, vec![]).next_command().unwrap().command;
            assert_eq!(
                c, "adhammer enum adcs --url ldaps://<dc> --user <user>",
                "{id} mis-mapped: {c}"
            );
            assert!(
                !c.contains("icpr-esc1"),
                "{id} wrongly got the ESC1 command"
            );
        }
    }

    #[test]
    fn shell_metacharacters_in_affected_name_do_not_reach_the_command() {
        // Attacker-controlled template CN with a shell separator must NOT be substituted.
        let nc = f("A-Esc1", vec!["CN=x;rm -rf /,CN=Templates".into()])
            .next_command()
            .unwrap();
        assert!(
            nc.command.contains("--template <template>"),
            "unsafe name substituted: {}",
            nc.command
        );
        assert!(
            !nc.command.contains("rm -rf"),
            "shell injection into suggestion: {}",
            nc.command
        );
        // A clean name is still substituted.
        let ok = f("A-Esc1", vec!["CN=WeakTpl,CN=Templates".into()])
            .next_command()
            .unwrap();
        assert!(ok.command.contains("--template WeakTpl"));
    }
}
