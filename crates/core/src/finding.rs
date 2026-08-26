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
