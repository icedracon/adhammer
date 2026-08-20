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
