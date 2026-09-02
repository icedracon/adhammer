//! Black-box runner control-plane.
//!
//! WS-FOUNDATION-INTEGRATE (1.4.10 foundation, capability in 1.5.0). Small, protocol-agnostic surface that
//! lets a runner:
//!   - filter checks by an `only`/`skip` selection,
//!   - refuse a check whose class violates the current consent posture
//!     (BF-5 for PostCred, `allow_impact` for Impact),
//!   - stop before touching a new host if `max_hosts` would be exceeded
//!     (BF-4),
//!   - report whether the wall-clock budget has been consumed
//!     (BF-4 for `max_duration_secs`),
//!   - record landed capabilities so a later PostCred check can proceed.
//!
//! DNS discovery is intentionally NOT wired here. Per D2 locked in
//! docs/PLAN_1.5.0.md we hand-roll SRV lookup (WS-FOUNDATION-DNS-HANDROLL,
//! 1.5.1) rather than pulling `hickory-resolver`. The previous draft's
//! `discover_dns` method + `adhammer_collector::DnsDiscovery` import are
//! removed here. When the hand-rolled backend lands, a `discover_dns`
//! method will re-appear as a wrapper that respects `may_run` + budgets.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use adhammer_core::{Capability, CheckClass, CheckId, EngagementScope, FindingStatus};

/// Operator policy for a black-box assessment run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunPolicy {
    pub scope: EngagementScope,
    pub consent: ConsentPolicy,
    pub max_hosts: Option<usize>,
    pub max_duration_secs: Option<u64>,
}

/// Consent flags that govern whether a runner may execute higher-risk checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ConsentPolicy {
    pub allow_impact: bool,
    /// Runners that broadcast-spoof (LLMNR/NBT-NS/DHCPv6 poisoners) must
    /// query this flag directly before sending a poisoned response.
    pub allow_spoof: bool,
    pub interactive: bool,
}

/// Inclusive and exclusive check selectors.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CheckSelection {
    pub only: Vec<CheckId>,
    pub skip: Vec<CheckId>,
}

impl CheckSelection {
    pub fn includes(&self, check: &CheckId) -> bool {
        (self.only.is_empty() || self.only.iter().any(|candidate| candidate == check))
            && !self.skip.iter().any(|candidate| candidate == check)
    }
}

/// Compact rollup for a run.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RunSummary {
    pub planned: usize,
    pub completed: usize,
    pub findings: usize,
    pub blocked: usize,
    pub errors: usize,
}

impl RunSummary {
    pub fn record(&mut self, status: FindingStatus) {
        self.completed += 1;
        match status {
            FindingStatus::Found => self.findings += 1,
            FindingStatus::Blocked => self.blocked += 1,
            FindingStatus::Error => self.errors += 1,
            FindingStatus::NotFound | FindingStatus::NotApplicable => {}
        }
    }
}

/// Reason a runner refused a check. Distinct variants let a report render
/// "why", not just "no".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunnerRefusal {
    NotInSelection,
    ImpactRequiresConsent,
    /// BF-5 (1.4.10): PostCred fired without a landed capability.
    PostCredRequiresCapability,
    /// BF-4 (1.4.10): host budget exhausted.
    HostBudgetExhausted {
        limit: usize,
    },
    /// BF-4 (1.4.10): wall-clock budget exhausted.
    DurationBudgetExhausted {
        limit_secs: u64,
    },
}

impl std::fmt::Display for RunnerRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInSelection => f.write_str("check not in operator selection"),
            Self::ImpactRequiresConsent => {
                f.write_str("impact-class check requires ConsentPolicy.allow_impact=true")
            }
            Self::PostCredRequiresCapability => {
                f.write_str("post-cred check requires at least one landed capability (see BF-5)")
            }
            Self::HostBudgetExhausted { limit } => {
                write!(f, "host budget exhausted (max_hosts={limit})")
            }
            Self::DurationBudgetExhausted { limit_secs } => {
                write!(
                    f,
                    "duration budget exhausted (max_duration_secs={limit_secs})"
                )
            }
        }
    }
}

impl std::error::Error for RunnerRefusal {}

/// Selection + policy + runtime accounting for a black-box run.
///
/// Not `Clone` — the interior `Mutex` around the touched-host set and the
/// landed capabilities is per-run state. Wrap in `Arc` for concurrent use.
pub struct BlackBoxRunner {
    policy: RunPolicy,
    selection: CheckSelection,
    started_at: Instant,
    touched_hosts: Mutex<HashSet<IpAddr>>,
    landed_capabilities: Mutex<Vec<Capability>>,
}

impl BlackBoxRunner {
    pub fn new(policy: RunPolicy, selection: CheckSelection) -> Self {
        Self {
            policy,
            selection,
            started_at: Instant::now(),
            touched_hosts: Mutex::new(HashSet::new()),
            landed_capabilities: Mutex::new(Vec::new()),
        }
    }

    pub fn policy(&self) -> &RunPolicy {
        &self.policy
    }

    /// Record that a check landed a capability (anonymous LDAP bind
    /// succeeded, SMB null session opened, credential recovered, …). Later
    /// PostCred-class checks may now proceed.
    pub fn record_capability(&self, cap: Capability) {
        self.landed_capabilities
            .lock()
            .expect("landed_capabilities mutex poisoned")
            .push(cap);
    }

    /// Snapshot of landed capabilities (defensive clone — callers should
    /// not hold the internal lock).
    pub fn capabilities(&self) -> Vec<Capability> {
        self.landed_capabilities
            .lock()
            .expect("landed_capabilities mutex poisoned")
            .clone()
    }

    /// Elapsed wall-clock time within the budget cap? BF-4.
    pub fn duration_within_budget(&self) -> bool {
        match self.policy.max_duration_secs {
            None => true,
            Some(cap) => self.started_at.elapsed().as_secs() < cap,
        }
    }

    /// BF-4 gate: register a first-touch of `ip`. Errors if the host would
    /// push us over `max_hosts`. Repeat calls with the same `ip` are free
    /// (already counted). Callers place this immediately before dialing.
    pub fn start_host(&self, ip: IpAddr) -> Result<(), RunnerRefusal> {
        let mut touched = self
            .touched_hosts
            .lock()
            .expect("touched_hosts mutex poisoned");
        if touched.contains(&ip) {
            return Ok(());
        }
        if let Some(cap) = self.policy.max_hosts {
            if touched.len() >= cap {
                return Err(RunnerRefusal::HostBudgetExhausted { limit: cap });
            }
        }
        touched.insert(ip);
        Ok(())
    }

    /// Distinct hosts touched so far. Diagnostic only — the budget check
    /// happens in `start_host`.
    pub fn hosts_touched(&self) -> usize {
        self.touched_hosts
            .lock()
            .expect("touched_hosts mutex poisoned")
            .len()
    }

    /// BF-4 + BF-5 gate: return `Ok(())` if `check` at `class` may run
    /// under the current policy AND runtime state; `Err(RunnerRefusal)`
    /// otherwise. Does NOT register a host touch — call `start_host`
    /// before the actual dial.
    pub fn may_run(&self, check: &CheckId, class: CheckClass) -> Result<(), RunnerRefusal> {
        if !self.selection.includes(check) {
            return Err(RunnerRefusal::NotInSelection);
        }
        if !self.duration_within_budget() {
            return Err(RunnerRefusal::DurationBudgetExhausted {
                limit_secs: self.policy.max_duration_secs.unwrap_or(0),
            });
        }
        match class {
            CheckClass::Discovery => Ok(()),
            CheckClass::Impact => {
                if self.policy.consent.allow_impact {
                    Ok(())
                } else {
                    Err(RunnerRefusal::ImpactRequiresConsent)
                }
            }
            CheckClass::PostCred => {
                // BF-5: a PostCred check requires SOMETHING already
                // landed. Any capability suffices — the specific
                // subclass check (does this capability actually reach
                // this target?) is the caller's responsibility.
                if self
                    .landed_capabilities
                    .lock()
                    .expect("landed_capabilities mutex poisoned")
                    .is_empty()
                {
                    Err(RunnerRefusal::PostCredRequiresCapability)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Boolean sibling of `may_run` for hot-path filters where the reason
    /// does not need surfacing. Prefer `may_run` when the caller wants to
    /// log or report a refusal.
    pub fn should_run(&self, check: &CheckId, class: CheckClass) -> bool {
        self.may_run(check, class).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use adhammer_core::{
        Capability, CapabilityKind, CheckClass, CheckId, EngagementScope, FindingStatus,
        ScopeTarget,
    };
    use std::net::IpAddr;
    use std::str::FromStr;

    use super::{
        BlackBoxRunner, CheckSelection, ConsentPolicy, RunPolicy, RunSummary, RunnerRefusal,
    };

    fn scope() -> EngagementScope {
        EngagementScope::new(vec![ScopeTarget::Host {
            addr: IpAddr::from_str("127.0.0.1").unwrap(),
        }])
        .unwrap()
    }

    fn cap(kind: CapabilityKind) -> Capability {
        Capability {
            kind,
            principal: None,
            source: None,
            secret: None,
        }
    }

    fn runner_with(policy: RunPolicy, selection: CheckSelection) -> BlackBoxRunner {
        BlackBoxRunner::new(policy, selection)
    }

    fn default_policy(max_hosts: Option<usize>, max_secs: Option<u64>) -> RunPolicy {
        RunPolicy {
            scope: scope(),
            consent: ConsentPolicy::default(),
            max_hosts,
            max_duration_secs: max_secs,
        }
    }

    #[test]
    fn only_and_skip_filter_checks() {
        let dns = CheckId::new("dns-enum").unwrap();
        let ldap = CheckId::new("ldap-rootdse").unwrap();
        let selection = CheckSelection {
            only: vec![dns.clone()],
            skip: vec![ldap.clone()],
        };
        assert!(selection.includes(&dns));
        assert!(!selection.includes(&ldap));
    }

    #[test]
    fn impact_checks_require_consent() {
        let r = runner_with(default_policy(None, None), CheckSelection::default());
        assert!(r.should_run(&CheckId::new("dns-enum").unwrap(), CheckClass::Discovery));
        let err = r
            .may_run(&CheckId::new("spray-kerberos").unwrap(), CheckClass::Impact)
            .unwrap_err();
        assert_eq!(err, RunnerRefusal::ImpactRequiresConsent);
    }

    /// BF-5 regression. A PostCred check without any landed capability
    /// must refuse. Once a capability is recorded, the same check
    /// proceeds.
    #[test]
    fn postcred_requires_landed_capability() {
        let r = runner_with(default_policy(None, None), CheckSelection::default());
        let check = CheckId::new("laps-read").unwrap();
        let err = r.may_run(&check, CheckClass::PostCred).unwrap_err();
        assert_eq!(err, RunnerRefusal::PostCredRequiresCapability);

        r.record_capability(cap(CapabilityKind::AnonymousLdap));
        assert!(r.should_run(&check, CheckClass::PostCred));
        assert_eq!(r.capabilities().len(), 1);
    }

    /// BF-4 regression. `start_host` enforces `max_hosts` and refuses
    /// the first host beyond the cap; already-touched hosts are free.
    #[test]
    fn max_hosts_budget_refuses_extra_first_touches() {
        let r = runner_with(default_policy(Some(2), None), CheckSelection::default());
        r.start_host(IpAddr::from_str("10.0.0.1").unwrap()).unwrap();
        r.start_host(IpAddr::from_str("10.0.0.2").unwrap()).unwrap();
        // Re-touch the same host: free.
        r.start_host(IpAddr::from_str("10.0.0.1").unwrap()).unwrap();
        // Third distinct host: refused.
        let err = r
            .start_host(IpAddr::from_str("10.0.0.3").unwrap())
            .unwrap_err();
        assert_eq!(err, RunnerRefusal::HostBudgetExhausted { limit: 2 });
        assert_eq!(r.hosts_touched(), 2);
    }

    /// BF-4 regression. `max_duration_secs = Some(0)` forces every
    /// may_run past `started_at` to refuse. `None` never refuses on time.
    #[test]
    fn duration_budget_refuses_after_cap() {
        let r = runner_with(default_policy(None, Some(0)), CheckSelection::default());
        let check = CheckId::new("dns-enum").unwrap();
        let err = r.may_run(&check, CheckClass::Discovery).unwrap_err();
        assert!(matches!(
            err,
            RunnerRefusal::DurationBudgetExhausted { limit_secs: 0 }
        ));

        let r = runner_with(default_policy(None, None), CheckSelection::default());
        assert!(r.duration_within_budget());
        assert!(r.should_run(&check, CheckClass::Discovery));
    }

    /// Selection refusal is distinct from consent / budget refusal.
    #[test]
    fn refusal_reasons_are_distinct() {
        let dns = CheckId::new("dns-enum").unwrap();
        let ldap = CheckId::new("ldap-rootdse").unwrap();
        let r = runner_with(
            default_policy(None, None),
            CheckSelection {
                only: vec![dns.clone()],
                skip: Vec::new(),
            },
        );
        assert_eq!(
            r.may_run(&ldap, CheckClass::Discovery).unwrap_err(),
            RunnerRefusal::NotInSelection
        );
    }

    #[test]
    fn summary_counts_findings_blocks_and_errors() {
        let mut summary = RunSummary {
            planned: 3,
            ..RunSummary::default()
        };
        summary.record(FindingStatus::Found);
        summary.record(FindingStatus::Blocked);
        summary.record(FindingStatus::Error);
        assert_eq!(summary.planned, 3);
        assert_eq!(summary.completed, 3);
        assert_eq!(summary.findings, 1);
        assert_eq!(summary.blocked, 1);
        assert_eq!(summary.errors, 1);
    }

    #[test]
    fn refusal_display_is_operator_readable() {
        assert!(format!("{}", RunnerRefusal::NotInSelection).contains("selection"));
        assert!(format!("{}", RunnerRefusal::ImpactRequiresConsent).contains("allow_impact"));
        assert!(format!("{}", RunnerRefusal::PostCredRequiresCapability).contains("capability"));
        assert!(format!("{}", RunnerRefusal::HostBudgetExhausted { limit: 42 }).contains("42"));
        assert!(format!(
            "{}",
            RunnerRefusal::DurationBudgetExhausted { limit_secs: 900 }
        )
        .contains("900"));
    }

    /// The runner does not clone or leak the internal capability lock
    /// (defensive-clone contract).
    #[test]
    fn capabilities_snapshot_is_defensive_clone() {
        let r = runner_with(default_policy(None, None), CheckSelection::default());
        r.record_capability(cap(CapabilityKind::AnonymousLdap));
        let snap = r.capabilities();
        assert_eq!(snap.len(), 1);
        r.record_capability(cap(CapabilityKind::SmbNullSession));
        // The snapshot returned above is not affected by later records.
        assert_eq!(snap.len(), 1);
        assert_eq!(r.capabilities().len(), 2);
    }
}
