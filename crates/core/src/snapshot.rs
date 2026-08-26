//! An immutable point-in-time capture of the directory. Checks and the graph
//! builder read this; the collector produces it. Keeps a few precomputed indices.

use crate::finding::{WireDirection, WireExchange, WireLayer};
use crate::object::AdObject;
use crate::sid::Sid;
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct DomainInfo {
    pub domain_dn: String, // DC=corp,DC=local
    pub domain_sid: Option<Sid>,
    pub netbios: Option<String>,
    pub functional_level: Option<i64>,
    pub machine_account_quota: Option<i64>,
}

/// WS-WPT (1.4.6): one LDAP search recorded by the collector. Every attribute a check reads out of
/// [`Snapshot`] traces back to the `SearchOp` that pulled it, so a `WireExchange` for every
/// LDAP-passive finding is synthesized from the same recorded search (no per-check instrumentation
/// needed for the LDAP tier — one instrumentation site inside the collector fans out to all 50
/// LDAP-decidable checks). Reused directly as the payload of a [`WireExchange::sent()`] frame.
#[derive(Clone, Debug, Default)]
pub struct SearchOp {
    pub base_dn: String,
    pub filter: String,
    /// Attributes requested; empty when the collector asked for the default set.
    pub attrs: Vec<String>,
    pub returned_count: usize,
    /// LDAP scope label as recorded by the collector (`base`, `one`, `sub`, …).
    pub scope: String,
}

impl SearchOp {
    /// Render this search as a pair of [`WireExchange`] frames — one `Sent` (the search request)
    /// and one `Recv` (the count of entries returned). The atomic unit a WPT renderer wants.
    pub fn as_exchange(&self) -> Vec<WireExchange> {
        let attrs_hint = if self.attrs.is_empty() {
            "".into()
        } else if self.attrs.len() <= 3 {
            format!(" attrs=[{}]", self.attrs.join(","))
        } else {
            format!(
                " attrs=[{},… +{}]",
                self.attrs[..3].join(","),
                self.attrs.len() - 3
            )
        };
        vec![
            WireExchange {
                layer: WireLayer::Ldap,
                direction: WireDirection::Sent,
                opnum: None,
                summary: format!(
                    "LDAP search base={} scope={} filter={}{}",
                    self.base_dn, self.scope, self.filter, attrs_hint
                ),
                raw_hex: None,
            },
            WireExchange {
                layer: WireLayer::Ldap,
                direction: WireDirection::Recv,
                opnum: None,
                summary: format!("{} entries returned", self.returned_count),
                raw_hex: None,
            },
        ]
    }
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub domain: DomainInfo,
    pub objects: Vec<AdObject>,
    /// dn (lowercased) -> index into `objects`, for O(1) resolution while walking ACLs.
    dn_index: HashMap<String, usize>,
    /// WS-WPT: every LDAP search the collector ran, in order. Session 3 infra; the collector
    /// starts populating it in session 3b, checks start referencing it in session 3c.
    searches: Vec<SearchOp>,
    /// WS-WPT: dn (lowercased) -> index into `searches` — which search first captured this object.
    /// When two searches would populate the same DN, first-write wins (session 3b will refine to
    /// last-populated-attribute, but "which search saw this object" is the useful minimum).
    dn_to_search: HashMap<String, usize>,
}

impl Snapshot {
    pub fn new(domain: DomainInfo, objects: Vec<AdObject>) -> Self {
        let dn_index = objects
            .iter()
            .enumerate()
            .map(|(i, o)| (o.dn.to_ascii_lowercase(), i))
            .collect();
        Snapshot {
            domain,
            objects,
            dn_index,
            searches: Vec::new(),
            dn_to_search: HashMap::new(),
        }
    }

    /// WS-WPT: append a SearchOp to the record. Returns its stable index for later `link_dn_to_search`
    /// calls. Called by the collector for every LDAP search it runs; no-op for callers that never
    /// invoke it (the Snapshot then has no WPT data, and `wire_for_dn` returns `None`).
    pub fn record_search(&mut self, op: SearchOp) -> usize {
        let idx = self.searches.len();
        self.searches.push(op);
        idx
    }

    /// WS-WPT: associate a DN with the SearchOp that populated it. First-write wins.
    pub fn link_dn_to_search(&mut self, dn: &str, search_idx: usize) {
        self.dn_to_search
            .entry(dn.to_ascii_lowercase())
            .or_insert(search_idx);
    }

    /// WS-WPT: full list of searches the collector recorded (empty when uninstrumented — legacy
    /// consumers just get no wire proof for LDAP checks, everything else keeps working).
    pub fn searches(&self) -> &[SearchOp] {
        &self.searches
    }

    /// WS-WPT: the two-frame wire exchange for the search that first captured this DN, ready to
    /// attach to a Finding via [`crate::Finding::with_wires`]. Returns an empty Vec when the
    /// collector hasn't been instrumented yet (session 3b) — safe to call from any check today.
    pub fn wire_for_dn(&self, dn: &str) -> Vec<WireExchange> {
        self.dn_to_search
            .get(&dn.to_ascii_lowercase())
            .and_then(|&i| self.searches.get(i))
            .map(SearchOp::as_exchange)
            .unwrap_or_default()
    }

    pub fn by_dn(&self, dn: &str) -> Option<&AdObject> {
        self.dn_index
            .get(&dn.to_ascii_lowercase())
            .map(|&i| &self.objects[i])
    }

    /// Find an object by exact SID (objectSid).
    pub fn by_sid(&self, sid: &Sid) -> Option<&AdObject> {
        self.objects
            .iter()
            .find(|o| o.bin1("objectSid").and_then(Sid::from_bytes).as_ref() == Some(sid))
    }

    /// Find a group/object by sAMAccountName (case-insensitive). Locale-dependent —
    /// prefer `by_sid` for well-known groups.
    pub fn by_sam(&self, sam: &str) -> Option<&AdObject> {
        self.objects.iter().find(|o| {
            o.one("sAMAccountName")
                .is_some_and(|s| s.eq_ignore_ascii_case(sam))
        })
    }

    pub fn iter_class<'a>(&'a self, class: &'a str) -> impl Iterator<Item = &'a AdObject> {
        self.objects.iter().filter(move |o| o.has_class(class))
    }

    /// Resolve a domain RID to its object (e.g. krbtgt = 502) via objectSid.
    pub fn by_rid(&self, rid: u32) -> Option<&AdObject> {
        let dsid = self.domain.domain_sid.as_ref()?;
        self.objects.iter().find(|o| {
            o.bin1("objectSid")
                .and_then(Sid::from_bytes)
                .map(|s| {
                    s.rid() == Some(rid)
                        && s.sub_authorities[..s.sub_authorities.len() - 1]
                            == dsid.sub_authorities[..]
                })
                .unwrap_or(false)
        })
    }
}

#[cfg(test)]
mod wpt_tests {
    use super::*;

    #[test]
    fn snapshot_records_search_and_returns_wire_for_dn() {
        let mut snap = Snapshot::new(DomainInfo::default(), vec![]);
        let idx = snap.record_search(SearchOp {
            base_dn: "DC=corp,DC=local".into(),
            filter: "(objectClass=user)".into(),
            attrs: vec!["userAccountControl".into(), "sAMAccountName".into()],
            returned_count: 42,
            scope: "sub".into(),
        });
        assert_eq!(idx, 0);
        snap.link_dn_to_search("CN=bob,DC=corp,DC=local", idx);
        let ex = snap.wire_for_dn("cn=bob,dc=corp,dc=local"); // case-insensitive
        assert_eq!(ex.len(), 2, "wire_for_dn should render (Sent, Recv) pair");
        assert!(ex[0].summary.contains("(objectClass=user)"));
        assert!(ex[1].summary.contains("42 entries"));
    }

    #[test]
    fn wire_for_dn_returns_empty_when_uninstrumented() {
        // Legacy path — collector hasn't recorded searches yet, checks still see no wire proof.
        let snap = Snapshot::new(DomainInfo::default(), vec![]);
        assert!(snap.wire_for_dn("CN=any").is_empty());
        assert!(snap.searches().is_empty());
    }

    #[test]
    fn link_dn_to_search_is_first_write_wins() {
        let mut snap = Snapshot::new(DomainInfo::default(), vec![]);
        let a = snap.record_search(SearchOp {
            filter: "first".into(),
            ..Default::default()
        });
        let b = snap.record_search(SearchOp {
            filter: "second".into(),
            ..Default::default()
        });
        snap.link_dn_to_search("CN=x", a);
        snap.link_dn_to_search("CN=x", b); // ignored
        let ex = snap.wire_for_dn("CN=x");
        assert!(ex[0].summary.contains("first"), "first-write should win");
        // b still exists in the searches log — nothing is dropped.
        assert_eq!(snap.searches().len(), 2);
    }

    #[test]
    fn searchop_attrs_hint_truncates_for_readability() {
        let op = SearchOp {
            base_dn: "DC=x".into(),
            filter: "(a)".into(),
            attrs: (0..10).map(|i| format!("attr{i}")).collect(),
            returned_count: 1,
            scope: "sub".into(),
        };
        let sent = &op.as_exchange()[0];
        assert!(
            sent.summary.contains("+7"),
            "expected '+7' overflow marker in attrs hint: {}",
            sent.summary
        );
    }
}
