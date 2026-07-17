//! An immutable point-in-time capture of the directory. Checks and the graph
//! builder read this; the collector produces it. Keeps a few precomputed indices.

use crate::object::AdObject;
use crate::sid::Sid;
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct DomainInfo {
    pub domain_dn: String,        // DC=corp,DC=local
    pub domain_sid: Option<Sid>,
    pub netbios: Option<String>,
    pub functional_level: Option<i64>,
    pub machine_account_quota: Option<i64>,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub domain: DomainInfo,
    pub objects: Vec<AdObject>,
    /// dn (lowercased) -> index into `objects`, for O(1) resolution while walking ACLs.
    dn_index: HashMap<String, usize>,
}

impl Snapshot {
    pub fn new(domain: DomainInfo, objects: Vec<AdObject>) -> Self {
        let dn_index = objects
            .iter()
            .enumerate()
            .map(|(i, o)| (o.dn.to_ascii_lowercase(), i))
            .collect();
        Snapshot { domain, objects, dn_index }
    }

    pub fn by_dn(&self, dn: &str) -> Option<&AdObject> {
        self.dn_index.get(&dn.to_ascii_lowercase()).map(|&i| &self.objects[i])
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
        self.objects.iter().find(|o| o.one("sAMAccountName").map_or(false, |s| s.eq_ignore_ascii_case(sam)))
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
                .map(|s| s.rid() == Some(rid) && s.sub_authorities[..s.sub_authorities.len() - 1] == dsid.sub_authorities[..])
                .unwrap_or(false)
        })
    }
}
