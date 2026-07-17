//! Shared check helpers.

use adhammer_core::sid::Sid;

/// Broad, low-privilege principals whose grant on an object turns it into a vuln:
/// Everyone, Authenticated Users, BUILTIN\Users, Domain Users/Guests/Computers.
pub fn is_broad(sid: &Sid, domain_sid: Option<&Sid>) -> bool {
    // Everyone  S-1-1-0
    if sid.identifier_authority == 1 && sid.sub_authorities == [0] {
        return true;
    }
    if sid.identifier_authority == 5 {
        // Authenticated Users  S-1-5-11
        if sid.sub_authorities == [11] {
            return true;
        }
        // BUILTIN\Users  S-1-5-32-545
        if sid.sub_authorities == [32, 545] {
            return true;
        }
    }
    // Domain Users (513) / Domain Guests (514) / Domain Computers (515), this domain.
    if let (Some(d), Some(rid)) = (domain_sid, sid.rid()) {
        if matches!(rid, 513 | 514 | 515) {
            let prefix = &sid.sub_authorities[..sid.sub_authorities.len().saturating_sub(1)];
            if prefix == d.sub_authorities.as_slice() {
                return true;
            }
        }
    }
    false
}

/// A domain-relative SID: `domain_sid` with `rid` appended.
pub fn domain_sid_with_rid(domain_sid: &Sid, rid: u32) -> Sid {
    let mut subs = domain_sid.sub_authorities.clone();
    subs.push(rid);
    Sid { revision: domain_sid.revision, identifier_authority: domain_sid.identifier_authority, sub_authorities: subs }
}

/// A BUILTIN alias SID: S-1-5-32-`rid` (Administrators 544, Account/Backup/Print Operators…).
pub fn builtin_sid(rid: u32) -> Sid {
    Sid { revision: 1, identifier_authority: 5, sub_authorities: vec![32, rid] }
}
