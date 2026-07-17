//! AD control-access-right / property-set GUIDs. When an object ACE carries one of
//! these in `object_type`, a generic-looking mask becomes a concrete attack primitive.

use adhammer_core::sid::Guid;

/// Extended-right GUID, lazily parsed from the canonical string.
pub struct Right {
    pub name: &'static str,
    guid: &'static str,
}

impl Right {
    pub const fn new(name: &'static str, guid: &'static str) -> Self {
        Right { name, guid }
    }
    pub fn guid(&self) -> Guid {
        Guid::parse(self.guid).expect("static right GUID is valid")
    }
    pub fn matches(&self, g: &Guid) -> bool {
        self.guid() == *g
    }
}

// DS-Replication-Get-Changes + Get-Changes-All ⇒ DCSync.
pub const REPL_GET_CHANGES: Right =
    Right::new("DS-Replication-Get-Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
pub const REPL_GET_CHANGES_ALL: Right =
    Right::new("DS-Replication-Get-Changes-All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");

// User-Force-Change-Password ⇒ takeover without knowing current password.
pub const FORCE_CHANGE_PASSWORD: Right =
    Right::new("User-Force-Change-Password", "00299570-246d-11d0-a768-00aa006e0529");

// Write msDS-KeyCredentialLink ⇒ Shadow Credentials.
pub const KEY_CREDENTIAL_LINK: Right =
    Right::new("msDS-KeyCredentialLink", "5b47d60f-6090-40b2-9f37-2a4de88f3063");

// Write member ⇒ AddMember to a group.
pub const MEMBER_ATTR: Right = Right::new("member", "bf9679c0-0de6-11d0-a285-00aa003049e2");

// Write msDS-AllowedToActOnBehalfOfOtherIdentity ⇒ RBCD.
pub const RBCD_ATTR: Right =
    Right::new("msDS-AllowedToActOnBehalfOfOtherIdentity", "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79");

// AD CS enrollment control-access rights on a certificate template.
// Presence for a low-priv principal = "can request a cert from this template".
pub const ENROLLMENT: Right =
    Right::new("Certificate-Enrollment", "0e10c968-78fb-11d2-90d4-00c04f79dc55");
pub const AUTO_ENROLLMENT: Right =
    Right::new("Certificate-AutoEnrollment", "a05b8cc2-17bc-4802-a710-e7c15ab866a2");

/// True if the GUID grants certificate enrollment (manual or auto).
pub fn is_enrollment_right(g: &Guid) -> bool {
    ENROLLMENT.matches(g) || AUTO_ENROLLMENT.matches(g)
}

/// The two GUIDs whose *combination* on the domain head equals DCSync.
pub fn is_dcsync_right(g: &Guid) -> bool {
    REPL_GET_CHANGES.matches(g) || REPL_GET_CHANGES_ALL.matches(g)
}
