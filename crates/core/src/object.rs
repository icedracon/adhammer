//! A generic collected directory object: DN + multi-valued string attributes,
//! plus the raw binary blobs we need to parse ourselves (objectSid, nTSecurityDescriptor).

use std::collections::HashMap;

/// userAccountControl bit flags (subset we act on).
pub mod uac {
    pub const ACCOUNTDISABLE: u32 = 0x0002;
    pub const HOMEDIR_REQUIRED: u32 = 0x0008;
    pub const PASSWD_NOTREQD: u32 = 0x0020;
    pub const NORMAL_ACCOUNT: u32 = 0x0200;
    pub const DONT_EXPIRE_PASSWORD: u32 = 0x0001_0000;
    pub const TRUSTED_FOR_DELEGATION: u32 = 0x0008_0000; // unconstrained delegation
    pub const NOT_DELEGATED: u32 = 0x0010_0000; // "sensitive, cannot be delegated"
    pub const USE_DES_KEY_ONLY: u32 = 0x0020_0000;
    pub const DONT_REQ_PREAUTH: u32 = 0x0040_0000; // AS-REP roastable
    pub const TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x0100_0000; // constrained w/ protocol transition
    pub const USE_AES: u32 = 0; // placeholder; AES lives in msDS-SupportedEncryptionTypes
}

#[derive(Clone, Debug, Default)]
pub struct AdObject {
    pub dn: String,
    pub attrs: HashMap<String, Vec<String>>,
    /// Raw binary attributes (objectSid, nTSecurityDescriptor, objectGUID, ...).
    pub bin: HashMap<String, Vec<Vec<u8>>>,
}

impl AdObject {
    pub fn one(&self, attr: &str) -> Option<&str> {
        self.attrs
            .get(attr)
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    pub fn all(&self, attr: &str) -> &[String] {
        self.attrs.get(attr).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn int(&self, attr: &str) -> Option<i64> {
        self.one(attr).and_then(|s| s.parse().ok())
    }

    /// Like [`Self::int`] but distinguishes an absent attribute from one present-but-unparseable
    /// and lets the caller pick a per-domain worst-case for the latter.
    ///
    /// - Absent (schema-legitimate default)                → `absent`.
    /// - Present, parses cleanly                           → the parsed value.
    /// - Present, does not parse (corrupt LDAP / hostile   → `unparseable`.
    ///   snapshot / future schema mismatch)
    ///
    /// Security-relevant callers (audit finding C1) MUST NOT collapse both non-Ok cases with a
    /// single `.int().unwrap_or(0)` — that biases toward "not vulnerable" on unreadable input
    /// and silently suppresses findings. Pick `unparseable` as the worst-case that keeps the
    /// gate active (e.g. all bits set for a bit-flag attribute).
    pub fn int_or_worst(&self, attr: &str, absent: i64, unparseable: i64) -> i64 {
        match self.one(attr) {
            None => absent,
            Some(s) => s.parse::<i64>().unwrap_or(unparseable),
        }
    }

    pub fn bin1(&self, attr: &str) -> Option<&[u8]> {
        self.bin
            .get(attr)
            .and_then(|v| v.first())
            .map(Vec::as_slice)
    }

    /// All values of a multi-valued binary attribute (e.g. sIDHistory).
    pub fn bin_all(&self, attr: &str) -> &[Vec<u8>] {
        self.bin.get(attr).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn uac(&self) -> u32 {
        self.int("userAccountControl").unwrap_or(0) as u32
    }

    pub fn has_class(&self, class: &str) -> bool {
        self.all("objectClass")
            .iter()
            .any(|c| c.eq_ignore_ascii_case(class))
    }

    /// FILETIME attribute (pwdLastSet, lastLogonTimestamp) as raw 100ns ticks since 1601.
    pub fn filetime(&self, attr: &str) -> Option<i64> {
        self.int(attr)
    }
}
