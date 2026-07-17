//! SID / GUID parsing per MS-DTYP. No FFI — pure binary + string handling.

use std::fmt;

/// Windows Security Identifier. Stored canonically; `Display` yields `S-1-5-...`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    pub revision: u8,
    pub identifier_authority: u64, // 6 bytes, big-endian in the wire format
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Parse the binary (SID_AND_ATTRIBUTES / objectSid) representation.
    pub fn from_bytes(b: &[u8]) -> Option<Sid> {
        if b.len() < 8 {
            return None;
        }
        let revision = b[0];
        let count = b[1] as usize;
        let mut authority: u64 = 0;
        for &byte in &b[2..8] {
            authority = (authority << 8) | byte as u64; // big-endian
        }
        if b.len() < 8 + count * 4 {
            return None;
        }
        let mut subs = Vec::with_capacity(count);
        for i in 0..count {
            let off = 8 + i * 4;
            subs.push(u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]));
        }
        Some(Sid { revision, identifier_authority: authority, sub_authorities: subs })
    }

    /// Parse the string form `S-1-5-21-...-513`.
    pub fn parse(s: &str) -> Option<Sid> {
        let mut it = s.split('-');
        if it.next()? != "S" {
            return None;
        }
        let revision = it.next()?.parse().ok()?;
        let identifier_authority = it.next()?.parse().ok()?;
        let sub_authorities = it.map(|p| p.parse().ok()).collect::<Option<Vec<u32>>>()?;
        Some(Sid { revision, identifier_authority, sub_authorities })
    }

    /// Last sub-authority — the RID.
    pub fn rid(&self) -> Option<u32> {
        self.sub_authorities.last().copied()
    }

    /// True for the built-in / well-known SIDs that are never domain-specific
    /// (S-1-5-32-544 etc.). Used to skip noise when scoring ACLs.
    pub fn is_well_known(&self) -> bool {
        matches!(self.identifier_authority, 1 | 3) // WORLD, CREATOR
            || (self.identifier_authority == 5 && self.sub_authorities.first() == Some(&32))
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-{}-{}", self.revision, self.identifier_authority)?;
        for s in &self.sub_authorities {
            write!(f, "-{s}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// Well-known RIDs (relative to the domain SID unless noted).
pub mod rid {
    pub const ADMINISTRATOR: u32 = 500;
    pub const GUEST: u32 = 501;
    pub const KRBTGT: u32 = 502;
    pub const DOMAIN_ADMINS: u32 = 512;
    pub const DOMAIN_CONTROLLERS: u32 = 516;
    pub const SCHEMA_ADMINS: u32 = 518;
    pub const ENTERPRISE_ADMINS: u32 = 519;
    pub const ADMINISTRATORS_BUILTIN: u32 = 544; // under S-1-5-32
}

/// 16-byte GUID, stored in the mixed-endian on-wire layout already normalized
/// to a comparable byte array. Rendered `{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub fn from_bytes(b: &[u8]) -> Option<Guid> {
        Some(Guid(b.get(..16)?.try_into().ok()?))
    }

    /// Parse `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (braces optional).
    pub fn parse(s: &str) -> Option<Guid> {
        let s = s.trim_matches(|c| c == '{' || c == '}');
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 {
            return None;
        }
        let raw: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
            .collect::<Option<_>>()?;
        // string form is big-endian for first 3 groups; store as-is for compare.
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);
        b[4..6].copy_from_slice(&[raw[5], raw[4]]);
        b[6..8].copy_from_slice(&[raw[7], raw[6]]);
        b[8..16].copy_from_slice(&raw[8..16]);
        Some(Guid(b))
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}
