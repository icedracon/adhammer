//! Self-rolled parser for the *self-relative* SECURITY_DESCRIPTOR blob stored in
//! `nTSecurityDescriptor` (MS-DTYP §2.4.6). No Windows FFI — works cross-platform
//! against raw LDAP bytes. This is what feeds the ESC checks and the control-path graph.

use adhammer_core::sid::{Guid, Sid};
use bitflags::bitflags;

pub mod rights;

/// Serialize a SID to its binary (objectSid) form.
pub fn sid_to_bytes(sid: &Sid) -> Vec<u8> {
    let mut b = vec![sid.revision, sid.sub_authorities.len() as u8];
    let a = sid.identifier_authority;
    b.extend_from_slice(&[(a >> 40) as u8, (a >> 32) as u8, (a >> 24) as u8, (a >> 16) as u8, (a >> 8) as u8, a as u8]);
    for s in &sid.sub_authorities {
        b.extend_from_slice(&s.to_le_bytes());
    }
    b
}

/// Build the `msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor granting
/// `trustee` control — the RBCD attack primitive. Self-relative SD, one allow ACE.
pub fn build_rbcd_sd(trustee: &Sid) -> Vec<u8> {
    let sidb = sid_to_bytes(trustee);

    // ACCESS_ALLOWED_ACE: type 0, flags 0, size, mask=GENERIC_ALL, sid
    let ace_size = (4 + 4 + sidb.len()) as u16;
    let mut ace = vec![0x00u8, 0x00];
    ace.extend_from_slice(&ace_size.to_le_bytes());
    ace.extend_from_slice(&0x1000_0000u32.to_le_bytes()); // GENERIC_ALL
    ace.extend_from_slice(&sidb);

    // ACL: revision 2, size, ace_count 1
    let dacl_size = (8 + ace.len()) as u16;
    let mut dacl = vec![0x02u8, 0x00];
    dacl.extend_from_slice(&dacl_size.to_le_bytes());
    dacl.extend_from_slice(&1u16.to_le_bytes());
    dacl.extend_from_slice(&0u16.to_le_bytes());
    dacl.extend_from_slice(&ace);

    // self-relative SD: owner = group = trustee, DACL present
    let owner_off = 20u32;
    let group_off = 20 + sidb.len() as u32;
    let dacl_off = group_off + sidb.len() as u32;
    let mut sd = vec![1u8, 0];
    sd.extend_from_slice(&0x8004u16.to_le_bytes()); // SE_SELF_RELATIVE | SE_DACL_PRESENT
    sd.extend_from_slice(&owner_off.to_le_bytes());
    sd.extend_from_slice(&group_off.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes()); // SACL offset
    sd.extend_from_slice(&dacl_off.to_le_bytes());
    sd.extend_from_slice(&sidb); // owner
    sd.extend_from_slice(&sidb); // group
    sd.extend_from_slice(&dacl);
    sd
}

#[cfg(test)]
mod build_tests {
    use super::*;

    #[test]
    fn rbcd_sd_roundtrips_through_parser() {
        let sid = Sid::parse("S-1-5-21-1-2-3-1104").unwrap();
        let sd = build_rbcd_sd(&sid);
        let parsed = parse(&sd).expect("parse our own SD");
        let aces = &parsed.dacl.expect("dacl").aces;
        assert_eq!(aces.len(), 1);
        assert!(aces[0].is_allow());
        assert_eq!(aces[0].trustee, sid);
        assert!(aces[0].mask.contains(AccessMask::GENERIC_ALL));
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SddlError {
    #[error("buffer too short at {0}")]
    Truncated(&'static str),
    #[error("bad ACE sid")]
    BadSid,
}

type Result<T> = std::result::Result<T, SddlError>;

bitflags! {
    /// ACCESS_MASK bits relevant to AD control paths (MS-DTYP §2.4.3 + AD extended).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AccessMask: u32 {
        const CREATE_CHILD    = 0x0000_0001;
        const DELETE_CHILD    = 0x0000_0002;
        const SELF           = 0x0000_0008; // validated write
        const WRITE_PROP      = 0x0000_0020; // write property (scoped by object GUID)
        const CONTROL_ACCESS  = 0x0000_0100; // extended right (scoped by object GUID)
        const DELETE          = 0x0001_0000;
        const WRITE_DAC       = 0x0004_0000;
        const WRITE_OWNER     = 0x0008_0000;
        const GENERIC_ALL     = 0x1000_0000;
        const GENERIC_WRITE   = 0x4000_0000;
    }
}

/// ACE header type byte (MS-DTYP §2.4.4). We only care about the allow/deny + object variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AceType {
    AccessAllowed,
    AccessDenied,
    AccessAllowedObject,
    AccessDeniedObject,
    Other(u8),
}

#[derive(Clone, Debug)]
pub struct Ace {
    pub ace_type: AceType,
    pub flags: u8,
    pub mask: AccessMask,
    pub trustee: Sid,
    /// Present for *object* ACEs: which property-set / extended-right / child-class this grants.
    pub object_type: Option<Guid>,
    pub inherited_object_type: Option<Guid>,
}

impl Ace {
    pub fn is_allow(&self) -> bool {
        matches!(self.ace_type, AceType::AccessAllowed | AceType::AccessAllowedObject)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Acl {
    pub aces: Vec<Ace>,
}

#[derive(Clone, Debug, Default)]
pub struct SecurityDescriptor {
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub dacl: Option<Acl>,
}

fn u16le(b: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(b.get(o..o + 2).ok_or(SddlError::Truncated("u16"))?.try_into().unwrap()))
}
fn u32le(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(b.get(o..o + 4).ok_or(SddlError::Truncated("u32"))?.try_into().unwrap()))
}
fn sid_at(b: &[u8], o: usize) -> Result<Sid> {
    let count = *b.get(o + 1).ok_or(SddlError::Truncated("sid"))? as usize;
    let end = o + 8 + count * 4;
    Sid::from_bytes(b.get(o..end).ok_or(SddlError::Truncated("sid"))?).ok_or(SddlError::BadSid)
}

/// Parse a self-relative SECURITY_DESCRIPTOR. Offsets are from the start of `b`.
pub fn parse(b: &[u8]) -> Result<SecurityDescriptor> {
    if b.len() < 20 {
        return Err(SddlError::Truncated("sd header"));
    }
    let owner_off = u32le(b, 4)? as usize;
    let group_off = u32le(b, 8)? as usize;
    let dacl_off = u32le(b, 16)? as usize;

    let owner = (owner_off != 0).then(|| sid_at(b, owner_off)).transpose()?;
    let group = (group_off != 0).then(|| sid_at(b, group_off)).transpose()?;
    let dacl = (dacl_off != 0).then(|| parse_acl(b, dacl_off)).transpose()?;

    Ok(SecurityDescriptor { owner, group, dacl })
}

fn parse_acl(b: &[u8], off: usize) -> Result<Acl> {
    // ACL header: Revision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)
    let ace_count = u16le(b, off + 4)? as usize;
    let mut cur = off + 8;
    let mut aces = Vec::with_capacity(ace_count);
    for _ in 0..ace_count {
        let ace_type_byte = *b.get(cur).ok_or(SddlError::Truncated("ace type"))?;
        let flags = b[cur + 1];
        let size = u16le(b, cur + 2)? as usize;
        let ace_type = match ace_type_byte {
            0x00 => AceType::AccessAllowed,
            0x01 => AceType::AccessDenied,
            0x05 => AceType::AccessAllowedObject,
            0x06 => AceType::AccessDeniedObject,
            x => AceType::Other(x),
        };
        let mask = AccessMask::from_bits_truncate(u32le(b, cur + 4)?);

        let (object_type, inherited_object_type, sid_off) = match ace_type {
            AceType::AccessAllowedObject | AceType::AccessDeniedObject => {
                // Mask(4) Flags(4) [ObjectType 16] [InheritedObjectType 16] Sid
                let obj_flags = u32le(b, cur + 8)?;
                let mut p = cur + 12;
                let mut ot = None;
                let mut iot = None;
                if obj_flags & 0x1 != 0 {
                    ot = Guid::from_bytes(&b[p..p + 16]);
                    p += 16;
                }
                if obj_flags & 0x2 != 0 {
                    iot = Guid::from_bytes(&b[p..p + 16]);
                    p += 16;
                }
                (ot, iot, p)
            }
            _ => (None, None, cur + 8),
        };

        let trustee = sid_at(b, sid_off)?;
        aces.push(Ace { ace_type, flags, mask, trustee, object_type, inherited_object_type });
        if size == 0 {
            break;
        }
        cur += size;
    }
    Ok(Acl { aces })
}
