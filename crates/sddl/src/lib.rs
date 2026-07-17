//! Self-rolled parser for the *self-relative* SECURITY_DESCRIPTOR blob stored in
//! `nTSecurityDescriptor` (MS-DTYP §2.4.6). No Windows FFI — works cross-platform
//! against raw LDAP bytes. This is what feeds the ESC checks and the control-path graph.

use adhammer_core::sid::{Guid, Sid};
use bitflags::bitflags;

pub mod rights;

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
