//! NDR (Network Data Representation) marshaling — DCE/RPC Transfer Syntax, little-endian.
//!
//! Implements the pieces the SAMR/LSAT/EPM calls need: aligned primitives, conformant &
//! varying arrays, unique (referent) pointers, and conformant-varying UTF-16 strings
//! (the `RPC_UNICODE_STRING` payload shape).

use crate::{Result, RpcError};

/// Serializer. Alignment is relative to the start of the stub buffer.
#[derive(Default)]
pub struct NdrEncoder {
    buf: Vec<u8>,
    next_referent: u32,
}

impl NdrEncoder {
    pub fn new() -> Self {
        NdrEncoder { buf: Vec::new(), next_referent: 0x0002_0000 }
    }

    fn align(&mut self, a: usize) {
        while self.buf.len() % a != 0 {
            self.buf.push(0);
        }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    /// A UUID / GUID field (DCE wire layout, 16 bytes, aligned to 4).
    pub fn uuid(&mut self, b: &[u8; 16]) {
        self.align(4);
        self.buf.extend_from_slice(b);
    }

    /// A non-null unique pointer: emit a fresh referent id. Caller emits the pointee next.
    pub fn referent(&mut self) -> u32 {
        let id = self.next_referent;
        self.next_referent += 4;
        self.u32(id);
        id
    }
    pub fn null_ptr(&mut self) {
        self.u32(0);
    }

    /// A conformant+varying wide string: max_count, offset(0), actual_count, then UTF-16LE
    /// including the terminating NUL. Matches the `[size_is][length_is]` wchar payload.
    pub fn conformant_varying_wstr(&mut self, s: &str) {
        let mut units: Vec<u16> = s.encode_utf16().collect();
        units.push(0);
        let n = units.len() as u32;
        self.u32(n); // max_count
        self.u32(0); // offset
        self.u32(n); // actual_count
        for u in units {
            self.u16(u);
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Deserializer over a stub buffer.
pub struct NdrDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> NdrDecoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        NdrDecoder { buf, pos: 0 }
    }

    fn align(&mut self, a: usize) {
        while self.pos % a != 0 {
            self.pos += 1;
        }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos + n;
        if end > self.buf.len() {
            return Err(RpcError::Underrun { need: n, pos: self.pos });
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        self.align(2);
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32> {
        self.align(4);
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64> {
        self.align(8);
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn uuid(&mut self) -> Result<[u8; 16]> {
        self.align(4);
        Ok(self.take(16)?.try_into().unwrap())
    }

    /// Read a conformant+varying wide string; returns it without the trailing NUL.
    pub fn conformant_varying_wstr(&mut self) -> Result<String> {
        let _max = self.u32()?;
        let _offset = self.u32()?;
        let actual = self.u32()? as usize;
        let mut units = Vec::with_capacity(actual);
        for _ in 0..actual {
            units.push(self.u16()?);
        }
        while units.last() == Some(&0) {
            units.pop();
        }
        Ok(String::from_utf16_lossy(&units))
    }

    /// Read `n` raw bytes with no alignment (e.g. a fixed context handle or tower blob).
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn position(&self) -> usize {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_alignment() {
        let mut e = NdrEncoder::new();
        e.u8(0x01);
        e.u32(0xAABB_CCDD); // must align to 4 → 3 pad bytes
        assert_eq!(e.into_bytes(), vec![0x01, 0, 0, 0, 0xDD, 0xCC, 0xBB, 0xAA]);
    }

    #[test]
    fn wstr_roundtrip() {
        let mut e = NdrEncoder::new();
        e.conformant_varying_wstr("ADHAMMER");
        let bytes = e.into_bytes();
        // max/offset/actual each 4 bytes = 12, then 9 u16 (8 chars + NUL) = 18 → 30 bytes.
        assert_eq!(bytes.len(), 30);
        let mut d = NdrDecoder::new(&bytes);
        assert_eq!(d.conformant_varying_wstr().unwrap(), "ADHAMMER");
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn referent_ids_are_nonzero_and_advance() {
        let mut e = NdrEncoder::new();
        let a = e.referent();
        let b = e.referent();
        assert_ne!(a, 0);
        assert_eq!(b, a + 4);
    }
}
