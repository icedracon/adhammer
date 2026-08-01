//! Minimal Windows registry hive (`regf`) reader — enough to navigate keys by path and read
//! their values and class names, which is all the SAM/SYSTEM offline dump needs. Handles the
//! `lf`/`lh`/`li`/`ri` subkey-list cell types and inline / single-cell value data. Big-data
//! (`db`, values > 16344 bytes split across blocks) is not needed for SAM/SYSTEM and is not
//! implemented.

/// A parsed hive: the raw bytes plus the offset of the root key cell.
pub struct Hive {
    data: Vec<u8>,
    root: u32,
}

const BASE: usize = 0x1000; // hbin data starts 4 KiB in; all cell offsets are relative to here.

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

impl Hive {
    pub fn parse(data: Vec<u8>) -> Option<Hive> {
        if data.len() < BASE || &data[0..4] != b"regf" {
            return None;
        }
        let root = le32(&data, 0x24); // root cell offset in the base block header
        Some(Hive { data, root })
    }

    /// The bytes of the cell at `rel` (offset relative to the first hbin), minus the 4-byte size.
    fn cell(&self, rel: u32) -> Option<&[u8]> {
        let start = BASE + rel as usize;
        if start + 4 > self.data.len() {
            return None;
        }
        let raw = le32(&self.data, start) as i32;
        let size = raw.unsigned_abs() as usize; // negative = allocated
        if size < 4 || start + size > self.data.len() {
            return None;
        }
        Some(&self.data[start + 4..start + size])
    }

    fn root_cell(&self) -> Option<&[u8]> {
        self.cell(self.root)
    }

    /// Resolve a backslash-separated key path from the root; returns the nk cell offset.
    fn find_key(&self, path: &str) -> Option<u32> {
        let mut cur = self.root;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            cur = self.subkey(cur, part)?;
        }
        Some(cur)
    }

    /// Offset of the named direct subkey of the nk at `nk_off` (case-insensitive).
    fn subkey(&self, nk_off: u32, name: &str) -> Option<u32> {
        let nk = self.cell(nk_off)?;
        if nk.len() < 0x50 || &nk[0..2] != b"nk" {
            return None;
        }
        let count = le32(nk, 0x14);
        let list_off = le32(nk, 0x1c);
        if count == 0 || list_off == 0xffff_ffff {
            return None;
        }
        for off in self.subkey_offsets(list_off) {
            if let Some(kn) = self.key_name(off) {
                if kn.eq_ignore_ascii_case(name) {
                    return Some(off);
                }
            }
        }
        None
    }

    /// All subkey nk offsets referenced by a subkey-list cell (lf/lh/li/ri).
    fn subkey_offsets(&self, list_off: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let Some(cell) = self.cell(list_off) else {
            return out;
        };
        if cell.len() < 4 {
            return out;
        }
        let sig = &cell[0..2];
        let count = le16(cell, 2) as usize;
        match sig {
            b"lf" | b"lh" => {
                // pairs of (key offset, name hint) — 8 bytes each.
                for i in 0..count {
                    let base = 4 + i * 8;
                    if base + 4 <= cell.len() {
                        out.push(le32(cell, base));
                    }
                }
            }
            b"li" => {
                for i in 0..count {
                    let base = 4 + i * 4;
                    if base + 4 <= cell.len() {
                        out.push(le32(cell, base));
                    }
                }
            }
            b"ri" => {
                // list of sublists — recurse.
                for i in 0..count {
                    let base = 4 + i * 4;
                    if base + 4 <= cell.len() {
                        out.extend(self.subkey_offsets(le32(cell, base)));
                    }
                }
            }
            _ => {}
        }
        out
    }

    fn key_name(&self, nk_off: u32) -> Option<String> {
        let nk = self.cell(nk_off)?;
        if nk.len() < 0x50 || &nk[0..2] != b"nk" {
            return None;
        }
        let flags = le16(nk, 0x02);
        let name_len = le16(nk, 0x48) as usize;
        let name = nk.get(0x4c..0x4c + name_len)?;
        Some(decode_name(name, flags & 0x20 != 0))
    }

    /// Names of all direct subkeys of a key path (for enumerating SAM users).
    pub fn subkey_names(&self, path: &str) -> Vec<String> {
        let Some(nk_off) = self.find_key(path) else {
            return vec![];
        };
        let Some(nk) = self.cell(nk_off) else {
            return vec![];
        };
        if nk.len() < 0x50 {
            return vec![];
        }
        let list_off = le32(nk, 0x1c);
        if list_off == 0xffff_ffff {
            return vec![];
        }
        self.subkey_offsets(list_off)
            .into_iter()
            .filter_map(|o| self.key_name(o))
            .collect()
    }

    /// The class-name bytes (raw UTF-16LE) of a key — the SYSTEM\...\Lsa bootkey pieces live here.
    pub fn key_class(&self, path: &str) -> Option<Vec<u8>> {
        let nk_off = self.find_key(path)?;
        let nk = self.cell(nk_off)?;
        if nk.len() < 0x50 {
            return None;
        }
        let class_off = le32(nk, 0x30);
        let class_len = le16(nk, 0x4a) as usize;
        if class_off == 0xffff_ffff || class_len == 0 {
            return None;
        }
        let cell = self.cell(class_off)?;
        cell.get(0..class_len).map(|s| s.to_vec())
    }

    /// The raw data of a named value under a key path.
    pub fn value(&self, path: &str, name: &str) -> Option<Vec<u8>> {
        let nk_off = self.find_key(path)?;
        let nk = self.cell(nk_off)?;
        if nk.len() < 0x50 {
            return None;
        }
        let vcount = le32(nk, 0x24) as usize;
        let vlist_off = le32(nk, 0x28);
        if vcount == 0 || vlist_off == 0xffff_ffff {
            return None;
        }
        let vlist = self.cell(vlist_off)?;
        for i in 0..vcount {
            let base = i * 4;
            if base + 4 > vlist.len() {
                break;
            }
            let vk_off = le32(vlist, base);
            let Some(vk) = self.cell(vk_off) else {
                continue;
            };
            if vk.len() < 0x14 || &vk[0..2] != b"vk" {
                continue;
            }
            let name_len = le16(vk, 0x02) as usize;
            let flags = le16(vk, 0x10);
            let vname = if name_len == 0 {
                String::new()
            } else {
                decode_name(vk.get(0x14..0x14 + name_len)?, flags & 0x1 != 0)
            };
            if !vname.eq_ignore_ascii_case(name) {
                continue;
            }
            let data_len_raw = le32(vk, 0x04);
            let data_off = le32(vk, 0x08);
            let inline = data_len_raw & 0x8000_0000 != 0;
            let data_len = (data_len_raw & 0x7fff_ffff) as usize;
            if inline {
                // data stored in the offset field itself (≤ 4 bytes).
                return Some(vk[0x08..0x08 + data_len.min(4)].to_vec());
            }
            // Values > 16344 bytes use "db" big-data indirection (data split across blocks). We
            // don't reassemble those, so return None rather than risk handing back the indirection
            // cell's raw bytes as if they were the value (silent garbage → wrong decryption).
            if data_len > 16344 {
                return None;
            }
            let cell = self.cell(data_off)?;
            return cell.get(0..data_len).map(|s| s.to_vec());
        }
        None
    }

    /// Names of all values under a key path (e.g. the `NL$n` cached-logon entries under `Cache`).
    pub fn value_names(&self, path: &str) -> Vec<String> {
        let Some(nk_off) = self.find_key(path) else {
            return vec![];
        };
        let Some(nk) = self.cell(nk_off) else {
            return vec![];
        };
        if nk.len() < 0x50 {
            return vec![];
        }
        let vcount = le32(nk, 0x24) as usize;
        let vlist_off = le32(nk, 0x28);
        if vcount == 0 || vlist_off == 0xffff_ffff {
            return vec![];
        }
        let Some(vlist) = self.cell(vlist_off) else {
            return vec![];
        };
        let mut out = Vec::new();
        for i in 0..vcount {
            let base = i * 4;
            if base + 4 > vlist.len() {
                break;
            }
            let Some(vk) = self.cell(le32(vlist, base)) else {
                continue;
            };
            if vk.len() < 0x14 || &vk[0..2] != b"vk" {
                continue;
            }
            let name_len = le16(vk, 0x02) as usize;
            let flags = le16(vk, 0x10);
            if name_len == 0 {
                out.push(String::new());
            } else if let Some(nm) = vk.get(0x14..0x14 + name_len) {
                out.push(decode_name(nm, flags & 0x1 != 0));
            }
        }
        out
    }

    /// Convenience: a REG_DWORD value as u32.
    pub fn value_u32(&self, path: &str, name: &str) -> Option<u32> {
        let v = self.value(path, name)?;
        (v.len() >= 4).then(|| le32(&v, 0))
    }

    pub fn is_valid(&self) -> bool {
        self.root_cell()
            .map(|c| c.starts_with(b"nk"))
            .unwrap_or(false)
    }
}

/// Key/value names are ASCII (Latin-1) when the compressed-name flag is set, else UTF-16LE.
fn decode_name(bytes: &[u8], ascii: bool) -> String {
    if ascii {
        bytes.iter().map(|&b| b as char).collect()
    } else {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;

    /// Fuzz-lite: a `regf`-prefixed buffer with random contents + a random root offset, then a
    /// full navigation pass. The hive is retrieved from a target, so a corrupt/hostile one must
    /// never panic the parser (all cell reads are bounds-checked).
    #[test]
    fn fuzz_parse_and_navigate_never_panics() {
        let mut s: u64 = 0x0123_4567_89AB_CDEF;
        let mut rng = || {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut fail = None;
        for _ in 0..80_000 {
            let len = 0x1000 + 1 + (rng() as usize % 0x1000);
            let mut buf = vec![0u8; len];
            buf[0..4].copy_from_slice(b"regf");
            // random root offset (often out of range) + scattered random bytes in the hbin area.
            buf[0x24..0x28].copy_from_slice(&(rng() as u32).to_le_bytes());
            for _ in 0..(rng() as usize % 400) {
                let i = 0x1000 + (rng() as usize % (len - 0x1000));
                buf[i] = rng() as u8;
            }
            let res = std::panic::catch_unwind(|| {
                if let Some(h) = Hive::parse(buf.clone()) {
                    let _ = h.is_valid();
                    let _ = h.subkey_names("SAM\\Domains\\Account\\Users");
                    let _ = h.value("SAM\\Domains\\Account", "F");
                    let _ = h.key_class("ControlSet001\\Control\\Lsa\\JD");
                    let _ = h.value_u32("Select", "Current");
                }
            });
            if res.is_err() {
                fail = Some(buf);
                break;
            }
        }
        std::panic::set_hook(prev);
        if let Some(buf) = fail {
            panic!(
                "hive parse/navigate panicked on {} bytes (root_off {:08x})",
                buf.len(),
                u32::from_le_bytes([buf[0x24], buf[0x25], buf[0x26], buf[0x27]])
            );
        }
    }
}
