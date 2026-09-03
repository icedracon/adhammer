//! Hand-rolled DNS message codec (RFC 1035 §4) — no third-party resolver.
//!
//! WS-FOUNDATION-DNS-HANDROLL (1.5.0). The black-box discovery flow needs
//! SRV / A / AAAA / PTR lookups against an AD domain's DNS (usually a DC).
//! Rather than pull `hickory-resolver` (a large async resolver stack), we
//! hand-roll the wire format per the s-tier-minimalism rule: one file of
//! pure encode/decode with zero I/O, driven by a thin tokio UDP/TCP
//! transport in `discovery.rs`.
//!
//! ## Parser safety
//!
//! `parse_response` consumes attacker-controlled bytes (a hostile or
//! spoofed DNS server can return arbitrary content). It must never panic:
//! every slice index is bounds-checked, name decompression follows a
//! bounded pointer budget to defeat compression-pointer loops, and label
//! lengths are validated before use. On any malformed input it returns
//! `Err`, never an out-of-range access.

use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS record types we query. Values are the IANA TYPE codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Ptr = 12,
    Aaaa = 28,
    Srv = 33,
}

impl QType {
    fn from_u16(v: u16) -> Option<QType> {
        Some(match v {
            1 => QType::A,
            2 => QType::Ns,
            5 => QType::Cname,
            12 => QType::Ptr,
            28 => QType::Aaaa,
            33 => QType::Srv,
            _ => return None,
        })
    }
}

const CLASS_IN: u16 = 1;
/// Hard cap on compression-pointer jumps while decoding one name. A
/// well-formed name needs at most one jump per label; 64 is generous and
/// bounds any hostile self-referential pointer chain.
const MAX_NAME_JUMPS: usize = 64;
/// Hard cap on total labels in one decoded name (defence against a long
/// pointer-stitched chain that never loops but is pathologically long).
const MAX_NAME_LABELS: usize = 128;

/// One decoded resource record's payload, limited to the shapes the
/// black-box flow consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
    Cname(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// A record type we recognized the header of but do not decode.
    Other(u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub data: RecordData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsResponse {
    pub id: u16,
    /// RCODE (0 = NOERROR, 3 = NXDOMAIN, …).
    pub rcode: u8,
    /// TC bit — response was truncated; caller should retry over TCP.
    pub truncated: bool,
    pub answers: Vec<ResourceRecord>,
}

/// Build a DNS query message for `qname` of type `qtype` with transaction
/// id `id`. Standard recursive query, one question, class IN.
pub fn encode_query(id: u16, qname: &str, qtype: QType) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + qname.len());
    // Header.
    buf.extend_from_slice(&id.to_be_bytes());
    // flags: QR=0, Opcode=0, AA=0, TC=0, RD=1  |  RA=0, Z=0, RCODE=0
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                // Question: QNAME.
    encode_name(&mut buf, qname);
    buf.extend_from_slice(&(qtype as u16).to_be_bytes()); // QTYPE
    buf.extend_from_slice(&CLASS_IN.to_be_bytes()); // QCLASS
    buf
}

/// Encode a dotted name into length-prefixed labels terminated by a zero
/// byte. Empty / root name encodes as a single zero byte. Labels longer
/// than 63 bytes are truncated to 63 (the wire max) rather than rejected —
/// callers pass validated names, this is a last-resort clamp.
fn encode_name(buf: &mut Vec<u8>, name: &str) {
    let trimmed = name.trim_end_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            let bytes = label.as_bytes();
            let len = bytes.len().min(63);
            buf.push(len as u8);
            buf.extend_from_slice(&bytes[..len]);
        }
    }
    buf.push(0);
}

/// Parse a DNS response message. Returns `Err(&str)` on any malformed
/// input; never panics or indexes out of range.
pub fn parse_response(msg: &[u8]) -> Result<DnsResponse, &'static str> {
    if msg.len() < 12 {
        return Err("dns response shorter than header");
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let truncated = (flags & 0x0200) != 0;
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    let mut pos = 12;
    // Skip the question section.
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)?;
        // QTYPE (2) + QCLASS (2)
        pos = pos.checked_add(4).ok_or("question section overflow")?;
        if pos > msg.len() {
            return Err("question section truncated");
        }
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (name, after_name) = decode_name(msg, pos)?;
        pos = after_name;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 bytes fixed.
        if pos.checked_add(10).ok_or("rr header overflow")? > msg.len() {
            return Err("rr header truncated");
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or("rdata length overflow")?;
        if rdata_end > msg.len() {
            return Err("rdata truncated");
        }
        let data = decode_rdata(msg, rtype, rdata_start, rdata_end)?;
        answers.push(ResourceRecord { name, data });
        pos = rdata_end;
    }

    Ok(DnsResponse {
        id,
        rcode,
        truncated,
        answers,
    })
}

fn decode_rdata(
    msg: &[u8],
    rtype: u16,
    start: usize,
    end: usize,
) -> Result<RecordData, &'static str> {
    match QType::from_u16(rtype) {
        Some(QType::A) => {
            if end - start != 4 {
                return Err("A rdata not 4 bytes");
            }
            Ok(RecordData::A(Ipv4Addr::new(
                msg[start],
                msg[start + 1],
                msg[start + 2],
                msg[start + 3],
            )))
        }
        Some(QType::Aaaa) => {
            if end - start != 16 {
                return Err("AAAA rdata not 16 bytes");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&msg[start..end]);
            Ok(RecordData::Aaaa(Ipv6Addr::from(octets)))
        }
        Some(QType::Ptr) => {
            let (name, _) = decode_name(msg, start)?;
            Ok(RecordData::Ptr(name))
        }
        Some(QType::Cname) => {
            let (name, _) = decode_name(msg, start)?;
            Ok(RecordData::Cname(name))
        }
        Some(QType::Srv) => {
            if end - start < 7 {
                return Err("SRV rdata shorter than fixed fields");
            }
            let priority = u16::from_be_bytes([msg[start], msg[start + 1]]);
            let weight = u16::from_be_bytes([msg[start + 2], msg[start + 3]]);
            let port = u16::from_be_bytes([msg[start + 4], msg[start + 5]]);
            let (target, _) = decode_name(msg, start + 6)?;
            Ok(RecordData::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        _ => Ok(RecordData::Other(rtype)),
    }
}

/// Advance past a name in the wire (following NOT into it — a name in the
/// question section has no compression, but be defensive). Returns the
/// offset just after the name's terminating byte or first pointer.
fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize, &'static str> {
    loop {
        let len = *msg.get(pos).ok_or("name length out of range")?;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer occupies two bytes; a name ends here.
            if pos + 2 > msg.len() {
                return Err("compression pointer truncated");
            }
            return Ok(pos + 2);
        }
        if len & 0xC0 != 0 {
            return Err("reserved label length bits set");
        }
        pos = pos
            .checked_add(1 + len as usize)
            .ok_or("label length overflow")?;
        if pos > msg.len() {
            return Err("label runs past message");
        }
    }
}

/// Decode a (possibly compressed) name starting at `pos`. Returns the
/// decoded dotted lowercase name plus the offset just after the name's
/// on-the-wire encoding at the ORIGINAL position (pointer jumps do not
/// advance the returned cursor past the two pointer bytes).
fn decode_name(msg: &[u8], start: usize) -> Result<(String, usize), &'static str> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumps = 0usize;
    // The cursor we report back: fixed at the first pointer we follow.
    let mut cursor_after: Option<usize> = None;

    loop {
        if labels.len() > MAX_NAME_LABELS {
            return Err("name has too many labels");
        }
        let len = *msg.get(pos).ok_or("name length out of range")?;
        if len == 0 {
            let after = pos + 1;
            return Ok((labels.join("."), cursor_after.unwrap_or(after)));
        }
        if len & 0xC0 == 0xC0 {
            // Two-byte pointer: 14-bit offset into the message.
            let b2 = *msg.get(pos + 1).ok_or("compression pointer truncated")?;
            let offset = (((len & 0x3F) as usize) << 8) | b2 as usize;
            if cursor_after.is_none() {
                cursor_after = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_NAME_JUMPS {
                return Err("compression pointer budget exceeded (loop?)");
            }
            if offset >= msg.len() {
                return Err("compression pointer past message");
            }
            pos = offset;
            continue;
        }
        if len & 0xC0 != 0 {
            return Err("reserved label length bits set");
        }
        let label_start = pos + 1;
        let label_end = label_start
            .checked_add(len as usize)
            .ok_or("label length overflow")?;
        if label_end > msg.len() {
            return Err("label runs past message");
        }
        // DNS labels are conventionally ASCII; lossy-decode + lowercase.
        let label = String::from_utf8_lossy(&msg[label_start..label_end]).to_ascii_lowercase();
        labels.push(label);
        pos = label_end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrips_header_and_question() {
        let q = encode_query(0x1234, "_ldap._tcp.dc._msdcs.corp.local", QType::Srv);
        assert_eq!(u16::from_be_bytes([q[0], q[1]]), 0x1234);
        assert_eq!(u16::from_be_bytes([q[2], q[3]]), 0x0100); // RD set
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1); // QDCOUNT
                                                         // QTYPE tail = SRV(33), QCLASS = IN(1).
        let n = q.len();
        assert_eq!(u16::from_be_bytes([q[n - 4], q[n - 3]]), 33);
        assert_eq!(u16::from_be_bytes([q[n - 2], q[n - 1]]), 1);
    }

    #[test]
    fn encode_name_labels_and_root() {
        let mut buf = Vec::new();
        encode_name(&mut buf, "dc.corp.local.");
        // 2 "dc" 4 "corp" 5 "local" 0
        assert_eq!(buf, b"\x02dc\x04corp\x05local\x00");
        let mut root = Vec::new();
        encode_name(&mut root, "");
        assert_eq!(root, b"\x00");
    }

    // Build a minimal response: header + 1 question + N answers.
    fn resp_with(answers_wire: &[u8], ancount: u16) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0xABCDu16.to_be_bytes()); // id
        m.extend_from_slice(&0x8180u16.to_be_bytes()); // QR+RD+RA, RCODE 0
        m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        m.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        // question: corp.local SRV IN
        encode_name(&mut m, "corp.local");
        m.extend_from_slice(&33u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(answers_wire);
        m
    }

    #[test]
    fn parse_a_record() {
        // answer: name ptr to qname(0x0c), TYPE A, CLASS IN, TTL 60, RDLEN 4, 10.0.0.10
        let mut a = Vec::new();
        a.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12 (qname)
        a.extend_from_slice(&1u16.to_be_bytes()); // A
        a.extend_from_slice(&1u16.to_be_bytes()); // IN
        a.extend_from_slice(&60u32.to_be_bytes()); // TTL
        a.extend_from_slice(&4u16.to_be_bytes()); // RDLEN
        a.extend_from_slice(&[10, 0, 0, 10]);
        let msg = resp_with(&a, 1);
        let r = parse_response(&msg).unwrap();
        assert_eq!(r.id, 0xABCD);
        assert_eq!(r.rcode, 0);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(
            r.answers[0].data,
            RecordData::A(Ipv4Addr::new(10, 0, 0, 10))
        );
    }

    #[test]
    fn parse_srv_record_with_target_name() {
        // SRV rdata: prio 0, weight 100, port 389, target dc01.corp.local
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&0u16.to_be_bytes());
        rdata.extend_from_slice(&100u16.to_be_bytes());
        rdata.extend_from_slice(&389u16.to_be_bytes());
        encode_name(&mut rdata, "dc01.corp.local");
        let mut a = Vec::new();
        a.extend_from_slice(&[0xC0, 0x0C]);
        a.extend_from_slice(&33u16.to_be_bytes()); // SRV
        a.extend_from_slice(&1u16.to_be_bytes());
        a.extend_from_slice(&0u32.to_be_bytes());
        a.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        a.extend_from_slice(&rdata);
        let msg = resp_with(&a, 1);
        let r = parse_response(&msg).unwrap();
        assert_eq!(
            r.answers[0].data,
            RecordData::Srv {
                priority: 0,
                weight: 100,
                port: 389,
                target: "dc01.corp.local".into()
            }
        );
    }

    #[test]
    fn truncation_bit_detected() {
        let mut m = resp_with(&[], 0);
        // set TC bit (0x0200) in flags at bytes 2..4
        let flags = u16::from_be_bytes([m[2], m[3]]) | 0x0200;
        m[2..4].copy_from_slice(&flags.to_be_bytes());
        let r = parse_response(&m).unwrap();
        assert!(r.truncated);
    }

    #[test]
    fn nxdomain_rcode_surfaced() {
        let mut m = resp_with(&[], 0);
        let flags = (u16::from_be_bytes([m[2], m[3]]) & 0xFFF0) | 3; // RCODE=3
        m[2..4].copy_from_slice(&flags.to_be_bytes());
        let r = parse_response(&m).unwrap();
        assert_eq!(r.rcode, 3);
    }

    // ---- hostile / malformed inputs: must Err, never panic ----

    #[test]
    fn short_message_errs() {
        assert!(parse_response(&[0, 1, 2]).is_err());
    }

    #[test]
    fn compression_pointer_loop_is_bounded() {
        // A name that points to itself → must hit the jump budget and Err.
        let mut m = Vec::new();
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0x8180u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT 0
        m.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT 1
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        // answer name = pointer to offset 12 (itself)
        let self_off = m.len() as u16;
        let ptr = 0xC000 | self_off;
        m.extend_from_slice(&ptr.to_be_bytes());
        // never reached cleanly — parser must Err, not loop forever/panic
        let r = parse_response(&m);
        assert!(r.is_err());
    }

    #[test]
    fn rdlength_past_end_errs() {
        let mut a = Vec::new();
        a.extend_from_slice(&[0xC0, 0x0C]);
        a.extend_from_slice(&1u16.to_be_bytes());
        a.extend_from_slice(&1u16.to_be_bytes());
        a.extend_from_slice(&60u32.to_be_bytes());
        a.extend_from_slice(&9999u16.to_be_bytes()); // absurd RDLEN
        a.extend_from_slice(&[10, 0, 0, 10]);
        let msg = resp_with(&a, 1);
        assert!(parse_response(&msg).is_err());
    }

    #[test]
    fn reserved_label_bits_err() {
        // 0x40/0x80 top bits (not 0xC0 pointer, not 0x00 label) are reserved.
        let mut m = Vec::new();
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0x8180u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.push(0x40); // reserved bits
        let r = parse_response(&m);
        assert!(r.is_err());
    }
}
