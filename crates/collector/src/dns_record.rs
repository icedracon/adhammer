//! MS-DNSP `DNS_RPC_RECORD` builders — the write side of the ADIDNS wire
//! format the read path in `lib.rs` (`parse_dns_record`) already understands.
//! Only the record types `attack dns` needs are built here (WS-13, 1.4.1).
//!
//! Wire layout of a single `DNS_RPC_RECORD` (MS-DNSP 2.2.2.2.1, 24-byte header):
//!
//! ```text
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +---------------+-------------------------------+---------------+
//!  |         DataLength (LE)     |          Type (LE, 1=A)         |
//!  +---------------+---------------+---------------+---------------+
//!  |  Version=5   |   Rank=0xF0   |         Flags (LE)             |
//!  +-------------------------------+-------------------------------+
//!  |                         Serial (LE)                           |
//!  +---------------------------------------------------------------+
//!  |                     TtlSeconds (BIG endian)                   |
//!  +---------------------------------------------------------------+
//!  |                         Reserved                              |
//!  +---------------------------------------------------------------+
//!  |                        TimeStamp (0 = static)                 |
//!  +---------------------------------------------------------------+
//!  |                          Data ...                             |
//!  +---------------------------------------------------------------+
//! ```

use std::net::Ipv4Addr;

/// Build a `DNS_RPC_RECORD` for an A record with the given IPv4 address, TTL
/// (seconds), and zone SOA serial. Rank is fixed at `RANK_ZONE = 0xF0` (record
/// loaded from the zone), Version at 5, TimeStamp at 0 (static / non-aged) —
/// which is what `dnscmd /RecordAdd` and every mainstream AD DNS write tool
/// emit for a fresh A node.
pub fn build_a_record(ip: &Ipv4Addr, ttl: u32, serial: u32) -> Vec<u8> {
    const DATA_LEN: u16 = 4; // an A record is 4 bytes of octets
    const RTYPE_A: u16 = 1;
    let mut b = Vec::with_capacity(24 + DATA_LEN as usize);
    b.extend_from_slice(&DATA_LEN.to_le_bytes()); // wDataLength
    b.extend_from_slice(&RTYPE_A.to_le_bytes()); // wType
    b.extend_from_slice(&[5, 0xF0, 0x00, 0x00]); // Version, Rank, Flags(LE)
    b.extend_from_slice(&serial.to_le_bytes()); // dwSerial
    b.extend_from_slice(&ttl.to_be_bytes()); // dwTtlSeconds — BE per MS-DNSP
    b.extend_from_slice(&[0u8; 4]); // dwReserved
    b.extend_from_slice(&[0u8; 4]); // dwTimeStamp (0 = static)
    b.extend_from_slice(&ip.octets()); // Data (BE octets)
    b
}

/// Read the SOA serial out of an existing `dnsRecord` blob (the `@` node of a
/// zone carries the SOA). Returns `None` if the record is not a SOA or the
/// blob is malformed. Used by `attack dns` to pick a serial for newly-built
/// records; the DC's DNS server re-writes the SOA on the next zone update.
pub fn read_soa_serial(blob: &[u8]) -> Option<u32> {
    if blob.len() < 28 {
        return None;
    }
    let rtype = u16::from_le_bytes([blob[2], blob[3]]);
    if rtype != 6 {
        // SOA = 6
        return None;
    }
    // SOA data begins at offset 24. First 4 bytes = serial (BIG endian per MS-DNSP).
    let s = &blob[24..28];
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_wire_layout() {
        let rec = build_a_record(&Ipv4Addr::new(1, 2, 3, 4), 3600, 1);
        assert_eq!(rec.len(), 28);
        // wDataLength = 4 LE
        assert_eq!(&rec[0..2], &[0x04, 0x00]);
        // wType = 1 LE (A)
        assert_eq!(&rec[2..4], &[0x01, 0x00]);
        // Version=5, Rank=0xF0, Flags=0
        assert_eq!(&rec[4..8], &[0x05, 0xF0, 0x00, 0x00]);
        // Serial=1 LE
        assert_eq!(&rec[8..12], &[0x01, 0x00, 0x00, 0x00]);
        // TTL=3600 BE
        assert_eq!(&rec[12..16], &3600u32.to_be_bytes());
        // Data = 1.2.3.4
        assert_eq!(&rec[24..28], &[1, 2, 3, 4]);
    }

    #[test]
    fn round_trip_serial_via_soa_parser() {
        // Craft a minimal SOA blob: 24-byte header + serial (BE) + 20 bytes filler + trivial DNS_COUNT_NAME (root).
        let mut b = Vec::new();
        b.extend_from_slice(&24u16.to_le_bytes()); // DataLength
        b.extend_from_slice(&6u16.to_le_bytes()); // Type = SOA
        b.extend_from_slice(&[5, 0xF0, 0, 0, 0, 0, 0, 0]); // Ver+Rank+Flags+Serial-placeholder
        b.extend_from_slice(&[0u8; 4]); // TTL
        b.extend_from_slice(&[0u8; 4]); // Reserved
        b.extend_from_slice(&[0u8; 4]); // TimeStamp
                                        // SOA data (first 4 bytes = serial BE)
        b.extend_from_slice(&42u32.to_be_bytes());
        b.extend_from_slice(&[0u8; 20]);
        assert_eq!(read_soa_serial(&b), Some(42));
    }

    #[test]
    fn read_soa_serial_rejects_non_soa() {
        let rec = build_a_record(&Ipv4Addr::new(1, 2, 3, 4), 60, 1);
        assert!(read_soa_serial(&rec).is_none());
    }
}
