//! Minimal SPNEGO/GSS-API wrapping for SMB2 session setup. Windows expects the NTLM
//! token inside a SPNEGO `negTokenInit` (first message) / `negTokenResp` (auth message),
//! not raw NTLMSSP. We emit just enough hand-rolled DER for the NTLM-only mech list.

const OID_SPNEGO: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const OID_NTLMSSP: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

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

/// Wrap an NTLM NEGOTIATE (Type 1) in a SPNEGO `negTokenInit` advertising NTLMSSP.
pub fn negotiate_init(ntlm_type1: &[u8]) -> Vec<u8> {
    let mech_types = tlv(0xa0, &tlv(0x30, &tlv(0x06, &OID_NTLMSSP))); // [0] MechTypeList
    let mech_token = tlv(0xa2, &tlv(0x04, ntlm_type1)); // [2] mechToken
    let mut inner = mech_types;
    inner.extend(mech_token);
    let neg_token_init = tlv(0xa0, &tlv(0x30, &inner)); // [0] NegTokenInit SEQUENCE
    let mut gss = tlv(0x06, &OID_SPNEGO);
    gss.extend(neg_token_init);
    tlv(0x60, &gss) // [APPLICATION 0]
}

/// Wrap an NTLM AUTHENTICATE (Type 3) in a SPNEGO `negTokenResp`.
pub fn negotiate_resp(ntlm_type3: &[u8]) -> Vec<u8> {
    let response_token = tlv(0xa2, &tlv(0x04, ntlm_type3)); // [2] responseToken
    tlv(0xa1, &tlv(0x30, &response_token)) // [1] NegTokenResp SEQUENCE
}

/// Server side: wrap an NTLM CHALLENGE (Type 2) in a SPNEGO `negTokenResp` with
/// negState=accept-incomplete and supportedMech=NTLMSSP (the reply to the client's Type 1).
pub fn challenge_resp(ntlm_type2: &[u8]) -> Vec<u8> {
    let neg_state = tlv(0xa0, &tlv(0x0a, &[0x01])); // [0] ENUMERATED accept-incomplete
    let supported_mech = tlv(0xa1, &tlv(0x06, &OID_NTLMSSP)); // [1] MechType
    let response_token = tlv(0xa2, &tlv(0x04, ntlm_type2)); // [2] responseToken
    let mut inner = neg_state;
    inner.extend(supported_mech);
    inner.extend(response_token);
    tlv(0xa1, &tlv(0x30, &inner)) // [1] NegTokenResp SEQUENCE
}

/// Locate the embedded NTLM message inside a SPNEGO/GSS blob by its "NTLMSSP\0" signature.
pub fn find_ntlm(buf: &[u8]) -> Option<&[u8]> {
    buf.windows(8).position(|w| w == b"NTLMSSP\0").map(|i| &buf[i..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_wellformed_and_embeds_token() {
        let t1 = b"NTLMSSP\0aaaa";
        let w = negotiate_init(t1);
        assert_eq!(w[0], 0x60); // [APPLICATION 0]
        assert_eq!(find_ntlm(&w), Some(&t1[..]));
    }

    #[test]
    fn long_len_encoding() {
        assert_eq!(der_len(0x7f), vec![0x7f]);
        assert_eq!(der_len(0x80), vec![0x81, 0x80]);
        assert_eq!(der_len(0x1234), vec![0x82, 0x12, 0x34]);
    }
}
