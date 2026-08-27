//! Minimal GSS-API / SPNEGO framing for a Kerberos AP-REQ carried in an SMB2 SESSION_SETUP.
//!
//! Windows accepts a SPNEGO `negTokenInit` whose single mechType is Kerberos and whose mechToken
//! is the GSS-Kerberos AP-REQ token (`[APPLICATION 0]{ krb5-OID, 0x0100, AP-REQ }`).

/// DER length encoding (definite form).
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut b = Vec::new();
        let mut v = n;
        while v > 0 {
            b.insert(0, (v & 0xff) as u8);
            v >>= 8;
        }
        let mut out = vec![0x80 | b.len() as u8];
        out.extend_from_slice(&b);
        out
    }
}

/// TLV: tag byte + DER length + content.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// SPNEGO OID 1.3.6.1.5.5.2 (DER value bytes).
const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// Kerberos V5 OID 1.2.840.113554.1.2.2 (DER value bytes).
const KRB5_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// Wrap a raw AP-REQ DER as the GSS-Kerberos mechToken:
/// `[APPLICATION 0] { OID krb5, TOK_ID=0x0100, AP-REQ }`.
///
/// This is the RAW GSS-Kerberos form (RFC 4121 §4.1) — not SPNEGO-wrapped. Windows
/// DCE-RPC BINDs with `auth_type = RPC_C_AUTHN_GSS_KERBEROS (0x10)` expect this
/// exact shape; the SPNEGO-wrapped form is only for `RPC_C_AUTHN_GSS_NEGOTIATE
/// (0x09)`. Sending SPNEGO where raw is expected trips a BIND_NAK reject_reason=2
/// (local_limit_exceeded — Windows' generic auth-format-mismatch signal).
pub fn gss_krb5_aprep(ap_req_der: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&tlv(0x06, KRB5_OID)); // thisMech
    inner.extend_from_slice(&[0x01, 0x00]); // TOK_ID = AP-REQ
    inner.extend_from_slice(ap_req_der);
    tlv(0x60, &inner) // [APPLICATION 0]
}

/// Build the full SPNEGO `negTokenInit` blob for an SMB2 SESSION_SETUP security buffer,
/// advertising Kerberos as the sole mechanism and carrying the AP-REQ as the mechToken.
pub fn spnego_krb5_init(ap_req_der: &[u8]) -> Vec<u8> {
    let mech_token = gss_krb5_aprep(ap_req_der);

    // mechTypes [0] SEQUENCE OF OID { krb5 }
    let mech_types = tlv(0x30, &tlv(0x06, KRB5_OID));
    let mut neg_init = Vec::new();
    neg_init.extend_from_slice(&tlv(0xa0, &mech_types)); // mechTypes [0]
    neg_init.extend_from_slice(&tlv(0xa2, &tlv(0x04, &mech_token))); // mechToken [2] OCTET STRING

    // NegotiationToken CHOICE negTokenInit [0]
    let neg_token = tlv(0xa0, &tlv(0x30, &neg_init));

    // GSSAPI InitialContextToken: [APPLICATION 0] { SPNEGO-OID, negTokenInit }
    let mut inner = Vec::new();
    inner.extend_from_slice(&tlv(0x06, SPNEGO_OID));
    inner.extend_from_slice(&neg_token);
    tlv(0x60, &inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_len_forms() {
        assert_eq!(der_len(5), vec![5]);
        assert_eq!(der_len(200), vec![0x81, 200]);
        assert_eq!(der_len(300), vec![0x82, 0x01, 0x2c]);
    }

    #[test]
    fn spnego_wraps_krb5() {
        let blob = spnego_krb5_init(&[0x6e, 0x02, 0x00, 0x00]); // fake AP-REQ
        assert_eq!(blob[0], 0x60); // GSSAPI app tag
                                   // SPNEGO OID present
        assert!(blob.windows(SPNEGO_OID.len()).any(|w| w == SPNEGO_OID));
        // krb5 OID present (mechTypes + mechToken)
        assert!(
            blob.windows(KRB5_OID.len())
                .filter(|w| *w == KRB5_OID)
                .count()
                >= 2
        );
    }
}
