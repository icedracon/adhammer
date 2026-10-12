//! Minimal MIT ccache (`FCC_FVNO_4`) reader, the mirror of [`crate::pkinit::build_ccache`].
//!
//! Parses the shape adhammer writes itself (one principal, one credential, no
//! addresses/authdata) and rebuilds a [`Tgt`] for `attack ptt --ccache`. Other tools'
//! ccaches with multiple credentials or authdata are rejected rather than mis-parsed.
//! Every length is bounds-checked, so a truncated file returns `Err`, never a panic.

use crate::tgs::Tgt;
use anyhow::{bail, Context, Result};
use picky_krb::constants::types::NT_PRINCIPAL;
use picky_krb::data_types::Ticket;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "ccache: truncated (need {n} bytes at offset {}, have {})",
                    self.pos,
                    self.buf.len().saturating_sub(self.pos)
                )
            })?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    /// Length-prefixed (u32 BE) byte vector.
    fn cvec(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        if n > self.buf.len().saturating_sub(self.pos) {
            bail!(
                "ccache: counted string claims {n} bytes but only {} remain",
                self.buf.len().saturating_sub(self.pos)
            );
        }
        Ok(self.take(n)?.to_vec())
    }
}

/// `(name_type, realm, components)`.
struct RawPrincipal {
    realm: String,
    components: Vec<String>,
}

fn read_principal(r: &mut Reader) -> Result<RawPrincipal> {
    let _name_type = r.u32()?;
    let num_comps = r.u32()? as usize;
    // Reject an absurd component count before looping.
    if num_comps > 32 {
        bail!("ccache: principal claims {num_comps} components (>32, refusing)");
    }
    let realm = String::from_utf8(r.cvec()?).context("ccache: realm is not valid UTF-8")?;
    let mut components = Vec::with_capacity(num_comps);
    for _ in 0..num_comps {
        components
            .push(String::from_utf8(r.cvec()?).context("ccache: principal component not UTF-8")?);
    }
    Ok(RawPrincipal { realm, components })
}

/// Parse a ccache blob (as written by [`crate::pkinit::build_ccache`]) into its TGT.
pub fn load_tgt(bytes: &[u8]) -> Result<Tgt> {
    let mut r = Reader::new(bytes);

    let magic = r.take(2)?;
    if magic != [0x05, 0x04] {
        bail!(
            "ccache: unsupported version tag {magic:02x?} (only FCC_FVNO_4 / 0x0504 — \
             adhammer's own `kerb pkinit`/`esc1 --pkinit` output — is supported)"
        );
    }
    let header_len = r.u16()? as usize;
    r.take(header_len)?; // header tag(s) — adhammer always writes one zeroed deltatime tag

    let _default_principal = read_principal(&mut r)?;

    let client = read_principal(&mut r)?;
    let cname_part = client
        .components
        .first()
        .cloned()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("ccache: client principal has no component"))?;
    let _server = read_principal(&mut r)?;

    let _keytype = r.u16()?;
    let _etype = r.u16()?;
    let keylen = r.u16()? as usize;
    if keylen > 64 {
        bail!("ccache: implausible session-key length {keylen}");
    }
    let session_key = r.take(keylen)?.to_vec();

    for _ in 0..4 {
        r.u32()?; // authtime, starttime, endtime, renew_till — not needed to reuse the ticket
    }
    let _is_skey = r.u8()?;
    let _tktflags = r.u32()?;

    let num_address = r.u32()?;
    if num_address != 0 {
        bail!("ccache: addresses not supported (num_address={num_address})");
    }
    let num_authdata = r.u32()?;
    if num_authdata != 0 {
        bail!("ccache: authdata not supported (num_authdata={num_authdata})");
    }

    let ticket_der = r.cvec()?;
    if ticket_der.is_empty() {
        bail!("ccache: empty ticket");
    }
    let _second_ticket = r.cvec()?;

    let ticket: Ticket =
        picky_asn1_der::from_bytes(&ticket_der).context("ccache: parse ticket DER")?;
    let cname = crate::principal(NT_PRINCIPAL, &[&cname_part])?;

    Ok(Tgt::from_parts(ticket, session_key, cname, client.realm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tgs::{encrypted_data, golden_ccache};
    use crate::{krb_string, principal};
    use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2};
    use picky_krb::constants::types::NT_SRV_INST;
    use picky_krb::data_types::TicketInner;

    /// Serialize a stand-in `Tgt` with [`golden_ccache`] so the reader runs without a KDC.
    #[test]
    fn round_trips_own_writer_output() {
        let session_key = vec![0x42u8; 32];
        let ticket = Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0::from(picky_asn1::wrapper::IntegerAsn1(vec![5])),
            realm: ExplicitContextTag1::from(krb_string("CORP.LOCAL").unwrap()),
            sname: ExplicitContextTag2::from(principal(NT_SRV_INST, &["krbtgt", "CORP.LOCAL"]).unwrap()),
            enc_part: picky_asn1::wrapper::ExplicitContextTag3::from(encrypted_data(
                18,
                b"CIPHERTEXT_PLACEHOLDER".to_vec(),
            )),
        });
        let tgt = crate::tgs::Tgt::from_parts(
            ticket,
            session_key.clone(),
            principal(1, &["administrator"]).unwrap(),
            "CORP.LOCAL".to_string(),
        );
        let bytes = golden_ccache(&tgt, "administrator").unwrap();
        let loaded = load_tgt(&bytes).unwrap();
        assert_eq!(loaded.crealm(), "CORP.LOCAL");
        assert_eq!(loaded.session_key_bytes(), session_key.as_slice());
        assert_eq!(loaded.ticket_cipher(), b"CIPHERTEXT_PLACEHOLDER");
    }

    #[test]
    fn rejects_bad_magic() {
        let err = load_tgt(&[0xAA, 0xBB, 0, 0]).unwrap_err();
        assert!(err.to_string().contains("unsupported version tag"));
    }

    #[test]
    fn rejects_truncated_input() {
        let err = load_tgt(&[0x05, 0x04, 0x00]).unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn rejects_oversized_counted_string() {
        // Realm length field claims 0xFFFF_FFFF bytes the buffer can't supply.
        let mut buf = vec![0x05, 0x04, 0x00, 0x00];
        buf.extend_from_slice(&1u32.to_be_bytes()); // name_type
        buf.extend_from_slice(&1u32.to_be_bytes()); // num_comps
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // realm length lie
        let err = load_tgt(&buf).unwrap_err();
        assert!(err.to_string().contains("only") && err.to_string().contains("remain"));
    }
}
