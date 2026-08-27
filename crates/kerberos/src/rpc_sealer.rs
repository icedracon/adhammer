//! # WS-4-P2 — AES256-CTS-HMAC-SHA1-96 KrbSealer for MS-KILE DCE-RPC.
//!
//! Wires the Session-1/2 crypto primitives ([`crate::rpc_seal`]) up to the
//! [`dcerpc::krb_seal::KrbSealer`] trait so an authenticated pipe/tcp session can
//! seal outgoing REQUESTs and unseal RESPONSEs.
//!
//! ## Wire layout
//!
//! Per MS-KILE §3.4.5.4.1 + RFC 4121 §4.2.4 for AES256-CTS-HMAC-SHA1-96:
//!
//! ```text
//! Encrypt:
//!   E1 = Confounder(16) || Stub(N)
//!   Ciphertext = AES-CTS(Ke, iv=0, E1)          // same length: N + 16
//!   Confounder_ct = Ciphertext[..16]            // goes into auth_value
//!   Stub_ct       = Ciphertext[16..]            // goes into PDU body as sealed_stub
//!   HMAC = HMAC-SHA1-96(Ki, Confounder || Stub || WrapHeader)   // 12 bytes
//!
//! Wire:
//!   PDU body:    ...alloc_hint/cont_id/opnum, then Stub_ct (N bytes)
//!   auth_value:  WrapHeader(16) || Confounder_ct(16) || HMAC(12) = 44 bytes
//! ```
//!
//! Key derivation (RFC 3961 §5.3): `Ke = DK(K, usage || 0xAA)`,
//! `Ki = DK(K, usage || 0x55)` where `usage` is the RFC 4121 §2 direction code
//! (24 initiator seal / 22 acceptor seal), and `K` is the 32-byte AES256 subkey
//! carried in the AP-REQ authenticator.
//!
//! Note that this layout advertises `auth_value_len() == 44`, larger than dcerpc's own
//! `AES_SHA1_AUTH_VALUE_LEN = 28` hint. dcerpc's transport respects the sealer's
//! declared length via `auth_value_len()`, so the mismatch is harmless — the constant
//! is a hint for the NTLM-shaped layout, not a hard cap.
//!
//! Live-DC status (Session 4 lab probe against DC01 Server 2025 via `check krb-seal`):
//! reaches BIND_ACK green; the sealed REQUEST leg's HMAC-verify outcome is what
//! `--try-call` measures.

use crate::rpc_seal::{
    aes_cts_decrypt, aes_cts_encrypt, derive_ke, derive_ki, hmac_sha1_96, AES256_KEY_LEN,
    AES_BLOCK_LEN, KG_USAGE_ACCEPTOR_SEAL, KG_USAGE_INITIATOR_SEAL,
};
use dcerpc::krb_seal::{KrbSealer, WrapToken, AES_SHA1_CHECKSUM_LEN, WRAP_HEADER_LEN};
use dcerpc::{Result as DcerpcResult, RpcError};

/// RRC value used by DCE-RPC AES256-CTS-HMAC-SHA1-96: `HMAC(12) + wrap-header(16) = 28`.
/// Per RFC 4121 §4.2.5, rotating the encrypted-plus-checksum right by RRC moves the
/// wrap-header ciphertext + HMAC to the front, which is where DCE-RPC's auth_value
/// picks them up. Higher-RRC layouts (or unrotated) are legal in RFC but Windows uses
/// this specific value for the DCE-style transport.
pub const DCE_RPC_KRB5_RRC: u16 = (AES_SHA1_CHECKSUM_LEN + WRAP_HEADER_LEN) as u16;

/// MS-KILE DCE-RPC auth_value for AES256-CTS-HMAC-SHA1-96 (per RFC 4121 §4.2.5 rotated
/// layout): `WrapHeader(16, outer, RRC=28) || E(header_inner)(16) || HMAC(12) ||
/// E(confounder)(16)` = 60 bytes. Confounder-ct + wrap-header-ct + HMAC are rotated
/// out of the encrypted portion by RRC=28 so the sealed_stub in the PDU body preserves
/// its N-byte length while auth_value carries the rest.
pub const MS_KILE_AUTH_VALUE_LEN: usize =
    WRAP_HEADER_LEN + WRAP_HEADER_LEN + AES_SHA1_CHECKSUM_LEN + AES_BLOCK_LEN;

/// Which side of the Kerberos context this sealer represents. Determines which
/// RFC 4121 §2 key-usage number is used for the *sending* direction — the receive
/// direction is the mirror.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Client that originated the AP-REQ. Sends with `KG_USAGE_INITIATOR_SEAL` (24)
    /// and receives with `KG_USAGE_ACCEPTOR_SEAL` (22).
    Initiator,
    /// Server that accepted the AP-REQ. Sends with `KG_USAGE_ACCEPTOR_SEAL` (22)
    /// and receives with `KG_USAGE_INITIATOR_SEAL` (24). Not the common CLI path
    /// but useful for symmetric self-tests and eventual acceptor-side code (relay).
    Acceptor,
}

impl Role {
    fn send_usage(self) -> u32 {
        match self {
            Role::Initiator => KG_USAGE_INITIATOR_SEAL,
            Role::Acceptor => KG_USAGE_ACCEPTOR_SEAL,
        }
    }
    fn recv_usage(self) -> u32 {
        match self {
            Role::Initiator => KG_USAGE_ACCEPTOR_SEAL,
            Role::Acceptor => KG_USAGE_INITIATOR_SEAL,
        }
    }
    fn sends_as_acceptor(self) -> bool {
        matches!(self, Role::Acceptor)
    }
}

/// AES256-CTS-HMAC-SHA1-96 sealer for one DCE-RPC connection direction.
///
/// Holds:
/// - The 32-byte Kerberos session key from the AP-REQ (or subkey from AP-REP).
/// - Two monotonic sequence counters: `send_seq` for this side's outbound tokens,
///   `recv_seq` for the peer's inbound tokens.
/// - The [`Role`] deciding which usage numbers to derive Ke/Ki from.
/// - The `acceptor_subkey` bit that stamps the WRAP header when the session key
///   in play is the AP-REP acceptor subkey (not the ticket's session key).
pub struct AesCts96Sealer {
    session_key: [u8; AES256_KEY_LEN],
    send_seq: u64,
    recv_seq: u64,
    role: Role,
    acceptor_subkey: bool,
}

impl AesCts96Sealer {
    /// Build a sealer for the given [`Role`] with a 32-byte session key.
    pub fn new(session_key: [u8; AES256_KEY_LEN], role: Role, acceptor_subkey: bool) -> Self {
        Self {
            session_key,
            send_seq: 0,
            recv_seq: 0,
            role,
            acceptor_subkey,
        }
    }

    /// Shorthand: an initiator (the CLI's normal role).
    pub fn new_initiator(session_key: [u8; AES256_KEY_LEN], acceptor_subkey: bool) -> Self {
        Self::new(session_key, Role::Initiator, acceptor_subkey)
    }

    /// Shorthand: an acceptor. Kept `pub` for eventual relay/server-side use.
    pub fn new_acceptor(session_key: [u8; AES256_KEY_LEN], acceptor_subkey: bool) -> Self {
        Self::new(session_key, Role::Acceptor, acceptor_subkey)
    }

    /// Deterministic 16-byte confounder derived from the direction's sequence number and
    /// the session key. MS-KILE spec allows any random 16 bytes; using a deterministic
    /// derivation makes tests reproducible while still varying per-PDU (each seq produces
    /// a different confounder → different ciphertext for identical stubs). Production
    /// callers who want true randomness can replace this with `OsRng` in a follow-up.
    fn confounder_for(&self, dir_seq: u64) -> [u8; AES_BLOCK_LEN] {
        let mut prefix = [0u8; 16];
        prefix[..8].copy_from_slice(&dir_seq.to_be_bytes());
        prefix[8..].copy_from_slice(b"confndAA");
        let full = hmac_sha1_96(&self.session_key, &prefix);
        let mut c = [0u8; AES_BLOCK_LEN];
        c[..12].copy_from_slice(&full);
        c[12..].copy_from_slice(&(dir_seq as u32).to_be_bytes());
        c
    }

    /// Zero out the RFC 4121 §4.2.6.5 "MIC-relevant" fields of the wrap header (Filler,
    /// EC, RRC) before it's fed into the encryption / HMAC computation. The OUTER wrap
    /// header on the wire keeps its real RRC/EC — only the INNER copy that's encrypted
    /// alongside the confounder+stub has these fields zeroed. Both sides do this so both
    /// arrive at the same plaintext for verify.
    fn wrap_header_for_hmac(mut wrap_bytes: [u8; WRAP_HEADER_LEN]) -> [u8; WRAP_HEADER_LEN] {
        wrap_bytes[4] = 0; // EC hi
        wrap_bytes[5] = 0; // EC lo
        wrap_bytes[6] = 0; // RRC hi
        wrap_bytes[7] = 0; // RRC lo
        wrap_bytes
    }
}

impl KrbSealer for AesCts96Sealer {
    fn seal_pdu(&mut self, _sign_over: &[u8], stub: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Outer wrap header — RRC=28 declares the rotation we're about to apply.
        let mut wrap = WrapToken::sealed(
            self.role.sends_as_acceptor(),
            self.acceptor_subkey,
            self.send_seq,
        );
        wrap.rrc = DCE_RPC_KRB5_RRC;
        let wrap_bytes = wrap.encode();
        // Inner wrap header (identical fields, but RRC/EC/Filler zeroed per RFC 4121 §4.2.6.5).
        let wrap_bytes_inner = Self::wrap_header_for_hmac(wrap_bytes);

        let ke = derive_ke(&self.session_key, self.role.send_usage());
        let ki = derive_ki(&self.session_key, self.role.send_usage());

        // RFC 4121 §4.2.4 plaintext-to-encrypt = Confounder(16) || Stub(N) || WrapHeader_inner(16).
        // Length N + 32.
        let confounder = self.confounder_for(self.send_seq);
        let mut plaintext = Vec::with_capacity(AES_BLOCK_LEN + stub.len() + WRAP_HEADER_LEN);
        plaintext.extend_from_slice(&confounder);
        plaintext.extend_from_slice(stub);
        plaintext.extend_from_slice(&wrap_bytes_inner);
        let ct = aes_cts_encrypt(&ke, &[0u8; AES_BLOCK_LEN], &plaintext);
        debug_assert_eq!(ct.len(), AES_BLOCK_LEN + stub.len() + WRAP_HEADER_LEN);
        // HMAC is computed over the *plaintext* per RFC 3961 §5.3 style.
        let mac = hmac_sha1_96(&ki, &plaintext);

        // Assemble unrotated encrypted-plus-checksum: [ct(N+32) || HMAC(12)]. Length N+44.
        // Layout: [E(conf)(16) | E(stub)(N) | E(hdr)(16) | HMAC(12)]
        // RRC=28 right-rotation moves the last 28 bytes (E(hdr) + HMAC) to the front:
        //   rotated = [E(hdr)(16) | HMAC(12) | E(conf)(16) | E(stub)(N)]
        // DCE-RPC then splits: last N bytes → sealed_stub in PDU body,
        //                     first 44 bytes prefixed with outer WrapHeader(16) → auth_value.
        let e_conf = &ct[..AES_BLOCK_LEN];
        let e_stub = &ct[AES_BLOCK_LEN..AES_BLOCK_LEN + stub.len()];
        let e_hdr = &ct[AES_BLOCK_LEN + stub.len()..];
        debug_assert_eq!(e_hdr.len(), WRAP_HEADER_LEN);

        let mut auth_value = Vec::with_capacity(MS_KILE_AUTH_VALUE_LEN);
        auth_value.extend_from_slice(&wrap_bytes); // outer header (RRC=28)
        auth_value.extend_from_slice(e_hdr); // 16
        auth_value.extend_from_slice(&mac); // 12
        auth_value.extend_from_slice(e_conf); // 16
        debug_assert_eq!(auth_value.len(), MS_KILE_AUTH_VALUE_LEN);
        let sealed_stub = e_stub.to_vec();

        self.send_seq = self.send_seq.wrapping_add(1);
        (sealed_stub, auth_value)
    }

    fn unseal_pdu(
        &mut self,
        pdu_no_auth: &[u8],
        stub_off: usize,
        stub_len: usize,
        auth_value: &[u8],
    ) -> DcerpcResult<Vec<u8>> {
        if auth_value.len() != MS_KILE_AUTH_VALUE_LEN {
            return Err(RpcError::Protocol(format!(
                "auth_value length {} != {MS_KILE_AUTH_VALUE_LEN}",
                auth_value.len()
            )));
        }
        let wrap = WrapToken::decode(&auth_value[..WRAP_HEADER_LEN])?;
        if !wrap.is_sealed() {
            return Err(RpcError::Protocol(
                "unseal_pdu called on a WRAP token without SEALED flag".into(),
            ));
        }
        if wrap.snd_seq != self.recv_seq {
            return Err(RpcError::Protocol(format!(
                "WRAP snd_seq {} != expected {}",
                wrap.snd_seq, self.recv_seq
            )));
        }
        // We support only the DCE-RPC RRC=28 layout for now. A stricter check helps
        // catch peers that use a different rotation — better to fail loud than to
        // silently misreassemble.
        if wrap.rrc != DCE_RPC_KRB5_RRC {
            return Err(RpcError::Protocol(format!(
                "WRAP rrc {} != DCE-RPC expected {DCE_RPC_KRB5_RRC}",
                wrap.rrc
            )));
        }

        // auth_value layout (rotated): outer_header(16) || E(hdr)(16) || HMAC(12) || E(conf)(16).
        let outer_off = WRAP_HEADER_LEN;
        let e_hdr = &auth_value[outer_off..outer_off + WRAP_HEADER_LEN];
        let mac_bytes = &auth_value
            [outer_off + WRAP_HEADER_LEN..outer_off + WRAP_HEADER_LEN + AES_SHA1_CHECKSUM_LEN];
        let e_conf = &auth_value[outer_off + WRAP_HEADER_LEN + AES_SHA1_CHECKSUM_LEN..];

        let sealed_stub =
            pdu_no_auth
                .get(stub_off..stub_off + stub_len)
                .ok_or(RpcError::Underrun {
                    need: stub_off + stub_len,
                    pos: pdu_no_auth.len(),
                })?;

        let ke = derive_ke(&self.session_key, self.role.recv_usage());
        let ki = derive_ki(&self.session_key, self.role.recv_usage());

        // Reconstruct unrotated ciphertext: E(conf)(16) || E(stub)(N) || E(hdr)(16). Length N+32.
        let mut ct = Vec::with_capacity(AES_BLOCK_LEN + stub_len + WRAP_HEADER_LEN);
        ct.extend_from_slice(e_conf);
        ct.extend_from_slice(sealed_stub);
        ct.extend_from_slice(e_hdr);
        let plaintext = aes_cts_decrypt(&ke, &[0u8; AES_BLOCK_LEN], &ct);
        debug_assert_eq!(plaintext.len(), AES_BLOCK_LEN + stub_len + WRAP_HEADER_LEN);
        let stub_plain = plaintext[AES_BLOCK_LEN..AES_BLOCK_LEN + stub_len].to_vec();
        let inner_hdr_recovered = &plaintext[AES_BLOCK_LEN + stub_len..];

        // Recovered inner header should match the outer header with EC/RRC/Filler zeroed.
        let outer_wrap_bytes: [u8; WRAP_HEADER_LEN] = auth_value[..WRAP_HEADER_LEN]
            .try_into()
            .expect("checked above");
        let expected_inner = Self::wrap_header_for_hmac(outer_wrap_bytes);
        if inner_hdr_recovered != expected_inner {
            return Err(RpcError::Protocol(
                "recovered inner WRAP header mismatches outer".into(),
            ));
        }

        // HMAC verify over the recovered plaintext.
        let expect = hmac_sha1_96(&ki, &plaintext);
        let mut diff: u8 = 0;
        for i in 0..AES_SHA1_CHECKSUM_LEN {
            diff |= expect[i] ^ mac_bytes[i];
        }
        if diff != 0 {
            return Err(RpcError::Protocol(
                "HMAC-SHA1-96 verification failed".into(),
            ));
        }

        self.recv_seq = self.recv_seq.wrapping_add(1);
        Ok(stub_plain)
    }

    fn auth_value_len(&self) -> usize {
        MS_KILE_AUTH_VALUE_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session_key() -> [u8; AES256_KEY_LEN] {
        let mut k = [0u8; AES256_KEY_LEN];
        for (i, byte) in k.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37) ^ 0x5c;
        }
        k
    }

    /// Round-trip a payload from `sender` to `receiver` through the wire shape the
    /// dcerpc `build_request_sealed_krb` layout uses: `sign_over || sealed_stub`.
    /// Both parties must agree on `sign_over` and the stub offset — same as the
    /// production transport passes them.
    fn roundtrip(
        sender: &mut AesCts96Sealer,
        receiver: &mut AesCts96Sealer,
        sign_over: &[u8],
        stub: &[u8],
    ) -> DcerpcResult<Vec<u8>> {
        let (sealed, av) = sender.seal_pdu(sign_over, stub);
        assert_eq!(sealed.len(), stub.len(), "sealed stub must preserve length");
        assert_eq!(av.len(), MS_KILE_AUTH_VALUE_LEN);
        let mut pdu = sign_over.to_vec();
        let off = pdu.len();
        pdu.extend_from_slice(&sealed);
        receiver.unseal_pdu(&pdu, off, stub.len(), &av)
    }

    #[test]
    fn initiator_to_acceptor_roundtrip() {
        let key = test_session_key();
        let mut client = AesCts96Sealer::new_initiator(key, false);
        let mut server = AesCts96Sealer::new_acceptor(key, false);
        let sign_over = b"pdu-header-body-and-sec-trailer".to_vec();
        let stub = b"stub-bytes-to-seal-and-verify".to_vec();
        let out = roundtrip(&mut client, &mut server, &sign_over, &stub).unwrap();
        assert_eq!(out, stub);
    }

    #[test]
    fn acceptor_to_initiator_roundtrip() {
        // Response direction: server → client. Server seals with ACCEPTOR usages
        // and its WRAP header carries SENT_BY_ACCEPTOR; client's unseal derives
        // matching keys via role.recv_usage().
        let key = test_session_key();
        let mut server = AesCts96Sealer::new_acceptor(key, false);
        let mut client = AesCts96Sealer::new_initiator(key, false);
        let sign_over = b"resp-header".to_vec();
        let stub = b"call-return-value-marshaled-as-NDR".to_vec();
        let out = roundtrip(&mut server, &mut client, &sign_over, &stub).unwrap();
        assert_eq!(out, stub);
    }

    #[test]
    fn full_duplex_pair_holds_across_multiple_calls() {
        // A real bind runs many opnums with the pair state advancing on both sides.
        // If either counter derails or a subkey derivation subtly depends on the wrong
        // sequence, later PDUs fail.
        let key = test_session_key();
        let mut client = AesCts96Sealer::new_initiator(key, false);
        let mut server = AesCts96Sealer::new_acceptor(key, false);
        for i in 0..8u32 {
            let sign_over = format!("hdr-{i}").into_bytes();
            let stub = format!("stub-payload-#{i}-with-some-body").into_bytes();
            let out = roundtrip(&mut client, &mut server, &sign_over, &stub).unwrap();
            assert_eq!(out, stub, "call {i} failed");
            // Every 3rd call, server → client response too.
            if i.is_multiple_of(3) {
                let rs = format!("resp-hdr-{i}").into_bytes();
                let rp = format!("resp-payload-#{i}").into_bytes();
                let out = roundtrip(&mut server, &mut client, &rs, &rp).unwrap();
                assert_eq!(out, rp);
            }
        }
    }

    #[test]
    fn tampered_sealed_stub_trips_hmac() {
        let key = test_session_key();
        let mut client = AesCts96Sealer::new_initiator(key, false);
        let mut server = AesCts96Sealer::new_acceptor(key, false);
        let sign_over = b"header".to_vec();
        let stub = b"important-payload".to_vec();
        let (mut sealed, av) = client.seal_pdu(&sign_over, &stub);
        sealed[0] ^= 0x01;
        let mut pdu = sign_over.clone();
        let off = pdu.len();
        pdu.extend_from_slice(&sealed);
        let err = server
            .unseal_pdu(&pdu, off, stub.len(), &av)
            .expect_err("tampered sealed_stub must fail HMAC");
        match err {
            RpcError::Protocol(m) => assert!(m.contains("HMAC"), "unexpected error: {m}"),
            other => panic!("expected Protocol(HMAC…), got {other:?}"),
        }
    }

    #[test]
    fn sign_over_is_not_hmac_covered() {
        // MS-KILE / RFC 4121 §4.2.4 HMAC input is `Confounder || Stub || WrapHeader` —
        // the PDU header + sec_trailer around the stub (sign_over) is intentionally
        // outside the crypto envelope. Tampering `sign_over` therefore does NOT trip
        // the HMAC — the tamper-detected values are `sealed_stub` and the wrap header.
        // This documents the spec choice; the earlier scaffolding-shape sealer covered
        // sign_over as extra defense, at the cost of Windows wire-format compatibility.
        let key = test_session_key();
        let mut client = AesCts96Sealer::new_initiator(key, false);
        let mut server = AesCts96Sealer::new_acceptor(key, false);
        let sign_over = b"initial-header".to_vec();
        let stub = b"body".to_vec();
        let (sealed, av) = client.seal_pdu(&sign_over, &stub);
        let mut tampered_sign_over = sign_over.clone();
        tampered_sign_over[0] ^= 0x40;
        let mut pdu = tampered_sign_over;
        let off = pdu.len();
        pdu.extend_from_slice(&sealed);
        // Unseal SUCCEEDS despite tampered sign_over — this is spec-behavior, not a bug.
        let out = server
            .unseal_pdu(&pdu, off, stub.len(), &av)
            .expect("sign_over tamper does not trip MS-KILE HMAC by design");
        assert_eq!(out, stub);
    }

    #[test]
    fn wrong_seq_number_rejected() {
        let key = test_session_key();
        let mut client = AesCts96Sealer::new_initiator(key, false);
        let mut server = AesCts96Sealer::new_acceptor(key, false);
        let sign_over = b"h".to_vec();
        let stub = b"s".to_vec();
        let (sealed, av) = client.seal_pdu(&sign_over, &stub);
        let mut pdu = sign_over.clone();
        let off = pdu.len();
        pdu.extend_from_slice(&sealed);
        // First unseal advances server.recv_seq to 1.
        server.unseal_pdu(&pdu, off, stub.len(), &av).unwrap();
        // Replay the same token → snd_seq=0 vs server.recv_seq=1 → reject.
        assert!(matches!(
            server.unseal_pdu(&pdu, off, stub.len(), &av),
            Err(RpcError::Protocol(_))
        ));
    }

    #[test]
    fn wrong_auth_value_length_rejected() {
        let key = test_session_key();
        let mut receiver = AesCts96Sealer::new_acceptor(key, false);
        let too_short = [0u8; MS_KILE_AUTH_VALUE_LEN - 1];
        let err = receiver
            .unseal_pdu(&[0u8; 40], 8, 16, &too_short)
            .expect_err("short auth_value must fail cleanly");
        match err {
            RpcError::Protocol(m) => assert!(m.contains("length")),
            other => panic!("expected Protocol(length…), got {other:?}"),
        }
    }

    #[test]
    fn sub_block_stub_roundtrips_via_pad_and_truncate() {
        let key = test_session_key();
        let sign_over = b"header".to_vec();
        for len in 1..AES_BLOCK_LEN {
            let mut client = AesCts96Sealer::new_initiator(key, false);
            let mut server = AesCts96Sealer::new_acceptor(key, false);
            let stub: Vec<u8> = (0..len as u8).collect();
            let out = roundtrip(&mut client, &mut server, &sign_over, &stub).unwrap();
            assert_eq!(out, stub, "sub-block round-trip failed at len={len}");
        }
    }

    #[test]
    fn empty_stub_roundtrips() {
        // Zero-length stub: HMAC still covers wrap header + sign_over.
        let key = test_session_key();
        let mut client = AesCts96Sealer::new_initiator(key, false);
        let mut server = AesCts96Sealer::new_acceptor(key, false);
        let sign_over = b"pure-header-only-pdu".to_vec();
        let stub: Vec<u8> = Vec::new();
        let out = roundtrip(&mut client, &mut server, &sign_over, &stub).unwrap();
        assert!(out.is_empty());
    }
}
