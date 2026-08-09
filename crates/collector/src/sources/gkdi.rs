//! GKDI seed-key parsers wrapped for the collector.
//!
//! [`ms_gkdi`] owns the wire structs (`KEY_IDENTIFIER`, `GROUP_KEY_ENVELOPE`),
//! the SP800-108 KDF, and the L0/L1/L2 tree walk. This module reuses those
//! types and adds a single-step convenience: given a raw LAPS-v2 (or gMSA)
//! blob header + the `GetKey` envelope, derive the L2 key that opens it.
//!
//! No live-DC I/O — the `GetKey` RPC caller stays in [`ms_gkdi::rpc`]. adhammer's
//! `attack laps` code path already handles the sealed `ISDKey` transport via
//! the mature `dpapi-ng` route; this module is the offline seed-key math the
//! decrypter sits on top of.

use ms_gkdi::gkdi::{compute_l2_key, GroupKeyEnvelope, KeyIdentifier};
use ms_gkdi::GkdiError;

/// Re-exported so callers can pattern-match on GKDI errors without adding a
/// direct dep on `ms-gkdi`.
pub use ms_gkdi::GkdiError as Error;

/// Parse the raw `KEY_IDENTIFIER` structure (the header of a LAPS-v2 or gMSA
/// managed-password blob's `ProtectedData` field).
pub fn parse_key_identifier(bytes: &[u8]) -> Result<KeyIdentifier, GkdiError> {
    KeyIdentifier::parse(bytes)
}

/// Parse a `GROUP_KEY_ENVELOPE` (what an `ISDKey::GetKey` RPC returns).
pub fn parse_group_key_envelope(bytes: &[u8]) -> Result<GroupKeyEnvelope, GkdiError> {
    GroupKeyEnvelope::parse(bytes)
}

/// Given a `KeyIdentifier` (from the encrypted blob) and a `GroupKeyEnvelope`
/// (from `GetKey`), derive the L2 seed key that decrypts the payload. Pure
/// computation — no I/O.
///
/// The envelope's `(l0, l1, l2)` must be at-or-above the identifier's node in
/// the tree — that's the invariant `ISDKey::GetKey` guarantees on a healthy DC.
pub fn derive_l2_key(id: &KeyIdentifier, env: &GroupKeyEnvelope) -> Result<Vec<u8>, GkdiError> {
    if env.root_key_id != id.root_key_id {
        return Err(GkdiError::MissingSeedKey("root key id mismatch"));
    }
    compute_l2_key(env, id.l1, id.l2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_identifier() {
        let short = [0u8; 4];
        let err = parse_key_identifier(&short).expect_err("must fail on truncated");
        assert!(matches!(err, GkdiError::Truncated(_)));
    }

    #[test]
    fn rejects_bad_magic() {
        // 4 bytes version, 4 bytes bogus magic, and enough padding for the parser to
        // reach the magic check.
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let err = parse_key_identifier(&buf).expect_err("must fail on bad magic");
        assert!(
            matches!(
                err,
                GkdiError::BadMagic {
                    got: 0xDEAD_BEEF,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn round_trips_synthesized_identifier() {
        // A valid KeyIdentifier with the crate's own to_bytes round-trip proves the
        // wrapper is on the same wire dialect as `ms_gkdi`.
        let id = KeyIdentifier {
            version: 1,
            flags: 0,
            l0: 361,
            l1: 12,
            l2: 30,
            root_key_id: ms_gkdi::gkdi::RootKeyId([0x11; 16]),
            kdf_algorithm: "SP800_108_CTR_HMAC".into(),
            kdf_parameters: vec![],
            secret_algorithm: "DH".into(),
            secret_parameters: vec![],
            private_key_length: 512,
            public_key_length: 2048,
            domain_name: "corp.local".into(),
            forest_name: "corp.local".into(),
        };
        let bytes = id.to_bytes();
        let parsed = parse_key_identifier(&bytes).expect("round-trip parse");
        assert_eq!(parsed, id);
    }
}
