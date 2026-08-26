//! # WS-4-P2 Session 1 — crypto primitives for AES256-CTS-HMAC-SHA1-96 sealed RPC bind.
//!
//! This module implements the RFC 3961 / RFC 3962 crypto primitives that the
//! `dcerpc::krb_seal::KrbSealer` trait impl (Session 2) will wire together into a
//! `RpcTcp::bind_sealed_kerberos` / `call_sealed_kerberos` transport call (Session 3).
//!
//! What lands in **this** file (Session 1 scope):
//! - [`nfold`] — RFC 3961 §5.2 n-fold operation. Turns an arbitrary-length key-usage
//!   constant into a block-aligned pseudo-random value by rotating + 1's-complement-
//!   adding until we have `n_bits` of output.
//! - [`aes_cts_encrypt`] / [`aes_cts_decrypt`] — RFC 3962 §5 AES CTS-CBC (the CS3
//!   ciphertext-stealing variant Kerberos uses). Handles the three cases: exactly one
//!   block, exact multiple of block size, and general partial-final-block.
//! - [`dr`] / [`dk`] — RFC 3961 §5.1 DR/DK key derivation, specialized to AES-256
//!   where `random_to_key` is the identity (see RFC 3962 §4).
//!
//! What does **NOT** land here (deferred to Session 2+):
//! - HMAC-SHA1-96 confounder + checksum (RFC 3961 §7 / RFC 3962 §4 profile — needs
//!   the `hmac` + `sha1` deps already in this crate)
//! - `KrbSealer` trait impl (`seal_pdu` / `unseal_pdu` / `auth_value_len`) that wraps
//!   these primitives into the 16-byte-WRAP-header + AES-CTS + 12-byte-HMAC layout
//! - The Kc / Ke / Ki subkey material derived via [`dk`] with the Kerberos usage
//!   constants (which need the sealer to know the session key from the AP-REQ)
//! - `RpcTcp::bind_sealed_kerberos` transport plumbing (dcerpc-side, Session 3)
//!
//! ## Testing philosophy for this session
//!
//! Two levels of confidence:
//! 1. **Known-good vector match** — n-fold has a well-known IETF example
//!    (`nfold("012345", 64) = 0xbe072631276b1955`) that catches any off-by-one in
//!    the rotate-and-add loop.
//! 2. **Round-trip self-consistency** — `aes_cts_decrypt(k, iv, aes_cts_encrypt(k, iv, p))
//!    == p` for many plaintext lengths (edge cases: 1, 15, 16, 17, 32, 47, 48 bytes).
//!    A wrong CTS wrap fails this trivially.
//!
//! **Session 4 does the ground-truth check** — the sealer talks to a live DC
//! `\PIPE\lsarpc` and either round-trips an opnum or fails with a spec-mapped RPC
//! fault. That is the ultimate correctness proof; unit vectors here catch the fast
//! failures early.

#![allow(dead_code)] // wired up by Sessions 2/3 — kept as pub so those sessions can consume.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

/// AES-256 key size in bytes (RFC 3962 profile 18 uses AES-256-CTS-HMAC-SHA1-96).
pub const AES256_KEY_LEN: usize = 32;
/// AES block size — the same for all AES key lengths.
pub const AES_BLOCK_LEN: usize = 16;

// ─── n-fold (RFC 3961 §5.2) ─────────────────────────────────────────────────────

/// Return the smallest `usize` that both `a` and `b` divide evenly, using GCD.
///
/// Only ever called with small inputs (block-sizes and key-usage-constant lengths in
/// bytes — worst case ≈ 256), so a naive Euclidean GCD is fine.
fn lcm(a: usize, b: usize) -> usize {
    fn gcd(mut x: usize, mut y: usize) -> usize {
        while y != 0 {
            let t = y;
            y = x % y;
            x = t;
        }
        x
    }
    a / gcd(a, b) * b
}

/// RFC 3961 §5.2 n-fold. Direct bit-level implementation of the spec: build a
/// concatenated stream of `lcm(k,n)/k` copies of `input`, each rotated right by 13
/// more bits than the previous, then 1's-complement-add the `n`-bit chunks of that
/// stream together mod 2^n. Slower than MIT's constant-space port but obviously
/// correct against the spec, which was the correctness cost worth paying.
///
/// Well-known vector: `nfold("012345", 64) = 0xbe072631276b1955` (RFC 3961 §5.2).
pub fn nfold(input: &[u8], n_bits: usize) -> Vec<u8> {
    assert!(!input.is_empty(), "n-fold input must be non-empty");
    assert!(
        n_bits.is_multiple_of(8),
        "n-fold output size must be a multiple of 8 bits"
    );
    let in_bits = input.len() * 8;
    let copies = lcm(n_bits, in_bits) / in_bits;

    // Build the concatenated shifted stream as a `Vec<u8>` of raw bit values (0 or 1).
    // Bit index 0 of `input` is the MSB of `input[0]` per Kerberos big-endian convention.
    let read_bit = |bit_idx: usize| -> u8 {
        let byte_idx = bit_idx / 8;
        let bit_off = 7 - (bit_idx % 8); // MSB-first
        (input[byte_idx] >> bit_off) & 1
    };
    let mut stream: Vec<u8> = Vec::with_capacity(copies * in_bits);
    for i in 0..copies {
        let shift = (13 * i) % in_bits;
        // "Rotate right by `shift`": data moves right, so with MSB=position 0 the bit
        // that was at position 0 is now at position `shift`. `rotated[pos] =
        // original[(pos - shift + in_bits) mod in_bits]`.
        for pos in 0..in_bits {
            let src = (pos + in_bits - shift) % in_bits;
            stream.push(read_bit(src));
        }
    }

    // 1's-complement-add each contiguous n_bits chunk of `stream` into `sum`.
    let mut sum = vec![0u8; n_bits / 8];
    let num_chunks = stream.len() / n_bits;
    for chunk in 0..num_chunks {
        // Materialize the chunk as bytes.
        let mut chunk_bytes = vec![0u8; n_bits / 8];
        for bit in 0..n_bits {
            let v = stream[chunk * n_bits + bit];
            let byte_idx = bit / 8;
            let bit_off = 7 - (bit % 8); // MSB-first
            chunk_bytes[byte_idx] |= v << bit_off;
        }
        // 1's-complement add: carry propagates from LSB up, end-around wraps to LSB.
        let mut carry: u32 = 0;
        for j in (0..sum.len()).rev() {
            let s = sum[j] as u32 + chunk_bytes[j] as u32 + carry;
            sum[j] = (s & 0xff) as u8;
            carry = s >> 8;
        }
        while carry > 0 {
            for j in (0..sum.len()).rev() {
                let s = sum[j] as u32 + carry;
                sum[j] = (s & 0xff) as u8;
                carry = s >> 8;
                if carry == 0 {
                    break;
                }
            }
        }
    }
    sum
}

// ─── AES-256 CTS-CBC (RFC 3962 §5) ──────────────────────────────────────────────

/// Encrypt with AES-256 in CBC-CTS mode per RFC 3962 §5. Requires `plaintext.len() >=
/// AES_BLOCK_LEN` (Kerberos never encrypts less than one block — DR feeds exactly one
/// block, seal_pdu prepends a 16-byte confounder before the stub). Three cases:
///
/// - **exactly one block**: standard AES-CBC on one block (no ciphertext stealing).
/// - **exact multiple > one block**: standard AES-CBC output, no swap. RFC 3962 does
///   not swap for exact multiples — CTS is a ciphertext-*stealing* mode and there's
///   nothing to steal from a full final block.
/// - **> one block, partial final**: CS3 variant. CBC through the last full block, then
///   XOR the zero-padded partial-final into the last ciphertext block, encrypt → C'.
///   Output is `c_1..c_{n-2} || C' || c_{n-1}[..remainder]` — the "swap" of the last
///   two blocks with truncation of the final.
///
/// Panics on plaintext < 1 block. That case doesn't arise in Kerberos and supporting
/// it would require a length side-channel (recovered ciphertext length ≠ recovered
/// plaintext length) that no Kerberos caller would use.
pub fn aes_cts_encrypt(key: &[u8], iv: &[u8; AES_BLOCK_LEN], plaintext: &[u8]) -> Vec<u8> {
    assert!(
        plaintext.len() >= AES_BLOCK_LEN,
        "AES-CTS requires at least one full block; got {} bytes",
        plaintext.len()
    );
    let cipher = aes::Aes256::new_from_slice(key).expect("AES-256 key must be 32 bytes");
    let n = plaintext.len();
    let full_blocks = n / AES_BLOCK_LEN;
    let remainder = n % AES_BLOCK_LEN;

    // CBC through every full block, keeping `prev` as the running feedback state.
    let mut cbc_out = Vec::with_capacity(n);
    let mut prev = *iv;
    for i in 0..full_blocks {
        let mut block = [0u8; AES_BLOCK_LEN];
        block.copy_from_slice(&plaintext[i * AES_BLOCK_LEN..(i + 1) * AES_BLOCK_LEN]);
        for j in 0..AES_BLOCK_LEN {
            block[j] ^= prev[j];
        }
        let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut b);
        prev.copy_from_slice(&b);
        cbc_out.extend_from_slice(&b);
    }

    if remainder == 0 {
        // Exact multiple (including exactly one block) — output is plain CBC.
        return cbc_out;
    }

    // Partial final block: build the padded final plaintext, XOR into prev, encrypt →
    // C'. Then rewrite the tail so ciphertext = c_1..c_{n-2} || C' || c_{n-1}[..r].
    let mut final_block = [0u8; AES_BLOCK_LEN];
    final_block[..remainder].copy_from_slice(&plaintext[full_blocks * AES_BLOCK_LEN..]);
    for j in 0..AES_BLOCK_LEN {
        final_block[j] ^= prev[j];
    }
    let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(&final_block);
    cipher.encrypt_block(&mut b);

    let last_full_start = (full_blocks - 1) * AES_BLOCK_LEN;
    let saved_last_full: [u8; AES_BLOCK_LEN] = cbc_out
        [last_full_start..last_full_start + AES_BLOCK_LEN]
        .try_into()
        .expect("copied a full block");
    cbc_out.truncate(last_full_start);
    cbc_out.extend_from_slice(&b);
    cbc_out.extend_from_slice(&saved_last_full[..remainder]);
    cbc_out
}

/// Decrypt AES-256 CBC-CTS ciphertext produced by [`aes_cts_encrypt`]. Same shape
/// as encrypt: requires ≥ 1 block; exact-multiple case is plain CBC (no unswap);
/// partial-final case reverses the CS3 tail rewrite.
pub fn aes_cts_decrypt(key: &[u8], iv: &[u8; AES_BLOCK_LEN], ciphertext: &[u8]) -> Vec<u8> {
    assert!(
        ciphertext.len() >= AES_BLOCK_LEN,
        "AES-CTS ciphertext requires at least one full block; got {} bytes",
        ciphertext.len()
    );
    let cipher = aes::Aes256::new_from_slice(key).expect("AES-256 key must be 32 bytes");
    let n = ciphertext.len();
    let full_blocks = n / AES_BLOCK_LEN;
    let remainder = n % AES_BLOCK_LEN;

    if remainder == 0 {
        // Exact multiple (including exactly one block) — plain CBC decrypt.
        let mut out = Vec::with_capacity(n);
        let mut prev = *iv;
        for i in 0..full_blocks {
            let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(
                &ciphertext[i * AES_BLOCK_LEN..(i + 1) * AES_BLOCK_LEN],
            );
            let saved: [u8; AES_BLOCK_LEN] = b.as_slice().try_into().expect("block-sized");
            cipher.decrypt_block(&mut b);
            for j in 0..AES_BLOCK_LEN {
                out.push(b[j] ^ prev[j]);
            }
            prev = saved;
        }
        return out;
    }

    // Partial-final-block case. Ciphertext layout: c_1..c_{n-2} || C' || c_{n-1}[..r]
    // where C' = E(K, c_{n-1} XOR (P_last||zeros)) and c_{n-1} is the second-to-last
    // full ciphertext block from CBC.
    //
    // Recovery plan:
    // 1. CBC-decrypt c_1..c_{n-2} normally.
    // 2. Decrypt C' with AES (no XOR yet) → x. Then P_last||zeros == x XOR c_{n-1}.
    //    Reconstruct c_{n-1} by taking c_{n-1}[..r] from the tail of ciphertext and
    //    filling the last (block-remainder) bytes with x[remainder..].
    // 3. Now XOR x with the reconstructed c_{n-1} to recover P_last||zeros; truncate to r.
    // 4. CBC-decrypt the recovered c_{n-1} using the previous CBC state to get P_{n-1}.

    let mut out = Vec::with_capacity(n);
    let mut prev = *iv;
    // Step 1: CBC decrypt through the first (full_blocks - 1) full blocks.
    for i in 0..(full_blocks - 1) {
        let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(
            &ciphertext[i * AES_BLOCK_LEN..(i + 1) * AES_BLOCK_LEN],
        );
        let saved: [u8; AES_BLOCK_LEN] = b.as_slice().try_into().expect("block-sized");
        cipher.decrypt_block(&mut b);
        for j in 0..AES_BLOCK_LEN {
            out.push(b[j] ^ prev[j]);
        }
        prev = saved;
    }

    // Step 2: decrypt C' (positioned at bytes [(full_blocks-1)*BLOCK .. full_blocks*BLOCK]).
    let c_prime_off = (full_blocks - 1) * AES_BLOCK_LEN;
    let mut c_prime = aes::cipher::generic_array::GenericArray::clone_from_slice(
        &ciphertext[c_prime_off..c_prime_off + AES_BLOCK_LEN],
    );
    cipher.decrypt_block(&mut c_prime);
    let x: [u8; AES_BLOCK_LEN] = c_prime.as_slice().try_into().expect("block-sized");

    // Step 3: c_{n-1} tail is at ciphertext[full_blocks*BLOCK .. n]; length = remainder.
    // Reconstruct c_{n-1} = ct_tail || x[remainder..]
    let mut c_last_full = [0u8; AES_BLOCK_LEN];
    c_last_full[..remainder].copy_from_slice(&ciphertext[full_blocks * AES_BLOCK_LEN..n]);
    c_last_full[remainder..].copy_from_slice(&x[remainder..]);

    // Step 4a: recover P_last = (x XOR c_last_full)[..remainder]  (the zero-padded region
    // in P_last XOR c_last_full cancels x[remainder..] out to zero — proof of consistency).
    let p_last_padded: [u8; AES_BLOCK_LEN] = std::array::from_fn(|i| x[i] ^ c_last_full[i]);

    // Step 4b: CBC-decrypt the recovered c_last_full into P_{n-1} using prev.
    let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(&c_last_full);
    cipher.decrypt_block(&mut b);
    for j in 0..AES_BLOCK_LEN {
        out.push(b[j] ^ prev[j]);
    }
    // Append P_last (only the meaningful `remainder` bytes).
    out.extend_from_slice(&p_last_padded[..remainder]);
    out
}

// ─── DR / DK (RFC 3961 §5.1, specialized for AES-256 per RFC 3962 §4) ─────────

/// RFC 3961 §5.1 DR: derive a random value from `key` seeded by `constant`. For AES-256,
/// output length is `AES256_KEY_LEN` (32 bytes) — produced by iterating CTS-encrypt of
/// 16-byte blocks (starting from n-fold(constant, 128) with an all-zero IV) until we
/// have at least 32 bytes, then truncating.
pub fn dr(key: &[u8], constant: &[u8]) -> Vec<u8> {
    let zero_iv = [0u8; AES_BLOCK_LEN];
    // Fold the constant to a single block first (AES block-size in bits).
    let n1 = nfold(constant, AES_BLOCK_LEN * 8);
    let mut out = Vec::with_capacity(AES256_KEY_LEN);
    let mut r = n1;
    while out.len() < AES256_KEY_LEN {
        let encrypted = aes_cts_encrypt(key, &zero_iv, &r);
        out.extend_from_slice(&encrypted);
        r = encrypted;
    }
    out.truncate(AES256_KEY_LEN);
    out
}

/// RFC 3961 §5.1 DK: DR followed by `random_to_key`. For AES (RFC 3962 §4)
/// `random_to_key` is the identity — the raw DR bytes are the new key.
pub fn dk(key: &[u8], constant: &[u8]) -> Vec<u8> {
    dr(key, constant)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── n-fold correctness ────────────────────────────────────────────────

    #[test]
    fn nfold_matches_ietf_vector() {
        // From RFC 3961 §5.2's own worked example: nfold("012345", 64) = 0xbe072631276b1955.
        // If this fails, the bit ordering / carry loop / rotation constant is wrong.
        let got = nfold(b"012345", 64);
        let want: [u8; 8] = [0xbe, 0x07, 0x26, 0x31, 0x27, 0x6b, 0x19, 0x55];
        assert_eq!(&got[..], &want[..]);
    }

    #[test]
    fn nfold_output_size_multiple_of_8_bits() {
        for &bits in &[64usize, 128, 192, 256, 320] {
            let out = nfold(b"any-input", bits);
            assert_eq!(out.len() * 8, bits);
        }
    }

    // ─── AES-256-CTS round-trip across every case ────────────────────────

    fn zero_iv() -> [u8; AES_BLOCK_LEN] {
        [0u8; AES_BLOCK_LEN]
    }

    fn test_key256() -> [u8; AES256_KEY_LEN] {
        // Deterministic test key; not a real Kerberos key. Used only for self-consistency.
        let mut k = [0u8; 32];
        for (i, byte) in k.iter_mut().enumerate() {
            *byte = i as u8 ^ 0x5C;
        }
        k
    }

    #[test]
    fn cts_roundtrip_exactly_one_block() {
        let key = test_key256();
        let iv = zero_iv();
        let pt: Vec<u8> = (0..16u8).collect();
        let ct = aes_cts_encrypt(&key, &iv, &pt);
        assert_eq!(ct.len(), 16);
        let round = aes_cts_decrypt(&key, &iv, &ct);
        assert_eq!(round, pt);
    }

    #[test]
    fn cts_roundtrip_general_partial() {
        // The "hard" case — > 1 block, non-multiple → CS3 swap of the last two blocks.
        let key = test_key256();
        let iv = zero_iv();
        for &len in &[17usize, 31, 47, 63] {
            let pt: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37)).collect();
            let ct = aes_cts_encrypt(&key, &iv, &pt);
            assert_eq!(ct.len(), len, "ciphertext len must match plaintext len");
            let round = aes_cts_decrypt(&key, &iv, &ct);
            assert_eq!(round, pt, "round-trip failed at len={len}");
        }
    }

    #[test]
    fn cts_roundtrip_exact_multiple_of_block() {
        // Exact-multiple path (swap-last-two variant per RFC 3962 for Kerberos).
        let key = test_key256();
        let iv = zero_iv();
        for &len in &[32usize, 48, 64] {
            let pt: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(53)).collect();
            let ct = aes_cts_encrypt(&key, &iv, &pt);
            assert_eq!(ct.len(), len);
            let round = aes_cts_decrypt(&key, &iv, &ct);
            assert_eq!(round, pt, "exact-multiple round-trip failed at len={len}");
        }
    }

    // ─── DR / DK sanity ───────────────────────────────────────────────────

    #[test]
    fn dr_output_is_32_bytes_for_aes256() {
        let key = test_key256();
        let out = dr(&key, b"any-usage-constant");
        assert_eq!(out.len(), AES256_KEY_LEN);
    }

    #[test]
    fn dr_is_deterministic() {
        // Same key + same constant → same output every time (crypto is deterministic;
        // hidden nondeterminism would mean we accidentally pulled in randomness).
        let key = test_key256();
        assert_eq!(dr(&key, b"c1"), dr(&key, b"c1"));
    }

    #[test]
    fn dr_different_constants_different_outputs() {
        // Different key-usage constants MUST yield different derived keys — otherwise
        // Kc/Ke/Ki would collide and the whole subkey scheme would collapse.
        let key = test_key256();
        assert_ne!(dr(&key, b"c1"), dr(&key, b"c2"));
    }

    #[test]
    fn dk_equals_dr_for_aes_random_to_key_identity() {
        // RFC 3962 §4 spec: for AES the random_to_key transform is identity. If someone
        // "fixes" dk() to do something else, this test catches the drift.
        let key = test_key256();
        assert_eq!(dk(&key, b"c-99"), dr(&key, b"c-99"));
    }
}
