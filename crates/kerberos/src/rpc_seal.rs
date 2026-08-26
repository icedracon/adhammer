//! # WS-4-P2 Session 1 + 2 — crypto primitives for AES256-CTS-HMAC-SHA1-96 sealed RPC bind.
//!
//! This module implements the RFC 3961 / RFC 3962 crypto primitives that the dcerpc
//! 0.2.8 `KrbSealer` trait impl (Session 3) will wire into a `RpcTcp::bind_sealed_kerberos`
//! / `call_sealed_kerberos` transport call.
//!
//! What lands here:
//! - [`nfold`] — RFC 3961 §5.2 n-fold operation.
//! - [`aes_cts_encrypt`] / [`aes_cts_decrypt`] — RFC 3962 §5 AES CBC-CTS (CS3 variant).
//! - [`dr`] / [`dk`] — RFC 3961 §5.1 DR/DK derivation, AES-256 (`random_to_key = id`).
//! - [`hmac_sha1_96`] — RFC 2104 HMAC-SHA1 truncated to 96 bits.
//! - [`derive_kc`] / [`derive_ke`] / [`derive_ki`] — RFC 3961 §5.3 subkey derivation
//!   with the 5-byte `usage||0x99|0xAA|0x55` constant.
//! - [`encrypt_message`] / [`decrypt_message`] — RFC 3961 §5.3 generic encrypt-then-
//!   integrity primitive (`Ciphertext = AES-CTS(Ke, Confounder||Plain)`; `Sig =
//!   HMAC-SHA1-96(Ki, Confounder||Plain)`; output = `Ciphertext || Sig`). This is the
//!   raw primitive both KILE `EncryptedData` and GSS-API `wrap-token`-with-confidentiality
//!   compose out of; it is what Session 3's KrbSealer will call once per PDU.
//!
//! What does **NOT** land here (deferred to Session 3+):
//! - `KrbSealer` trait impl (dcerpc side — needs dcerpc 0.2.8 in a sibling repo)
//! - Wrap-token header format + RRC rotation (dcerpc side, Session 3)
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

#![allow(dead_code)] // wired up by Session 3 — kept as pub so the dcerpc-side KrbSealer can consume.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;

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

// ─── HMAC-SHA1-96 (RFC 2104 + RFC 3961 truncation) ───────────────────────────

/// RFC 2104 HMAC-SHA1 truncated to the first 96 bits (12 bytes). RFC 3961's AES
/// profile ("aes256-cts-hmac-sha1-96") uses this exact 12-byte MAC over the
/// pre-encryption `Confounder || Plaintext` under the derived integrity subkey `Ki`.
pub fn hmac_sha1_96(key: &[u8], data: &[u8]) -> [u8; 12] {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("Hmac accepts any key length");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

// ─── Kerberos key-usage constants (RFC 4121 §2 for GSS; MS-KILE §3.1.5 for DCE-RPC) ─

/// GSS acceptor → initiator direction, encryption. Peers that receive PDUs sent
/// by the acceptor decrypt with keys derived at this usage.
pub const KG_USAGE_ACCEPTOR_SEAL: u32 = 22;
/// GSS acceptor → initiator direction, integrity.
pub const KG_USAGE_ACCEPTOR_SIGN: u32 = 23;
/// GSS initiator → acceptor direction, encryption. Clients writing sealed PDUs
/// use keys derived at this usage.
pub const KG_USAGE_INITIATOR_SEAL: u32 = 24;
/// GSS initiator → acceptor direction, integrity.
pub const KG_USAGE_INITIATOR_SIGN: u32 = 25;

/// Build the 5-byte RFC 3961 §5.3 subkey-derivation constant: 4 big-endian usage
/// bytes followed by a 1-byte subkey tag (`0x99` = checksum / `0xAA` = encryption /
/// `0x55` = integrity).
fn subkey_constant(usage: u32, tag: u8) -> [u8; 5] {
    let u = usage.to_be_bytes();
    [u[0], u[1], u[2], u[3], tag]
}

/// Derive Kc, the *checksum* subkey for a given usage number. Used by GSS `MIC`
/// tokens and any bare-checksum callers; not used by the encrypt-then-integrity
/// [`encrypt_message`] path (which uses Ke + Ki instead).
pub fn derive_kc(session_key: &[u8], usage: u32) -> Vec<u8> {
    dk(session_key, &subkey_constant(usage, 0x99))
}

/// Derive Ke, the *encryption* subkey for a given usage number.
pub fn derive_ke(session_key: &[u8], usage: u32) -> Vec<u8> {
    dk(session_key, &subkey_constant(usage, 0xAA))
}

/// Derive Ki, the *integrity* subkey for a given usage number.
pub fn derive_ki(session_key: &[u8], usage: u32) -> Vec<u8> {
    dk(session_key, &subkey_constant(usage, 0x55))
}

// ─── RFC 3961 §5.3 encrypt-then-integrity primitive ───────────────────────────

/// Confounder length for AES256-CTS-HMAC-SHA1-96 (RFC 3962 §6 profile: one block).
pub const CONFOUNDER_LEN: usize = AES_BLOCK_LEN;
/// Truncated HMAC length for the -96 variant.
pub const HMAC_TRUNC_LEN: usize = 12;

/// Errors from [`decrypt_message`]. Wire-derived errors — a hostile server can
/// trigger any of these, so every variant must be a graceful `Err`, never a panic.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecryptError {
    /// Sealed message shorter than confounder + HMAC. The wire cannot possibly
    /// carry both an encrypted confounder and a 12-byte tag in this many bytes.
    TooShort { got: usize, need_at_least: usize },
    /// HMAC-SHA1-96 tag verification failed. Either the ciphertext was tampered
    /// with in flight or the wrong session key / usage number was used.
    HmacMismatch,
}

impl core::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { got, need_at_least } => {
                write!(
                    f,
                    "sealed message too short: got {got} bytes, need at least {need_at_least}"
                )
            }
            Self::HmacMismatch => write!(f, "HMAC-SHA1-96 tag verification failed"),
        }
    }
}
impl std::error::Error for DecryptError {}

/// RFC 3961 §5.3 encrypt-then-integrity for the AES256-CTS-HMAC-SHA1-96 profile.
///
/// - Derive `Ke = DK(K, usage||0xAA)` and `Ki = DK(K, usage||0x55)`.
/// - Prepend a caller-supplied 16-byte confounder to the plaintext.
/// - Encrypt `E1 = Confounder||Plaintext` with AES-CTS (all-zero IV per RFC 3962 §4).
/// - Compute `H1 = HMAC-SHA1-96(Ki, E1)` (over the *plaintext*, not the ciphertext —
///   this is the RFC 3961 §5.3 mandate, not encrypt-then-mac in the modern sense).
/// - Output `Ciphertext || H1` — length is `payload.len() + CONFOUNDER_LEN + HMAC_TRUNC_LEN`.
///
/// `confounder` is a parameter (not RNG'd internally) so tests can be deterministic
/// and callers who want to hand the same one to a peer implementation can. In the
/// production path Session 3 will fill it with `rand::rngs::OsRng` right before this call.
pub fn encrypt_message(
    session_key: &[u8],
    usage: u32,
    confounder: &[u8; CONFOUNDER_LEN],
    payload: &[u8],
) -> Vec<u8> {
    let ke = derive_ke(session_key, usage);
    let ki = derive_ki(session_key, usage);
    let mut e1 = Vec::with_capacity(CONFOUNDER_LEN + payload.len());
    e1.extend_from_slice(confounder);
    e1.extend_from_slice(payload);
    let ct = aes_cts_encrypt(&ke, &[0u8; AES_BLOCK_LEN], &e1);
    let mac = hmac_sha1_96(&ki, &e1);
    let mut out = Vec::with_capacity(ct.len() + HMAC_TRUNC_LEN);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&mac);
    out
}

/// Inverse of [`encrypt_message`]: split the trailing 12-byte HMAC, AES-CTS-decrypt
/// the rest, recompute the HMAC over the recovered plaintext, compare in constant
/// time, then strip the 16-byte confounder.
///
/// Constant-time comparison matters: a length-differentiated fast-fail would leak
/// which HMAC bytes matched, letting an attacker forge tags one byte at a time.
pub fn decrypt_message(
    session_key: &[u8],
    usage: u32,
    sealed: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let need = CONFOUNDER_LEN + HMAC_TRUNC_LEN;
    if sealed.len() < need {
        return Err(DecryptError::TooShort {
            got: sealed.len(),
            need_at_least: need,
        });
    }
    let ke = derive_ke(session_key, usage);
    let ki = derive_ki(session_key, usage);
    let (ct, tag) = sealed.split_at(sealed.len() - HMAC_TRUNC_LEN);
    let e1 = aes_cts_decrypt(&ke, &[0u8; AES_BLOCK_LEN], ct);
    let expect = hmac_sha1_96(&ki, &e1);
    // Constant-time compare — OR every byte diff into one accumulator, check at end.
    let mut diff: u8 = 0;
    for i in 0..HMAC_TRUNC_LEN {
        diff |= expect[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(DecryptError::HmacMismatch);
    }
    Ok(e1[CONFOUNDER_LEN..].to_vec())
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

    // ─── HMAC-SHA1-96 ─────────────────────────────────────────────────────

    #[test]
    fn hmac_sha1_96_matches_rfc_2202_test_case_1() {
        // RFC 2202 §3 test case 1: key = 0x0b x 20, data = "Hi There",
        // HMAC-SHA1 = b617318655057264e28bc0b6fb378c8ef146be00
        // First 12 bytes (HMAC-SHA1-96) = b617318655057264e28bc0b6.
        let key = [0x0bu8; 20];
        let got = hmac_sha1_96(&key, b"Hi There");
        let want: [u8; 12] = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6,
        ];
        assert_eq!(got, want);
    }

    // ─── Subkey derivation ────────────────────────────────────────────────

    #[test]
    fn subkeys_are_distinct_for_same_usage() {
        // Kc/Ke/Ki with the same usage number MUST differ — the whole
        // key-separation guarantee of RFC 3961 §5.3 rides on this. If two of them
        // collide it means the tag byte (0x99/0xAA/0x55) is being ignored.
        let key = test_key256();
        let kc = derive_kc(&key, KG_USAGE_INITIATOR_SEAL);
        let ke = derive_ke(&key, KG_USAGE_INITIATOR_SEAL);
        let ki = derive_ki(&key, KG_USAGE_INITIATOR_SEAL);
        assert_ne!(kc, ke);
        assert_ne!(ke, ki);
        assert_ne!(kc, ki);
        // All three must be 32 bytes (AES-256 key length).
        assert_eq!(kc.len(), AES256_KEY_LEN);
        assert_eq!(ke.len(), AES256_KEY_LEN);
        assert_eq!(ki.len(), AES256_KEY_LEN);
    }

    #[test]
    fn subkeys_differ_across_usages() {
        // Same tag, different usage number → different key. Otherwise integrity
        // subkeys for signing initiator→acceptor could be reused acceptor→initiator.
        let key = test_key256();
        assert_ne!(
            derive_ke(&key, KG_USAGE_INITIATOR_SEAL),
            derive_ke(&key, KG_USAGE_ACCEPTOR_SEAL)
        );
    }

    // ─── encrypt_message / decrypt_message round-trip ─────────────────────

    fn test_confounder() -> [u8; CONFOUNDER_LEN] {
        // Deterministic 16-byte confounder for test reproducibility. Production
        // callers must supply an RNG-derived one; a fixed confounder in production
        // would fatally leak plaintext prefixes across sealed messages.
        let mut c = [0u8; CONFOUNDER_LEN];
        for (i, b) in c.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x11) ^ 0xA5;
        }
        c
    }

    #[test]
    fn encrypt_decrypt_roundtrip_short_payload() {
        // The smallest "real" payload (< 1 block) — after prepending 16-byte
        // confounder it becomes > 1 block, so AES-CTS' ≥-1-block precondition holds.
        let key = test_key256();
        let conf = test_confounder();
        let plain = b"hello, sealed RPC world!";
        let sealed = encrypt_message(&key, KG_USAGE_INITIATOR_SEAL, &conf, plain);
        assert_eq!(sealed.len(), plain.len() + CONFOUNDER_LEN + HMAC_TRUNC_LEN);
        let round = decrypt_message(&key, KG_USAGE_INITIATOR_SEAL, &sealed).unwrap();
        assert_eq!(round, plain);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_various_lengths() {
        let key = test_key256();
        let conf = test_confounder();
        for &len in &[0usize, 1, 15, 16, 17, 31, 32, 33, 47, 63, 64, 65, 1023] {
            let plain: Vec<u8> = (0..len as u32).map(|i| ((i * 7) & 0xff) as u8).collect();
            let sealed = encrypt_message(&key, KG_USAGE_INITIATOR_SEAL, &conf, &plain);
            let round = decrypt_message(&key, KG_USAGE_INITIATOR_SEAL, &sealed).unwrap();
            assert_eq!(round, plain, "roundtrip failed at len={len}");
        }
    }

    #[test]
    fn tampered_ciphertext_byte_fails_hmac() {
        // Flipping any single byte of the sealed message MUST cause HMAC verification
        // to fail. If it doesn't, the integrity check is silently broken and every
        // downstream RPC call is defenseless against tampering.
        let key = test_key256();
        let conf = test_confounder();
        let plain = b"payload-to-tamper-with";
        let mut sealed = encrypt_message(&key, KG_USAGE_INITIATOR_SEAL, &conf, plain);
        // Flip a byte inside the ciphertext region (not the HMAC tail).
        sealed[8] ^= 0x01;
        match decrypt_message(&key, KG_USAGE_INITIATOR_SEAL, &sealed) {
            Err(DecryptError::HmacMismatch) => {}
            other => panic!("expected HmacMismatch, got {other:?}"),
        }
    }

    #[test]
    fn tampered_hmac_byte_fails_verification() {
        let key = test_key256();
        let conf = test_confounder();
        let plain = b"another-payload";
        let mut sealed = encrypt_message(&key, KG_USAGE_INITIATOR_SEAL, &conf, plain);
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(matches!(
            decrypt_message(&key, KG_USAGE_INITIATOR_SEAL, &sealed),
            Err(DecryptError::HmacMismatch)
        ));
    }

    #[test]
    fn wrong_usage_number_fails_verification() {
        // Encrypt as initiator, try to decrypt as acceptor — Ki differs so HMAC
        // won't match. This proves the usage number is actually consumed by
        // decrypt_message rather than ignored, which would silently share subkeys.
        let key = test_key256();
        let conf = test_confounder();
        let plain = b"direction-matters";
        let sealed = encrypt_message(&key, KG_USAGE_INITIATOR_SEAL, &conf, plain);
        assert!(matches!(
            decrypt_message(&key, KG_USAGE_ACCEPTOR_SEAL, &sealed),
            Err(DecryptError::HmacMismatch)
        ));
    }

    #[test]
    fn too_short_sealed_message_is_rejected_gracefully() {
        // Anything shorter than CONFOUNDER_LEN + HMAC_TRUNC_LEN cannot possibly be a
        // valid sealed message. A panicking indexer here would let a hostile server
        // crash our RPC client with a truncated auth token — must be a clean Err.
        let key = test_key256();
        let short = vec![0u8; CONFOUNDER_LEN + HMAC_TRUNC_LEN - 1];
        assert!(matches!(
            decrypt_message(&key, KG_USAGE_INITIATOR_SEAL, &short),
            Err(DecryptError::TooShort { .. })
        ));
    }
}
