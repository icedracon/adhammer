//! KDBX4 header parser + body extractor for [`crate::attacks::creds::kdbx_extract`].
//!
//! Given a KNOWN master password, this module runs the full KeePass
//! decryption chain: parse header + composite key + Argon2d KDF + HMAC-SHA256
//! verification of the header, then walk the body's HMAC-block sequence,
//! decrypt with the outer cipher (AES256-CBC or ChaCha20), gzip-inflate,
//! parse the inner header, and unmask each protected `<Value>` via the
//! inner ChaCha20 random stream. Brute-forcing the master password is
//! **not** in-tree — that's what `keepass2john <file> | hashcat -m 13400`
//! is for.
//!
//! References:
//! - KDBX 4.0 spec: <https://keepass.info/help/kb/kdbx_4.html>
//! - KeePass source: `Kdbx4/KdbxFile.Read.cs` + `KdbHeaderFieldID.cs`
//! - hashcat mode 13400 (KeePass): the brute-force pass adhammer defers to.

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;

pub(crate) const MAGIC1: u32 = 0x9AA2_D903;
pub(crate) const MAGIC2: u32 = 0xB54B_FB67;

/// AES-KDF UUID (legacy — pre-KDBX4 default). KDBX4 databases created by
/// KeePass 2.35+ use Argon2d by default; verifying an AES-KDF file is a
/// follow-up scoped separately since it needs the AES-256 ECB key ratchet.
pub(crate) const KDF_UUID_AES: [u8; 16] = [
    0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
];

/// Argon2d UUID (KDBX4 default). Matches `PwUuid.CreateFromBytes` for the
/// Argon2d KDF ID in KeePass source.
pub(crate) const KDF_UUID_ARGON2D: [u8; 16] = [
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
];

/// Argon2id UUID (KDBX 4.1 default on newer clients).
pub(crate) const KDF_UUID_ARGON2ID: [u8; 16] = [
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
];

#[derive(Debug)]
pub(crate) struct Kdbx4Header {
    pub minor: u16,
    pub major: u16,
    /// The header bytes as-read from the file, from offset 0 up to (but not
    /// including) the trailing SHA-256 + HMAC-SHA-256 (32 bytes each).
    pub header_bytes: Vec<u8>,
    pub master_seed: [u8; 32],
    pub kdf_uuid: [u8; 16],
    /// KDF parameters, as a name → value VariantDictionary. Argon2d uses the
    /// keys `S` (salt), `V` (version), `I` (iterations), `M` (memory bytes),
    /// `P` (parallelism); AES-KDF uses `S` and `R` (rounds).
    pub kdf_params: HashMap<String, VariantValue>,
    /// SHA-256 of `header_bytes` — sanity check that the file is intact.
    /// Verified inside `parse_header`; kept on the struct so a downstream
    /// consumer that wants to receipt-record the read has it, without
    /// touching the file a second time.
    #[allow(dead_code)]
    pub header_sha256: [u8; 32],
    /// HMAC-SHA-256 of `header_bytes` under `block_hmac_key(u64::MAX)`.
    /// This is what we recompute with the candidate password.
    pub header_hmac: [u8; 32],
    /// **F4b**: cipher UUID for the OUTER body cipher. AES256-CBC = a fixed
    /// UUID (see [`CIPHER_UUID_AES256_CBC`]); ChaCha20 = another
    /// (see [`CIPHER_UUID_CHACHA20`]).
    pub cipher_uuid: [u8; 16],
    /// **F4b**: `0` = uncompressed, `1` = gzip after decrypt (KDBX4 default).
    pub compression: u32,
    /// **F4b**: outer cipher IV. AES256-CBC needs 16 bytes; ChaCha20 needs 12.
    pub encryption_iv: Vec<u8>,
    /// **F4b**: file offset where the encrypted-body HMAC blocks start
    /// (immediately after the 32-byte HMAC that follows the header).
    pub body_offset: usize,
}

/// KDBX4 outer-cipher UUIDs.
pub(crate) const CIPHER_UUID_AES256_CBC: [u8; 16] = [
    0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
];
pub(crate) const CIPHER_UUID_CHACHA20: [u8; 16] = [
    0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A,
];

// KDBX4 VariantDictionary values — full set per the KeePass source. Only
// U32/U64/Bytes are read by the crack path today; the other variants exist
// so `parse_variant_dict` is complete when the extract path (F4b) starts
// consuming them. Suppress dead_code warnings for that reason.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum VariantValue {
    U32(u32),
    U64(u64),
    Bool(bool),
    I32(i32),
    I64(i64),
    Str(String),
    Bytes(Vec<u8>),
}

impl VariantValue {
    pub(crate) fn as_u32(&self) -> Option<u32> {
        match self {
            Self::U32(v) => Some(*v),
            Self::I32(v) => u32::try_from(*v).ok(),
            _ => None,
        }
    }
    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(v) => Some(*v),
            Self::I64(v) => u64::try_from(*v).ok(),
            Self::U32(v) => Some(u64::from(*v)),
            _ => None,
        }
    }
    pub(crate) fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

pub(crate) fn parse_header(bytes: &[u8]) -> Result<Kdbx4Header> {
    if bytes.len() < 12 + 64 {
        bail!(
            "file is too small for a KDBX header ({} bytes)",
            bytes.len()
        );
    }
    let m1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let m2 = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if m1 != MAGIC1 || m2 != MAGIC2 {
        bail!(
            "not a KDBX file (magic bytes {:08x} {:08x}, expected {:08x} {:08x})",
            m1,
            m2,
            MAGIC1,
            MAGIC2
        );
    }
    let minor = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    let major = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
    if major != 4 {
        bail!("KDBX{major}.{minor} — this pipeline targets KDBX4 only");
    }

    // Parse the TLV header fields until END (id=0).
    let mut cursor = 12usize;
    let mut master_seed: Option<[u8; 32]> = None;
    let mut kdf_params: Option<HashMap<String, VariantValue>> = None;
    let mut cipher_uuid: Option<[u8; 16]> = None;
    let mut compression: Option<u32> = None;
    let mut encryption_iv: Option<Vec<u8>> = None;
    loop {
        if cursor + 5 > bytes.len() {
            bail!("truncated header");
        }
        let field_id = bytes[cursor];
        let field_len =
            u32::from_le_bytes(bytes[cursor + 1..cursor + 5].try_into().unwrap()) as usize;
        cursor += 5;
        if cursor + field_len > bytes.len() {
            bail!("truncated header field {field_id}");
        }
        let field_bytes = &bytes[cursor..cursor + field_len];
        cursor += field_len;
        match field_id {
            0 => break, // END
            2 => {
                if field_len != 16 {
                    bail!("CipherUUID length {field_len}, expected 16");
                }
                let mut u = [0u8; 16];
                u.copy_from_slice(field_bytes);
                cipher_uuid = Some(u);
            }
            3 => {
                if field_len != 4 {
                    bail!("CompressionFlags length {field_len}, expected 4");
                }
                compression = Some(u32::from_le_bytes(field_bytes.try_into().unwrap()));
            }
            4 => {
                if field_len != 32 {
                    bail!("MasterSeed length {field_len}, expected 32");
                }
                let mut m = [0u8; 32];
                m.copy_from_slice(field_bytes);
                master_seed = Some(m);
            }
            7 => {
                encryption_iv = Some(field_bytes.to_vec());
            }
            11 => {
                kdf_params = Some(parse_variant_dict(field_bytes).context("KDF params")?);
            }
            12 => {
                // Public custom data (VariantDictionary) — ignored.
            }
            _ => {
                // Unknown field — skipped per spec.
            }
        }
    }

    let header_bytes = bytes[..cursor].to_vec();
    if cursor + 64 > bytes.len() {
        bail!(
            "KDBX header missing the trailing SHA256 + HMAC (need 64 more bytes after header end)"
        );
    }
    let mut header_sha256 = [0u8; 32];
    header_sha256.copy_from_slice(&bytes[cursor..cursor + 32]);
    let mut header_hmac = [0u8; 32];
    header_hmac.copy_from_slice(&bytes[cursor + 32..cursor + 64]);

    // Verify the plaintext SHA-256 first — this catches truncation and file
    // corruption before we burn Argon2d cycles on a doomed run.
    let mut hasher = Sha256::new();
    hasher.update(&header_bytes);
    let computed: [u8; 32] = hasher.finalize().into();
    if computed != header_sha256 {
        bail!("KDBX header SHA-256 mismatch — file is corrupt or truncated");
    }

    let master_seed = master_seed.context("KDBX header missing MasterSeed (field 4)")?;
    let kdf_params = kdf_params.context("KDBX header missing KDFParameters (field 11)")?;
    let kdf_uuid_bytes = kdf_params
        .get("$UUID")
        .and_then(|v| v.as_bytes())
        .context("KDF parameters missing $UUID")?;
    if kdf_uuid_bytes.len() != 16 {
        bail!("KDF $UUID is {} bytes, expected 16", kdf_uuid_bytes.len());
    }
    let mut kdf_uuid = [0u8; 16];
    kdf_uuid.copy_from_slice(kdf_uuid_bytes);

    Ok(Kdbx4Header {
        minor,
        major,
        header_bytes,
        master_seed,
        kdf_uuid,
        kdf_params,
        header_sha256,
        header_hmac,
        cipher_uuid: cipher_uuid.unwrap_or([0; 16]),
        compression: compression.unwrap_or(0),
        encryption_iv: encryption_iv.unwrap_or_default(),
        body_offset: cursor + 64, // header + trailing SHA256 (32) + HMAC (32)
    })
}

/// Parse a KeePass VariantDictionary (KDBX4 header inner encoding).
/// Format: 2-byte version LE | (1-byte type | 4-byte name-len LE | name UTF-8 |
///                              4-byte value-len LE | value) *N | 0-byte end.
fn parse_variant_dict(bytes: &[u8]) -> Result<HashMap<String, VariantValue>> {
    if bytes.len() < 2 {
        bail!("VariantDictionary too short");
    }
    let _version = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
    let mut cursor = 2usize;
    let mut out = HashMap::new();
    loop {
        if cursor >= bytes.len() {
            bail!("VariantDictionary truncated");
        }
        let ty = bytes[cursor];
        cursor += 1;
        if ty == 0 {
            break;
        }
        if cursor + 4 > bytes.len() {
            bail!("VariantDictionary truncated at name-len");
        }
        let name_len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if cursor + name_len > bytes.len() {
            bail!("VariantDictionary truncated in name");
        }
        let name = String::from_utf8(bytes[cursor..cursor + name_len].to_vec())
            .context("VariantDictionary name not UTF-8")?;
        cursor += name_len;
        if cursor + 4 > bytes.len() {
            bail!("VariantDictionary truncated at value-len");
        }
        let val_len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if cursor + val_len > bytes.len() {
            bail!("VariantDictionary truncated in value");
        }
        let vb = &bytes[cursor..cursor + val_len];
        cursor += val_len;
        let value = match ty {
            0x04 => {
                if vb.len() != 4 {
                    bail!("VariantDictionary U32 length {}", vb.len());
                }
                VariantValue::U32(u32::from_le_bytes(vb.try_into().unwrap()))
            }
            0x05 => {
                if vb.len() != 8 {
                    bail!("VariantDictionary U64 length {}", vb.len());
                }
                VariantValue::U64(u64::from_le_bytes(vb.try_into().unwrap()))
            }
            0x08 => {
                if vb.len() != 1 {
                    bail!("VariantDictionary Bool length {}", vb.len());
                }
                VariantValue::Bool(vb[0] != 0)
            }
            0x0C => {
                if vb.len() != 4 {
                    bail!("VariantDictionary I32 length {}", vb.len());
                }
                VariantValue::I32(i32::from_le_bytes(vb.try_into().unwrap()))
            }
            0x0D => {
                if vb.len() != 8 {
                    bail!("VariantDictionary I64 length {}", vb.len());
                }
                VariantValue::I64(i64::from_le_bytes(vb.try_into().unwrap()))
            }
            0x18 => VariantValue::Str(
                String::from_utf8(vb.to_vec()).context("VariantDictionary Str not UTF-8")?,
            ),
            0x42 => VariantValue::Bytes(vb.to_vec()),
            other => bail!("VariantDictionary unknown value type 0x{other:02x}"),
        };
        out.insert(name, value);
    }
    Ok(out)
}

/// Derive the KDBX4 final key from a password + parsed KDF parameters.
///
/// Composite key: SHA256 of the concatenated SHA256(key components). For a
/// password-only file that is `SHA256(SHA256(password_utf8))`.
///
/// KDF: Argon2d (or Argon2id on KDBX 4.1) parametrised from the header
/// VariantDictionary. AES-KDF (legacy) returns an error — we route those
/// files to the external-tool `[hint]` for now.
pub(crate) fn derive_final_key(password: &str, header: &Kdbx4Header) -> Result<[u8; 32]> {
    // Composite key.
    let mut inner = Sha256::new();
    inner.update(password.as_bytes());
    let inner_hash: [u8; 32] = inner.finalize().into();
    let mut outer = Sha256::new();
    outer.update(inner_hash);
    let composite: [u8; 32] = outer.finalize().into();

    // KDF.
    match header.kdf_uuid {
        KDF_UUID_ARGON2D | KDF_UUID_ARGON2ID => argon2_kdf(&composite, &header.kdf_params),
        KDF_UUID_AES => bail!(
            "AES-KDF (legacy) — this pipeline targets Argon2d/Argon2id. Fall back to \
             `keepass2john | hashcat -m 13400` for AES-KDF databases."
        ),
        _ => bail!("unknown KDF UUID {:02x?}", header.kdf_uuid),
    }
}

fn argon2_kdf(composite: &[u8; 32], params: &HashMap<String, VariantValue>) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, ParamsBuilder, Version};

    let salt = params
        .get("S")
        .and_then(|v| v.as_bytes())
        .context("Argon2 params missing S (salt)")?;
    let memory_bytes = params
        .get("M")
        .and_then(|v| v.as_u64())
        .context("Argon2 params missing M (memory)")?;
    let iterations = params
        .get("I")
        .and_then(|v| v.as_u64())
        .context("Argon2 params missing I (iterations)")?;
    let parallelism = params
        .get("P")
        .and_then(|v| v.as_u32())
        .context("Argon2 params missing P (parallelism)")?;
    let version = params.get("V").and_then(|v| v.as_u32()).unwrap_or(0x13); // 0x13 = argon2 version 1.3 default

    // KeePass stores memory in BYTES; argon2 crate expects KiB. Round DOWN
    // to the nearest KiB — KeePass writer always uses multiples of 1024 so
    // this is exact in practice.
    let memory_kib =
        u32::try_from(memory_bytes / 1024).context("Argon2 memory does not fit in u32 KiB")?;
    let t_cost = u32::try_from(iterations).context("Argon2 iterations do not fit in u32")?;

    let algo = if params
        .get("$UUID")
        .and_then(|v| v.as_bytes())
        .map(|b| b == KDF_UUID_ARGON2ID)
        .unwrap_or(false)
    {
        Algorithm::Argon2id
    } else {
        Algorithm::Argon2d
    };
    let ver = if version == 0x10 {
        Version::V0x10
    } else {
        Version::V0x13
    };

    let mut pb = ParamsBuilder::new();
    pb.m_cost(memory_kib)
        .t_cost(t_cost)
        .p_cost(parallelism)
        .output_len(32);
    let params_built = pb
        .build()
        .map_err(|e| anyhow::anyhow!("Argon2 param build: {e}"))?;
    let a2 = Argon2::new(algo, ver, params_built);
    let mut out = [0u8; 32];
    a2.hash_password_into(composite, salt, &mut out)
        .map_err(|e| anyhow::anyhow!("Argon2 KDF: {e}"))?;
    Ok(out)
}

/// Compute the KDBX4 header HMAC-SHA-256 with a candidate final key and
/// compare it against the stored HMAC. Returns `Ok(true)` iff the password
/// used to derive `final_key` is correct.
pub(crate) fn verify_header_hmac(header: &Kdbx4Header, final_key: &[u8; 32]) -> bool {
    // hmacBaseKey = SHA512(masterSeed || finalKey || 0x01)
    let mut base = Sha512::new();
    base.update(header.master_seed);
    base.update(final_key);
    base.update([0x01u8]);
    let base_key = base.finalize();

    // Header HMAC uses block index u64::MAX per KeePass source.
    let mut idx_hasher = Sha512::new();
    idx_hasher.update(u64::MAX.to_le_bytes());
    idx_hasher.update(base_key);
    let block_key = idx_hasher.finalize();

    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&block_key).expect("HMAC accepts any key length");
    mac.update(&header.header_bytes);
    let computed = mac.finalize().into_bytes();
    // Plain equality is correct here: this is a local self-check against a value
    // already sitting in the operator's own file, not a secret compared across a
    // trust boundary, so there is no remote timing oracle to defend against.
    computed.as_slice() == header.header_hmac
}

// --------------------------------------------------------------------------
// F4b: KDBX4 body extract pipeline (Argon2d → HMAC blocks → outer cipher
// decrypt → gzip inflate → inner header parse → XML walk → protected-field
// unmask via inner ChaCha20 stream).
// --------------------------------------------------------------------------

/// One recovered KDBX entry. `custom_fields` carries user-defined String
/// fields beyond the KeePass builtins (Title, UserName, Password, URL, Notes).
#[derive(Debug, Clone, Default)]
pub(crate) struct KdbxEntry {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub custom: std::collections::BTreeMap<String, String>,
}

/// Decrypt, inflate and XML-walk a KDBX4 file using the Argon2d `final_key` the
/// caller already derived and HMAC-verified via [`derive_final_key`] +
/// [`verify_header_hmac`]. Returns the entries recovered (protected fields
/// unmasked). This does NOT re-run the KDF — Argon2d is expensive and the caller
/// has already paid for it on the verify path.
pub(crate) fn extract(
    file_bytes: &[u8],
    header: &Kdbx4Header,
    final_key: &[u8; 32],
) -> Result<Vec<KdbxEntry>> {
    // Recompute the body-block HMAC base key from the caller-supplied final_key.
    let mut base_hasher = Sha512::new();
    base_hasher.update(header.master_seed);
    base_hasher.update(final_key);
    base_hasher.update([0x01u8]);
    let hmac_base_key = base_hasher.finalize();

    // Reassemble HMAC-block sequence into a single ciphertext buffer.
    let mut cursor = header.body_offset;
    let mut ciphertext = Vec::new();
    for idx in 0u64.. {
        if cursor + 32 + 4 > file_bytes.len() {
            bail!("KDBX body truncated at block {idx}");
        }
        let block_hmac = &file_bytes[cursor..cursor + 32];
        let block_size =
            u32::from_le_bytes(file_bytes[cursor + 32..cursor + 36].try_into().unwrap()) as usize;
        cursor += 36;
        if cursor + block_size > file_bytes.len() {
            bail!("KDBX body block {idx} size {block_size} extends past EOF");
        }
        let data = &file_bytes[cursor..cursor + block_size];
        cursor += block_size;
        // block key = SHA512(idx_LE_u64 || hmac_base_key)
        let mut kh = Sha512::new();
        kh.update(idx.to_le_bytes());
        kh.update(hmac_base_key);
        let bk = kh.finalize();
        // HMAC-SHA256 over (idx || block_size || data)
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&bk).expect("HMAC accepts any key length");
        mac.update(&idx.to_le_bytes());
        mac.update(&(block_size as u32).to_le_bytes());
        mac.update(data);
        let want = mac.finalize().into_bytes();
        if want.as_slice() != block_hmac {
            bail!("KDBX body HMAC mismatch at block {idx} — password may be wrong");
        }
        if block_size == 0 {
            break;
        }
        ciphertext.extend_from_slice(data);
    }

    // Outer cipher decrypt. cipher key = SHA256(master_seed || final_key).
    let mut ek_hash = Sha256::new();
    ek_hash.update(header.master_seed);
    ek_hash.update(final_key);
    let enc_key: [u8; 32] = ek_hash.finalize().into();

    let plaintext_body = match header.cipher_uuid {
        CIPHER_UUID_AES256_CBC => {
            use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
            if header.encryption_iv.len() != 16 {
                bail!(
                    "AES256-CBC needs 16-byte IV, header has {}",
                    header.encryption_iv.len()
                );
            }
            let dec = Aes256CbcDec::new_from_slices(&enc_key, &header.encryption_iv)
                .map_err(|e| anyhow::anyhow!("AES256 init: {e}"))?;
            let mut ct = ciphertext.clone();
            dec.decrypt_padded_mut::<Pkcs7>(&mut ct)
                .map_err(|e| anyhow::anyhow!("AES256-CBC unpadding: {e}"))?
                .to_vec()
        }
        CIPHER_UUID_CHACHA20 => {
            use chacha20::cipher::{KeyIvInit, StreamCipher};
            if header.encryption_iv.len() != 12 {
                bail!(
                    "ChaCha20 needs 12-byte nonce, header has {}",
                    header.encryption_iv.len()
                );
            }
            let mut c =
                chacha20::ChaCha20::new((&enc_key).into(), header.encryption_iv.as_slice().into());
            let mut buf = ciphertext.clone();
            c.apply_keystream(&mut buf);
            buf
        }
        other => bail!("unsupported cipher UUID {:02x?}", other),
    };

    // Optional gzip inflate.
    let mut decompressed = if header.compression == 1 {
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut d = GzDecoder::new(&plaintext_body[..]);
        let mut out = Vec::new();
        d.read_to_end(&mut out)
            .map_err(|e| anyhow::anyhow!("gzip inflate: {e}"))?;
        out
    } else {
        plaintext_body
    };

    // Inner header: TLV of (id_u8, len_u32, data) until id=0 (END).
    let mut ic = 0usize;
    let mut inner_stream_id: u32 = 3; // ChaCha20 default per KDBX4
    let mut inner_stream_key: Vec<u8> = Vec::new();
    loop {
        if ic + 5 > decompressed.len() {
            bail!("KDBX inner header truncated");
        }
        let id = decompressed[ic];
        let ln = u32::from_le_bytes(decompressed[ic + 1..ic + 5].try_into().unwrap()) as usize;
        ic += 5;
        if ic + ln > decompressed.len() {
            bail!("KDBX inner header field {id} truncated");
        }
        let fb = &decompressed[ic..ic + ln];
        ic += ln;
        match id {
            0 => break,
            1 => inner_stream_id = u32::from_le_bytes(fb.try_into().unwrap_or([0; 4])),
            2 => inner_stream_key = fb.to_vec(),
            3 => { /* binary attachment — skip */ }
            _ => {}
        }
    }
    let xml_bytes = decompressed.split_off(ic);
    // drop the drained inner-header prefix explicitly.
    drop(decompressed);

    // Inner stream cipher for protected fields.
    if inner_stream_id != 3 {
        bail!(
            "unsupported inner stream ID {inner_stream_id} — this build handles ChaCha20 (3) only"
        );
    }
    if inner_stream_key.len() != 64 {
        bail!(
            "inner ChaCha20 key must be 64 bytes (KeePass expands via SHA512), got {}",
            inner_stream_key.len()
        );
    }
    // KDBX4 inner ChaCha20: key = SHA512(inner_key)[0..32], nonce = SHA512(inner_key)[32..44].
    let expanded = {
        let mut h = Sha512::new();
        h.update(&inner_stream_key);
        h.finalize()
    };
    let ikey: [u8; 32] = expanded[0..32].try_into().unwrap();
    let inonce: [u8; 12] = expanded[32..44].try_into().unwrap();
    let mut inner_cipher = {
        use chacha20::cipher::KeyIvInit;
        chacha20::ChaCha20::new((&ikey).into(), (&inonce).into())
    };

    // XML walk. Extract every <String><Key>K</Key><Value Protected="?">V</Value></String>
    // pair inside an <Entry>. Protected values are base64-decoded and then
    // XOR'd with the inner ChaCha20 stream IN DOCUMENT ORDER (KeePass writes
    // them into a single stream, decryption must consume the stream in the
    // same order).
    let entries = walk_kdbx_xml(&xml_bytes, &mut inner_cipher)?;
    Ok(entries)
}

fn walk_kdbx_xml(xml: &[u8], inner_cipher: &mut chacha20::ChaCha20) -> Result<Vec<KdbxEntry>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use chacha20::cipher::StreamCipher;
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut entries: Vec<KdbxEntry> = Vec::new();
    // Entry stack: KDBX nests prior versions as <History><Entry>…</Entry></History>
    // inside each live entry. Fields bind to the innermost open entry (top of
    // stack); protected values are unmasked for EVERY entry — history included —
    // so the inner ChaCha20 stream stays byte-aligned. Only entries that close
    // at depth 0 are emitted; history entries are consumed for sync then dropped.
    let mut stack: Vec<KdbxEntry> = Vec::new();
    let mut in_string = false;
    let mut in_key = false;
    let mut in_value = false;
    let mut value_protected = false;
    let mut cur_key = String::new();
    let mut cur_value = String::new();
    let mut buf = Vec::new();

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| anyhow::anyhow!("kdbx xml: {e}"))?
        {
            Event::Start(e) => match e.name().as_ref() {
                b"Entry" => stack.push(KdbxEntry::default()),
                b"String" if !stack.is_empty() => {
                    in_string = true;
                    cur_key.clear();
                    cur_value.clear();
                    value_protected = false;
                }
                b"Key" if in_string => in_key = true,
                b"Value" if in_string => {
                    in_value = true;
                    value_protected = e
                        .attributes()
                        .flatten()
                        .any(|a| a.key.as_ref() == b"Protected" && a.value.as_ref() == b"True");
                }
                _ => {}
            },
            Event::Empty(e) => {
                // Self-closing tags like <Value Protected="True" /> — treat as empty value
                if in_string && e.name().as_ref() == b"Value" {
                    let prot = e
                        .attributes()
                        .flatten()
                        .any(|a| a.key.as_ref() == b"Protected" && a.value.as_ref() == b"True");
                    if prot {
                        // Protected empty is still a stream consumer of 0 bytes → skip.
                    }
                }
            }
            Event::Text(t) => {
                let text = t
                    .unescape()
                    .map_err(|e| anyhow::anyhow!("kdbx xml text: {e}"))?
                    .into_owned();
                if in_key {
                    cur_key.push_str(&text);
                } else if in_value {
                    cur_value.push_str(&text);
                }
            }
            Event::End(e) => match e.name().as_ref() {
                b"Entry" => {
                    if let Some(done) = stack.pop() {
                        // Emit only top-level entries; discard history versions.
                        if stack.is_empty() {
                            entries.push(done);
                        }
                    }
                }
                b"String" => {
                    if in_string {
                        // Unmask protected values.
                        let final_val = if value_protected && !cur_value.is_empty() {
                            let ct = B64
                                .decode(cur_value.as_bytes())
                                .map_err(|e| anyhow::anyhow!("protected value b64: {e}"))?;
                            let mut vbuf = ct.clone();
                            inner_cipher.apply_keystream(&mut vbuf);
                            String::from_utf8_lossy(&vbuf).into_owned()
                        } else {
                            cur_value.clone()
                        };
                        if let Some(entry) = stack.last_mut() {
                            match cur_key.as_str() {
                                "Title" => entry.title = Some(final_val),
                                "UserName" => entry.username = Some(final_val),
                                "Password" => entry.password = Some(final_val),
                                "URL" => entry.url = Some(final_val),
                                "Notes" => entry.notes = Some(final_val),
                                other => {
                                    entry.custom.insert(other.to_string(), final_val);
                                }
                            }
                        }
                    }
                    in_string = false;
                    cur_key.clear();
                    cur_value.clear();
                    value_protected = false;
                }
                b"Key" => in_key = false,
                b"Value" => in_value = false,
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_file() {
        let err = parse_header(&[0u8; 8]).unwrap_err();
        assert!(err.to_string().contains("too small"));
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut bytes = vec![0u8; 200];
        bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        bytes[4..8].copy_from_slice(&MAGIC2.to_le_bytes());
        let err = parse_header(&bytes).unwrap_err();
        assert!(err.to_string().contains("not a KDBX file"));
    }

    #[test]
    fn rejects_non_kdbx4() {
        let mut bytes = vec![0u8; 200];
        bytes[0..4].copy_from_slice(&MAGIC1.to_le_bytes());
        bytes[4..8].copy_from_slice(&MAGIC2.to_le_bytes());
        // major=3
        bytes[10..12].copy_from_slice(&3u16.to_le_bytes());
        let err = parse_header(&bytes).unwrap_err();
        assert!(err.to_string().contains("KDBX3"));
    }

    #[test]
    fn variant_dict_roundtrip_shape() {
        // Minimal VariantDict: version=0x0100, one U32 field "T"=42, end.
        let mut b = Vec::new();
        b.extend_from_slice(&0x0100u16.to_le_bytes());
        b.push(0x04); // U32
        b.extend_from_slice(&1u32.to_le_bytes()); // name len
        b.extend_from_slice(b"T");
        b.extend_from_slice(&4u32.to_le_bytes()); // value len
        b.extend_from_slice(&42u32.to_le_bytes());
        b.push(0x00); // END
        let dict = parse_variant_dict(&b).unwrap();
        assert_eq!(dict.get("T").unwrap().as_u32(), Some(42));
    }

    #[test]
    fn kdf_uuid_constants_are_16_bytes() {
        assert_eq!(KDF_UUID_AES.len(), 16);
        assert_eq!(KDF_UUID_ARGON2D.len(), 16);
        assert_eq!(KDF_UUID_ARGON2ID.len(), 16);
    }

    /// Base64-encode `plaintext` XOR'd with the next bytes of `cipher`'s
    /// keystream — i.e. exactly how KeePass serializes a protected value.
    fn protect(cipher: &mut chacha20::ChaCha20, plaintext: &str) -> String {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use chacha20::cipher::StreamCipher;
        let mut buf = plaintext.as_bytes().to_vec();
        cipher.apply_keystream(&mut buf);
        B64.encode(buf)
    }

    /// Regression: KDBX entries keep prior versions in a nested
    /// `<History><Entry>…</Entry></History>`. The walker must (a) bind fields to
    /// the innermost open entry, (b) consume the inner ChaCha20 stream for the
    /// history value so later entries stay aligned, and (c) emit ONLY the live
    /// top-level entries. The pre-fix walker reset the live entry on the nested
    /// `<Entry>` and emitted the history version in its place.
    #[test]
    fn history_entries_do_not_clobber_live_entry() {
        use chacha20::cipher::KeyIvInit;

        let key = [7u8; 32];
        let nonce = [0u8; 12];
        // Protected values are encoded against ONE stream in document order:
        //   pass1 (entry 1) -> old1 (entry 1 history) -> pass2 (entry 2).
        let mut enc = chacha20::ChaCha20::new((&key).into(), (&nonce).into());
        let p_pass1 = protect(&mut enc, "pass1");
        let p_old1 = protect(&mut enc, "old1");
        let p_pass2 = protect(&mut enc, "pass2");

        let xml = format!(
            r#"<Root><Group>
              <Entry>
                <String><Key>Title</Key><Value>One</Value></String>
                <String><Key>UserName</Key><Value>alice</Value></String>
                <String><Key>Password</Key><Value Protected="True">{p_pass1}</Value></String>
                <History>
                  <Entry>
                    <String><Key>Password</Key><Value Protected="True">{p_old1}</Value></String>
                  </Entry>
                </History>
              </Entry>
              <Entry>
                <String><Key>Title</Key><Value>Two</Value></String>
                <String><Key>Password</Key><Value Protected="True">{p_pass2}</Value></String>
              </Entry>
            </Group></Root>"#
        );

        let mut dec = chacha20::ChaCha20::new((&key).into(), (&nonce).into());
        let entries = walk_kdbx_xml(xml.as_bytes(), &mut dec).unwrap();

        // History version is discarded — only the two live entries survive.
        assert_eq!(entries.len(), 2, "history entry must not be emitted");
        // Entry 1's live fields are intact (the bug replaced them with history).
        assert_eq!(entries[0].title.as_deref(), Some("One"));
        assert_eq!(entries[0].username.as_deref(), Some("alice"));
        assert_eq!(entries[0].password.as_deref(), Some("pass1"));
        // Entry 2 still decrypts correctly, proving the inner stream stayed
        // byte-aligned across the consumed history value.
        assert_eq!(entries[1].title.as_deref(), Some("Two"));
        assert_eq!(entries[1].password.as_deref(), Some("pass2"));
    }
}
