//! Secret-holding newtype whose `Debug`/`Display` impls print `"***"` instead of the value.
//!
//! Wrap any sensitive field (password, NT hash, ccache bytes, keytab, ntlmssp session key,
//! kerberos subkey, dpapi masterkey, cookie, token) in [`Redacted<T>`] so a stray
//! `tracing::debug!("{cfg:?}")` — including `--debug` output the user might paste into a
//! bug report — cannot leak the secret. Use [`Redacted::expose`] at the exact call site
//! that needs the raw value (LDAP bind, RPC seal, ccache serialize) — that call is visible
//! in `git grep expose\\(` for audit.
//!
//! **1.4.9 WS-ZEROIZE** — for byte-material types (`Vec<u8>` and
//! `String`), Redacted also erases the memory on `Drop` via
//! [`SecretBytes`] / [`SecretString`] variants. Wrapping a byte vec in
//! `Redacted::<Vec<u8>>::new(v)` gives the print-hiding surface but does
//! NOT erase on drop; use [`Redacted::new_zeroize`] for `Vec<u8>`, or
//! store text directly in [`SecretString`]. All erasure paths use the
//! `zeroize` crate (RustCrypto-maintained, no-std-friendly, widely
//! audited).
//!
//! ```
//! use adhammer_core::Redacted;
//! let pw = Redacted::new("hunter2".to_string());
//! assert_eq!(format!("{pw}"), "***");
//! assert_eq!(format!("{pw:?}"), "***");
//! assert_eq!(pw.expose(), "hunter2");
//! ```
//!
//! `PartialEq`/`Eq` compare underlying values (so tests can `assert_eq!(pw, expected)`
//! without unwrapping) but the compared values themselves stay hidden from any panic
//! message thanks to the custom `Debug`.

use std::fmt;
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A `T` that hides its own value in `Debug`/`Display` output.
///
/// Cheap wrapper — zero runtime cost, just a compile-time type-level flag that "this is a
/// secret." Access the wrapped value explicitly via [`Redacted::expose`], which makes every
/// secret-touching call site greppable for security audit.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap a secret. Prefer this at every construction site over `Redacted(x)` so a
    /// future refactor (e.g. serde-skip attribute) has one place to change.
    pub const fn new(v: T) -> Self {
        Redacted(v)
    }

    /// Deliberate escape hatch — returns the wrapped secret by reference. Every call is
    /// greppable (`git grep '\.expose('`) so a review can enumerate every place secrets
    /// are actually used vs merely held.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper and return the underlying secret. Same rule as `expose`:
    /// every call is greppable.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl Redacted<SecretBytes> {
    /// Wrap byte material with print-hiding AND zero-on-drop. Prefer this over
    /// `Redacted::<Vec<u8>>::new(v)` for anything that lives long enough to
    /// be worth erasing (session keys, ccache bytes, NT hashes cached in-
    /// process, DPAPI masterkeys). The convenience `expose_bytes` returns
    /// `&[u8]` directly for zero-friction consumption.
    pub fn new_zeroize(v: Vec<u8>) -> Self {
        Redacted(SecretBytes(v))
    }
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0 .0
    }
}

/// UTF-8 secret that is redacted in formatting and erased before its heap
/// allocation is released. CLI parsers should use this type at the first
/// owned boundary so a derived `Debug` implementation cannot reveal the
/// value.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Explicitly reveal the value at the narrow protocol/crypto call site.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Compatibility spelling for existing explicit secret-use sites.
    pub fn expose(&self) -> &String {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.expose_secret()
    }
}

impl std::ops::Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.expose_secret()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretString {}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl FromStr for SecretString {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(key) = value.strip_prefix("env:") {
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
                || key.as_bytes()[0].is_ascii_digit()
            {
                return Err("invalid environment-variable reference in credential argument".into());
            }
            return std::env::var(key)
                .map(Self::new)
                .map_err(|_| format!("credential environment variable {key} is not set"));
        }
        if let Some(path) = value.strip_prefix("@file:") {
            if path.is_empty() {
                return Err("credential file reference has an empty path".into());
            }
            return std::fs::read_to_string(path)
                .map(|raw| Self::new(raw.trim_end_matches(['\n', '\r']).to_owned()))
                .map_err(|error| format!("read credential file {path}: {error}"));
        }
        Ok(Self::from(value))
    }
}

impl serde::Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Byte-buffer secret that erases its heap allocation on Drop. Prefer
/// [`Redacted<SecretBytes>`] over raw `Redacted<Vec<u8>>` for anything
/// held longer than one call frame.
///
/// The `zeroize` crate's `Zeroize` impl for `Vec<u8>` overwrites the
/// backing allocation to zero; `ZeroizeOnDrop` invokes that in Drop.
/// Zero runtime cost when not dropped.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct SecretBytes(Vec<u8>);

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretBytes {}

impl SecretBytes {
    pub fn from_vec(v: Vec<u8>) -> Self {
        SecretBytes(v)
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

impl serde::Serialize for SecretBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}
impl<'de> serde::Deserialize<'de> for SecretBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Vec::<u8>::deserialize(d).map(SecretBytes)
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(v: T) -> Self {
        Redacted(v)
    }
}

/// Transparent Serialize — a `Redacted<T>` serializes exactly as `T` would. This lets us
/// wrap existing persisted fields (e.g. the on-disk Session file) without changing the
/// wire format. If a struct instead wants a "***" placeholder in its serialized form,
/// use `#[serde(serialize_with = "...")]` at the field rather than making Redacted lie.
impl<T: serde::Serialize> serde::Serialize for Redacted<T> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}
impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Redacted<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        T::deserialize(d).map(Redacted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_zeroize_on_drop_reference_check() {
        // Can't observe raw memory in safe Rust without unsafe, so instead
        // check the public contract: `zeroize::Zeroize` is implemented and
        // callable; `ZeroizeOnDrop` is implemented (compile-time via the
        // derive). If someone removes the derive, this test still compiles
        // if the trait bound is missing — so we assert it via a trait bound.
        use zeroize::{Zeroize, ZeroizeOnDrop};
        fn assert_zeroize<T: Zeroize + ZeroizeOnDrop>() {}
        assert_zeroize::<SecretBytes>();

        let mut s = SecretBytes::from_vec(vec![0xAB, 0xCD]);
        assert_eq!(s.as_slice(), &[0xAB, 0xCD]);
        s.zeroize();
        // `Zeroize` on `Vec<u8>` overwrites the bytes AND clears the vec
        // (len -> 0, capacity retained but zeroed). So `as_slice()` after
        // `zeroize()` is empty. Both facts matter: no residual bytes are
        // visible via the public API, and the freed heap region has been
        // overwritten before the eventual deallocation.
        assert!(s.as_slice().is_empty(), "vec cleared after zeroize");
    }

    #[test]
    fn secret_bytes_hides_via_redacted() {
        let key = Redacted::<SecretBytes>::new_zeroize(vec![0xAA; 32]);
        assert_eq!(format!("{key:?}"), "***");
        assert_eq!(key.expose_bytes().len(), 32);
    }

    #[test]
    fn secret_string_redacts_and_implements_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretString>();

        let secret = SecretString::from("correct horse battery staple");
        assert_eq!(secret.expose_secret(), "correct horse battery staple");
        assert_eq!(format!("{secret:?}"), "***");
        assert_eq!(format!("{secret}"), "***");
    }

    #[test]
    fn debug_and_display_print_stars_not_the_value() {
        let pw = Redacted::new(String::from("hunter2"));
        assert_eq!(format!("{pw}"), "***");
        assert_eq!(format!("{pw:?}"), "***");
        // Nested formatting — a struct field of type Redacted<String> still hides.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Cfg {
            user: String,
            password: Redacted<String>,
        }
        let c = Cfg {
            user: "alice".into(),
            password: Redacted::new("supersecret".into()),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("alice"));
        assert!(dbg.contains("***"));
        assert!(
            !dbg.contains("supersecret"),
            "Debug of a struct containing Redacted must not leak the secret"
        );
    }

    #[test]
    fn expose_returns_the_real_value() {
        let key = Redacted::new(vec![0xAAu8; 32]);
        assert_eq!(key.expose().len(), 32);
        assert_eq!(key.expose()[0], 0xAA);
        // into_inner drops the wrapper.
        let raw = key.into_inner();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn from_impl_and_equality() {
        let a: Redacted<u32> = 42.into();
        let b = Redacted::new(42u32);
        assert_eq!(a, b);
    }

    #[test]
    fn hidden_in_option_and_result_debug() {
        // Common pattern: Option<Redacted<Password>> in a config struct.
        let opt: Option<Redacted<&str>> = Some(Redacted::new("secret-token"));
        let dbg = format!("{opt:?}");
        assert!(dbg.contains("***"));
        assert!(!dbg.contains("secret-token"));
    }

    #[test]
    fn serde_is_transparent() {
        // Serializing a Redacted<T> must produce the same output as serializing the raw
        // T — otherwise persistent Session files break the moment a field is wrapped.
        let raw: String = "hunter2".into();
        let wrapped = Redacted::new(raw.clone());
        assert_eq!(
            serde_json::to_string(&wrapped).unwrap(),
            serde_json::to_string(&raw).unwrap(),
        );
        // Round-trip: deserialize a plain JSON string back into a Redacted<String>.
        let s = "\"round-trip\"";
        let back: Redacted<String> = serde_json::from_str(s).unwrap();
        assert_eq!(back.expose(), "round-trip");
    }
}
