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

/// **1.5.1 P0 bug fix — expand `@file:` / `env:` credential references at the `From`
/// conversion boundary, not just in `FromStr`.**
///
/// Root cause narrative (P0 shipping blocker, caught by an HTB Pirate live-test on
/// 2026-09-11): clap-derive builds `SecretString` from CLI arg strings via
/// `<T as From<String>>::from` (its default `TypedValueParser` route for types that
/// implement both `From<String>` and `FromStr` — `From<String>` wins). The identity
/// implementations that used to live here therefore returned the LITERAL string —
/// `@file:/tmp/pw.txt` or `env:ADHAMMER_PW` — as the credential bytes. Every
/// authenticated verb (doctor / scan / enum / attack) was silently broken: the DC
/// rightfully rejected the raw reference-string as an invalid password and returned
/// `AcceptSecurityContext error, data 52e`. The classifier said "InvalidCredentials"
/// and the operator was left wondering why known-good creds are rejected.
///
/// Fix discipline: **the expansion happens once, inside a shared helper**, and both
/// `From<String>` and `From<&str>` (and `FromStr`) route through it. That way clap's
/// resolution order doesn't matter — every path expands.
///
/// Fallback: on a malformed reference (`env:MISSING`, `@file:/does/not/exist`) we
/// print a WARN on stderr and return an empty secret. Never leak the raw reference
/// string as bytes — that would send `@file:/tmp/pw` to the DC as the "password" and
/// leave the operator hunting a phantom bad-creds error.
fn expand_credential_reference(value: &str) -> SecretString {
    if let Some(key) = value.strip_prefix("env:") {
        match std::env::var(key) {
            Ok(v) => SecretString(v),
            Err(_) => {
                eprintln!(
                    "warning: env credential `{key}` is not set — bind will send empty. \
                     Fix: export {key}=... in the same shell before invoking."
                );
                SecretString(String::new())
            }
        }
    } else if let Some(path) = value.strip_prefix("@file:") {
        match std::fs::read_to_string(path) {
            Ok(raw) => SecretString(raw.trim_end_matches(['\n', '\r']).to_owned()),
            Err(e) => {
                eprintln!(
                    "warning: read credential file `{path}` failed: {e} — bind will send empty. \
                     Fix: check the path exists and is readable by this process."
                );
                SecretString(String::new())
            }
        }
    } else {
        SecretString(value.to_owned())
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        expand_credential_reference(&value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        expand_credential_reference(value)
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
        // Identity path — construct directly to avoid `From<&str>` recursion (`From<&str>`
        // now shells out to inline expansion; calling `Self::from(value)` here would loop
        // back through it. This branch is guaranteed to be past both `env:` and `@file:`
        // strip_prefix guards, so the raw value is the intended plain secret.).
        Ok(Self::new(value.to_owned()))
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

    // -----------------------------------------------------------------------------
    // 1.5.1 P0 regression guard — `SecretString::From<String>` and `From<&str>` must
    // expand `@file:PATH` and `env:VAR` credential references. Clap-derive routes
    // CLI args through `From<String>` (its default `TypedValueParser` prefers it
    // over `FromStr` when both exist). Before the fix these impls were identity —
    // every authenticated verb silently sent the LITERAL reference string to the
    // DC and 52e-classified as "InvalidCredentials". Wire-diffed vs ldapsearch
    // against HTB Pirate DC01 on 2026-09-11; fix landed in the same file. These
    // tests exist so a "helpful" refactor of `From<String>` cannot silently
    // reintroduce the class.
    // -----------------------------------------------------------------------------

    #[test]
    fn from_string_expands_file_reference() {
        use std::io::Write;
        let mut tmp = std::env::temp_dir();
        tmp.push(format!(
            "adhammer_secret_from_string_expands_{}.txt",
            std::process::id()
        ));
        {
            let mut f = std::fs::File::create(&tmp).unwrap();
            f.write_all(b"expanded-file-secret\n").unwrap();
        }
        let raw: String = format!("@file:{}", tmp.display());
        let s: SecretString = SecretString::from(raw);
        assert_eq!(
            s.expose_secret(),
            "expanded-file-secret",
            "From<String> must expand @file:PATH and trim trailing newline"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn from_str_expands_file_reference() {
        use std::io::Write;
        let mut tmp = std::env::temp_dir();
        tmp.push(format!(
            "adhammer_secret_from_str_expands_{}.txt",
            std::process::id()
        ));
        {
            let mut f = std::fs::File::create(&tmp).unwrap();
            f.write_all(b"expanded-str-secret").unwrap();
        }
        let raw = format!("@file:{}", tmp.display());
        let s: SecretString = SecretString::from(raw.as_str());
        assert_eq!(s.expose_secret(), "expanded-str-secret");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn from_string_expands_env_reference() {
        // Unique name per test process — parallel tests cannot collide, and
        // std::env::set_var is thread-safe in the current Rust std.
        let name = format!("ADHAMMER_REGRESSION_TEST_ENV_{}", std::process::id());
        // SAFETY: `set_var` in tests runs on the current process; the pw stays a
        // literal short string, never leaks a real credential.
        // Safe because no other thread is racing on this specific var name.
        unsafe {
            std::env::set_var(&name, "expanded-env-secret");
        }
        let s: SecretString = SecretString::from(format!("env:{name}"));
        assert_eq!(s.expose_secret(), "expanded-env-secret");
        unsafe {
            std::env::remove_var(&name);
        }
    }

    #[test]
    fn from_str_identity_when_not_a_reference() {
        // Plain string with no `env:` / `@file:` prefix must pass through
        // untouched. This is the "programmatic-use" contract for
        // `SecretString::from(some_literal_bytes)` in tests + producers.
        let s: SecretString = SecretString::from("plain-not-a-reference");
        assert_eq!(s.expose_secret(), "plain-not-a-reference");
    }

    #[test]
    fn new_is_identity_never_expands_references() {
        // Contract: `SecretString::new(x)` is the raw-literal constructor. It must
        // NOT walk the `env:` / `@file:` expansion path — that path is reserved
        // for `From<String>` / `From<&str>` / `FromStr`, all of which are the
        // CLI-flag intake surface. Interactive prompt sites (e.g. `dialoguer::
        // Password::interact()`) use `::new` precisely because a value the
        // operator just typed at a live prompt is a literal, not a shell
        // composition. If a future refactor "helpfully" routes `::new` through
        // `expand_credential_reference`, an operator whose PFX password
        // happens to look like `env:PROD` would silently have the wrong bytes
        // sent to Kerberos/LDAP. Lock the invariant here.
        let s1 = SecretString::new("env:ADHAMMER_UNSET_XYZ".to_string());
        assert_eq!(s1.expose_secret(), "env:ADHAMMER_UNSET_XYZ");
        let s2 = SecretString::new("@file:/definitely/does/not/exist".to_string());
        assert_eq!(s2.expose_secret(), "@file:/definitely/does/not/exist");
    }

    #[test]
    fn from_string_missing_env_becomes_empty_never_leaks_literal() {
        // On a malformed / missing env reference, the impl must NOT return the
        // raw `env:MISSING` string as the credential bytes — that would ship
        // the literal reference to the DC and mislead the operator into
        // thinking their password is wrong. Empty is the safe fallback.
        // Pick a name that no reasonable test env would set.
        let name = format!(
            "ADHAMMER_DEFINITELY_UNSET_ENV_VAR_{}_{}",
            std::process::id(),
            42u64
        );
        // Belt-and-braces: make sure it really is unset.
        unsafe {
            std::env::remove_var(&name);
        }
        let s: SecretString = SecretString::from(format!("env:{name}"));
        assert_eq!(
            s.expose_secret(),
            "",
            "missing env ref must fall back to empty, not the literal `env:...`"
        );
    }
}
