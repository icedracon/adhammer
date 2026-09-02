use std::process::Command;

pub fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

/// Run the built `adhammer` binary with args; return combined stdout+stderr. Returns None when
/// the lab env isn't configured (so the test is skipped rather than failing).
pub fn run(args: &[&str]) -> Option<String> {
    env("ADH_DC")?; // gate: no lab configured
    let bin = env!("CARGO_BIN_EXE_adhammer");
    // A spawn failure (e.g. a sandboxed/locked-down host) skips rather than false-fails.
    let out = Command::new(bin).args(args).output().ok()?;
    Some(format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

pub fn dc() -> String {
    env("ADH_DC").unwrap()
}

pub fn domain() -> String {
    env("ADH_DOMAIN").unwrap_or_else(|| "CORP".into())
}

pub fn user() -> String {
    env("ADH_USER").unwrap_or_else(|| "Administrator".into())
}

pub fn pass() -> String {
    env("ADH_PASS").unwrap_or_default()
}

pub fn realm() -> String {
    env("ADH_REALM").unwrap_or_else(|| "CORP.LOCAL".into())
}

#[allow(dead_code)]
pub fn impact_enabled() -> bool {
    matches!(
        env("ADH_IMPACT")
            .as_deref()
            .map(str::trim)
            .map(|v| v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true")),
        Some(true)
    )
}
