//! Capture build-time provenance (git commit + date) into `$OUT_DIR/build_info.rs`,
//! included by `adhammer_core::build`. Off a git checkout (e.g. a crates.io
//! build) every field falls back to "unknown" — honest, never a hard error.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    // Re-embed when HEAD moves so the commit stays current across rebuilds.
    for p in ["../../.git/HEAD", "../../.git/refs/heads"] {
        if std::path::Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    println!("cargo:rerun-if-changed=build.rs");

    let sha = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let date = git(&["log", "-1", "--format=%cs", "HEAD"]).unwrap_or_else(|| "unknown".into());

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let path = std::path::Path::new(&out_dir).join("build_info.rs");
    std::fs::write(
        &path,
        format!(
            "/// Short git commit the binary was built from (\"unknown\" off a git checkout).\n\
             pub const GIT_SHA: &str = {sha:?};\n\
             /// Commit date `YYYY-MM-DD`, or \"unknown\".\n\
             pub const COMMIT_DATE: &str = {date:?};\n"
        ),
    )
    .expect("write build_info.rs");
}
