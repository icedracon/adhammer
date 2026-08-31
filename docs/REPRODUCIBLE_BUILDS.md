# Reproducible builds

This document states, honestly, **what is and isn't reproducible today**
about ADhammer release artifacts. Auditors' first question after "is
your CI green" and "where's the SBOM" is "can I rebuild this bit-for-
bit from source?" — the honest answer is *mostly, with caveats*.

## What is reproducible today

Given the same:

- git commit SHA
- release workflow (`.github/workflows/release.yml`)
- runner image (Ubuntu-latest / Windows-latest / macOS-latest, all
  pinned to a version by GitHub for a given date)
- Rust toolchain (each channel — stable / nightly / master — pinned to
  a commit SHA via `dtolnay/rust-toolchain@<sha>`; see
  `.github/dependabot.yml` for the update cadence)
- Cargo.lock (committed, `--locked` on every build in release.yml)

You get **bit-identical output** for:

- The Cargo-produced dependency graph (crates-io serves immutable
  tarballs by version; Cargo.lock pins hashes)
- The rustc binary version resolved through
  `dtolnay/rust-toolchain@<sha>`
- Every `[[bin]]` link — same input source, same compiler, same libc
  = same output object files

## What is not reproducible today

**Timestamps embedded in the binary.** Rust and cargo embed build-time
information in some places (debug info if `--release` doesn't strip,
DWARF timestamps, `.deb` control file). Two independent builds on
different days may differ in these bytes.

**Runner-image-local system libraries.** `x86_64-unknown-linux-gnu`
links glibc from the Ubuntu image; a runner rebuilt against a newer
Ubuntu patch level gets a newer glibc, and the binary changes even if
source + Rust + Cargo.lock don't. This is why we ship both a `-gnu`
build (fast, glibc-linked) and a `-musl` build (fully static, no libc
dependency) — the musl artifact is more reproducible in practice.

**cargo-deb output packaging.** Some fields (build-date in control
file, tarball mtimes inside the ar archive) are process-time
sensitive. `SOURCE_DATE_EPOCH` env var mitigates this — see below.

## The `SOURCE_DATE_EPOCH` mitigation

The Reproducible-Builds project's `SOURCE_DATE_EPOCH` variable
overrides most timestamp embedding. The release workflow derives it
from the git tag commit's timestamp so every rebuild of the same
tag produces the same value:

    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

This is set in `release.yml` for every build job. Effect: `cargo-deb`
control-file timestamps and inner-tarball mtimes match tag-cut time,
not workflow-run time.

## The `x86_64-unknown-linux-musl` reproducibility profile

The recommended reproducibility path is the musl build:

- Fully static — no glibc or runtime C library dependency to drift
- Cross-compiled from Ubuntu-latest via
  `rust-toolchain add x86_64-unknown-linux-musl`
- `SOURCE_DATE_EPOCH` set per above
- `--locked --frozen` on cargo build

Verification recipe (for the auditor):

    git clone https://github.com/icedracon/adhammer && cd adhammer
    git checkout v<X.Y.Z>
    export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
    rustup target add x86_64-unknown-linux-musl
    cargo build --release --locked --frozen \
        --target x86_64-unknown-linux-musl -p adhammer
    sha256sum target/x86_64-unknown-linux-musl/release/adhammer
    # compare to the sha256 on the GitHub Releases page

Discrepancies from the released sha256 have known causes:
1. Toolchain mismatch — verify `rustc --version` matches the tag's
   `.github/workflows/release.yml` toolchain pin.
2. glibc drift — this recipe uses musl, so glibc drift is out of
   scope; if you build the `-gnu` target you'll see it.
3. Different Ubuntu runner image — GitHub bumps `ubuntu-latest`
   periodically; the exact image is recorded in the run log's
   "Runner" step.

## Not yet claimed

- **SLSA Level 3 provenance** — sigstore attestations are level 2.
  Level 3 requires a hardened build platform + non-falsifiable
  provenance. Deferred to 2.0.
- **Deterministic linker output across OSes** — every OS's toolchain
  emits its own object file format; cross-platform bit-identity is
  out of scope.
- **`.deb` cross-verifier tooling** — cargo-deb + SOURCE_DATE_EPOCH
  gets you close on Linux; formal verification via `diffoscope`
  would tell you exactly what's still floating. Not automated today.

## Related

- <https://reproducible-builds.org/> — SOURCE_DATE_EPOCH spec
- 1.4.8 audit § 12 (Supply chain), the paragraph flagging
  "No reproducible-build claim"
- `docs/SUPPLY_CHAIN.md` — SBOM + sigstore verification
- `SECURITY.md` § "Signing key custody"
