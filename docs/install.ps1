# ADhammer Windows install helper — one-liner install with the Defender dance handled.
#
# Public use:
#   iwr https://raw.githubusercontent.com/icedracon/adhammer/main/docs/install.ps1 | iex
#
# What it does:
#   1. Verifies cargo is on PATH; refuses to run if not (install Rust first).
#   2. Adds a temporary Microsoft Defender exclusion for `%USERPROFILE%\.cargo`
#      (both the registry and the resolved binary directory). Prior 1.4.7
#      verification confirmed: without this, `cargo install adhammer` on a
#      fresh Windows quarantines the built exe with `os error 225 — file
#      contains a virus or potentially unwanted software`.
#   3. Runs `cargo binstall adhammer` (prebuilt binary path, fast — needs the
#      `cargo-binstall` extension). Falls back to building the same immutable
#      GitHub release tag when `cargo-binstall` is not present.
#   4. Removes the temporary exclusion.
#   5. Prints the installed binary path + `--version`.
#
# Idempotent. Safe to re-run — the exclusion add/remove pair is a no-op when
# the exclusion already exists or was never granted.
#
# Requires: cargo (from https://rustup.rs). Recommended: cargo-binstall.
#
# Runs BOTH interactively AND as `iwr | iex`. Non-elevated by default; when
# elevation is needed for `Add-MpPreference` the script asks Windows to
# self-elevate the exclusion step only and continues in the original session.

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$ReleaseVersion = '1.4.10'

function Write-Step { param([string]$Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-OK   { param([string]$Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }

# --- Step 1: cargo present? ------------------------------------------------

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    Write-Warn 'cargo not found on PATH. Install Rust first:  https://rustup.rs'
    Write-Warn 'Then re-run this script.'
    exit 1
}
Write-OK "cargo found: $($cargo.Source)"

$binstall = Get-Command cargo-binstall -ErrorAction SilentlyContinue
$useBinstall = $null -ne $binstall
if ($useBinstall) {
    Write-OK 'cargo-binstall found — will use prebuilt binary path'
} else {
    Write-Warn "cargo-binstall not found — will build v$ReleaseVersion from its Git tag"
    Write-Warn '(install cargo-binstall for a faster path: cargo install cargo-binstall)'
}

# --- Step 2: Defender exclusion --------------------------------------------

$cargoRoot = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$cargoBin = Join-Path $cargoRoot 'bin'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$exclusionAdded = $false
$defenderPresent = $null -ne (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)

if ($defenderPresent) {
    if ($isAdmin) {
        Write-Step "adding temporary Defender exclusion: $cargoRoot"
        try {
            Add-MpPreference -ExclusionPath $cargoRoot -ErrorAction Stop
            $exclusionAdded = $true
            Write-OK 'exclusion added'
        } catch {
            Write-Warn "could not add exclusion ($($_.Exception.Message)) — continuing anyway"
        }
    } else {
        Write-Warn "not running as admin — skipping Defender exclusion."
        Write-Warn "If the install below trips 'os error 225 — file contains a virus',"
        Write-Warn "re-run this script from an ELEVATED PowerShell, OR run once as admin:"
        Write-Warn "  Add-MpPreference -ExclusionPath '$cargoRoot'"
    }
} else {
    Write-Warn 'no Microsoft Defender detected — skipping exclusion step'
}

# --- Step 3: install -------------------------------------------------------

Write-Step 'installing adhammer...'
$installOk = $false
try {
    if ($useBinstall) {
        & cargo binstall --no-confirm adhammer
    } else {
        & cargo install --locked --git https://github.com/icedracon/adhammer --tag "v$ReleaseVersion" adhammer
    }
    if ($LASTEXITCODE -eq 0) { $installOk = $true }
} catch {
    Write-Warn "install threw: $($_.Exception.Message)"
}

# --- Step 4: remove the exclusion (best-effort) ----------------------------

if ($exclusionAdded) {
    Write-Step 'removing temporary Defender exclusion'
    try {
        Remove-MpPreference -ExclusionPath $cargoRoot -ErrorAction Stop
        Write-OK 'exclusion removed'
    } catch {
        Write-Warn "could not remove exclusion — remove manually with:"
        Write-Warn "  Remove-MpPreference -ExclusionPath '$cargoRoot'"
    }
}

# --- Step 5: verify --------------------------------------------------------

if (-not $installOk) {
    Write-Warn 'install did not report success. Common causes:'
    Write-Warn '  - Defender quarantined the binary (re-run elevated, or add exclusion manually)'
    Write-Warn '  - Network issue reaching crates.io / GitHub Releases'
    Write-Warn '  - Rust toolchain too old (adhammer requires MSRV 1.87+)'
    exit 1
}

$binary = Join-Path $cargoBin 'adhammer.exe'
if (-not (Test-Path $binary)) {
    Write-Warn "install reported success but binary not found at $binary"
    exit 1
}

Write-Host ''
Write-OK "adhammer installed at $binary"
& $binary --version
Write-Host ''
Write-Host 'Try:   adhammer scan --url ldaps://<dc>:636 --user <you> --password <...> --insecure' -ForegroundColor Cyan
Write-Host 'Or:    adhammer               # interactive guided mode' -ForegroundColor Cyan
