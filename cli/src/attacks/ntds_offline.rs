//! `attack ntds-offline` — offline NTDS.dit domain-secrets extraction.
//!
//! **1.5.2 scaffold.** Full end-to-end secretsdump-`-ntds`-style extraction needs
//! two things: (a) a ROW walker over the ESE `datatable` (the `ese-parser 0.1.x`
//! upstream stops at the header + random-access page layer; row/tag decode is
//! their v0.2 roadmap), and (b) the SYSTEM-hive bootkey chain that
//! `attack secretsdump` already implements via `adhammer-secrets`. This build
//! ships the surface + validation layer:
//!
//! - Validates the ESE file header (magic, format version, page size) via
//!   `ese_parser::EseFile::open` — proves the input really is an NTDS.dit.
//! - Reports the format + page-size + log-generation metadata so an operator
//!   can triage a captured `.dit` before handing it to a slower specialist.
//! - Emits a `[hint]` block pointing at `impacket-secretsdump -ntds <file>
//!   -system <system.hive> LOCAL` with the paths pre-substituted, so the CLI
//!   surface is stable for muscle memory + scripting while the pure-Rust row
//!   walk matures upstream.
//!
//! Same staging pattern as F5 `lsa lsass-parse` (docs/PRE_REVIEW_1.5.1.md §5)
//! and F4a `creds kdbx-*` (crack → hashcat, extract in-tree).

use anyhow::{Context, Result};
use clap::Parser;
use ese_parser::EseFile;

#[derive(Parser)]
pub(crate) struct NtdsOfflineArgs {
    /// Path to a captured `NTDS.dit` file. Typical sources: `ntdsutil ...
    /// activate instance ntds ... ifm ... create full <dir>`, a VSS snapshot
    /// of `C:\Windows\NTDS\ntds.dit`, or a DCSync-blocked engagement's
    /// last-resort SYSTEM+NTDS pair.
    #[arg(long, value_name = "PATH")]
    pub ntds: String,
    /// Path to the paired SYSTEM registry hive (`C:\Windows\System32\config\
    /// SYSTEM` OR the same-named file from an `ntdsutil ifm` dump). Required
    /// to derive the bootkey → PEK chain.
    #[arg(long, value_name = "PATH")]
    pub system: String,
    /// Emit JSON envelope.
    #[arg(long)]
    pub json: bool,
}

pub(crate) async fn ntds_offline(a: NtdsOfflineArgs) -> Result<()> {
    let sp = crate::ui::Spinner::start(format!("ESE header validate → {}", a.ntds));

    let f = EseFile::open(&a.ntds).with_context(|| format!("open ESE file {}", a.ntds))?;

    // Header-only validator today — record what we CAN prove.
    let fmt_ver = f.format_version();
    let page = f.page_size();
    let file_type = format!("{:?}", f.file_type());

    // The SYSTEM hive is validated later (bootkey extraction), but confirm the
    // file exists + is readable now so we fail early on a wrong path.
    let sys_meta =
        std::fs::metadata(&a.system).with_context(|| format!("stat --system {}", a.system))?;
    let sys_size = sys_meta.len();

    sp.done(&format!(
        "{}: ESE format v{} · {}-byte page · type={} · SYSTEM hive {} bytes",
        a.ntds, fmt_ver, page, file_type, sys_size
    ));

    eprintln!(
        "[hint] this step is a known adhammer gap: NTDS.dit ESE row walk lands \
         upstream at ese-parser 0.2. adhammer-secrets already carries bootkey \
         + PEK crypto; the last mile is the datatable B-tree walk."
    );
    eprintln!(
        "[hint] external tool: impacket-secretsdump -ntds {ntds} -system {sys} LOCAL",
        ntds = a.ntds,
        sys = a.system
    );
    eprintln!("[hint] see docs/GAPS.md#ntds-dit-offline for the full row");

    if a.json {
        println!(
            "{{\"command\":\"adhammer attack ntds-offline\",\"success\":true,\
             \"evidence\":{{\"ntds\":{n:?},\"system\":{s:?},\
             \"ese_format\":{fv},\"page_size\":{ps},\"file_type\":{ft:?},\
             \"system_hive_bytes\":{ss},\
             \"status\":\"validated; row walk deferred to ese-parser 0.2\"}}}}",
            n = a.ntds,
            s = a.system,
            fv = fmt_ver,
            ps = page,
            ft = file_type,
            ss = sys_size
        );
    }
    Ok(())
}
