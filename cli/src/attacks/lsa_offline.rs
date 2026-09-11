//! `lsa` — offline LSASS credential extraction primitives.
//!
//! First inhabitant (1.5.1 F5, scaffold): `lsa lsass-parse <dump>` — parses a
//! Windows minidump (`.dmp`) file's outer header + stream directory and
//! prints an inventory of what's inside. This is the **surface** for the
//! full LSASS-symbol walk (WDigest / MSV1_0 / TSPKG / Kerberos / SSP) that
//! ships in follow-up commits.
//!
//! **Why staged:** the per-version LSASS symbol offsets (lsasrv.dll's
//! `LogonSessionList` + `LogonSessionListCount`) are per-Windows-build
//! moving targets — a specialist tool (`pypykatz`) already maintains that
//! table. Landing the outer minidump reader now gives:
//!   1. an honest "here's what's in your dump" answer (module count, OS
//!      build, arch, thread count) that helps the operator triage which
//!      dumps are worth handing to the specialist tool;
//!   2. an integrated `[hint]` block pointing at the specialist with the
//!      captured dump path pre-substituted;
//!   3. the CLI surface (`Command::Lsa`, `LsaCmd::LsassParse`) so a
//!      follow-up commit fills the symbol walk without breaking any user's
//!      muscle memory.
//!
//! Minidump format reference: MSDN _MINIDUMP_HEADER + _MINIDUMP_DIRECTORY.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub(crate) enum LsaCmd {
    /// **[SCAFFOLDING]** Parse a Windows minidump (`.dmp`) header + stream
    /// directory and print an inventory. **This is not credential extraction.**
    /// It reads only the outer MDMP header (MSDN _MINIDUMP_HEADER +
    /// _MINIDUMP_DIRECTORY) — module count, OS build, arch, thread count — so
    /// you can triage which dumps are worth handing to a specialist tool. The
    /// per-Windows-build LSASS symbol walk (`LogonSessionList`,
    /// credential-package secrets) is a follow-up workstream and is NOT
    /// present in this build. The verb emits a `[hint]` block pointing at
    /// the specialist tool with your dump path pre-substituted; run that
    /// tool for the actual creds. Hidden from `--help` until the symbol
    /// walk lands, per the 1.4.7 `check krb-seal` scaffolding precedent
    /// (docs/PRE_REVIEW_1.5.1.md §5).
    #[command(hide = true)]
    LsassParse(LsassParseArgs),
}

#[derive(Parser)]
pub(crate) struct LsassParseArgs {
    /// Path to the minidump file (`.dmp`).
    #[arg(value_name = "PATH")]
    pub file: String,
    /// Suppress the external-tool `[hint]` (for scripted pipelines that
    /// only want the inventory).
    #[arg(long)]
    pub no_hint: bool,
}

const MDMP_SIGNATURE: u32 = 0x504D_444D; // 'MDMP' little-endian

pub(crate) async fn lsass_parse(a: LsassParseArgs) -> Result<()> {
    // Scaffolding banner (1.4.7 `check krb-seal` precedent) — the verb is
    // hidden from --help but reachable by name; a caller who typed the name
    // must be told what this actually does vs what pypykatz would.
    eprintln!(
        "[SCAFFOLDING] lsa lsass-parse only reads the outer MDMP header + \
         stream directory. It does NOT walk lsasrv.dll symbols and does NOT \
         extract WDigest/MSV1_0/TSPKG/Kerberos/SSP secrets. Use the hint \
         below for actual credential extraction."
    );
    let bytes = std::fs::read(&a.file).with_context(|| format!("read {}", a.file))?;
    if bytes.len() < 32 {
        bail!("file too short for a minidump ({} bytes)", bytes.len());
    }
    let sig = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if sig != MDMP_SIGNATURE {
        bail!("not a minidump — bad signature {sig:#x} (expected MDMP)");
    }
    let version_low = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    let stream_count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let stream_dir_rva = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let flags = u64::from_le_bytes(bytes[24..32].try_into().unwrap());

    println!("[+] minidump OK — version={version_low:#x} streams={stream_count} flags={flags:#x}");

    // Read the stream directory (12 bytes per entry: StreamType u32, DataSize u32, RVA u32).
    let dir_size = stream_count.checked_mul(12).context("stream dir size")?;
    if stream_dir_rva
        .checked_add(dir_size)
        .is_none_or(|end| end > bytes.len())
    {
        bail!(
            "stream directory truncated: rva {stream_dir_rva} + {dir_size}B > file {}B",
            bytes.len()
        );
    }
    let mut has_module_list = false;
    let mut has_thread_list = false;
    let mut has_system_info = false;
    let mut has_memory64 = false;
    println!("    streams:");
    for i in 0..stream_count {
        let off = stream_dir_rva + i * 12;
        let ty = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let sz = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap());
        let rva = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap());
        let name = stream_type_name(ty);
        println!("      · [{ty:>4}] {name:<28} size={sz:>10} rva={rva:>10}");
        match ty {
            4 => has_module_list = true,
            3 => has_thread_list = true,
            7 => has_system_info = true,
            9 | 0x11 /* Memory64ListStream */ => has_memory64 = true,
            _ => {}
        }
    }

    // Surface a system-info summary if the stream is present (helps triage
    // which per-OS offset table pypykatz will need).
    if has_system_info {
        if let Some(sys) = find_stream(&bytes, stream_dir_rva, stream_count, 7) {
            summarize_system_info(&bytes, sys);
        }
    }

    // Triage verdict.
    println!("[i] triage:");
    println!(
        "      · full LSASS walk viable? {}",
        yesno(has_module_list && has_thread_list && has_memory64)
    );
    println!(
        "      · module list present     — {}",
        yesno(has_module_list)
    );
    println!(
        "      · thread list present     — {}",
        yesno(has_thread_list)
    );
    println!("      · memory64 (mem regions)  — {}", yesno(has_memory64));

    if !a.no_hint {
        let mut p = crate::gap_hint::HintParams::new();
        p.file = Some(a.file.clone());
        crate::gap_hint::hint_external(crate::gap_hint::Gap::LsassMinidump, &p);
    }
    Ok(())
}

/// Locate a stream's (rva, size) by StreamType. Returns None if absent.
fn find_stream(
    bytes: &[u8],
    dir_rva: usize,
    count: usize,
    want_type: u32,
) -> Option<(usize, usize)> {
    for i in 0..count {
        let off = dir_rva + i * 12;
        if off + 12 > bytes.len() {
            return None;
        }
        let ty = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        if ty != want_type {
            continue;
        }
        let sz = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()) as usize;
        let rva = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap()) as usize;
        return Some((rva, sz));
    }
    None
}

/// Print a summary of the SystemInfoStream: OS build + arch + processor count.
fn summarize_system_info(bytes: &[u8], (rva, sz): (usize, usize)) {
    if sz < 24 || rva + 24 > bytes.len() {
        return;
    }
    // MDRawSystemInfo: ProcessorArchitecture u16, ProcessorLevel u16, ProcessorRevision u16,
    //                  NumberOfProcessors u8, ProductType u8, MajorVersion u32, MinorVersion u32,
    //                  BuildNumber u32, PlatformId u32, ...
    let arch = u16::from_le_bytes(bytes[rva..rva + 2].try_into().unwrap());
    let n_proc = bytes[rva + 6];
    let major = u32::from_le_bytes(bytes[rva + 8..rva + 12].try_into().unwrap());
    let minor = u32::from_le_bytes(bytes[rva + 12..rva + 16].try_into().unwrap());
    let build = u32::from_le_bytes(bytes[rva + 16..rva + 20].try_into().unwrap());
    let arch_s = match arch {
        0 => "x86",
        6 => "IA64",
        9 => "AMD64",
        12 => "ARM64",
        _ => "?",
    };
    println!("    system info: arch={arch_s} os={major}.{minor}.{build} n_proc={n_proc}");
}

fn stream_type_name(ty: u32) -> &'static str {
    match ty {
        0 => "UnusedStream",
        3 => "ThreadListStream",
        4 => "ModuleListStream",
        5 => "MemoryListStream",
        6 => "ExceptionStream",
        7 => "SystemInfoStream",
        8 => "ThreadExListStream",
        9 => "Memory64ListStream",
        10 => "CommentStreamA",
        11 => "CommentStreamW",
        12 => "HandleDataStream",
        13 => "FunctionTableStream",
        14 => "UnloadedModuleListStream",
        15 => "MiscInfoStream",
        16 => "MemoryInfoListStream",
        17 => "ThreadInfoListStream",
        18 => "HandleOperationListStream",
        19 => "TokenStream",
        _ => "(other)",
    }
}

fn yesno(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_file() {
        // Attempt to parse a 4-byte file → header-length bail.
        let dir = std::env::temp_dir();
        let p = dir.join("adhammer-lsa-short.dmp");
        std::fs::write(&p, [0u8; 4]).unwrap();
        let path_s = p.to_string_lossy().to_string();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(lsass_parse(LsassParseArgs {
                file: path_s,
                no_hint: true,
            }))
            .unwrap_err();
        assert!(format!("{err:#}").contains("too short"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_bad_signature() {
        let dir = std::env::temp_dir();
        let p = dir.join("adhammer-lsa-badsig.dmp");
        // 32 zero bytes → sig 0 != MDMP
        std::fs::write(&p, [0u8; 128]).unwrap();
        let path_s = p.to_string_lossy().to_string();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(lsass_parse(LsassParseArgs {
                file: path_s,
                no_hint: true,
            }))
            .unwrap_err();
        assert!(format!("{err:#}").contains("bad signature"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn stream_type_name_covers_the_common_ones() {
        assert_eq!(stream_type_name(3), "ThreadListStream");
        assert_eq!(stream_type_name(4), "ModuleListStream");
        assert_eq!(stream_type_name(7), "SystemInfoStream");
        assert_eq!(stream_type_name(9), "Memory64ListStream");
        assert_eq!(stream_type_name(99999), "(other)");
    }

    #[test]
    fn parses_minimal_valid_header() {
        // Build a minimum valid MDMP: 32B header + 0 streams.
        let mut buf = Vec::new();
        buf.extend_from_slice(&MDMP_SIGNATURE.to_le_bytes()); // sig
        buf.extend_from_slice(&0xA793u32.to_le_bytes()); // Version (low 0xA793, high 0x0000 = MDMP)
        buf.extend_from_slice(&0u32.to_le_bytes()); // NumberOfStreams = 0
        buf.extend_from_slice(&0u32.to_le_bytes()); // StreamDirectoryRva = 0
        buf.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        buf.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        buf.extend_from_slice(&0u64.to_le_bytes()); // Flags
        let dir = std::env::temp_dir();
        let p = dir.join("adhammer-lsa-min.dmp");
        std::fs::write(&p, &buf).unwrap();
        let path_s = p.to_string_lossy().to_string();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let r = rt.block_on(lsass_parse(LsassParseArgs {
            file: path_s,
            no_hint: true,
        }));
        assert!(
            r.is_ok(),
            "expected OK for a minimal valid header, got {r:?}"
        );
        let _ = std::fs::remove_file(&p);
    }
}
