//! Network sweep: full service scan + banner grab per target, DC detection, and SMB signing
//! (NTLM-relay) posture — the attack-surface map for the whole estate.

use anyhow::{Context, Result};
use clap::Parser;

use crate::ui;

#[derive(Parser)]
pub(crate) struct NetArgs {
    /// Targets: CIDR (10.0.0.0/24), comma-list (a,b,c), or @file (one host per line)
    #[arg(long)]
    pub targets: String,
    /// Max concurrent host probes
    #[arg(long, default_value = "256")]
    pub concurrency: usize,
    /// Per-service checks: FTP anon, SMTP VRFY, DNS version/AXFR, NFS showmount, rsync modules,
    /// SNMP community, MSSQL/MySQL version+login, RPC/EPM surface, WinRM auth, VNC no-auth, Redis
    #[arg(long)]
    pub deep: bool,
    /// DNS zone to attempt AXFR against (deep DNS check); e.g. corp.local
    #[arg(long)]
    pub zone: Option<String>,
    /// SNMP community strings to try (deep, UDP/161); comma-separated
    #[arg(long, default_value = "public,private")]
    pub community: String,
}

/// Common service ports scanned by the network sweep (FTP → RDP and the rest of the estate).
const SERVICES: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (88, "kerberos"),
    (110, "pop3"),
    (111, "rpcbind"),
    (135, "msrpc"),
    (139, "netbios"),
    (143, "imap"),
    (389, "ldap"),
    (443, "https"),
    (445, "smb"),
    (464, "kpasswd"),
    (587, "smtp"),
    (636, "ldaps"),
    (873, "rsync"),
    (993, "imaps"),
    (995, "pop3s"),
    (1433, "mssql"),
    (1521, "oracle"),
    (2049, "nfs"),
    (3268, "gc"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5432, "postgres"),
    (5900, "vnc"),
    (5985, "winrm"),
    (5986, "winrm-s"),
    (6379, "redis"),
    (8080, "http-alt"),
    (8443, "https-alt"),
    (9200, "elastic"),
];
/// Ports whose services send a text greeting on connect — grab it for version intel.
const GREETERS: &[u16] = &[21, 22, 25, 110, 143];

pub(crate) async fn netenum(a: NetArgs) -> Result<()> {
    let hosts = expand_targets(&a.targets)?;
    let sp = ui::Spinner::start(format!(
        "sweeping {} host(s) × {} ports",
        hosts.len(),
        SERVICES.len()
    ));

    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(a.concurrency));
    let mut set = tokio::task::JoinSet::new();
    for host in hosts {
        for &(port, svc) in SERVICES {
            let sem = sem.clone();
            let host = host.clone();
            set.spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let banner = probe_port(&host, port).await?; // None if closed
                Some((host, port, svc, banner))
            });
        }
    }
    // Group open ports by host. (port, service-name, optional banner)
    type PortEntry = (u16, &'static str, Option<String>);
    let mut hosts_map: std::collections::HashMap<String, Vec<PortEntry>> = Default::default();
    while let Some(r) = set.join_next().await {
        if let Ok(Some((host, port, svc, banner))) = r {
            hosts_map.entry(host).or_default().push((port, svc, banner));
        }
    }

    // SMB signing (relay) posture for hosts exposing 445.
    let mut signing: std::collections::HashMap<String, (u16, bool)> = Default::default();
    for (host, ports) in &hosts_map {
        if ports.iter().any(|(p, _, _)| *p == 445) {
            if let Ok(mut c) = smb2_client::SmbClient::connect(host).await {
                if let Ok(s) = c.probe_signing().await {
                    signing.insert(host.clone(), s);
                }
            }
        }
    }

    let mut hosts_sorted: Vec<_> = hosts_map.into_iter().collect();
    hosts_sorted.sort_by_key(|(h, _)| {
        h.parse::<std::net::Ipv4Addr>()
            .map(u32::from)
            .unwrap_or(u32::MAX)
    });

    if hosts_sorted.is_empty() {
        sp.done_warn("no live hosts found in range");
    } else {
        sp.done(&format!("{} live host(s)", hosts_sorted.len()));
    }
    ui::header(&format!(
        "network sweep — {} live host(s)",
        hosts_sorted.len()
    ));
    let mut relay = Vec::new();
    for (host, mut ports) in hosts_sorted {
        ports.sort_by_key(|(p, _, _)| *p);
        let has = |p: u16| ports.iter().any(|(x, _, _)| *x == p);
        let role = if has(88) && has(389) { "DC  " } else { "host" };
        println!("  {host:<15} {role}");
        for (port, svc, banner) in &ports {
            let b = banner
                .as_deref()
                .map(|s| format!("  {s}"))
                .unwrap_or_default();
            println!("      {port:<5} {svc:<10}{b}");
        }
        if let Some((d, req)) = signing.get(&host) {
            if *req {
                println!("      445   smb-signing REQUIRED (0x{d:04x})");
            } else {
                println!("      445   smb-signing OFF → NTLM-RELAY TARGET (0x{d:04x})");
                relay.push(host.clone());
            }
        }
        if a.deep {
            for (port, _, _) in &ports {
                if let Some(finding) = deep_check(&host, *port, a.zone.as_deref()).await {
                    println!("      [!]   {port:<5} {finding}");
                }
            }
            // SNMP is UDP/161 — not in the TCP sweep, so probe it per host under --deep.
            if let Some(finding) = snmp_public(&host, &a.community).await {
                println!("      [!]   161   {finding}");
            }
        }
    }
    if !relay.is_empty() {
        println!(
            "\n[+] {} NTLM-relay target(s) (SMB signing not required): {}",
            relay.len(),
            relay.join(", ")
        );
    }
    Ok(())
}

/// Connect to `host:port` (timeout). Returns Some(banner) if open — banner is the service
/// greeting for text protocols, empty otherwise; None if the port is closed/filtered.
async fn probe_port(host: &str, port: u16) -> Option<Option<String>> {
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};
    let connect = smb2_client::socks::dial(host, port);
    let mut stream = match timeout(Duration::from_millis(800), connect).await {
        Ok(Ok(s)) => s,
        _ => return None, // closed / filtered
    };
    if !GREETERS.contains(&port) {
        return Some(None);
    }
    // Read the service greeting (FTP/SSH/SMTP/POP3/IMAP announce on connect).
    let mut buf = [0u8; 256];
    let banner = match timeout(Duration::from_millis(600), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let line = String::from_utf8_lossy(&buf[..n]);
            Some(line.lines().next().unwrap_or("").trim().to_string())
        }
        _ => None,
    };
    Some(banner)
}

/// Per-service unauthenticated attack checks (--deep).
async fn deep_check(host: &str, port: u16, zone: Option<&str>) -> Option<String> {
    match port {
        21 => ftp_anon(host).await,
        25 => smtp_vrfy(host).await,
        53 => dns_check(host, zone).await,
        111 => nfs_showmount(host).await, // portmap → mountd EXPORT; covers NFS behind it
        135 => rpc_surface(host).await,
        873 => rsync_modules(host).await,
        1433 => mssql_prelogin(host).await,
        3306 => mysql_probe(host).await,
        6379 => redis_unauth(host).await,
        5900 => vnc_noauth(host).await,
        5985 | 5986 => winrm_probe(host, port).await,
        _ => None,
    }
}

async fn connect(host: &str, port: u16) -> Option<tokio::net::TcpStream> {
    tokio::time::timeout(
        std::time::Duration::from_millis(1200),
        smb2_client::socks::dial(host, port),
    )
    .await
    .ok()?
    .ok()
}
async fn read_some(s: &mut tokio::net::TcpStream, buf: &mut [u8]) -> usize {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_millis(900), s.read(buf))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0)
}

/// True if an HTTP reply to `/certsrv` is an NTLM/Negotiate 401 over cleartext HTTP — the
/// relayable ESC8 web-enrollment surface (no TLS ⇒ no channel binding to stop the relay).
fn is_esc8_response(resp: &str) -> bool {
    let head = resp.split("\r\n\r\n").next().unwrap_or(resp);
    let low = head.to_ascii_lowercase();
    head.contains(" 401")
        && low.contains("www-authenticate")
        && (low.contains("negotiate") || low.contains("ntlm"))
}

/// WS-WPT: outcome of an ESC8 probe — the finding text plus the exact HTTP request/response
/// exchange that produced the verdict, so downstream can attach `wire` to the Finding.
pub(crate) struct Esc8Probe {
    pub finding_text: String,
    pub wire: Vec<adhammer_core::WireExchange>,
}

/// ESC8 detection: probe a CA host's web-enrollment endpoint over HTTP/80. A cleartext NTLM 401
/// means the CA is relay-enrollable (coerce a machine → relay its NTLM to `/certsrv` → machine
/// cert → PKINIT → its TGT). Returns the probe outcome + wire transcript, or None if not exposed.
pub(crate) async fn esc8_probe(host: &str) -> Option<Esc8Probe> {
    use adhammer_core::{WireExchange, WireLayer};
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, 80).await?;
    let req =
        format!("GET /certsrv/certfnsh.asp HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 2048];
    let n = read_some(&mut s, &mut buf).await;
    let resp = String::from_utf8_lossy(&buf[..n]);

    if !is_esc8_response(&resp) {
        return None;
    }

    // WS-WPT: capture the actual conversation — request line + host, response status line +
    // WWW-Authenticate — so the report shows "adhammer sent X, CA replied Y, that reply means
    // NTLM-over-cleartext is enabled → relayable."
    let status_line = resp.lines().next().unwrap_or("<no status>").to_string();
    let www_auth = resp
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("www-authenticate:"))
        .unwrap_or("<no WWW-Authenticate header>")
        .to_string();
    let wire = vec![
        WireExchange::sent(
            WireLayer::Http,
            format!("GET http://{host}/certsrv/certfnsh.asp"),
        )
        .with_raw_bytes(req.as_bytes()),
        WireExchange::recv(WireLayer::Http, format!("{status_line}  ·  {www_auth}"))
            .with_raw_bytes(&buf[..n.min(512)]),
    ];

    Some(Esc8Probe {
        finding_text: format!(
            "ESC8: web enrollment at http://{host}/certsrv exposes NTLM over cleartext (relayable)"
        ),
        wire,
    })
}

async fn ftp_anon(host: &str) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, 21).await?;
    let mut buf = [0u8; 512];
    read_some(&mut s, &mut buf).await; // 220 banner
    s.write_all(b"USER anonymous\r\n").await.ok()?;
    read_some(&mut s, &mut buf).await;
    s.write_all(b"PASS anonymous@adhammer\r\n").await.ok()?;
    let n = read_some(&mut s, &mut buf).await;
    String::from_utf8_lossy(&buf[..n])
        .starts_with("230")
        .then(|| "FTP: ANONYMOUS LOGIN ALLOWED".to_string())
}

async fn smtp_vrfy(host: &str) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, 25).await?;
    let mut buf = [0u8; 512];
    read_some(&mut s, &mut buf).await;
    s.write_all(b"VRFY root\r\n").await.ok()?;
    let n = read_some(&mut s, &mut buf).await;
    let r = String::from_utf8_lossy(&buf[..n]);
    (r.starts_with("250") || r.starts_with("252"))
        .then(|| "SMTP: VRFY enabled (user enumeration)".to_string())
}

async fn redis_unauth(host: &str) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, 6379).await?;
    s.write_all(b"INFO\r\n").await.ok()?;
    let mut buf = [0u8; 512];
    let n = read_some(&mut s, &mut buf).await;
    String::from_utf8_lossy(&buf[..n])
        .contains("redis_version")
        .then(|| "REDIS: UNAUTHENTICATED (no AUTH required)".to_string())
}

/// EPM (135): report which attack-relevant RPC interfaces are registered on the endpoint mapper.
async fn rpc_surface(host: &str) -> Option<String> {
    use dcerpc::{epm, Syntax};
    let ifaces = [
        (
            "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
            4u16,
            0u16,
            "DRSUAPI(dcsync)",
        ),
        ("367abb81-9844-35f1-ad32-98f038001003", 2, 0, "SVCCTL(exec)"),
        ("86d35949-83c9-4044-b424-db363231fd0c", 1, 0, "TSCH(exec)"),
        (
            "338cd001-2244-31f1-aaaa-900038001003",
            1,
            0,
            "RemoteRegistry",
        ),
        (
            "c681d488-d850-11d0-8c52-00c04fd90f7e",
            1,
            0,
            "EFSR(petitpotam)",
        ),
        (
            "12345678-1234-abcd-ef00-0123456789ab",
            1,
            0,
            "RPRN(printerbug)",
        ),
    ];
    let mut found = Vec::new();
    for (uuid, maj, min, name) in ifaces {
        if epm::resolve_port(host, Syntax::new(uuid, maj, min))
            .await
            .is_ok()
        {
            found.push(name);
        }
    }
    (!found.is_empty()).then(|| format!("RPC/EPM registered: {}", found.join(", ")))
}

/// VNC (5900): RFB handshake — flag if security-type None (no auth) is offered.
async fn vnc_noauth(host: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = connect(host, 5900).await?;
    let mut ver = [0u8; 12];
    tokio::time::timeout(
        std::time::Duration::from_millis(900),
        s.read_exact(&mut ver),
    )
    .await
    .ok()?
    .ok()?;
    if &ver[0..3] != b"RFB" {
        return None;
    }
    s.write_all(&ver).await.ok()?; // accept the server's protocol version
    let mut buf = [0u8; 64];
    let n = read_some(&mut s, &mut buf).await;
    let v = String::from_utf8_lossy(&ver).trim().to_string();
    if n >= 2 {
        let count = buf[0] as usize;
        if buf[1..(1 + count).min(n)].contains(&1) {
            return Some(format!("VNC ({v}): NO AUTH (security-type None offered)"));
        }
        return Some(format!("VNC ({v}): auth required"));
    }
    None
}

/// WinRM (5985/5986): probe /wsman and report the offered HTTP auth methods.
async fn winrm_probe(host: &str, port: u16) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, port).await?;
    let req = format!("POST /wsman HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: 0\r\n\r\n");
    s.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 1024];
    let n = read_some(&mut s, &mut buf).await;
    let r = String::from_utf8_lossy(&buf[..n]);
    if r.contains(" 401") {
        let mut m = Vec::new();
        for a in ["Negotiate", "NTLM", "Kerberos", "Basic"] {
            if r.contains(a) {
                m.push(a);
            }
        }
        Some(format!(
            "WinRM: enabled (auth: {})",
            if m.is_empty() {
                "unknown".into()
            } else {
                m.join("/")
            }
        ))
    } else {
        r.contains("HTTP/1.")
            .then(|| "WinRM: HTTP responding".to_string())
    }
}

/// Rsync (873): speak the rsyncd greeting and list modules — a blank module name asks the
/// daemon to enumerate everything it exports (classic anonymous-rsync exposure).
async fn rsync_modules(host: &str) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut s = connect(host, 873).await?;
    let mut buf = [0u8; 1024];
    let n = read_some(&mut s, &mut buf).await; // "@RSYNCD: <ver>\n"
    let greet = String::from_utf8_lossy(&buf[..n]);
    let ver = greet.strip_prefix("@RSYNCD:").map(|v| v.trim())?;
    // Echo the version back, then send an empty module name to request the module list.
    s.write_all(format!("@RSYNCD: {ver}\n").as_bytes())
        .await
        .ok()?;
    s.write_all(b"\n").await.ok()?;
    let n = read_some(&mut s, &mut buf).await;
    let body = String::from_utf8_lossy(&buf[..n]);
    let mods: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("@RSYNCD"))
        .map(|l| l.split_whitespace().next().unwrap_or(l))
        .collect();
    if mods.is_empty() {
        Some("RSYNC: daemon reachable (no anonymous modules listed)".to_string())
    } else {
        Some(format!(
            "RSYNC: {} module(s) exported: {}",
            mods.len(),
            mods.join(", ")
        ))
    }
}

/// MySQL (3306): parse the initial handshake for the server version, then test an
/// empty-password `root` login — a real credential finding, consistent with the other
/// deep checks (FTP anon / Redis unauth).
async fn mysql_probe(host: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = connect(host, 3306).await?;
    // --- read the server's initial HandshakeV10 packet ---
    let mut hdr = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_millis(1000),
        s.read_exact(&mut hdr),
    )
    .await
    .ok()?
    .ok()?;
    let plen = (hdr[0] as usize) | (hdr[1] as usize) << 8 | (hdr[2] as usize) << 16;
    if !(1..=1024).contains(&plen) {
        return None;
    }
    let mut pkt = vec![0u8; plen];
    s.read_exact(&mut pkt).await.ok()?;
    if pkt.first() != Some(&10) {
        // Not protocol 10 — could be an ERR (e.g. host not allowed). Report what we can.
        if pkt.first() == Some(&0xff) {
            return Some("MySQL: reachable, host-not-allowed / access denied".to_string());
        }
        return Some("MySQL: reachable (unrecognized handshake)".to_string());
    }
    let ver_end = pkt[1..].iter().position(|&b| b == 0).map(|p| p + 1)?;
    let version = String::from_utf8_lossy(&pkt[1..ver_end]).to_string();

    // --- HandshakeResponse41: user root, empty auth, native-password plugin ---
    let mut body = Vec::new();
    body.extend_from_slice(&0x0008_8201u32.to_le_bytes()); // LONG_PASSWORD|PROTOCOL_41|SECURE_CONNECTION|PLUGIN_AUTH
    body.extend_from_slice(&0x0100_0000u32.to_le_bytes()); // max packet 16M
    body.push(0x21); // charset utf8
    body.extend_from_slice(&[0u8; 23]); // reserved
    body.extend_from_slice(b"root\0");
    body.push(0x00); // auth-response length = 0 (empty password)
    body.extend_from_slice(b"mysql_native_password\0");
    let mut resp = vec![
        body.len() as u8,
        (body.len() >> 8) as u8,
        (body.len() >> 16) as u8,
        1,
    ];
    resp.extend_from_slice(&body);
    s.write_all(&resp).await.ok()?;

    // --- read the auth result ---
    let mut rh = [0u8; 4];
    if s.read_exact(&mut rh).await.is_err() {
        return Some(format!(
            "MySQL {version}: handshake parsed (login result unavailable)"
        ));
    }
    let rlen = (rh[0] as usize) | (rh[1] as usize) << 8 | (rh[2] as usize) << 16;
    let mut rp = vec![0u8; rlen.min(1024)];
    let _ = s.read_exact(&mut rp).await;
    match rp.first() {
        Some(0x00) => Some(format!("MySQL {version}: EMPTY root PASSWORD ACCEPTED")),
        Some(0x01) if rp.get(1) == Some(&0x03) => Some(format!(
            "MySQL {version}: EMPTY root PASSWORD ACCEPTED (caching_sha2 fast-auth)"
        )),
        _ => Some(format!(
            "MySQL {version}: auth required (root/empty rejected)"
        )),
    }
}

/// MSSQL (1433): TDS PRELOGIN handshake — reports the SQL Server version and whether transport
/// encryption is enforced (ENCRYPT_OFF/NOT_SUP = credentials cross the wire in cleartext).
async fn mssql_prelogin(host: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = connect(host, 1433).await?;
    // PRELOGIN options: VERSION(0x00,6) ENCRYPTION(0x01,1) TERMINATOR(0xff), then the data.
    let mut opts = Vec::new();
    let data_start = 3 * 2 + 1; // two 5-byte option entries + 1 terminator
    opts.extend_from_slice(&[0x00, 0x00, data_start as u8, 0x00, 0x06]); // VERSION @ +0, len 6
    opts.extend_from_slice(&[0x01, 0x00, (data_start + 6) as u8, 0x00, 0x01]); // ENCRYPTION, len 1
    opts.push(0xff); // terminator
    opts.extend_from_slice(&[0u8; 6]); // VERSION data
    opts.push(0x00); // ENCRYPT_OFF
    let total = 8 + opts.len();
    let mut pkt = vec![0x12, 0x01, (total >> 8) as u8, total as u8, 0, 0, 0, 0]; // TDS header (type PRELOGIN, EOM)
    pkt.extend_from_slice(&opts);
    s.write_all(&pkt).await.ok()?;

    let mut hdr = [0u8; 8];
    tokio::time::timeout(
        std::time::Duration::from_millis(1000),
        s.read_exact(&mut hdr),
    )
    .await
    .ok()?
    .ok()?;
    if hdr[0] != 0x04 {
        return Some("MSSQL: reachable (unexpected TDS response)".to_string());
    }
    let len = ((hdr[2] as usize) << 8 | hdr[3] as usize).saturating_sub(8);
    let mut body = vec![0u8; len.min(512)];
    if s.read_exact(&mut body).await.is_err() || body.len() < 5 {
        return Some("MSSQL: TDS PRELOGIN responded".to_string());
    }
    let (version, enc) = parse_prelogin(&body);
    let v = version.unwrap_or_else(|| "unknown".into());
    let e = match enc {
        Some(0x00) => "encryption OFF (login in cleartext)",
        Some(0x02) => "encryption NOT SUPPORTED (login in cleartext)",
        Some(0x01) => "encryption available",
        Some(0x03) => "encryption REQUIRED",
        _ => "encryption state unknown",
    };
    Some(format!("MSSQL {v}: {e}"))
}

/// Walk a TDS PRELOGIN option table for VERSION(0x00) → "maj.min.build" and ENCRYPTION(0x01).
fn parse_prelogin(body: &[u8]) -> (Option<String>, Option<u8>) {
    let (mut version, mut enc) = (None, None);
    let mut i = 0;
    while i + 5 <= body.len() && body[i] != 0xff {
        let token = body[i];
        let off = (body[i + 1] as usize) << 8 | body[i + 2] as usize;
        let l = (body[i + 3] as usize) << 8 | body[i + 4] as usize;
        if off + l <= body.len() {
            let d = &body[off..off + l];
            if token == 0x00 && l >= 4 {
                version = Some(format!(
                    "{}.{}.{}",
                    d[0],
                    d[1],
                    (d[2] as u16) << 8 | d[3] as u16
                ));
            } else if token == 0x01 && l >= 1 {
                enc = Some(d[0]);
            }
        }
        i += 5;
    }
    (version, enc)
}

/// DNS (53): fingerprint via `version.bind` (CHAOS TXT) and, if a zone is supplied, attempt an
/// AXFR zone transfer over TCP and report how many records the server leaked.
async fn dns_check(host: &str, zone: Option<&str>) -> Option<String> {
    let mut out = Vec::new();
    if let Some(v) = dns_version_bind(host).await {
        out.push(format!("version.bind={v}"));
    }
    if let Some(z) = zone {
        match dns_axfr(host, z).await {
            Some(count) if count > 0 => {
                out.push(format!("AXFR OK for {z}: {count} records LEAKED"))
            }
            Some(_) => out.push(format!("AXFR refused for {z}")),
            None => {}
        }
    }
    (!out.is_empty()).then(|| format!("DNS: {}", out.join(" · ")))
}

/// CHAOS-class TXT query for `version.bind` over UDP — reveals the resolver software/version.
async fn dns_version_bind(host: &str) -> Option<String> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect((host, 53)).await.ok()?;
    // Header: id, flags(RD), qd=1; Question: version.bind TXT CH.
    let mut q = vec![0x13, 0x37, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["version", "bind"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x10, 0x00, 0x03]); // TXT, CHAOS
    sock.send(&q).await.ok()?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_millis(900), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    // Grab the longest printable run in the answer section as the version string.
    let ans = &buf[..n];
    let mut best = String::new();
    let mut cur = String::new();
    for &b in &ans[12.min(n)..] {
        if (0x20..0x7f).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.trim().len() > best.trim().len() {
                best = cur.clone();
            }
            cur.clear();
        }
    }
    if cur.trim().len() > best.trim().len() {
        best = cur;
    }
    let best = best.trim().to_string();
    (best.len() >= 3).then_some(best)
}

/// Attempt a full AXFR zone transfer over TCP/53. Returns the number of resource records
/// returned (0 = server refused / not authoritative), or None if the query failed.
async fn dns_axfr(host: &str, zone: &str) -> Option<usize> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = connect(host, 53).await?;
    let mut msg = vec![0x13, 0x38, 0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]; // no RD; AXFR is authoritative
    for label in zone.split('.').filter(|l| !l.is_empty()) {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0xfc, 0x00, 0x01]); // QTYPE=AXFR(252), QCLASS=IN
    let framed = [&(msg.len() as u16).to_be_bytes()[..], &msg].concat(); // TCP DNS 2-byte length prefix
    s.write_all(&framed).await.ok()?;
    // Read length-prefixed response messages until the connection closes or a short read.
    let mut total_ancount = 0usize;
    let mut got_any = false;
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            s.read_exact(&mut len),
        )
        .await
        {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let n = u16::from_be_bytes(len) as usize;
        if n < 12 {
            break;
        }
        let mut buf = vec![0u8; n];
        if s.read_exact(&mut buf).await.is_err() {
            break;
        }
        got_any = true;
        let rcode = buf[3] & 0x0f;
        if rcode != 0 {
            return Some(0); // REFUSED / NOTAUTH etc.
        }
        total_ancount += u16::from_be_bytes([buf[6], buf[7]]) as usize;
        // AXFR ends when the closing SOA is returned; a single message with ANCOUNT is enough
        // to conclude for our purposes, but keep reading in case it is chunked.
        if total_ancount > 1 {
            break;
        }
    }
    got_any.then_some(total_ancount)
}

/// NFS (via portmap/111): GETPORT for the MOUNT program, then MOUNTPROC_EXPORT to list the
/// exported shares — the `showmount -e` equivalent, a classic data-exposure finding.
async fn nfs_showmount(host: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // --- portmap GETPORT (prog 100000 v2 proc 3) for MOUNT (100005) v3 over TCP(6) ---
    let mut s = connect(host, 111).await?;
    let mut call = rpc_call(100000, 2, 3, 0x4841_4d31);
    call.extend_from_slice(&100005u32.to_be_bytes()); // prog
    call.extend_from_slice(&3u32.to_be_bytes()); // vers
    call.extend_from_slice(&6u32.to_be_bytes()); // proto = TCP
    call.extend_from_slice(&0u32.to_be_bytes()); // port (ignored)
    s.write_all(&rpc_frame(&call)).await.ok()?;
    let reply = rpc_recv(&mut s).await?;
    let port = reply
        .get(reply.len().saturating_sub(4)..)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))?;
    if port == 0 || port > 65535 {
        return Some("NFS: portmap up but MOUNT not registered".to_string());
    }
    // --- MOUNT EXPORT (prog 100005 v3 proc 5) on the resolved port ---
    let mut m = connect(host, port as u16).await?;
    let call = rpc_call(100005, 3, 5, 0x4841_4d32);
    m.write_all(&rpc_frame(&call)).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_millis(1200), m.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    // The export list is a chain of (opaque dirpath, group list, next?) — pull the dirpath strings.
    let exports = parse_exports(&buf[..n.min(buf.len())]);
    if exports.is_empty() {
        Some(format!(
            "NFS: MOUNT on :{port} (no exports listed / access denied)"
        ))
    } else {
        Some(format!(
            "NFS: {} export(s): {}",
            exports.len(),
            exports.join(", ")
        ))
    }
}

/// Build an ONC RPC v2 CALL header with AUTH_NULL creds/verifier for the given program.
fn rpc_call(prog: u32, vers: u32, proc_: u32, xid: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&xid.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes()); // msg_type = CALL
    b.extend_from_slice(&2u32.to_be_bytes()); // rpcvers
    b.extend_from_slice(&prog.to_be_bytes());
    b.extend_from_slice(&vers.to_be_bytes());
    b.extend_from_slice(&proc_.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // cred: AUTH_NULL, len 0
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // verf: AUTH_NULL, len 0
    b
}

/// Wrap an RPC message in a single last-fragment record marker (TCP transport).
fn rpc_frame(msg: &[u8]) -> Vec<u8> {
    let marker = 0x8000_0000u32 | (msg.len() as u32);
    [&marker.to_be_bytes()[..], msg].concat()
}

/// Read one record-marked RPC reply and return the payload after the 24-byte accepted-reply head.
async fn rpc_recv(s: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut m = [0u8; 4];
    tokio::time::timeout(std::time::Duration::from_millis(1200), s.read_exact(&mut m))
        .await
        .ok()?
        .ok()?;
    let len = (u32::from_be_bytes(m) & 0x7fff_ffff) as usize;
    if !(4..=65536).contains(&len) {
        return None;
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

/// Parse a MOUNTPROC_EXPORT reply body into export path strings (best-effort XDR walk).
fn parse_exports(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 24usize.min(body.len()); // skip RPC accepted-reply header
    while i + 4 <= body.len() {
        let more = u32::from_be_bytes(body[i..i + 4].try_into().unwrap());
        i += 4;
        if more != 1 {
            break; // 0 = end of export list
        }
        if i + 4 > body.len() {
            break;
        }
        let dlen = u32::from_be_bytes(body[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if dlen == 0 || dlen > 1024 || i + dlen > body.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&body[i..i + dlen]).to_string());
        i += (dlen + 3) & !3; // XDR 4-byte alignment
                              // Skip the group list attached to this export.
        while i + 4 <= body.len() {
            let g = u32::from_be_bytes(body[i..i + 4].try_into().unwrap());
            i += 4;
            if g != 1 {
                break;
            }
            if i + 4 > body.len() {
                break;
            }
            let glen = u32::from_be_bytes(body[i..i + 4].try_into().unwrap()) as usize;
            i += 4 + ((glen + 3) & !3);
        }
    }
    out
}

/// SNMP (UDP/161): GET sysDescr.0 with each community string; a valid reply means the community
/// is accepted (read access to the whole MIB) — reports the community and the system descriptor.
async fn snmp_public(host: &str, communities: &str) -> Option<String> {
    for community in communities
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        if let Some(desc) = snmp_get_sysdescr(host, community).await {
            let d = desc.chars().take(60).collect::<String>();
            return Some(format!("SNMP: community '{community}' VALID → {d}"));
        }
    }
    None
}

/// One SNMPv1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0); returns the descriptor if accepted.
async fn snmp_get_sysdescr(host: &str, community: &str) -> Option<String> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect((host, 161)).await.ok()?;
    let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]; // 1.3.6.1.2.1.1.1.0
    let varbind = ber_seq(&[ber(0x06, &oid), ber(0x05, &[])].concat()); // OID + NULL
    let varbinds = ber_seq(&varbind);
    let pdu_body = [
        ber(0x02, &[0x2a]), // request-id
        ber(0x02, &[0x00]), // error-status
        ber(0x02, &[0x00]), // error-index
        varbinds,
    ]
    .concat();
    let pdu = ber(0xa0, &pdu_body); // GetRequest
    let msg = ber_seq(
        &[
            ber(0x02, &[0x00]),              // version = 0 (v1)
            ber(0x04, community.as_bytes()), // community
            pdu,
        ]
        .concat(),
    );
    sock.send(&msg).await.ok()?;
    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(std::time::Duration::from_millis(900), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    // Any well-formed SEQUENCE reply means the community was accepted; pull the sysDescr string.
    let resp = &buf[..n];
    if resp.first() != Some(&0x30) {
        return None;
    }
    Some(snmp_first_octet_string(resp).unwrap_or_else(|| "(accepted)".to_string()))
}

/// Minimal BER: definite-length TLV (lengths < 65536).
fn ber(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = val.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(val);
    out
}
fn ber_seq(val: &[u8]) -> Vec<u8> {
    ber(0x30, val)
}

/// Walk BER and return the last printable OCTET STRING value — the sysDescr in an SNMP reply.
fn snmp_first_octet_string(buf: &[u8]) -> Option<String> {
    let mut i = 0;
    let mut best: Option<String> = None;
    while i + 2 <= buf.len() {
        let tag = buf[i];
        let mut len = buf[i + 1] as usize;
        let mut hdr = 2;
        if len == 0x81 && i + 2 < buf.len() {
            len = buf[i + 2] as usize;
            hdr = 3;
        } else if len == 0x82 && i + 3 < buf.len() {
            len = ((buf[i + 2] as usize) << 8) | buf[i + 3] as usize;
            hdr = 4;
        }
        if tag == 0x30 || tag == 0xa0 || tag == 0xa2 {
            i += hdr; // descend into constructed types
            continue;
        }
        if i + hdr + len > buf.len() {
            break;
        }
        if tag == 0x04 && len >= 4 {
            let v = &buf[i + hdr..i + hdr + len];
            if v.iter().all(|&b| (0x20..0x7f).contains(&b)) {
                best = Some(String::from_utf8_lossy(v).to_string());
            }
        }
        i += hdr + len;
    }
    best
}

/// Expand a target spec: `@file` (one host/line), `a.b.c.d/nn` CIDR, or a comma list.
fn expand_targets(spec: &str) -> Result<Vec<String>> {
    if let Some(file) = spec.strip_prefix('@') {
        let content = std::fs::read_to_string(file).context("read targets file")?;
        return Ok(content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect());
    }
    if spec.contains('/') {
        let (base, prefix) = spec.split_once('/').unwrap();
        let ip: std::net::Ipv4Addr = base.parse().context("bad CIDR address")?;
        let prefix: u32 = prefix.parse().context("bad CIDR prefix")?;
        anyhow::ensure!((8..=32).contains(&prefix), "CIDR prefix must be 8..=32");
        let host_bits = 32 - prefix;
        let size = if host_bits == 0 {
            1u32
        } else {
            1u32 << host_bits
        };
        let mask = if host_bits == 0 {
            u32::MAX
        } else {
            !(size - 1)
        };
        let net = u32::from(ip) & mask;
        // Skip network + broadcast addresses for blocks with room for them.
        let (start, end) = if prefix <= 30 {
            (1, size - 1)
        } else {
            (0, size)
        };
        return Ok((start..end)
            .map(|i| std::net::Ipv4Addr::from(net + i).to_string())
            .collect());
    }
    Ok(spec
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

#[cfg(test)]
mod net_tests {
    use super::*;

    #[test]
    fn esc8_classifier() {
        let vuln = "HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-IIS/10.0\r\nWWW-Authenticate: Negotiate\r\nWWW-Authenticate: NTLM\r\n\r\n";
        assert!(is_esc8_response(vuln), "cleartext NTLM 401 = ESC8");
        // 200 (anonymous), or a 401 without NTLM (e.g. Basic only), is not the ESC8 surface.
        assert!(!is_esc8_response("HTTP/1.1 200 OK\r\n\r\n"));
        assert!(!is_esc8_response(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\n"
        ));
    }

    #[test]
    fn ber_lengths() {
        assert_eq!(ber(0x02, &[0x2a]), vec![0x02, 0x01, 0x2a]);
        let long = vec![0u8; 200];
        let e = ber(0x04, &long);
        assert_eq!(&e[..2], &[0x04, 0x81]); // 1-byte extended length
        assert_eq!(e[2], 200);
        let longer = vec![0u8; 300];
        let e2 = ber(0x04, &longer);
        assert_eq!(&e2[..2], &[0x04, 0x82]); // 2-byte extended length
        assert_eq!(u16::from_be_bytes([e2[2], e2[3]]), 300);
    }

    #[test]
    fn rpc_record_marker_last_fragment() {
        let f = rpc_frame(&[1, 2, 3, 4]);
        assert_eq!(u32::from_be_bytes([f[0], f[1], f[2], f[3]]), 0x8000_0004);
        assert_eq!(&f[4..], &[1, 2, 3, 4]);
    }

    #[test]
    fn snmp_extracts_last_octet_string() {
        // Hand-build an SNMPv1 GetResponse and confirm the walker returns sysDescr, not community.
        let oid = ber(0x06, &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
        let val = ber(0x04, b"Linux router 5.10");
        let vb = ber_seq(&[ber_seq(&[oid, val].concat())].concat());
        let pdu_body = [ber(0x02, &[0x2a]), ber(0x02, &[0]), ber(0x02, &[0]), vb].concat();
        let pdu = ber(0xa2, &pdu_body); // GetResponse
        let msg = ber_seq(&[ber(0x02, &[0]), ber(0x04, b"public"), pdu].concat());
        assert_eq!(
            snmp_first_octet_string(&msg).as_deref(),
            Some("Linux router 5.10")
        );
    }

    #[test]
    fn parse_exports_walks_chain() {
        fn be(v: u32) -> [u8; 4] {
            v.to_be_bytes()
        }
        let mut body = vec![0u8; 24]; // RPC accepted-reply header
                                      // export 1: "/data", no groups
        body.extend_from_slice(&be(1));
        body.extend_from_slice(&be(5));
        body.extend_from_slice(b"/data\0\0\0"); // padded to 8
        body.extend_from_slice(&be(0)); // group list end
                                        // export 2: "/exports", one group "*"
        body.extend_from_slice(&be(1));
        body.extend_from_slice(&be(8));
        body.extend_from_slice(b"/exports");
        body.extend_from_slice(&be(1)); // group present
        body.extend_from_slice(&be(1));
        body.extend_from_slice(b"*\0\0\0");
        body.extend_from_slice(&be(0)); // group list end
        body.extend_from_slice(&be(0)); // export list end
        let ex = parse_exports(&body);
        assert_eq!(ex, vec!["/data".to_string(), "/exports".to_string()]);
    }

    /// Tiny deterministic PRNG (xorshift64*) so any fuzz failure reproduces from its seed.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let n = (self.next() as usize) % (max + 1);
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// Feed random + seed-mutated byte buffers to a parser; fail with a repro on any panic.
    fn fuzz<F: Fn(&[u8]) + std::panic::RefUnwindSafe>(name: &str, seeds: &[&[u8]], f: F) {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // silence expected-during-fuzz panic spew
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ name.bytes().map(|b| b as u64).sum::<u64>());
        let mut fail = None;
        for _ in 0..200_000 {
            // Half pure-random, half a mutated copy of a valid seed.
            let mut buf = rng.bytes(320);
            if !seeds.is_empty() && rng.next() & 1 == 0 {
                let mut s = seeds[(rng.next() as usize) % seeds.len()].to_vec();
                for _ in 0..(rng.next() as usize % 8) {
                    if !s.is_empty() {
                        let i = (rng.next() as usize) % s.len();
                        s[i] = rng.next() as u8;
                    }
                }
                buf = s;
            }
            let b = buf.clone();
            if std::panic::catch_unwind(|| f(&b)).is_err() {
                fail = Some(buf);
                break;
            }
        }
        std::panic::set_hook(prev);
        if let Some(buf) = fail {
            panic!(
                "{name} PANICKED on input ({} bytes): {}",
                buf.len(),
                hex_dump(&buf)
            );
        }
    }

    fn hex_dump(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn fuzz_network_parsers() {
        // These parse bytes from arbitrary remote hosts (SNMP/NFS/TDS) — must never panic.
        let snmp_seed = ber_seq(&[ber(0x02, &[0]), ber(0x04, b"public"), ber(0xa2, &[])].concat());
        fuzz("snmp_first_octet_string", &[&snmp_seed], |b| {
            let _ = snmp_first_octet_string(b);
        });
        let mut nfs_seed = vec![0u8; 24];
        nfs_seed.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 5]);
        nfs_seed.extend_from_slice(b"/data\0\0\0");
        fuzz("parse_exports", &[&nfs_seed], |b| {
            let _ = parse_exports(b);
        });
        fuzz("parse_prelogin", &[], |b| {
            let _ = parse_prelogin(b);
        });
    }

    #[test]
    fn prelogin_reads_version_and_encryption() {
        // VERSION @12 (16.0.1000), ENCRYPTION @18 = 0x03 (REQUIRED).
        let mut body = vec![
            0x00, 0x00, 12, 0x00, 6, // VERSION token
            0x01, 0x00, 18, 0x00, 1,    // ENCRYPTION token
            0xff, // terminator
        ];
        while body.len() < 12 {
            body.push(0);
        }
        body.extend_from_slice(&[16, 0, 0x03, 0xe8, 0, 0]); // 16.0.1000
        body.push(0x03); // ENCRYPT_REQ
        let (v, e) = parse_prelogin(&body);
        assert_eq!(v.as_deref(), Some("16.0.1000"));
        assert_eq!(e, Some(0x03));
    }
}
