# ADhammer test lab (Hyper-V)

A one-DC Active Directory lab (`testlab.local`, DC = `192.168.10.1`) seeded with the exact
misconfigurations ADhammer's checks look for, so a live run produces real findings.

Host already has the internal switch `pqclab` (host IP `192.168.10.100`). If not, `01`
recreates it.

## Run order

| # | Script | Where | Elevation |
|---|--------|-------|-----------|
| 0 | Get a Windows Server ISO (2022 or 2025 eval from MS Eval Center) | host | — |
| 1 | `01-create-vm.ps1` — create + start `DC01` | **host** | admin |
| — | Install Windows Server (Desktop Experience) via Hyper-V console; set Administrator password | guest console | — |
| 2 | `02-promote-dc.ps1` — static IP, rename, promote to `testlab.local` (run twice: prep→reboot→promote) | **guest** | admin |
| 3 | `03-seed-vulns.ps1` — create vulnerable users/groups/gMSA/GPP/policy | **guest DC** | admin |
| 4 | Run ADhammer from the host (see below) | host | — |

## Credentials created

- Forest/domain: `testlab.local` / NetBIOS `TESTLAB`
- DSRM + domain admin: `TESTLAB\Administrator` (set during install), password used in scripts: `Zikurat2003$`
- Seeded service/user passwords: `P@ssw0rd123!`

## Findings the seed produces

| Seeded object | ADhammer check |
|---|---|
| `svc_sql` (SPN + Domain Admins) | P-KerberoastAdmin, roast (13100) |
| `svc_legacy` (DONT_REQ_PREAUTH) | P-AsrepRoast, roast (18200) |
| `svc_deleg` (TRUSTED_FOR_DELEGATION) | P-UnconstrainedDelegation |
| `svc_nopass` (PASSWD_NOTREQD) | P-PasswdNotReqd |
| `svc_revpw` (reversible encryption) | A-ReversibleEncryption |
| `op_backup` in Backup Operators | P-SensitiveGroups |
| `gmsa_web` readable by Domain Users | P-GmsaRead |
| default policy (len 4, no complexity, no lockout) | A-PasswordPolicy |
| SYSVOL `Groups.xml` cpassword | A-GppPassword (`--sysvol`) |
| default MachineAccountQuota = 10 | A-MachineAccountQuota |

Optional heavier adds (own scripts, not included): AD CS + ESC1 template, a second forest
for trust checks, `dMSA` on Server 2025 for badSuccessor.

## Running ADhammer against the lab (from the host)

```powershell
$dc = '192.168.10.1'
.\target\release\adhammer.exe scan  --url "ldap://$dc:389" --user 'TESTLAB\Administrator' --password 'Zikurat2003$' --sysvol "\\testlab.local\SYSVOL"
.\target\release\adhammer.exe attack roast --url "ldaps://$dc:636" --user 'TESTLAB\Administrator' --password 'Zikurat2003$' --insecure --kdc $dc
```

Expected first breakages to debug (my predictions): simple bind may be refused if the DC
enforces LDAP signing (switch to `ldaps://…:636`); large SAMR responses hit the
single-fragment NDR read; SMB session-setup may want SPNEGO rather than raw NTLMSSP.
