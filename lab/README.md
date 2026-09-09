# ADhammer test lab (Hyper-V)

A one-DC Active Directory lab (`corp.local`, DC = `10.0.0.10`) seeded with the exact
misconfigurations ADhammer's checks look for, so a live run produces real findings.

Host already has the internal switch `pqclab` (host IP `10.0.0.100`). If not, `01`
recreates it.

## Run order

| # | Script | Where | Elevation |
|---|--------|-------|-----------|
| 0 | Get a Windows Server ISO (2022 or 2025 eval from MS Eval Center) | host | — |
| 1 | `01-create-vm.ps1` — create + start `DC01` | **host** | admin |
| — | Install Windows Server (Desktop Experience) via Hyper-V console; set Administrator password | guest console | — |
| 2 | `02-promote-dc.ps1` — static IP, rename, promote to `corp.local` (run twice: prep→reboot→promote) | **guest** | admin |
| 3 | `03-seed-vulns.ps1` — create vulnerable users/groups/gMSA/GPP/policy | **guest DC** | admin |
| 4 | Optional: install AD CS, then run `04-seed-adcs-esc1.ps1` | **guest DC** | admin |
| 5 | Optional: run `05-seed-adcs-esc-2-3-9-13.ps1` for the wider AD CS matrix | **guest DC** | admin |
| 6 | Run ADhammer from the host (see below) | host | — |

## Credentials created

- Forest/domain: `corp.local` / NetBIOS `CORP`
- DSRM + domain admin: `CORP\Administrator` (set during install; never commit it)
- Seeded service/user passwords: entered interactively when `03-seed-vulns.ps1` runs

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

The included AD CS seeders cover ESC1 and the ESC2/3/9/13 template matrix.
A second forest for trust checks and `dMSA` on Server 2025 for badSuccessor
remain optional manual extensions.

## Parser validation helper

`lab_validate.ps1` performs read-only collection from an authorized lab and
replays real directory/SYSVOL data through selected parsers. It writes output
only to its explicitly selected `-OutDir`; validation output is ignored by Git
and must be scrubbed before it is retained as release evidence.

## Running ADhammer against the lab (from the host)

```powershell
$dc = '10.0.0.10'
.\target\release\adhammer.exe scan  --url "ldap://$dc:389" --user 'CORP\Administrator' --password '<LAB_PASSWORD>' --sysvol "\\corp.local\SYSVOL"
.\target\release\adhammer.exe attack roast --url "ldaps://$dc:636" --user 'CORP\Administrator' --password '<LAB_PASSWORD>' --insecure --kdc $dc
```

Expected first breakages to debug (my predictions): simple bind may be refused if the DC
enforces LDAP signing (switch to `ldaps://…:636`); large SAMR responses hit the
single-fragment NDR read; SMB session-setup may want SPNEGO rather than raw NTLMSSP.
