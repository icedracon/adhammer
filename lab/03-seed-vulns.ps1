#Requires -RunAsAdministrator
# Run on the promoted DC (elevated). Seeds objects that trigger ADhammer's checks.
Import-Module ActiveDirectory
$ErrorActionPreference = 'Continue'   # keep going if one item already exists

$pw     = ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force
$domain = (Get-ADDomain).DNSRoot

function New-LabUser($name, [switch]$NeverExpire) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $name -SamAccountName $name -AccountPassword $pw -Enabled $true `
                   -PasswordNeverExpires:$NeverExpire
    }
}

# --- Kerberoastable Domain Admin: SPN + adminCount → P-KerberoastAdmin / roast 13100 ---
New-LabUser svc_sql -NeverExpire
Set-ADUser svc_sql -ServicePrincipalNames @{Add = 'MSSQLSvc/db.testlab.local:1433'}
Add-ADGroupMember 'Domain Admins' svc_sql -ErrorAction SilentlyContinue

# --- AS-REP roastable: DONT_REQ_PREAUTH → P-AsrepRoast / roast 18200 ---
New-LabUser svc_legacy
Set-ADAccountControl svc_legacy -DoesNotRequirePreAuth $true

# --- Unconstrained delegation on a non-DC principal → P-UnconstrainedDelegation ---
New-LabUser svc_deleg
Set-ADAccountControl svc_deleg -TrustedForDelegation $true

# --- PASSWD_NOTREQD → P-PasswdNotReqd ---
New-LabUser svc_nopass
Set-ADAccountControl svc_nopass -PasswordNotRequired $true

# --- reversible encryption → A-ReversibleEncryption ---
New-LabUser svc_revpw
Set-ADUser svc_revpw -AllowReversiblePasswordEncryption $true

# --- sensitive/Tier-0-equivalent group membership → P-SensitiveGroups ---
New-LabUser op_backup
Add-ADGroupMember 'Backup Operators' op_backup -ErrorAction SilentlyContinue

# --- weak password policy → A-PasswordPolicy (length<8, no complexity, no lockout) ---
Set-ADDefaultDomainPasswordPolicy -Identity $domain -MinPasswordLength 4 `
    -ComplexityEnabled $false -LockoutThreshold 0

# --- gMSA readable by Domain Users → P-GmsaRead ---
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction SilentlyContinue | Out-Null
if (-not (Get-ADServiceAccount -Filter "Name -eq 'gmsa_web'" -ErrorAction SilentlyContinue)) {
    New-ADServiceAccount -Name gmsa_web -DNSHostName "gmsa_web.$domain" `
        -PrincipalsAllowedToRetrieveManagedPassword 'Domain Users' -ErrorAction SilentlyContinue
}

# --- GPP cpassword in SYSVOL → A-GppPassword (scan --sysvol) ---
$gpo = '{31B2F340-016D-11D2-945F-00C04FB984F9}'  # Default Domain Policy
$dir = "C:\Windows\SYSVOL\sysvol\$domain\Policies\$gpo\Machine\Preferences\Groups"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="labadmin" image="2" changed="2026-01-01 00:00:00" uid="{AABBCCDD-1122-3344-5566-778899AABBCC}">
    <Properties action="U" newName="" fullName="Lab Admin" description="" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="labadmin"/>
  </User>
</Groups>
'@
$xml | Out-File -FilePath "$dir\Groups.xml" -Encoding utf8

Write-Host "`nSeed complete. From the host run:"
Write-Host "  adhammer scan  --url ldap://192.168.10.1:389 --user TESTLAB\Administrator --password 'Zikurat2003$' --sysvol \\$domain\SYSVOL"
Write-Host "  adhammer roast --url ldap://192.168.10.1:389 --user TESTLAB\Administrator --password 'Zikurat2003$' --kdc 192.168.10.1"
