<#
.SYNOPSIS
    Validate the four ADhammer support crates against a real domain controller.

.DESCRIPTION
    Every crate is covered by tests, but all of those tests feed it bytes we wrote
    ourselves. This pulls the real thing off a DC and re-runs the parsers against it:

      ad-acl        schemaIDGUID / rightsGuid from CN=Schema and CN=Extended-Rights,
                    diffed against the hard-coded catalog. A wrong GUID is silent —
                    the ACE stops classifying and an edge never appears.
      ms-dnsp       every dnsRecord value in the forward zone, parsed and re-encoded.
      registry-pol  every Registry.pol under SYSVOL, parsed and re-encoded.
      dpapi-ng      any msLAPS-EncryptedPassword or gMSA managed-password blob.

    Read-only: it binds LDAP, reads SYSVOL over SMB, and writes only into -OutDir.

.EXAMPLE
    .\lab_validate.ps1 -Server 10.10.10.22 -Domain testlab.local -User TESTLAB\administrator
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Server,
    [Parameter(Mandatory)] [string] $Domain,
    [Parameter(Mandatory)] [string] $User,
    [string] $OutDir = "$PSScriptRoot\validation",
    [string] $CratesRoot = "$PSScriptRoot\..\..",
    [switch] $SkipCargo
)

$ErrorActionPreference = 'Stop'
$cred = Get-Credential -UserName $User -Message "Password for $User (read-only LDAP + SYSVOL)"

$baseDn = ($Domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
$configDn = "CN=Configuration,$baseDn"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "base DN : $baseDn"
Write-Host "output  : $OutDir`n"

function New-Searcher {
    param([string] $SearchRoot, [string] $Filter, [string[]] $Props)
    $path = "LDAP://$Server/$SearchRoot"
    $entry = New-Object System.DirectoryServices.DirectoryEntry(
        $path, $cred.UserName, $cred.GetNetworkCredential().Password)
    $s = New-Object System.DirectoryServices.DirectorySearcher($entry, $Filter, $Props)
    $s.PageSize = 500
    $s
}

# ── 1. ad-acl: the GUID catalog ───────────────────────────────────────────────
Write-Host "[1/4] dumping schema + extended-right GUIDs"
$csv = Join-Path $OutDir 'schema_guids.csv'
'name,guid,kind' | Set-Content -Path $csv -Encoding utf8

$attrNames = @(
    'member', 'servicePrincipalName', 'altSecurityIdentities', 'gPLink',
    'msDS-KeyCredentialLink', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
    'msDS-AllowedToDelegateTo', 'msDS-ManagedPassword', 'msDS-GroupMSAMembership',
    'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword'
)
$classNames = @('msDS-DelegatedManagedServiceAccount')
$wanted = $attrNames + $classNames
$filter = '(|' + (($wanted | ForEach-Object { "(lDAPDisplayName=$_)" }) -join '') + ')'

$schema = New-Searcher -SearchRoot "CN=Schema,$configDn" -Filter $filter `
    -Props @('lDAPDisplayName', 'schemaIDGUID')
$attrCount = 0
foreach ($r in $schema.FindAll()) {
    $name = $r.Properties['ldapdisplayname'][0]
    $raw = $r.Properties['schemaidguid'][0]
    $guid = [guid]::new([byte[]]$raw)
    Add-Content -Path $csv -Encoding utf8 -Value "$name,$guid,attribute"
    $attrCount++
}
Write-Host "      $attrCount attribute/class GUID(s)"

$rights = New-Searcher -SearchRoot "CN=Extended-Rights,$configDn" `
    -Filter '(objectClass=controlAccessRight)' -Props @('cn', 'displayName', 'rightsGuid')
$rightCount = 0
foreach ($r in $rights.FindAll()) {
    $cn = $r.Properties['cn'][0]
    $guid = $r.Properties['rightsguid'][0]
    Add-Content -Path $csv -Encoding utf8 -Value "$cn,$guid,right"
    $rightCount++
}
Write-Host "      $rightCount extended right(s) -> $csv"

# ── 2. ms-dnsp: dnsRecord blobs ───────────────────────────────────────────────
Write-Host "[2/4] dumping dnsRecord values"
$dnsDir = Join-Path $OutDir 'dns'
New-Item -ItemType Directory -Force -Path $dnsDir | Out-Null
$dnsCount = 0
foreach ($partition in @("DC=DomainDnsZones,$baseDn", "DC=ForestDnsZones,$baseDn", "CN=System,$baseDn")) {
    try {
        $dns = New-Searcher -SearchRoot "DC=$Domain,CN=MicrosoftDNS,$partition" `
            -Filter '(objectClass=dnsNode)' -Props @('name', 'dnsRecord')
        foreach ($r in $dns.FindAll()) {
            $node = ($r.Properties['name'][0] -replace '[^\w\.\-]', '_')
            $i = 0
            foreach ($val in $r.Properties['dnsrecord']) {
                $file = Join-Path $dnsDir "$node`_$i.bin"
                [System.IO.File]::WriteAllBytes($file, [byte[]]$val)
                $i++; $dnsCount++
            }
        }
        Write-Host "      $partition -> ok"
    } catch {
        Write-Host "      $partition -> not present, skipping"
    }
}
Write-Host "      $dnsCount record(s) -> $dnsDir"

# ── 3. registry-pol: SYSVOL ───────────────────────────────────────────────────
Write-Host "[3/4] copying Registry.pol from SYSVOL"
$polDir = Join-Path $OutDir 'gpo'
New-Item -ItemType Directory -Force -Path $polDir | Out-Null
$share = "\\$Server\SYSVOL"
cmd /c "net use $share /user:$($cred.UserName) $($cred.GetNetworkCredential().Password)" | Out-Null
$polCount = 0
try {
    Get-ChildItem -Path "$share\$Domain\Policies" -Recurse -Filter 'Registry.pol' -ErrorAction Stop |
        ForEach-Object {
            # {GUID}\Machine\Registry.pol -> {GUID}_Machine.pol
            $parts = $_.FullName -split '\\'
            $tag = "$($parts[-3])_$($parts[-2])" -replace '[{}]', ''
            Copy-Item $_.FullName (Join-Path $polDir "$tag.pol")
            $polCount++
        }
} finally {
    cmd /c "net use $share /delete /y" | Out-Null
}
Write-Host "      $polCount file(s) -> $polDir"

# ── 4. dpapi-ng: protected password blobs ─────────────────────────────────────
Write-Host "[4/4] looking for DPAPI-NG protected blobs"
$blobDir = Join-Path $OutDir 'blobs'
New-Item -ItemType Directory -Force -Path $blobDir | Out-Null
$blobCount = 0
foreach ($attr in @('msLAPS-EncryptedPassword', 'msDS-ManagedPassword')) {
    try {
        $s = New-Searcher -SearchRoot $baseDn -Filter "($attr=*)" -Props @('sAMAccountName', $attr)
        foreach ($r in $s.FindAll()) {
            $sam = ($r.Properties['samaccountname'][0] -replace '[^\w\-]', '_')
            $val = $r.Properties[$attr.ToLower()][0]
            [System.IO.File]::WriteAllBytes((Join-Path $blobDir "$sam`_$attr.bin"), [byte[]]$val)
            $blobCount++
        }
    } catch {
        Write-Host "      $attr -> not readable / not present"
    }
}
# The KDS root key has to exist at all for any of this to be decryptable.
try {
    $kds = New-Searcher -SearchRoot "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$configDn" `
        -Filter '(objectClass=msKds-ProvRootKey)' -Props @('cn', 'msKds-CreateTime')
    $kdsCount = @($kds.FindAll()).Count
    Write-Host "      $kdsCount KDS root key(s) present"
} catch {
    Write-Host "      no KDS root keys — this forest cannot protect anything with DPAPI-NG"
}
Write-Host "      $blobCount blob(s) -> $blobDir"

if ($SkipCargo) { Write-Host "`ndumps written; -SkipCargo set, not running the parsers"; return }

# ── run the parsers against what we just pulled ───────────────────────────────
Write-Host "`n=== ad-acl: catalog vs forest ==="
Push-Location (Join-Path $CratesRoot 'ad-acl')
cargo run --quiet --example verify_schema -- $csv
$adAcl = $LASTEXITCODE
Pop-Location

Write-Host "`n=== ms-dnsp: parse + re-encode ==="
Push-Location (Join-Path $CratesRoot 'ms-dnsp')
cargo run --quiet --example parse_dump -- $dnsDir
$msDnsp = $LASTEXITCODE
Pop-Location

Write-Host "`n=== registry-pol: parse + re-encode ==="
Push-Location (Join-Path $CratesRoot 'registry-pol')
$pols = (Get-ChildItem $polDir -Filter '*.pol' | ForEach-Object { $_.FullName })
if ($pols) { cargo run --quiet --example roundtrip_file -- @pols; $regPol = $LASTEXITCODE }
else { Write-Host "no Registry.pol files found"; $regPol = 0 }
Pop-Location

Write-Host "`n=== dpapi-ng: blob metadata ==="
Push-Location (Join-Path $CratesRoot 'dpapi-ng')
$dpapi = 0
$blobs = Get-ChildItem $blobDir -Filter '*.bin' -ErrorAction SilentlyContinue
if ($blobs) {
    foreach ($b in $blobs) {
        $raw = if ($b.Name -like '*EncryptedPassword*') { @($b.FullName) } else { @('--raw', $b.FullName) }
        cargo run --quiet --example inspect_blob -- @raw
        if ($LASTEXITCODE -ne 0) { $dpapi = 1 }
    }
} else {
    Write-Host "no protected blobs on this DC (Windows LAPS needs 2019+/Win10; gMSA needs a KDS root key)"
}
Pop-Location

Write-Host "`n────────── summary ──────────"
foreach ($row in @(
    @{ n = 'ad-acl'; c = $adAcl }, @{ n = 'ms-dnsp'; c = $msDnsp },
    @{ n = 'registry-pol'; c = $regPol }, @{ n = 'dpapi-ng'; c = $dpapi })) {
    $verdict = if ($row.c -eq 0) { 'ok' } else { 'FAILED' }
    "{0,-14} {1}" -f $row.n, $verdict | Write-Host
}
