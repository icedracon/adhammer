$ErrorActionPreference='Stop'
$cfg  = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
$src  = [ADSI]"LDAP://CN=User,$base"
$cont = [ADSI]"LDAP://$base"
$ca   = [ADSI]"LDAP://CN=testlab-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg"
$enroll = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$au = New-Object Security.Principal.SecurityIdentifier('S-1-5-11')
$copy = 'flags','revision','pKIDefaultKeySpec','pKIKeyUsage','pKIMaxIssuingDepth',
        'pKICriticalExtensions','pKIExpirationPeriod','pKIOverlapPeriod','pKIExtendedKeyUsage',
        'pKIDefaultCSPs','msPKI-RA-Signature','msPKI-Minimal-Key-Size',
        'msPKI-Template-Schema-Version','msPKI-Cert-Template-OID','msPKI-Private-Key-Flag'

function New-Vuln($name, [scriptblock]$tweak) {
    try { $cont.Delete("pKICertificateTemplate","CN=$name") } catch {}
    $t = $cont.Create("pKICertificateTemplate","CN=$name")
    foreach($a in $copy){ $v=$src.Properties[$a].Value; if($null -ne $v){ $t.Properties[$a].Value=$v } }
    $t.Properties['displayName'].Value = $name
    $t.Properties['msPKI-Enrollment-Flag'].Value = 0
    $t.Properties['msPKI-RA-Signature'].Value = 0
    & $tweak $t
    $t.CommitChanges()
    $de = [ADSI]"LDAP://CN=$name,$base"
    $ace = New-Object DirectoryServices.ActiveDirectoryAccessRule($au,
        [DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [Security.AccessControl.AccessControlType]::Allow,$enroll)
    $de.ObjectSecurity.AddAccessRule($ace); $de.CommitChanges()
    if($ca.Properties['certificateTemplates'].Value -notcontains $name){
        $ca.Properties['certificateTemplates'].Add($name) | Out-Null; $ca.CommitChanges()
    }
    "  $name published"
}

# ESC2: Any Purpose EKU
New-Vuln 'VulnEsc2' { param($t) $t.Properties['pKIExtendedKeyUsage'].Value = '2.5.29.37.0' }
# ESC3: Certificate Request Agent EKU
New-Vuln 'VulnEsc3' { param($t) $t.Properties['pKIExtendedKeyUsage'].Value = '1.3.6.1.4.1.311.20.2.1' }
# ESC9: no security extension flag (0x80000) + keep client-auth EKU
New-Vuln 'VulnEsc9' { param($t) $t.Properties['msPKI-Enrollment-Flag'].Value = 0x80000 }
# ESC13: issuance policy OID + keep client-auth EKU
New-Vuln 'VulnEsc13' { param($t) $t.Properties['msPKI-Certificate-Policy'].Value = '1.3.6.1.4.1.311.21.8.9999.1' }
"done"
