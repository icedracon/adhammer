#Requires -RunAsAdministrator
# Run on the DC after AD CS is installed. Creates a vulnerable ESC1 certificate template
# (enrollee-supplies-subject + client-auth EKU, enrollable by Authenticated Users, no
# manager approval) and publishes it, so `adhammer scan` reports A-Esc1.
$ErrorActionPreference = 'Stop'
$cfg  = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
$src  = [ADSI]"LDAP://CN=User,$base"
$cont = [ADSI]"LDAP://$base"

try { $cont.Delete("pKICertificateTemplate", "CN=VulnUser") } catch {}

$t = $cont.Create("pKICertificateTemplate", "CN=VulnUser")
$copy = 'flags','revision','pKIDefaultKeySpec','pKIKeyUsage','pKIMaxIssuingDepth',
        'pKICriticalExtensions','pKIExpirationPeriod','pKIOverlapPeriod','pKIExtendedKeyUsage',
        'pKIDefaultCSPs','msPKI-RA-Signature','msPKI-Minimal-Key-Size',
        'msPKI-Template-Schema-Version','msPKI-Cert-Template-OID',
        'msPKI-Certificate-Application-Policy','msPKI-Private-Key-Flag'
foreach ($a in $copy) { $v = $src.Properties[$a].Value; if ($null -ne $v) { $t.Properties[$a].Value = $v } }
$t.Properties['displayName'].Value = 'VulnUser'
$t.Properties['msPKI-Certificate-Name-Flag'].Value = 1  # ENROLLEE_SUPPLIES_SUBJECT
$t.Properties['msPKI-Enrollment-Flag'].Value = 0        # no manager approval
$t.Properties['msPKI-RA-Signature'].Value = 0
$t.CommitChanges()

# Grant Authenticated Users the Certificate-Enrollment extended right (0e10c968-...79dc55).
$de = [ADSI]"LDAP://CN=VulnUser,$base"
$enroll = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$au = New-Object Security.Principal.SecurityIdentifier('S-1-5-11')
$ace = New-Object DirectoryServices.ActiveDirectoryAccessRule(
    $au, [DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [Security.AccessControl.AccessControlType]::Allow, $enroll)
$de.ObjectSecurity.AddAccessRule($ace)
$de.CommitChanges()

# Publish on the CA.
$ca = [ADSI]"LDAP://CN=testlab-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg"
if ($ca.Properties['certificateTemplates'].Value -notcontains 'VulnUser') {
    $ca.Properties['certificateTemplates'].Add('VulnUser') | Out-Null
    $ca.CommitChanges()
}
"ESC1 template VulnUser created + published"
