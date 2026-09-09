# Clone the complete built-in User template into an ESC1-vulnerable template (AdhESC1):
# enrollee-supplies-subject + client-auth, enrollable by Authenticated Users. Lab provisioning.
$ErrorActionPreference = 'Stop'
$cfg  = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
$src  = [ADSI]"LDAP://CN=User,$base"
$cont = [ADSI]"LDAP://$base"

try { $cont.Delete("pKICertificateTemplate", "CN=AdhESC1") } catch {}
$t = $cont.Create("pKICertificateTemplate", "CN=AdhESC1")

# Copy every schema/PKI attribute from User so the template is complete (the raw-ADSI seed
# omitted required ones → CERTSRV_E_UNSUPPORTED_CERT_TYPE).
$skip = @('cn','distinguishedName','name','objectguid','objectclass','usncreated','usnchanged',
          'whencreated','whenchanged','dscorepropagationdata','instancetype','adspath','showinadvancedviewonly')
foreach ($p in $src.Properties.PropertyNames) {
    if ($skip -contains $p.ToLower()) { continue }
    try { $t.Properties[$p].Value = $src.Properties[$p].Value } catch {}
}
$t.Properties['displayName'].Value = 'AdhESC1'
# ENROLLEE_SUPPLIES_SUBJECT (0x1) — the ESC1 condition.
$t.Properties['msPKI-Certificate-Name-Flag'].Value = 1
$t.CommitChanges()
Start-Sleep 2

# Copy User's security descriptor (grants Authenticated Users Enroll) onto the clone.
$t2 = [ADSI]"LDAP://CN=AdhESC1,$base"
$sd = $src.psbase.ObjectSecurity.GetSecurityDescriptorBinaryForm()
$t2.psbase.ObjectSecurity.SetSecurityDescriptorBinaryForm($sd)
$t2.psbase.CommitChanges()
Start-Sleep 2

# Publish on the CA + refresh.
certutil -SetCATemplates +AdhESC1
Restart-Service certsvc
Start-Sleep 3
certutil -CATemplates | Select-String AdhESC1
"done"
