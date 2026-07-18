#Requires -RunAsAdministrator
# Run INSIDE the guest (elevated). Idempotent: first run does IP/DNS/rename + reboot;
# after reboot, run it again and it promotes the box to a domain controller.
$ErrorActionPreference = 'Stop'

$DcName   = 'DC01'
$DcIp     = '192.168.10.1'
$Domain   = 'testlab.local'
$NetBios  = 'TESTLAB'
$DsrmPw   = 'Zikurat2003$'

if ($env:COMPUTERNAME -ne $DcName) {
    # ---- phase 1: network + rename, then reboot ----
    $if = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
    if (-not (Get-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress $DcIp -ErrorAction SilentlyContinue)) {
        New-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress $DcIp -PrefixLength 24 | Out-Null
    }
    Set-DnsClientServerAddress -InterfaceIndex $if.ifIndex -ServerAddresses 127.0.0.1
    Rename-Computer -NewName $DcName -Force
    Write-Host "Set IP $DcIp, renamed to $DcName. Rebooting; re-run this script after login to promote."
    Restart-Computer -Force
}
else {
    # ---- phase 2: promote to a new forest ----
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    Import-Module ADDSDeployment
    Install-ADDSForest `
        -DomainName $Domain -DomainNetbiosName $NetBios `
        -SafeModeAdministratorPassword (ConvertTo-SecureString $DsrmPw -AsPlainText -Force) `
        -InstallDns -Force
    # Install-ADDSForest reboots automatically. After it comes back, run 03-seed-vulns.ps1.
}
