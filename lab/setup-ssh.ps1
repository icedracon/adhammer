#Requires -RunAsAdministrator
# Run ONCE on the DC (guest). Enables OpenSSH + authorizes the adhammer key so the
# operator can drive the DC over SSH from the host. Lab only.
$ErrorActionPreference = 'Stop'

# OpenSSH server (Feature-on-Demand; needs the install media / internet if not staged)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic
Start-Service sshd

if (-not (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True `
        -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}

# make PowerShell the SSH shell (nicer than cmd)
New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
    -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null

# authorize the adhammer key (admin accounts use administrators_authorized_keys)
$akf = "$env:ProgramData\ssh\administrators_authorized_keys"
Set-Content -Path $akf -Encoding ascii -Value `
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHD/Z/hqmB+V9pcdxfh+tcTVXldvDZ3wg1G9Qo3Y4gFf adhammer-lab'
icacls $akf /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null

Restart-Service sshd
Write-Host "SSH ready: ssh Administrator@192.168.10.1"
