#Requires -RunAsAdministrator
# Run on the HOST in an elevated PowerShell. Creates the lab switch + DC01 VM and boots it.
$ErrorActionPreference = 'Stop'

# ---- settings ----
$VMName     = 'DC01'
$SwitchName = 'pqclab'
$IsoPath    = 'C:\Users\zevs\Downloads\26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso'  # Windows Server 2025 EVAL
$VmRoot     = 'C:\Hyper-V'
$RamGB      = 6
$DiskGB     = 60
$HostIp     = '192.168.10.100'                   # host address on the internal lab subnet

if (-not (Test-Path $IsoPath)) {
    throw "ISO not found at $IsoPath. Download a Windows Server evaluation ISO and set `$IsoPath."
}

# ---- internal switch on 192.168.10.0/24 ----
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
    Start-Sleep 2
    $if = Get-NetAdapter -Name "vEthernet ($SwitchName)"
    if (-not (Get-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress $HostIp -ErrorAction SilentlyContinue)) {
        New-NetIPAddress -IPAddress $HostIp -PrefixLength 24 -InterfaceIndex $if.ifIndex | Out-Null
    }
    Write-Host "Created internal switch '$SwitchName' (host $HostIp)."
}

# ---- VM ----
$vhd = Join-Path $VmRoot "$VMName\$VMName.vhdx"
New-Item -ItemType Directory -Force -Path (Split-Path $vhd) | Out-Null

New-VM -Name $VMName -Generation 2 -MemoryStartupBytes ${RamGB}GB `
       -NewVHDPath $vhd -NewVHDSizeBytes ${DiskGB}GB -SwitchName $SwitchName | Out-Null
Set-VM -Name $VMName -ProcessorCount 2 -DynamicMemory
Add-VMDvdDrive -VMName $VMName -Path $IsoPath
Set-VMFirmware -VMName $VMName -SecureBootTemplate MicrosoftWindows `
               -FirstBootDevice (Get-VMDvdDrive -VMName $VMName)

Start-VM -Name $VMName
Write-Host "`n$VMName started. Open Hyper-V Manager -> Connect to $VMName, install"
Write-Host "'Windows Server (Desktop Experience)', set the Administrator password, then run 02-promote-dc.ps1 inside the guest."
