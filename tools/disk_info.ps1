# disk_info.ps1 -- INIT 13/14 disk configuration helpers.
#
# Extracted from doze_sec.bat's inline PowerShell (calculated properties like
# @{N='SizeGB';E={...}} and nested if/match blocks were exactly the cmd.exe
# escaping that caused the INIT 12 / HTML regressions). Each -Mode replaces one
# inline block. Windows PowerShell 5.1 compatible; never throws.
#
#   VmReport   -> Manufacturer/Model line + VM-or-physical verdict (to report)
#   VmFlag     -> 'yes_vm' / 'no'        (consumed by a for /f loop)
#   SsdFlag    -> 'yes_ssd' / 'no'       (consumed by a for /f loop)
#   DiskDetail -> physical-disk table    (to report)
#   FreeSpace  -> free bytes on the system drive (consumed by a for /f loop)

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('VmReport','VmFlag','SsdFlag','DiskDetail','FreeSpace')]
    [string]$Mode,
    [string]$SystemDrive = $env:SystemDrive
)

$ErrorActionPreference = 'Continue'

$vmManufacturer = 'VMware|QEMU|Xen|Bochs|Parallels|innotek'
$vmModel        = 'Virtual|VMware|VirtualBox|KVM|HVM domU'

function Test-IsVM {
    $cs = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
    if (-not $cs) { return $false }
    return [bool](($cs.Manufacturer -match $vmManufacturer) -or ($cs.Model -match $vmModel))
}

switch ($Mode) {
    'VmReport' {
        $cs = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
        if ($cs) {
            Write-Output ('Manufacturer: ' + $cs.Manufacturer + '  Model: ' + $cs.Model)
            if (($cs.Manufacturer -match $vmManufacturer) -or ($cs.Model -match $vmModel)) {
                Write-Output '[VM DETECTED] Running inside a virtual machine. Defrag will be skipped.'
            } else {
                Write-Output '[OK] Physical hardware (not a known VM hypervisor).'
            }
        }
    }
    'VmFlag' {
        if (Test-IsVM) { Write-Output 'yes_vm' } else { Write-Output 'no' }
    }
    'SsdFlag' {
        $d = Get-PhysicalDisk -EA SilentlyContinue | Where-Object { $_.MediaType -eq 'SSD' }
        if ($d) { Write-Output 'yes_ssd' } else { Write-Output 'no' }
    }
    'DiskDetail' {
        $pd = Get-PhysicalDisk -EA SilentlyContinue
        if ($pd) {
            $pd | Select-Object FriendlyName,MediaType,BusType,@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}},OperationalStatus,HealthStatus | Format-Table -AutoSize
        } else {
            Get-CimInstance Win32_DiskDrive | Select-Object Model,MediaType,Status,@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}} | Format-Table -AutoSize
        }
    }
    'FreeSpace' {
        $ld = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $SystemDrive + "'") -EA SilentlyContinue
        if ($ld -and $ld.FreeSpace) { Write-Output $ld.FreeSpace }
    }
}
