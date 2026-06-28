# smart_health.ps1 -- INIT 14/14 WMI disk-health fallback (used when smartctl
# / smartmontools is not installed).
#
# Extracted from doze_sec.bat's inline PowerShell: the foreach + try/catch +
# Where-Object blocks were assembled through cmd.exe echo escaping, the crash
# class behind the INIT 12 / HTML regressions. Windows PowerShell 5.1
# compatible; never throws.
#
#   Report -> per-drive status + physical-disk health table (to the report)
#   Flag   -> 'warn' / 'ok'  (consumed by a for /f loop to set SMART_WARN)

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Report','Flag')]
    [string]$Mode
)

$ErrorActionPreference = 'Continue'

switch ($Mode) {
    'Report' {
        $d = Get-CimInstance Win32_DiskDrive -EA SilentlyContinue
        foreach ($disk in $d) {
            $gb = [math]::Round($disk.Size/1GB,1)
            Write-Output ('Drive: ' + $disk.Model + '  Size: ' + $gb + 'GB  Status: ' + $disk.Status)
            if ($disk.Status -and $disk.Status -notmatch '^OK$') {
                Write-Output ('[WARNING] ' + $disk.Model + ' reports status: ' + $disk.Status)
            }
        }
        try {
            $pd = Get-PhysicalDisk -EA Stop
            $pd | Select-Object FriendlyName,MediaType,HealthStatus,OperationalStatus | Format-Table -AutoSize
            $bad = $pd | Where-Object { $_.HealthStatus -ne 'Healthy' }
            if ($bad) {
                Write-Output '[WARNING] Unhealthy physical disk detected. Check above for details.'
            } else {
                Write-Output '[OK] All physical disks report Healthy status.'
            }
        } catch {}
    }
    'Flag' {
        $d = Get-CimInstance Win32_DiskDrive -EA SilentlyContinue
        $bad = $d | Where-Object { $_.Status -and $_.Status -notmatch '^OK$' }
        try {
            $pd = Get-PhysicalDisk -EA Stop
            $badpd = $pd | Where-Object { $_.HealthStatus -ne 'Healthy' }
            if ($bad -or $badpd) { Write-Output 'warn' } else { Write-Output 'ok' }
        } catch {
            if ($bad) { Write-Output 'warn' } else { Write-Output 'ok' }
        }
    }
}
