# smart_health.ps1 -- INIT 14/14 WMI disk-health fallback (used when smartctl
# / smartmontools is not installed).
#
# Extracted from doze_sec.bat's inline PowerShell: the foreach + try/catch +
# Where-Object blocks were assembled through cmd.exe echo escaping, the crash
# class behind the INIT 12 / HTML regressions. Windows PowerShell 5.1
# compatible; never throws.
#
#   Report -> per-drive status + physical-disk health table (to the report)
#   Flag   -> 'warn' / 'ok'  (kept for callers outside the bats)
#   State  -> 'warn' / 'ok' / 'gap' written to -StateFile, read by the bats
#             with set /p
#
# A HEALTH QUERY THAT DID NOT ANSWER IS NOT A HEALTHY DISK (2026-11-24). The
# bats read Flag through a for /f backtick, and both sources were asked with
# -EA SilentlyContinue: a broken WMI and a missing Storage module printed
# 'ok', and a for /f that read nothing left SMART_WARN at 0, so the summary
# said "All drives healthy" and the dashboard tile PASS having asked nothing.
# Get-SmartState holds the rule now (-SelfTest pins it): any drive or physical
# disk not reported healthy is 'warn'; neither source answering with a disk is
# 'gap'; otherwise 'ok'.

param(
    [ValidateSet('Report','Flag','State')]
    [string]$Mode,
    [string]$StateFile = '',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# PURE. $Drives: Win32_DiskDrive Status strings, or $null when the query did
# not answer; $Disks: Get-PhysicalDisk HealthStatus strings, or $null.
function Get-SmartState {
    param($Drives, $Disks)
    $d = @($Drives | Where-Object { $null -ne $_ }); $p = @($Disks | Where-Object { $null -ne $_ })
    if (@($d | Where-Object { [string]$_ -and [string]$_ -notmatch '^OK$' }).Count) { return 'warn' }
    if (@($p | Where-Object { [string]$_ -ne 'Healthy' }).Count) { return 'warn' }
    if ($d.Count -eq 0 -and $p.Count -eq 0) { return 'gap' }
    return 'ok'
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    T 'every drive OK and every physical disk Healthy: ok' ((Get-SmartState @('OK', 'OK') @('Healthy')) -eq 'ok') ''
    T 'a drive reporting Pred Fail: warn' ((Get-SmartState @('OK', 'Pred Fail') @('Healthy')) -eq 'warn') ''
    T 'a physical disk reporting Warning: warn' ((Get-SmartState @('OK') @('Warning')) -eq 'warn') ''
    T 'neither query answered: gap, never ok (the defect: this read "All drives healthy")' ((Get-SmartState $null $null) -eq 'gap') ''
    T 'both answered with no disk at all: gap' ((Get-SmartState @() @()) -eq 'gap') ''
    T 'only Win32_DiskDrive answered, all OK: ok (Get-PhysicalDisk is missing on some editions)' ((Get-SmartState @('OK') $null) -eq 'ok') ''
    T 'only Get-PhysicalDisk answered, a bad disk: warn' ((Get-SmartState $null @('Unhealthy')) -eq 'warn') ''
    if ($fails) { Write-Output "[FAIL] $fails smart_health self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] smart_health self-test: a drive not reported healthy is warn, and no drive reported at all is a gap, never healthy.'
    exit 0
}
if (-not $Mode) { 'smart_health: -Mode is required (Report, Flag or State).'; exit 1 }

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
        } catch { Write-Output ('[INFO] Get-PhysicalDisk did not answer (' + (($_.Exception.Message) -replace '[\r\n]+', ' ') + '); the drive status above is what Windows reported.') }
    }
    'State' {
        $drives = $null; $disks = $null
        try { $drives = @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop | ForEach-Object { [string]$_.Status }) } catch { $drives = $null }
        try { $disks = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object { [string]$_.HealthStatus }) } catch { $disks = $null }
        $st = Get-SmartState $drives $disks
        if ($StateFile) { Set-Content -LiteralPath $StateFile -Value $st -Encoding ASCII } else { $st }
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
