# unload_audit_hives.ps1 -- remove what an interrupted audit can leave behind
# when it read a signed-out account's Run keys (Section 5).
#
# The audit never mounts or opens an account's own registry file. Only with
# -readSignedOut, it copies NTUSER.DAT from a Volume Shadow Copy into
# %TEMP%\dz_hive_<pid>\<n>\, mounts the COPY as HKU\dz_sec_<pid>_<n>, reads
# it and unmounts it. If the run is stopped in between, the copy stays
# mounted until the next reboot and its folder stays in TEMP. Neither affects
# the account (its next sign-in loads its own, untouched file), but this
# removes both now. The next audit run also does it at its start.
#
# Run elevated: unloading a registry hive needs administrator.
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\unload_audit_hives.ps1
#
# Windows PowerShell 5.1 compatible; pure ASCII. Changes only the dz_sec_*
# mounts and dz_hive_* folders the audit itself creates.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$bad = 0
$mounts = @()
try { $mounts = @([Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match '^dz_sec_\d+_\d+$' }) }
catch { "[WARNING] HKEY_USERS could not be listed ($($_.Exception.Message)); nothing was unloaded."; exit 1 }
foreach ($m in $mounts) {
    & reg.exe unload ("HKU\" + $m) 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { "[OK] Unloaded HKU\$m (a copy of an account registry)." }
    else { "[WARNING] HKU\$m could not be unloaded -- run this from an elevated prompt, or restart the PC."; $bad++ }
}
$tmp = $env:TEMP; if (-not $tmp) { $tmp = [IO.Path]::GetTempPath() }
foreach ($d in @(Get-ChildItem -LiteralPath $tmp -Force -Filter 'dz_hive_*' -ErrorAction SilentlyContinue)) {
    $dpid = 0; if (-not [int]::TryParse(($d.Name -replace '^dz_hive_', ''), [ref]$dpid)) { continue }
    if ($dpid -ne $PID -and (Get-Process -Id $dpid -ErrorAction SilentlyContinue)) { "[INFO] $($d.FullName) belongs to a run still in progress; left alone."; continue }
    # Never follow a link: a junction named dz_hive_* would turn this
    # recursive delete onto whatever folder it points at.
    if (([int]$d.Attributes -band 0x400) -or @(Get-ChildItem -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { [int]$_.Attributes -band 0x400 }).Count) { "[WARNING] $($d.FullName) is or holds a link, not a folder the audit made; refused, left alone."; $bad++; continue }
    Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $d.FullName) { "[WARNING] $($d.FullName) could not be removed (a copy is still mounted from it?)."; $bad++ }
    else { "[OK] Removed $($d.FullName)." }
}
if ($mounts.Count -eq 0 -and $bad -eq 0) { '[OK] No audit registry copy is mounted.' }
exit $(if ($bad) { 1 } else { 0 })
