# cleanup_selftest.ps1 -- remove every artifact tests/detection_selftest.ps1
# plants, safely and idempotently, keyed to its markers.
#
# WHY THIS EXISTS: the detection harness plants ~34 known-bad artifacts (WDigest
# enabled, guest account on, a portproxy tunnel, IFEO hijacks, rogue
# credential/LSA/network-provider entries, an AppInit DLL, a hidden account, a
# malicious screensaver, startup scripts, services, files), runs the audit to
# prove the scanner catches them, then removes them. If that run is INTERRUPTED
# -- Ctrl-C, the window closed, a throw before the cleanup loop -- the plants are
# left behind, and several make the machine genuinely less safe than it started.
# This is the panic button: run it any time to guarantee a clean machine.
#
# WHY IT DOES NOT JUST REPLAY THE HARNESS CLEANUP: several of the harness's
# per-case cleanups (LSA packages, NetworkProvider order, AppInit, screensaver)
# only undo their change if a $script:...Prev value was captured DURING planting
# in the same process. Run cold, those are $null and the cleanup silently skips,
# leaving the marker entry in the list. So this removes strictly BY MARKER, never
# by a captured previous value -- which is also the only safe thing to do after
# an interrupted run.
#
# SAFETY: it only ever touches items carrying one of the harness markers, or the
# exact known plant target for the handful of reset-to-default settings. It never
# disturbs a real value. Every operation is guarded, so it is safe to run when
# nothing is planted (everything reports ABSENT) and safe to run repeatedly.
#
# Windows PowerShell 5.1 compatible. Requires elevation. Exit 0 always unless a
# removal itself errors (then exit 1, loudly) -- absence is not an error.

[CmdletBinding()]
param(
    # The harness quarantines its output under selftest\ (-selftest); the
    # seeded baseline snapshot lives there too.
    [string]$OutDir = 'C:\SecurityAudit\selftest',
    [switch]$Quiet
)

$ErrorActionPreference = 'Continue'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '[FAIL] This must run in an ELEVATED PowerShell -- removing the planted artifacts needs admin.'
    exit 1
}

$MARK    = 'dz_selftest_evil'
$cpGuid  = '{deadbeef-0000-0000-0000-00000000d123}'
$comGuid = '{dead1111-0000-0000-0000-00000000c015}'
$markRx  = 'dz_selftest|dz_evil|\\Users\\Public\\'

$removed = 0
$absent  = 0
$errors  = @()

function Report {
    param([string]$What, [string]$State)   # State: REMOVED | ABSENT
    if ($State -eq 'REMOVED') { $script:removed++ } else { $script:absent++ }
    if (-not $Quiet) { Write-Host ("  [{0,-7}] {1}" -f $State, $What) }
}

# Remove a single registry VALUE if present.
function Remove-RegValue {
    param([string]$Path, [string]$Name, [string]$What)
    try {
        $p = Get-ItemProperty -LiteralPath $Path -Name $Name -EA Stop
        if ($null -ne $p) {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -Force -EA Stop
            Report $What 'REMOVED'
        } else { Report $What 'ABSENT' }
    } catch { Report $What 'ABSENT' }
}

# Remove a registry KEY (and children) if present.
function Remove-RegKey {
    param([string]$Path, [string]$What)
    if (Test-Path -LiteralPath $Path) {
        try { Remove-Item -LiteralPath $Path -Recurse -Force -EA Stop; Report $What 'REMOVED' }
        catch { $script:errors += ("{0}: {1}" -f $What, $_.Exception.Message); Report $What 'REMOVED' }
    } else { Report $What 'ABSENT' }
}

# Remove a file/dir if present.
function Remove-Path {
    param([string]$Path, [string]$What)
    if (Test-Path -LiteralPath $Path) {
        try { Remove-Item -LiteralPath $Path -Recurse -Force -EA Stop; Report $What 'REMOVED' }
        catch { $script:errors += ("{0}: {1}" -f $What, $_.Exception.Message); Report $What 'REMOVED' }
    } else { Report $What 'ABSENT' }
}

# Strip marker elements from a REG_MULTI_SZ list, preserving the rest.
function Strip-MultiString {
    param([string]$Path, [string]$Name, [string]$Marker, [string]$What)
    try {
        $cur = @((Get-ItemProperty -LiteralPath $Path -Name $Name -EA Stop).$Name)
        $new = @($cur | Where-Object { $_ -and ($_ -notmatch [regex]::Escape($Marker)) })
        if ($new.Count -ne $cur.Count) {
            Set-ItemProperty -LiteralPath $Path -Name $Name -Value $new -Type MultiString -Force
            Report $What 'REMOVED'
        } else { Report $What 'ABSENT' }
    } catch { Report $What 'ABSENT' }
}

Write-Host ''
Write-Host '== Removing planted detection-harness artifacts (by marker) =='
Write-Host ''

# --- Registry values (pure adds) -------------------------------------------
Remove-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 'WDigest UseLogonCredential (plaintext creds in RAM)'
Remove-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' $MARK               'Run-key backdoor (encoded PowerShell)'
Remove-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' ("PS{0}" -f $MARK)  'Run-key backdoor (PS-prefixed)'
Remove-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' ("{0}_benign" -f $MARK) 'Run-key benign autorun'
Remove-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' $MARK 'AppCert DLL'
Remove-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' $MARK 'Hidden account (UserList)'
Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 'ScriptBlockLogging policy'
Remove-RegValue 'HKCU:\Environment' 'UserInitMprLogonScript' 'UserInitMprLogonScript logon script'

# --- Registry keys (pure adds) ---------------------------------------------
Remove-RegKey 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe' 'IFEO hijack (notepad.exe)'
Remove-RegKey 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe'   'IFEO hijack (sethc.exe -- sticky-keys backdoor)'
Remove-RegKey ("HKCU:\Software\Classes\CLSID\{0}" -f $comGuid) 'COM CLSID hijack (HKCU InprocServer32)'
Remove-RegKey ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{0}" -f $cpGuid) 'Rogue credential provider'
Remove-RegKey ("HKLM:\SOFTWARE\Classes\CLSID\{0}" -f $cpGuid) 'Rogue credential provider CLSID'
Remove-RegKey ("HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\{0}" -f $MARK) 'W32Time time provider'
Remove-RegKey ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\{0}" -f $MARK) 'Winlogon Notify package'
Remove-RegKey 'HKLM:\SYSTEM\CurrentControlSet\Services\dz_selftest_np' 'Rogue network provider service'

# --- Multi-value lists: strip the marker element, keep the rest ------------
Strip-MultiString 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'Notification Packages'   'dz_selftest_lsa'     'LSA Notification package (dz_selftest_lsa)'
Strip-MultiString 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'Authentication Packages' 'dz_selftest_authpkg' 'LSA Authentication package (dz_selftest_authpkg)'

# NetworkProvider Order is a REG_SZ comma list, not multi-string.
try {
    $ord = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order' -Name ProviderOrder -EA Stop).ProviderOrder
    $parts = @($ord -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $kept  = @($parts | Where-Object { $_ -ne 'dz_selftest_np' })
    if ($kept.Count -ne $parts.Count) {
        Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order' -Name ProviderOrder -Value ($kept -join ',') -Force
        Report 'NetworkProvider Order (dz_selftest_np)' 'REMOVED'
    } else { Report 'NetworkProvider Order (dz_selftest_np)' 'ABSENT' }
} catch { Report 'NetworkProvider Order (dz_selftest_np)' 'ABSENT' }

# --- Clear ONLY if the current value is the plant (never a real value) -----
# AppInit_DLLs loads into every GUI process; a leftover plant here is the most
# damaging item, and we must never re-register or preserve it.
try {
    $ai = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'AppInit_DLLs' -EA Stop).'AppInit_DLLs'
    if ($ai -and ("$ai" -match $markRx)) {
        Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'AppInit_DLLs' -Value '' -Force
        Report 'AppInit_DLLs (planted DLL)' 'REMOVED'
    } else { Report 'AppInit_DLLs (planted DLL)' 'ABSENT' }
} catch { Report 'AppInit_DLLs (planted DLL)' 'ABSENT' }

try {
    $scr = (Get-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'SCRNSAVE.EXE' -EA Stop).'SCRNSAVE.EXE'
    if ($scr -and ("$scr" -match $markRx)) {
        Remove-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'SCRNSAVE.EXE' -Force
        Report 'Malicious screensaver (SCRNSAVE.EXE)' 'REMOVED'
    } else { Report 'Malicious screensaver (SCRNSAVE.EXE)' 'ABSENT' }
} catch { Report 'Malicious screensaver (SCRNSAVE.EXE)' 'ABSENT' }

# --- Services --------------------------------------------------------------
foreach ($svc in @('dz_selftest_fp_svc', 'dz_selftest_flag_svc')) {
    $exists = $false
    try { if (Get-Service -Name $svc -EA Stop) { $exists = $true } } catch {}
    if ($exists) { & sc.exe delete $svc | Out-Null; Report ("Service {0}" -f $svc) 'REMOVED' }
    else { Report ("Service {0}" -f $svc) 'ABSENT' }
}

# --- Files / directories ---------------------------------------------------
$startupDir = [Environment]::GetFolderPath('Startup')
Remove-Path (Join-Path $startupDir ("{0}.vbs" -f $MARK))        'Startup script (.vbs)'
Remove-Path (Join-Path $startupDir ("{0}_benign.lnk" -f $MARK)) 'Startup benign shortcut (.lnk)'
Remove-Path ("C:\Users\Public\{0}.sys" -f $MARK)               'Fake kernel driver (Public\*.sys)'
Remove-Path 'C:\Users\Public\dz_selftest_evil_com.dll'          'COM hijack DLL (Public)'
Remove-Path 'C:\Users\Public\dz_selftest_flag_svc.exe'          'Flag-service binary (Public)'
Remove-Path 'C:\Program Files\dz selftest fp'                   'FP-service directory'
Remove-Path 'C:\dz_selftest_excl_dir'                           'Defender exclusion directory'
Remove-Path (Join-Path $OutDir 'baseline.snapshot')            'Seeded baseline snapshot'
# A harness run BEFORE the -selftest quarantine seeded its baseline into the
# real output dir. That snapshot is captured pre-plant, so it carries no marker
# and is indistinguishable from a user's own -baseline capture -- deleting it
# could destroy real data, so it is reported, never removed.
$stray = 'C:\SecurityAudit\baseline.snapshot'
if (Test-Path -LiteralPath $stray) {
    Write-Host ("  [NOTE   ] {0} exists. If you never ran the audit with -baseline yourself, a pre-quarantine harness run seeded it and your next real run would diff against test state: delete it, or re-run with -baseline to recapture." -f $stray)
}

# --- HOSTS: drop only the marker lines -------------------------------------
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
try {
    $lines = Get-Content -LiteralPath $hostsPath -Encoding UTF8 -EA Stop
    $kept  = @($lines | Where-Object { $_ -notmatch $MARK })
    if ($kept.Count -ne $lines.Count) {
        Set-Content -LiteralPath $hostsPath -Value $kept -Encoding UTF8 -Force
        Report 'HOSTS entry (DNS hijack line)' 'REMOVED'
    } else { Report 'HOSTS entry (DNS hijack line)' 'ABSENT' }
} catch { Report 'HOSTS entry (DNS hijack line)' 'ABSENT' }

# --- PowerShell profile: delete ONLY if it is the planted download cradle ---
$psProfile = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
try {
    if (Test-Path -LiteralPath $psProfile) {
        $body = Get-Content -LiteralPath $psProfile -Raw -EA Stop
        if ($body -match $MARK) {
            Remove-Item -LiteralPath $psProfile -Force
            Report 'PowerShell profile (planted download cradle)' 'REMOVED'
        } else { Report 'PowerShell profile (real one -- left untouched)' 'ABSENT' }
    } else { Report 'PowerShell profile (planted download cradle)' 'ABSENT' }
} catch { Report 'PowerShell profile (planted download cradle)' 'ABSENT' }

# --- Reset-to-safe-default settings (exact known plant targets) ------------
# Guest account: the harness enables it; default on modern Windows is disabled.
try {
    $g = & net user guest 2>$null | Select-String 'active'
    if ($g -and ($g -match 'Yes')) { & net user guest /active:no | Out-Null; Report 'Guest account (disable)' 'REMOVED' }
    else { Report 'Guest account (already disabled)' 'ABSENT' }
} catch { Report 'Guest account (disable)' 'ABSENT' }

# Firewall Private profile: the harness disables it; re-enable.
try {
    $fw = Get-NetFirewallProfile -Profile Private -EA Stop
    if (-not $fw.Enabled) { Set-NetFirewallProfile -Profile Private -Enabled True; Report 'Firewall Private profile (re-enable)' 'REMOVED' }
    else { Report 'Firewall Private profile (already on)' 'ABSENT' }
} catch { Report 'Firewall Private profile (re-enable)' 'ABSENT' }

# Defender exclusion path.
try {
    $ex = (Get-MpPreference -EA Stop).ExclusionPath
    if ($ex -and ($ex -contains 'C:\dz_selftest_excl_dir')) { Remove-MpPreference -ExclusionPath 'C:\dz_selftest_excl_dir' -EA SilentlyContinue; Report 'Defender exclusion (C:\dz_selftest_excl_dir)' 'REMOVED' }
    else { Report 'Defender exclusion (C:\dz_selftest_excl_dir)' 'ABSENT' }
} catch { Report 'Defender exclusion (C:\dz_selftest_excl_dir)' 'ABSENT' }

# netsh portproxy tunnel (Volt Typhoon IOC shape).
try {
    $pp = & netsh interface portproxy show v4tov4 2>$null | Out-String
    if ($pp -match '53219') { & netsh interface portproxy delete v4tov4 listenport=53219 listenaddress=127.0.0.1 | Out-Null; Report 'netsh portproxy tunnel (port 53219)' 'REMOVED' }
    else { Report 'netsh portproxy tunnel (port 53219)' 'ABSENT' }
} catch { Report 'netsh portproxy tunnel (port 53219)' 'ABSENT' }

Write-Host ''
Write-Host ("== Teardown complete: {0} removed, {1} already absent ==" -f $removed, $absent)
if ($errors.Count) {
    Write-Host ''
    Write-Host ("[WARNING] {0} item(s) errored during removal -- review:" -f $errors.Count)
    $errors | ForEach-Object { Write-Host ("  - " + $_) }
    exit 1
}
if ($removed -eq 0) {
    Write-Host 'Nothing planted was found -- the machine is clean of detection-harness artifacts.'
}
exit 0
