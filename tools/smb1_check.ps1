# smb1_check.ps1 -- Section 10: is the SMBv1 server enabled? (T1210,
# EternalBlue CVE-2017-0144)
#
# Extracted from an inline line in both bats that read
#   (Get-SmbServerConfiguration -EA SilentlyContinue).EnableSMB1Protocol
# so a query that FAILED printed "[SKIPPED] SMBv1 state unavailable." and
# raised nothing. On a standard-user token the cmdlet ALWAYS fails (it needs
# administrator), so every standard-user run printed a skip that was really
# a deferral, and the dashboard re-ran the same query for its tile.
#
# THE RULE (pure, in Get-Smb1Verdict, pinned by -SelfTest):
#   * two sources of the EFFECT, every one weighed: the SMB server's own
#     configuration (Get-SmbServerConfiguration .EnableSMB1Protocol), and the
#     Windows optional feature that carries the SMBv1 server
#     (Win32_OptionalFeature SMB1Protocol-Server, or SMB1Protocol on a build
#     without that subfeature; InstallState 1 Enabled, 2 Disabled, 3 Absent);
#   * evidence is not symmetric: SMBv1 enabled from EITHER source is the
#     CRITICAL finding (wording kept, hit marker dz_smb1_hit.txt that the bat
#     already raises), whatever the other says;
#   * the LanmanServer SMB1 registry value is INTENT, printed as [INFO] and
#     never deciding: a stale value must not raise CRITICAL on a machine
#     whose SMBv1 component is removed, nor clear one where it runs;
#   * neither source readable -> on an administrator token, or when a failure
#     is NOT access denied, a raised "[WARNING] ... NOT performed" gap
#     (dz_smb1_gap.txt); on a standard-user token where every failure was
#     access denied, [DEFERRED - ADMIN REQUIRED] (dz_smb1_deferred.txt).
# State line (dz_smb1_state.txt): smb1=<enabled|disabled|absent|gap|deferred>
#
# Usage:
#   powershell -File tools\smb1_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1]
#   powershell -File tools\smb1_check.ps1 -SelfTest   (queries nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # Only CI changes these, so each failure path runs through the real
    # readers: which sources to ask, and a CIM class that does not exist.
    [ValidateSet('all', 'smb', 'cim')]
    [string[]]$Sources = @('all'),
    [string]$CimClass = 'Win32_OptionalFeature',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_smb1_state.txt' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    # An empty value is no verdict, never a marker.
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintableText {
    # An error message goes into the report as text: no control characters.
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

# PURE. $Reads: one entry per source tried, each @{ Source; Verdict; Error;
# Denied }, Verdict 'enabled'|'disabled'|'absent'. $RegValue: the
# LanmanServer SMB1 value as read ($null when absent or unreadable).
# Returns @{ Lines; Hit; Gap; Deferred; State }.
function Get-Smb1Verdict {
    param([object[]]$Reads = @(), $RegValue = $null, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $failed = New-Object System.Collections.ArrayList
    $allDenied = $true
    $seen = New-Object System.Collections.ArrayList
    foreach ($r in @($Reads)) {
        if ($r.Error) {
            [void]$failed.Add(($r.Source + ': ' + (ConvertTo-PrintableText $r.Error)))
            if (-not $r.Denied) { $allDenied = $false }
            continue
        }
        if (@('enabled', 'disabled', 'absent') -notcontains [string]$r.Verdict) {
            [void]$failed.Add(($r.Source + ': gave no usable answer'))
            $allDenied = $false
            continue
        }
        [void]$seen.Add(@{ Source = $r.Source; Verdict = [string]$r.Verdict })
    }
    $reg = ''
    if ($null -ne $RegValue) {
        $reg = ('[INFO] Registry intent: LanmanServer\Parameters SMB1 = ' + (ConvertTo-PrintableText ([string]$RegValue)) + ' (a setting, not the effect; it does not decide this verdict).')
    }
    if ($seen.Count -eq 0) {
        $why = if ($failed.Count -gt 0) { ($failed.ToArray() -join '; ') } else { 'no source was tried' }
        if ((-not $IsElevated) -and $allDenied -and $failed.Count -gt 0) {
            [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] SMBv1 check: a standard-user token cannot read the SMB server state (' + $why + ') -- re-run as administrator to check it.'))
            if ($reg) { [void]$out.Add($reg) }
            return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 1; State = 'smb1=deferred' }
        }
        [void]$out.Add(('[WARNING] SMBv1 check NOT performed -- the SMB server state could not be read (' + $why + '), so an enabled SMBv1 server would go unseen (T1210).'))
        if ($reg) { [void]$out.Add($reg) }
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0; State = 'smb1=gap' }
    }
    $by = { param($v) (@($seen | Where-Object { $_.Verdict -eq $v } | ForEach-Object { $_.Source }) -join ' and ') }
    $hit = $false
    if (@($seen | Where-Object { $_.Verdict -eq 'enabled' }).Count -gt 0) {
        [void]$out.Add('[CRITICAL] SMBv1 ENABLED (EternalBlue CVE-2017-0144)')
        [void]$out.Add(('[INFO] Read by ' + (& $by 'enabled') + '.'))
        $hit = $true; $state = 'smb1=enabled'
    } elseif (@($seen | Where-Object { $_.Verdict -eq 'disabled' }).Count -gt 0) {
        [void]$out.Add(('[OK] SMBv1 disabled. (read by ' + (& $by 'disabled') + ')'))
        $state = 'smb1=disabled'
    } else {
        [void]$out.Add(('[OK] SMBv1 server component not installed. (read by ' + (& $by 'absent') + ')'))
        $state = 'smb1=absent'
    }
    if (@($seen | ForEach-Object { $_.Verdict } | Sort-Object -Unique).Count -gt 1) {
        [void]$out.Add(('[INFO] The sources disagree: ' + ((@($seen | ForEach-Object { $_.Source + ' read ' + $_.Verdict })) -join ', ') + '. The verdict above takes the one that found SMBv1 in use.'))
    }
    if ($failed.Count -gt 0) { [void]$out.Add(('[INFO] Not every source could be read: ' + ($failed.ToArray() -join '; ') + '.')) }
    if ($reg) { [void]$out.Add($reg) }
    return @{ Lines = @($out.ToArray()); Hit = $hit; Gap = $false; Deferred = 0; State = $state }
}

# PURE. Which verdict a set of optional-feature rows gives: the -Server
# subfeature when it exists, else the parent. $null when neither is listed
# (only meaningful when the class answered).
function Get-FeatureVerdict {
    param([object[]]$Rows = @())
    $pick = @($Rows | Where-Object { [string]$_.Name -eq 'SMB1Protocol-Server' })
    if ($pick.Count -eq 0) { $pick = @($Rows | Where-Object { [string]$_.Name -eq 'SMB1Protocol' }) }
    if ($pick.Count -eq 0) { return 'absent' }
    switch ([int]$pick[0].InstallState) { 1 { 'enabled' } 2 { 'disabled' } 3 { 'absent' } default { '' } }
}

function Test-Denied {
    # Access denied anywhere in the exception chain: the .NET type, the Win32
    # HRESULT (E_ACCESSDENIED) or a CIM AccessDenied result.
    param($Err)
    $x = $Err.Exception
    while ($x) {
        if ($x -is [System.UnauthorizedAccessException]) { return $true }
        if ($x.HResult -eq -2147024891) { return $true }
        try { if ([string]$x.NativeErrorCode -eq 'AccessDenied') { return $true } } catch {}
        $x = $x.InnerException
    }
    return $false
}

function Read-ViaSmb {
    $src = 'Get-SmbServerConfiguration'
    try {
        $c = Get-SmbServerConfiguration -ErrorAction Stop
        $e = $c.EnableSMB1Protocol
        $verdict = if ($e -eq $true) { 'enabled' } elseif ($e -eq $false) { 'disabled' } else { '' }
        return @{ Source = $src; Verdict = $verdict; Error = ''; Denied = $false }
    } catch { return @{ Source = $src; Verdict = ''; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_) } }
}
function Read-ViaCim {
    $src = 'CIM Win32_OptionalFeature'
    try {
        $rows = @(Get-CimInstance -ClassName $CimClass -Filter "Name LIKE 'SMB1Protocol%'" -ErrorAction Stop)
        return @{ Source = $src; Verdict = (Get-FeatureVerdict -Rows $rows); Error = ''; Denied = $false }
    } catch { return @{ Source = $src; Verdict = ''; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_) } }
}
function Read-RegistryIntent {
    try {
        $p = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -ErrorAction Stop
        return $p.SMB1
    } catch { return $null }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $sm = { param($v, $err = '', $den = $false) @{ Source = 'Get-SmbServerConfiguration'; Verdict = $v; Error = $err; Denied = $den } }
    $ci = { param($v, $err = '', $den = $false) @{ Source = 'CIM Win32_OptionalFeature'; Verdict = $v; Error = $err; Denied = $den } }
    function F { param([string]$n, [int]$s) New-Object PSObject -Property @{ Name = $n; InstallState = $s } }

    $v = Get-Smb1Verdict -Reads @((& $sm 'disabled'), (& $ci 'disabled'))
    $t = $v.Lines -join "`n"
    T 'both sources disabled: [OK] naming both, nothing raised' ((-not $v.Hit) -and (-not $v.Gap) -and $v.State -eq 'smb1=disabled' -and $t -match '(?m)^\[OK\] SMBv1 disabled\. \(read by Get-SmbServerConfiguration and CIM Win32_OptionalFeature\)$') $t
    $v = Get-Smb1Verdict -Reads @((& $sm 'enabled'), (& $ci 'disabled'))
    $t = $v.Lines -join "`n"
    T 'the server configuration says enabled: the CRITICAL wording the bats always printed, and the disagreement is said' ($v.Hit -and $v.State -eq 'smb1=enabled' -and $t -match '(?m)^\[CRITICAL\] SMBv1 ENABLED \(EternalBlue CVE-2017-0144\)$' -and $t -match 'The sources disagree') $t
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Access denied' $true), (& $ci 'enabled'))
    T 'the cmdlet denied, the feature enabled: still CRITICAL, from the feature' ($v.Hit -and ($v.Lines -join "`n") -match 'Read by CIM Win32_OptionalFeature\.') ($v.Lines -join ' | ')
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Access denied' $true), (& $ci 'absent'))
    T 'the cmdlet denied, the feature absent: [OK] not installed, and the failure is said' ((-not $v.Hit) -and $v.State -eq 'smb1=absent' -and ($v.Lines -join "`n") -match 'Not every source could be read') ($v.Lines -join ' | ')
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Invalid class'), (& $ci '' 'CimException: Invalid class')) -IsElevated $true
    $t = $v.Lines -join "`n"
    T 'neither source readable, elevated: a raised gap naming both, never [OK] and never [SKIPPED]' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'smb1=gap' -and $t -match '(?m)^\[WARNING\] SMBv1 check NOT performed' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[SKIPPED\]') $t
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Access denied' $true), (& $ci '' 'CimException: Access denied' $true)) -IsElevated $false
    $t = $v.Lines -join "`n"
    T 'standard-user token, every failure access denied: a counted deferral, never a gap row and never an all-clear' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.State -eq 'smb1=deferred' -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] SMBv1 check' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[WARNING\]') $t
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Access denied' $true), (& $ci '' 'CimException: Invalid class' $false)) -IsElevated $false
    T 'standard-user token, one failure NOT access denied: a raised gap, the token does not explain it' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-Smb1Verdict -Reads @((& $sm 'disabled'), (& $ci 'absent')) -RegValue 1
    $t = $v.Lines -join "`n"
    T 'registry SMB1=1 while the effect is off: [OK] with the intent as INFO, never CRITICAL' ((-not $v.Hit) -and $v.State -eq 'smb1=disabled' -and $t -match '\[INFO\] Registry intent: LanmanServer\\Parameters SMB1 = 1' -and $t -notmatch '\[CRITICAL\]') $t
    $v = Get-Smb1Verdict -Reads @((& $sm 'enabled')) -RegValue 0
    T 'registry SMB1=0 while the server reports it enabled: CRITICAL, the registry cannot clear it' ($v.Hit -and $v.State -eq 'smb1=enabled') ($v.Lines -join ' | ')
    $v = Get-Smb1Verdict -Reads @((& $sm ''))
    T 'a source with no usable answer is a failure, not an all-clear' ($v.Gap -and ($v.Lines -join "`n") -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-Smb1Verdict -Reads @((& $sm '' ('bad' + [char]10 + '[OK] fine')))
    T 'a control character in an error cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    T 'feature rows: the -Server subfeature decides when it exists' ((Get-FeatureVerdict -Rows @((F 'SMB1Protocol' 1), (F 'SMB1Protocol-Server' 2))) -eq 'disabled') ''
    T 'feature rows: the parent decides on a build without the subfeature' ((Get-FeatureVerdict -Rows @((F 'SMB1Protocol' 1))) -eq 'enabled') ''
    T 'feature rows: none listed by a class that answered is absent; an unknown state is no answer' ((Get-FeatureVerdict -Rows @()) -eq 'absent' -and (Get-FeatureVerdict -Rows @((F 'SMB1Protocol-Server' 7))) -eq '') ''
    if ($fails) { Write-Output "[FAIL] $fails smb1_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] smb1_check self-test: SMBv1 enabled from either source is CRITICAL, the registry is intent and never decides, and a state that could not be read is a raised gap (a deferral only for an access-denied standard user), never an all-clear.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$all = $Sources -contains 'all'
$reads = @()
if ($all -or $Sources -contains 'smb') { $reads += , (Read-ViaSmb) }
if ($all -or $Sources -contains 'cim') { $reads += , (Read-ViaCim) }
$v = $null
try { $v = Get-Smb1Verdict -Reads $reads -RegValue (Read-RegistryIntent) -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^smb1=(enabled|disabled|absent|gap|deferred)$') {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'smb1_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.Hit) { Write-Marker -Name 'smb1_hit' -Sev 'hit' }
if ($v.Gap) { Write-Marker -Name 'smb1_gap' -Sev 'WARNING' }
if ($v.Deferred -gt 0) { Write-Marker -Name 'smb1_deferred' -Sev ([string]$v.Deferred) }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('smb1_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
