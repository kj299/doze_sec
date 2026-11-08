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
#   * the SMB server's own configuration (Get-SmbServerConfiguration
#     .EnableSMB1Protocol) is the EFFECT -- what the server accepts -- and
#     decides whenever it answered: enabled -> the CRITICAL finding (wording
#     kept, hit marker dz_smb1_hit.txt that the bat already raises);
#     disabled -> [OK], even with the component installed (Microsoft
#     documents that setting as a way to disable SMBv1), the installed
#     component then said as [INFO];
#   * the optional feature (Win32_OptionalFeature SMB1Protocol-Server, or
#     SMB1Protocol on a build without that subfeature; InstallState 1
#     Enabled, 2 Disabled, 3 Absent) decides only when the configuration
#     could not be read: installed -> a WARNING that says the setting was not
#     seen (marker dz_smb1_inst.txt, its own row), never the CRITICAL; off or
#     not installed -> [OK]. A class that lists no SMB1Protocol row at all is
#     no answer: every Windows 10/11 build lists it;
#   * the LanmanServer SMB1 registry value is INTENT, printed as [INFO] and
#     never deciding: a stale value must not raise CRITICAL on a machine
#     whose SMBv1 component is removed, nor clear one where it runs;
#   * neither source readable -> on an administrator token, or when a failure
#     is NOT access denied, a raised "[WARNING] ... NOT performed" gap
#     (dz_smb1_gap.txt); on a standard-user token where every failure was
#     access denied, [DEFERRED - ADMIN REQUIRED] (dz_smb1_deferred.txt).
# State line (dz_smb1_state.txt): smb1=<enabled|installed|disabled|absent|gap|deferred>
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

# PURE. $Reads: one entry per source tried, each @{ Source; Kind; Verdict;
# Error; Denied }, Kind 'config' (Get-SmbServerConfiguration: what the server
# ACCEPTS) or 'feature' (Win32_OptionalFeature: whether the component is
# installed), Verdict 'enabled'|'disabled'|'absent'. The server configuration
# is the effect and DECIDES whenever it answered: Microsoft documents
# Set-SmbServerConfiguration -EnableSMB1Protocol $false as a way to disable
# SMBv1 with the component still installed, so "installed" is not "enabled".
# The feature decides only when the configuration could not be read, and
# then an installed component is a WARNING (the server accepts SMBv1 by
# default when it is installed, but this run could not see the setting),
# never the CRITICAL. $RegValue: the LanmanServer SMB1 value as read ($null
# when absent or unreadable) -- intent, printed, never deciding.
# Returns @{ Lines; Hit; Installed; Gap; Deferred; State }.
function Get-Smb1Verdict {
    param([object[]]$Reads = @(), $RegValue = $null, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $failed = New-Object System.Collections.ArrayList
    $allDenied = $true
    $cfg = $null; $feat = $null
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
        if ($r.Kind -eq 'config' -and $null -eq $cfg) { $cfg = $r }
        elseif ($r.Kind -eq 'feature' -and $null -eq $feat) { $feat = $r }
    }
    $reg = ''
    if ($null -ne $RegValue) {
        $reg = ('[INFO] Registry intent: LanmanServer\Parameters SMB1 = ' + (ConvertTo-PrintableText ([string]$RegValue)) + ' (a setting, not the effect; it does not decide this verdict).')
    }
    $done = { param($o, $hit, $inst, $state)
        if ($failed.Count -gt 0) { [void]$o.Add(('[INFO] Not every source could be read: ' + ($failed.ToArray() -join '; ') + '.')) }
        if ($reg) { [void]$o.Add($reg) }
        return @{ Lines = @($o.ToArray()); Hit = $hit; Installed = $inst; Gap = $false; Deferred = 0; State = $state }
    }
    if ($null -ne $cfg) {
        if ($cfg.Verdict -eq 'enabled') {
            [void]$out.Add('[CRITICAL] SMBv1 ENABLED (EternalBlue CVE-2017-0144)')
            [void]$out.Add(('[INFO] Read by ' + $cfg.Source + ' (the server accepts SMBv1).'))
            return (& $done $out $true $false 'smb1=enabled')
        }
        [void]$out.Add(('[OK] SMBv1 disabled. (read by ' + $cfg.Source + ': the server does not accept SMBv1)'))
        if ($null -ne $feat -and $feat.Verdict -eq 'enabled') {
            [void]$out.Add('[INFO] The SMBv1 server component is still installed (' + $feat.Source + '). Removing it, Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol, is the stronger mitigation: a setting can be turned back on.')
        }
        return (& $done $out $false $false 'smb1=disabled')
    }
    if ($null -ne $feat) {
        if ($feat.Verdict -eq 'enabled') {
            [void]$out.Add(('[WARNING] SMBv1 server component INSTALLED (' + $feat.Source + ') and the SMB server configuration could not be read, so whether it accepts SMBv1 is unknown -- installed, it does by default (T1210).'))
            return (& $done $out $false $true 'smb1=installed')
        }
        if ($feat.Verdict -eq 'disabled') { [void]$out.Add(('[OK] SMBv1 disabled. (read by ' + $feat.Source + ': the server component is turned off)')); return (& $done $out $false $false 'smb1=disabled') }
        [void]$out.Add(('[OK] SMBv1 server component not installed. (read by ' + $feat.Source + ')'))
        return (& $done $out $false $false 'smb1=absent')
    }
    $why = if ($failed.Count -gt 0) { ($failed.ToArray() -join '; ') } else { 'no source was tried' }
    if ((-not $IsElevated) -and $allDenied -and $failed.Count -gt 0) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] SMBv1 check: a standard-user token cannot read the SMB server state (' + $why + ') -- re-run as administrator to check it.'))
        if ($reg) { [void]$out.Add($reg) }
        return @{ Lines = @($out.ToArray()); Hit = $false; Installed = $false; Gap = $false; Deferred = 1; State = 'smb1=deferred' }
    }
    [void]$out.Add(('[WARNING] SMBv1 check NOT performed -- the SMB server state could not be read (' + $why + '), so an enabled SMBv1 server would go unseen (T1210).'))
    if ($reg) { [void]$out.Add($reg) }
    return @{ Lines = @($out.ToArray()); Hit = $false; Installed = $false; Gap = $true; Deferred = 0; State = 'smb1=gap' }
}

# PURE. Which verdict a set of optional-feature rows gives: the -Server
# subfeature when it exists, else the parent. Every Windows 10/11 build lists
# SMB1Protocol even when it is not installed, so NO row is no answer (a
# provider that returned nothing), never "absent".
function Get-FeatureVerdict {
    param([object[]]$Rows = @())
    $pick = @($Rows | Where-Object { [string]$_.Name -eq 'SMB1Protocol-Server' })
    if ($pick.Count -eq 0) { $pick = @($Rows | Where-Object { [string]$_.Name -eq 'SMB1Protocol' }) }
    if ($pick.Count -eq 0) { return '' }
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
        return @{ Source = $src; Kind = 'config'; Verdict = $verdict; Error = ''; Denied = $false }
    } catch { return @{ Source = $src; Kind = 'config'; Verdict = ''; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_) } }
}
function Read-ViaCim {
    $src = 'CIM Win32_OptionalFeature'
    try {
        $rows = @(Get-CimInstance -ClassName $CimClass -Filter "Name LIKE 'SMB1Protocol%'" -ErrorAction Stop)
        return @{ Source = $src; Kind = 'feature'; Verdict = (Get-FeatureVerdict -Rows $rows); Error = ''; Denied = $false }
    } catch { return @{ Source = $src; Kind = 'feature'; Verdict = ''; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_) } }
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
    $sm = { param($v, $err = '', $den = $false) @{ Source = 'Get-SmbServerConfiguration'; Kind = 'config'; Verdict = $v; Error = $err; Denied = $den } }
    $ci = { param($v, $err = '', $den = $false) @{ Source = 'CIM Win32_OptionalFeature'; Kind = 'feature'; Verdict = $v; Error = $err; Denied = $den } }
    function F { param([string]$n, [int]$s) New-Object PSObject -Property @{ Name = $n; InstallState = $s } }

    $v = Get-Smb1Verdict -Reads @((& $sm 'disabled'), (& $ci 'disabled'))
    $t = $v.Lines -join "`n"
    T 'the server configuration disabled: [OK] naming it, nothing raised' ((-not $v.Hit) -and (-not $v.Installed) -and (-not $v.Gap) -and $v.State -eq 'smb1=disabled' -and $t -match '(?m)^\[OK\] SMBv1 disabled\. \(read by Get-SmbServerConfiguration: the server does not accept SMBv1\)$') $t
    $v = Get-Smb1Verdict -Reads @((& $sm 'enabled'), (& $ci 'enabled'))
    $t = $v.Lines -join "`n"
    T 'the server configuration says enabled: the CRITICAL wording the bats always printed' ($v.Hit -and $v.State -eq 'smb1=enabled' -and $t -match '(?m)^\[CRITICAL\] SMBv1 ENABLED \(EternalBlue CVE-2017-0144\)$') $t
    $v = Get-Smb1Verdict -Reads @((& $sm 'disabled'), (& $ci 'enabled'))
    $t = $v.Lines -join "`n"
    T 'component installed but the server configured not to accept SMBv1 (a documented mitigation): [OK] with the removal advice, never CRITICAL' ((-not $v.Hit) -and (-not $v.Installed) -and $v.State -eq 'smb1=disabled' -and $t -match 'still installed' -and $t -notmatch '\[CRITICAL\]' -and $t -notmatch '\[WARNING\]') $t
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Access denied' $true), (& $ci 'enabled'))
    $t = $v.Lines -join "`n"
    T 'the configuration unreadable, the component installed: a WARNING that says the setting was not seen, never CRITICAL and never [OK]' ($v.Installed -and (-not $v.Hit) -and $v.State -eq 'smb1=installed' -and $t -match '(?m)^\[WARNING\] SMBv1 server component INSTALLED' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[CRITICAL\]') $t
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Access denied' $true), (& $ci 'absent'))
    T 'the configuration unreadable, the component not installed: [OK] not installed, and the failure is said' ((-not $v.Hit) -and $v.State -eq 'smb1=absent' -and ($v.Lines -join "`n") -match 'Not every source could be read') ($v.Lines -join ' | ')
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Invalid class'), (& $ci '' 'CimException: Invalid class')) -IsElevated $true
    $t = $v.Lines -join "`n"
    T 'neither source readable, elevated: a raised gap naming both, never [OK] and never [SKIPPED]' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'smb1=gap' -and $t -match '(?m)^\[WARNING\] SMBv1 check NOT performed' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[SKIPPED\]') $t
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Access denied' $true), (& $ci '' 'CimException: Access denied' $true)) -IsElevated $false
    $t = $v.Lines -join "`n"
    T 'standard-user token, every failure access denied: a counted deferral, never a gap row and never an all-clear' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.State -eq 'smb1=deferred' -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] SMBv1 check' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[WARNING\]') $t
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Access denied' $true), (& $ci '' 'CimException: Invalid class' $false)) -IsElevated $false
    T 'standard-user token, one failure NOT access denied: a raised gap, the token does not explain it' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-Smb1Verdict -Reads @((& $sm '' 'CimException: Access denied' $true), (& $ci '')) -IsElevated $false
    $t = $v.Lines -join "`n"
    T 'the configuration denied and the feature class listed nothing: no answer, a raised gap, never "[OK] not installed"' ($v.Gap -and $v.State -eq 'smb1=gap' -and $t -notmatch '\[OK\]') $t
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
    T 'feature rows: none listed is no answer (every build lists SMB1Protocol); an unknown state is no answer' ((Get-FeatureVerdict -Rows @()) -eq '' -and (Get-FeatureVerdict -Rows @((F 'SMB1Protocol-Server' 7))) -eq '' -and (Get-FeatureVerdict -Rows @((F 'SMB1Protocol' 3))) -eq 'absent') ''
    if ($fails) { Write-Output "[FAIL] $fails smb1_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] smb1_check self-test: the server configuration decides (enabled is CRITICAL, disabled is OK even with the component installed), an installed component with the setting unseen is a WARNING, the registry is intent and never decides, and a state that could not be read is a raised gap (a deferral only for an access-denied standard user), never an all-clear.'
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
if ($null -eq $v -or [string]$v.State -notmatch '^smb1=(enabled|installed|disabled|absent|gap|deferred)$') {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'smb1_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.Hit) { Write-Marker -Name 'smb1_hit' -Sev 'hit' }
if ($v.Installed) { Write-Marker -Name 'smb1_inst' -Sev 'WARNING' }
if ($v.Gap) { Write-Marker -Name 'smb1_gap' -Sev 'WARNING' }
if ($v.Deferred -gt 0) { Write-Marker -Name 'smb1_deferred' -Sev ([string]$v.Deferred) }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('smb1_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
