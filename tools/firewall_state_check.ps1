# firewall_state_check.ps1 -- Section 8: is Windows Firewall actually filtering
# on every profile? (T1562.004)
#
# Extracted from an inline line in both bats that read
#   $fwp=@(Get-NetFirewallProfile -EA SilentlyContinue)
# Two defects:
#   * a query that FAILED printed "[SKIPPED] Get-NetFirewallProfile
#     unavailable" and raised nothing -- the firewall state went unchecked and
#     the section could still read CLEAN;
#   * with no -PolicyStore, Get-NetFirewallProfile reads the LOCAL store. A
#     Group Policy that turns a profile off (or on) is not in it, so the
#     setting was graded, not the effect.
#
# THE RULE (pure, in Get-FirewallVerdict, pinned by -SelfTest):
#   * three sources, every one weighed: the EFFECTIVE profile state from
#     Get-NetFirewallProfile -PolicyStore ActiveStore; the same from the
#     HNetCfg.FwPolicy2 COM object (an independent API); and the mpssvc
#     service, without which no profile filters anything;
#   * evidence is not symmetric: a profile OFF from ANY source, or mpssvc not
#     running, is the CRITICAL finding (wording kept, hit marker dz_fw_hit.txt
#     that the bat already raises), whatever another source says;
#   * all three profiles ON from at least one profile source, and no source
#     saying otherwise -> [OK], naming the sources;
#   * no profile source could be read -> on an administrator token, or when a
#     failure is NOT access denied, a raised "[WARNING] ... NOT performed"
#     gap (dz_fw_gap.txt); on a standard-user token where every failure was
#     access denied, [DEFERRED - ADMIN REQUIRED] (dz_fw_deferred.txt).
# State line (dz_fw_state.txt): fw=<off|on|gap|deferred>,profiles=<names joined by + or ->
# (no '|': the dashboard pastes it into a cmd echo, where '|' is a pipe)
#
# Usage:
#   powershell -File tools\firewall_state_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1]
#   powershell -File tools\firewall_state_check.ps1 -SelfTest   (queries nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # Only CI changes these, so each failure path runs through the real
    # readers: which sources to ask, and a service name that does not exist.
    [ValidateSet('all', 'netsecurity', 'com', 'service')]
    [string[]]$Sources = @('all'),
    [string]$ServiceName = 'mpssvc',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_fw_state.txt' }

$script:FwProfiles = @('Domain', 'Private', 'Public')

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

# PURE. $Reads: one entry per profile source tried, each @{ Source; Profiles;
# Error; Denied }, Profiles a hashtable name -> 'on'|'off'|'unknown'.
# $Service: $null (not asked) or @{ Status; Error; Denied }, Status the
# service's Status as text. Returns @{ Lines; Hit; Gap; Deferred; State }.
function Get-FirewallVerdict {
    param([object[]]$Reads = @(), $Service = $null, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $failed = New-Object System.Collections.ArrayList
    $allDenied = $true
    $answered = New-Object System.Collections.ArrayList
    $off = New-Object System.Collections.ArrayList        # profile names
    $offBy = @{}                                           # profile -> sources
    $onSeen = @{}                                          # profile -> $true
    foreach ($r in @($Reads)) {
        if ($r.Error) {
            [void]$failed.Add(($r.Source + ': ' + (ConvertTo-PrintableText $r.Error)))
            if (-not $r.Denied) { $allDenied = $false }
            continue
        }
        $p = $r.Profiles
        if ($null -eq $p -or @($script:FwProfiles | Where-Object { $p.ContainsKey($_) }).Count -eq 0) {
            [void]$failed.Add(($r.Source + ': returned no firewall profiles'))
            $allDenied = $false
            continue
        }
        [void]$answered.Add($r.Source)
        foreach ($n in $script:FwProfiles) {
            $s = [string]$p[$n]
            if ($s -eq 'off') {
                if (-not $offBy.ContainsKey($n)) { $offBy[$n] = New-Object System.Collections.ArrayList; [void]$off.Add($n) }
                [void]$offBy[$n].Add($r.Source)
            } elseif ($s -eq 'on') { $onSeen[$n] = $true }
        }
    }
    $svcStopped = $false; $svcNote = ''
    if ($null -ne $Service) {
        if ($Service.Error) { $svcNote = ('the firewall service could not be queried (' + (ConvertTo-PrintableText $Service.Error) + ')') }
        elseif ([string]$Service.Status -ne 'Running') { $svcStopped = $true }
    }
    $hit = $false; $state = ''
    $orderedOff = @($script:FwProfiles | Where-Object { $off -contains $_ })
    if ($orderedOff.Count -gt 0) {
        [void]$out.Add(('[CRITICAL] Firewall DISABLED on ' + $orderedOff.Count + ' profile(s): ' + ($orderedOff -join ', ') + ' (T1562.004)'))
        [void]$out.Add(('[INFO] Effective state read by ' + (@($orderedOff | ForEach-Object { $_ + ': ' + ($offBy[$_].ToArray() -join ' and ') }) -join '; ') + '.'))
        $hit = $true; $state = ('fw=off,profiles=' + ($orderedOff -join '+'))
    }
    if ($svcStopped) {
        [void]$out.Add(('[CRITICAL] Firewall DISABLED: the Windows Defender Firewall service (mpssvc) is not running (status ' + (ConvertTo-PrintableText ([string]$Service.Status)) + '), so no profile filters anything (T1562.004)'))
        if (-not $hit) { $state = 'fw=off,profiles=service' }
        $hit = $true
    }
    if (-not $hit) {
        if ($answered.Count -eq 0) {
            $why = if ($failed.Count -gt 0) { ($failed.ToArray() -join '; ') } else { 'no source was tried' }
            if ((-not $IsElevated) -and $allDenied -and $failed.Count -gt 0) {
                [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] Firewall-state check: a standard-user token cannot read the firewall profiles (' + $why + ') -- re-run as administrator to check them.'))
                return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 1; State = 'fw=deferred,profiles=-' }
            }
            [void]$out.Add(('[WARNING] Firewall-state check NOT performed -- the firewall profiles could not be read (' + $why + '), so a disabled firewall would go unseen (T1562.004).'))
            if ($svcNote) { [void]$out.Add(('[INFO] Also: ' + $svcNote + '.')) }
            return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0; State = 'fw=gap,profiles=-' }
        }
        $unknown = @($script:FwProfiles | Where-Object { -not $onSeen.ContainsKey($_) })
        if ($unknown.Count -gt 0) {
            # A profile no source could place is not "enabled".
            [void]$out.Add(('[WARNING] Firewall-state check NOT performed in full -- the state of profile(s) ' + ($unknown -join ', ') + ' could not be read (read by ' + ($answered.ToArray() -join ' and ') + '), so a disabled profile would go unseen (T1562.004).'))
            return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0; State = ('fw=gap,profiles=' + ($unknown -join '+')) }
        }
        [void]$out.Add(('[OK] All firewall profiles enabled - Domain, Private, Public. (effective state, read by ' + ($answered.ToArray() -join ' and ') + ')'))
        $state = 'fw=on,profiles=-'
    }
    $disagree = @($orderedOff | Where-Object { $onSeen.ContainsKey($_) })
    if ($disagree.Count -gt 0) {
        [void]$out.Add(('[INFO] The sources disagree on ' + ($disagree -join ', ') + ': another source read it ON. The verdict above takes the one that found it off.'))
    }
    if ($failed.Count -gt 0) { [void]$out.Add(('[INFO] Not every source could be read: ' + ($failed.ToArray() -join '; ') + '.')) }
    if ($svcNote) { [void]$out.Add(('[INFO] ' + $svcNote.Substring(0, 1).ToUpper() + $svcNote.Substring(1) + '.')) }
    return @{ Lines = @($out.ToArray()); Hit = $hit; Gap = $false; Deferred = 0; State = $state }
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
function ConvertTo-OnOff { param($v) switch ([string]$v) { 'True' { 'on' } 'False' { 'off' } default { 'unknown' } } }

function Read-ViaNetSecurity {
    $src = 'Get-NetFirewallProfile (ActiveStore)'
    try {
        $h = @{}
        foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) { $h[[string]$p.Name] = ConvertTo-OnOff $p.Enabled }
        return @{ Source = $src; Profiles = $h; Error = ''; Denied = $false }
    } catch { return @{ Source = $src; Profiles = $null; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_) } }
}
function Read-ViaCom {
    $src = 'HNetCfg.FwPolicy2'
    try {
        $fw = New-Object -ComObject HNetCfg.FwPolicy2 -ErrorAction Stop
        $h = @{}
        foreach ($t in @(@('Domain', 1), @('Private', 2), @('Public', 4))) { $h[$t[0]] = ConvertTo-OnOff ([bool]$fw.FirewallEnabled($t[1])) }
        return @{ Source = $src; Profiles = $h; Error = ''; Denied = $false }
    } catch { return @{ Source = $src; Profiles = $null; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_) } }
}
function Read-Service {
    try {
        $s = Get-Service -Name $ServiceName -ErrorAction Stop
        return @{ Status = [string]$s.Status; Error = ''; Denied = $false }
    } catch { return @{ Status = ''; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_) } }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $allOn = @{ Domain = 'on'; Private = 'on'; Public = 'on' }
    $ns = { param($p, $err = '', $den = $false) @{ Source = 'Get-NetFirewallProfile (ActiveStore)'; Profiles = $p; Error = $err; Denied = $den } }
    $co = { param($p, $err = '', $den = $false) @{ Source = 'HNetCfg.FwPolicy2'; Profiles = $p; Error = $err; Denied = $den } }
    $run = @{ Status = 'Running'; Error = '' }

    $v = Get-FirewallVerdict -Reads @((& $ns $allOn), (& $co $allOn)) -Service $run
    $t = $v.Lines -join "`n"
    T 'all profiles on from both sources, service running: [OK] naming both, nothing raised' ((-not $v.Hit) -and (-not $v.Gap) -and $v.State -eq 'fw=on,profiles=-' -and $t -match '(?m)^\[OK\] All firewall profiles enabled - Domain, Private, Public\. \(effective state, read by Get-NetFirewallProfile \(ActiveStore\) and HNetCfg\.FwPolicy2\)$') $t
    $v = Get-FirewallVerdict -Reads @((& $ns @{ Domain = 'on'; Private = 'off'; Public = 'on' })) -Service $run
    $t = $v.Lines -join "`n"
    T 'Private off: the CRITICAL wording the bats always printed, a hit, state names the profile' ($v.Hit -and $v.State -eq 'fw=off,profiles=Private' -and $t -match '(?m)^\[CRITICAL\] Firewall DISABLED on 1 profile\(s\): Private \(T1562\.004\)$') $t
    $v = Get-FirewallVerdict -Reads @((& $ns $allOn), (& $co @{ Domain = 'on'; Private = 'on'; Public = 'off' })) -Service $run
    $t = $v.Lines -join "`n"
    T 'one source says Public is off, the other on: the finding wins, and the disagreement is said' ($v.Hit -and $v.State -eq 'fw=off,profiles=Public' -and $t -match 'Public: HNetCfg\.FwPolicy2' -and $t -match 'The sources disagree on Public') $t
    $v = Get-FirewallVerdict -Reads @((& $ns $allOn), (& $co $allOn)) -Service @{ Status = 'Stopped'; Error = '' }
    $t = $v.Lines -join "`n"
    T 'every profile reads on but mpssvc is stopped: CRITICAL, never [OK]' ($v.Hit -and $v.State -eq 'fw=off,profiles=service' -and $t -match '(?m)^\[CRITICAL\] Firewall DISABLED: the Windows Defender Firewall service \(mpssvc\) is not running \(status Stopped\)' -and $t -notmatch '\[OK\]') $t
    $v = Get-FirewallVerdict -Reads @((& $ns $null 'CimException: Invalid class'), (& $co $allOn)) -Service $run
    $t = $v.Lines -join "`n"
    T 'the cmdlet failed: COM answers, [OK] names it, and the failure is said' ((-not $v.Hit) -and $v.State -eq 'fw=on,profiles=-' -and $t -match 'read by HNetCfg\.FwPolicy2\)' -and $t -match 'Not every source could be read: Get-NetFirewallProfile \(ActiveStore\): CimException') $t
    $v = Get-FirewallVerdict -Reads @((& $ns $null 'CimException: Invalid class'), (& $co $null 'COMException: class not registered')) -Service $run -IsElevated $true
    $t = $v.Lines -join "`n"
    T 'no profile source could be read, elevated: a raised gap naming both, never [OK] and never [SKIPPED]' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'fw=gap,profiles=-' -and $t -match '(?m)^\[WARNING\] Firewall-state check NOT performed' -and $t -match 'CimException' -and $t -match 'COMException' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[SKIPPED\]') $t
    $v = Get-FirewallVerdict -Reads @((& $ns $null 'CimException: Access denied' $true), (& $co $null 'UnauthorizedAccessException: denied' $true)) -Service $run -IsElevated $false
    $t = $v.Lines -join "`n"
    T 'standard-user token, every failure access denied: a counted deferral, never a gap row and never an all-clear' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.State -eq 'fw=deferred,profiles=-' -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] Firewall-state check' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[WARNING\]') $t
    $v = Get-FirewallVerdict -Reads @((& $ns $null 'CimException: Access denied' $true), (& $co $null 'COMException: class not registered' $false)) -Service $run -IsElevated $false
    T 'standard-user token, one failure NOT access denied: a raised gap, the token does not explain it' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-FirewallVerdict -Reads @((& $ns $null 'CimException: Access denied' $true), (& $co $null 'x' $true)) -Service @{ Status = 'Stopped'; Error = '' } -IsElevated $false
    T 'profiles unreadable but the service is stopped: still the CRITICAL finding, not a deferral' ($v.Hit -and $v.Deferred -eq 0 -and $v.State -eq 'fw=off,profiles=service') ($v.Lines -join ' | ')
    $v = Get-FirewallVerdict -Reads @((& $ns @{ Domain = 'on'; Private = 'unknown'; Public = 'on' })) -Service $run
    $t = $v.Lines -join "`n"
    T 'a profile no source could place is a gap, never "enabled"' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'fw=gap,profiles=Private' -and $t -notmatch '\[OK\]') $t
    $v = Get-FirewallVerdict -Reads @((& $ns @{})) -Service $run
    T 'a source that returns no profiles is a failure, not an all-clear' ($v.Gap -and ($v.Lines -join "`n") -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-FirewallVerdict -Reads @((& $ns $allOn)) -Service @{ Status = ''; Error = 'InvalidOperationException: no such service' }
    $t = $v.Lines -join "`n"
    T 'the service could not be queried: the profile verdict stands and the failure is said' ($v.State -eq 'fw=on,profiles=-' -and $t -match 'firewall service could not be queried') $t
    $v = Get-FirewallVerdict -Reads @((& $ns $null ('bad' + [char]10 + '[OK] fine')))
    T 'a control character in an error cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    T 'a GpoBoolean that is neither True nor False reads unknown, never off' ((ConvertTo-OnOff 'NotConfigured') -eq 'unknown' -and (ConvertTo-OnOff 'False') -eq 'off' -and (ConvertTo-OnOff $true) -eq 'on') ''
    if ($fails) { Write-Output "[FAIL] $fails firewall_state_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] firewall_state_check self-test: a profile off from any source or a stopped firewall service is CRITICAL, all-on names its sources, and profiles that could not be read are a raised gap (a deferral only for an access-denied standard user), never an all-clear.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$all = $Sources -contains 'all'
$reads = @()
if ($all -or $Sources -contains 'netsecurity') { $reads += , (Read-ViaNetSecurity) }
if ($all -or $Sources -contains 'com') { $reads += , (Read-ViaCom) }
$svc = $null
if ($all -or $Sources -contains 'service') { $svc = Read-Service }
$v = $null
try { $v = Get-FirewallVerdict -Reads $reads -Service $svc -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^fw=(off|on|gap|deferred),profiles=[A-Za-z+-]+$') {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'firewall_state_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.Hit) { Write-Marker -Name 'fw_hit' -Sev 'hit' }
if ($v.Gap) { Write-Marker -Name 'fw_gap' -Sev 'WARNING' }
if ($v.Deferred -gt 0) { Write-Marker -Name 'fw_deferred' -Sev ([string]$v.Deferred) }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('firewall_state_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
