# winrm_check.ps1 -- Section 10: is the WinRM service (remote PowerShell,
# T1021.006) running?
#
# Extracted from an inline line in both bats that read
#   $wmr=Get-Service WinRM -EA SilentlyContinue;if($wmr -and ...){...}else{'[OK] WinRM not running.'}
# so a query that FAILED (a broken service manager, a denied query, a cmdlet
# that would not load) left $wmr empty and printed "[OK] WinRM not running."
# having looked at nothing, and the dashboard re-ran the same query.
#
# THE RULE (pure, in Get-WinRmVerdict, pinned by -SelfTest):
#   * Get-Service -Name WinRM decides when it answers: Running, StartPending
#     or ContinuePending is the finding (wording kept, hit marker
#     dz_winrm_hit.txt that the bat already raises); Stopped is [OK] naming the
#     startup type; Paused, PausePending or StopPending is neither, so a raised
#     gap that names the state, never [OK];
#   * when Get-Service fails, the service manager itself is asked by name
#     (sc.exe query, EXIT CODE only -- its text is localized): 1060 is the
#     SCM saying the service does not exist -> [OK] not present; 5 is access
#     denied -> on a standard-user token [DEFERRED - ADMIN REQUIRED]
#     (dz_winrm_deferred.txt), elevated a raised gap; any other answer, or no
#     answer, is a raised "[WARNING] ... NOT performed" gap (dz_winrm_gap.txt)
#     that prints what each probe said;
#   * listeners on TCP 5985/5986 are context: printed as [INFO], never deciding.
# State line (dz_winrm_state.txt): winrm=<running|stopped|absent|gap|deferred>
#
# Usage:
#   powershell -File tools\winrm_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1]
#   powershell -File tools\winrm_check.ps1 -SelfTest   (queries nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # Only CI changes it: a name that does not exist drives the fallback path
    # through the real readers.
    [string]$ServiceName = 'WinRM',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_winrm_state.txt' }

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

# PURE. $Svc: @{ Status; StartType; Error } from Get-Service ($Status empty
# when it failed). $Sc: $null (not asked) or @{ Code; Error }, Code the
# sc.exe exit code (-1 when it could not be run). $Ports: @{ Listening
# (int[]); Error }. Returns @{ Lines; Hit; Gap; Deferred; State }.
function Get-WinRmVerdict {
    param($Svc, $Sc = $null, $Ports = $null, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $ctx = New-Object System.Collections.ArrayList
    if ($null -ne $Ports) {
        if ($Ports.Error) { [void]$ctx.Add(('[INFO] The WinRM listening ports (5985/5986) could not be read (' + (ConvertTo-PrintableText $Ports.Error) + ').')) }
        elseif (@($Ports.Listening).Count -gt 0) { [void]$ctx.Add(('[INFO] Listening on TCP ' + ((@($Ports.Listening) | Sort-Object -Unique) -join ', ') + ' (the WinRM ports): reachable from the network unless a firewall rule blocks it.')) }
        else { [void]$ctx.Add('[INFO] Nothing is listening on TCP 5985/5986 (the WinRM ports).') }
    }
    $done = { param($o, $hit, $gap, $def, $state) foreach ($c in $ctx) { [void]$o.Add($c) }; @{ Lines = @($o.ToArray()); Hit = $hit; Gap = $gap; Deferred = $def; State = $state } }
    $status = [string]$Svc.Status
    if ($status) {
        $st = if ([string]$Svc.StartType) { ', startup type ' + (ConvertTo-PrintableText ([string]$Svc.StartType)) } else { '' }
        if (@('Running', 'StartPending', 'ContinuePending') -contains $status) {
            # Starting or resuming is about to listen: the same exposure.
            [void]$out.Add('[WARNING] WinRM RUNNING (remote PowerShell enabled)')
            [void]$out.Add(('[INFO] Read by Get-Service: status ' + (ConvertTo-PrintableText $status) + $st + '.'))
            return (& $done $out $true $false 0 'winrm=running')
        }
        if ($status -eq 'Stopped') {
            [void]$out.Add(('[OK] WinRM not running (status Stopped' + $st + ').'))
            return (& $done $out $false $false 0 'winrm=stopped')
        }
        # Paused, PausePending, StopPending: neither running nor stopped. Not
        # an all-clear; the audit cannot tell which way it will settle.
        [void]$out.Add(('[WARNING] WinRM check NOT performed -- the WinRM service is in the transitional state ' + (ConvertTo-PrintableText $status) + $st + ', neither running nor stopped; re-run the audit to grade it (T1021.006).'))
        return (& $done $out $false $true 0 'winrm=gap')
    }
    $svcErr = ConvertTo-PrintableText ([string]$Svc.Error)
    $code = if ($null -ne $Sc) { [int]$Sc.Code } else { -1 }
    if ($code -eq 1060) {
        [void]$out.Add('[OK] WinRM service not present (the service manager reports it does not exist: sc.exe query exit 1060).')
        return (& $done $out $false $false 0 'winrm=absent')
    }
    $scSaid = if ($null -eq $Sc) { 'not asked' } elseif ($code -lt 0) { ('could not be run (' + (ConvertTo-PrintableText ([string]$Sc.Error)) + ')') } else { ('exit ' + $code) }
    $why = ('Get-Service: ' + $(if ($svcErr) { $svcErr } else { 'no answer' }) + '; sc.exe query: ' + $scSaid)
    if ($code -eq 5 -and -not $IsElevated) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] WinRM check: a standard-user token cannot query the WinRM service (' + $why + ') -- re-run as administrator to check it.'))
        return (& $done $out $false $false 1 'winrm=deferred')
    }
    [void]$out.Add(('[WARNING] WinRM check NOT performed -- the WinRM service could not be queried (' + $why + '), so a running remote-PowerShell service would go unseen (T1021.006).'))
    return (& $done $out $false $true 0 'winrm=gap')
}

function Read-Service {
    try {
        $s = Get-Service -Name $ServiceName -ErrorAction Stop
        $t = ''
        try { $t = [string]$s.StartType } catch {}
        return @{ Status = [string]$s.Status; StartType = $t; Error = '' }
    } catch { return @{ Status = ''; StartType = ''; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
}
function Read-Sc {
    try {
        $exe = Join-Path $env:SystemRoot 'System32\sc.exe'
        $null = & $exe query $ServiceName 2>&1
        return @{ Code = [int]$LASTEXITCODE; Error = '' }
    } catch { return @{ Code = -1; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
}
function Read-Ports {
    try {
        # Filter after the query: with -LocalPort 5985,5986 the cmdlet writes a
        # separate not-found error for EACH port with no listener, and under
        # -ErrorAction Stop the 5986 miss throws away the 5985 rows it found --
        # the default WinRM setup (HTTP on 5985, no HTTPS listener) would then
        # read "nothing is listening" under "WinRM RUNNING".
        $c = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { @(5985, 5986) -contains [int]$_.LocalPort })
        return @{ Listening = @($c | ForEach-Object { [int]$_.LocalPort }); Error = '' }
    } catch {
        # No listener on either port is reported by this cmdlet as an error.
        if ($_.FullyQualifiedErrorId -match 'CmdletizationQuery_NotFound') { return @{ Listening = @(); Error = '' } }
        return @{ Listening = @(); Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
    }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $none = @{ Listening = @(); Error = '' }
    $v = Get-WinRmVerdict -Svc @{ Status = 'Running'; StartType = 'Automatic'; Error = '' } -Ports @{ Listening = @(5985); Error = '' }
    $t = $v.Lines -join "`n"
    T 'running: the WARNING wording the bats always printed, a hit, and the listener said' ($v.Hit -and (-not $v.Gap) -and $v.State -eq 'winrm=running' -and $t -match '(?m)^\[WARNING\] WinRM RUNNING \(remote PowerShell enabled\)$' -and $t -match 'Listening on TCP 5985') $t
    $v = Get-WinRmVerdict -Svc @{ Status = 'Stopped'; StartType = 'Manual'; Error = '' } -Ports $none
    $t = $v.Lines -join "`n"
    T 'stopped: [OK] naming the status and startup type, nothing raised' ((-not $v.Hit) -and (-not $v.Gap) -and $v.State -eq 'winrm=stopped' -and $t -match '(?m)^\[OK\] WinRM not running \(status Stopped, startup type Manual\)\.$') $t
    $v = Get-WinRmVerdict -Svc @{ Status = ''; Error = 'InvalidOperationException: Cannot find any service with service name' } -Sc @{ Code = 1060; Error = '' }
    $t = $v.Lines -join "`n"
    T 'Get-Service failed and the service manager says the service does not exist (1060): [OK] not present' ((-not $v.Gap) -and $v.State -eq 'winrm=absent' -and $t -match '(?m)^\[OK\] WinRM service not present') $t
    $v = Get-WinRmVerdict -Svc @{ Status = ''; Error = 'InvalidOperationException: x' } -Sc @{ Code = 5; Error = '' } -IsElevated $false
    $t = $v.Lines -join "`n"
    T 'denied (5) on a standard-user token: a counted deferral, never a gap row and never an all-clear' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.State -eq 'winrm=deferred' -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] WinRM check' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[WARNING\]') $t
    $v = Get-WinRmVerdict -Svc @{ Status = ''; Error = 'InvalidOperationException: x' } -Sc @{ Code = 5; Error = '' } -IsElevated $true
    T 'denied (5) on an administrator token: a raised gap, the token does not explain it' ($v.Gap -and $v.Deferred -eq 0 -and $v.State -eq 'winrm=gap') ($v.Lines -join ' | ')
    $v = Get-WinRmVerdict -Svc @{ Status = ''; Error = 'Win32Exception: The RPC server is unavailable' } -Sc @{ Code = 1722; Error = '' }
    $t = $v.Lines -join "`n"
    T 'any other answer: a raised gap that prints what each probe said, never "[OK] WinRM not running"' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'winrm=gap' -and $t -match '(?m)^\[WARNING\] WinRM check NOT performed' -and $t -match 'sc\.exe query: exit 1722' -and $t -match 'RPC server is unavailable' -and $t -notmatch '\[OK\]') $t
    $v = Get-WinRmVerdict -Svc @{ Status = ''; Error = '' } -Sc $null
    T 'an empty Get-Service answer with no fallback is a gap, never "not running"' ($v.Gap -and $v.State -eq 'winrm=gap' -and ($v.Lines -join "`n") -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-WinRmVerdict -Svc @{ Status = ''; Error = 'x' } -Sc @{ Code = -1; Error = 'CommandNotFoundException: sc.exe' }
    T 'sc.exe could not be run: a gap that says so' ($v.Gap -and ($v.Lines -join "`n") -match 'could not be run \(CommandNotFoundException') ($v.Lines -join ' | ')
    $v = Get-WinRmVerdict -Svc @{ Status = 'StartPending'; StartType = 'AutomaticDelayedStart'; Error = '' } -Ports $none
    T 'starting (delayed auto-start right after boot): the RUNNING finding, never [OK]' ($v.Hit -and $v.State -eq 'winrm=running' -and ($v.Lines -join "`n") -match 'status StartPending' -and ($v.Lines -join "`n") -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-WinRmVerdict -Svc @{ Status = 'Paused'; StartType = 'Automatic'; Error = '' } -Ports $none
    T 'paused (transitional): a raised gap that names the state, never [OK] and never the RUNNING finding' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'winrm=gap' -and ($v.Lines -join "`n") -match 'transitional state Paused' -and ($v.Lines -join "`n") -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-WinRmVerdict -Svc @{ Status = 'Stopped'; StartType = 'Manual'; Error = '' } -Ports @{ Listening = @(5985); Error = '' }
    $t = $v.Lines -join "`n"
    T 'a listener on 5985 with the service stopped (http.sys shares the port): [OK] plus INFO, never a finding' ((-not $v.Hit) -and (-not $v.Gap) -and $v.State -eq 'winrm=stopped' -and $t -match '\[INFO\] Listening on TCP 5985' -and $t -notmatch '\[WARNING\]') $t
    $v = Get-WinRmVerdict -Svc @{ Status = 'Stopped'; StartType = 'Manual'; Error = '' } -Ports @{ Listening = @(); Error = 'CimException: denied' }
    T 'a port read that failed is said, and does not move the verdict' ($v.State -eq 'winrm=stopped' -and ($v.Lines -join "`n") -match 'ports \(5985/5986\) could not be read') ($v.Lines -join ' | ')
    $v = Get-WinRmVerdict -Svc @{ Status = ''; Error = ('bad' + [char]10 + '[OK] fine') } -Sc @{ Code = 1722; Error = '' }
    T 'a control character in an error cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails winrm_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] winrm_check self-test: a running WinRM is WARNING, stopped and not-present are OK and say how they were read, and a service that could not be queried is a raised gap (a deferral only for an access-denied standard user), never "[OK] WinRM not running".'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$svc = Read-Service
$sc = $null
if (-not $svc.Status) { $sc = Read-Sc }
$v = $null
try { $v = Get-WinRmVerdict -Svc $svc -Sc $sc -Ports (Read-Ports) -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^winrm=(running|stopped|absent|gap|deferred)$') {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'winrm_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.Hit) { Write-Marker -Name 'winrm_hit' -Sev 'hit' }
if ($v.Gap) { Write-Marker -Name 'winrm_gap' -Sev 'WARNING' }
if ($v.Deferred -gt 0) { Write-Marker -Name 'winrm_deferred' -Sev ([string]$v.Deferred) }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('winrm_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
