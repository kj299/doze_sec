# account_events_check.ps1 -- Section 16: new local accounts (Security Event
# 4720, T1136.001) and accounts added to a privileged group (Event 4732, T1098).
#
# Extracted from two inline lines that lived in both bats. They read the
# Security log with -EA SilentlyContinue, so a read that FAILED returned
# nothing and printed "[OK] No new local account creation events (4720)."
# having checked nothing -- the false all-clear the log-clear check had, in
# the check that answers "did someone make an account on my PC". The
# dashboard tiles then re-read the log the same way and printed PASS.
#
# THE RULE (pure, in Get-AccountEventVerdict, pinned by -SelfTest):
#   * events found        -> WARNING, the wording the bats always printed, and
#                            the hit marker the bat already raises
#                            (dz_ev4720_hit.txt / dz_ev4732_hit.txt);
#   * no events           -> [OK], the same wording as before;
#   * the log could not be read:
#       - access denied on a standard-user token -> [DEFERRED - ADMIN
#                            REQUIRED], counted through dz_acctev_deferred.txt,
#                            never a ledger row;
#       - any other failure, or an administrator token -> a raised gap:
#                            "[WARNING] ... NOT performed", one marker per
#                            check (dz_acctev4720_gap / dz_acctev4732_gap),
#                            never the hit marker.
# One state line for the dashboard (a tile that re-measures is a second
# opinion), a comma never a pipe (the bat pastes it into an echo):
#   e4720=<count|gap|deferred>,e4732=<count|gap|deferred>
#
# Usage:
#   powershell -File tools\account_events_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1] [-LogName <log>]
#   powershell -File tools\account_events_check.ps1 -SelfTest   (reads no log)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # The log to read. Only CI changes it, to a log that does not exist, so the
    # could-not-read path runs through the real reader.
    [string]$LogName = 'Security',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_acctev_state.txt' }

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

# The two checks, in the order the report prints them.
$script:AcctChecks = @(
    @{ Id = 4720; Key = 'e4720'; Hit = 'ev4720_hit'; Gap = 'acctev4720_gap'; What = 'New-account check (Event 4720)'
       Found = '[WARNING] New local account(s) created: {0} event(s) (T1136.001) -- review the names listed above.'
       None = '[OK] No new local account creation events (4720).' },
    @{ Id = 4732; Key = 'e4732'; Hit = 'ev4732_hit'; Gap = 'acctev4732_gap'; What = 'Privileged-group check (Event 4732)'
       Found = '[WARNING] Account(s) added to a privileged group: {0} event(s) (T1098) -- review the names listed above.'
       None = '[OK] No unexpected additions to Administrators (4732).' }
)

# PURE. $Results maps an event id to @{ Count; Error; Denied }: Error is ''
# when the log was read, else why it could not be; Denied says the reason was
# access denied. Only a DENIED read on a standard-user token is a deferral --
# the token explains it. Any other failure (the EventLog service down, a
# corrupt log) is a raised gap on either token: the token does not explain
# it, and calling it a deferral would state a cause the tool never observed.
# Returns @{ Lines; Hits; Gaps; Deferred; State }, Hits and Gaps being the
# marker names to write (one gap marker per check, so each raises under its
# own technique).
function Get-AccountEventVerdict {
    param([hashtable]$Results, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $hits = New-Object System.Collections.ArrayList
    $gaps = New-Object System.Collections.ArrayList; $deferred = 0
    $state = New-Object System.Collections.ArrayList
    foreach ($c in $script:AcctChecks) {
        $r = $Results[$c.Id]
        if ($null -eq $r) { $r = @{ Count = 0; Error = 'no result was produced' } }
        if ($r.Error) {
            if ($IsElevated -or -not $r.Denied) {
                [void]$gaps.Add($c.Gap)
                [void]$state.Add($c.Key + '=gap')
                [void]$out.Add(('[WARNING] ' + $c.What + ' NOT performed -- the Security log could not be read (' + (ConvertTo-PrintableText $r.Error) + '), so such an event would go unseen.'))
            } else {
                $deferred++
                [void]$state.Add($c.Key + '=deferred')
                [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] ' + $c.What + ': a standard-user token cannot read the Security log -- re-run as administrator to check it.'))
            }
        } elseif ([int]$r.Count -gt 0) {
            [void]$hits.Add($c.Hit)
            [void]$state.Add($c.Key + '=' + [int]$r.Count)
            [void]$out.Add(($c.Found -f [int]$r.Count))
        } else {
            [void]$state.Add($c.Key + '=0')
            [void]$out.Add($c.None)
        }
    }
    return @{ Lines = @($out.ToArray()); Hits = @($hits.ToArray()); Gaps = @($gaps.ToArray()); Gap = ($gaps.Count -gt 0); Deferred = $deferred; State = (@($state.ToArray()) -join ',') }
}

# Live: how many of one event the Security log holds (up to 5, as before), and
# why it could not be read. The log is opened first by name: a log this token
# may not read must be "could not be read", never "no matching events".
function Test-Denied {
    # Access denied anywhere in the exception chain.
    param($Err)
    $x = $Err.Exception
    while ($x) {
        if ($x -is [System.UnauthorizedAccessException]) { return $true }
        $x = $x.InnerException
    }
    return $false
}
function Read-EventCount {
    param([int]$Id)
    try { $null = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop }
    catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { return @{ Count = 0; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_) } }
    }
    try {
        $e = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Id } -MaxEvents 5 -ErrorAction Stop)
        return @{ Count = $e.Count; Error = ''; Denied = $false }
    } catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { return @{ Count = 0; Error = ''; Denied = $false } }
        return @{ Count = 0; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_) }
    }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $v = Get-AccountEventVerdict -Results @{ 4720 = @{ Count = 0; Error = '' }; 4732 = @{ Count = 0; Error = '' } }
    $t = $v.Lines -join "`n"
    T 'no events: both [OK], nothing raised, the old wording kept' ($v.Hits.Count -eq 0 -and -not $v.Gap -and $v.State -eq 'e4720=0,e4732=0' -and $t -match '(?m)^\[OK\] No new local account creation events \(4720\)\.$' -and $t -match '(?m)^\[OK\] No unexpected additions to Administrators \(4732\)\.$') $t
    $v = Get-AccountEventVerdict -Results @{ 4720 = @{ Count = 2; Error = '' }; 4732 = @{ Count = 1; Error = '' } }
    $t = $v.Lines -join "`n"
    T 'events found: both WARNING with their counts, and both hit markers' (($v.Hits -join ',') -eq 'ev4720_hit,ev4732_hit' -and $v.State -eq 'e4720=2,e4732=1' -and $t -match '(?m)^\[WARNING\] New local account\(s\) created: 2 event\(s\) \(T1136\.001\)' -and $t -match '(?m)^\[WARNING\] Account\(s\) added to a privileged group: 1 event\(s\) \(T1098\)') $t
    $v = Get-AccountEventVerdict -Results @{ 4720 = @{ Count = 0; Error = 'EventLogException: access denied' }; 4732 = @{ Count = 0; Error = 'EventLogException: access denied' } } -IsElevated $true
    $t = $v.Lines -join "`n"
    T 'an administrator who cannot read the Security log gets a raised gap, never "[OK] No new local account"' ($v.Gap -and $v.Hits.Count -eq 0 -and $v.State -eq 'e4720=gap,e4732=gap' -and $t -match '(?m)^\[WARNING\] New-account check \(Event 4720\) NOT performed' -and $t -notmatch '\[OK\]') $t
    $v = Get-AccountEventVerdict -Results @{ 4720 = @{ Count = 0; Error = 'UnauthorizedAccessException: denied'; Denied = $true }; 4732 = @{ Count = 0; Error = 'UnauthorizedAccessException: denied'; Denied = $true } } -IsElevated $false
    $t = $v.Lines -join "`n"
    T 'a standard-user token is a deferral, never a gap row and never an all-clear' ((-not $v.Gap) -and $v.Deferred -eq 2 -and $v.State -eq 'e4720=deferred,e4732=deferred' -and $t -match '\[DEFERRED - ADMIN REQUIRED\] New-account check' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[WARNING\]') $t
    $v = Get-AccountEventVerdict -Results @{ 4720 = @{ Count = 0; Error = 'EventLogException: The RPC server is unavailable'; Denied = $false }; 4732 = @{ Count = 0; Error = ''; Denied = $false } } -IsElevated $false
    T 'on a standard-user token a failure that is NOT access denied is a raised gap, not a deferral (the token does not explain it)' ($v.Gap -and $v.Deferred -eq 0 -and (($v.Gaps -join ',') -eq 'acctev4720_gap') -and $v.State -eq 'e4720=gap,e4732=0') ($v.Lines -join ' | ')
    $v = Get-AccountEventVerdict -Results @{ 4720 = @{ Count = 3; Error = '' }; 4732 = @{ Count = 0; Error = 'x' } } -IsElevated $true
    T 'one log readable and one not: the finding raised AND the gap raised, each under its own marker' (($v.Hits -join ',') -eq 'ev4720_hit' -and (($v.Gaps -join ',') -eq 'acctev4732_gap') -and $v.State -eq 'e4720=3,e4732=gap') ($v.Lines -join ' | ')
    $v = Get-AccountEventVerdict -Results @{ 4720 = @{ Count = 0; Error = '' } } -IsElevated $true
    T 'a check that produced no result is a gap, never an [OK]' ($v.Gap -and $v.State -eq 'e4720=0,e4732=gap') ($v.Lines -join ' | ')
    $v = Get-AccountEventVerdict -Results @{ 4720 = @{ Count = 0; Error = ('bad' + [char]10 + '[OK] fine') }; 4732 = @{ Count = 0; Error = '' } } -IsElevated $true
    T 'a control character in an error message cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails account_events_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] account_events_check self-test: events found are WARNING, none is OK, and a Security log that could not be read is a raised gap (administrator) or a deferral (standard user), never an all-clear.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$res = @{}
foreach ($c in $script:AcctChecks) { $res[$c.Id] = Read-EventCount -Id $c.Id }
$v = $null
try { $v = Get-AccountEventVerdict -Results $res -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^e4720=(\d+|gap|deferred),e4732=(\d+|gap|deferred)$') {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'account_events_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
foreach ($h in $v.Hits) { Write-Marker -Name $h -Sev 'hit' }
# Named literally, one per check, so each raises under its own technique.
if ($v.Gaps -contains 'acctev4720_gap') { Write-Marker -Name 'acctev4720_gap' -Sev 'WARNING' }
if ($v.Gaps -contains 'acctev4732_gap') { Write-Marker -Name 'acctev4732_gap' -Sev 'WARNING' }
if ($v.Deferred -gt 0) { Write-Marker -Name 'acctev_deferred' -Sev ([string]$v.Deferred) }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('account_events_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
