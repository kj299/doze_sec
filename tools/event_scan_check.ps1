# event_scan_check.ps1 -- three checks that read an event log and used to read
# a log they could not open as a log with nothing in it:
#   -Check AmsiBypass       Section 18: AMSI-bypass patterns in PowerShell
#                           Script Block events (4104), T1562.001.
#   -Check ServiceInstalls  Section 18: service installs (System 7045) from a
#                           staging path or through a script host, T1543.003.
#   -Check ScriptBlockList  Section 17: the listing of recent Script Block
#                           events that are not the audit's own.
#
# Each was an inline block built on
#   $evts = Get-WinEvent -FilterHashtable @{...} -EA SilentlyContinue
#   if ($evts) { ... } ... else { '[OK] No ...' }
# A log that could not be read left $evts empty and the block printed
# "[OK] No AMSI bypass patterns", "[OK] No suspicious service installations"
# or "[OK] No PS Script Block events found." having looked at nothing.
#
# THE RULE (pure, in Get-EventScanVerdict, pinned by -SelfTest):
#   * the log is opened by name first (the account_events_check idiom):
#     "no matching events" is an ANSWER; anything else is "did not answer";
#   * did not answer -> "[WARNING] ... NOT performed" and its own gap marker.
#     On a standard-user token, when access denied is the whole explanation,
#     it is [DEFERRED - ADMIN REQUIRED], counted, never a row: these are the
#     system's logs, not the user's;
#   * a finding keeps its wording; the audit's own script blocks and the
#     harness's own service installs (by MARKER, declared with a count) are
#     excluded exactly as before;
#   * [OK] says how many events were examined. For AMSI, when Script Block
#     Logging is off, it also says that the log then records little: an
#     empty log is weak evidence;
#   * an event whose text Windows could not render is counted and said --
#     it was not examined.
# Markers: dz_amsiev_hit / _gap / _deferred, dz_svc7045_hit / _gap /
# _deferred, dz_sblist_gap / _deferred; and dz_<name>_done, written last on
# every run -- the bat raises a "produced no verdict" row when it is absent.
#
# Usage:
#   powershell -File tools\event_scan_check.ps1 -Check <AmsiBypass|ServiceInstalls|ScriptBlockList> [-MarkerDir <dir>] [-Elevated 0|1] [-SblState <sbl=on|sbl=off|...>]
#   powershell -File tools\event_scan_check.ps1 -SelfTest   (reads no log)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [ValidateSet('AmsiBypass', 'ServiceInstalls', 'ScriptBlockList')]
    [string]$Check,
    [string]$MarkerDir = $env:TEMP,
    [int]$Elevated = -1,
    # Section 11's verdict on Script Block Logging, as the bat holds it.
    [string]$SblState = '',
    # Only CI changes this, to a log that does not exist, so the
    # could-not-read path runs through the real reader.
    [string]$LogName,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }

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
    # Event text and error messages go into the report as text: no control
    # characters, and capped.
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', ' ')
    if ($t.Length -gt 400) { $t = $t.Substring(0, 400) + '...' }
    return $t
}

$script:Checks = @{
    AmsiBypass      = @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Max = 500; What = 'AMSI-bypass check (Script Block events)'; Tech = 'T1562.001'; Miss = 'an AMSI bypass recorded there would go unseen' }
    ServiceInstalls = @{ Log = 'System'; Id = 7045; Max = 50; What = 'Service-install check (Event 7045)'; Tech = 'T1543.003'; Miss = 'a service installed from a staging path would go unseen' }
    ScriptBlockList = @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Max = 200; What = 'Script Block event listing'; Tech = 'T1059.001'; Miss = 'recent PowerShell activity is not shown' }
}
# The audit's own script blocks, by the path the event records.
$script:SelfPath = 'AuditPS_\d{8}_\d{6}\.ps1|doze_sec_noAdmin\.bat|doze_sec\.bat'
# ...and THIS file, by its exact path. It holds every pattern it searches
# for, and PowerShell logs a script as it starts -- before the query below
# runs. The inline block this replaced ran as AuditPS_<ts>.ps1 and was
# covered by the line above; a tool file is not, and without this the audit
# reports itself as an AMSI bypass on every machine that logs script blocks.
$script:OwnScript = [string]$PSCommandPath
$script:AmsiPatterns = @('AmsiUtils', 'amsiInitFailed', 'AmsiScanBuffer', 'SetProtectedState', 'Reflection.Assembly', 'System.Management.Automation.AmsiUtils', 'amsiscanbuffer', 'amsi.dll', 'Unmanaged.*amsi')
# The harness's own plants, by the MARKER in the image path -- never by a
# service name, which an attacker could borrow.
$script:OwnMarker = 'dz_selftest|dz_evil|dzsmoke|dz_probe'
$script:SuspInstall = '\\Temp\\|\\AppData\\|\\Users\\Public\\|\\Downloads\\|cmd\.exe|powershell|mshta|regsvr32'

# PURE. Turns raw records into what the verdict needs. $Records: @( @{ Time;
# Message; Path } ); Message is $null when Windows could not render it.
function Get-EventScan {
    param([string]$Check, $Records)
    $scan = @{ Total = 0; Own = 0; NoText = 0; Hits = (New-Object System.Collections.ArrayList); Shown = (New-Object System.Collections.ArrayList) }
    foreach ($r in @($Records)) {
        if ($null -eq $r) { continue }
        $scan.Total++
        $msg = $r.Message
        if ($Check -eq 'ServiceInstalls') {
            if ($null -eq $msg -or -not [string]$msg) { $scan.NoText++; continue }
            if ([string]$msg -match $script:OwnMarker) { $scan.Own++; continue }
            if ([string]$msg -match $script:SuspInstall) { [void]$scan.Hits.Add(('[' + [string]$r.Time + '] ' + (ConvertTo-PrintableText (([string]$msg) -replace '[\r\n]+', ' ')))) }
            continue
        }
        if ([string]$r.Path -match $script:SelfPath -or ($script:OwnScript -and [string]$r.Path -ieq $script:OwnScript)) { $scan.Own++; continue }
        if ($Check -eq 'ScriptBlockList') { [void]$scan.Shown.Add($r); continue }
        if ($null -eq $msg -or -not [string]$msg) { $scan.NoText++; continue }
        foreach ($p in $script:AmsiPatterns) {
            if ([string]$msg -match $p) { [void]$scan.Hits.Add(('[' + [string]$r.Time + '] Pattern: ' + $p)); break }
        }
    }
    return $scan
}

# PURE. $Read: @{ Error; Denied } from the reader ('' = the log answered).
# Returns @{ Lines; Hit; Gap; Deferred }.
function Get-EventScanVerdict {
    param([string]$Check, $Read, $Scan, [bool]$IsElevated = $true, [string]$Sbl = '')
    $c = $script:Checks[$Check]
    $out = New-Object System.Collections.ArrayList
    if ($null -eq $Read -or [string]$Read.Error -or $null -eq $Scan) {
        $why = if ($null -eq $Read) { 'no result' } elseif ([string]$Read.Error) { ConvertTo-PrintableText ([string]$Read.Error) } else { 'no result' }
        if ((-not $IsElevated) -and $null -ne $Read -and $Read.Denied) {
            [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] ' + $c.What + ': the ' + $c.Log + ' log is not readable from a standard-user token (' + $why + ') -- re-run as administrator to check it.'))
            return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 1 }
        }
        [void]$out.Add(('[WARNING] ' + $c.What + ' NOT performed -- the ' + $c.Log + ' log could not be read (' + $why + '), so ' + $c.Miss + ' (' + $c.Tech + ').'))
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0 }
    }
    $scope = ([string]$Scan.Total + ' event(s) read from the ' + $c.Log + ' log (newest ' + [string]$c.Max + ' at most)')
    $noText = if ([int]$Scan.NoText -gt 0) { ('[INFO] ' + [string]$Scan.NoText + ' event(s) had no text Windows could render, so they were NOT examined.') } else { '' }
    if ($Check -eq 'ScriptBlockList') {
        $shown = @($Scan.Shown)
        if ([int]$Scan.Total -eq 0) { [void]$out.Add('[OK] No PS Script Block events found.') }
        elseif ($shown.Count -eq 0) { [void]$out.Add('[OK] No external PS Script Block events (audit-self events filtered).') }
        else {
            foreach ($r in @($shown | Select-Object -First 30)) {
                [void]$out.Add(('TimeCreated: ' + [string]$r.Time))
                foreach ($ln in @(([string]$r.Message) -split "`n" | Where-Object { $_ -match '^(ScriptBlock ID:|Path:)' })) { [void]$out.Add(('  ' + (ConvertTo-PrintableText $ln.Trim()))) }
                [void]$out.Add('')
            }
        }
        [void]$out.Add(('[INFO] ' + $scope + '; ' + [string]$Scan.Own + ' were the audit''s own and are not listed.'))
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 0 }
    }
    $hits = @($Scan.Hits | Where-Object { [string]$_ })
    if ($Check -eq 'ServiceInstalls' -and [int]$Scan.Own -gt 0) {
        [void]$out.Add(('[INFO] ' + [string]$Scan.Own + ' service-install event(s) were doze_sec''s own test harness (dz_selftest/dzsmoke/dz_probe) and were excluded. Cleanup removes the service; it cannot remove the Security log record of installing it.'))
    }
    if ($hits.Count -gt 0) {
        [void]$out.Add($(if ($Check -eq 'AmsiBypass') { '[WARNING][T1562.001] AMSI bypass attempts detected in PS logs:' } else { '[WARNING][T1543.003] Suspicious service installations found:' }))
        foreach ($h in @($hits | Select-Object -First 10)) { [void]$out.Add(('  ' + $h)) }
        if ($hits.Count -gt 10) { [void]$out.Add(('[INFO] ' + ($hits.Count - 10) + ' more not listed (' + $hits.Count + ' in all).')) }
    } elseif ($Check -eq 'AmsiBypass') {
        [void]$out.Add('[OK] No AMSI bypass patterns in recent PowerShell Script Block logs (audit-self events filtered).')
    } else {
        [void]$out.Add('[OK] No suspicious service installations in recent Event 7045 logs.')
    }
    [void]$out.Add(('[INFO] ' + $scope + $(if ($Check -eq 'AmsiBypass') { ('; ' + [string]$Scan.Own + ' were the audit''s own and were not examined.') } else { '.' })))
    if ($noText) { [void]$out.Add($noText) }
    if ($Check -eq 'AmsiBypass' -and $hits.Count -eq 0 -and $Sbl -ne 'sbl=on') {
        [void]$out.Add('[INFO] Script Block Logging is not switched on (Section 11), so PowerShell records only the blocks it flags by itself. Finding nothing here is weak evidence that nothing ran.')
    }
    return @{ Lines = @($out.ToArray()); Hit = ($hits.Count -gt 0); Gap = $false; Deferred = 0 }
}

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

# Live. Opens the log by name first: a log this token may not read, or one
# that does not exist, must be "could not be read", never "no matching
# events". Returns @{ Error; Denied; Records }.
function Read-Events {
    param([string]$Log, [int]$Id, [int]$Max)
    try { $null = Get-WinEvent -LogName $Log -MaxEvents 1 -ErrorAction Stop }
    catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { return @{ Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_); Records = @() } }
    }
    $evts = @()
    try { $evts = @(Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Id } -MaxEvents $Max -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { return @{ Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = (Test-Denied $_); Records = @() } }
    }
    $recs = New-Object System.Collections.ArrayList
    foreach ($e in $evts) {
        $msg = $null; try { $msg = $e.Message } catch { $msg = $null }
        $path = ''; try { if ($e.Properties.Count -ge 5) { $path = [string]$e.Properties[4].Value } } catch { $path = '' }
        $time = ''; try { $time = $e.TimeCreated.ToString('s') } catch { $time = '' }
        [void]$recs.Add(@{ Time = $time; Message = $msg; Path = $path })
    }
    return @{ Error = ''; Denied = $false; Records = @($recs.ToArray()) }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function V { param([string]$Check, $Records, $Read = @{ Error = ''; Denied = $false }, [bool]$Adm = $true, [string]$Sbl = 'sbl=on')
        $scan = if ([string]$Read.Error) { $null } else { Get-EventScan -Check $Check -Records $Records }
        return (Get-EventScanVerdict -Check $Check -Read $Read -Scan $scan -IsElevated $Adm -Sbl $Sbl)
    }
    $own = @{ Time = '2026-11-12T10:00:00'; Message = 'Creating Scriptblock text: [Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils'')'; Path = 'C:\Users\alice\AppData\Local\Temp\AuditPS_20261112_100000.ps1' }
    $bad = @{ Time = '2026-11-12T10:01:00'; Message = 'Creating Scriptblock text: $a=[Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils'');$a.GetField(''amsiInitFailed'',''NonPublic,Static'').SetValue($null,$true)'; Path = '' }
    $plain = @{ Time = '2026-11-12T10:02:00'; Message = "Creating Scriptblock text (1 of 1):`nGet-Date`nScriptBlock ID: 11111111-2222`nPath: C:\Scripts\backup.ps1"; Path = 'C:\Scripts\backup.ps1' }

    $v = V 'AmsiBypass' @($plain); $t = $v.Lines -join "`n"
    T 'AMSI, a readable log with nothing in it: the [OK] wording the bats always printed, and how many events were read' ((-not ($v.Hit -or $v.Gap)) -and $t -match '(?m)^\[OK\] No AMSI bypass patterns in recent PowerShell Script Block logs \(audit-self events filtered\)\.$' -and $t -match '\[INFO\] 1 event\(s\) read') $t
    $v = V 'AmsiBypass' @($plain, $bad); $t = $v.Lines -join "`n"
    T 'AMSI, a bypass in the log: the WARNING wording the harness greps, and a hit' ($v.Hit -and $t -match '(?m)^\[WARNING\]\[T1562\.001\] AMSI bypass attempts detected in PS logs:$' -and $t -match 'Pattern: AmsiUtils') $t
    $v = V 'AmsiBypass' @($own); $t = $v.Lines -join "`n"
    T 'AMSI, the audit''s own script block is not a bypass (it names the patterns it searches for)' ((-not $v.Hit) -and $t -match '1 were the audit''s own') $t
    $me = @{ Time = '2026-11-12T10:03:00'; Message = $bad.Message; Path = [string]$PSCommandPath }
    $v = V 'AmsiBypass' @($me); $t = $v.Lines -join "`n"
    T 'AMSI, this tool''s own script block (it holds every pattern, and is logged as it starts) is the audit''s own, never a bypass' ((-not $v.Hit) -and $t -match '1 were the audit''s own') $t
    $v = V 'AmsiBypass' @(@{ Time = 't'; Message = $bad.Message; Path = 'C:\Users\Public\event_scan_check.ps1' })
    T 'AMSI, a script with this tool''s NAME somewhere else is still the finding (the exact path is the exclusion, not the name)' ($v.Hit) ($v.Lines -join ' | ')
    $v = V 'AmsiBypass' @() @{ Error = 'EventLogNotFoundException: There is not an event log on the localhost computer that matches "X"'; Denied = $false }; $t = $v.Lines -join "`n"
    T 'AMSI, the log could not be read: a raised gap, never "[OK] No AMSI bypass patterns"' ($v.Gap -and (-not $v.Hit) -and $t -match '(?m)^\[WARNING\] AMSI-bypass check \(Script Block events\) NOT performed -- ' -and $t -notmatch '\[OK\]') $t
    $v = V 'AmsiBypass' @() @{ Error = 'UnauthorizedAccessException: denied'; Denied = $true } $false; $t = $v.Lines -join "`n"
    T 'a standard-user token denied the log: a counted deferral, never a row and never [OK]' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] AMSI-bypass check' -and $t -notmatch '\[OK\]|\[WARNING\]') $t
    $v = V 'AmsiBypass' @() @{ Error = 'EventLogException: The RPC server is unavailable'; Denied = $false } $false
    T 'a standard-user token and a failure that is NOT access denied: a raised gap (the token does not explain it)' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = V 'AmsiBypass' @() @{ Error = 'UnauthorizedAccessException: denied'; Denied = $true } $true
    T 'an administrator denied the log: a raised gap, not a deferral' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = V 'AmsiBypass' @($plain) @{ Error = ''; Denied = $false } $true 'sbl=off'; $t = $v.Lines -join "`n"
    T 'AMSI clean with Script Block Logging off: [OK], and the reader is told the log then records little' ((-not $v.Gap) -and $t -match 'Finding nothing here is weak evidence') $t
    $v = V 'AmsiBypass' @($plain, $bad) @{ Error = ''; Denied = $false } $true 'sbl=off'
    T 'AMSI hit with logging off: the finding stands, without the weak-evidence line' ($v.Hit -and ($v.Lines -join ' ') -notmatch 'weak evidence') ($v.Lines -join ' | ')
    $v = V 'AmsiBypass' @(@{ Time = 't'; Message = $null; Path = '' }); $t = $v.Lines -join "`n"
    T 'an event Windows could not render is counted and said, never silently passed' ($t -match '\[INFO\] 1 event\(s\) had no text Windows could render, so they were NOT examined') $t
    $v = Get-EventScanVerdict -Check 'AmsiBypass' -Read @{ Error = ''; Denied = $false } -Scan $null
    T 'no scan result at all is a gap, never an [OK]' ($v.Gap -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')

    $i1 = @{ Time = '2026-11-12T09:00:00'; Message = "A service was installed in the system.`r`nService Name:  Updater`r`nService File Name:  C:\Users\Public\upd.exe`r`nService Type:  user mode service"; Path = '' }
    $i2 = @{ Time = '2026-11-12T09:01:00'; Message = "A service was installed in the system.`r`nService Name:  Print Spooler Helper`r`nService File Name:  C:\Windows\System32\spoolhelper.exe"; Path = '' }
    $i3 = @{ Time = '2026-11-12T09:02:00'; Message = "A service was installed in the system.`r`nService Name:  SentinelAgent`r`nService File Name:  cmd.exe /c rem dz_selftest"; Path = '' }
    $i4 = @{ Time = '2026-11-12T09:03:00'; Message = "A service was installed in the system.`r`nService Name:  SentinelAgent`r`nService File Name:  cmd.exe /c C:\ProgramData\x.bat"; Path = '' }
    $v = V 'ServiceInstalls' @($i2); $t = $v.Lines -join "`n"
    T '7045, an ordinary install from System32: the [OK] wording the bats always printed' ((-not ($v.Hit -or $v.Gap)) -and $t -match '(?m)^\[OK\] No suspicious service installations in recent Event 7045 logs\.$') $t
    $v = V 'ServiceInstalls' @($i1, $i2); $t = $v.Lines -join "`n"
    T '7045, a service installed from C:\Users\Public: the WARNING wording, one line for the record, and a hit' ($v.Hit -and $t -match '(?m)^\[WARNING\]\[T1543\.003\] Suspicious service installations found:$' -and $t -match 'C:\\Users\\Public\\upd\.exe' -and $t -notmatch 'spoolhelper') $t
    $v = V 'ServiceInstalls' @($i3); $t = $v.Lines -join "`n"
    T '7045, the harness''s own plant is excluded BY MARKER and declared with a count' ((-not $v.Hit) -and $t -match '(?m)^\[INFO\] 1 service-install event\(s\) were doze_sec''s own test harness') $t
    $v = V 'ServiceInstalls' @($i4)
    T '7045, the same service NAME without the marker is the finding (a name is not an exclusion)' ($v.Hit) ($v.Lines -join ' | ')
    $v = V 'ServiceInstalls' @() @{ Error = 'EventLogException: The handle is invalid'; Denied = $false }; $t = $v.Lines -join "`n"
    T '7045, the System log could not be read: a raised gap, never "[OK] No suspicious service installations"' ($v.Gap -and $t -match '(?m)^\[WARNING\] Service-install check \(Event 7045\) NOT performed -- ' -and $t -notmatch '\[OK\]') $t
    $v = V 'ServiceInstalls' @(@{ Time = 't'; Message = ''; Path = '' })
    T '7045, a record with no text is said as not examined' (($v.Lines -join ' ') -match 'NOT examined') ($v.Lines -join ' | ')

    $v = V 'ScriptBlockList' @(); $t = $v.Lines -join "`n"
    T 'listing, a readable log with no 4104 events: the [OK] line the bats printed' ($t -match '(?m)^\[OK\] No PS Script Block events found\.$' -and -not $v.Gap) $t
    $v = V 'ScriptBlockList' @($own); $t = $v.Lines -join "`n"
    T 'listing, only the audit''s own events: the filtered [OK] line' ($t -match '(?m)^\[OK\] No external PS Script Block events \(audit-self events filtered\)\.$') $t
    $v = V 'ScriptBlockList' @($own, $plain); $t = $v.Lines -join "`n"
    T 'listing, an external script block is listed with its ID and path, and no [OK]' ($t -match '(?m)^TimeCreated: 2026-11-12T10:02:00$' -and $t -match '(?m)^  Path: C:\\Scripts\\backup\.ps1$' -and $t -notmatch '\[OK\]') $t
    $v = V 'ScriptBlockList' @() @{ Error = 'EventLogException: x'; Denied = $false }; $t = $v.Lines -join "`n"
    T 'listing, the log could not be read: a raised gap, never "[OK] No PS Script Block events found."' ($v.Gap -and $t -match '(?m)^\[WARNING\] Script Block event listing NOT performed -- ' -and $t -notmatch '\[OK\]') $t
    $v = V 'ServiceInstalls' @() @{ Error = ('bad' + [char]10 + '[OK] fine'); Denied = $false }
    T 'a control character in an error message cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails event_scan_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] event_scan_check self-test: a finding keeps its wording; a log that answered with nothing is [OK] and says how much it read; and a log that could not be read is a raised gap (or a deferral for an access-denied standard user), never an all-clear.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if (-not $Check) { 'event_scan_check: -Check is required (AmsiBypass, ServiceInstalls or ScriptBlockList).'; exit 1 }
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$c = $script:Checks[$Check]
if ($LogName) { $c.Log = $LogName }
$v = $null
try {
    $read = Read-Events -Log $c.Log -Id $c.Id -Max $c.Max
    $scan = if ([string]$read.Error) { $null } else { Get-EventScan -Check $Check -Records $read.Records }
    $v = Get-EventScanVerdict -Check $Check -Read $read -Scan $scan -IsElevated ($Elevated -eq 1) -Sbl $SblState
} catch { $v = $null }
if ($null -eq $v -or @($v.Lines).Count -eq 0) {
    # No verdict is never a verdict: say so and raise it as this check's gap.
    ('[WARNING] ' + $c.What + ' NOT performed -- the check failed before it produced a verdict (' + $c.Tech + ').')
    $v = @{ Lines = @(); Hit = $false; Gap = $true; Deferred = 0 }
}
foreach ($l in $v.Lines) { $l }
# Marker names are written out, not built: lint_unraised_findings reads them.
if ($Check -eq 'AmsiBypass') {
    if ($v.Hit) { Write-Marker -Name 'amsiev_hit' -Sev 'hit' }
    if ($v.Gap) { Write-Marker -Name 'amsiev_gap' -Sev 'WARNING' }
    if ($v.Deferred -gt 0) { Write-Marker -Name 'amsiev_deferred' -Sev ([string]$v.Deferred) }
    Write-Marker -Name 'amsiev_done' -Sev 'done'
} elseif ($Check -eq 'ServiceInstalls') {
    if ($v.Hit) { Write-Marker -Name 'svc7045_hit' -Sev 'hit' }
    if ($v.Gap) { Write-Marker -Name 'svc7045_gap' -Sev 'WARNING' }
    if ($v.Deferred -gt 0) { Write-Marker -Name 'svc7045_deferred' -Sev ([string]$v.Deferred) }
    Write-Marker -Name 'svc7045_done' -Sev 'done'
} else {
    if ($v.Gap) { Write-Marker -Name 'sblist_gap' -Sev 'WARNING' }
    if ($v.Deferred -gt 0) { Write-Marker -Name 'sblist_deferred' -Sev ([string]$v.Deferred) }
    Write-Marker -Name 'sblist_done' -Sev 'done'
}
exit 0
