# log_clear_check.ps1 -- Section 16: was an event log cleared (Security 1102,
# System 104), and WHEN in this machine's life?
#
# Extracted from two lines that lived inline in both bats, after a real run
# graded a cloud image's build step as an intrusion. WIN11-02 (2026-10-24, the
# owner's own VM template) read "[CRITICAL] Security event log was CLEARED ...
# Treat as active compromise", and the dashboard told its owner to isolate the
# machine and image the drive. The records said otherwise: the 1102 and three
# 104 records (System, Application and Setup cleared within 20 ms) were
# written by the built-in Administrator under the computer name
# WIN-EIH5CPD9P56 -- the random name Windows Setup gives a fresh install --
# before the machine was renamed WIN11-02 by its cloud agent (cloudbase-init).
# An image being prepared clears every log before it is handed out; an
# intruder covering tracks does not rename the computer afterwards.
#
# THE RULE (pure, in Get-LogClearVerdict, pinned by -SelfTest). Every event
# record carries the name of the computer that wrote it. So:
#   * any 1102 written under THIS computer's name (its NetBIOS name or the
#     first label of its DNS host name, case-insensitive) is CRITICAL, as
#     before: the log was cleared during this machine's own life;
#   * when EVERY 1102 was written under another name, the clear predates the
#     machine's current identity -- the shape of image preparation -- and it
#     is a WARNING that names both names and says what to do if the image is
#     not one the reader built or trusts. Still a counted finding, never
#     silenced: an attacker who cleared the log and then renamed the PC would
#     read here too, and the line says so by telling the reader to treat it as
#     a compromise when they did not build the image.
#   * a Security log that cannot be read is a raised gap for an administrator
#     and a DEFERRAL on a standard-user token (which can never read it) --
#     never "has not been cleared". The dashboard tile used to re-read the log
#     itself, and on doze_sec_noAdmin.bat that failed read printed PASS
#     "Security event log has not been cleared" having checked nothing.
#
# Output goes to the report; markers: dz_logclear.txt (severity of the
# Security clear), dz_logclear104.txt (WARNING when the System log records a
# clear), dz_logclear_gap.txt, dz_logclear_deferred.txt (a count). One state
# line for the dashboard (a tile that re-measures is a second opinion):
#   sec=<critical|prep|none|gap|deferred>,sys=<cleared|none|gap>
# (a comma, never a pipe: the bat pastes it into an echo, where | is a pipe)
#
# Usage:
#   powershell -File tools\log_clear_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1]
#   powershell -File tools\log_clear_check.ps1 -SelfTest   (reads no log)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_logclear_state.txt' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintableText {
    # A computer or account name goes into the report as text: no control
    # characters, so nothing a record carries can break a line.
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

function Get-HostLabel {
    # PURE. The first label of a host name, upper-cased: WIN11-02.contoso.local
    # and WIN11-02 are one computer.
    param([string]$Name)
    $n = ([string]$Name).Trim()
    $i = $n.IndexOf('.')
    if ($i -ge 0) { $n = $n.Substring(0, $i) }
    return $n.ToUpperInvariant()
}

function Format-When {
    param($Time)
    if ($null -eq $Time) { return 'an unknown time' }
    return ([datetime]$Time).ToString('MM/dd/yyyy HH:mm:ss')
}

# PURE. Records are plain objects: @{ Time; Machine; Account; Channel }.
#   CurrentNames  this computer's names (NetBIOS, DNS host name)
#   SecError      '' when the Security log was read, else why it could not be
#   SysError      the same for the System log
#   IsElevated    the token this ran under
# Returns @{ Lines; SecSev; SysSev; GapSev; Deferred; State }.
function Get-LogClearVerdict {
    param($Sec1102 = @(), $Sys104 = @(), [string[]]$CurrentNames = @(), [string]$SecError = '', [string]$SysError = '', [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $mine = @{}
    foreach ($c in @($CurrentNames)) { $l = Get-HostLabel $c; if ($l) { $mine[$l] = $true } }
    $secSev = 'OK'; $sysSev = 'OK'; $gapSev = 'OK'; $deferred = 0
    $secState = 'none'; $sysState = 'none'
    $cur = (@($CurrentNames) | Where-Object { $_ } | Select-Object -First 1)
    $prepNames = @()
    if ($SecError) {
        if ($IsElevated) {
            $gapSev = 'WARNING'; $secState = 'gap'
            [void]$out.Add(('[WARNING] Event-log clear check NOT performed -- the Security log could not be read (' + (ConvertTo-PrintableText $SecError) + '), so a cleared log would go unseen (T1070.001).'))
        } else {
            $deferred = 1; $secState = 'deferred'
            [void]$out.Add('[DEFERRED - ADMIN REQUIRED] Security log clears (Event 1102): a standard-user token cannot read the Security log -- re-run as administrator to check it.')
        }
    } else {
        $sec = @($Sec1102 | Where-Object { $_ } | Sort-Object { $_.Time } -Descending)
        if ($sec.Count -eq 0) {
            [void]$out.Add('[OK] Security event log has not been cleared.')
        } else {
            $own = @($sec | Where-Object { $mine.ContainsKey((Get-HostLabel $_.Machine)) })
            if ($own.Count -gt 0) {
                $e = $own[0]
                $secSev = 'CRITICAL'; $secState = 'critical'
                [void]$out.Add(('[CRITICAL] Security event log was CLEARED at ' + (Format-When $e.Time) + ' by ' + (ConvertTo-PrintableText $e.Account) + ' -- attacker erased evidence (T1070.001). Treat as active compromise.'))
            } else {
                $e = $sec[0]
                $secSev = 'WARNING'; $secState = 'prep'
                $old = ConvertTo-PrintableText $e.Machine
                $prepNames = @($sec | ForEach-Object { Get-HostLabel $_.Machine } | Sort-Object -Unique)
                [void]$out.Add(('[WARNING] Security event log was cleared at ' + (Format-When $e.Time) + ' by ' + (ConvertTo-PrintableText $e.Account) + ', before this PC took its current name: the record names ' + $old + ', this PC is ' + (ConvertTo-PrintableText $cur) + ' -- the shape of a Windows image being prepared before it was handed out (T1070.001). If you did not build this image or get it from a source you trust, treat it as a compromise: a clear erases the record of what came before it.'))
                # The other logs cleared in the same moment, as an image build does.
                $near = @($Sys104 | Where-Object { $_ -and $null -ne $_.Time -and $null -ne $e.Time -and [math]::Abs((([datetime]$_.Time) - ([datetime]$e.Time)).TotalSeconds) -le 2 } | ForEach-Object { [string]$_.Channel } | Where-Object { $_ } | Sort-Object -Unique)
                if ($near.Count -gt 0) {
                    [void]$out.Add(('[INFO] Cleared within the same 2 seconds, under the same earlier name: ' + ((@($near) | ForEach-Object { ConvertTo-PrintableText $_ }) -join ', ') + ' (Event 104) -- every log at once, as an image build does.'))
                }
            }
            if ($sec.Count -gt 1) { [void]$out.Add(('[INFO] ' + $sec.Count + ' Security-log clear record(s) found; the newest is graded above.')) }
        }
    }
    if ($SysError) {
        $sysState = 'gap'
        if ($IsElevated) {
            $gapSev = 'WARNING'
            [void]$out.Add(('[WARNING] System-log clear check NOT performed -- the System log could not be read (' + (ConvertTo-PrintableText $SysError) + ').'))
        } else {
            [void]$out.Add(('[INFO] System-log clear check not performed -- the System log could not be read (' + (ConvertTo-PrintableText $SysError) + ').'))
        }
    } else {
        $sys = @($Sys104 | Where-Object { $_ } | Sort-Object { $_.Time } -Descending)
        if ($sys.Count -eq 0) {
            [void]$out.Add('[OK] System event log has not been cleared.')
        } else {
            $e = $sys[0]
            $sysSev = 'WARNING'; $sysState = 'cleared'
            $why = ''
            if (-not $mine.ContainsKey((Get-HostLabel $e.Machine))) { $why = ' It was recorded under ' + (ConvertTo-PrintableText $e.Machine) + ', before this PC took its current name.' }
            [void]$out.Add(('[WARNING] System event log was cleared at ' + (Format-When $e.Time) + ' -- often benign (updates/driver installs/disk cleanup); the Security 1102 check above is the attacker cover-up signal.' + $why))
        }
    }
    return @{ Lines = @($out.ToArray()); SecSev = $secSev; SysSev = $sysSev; GapSev = $gapSev; Deferred = $deferred; State = ('sec=' + $secState + ',sys=' + $sysState) }
}

# Live: one log's clear records as plain objects, and why it could not be read.
function Read-ClearRecords {
    param([string]$Log, [int]$Id)
    $recs = New-Object System.Collections.ArrayList
    try {
        foreach ($ev in @(Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Id; ProviderName = 'Microsoft-Windows-Eventlog' } -MaxEvents 50 -ErrorAction Stop)) {
            $acct = ''; $chan = ''
            $p = @($ev.Properties)
            if ($Id -eq 1102 -and $p.Count -ge 3) { $acct = ([string]$p[2].Value) + '\' + ([string]$p[1].Value) }
            if ($Id -eq 104 -and $p.Count -ge 3) { $acct = ([string]$p[1].Value) + '\' + ([string]$p[0].Value); $chan = [string]$p[2].Value }
            if (-not $acct -or $acct -eq '\') { $acct = [string]$ev.UserId }
            if (-not $acct) { $acct = 'an unrecorded account' }
            [void]$recs.Add(@{ Time = $ev.TimeCreated; Machine = [string]$ev.MachineName; Account = $acct; Channel = $chan })
        }
        return @{ Records = @($recs.ToArray()); Error = '' }
    } catch {
        # No matching records is an answer; anything else is a read failure.
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { return @{ Records = @(); Error = '' } }
        return @{ Records = @(); Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
    }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function Rec { param($t, [string]$m, [string]$a = 'WIN-EIH5CPD9P56\Administrator', [string]$c = '') @{ Time = [datetime]$t; Machine = $m; Account = $a; Channel = $c } }
    # WIN11-02, 2026-10-24, verbatim: one 1102 and three 104 within 20 ms, all
    # under Setup's random name, the machine since renamed by its cloud agent.
    $w1102 = @(Rec '2026-10-17T23:00:23.567' 'WIN-EIH5CPD9P56')
    $w104 = @((Rec '2026-10-17T23:00:23.572' 'WIN-EIH5CPD9P56' 'WIN-EIH5CPD9P56\Administrator' 'Setup'), (Rec '2026-10-17T23:00:23.554' 'WIN-EIH5CPD9P56' 'WIN-EIH5CPD9P56\Administrator' 'Application'), (Rec '2026-10-17T23:00:23.549' 'WIN-EIH5CPD9P56' 'WIN-EIH5CPD9P56\Administrator' 'System'))
    $v = Get-LogClearVerdict -Sec1102 $w1102 -Sys104 $w104 -CurrentNames @('WIN11-02', 'WIN11-02')
    $t = $v.Lines -join "`n"
    T 'the WIN11-02 clear (made before the PC took its name) is a WARNING, not CRITICAL' ($v.SecSev -eq 'WARNING' -and $v.State -eq 'sec=prep,sys=cleared' -and $t -notmatch 'CRITICAL') $t
    T '...and the line names both computer names and who cleared it' ($t -match '(?m)^\[WARNING\] Security event log was cleared at 10/17/2026 23:00:23 by WIN-EIH5CPD9P56\\Administrator, before this PC took its current name: the record names WIN-EIH5CPD9P56, this PC is WIN11-02 -- the shape of a Windows image being prepared') $t
    T '...and tells a reader who did not build the image to treat it as a compromise' ($t -match 'If you did not build this image or get it from a source you trust, treat it as a compromise') $t
    T '...and names the other logs cleared in the same moment' ($t -match '(?m)^\[INFO\] Cleared within the same 2 seconds, under the same earlier name: Application, Setup, System \(Event 104\)') $t
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-10-17T23:00:23.567' 'WIN11-02') -Sys104 @() -CurrentNames @('WIN11-02')
    T 'the same clear under THIS computer''s name stays CRITICAL' ($v.SecSev -eq 'CRITICAL' -and $v.State -eq 'sec=critical,sys=none' -and ($v.Lines -join "`n") -match '(?m)^\[CRITICAL\] Security event log was CLEARED at 10/17/2026 23:00:23 by .* Treat as active compromise\.') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @((Rec '2026-10-17T23:00:23' 'WIN-EIH5CPD9P56'), (Rec '2026-10-20T08:00:00' 'WIN11-02')) -CurrentNames @('WIN11-02')
    T 'one clear under an old name and one under the current name: CRITICAL (a clear in this machine''s own life)' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @((Rec '2026-10-20T08:00:00' 'WIN-EIH5CPD9P56'), (Rec '2026-10-17T08:00:00' 'WIN11-02')) -CurrentNames @('WIN11-02')
    T 'an OLDER clear under the current name and a newer one under another name: still CRITICAL' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-10-20T08:00:00' 'win11-02.corp.example.com') -CurrentNames @('WIN11-02')
    T 'a record naming the DNS host name of this same computer is CRITICAL (first label, any case)' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-10-20T08:00:00' 'LAPTOP-WITHALONGNAME') -CurrentNames @('LAPTOP-WITHALON', 'laptop-withalongname')
    T 'a host name longer than its 15-character NetBIOS name still matches by the DNS host name' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @() -Sys104 @() -CurrentNames @('WIN11-02')
    T 'no clear records: both OK, nothing raised' ($v.SecSev -eq 'OK' -and $v.SysSev -eq 'OK' -and $v.State -eq 'sec=none,sys=none' -and ($v.Lines -join "`n") -match '\[OK\] Security event log has not been cleared\.' -and ($v.Lines -join "`n") -match '\[OK\] System event log has not been cleared\.') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -SecError 'UnauthorizedAccessException: denied' -CurrentNames @('WIN11-02') -IsElevated $true
    T 'an administrator who cannot read the Security log gets a raised gap, never "has not been cleared"' ($v.GapSev -eq 'WARNING' -and $v.State -match '^sec=gap' -and ($v.Lines -join "`n") -match 'Event-log clear check NOT performed' -and ($v.Lines -join "`n") -notmatch 'Security event log has not been cleared') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -SecError 'UnauthorizedAccessException: denied' -CurrentNames @('WIN11-02') -IsElevated $false
    T 'a standard-user token is a deferral, never a gap row and never an all-clear' ($v.Deferred -eq 1 -and $v.GapSev -eq 'OK' -and $v.State -match '^sec=deferred' -and ($v.Lines -join "`n") -match '\[DEFERRED - ADMIN REQUIRED\]' -and ($v.Lines -join "`n") -notmatch 'Security event log has not been cleared') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-10-17T23:00:23' ('EVIL' + [char]10 + '[OK] fine')) -CurrentNames @('WIN11-02')
    T 'a control character in a recorded computer name cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sys104 @(Rec '2026-10-17T23:00:23' 'WIN-EIH5CPD9P56' 'x' 'System') -CurrentNames @('WIN11-02')
    T 'a System-log clear stays a WARNING, and says when it predates the current name' ($v.SysSev -eq 'WARNING' -and ($v.Lines -join "`n") -match 'System event log was cleared at .* recorded under WIN-EIH5CPD9P56, before this PC took its current name') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails log_clear_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] log_clear_check self-test: a log cleared under this computer''s name is CRITICAL, one cleared before the PC took its current name is a WARNING that names both names, and an unreadable log is a gap or a deferral, never an all-clear.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$names = @($env:COMPUTERNAME)
try { $names += [System.Net.Dns]::GetHostName() } catch {}
$s = Read-ClearRecords -Log 'Security' -Id 1102
$y = Read-ClearRecords -Log 'System' -Id 104
$v = Get-LogClearVerdict -Sec1102 $s.Records -Sys104 $y.Records -CurrentNames $names -SecError $s.Error -SysError $y.Error -IsElevated ($Elevated -eq 1)
foreach ($l in $v.Lines) { $l }
Write-Marker -Name 'logclear' -Sev $v.SecSev
Write-Marker -Name 'logclear104' -Sev $v.SysSev
Write-Marker -Name 'logclear_gap' -Sev $v.GapSev
if ($v.Deferred -gt 0) { Write-Marker -Name 'logclear_deferred' -Sev ([string]$v.Deferred) }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII } catch {}
exit 0
