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
#   * a 1102 written under ANOTHER name is image preparation only when it
#     was ALSO made no later than 24 hours after the OLDEST install date this
#     PC records, and the PC was not renamed more than 24 hours after that
#     date. An image is cleared before the clone's first boot sets the install
#     date, and the first-boot rename follows within minutes. A name alone is
#     not enough -- an owner who renames DESKTOP-XXXX months later moves the
#     name, not the history, so a real clear before that rename stays
#     CRITICAL. And the CURRENT install date is not enough either: a feature
#     update resets Win32_OperatingSystem.InstallDate to the upgrade's date
#     while the Security log carries over, so every older clear would look
#     "before the install". The date used is the oldest of that value and
#     each HKLM\SYSTEM\Setup\Source OS (Updated on ...) InstallDate, which
#     Windows writes for the OS an upgrade replaced. Image preparation is a
#     WARNING that names both names and the install date, asks whether the
#     PC was ever called the old name while in use, and says what to do if
#     the image is not one the reader built or trusts. Still a counted
#     finding, never silenced. An unknown install date, an empty record
#     name, or no name of our own keeps it CRITICAL.
#   * a Security log that cannot be read is a raised gap for an administrator
#     and a DEFERRAL on a standard-user token (which can never read it) --
#     never "has not been cleared". A System log that cannot be read is a
#     raised gap on either token (users can read it). The dashboard tile used
#     to re-read the Security log itself with -EA SilentlyContinue, so a read
#     that failed on an elevated run printed PASS "Security event log has not
#     been cleared" having checked nothing.
#   * every Event 104 names the log it cleared: a cleared Sysmon or
#     PowerShell log is not the routine System-log clear.
#
# Output goes to the report; markers: dz_logclear.txt (severity of the
# Security clear), dz_logclear104.txt (WARNING when the System log records a
# clear), dz_logclear_gap.txt (Security unreadable), dz_logclear104_gap.txt
# (System unreadable), dz_logclear_deferred.txt (a count). One state
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
    # An empty severity is no verdict, never a marker: the bat would raise a
    # row with a blank severity for it.
    if (-not $Sev -or $Sev -eq 'OK') { return }
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
    # The same text on every machine: '/' in a .NET format string is the
    # CULTURE's date separator, so MM/dd/yyyy printed 10.17.2026 on de-DE.
    param($Time)
    if ($null -eq $Time) { return 'an unknown time' }
    return ([datetime]$Time).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-OldestDate {
    # PURE. The earliest of the dates given, ignoring nulls; $null when none.
    param([object[]]$Dates = @())
    $d = @($Dates | Where-Object { $null -ne $_ } | ForEach-Object { [datetime]$_ } | Sort-Object)
    if ($d.Count -eq 0) { return $null }
    return $d[0]
}

function ConvertFrom-UnixSeconds {
    # PURE. A Source OS key's InstallDate is a DWORD of seconds since 1970 UTC.
    param([double]$Seconds)
    return ([DateTime]::SpecifyKind([datetime]'1970-01-01', [DateTimeKind]::Utc)).AddSeconds($Seconds).ToLocalTime()
}

# PURE. Records are plain objects: @{ Time; Machine; Account; Channel }.
#   CurrentNames  this computer's names (NetBIOS, DNS host name)
#   InstallDate   the OLDEST install date this PC records (Get-OldestDate), or $null
#   RenameTime    the newest System Event 6011 (computer renamed), or $null
#   SecError      '' when the Security log was read, else why it could not be
#   SysError      the same for the System log
#   IsElevated    the token this ran under
# A Security clear is image preparation ONLY when every record names another
# computer AND it was made no later than 24 hours after the oldest install
# date AND the PC was not renamed more than 24 hours after that date (see the
# header). Unknown or missing data keeps CRITICAL.
# Returns @{ Lines; SecSev; SysSev; SecGap; SysGap; Deferred; State }.
function Get-LogClearVerdict {
    param($Sec1102 = @(), $Sys104 = @(), [string[]]$CurrentNames = @(), $InstallDate = $null, $RenameTime = $null, [string]$SecError = '', [string]$SysError = '', [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $mine = @{}
    foreach ($c in @($CurrentNames)) { $l = Get-HostLabel $c; if ($l) { $mine[$l] = $true } }
    $secSev = 'OK'; $sysSev = 'OK'; $secGap = 'OK'; $sysGap = 'OK'; $deferred = 0
    $secState = 'none'; $sysState = 'none'
    $cur = (@($CurrentNames) | Where-Object { $_ } | Select-Object -First 1)
    # A record is THIS computer's unless it names, clearly, another one: an
    # empty name, or no name of our own to compare with, keeps it ours.
    $isOwn = { param($m) (-not ([string]$m).Trim()) -or ($mine.Count -eq 0) -or $mine.ContainsKey((Get-HostLabel $m)) }
    $limit = $null; if ($null -ne $InstallDate) { $limit = ([datetime]$InstallDate).AddHours(24) }
    # A first-boot rename follows the install within minutes; one more than a
    # day later is an owner's or an intruder's, not the shape this rule reads.
    $lateRename = ($null -ne $RenameTime -and $null -ne $limit -and ([datetime]$RenameTime) -gt $limit)
    $isLate = { param($r) ($null -eq $r.Time) -or ($null -eq $limit) -or (([datetime]$r.Time) -gt $limit) }
    if ($SecError) {
        if ($IsElevated) {
            $secGap = 'WARNING'; $secState = 'gap'
            [void]$out.Add(('[WARNING] Security-log clear check NOT performed -- the Security log could not be read (' + (ConvertTo-PrintableText $SecError) + '), so a cleared log would go unseen (T1070.001).'))
        } else {
            $deferred = 1; $secState = 'deferred'
            [void]$out.Add('[DEFERRED - ADMIN REQUIRED] Security log clears (Event 1102): a standard-user token cannot read the Security log -- re-run as administrator to check it.')
        }
    } else {
        $sec = @($Sec1102 | Where-Object { $_ } | Sort-Object { $_.Time } -Descending)
        if ($sec.Count -eq 0) {
            [void]$out.Add('[OK] Security event log has not been cleared.')
        } else {
            $own = @($sec | Where-Object { & $isOwn $_.Machine })
            $e = $sec[0]
            $late = @($sec | Where-Object { & $isLate $_ })
            if ($own.Count -gt 0 -or $late.Count -gt 0 -or $lateRename) {
                if ($own.Count -gt 0) { $e = $own[0] }
                $secSev = 'CRITICAL'; $secState = 'critical'
                [void]$out.Add(('[CRITICAL] Security event log was CLEARED at ' + (Format-When $e.Time) + ' by ' + (ConvertTo-PrintableText $e.Account) + ' -- attacker erased evidence (T1070.001). Treat as active compromise.'))
                if ($own.Count -eq 0) {
                    # Recorded under another name, but not the image shape:
                    # say which test it failed.
                    if ($null -eq $InstallDate) { $why = 'Windows'' install date could not be read' }
                    elseif ($late.Count -gt 0) { $e = $late[0]; $why = 'it was made more than 24 hours after Windows was installed here (' + (Format-When $InstallDate) + ')' }
                    else { $why = 'the computer was renamed at ' + (Format-When $RenameTime) + ' (System Event 6011), more than 24 hours after Windows was installed here (' + (Format-When $InstallDate) + ') -- not a first-boot rename' }
                    [void]$out.Add(('[INFO] The clear record names ' + (ConvertTo-PrintableText $e.Machine) + ', not ' + (ConvertTo-PrintableText $cur) + ', but ' + $why + ', so it is not read as image preparation.'))
                }
                if ($sec.Count -gt 1) { [void]$out.Add(('[INFO] ' + $sec.Count + ' Security-log clear record(s) found.')) }
            } else {
                $secSev = 'WARNING'; $secState = 'prep'
                $old = ConvertTo-PrintableText $e.Machine
                $names = (@($sec | ForEach-Object { ConvertTo-PrintableText $_.Machine } | Sort-Object -Unique) -join ', ')
                [void]$out.Add(('[WARNING] Security event log was cleared at ' + (Format-When $e.Time) + ' by ' + (ConvertTo-PrintableText $e.Account) + ', before this PC took its current name and before Windows'' install date here (' + (Format-When $InstallDate) + '): the record names ' + $old + ', this PC is ' + (ConvertTo-PrintableText $cur) + ' -- the shape of a Windows image being prepared before it was handed out (T1070.001). If this PC was ever called ' + $old + ' while you were using it, the clear happened in its own life: treat it as a compromise. And if you did not build this image or get it from a source you trust, treat it as one too: a clear erases the record of what came before it.'))
                if ($sec.Count -gt 1) { [void]$out.Add(('[INFO] ' + $sec.Count + ' Security-log clear record(s), all under an earlier name: ' + $names + '.')) }
                if ($null -ne $RenameTime) { [void]$out.Add(('[INFO] The computer was renamed at ' + (Format-When $RenameTime) + ' (System Event 6011).')) }
                # The other logs cleared in the same moment under the same
                # earlier name, as an image build does.
                $near = @($Sys104 | Where-Object { $_ -and $null -ne $_.Time -and $null -ne $e.Time -and (Get-HostLabel $_.Machine) -eq (Get-HostLabel $e.Machine) -and [math]::Abs((([datetime]$_.Time) - ([datetime]$e.Time)).TotalSeconds) -le 2 } | ForEach-Object { [string]$_.Channel } | Where-Object { $_ } | Sort-Object -Unique)
                if ($near.Count -gt 0) {
                    [void]$out.Add(('[INFO] Cleared within the same 2 seconds, under the same earlier name: ' + ((@($near) | ForEach-Object { ConvertTo-PrintableText $_ }) -join ', ') + ' (Event 104) -- every log at once, as an image build does.'))
                }
            }
        }
    }
    if ($SysError) {
        # Interactive users can read the System log, so on either token a
        # failure here is the machine, not the token: a raised gap.
        $sysGap = 'WARNING'; $sysState = 'gap'
        [void]$out.Add(('[WARNING] System-log clear check NOT performed -- the System log could not be read (' + (ConvertTo-PrintableText $SysError) + ').'))
    } else {
        $sys = @($Sys104 | Where-Object { $_ } | Sort-Object { $_.Time } -Descending)
        if ($sys.Count -eq 0) {
            [void]$out.Add('[OK] No event log has been cleared (no Event 104 in the System log).')
        } else {
            $e = $sys[0]
            $sysSev = 'WARNING'; $sysState = 'cleared'
            $why = ''
            if (-not (& $isOwn $e.Machine)) {
                # The same test as the Security clear: a name alone does not
                # place a record before this PC's own life.
                if (-not (& $isLate $e) -and -not $lateRename) { $why = ' It was recorded under ' + (ConvertTo-PrintableText $e.Machine) + ', before this PC took its current name and before Windows'' install date here.' }
                else { $why = ' It was recorded under ' + (ConvertTo-PrintableText $e.Machine) + ', another name, but not in the shape of image preparation (made after Windows was installed here, renamed later, or no install date to compare): read it as this PC''s own history.' }
            }
            $ch = ([string]$e.Channel).Trim()
            if (-not $ch -or $ch -eq 'System') {
                [void]$out.Add(('[WARNING] System event log was cleared at ' + (Format-When $e.Time) + ' -- often benign (updates/driver installs/disk cleanup); the Security 1102 check above is the attacker cover-up signal.' + $why))
            } else {
                [void]$out.Add(('[WARNING] Event log ''' + (ConvertTo-PrintableText $ch) + ''' was cleared at ' + (Format-When $e.Time) + ' (Event 104 in the System log) -- check who cleared it: clearing a security tool''s own log (Sysmon, PowerShell) is how an intruder hides what it recorded.' + $why))
            }
            if ($sys.Count -gt 1) {
                $chs = (@($sys | ForEach-Object { $c = ([string]$_.Channel).Trim(); if (-not $c) { 'System' } else { ConvertTo-PrintableText $c } } | Sort-Object -Unique) -join ', ')
                [void]$out.Add(('[INFO] ' + $sys.Count + ' Event 104 record(s); logs cleared: ' + $chs + '.'))
            }
        }
    }
    return @{ Lines = @($out.ToArray()); SecSev = $secSev; SysSev = $sysSev; SecGap = $secGap; SysGap = $sysGap; Deferred = $deferred; State = ('sec=' + $secState + ',sys=' + $sysState) }
}

# Live: one log's clear records as plain objects, and why it could not be read.
# The log is opened first by name: a channel this token may not read must be
# "could not be read", never "no matching events".
function Read-ClearRecords {
    param([string]$Log, [int]$Id)
    $recs = New-Object System.Collections.ArrayList
    try { $null = Get-WinEvent -LogName $Log -MaxEvents 1 -ErrorAction Stop }
    catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { return @{ Records = @(); Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
    }
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
    # The install date is the day after the clear (its apps date from then).
    $w1102 = @(Rec '2026-10-17T23:00:23.567' 'WIN-EIH5CPD9P56')
    $w104 = @((Rec '2026-10-17T23:00:23.572' 'WIN-EIH5CPD9P56' 'WIN-EIH5CPD9P56\Administrator' 'Setup'), (Rec '2026-10-17T23:00:23.554' 'WIN-EIH5CPD9P56' 'WIN-EIH5CPD9P56\Administrator' 'Application'), (Rec '2026-10-17T23:00:23.549' 'WIN-EIH5CPD9P56' 'WIN-EIH5CPD9P56\Administrator' 'System'))
    $wInstall = [datetime]'2026-10-18T09:12:00'
    $v = Get-LogClearVerdict -Sec1102 $w1102 -Sys104 $w104 -CurrentNames @('WIN11-02', 'WIN11-02') -InstallDate $wInstall -RenameTime ([datetime]'2026-10-18T09:20:41')
    $t = $v.Lines -join "`n"
    T 'the WIN11-02 clear (before the PC took its name, before its install date) is a WARNING, not CRITICAL' ($v.SecSev -eq 'WARNING' -and $v.State -eq 'sec=prep,sys=cleared' -and $t -notmatch 'CRITICAL') $t
    T '...and the line names both computer names, who cleared it and the install date' ($t -match '(?m)^\[WARNING\] Security event log was cleared at 2026-10-17 23:00:23 by WIN-EIH5CPD9P56\\Administrator, before this PC took its current name and before Windows'' install date here \(2026-10-18 09:12:00\): the record names WIN-EIH5CPD9P56, this PC is WIN11-02 -- the shape of a Windows image being prepared') $t
    T '...and asks the question a retail-PC owner can answer' ($t -match 'If this PC was ever called WIN-EIH5CPD9P56 while you were using it, the clear happened in its own life: treat it as a compromise\.') $t
    T '...and tells a reader who did not build the image to treat it as a compromise too' ($t -match 'if you did not build this image or get it from a source you trust, treat it as one too') $t
    T '...and prints when the computer was renamed' ($t -match '(?m)^\[INFO\] The computer was renamed at 2026-10-18 09:20:41 \(System Event 6011\)\.') $t
    T '...and names the other logs cleared in the same moment' ($t -match '(?m)^\[INFO\] Cleared within the same 2 seconds, under the same earlier name: Application, Setup, System \(Event 104\)') $t
    T '...and the newest Event 104 names its channel' ($v.SysSev -eq 'WARNING' -and $t -match '(?m)^\[WARNING\] Event log ''Setup'' was cleared at 2026-10-17 23:00:23 \(Event 104 in the System log\)') $t
    $v = Get-LogClearVerdict -Sec1102 $w1102 -Sys104 $w104 -CurrentNames @('WIN11-02') -InstallDate ([datetime]'2025-01-01')
    $t = $v.Lines -join "`n"
    T 'the same clear on a PC installed long BEFORE it (a retail PC renamed later) is CRITICAL' ($v.SecSev -eq 'CRITICAL' -and $v.State -match '^sec=critical' -and $t -match '(?m)^\[INFO\] The clear record names WIN-EIH5CPD9P56, not WIN11-02, but it was made more than 24 hours after Windows was installed here \(2025-01-01 00:00:00\)') $t
    $v = Get-LogClearVerdict -Sec1102 $w1102 -CurrentNames @('WIN11-02') -InstallDate $null
    T 'an install date that could not be read keeps it CRITICAL, and says why' ($v.SecSev -eq 'CRITICAL' -and ($v.Lines -join "`n") -match 'install date could not be read') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-10-19T23:00:23' 'WIN-EIH5CPD9P56') -CurrentNames @('WIN11-02') -InstallDate $wInstall
    T 'a clear under another name more than 24 hours after the install date is CRITICAL' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-10-17T23:00:23.567' 'WIN11-02') -Sys104 @() -CurrentNames @('WIN11-02') -InstallDate $wInstall
    T 'the same clear under THIS computer''s name stays CRITICAL' ($v.SecSev -eq 'CRITICAL' -and $v.State -eq 'sec=critical,sys=none' -and ($v.Lines -join "`n") -match '(?m)^\[CRITICAL\] Security event log was CLEARED at 2026-10-17 23:00:23 by .* Treat as active compromise\.') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-10-17T23:00:23' '') -CurrentNames @('WIN11-02') -InstallDate $wInstall
    T 'a record with no computer name counts as this computer''s: CRITICAL' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 $w1102 -CurrentNames @() -InstallDate $wInstall
    T 'no name of our own to compare with: CRITICAL' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @((Rec '2026-10-17T23:00:23' 'WIN-EIH5CPD9P56'), (Rec '2026-10-20T08:00:00' 'WIN11-02')) -CurrentNames @('WIN11-02') -InstallDate $wInstall
    T 'one clear under an old name and one under the current name: CRITICAL (a clear in this machine''s own life)' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @((Rec '2026-10-18T08:00:00' 'WIN-EIH5CPD9P56'), (Rec '2026-10-17T08:00:00' 'WIN11-02')) -CurrentNames @('WIN11-02') -InstallDate $wInstall
    T 'an OLDER clear under the current name and a newer one under another name: still CRITICAL' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-10-17T08:00:00' 'win11-02.corp.example.com') -CurrentNames @('WIN11-02') -InstallDate $wInstall
    T 'a record naming the DNS host name of this same computer is CRITICAL (first label, any case)' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-10-17T08:00:00' 'LAPTOP-WITHALONGNAME') -CurrentNames @('LAPTOP-WITHALON', 'laptop-withalongname') -InstallDate $wInstall
    T 'a host name longer than its 15-character NetBIOS name still matches by the DNS host name' ($v.SecSev -eq 'CRITICAL') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @() -Sys104 @() -CurrentNames @('WIN11-02')
    T 'no clear records: both OK, nothing raised' ($v.SecSev -eq 'OK' -and $v.SysSev -eq 'OK' -and $v.State -eq 'sec=none,sys=none' -and ($v.Lines -join "`n") -match '\[OK\] Security event log has not been cleared\.' -and ($v.Lines -join "`n") -match '\[OK\] No event log has been cleared \(no Event 104 in the System log\)\.') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -SecError 'UnauthorizedAccessException: denied' -CurrentNames @('WIN11-02') -IsElevated $true
    T 'an administrator who cannot read the Security log gets a raised gap, never "has not been cleared"' ($v.SecGap -eq 'WARNING' -and $v.SecSev -eq 'OK' -and $v.State -match '^sec=gap' -and ($v.Lines -join "`n") -match '(?m)^\[WARNING\] Security-log clear check NOT performed' -and ($v.Lines -join "`n") -notmatch 'Security event log has not been cleared') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -SecError 'UnauthorizedAccessException: denied' -CurrentNames @('WIN11-02') -IsElevated $false
    T 'a standard-user token is a deferral, never a gap row and never an all-clear' ($v.Deferred -eq 1 -and $v.SecGap -eq 'OK' -and $v.State -match '^sec=deferred' -and ($v.Lines -join "`n") -match '\[DEFERRED - ADMIN REQUIRED\]' -and ($v.Lines -join "`n") -notmatch 'Security event log has not been cleared') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -SecError 'x' -SysError 'EventLogException: denied' -CurrentNames @('WIN11-02') -IsElevated $false
    T 'a System log that cannot be read is a raised gap on a standard-user token too (users can read it)' ($v.SysGap -eq 'WARNING' -and $v.SysSev -eq 'OK' -and $v.State -eq 'sec=deferred,sys=gap' -and ($v.Lines -join "`n") -match '(?m)^\[WARNING\] System-log clear check NOT performed' -and ($v.Lines -join "`n") -notmatch 'No event log has been cleared') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-10-17T23:00:23' ('EVIL' + [char]10 + '[OK] fine')) -CurrentNames @('WIN11-02') -InstallDate $wInstall
    T 'a control character in a recorded computer name cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sys104 @(Rec '2026-10-17T23:00:23' 'WIN-EIH5CPD9P56' 'x' 'System') -CurrentNames @('WIN11-02') -InstallDate $wInstall
    T 'a System-log clear stays a WARNING, and says when it predates the current name' ($v.SysSev -eq 'WARNING' -and ($v.Lines -join "`n") -match '(?m)^\[WARNING\] System event log was cleared at 2026-10-17 23:00:23 .* recorded under WIN-EIH5CPD9P56, before this PC took its current name and before Windows'' install date here\.') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sys104 @(Rec '2026-10-17T23:00:23' 'WIN-EIH5CPD9P56' 'x' 'Microsoft-Windows-Sysmon/Operational') -CurrentNames @('WIN11-02') -InstallDate ([datetime]'2025-01-01')
    T 'an Event 104 under another name made after the install date is not called image preparation' ($v.SysSev -eq 'WARNING' -and ($v.Lines -join "`n") -notmatch 'before this PC took its current name' -and ($v.Lines -join "`n") -match 'read it as this PC''s own history') ($v.Lines -join ' | ')
    # A feature update resets the CIM install date and keeps the Security log:
    # the oldest recorded install date decides. DESKTOP-AB12CD was installed
    # in January, cleared by an intruder in March, renamed MYPC by its owner
    # in June, and upgraded in October.
    $oldest = Get-OldestDate @([datetime]'2026-10-08T03:00:00', $null, [datetime]'2026-01-10T12:00:00')
    T 'the oldest install date is taken across the current OS and every Source OS key' ($null -ne $oldest -and $oldest -eq [datetime]'2026-01-10T12:00:00') ([string]$oldest)
    $v = Get-LogClearVerdict -Sec1102 @(Rec '2026-03-14T02:10:00' 'DESKTOP-AB12CD' 'DESKTOP-AB12CD\owner') -CurrentNames @('MYPC') -InstallDate $oldest
    T 'an intruder''s clear, then an owner''s rename and a feature update: still CRITICAL' ($v.SecSev -eq 'CRITICAL' -and $v.State -match '^sec=critical') ($v.Lines -join ' | ')
    T 'Get-OldestDate of nothing is unknown, never a date' ($null -eq (Get-OldestDate @($null))) ''
    $u = (ConvertFrom-UnixSeconds 1729000000).ToUniversalTime()
    T 'a Source OS InstallDate DWORD converts from Unix seconds (UTC)' ($u.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) -eq '2024-10-15 13:46:40') ([string]$u)
    $v = Get-LogClearVerdict -Sec1102 $w1102 -Sys104 $w104 -CurrentNames @('WIN11-02') -InstallDate $wInstall -RenameTime ([datetime]'2027-01-05T10:00:00')
    T 'the image-shaped clear on a PC renamed months after its install is CRITICAL, and says why' ($v.SecSev -eq 'CRITICAL' -and ($v.Lines -join "`n") -match 'the computer was renamed at 2027-01-05 10:00:00 \(System Event 6011\), more than 24 hours after') ($v.Lines -join ' | ')
    $v = Get-LogClearVerdict -Sys104 @(Rec '2026-10-20T10:00:00' 'WIN11-02' 'x' 'Microsoft-Windows-Sysmon/Operational') -CurrentNames @('WIN11-02')
    T 'a cleared security-tool log is named by its channel' ($v.SysSev -eq 'WARNING' -and $v.State -eq 'sec=none,sys=cleared' -and ($v.Lines -join "`n") -match '(?m)^\[WARNING\] Event log ''Microsoft-Windows-Sysmon/Operational'' was cleared at 2026-10-20 10:00:00') ($v.Lines -join ' | ')
    # Dates are the same text on every culture (de-DE printed 10.17.2026).
    $saved = [Threading.Thread]::CurrentThread.CurrentCulture
    try {
        [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('de-DE')
        $v = Get-LogClearVerdict -Sec1102 $w1102 -CurrentNames @('WIN11-02') -InstallDate $wInstall
    } finally { [Threading.Thread]::CurrentThread.CurrentCulture = $saved }
    T 'under a de-DE culture the dates print as 2026-10-17 23:00:23' (($v.Lines -join "`n") -match 'cleared at 2026-10-17 23:00:23 by' -and ($v.Lines -join "`n") -match 'install date here \(2026-10-18 09:12:00\)') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails log_clear_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] log_clear_check self-test: a log cleared under this computer''s name, or after Windows was installed here, is CRITICAL; one cleared before the PC took its current name and before its install date is a WARNING that names both; an unreadable log is a gap or a deferral, never an all-clear.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$names = @($env:COMPUTERNAME)
try { $names += [System.Net.Dns]::GetHostName() } catch {}
# The OLDEST install date: a feature update resets the CIM value, and each
# Source OS key records the install date of the OS an upgrade replaced.
# Unknown stays $null: the verdict then keeps any clear CRITICAL.
$dates = @()
try { $dates += (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).InstallDate } catch {}
try {
    foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\Setup' -ErrorAction Stop | Where-Object { $_.PSChildName -like 'Source OS*' })) {
        $d = (Get-ItemProperty -LiteralPath $k.PSPath -Name InstallDate -ErrorAction SilentlyContinue).InstallDate
        if ($d) { $dates += (ConvertFrom-UnixSeconds ([double]$d)) }
    }
} catch {}
$install = Get-OldestDate $dates
$rename = $null
try { $rename = (Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6011 } -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch {}
$s = Read-ClearRecords -Log 'Security' -Id 1102
$y = Read-ClearRecords -Log 'System' -Id 104
$v = $null
try { $v = Get-LogClearVerdict -Sec1102 $s.Records -Sys104 $y.Records -CurrentNames $names -InstallDate $install -RenameTime $rename -SecError $s.Error -SysError $y.Error -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^sec=(critical|prep|none|gap|deferred),sys=(cleared|none|gap)$') {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'log_clear_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
Write-Marker -Name 'logclear' -Sev $v.SecSev
Write-Marker -Name 'logclear104' -Sev $v.SysSev
Write-Marker -Name 'logclear_gap' -Sev $v.SecGap
Write-Marker -Name 'logclear104_gap' -Sev $v.SysGap
if ($v.Deferred -gt 0) { Write-Marker -Name 'logclear_deferred' -Sev ([string]$v.Deferred) }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII } catch {}
exit 0
