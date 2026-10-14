# lsass_copy_events.ps1 -- a copy of LSASS recorded in the Security log
# (T1003.001). Invoked from Section 12 of doze_sec.bat / doze_sec_noAdmin.bat.
#
# WHY. Process snapshotting and reflection make a new process that is a copy
# of an existing one, with the original recorded as its parent. Tools that
# want LSASS's secrets copy LSASS and read the copy, so they never read LSASS
# itself; the public detections for that (Elastic "Potential LSASS Clone
# Creation via PssCaptureSnapShot", Sigma "Potential Credential Dumping Via
# LSASS Process Clone") key on exactly one record: lsass.exe created by
# lsass.exe. Section 4 names such a copy when it is running, but a copy made
# for that lives for seconds -- the process snapshot will almost never see
# one. The Security log keeps the record: Event 4688 carries the new process
# and, since Windows 10, the name of the process that created it ("Creator
# Process Name", Microsoft: "What's new in Windows 10, version 1507").
#
# THE RULE (pure, in Get-CopyEventReport, pinned by -SelfTest):
#   * a 4688 record creating <Image> whose creator is <Image> itself:
#     CRITICAL -- LSASS was copied;
#   * created by the wininit.exe beside it: the start at boot, counted;
#   * created by anything else: WARNING -- Windows starts LSASS only from
#     wininit.exe;
#   * a record with no creator name (an old event format): counted as not
#     graded, never cleared.
# The image comparison is case-insensitive and in PowerShell, not in the
# XPath query: XPath compares strings case-sensitively, and a filter whose
# spelling never matches the recorded path would be a permanent all-clear.
#
# WHAT IT CANNOT SEE, said where it applies. With process-creation auditing
# off the log holds no 4688 record at all, and a copy leaves nothing here:
# that prints [SKIPPED] and raises nothing -- Section 16's audit-policy check
# raises the auditing gap itself. A copy older than the log's oldest record
# is gone with it; the OK line names the date the log reaches back to.
#
# MARKERS (the log_gap_check idiom): dz_lsacopy.txt holds the highest
# severity found; dz_lsacopy_gap.txt is written when the log could not be read
# by an administrator (its own ledger row); dz_lsacopy_deferred.txt holds the
# count of checks a standard-user token could not perform (it cannot read the
# Security log), added to DEFERRED_COUNT, never a ledger row.
#
# -Image is the program whose copies are looked for; the audit leaves it at
# <SystemRoot>\System32\lsass.exe. CI points it at cmd.exe to prove the field
# reading on a REAL 4688 record (cmd.exe started by cmd.exe) without copying
# anything.
#
# Read-only. Windows PowerShell 5.1 and pwsh. Pure ASCII.

[CmdletBinding()]
param(
    [string]$MarkerDir = '',
    [string]$Image = '',
    [int]$MaxRecords = 200000,
    # Whether this process runs elevated. Read once from the token below;
    # injectable so the self-test can grade both tokens. -1 = detect.
    [int]$Elevated = -1,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write turns a
    # finding into a CLEAN section. Create the directory, and let a genuine
    # write failure print instead of vanishing.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintableText {
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

function ConvertTo-ProcessId {
    # 4688 carries process IDs as pointers: a number, or a '0x...' string in
    # some renderings. Decimal for the report, $null when unreadable.
    param($Value)
    if ($null -eq $Value) { return $null }
    $t = ([string]$Value).Trim()
    if ($t -match '^0x([0-9A-Fa-f]{1,16})$') { return [Convert]::ToInt64($Matches[1], 16) }
    if ($t -match '^\d{1,19}$') { return [long]$t }
    return $null
}

function Get-LeafName {
    param([string]$Path)
    $p = ([string]$Path).Trim()
    $cut = $p.LastIndexOf('\')
    if ($cut -ge 0) { return $p.Substring($cut + 1) }
    return $p
}

# PURE: the 4688 records that created <Image>, graded.
#   Records  @{ Time = [datetime] or $null; NewPid; NewName; ParentPid; ParentName }
#   Total    how many 4688 records were read in all; 0 means none exists
#   Oldest   the oldest 4688 record read ([datetime] or $null)
#   Capped   reading stopped at -MaxRecords
#   Newest   the newest 4688 record read; with -Now, a newest record more
#            than an hour old means nothing has been recorded since (the
#            audit's own process starts would be, were auditing on)
#   StoppedBy  the error that ended the read part-way, or ''
#   Unreadable records that could not be read and were skipped
function Get-CopyEventReport {
    param($Records, [string]$Image, [long]$Total = 0, $Oldest = $null, [bool]$Capped = $false,
          $Newest = $null, $Now = $null, [string]$StoppedBy = '', [long]$Unreadable = 0)
    $out = New-Object System.Collections.ArrayList
    $leaf = Get-LeafName $Image
    $isLsass = ($leaf -ieq 'lsass.exe')
    $dir = ''
    $cut = $Image.LastIndexOf('\'); if ($cut -gt 0) { $dir = $Image.Substring(0, $cut) }
    $boot = $dir + '\wininit.exe'
    if ($Total -le 0) {
        [void]$out.Add(('[SKIPPED] Copies of ' + $leaf + ' in the Security log NOT checked -- the log holds no process-creation record (Event 4688): process creation is not being audited, or only recently was, so a copy leaves no record here. Section 16 reports the audit policy.'))
        return @{ Lines = @($out.ToArray()); Sev = 'OK'; Copies = 0 }
    }
    $copies = @(); $odd = @(); $bootStarts = 0; $noCreator = 0
    foreach ($r in @($Records)) {
        if ($null -eq $r) { continue }
        if (([string]$r.NewName).Trim() -ine $Image) { continue }
        $pn = ([string]$r.ParentName).Trim()
        if (-not $pn) { $noCreator++; continue }
        if ($pn -ieq $Image) { $copies += $r; continue }
        if ($pn -ieq $boot) { $bootStarts++; continue }
        $odd += $r
    }
    function Show-When($t) { if ($null -eq $t) { return 'an unknown time' } return ([datetime]$t).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z' }
    function Show-Pid($v) { if ($null -eq $v) { return '?' } return [string]$v }
    $cap = 10
    $sev = 'OK'
    $i = 0
    foreach ($r in $copies) {
        $i++
        if ($i -gt $cap) { break }
        $why = ''
        if ($isLsass) { $why = ' -- a second process holding LSASS''s memory, the shape credential-dumping tools leave (T1003.001). Windows does not copy LSASS on a healthy machine; an administrator''s own dump (ProcDump -r) does.' }
        [void]$out.Add(('[CRITICAL] ' + $leaf + ' was copied at ' + (Show-When $r.Time) + ': Event 4688 records ' + $leaf + ' (PID ' + (Show-Pid $r.NewPid) + ') created by ' + $leaf + ' (PID ' + (Show-Pid $r.ParentPid) + ') itself' + $why))
    }
    if ($copies.Count -gt $cap) { [void]$out.Add(('    ...and ' + ($copies.Count - $cap) + ' more record(s) of the same shape.')) }
    if ($copies.Count -gt 0) { $sev = 'CRITICAL' }
    $i = 0
    foreach ($r in $odd) {
        $i++
        if ($i -gt $cap) { break }
        [void]$out.Add(('[WARNING] ' + $leaf + ' was started at ' + (Show-When $r.Time) + ' by ' + (ConvertTo-PrintableText $r.ParentName) + ' (PID ' + (Show-Pid $r.ParentPid) + ') -- Windows starts it only from ' + $boot + ' at boot (Event 4688, T1036).'))
    }
    if ($odd.Count -gt $cap) { [void]$out.Add(('    ...and ' + ($odd.Count - $cap) + ' more record(s) of the same shape.')) }
    if ($odd.Count -gt 0 -and $sev -eq 'OK') { $sev = 'WARNING' }
    if ($noCreator -gt 0) {
        [void]$out.Add(('[INFO] ' + $noCreator + ' record(s) of ' + $leaf + ' starting carry no creator name (an older event format) -- not graded, not cleared.'))
    }
    $span = 'the records read'
    if ($null -ne $Oldest -and $null -ne $Newest) { $span = 'from ' + (Show-When $Oldest) + ' to ' + (Show-When $Newest) }
    elseif ($null -ne $Oldest) { $span = 'back to ' + (Show-When $Oldest) }
    if ($StoppedBy) {
        [void]$out.Add(('[INFO] Reading the Security log stopped after ' + $Total + ' record(s) (' + (ConvertTo-PrintableText $StoppedBy) + '): records older than ' + (Show-When $Oldest) + ' were NOT checked.'))
    }
    if ($Unreadable -gt 0) {
        [void]$out.Add(('[INFO] ' + $Unreadable + ' process-creation record(s) could not be read and were skipped -- not graded, not cleared.'))
    }
    if ($null -ne $Newest -and $null -ne $Now -and (([datetime]$Now).ToUniversalTime() - ([datetime]$Newest).ToUniversalTime()).TotalHours -gt 1) {
        [void]$out.Add(('[INFO] The newest process-creation record is from ' + (Show-When $Newest) + ': no process start since then is recorded, so process creation is likely not being audited now (Section 16 reports the audit policy) -- a copy made since leaves no record here.'))
    }
    if ($Capped) {
        [void]$out.Add(('[INFO] Only the newest ' + $Total + ' process-creation records were read; older ones were not.'))
    }
    if ($sev -eq 'OK') {
        [void]$out.Add(('[OK] No copy of ' + $leaf + ' in the Security log: ' + $Total + ' process-creation record(s) read, ' + $span + '; ' + $bootStarts + ' start(s) of ' + $leaf + ' by wininit.exe.'))
    }
    return @{ Lines = @($out.ToArray()); Sev = $sev; Copies = $copies.Count }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $L = 'C:\Windows\System32\lsass.exe'
    $W = 'C:\Windows\System32\wininit.exe'
    $t0 = New-Object DateTime 2026, 10, 1, 8, 0, 0, ([DateTimeKind]::Utc)
    # Not R: that is a built-in alias (Invoke-History), and an alias wins over a function.
    function NewRec { param([string]$new, [string]$par, $np = 900, $pp = 780, $t = $t0) @{ Time = $t; NewPid = $np; NewName = $new; ParentPid = $pp; ParentName = $par } }

    $r = Get-CopyEventReport -Records @((NewRec $L $W), (NewRec 'C:\Windows\System32\svchost.exe' 'C:\Windows\System32\services.exe')) -Image $L -Total 5000 -Oldest $t0 -Newest $t0.AddDays(2) -Now $t0.AddDays(2).AddMinutes(5)
    $j = $r.Lines -join "`n"
    T 'LSASS started by wininit.exe at boot is the normal record: OK, counted, with the span the log covers' ($r.Sev -eq 'OK' -and $j -match '\[OK\] No copy of lsass\.exe in the Security log: 5000 process-creation record\(s\) read, from 2026-10-01 08:00:00Z to 2026-10-03 08:00:00Z; 1 start\(s\) of lsass\.exe by wininit\.exe' -and $j -notmatch 'newest process-creation record is from') $j
    $r = Get-CopyEventReport -Records @((NewRec $L $W)) -Image $L -Total 5000 -Oldest $t0 -Newest $t0.AddDays(2) -Now $t0.AddDays(30)
    T 'a newest record a month old says nothing has been recorded since (auditing likely off now)' (($r.Lines -join "`n") -match '\[INFO\] The newest process-creation record is from 2026-10-03 08:00:00Z: no process start since then is recorded') ($r.Lines -join ' | ')
    $r = Get-CopyEventReport -Records @((NewRec $L $W)) -Image $L -Total 1200 -Oldest $t0 -Newest $t0.AddDays(1) -StoppedBy 'The handle is invalid' -Unreadable 3
    $j = $r.Lines -join "`n"
    T 'a read that stopped part-way, and records that could not be read, are said, never folded into the OK line silently' ($j -match '\[INFO\] Reading the Security log stopped after 1200 record\(s\) \(The handle is invalid\): records older than 2026-10-01 08:00:00Z were NOT checked' -and $j -match '\[INFO\] 3 process-creation record\(s\) could not be read and were skipped') $j
    $r = Get-CopyEventReport -Records @((NewRec $L $W), (NewRec $L $L 6120 900 $t0.AddHours(3))) -Image $L -Total 5000 -Oldest $t0
    $j = $r.Lines -join "`n"
    T 'lsass.exe created by lsass.exe is CRITICAL: LSASS was copied, with the time and both PIDs' ($r.Sev -eq 'CRITICAL' -and $r.Copies -eq 1 -and $j -match '(?m)^\[CRITICAL\] lsass\.exe was copied at 2026-10-01 11:00:00Z: Event 4688 records lsass\.exe \(PID 6120\) created by lsass\.exe \(PID 900\) itself -- a second process holding LSASS''s memory, the shape credential-dumping tools leave \(T1003.001\)' -and $j -notmatch '\[OK\]') $j
    $r = Get-CopyEventReport -Records @((NewRec 'c:\windows\system32\LSASS.EXE' 'C:\WINDOWS\system32\lsass.exe')) -Image $L -Total 10
    T 'paths compare case-insensitively: a recorded spelling cannot hide a copy' ($r.Sev -eq 'CRITICAL') ($r.Lines -join ' | ')
    $r = Get-CopyEventReport -Records @((NewRec $L 'C:\Windows\System32\cmd.exe' 900 4400)) -Image $L -Total 10
    $j = $r.Lines -join "`n"
    T 'the real lsass.exe started by anything but wininit.exe is a WARNING naming the starter' ($r.Sev -eq 'WARNING' -and $j -match '(?m)^\[WARNING\] lsass\.exe was started at .* by C:\\Windows\\System32\\cmd\.exe \(PID 4400\) -- Windows starts it only from C:\\Windows\\System32\\wininit\.exe at boot') $j
    $r = Get-CopyEventReport -Records @((NewRec 'C:\Users\Public\lsass.exe' 'C:\Users\Public\lsass.exe')) -Image $L -Total 10
    T 'a program named lsass.exe elsewhere is not the image looked for (Section 4 grades it by path)' ($r.Sev -eq 'OK') ($r.Lines -join ' | ')
    $r = Get-CopyEventReport -Records @((NewRec $L '')) -Image $L -Total 10
    $j = $r.Lines -join "`n"
    T 'a record with no creator name is counted as not graded, never cleared as a copy-free start' ($r.Sev -eq 'OK' -and $j -match '\[INFO\] 1 record\(s\) of lsass\.exe starting carry no creator name') $j
    $r = Get-CopyEventReport -Records @() -Image $L -Total 0
    $j = $r.Lines -join "`n"
    T 'no process-creation record at all: SKIPPED (auditing off), never OK, raises nothing' ($r.Sev -eq 'OK' -and $j -match '^\[SKIPPED\] Copies of lsass\.exe in the Security log NOT checked -- the log holds no process-creation record' -and $j -notmatch '\[OK\]') $j
    $many = @(); for ($k = 0; $k -lt 14; $k++) { $many += (NewRec $L $L (7000 + $k) 900) }
    $r = Get-CopyEventReport -Records $many -Image $L -Total 50
    $j = $r.Lines -join "`n"
    T 'many copies: ten lines and the rest counted' (@($r.Lines | Where-Object { $_ -match '^\[CRITICAL\]' }).Count -eq 10 -and $j -match '\.\.\.and 4 more record\(s\)') $j
    $r = Get-CopyEventReport -Records @((NewRec $L $W)) -Image $L -Total 200000 -Oldest $t0 -Capped $true
    T 'a read that stopped at the cap says so' (($r.Lines -join "`n") -match '\[INFO\] Only the newest 200000 process-creation records were read') ($r.Lines -join ' | ')
    $C = 'C:\Windows\System32\cmd.exe'
    $r = Get-CopyEventReport -Records @((NewRec $C $C 5100 5000)) -Image $C -Total 3
    $j = $r.Lines -join "`n"
    T 'pointed at cmd.exe (the CI proof), cmd.exe started by cmd.exe reads as a copy without the LSASS sentence' ($r.Sev -eq 'CRITICAL' -and $j -match '\[CRITICAL\] cmd\.exe was copied at .*created by cmd\.exe \(PID 5000\) itself$' -and $j -notmatch 'LSASS') $j
    T 'process IDs read as numbers or 0x strings' ((ConvertTo-ProcessId '0x1a4') -eq 420 -and (ConvertTo-ProcessId 420) -eq 420 -and $null -eq (ConvertTo-ProcessId 'x')) ''
    $r = Get-CopyEventReport -Records @((NewRec $L ('C:\evil' + [char]10 + '[OK] fake'))) -Image $L -Total 3
    T 'a control character in a creator name cannot start a report line' ((($r.Lines -join "`n") -notmatch '(?m)^\[OK\] fake') -and @($r.Lines | Where-Object { $_ -match '[\x00-\x1F]' }).Count -eq 0) ($r.Lines -join ' | ')

    if ($fails) { Write-Output "[FAIL] $fails lsass_copy_events self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] lsass_copy_events self-test: a boot start is counted, lsass.exe created by lsass.exe is CRITICAL in any spelling, any other starter is a WARNING, a record with no creator is not cleared, and a log with no process-creation record is SKIPPED, never OK.'
    exit 0
}

if (-not $MarkerDir) { $MarkerDir = $env:TEMP }
$leaf = 'lsass.exe'
if ($Image) { $leaf = Get-LeafName $Image }
'--- [T1003.001] Copies of ' + $leaf + ' recorded in the Security log (Event 4688: ' + $leaf + ' created by ' + $leaf + ') ---'
if (-not $Image) {
    # By string, not Join-Path: Join-Path resolves the drive, and the path is
    # only ever compared, never opened.
    if (-not $env:SystemRoot) {
        '[SKIPPED] Copies of lsass.exe in the Security log NOT checked -- the Windows directory is unknown (no SystemRoot), so the path to look for cannot be built.'
        exit 0
    }
    $Image = $env:SystemRoot.TrimEnd('\') + '\System32\lsass.exe'
}

if ($Elevated -lt 0) {
    $Elevated = 0
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 }
    } catch { }
}

$records = New-Object System.Collections.ArrayList
$total = 0L; $oldest = $null; $newest = $null; $capped = $false; $unreadable = 0L
$readError = $null
try {
    # EventLogReader rather than Get-WinEvent: no message is rendered, so a
    # full Security log reads in seconds. Newest first.
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*[System[EventID=4688]]')
    $q.ReverseDirection = $true
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
    try {
        while ($true) {
            $e = $reader.ReadEvent()
            if ($null -eq $e) { break }
            try {
                $total++
                $oldest = $e.TimeCreated
                if ($null -eq $newest) { $newest = $e.TimeCreated }
                $props = $e.Properties
                # NewProcessName is field 5 in every version of 4688; the
                # creator's name (ParentProcessName) is field 13, from
                # Windows 10 on.
                if ($props.Count -gt 5 -and ([string]$props[5].Value).Trim() -ieq $Image) {
                    $pn = ''; if ($props.Count -gt 13) { $pn = [string]$props[13].Value }
                    $pp = $null; if ($props.Count -gt 7) { $pp = ConvertTo-ProcessId $props[7].Value }
                    [void]$records.Add(@{ Time = $e.TimeCreated; NewPid = (ConvertTo-ProcessId $props[4].Value); NewName = [string]$props[5].Value; ParentPid = $pp; ParentName = $pn })
                }
            } catch {
                # One record that cannot be read is counted and skipped; it
                # must not end the read (and with it every older record).
                $unreadable++
            } finally { $e.Dispose() }
            if ($total -ge $MaxRecords) { $capped = $true; break }
        }
    } finally { $reader.Dispose() }
} catch {
    $readError = $_.Exception.Message
}

if ($null -ne $readError -and $total -eq 0) {
    if ($Elevated -ne 1) {
        ('[DEFERRED - ADMIN REQUIRED] Copies of ' + $leaf + ' in the Security log: a standard-user token cannot read the Security log -- re-run as administrator.')
        Write-Marker -Name 'lsacopy_deferred' -Sev '1'
    } else {
        ('[WARNING] Copies of ' + $leaf + ' in the Security log NOT checked -- the Security log could not be read by an administrator (' + (ConvertTo-PrintableText $readError) + ').')
        Write-Marker -Name 'lsacopy_gap' -Sev 'WARNING'
    }
    exit 0
}
# A read that stopped part-way (the log wrapped under it, say) still grades
# what it read, and says where it stopped.
$stopped = ''; if ($null -ne $readError) { $stopped = $readError }
$report = Get-CopyEventReport -Records $records -Image $Image -Total $total -Oldest $oldest -Capped $capped -Newest $newest -Now (Get-Date) -StoppedBy $stopped -Unreadable $unreadable
foreach ($l in $report.Lines) { $l }
Write-Marker -Name 'lsacopy' -Sev $report.Sev
