# log_gap_check.ps1 -- detect event-log records that went missing WITHOUT a
# clear event. Invoked from Section 16 (T1070.001).
#
# WHY THIS EXISTS. Section 16 already detects an explicit wipe: Security 1102
# and System 104. But 1102 only appears when someone clears the WHOLE log. The
# quieter moves leave no such event at all:
#
#   * removing individual records from the middle of a log;
#   * shrinking MaximumSizeInBytes so ordinary activity rolls the log over and
#     erases the interesting window by itself;
#   * disabling the log outright.
#
# In every one of those cases the existing checks read a truncated log, find
# nothing, and report clean -- which is the failure this whole project keeps
# coming back to. This check asks a different question: does the log's own
# accounting add up?
#
# THE CENTREPIECE: RECORD-NUMBER ARITHMETIC.
#   For a healthy log, (newest record id - oldest SURVIVING record id + 1) ==
#   RecordCount. Circular rollover does NOT break that -- dropping the oldest
#   records raises the oldest surviving id and lowers RecordCount together, so
#   the identity holds.
#
#   Both ids come from the ACTUAL EVENTS. The config's OldestRecordNumber field
#   looks like the right source and is not: on a runner whose Application log
#   had rolled over it read 1 while the newest id was 3852 and only 142 records
#   remained, which would have reported 3710 deleted records on a healthy
#   machine. Trusting a property because of its name is how that happens.
#   Removing records from the MIDDLE does break it: the span stays wide while
#   the count falls. That asymmetry is what makes this worth checking, and it is
#   cheap: two property reads and one event read per log.
#
# WHAT THIS IS NOT. A gap is an INCONSISTENCY IN THE LOG'S OWN ACCOUNTING, not
# proof that someone deleted records. Log-service restarts, archival tooling and
# backup agents can disturb numbering too. The finding says so and says what to
# check next. Reporting a arithmetic discrepancy as proven tampering would be
# exactly the kind of confident-but-unprovable claim this tool exists not to
# make.
#
# MARKER: max severity word to $env:TEMP\dz_loggap.txt; the caller raises via
# :dz_finding. No marker when every log's accounting is consistent.
# A SECOND marker, dz_loggap_deferred.txt, holds the COUNT of checks this token
# could not perform (the Security log as a standard user); the caller adds it
# to DEFERRED_COUNT. A deferral is never a ledger row: the first standard-user
# field run raised "records missing with no clear event" for the Security log
# a standard user cannot list, with nothing printed to review.
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string[]]$LogNames = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational'),
    # Runs the gap arithmetic over fixed inputs and prints PASS/FAIL for each.
    # Selective record deletion cannot be planted safely on a runner, so this is
    # how CI proves the decision logic rather than merely that the script runs.
    # No effect on a production run; the audit never passes it.
    [switch]$SelfTest,
    # Whether this process runs elevated. Read once from the token below;
    # injectable so the self-test can grade both tokens. -1 = detect.
    [int]$Elevated = -1
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write here turns
    # a real finding into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine write failure print instead of vanishing --
    # an -EA SilentlyContinue on this write cost a field test its finding.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}
function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

# PURE DECISION FUNCTION -- no I/O, so CI can prove it over known inputs.
# Returns the number of records unaccounted for, or -1 when the inputs cannot
# support a judgement (missing/zero values). A small tolerance absorbs the
# race between reading the config and reading the newest record on a log that
# is being written to while we look at it.
function Get-RecordGap {
    param($OldestRecordId, $RecordCount, $NewestRecordId, [int]$Tolerance = 25)
    if ($null -eq $OldestRecordId -or $null -eq $RecordCount -or $null -eq $NewestRecordId) { return -1 }
    $o = [int64]$OldestRecordId; $c = [int64]$RecordCount; $n = [int64]$NewestRecordId
    if ($c -le 0 -or $n -lt $o) { return -1 }
    $span = $n - $o + 1
    $gap  = $span - $c
    if ($gap -le $Tolerance) { return 0 }
    return [int64]$gap
}


# Retention posture and the rolled-without-pressure heuristic, as PURE
# functions. Get-RecordGap below was already pure and already carries four
# must-not-raise cases (including a real CI false positive); these two rules
# had none, and "records were lost" is an alarming thing to tell someone.
function Get-RetentionVerdict {
    param([string]$Name, [double]$MaxMb, [bool]$IsSecurity)
    $r = @{ Lines = @(); Sev = 'OK' }
    $floorMb = if ($IsSecurity) { 20 } else { 10 }
    # MaxMb of 0 means the size could not be read -- not a small log.
    if ($MaxMb -gt 0 -and $MaxMb -lt $floorMb) {
        $r.Lines += "[WARNING] Event log '$Name' is capped at $MaxMb MB, below the $floorMb MB this log normally gets -- it rolls over and erases its own history quickly, with no clear event to show for it. Raise it in Event Viewer > Properties."
        $r.Sev = 'WARNING'
    }
    return $r
}

# PURE: a log the token could not even list. Elevated, a log an administrator
# cannot open is a raised gap (WARNING): the machine, not the token. As a
# standard user the Security log is unreadable BY DESIGN, so that one is
# DEFERRED -- named, counted, never a ledger row. Any OTHER log a standard user
# cannot list is still a raised gap: users can read System, Application and
# PowerShell/Operational, so their absence is not the token.
function Get-UnlistableLogVerdict {
    param([string]$Name, [bool]$IsElevated)
    if (-not $IsElevated -and $Name -eq 'Security') {
        return @{ Deferred = $true; Sev = 'OK'; Line = "[DEFERRED - ADMIN REQUIRED] Log 'Security' needs administrator rights -- gap check NOT performed for it; re-run as administrator." }
    }
    return @{ Deferred = $false; Sev = 'WARNING'; Line = "[SKIPPED] Log '$Name' could not be read -- gap check NOT performed for it (the Security log needs administrator rights)." }
}

function Get-RolloverVerdict {
    # "Records left while there was still room" is the signal. Every one of
    # these guards is a benign case in its own right: a FULL log rolled for
    # the ordinary reason, a log above the fill threshold is under genuine
    # pressure, and an oldest record predating the last boot means nothing
    # was lost since.
    param([string]$Name, $Booted, [bool]$IsLogFull, [double]$FileSize, [double]$MaxBytes, $OldestTime)
    $r = @{ Lines = @(); Sev = 'OK' }
    if (-not $Booted -or $IsLogFull -or $MaxBytes -le 0) { return $r }
    $usedPct = 100 * ($FileSize / $MaxBytes)
    if ($usedPct -ge 70) { return $r }
    if (-not $OldestTime -or $OldestTime -le $Booted) { return $r }
    $r.Lines += "[WARNING] Event log '$Name': its oldest surviving record ($($OldestTime.ToString('yyyy-MM-dd HH:mm:ss'))) is NEWER than the last boot ($($Booted.ToString('yyyy-MM-dd HH:mm:ss'))), yet the log is only $([math]::Round($usedPct))% full -- records were lost without the log running out of room."
    $r.Sev = 'WARNING'
    return $r
}

if ($SelfTest) {
    '--- log_gap_check self-test (gap arithmetic over fixed inputs) ---'
    $cases = @(
        @{ Name = 'healthy log (span == count)';              O = 1;     C = 5000;  N = 5000;  Expect = 0 },
        @{ Name = 'rolled over (oldest raised, count lower)'; O = 3001;  C = 2000;  N = 5000;  Expect = 0 },
        @{ Name = 'within tolerance (live writes)';           O = 1;     C = 4990;  N = 5000;  Expect = 0 },
        @{ Name = 'records removed from the middle';          O = 1;     C = 1000;  N = 5000;  Expect = 4000 },
        # The exact shape that produced a false positive on a CI runner when
        # this read the config's OldestRecordNumber (which said 1) instead of
        # the oldest surviving record's real id. Kept as a permanent case.
        @{ Name = 'rolled log, real oldest id (was a false positive)'; O = 3711; C = 142; N = 3852; Expect = 0 },
        @{ Name = 'unreadable RecordCount';                   O = 1;     C = $null; N = 5000;  Expect = -1 },
        @{ Name = 'zero records';                             O = 1;     C = 0;     N = 0;     Expect = -1 }
    )
    $bad = 0
    foreach ($c in $cases) {
        $got = Get-RecordGap $c.O $c.C $c.N
        if ($got -eq $c.Expect) { "[OK] {0} -> {1}" -f $c.Name, $got }
        else { "[CRITICAL] {0} -> expected {1}, got {2}" -f $c.Name, $c.Expect, $got; $bad++ }
    }
    if ($bad -gt 0) { "[CRITICAL] $bad self-test case(s) failed."; exit 2 }

    # --- retention floor -----------------------------------------------------
    # Windows' own defaults are 20 MB for Security, System and Application, so
    # the floors sit AT the default rather than above it: an untouched machine
    # must produce nothing here.
    $rt = 0
    function RT { param([string]$n, [bool]$ok, [string]$got) if ($ok) { "[OK] $n" } else { "[CRITICAL] $n -- $got"; $script:rtFails++ } }
    $script:rtFails = 0
    foreach ($c in @(
        @{ N = 'Security';    Mb = 20;  Sec = $true;  Raise = $false; Why = 'the Windows default' },
        @{ N = 'Application'; Mb = 20;  Sec = $false; Raise = $false; Why = 'the Windows default' },
        @{ N = 'System';      Mb = 20;  Sec = $false; Raise = $false; Why = 'the Windows default' },
        @{ N = 'PSOperational'; Mb = 15; Sec = $false; Raise = $false; Why = 'the PowerShell/Operational default' },
        @{ N = 'Application'; Mb = 10;  Sec = $false; Raise = $false; Why = 'exactly at the floor' },
        @{ N = 'Unreadable';  Mb = 0;   Sec = $false; Raise = $false; Why = 'size unreadable is not a small log' },
        @{ N = 'Security';    Mb = 15;  Sec = $true;  Raise = $true;  Why = 'Security below its 20 MB floor' },
        @{ N = 'Application'; Mb = 2;   Sec = $false; Raise = $true;  Why = 'starved at 2 MB' })) {
        $v = Get-RetentionVerdict -Name $c.N -MaxMb $c.Mb -IsSecurity $c.Sec
        RT ("retention: {0} MB on {1} -- {2}" -f $c.Mb, $c.N, $c.Why) (($v.Sev -eq 'WARNING') -eq $c.Raise) ("sev=$($v.Sev)")
    }

    # --- rolled without capacity pressure ------------------------------------
    $boot = [datetime]'2026-09-19T08:00:00'
    foreach ($c in @(
        @{ N = 'full log rolled for the ordinary reason';     Full = $true;  Used = 0.10; Oldest = [datetime]'2026-09-19T12:00:00'; Raise = $false },
        @{ N = 'log under genuine pressure (90% full)';       Full = $false; Used = 0.90; Oldest = [datetime]'2026-09-19T12:00:00'; Raise = $false },
        @{ N = 'oldest record predates the boot';             Full = $false; Used = 0.10; Oldest = [datetime]'2026-09-18T08:00:00'; Raise = $false },
        @{ N = 'oldest record time unreadable';               Full = $false; Used = 0.10; Oldest = $null;                           Raise = $false },
        @{ N = 'records left while there was room';           Full = $false; Used = 0.10; Oldest = [datetime]'2026-09-19T12:00:00'; Raise = $true })) {
        $v = Get-RolloverVerdict -Name 'System' -Booted $boot -IsLogFull $c.Full -FileSize ($c.Used * 1000) -MaxBytes 1000 -OldestTime $c.Oldest
        RT ("rollover: {0}" -f $c.N) (($v.Sev -eq 'WARNING') -eq $c.Raise) ("sev=$($v.Sev)")
    }
    # No boot time means the heuristic cannot run; it must stay silent rather
    # than assume.
    $v = Get-RolloverVerdict -Name 'System' -Booted $null -IsLogFull $false -FileSize 100 -MaxBytes 1000 -OldestTime ([datetime]'2026-09-19T12:00:00')
    RT 'rollover: no boot time is silence, not a finding' ($v.Sev -eq 'OK') ("sev=$($v.Sev)")

    # --- a log the token cannot list --------------------------------------
    # The standard-user field run 2026-09-24 21:03: Security unlistable as a
    # standard user was raised as "records missing with no clear event".
    $v = Get-UnlistableLogVerdict -Name 'Security' -IsElevated $false
    RT 'unlistable: Security as a standard user is DEFERRED (the token, not the machine) -- no raise' ($v.Deferred -and $v.Sev -eq 'OK' -and $v.Line -match "^\[DEFERRED - ADMIN REQUIRED\] Log 'Security'") ("sev=$($v.Sev) line=$($v.Line)")
    $v = Get-UnlistableLogVerdict -Name 'Security' -IsElevated $true
    RT 'unlistable: Security while ELEVATED is a raised gap (WARNING), never a deferral' ((-not $v.Deferred) -and $v.Sev -eq 'WARNING' -and $v.Line -match '^\[SKIPPED\]') ("sev=$($v.Sev)")
    $v = Get-UnlistableLogVerdict -Name 'System' -IsElevated $false
    RT 'unlistable: System as a standard user is a raised gap -- users can read System, so its absence is not the token' ((-not $v.Deferred) -and $v.Sev -eq 'WARNING') ("sev=$($v.Sev)")
    if ($script:rtFails -gt 0) { "[CRITICAL] $($script:rtFails) retention/rollover case(s) failed."; exit 2 }
    '[OK] Gap arithmetic, the retention floor and the rolled-without-pressure heuristic all behave on fixed inputs.'
    exit 0
}

if ($Elevated -lt 0) {
    $Elevated = 0
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 }
    } catch {}
}

'--- [T1070.001] Event-log gap check (records missing with no clear event) ---'
$sev = 'OK'
$inspected = 0
$deferred = 0

# Last boot: a log whose oldest surviving record post-dates the boot, while the
# log is nowhere near full, lost records without capacity pressure.
$booted = $null
try { $booted = (Get-CimInstance Win32_OperatingSystem -EA Stop).LastBootUpTime } catch {}

foreach ($name in $LogNames) {
    $cfg = $null
    try { $cfg = Get-WinEvent -ListLog $name -EA Stop } catch {}
    if (-not $cfg) {
        $uv = Get-UnlistableLogVerdict -Name $name -IsElevated ($Elevated -eq 1)
        $uv.Line
        if ($uv.Deferred) { $deferred++ } else { $sev = Get-MaxSev $sev $uv.Sev }
        continue
    }
    $inspected++
    $isSecurity = ($name -eq 'Security')

    if (-not $cfg.IsEnabled) {
        $s = if ($isSecurity) { 'CRITICAL' } else { 'WARNING' }
        "[$s] Event log '$name' is DISABLED -- nothing is being recorded, so every event-based check against it is blind (T1070.001). Re-enable it in Event Viewer > Properties."
        $sev = Get-MaxSev $sev $s
        continue
    }

    # Read the oldest and newest record ids from the ACTUAL EVENTS, not from
    # the config's OldestRecordNumber field.
    #
    # OldestRecordNumber does NOT reliably track the oldest surviving record: on
    # a runner whose Application log had rolled over it read 1 while the newest
    # id was 3852 and only 142 records were present, which made this check
    # report 3710 deleted records on a perfectly healthy machine. CI caught it.
    # The events themselves are authoritative, and asking for one record from
    # each end costs no more than the boot-time read below already does.
    $newest = $null
    $oldest = $null
    try { $newest = (Get-WinEvent -LogName $name -MaxEvents 1 -EA Stop).RecordId } catch {}
    try { $oldest = (Get-WinEvent -LogName $name -MaxEvents 1 -Oldest -EA Stop).RecordId } catch {}

    $gap = Get-RecordGap $oldest $cfg.RecordCount $newest
    if ($gap -lt 0) {
        "[SKIPPED] Log '$name': record accounting unavailable (RecordCount or record ids unreadable) -- gap check NOT performed for it."
        $sev = Get-MaxSev $sev 'WARNING'
    } elseif ($gap -gt 0) {
        $s = if ($isSecurity) { 'CRITICAL' } else { 'WARNING' }
        "[$s] Event log '$name': $gap record(s) are missing from the middle of its numbering (oldest surviving #$oldest, newest #$newest, but only $($cfg.RecordCount) present). Normal rollover does NOT cause this -- dropping the oldest records lowers the count and raises the oldest number together. Selective deletion does (T1070.001), and it leaves no 1102 clear event."
        '  what this is: an inconsistency in the log''s own accounting, not proof of deletion. Log-service restarts and some backup/archival tools can also disturb numbering.'
        '  what to check next: whether a 1102/104 clear event exists above, and whether a SIEM, log-forwarding or backup copy of this log covers the missing range.'
        $sev = Get-MaxSev $sev $s
    } else {
        "[OK] Event log '$name': record numbering is consistent ($($cfg.RecordCount) records, #$oldest-#$newest)."
    }

    # Retention posture. An undersized log erases its own history under ordinary
    # activity -- a quieter way to lose the interesting window than clearing it.
    $maxMb = 0
    try { $maxMb = [math]::Round($cfg.MaximumSizeInBytes / 1MB, 1) } catch {}
    $rv = Get-RetentionVerdict -Name $name -MaxMb $maxMb -IsSecurity $isSecurity
    foreach ($l in $rv.Lines) { $l }
    $sev = Get-MaxSev $sev $rv.Sev

    # Rolled without capacity pressure: records left while there was room.
    # The oldest-record read stays here (it needs the live log); the RULE is
    # in Get-RolloverVerdict, whose every guard is itself a benign case.
    $oldestTime = $null
    if ($booted -and -not $cfg.IsLogFull -and $cfg.MaximumSizeInBytes -gt 0) {
        try { $oldestTime = (Get-WinEvent -LogName $name -MaxEvents 1 -Oldest -EA Stop).TimeCreated } catch {}
    }
    $fs = 0
    try { $fs = [double]$cfg.FileSize } catch {}
    $mb = 0
    try { $mb = [double]$cfg.MaximumSizeInBytes } catch {}
    $ov = Get-RolloverVerdict -Name $name -Booted $booted -IsLogFull ([bool]$cfg.IsLogFull) -FileSize $fs -MaxBytes $mb -OldestTime $oldestTime
    foreach ($l in $ov.Lines) { $l }
    $sev = Get-MaxSev $sev $ov.Sev

    if ($cfg.LogMode -and $cfg.LogMode -ne 'Circular') {
        "[INFO] Event log '$name' uses LogMode $($cfg.LogMode) (archives rather than overwrites), so its record accounting differs from the circular case above."
    }
}

if ($inspected -eq 0) {
    '[SKIPPED] No event logs could be inspected -- the gap check verified nothing.'
    $sev = Get-MaxSev $sev 'WARNING'
} else {
    "[INFO] $inspected event log(s) inspected for missing-record gaps."
}

Write-Marker -Name 'loggap' -Sev $sev
if ($deferred -gt 0) { Write-Marker -Name 'loggap_deferred' -Sev ([string]$deferred) }
