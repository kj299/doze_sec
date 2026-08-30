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
    [switch]$SelfTest
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
    '[OK] Gap arithmetic behaves correctly on all fixed cases.'
    exit 0
}

'--- [T1070.001] Event-log gap check (records missing with no clear event) ---'
$sev = 'OK'
$inspected = 0

# Last boot: a log whose oldest surviving record post-dates the boot, while the
# log is nowhere near full, lost records without capacity pressure.
$booted = $null
try { $booted = (Get-CimInstance Win32_OperatingSystem -EA Stop).LastBootUpTime } catch {}

foreach ($name in $LogNames) {
    $cfg = $null
    try { $cfg = Get-WinEvent -ListLog $name -EA Stop } catch {}
    if (-not $cfg) {
        "[SKIPPED] Log '$name' could not be read -- gap check NOT performed for it (the Security log needs administrator rights)."
        $sev = Get-MaxSev $sev 'WARNING'
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
    $floorMb = if ($isSecurity) { 20 } else { 10 }
    if ($maxMb -gt 0 -and $maxMb -lt $floorMb) {
        "[WARNING] Event log '$name' is capped at $maxMb MB, below the $floorMb MB this log normally gets -- it rolls over and erases its own history quickly, with no clear event to show for it. Raise it in Event Viewer > Properties."
        $sev = Get-MaxSev $sev 'WARNING'
    }

    # Rolled without capacity pressure: records left while there was room.
    if ($booted -and -not $cfg.IsLogFull -and $cfg.MaximumSizeInBytes -gt 0) {
        $usedPct = 0
        try { $usedPct = 100 * ($cfg.FileSize / $cfg.MaximumSizeInBytes) } catch {}
        if ($usedPct -lt 70) {
            $oldestTime = $null
            try { $oldestTime = (Get-WinEvent -LogName $name -MaxEvents 1 -Oldest -EA Stop).TimeCreated } catch {}
            if ($oldestTime -and $oldestTime -gt $booted) {
                "[WARNING] Event log '$name': its oldest surviving record ($($oldestTime.ToString('yyyy-MM-dd HH:mm:ss'))) is NEWER than the last boot ($($booted.ToString('yyyy-MM-dd HH:mm:ss'))), yet the log is only $([math]::Round($usedPct))% full -- records were lost without the log running out of room."
                $sev = Get-MaxSev $sev 'WARNING'
            }
        }
    }

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
