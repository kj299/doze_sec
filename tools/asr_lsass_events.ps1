# asr_lsass_events.ps1 -- Defender's own record of a program trying to read
# LSASS memory (T1003.001). Section 12.
#
# WHY. Defender's attack-surface-reduction rule "Block credential stealing from
# the Windows local security authority subsystem"
# (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2) writes an event every time it blocks
# or observes such an access. Microsoft documents that this rule raises NO EDR
# alert and NO user notification and has no Warn mode, so the local event log
# is the only place the owner can see it happened -- and nothing in this audit
# read that log before now.
#
#   Event 1121 = blocked (the rule is in Block mode)
#   Event 1122 = audited only (the rule is in Audit mode: recorded, NOT blocked)
#   both in Microsoft-Windows-Windows Defender/Operational
#
# WHICH FIELD HOLDS THE ACCESSING PROGRAM IS NOT FIXED. In a real captured 1121
# for this rule, `Process Name` held C:\Windows\System32\lsass.exe and `Path`
# held the accessing program -- the REVERSE of the public SigmaHQ rule, which
# matches `Path` ending in \lsass.exe. For the Office rules in the same capture
# the roles are the other way round. So this check takes whichever of the two
# is not lsass.exe as the accessor, and when neither is, prints both and says
# it could not tell them apart rather than guessing. Both orders are pinned as
# self-test cases, from that capture, verbatim.
#
# A RECORD IS WORTH READING, NOT AN EMERGENCY. Microsoft's own rule reference
# says "Many processes make unnecessary calls to LSASS for access rights that
# aren't needed... For example, Google Chrome updates unnecessarily access
# LSASS", and the accessor in the captured event is OneDrive's updater. So this
# is a WARNING naming the program, grouped and counted -- never CRITICAL, which
# would teach the reader to ignore the one check Defender gives them here.
#
# NO RECORD IS NOT AN ALL-CLEAR. The rule writes nothing while it is off or not
# configured, so the mode decides what an empty log means. It is MEASURED ONCE,
# in Section 9's ASR block, and passed in as -RuleMode: a second Get-MpPreference
# here would be a second opinion, not a summary (CLAUDE.md, "a tile that
# re-measures"). Off or not configured -> [SKIPPED], raising nothing, pointing
# at the row Section 9 already raises for the rule's state.
#
# AND AN EXCLUSION HIDES ACCESSES. Microsoft documents that this rule ignores
# antivirus file exclusions but honours ASR per-rule exclusions, so a program
# excluded here can read LSASS leaving no event at all -- the contents are
# printed and raised.
#
# MARKERS: dz_asrlsass.txt (highest severity), dz_asrlsass_gap.txt (the channel
# could not be read by an administrator; its own ledger row),
# dz_asrlsass_deferred.txt (a count a standard-user token could not perform,
# added to DEFERRED_COUNT, never a ledger row).
#
# Read-only. Windows PowerShell 5.1 and pwsh. Pure ASCII.

[CmdletBinding()]
param(
    [string]$MarkerDir = '',
    # block | audit | off | notconfigured | ungraded, measured in Section 9.
    [string]$RuleMode = 'ungraded',
    [string]$RuleId = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
    [int]$MaxRecords = 20000,
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

function Format-When {
    param($t)
    if ($null -eq $t) { return 'an unknown time' }
    return (([datetime]$t).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z')
}

# PURE: which of the two fields names the program that tried to read LSASS.
# Returns @{ Accessor; Certain }. Certain is $false when neither field is
# lsass.exe, and then Accessor holds both, said as unresolved.
function Get-AsrAccessor {
    param([string]$Path, [string]$ProcessName)
    $p = ([string]$Path).Trim()
    $n = ([string]$ProcessName).Trim()
    $pIsTarget = ($p -like '*\lsass.exe')
    $nIsTarget = ($n -like '*\lsass.exe')
    # The OTHER field must actually name something: an event that holds
    # lsass.exe and nothing else would otherwise produce a WARNING naming
    # nobody -- and that line does not even match the contract written to
    # protect it, so no gate would have caught it.
    if ($nIsTarget -and -not $pIsTarget -and $p) { return @{ Accessor = $p; Certain = $true } }
    if ($pIsTarget -and -not $nIsTarget -and $n) { return @{ Accessor = $n; Certain = $true } }
    if ($pIsTarget -and $nIsTarget) { return @{ Accessor = ''; Certain = $false } }
    # Neither names lsass.exe: the event's own fields do not say which side is
    # which, so both are reported rather than one of them guessed at.
    return @{ Accessor = ''; Certain = $false }
}

# PURE: the records, graded.
#   Records     @( @{ Time; Id; RuleId; Path; ProcessName; CommandLine; User } )
#   RuleMode    block | audit | off | notconfigured | ungraded
#   Exclusions  @( 'path or program excluded from THIS rule' )
#   Total       how many 1121/1122 records were read in all (any rule)
#   Oldest/Newest  the span the log covers, or $null
#   ReadError   the channel could not be read ('' when it was)
function Get-AsrEventReport {
    param($Records, [string]$RuleMode = 'ungraded', $Exclusions = @(), [long]$Total = 0,
          $Oldest = $null, $Newest = $null, [string]$ReadError = '', [bool]$IsElevated = $true,
          [long]$Unreadable = 0, [bool]$Truncated = $false, [string]$ExclusionError = '')
    $out = New-Object System.Collections.ArrayList
    $sev = 'OK'; $gapSev = 'OK'; $deferred = 0
    $ruleName = 'Defender''s rule against reading LSASS memory ("Block credential stealing from the Windows local security authority subsystem")'

    # An exclusion on this rule lets a program read LSASS leaving no record, so
    # it is graded whatever the rule's mode is.
    $exc = @(@($Exclusions) | Where-Object { ([string]$_).Trim() })
    foreach ($e in $exc) {
        [void]$out.Add(('[WARNING] ' + (ConvertTo-PrintableText ([string]$e)) + ' is EXCLUDED from ' + $ruleName + ' -- it can read LSASS memory and leave no record here. Microsoft documents that this rule ignores antivirus file exclusions but honours its own per-rule exclusions (T1562.001).'))
        $sev = 'WARNING'
    }

    # An exclusion list that could not be read is the one state in which an
    # empty log proves nothing at all, so it is said before anything else.
    if ($ExclusionError) {
        [void]$out.Add(('[WARNING] The programs excluded from ' + $ruleName + ' were NOT checked -- the exclusion list could not be read (' + (ConvertTo-PrintableText $ExclusionError) + '). An excluded program can read LSASS memory and leave no record here.'))
        $gapSev = 'WARNING'
    }
    $mode = ([string]$RuleMode).Trim().ToLowerInvariant()
    $known = @('block', 'audit', 'warn', 'off', 'notconfigured', 'ungraded')
    if ($known -notcontains $mode) {
        # An unrecognised mode is not assumed to be blocking: that wording
        # would claim protection this check cannot see.
        [void]$out.Add(('[WARNING] ' + $ruleName + ' records NOT checked -- Section 9 reported its mode as ''' + (ConvertTo-PrintableText $mode) + ''', which this check does not recognise, so what an empty log means here cannot be said.'))
        $gapSev = 'WARNING'
        return @{ Lines = @($out.ToArray()); Sev = $sev; GapSev = $gapSev; Deferred = $deferred; Hits = 0 }
    }
    if ($mode -eq 'off' -or $mode -eq 'notconfigured' -or $mode -eq 'ungraded') {
        $why = switch ($mode) {
            'off'           { 'the rule is turned OFF' }
            'notconfigured' { 'the rule is not configured' }
            default         { 'Section 9 did not grade the rule''s state' }
        }
        # The mode is decided BEFORE the channel is considered: with the rule
        # off there is nothing in the log whether or not this token could read
        # it, and reporting a gap or a deferral for a log that would be empty
        # anyway overstates what is missing.
        [void]$out.Add(('[SKIPPED] ' + $ruleName + ' records NOT checked -- ' + $why + ', so nothing is written here and an empty log means nothing. Section 9 reports the rule''s state; turning it on is what makes this evidence exist.'))
        return @{ Lines = @($out.ToArray()); Sev = $sev; GapSev = $gapSev; Deferred = $deferred; Hits = 0 }
    }

    # A read that failed part-way still grades what it read: returning here
    # would throw away the records already in hand, including the one naming
    # the program. The gap is added beside them, never instead of them.
    if ($ReadError) {
        if ($IsElevated) {
            [void]$out.Add(('[WARNING] ' + $ruleName + ': its records were NOT checked, or only partly -- the Defender Operational log could not be read (' + (ConvertTo-PrintableText $ReadError) + '). Anything found before it stopped is below.'))
            $gapSev = 'WARNING'
        } else {
            [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] ' + $ruleName + ': the Defender Operational log is not readable from a standard-user token (' + (ConvertTo-PrintableText $ReadError) + ') -- re-run as administrator.'))
            $deferred = 1
        }
    }

    # Group by the accessing program: one line per program, with a count and
    # the newest time, rather than one line per event.
    $groups = @{}
    $unresolved = New-Object System.Collections.ArrayList
    $hits = 0
    foreach ($r in @($Records)) {
        if ($null -eq $r) { continue }
        $hits++
        $a = Get-AsrAccessor -Path ([string]$r.Path) -ProcessName ([string]$r.ProcessName)
        if (-not $a.Certain) {
            [void]$unresolved.Add($r)
            continue
        }
        $key = $a.Accessor
        # 'Hits', not 'Count': a hashtable has a Count property of its own, and
        # on an engine that resolved the property instead of the key every group
        # would sort equal and "the busiest first" would be arbitrary.
        if (-not $groups.ContainsKey($key)) { $groups[$key] = @{ Hits = 0; Newest = $null; Blocked = 0; Audited = 0; User = '' } }
        $g = $groups[$key]
        $g.Hits++
        if ([int]$r.Id -eq 1121) { $g.Blocked++ } else { $g.Audited++ }
        if ($null -eq $g.Newest -or ($null -ne $r.Time -and [datetime]$r.Time -gt [datetime]$g.Newest)) { $g.Newest = $r.Time }
        if (-not $g.User -and ([string]$r.User).Trim()) { $g.User = ([string]$r.User).Trim() }
    }

    $cap = 10
    $i = 0
    foreach ($key in @($groups.Keys | Sort-Object { -($groups[$_]['Hits']) })) {
        $i++
        if ($i -gt $cap) { break }
        $g = $groups[$key]
        $what = ''
        if ($g.Blocked -gt 0 -and $g.Audited -gt 0) {
            $what = $g.Blocked.ToString() + ' blocked and ' + $g.Audited.ToString() + ' recorded but NOT blocked (the rule was in audit mode)'
        } elseif ($g.Blocked -gt 0) {
            $what = $g.Blocked.ToString() + ' blocked by Defender'
        } else {
            $what = $g.Audited.ToString() + ' recorded but NOT blocked -- the rule is in audit mode, so the access went through'
        }
        $who = ''
        if ($g.User) { $who = ', running as ' + (ConvertTo-PrintableText $g.User) }
        [void]$out.Add(('[WARNING] ' + (ConvertTo-PrintableText $key) + ' tried to read LSASS memory: ' + $what + $who + ', most recently ' + (Format-When $g.Newest) + ' (T1003.001).'))
        $sev = 'WARNING'
    }
    if ($groups.Keys.Count -gt $cap) {
        [void]$out.Add(('    ...and ' + ($groups.Keys.Count - $cap) + ' more program(s) of the same shape.'))
    }
    # Grouped and capped like the lines above: a provider that writes a bare
    # image name would otherwise put one line in the report per event, up to
    # every record in the channel, for one ledger row.
    $ugroups = @{}
    foreach ($r in @($unresolved)) {
        $uk = ([string]$r.Path) + '|' + ([string]$r.ProcessName)
        if (-not $ugroups.ContainsKey($uk)) { $ugroups[$uk] = @{ Hits = 0; Newest = $null; Path = [string]$r.Path; ProcessName = [string]$r.ProcessName } }
        $ug = $ugroups[$uk]
        $ug.Hits++
        if ($null -eq $ug.Newest -or ($null -ne $r.Time -and [datetime]$r.Time -gt [datetime]$ug.Newest)) { $ug.Newest = $r.Time }
    }
    $i = 0
    foreach ($uk in @($ugroups.Keys | Sort-Object { -($ugroups[$_]['Hits']) })) {
        $i++
        if ($i -gt $cap) { break }
        $ug = $ugroups[$uk]
        $times = 'once'
        if ($ug.Hits -gt 1) { $times = [string]$ug.Hits + ' times' }
        [void]$out.Add(('[WARNING] A program tried to read LSASS memory ' + $times + ', most recently ' + (Format-When $ug.Newest) + ', and the event does not say which of its two fields names it -- Path = ' + (ConvertTo-PrintableText $ug.Path) + ', Process Name = ' + (ConvertTo-PrintableText $ug.ProcessName) + '. Both are reported rather than one of them guessed at (T1003.001).'))
        $sev = 'WARNING'
    }
    if ($ugroups.Keys.Count -gt $cap) {
        [void]$out.Add(('    ...and ' + ($ugroups.Keys.Count - $cap) + ' more pair(s) of the same shape.'))
    }
    if ($Unreadable -gt 0) {
        [void]$out.Add(('[WARNING] ' + $Unreadable + ' record(s) in the Defender log could not be read and were skipped -- NOT graded, not cleared.'))
        $gapSev = 'WARNING'
    }
    if ($Truncated) {
        [void]$out.Add(('[INFO] Only the newest ' + $Total + ' attack-surface-reduction record(s) were read; older ones were not.'))
    }

    # The all-clear is withheld whenever the read failed or was deferred: "I
    # could not read the log" and "no program tried" must never print together.
    if ($sev -eq 'OK' -and -not $ReadError -and $Unreadable -eq 0) {
        $span = 'the records read'
        if ($null -ne $Oldest -and $null -ne $Newest) { $span = 'from ' + (Format-When $Oldest) + ' to ' + (Format-When $Newest) }
        elseif ($null -ne $Oldest) { $span = 'back to ' + (Format-When $Oldest) }
        $modeText = 'blocking'
        if ($mode -eq 'audit') { $modeText = 'in audit mode (it records such attempts without blocking them)' }
        if ($mode -eq 'warn') { $modeText = 'in warn mode (it asks the person at the keyboard, who can allow it; Microsoft documents that this rule does not support warn mode)' }
        [void]$out.Add(('[OK] No program tried to read LSASS memory: ' + $ruleName + ' is ' + $modeText + ', and none of the ' + $Total + ' attack-surface-reduction record(s) in the Defender log, ' + $span + ', names it.'))
    }
    return @{ Lines = @($out.ToArray()); Sev = $sev; GapSev = $gapSev; Deferred = $deferred; Hits = $hits }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $L = 'C:\Windows\System32\lsass.exe'
    $t0 = New-Object DateTime 2026, 10, 2, 9, 0, 0, ([DateTimeKind]::Utc)
    function NewRec { param([string]$path, [string]$proc, [int]$id = 1121, $t = $t0, [string]$user = 'NT AUTHORITY\SYSTEM')
        @{ Time = $t; Id = $id; RuleId = '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'; Path = $path; ProcessName = $proc; CommandLine = ''; User = $user } }

    # The field order of a REAL captured 1121 for this rule: Process Name is
    # lsass.exe and Path is the accessing program.
    $one = 'C:\Program Files (x86)\Microsoft OneDrive\OneDriveStandaloneUpdater.exe'
    $r = Get-AsrEventReport -Records @((NewRec $one $L)) -RuleMode 'block' -Total 7 -Oldest $t0 -Newest $t0
    $j = $r.Lines -join "`n"
    T 'the real captured field order (Process Name = lsass.exe, Path = the program) names the program, not lsass.exe' ($r.Sev -eq 'WARNING' -and $j -cmatch ('^\[WARNING\] ' + [regex]::Escape($one) + ' tried to read LSASS memory: 1 blocked by Defender, running as NT AUTHORITY\\SYSTEM, most recently 2026-10-02 09:00:00Z \(T1003\.001\)\.$')) $j
    # The other order, which the public rule assumes.
    $r = Get-AsrEventReport -Records @((NewRec $L $one)) -RuleMode 'block' -Total 7
    T 'the reversed order (Path = lsass.exe) names the same program -- neither field is trusted to be the accessor' ($r.Sev -eq 'WARNING' -and ($r.Lines -join "`n") -match ([regex]::Escape($one) + ' tried to read LSASS memory')) ($r.Lines -join ' | ')
    T 'the accessor is picked by which field is NOT lsass.exe, in either order' ((Get-AsrAccessor -Path $one -ProcessName $L).Accessor -eq $one -and (Get-AsrAccessor -Path $L -ProcessName $one).Accessor -eq $one -and (Get-AsrAccessor -Path $one -ProcessName $L).Certain -and (Get-AsrAccessor -Path $L -ProcessName $one).Certain) ''
    T 'a lowercase or 8.3-style spelling of the target still resolves' ((Get-AsrAccessor -Path 'c:\windows\system32\LSASS.EXE' -ProcessName $one).Accessor -eq $one) ''

    # Neither field names lsass.exe: say so, do not guess.
    $r = Get-AsrEventReport -Records @((NewRec 'C:\a\x.exe' 'C:\b\y.exe')) -RuleMode 'block' -Total 3
    $j = $r.Lines -join "`n"
    T 'when neither field names lsass.exe, both are printed and the line says it could not tell them apart' ($r.Sev -eq 'WARNING' -and $j -match 'does not say which of its two fields names it -- Path = C:\\a\\x\.exe, Process Name = C:\\b\\y\.exe' -and $j -match 'rather than one of them guessed at') $j
    T 'both fields naming lsass.exe is also unresolved, never reported as lsass accessing itself' ((Get-AsrAccessor -Path $L -ProcessName $L).Certain -eq $false) ''

    # Audit mode: recorded but NOT blocked. The wording must say so.
    $r = Get-AsrEventReport -Records @((NewRec $one $L 1122)) -RuleMode 'audit' -Total 4
    $j = $r.Lines -join "`n"
    T 'an audit-mode record says the access was NOT blocked' ($r.Sev -eq 'WARNING' -and $j -match '1 recorded but NOT blocked -- the rule is in audit mode, so the access went through') $j
    $r = Get-AsrEventReport -Records @((NewRec $one $L 1121 $t0), (NewRec $one $L 1122 $t0.AddHours(1))) -RuleMode 'block' -Total 4
    $j = $r.Lines -join "`n"
    T 'blocked and audited records for one program make ONE line that counts both, with the newer time' (@($r.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 1 -and $j -match '1 blocked and 1 recorded but NOT blocked \(the rule was in audit mode\)' -and $j -match 'most recently 2026-10-02 10:00:00Z') $j
    T 'every record this self-test builds is a record (a call that threw would make a case pass for the wrong reason)' ((NewRec $one $L 1122 $t0) -ne $null -and (NewRec $one $L 1122 $t0).Id -eq 1122 -and (NewRec $one $L).Id -eq 1121) ''

    # Grouping, ordering and the cap.
    $many = @()
    foreach ($k in 1..12) { $many += (NewRec ('C:\p\prog' + $k + '.exe') $L) }
    $many += (NewRec 'C:\p\prog1.exe' $L)
    $r = Get-AsrEventReport -Records $many -RuleMode 'block' -Total 99
    $j = $r.Lines -join "`n"
    T 'one line per program, the busiest first, the rest counted' (@($r.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 10 -and $j -match '\.\.\.and 2 more program\(s\)' -and ($j -split "`n")[0] -match 'prog1\.exe tried to read LSASS memory: 2 blocked') $j

    # Nothing recorded, with the mode deciding what that means.
    $r = Get-AsrEventReport -Records @() -RuleMode 'block' -Total 31 -Oldest $t0 -Newest $t0.AddDays(5)
    $j = $r.Lines -join "`n"
    T 'no record while the rule blocks: OK, naming the span the log covers' ($r.Sev -eq 'OK' -and $j -cmatch '^\[OK\] No program tried to read LSASS memory: .* is blocking, and none of the 31 attack-surface-reduction record\(s\) in the Defender log, from 2026-10-02 09:00:00Z to 2026-10-07 09:00:00Z, names it\.$') $j
    $r = Get-AsrEventReport -Records @() -RuleMode 'audit' -Total 2
    T 'no record while the rule only audits says so, rather than implying it was blocking' ($r.Sev -eq 'OK' -and ($r.Lines -join "`n") -match 'in audit mode \(it records such attempts without blocking them\)') ($r.Lines -join ' | ')
    foreach ($m in @('off', 'notconfigured', 'ungraded')) {
        $r = Get-AsrEventReport -Records @() -RuleMode $m -Total 0
        $j = $r.Lines -join "`n"
        T ('with the rule ' + $m + ', an empty log is [SKIPPED] and raises nothing -- never an all-clear') ($r.Sev -eq 'OK' -and $r.GapSev -eq 'OK' -and $j -cmatch '^\[SKIPPED\] ' -and $j -match 'an empty log means nothing' -and $j -notmatch '\[OK\]') $j
    }
    T 'a record found while the rule reads off is still not graded from this log (Section 9 owns the state)' ((Get-AsrEventReport -Records @((NewRec $one $L)) -RuleMode 'off' -Total 1).Sev -eq 'OK') ''

    # An exclusion hides accesses, whatever the mode.
    $r = Get-AsrEventReport -Records @() -RuleMode 'block' -Exclusions @('C:\tools\grabber.exe') -Total 5
    $j = $r.Lines -join "`n"
    T 'a per-rule exclusion is a WARNING naming the excluded program, and the all-clear line is withheld' ($r.Sev -eq 'WARNING' -and $j -match '^\[WARNING\] C:\\tools\\grabber\.exe is EXCLUDED from ' -and $j -notmatch '\[OK\]') $j
    $r = Get-AsrEventReport -Records @() -RuleMode 'off' -Exclusions @('C:\tools\grabber.exe') -Total 0
    T 'an exclusion is graded even when the rule is off (the [SKIPPED] line still follows)' ($r.Sev -eq 'WARNING' -and ($r.Lines -join "`n") -match 'EXCLUDED from ' -and ($r.Lines -join "`n") -match '\[SKIPPED\]') ($r.Lines -join ' | ')
    $r = Get-AsrEventReport -Records @() -RuleMode 'block' -Exclusions @('', '   ') -Total 5
    T 'a blank exclusion value is not an exclusion' ($r.Sev -eq 'OK') ($r.Lines -join ' | ')

    $r = Get-AsrEventReport -Records @() -RuleMode 'off' -ReadError 'EventLog access is not supported on this platform.'
    $j = $r.Lines -join "`n"
    T 'with the rule off, an unreadable log is not a gap either: there would be nothing in it to read' ($r.GapSev -eq 'OK' -and $r.Deferred -eq 0 -and $j -cmatch '^\[SKIPPED\] ' -and $j -notmatch 'could not be read' -and $j -notmatch 'DEFERRED') $j
    T 'but an exclusion is still raised when the rule is off and the log unreadable' ((Get-AsrEventReport -Records @() -RuleMode 'off' -ReadError 'x' -Exclusions @('C:\t\g.exe')).Sev -eq 'WARNING') ''

    # The channel itself.
    $r = Get-AsrEventReport -Records @() -RuleMode 'block' -ReadError 'The specified channel could not be found.'
    $j = $r.Lines -join "`n"
    T 'elevated, an unreadable Defender log is a raised gap, never an all-clear' ($r.Sev -eq 'OK' -and $r.GapSev -eq 'WARNING' -and $j -match 'NOT checked, or only partly -- the Defender Operational log could not be read' -and $j -notmatch '\[OK\]') $j
    # A read that stopped PART-WAY: what it did find must survive.
    $r = Get-AsrEventReport -Records @((NewRec 'C:\x\grab.exe' $L)) -RuleMode 'block' -Total 9 -ReadError 'The handle is invalid.'
    $j = $r.Lines -join "`n"
    T 'a read that failed part-way keeps the program it already found, and still declares the gap' ($r.Sev -eq 'WARNING' -and $r.GapSev -eq 'WARNING' -and $r.Hits -eq 1 -and $j -match 'C:\\x\\grab\.exe tried to read LSASS memory' -and $j -match 'only partly' -and $j -notmatch '\[OK\]') $j
    $r = Get-AsrEventReport -Records @() -RuleMode 'block' -Total 9 -Unreadable 4
    $j = $r.Lines -join "`n"
    T 'records that could not be read are declared as not graded, and withhold the all-clear' ($r.GapSev -eq 'WARNING' -and $j -match '\[WARNING\] 4 record\(s\) in the Defender log could not be read and were skipped -- NOT graded, not cleared' -and $j -notmatch '\[OK\]') $j
    $r = Get-AsrEventReport -Records @() -RuleMode 'block' -Total 20000 -Truncated $true -Oldest $t0 -Newest $t0
    T 'a read that stopped at the cap says so, and may still print the all-clear for what it read' ($r.Sev -eq 'OK' -and ($r.Lines -join "`n") -match '\[INFO\] Only the newest 20000 attack-surface-reduction record\(s\) were read' -and ($r.Lines -join "`n") -match '\[OK\]') ($r.Lines -join ' | ')
    $r = Get-AsrEventReport -Records @() -RuleMode 'block' -ExclusionError 'Requested registry access is not allowed.'
    $j = $r.Lines -join "`n"
    T 'an exclusion list that could not be read is a raised gap and withholds nothing it cannot claim' ($r.GapSev -eq 'WARNING' -and $j -match 'The programs excluded from .* were NOT checked' -and $j -match 'can read LSASS memory and leave no record here') $j
    $r = Get-AsrEventReport -Records @() -RuleMode 'enforced' -Total 3
    $j = $r.Lines -join "`n"
    T 'a mode this check does not recognise is a declared gap, never assumed to be blocking' ($r.GapSev -eq 'WARNING' -and $j -match 'which this check does not recognise' -and $j -notmatch 'is blocking' -and $j -notmatch '\[OK\]') $j
    $r = Get-AsrEventReport -Records @() -RuleMode 'warn' -Total 3 -Oldest $t0 -Newest $t0
    T 'warn mode has its own wording and is never called blocking' ($r.Sev -eq 'OK' -and ($r.Lines -join "`n") -match 'in warn mode \(it asks the person at the keyboard' -and ($r.Lines -join "`n") -notmatch 'is blocking') ($r.Lines -join ' | ')
    T 'an event naming lsass.exe and nothing else names nobody as the accessor: unresolved, not a blank WARNING' ((Get-AsrAccessor -Path '' -ProcessName $L).Certain -eq $false -and (Get-AsrAccessor -Path $L -ProcessName '  ').Certain -eq $false) ''
    $r = Get-AsrEventReport -Records @((NewRec '' $L)) -RuleMode 'block' -Total 1
    $j = $r.Lines -join "`n"
    T 'such an event prints both fields rather than a WARNING naming nobody' ($j -notmatch '\[WARNING\]\s+tried to read' -and $j -match 'does not say which of its two fields names it') $j
    $many2 = @()
    foreach ($k in 1..13) { $many2 += (NewRec ('bare' + $k + '.exe') 'alsobare.exe') }
    $r = Get-AsrEventReport -Records $many2 -RuleMode 'block' -Total 13
    T 'unresolved lines are grouped and capped too: a provider writing bare names cannot fill the report' (@($r.Lines | Where-Object { $_ -match 'does not say which of its two fields' }).Count -eq 10 -and ($r.Lines -join "`n") -match '\.\.\.and 3 more pair\(s\)') ($r.Lines -join ' | ')
    $r = Get-AsrEventReport -Records @((NewRec 'bare.exe' 'alsobare.exe'), (NewRec 'bare.exe' 'alsobare.exe'), (NewRec 'bare.exe' 'alsobare.exe')) -RuleMode 'block' -Total 3
    T 'three identical unresolved events are one line, counted' (@($r.Lines | Where-Object { $_ -match 'does not say which' }).Count -eq 1 -and ($r.Lines -join "`n") -match 'read LSASS memory 3 times') ($r.Lines -join ' | ')
    $r = Get-AsrEventReport -Records @() -RuleMode 'block' -ReadError 'Attempted to perform an unauthorized operation.' -IsElevated $false
    T 'on a standard-user token the same channel is a counted deferral, never a ledger row, and never an all-clear' ($r.Sev -eq 'OK' -and $r.GapSev -eq 'OK' -and $r.Deferred -eq 1 -and ($r.Lines -join "`n") -match '^\[DEFERRED - ADMIN REQUIRED\]' -and ($r.Lines -join "`n") -notmatch '\[OK\]') ($r.Lines -join ' | ')

    T 'a control character in a field cannot start a report line' ((((Get-AsrEventReport -Records @((NewRec ('C:\a' + [char]10 + '[OK] fake') $L)) -RuleMode 'block' -Total 1).Lines -join "`n") -notmatch '(?m)^\[OK\] fake')) ''

    if ($fails) { Write-Output "[FAIL] $fails asr_lsass_events self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] asr_lsass_events self-test: the accessing program is taken from whichever field is not lsass.exe and both are printed when neither is, audit-mode records say the access was not blocked, an exclusion is raised, and a log that records nothing because the rule is off is SKIPPED rather than cleared.'
    exit 0
}

if (-not $MarkerDir) { $MarkerDir = $env:TEMP }
'--- [T1003.001] Defender''s record of a program trying to read LSASS memory (ASR rule ' + $RuleId + ', Events 1121/1122) ---'

if ($Elevated -lt 0) {
    $Elevated = 0
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 }
    } catch { }
}

# Per-rule exclusions, from both the policy and the local key. An exclusion
# here lets a program read LSASS leaving no event at all.
$exclusions = New-Object System.Collections.ArrayList
$exclusionError = ''
foreach ($base in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyPerRuleExclusions',
                    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyPerRuleExclusions')) {
    $k = $base + '\' + $RuleId
    try {
        if (-not (Test-Path -LiteralPath $k -EA Stop)) { continue }
        $p = Get-ItemProperty -LiteralPath $k -EA Stop
        foreach ($n in @($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
            if ($exclusions -notcontains $n.Name) { [void]$exclusions.Add($n.Name) }
        }
    } catch {
        # Swallowing this was the one failure that makes an empty log
        # meaningless: an excluded program leaves no record at all.
        if (-not $exclusionError) { $exclusionError = $_.Exception.Message }
    }
}

$records = New-Object System.Collections.ArrayList
$total = 0L; $oldest = $null; $newest = $null; $unreadable = 0L; $truncated = $false
$readError = ''
try {
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Microsoft-Windows-Windows Defender/Operational', [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*[System[EventID=1121 or EventID=1122]]')
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
                # The fields are named, not positional, in this provider, so
                # they are read from the event's XML by name.
                $h = @{}
                foreach ($d in @(([xml]$e.ToXml()).Event.EventData.Data)) {
                    if ($null -ne $d -and $d.Name) { $h[[string]$d.Name] = [string]$d.'#text' }
                }
                if (([string]$h['ID']).Trim() -and ([string]$h['ID']).Trim().Trim('{', '}') -ieq $RuleId.Trim('{', '}')) {
                    [void]$records.Add(@{ Time = $e.TimeCreated; Id = $e.Id; RuleId = $h['ID']; Path = $h['Path']; ProcessName = $h['Process Name']; CommandLine = $h['Target Commandline']; User = $h['User'] })
                }
            } catch {
                # One unreadable record is skipped, never the whole read -- and
                # counted, so a provider this cannot parse does not read as a
                # log with nothing in it.
                $unreadable++
            } finally { $e.Dispose() }
            if ($total -ge $MaxRecords) { $truncated = $true; break }
        }
    } finally { $reader.Dispose() }
} catch {
    $readError = $_.Exception.Message
}

$report = Get-AsrEventReport -Records @($records.ToArray()) -RuleMode $RuleMode -Exclusions @($exclusions.ToArray()) `
    -Total $total -Oldest $oldest -Newest $newest -ReadError $readError -IsElevated ($Elevated -eq 1) `
    -Unreadable $unreadable -Truncated $truncated -ExclusionError $exclusionError
foreach ($l in $report.Lines) { $l }
Write-Marker -Name 'asrlsass' -Sev $report.Sev
if ($report.GapSev -ne 'OK') { Write-Marker -Name 'asrlsass_gap' -Sev $report.GapSev }
if ($report.Deferred -gt 0) { Write-Marker -Name 'asrlsass_deferred' -Sev ([string]$report.Deferred) }
