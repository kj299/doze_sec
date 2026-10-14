# masquerade_check.ps1 -- a system-process NAME running outside its canonical
# directory, or started by a parent Windows never uses (T1036, masquerading).
# Invoked from Section 4 of doze_sec.bat / doze_sec_noAdmin.bat against the
# process snapshot Section 4 already took (-Path, the Name-PID-Path dump) and
# the process tree proc_snapshot.ps1 wrote from the same query (-TreePath).
# The parent rule is described where it starts, below Get-MasqueradeReport.
#
# WHY: naming an implant svchost.exe, lsass.exe or explorer.exe and running it
# from AppData, ProgramData, Temp or a vendor directory is the most common
# evasion on a client machine -- Task Manager shows a familiar name and most
# readers stop there. Windows itself never runs those names from anywhere but
# a fixed directory, so the path IS the verdict. The 2026-09 retrospective
# found this the one real detection gap among the manifest techniques with no
# check behind them.
#
# ONE MEASUREMENT: this reads the SAME dump Section 4 grades with
# proc_path_grade.ps1 (`Name  PID  Path`, one bulk Win32_Process query taken
# early in the run). It never enumerates processes itself, so it cannot
# disagree with the section about which processes existed.
#
# THE RULE (pure, in Get-MasqueradeVerdict, pinned by -SelfTest):
#   * a listed system-process name whose directory is not one of its canonical
#     directories is a WARNING ("investigate"), never CRITICAL: the path alone
#     says the file is not the Windows binary, not what it is. The
#     comparison is case-insensitive (the owner's machine spells it
#     C:\WINDOWS\system32\ and C:\WINDOWS\Explorer.EXE) and anchored on both
#     the directory and the file name, so System32x\ and System32\drivers\ are
#     not System32\.
#   * a listed name with NO path is UNVERIFIED, never a finding and never an
#     all-clear: protected processes, and every other user's processes on a
#     non-admin run, come back with an empty ExecutablePath.
#   * any other name is IGNORED here; proc_path_grade grades paths by
#     location and module_inspect grades what is loaded inside.
#
# MARKERS: -MarkerFile is written with WARNING when the path rule has a hit,
# -ParentMarkerFile when the parent rule does, -CountMarkerFile when a process
# Windows runs once is there twice or in the wrong session, -LsassCopyMarkerFile
# (CRITICAL) when LSASS has a copy of itself running, -CopyMarkerFile when any
# other system process does; the caller raises each as its own ledger row via
# :dz_finding, so the row names what was seen.
# Read-only. Windows PowerShell 5.1 and pwsh.

[CmdletBinding()]
param(
    # NOT Mandatory: a mandatory parameter makes -SelfTest (and the report
    # command probe, which runs the printed Command: line without arguments)
    # sit at an interactive prompt. Validated below, where it is needed.
    [string]$Path,
    [string]$MarkerFile,
    # The process tree proc_snapshot.ps1 wrote from the SAME query as -Path,
    # and the marker the parent rule writes (its own ledger row).
    [string]$TreePath,
    [string]$ParentMarkerFile,
    # One of each, and the session rule: their own ledger row.
    [string]$CountMarkerFile,
    # A process that is a copy of its parent: LSASS (CRITICAL, T1003.001) and
    # any other system process (WARNING, T1055), each its own ledger row.
    [string]$LsassCopyMarkerFile,
    [string]$CopyMarkerFile,
    [string]$SystemRoot = $env:SystemRoot,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'

function Write-MarkerFile {
    # The marker IS the route to the findings ledger: a failed write turns a
    # real finding into a CLEAN section. Create the directory rather than
    # assume it, and no -EA SilentlyContinue -- a swallowed failure here is how
    # a field test lost its finding. Local to each tool, like Write-Marker.
    param([string]$Path, [string]$Value = 'WARNING')
    if (-not $Path) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Value -Encoding ASCII
}

# Canonical directories, relative to the Windows directory unless absolute.
# 'sys32' = <root>\System32, 'wow' = <root>\SysWOW64, 'root' = <root>,
# 'wbem' = <root>\System32\wbem and <root>\SysWOW64\wbem,
# 'defender' = the Defender platform directories (versioned) and Program Files.
$script:Canonical = @{
    'lsass.exe'                 = @('sys32')
    'csrss.exe'                 = @('sys32')
    'smss.exe'                  = @('sys32')
    'wininit.exe'               = @('sys32')
    'services.exe'              = @('sys32')
    'winlogon.exe'              = @('sys32')
    'spoolsv.exe'               = @('sys32')
    'sihost.exe'                = @('sys32')
    'taskhostw.exe'             = @('sys32')
    'dwm.exe'                   = @('sys32')
    'ctfmon.exe'                = @('sys32')
    'fontdrvhost.exe'           = @('sys32')
    'lsaiso.exe'                = @('sys32')
    'logonui.exe'               = @('sys32')
    'userinit.exe'              = @('sys32')
    'searchindexer.exe'         = @('sys32')
    'securityhealthservice.exe' = @('sys32')
    'svchost.exe'               = @('sys32', 'wow')
    'dllhost.exe'               = @('sys32', 'wow')
    'conhost.exe'               = @('sys32', 'wow')
    'runtimebroker.exe'         = @('sys32', 'wow')
    'rundll32.exe'              = @('sys32', 'wow')
    'werfault.exe'              = @('sys32', 'wow')
    'explorer.exe'              = @('root', 'wow')
    'wmiprvse.exe'              = @('wbem')
    'msmpeng.exe'               = @('defender')
    'nissrv.exe'                = @('defender')
}

function Get-CanonicalDirs {
    # The directories a name may live in, as regex fragments anchored at the
    # start of the path. Built from the Windows directory of THIS machine so
    # an install on D:\ or a renamed Windows directory is graded correctly.
    param([string]$Name, [string]$Root)
    $r = [regex]::Escape($Root.TrimEnd('\'))
    $out = @()
    foreach ($k in $script:Canonical[$Name.ToLowerInvariant()]) {
        switch ($k) {
            'sys32'    { $out += ($r + '\\System32\\') }
            'wow'      { $out += ($r + '\\SysWOW64\\') }
            'root'     { $out += ($r + '\\') }
            'wbem'     { $out += ($r + '\\System32\\wbem\\'); $out += ($r + '\\SysWOW64\\wbem\\') }
            'defender' {
                $out += '[A-Za-z]:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\[^\\]+\\'
                $out += '[A-Za-z]:\\Program Files\\Windows Defender\\'
            }
        }
    }
    return $out
}

# PURE: one process, graded. Sev is OK, WARNING, UNVERIFIED or IGNORED.
function Get-MasqueradeVerdict {
    param([string]$Name, [string]$ProcPath, [string]$SystemRoot)
    $n = ([string]$Name).Trim()
    if (-not $n) { return @{ Sev = 'IGNORED'; Why = 'no name' } }
    if (-not $script:Canonical.ContainsKey($n.ToLowerInvariant())) { return @{ Sev = 'IGNORED'; Why = 'not a system-process name' } }
    $p = ([string]$ProcPath).Trim()
    if (-not $p) { return @{ Sev = 'UNVERIFIED'; Why = 'no readable path (protected process, or another user''s process on a non-admin run)' } }
    if (-not $SystemRoot) { return @{ Sev = 'UNVERIFIED'; Why = 'the Windows directory is unknown, so no canonical directory can be built' } }
    $dirs = Get-CanonicalDirs -Name $n -Root $SystemRoot
    $esc = [regex]::Escape($n)
    foreach ($d in $dirs) {
        # Anchored at both ends: the directory, then exactly the file name.
        if ($p -match ('(?i)^' + $d + $esc + '$')) { return @{ Sev = 'OK'; Why = 'canonical directory' } }
    }
    $shown = @()
    foreach ($k in $script:Canonical[$n.ToLowerInvariant()]) {
        switch ($k) {
            'sys32'    { $shown += ($SystemRoot.TrimEnd('\') + '\System32') }
            'wow'      { $shown += ($SystemRoot.TrimEnd('\') + '\SysWOW64') }
            'root'     { $shown += $SystemRoot.TrimEnd('\') }
            'wbem'     { $shown += ($SystemRoot.TrimEnd('\') + '\System32\wbem') }
            'defender' { $shown += 'the Windows Defender platform directory' }
        }
    }
    return @{ Sev = 'WARNING'; Why = ('the genuine ' + $n + ' lives only in ' + ($shown -join ' or ')) }
}

# PURE: a whole snapshot (lines of `Name  PID  Path`) to report lines + marker.
function Get-MasqueradeReport {
    param([string[]]$Lines, [string]$SystemRoot)
    $out = New-Object System.Collections.ArrayList
    $hits = 0; $ok = 0; $unverified = 0; $parsed = 0
    foreach ($ln in @($Lines)) {
        if (-not $ln) { continue }
        # Name, two spaces, PID, two spaces, Path (Path may be empty).
        $m = [regex]::Match($ln, '^(\S.*?)\s{2,}(\d+)\s{0,}(.*)$')
        if (-not $m.Success) { continue }
        $parsed++
        $name = $m.Groups[1].Value; $procId = $m.Groups[2].Value; $p = $m.Groups[3].Value.Trim()
        $v = Get-MasqueradeVerdict -Name $name -ProcPath $p -SystemRoot $SystemRoot
        switch ($v.Sev) {
            'WARNING'    {
                $hits++
                # The directory by string, not Split-Path: on the Linux lint runner
                # Split-Path rewrites backslashes, and the report must show the
                # path as Windows spells it.
                $dir = $p; $cut = $p.LastIndexOf('\'); if ($cut -gt 0) { $dir = $p.Substring(0, $cut) }
                [void]$out.Add(('[WARNING] Process ' + $name + ' (PID ' + $procId + ') runs from ' + $dir + ' -- ' + $v.Why + ' (T1036 masquerading)'))
            }
            'OK'         { $ok++ }
            'UNVERIFIED' { $unverified++ }
        }
    }
    if ($parsed -eq 0) {
        [void]$out.Add('[SKIPPED] the process snapshot held no parseable lines -- masquerading check NOT performed.')
        return @{ Lines = @($out.ToArray()); Marker = $null }
    }
    if ($unverified -gt 0) {
        [void]$out.Add(('[INFO] ' + $unverified + ' system-process name(s) had no readable path (protected, or another user''s on a non-admin run) -- not graded, not cleared.'))
    }
    if ($hits -eq 0) {
        if ($ok -gt 0) {
            [void]$out.Add(('[OK] ' + $ok + ' system-process name(s) run from their canonical directories -- no masquerading by name.'))
        } else {
            # Nothing could be graded. That is not an all-clear, and it must
            # not read like one.
            [void]$out.Add('[SKIPPED] no system-process path could be graded -- masquerading by name NOT verified.')
        }
        return @{ Lines = @($out.ToArray()); Marker = $null }
    }
    return @{ Lines = @($out.ToArray()); Marker = 'WARNING' }
}

# ---- Masquerading by PARENT ------------------------------------------------
# A copy of an implant named svchost.exe can sit in System32 and pass the
# path rule above. Windows starts each of these names from one parent, so the
# parent is the second signal.
#
# TWO KINDS OF PARENT. Some never exit while Windows runs: System, smss.exe,
# wininit.exe and services.exe are critical processes (Windows stops with a
# bug check if one exits -- Bug check 0xEF, "Critical System Services"), and
# so is the service host that runs the DCOM launcher, which starts
# RuntimeBroker.exe, WmiPrvSE.exe and dllhost.exe. A session's winlogon.exe
# runs as long as its session. For a child of one of those, a process with
# the wrong name at the parent PID -- or none -- means something else started
# the child: the rightful parent cannot have exited and freed the number.
#
# WHEN THE NAME IS ENOUGH. System (only ever PID 4), wininit.exe and
# services.exe are each one process (one of each, below), and every smss.exe
# is the one System started or a short-lived copy of it for a session, so a
# parent with one of those names IS a rightful one, and time is not
# consulted: a clock that stepped backward after boot (a dual-boot PC, a time
# service correcting a fast clock) cannot make a genuine parent look reused.
# A winlogon.exe parent
# must be the one in the child's own session -- each session has exactly one,
# and it predates everything it starts, so no clock can confuse it. An
# svchost.exe parent is one of many: a service host started AFTER the child
# took over the number of whatever really started it, so it counts only when
# its creation time is earlier and the clock is seen not to have moved.
#
# Other parents exit by design: a session's smss.exe exits once it has
# started csrss, wininit and winlogon, and the service hosts that start
# taskhostw.exe and sihost.exe can restart. csrss, wininit and winlogon are
# not graded by their parent at all: one of each per session (below) catches
# an impostor without depending on the clock. For taskhostw and sihost a PID
# held by a process with the wrong name is either the real parent or a later
# process that reused the number, and Microsoft documents how to tell
# (Win32_Process, ParentProcessId): CreationDate shows whether the listed
# parent was created after the child. That is trusted only when the clock is
# seen not to have moved backward since boot, and never on equal times.
#
# A SESSION THAT IS ENDING. When a session ends its winlogon.exe exits, and
# for a moment its dwm, logonui or fontdrvhost can outlive it. A child whose
# session holds no winlogon.exe is counted as one whose parent exited, never
# a finding -- unless a process OLDER than the child holds its parent PID
# (that is no reused number; it started the child). Session 0 is never
# ending: it lasts until shutdown and never holds a winlogon.exe, and it is
# where a SYSTEM service, scheduled task or remote launch lands.
#
# A COPY OF ITS PARENT. Process snapshotting and reflection make a new process
# that is a copy of an existing one: the same image, and the original as its
# parent (Microsoft, PSS_CAPTURE_VA_CLONE: the VA clone is a process, and keeps
# the image unless PSS_CREATE_RELEASE_SECTION). Two kinds of software make one.
# Diagnostics copy a hung process so it can keep running while it is examined
# (Windows Error Reporting; ProcDump -r, "Dump using a clone"). And tools that
# want LSASS's secrets copy LSASS and read the copy: the public detections for
# that (Elastic "Potential LSASS Clone Creation via PssCaptureSnapShot", Sigma
# "Potential Credential Dumping Via LSASS Process Clone", T1003.001) key on
# exactly lsass.exe created by lsass.exe. So a system process whose parent has
# its own name and image is reported as a COPY -- an LSASS copy CRITICAL, any
# other WARNING -- once, instead of as a wrong parent and a second instance.
# Only the names in the parent table, and not smss.exe, whose first instance
# starts a copy of itself for each session by design: browsers, explorer.exe
# and many others start children from their own image, so a same-name pair is
# no signal for them. A copy made to read LSASS lives for seconds; Section 12
# reads the Security log, where Event 4688 keeps the record.
#
# ONE OF EACH. Windows runs exactly one wininit.exe, services.exe, lsass.exe
# and LsaIso.exe, all in session 0, one smss.exe started by System, and one
# csrss.exe per session and one winlogon.exe per session other than 0. A
# second one is an impostor even when its own parent looks right -- which is
# how a renamed chain (a fake wininit starting a fake services starting an
# implant svchost) would otherwise pass.
#
# Not graded by parent, on purpose: explorer.exe (userinit, winlogon, Task
# Manager and explorer itself all start it), conhost, rundll32, werfault and
# ctfmon (their parents vary by design). And a dropper that starts
# taskhostw.exe or sihost.exe and exits leaves only a counted line --
# THREAT_MODEL names it, with parent PID spoofing and process-isolated
# Windows containers (their own smss, csrss and services trees on the host).
#
#   Parents     the names Windows starts it from
#   Show/Until  how the finding names them, and why they cannot have exited
#   Lifetime    the rightful parent never exits (while its session lasts)
#   PerSession  the rightful parent is the one in the child's own session
#   TimeGraded  a parent that exits by design, graded by creation time
$script:ParentRule = @{
    'smss.exe'                  = @{ Parents = @('system', 'smss.exe'); Show = 'System or the first smss.exe'; Until = 'which run until shutdown'; Lifetime = $true }
    'csrss.exe'                 = @{ Parents = @('smss.exe'); Show = 'smss.exe'; Lifetime = $false; TimeGraded = $false }
    'wininit.exe'               = @{ Parents = @('smss.exe'); Show = 'smss.exe'; Lifetime = $false; TimeGraded = $false }
    'winlogon.exe'              = @{ Parents = @('smss.exe'); Show = 'smss.exe'; Lifetime = $false; TimeGraded = $false }
    'services.exe'              = @{ Parents = @('wininit.exe'); Show = 'wininit.exe'; Until = 'which runs until shutdown'; Lifetime = $true }
    'lsass.exe'                 = @{ Parents = @('wininit.exe'); Show = 'wininit.exe'; Until = 'which runs until shutdown'; Lifetime = $true }
    'lsaiso.exe'                = @{ Parents = @('wininit.exe'); Show = 'wininit.exe'; Until = 'which runs until shutdown'; Lifetime = $true }
    'svchost.exe'               = @{ Parents = @('services.exe'); Show = 'services.exe'; Until = 'which runs until shutdown'; Lifetime = $true }
    'spoolsv.exe'               = @{ Parents = @('services.exe'); Show = 'services.exe'; Until = 'which runs until shutdown'; Lifetime = $true }
    'searchindexer.exe'         = @{ Parents = @('services.exe'); Show = 'services.exe'; Until = 'which runs until shutdown'; Lifetime = $true }
    'securityhealthservice.exe' = @{ Parents = @('services.exe'); Show = 'services.exe'; Until = 'which runs until shutdown'; Lifetime = $true }
    'msmpeng.exe'               = @{ Parents = @('services.exe'); Show = 'services.exe'; Until = 'which runs until shutdown'; Lifetime = $true }
    'nissrv.exe'                = @{ Parents = @('services.exe'); Show = 'services.exe'; Until = 'which runs until shutdown'; Lifetime = $true }
    'dwm.exe'                   = @{ Parents = @('winlogon.exe'); Show = 'the winlogon.exe of its own session'; Until = 'which runs as long as that session'; Lifetime = $true; PerSession = $true }
    'logonui.exe'               = @{ Parents = @('winlogon.exe'); Show = 'the winlogon.exe of its own session'; Until = 'which runs as long as that session'; Lifetime = $true; PerSession = $true }
    'userinit.exe'              = @{ Parents = @('winlogon.exe'); Show = 'the winlogon.exe of its own session'; Until = 'which runs as long as that session'; Lifetime = $true; PerSession = $true }
    'fontdrvhost.exe'           = @{ Parents = @('wininit.exe', 'winlogon.exe'); Show = 'wininit.exe in session 0, or the winlogon.exe of its own session'; Until = 'each of which runs as long as its session'; Lifetime = $true; PerSession = $true }
    'runtimebroker.exe'         = @{ Parents = @('svchost.exe'); Show = 'svchost.exe (the DCOM launcher''s service host)'; Until = 'which runs until shutdown'; Lifetime = $true }
    'wmiprvse.exe'              = @{ Parents = @('svchost.exe'); Show = 'svchost.exe (the DCOM launcher''s service host)'; Until = 'which runs until shutdown'; Lifetime = $true }
    # COM+ server applications, and the COM+ System Application service
    # (COMSysApp, whose image IS dllhost.exe), run as services.
    'dllhost.exe'               = @{ Parents = @('svchost.exe', 'services.exe'); Show = 'svchost.exe (the DCOM launcher''s service host) or services.exe'; Until = 'both of which run until shutdown'; Lifetime = $true }
    'taskhostw.exe'             = @{ Parents = @('svchost.exe'); Show = 'svchost.exe'; Lifetime = $false; TimeGraded = $true }
    'sihost.exe'                = @{ Parents = @('svchost.exe'); Show = 'svchost.exe'; Lifetime = $false; TimeGraded = $true }
}
# Parents that are one process each: their name alone identifies them.
$script:UniqueParent   = @('system', 'smss.exe', 'wininit.exe', 'services.exe')
# Exactly one instance (all in session 0), and one per session.
$script:OnlyOne        = @('wininit.exe', 'services.exe', 'lsass.exe', 'lsaiso.exe')
$script:Session0Only   = @('wininit.exe', 'services.exe', 'lsass.exe', 'lsaiso.exe')
$script:OnePerSession  = @('csrss.exe', 'winlogon.exe')
# Every running Windows holds these; a snapshot without one is incomplete.
$script:CoreProcess    = @('wininit.exe', 'services.exe', 'lsass.exe', 'csrss.exe')

function ConvertTo-PrintableText {
    # A process name or path goes into the report as text: no control
    # characters, so nothing a process calls itself can break a line.
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

function Format-UtcTicks {
    param($Ticks)
    if ($null -eq $Ticks) { return 'at an unknown time' }
    return ([datetime]::new([long]$Ticks, [DateTimeKind]::Utc).ToString('yyyy-MM-dd HH:mm:ss') + 'Z')
}

# PURE: is the child a copy of its parent? The same name (case-insensitive),
# a name Windows never starts from itself, and the same image -- or an image
# that cannot be compared because a path is not readable (another user's
# process on a standard-user token). Returns 'same image', 'same name' (the
# image could not be compared) or $null.
function Test-IsCopy {
    param($Child, $Parent)
    if ($null -eq $Child -or $null -eq $Parent) { return $null }
    $cn = ([string]$Child.Name).Trim().ToLowerInvariant()
    if (-not $cn -or $cn -ne ([string]$Parent.Name).Trim().ToLowerInvariant()) { return $null }
    if (-not $script:ParentRule.ContainsKey($cn) -or $cn -eq 'smss.exe') { return $null }
    $cp = ([string]$Child.Path).Trim(); $pp = ([string]$Parent.Path).Trim()
    if ($cp -and $pp) {
        if ($cp -ieq $pp) { return 'same image' }
        return $null
    }
    return 'same name'
}

# PURE: one process, graded by its parent. Sev is OK, WARNING, EXITED,
# UNVERIFIED or IGNORED; a WARNING's Kind is 'other' (a living process with
# the wrong name holds the parent PID), 'reused' (a LATER process holds it,
# so the real parent is gone) or 'gone' (nothing holds it).
#   ChildTicks       the child's creation time (UTC ticks) or $null
#   ChildSession     the child's session ID or $null
#   Parent           $null when no process holds the parent PID, else
#                    @{ Pid; Name; Ticks; Session }
#   RightfulPresent  the snapshot holds every rightful parent the rule names
#                    (a snapshot missing services.exe is incomplete, not a crime)
#   ClockMoved       the clock stepped backward since boot: creation times
#                    cannot order processes
#   AliveInSession   for a PerSession rule: the child's session holds a
#                    rightful parent ($null: the session is unknown)
function Get-ParentVerdict {
    param([string]$Name, $ChildTicks, $ChildSession = $null, $Parent, [bool]$RightfulPresent = $true, [bool]$ClockMoved = $false, $AliveInSession = $true)
    $n = ([string]$Name).Trim().ToLowerInvariant()
    if (-not $script:ParentRule.ContainsKey($n)) { return @{ Sev = 'IGNORED' } }
    $rule = $script:ParentRule[$n]
    $haveTimes = ($null -ne $Parent -and $null -ne $ChildTicks -and $null -ne $Parent.Ticks)
    # A later process holds the parent PID: the real parent exited and the
    # number was reused. Only when the clock is seen not to have moved.
    $younger = ($haveTimes -and -not $ClockMoved -and [long]$Parent.Ticks -gt [long]$ChildTicks)
    $reused = $younger
    if ($null -ne $Parent) {
        $pname = ([string]$Parent.Name).Trim().ToLowerInvariant()
        # System is PID 4 and nothing else; a process that calls itself System
        # elsewhere is not it.
        if ($pname -eq 'system' -and [long]$Parent.Pid -ne 4) { $pname = '' }
        if ($rule.Parents -contains $pname) {
            if ($script:UniqueParent -contains $pname) { return @{ Sev = 'OK' } }
            if ($pname -eq 'winlogon.exe') {
                if ($null -eq $ChildSession -or $null -eq $Parent.Session) { return @{ Sev = 'UNVERIFIED'; Why = 'no session to tell the winlogon.exe of its own session from another' } }
                # The winlogon.exe of the child's session started it; one in
                # another session never does.
                if ([long]$ChildSession -eq [long]$Parent.Session) { return @{ Sev = 'OK' } }
            } else {
                # svchost.exe: one of many. A service host started after the
                # child is not what started it.
                if (-not $haveTimes) { return @{ Sev = 'UNVERIFIED'; Why = 'no creation time to tell the service host that started it from a later one' } }
                if ($ClockMoved) { return @{ Sev = 'UNVERIFIED'; Why = 'the clock moved backward since boot, so a later service host cannot be told from the one that started it' } }
                if ([long]$Parent.Ticks -eq [long]$ChildTicks) { return @{ Sev = 'UNVERIFIED'; Why = 'the parent and the child have the same creation time' } }
                if (-not $younger) { return @{ Sev = 'OK' } }
            }
        }
    }
    if ($rule.Lifetime) {
        # The rightful parent cannot have exited, so anything else at the
        # parent PID -- or nothing -- means it did not start this process.
        # Only a snapshot with no rightful parent at all is left ungraded:
        # that is an incomplete snapshot, not evidence.
        if (-not $RightfulPresent) { return @{ Sev = 'UNVERIFIED'; Why = ('the snapshot holds no ' + ($rule.Parents -join ' or ') + ' at all, so it may be incomplete') } }
        if ($rule.PerSession) {
            if ($null -eq $AliveInSession) { return @{ Sev = 'UNVERIFIED'; Why = 'no session to find its winlogon.exe in' } }
            if (-not $AliveInSession) {
                # The session is ending: its winlogon.exe exited first, and
                # its number may since have been reused by a later process.
                # A living holder that predates the child is no reuse -- it
                # is what started the child, and it is the wrong name.
                if ($null -eq $Parent -or $reused) { return @{ Sev = 'EXITED' } }
                if (-not $haveTimes -or $ClockMoved -or [long]$Parent.Ticks -eq [long]$ChildTicks) { return @{ Sev = 'UNVERIFIED'; Why = 'its session is ending, and no creation time can tell the process holding its parent PID from a later one' } }
            }
        }
        $kind = 'other'
        if ($null -eq $Parent) { $kind = 'gone' } elseif ($reused) { $kind = 'reused' }
        return @{ Sev = 'WARNING'; Kind = $kind; Why = ('Windows starts ' + $n + ' only from ' + $rule.Show + ', ' + $rule.Until) }
    }
    # A parent that exits by design: nothing at the PID is the expected case.
    if ($null -eq $Parent -or $reused) { return @{ Sev = 'EXITED' } }
    if (-not $rule.TimeGraded) {
        # csrss, wininit, winlogon: one of each per session grades them, not
        # the clock.
        return @{ Sev = 'UNVERIFIED'; Why = 'a living process other than smss.exe holds its parent PID; one per session is what grades it' }
    }
    if (-not $haveTimes) { return @{ Sev = 'UNVERIFIED'; Why = 'no creation time to tell a reused process ID from the parent' } }
    if ($ClockMoved) { return @{ Sev = 'UNVERIFIED'; Why = 'the clock moved backward since boot, so a reused process ID cannot be told from the parent' } }
    if ([long]$Parent.Ticks -eq [long]$ChildTicks) { return @{ Sev = 'UNVERIFIED'; Why = 'the parent and the child have the same creation time' } }
    return @{ Sev = 'WARNING'; Kind = 'other'; Why = ('Windows starts ' + $n + ' only from ' + $rule.Show) }
}

# PURE: has the clock stepped backward since boot? Only the kernel starts a
# process before the System-started smss.exe, so any later process recorded
# as older than it means the clock moved; so does a process recorded as older
# than the wininit.exe or services.exe that started it, since each is one
# process that never exits; and so does a name a service host starts
# (RuntimeBroker, WmiPrvSE, dllhost, taskhostw, sihost) recorded as older than
# the FIRST service host services.exe started -- nothing a service host
# starts can predate every service host. A child older than its OWN
# svchost.exe parent is not such proof: that is what a reused PID looks like,
# and reading it as a moved clock would hide it.
function Test-ClockMovedBackward {
    param($Records, $ByPid)
    $smss = @($Records | Where-Object { $_.Name -ieq 'smss.exe' -and $_.PPid -eq 4 -and $null -ne $_.Ticks }) | Select-Object -First 1
    $firstHost = $null
    foreach ($r in $Records) {
        if ($null -eq $r.Ticks -or $r.Name -ine 'svchost.exe' -or -not $ByPid.ContainsKey($r.PPid)) { continue }
        if ([string]$ByPid[$r.PPid].Name -ine 'services.exe') { continue }
        if ($null -eq $firstHost -or [long]$r.Ticks -lt $firstHost) { $firstHost = [long]$r.Ticks }
    }
    foreach ($r in $Records) {
        if ($null -eq $r.Ticks) { continue }
        if ($smss -and $r.PPid -ne 4 -and $r.PPid -ne 0 -and $r.Pid -ne $smss.Pid -and [long]$r.Ticks -lt [long]$smss.Ticks) { return $true }
        $n = ([string]$r.Name).ToLowerInvariant()
        if ($script:ParentRule.ContainsKey($n) -and $ByPid.ContainsKey($r.PPid)) {
            $p = $ByPid[$r.PPid]
            $pn = ([string]$p.Name).ToLowerInvariant()
            if ($null -ne $p.Ticks -and ($pn -eq 'wininit.exe' -or $pn -eq 'services.exe') -and $script:ParentRule[$n].Parents -contains $pn -and [long]$p.Ticks -gt [long]$r.Ticks) { return $true }
        }
        if ($null -ne $firstHost -and $script:ParentRule.ContainsKey($n) -and $script:ParentRule[$n].Parents -contains 'svchost.exe' -and [long]$r.Ticks -lt $firstHost) { return $true }
    }
    return $false
}

# PURE: the tree (`PID|PPID|CreatedUtcTicks|SessionId|Path|Name`, written by
# proc_snapshot.ps1 from the same query as the path rule's dump) to report
# lines + marker.
function Get-ParentReport {
    param([string[]]$Tree)
    $out = New-Object System.Collections.ArrayList
    $byPid = @{}
    $records = New-Object System.Collections.ArrayList
    foreach ($ln in @($Tree)) {
        if (-not $ln) { continue }
        # A session ID is a 32-bit unsigned number: up to ten digits, held in
        # a [long] so the largest does not overflow an [int].
        $m = [regex]::Match($ln, '^(\d{1,9})\|(\d{1,9})\|(\d{0,19})\|(\d{0,10})\|([^|]*)\|(.+)$')
        if (-not $m.Success) { continue }
        $procId = [int]$m.Groups[1].Value
        if ($byPid.ContainsKey($procId)) { continue }   # one snapshot holds a PID once
        $t = $null; if ($m.Groups[3].Value) { $t = [long]$m.Groups[3].Value }
        $sid = $null; if ($m.Groups[4].Value) { $sid = [long]$m.Groups[4].Value }
        $rec = @{ Pid = $procId; PPid = [int]$m.Groups[2].Value; Ticks = $t; Session = $sid; Path = $m.Groups[5].Value; Name = $m.Groups[6].Value.Trim() }
        $byPid[$procId] = $rec
        [void]$records.Add($rec)
    }
    if ($records.Count -eq 0) {
        [void]$out.Add('[SKIPPED] the process tree snapshot held no parseable lines -- masquerading by parent NOT verified.')
        return @{ Lines = @($out.ToArray()); Marker = $null }
    }
    # The names the snapshot holds, and the names each session holds. System
    # counts only at PID 4: a process elsewhere calling itself System is not it.
    $names = @{}; $inSession = @{}
    foreach ($r in $records) {
        $rn = ([string]$r.Name).ToLowerInvariant()
        if ($rn -eq 'system') { continue }
        $names[$rn] = $true
        if ($null -ne $r.Session) { $inSession[$rn + '|' + $r.Session] = $true }
    }
    $systemAt4 = ($byPid.ContainsKey(4) -and ([string]$byPid[4].Name) -eq 'System')
    if ($systemAt4) { $names['system'] = $true }
    $clockMoved = Test-ClockMovedBackward -Records $records -ByPid $byPid
    # A snapshot without one of these is incomplete: every running Windows
    # holds them. It can still show an impostor; it cannot be an all-clear.
    $missing = @()
    if (-not $systemAt4) { $missing += 'System (PID 4)' }
    if (-not @($records | Where-Object { $_.Name -ieq 'smss.exe' -and $_.PPid -eq 4 }).Count) { $missing += 'smss.exe started by System' }
    foreach ($c in $script:CoreProcess) { if (-not $names.ContainsKey($c)) { $missing += $c } }

    function Show-Proc($r) {
        $p = ConvertTo-PrintableText $r.Path
        if (-not $p) { $p = '(path not readable)' }
        $s = 'unknown'; if ($null -ne $r.Session) { $s = [string]$r.Session }
        return ($p + ', session ' + $s + ', started ' + (Format-UtcTicks $r.Ticks))
    }
    $hits = 0; $countHits = 0; $ok = 0; $exited = 0; $unverified = 0
    $lsassCopies = 0; $otherCopies = 0; $copyPids = @{}
    foreach ($rec in $records) {
        $parent = $null
        if ($rec.PPid -ne $rec.Pid -and $byPid.ContainsKey($rec.PPid)) { $parent = $byPid[$rec.PPid] }
        $n = ([string]$rec.Name).ToLowerInvariant()
        # A copy of its parent is graded once, as a copy -- not as a wrong
        # parent and again as a second instance.
        $how = Test-IsCopy -Child $rec -Parent $parent
        if ($how) {
            $copyPids[$rec.Pid] = $true
            $hits++
            $nm = ConvertTo-PrintableText $rec.Name
            $pn = ConvertTo-PrintableText $parent.Name
            if ($n -eq 'lsass.exe') {
                $lsassCopies++
                [void]$out.Add(('[CRITICAL] Process ' + $nm + ' (PID ' + $rec.Pid + ') is a copy of LSASS (PID ' + $parent.Pid + '), ' + $how + ' -- a second process holding LSASS''s memory, the shape credential-dumping tools leave (T1003.001). Windows does not copy LSASS on a healthy machine; an administrator''s own dump (ProcDump -r) does.'))
            } else {
                $otherCopies++
                [void]$out.Add(('[WARNING] Process ' + $nm + ' (PID ' + $rec.Pid + ') is a copy of its parent ' + $pn + ' (PID ' + $parent.Pid + '), ' + $how + ' -- Windows Error Reporting copies a hung process this way, and so does code injection by forking (T1055). If WerFault.exe is running and the copy is gone on a second look, it was the error report.'))
            }
            [void]$out.Add(('    copy:   ' + (Show-Proc $rec)))
            [void]$out.Add(('    parent: ' + $pn + ' (PID ' + $parent.Pid + ') ' + (Show-Proc $parent)))
            continue
        }
        # Every rightful parent the rule names must be in the snapshot (a
        # complete Windows snapshot always holds System, smss, wininit,
        # winlogon, services and svchost): one missing means the snapshot is
        # incomplete, and a child's absent parent proves nothing.
        $present = $true
        $alive = $true
        if ($script:ParentRule.ContainsKey($n)) {
            $rule = $script:ParentRule[$n]
            foreach ($pn in $rule.Parents) { if (-not $names.ContainsKey($pn)) { $present = $false } }
            # For a child of a session's winlogon.exe: does its session still
            # hold one (or, for fontdrvhost in session 0, wininit.exe)?
            if ($rule.PerSession) {
                # Session 0 lasts until shutdown and never holds a
                # winlogon.exe, so it is never "a session that is ending":
                # dwm, LogonUI and userinit are never started there.
                if ($null -eq $rec.Session) { $alive = $null } elseif ([long]$rec.Session -eq 0) { $alive = $true } else {
                    $alive = $false
                    foreach ($pn in $rule.Parents) { if ($inSession.ContainsKey($pn + '|' + $rec.Session)) { $alive = $true } }
                }
            }
        }
        $v = Get-ParentVerdict -Name $rec.Name -ChildTicks $rec.Ticks -ChildSession $rec.Session -Parent $parent -RightfulPresent $present -ClockMoved $clockMoved -AliveInSession $alive
        switch ($v.Sev) {
            'OK'         { $ok++ }
            'EXITED'     { $exited++ }
            'UNVERIFIED' { $unverified++ }
            'WARNING'    {
                $hits++
                $nm = ConvertTo-PrintableText $rec.Name
                if ($v.Kind -eq 'other') {
                    [void]$out.Add(('[WARNING] Process ' + $nm + ' (PID ' + $rec.Pid + ') has the wrong parent: PID ' + $rec.PPid + ' belongs to ' + (ConvertTo-PrintableText $parent.Name) + ' -- ' + $v.Why + ' (T1036 masquerading by parent)'))
                } else {
                    [void]$out.Add(('[WARNING] Process ' + $nm + ' (PID ' + $rec.Pid + ') has the wrong parent: the process that started it (PID ' + $rec.PPid + ') is no longer running -- ' + $v.Why + ' (T1036 masquerading by parent)'))
                }
                [void]$out.Add(('    child:  ' + (Show-Proc $rec)))
                if ($v.Kind -eq 'other') {
                    [void]$out.Add(('    parent: ' + (ConvertTo-PrintableText $parent.Name) + ' (PID ' + $parent.Pid + ') ' + (Show-Proc $parent)))
                } elseif ($v.Kind -eq 'reused') {
                    [void]$out.Add(('    parent: PID ' + $rec.PPid + ' is no longer running; the number now belongs to a later process, ' + (ConvertTo-PrintableText $parent.Name) + ' ' + (Show-Proc $parent)))
                } else {
                    [void]$out.Add(('    parent: PID ' + $rec.PPid + ' is no longer running'))
                }
            }
        }
    }
    # One of each, in its session.
    $groups = @{}
    foreach ($rec in $records) {
        $n = ([string]$rec.Name).ToLowerInvariant()
        if ($copyPids.ContainsKey($rec.Pid)) { continue }
        if ($script:OnlyOne -contains $n) { $k = $n } elseif ($script:OnePerSession -contains $n -and $null -ne $rec.Session) { $k = $n + '|' + $rec.Session } elseif ($n -eq 'smss.exe' -and $rec.PPid -eq 4) { $k = 'smss.exe|system' } else { continue }
        if (-not $groups.ContainsKey($k)) { $groups[$k] = New-Object System.Collections.ArrayList }
        [void]$groups[$k].Add($rec)
    }
    foreach ($k in @($groups.Keys | Sort-Object)) {
        $g = @($groups[$k])
        if ($g.Count -lt 2) { continue }
        $hits++; $countHits++
        $parts = $k.Split('|')
        $where = 'one ' + $parts[0]
        if ($parts.Count -gt 1 -and $parts[1] -eq 'system') { $where = 'one smss.exe started by System' }
        elseif ($parts.Count -gt 1) { $where = 'one ' + $parts[0] + ' per session; session ' + $parts[1] + ' has' }
        if ($parts.Count -gt 1 -and $parts[1] -ne 'system') {
            [void]$out.Add(('[WARNING] Windows runs ' + $where + ' ' + $g.Count + ' -- all but one are impostors (T1036 masquerading by parent)'))
        } else {
            [void]$out.Add(('[WARNING] Windows runs ' + $where + '; this snapshot holds ' + $g.Count + ' -- all but one are impostors (T1036 masquerading by parent)'))
        }
        foreach ($r in $g) {
            $pn = 'PID ' + $r.PPid + ' (no longer running)'
            if ($byPid.ContainsKey($r.PPid) -and $r.PPid -ne $r.Pid) { $pn = (ConvertTo-PrintableText $byPid[$r.PPid].Name) + ' (PID ' + $r.PPid + ')' }
            [void]$out.Add(('    instance: PID ' + $r.Pid + ', parent ' + $pn + ', ' + (Show-Proc $r)))
        }
    }
    foreach ($rec in $records) {
        $n = ([string]$rec.Name).ToLowerInvariant()
        $bad = $false
        if ($null -eq $rec.Session -or $copyPids.ContainsKey($rec.Pid)) { continue }
        if ($script:Session0Only -contains $n -and $rec.Session -ne 0) { $bad = $true; $want = 'only in session 0' }
        if ($n -eq 'winlogon.exe' -and $rec.Session -eq 0) { $bad = $true; $want = 'never in session 0' }
        if (-not $bad) { continue }
        $hits++; $countHits++
        [void]$out.Add(('[WARNING] Process ' + (ConvertTo-PrintableText $rec.Name) + ' (PID ' + $rec.Pid + ') runs in session ' + $rec.Session + ' -- Windows runs ' + $n + ' ' + $want + ' (T1036 masquerading by parent)'))
        [void]$out.Add(('    child:  ' + (Show-Proc $rec)))
    }
    if ($clockMoved) {
        [void]$out.Add('[INFO] The clock moved backward since this boot (a process is recorded as starting before the smss.exe System started, before the wininit.exe or services.exe that started it, or a service host''s child before the first service host), so creation times do not order processes here: a service-host parent and a parent that can exit are not graded by time.')
    }
    if ($exited -gt 0) {
        [void]$out.Add(('[INFO] ' + $exited + ' system-process name(s) whose parent is no longer running, as it may be by design (a session''s smss.exe exits once it has started csrss, wininit and winlogon; the service host that starts taskhostw or sihost can restart; a session that is ending loses its winlogon.exe first) -- not graded by parent.'))
    }
    if ($unverified -gt 0) {
        [void]$out.Add(('[INFO] ' + $unverified + ' system-process name(s) could not be graded by parent (no creation time or session, a clock that moved, a snapshot with no rightful parent in it, or a csrss, wininit or winlogon under another living process, which one per session grades instead) -- not graded by parent, not cleared.'))
    }
    if ($missing.Count -gt 0 -and $hits -gt 0) {
        [void]$out.Add(('[INFO] The process snapshot holds no ' + ($missing -join ', ') + ', which every running Windows has: it is incomplete, so a process it does not list was not graded. The findings above stand.'))
    }
    if ($hits -eq 0) {
        if ($missing.Count -gt 0) {
            # A snapshot without the core processes cannot clear anything: the
            # processes it lost are exactly the ones this check compares against.
            [void]$out.Add(('[SKIPPED] the process snapshot holds no ' + ($missing -join ', ') + ', which every running Windows has -- the snapshot is incomplete, so masquerading by parent is NOT verified.'))
        } elseif ($ok -gt 0) {
            [void]$out.Add(('[OK] ' + $ok + ' system-process name(s) were started by the parent Windows uses, one of each where Windows runs one -- no masquerading by parent.'))
        } else {
            [void]$out.Add('[SKIPPED] no system-process parent could be graded -- masquerading by parent NOT verified.')
        }
        return @{ Lines = @($out.ToArray()); Marker = $null; CountMarker = $null; LsassCopyMarker = $null; CopyMarker = $null }
    }
    # Four rows: a wrong parent; a process Windows runs once found twice or in
    # the wrong session; an LSASS copy; any other copy. Each names what was seen.
    $pm = $null; if (($hits - $countHits - $lsassCopies - $otherCopies) -gt 0) { $pm = 'WARNING' }
    $cm = $null; if ($countHits -gt 0) { $cm = 'WARNING' }
    $lm = $null; if ($lsassCopies -gt 0) { $lm = 'CRITICAL' }
    $om = $null; if ($otherCopies -gt 0) { $om = 'WARNING' }
    return @{ Lines = @($out.ToArray()); Marker = $pm; CountMarker = $cm; LsassCopyMarker = $lm; CopyMarker = $om }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $root = 'C:\WINDOWS'
    function V { param([string]$n, [string]$p, [string]$r = $root) (Get-MasqueradeVerdict -Name $n -ProcPath $p -SystemRoot $r).Sev }

    # The owner's machine spells its paths C:\WINDOWS\system32\ and
    # C:\WINDOWS\Explorer.EXE. Case must never be the difference.
    T 'svchost.exe at C:\WINDOWS\system32\svchost.exe (the owner''s casing) is canonical' ((V 'svchost.exe' 'C:\WINDOWS\system32\svchost.exe') -eq 'OK') (V 'svchost.exe' 'C:\WINDOWS\system32\svchost.exe')
    T 'Explorer.EXE at C:\WINDOWS\Explorer.EXE (the owner''s casing) is canonical' ((V 'explorer.exe' 'C:\WINDOWS\Explorer.EXE') -eq 'OK') (V 'explorer.exe' 'C:\WINDOWS\Explorer.EXE')
    T 'lsass.exe under System32 is canonical' ((V 'lsass.exe' 'C:\Windows\System32\lsass.exe') -eq 'OK') ''
    T 'a 32-bit svchost.exe under SysWOW64 is canonical' ((V 'svchost.exe' 'C:\Windows\SysWOW64\svchost.exe') -eq 'OK') ''
    T 'a 32-bit dllhost.exe under SysWOW64 is canonical' ((V 'dllhost.exe' 'C:\Windows\SysWOW64\dllhost.exe') -eq 'OK') ''
    T 'conhost.exe under SysWOW64 is canonical' ((V 'conhost.exe' 'C:\Windows\SysWOW64\conhost.exe') -eq 'OK') ''
    T 'WmiPrvSE.exe lives under System32\wbem, not System32' ((V 'WmiPrvSE.exe' 'C:\WINDOWS\system32\wbem\WmiPrvSE.exe') -eq 'OK') ''
    T 'MsMpEng.exe under the versioned Defender platform directory is canonical' ((V 'MsMpEng.exe' 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MsMpEng.exe') -eq 'OK') ''
    T 'MsMpEng.exe under Program Files\Windows Defender is canonical too' ((V 'MsMpEng.exe' 'C:\Program Files\Windows Defender\MsMpEng.exe') -eq 'OK') ''
    T 'a Windows installed on D:\Win is graded against D:\Win, not C:\Windows' ((V 'lsass.exe' 'D:\Win\System32\lsass.exe' 'D:\Win') -eq 'OK' -and (V 'lsass.exe' 'C:\Windows\System32\lsass.exe' 'D:\Win') -eq 'WARNING') ''
    T 'a trailing backslash on the Windows directory changes nothing' ((V 'svchost.exe' 'C:\Windows\System32\svchost.exe' 'C:\Windows\') -eq 'OK') ''
    T 'a system name with NO path is UNVERIFIED, not a finding' ((V 'csrss.exe' '') -eq 'UNVERIFIED') (V 'csrss.exe' '')
    T 'a system name with an unknown Windows directory is UNVERIFIED' ((V 'csrss.exe' 'C:\Windows\System32\csrss.exe' '') -eq 'UNVERIFIED') ''
    T 'chrome.exe anywhere is not this check''s business' ((V 'chrome.exe' 'C:\Users\u\AppData\Local\Google\Chrome\Application\chrome.exe') -eq 'IGNORED') ''
    T 'an empty name is ignored' ((V '' 'C:\x.exe') -eq 'IGNORED') ''

    # Must raise.
    T 'svchost.exe from AppData\Roaming is WARNING' ((V 'svchost.exe' 'C:\Users\u\AppData\Roaming\svchost.exe') -eq 'WARNING') ''
    T 'lsass.exe from Windows\Temp is WARNING' ((V 'lsass.exe' 'C:\Windows\Temp\lsass.exe') -eq 'WARNING') ''
    T 'csrss.exe from ProgramData is WARNING' ((V 'csrss.exe' 'C:\ProgramData\csrss.exe') -eq 'WARNING') ''
    T 'svchost.exe from System32\drivers (a SUBdirectory) is WARNING' ((V 'svchost.exe' 'C:\Windows\System32\drivers\svchost.exe') -eq 'WARNING') ''
    T 'svchost.exe from System32x (a prefix trick) is WARNING' ((V 'svchost.exe' 'C:\Windows\System32x\svchost.exe') -eq 'WARNING') ''
    T 'explorer.exe from C:\Intel is WARNING' ((V 'explorer.exe' 'C:\Intel\explorer.exe') -eq 'WARNING') ''
    T 'explorer.exe from System32 is WARNING (the real one lives in the Windows root)' ((V 'explorer.exe' 'C:\Windows\System32\explorer.exe') -eq 'WARNING') ''
    T 'lsass.exe from SysWOW64 is WARNING (no 32-bit lsass exists)' ((V 'lsass.exe' 'C:\Windows\SysWOW64\lsass.exe') -eq 'WARNING') ''
    T 'WmiPrvSE.exe directly in System32 is WARNING (it lives in wbem)' ((V 'WmiPrvSE.exe' 'C:\Windows\System32\WmiPrvSE.exe') -eq 'WARNING') ''
    T 'MsMpEng.exe from Users\Public is WARNING' ((V 'MsMpEng.exe' 'C:\Users\Public\MsMpEng.exe') -eq 'WARNING') ''
    T 'a name spelled SVCHOST.EXE from Downloads is still graded (case-insensitive lookup)' ((V 'SVCHOST.EXE' 'C:\Users\u\Downloads\SVCHOST.EXE') -eq 'WARNING') ''
    $w = Get-MasqueradeVerdict -Name 'svchost.exe' -ProcPath 'C:\Users\u\AppData\Roaming\svchost.exe' -SystemRoot $root
    T 'the WARNING names where the genuine binary lives' ($w.Why -match 'lives only in C:\\WINDOWS\\System32 or C:\\WINDOWS\\SysWOW64') $w.Why

    # The snapshot as Section 4 writes it: `Name  PID  Path`, path optional.
    $dump = @(
        'svchost.exe  1234  C:\WINDOWS\system32\svchost.exe',
        'Explorer.EXE  5678  C:\WINDOWS\Explorer.EXE',
        'brave.exe  25976  C:\Users\khali\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe',
        'csrss.exe  700  ',
        'System  4  ',
        'svchost.exe  9999  C:\Users\Public\dz_selftest_masq\svchost.exe'
    )
    $r = Get-MasqueradeReport -Lines $dump -SystemRoot $root
    T 'a snapshot with one masquerading svchost.exe raises exactly one WARNING and the marker' ($r.Marker -eq 'WARNING' -and @($r.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 1) ($r.Lines -join ' | ')
    T 'the WARNING line carries the name, the PID and the directory' (($r.Lines -join "`n") -match '\[WARNING\] Process svchost\.exe \(PID 9999\) runs from C:\\Users\\Public\\dz_selftest_masq --') ($r.Lines -join ' | ')
    T 'the pathless csrss.exe is counted as not graded, and said so' (($r.Lines -join "`n") -match '\[INFO\] 1 system-process name\(s\) had no readable path') ($r.Lines -join ' | ')
    $clean = Get-MasqueradeReport -Lines ($dump | Select-Object -First 5) -SystemRoot $root
    T 'the same snapshot without the impostor is OK with no marker' ($null -eq $clean.Marker -and (($clean.Lines -join "`n") -match '\[OK\] 2 system-process name\(s\) run from their canonical directories')) ($clean.Lines -join ' | ')
    $none = Get-MasqueradeReport -Lines @('', '   ') -SystemRoot $root
    T 'an empty snapshot is SKIPPED, never OK' ($null -eq $none.Marker -and (($none.Lines -join "`n") -match '^\[SKIPPED\]')) ($none.Lines -join ' | ')
    $noroot = Get-MasqueradeReport -Lines $dump -SystemRoot ''
    T 'no Windows directory: every system name is unverified, nothing is cleared, and the block says SKIPPED' ($null -eq $noroot.Marker -and (($noroot.Lines -join "`n") -notmatch '\[OK\]') -and (($noroot.Lines -join "`n") -match '\[INFO\] 4 system-process name') -and (($noroot.Lines -join "`n") -match '\[SKIPPED\] no system-process path could be graded')) ($noroot.Lines -join ' | ')

    # ---- by parent ----
    function PV { param([string]$n, $ct, $par, [bool]$present = $true, [bool]$moved = $false, $cs = $null, $alive = $true) Get-ParentVerdict -Name $n -ChildTicks $ct -ChildSession $cs -Parent $par -RightfulPresent $present -ClockMoved $moved -AliveInSession $alive }
    function Par { param([int]$procId, [string]$n, $t, $s = $null) @{ Pid = $procId; Name = $n; Ticks = $t; Session = $s } }
    # Rightful parents: OK. A parent that is one process (System, smss,
    # wininit, services) is OK whatever the times say.
    T 'svchost.exe started by services.exe is OK' ((PV 'svchost.exe' 1300 (Par 900 'services.exe' 1200)).Sev -eq 'OK') ''
    T 'svchost.exe under services.exe is OK even when the clock makes services.exe look younger (a backward clock step is not a reused PID)' ((PV 'svchost.exe' 1300 (Par 900 'services.exe' 9000)).Sev -eq 'OK') ''
    T 'lsass.exe and services.exe started by wininit.exe are OK' ((PV 'lsass.exe' 1210 (Par 780 'wininit.exe' 1011)).Sev -eq 'OK' -and (PV 'services.exe' 1200 (Par 780 'wininit.exe' 1011)).Sev -eq 'OK') ''
    T 'LsaIso.exe (Credential Guard) started by wininit.exe is OK' ((PV 'LsaIso.exe' 1220 (Par 780 'wininit.exe' 1011)).Sev -eq 'OK') ''
    T 'smss.exe started by System (PID 4, no creation time) is OK' ((PV 'smss.exe' 1002 (Par 4 'System' $null)).Sev -eq 'OK') ''
    T 'csrss.exe started by a living smss.exe is OK' ((PV 'csrss.exe' 1010 (Par 612 'smss.exe' 1005)).Sev -eq 'OK') ''
    T 'dwm.exe started by the winlogon.exe of its own session is OK' ((PV 'dwm.exe' 1040 (Par 860 'winlogon.exe' 1013 1) $true $false 1).Sev -eq 'OK') ''
    T 'dwm.exe under its own session''s winlogon.exe is OK even when the clock makes winlogon look younger (the session decides, not the clock)' ((PV 'dwm.exe' 1040 (Par 860 'winlogon.exe' 9000 1) $true $false 1).Sev -eq 'OK') ''
    T 'fontdrvhost.exe started by wininit.exe or by its own session''s winlogon.exe is OK' ((PV 'fontdrvhost.exe' 1031 (Par 780 'wininit.exe' 1011 0) $true $false 0).Sev -eq 'OK' -and (PV 'fontdrvhost.exe' 1032 (Par 860 'winlogon.exe' 1013 1) $true $false 1).Sev -eq 'OK') ''
    T 'RuntimeBroker.exe and WmiPrvSE.exe started by an older svchost.exe are OK' ((PV 'RuntimeBroker.exe' 2000 (Par 1000 'svchost.exe' 1030)).Sev -eq 'OK' -and (PV 'WmiPrvSE.exe' 2100 (Par 1000 'svchost.exe' 1030)).Sev -eq 'OK') ''
    T 'dllhost.exe started by services.exe (the COM+ System Application service) is OK, as is one started by an older svchost.exe' ((PV 'dllhost.exe' 2200 (Par 900 'services.exe' 1200)).Sev -eq 'OK' -and (PV 'dllhost.exe' 2200 (Par 1000 'svchost.exe' 1030)).Sev -eq 'OK') ''
    T 'dllhost.exe under a services.exe that looks younger is OK (services.exe is one process; time is not consulted)' ((PV 'dllhost.exe' 2200 (Par 900 'services.exe' 9000)).Sev -eq 'OK') ''
    $svc = $true
    foreach ($n in 'spoolsv.exe', 'SearchIndexer.exe', 'SecurityHealthService.exe', 'MsMpEng.exe', 'NisSrv.exe') { if ((PV $n 1300 (Par 900 'services.exe' 1200)).Sev -ne 'OK') { $svc = $false } }
    T 'every service-started name in the table is OK under services.exe' $svc ''
    T 'names compare case-insensitively (SVCHOST.EXE under Services.exe)' ((PV 'SVCHOST.EXE' 1300 (Par 900 'Services.exe' 1200)).Sev -eq 'OK') ''
    # A parent that exits by design is counted, never graded.
    T 'csrss.exe whose session smss.exe has exited is EXITED, not a finding' ((PV 'csrss.exe' 1010 $null).Sev -eq 'EXITED') ''
    T 'winlogon.exe whose parent PID now belongs to a LATER process is EXITED (PID reuse), not a finding' ((PV 'winlogon.exe' 1013 (Par 770 'chrome.exe' 5000)).Sev -eq 'EXITED') ''
    T 'taskhostw.exe whose service host has exited is EXITED, not a finding' ((PV 'taskhostw.exe' 2000 $null).Sev -eq 'EXITED') ''
    T 'taskhostw.exe under a LATER svchost.exe is EXITED (its service host restarted), not a finding' ((PV 'taskhostw.exe' 2000 (Par 1000 'svchost.exe' 5000)).Sev -eq 'EXITED') ''
    # csrss, wininit and winlogon are graded by one per session, never by the
    # clock: a living wrong-named parent that looks older is UNVERIFIED.
    $nc = $true
    foreach ($n in 'csrss.exe', 'wininit.exe', 'winlogon.exe') { if ((PV $n 1300 (Par 2500 'cmd.exe' 1250)).Sev -ne 'UNVERIFIED') { $nc = $false } }
    T 'csrss, wininit and winlogon under a living, OLDER cmd.exe are not graded by parent (one per session grades them, so no clock step can raise one)' $nc ''
    # A session that is ending: its winlogon.exe exited first.
    T 'dwm.exe whose parent is gone, in a session with no winlogon.exe left, is EXITED (a session that is ending)' ((PV 'dwm.exe' 1040 $null $true $false 2 $false).Sev -eq 'EXITED') ''
    T 'logonui.exe and fontdrvhost.exe with no parent, or userinit.exe under a LATER process, in a session with no winlogon.exe are EXITED too' ((PV 'logonui.exe' 1040 $null $true $false 2 $false).Sev -eq 'EXITED' -and (PV 'userinit.exe' 1040 (Par 2500 'cmd.exe' 5000 2) $true $false 2 $false).Sev -eq 'EXITED' -and (PV 'fontdrvhost.exe' 1040 $null $true $false 2 $false).Sev -eq 'EXITED') ''
    T 'userinit.exe under a living, OLDER cmd.exe in a session that is ending is WARNING: an older holder is no reused number, it started the child' ((PV 'userinit.exe' 1040 (Par 2500 'cmd.exe' 1000 2) $true $false 2 $false).Sev -eq 'WARNING') ''
    T 'in a session that is ending, a living holder with no creation time, the same time, or a moved clock is UNVERIFIED' ((PV 'dwm.exe' 1040 (Par 2500 'cmd.exe' $null 2) $true $false 2 $false).Sev -eq 'UNVERIFIED' -and (PV 'dwm.exe' 1040 (Par 2500 'cmd.exe' 1040 2) $true $false 2 $false).Sev -eq 'UNVERIFIED' -and (PV 'dwm.exe' 1040 (Par 2500 'cmd.exe' 1000 2) $true $true 2 $false).Sev -eq 'UNVERIFIED') ''
    T 'dwm.exe with no session is UNVERIFIED, never graded' ((PV 'dwm.exe' 1040 $null $true $false $null $null).Sev -eq 'UNVERIFIED' -and (PV 'dwm.exe' 1040 (Par 860 'winlogon.exe' 1013 1) $true $false $null).Sev -eq 'UNVERIFIED') ''
    # Must raise.
    $w = PV 'svchost.exe' 1300 (Par 3000 'explorer.exe' 1250)
    T 'svchost.exe whose parent PID is explorer.exe is WARNING, and names services.exe' ($w.Sev -eq 'WARNING' -and $w.Kind -eq 'other' -and $w.Why -match 'only from services\.exe') ($w.Why)
    $w = PV 'svchost.exe' 1300 (Par 3000 'explorer.exe' 9000)
    T 'svchost.exe whose parent PID is a NEWER explorer.exe is still WARNING, and is told as a reused number: services.exe never exits, so its PID was never free' ($w.Sev -eq 'WARNING' -and $w.Kind -eq 'reused') ($w.Kind)
    T 'lsass.exe started by cmd.exe is WARNING' ((PV 'lsass.exe' 1300 (Par 2500 'cmd.exe' 1250)).Sev -eq 'WARNING') ''
    T 'services.exe started by explorer.exe is WARNING' ((PV 'services.exe' 1300 (Par 3000 'explorer.exe' 1250)).Sev -eq 'WARNING') ''
    T 'RuntimeBroker.exe whose parent is gone is WARNING: the DCOM launcher''s service host never exits' ((PV 'RuntimeBroker.exe' 2000 $null).Sev -eq 'WARNING') ''
    $g = PV 'svchost.exe' 1300 $null
    T 'svchost.exe whose parent is no longer running is WARNING: services.exe runs until shutdown' ($g.Sev -eq 'WARNING' -and $g.Kind -eq 'gone' -and $g.Why -match 'runs until shutdown') ($g.Why)
    T 'smss.exe started by cmd.exe, or whose parent is gone, is WARNING' ((PV 'smss.exe' 1300 (Par 2500 'cmd.exe' 1250)).Sev -eq 'WARNING' -and (PV 'smss.exe' 1300 $null).Sev -eq 'WARNING') ''
    T 'svchost.exe started by System (PID 4) is WARNING: System is not services.exe' ((PV 'svchost.exe' 1300 (Par 4 'System' $null)).Sev -eq 'WARNING') ''
    T 'smss.exe whose parent calls itself System but is not PID 4 is WARNING: System is PID 4 and nothing else' ((PV 'smss.exe' 1300 (Par 666 'System' 1250)).Sev -eq 'WARNING') ''
    $w = PV 'taskhostw.exe' 2000 (Par 2500 'cmd.exe' 1250)
    T 'taskhostw.exe under a living, OLDER cmd.exe is WARNING (its parent is told by creation time)' ($w.Sev -eq 'WARNING' -and $w.Kind -eq 'other' -and $w.Why -ceq 'Windows starts taskhostw.exe only from svchost.exe') ($w.Why)
    # A service host is one of many: one started after the child is not what
    # started it.
    $w = PV 'RuntimeBroker.exe' 2000 (Par 1000 'svchost.exe' 5000)
    T 'RuntimeBroker.exe under an svchost.exe created AFTER it is WARNING: whatever started it is gone, and the number was reused' ($w.Sev -eq 'WARNING' -and $w.Kind -eq 'reused') ($w.Sev + ' ' + $w.Kind)
    T 'dllhost.exe under an svchost.exe created after it is WARNING too' ((PV 'dllhost.exe' 2200 (Par 1000 'svchost.exe' 5000)).Sev -eq 'WARNING') ''
    $w = PV 'dwm.exe' 1040 (Par 870 'winlogon.exe' 1000 2) $true $false 1
    T 'dwm.exe in session 1 under the winlogon.exe of session 2 is WARNING (a winlogon.exe only starts processes in its own session)' ($w.Sev -eq 'WARNING' -and $w.Kind -eq 'other') ($w.Sev)
    T 'dwm.exe whose parent is gone while its session''s winlogon.exe runs is WARNING' ((PV 'dwm.exe' 1040 $null $true $false 1 $true).Sev -eq 'WARNING') ''
    T 'fontdrvhost.exe in session 0 whose parent is gone while wininit.exe runs is WARNING' ((PV 'fontdrvhost.exe' 1031 $null $true $false 0 $true).Sev -eq 'WARNING') ''
    # Each finding says why the rightful parent cannot have exited.
    T 'services.exe: "only from wininit.exe, which runs until shutdown"' ((PV 'services.exe' 1300 $null).Why -ceq 'Windows starts services.exe only from wininit.exe, which runs until shutdown') ((PV 'services.exe' 1300 $null).Why)
    T 'RuntimeBroker.exe names the DCOM launcher''s service host' ((PV 'RuntimeBroker.exe' 2000 $null).Why -ceq 'Windows starts runtimebroker.exe only from svchost.exe (the DCOM launcher''s service host), which runs until shutdown') ((PV 'RuntimeBroker.exe' 2000 $null).Why)
    T 'dwm.exe names its own session''s winlogon.exe, which runs as long as that session' ((PV 'dwm.exe' 1040 $null $true $false 1 $true).Why -ceq 'Windows starts dwm.exe only from the winlogon.exe of its own session, which runs as long as that session') ((PV 'dwm.exe' 1040 $null $true $false 1 $true).Why)
    T 'smss.exe names System or the first smss.exe, which run until shutdown' ((PV 'smss.exe' 1300 $null).Why -ceq 'Windows starts smss.exe only from System or the first smss.exe, which run until shutdown') ((PV 'smss.exe' 1300 $null).Why)
    # Cannot tell.
    T 'a snapshot with no services.exe at all: an svchost.exe with no parent is UNVERIFIED (incomplete), not a finding' ((PV 'svchost.exe' 1300 $null $false).Sev -eq 'UNVERIFIED') ''
    T 'a clock that moved does not hide svchost.exe under explorer.exe (time is not consulted for a parent that never exits)' ((PV 'svchost.exe' 1300 (Par 3000 'explorer.exe' 1250) $true $true).Sev -eq 'WARNING') ''
    T 'a clock that moved: RuntimeBroker.exe under any svchost.exe is UNVERIFIED (which service host started it cannot be told)' ((PV 'RuntimeBroker.exe' 2000 (Par 1000 'svchost.exe' 5000) $true $true).Sev -eq 'UNVERIFIED' -and (PV 'RuntimeBroker.exe' 2000 (Par 1000 'svchost.exe' 1030) $true $true).Sev -eq 'UNVERIFIED') ''
    T 'no creation time on an svchost.exe parent, or the same time as the child, is UNVERIFIED' ((PV 'RuntimeBroker.exe' 2000 (Par 1000 'svchost.exe' $null)).Sev -eq 'UNVERIFIED' -and (PV 'RuntimeBroker.exe' $null (Par 1000 'svchost.exe' 1030)).Sev -eq 'UNVERIFIED' -and (PV 'RuntimeBroker.exe' 2000 (Par 1000 'svchost.exe' 2000)).Sev -eq 'UNVERIFIED') ''
    T 'a clock that moved, equal times, or no times: taskhostw.exe under a wrong-named holder is UNVERIFIED' ((PV 'taskhostw.exe' 2000 (Par 2500 'cmd.exe' 1250) $true $true).Sev -eq 'UNVERIFIED' -and (PV 'taskhostw.exe' 2000 (Par 2500 'cmd.exe' 2000)).Sev -eq 'UNVERIFIED' -and (PV 'taskhostw.exe' $null (Par 2500 'cmd.exe' 1250)).Sev -eq 'UNVERIFIED') ''
    $ign = $true
    foreach ($n in 'explorer.exe', 'conhost.exe', 'rundll32.exe', 'WerFault.exe', 'ctfmon.exe', 'chrome.exe') { if ((PV $n 1300 (Par 2500 'cmd.exe' 1250)).Sev -ne 'IGNORED') { $ign = $false } }
    T 'names whose parent varies by design (explorer, conhost, rundll32, werfault, ctfmon) are not graded by parent' $ign ''

    # The report, on a Windows 11-shaped tree (PID|PPID|ticks|session|path|name):
    # session smss instances gone (612, 770), winlogon's parent PID reused by a
    # later chrome.exe, explorer.exe whose userinit has exited.
    $tree = @(
        '0|0||0||System Idle Process', '4|0||0||System', '128|4|1001|0||Registry', '520|4|1002|0|C:\Windows\System32\smss.exe|smss.exe',
        '700|612|1010|0||csrss.exe', '780|612|1011|0||wininit.exe', '790|770|1012|1||csrss.exe', '860|770|1013|1|C:\Windows\System32\winlogon.exe|winlogon.exe',
        '900|780|1020|0||services.exe', '920|780|1021|0||lsass.exe', '930|780|1022|0||LsaIso.exe',
        '1000|900|1030|0|C:\Windows\System32\svchost.exe|svchost.exe', '1010|780|1031|0||fontdrvhost.exe', '1020|860|1032|1||fontdrvhost.exe', '1100|860|1040|1||dwm.exe',
        '1500|900|1050|0||spoolsv.exe', '1600|900|1060|0||MsMpEng.exe', '1700|900|1065|0|C:\Windows\System32\dllhost.exe|dllhost.exe',
        '2000|1000|1100|1||RuntimeBroker.exe', '2100|1000|1110|0||WmiPrvSE.exe',
        '2200|1000|1120|1||taskhostw.exe', '2300|1000|1130|1||sihost.exe', '3000|2900|1200|1|C:\Windows\explorer.exe|explorer.exe', '3100|3000|1300|1||ctfmon.exe',
        '770|3000|5000|1||chrome.exe'
    )
    $pr = Get-ParentReport -Tree $tree
    $pt = $pr.Lines -join "`n"
    T 'a real-shaped Windows tree raises nothing and prints the OK line' ($null -eq $pr.Marker -and $null -eq $pr.CountMarker -and $pt -match '\[OK\] \d+ system-process name\(s\) were started by the parent Windows uses' -and $pt -notmatch '\[WARNING\]') $pt
    T 'the parents that exited by design (two csrss, wininit, winlogon) are counted, not graded' ($pt -match '\[INFO\] 4 system-process name\(s\) whose parent is no longer running') $pt
    T 'a clean tree with ordered times does not read as a clock that moved' ($pt -notmatch 'The clock moved backward') $pt
    $bad = $tree + @('4242|3000|6000|1|C:\Windows\System32\svchost.exe|svchost.exe', '4243|5555|6001|1|C:\Users\Public\x\svchost.exe|svchost.exe')
    $pr = Get-ParentReport -Tree $bad
    $pt = $pr.Lines -join "`n"
    T 'two svchost.exe impostors: two WARNINGs and the marker' ($pr.Marker -eq 'WARNING' -and @($pr.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 2) $pt
    T 'a System32 svchost.exe whose parent PID is explorer.exe is named, with both processes beneath it' ($pt -match '\[WARNING\] Process svchost\.exe \(PID 4242\) has the wrong parent: PID 3000 belongs to explorer\.exe -- Windows starts svchost\.exe only from services\.exe, which runs until shutdown \(T1036 masquerading by parent\)' -and $pt -match '(?m)^    child:  C:\\Windows\\System32\\svchost\.exe, session 1, started ' -and $pt -match '(?m)^    parent: explorer\.exe \(PID 3000\) C:\\Windows\\explorer\.exe, session 1, started ') $pt
    T 'an svchost.exe whose parent is gone says so' ($pt -match '\[WARNING\] Process svchost\.exe \(PID 4243\) has the wrong parent: the process that started it \(PID 5555\) is no longer running -- Windows starts svchost\.exe only from services\.exe, which runs until shutdown' -and $pt -match '(?m)^    parent: PID 5555 is no longer running$') $pt
    T 'the times are shown in UTC' ($pt -match 'started \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z') $pt
    # A reused number: RuntimeBroker.exe whose parent PID now belongs to a
    # service host started after it. Named as such, and not mistaken for a
    # clock that moved (that would hide it).
    $pr = Get-ParentReport -Tree ($tree + @('6200|6150|1500|1||RuntimeBroker.exe', '6150|900|7000|0|C:\Windows\System32\svchost.exe|svchost.exe'))
    $pt = $pr.Lines -join "`n"
    T 'RuntimeBroker.exe whose parent PID belongs to a LATER svchost.exe is named as a reused number, and the clock is not blamed' ($pr.Marker -eq 'WARNING' -and $pt -match '\[WARNING\] Process RuntimeBroker\.exe \(PID 6200\) has the wrong parent: the process that started it \(PID 6150\) is no longer running -- Windows starts runtimebroker\.exe only from svchost\.exe \(the DCOM launcher''s service host\), which runs until shutdown' -and $pt -match '(?m)^    parent: PID 6150 is no longer running; the number now belongs to a later process, svchost\.exe C:\\Windows\\System32\\svchost\.exe, session 0, started ' -and $pt -notmatch 'The clock moved backward') $pt
    # A session that is ending: dwm and fontdrvhost of session 2 outlived its
    # winlogon.exe. Counted, never a finding. In session 1, whose winlogon.exe
    # runs, the same shape is a finding.
    $pr = Get-ParentReport -Tree ($tree + @('6300|6100|1400|2||dwm.exe', '6310|6100|1401|2||fontdrvhost.exe', '6320|6100|1402|2||csrss.exe'))
    $pt = $pr.Lines -join "`n"
    T 'a session whose winlogon.exe has exited: its dwm.exe and fontdrvhost.exe are counted as exited, not flagged' ($null -eq $pr.Marker -and $pt -match '\[INFO\] 7 system-process name\(s\) whose parent is no longer running') $pt
    $pr = Get-ParentReport -Tree ($tree + @('6300|6100|1400|1||dwm.exe'))
    T 'a dwm.exe in session 1, whose winlogon.exe runs, with its parent gone is a finding (and a second dwm is not graded by count)' ($pr.Marker -eq 'WARNING' -and ($pr.Lines -join "`n") -match '\[WARNING\] Process dwm\.exe \(PID 6300\) has the wrong parent: the process that started it \(PID 6100\) is no longer running -- Windows starts dwm\.exe only from the winlogon\.exe of its own session, which runs as long as that session') ($pr.Lines -join ' | ')
    # Session 0 lasts until shutdown and never holds a winlogon.exe: a dwm,
    # LogonUI or userinit there is not "a session that is ending". It is where
    # a SYSTEM service, scheduled task, PsExec or WMI launch lands.
    foreach ($s0 in @(@('7100|900|6000|0|C:\Windows\System32\dwm.exe|dwm.exe', 'dwm.exe under services.exe'),
                      @('7101|1000|6000|0|C:\Windows\System32\LogonUI.exe|LogonUI.exe', 'LogonUI.exe under svchost.exe'),
                      @('7102|6999|6000|0||userinit.exe', 'userinit.exe whose parent is gone'))) {
        $pr = Get-ParentReport -Tree ($tree + @($s0[0]))
        T ('a ' + $s0[1] + ' in session 0 is a finding, never "a session that is ending"') ($pr.Marker -eq 'WARNING' -and ($pr.Lines -join "`n") -notmatch '\[OK\]') ($pr.Lines -join ' | ')
    }
    $pr = Get-ParentReport -Tree ($tree + @('6990|1000|5900|0|C:\Windows\System32\cmd.exe|cmd.exe', '7103|6990|6000|0|C:\ProgramData\x\dwm.exe|dwm.exe'))
    T 'a dwm.exe in session 0 started by cmd.exe is named, with cmd.exe as its parent' ($pr.Marker -eq 'WARNING' -and ($pr.Lines -join "`n") -match '\(PID 7103\) has the wrong parent: PID 6990 belongs to cmd\.exe -- Windows starts dwm\.exe only from the winlogon\.exe of its own session') ($pr.Lines -join ' | ')
    # Each way the clock is seen to have moved, alone. A process older than
    # the smss.exe System started:
    $pr = Get-ParentReport -Tree ($tree + @('5150|3000|900|1||notepad.exe'))
    T 'a process recorded before the System-started smss.exe, alone, reads as a clock that moved' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '\[INFO\] The clock moved backward since this boot') ($pr.Lines -join ' | ')
    # ...an svchost.exe older than the services.exe that started it, but not
    # older than smss:
    $pr = Get-ParentReport -Tree ($tree + @('5100|900|1015|0|C:\Windows\System32\svchost.exe|svchost.exe'))
    T 'an svchost.exe recorded before its services.exe (but after smss), alone, reads as a clock that moved' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '\[INFO\] The clock moved backward since this boot') ($pr.Lines -join ' | ')
    # ...and a service host's child recorded before the FIRST service host: a
    # few seconds' step back soon after boot. The genuine WmiPrvSE must not be
    # read as a reused number.
    $pr = Get-ParentReport -Tree ($tree + @('2150|1000|1025|0|C:\Windows\System32\wbem\WmiPrvSE.exe|WmiPrvSE.exe'))
    T 'a WmiPrvSE.exe recorded before the first service host (a small step back soon after boot) reads as a clock that moved, not a finding' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '\[INFO\] The clock moved backward since this boot') ($pr.Lines -join ' | ')
    # A copy of its parent: the same name and image as the process recorded
    # as its parent. Both directions: what a copy is, and what is not one.
    # Not CP: on Windows that is an alias of Copy-Item, and an alias wins over
    # a function (pwsh on Linux drops it, so only Windows would have shown it).
    function CopyOf { param([string]$cn, [string]$cp, [string]$pn, [string]$pp) Test-IsCopy -Child @{ Name = $cn; Path = $cp } -Parent @{ Name = $pn; Path = $pp } }
    $L = 'C:\Windows\System32\lsass.exe'
    T 'lsass.exe under lsass.exe with the same image is a copy' ((CopyOf 'lsass.exe' $L 'lsass.exe' $L) -eq 'same image') ''
    T 'names and paths compare case-insensitively' ((CopyOf 'LSASS.EXE' 'c:\windows\system32\LSASS.exe' 'lsass.exe' $L) -eq 'same image') ''
    T 'lsass.exe under lsass.exe from ANOTHER path is not a copy (the other rules grade an impostor)' ($null -eq (CopyOf 'lsass.exe' 'C:\Users\Public\lsass.exe' 'lsass.exe' $L)) ''
    T 'with a path unreadable (another user''s process on a standard-user token), the same name is a copy, said so' ((CopyOf 'lsass.exe' '' 'lsass.exe' '') -eq 'same name' -and (CopyOf 'lsass.exe' $L 'lsass.exe' '') -eq 'same name') ''
    T 'smss.exe under smss.exe is no copy: the first smss starts one for each session by design' ($null -eq (CopyOf 'smss.exe' 'C:\Windows\System32\smss.exe' 'smss.exe' 'C:\Windows\System32\smss.exe')) ''
    T 'browsers and explorer start children from their own image: chrome.exe, msedge.exe or explorer.exe under itself is no copy' ($null -eq (CopyOf 'chrome.exe' 'C:\Program Files\Google\Chrome\Application\chrome.exe' 'chrome.exe' 'C:\Program Files\Google\Chrome\Application\chrome.exe') -and $null -eq (CopyOf 'msedge.exe' 'C:\x\msedge.exe' 'msedge.exe' 'C:\x\msedge.exe') -and $null -eq (CopyOf 'explorer.exe' 'C:\Windows\explorer.exe' 'explorer.exe' 'C:\Windows\explorer.exe')) ''
    T 'a different name is no copy, and no parent is no copy' ($null -eq (CopyOf 'lsass.exe' $L 'wininit.exe' 'C:\Windows\System32\wininit.exe') -and $null -eq (Test-IsCopy -Child @{ Name = 'lsass.exe'; Path = $L } -Parent $null)) ''
    $treeL = $tree | ForEach-Object { if ($_ -like '920|*') { '920|780|1021|0|C:\Windows\System32\lsass.exe|lsass.exe' } else { $_ } }
    $pr = Get-ParentReport -Tree ($treeL + @('9920|920|6000|0|C:\Windows\System32\lsass.exe|lsass.exe'))
    $pt = $pr.Lines -join "`n"
    T 'a copy of LSASS is CRITICAL, on its own row, named once: no wrong-parent line and no second-instance line for it' ($pr.LsassCopyMarker -eq 'CRITICAL' -and $null -eq $pr.Marker -and $null -eq $pr.CountMarker -and $null -eq $pr.CopyMarker -and $pt -match '(?m)^\[CRITICAL\] Process lsass\.exe \(PID 9920\) is a copy of LSASS \(PID 920\), same image -- a second process holding LSASS''s memory, the shape credential-dumping tools leave \(T1003.001\)' -and $pt -notmatch 'Windows runs one lsass' -and $pt -notmatch 'PID 9920\) has the wrong parent') $pt
    T 'the LSASS copy shows the copy and its parent beneath it' ($pt -match '(?m)^    copy:   C:\\Windows\\System32\\lsass\.exe, session 0, started ' -and $pt -match '(?m)^    parent: lsass\.exe \(PID 920\) C:\\Windows\\System32\\lsass\.exe, session 0, started ') $pt
    $pr = Get-ParentReport -Tree ($tree + @('9930|1000|6000|0|C:\Windows\System32\svchost.exe|svchost.exe'))
    $pt = $pr.Lines -join "`n"
    T 'a copy of an svchost.exe is a WARNING on its own row (an error report, or code injection by forking)' ($pr.CopyMarker -eq 'WARNING' -and $null -eq $pr.Marker -and $null -eq $pr.LsassCopyMarker -and $pt -match '(?m)^\[WARNING\] Process svchost\.exe \(PID 9930\) is a copy of its parent svchost\.exe \(PID 1000\), same image -- Windows Error Reporting copies a hung process this way, and so does code injection by forking \(T1055\)') $pt
    $pr = Get-ParentReport -Tree ($tree + @('9940|3000|6000|1|C:\Windows\explorer.exe|explorer.exe', '9950|9951|6000|1|C:\x\chrome.exe|chrome.exe', '9951|3000|5900|1|C:\x\chrome.exe|chrome.exe', '9960|520|6000|1|C:\Windows\System32\smss.exe|smss.exe'))
    T 'explorer under explorer, chrome under chrome and a session smss under the first smss raise nothing' ($null -eq $pr.Marker -and $null -eq $pr.CountMarker -and $null -eq $pr.CopyMarker -and $null -eq $pr.LsassCopyMarker -and ($pr.Lines -join "`n") -match '\[OK\]') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree ($treeL + @('9970|920|6000|0|C:\Users\Public\lsass.exe|lsass.exe'))
    $pt = $pr.Lines -join "`n"
    T 'an lsass.exe from another path under the real LSASS is no copy: graded as a wrong parent and a second instance' ($null -eq $pr.LsassCopyMarker -and $pr.Marker -eq 'WARNING' -and $pr.CountMarker -eq 'WARNING' -and $pt -match '\(PID 9970\) has the wrong parent: PID 920 belongs to lsass\.exe') $pt
    $pr = Get-ParentReport -Tree ($tree + @('9980|9979|6000|0||lsass.exe'))
    T 'an lsass.exe whose parent has exited is no copy (nothing to compare): graded as today' ($null -eq $pr.LsassCopyMarker -and $pr.Marker -eq 'WARNING' -and $pr.CountMarker -eq 'WARNING') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree ($tree + @('9990|920|6000|0||lsass.exe'))
    T 'on a standard-user token (no paths) an lsass.exe under LSASS is a copy by name, and says the image could not be compared' ($pr.LsassCopyMarker -eq 'CRITICAL' -and ($pr.Lines -join "`n") -match 'is a copy of LSASS \(PID 920\), same name -- ') ($pr.Lines -join ' | ')

    # The renamed chain: a launcher that exits starts a fake wininit, which
    # starts a fake services, which starts an implant svchost. Every parent
    # NAME looks right; one of each is what gives it away.
    $chain = $tree + @('8000|7999|6000|0|C:\ProgramData\w\wininit.exe|wininit.exe', '8001|8000|6001|0|C:\ProgramData\w\services.exe|services.exe', '8002|8001|6002|0|C:\ProgramData\w\svchost.exe|svchost.exe')
    $pr = Get-ParentReport -Tree $chain
    $pt = $pr.Lines -join "`n"
    T 'a renamed chain (fake wininit -> fake services -> implant svchost) is caught: two wininit and two services, on the one-of-each row (no parent is wrong)' ($pr.CountMarker -eq 'WARNING' -and $null -eq $pr.Marker -and $pt -match '\[WARNING\] Windows runs one services\.exe; this snapshot holds 2' -and $pt -match '\[WARNING\] Windows runs one wininit\.exe; this snapshot holds 2' -and $pt -match '(?m)^    instance: PID 8001, parent wininit\.exe \(PID 8000\), C:\\ProgramData\\w\\services\.exe, session 0') $pt
    $pr = Get-ParentReport -Tree ($tree + @('7000|6999|6000|1||csrss.exe'))
    T 'a second csrss.exe in session 1 is caught, even though its parent exited (the dropper case)' ($pr.CountMarker -eq 'WARNING' -and ($pr.Lines -join "`n") -match '\[WARNING\] Windows runs one csrss\.exe per session; session 1 has 2') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree ($tree + @('7000|3000|6000|1|C:\Users\Public\w\wininit.exe|wininit.exe'))
    T 'a wininit.exe started by explorer.exe is caught by count (Windows runs one), not by its parent' ($pr.CountMarker -eq 'WARNING' -and $null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '\[WARNING\] Windows runs one wininit\.exe; this snapshot holds 2' -and ($pr.Lines -join "`n") -notmatch 'PID 7000\) has the wrong parent') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree ($tree | ForEach-Object { if ($_ -like '920|*') { '920|780|1021|1||lsass.exe' } else { $_ } })
    T 'lsass.exe outside session 0 is caught, on the one-of-each row' ($pr.CountMarker -eq 'WARNING' -and $null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '\[WARNING\] Process lsass\.exe \(PID 920\) runs in session 1 -- Windows runs lsass\.exe only in session 0') ($pr.Lines -join ' | ')
    # A session ID is a 32-bit unsigned number; the largest must parse.
    $pr = Get-ParentReport -Tree ($tree | ForEach-Object { if ($_ -like '920|*') { '920|780|1021|4294967295||lsass.exe' } else { $_ } })
    T 'a ten-digit session ID parses (4294967295 is not dropped or overflowed)' ($pr.CountMarker -eq 'WARNING' -and ($pr.Lines -join "`n") -match '\(PID 920\) runs in session 4294967295 -- ') ($pr.Lines -join ' | ')
    # A clock that stepped backward after boot: every svchost started after the
    # correction looks older than services.exe. Nothing may be flagged for it.
    $skew = $tree + @('5100|900|900|0|C:\Windows\System32\svchost.exe|svchost.exe', '5200|5150|950|1||taskhostw.exe', '5150|3000|900|1||notepad.exe')
    $pr = Get-ParentReport -Tree $skew
    $pt = $pr.Lines -join "`n"
    T 'a clock that moved backward: nothing is flagged for it, and the report says time was not used' ($null -eq $pr.Marker -and $pt -match '\[INFO\] The clock moved backward since this boot') $pt
    # Incomplete snapshots: they can show an impostor, never clear anything.
    $pr = Get-ParentReport -Tree ($tree | Where-Object { $_ -notlike '900|*' })
    T 'a snapshot that lost services.exe does not turn every svchost.exe into a finding, and is SKIPPED, not OK' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match 'could not be graded by parent' -and ($pr.Lines -join "`n") -match '\[SKIPPED\] the process snapshot holds no services\.exe' -and ($pr.Lines -join "`n") -notmatch '\[OK\]') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree ($tree | Where-Object { $_ -notlike '920|*' })
    T 'a snapshot with no lsass.exe is SKIPPED, never OK (every running Windows has one)' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '(?m)^\[SKIPPED\] the process snapshot holds no lsass\.exe, which every running Windows has' -and ($pr.Lines -join "`n") -notmatch '\[OK\]') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree (@($tree | Where-Object { $_ -notlike '920|*' }) + @('4242|3000|6000|1|C:\Windows\System32\svchost.exe|svchost.exe'))
    T 'an incomplete snapshot still shows an impostor, and says it is incomplete' ($pr.Marker -eq 'WARNING' -and ($pr.Lines -join "`n") -match '\(PID 4242\) has the wrong parent' -and ($pr.Lines -join "`n") -match '\[INFO\] The process snapshot holds no lsass\.exe') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree (@($tree | Where-Object { $_ -notlike '4|*' }) + @('666|3000|1500|1|C:\Users\Public\System|System'))
    T 'a process calling itself System that is not PID 4 does not stand in for it: SKIPPED, not OK' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '\[SKIPPED\] the process snapshot holds no System \(PID 4\)' -and ($pr.Lines -join "`n") -notmatch '\[OK\]') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree ($tree + @('666|3000|1500|1|C:\Users\Public\System|System', '6400|666|1600|1||smss.exe'))
    T 'smss.exe started by a fake System (not PID 4) is a finding' ($pr.Marker -eq 'WARNING' -and ($pr.Lines -join "`n") -match '\(PID 6400\) has the wrong parent: PID 666 belongs to System -- Windows starts smss\.exe only from System or the first smss\.exe') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree @('', 'garbage', '1|2|3|svchost.exe')
    T 'an empty, unparseable or old-format tree is SKIPPED, never OK' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '^\[SKIPPED\] the process tree snapshot held no parseable lines') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree @('4|0||0||System', '520|4||0||smss.exe', '700|612|||C:\Windows\System32\csrss.exe|csrss.exe', '900|780|||C:\Windows\System32\services.exe|services.exe', '920|780|||C:\Windows\System32\lsass.exe|lsass.exe', '1000|900|||C:\Windows\System32\svchost.exe|svchost.exe', '780|612|||C:\Windows\System32\wininit.exe|wininit.exe')
    T 'a tree with no creation times still grades, by name, the parents that are one process' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '\[OK\] 4 system-process name') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree @('9|4|1|0||Registry', '10|9|2|0||conhost.exe')
    T 'a tree with nothing gradable says SKIPPED, never OK' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '(?m)^\[SKIPPED\]' -and ($pr.Lines -join "`n") -notmatch '\[OK\]') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree @('900|780|1020|0||services.exe', '780|612|1011|0||wininit.exe', '1000|3000|1300|0||svchost.exe', ('3000|1|1250|1||evil' + [char]7 + 'name.exe'))
    T 'a control character in a parent name is not printed' ((($pr.Lines -join "`n") -notmatch [char]7) -and (($pr.Lines -join "`n") -match 'evil\?name\.exe')) ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree @('900|780|1020|0||services.exe', '780|612|1011|0||wininit.exe', '1000|900|1030|0||svchost.exe', '1000|3000|1030|0||svchost.exe')
    T 'a PID listed twice keeps its first record (no later line can overwrite it)' ($null -eq $pr.Marker) ($pr.Lines -join ' | ')

    if ($fails) { Write-Output "[FAIL] $fails masquerade_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] masquerade_check self-test: canonical directories in any casing are clean, a system name anywhere else is a WARNING, and a name with no path is stated as unverified; by parent, a parent that is one process (System at PID 4, smss, wininit, services) or the winlogon of the child''s own session is clean whatever the clock did, a service host counts only when it is older than the child, anything else at a parent that cannot exit is a WARNING, a session that is ending is counted not flagged, csrss/wininit/winlogon are graded by one per session and never by the clock, a snapshot missing a core process is SKIPPED, never OK, and a system process that is a copy of its parent is named as one (an LSASS copy CRITICAL), while browsers, explorer and the per-session smss are not.'
    exit 0
}

'--- [T1036] System-process name masquerading (a system name running outside its directory) ---'
if (-not $Path) {
    '[SKIPPED] masquerade_check: -Path <process snapshot> required -- the audit passes the Section 4 dump; masquerading check NOT performed.'
    exit 0
}
if (-not (Test-Path -LiteralPath $Path)) {
    "[SKIPPED] masquerade_check: snapshot '$Path' not found -- masquerading check NOT performed."
    exit 0
}
$lines = @()
try { $lines = @(Get-Content -LiteralPath $Path -EA Stop) } catch {
    "[SKIPPED] masquerade_check: snapshot unreadable ($($_.Exception.Message)) -- masquerading check NOT performed."
    exit 0
}
$report = Get-MasqueradeReport -Lines $lines -SystemRoot $SystemRoot
foreach ($l in $report.Lines) { $l }
if ($report.Marker) { Write-MarkerFile -Path $MarkerFile -Value $report.Marker }

'--- [T1036] System-process name masquerading by parent (a system name started by a parent Windows never uses) ---'
if (-not $TreePath) {
    '[SKIPPED] masquerade_check: -TreePath <process tree> not given -- masquerading by parent NOT verified.'
    exit 0
}
if (-not (Test-Path -LiteralPath $TreePath)) {
    "[SKIPPED] masquerade_check: process tree '$TreePath' not found -- masquerading by parent NOT verified."
    exit 0
}
$tree = @()
try { $tree = @(Get-Content -LiteralPath $TreePath -EA Stop) } catch {
    "[SKIPPED] masquerade_check: process tree unreadable ($($_.Exception.Message)) -- masquerading by parent NOT verified."
    exit 0
}
$parentReport = Get-ParentReport -Tree $tree
foreach ($l in $parentReport.Lines) { $l }
if ($parentReport.Marker) { Write-MarkerFile -Path $ParentMarkerFile -Value $parentReport.Marker }
if ($parentReport.CountMarker) { Write-MarkerFile -Path $CountMarkerFile -Value $parentReport.CountMarker }
if ($parentReport.LsassCopyMarker) { Write-MarkerFile -Path $LsassCopyMarkerFile -Value $parentReport.LsassCopyMarker }
if ($parentReport.CopyMarker) { Write-MarkerFile -Path $CopyMarkerFile -Value $parentReport.CopyMarker }
