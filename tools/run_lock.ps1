# run_lock.ps1 -- one audit at a time. Called by both bats before anything an
# audit shares with another is written.
#
# WHY. Two audits running at once corrupt each other. Both bats write the same
# fixed %TEMP%\dz_* names (markers, state files, staged blocks -- about 146 of
# them), and the same output folder (the runtime threat lists Section 18
# reads, SmartData, the baseline snapshot). It happens: INIT 8 writes a RunOnce
# resume entry so an interrupted run restarts at the next logon, and on CI it
# fired six seconds into a live run and a second audit ran beside the first --
# in that job the two shared the output folder, since the job points TEMP
# elsewhere. Microsoft documents that Windows deletes a RunOnce value BEFORE it
# runs the command ("Run and RunOnce Registry Keys"), so by then the first run
# has lost its resume protection anyway; what is left to protect is its
# results. A second audit started by hand, or the plant harness beside a real
# run, is the same collision. So the lock is taken in BOTH places a run shares:
# the temp folder and the output folder. A run is busy if either is held.
#
# THE LOCK names the process that holds it, not a time. The holder is this
# helper's PARENT -- the cmd.exe running the audit body (on the default path
# the console-log wrapper's child, the left side of its pipe, which lives
# exactly as long as the audit) -- recorded by PID, creation time and image
# name. A later invocation is BUSY only on positive evidence: a live process
# with that PID, that creation time and that name. Anything else is STALE and
# replaced, so the case resume exists for (a reboot or a crash mid-run, which
# leaves the lock behind) proceeds. An age threshold would block that resume or
# let a long audit be joined. Creation time is what defeats PID reuse.
#
# ONE WINDOW, ONE BATCH. An audit run with -noConsoleLog from an open Command
# Prompt runs in that prompt's own cmd.exe, so an interruption there (Ctrl+C,
# a parse abort) leaves a lock whose holder is still alive. Run again in the
# same window, the holder IS this run's parent -- and one cmd runs one batch at
# a time, so that lock is stale by construction. From any other window it
# reads busy, and the message then says how to clear it rather than "nothing
# to do".
#
# FAIL OPEN. A probe that cannot answer -- Win32_Process unavailable, a lock
# unreadable -- is UNKNOWN: the audit runs without that lock and says so. The
# worst case is the behaviour before this existed; a lock must never stop an
# audit on a guess.
#
# OUTPUT. -StateFile gets one word the bat reads with set /p: acquired,
# replaced-stale, busy or unknown. -NoteFile gets the sentence the bat prints
# (into the report, or to the console for busy). Each lock carries -Token, so
# the bat's release at its exit labels deletes only a lock that is still its
# own (findstr for the token, then del) -- never one another run replaced.
#
# Read-only apart from the locks and the two output files.
# Windows PowerShell 5.1 and pwsh. Pure ASCII.

[CmdletBinding()]
param(
    [string]$LockFiles = '',
    [string]$StateFile = '',
    [string]$NoteFile = '',
    [string]$Label = 'doze_sec',
    [string]$Token = '',
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'

function ConvertTo-PrintableText {
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

function Format-LockText {
    # One line: pid=;ticks=;name=;started=;label=;token=. Name, label and
    # token are reduced to an allowlist so nothing in them can break the line.
    param([int64]$HolderPid, [long]$Ticks, [string]$Name, [string]$Label, [datetime]$NowUtc, [string]$Token = '')
    $n = ([string]$Name) -replace '[^A-Za-z0-9_.\-]', '_'
    $l = ([string]$Label) -replace '[^A-Za-z0-9_.\-]', '_'
    $t = ([string]$Token) -replace '[^A-Za-z0-9]', ''
    # The token field is TERMINATED, so a release matching 'token=123;' can
    # never take a lock whose token merely starts with 123.
    return ('pid={0};ticks={1};name={2};started={3};label={4};token={5};' -f $HolderPid, $Ticks, $n, $NowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'), $l, $t)
}

function ConvertFrom-LockText {
    # @{ Pid; Ticks; Name; Started; Label; Token } or $null when the text does
    # not name a holder.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $h = @{}
    foreach ($part in (([string]$Text).Trim() -split ';')) {
        $kv = $part -split '=', 2
        if ($kv.Count -eq 2) { $h[$kv[0].Trim().ToLowerInvariant()] = $kv[1].Trim() }
    }
    if (-not ($h['pid'] -match '^\d{1,10}$') -or -not ($h['ticks'] -match '^\d{1,20}$')) { return $null }
    return @{ Pid = [int64]$h['pid']; Ticks = [int64]$h['ticks']; Name = [string]$h['name']; Started = [string]$h['started']; Label = [string]$h['label']; Token = [string]$h['token'] }
}

function Get-LockVerdict {
    # $Probe: param($pid) -> $null (no such process) or @{ Ticks; Name };
    # throws when it cannot answer. $Self: this run's holder identity, so a
    # lock this very window left behind is recognised. Returns @{ Verdict =
    # busy|stale|unknown; Holder; Why }.
    param([string]$Text, [scriptblock]$Probe, $Self = $null)
    $h = ConvertFrom-LockText -Text $Text
    if ($null -eq $h) { return @{ Verdict = 'stale'; Holder = $null; Why = 'the lock names no process' } }
    if ($null -ne $Self) {
        # One cmd runs one batch at a time: a lock naming THIS run's own
        # process -- or any process above it (an open prompt that started this
        # run through the console-log wrapper's pipe child) -- was left by an
        # earlier audit in the same window.
        $chain = @(@{ Pid = $Self.Pid; Ticks = $Self.Ticks }) + @($Self.Ancestors | Where-Object { $null -ne $_ })
        foreach ($c in $chain) {
            if ([int64]$c.Pid -eq $h.Pid -and [int64]$c.Ticks -eq $h.Ticks) {
                return @{ Verdict = 'stale'; Holder = $h; Why = 'it was left by an earlier audit in this same command window, which was interrupted' }
            }
        }
    }
    $p = $null
    try { $p = & $Probe $h.Pid } catch { return @{ Verdict = 'unknown'; Holder = $h; Why = ('whether process {0} is still running could not be checked ({1})' -f $h.Pid, $_.Exception.Message) } }
    if ($null -eq $p) { return @{ Verdict = 'stale'; Holder = $h; Why = ('process {0} is no longer running' -f $h.Pid) } }
    if ([int64]$p.Ticks -ne $h.Ticks) { return @{ Verdict = 'stale'; Holder = $h; Why = ('process {0} is now a different program started at another time (the number was reused)' -f $h.Pid) } }
    if ($h.Name -and ([string]$p.Name) -ne $h.Name) { return @{ Verdict = 'stale'; Holder = $h; Why = ('process {0} is now {1}, not the {2} that took the lock' -f $h.Pid, $p.Name, $h.Name) } }
    return @{ Verdict = 'busy'; Holder = $h; Why = ('process {0} ({1}) is still running' -f $h.Pid, $h.Name) }
}

function Invoke-OneLock {
    # Take ONE lock file. Returns @{ State = acquired|replaced-stale|busy|
    # unknown; Holder; Why }.
    param([string]$LockFile, $Self, [scriptblock]$Probe, [string]$Label, [datetime]$NowUtc, [string]$Token)
    $text = Format-LockText -HolderPid $Self.Pid -Ticks $Self.Ticks -Name $Self.Name -Label $Label -NowUtc $NowUtc -Token $Token
    $replaced = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $fs = [System.IO.File]::Open($LockFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($text)
                $fs.Write($bytes, 0, $bytes.Length)
            } finally { $fs.Dispose() }
            if ($null -eq $replaced) { return @{ State = 'acquired'; Holder = $null; Why = '' } }
            return @{ State = 'replaced-stale'; Holder = $replaced.Holder; Why = $replaced.Why }
        } catch {
            if (-not (Test-Path -LiteralPath $LockFile -PathType Leaf)) {
                return @{ State = 'unknown'; Holder = $null; Why = ('the lock file ' + $LockFile + ' could not be created (' + $_.Exception.Message + ')') }
            }
        }
        $existing = $null; $readErr = ''
        # Another helper may be writing it this instant (FileShare.None):
        # retry briefly before calling it unreadable.
        for ($k = 0; $k -lt 10 -and $null -eq $existing; $k++) {
            try { $existing = [System.IO.File]::ReadAllText($LockFile) } catch { $readErr = $_.Exception.Message; Start-Sleep -Milliseconds 100 }
        }
        if ($null -eq $existing) {
            if (-not (Test-Path -LiteralPath $LockFile -PathType Leaf)) { continue }
            return @{ State = 'unknown'; Holder = $null; Why = ('the lock ' + $LockFile + ' could not be read (' + $readErr + ')') }
        }
        $v = Get-LockVerdict -Text $existing -Probe $Probe -Self $Self
        if ($v.Verdict -eq 'busy') { return @{ State = 'busy'; Holder = $v.Holder; Why = $v.Why } }
        if ($v.Verdict -eq 'unknown') { return @{ State = 'unknown'; Holder = $v.Holder; Why = $v.Why } }
        # Stale. Re-read before deleting: another run replacing the same stale
        # lock at this moment may already have written its own, and deleting
        # THAT would let both run.
        $again = $null
        try { $again = [System.IO.File]::ReadAllText($LockFile) } catch { $again = $null }
        # A re-read that fails or differs means someone else is at it: look
        # again rather than delete a lock that may now be theirs.
        if ($null -eq $again -or $again -ne $existing) { Start-Sleep -Milliseconds 100; continue }
        $replaced = $v
        try { [System.IO.File]::Delete($LockFile) } catch {
            return @{ State = 'unknown'; Holder = $null; Why = ('a stale lock ' + $LockFile + ' could not be removed (' + $_.Exception.Message + ')') }
        }
    }
    return @{ State = 'unknown'; Holder = $null; Why = 'another audit took the lock at the same moment' }
}

function Invoke-LockAcquire {
    # Take every lock in $LockFiles. Busy if ANY is held by a live audit (and
    # then the locks this call took are given back); otherwise acquired or
    # replaced-stale, with unknown locks named in the note. $Self is $null when
    # this run's own process could not be identified: then no lock is taken.
    param([string[]]$LockFiles, $Self, [scriptblock]$Probe, [string]$Label, [datetime]$NowUtc, [string]$SelfError = '', [string]$Token = '')
    $files = @($LockFiles | Where-Object { $_ })
    if ($null -eq $Self) {
        return @{ State = 'unknown'; Note = ('[INFO] Run lock NOT taken: this audit could not identify its own process (' + (ConvertTo-PrintableText $SelfError) + '), so it runs without protection against a second audit started beside it.') }
    }
    $taken = @(); $stale = @(); $unknown = @()
    foreach ($f in $files) {
        $r = Invoke-OneLock -LockFile $f -Self $Self -Probe $Probe -Label $Label -NowUtc $NowUtc -Token $Token
        if ($r.State -eq 'busy') {
            # Give back what this call took, by token, so nothing of ours is
            # left behind by an invocation that is standing down.
            foreach ($t in $taken) { try { if (([System.IO.File]::ReadAllText($t)) -match ('token=' + [regex]::Escape($Token) + ';')) { [System.IO.File]::Delete($t) } } catch { } }
            $h = $r.Holder
            $when = ''; if ($h.Started) { $when = ', started ' + (ConvertTo-PrintableText $h.Started) }
            $lbl = ''; if ($h.Label) { $lbl = ', ' + (ConvertTo-PrintableText $h.Label) }
            return @{ State = 'busy'; Note = ('Another doze_sec audit is already running (process ' + [string]$h.Pid + $when + $lbl + '). This one did nothing and exits: two audits at once overwrite each other''s results. If that is an audit you started, let it finish. If none is running -- one was interrupted in a Command Prompt window that is still open -- close that window, or delete ' + (ConvertTo-PrintableText $f) + ', and start again.') }
        }
        if ($r.State -eq 'unknown') { $unknown += $r; continue }
        $taken += $f
        if ($r.State -eq 'replaced-stale') { $stale += $r }
    }
    if ($taken.Count -eq 0) {
        $why = (@($unknown | ForEach-Object { ConvertTo-PrintableText $_.Why }) -join '; ')
        return @{ State = 'unknown'; Note = ('[INFO] Run lock NOT taken: ' + $why + '; this audit runs without the lock rather than refuse to run on a guess.') }
    }
    $note = ''
    $state = 'acquired'
    if ($stale.Count) {
        $state = 'replaced-stale'
        $s = $stale[0]
        $who = 'the earlier audit'
        if ($s.Holder) { $who = 'process ' + [string]$s.Holder.Pid; if ($s.Holder.Started) { $who += ', started ' + (ConvertTo-PrintableText $s.Holder.Started) } }
        $note = '[INFO] Run lock: replaced a stale lock left by an audit that is no longer running (' + $who + '; ' + (ConvertTo-PrintableText $s.Why) + ') -- that run was interrupted; this one continues.'
    } else {
        $note = '[INFO] Run lock taken: a second audit started while this one runs will stand down instead of running beside it.'
    }
    if ($unknown.Count) { $note += ' One lock could not be taken (' + (@($unknown | ForEach-Object { ConvertTo-PrintableText $_.Why }) -join '; ') + '), so the protection is partial.' }
    return @{ State = $state; Note = $note }
}

function Get-ProcessIdentity {
    param([int64]$ProcessId)
    $p = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId={0}' -f $ProcessId) -EA Stop
    if ($null -eq $p) { return $null }
    return @{ Pid = [int64]$p.ProcessId; Ticks = ([datetime]$p.CreationDate).ToUniversalTime().Ticks; Name = [string]$p.Name; Parent = [int64]$p.ParentProcessId; CommandLine = [string]$p.CommandLine }
}

if ($SelfTest) {
    $script:fails = 0
    function T {
        param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $now = New-Object DateTime 2026, 10, 16, 18, 0, 0, ([DateTimeKind]::Utc)
    $tdir = Join-Path ([System.IO.Path]::GetTempPath()) ("dz_runlock_selftest_{0}" -f $PID)
    New-Item -ItemType Directory -Path $tdir -Force | Out-Null
    $lock = Join-Path $tdir 'temp.lock'
    $lock2 = Join-Path $tdir 'outdir.lock'
    $me = @{ Pid = 4242; Ticks = 638000000000000000; Name = 'cmd.exe' }
    $other = @{ Pid = 5151; Ticks = 638000000001000000; Name = 'cmd.exe' }
    # A probe over a fixed table of "running processes".
    $script:procs = @{}
    $probe = { param($p) if ($script:procs.ContainsKey([int64]$p)) { $script:procs[[int64]$p] } else { $null } }
    function Clean { Remove-Item -LiteralPath $lock, $lock2 -Force -EA SilentlyContinue; $script:procs.Clear() }
    try {
        $t = Format-LockText -HolderPid 4242 -Ticks 638000000000000000 -Name 'cmd.exe' -Label 'WIN11_SecurityAudit' -NowUtc $now -Token 'ab12'
        $h = ConvertFrom-LockText -Text $t
        T 'the lock text round-trips: pid, creation ticks, name, start time, label and token' ($h.Pid -eq 4242 -and $h.Ticks -eq 638000000000000000 -and $h.Name -eq 'cmd.exe' -and $h.Started -eq '2026-10-16T18:00:00Z' -and $h.Label -eq 'WIN11_SecurityAudit' -and $h.Token -eq 'ab12') $t
        T 'a label with a line break or a separator cannot break the line apart' ((Format-LockText -HolderPid 1 -Ticks 2 -Name 'cmd.exe' -Label "x;pid=9`r`n[OK] forged" -NowUtc $now) -notmatch "[\r\n]|;pid=9") ''

        Clean
        $r = Invoke-LockAcquire -LockFiles @($lock, $lock2) -Self $me -Probe $probe -Label 'WIN11_SecurityAudit' -NowUtc $now -Token 'mine1'
        T 'no lock yet: acquired, BOTH locks name this holder and carry its token' ($r.State -eq 'acquired' -and ([IO.File]::ReadAllText($lock)) -match '^pid=4242;ticks=638000000000000000;name=cmd\.exe;.*;token=mine1;$' -and ([IO.File]::ReadAllText($lock2)) -match 'token=mine1;$') "$($r.State)"

        $script:procs[[int64]4242] = @{ Ticks = 638000000000000000; Name = 'cmd.exe' }
        $r = Invoke-LockAcquire -LockFiles @($lock, $lock2) -Self $other -Probe $probe -Label 'WIN11_SecurityAudit' -NowUtc $now -Token 'other1'
        T 'a live holder with the same creation time and name: BUSY, the locks untouched' ($r.State -eq 'busy' -and ([IO.File]::ReadAllText($lock)) -match '^pid=4242;' -and ([IO.File]::ReadAllText($lock2)) -match '^pid=4242;' -and $r.Note -match 'Another doze_sec audit is already running \(process 4242, started 2026-10-16T18:00:00Z, WIN11_SecurityAudit\)\. This one did nothing and exits') "$($r.State) | $($r.Note)"
        T 'and the busy message says how to clear an interrupted lock, naming the file -- not "nothing to do"' ($r.Note -match 'If none is running -- one was interrupted in a Command Prompt window that is still open -- close that window, or delete .*temp\.lock' -and $r.Note -notmatch 'nothing to do') $r.Note

        # Only the OUTPUT-folder lock is held (a run with another TEMP, as
        # the CI full-run job has): still busy, and the temp lock this call
        # took is given back.
        Clean
        [IO.File]::WriteAllText($lock2, (Format-LockText -HolderPid 4242 -Ticks 638000000000000000 -Name 'cmd.exe' -Label 'x' -NowUtc $now -Token 'held'))
        $script:procs[[int64]4242] = @{ Ticks = 638000000000000000; Name = 'cmd.exe' }
        $r = Invoke-LockAcquire -LockFiles @($lock, $lock2) -Self $other -Probe $probe -Label 'x' -NowUtc $now -Token 'other2'
        T 'busy when only the OUTPUT-folder lock is held (a second run with another TEMP), and the temp lock it took is given back' ($r.State -eq 'busy' -and -not (Test-Path $lock) -and ([IO.File]::ReadAllText($lock2)) -match 'token=held;$') "$($r.State) temp-left=$(Test-Path $lock)"

        Clean
        [IO.File]::WriteAllText($lock, (Format-LockText -HolderPid 4242 -Ticks 638000000000000000 -Name 'cmd.exe' -Label 'x' -NowUtc $now -Token 'old'))
        $script:procs[[int64]4242] = @{ Ticks = 638000000099000000; Name = 'cmd.exe' }
        $r = Invoke-LockAcquire -LockFiles @($lock, $lock2) -Self $other -Probe $probe -Label 'x' -NowUtc $now -Token 'new1'
        T 'the PID reused by a later process: STALE, replaced, and the note says so' ($r.State -eq 'replaced-stale' -and ([IO.File]::ReadAllText($lock)) -match 'token=new1;$' -and $r.Note -match 'replaced a stale lock left by an audit that is no longer running \(process 4242, started 2026-10-16T18:00:00Z; process 4242 is now a different program') "$($r.State) | $($r.Note)"

        Clean
        [IO.File]::WriteAllText($lock, (Format-LockText -HolderPid 5151 -Ticks 638000000001000000 -Name 'cmd.exe' -Label 'x' -NowUtc $now -Token 'old'))
        $script:procs[[int64]5151] = @{ Ticks = 638000000001000000; Name = 'notepad.exe' }
        $r = Invoke-LockAcquire -LockFiles @($lock) -Self $me -Probe $probe -Label 'x' -NowUtc $now -Token 'n2'
        T 'the PID now another program with the same start time: STALE, not busy' ($r.State -eq 'replaced-stale' -and $r.Note -match 'is now notepad\.exe') "$($r.State)"

        Clean
        [IO.File]::WriteAllText($lock, (Format-LockText -HolderPid 4242 -Ticks 638000000000000000 -Name 'cmd.exe' -Label 'x' -NowUtc $now -Token 'old'))
        $r = Invoke-LockAcquire -LockFiles @($lock) -Self $other -Probe $probe -Label 'x' -NowUtc $now -Token 'n3'
        T 'the holder is gone (a reboot or a crash mid-run): STALE, replaced -- the case resume exists for always proceeds' ($r.State -eq 'replaced-stale' -and $r.Note -match 'process 4242 is no longer running' -and ([IO.File]::ReadAllText($lock)) -match 'token=n3;$') "$($r.State) | $($r.Note)"

        Clean
        [IO.File]::WriteAllText($lock, (Format-LockText -HolderPid 4242 -Ticks 638000000000000000 -Name 'cmd.exe' -Label 'x' -NowUtc $now -Token 'old'))
        $script:procs[[int64]4242] = @{ Ticks = 638000000000000000; Name = 'cmd.exe' }
        $r = Invoke-LockAcquire -LockFiles @($lock) -Self $me -Probe $probe -Label 'x' -NowUtc $now -Token 'n4'
        T 'a lock naming THIS run''s own window (an earlier audit there was interrupted) is stale, not busy against itself' ($r.State -eq 'replaced-stale' -and $r.Note -match 'left by an earlier audit in this same command window') "$($r.State) | $($r.Note)"

        Clean
        [IO.File]::WriteAllText($lock, (Format-LockText -HolderPid 777 -Ticks 600 -Name 'cmd.exe' -Label 'x' -NowUtc $now -Token 'old'))
        $script:procs[[int64]777] = @{ Ticks = 600; Name = 'cmd.exe' }
        $child = @{ Pid = 9001; Ticks = 700; Name = 'cmd.exe'; Ancestors = @(@{ Pid = 777; Ticks = 600 }) }
        $r = Invoke-LockAcquire -LockFiles @($lock) -Self $child -Probe $probe -Label 'x' -NowUtc $now -Token 'n41'
        T 'a lock held by the open prompt ABOVE this run (re-run through the console-log pipe after a -noConsoleLog interruption) is stale too' ($r.State -eq 'replaced-stale' -and $r.Note -match 'same command window') "$($r.State) | $($r.Note)"
        Clean
        [IO.File]::WriteAllText($lock, (Format-LockText -HolderPid 777 -Ticks 600 -Name 'cmd.exe' -Label 'x' -NowUtc $now -Token 'old'))
        $script:procs[[int64]777] = @{ Ticks = 600; Name = 'cmd.exe' }
        $r = Invoke-LockAcquire -LockFiles @($lock) -Self @{ Pid = 9002; Ticks = 701; Name = 'cmd.exe'; Ancestors = @(@{ Pid = 555; Ticks = 500 }) } -Probe $probe -Label 'x' -NowUtc $now -Token 'n42'
        T 'but a live holder that is NOT above this run is still busy' ($r.State -eq 'busy') "$($r.State)"
        Clean
        [IO.File]::WriteAllText($lock, (Format-LockText -HolderPid 4242 -Ticks 1 -Name 'cmd.exe' -Label 'x' -NowUtc $now -Token '123'))
        T 'the token field is terminated, so token 12 never matches a lock whose token is 123' (([IO.File]::ReadAllText($lock)) -notmatch 'token=12;' -and ([IO.File]::ReadAllText($lock)) -match 'token=123;') ''
        Clean
        [IO.File]::WriteAllText($lock, 'garbage that names nobody')
        $r = Invoke-LockAcquire -LockFiles @($lock) -Self $me -Probe $probe -Label 'x' -NowUtc $now -Token 'n5'
        T 'an unreadable lock text is stale and replaced, never busy' ($r.State -eq 'replaced-stale' -and $r.Note -match 'the lock names no process') "$($r.State)"

        Clean
        [IO.File]::WriteAllText($lock, (Format-LockText -HolderPid 4242 -Ticks 638000000000000000 -Name 'cmd.exe' -Label 'x' -NowUtc $now -Token 'old'))
        $broken = { param($p) throw 'Invalid class' }
        $r = Invoke-LockAcquire -LockFiles @($lock) -Self $other -Probe $broken -Label 'x' -NowUtc $now -Token 'n6'
        T 'a probe that cannot answer is UNKNOWN: the audit runs, the lock is left alone, and the note says it ran unprotected' ($r.State -eq 'unknown' -and ([IO.File]::ReadAllText($lock)) -match 'token=old;$' -and $r.Note -match 'runs without the lock rather than refuse to run on a guess') "$($r.State) | $($r.Note)"

        Clean
        $r = Invoke-LockAcquire -LockFiles @($lock) -Self $null -Probe $probe -Label 'x' -NowUtc $now -SelfError 'Get-CimInstance failed'
        T 'an audit that cannot identify its own process takes no lock and says so' ($r.State -eq 'unknown' -and $r.Note -match 'could not identify its own process \(Get-CimInstance failed\)' -and -not (Test-Path $lock)) "$($r.State)"

        Clean
        $r = Invoke-LockAcquire -LockFiles @((Join-Path $tdir 'no\such\dir\x.lock'), $lock) -Self $me -Probe $probe -Label 'x' -NowUtc $now -Token 'n7'
        T 'one lock that cannot be created leaves the other held, and the note says the protection is partial' ($r.State -eq 'acquired' -and (Test-Path $lock) -and $r.Note -match 'the protection is partial') "$($r.State) | $($r.Note)"
        Clean
        $r = Invoke-LockAcquire -LockFiles @((Join-Path $tdir 'no\such\dir\x.lock')) -Self $me -Probe $probe -Label 'x' -NowUtc $now -Token 'n8'
        T 'no lock that can be created at all is UNKNOWN, never a refusal' ($r.State -eq 'unknown' -and $r.Note -match 'could not be created') "$($r.State)"

        Clean
        [IO.File]::WriteAllText($lock, "pid=7;ticks=1;name=cmd.exe;started=x`r`n[OK] forged;label=y")
        $script:procs[[int64]7] = @{ Ticks = 1; Name = 'cmd.exe' }
        $r = Invoke-LockAcquire -LockFiles @($lock) -Self $me -Probe $probe -Label 'x' -NowUtc $now -Token 'n9'
        T 'a crafted lock cannot forge a line of the busy message' ($r.State -eq 'busy' -and $r.Note -notmatch "[\r\n]") "$($r.Note)"

        $v = Get-LockVerdict -Text 'pid=12;ticks=34;name=cmd.exe' -Probe { param($p) @{ Ticks = 34; Name = 'cmd.exe' } }
        T 'the verdict is busy only on positive evidence: alive, same creation time, same name' ($v.Verdict -eq 'busy') "$($v.Verdict)"
        $v = Get-LockVerdict -Text 'pid=12;ticks=34;name=cmd.exe' -Probe { param($p) @{ Ticks = 35; Name = 'cmd.exe' } }
        T 'one tick apart is a different process' ($v.Verdict -eq 'stale') "$($v.Verdict)"
    } finally {
        Remove-Item -LiteralPath $tdir -Recurse -Force -EA SilentlyContinue
    }
    if ($script:fails) {
        Write-Output "[FAIL] $($script:fails) run_lock self-test expectation(s) unmet"
        exit 1
    }
    Write-Output '[OK] run_lock self-test: both locks name their holder by PID, creation time and image; busy only on positive evidence and if either is held; a dead, reused, unreadable or same-window holder is replaced so a resume after a reboot proceeds; a probe that cannot answer runs the audit unlocked rather than refuse it.'
    exit 0
}

# ===========================================================================
# LIVE PATH
# ===========================================================================

# '|' separates the lock paths: it cannot appear in a Windows path, while ';'
# can.
$files = @(($LockFiles -split '\|') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($files.Count -eq 0) { $files = @(Join-Path $env:TEMP 'dz_audit_running.lock') }
$self = $null; $selfErr = ''
try {
    $mine = Get-ProcessIdentity -ProcessId $PID
    if ($null -eq $mine) { throw 'this process is not listed' }
    $parent = Get-ProcessIdentity -ProcessId $mine.Parent
    if ($null -eq $parent) { throw ('the parent process {0} is not listed' -f $mine.Parent) }
    # The ancestors of the holder (a few levels) are what the same-window
    # rule compares against: an open prompt that started this audit is one.
    $anc = @(); $cur = $parent
    for ($i = 0; $i -lt 5 -and $cur -and $cur.Parent -gt 0; $i++) {
        $up = $null
        try { $up = Get-ProcessIdentity -ProcessId $cur.Parent } catch { $up = $null }
        if ($null -eq $up -or $up.Ticks -gt $cur.Ticks) { break }   # a reused parent PID is not an ancestor
        $anc += @{ Pid = $up.Pid; Ticks = $up.Ticks }
        $cur = $up
    }
    $self = @{ Pid = $parent.Pid; Ticks = $parent.Ticks; Name = $parent.Name; Ancestors = $anc }
} catch { $selfErr = $_.Exception.Message }
$probe = { param($p) $x = Get-ProcessIdentity -ProcessId $p; if ($null -eq $x) { return $null }; return @{ Ticks = $x.Ticks; Name = $x.Name } }
$res = Invoke-LockAcquire -LockFiles $files -Self $self -Probe $probe -Label $Label -NowUtc ([datetime]::UtcNow) -SelfError $selfErr -Token $Token
if ($StateFile) { Set-Content -LiteralPath $StateFile -Value $res.State -Encoding ASCII }
if ($NoteFile) { Set-Content -LiteralPath $NoteFile -Value (' ' + $res.Note) -Encoding ASCII }
$res.State
