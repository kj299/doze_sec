# select_lines.ps1 -- findstr-replacement that handles arbitrarily long lines.
#
# findstr's input-line buffer aborts with "FINDSTR: Line N is too long" when a
# single input line exceeds ~8KB, AND silently drops the match on that line.
# wevtutil event-log XML and `wmic process get CommandLine` output regularly
# produce >8KB lines (Chrome with extension args, Java classpaths, Defender
# scan commands, etc.), so any pipeline like
#   wevtutil qe Security ... ^| findstr /c:"Command Line"
# misses matches AND pollutes the report.
#
# This helper reads -Path via .NET StreamReader.ReadLine which has no fixed-size
# line buffer, so the same patterns against the same input always return every
# match without errors.
#
# Patterns are matched as literal substrings (mirroring `findstr /c:"..."`),
# not regex. Case-insensitive by default; pass -CaseSensitive to disable.
# -Invert mirrors `findstr /v` (emit non-matching lines).
#
# Usage:
#   pwsh -NoProfile -File select_lines.ps1 -Path "%TEMP%\dz_pipe.tmp" "TimeCreated" "Account Name"
#   pwsh -NoProfile -File select_lines.ps1 -Path "..." -CaseSensitive -Invert "drop me"
#   pwsh -NoProfile -File select_lines.ps1 -Path "..." -PatternFile "ioc_lolbins.txt"
#
# Callers should write the upstream command's output to a temp file first
# (e.g. `wevtutil qe ... > "%TEMP%\dz_pipe.tmp"`) and then invoke this helper
# with -Path. Stdin is intentionally not supported because powershell.exe -File
# does not reliably forward piped stdin to the script.
#
# EXIT CODES (the contract every caller branches on):
#   0  at least one line emitted
#   1  every line was read and none matched -- the ONLY "clean" answer
#   2  nothing to match with, the input missing, or ANY error while reading
# Exit 1 used to cover a missing input file too, and a crash: the reader had
# a try/finally and no catch, and Windows PowerShell 5.1 under -File returns
# 1 for an unhandled terminating error. So an input file locked by antivirus,
# or a read that threw, reached every caller's `else if errorlevel 1 echo
# [OK]` -- Section 4's "No processes from suspicious locations" (and its PASS
# tile) among them. Found by the 2026-11-22 survey.
#
# Notes:
# - Patterns are taken from trailing positional args (ValueFromRemainingArguments).
#   This avoids the "powershell -File ... -Pattern a,b" array-splatting quirk
#   where comma-separated values don't round-trip cleanly through CMD into
#   the script's [string[]] parameter.
# - The input-file parameter is -Path, not -File, because powershell.exe's own
#   -File switch would otherwise consume the value before the script sees it.

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)] [string]$Path = '',
    [Parameter(Mandatory=$false)] [string]$PatternFile = '',
    [Parameter(Mandatory=$false)] [switch]$CaseSensitive,
    [Parameter(Mandatory=$false)] [switch]$Invert,
    # Set aside the audit's OWN esentutl calls (Section 5, -readSignedOut):
    # exactly the shape it runs, a profile's NTUSER.DAT/.MAN copied to a
    # %TEMP%\dz_hive_<pid>\<n>\ folder, never any other esentutl line. The
    # count is printed, so the exclusion is declared, never silent.
    [Parameter(Mandatory=$false)] [switch]$ExcludeAuditEsentutl,
    [Parameter(Mandatory=$false)] [switch]$SelfTest,
    [Parameter(Position=0, ValueFromRemainingArguments=$true)] [string[]]$Pattern
)

# -SelfTest runs THIS script as a child process, the way the bats do, so the
# exit codes checked are the ones cmd.exe sees. Sections 18a, 18f and 18g
# branch on them: 0 = a line matched, 1 = none matched, 2 = nothing to match
# with (the list missing or only comments), which the bats report as NOT
# performed. findstr /g: used to read a broken list as [OK].
if ($SelfTest) {
    # The exit-2 cases make the child write to stderr. Windows PowerShell 5.1
    # turns redirected native stderr into a terminating error when the
    # caller's preference is Stop (CI's is), so the test would die on the
    # very cases it exists to prove.
    $ErrorActionPreference = 'Continue'
    $exe = (Get-Process -Id $PID).Path
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_select_lines_selftest_' + $PID)
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ': ' + $Got })"; $script:fails++ }
    }
    function Run { param([string[]]$ArgList)
        $out = @(& $exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @ArgList 2>$null)
        return @{ Exit = $LASTEXITCODE; Lines = $out }
    }
    function W { param([string]$Name, [string]$Text) $f = Join-Path $tmp $Name; [IO.File]::WriteAllText($f, $Text); return $f }
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $list = W 'list.txt' ("# Last verified by doze_sec: 2026-06-06 10.20.37 sha256:63F7`n#`n# Lines starting with # are comments`n`nchisel`n  ngrok.io  `nwindowsupdate.cc`nC:\Users\Public\x.exe`n")
        $input1 = W 'input.txt' ("svchost.exe  4  C:\Windows\System32\svchost.exe`ndz_selftest_evil_CHISEL.exe  77  C:\dz_selftest_ioc\dz_selftest_evil_chisel.exe`nC# compiler  9  C:\tools\ngrok.io\x.exe`nwindowsupdateXcc`nconcat.exe  5  C:\c\concat.exe`n# Lines starting with # are comments`n")
        $r = Run @('-Path', $input1, '-PatternFile', $list)
        $j = $r.Lines -join ' | '
        T 'a listed name matches, case-insensitively, and the exit is 0' ($r.Exit -eq 0 -and $j -match 'dz_selftest_evil_CHISEL') ("exit=" + $r.Exit + ' ' + $j)
        T 'a hit on a line holding # is kept (findstr /v "#" used to drop it)' ($j -match 'C# compiler') $j
        T 'the list''s comment lines are not search strings, even when the input holds the same text' ($j -notmatch 'Lines starting with') $j
        T 'a dot is literal: windowsupdate.cc does not match windowsupdateXcc (the header''s 10.20.37 changes nothing)' ($j -notmatch 'windowsupdateXcc') $j
        T 'an entry is trimmed, and a line without any entry is not emitted' ($j -match 'ngrok\.io' -and $j -notmatch 'concat' -and $j -notmatch 'svchost') $j
        $r = Run @('-Path', (W 'in2.txt' "nothing to see`nhere`n"), '-PatternFile', $list)
        T 'no match is exit 1 with no output' ($r.Exit -eq 1 -and $r.Lines.Count -eq 0) ("exit=" + $r.Exit)
        $r = Run @('-Path', $input1, '-PatternFile', (W 'comments.txt' "# only`n#`n`n   `n"))
        T 'a list holding only comments and blanks is exit 2 (NOT performed), never 1' ($r.Exit -eq 2) ("exit=" + $r.Exit)
        $r = Run @('-Path', $input1, '-PatternFile', (Join-Path $tmp 'no_such_list.txt'))
        T 'a missing list is exit 2 (NOT performed), never 1' ($r.Exit -eq 2) ("exit=" + $r.Exit)
        $r = Run @('-Path', (Join-Path $tmp 'no_such_input.txt'), '-PatternFile', $list)
        T 'a missing input file is exit 2 (NOT performed), never 1: the bats create it with > even when the command fails' ($r.Exit -eq 2) ("exit=" + $r.Exit)
        $r = Run @('-Path', $tmp, '-PatternFile', $list)
        T 'an input that cannot be read (here a folder) is exit 2, never the "no match" 1 that callers print [OK] for' ($r.Exit -eq 2 -and $r.Lines.Count -eq 0) ("exit=" + $r.Exit + ' ' + ($r.Lines -join ' | '))
        # A read that THROWS: a file another process holds open with no sharing
        # (what antivirus scanning it does). Windows enforces the lock; Linux
        # does not, so there it is a declared skip.
        if ($env:OS -eq 'Windows_NT') {
            $lk = W 'locked.txt' "chisel`n"
            $fs = [IO.File]::Open($lk, 'Open', 'Read', 'None')
            try { $r = Run @('-Path', $lk, '-PatternFile', $list) } finally { $fs.Dispose() }
            T 'an input file locked by another process is exit 2 (the read threw), never 1' ($r.Exit -eq 2) ("exit=" + $r.Exit)
        } else { Write-Output '[ SKIP ] a locked input file: only Windows enforces the lock; the Windows CI job runs this case' }
        $r = Run @('-Path', (W 'empty.txt' ''), '-PatternFile', $list)
        T 'an empty input that was read is exit 1: nothing matched, and that is an answer' ($r.Exit -eq 1) ("exit=" + $r.Exit)
        $r = Run @('-Path', $input1, '-PatternFile', (W 'crlf.txt' "# h`r`nchisel`r`n"))
        T 'a CRLF list matches the same as an LF one' ($r.Exit -eq 0 -and ($r.Lines -join ' ') -match 'CHISEL') ("exit=" + $r.Exit)
        $r = Run @('-Path', $input1, '-PatternFile', (W 'bs.txt' "C:\dz_selftest_ioc\`n"))
        T 'a backslash in an entry is literal' ($r.Exit -eq 0 -and ($r.Lines -join ' ') -match 'dz_selftest_ioc') ("exit=" + $r.Exit)
        $self = 'Process Command Line: "C:\Windows\System32\esentutl.exe" /y C:\Users\bob\NTUSER.DAT /vss /d C:\Users\admin\AppData\Local\Temp\dz_hive_4242\1\NTUSER.DAT'
        $evil = 'Process Command Line: esentutl.exe /y C:\Windows\NTDS\ntds.dit /vss /d C:\Users\Public\n.dit'
        $inE = W 'esent.txt' ($self + "`n" + $evil + "`n")
        $r = Run @('-Path', $inE, '-ExcludeAuditEsentutl', 'esentutl')
        $j = $r.Lines -join ' | '
        T 'the audit''s own esentutl copy is set aside and COUNTED; another esentutl line is still listed' ($r.Exit -eq 0 -and $j -match 'ntds\.dit' -and $j -notmatch 'dz_hive_4242' -and $j -match '\[INFO\] 1 line\(s\) set aside') ("exit=" + $r.Exit + ' ' + $j)
        $r = Run @('-Path', $inE, 'esentutl')
        T 'without the switch nothing is set aside' (($r.Lines -join ' ') -match 'dz_hive_4242') ''
        $long = ('x' * 20000) + ' chisel'
        $r = Run @('-Path', (W 'long.txt' ($long + "`n")), '-PatternFile', $list)
        T 'a hit at the end of a 20,000-character line is found' ($r.Exit -eq 0) ("exit=" + $r.Exit)
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -EA SilentlyContinue }
    }
    if ($fails -gt 0) { Write-Output "FAILED: $fails"; exit 1 }
    Write-Output '[OK] select_lines self-test: comments are never search strings, matching is literal and case-insensitive, and a list with nothing to match, a missing input or an unreadable one exits 2, never 1.'
    exit 0
}

# Any terminating error is exit 2, never the 1 that means "read everything,
# nothing matched". (A trap covers its whole scope, -SelfTest included; there
# a throw is simply a non-zero exit, which CI reads as a failure.)
trap {
    [Console]::Error.WriteLine('select_lines.ps1: ' + [string]$_.Exception.Message)
    exit 2
}

# Load patterns from -PatternFile (mirrors `findstr /g:file`). Blank lines and
# lines starting with `#` are ignored, matching the threat-list convention used
# under ThreatLists/.
if ($PatternFile -ne '') {
    if (Test-Path -LiteralPath $PatternFile) {
        $fromFile = @(Get-Content -LiteralPath $PatternFile -EA SilentlyContinue |
            Where-Object { $_ -and -not ($_ -match '^\s*#') } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne '' })
        if ($Pattern) { $Pattern = @($Pattern) + $fromFile } else { $Pattern = $fromFile }
    }
}

if (-not $Pattern -or $Pattern.Count -eq 0) {
    Write-Error "select_lines.ps1: at least one pattern is required (pass as trailing positional args, or via -PatternFile <file>)."
    exit 2
}

$ErrorActionPreference = 'Continue'

# Pre-lowercase the patterns once when case-insensitive to avoid per-line work.
$needles = if ($CaseSensitive) { $Pattern } else { @($Pattern | ForEach-Object { $_.ToLowerInvariant() }) }

function Test-Hit {
    param([string]$Line)
    if ($null -eq $Line) { return $false }
    $hay = if ($CaseSensitive) { $Line } else { $Line.ToLowerInvariant() }
    foreach ($n in $needles) {
        if ($hay.Contains($n)) { return $true }
    }
    return $false
}

# Footgun guard: if -Path was omitted but the first positional pattern looks
# like a file path that exists on disk, the caller likely forgot the -Path
# flag and the file would silently be treated as a literal pattern. Fail loud.
# (Mandatory=$true on -Path is NOT used because powershell -File hangs waiting
# for stdin when a mandatory parameter is missing, instead of erroring cleanly.)
if ($Path -eq '' -and $Pattern -and $Pattern.Count -gt 0 -and (Test-Path -LiteralPath $Pattern[0] -EA SilentlyContinue)) {
    Write-Error "select_lines.ps1: -Path was omitted but the first positional argument '$($Pattern[0])' looks like an existing file. Did you forget the -Path flag?"
    exit 2
}

if ($Path -eq '') {
    Write-Error "select_lines.ps1: -Path <file> is required."
    exit 2
}

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    [Console]::Error.WriteLine("select_lines.ps1: the input file '$Path' does not exist or is not a file -- nothing was matched.")
    exit 2
}

# Mirror findstr's exit code: 0 = at least one line emitted, 1 = none emitted.
# Callers (e.g. doze_sec.bat) gate WARN/CRITICAL blocks on `if errorlevel 0`.
$emitted = 0
$setAside = 0
$selfRx = '(?i)\\esentutl\.exe"?\s+/y\s+"?[^"]*\\NTUSER\.(DAT|MAN)(\.LOG[12])?"?\s+/vss\s+/d\s+"?[^"]*\\dz_hive_\d+\\\d+\\NTUSER\.(DAT|MAN)(\.LOG[12])?"?\s*$'
$reader = $null
try {
    $reader = [System.IO.StreamReader]::new($Path)
    while ($null -ne ($line = $reader.ReadLine())) {
        $hit = Test-Hit $line
        if ($hit -and $ExcludeAuditEsentutl -and $line -match $selfRx) { $setAside++; continue }
        if ($hit -xor $Invert) {
            Write-Output $line
            $emitted++
        }
    }
} catch {
    # A read that failed part-way is never "no match". If a line already
    # matched, that hit is the stronger fact and the callers' only way to
    # raise it is exit 0 -- the incompleteness is still said, on stderr, which
    # every caller sends into the report. With no hit yet it is exit 2.
    [Console]::Error.WriteLine('select_lines.ps1: reading the input failed part-way, so lines after the failure were not searched -- ' + [string]$_.Exception.Message)
    if ($reader) { $reader.Dispose(); $reader = $null }
    if ($emitted -gt 0) { exit 0 }
    exit 2
} finally {
    if ($reader) { $reader.Dispose() }
}
if ($setAside -gt 0) { ('[INFO] ' + $setAside + ' line(s) set aside: this audit''s own esentutl copies of a signed-out account''s registry (-readSignedOut), recognised by their exact shape.') }
if ($emitted -gt 0) { exit 0 } else { exit 1 }
