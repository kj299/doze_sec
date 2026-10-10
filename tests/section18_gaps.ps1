# section18_gaps.ps1 -- Section 18's staged IOC matchers, run the way cmd
# writes them: each one that cannot run must say NOT performed and raise it.
#
# WHY. Five Section 18 matchers (18b named pipes, 18c services, 18d staging
# files, 18e scheduled tasks, 18h registry) are PowerShell that the bats ECHO
# into %PSRUN% and run. When the list was missing or held no entries, or
# Windows would not list what they match against, they printed [SKIPPED] or
# [INFO] and raised nothing, and the Section 18 summary did not even count 18e's
# [INFO] lines as gaps -- so the sweep could read as an all-clear having
# compared nothing. 18a, 18g and 18k had the same shape in the bat itself.
# Each now prints "[WARNING] <check> IOC match NOT performed -- <reason>" and
# raises a gap-worded ledger row under its section and technique.
#
# Those branches only run when something is missing, which a healthy machine or
# runner never shows, so this script renders each block exactly as cmd writes
# it (the echo and its redirection stripped, carets outside double quotes
# consumed, %IOCDIR% substituted) and RUNS it against list folders it builds.
#
# READ-ONLY: it writes only under a fresh folder in the temp directory (the
# rendered blocks, their markers, the list folders) and removes it. It plants
# nothing; a CI step that proves a match fires does its own planting and uses
# -Mode Run.
#
#   -Mode Missing  (default) every block of both bats, its list absent, then
#                  holding only comments, then absent from a folder whose name
#                  holds an apostrophe (C:\Users\O'Brien): the gap line, the gap
#                  marker, the done marker (the block reached a verdict), no
#                  [OK] line, no hit marker.
#   -Mode Shipped  the blocks against -ListDir (default ThreatLists). On Windows
#                  no gap at all -- every listing works there. On Linux the
#                  listings 18b, 18c and 18e need do not exist, so those three
#                  print their listing gap and 18d and 18h print [OK].
#   -Mode Run      -ListDir and -Sections: run those blocks of doze_sec.bat and
#                  print their output and one 'S18 <sec> hit=<0|1> gap=<0|1>'
#                  line each.
# Every mode first checks the bats themselves: both carry the same blocks; each
# block reads its list path from the environment ($env:IOCDIR), never pasted
# between single quotes, and ends by writing its done marker; its gap branch
# prints the NOT-performed line and writes its gap marker; the bat deletes both
# markers before the run, raises the gap after under the section's technique,
# and raises a block that never reached its done marker; neither raise touches
# IOC_HITS; every direct NOT-performed echo in Section 18 raises and no
# [SKIPPED] line is left there but the empty-DNS-cache one; a missing
# ThreatLists folder raises IOCSWEEP; the 18k hash match raises CRITICAL, as the
# tool prints it; the summary prints its tally. -SelfTest proves each check
# fails on the defect it exists for.
#
# Windows PowerShell 5.1 and pwsh 7; pure ASCII. On Windows the blocks run
# under Windows PowerShell 5.1 (powershell.exe), as the bats run them.

[CmdletBinding()]
param(
    [ValidateSet('Missing', 'Shipped', 'Run')]
    [string]$Mode = 'Missing',
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [string]$ListDir = '',
    [string[]]$Sections = @(),
    [switch]$SelfTest
)

# Continue, not Stop: on 5.1 a native command's redirected stderr under Stop is
# a terminating error, and the blocks print errors on purpose (on Linux every
# Windows listing fails).
$ErrorActionPreference = 'Continue'

$script:Specs = @(
    @{ S = '18b'; List = 'ioc_named_pipes.txt';     Name = 'Named pipe IOC match';     Tech = 'T1071'; Linux = 'gap' },
    @{ S = '18c'; List = 'ioc_services.txt';        Name = 'Service IOC match';        Tech = 'T1543'; Linux = 'gap' },
    @{ S = '18d'; List = 'ioc_file_paths.txt';      Name = 'Staging file IOC match';   Tech = 'T1074'; Linux = 'ok' },
    @{ S = '18e'; List = 'ioc_scheduled_tasks.txt'; Name = 'Scheduled task IOC match'; Tech = 'T1053'; Linux = 'gap' },
    @{ S = '18h'; List = 'ioc_registry.txt';        Name = 'Registry IOC match';       Tech = 'T1112'; Linux = 'ok' }
)
# Through -File, '-Sections 18b,18e' arrives as ONE string; split it.
$Sections = @($Sections | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$script:OnWindows = ([Environment]::OSVersion.Platform -eq 'Win32NT')
$script:Exe = (Get-Process -Id $PID).Path
if ($script:OnWindows) {
    $wp = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $wp) { $script:Exe = $wp }
}

function Expand-CmdEscapes {
    # cmd consumes ^ as an escape ONLY outside double quotes; inside quotes a
    # caret is literal. Getting this backwards is what put a literal ^| into a
    # generated command and ate the ^ anchors out of the fix-counter regex.
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    $inQ = $false
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($c -eq '"') { $inQ = -not $inQ; [void]$sb.Append($c); continue }
        if ($c -eq '^' -and -not $inQ -and $i + 1 -lt $Text.Length) { [void]$sb.Append($Text[$i + 1]); $i++; continue }
        [void]$sb.Append($c)
    }
    return $sb.ToString()
}

function Get-Spec {
    param([string]$S)
    return @($script:Specs | Where-Object { $_.S -eq $S })[0]
}

function Get-StagedBlock {
    # The PowerShell a section's echo lines write into %PSRUN%, as cmd writes
    # it: each 'echo X > "%PSRUN%"' or 'echo X >> "%PSRUN%"' line from the
    # section's header to its run line. $null when the header or the run line
    # is not found. A '!' would be eaten by cmd's delayed expansion, which this
    # does not reproduce, so a block holding one is reported, not rendered.
    param([string]$Text, [string]$Section)
    $lines = $Text -split "\r?\n"
    $h = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].StartsWith('echo --- [' + $Section + ']')) { $h = $i; break } }
    if ($h -lt 0) { return $null }
    $out = New-Object System.Collections.Generic.List[string]
    for ($i = $h + 1; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l -match '^"%PWSH%" .*-File "%PSRUN%"') { return ,$out.ToArray() }
        if ($l.StartsWith('echo --- [')) { return $null }
        $m = [regex]::Match($l, '^echo (.*?)\s*>>?\s*"%PSRUN%"\s*$')
        if ($m.Success) {
            if ($m.Groups[1].Value.Contains('!')) { return ,@('!') }
            $out.Add((Expand-CmdEscapes $m.Groups[1].Value))
        }
    }
    return $null
}

function Invoke-Block {
    # Run one rendered block with IOCDIR = $Dir (in the environment, as cmd
    # hands it to the child; a %IOCDIR% left in the text is substituted the way
    # cmd would paste it) and TEMP = $Work. Returns @{ Out; Hit; Gap; Done }.
    param([string[]]$Block, [string]$Section, [string]$Dir, [string]$Work)
    $hit = Join-Path $Work ('dz_iochit_' + $Section + '.txt')
    $gap = Join-Path $Work ('dz_iochit_' + $Section + '_gap.txt')
    $done = Join-Path $Work ('dz_iochit_' + $Section + '_done.txt')
    foreach ($f in $hit, $gap, $done) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
    $ps1 = Join-Path $Work ('block_' + $Section + '.ps1')
    $src = @($Block | ForEach-Object { $_.Replace('%IOCDIR%', $Dir) }) -join "`r`n"
    [IO.File]::WriteAllText($ps1, $src, [Text.Encoding]::ASCII)
    $savedTemp = $env:TEMP
    $savedIoc = $env:IOCDIR
    $env:TEMP = $Work
    $env:IOCDIR = $Dir
    try { $out = (& $script:Exe -NoProfile -ExecutionPolicy Bypass -File $ps1 2>&1 | ForEach-Object { "$_" }) -join "`n" }
    finally { $env:TEMP = $savedTemp; $env:IOCDIR = $savedIoc }
    return @{ Out = $out; Hit = (Test-Path -LiteralPath $hit); Gap = (Test-Path -LiteralPath $gap); Done = (Test-Path -LiteralPath $done) }
}

function Get-CodeLines {
    # The bat's lines with comments dropped, keeping their index order.
    param([string]$Text)
    return @($Text -split "\r?\n" | Where-Object { $_.Trim() -and $_ -notmatch '^\s*(::|rem\s)' })
}

function Get-StructureDefects {
    # What is wrong with one bat's Section 18, structurally. $Name labels it.
    param([string]$Text, [string]$Name)
    $bad = @()
    $code = Get-CodeLines $Text
    foreach ($sp in $script:Specs) {
        $tag = $Name + ' ' + $sp.S
        $blk = Get-StagedBlock $Text $sp.S
        if ($null -eq $blk) { $bad += "${tag}: block or its run line not found -- this check is broken, not the code"; continue }
        if ($blk.Count -eq 1 -and $blk[0] -eq '!') { $bad += "${tag}: an echo line holds '!', which cmd's delayed expansion eats"; continue }
        $joined = $blk -join "`n"
        $gapLine = "'[WARNING] " + $sp.Name + ' NOT performed -- '
        $gapMark = 'dz_iochit_' + $sp.S + '_gap.txt'
        if (-not $joined.Contains($gapLine)) { $bad += "${tag}: the block has no $gapLine... line" }
        if (-not $joined.Contains($gapMark)) { $bad += "${tag}: the block never writes $gapMark" }
        if ($joined -match "'\[(SKIPPED|INFO)\]") { $bad += "${tag}: the block still prints a [SKIPPED]/[INFO] line, which raises nothing" }
        $doneMark = 'dz_iochit_' + $sp.S + '_done.txt'
        if ($joined.Contains('%IOCDIR%')) { $bad += "${tag}: the block pastes %IOCDIR% into its text; a profile folder holding an apostrophe makes it a parse error that prints and raises nothing -- read `$env:IOCDIR" }
        if (-not $joined.Contains('$env:IOCDIR')) { $bad += "${tag}: the block does not read its list folder from `$env:IOCDIR" }
        if ($blk.Count -eq 0 -or -not $blk[$blk.Count - 1].Contains($doneMark)) { $bad += "${tag}: the block does not END by writing $doneMark, so a block that stops early is indistinguishable from one that finished" }
        # The run line that belongs to this block: the first after the header.
        $hi = -1
        for ($i = 0; $i -lt $code.Count; $i++) { if ($code[$i].StartsWith('echo --- [' + $sp.S + ']')) { $hi = $i; break } }
        $r = -1
        for ($i = $hi + 1; $i -lt $code.Count; $i++) { if ($code[$i] -match '^"%PWSH%" .*-File "%PSRUN%"') { $r = $i; break } }
        if ($hi -lt 0 -or $r -lt 0) { $bad += "${tag}: header or run line not found among the code lines"; continue }
        $before = @($code[[Math]::Max(0, $r - 4)..($r - 1)])
        if (-not @($before | Where-Object { $_.Trim() -eq ('del "%TEMP%\' + $gapMark + '" 2>nul') }).Count) { $bad += "${tag}: the gap marker is not deleted before the run (a stale one would raise a gap that did not happen)" }
        if (-not @($before | Where-Object { $_.Trim() -eq ('del "%TEMP%\' + $doneMark + '" 2>nul') }).Count) { $bad += "${tag}: the done marker is not deleted before the run (a stale one would hide a block that stopped early)" }
        $after = @($code[($r + 1)..([Math]::Min($code.Count - 1, $r + 18))])
        $gi = -1
        for ($i = 0; $i -lt $after.Count; $i++) { if ($after[$i].Trim() -eq ('if exist "%TEMP%\' + $gapMark + '" (')) { $gi = $i; break } }
        if ($gi -lt 0) { $bad += "${tag}: the bat never reads $gapMark after the run, so the gap reaches no ledger row" }
        elseif ($gi + 1 -ge $after.Count -or $after[$gi + 1] -notmatch ('^\s*call :dz_finding WARNING 18 ' + [regex]::Escape($sp.Tech) + ' "' + [regex]::Escape($sp.Name) + ' NOT performed')) {
            $bad += "${tag}: the gap marker is not raised as WARNING 18 $($sp.Tech) `"$($sp.Name) NOT performed...`""
        }
        $di = -1
        for ($i = 0; $i -lt $after.Count; $i++) { if ($after[$i].Trim() -eq ('if not exist "%TEMP%\' + $doneMark + '" (')) { $di = $i; break } }
        if ($di -lt 0) { $bad += "${tag}: the bat never checks $doneMark, so a block that stopped before its verdict raises nothing" }
        elseif ($di + 2 -ge $after.Count -or $after[$di + 1] -notmatch ('^\s*echo \[WARNING\] ' + [regex]::Escape($sp.Name) + ' NOT performed -- ') -or $after[$di + 2] -notmatch ('^\s*call :dz_finding WARNING 18 ' + [regex]::Escape($sp.Tech) + ' ')) {
            $bad += "${tag}: a block that stopped before its verdict is not printed and raised as WARNING 18 $($sp.Tech)"
        }
        # A gap is not a match: nothing between each gap/done read and its
        # closing parenthesis may touch IOC_HITS.
        foreach ($start in @($gi, $di)) {
            if ($start -lt 0) { continue }
            for ($i = $start + 1; $i -lt $after.Count -and $after[$i].Trim() -ne ')'; $i++) {
                if ($after[$i] -match 'IOC_HITS') { $bad += "${tag}: a gap read changes IOC_HITS -- a check that did not run would count as a match"; break }
            }
        }
    }
    # Every direct NOT-performed echo in Section 18 raises within two code lines.
    $s = -1; $e = -1
    for ($i = 0; $i -lt $code.Count; $i++) {
        if ($s -lt 0 -and $code[$i].StartsWith('echo --- [18a]')) { $s = $i }
        if ($code[$i].StartsWith('echo --- [18 SUMMARY]')) { $e = $i; break }
    }
    if ($s -lt 0 -or $e -lt 0) { $bad += "${Name}: Section 18 span not found -- this check is broken, not the code" }
    else {
        $direct = 0
        for ($i = $s; $i -lt $e; $i++) {
            if ($code[$i] -notmatch '^\s*echo \[WARNING\] .*NOT performed.*>>\s*"%REPORT%"') { continue }
            $direct++
            $win = @($code[($i + 1)..([Math]::Min($e, $i + 2))])
            if (-not @($win | Where-Object { $_ -match '^\s*call :dz_finding WARNING 18 T\d' }).Count) { $bad += ("{0}: a NOT-performed line is printed and not raised: {1}" -f $Name, $code[$i].Trim()) }
        }
        # 18a, 18f, 18g (lists and listings), 18k (list missing, tool missing)
        # and the five blocks' stopped-before-a-verdict lines.
        if ($direct -lt 14) { $bad += "${Name}: only $direct direct NOT-performed lines in Section 18 (expected at least 14) -- this check is not looking at the code it was written for" }
        # [SKIPPED] raises nothing, so it is only for an input that is absent,
        # never for a list or a listing that failed: the one left is 18f's
        # empty DNS cache with the DNS Client running.
        for ($i = $s; $i -lt $e; $i++) {
            if ($code[$i] -match '^\s*echo \[SKIPPED\]' -and $code[$i] -notmatch 'The DNS cache holds no records') { $bad += ("{0}: a [SKIPPED] line raises nothing for a check that could not run: {1}" -f $Name, $code[$i].Trim()) }
        }
        foreach ($want in @(
            @{ Line = 'echo [WARNING] Process IOC match NOT performed -- running processes could not be listed.'; Tech = 'T1057' },
            @{ Line = 'echo [WARNING] LOLBin pattern match NOT performed -- process command lines could not be listed.'; Tech = 'T1059' },
            @{ Line = 'echo [WARNING] File hash IOC match NOT performed -- tools\ioc_hash_check.ps1 not found.'; Tech = 'T1105' })) {
            $k = -1
            for ($i = $s; $i -lt $e; $i++) { if ($code[$i].Trim().StartsWith($want.Line)) { $k = $i; break } }
            if ($k -lt 0) { $bad += ("{0}: the listing/tool gap line is missing: {1}" -f $Name, $want.Line) }
            elseif ($code[$k + 1] -notmatch ('^\s*call :dz_finding WARNING 18 ' + $want.Tech + ' ')) { $bad += ("{0}: the gap '{1}' is not raised under {2} on the next line" -f $Name, $want.Line, $want.Tech) }
        }
        $k = -1
        for ($i = $s; $i -lt $e; $i++) { if ($code[$i].Trim() -eq 'if exist "%TEMP%\dz_iochit_18k_gap.txt" (') { $k = $i; break } }
        if ($k -lt 0 -or $code[$k + 1] -notmatch '^\s*call :dz_finding WARNING 18 T1105 "File hash IOC match NOT performed') { $bad += "${Name}: 18k never raises the gap ioc_hash_check writes (dz_iochit_18k_gap.txt)" }
        if (-not @($code[$s..$e] | Where-Object { $_ -match '^\s*call :dz_finding CRITICAL 18 T1105 "File hash IOC match"' }).Count) { $bad += "${Name}: an 18k hash match is not raised CRITICAL, though ioc_hash_check prints it [CRITICAL]" }
    }
    # No ThreatLists folder at all: the whole sweep is a raised gap, and the
    # dashboard tile must not read PASS (IOC_GAPS nonzero).
    $ni = -1
    for ($i = 0; $i -lt $code.Count; $i++) { if ($code[$i].Trim() -eq 'if not exist "%IOCDIR%\ioc_processes.txt" (') { $ni = $i; break } }
    if ($ni -lt 0) { $bad += "${Name}: the no-ThreatLists branch was not found" }
    else {
        $nb = @()
        for ($i = $ni + 1; $i -lt $code.Count -and $code[$i].Trim() -ne ')'; $i++) { $nb += $code[$i] }
        if (-not @($nb | Where-Object { $_ -match '^\s*call :dz_finding WARNING 18 IOCSWEEP "IOC sweep NOT performed' }).Count) { $bad += "${Name}: a missing ThreatLists folder skips the whole sweep without raising it" }
        if (-not @($nb | Where-Object { $_ -match '^\s*set "IOC_GAPS=[1-9]' }).Count) { $bad += "${Name}: a missing ThreatLists folder leaves IOC_GAPS at 0, so the dashboard tile reads PASS" }
    }
    # The summary's hits branch prints its tally, unguarded.
    $hl = -1
    for ($i = 0; $i -lt $code.Count; $i++) { if ($code[$i].Trim() -eq ':sec18_sum_hits') { $hl = $i; break } }
    if ($hl -lt 0) { $bad += "${Name}: :sec18_sum_hits not found" }
    elseif ($code[$hl + 1] -notmatch '^echo \[INFO\] !IOC_HITS! IOC category matches found\.') { $bad += ("{0}: with a match the summary does not print its tally first (found: {1})" -f $Name, $code[$hl + 1].Trim()) }
    return $bad
}

function Get-BlockDefects {
    # Run each block of $Text against what -Mode asks; return what failed.
    param([string]$Text, [string]$Name, [string]$Mode, [string]$Dir, [string]$Work, [string[]]$Only = @())
    $bad = @()
    foreach ($sp in $script:Specs) {
        if ($Only.Count -and $Only -notcontains $sp.S) { continue }
        $blk = Get-StagedBlock $Text $sp.S
        if ($null -eq $blk -or ($blk.Count -eq 1 -and $blk[0] -eq '!')) { $bad += "$Name $($sp.S): the block could not be rendered"; continue }
        $tag = "$Name $($sp.S)"
        $gapRx = '(?m)^\[WARNING\] ' + [regex]::Escape($sp.Name) + ' NOT performed -- '
        if ($Mode -eq 'Missing') {
            $empty = Join-Path $Work 'lists_empty'
            $comments = Join-Path $Work 'lists_comments'
            $quoted = Join-Path $Work "lists_o'brien"
            foreach ($d in $empty, $comments, $quoted) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
            [IO.File]::WriteAllText((Join-Path $comments $sp.List), "# Last verified by doze_sec: 2026-10-10 00:00:00`r`n#`r`n# comments only`r`n", [Text.Encoding]::ASCII)
            foreach ($case in @(@{ D = $empty; What = 'list absent' }, @{ D = $comments; What = 'list holds only comments' }, @{ D = $quoted; What = 'list absent from a folder whose name holds an apostrophe' })) {
                $r = Invoke-Block $blk $sp.S $case.D $Work
                if (-not $r.Done) { $bad += ("{0}, {1}: the block stopped before its verdict (no done marker); it printed: {2}" -f $tag, $case.What, $r.Out) }
                if ($r.Out -notmatch $gapRx) { $bad += ("{0}, {1}: no '[WARNING] {2} NOT performed' line; it printed: {3}" -f $tag, $case.What, $sp.Name, $r.Out) }
                if (-not $r.Gap) { $bad += ("{0}, {1}: the gap marker was not written, so the gap reaches no ledger row" -f $tag, $case.What) }
                if ($r.Hit) { $bad += ("{0}, {1}: the hit marker was written with nothing to match" -f $tag, $case.What) }
                if ($r.Out -match '(?m)^\[OK\]') { $bad += ("{0}, {1}: it printed [OK] having matched nothing" -f $tag, $case.What) }
            }
        } else {
            $r = Invoke-Block $blk $sp.S $Dir $Work
            $want = if ($script:OnWindows) { 'ok' } else { $sp.Linux }
            if ($Mode -eq 'Run') {
                Write-Output $r.Out
                Write-Output ("S18 {0} hit={1} gap={2} done={3}" -f $sp.S, [int]$r.Hit, [int]$r.Gap, [int]$r.Done)
                continue
            }
            if (-not $r.Done) { $bad += ("{0}, shipped list: the block stopped before its verdict (no done marker); it printed: {1}" -f $tag, $r.Out) }
            if ($want -eq 'gap') {
                if ($r.Out -notmatch $gapRx -or -not $r.Gap) { $bad += ("{0}, shipped list on Linux: expected the listing gap and its marker; it printed: {1}" -f $tag, $r.Out) }
            } else {
                if ($r.Gap -or $r.Out -match $gapRx) { $bad += ("{0}, shipped list: a gap on a machine where the list and the listing both work -- a false WARNING; it printed: {1}" -f $tag, $r.Out) }
                if ($r.Out -notmatch '(?m)^\[(OK|WARNING|CRITICAL)\] ') { $bad += ("{0}, shipped list: printed no verdict line at all: {1}" -f $tag, $r.Out) }
            }
        }
    }
    return $bad
}

function Replace-Once {
    param([string]$Text, [string]$From, [string]$To, [string]$Label)
    $i = $Text.IndexOf($From)
    if ($i -lt 0) { throw ("mutation '{0}' found nothing to change -- the self-test no longer looks at the code it was written for" -f $Label) }
    return $Text.Substring(0, $i) + $To + $Text.Substring($i + $From.Length)
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('dz_s18_{0}' -f $PID)
New-Item -ItemType Directory -Path $work -Force | Out-Null
$exit = 0
try {
    $bats = @('doze_sec.bat', 'doze_sec_noAdmin.bat')
    $texts = @{}
    foreach ($b in $bats) { $texts[$b] = [IO.File]::ReadAllText((Join-Path $Root $b)) }
    if ($SelfTest) {
        $fails = 0
        function T { param([string]$N, [bool]$Ok, [string]$Got)
            if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ': ' + $Got })"; $script:fails++ }
        }
        # A mutation fails the check FOR ITS OWN REASON: some defect names it.
        function TM { param([string]$N, [string[]]$Defects, [string]$Need)
            $hit = @($Defects | Where-Object { $_.Contains($Need) })
            T $N ($hit.Count -gt 0) $(if ($Defects.Count) { 'defects did not name it: ' + ($Defects -join ' | ') } else { 'no defect reported' })
        }
        # The mutations below are written with LF; a Windows checkout is CRLF.
        $base = $texts['doze_sec.bat'] -replace "`r`n", "`n"
        $d = @(Get-StructureDefects $base 'doze_sec.bat')
        T 'the shipped doze_sec.bat passes the structural check' ($d.Count -eq 0) ($d -join ' | ')
        $d = @(Get-BlockDefects $base 'doze_sec.bat' 'Missing' '' $work)
        T 'the shipped blocks say NOT performed with no list' ($d.Count -eq 0) ($d -join ' | ')
        $m1 = Replace-Once $base ("'[WARNING] Named pipe IOC match NOT performed -- ioc_named_pipes.txt is missing or holds no entries.'; New-Item `"`$env:TEMP\dz_iochit_18b_gap.txt`" -Force ^| Out-Null}") "'[SKIPPED] ioc_named_pipes.txt missing or empty -- named pipe IOC match NOT performed.'}" '18b gap back to [SKIPPED]'
        TM '18b gap branch back to [SKIPPED] fails the structural check' @(Get-StructureDefects $m1 'mutated') 'still prints a [SKIPPED]/[INFO] line'
        TM '18b gap branch back to [SKIPPED] fails when the block is RUN with no list' @(Get-BlockDefects $m1 'mutated' 'Missing' '' $work @('18b')) "no '[WARNING] Named pipe IOC match NOT performed' line"
        $m2 = Replace-Once $base ("if exist `"%TEMP%\dz_iochit_18c_gap.txt`" (`n    call :dz_finding WARNING 18 T1543 ") ("if exist `"%TEMP%\dz_iochit_18c_gapX.txt`" (`n    call :dz_finding WARNING 18 T1543 ") '18c gap read removed'
        TM 'the bat no longer reading the 18c gap marker fails' @(Get-StructureDefects $m2 'mutated') 'never reads dz_iochit_18c_gap.txt'
        $m3 = Replace-Once $base 'call :dz_finding WARNING 18 T1053 "Scheduled task IOC match NOT performed' 'call :dz_finding WARNING 18 T1059 "Scheduled task IOC match NOT performed' '18e gap under the wrong technique'
        TM 'the 18e gap raised under the wrong technique fails' @(Get-StructureDefects $m3 'mutated') 'not raised as WARNING 18 T1053'
        $m4 = Replace-Once $base "echo [INFO] !IOC_HITS! IOC category matches found." "if `"!IOC_HITS!`"==`"0`" (`n    echo [INFO] !IOC_HITS! IOC category matches found." 'summary guard restored'
        TM 'the summary tally back behind the IOC_HITS==0 guard fails' @(Get-StructureDefects $m4 'mutated') 'does not print its tally first'
        $m5 = Replace-Once $base "call :dz_finding WARNING 18 T1057 `"Process IOC match NOT performed - processes not enumerable`"`n" '' '18a listing gap unraised'
        TM 'the 18a listing gap printed but not raised fails' @(Get-StructureDefects $m5 'mutated') 'printed and not raised: echo [WARNING] Process IOC match NOT performed'
        $m6 = Replace-Once $base 'call :dz_finding CRITICAL 18 T1105 "File hash IOC match"' 'call :dz_finding WARNING 18 T1105 "File hash IOC match"' '18k hash match back to WARNING'
        TM 'the 18k hash match raised WARNING again fails' @(Get-StructureDefects $m6 'mutated') 'is not raised CRITICAL'
        $m7 = Replace-Once $base ("del `"%TEMP%\dz_iochit_18h_gap.txt`" 2>nul`ndel `"%TEMP%\dz_iochit_18h_done.txt`" 2>nul`n") ("del `"%TEMP%\dz_iochit_18h_done.txt`" 2>nul`n") '18h gap marker not deleted before the run'
        TM 'a gap marker not deleted before its run fails' @(Get-StructureDefects $m7 'mutated') '18h: the gap marker is not deleted before the run'
        $m8 = Replace-Once $base "echo `$iocFile = Join-Path `$env:IOCDIR 'ioc_services.txt' > `"%PSRUN%`"" "echo `$iocFile='%IOCDIR%\ioc_services.txt' > `"%PSRUN%`"" '18c path pasted between quotes again'
        TM 'the 18c list path pasted between single quotes again fails the structural check' @(Get-StructureDefects $m8 'mutated') 'pastes %IOCDIR% into its text'
        TM 'the 18c list path pasted between single quotes again fails when RUN from a folder named with an apostrophe' @(Get-BlockDefects $m8 'mutated' 'Missing' '' $work @('18c')) 'folder whose name holds an apostrophe: the block stopped before its verdict'
        $m9 = Replace-Once $base 'if not exist "%TEMP%\dz_iochit_18d_done.txt" (' 'if not exist "%TEMP%\dz_iochit_18d_doneX.txt" (' '18d done check removed'
        TM 'the bat no longer checking the 18d done marker fails' @(Get-StructureDefects $m9 'mutated') 'never checks dz_iochit_18d_done.txt'
        $m10 = Replace-Once $base "    call :dz_finding WARNING 18 T1071 `"Named pipe IOC match NOT performed - list unreadable or empty, or pipes not enumerable`"`n" "    call :dz_finding WARNING 18 T1071 `"Named pipe IOC match NOT performed - list unreadable or empty, or pipes not enumerable`"`n    set /a IOC_HITS+=1`n" '18b gap counted as a match'
        TM 'a gap read that increments IOC_HITS fails' @(Get-StructureDefects $m10 'mutated') 'a gap read changes IOC_HITS'
        $m11 = Replace-Once $base "    call :dz_finding WARNING 18 IOCSWEEP `"IOC sweep NOT performed - no ThreatLists folder found`"`n" '' 'no-lists branch unraised'
        TM 'a missing ThreatLists folder no longer raised fails' @(Get-StructureDefects $m11 'mutated') 'skips the whole sweep without raising it'
        $m12 = Replace-Once $base ("echo [WARNING] C2 domain IOC match NOT performed -- ipconfig /displaydns printed nothing, so the DNS cache could not be read.>> `"%REPORT%`"`ncall :dz_finding WARNING 18 T1071.004 `"C2 domain IOC match NOT performed - DNS cache not readable`"`n") ("echo [SKIPPED] DNS cache could not be read -- C2 domain match NOT performed.>> `"%REPORT%`"`n") '18f empty output back to [SKIPPED]'
        TM '18f with ipconfig printing nothing back to an unraised [SKIPPED] fails' @(Get-StructureDefects $m12 'mutated') 'a [SKIPPED] line raises nothing'
        if ($fails) { Write-Output "FAILED: $fails"; $exit = 1 }
        else { Write-Output '[OK] section18_gaps self-test: every named defect fails the check for its own reason, the shipped bats pass.' }
    } else {
    $all = @()
    foreach ($b in $bats) { $all += @(Get-StructureDefects $texts[$b] $b) }
    foreach ($sp in $script:Specs) {
        $x = Get-StagedBlock $texts['doze_sec.bat'] $sp.S
        $y = Get-StagedBlock $texts['doze_sec_noAdmin.bat'] $sp.S
        if ($null -ne $x -and $null -ne $y -and (($x -join "`n") -cne ($y -join "`n"))) { $all += "$($sp.S): the two bats carry different blocks -- a fix in one is missing from the other" }
    }
    if ($Mode -eq 'Missing') {
        foreach ($b in $bats) { $all += @(Get-BlockDefects $texts[$b] $b 'Missing' '' $work) }
    } else {
        $dir = if ($ListDir) { $ListDir } else { Join-Path $Root 'ThreatLists' }
        if (-not (Test-Path -LiteralPath $dir)) { throw "list folder not found: $dir" }
        if ($Mode -eq 'Run') {
            $res = @(Get-BlockDefects $texts['doze_sec.bat'] 'doze_sec.bat' 'Run' $dir $work $Sections)
            $res | ForEach-Object { Write-Output $_ }
            $all += @($res | Where-Object { $_ -match ': the block could not be rendered$' })
        } else {
            foreach ($b in $bats) { $all += @(Get-BlockDefects $texts[$b] $b 'Shipped' $dir $work) }
        }
    }
    if ($all.Count) { $all | ForEach-Object { Write-Output "[FAIL] $_" }; $exit = 1 }
    elseif ($Mode -ne 'Run') { Write-Output ("[OK] section18_gaps -Mode {0}: Section 18's matchers say NOT performed and raise it when they cannot run, in both bats ({1})." -f $Mode, $(if ($script:OnWindows) { 'Windows PowerShell 5.1' } else { 'pwsh, non-Windows' })) }
    }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
}
exit $exit
