# lint_report_echo.ps1 -- a line the report PRINTS must actually reach the
# report, and a command it tells you to run must actually run.
#
# WHY (all three classes were found in one real field run, 2026-09-05):
#
#  1. ODD QUOTES. cmd honours DOUBLE quotes when it looks for a redirection
#     operator. Two narrative lines carried an odd number of them, so the `>>`
#     and the report path fell INSIDE an unterminated quote, became literal,
#     and the whole line -- text, operator and path -- was printed to the
#     console instead of the report. The report lost two lines and the
#     surviving sentence broke mid-clause.
#
#  2. CARET INSIDE QUOTES. Outside double quotes cmd CONSUMES `^`; inside them
#     it leaves it alone. 90 display lines carried `^(`, `^)` or `^|` inside
#     quotes, so the report printed stray carets -- and pasting one of those
#     `wevtutil ... /q:"*[System[^(EventID=4720^)]]"` lines into cmd hands the
#     carets straight to wevtutil, which rejects the XPath. The tool's own
#     "here is how to check this yourself" line did not work.
#
#  3. TRUNCATED COMMANDS. 18 `Command:` lines per bat had lost their opening
#     paren (`"Get-MpPreference).ExclusionPath"`, `"Test-Path $f) {"`) and 4
#     more stopped mid-hashtable (`@{LogName='Security'`). They printed, they
#     looked authoritative, and none of them would run.
#
# None of this changes what the tool DETECTS, which is exactly why it survived:
# every other gate in this repo watches findings and verdicts. This one watches
# the prose, because the report is the product.
#
# Windows PowerShell 5.1 and pwsh; no external dependencies.
#
# Output goes to the SUCCESS stream (Write-Output), never Write-Host: CI
# captures this lint's output to assert it scanned a non-vacuous number of
# lines, and Write-Host writes to the information stream, where `$out = (...)`
# captures nothing at all. lint_unraised_findings.ps1 is written the same way
# for the same reason.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

# Characters that need no escaping inside cmd double quotes, so a caret in
# front of one is always a mistake. `^^` is the same mistake doubled.
$script:BadAfterCaret = '()|<>&^'

function Split-EchoLine {
    # Returns @{ Body; Target } for an echo line, or $null when the line is not
    # an echo with a recognised redirection target.
    param([string]$Line)
    $t = $Line.TrimStart()
    if ($t -notmatch '^echo[ .]') { return $null }
    $m = [regex]::Match($t, '\s*>>?\s*"%(REPORT|PSRUN|CHANGELOG|UNDO_BAT|LEDGER)%"\s*$')
    if (-not $m.Success) { return $null }
    return @{ Body = $t.Substring(0, $m.Index); Target = $m.Groups[1].Value }
}

function Get-InQuoteCarets {
    # Offsets of every caret that sits between double quotes AND precedes a
    # character that does not need escaping there.
    param([string]$Body)
    $hits = @(); $inq = $false
    for ($i = 0; $i -lt $Body.Length; $i++) {
        $c = $Body[$i]
        if ($c -eq '"') { $inq = -not $inq }
        elseif ($c -eq '^' -and $inq -and $i + 1 -lt $Body.Length -and $script:BadAfterCaret.Contains($Body[$i + 1])) {
            $hits += $i
        }
    }
    return $hits
}

function Test-Balanced {
    param([string]$Text, [char]$Open, [char]$Close)
    $d = 0
    foreach ($c in $Text.ToCharArray()) {
        if ($c -eq $Open) { $d++ } elseif ($c -eq $Close) { $d-- }
        if ($d -lt 0) { return $false }
    }
    return $d -eq 0
}

function Invoke-Lint {
    param([string]$RepoRoot)

    $bats = @('doze_sec.bat', 'doze_sec_noAdmin.bat') |
            ForEach-Object { Join-Path $RepoRoot $_ } |
            Where-Object { Test-Path -LiteralPath $_ }
    if ($bats.Count -lt 2) {
        Write-Output "[FAIL] expected both bats under '$RepoRoot'; found $($bats.Count) -- this lint is broken, not the code"
        return @{ Bad = @('missing bats'); Echoes = 0; Commands = 0 }
    }

    $bad = @(); $nEcho = 0; $nCmd = 0

    foreach ($bat in $bats) {
        $name = Split-Path -Leaf $bat
        $lines = Get-Content -LiteralPath $bat
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $ln = $i + 1

            # 4 -- a digit directly before '>' is a HANDLE, not text.
            #   if defined DOZE_EXIT_FILE echo %EXIT_CODE%>"%DOZE_EXIT_FILE%"
            # with EXIT_CODE=8 is `echo` with handle 8 redirected: it prints
            # 'ECHO is off.' to the console and writes NOTHING. Every exit code
            # is one digit, so the parent of the console-log re-exec read an
            # empty file, kept its default and exited 0 -- on every machine,
            # for every run that did not pass -noConsoleLog. Put the
            # redirection first: >"file" echo %VAR%.
            if ($lines[$i] -match '(?i)\becho\s+(%[A-Za-z_][A-Za-z_0-9]*%|\d)>>?') {
                $bad += "${name}:${ln}: 'echo <value>>file' with no space -- if the value is a digit cmd reads it as a redirection HANDLE, prints 'ECHO is off.' and writes nothing; write the redirection first: >'file' echo %VAR%"
            }

            # 5 -- a report paragraph must reach the report in full.
            # Two three-line prose blocks had '>> "%REPORT%"' on the LAST line
            # only: the first two printed to the console and the report began
            # the sentence mid-way ('DLLs actually loaded in running
            # processes'). Only prose lines count (two-space indent, no colour
            # code), and only when the paragraph they run into is redirected to
            # the report -- a console message followed by 'echo.' is untouched.
            if ($lines[$i] -match '^echo  [^\s%]' -and $lines[$i] -notmatch '>') {
                $k = $i + 1
                while ($k -lt $lines.Count -and $lines[$k] -match '^echo  \S' -and $lines[$k] -notmatch '>') { $k++ }
                if ($k -lt $lines.Count -and $lines[$k] -match '^echo  \S' -and $lines[$k] -match '>>\s*"%REPORT%"') {
                    $bad += "${name}:${ln}: report prose with no redirection, in a paragraph whose next redirected line goes to %REPORT% -- this line prints to the CONSOLE and the report starts the sentence mid-way"
                }
            }

            $split = Split-EchoLine $lines[$i]
            if ($null -eq $split) { continue }
            $body = [string]$split.Body

            # 0 -- the severity tag must be spelled the way the graders read it.
            #
            # This one covers %PSRUN% as well as %REPORT%, because a staged
            # block's output IS report text. A real audit printed
            #   Write-Output '[WARN] Sticky Keys shortcut ENABLED ...'
            # into Section 13. block_sev.ps1, lint_unraised_findings.ps1 and
            # verdict_audit.ps1 all matched only the long spelling, so all
            # three went blind at once: the block graded OK, the finding never
            # reached the ledger, FINDINGS COUNTED or the exit code -- while
            # the dashboard showed it as a WARNING and the remediation script
            # the owner runs ELEVATED carried a fix for it. The tag spelling
            # is what hid the missing raise.
            #
            # The graders now accept the short forms too, but accepting them
            # is the backstop; the rule is that they must not be written. One
            # spelling means a new tag can never quietly go ungraded again.
            # Console-only 'echo [WARN] ...' status lines are untouched -- they
            # have no redirection target, so Split-EchoLine already ignores
            # them, and there are around ten of them in the INIT and CTI paths.
            if ($split.Target -eq 'REPORT' -or $split.Target -eq 'PSRUN') {
                $tm = [regex]::Match($body, '\[(WARN|CRIT|ERROR|FAIL|DANGER|ALERT)\]')
                if ($tm.Success) {
                    $canon = if ($tm.Groups[1].Value -eq 'CRIT') { 'CRITICAL' } else { 'WARNING' }
                    $bad += "${name}:${ln}: writes '[$($tm.Groups[1].Value)]' into %$($split.Target)% -- use '[$canon]'. Only the long spellings are the report's severity vocabulary; a short one is graded by nothing and reaches neither the ledger nor the exit code."
                }
            }

            if ($split.Target -ne 'REPORT') { continue }
            $nEcho++

            # 1 -- the redirect must not be swallowed by an open quote.
            if ((($lines[$i].ToCharArray() | Where-Object { $_ -eq '"' }).Count % 2) -ne 0) {
                $bad += "${name}:${ln}: odd number of double quotes -- the '>>' falls inside a quote, so this line prints to the CONSOLE and never reaches the report"
            }

            # 2 -- a caret inside quotes prints literally.
            $carets = @(Get-InQuoteCarets $body)
            if ($carets.Count) {
                $bad += "${name}:${ln}: $($carets.Count) caret(s) inside double quotes -- cmd leaves '^' alone there, so the report prints a stray caret and the printed command will not run"
            }

            # 3 -- a Command: line must be a command someone can actually run.
            $disp = $body -replace '^echo[ .]', ''
            if ($disp.TrimStart() -notlike 'Command:*') { continue }
            $nCmd++
            foreach ($pair in @(@('(', ')'), @('[', ']'), @('{', '}'))) {
                if (-not (Test-Balanced $disp $pair[0] $pair[1])) {
                    $bad += "${name}:${ln}: unbalanced '$($pair[0])$($pair[1])' in a Command: line -- it was truncated, so it cannot be run as printed"
                }
            }
            $pm = [regex]::Match($disp, '^\s*Command:\s*powershell(?:\s+-Command)?\s+"(.*)"(?:\s{2,}\[.*\])?\s*$')
            if ($pm.Success) {
                $errs = $null; $toks = $null
                [void][System.Management.Automation.Language.Parser]::ParseInput($pm.Groups[1].Value, [ref]$toks, [ref]$errs)
                if ($errs -and $errs.Count) {
                    $bad += "${name}:${ln}: the PowerShell command this line tells the reader to run does not parse -- $($errs[0].Message)"
                }
            }
        }
    }

    # Vacuity: a scanner that found nothing is broken, not vindicated.
    if ($nEcho -lt 400) { $bad += "only $nEcho report echo line(s) scanned -- the scanner is broken, not the code" }
    if ($nCmd  -lt 100) { $bad += "only $nCmd 'Command:' line(s) scanned -- the scanner is broken, not the code" }

    return @{ Bad = $bad; Echoes = $nEcho; Commands = $nCmd }
}

if ($SelfTest) {
    # Every class must FAIL on a mutated copy. A lint that cannot fail is not a
    # lint -- and a mutation that changes nothing is worse than no mutation at
    # all, because it reports OK.
    #
    # Mutations are LITERAL .Replace() calls, never a regex with a `$` anchor.
    # An earlier version anchored one mutation with '(?m)...$'. On this box the
    # checkout is LF and it matched; on the Windows runner actions/checkout
    # writes CRLF, the `\r` sat between the closing quote and the line end, and
    # the mutation silently changed nothing. Windows is the platform this tool
    # targets, so the self-test now runs every mutation against BOTH a
    # LF and a CRLF copy and requires it to be caught in each.
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dz_lre_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $mutations = @(
        @{ Name = 'odd quotes swallow the redirect'
           From = 'echo --- Defender Core Status: EVALUATED --->> "%REPORT%"'
           To   = 'echo --- Defender "Core Status: EVALUATED --->> "%REPORT%"' },
        @{ Name = 'caret inside double quotes'
           From = '"(Get-MpPreference).ExclusionPath"'
           To   = '"(Get-MpPreference^).ExclusionPath"' },
        @{ Name = 'Command: line truncated (unbalanced paren)'
           From = '"(Get-MpPreference).ExclusionProcess"'
           To   = '"Get-MpPreference).ExclusionProcess"' },
        @{ Name = 'printed PowerShell command does not parse'
           From = "(Get-ItemProperty 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name Flags).Flags"
           To   = "(Get-ItemProperty 'HKCU:\Control Panel\Accessibility\StickyKeys -Name Flags).Flags" },
        @{ Name = 'short severity tag [WARN] on the %PSRUN% path'
           From = "Write-Output '[WARNING] Sticky Keys shortcut ENABLED"
           To   = "Write-Output '[WARN] Sticky Keys shortcut ENABLED" },
        @{ Name = 'short severity tag [CRIT] on the %PSRUN% path'
           From = "('[WARNING] '+`$b+' - not found in System32')"
           To   = "('[CRIT] '+`$b+' - not found in System32')" },
        @{ Name = 'short severity tag [ERROR] on the %REPORT% path'
           From = 'echo [WARNING] C2 domain IOC matches found in DNS cache above.'
           To   = 'echo [ERROR] C2 domain IOC matches found in DNS cache above.' },
        @{ Name = 'exit code written as echo N>file (digit read as a handle; the file stays empty)'
           From = 'if defined DOZE_EXIT_FILE 2>nul >"%DOZE_EXIT_FILE%" echo %EXIT_CODE%'
           To   = 'if defined DOZE_EXIT_FILE echo %EXIT_CODE%>"%DOZE_EXIT_FILE%" 2>nul' },
        @{ Name = 'report prose line lost to the console (redirect missing inside a redirected paragraph)'
           From = 'echo  Every persistence check reads a registry key or a file on disk. An implant>> "%REPORT%"'
           To   = 'echo  Every persistence check reads a registry key or a file on disk. An implant' }
    )
    $failures = 0
    foreach ($eol in @('LF', 'CRLF')) {
        foreach ($m in $mutations) {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            foreach ($f in @('doze_sec.bat', 'doze_sec_noAdmin.bat')) {
                $src = Get-Content -LiteralPath (Join-Path $Root $f) -Raw
                $src = $src -replace "`r`n", "`n"
                if ($eol -eq 'CRLF') { $src = $src -replace "`n", "`r`n" }
                $mut = $src.Replace($m.From, $m.To)
                if ($mut -eq $src) {
                    Write-Output "[FAIL] $eol mutation '$($m.Name)' changed nothing in $f -- the self-test is vacuous"
                    $failures++
                }
                [System.IO.File]::WriteAllText((Join-Path $tmp $f), $mut)
            }
            $r = Invoke-Lint -RepoRoot $tmp
            if ($r.Bad.Count -gt 0) {
                Write-Output "[OK]   $eol mutation caught: $($m.Name)"
                Write-Output "         -> $($r.Bad[0])"
            } else {
                Write-Output "[FAIL] $eol mutation NOT caught: $($m.Name)"
                $failures++
            }
        }
    }

    # NEGATIVE CASE. The severity-tag rule must fire on the report path and
    # stay SILENT on a console-only status line. There are about ten of those
    # in the INIT and CTI paths ('echo  [WARN] No CTI skill file was found'),
    # they are not report text, and a lint that flagged them would be worked
    # around rather than obeyed.
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    foreach ($f in @('doze_sec.bat', 'doze_sec_noAdmin.bat')) {
        $src = Get-Content -LiteralPath (Join-Path $Root $f) -Raw
        # ...and a console-only PROSE line followed by a blank report line
        # (echo.) is not a lost paragraph either -- rule 5 must stay quiet.
        $ins = "echo  [WARN] console-only status line, no redirection target`r`necho  console-only prose line, followed by a blank report line, not a paragraph`r`n"
        $anchor = 'echo.>> "%REPORT%"'
        $at = $src.IndexOf($anchor)
        if ($at -lt 0) { Write-Output "[FAIL] negative case: anchor not found in $f"; $failures++ }
        else { $src = $src.Substring(0, $at) + $ins + $src.Substring($at) }
        [System.IO.File]::WriteAllText((Join-Path $tmp $f), $src)
    }
    $neg = Invoke-Lint -RepoRoot $tmp
    if ($neg.Bad.Count -gt 0) {
        Write-Output "[FAIL] a console-only status/prose line was flagged: $($neg.Bad[0])"
        $failures++
    } else {
        Write-Output '[OK]   console-only [WARN] status line and console-only prose before echo. are NOT flagged'
    }

    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
    if ($failures) { Write-Output "[FAIL] $failures self-test mutation(s) did not fail as required"; exit 1 }
    Write-Output "[OK] all $($mutations.Count) mutations fail this lint for the right reason on both LF and CRLF checkouts, and a console-only [WARN] does not."
    exit 0
}

$res = Invoke-Lint -RepoRoot $Root
if ($res.Bad.Count) {
    Write-Output ("[FAIL] {0} report-echo defect(s):" -f $res.Bad.Count)
    $res.Bad | ForEach-Object { Write-Output ("  - " + $_) }
    exit 1
}
Write-Output ("[OK] {0} report echo line(s) scanned, {1} of them 'Command:' lines: every line reaches the report, no caret prints literally, every printed PowerShell command parses, no exit code is written through a digit handle, and no report paragraph is split across console and report." -f $res.Echoes, $res.Commands)
exit 0
