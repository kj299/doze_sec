# ============================================================================
# lint_batch_comments.ps1 -- guard against '::' comments inside parenthesized
# blocks in .bat/.cmd files.
#
# WHY: cmd.exe parses '::' as a label (not a comment) inside ( ... ) blocks.
# A ')' in the comment text closes the block prematurely (both if/else
# branches fire, "The system cannot find the drive specified." errors);
# two adjacent '::' lines inside a block execute the second as a command.
# Only 'rem' is universally safe inside parens. This bug class has recurred
# repeatedly in this repo: issues #35, #36, #39, PR #93 review, #108.
#
# HOW IT TRACKS BLOCKS (mirrors cmd.exe's asymmetric paren rules):
#   - caret-escaped chars (^( ^) ^| ...) and double-quoted segments are
#     stripped first; an unmatched quote quotes the rest of the line.
#   - '::' / 'rem' comment lines and ':label' lines never change depth.
#   - '(' opens a block only at a command position (line start, right after
#     '(' or '&'/'|' separators), after the word 'do' or 'else', or anywhere
#     on lines whose first word is 'if' or 'for' (block headers). A bare '('
#     mid-argument (e.g. PowerShell text echoed into a temp .ps1) does NOT
#     open a block in cmd and is ignored here too.
#   - ')' closes whenever depth > 0.
# Every '::' comment found at depth > 0 is a violation. A file ending at
# non-zero depth is reported as a warning (unbalanced block or tracker
# drift -- investigate either way).
#
# USAGE (Windows 10/11 all versions -- built-in Windows PowerShell 5.1,
# no external dependencies; also runs under PowerShell 7+ / Linux pwsh):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_batch_comments.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_batch_comments.ps1 doze_sec.bat
#
# EXIT CODES: 0 = clean, 1 = violations found, 2 = non-zero final depth only
# ============================================================================
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Path
)

$ErrorActionPreference = 'Stop'

if (-not $Path -or $Path.Count -eq 0) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $Path = Get-ChildItem -Path $repoRoot -Recurse -File -Include *.bat, *.cmd |
        Select-Object -ExpandProperty FullName
}

$violationCount = 0
$depthWarnCount = 0
$tokenPattern = '[()]|[&|]+|[^()&|\s]+'

foreach ($file in $Path) {
    if (-not (Test-Path -LiteralPath $file)) {
        Write-Output ("{0}: ERROR: file not found" -f $file)
        $violationCount++
        continue
    }
    $lines = [System.IO.File]::ReadAllLines($file)
    $depth = 0

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $trim = $lines[$i].TrimStart()

        if ($trim.StartsWith('::')) {
            if ($depth -gt 0) {
                $violationCount++
                Write-Output ("{0}:{1}: [depth {2}] '::' comment inside a parenthesized block -- use 'rem' instead: {3}" -f `
                    $file, ($i + 1), $depth, $trim)
            }
            continue   # comment lines never change paren depth
        }
        if ($trim -match '^[Rr][Ee][Mm]([\s\.]|$)') { continue }
        if ($trim.StartsWith(':')) { continue }

        $code = $trim -replace '\^.', ''
        $code = $code -replace '"[^"]*"', ''
        $q = $code.IndexOf('"')
        if ($q -ge 0) { $code = $code.Substring(0, $q) }

        $toks = @([regex]::Matches($code, $tokenPattern) | ForEach-Object { $_.Value })

        $firstWord = ''
        foreach ($t in $toks) {
            if ($t -ne '(' -and $t -ne ')' -and $t -notmatch '^[&|]+$') {
                $firstWord = $t.TrimStart('@').ToLowerInvariant()
                break
            }
        }
        $symmetric = ($firstWord -eq 'if' -or $firstWord -eq 'for')

        $cmdpos = $true
        $prevWord = ''
        foreach ($t in $toks) {
            if ($t -eq '(') {
                if ($symmetric -or $cmdpos -or $prevWord -eq 'do' -or $prevWord -eq 'else') {
                    $depth++
                }
                $cmdpos = $true; $prevWord = ''
            }
            elseif ($t -eq ')') {
                if ($depth -gt 0) { $depth-- }
                $cmdpos = $false; $prevWord = ''
            }
            elseif ($t -match '^[&|]+$') {
                $cmdpos = $true; $prevWord = ''
            }
            else {
                $cmdpos = $false; $prevWord = $t.TrimStart('@').ToLowerInvariant()
            }
        }
    }

    if ($depth -ne 0) {
        $depthWarnCount++
        Write-Output ("{0}: WARNING: file ends at paren depth {1} -- unbalanced block or lint tracker drift; investigate." -f $file, $depth)
    }
}

if ($violationCount -gt 0) {
    Write-Output ""
    Write-Output ("FAIL: {0} '::'-inside-parens violation(s). cmd.exe parses '::' as a label inside ( ) blocks; use 'rem'. See issue #108." -f $violationCount)
    exit 1
}
if ($depthWarnCount -gt 0) {
    Write-Output ""
    Write-Output ("WARN: {0} file(s) ended at non-zero paren depth." -f $depthWarnCount)
    exit 2
}
Write-Output "OK: no '::' comments inside parenthesized blocks."
exit 0
