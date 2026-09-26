# lint_arg0.ps1 -- no %0-derived path after the switch-parsing loop's `shift`.
#
# WHY: cmd.exe's `shift` moves %0 along with the other arguments (only
# `shift /1` and above leave it alone). After a `:parse_args` loop that shifts
# once per switch, %0 is the LAST SWITCH typed, and `%~f0` / `%~dp0` / `%~nx0`
# resolve that word against the current directory. The RunOnce resume entry
# was written from `%~f0` after the loop and pointed at
#   "C:\...\doze_sec\-noVtSelf" -resume
# on the owner's 2026-09-26 run: a file that does not exist, so no interrupted
# run could ever have resumed. `SCRIPT_DIR=%~dp0`, set after the same loop,
# was the current directory, so tools\ was found only when run from the
# checkout. Nothing in the report or the tests could see it, because every
# runner and the owner both run the bat from its own directory.
#
# RULE: in every .bat/.cmd, after the FIRST line that is exactly `shift`
# (optionally followed by /n or a comment), any `%~<modifiers>0` token outside
# a `rem` / `::` comment is a defect. Capture SCRIPT_PATH / SCRIPT_DIR /
# SCRIPT_FILE before the loop and use those.
#
# -SelfTest copies a bat, re-introduces a `%~f0` after its first shift, and
# must fail on the copy; it must also pass on the unmodified bats.
#
# Windows PowerShell 5.1 and pwsh 7 (Linux CI) -- no dependencies.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

function Get-Arg0Defects {
    param([string[]]$Lines, [string]$Name)
    $bad = @()
    $shifted = $false
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $l = $Lines[$i]
        $t = $l.TrimStart()
        if ($t -match '^(::|[Rr][Ee][Mm]\b)') {
            # cmd expands percent-variables in a comment line too, at parse time.
            # A valid %~dp0 in a comment merely expands; an INVALID modifier
            # (the first draft of the bat's note wrote "%~...0") aborts the
            # WHOLE script before any line runs: "The following usage of the
            # path operator in batch-parameter substitution is invalid" and
            # the read-only CI job exited 255 with no report. Keep the tilde
            # out of comments altogether; there is no reason for it there.
            if ($l -match '%~') { $bad += ("{0}:{1}: percent-tilde inside a comment -- cmd expands it at parse time and an invalid modifier aborts the whole script; describe the modifier in words" -f $Name, ($i + 1)) }
            continue
        }
        if (-not $shifted) {
            if ($t -match '^[Ss][Hh][Ii][Ff][Tt](\s|$)') { $shifted = $true }
            continue
        }
        $m = [regex]::Matches($l, '%~[fdpnxsatz$:]*0(?![0-9])')
        foreach ($x in $m) {
            $bad += ("{0}:{1}: '{2}' after the first shift -- %0 is the last switch here, not the script; use SCRIPT_PATH / SCRIPT_DIR / SCRIPT_FILE captured before the loop" -f $Name, ($i + 1), $x.Value)
        }
    }
    return @($bad)
}

$bats = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Include *.bat, *.cmd | Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' })
if ($bats.Count -lt 2) { Write-Host ("[FAIL] only {0} batch file(s) found -- this lint is broken, not the code" -f $bats.Count); exit 1 }

if ($SelfTest) {
    $fails = @()
    # 1. the shipped bats must be clean, and each must actually contain a shift
    #    (a file with no shift would pass vacuously).
    foreach ($b in $bats) {
        $lines = [IO.File]::ReadAllLines($b.FullName)
        if (-not ($lines | Where-Object { $_.TrimStart() -match '^[Ss][Hh][Ii][Ff][Tt](\s|$)' })) { continue }
        $d = @(Get-Arg0Defects -Lines $lines -Name $b.Name)
        if ($d.Count) { $fails += ("shipped {0} has {1} defect(s): {2}" -f $b.Name, $d.Count, $d[0]) }
    }
    # 2. a mutated copy: %~f0 re-introduced after the first shift must be caught,
    #    and one inside a rem after the shift must NOT be.
    $src = $bats | Where-Object { $_.Name -ieq 'doze_sec.bat' } | Select-Object -First 1
    if (-not $src) { Write-Host '[FAIL] doze_sec.bat not found for the mutation case'; exit 1 }
    $lines = [IO.File]::ReadAllLines($src.FullName)
    $firstShift = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].TrimStart() -match '^[Ss][Hh][Ii][Ff][Tt](\s|$)') { $firstShift = $i; break } }
    if ($firstShift -lt 0) { Write-Host '[FAIL] doze_sec.bat has no shift line -- the mutation case cannot run'; exit 1 }
    $mut = [System.Collections.Generic.List[string]]$lines
    $mut.Insert($lines.Count - 1, 'reg add "HKCU\x" /v y /d "\"%~f0\" -resume" /f')
    $mut.Insert($lines.Count - 1, 'rem a plain %CD% in a comment is not a defect')
    $mut.Insert($firstShift, 'set "BEFORE=%~dp0"')
    $mut.Insert($firstShift, ':: an invalid %~...0 in a comment aborts cmd at parse time')
    $d = @(Get-Arg0Defects -Lines $mut.ToArray() -Name 'mutated.bat')
    if ($d.Count -ne 2) { $fails += ("mutated copy: expected exactly 2 defects (the %~f0 after the shift, the percent-tilde in a comment), got {0}: {1}" -f $d.Count, ($d -join ' | ')) }
    else {
        if (-not ($d | Where-Object { $_ -match "'%~f0' after the first shift" })) { $fails += ("mutated copy: the %~f0 after the shift was not reported: {0}" -f ($d -join ' | ')) }
        if (-not ($d | Where-Object { $_ -match 'percent-tilde inside a comment' })) { $fails += ("mutated copy: the percent-tilde in a comment was not reported: {0}" -f ($d -join ' | ')) }
    }
    # 3. the same token BEFORE the first shift is fine
    $pre = @('@echo off', 'set "P=%~f0"', 'set "D=%~dp0"', ':loop', 'if "%~1"=="" goto :done', 'shift', 'goto :loop', ':done', 'echo %P%')
    $d = @(Get-Arg0Defects -Lines $pre -Name 'pre.bat')
    if ($d.Count -ne 0) { $fails += ("tokens before the first shift were reported: {0}" -f ($d -join ' | ')) }
    if ($fails.Count) { Write-Host ("[FAIL] lint_arg0 self-test: {0} problem(s):" -f $fails.Count); $fails | ForEach-Object { Write-Host ("  - " + $_) }; exit 1 }
    Write-Host '[OK] lint_arg0 self-test: shipped bats clean; a %~f0 after the shift and a percent-tilde in a comment are caught; a plain comment and a pre-shift token are not.'
    exit 0
}

$bad = @()
$scanned = 0
foreach ($b in $bats) {
    $lines = [IO.File]::ReadAllLines($b.FullName)
    $scanned++
    $bad += @(Get-Arg0Defects -Lines $lines -Name $b.Name)
}
if ($bad.Count) {
    Write-Host ("[FAIL] {0} %0-derived token(s) after a shift ({1} batch file(s) scanned):" -f $bad.Count, $scanned)
    $bad | ForEach-Object { Write-Host ("  - " + $_) }
    exit 1
}
Write-Host ("[OK] lint_arg0: no %0-derived path after a shift in {0} batch file(s)." -f $scanned)
exit 0
