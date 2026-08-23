# section_coverage.ps1 -- calibrate each section's CLEAN verdict against the
# checks that could not run in it. Runs as a post-pass over the finished report,
# before report_format.ps1.
#
# WHY: doze_sec_noAdmin.bat prints "PARTIAL -- N check(s) deferred" when a
# section could not run something without elevation. doze_sec.bat has no
# equivalent -- every section prints the literal "CLEAN -- no issues detected"
# no matter how many of its checks emitted [SKIPPED].
#
# So a section whose Defender queries all failed, whose helper script was
# missing, or whose WMI provider was broken reads EXACTLY THE SAME as one where
# every check ran and passed. The COVERAGE & CONFIDENCE block at the end of the
# report gives an aggregate skip count, but the per-section verdict -- the line
# a reader actually scans -- says nothing. A clean verdict over checks that
# never ran is the quietest way this tool could mislead someone.
#
# WHY A POST-PASS instead of counting at each skip site: almost every [SKIPPED]
# line is emitted by a PowerShell tool or a staged block, not by the batch
# script, so the bat has no site to count at. Threading a return channel through
# ~46 blocks and a dozen tools would be a large, fragile change for a reporting
# improvement. The report already holds the ground truth -- one [SKIPPED] line
# per skipped check, inside a section body delimited by the [N/18] banner and
# the [SECTION N/18 RESULT:] line -- so one pass over it needs no new plumbing.
#
# WHAT IS REWRITTEN: only CLEAN verdicts, and only for sections that skipped
# something. ISSUES FOUND and PARTIAL verdicts are left exactly as they are;
# every other consumer of this line (detection_selftest.ps1, noadmin_smoke.ps1)
# keys on "ISSUES FOUND", and the section-sync assertion reads the first token
# after "RESULT:", which stays "CLEAN".
#
# NO DENOMINATOR, deliberately. "2 of 7 checks" would need a central register of
# checks attempted, which does not exist in this codebase. Printing a ratio the
# tool cannot actually compute is the kind of false precision the rest of this
# project exists to avoid.
#
# Windows PowerShell 5.1 compatible. Rewrites only the report it is given.
# Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Report
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path -LiteralPath $Report -PathType Leaf)) {
    "[SKIPPED] Report not found at $Report -- section coverage not calibrated."
    "Calibrated 0 section verdict(s)."
    exit 0
}

$lines = $null
try { $lines = @(Get-Content -LiteralPath $Report -EA Stop) } catch {}
if (-not $lines) {
    "[SKIPPED] Report could not be read -- section coverage not calibrated."
    "Calibrated 0 section verdict(s)."
    exit 0
}

# Pass 1: count skips per section. A skip is a line whose OWN leading tag is
# [SKIPPED] -- the same rule block_sev.ps1 and report_safety.ps1 apply -- so
# prose that merely mentions the word cannot inflate the count.
$skips = @{}
$cur = 0
foreach ($ln in $lines) {
    $m = [regex]::Match($ln, '^\s*\[(\d{1,2})/18\]\s')
    if ($m.Success) { $cur = [int]$m.Groups[1].Value; continue }
    if ($ln -match '^\s*\[SECTION \d{1,2}/18 RESULT:') { $cur = 0; continue }
    if ($cur -eq 0) { continue }
    if ($ln -match '^\s*\[SKIPPED\]') {
        if (-not $skips.ContainsKey($cur)) { $skips[$cur] = 0 }
        $skips[$cur]++
    }
}

# Pass 2: calibrate the CLEAN verdicts of sections that skipped something.
$calibrated = 0
$out = New-Object System.Collections.Generic.List[string]
foreach ($ln in $lines) {
    # Skip a verdict this pass has already calibrated. The rewrite replaces the
    # whole line rather than appending, so re-running is content-stable either
    # way -- but the tally should mean "newly calibrated", and CI asserts a
    # second run reports zero.
    $v = [regex]::Match($ln, '^(\s*)\[SECTION (\d{1,2})/18 RESULT: CLEAN\b')
    if ($v.Success -and $ln -notmatch 'could NOT run') {
        $n = [int]$v.Groups[2].Value
        if ($skips.ContainsKey($n) -and $skips[$n] -gt 0) {
            $c = $skips[$n]
            $word = if ($c -eq 1) { 'check' } else { 'checks' }
            $out.Add(("{0}[SECTION {1}/18 RESULT: CLEAN -- no issues detected, but {2} {3} in this section could NOT run (see [SKIPPED] above); a clean result does not cover them]" -f $v.Groups[1].Value, $n, $c, $word))
            $calibrated++
            continue
        }
    }
    $out.Add($ln)
}

if ($calibrated -gt 0) {
    try { Set-Content -LiteralPath $Report -Value $out -Encoding UTF8 -EA Stop }
    catch {
        "[WARNING] Section verdicts could not be written back to the report -- coverage calibration not applied."
        "Calibrated 0 section verdict(s)."
        exit 0
    }
}

"Calibrated $calibrated section verdict(s) whose CLEAN result did not cover every check."
exit 0
