# verdict_audit.ps1 -- catch a finding that was PRINTED but never RAISED.
#
# WHY THIS EXISTS: a real audit printed three
#   [WARNING] Key ASR rule not in Block mode: ...
# lines into Section 9 and then closed the section with
#   [SECTION 9/18 RESULT: CLEAN -- no issues detected]
# The finding never reached the ledger, so it never reached FINDINGS COUNTED,
# the exit code, or the remediation script. The owner had to read the report by
# hand to notice. The detection harness has asserted this invariant for a long
# time; a REAL run never checked itself, so the one machine that mattered was
# the one place the check did not run.
#
# The rule: within a section body, a line opening with [CRITICAL] or [WARNING]
# is a finding. A section that contains one and then declares anything other
# than ISSUES FOUND has lost a raise. With -Ledger, the stronger form also
# holds: that section must have at least one ledger record.
#
# Everything before the first section banner (INIT, the TOP FINDINGS block) is
# outside every section body and is deliberately ignored.
#
# Exit 0 always -- this reports, it does not gate. It writes MarkerFile when it
# finds a mismatch so the caller can raise a finding of its own.
#
# Windows PowerShell 5.1 compatible. Read-only apart from MarkerFile.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Report,
    [string]$Ledger,
    [string]$MarkerFile,
    [string]$Allowlist
)

$ErrorActionPreference = 'Continue'
if ($MarkerFile) { Remove-Item -LiteralPath $MarkerFile -Force -EA SilentlyContinue }

# Reuse the project's curated exemption list rather than inventing a second
# one. Entries there are lines that print a severity tag and deliberately do
# not raise -- audit self-degradation, or a per-item line whose aggregate raise
# is elsewhere. Format: FILE|SUBSTRING|reason.
if (-not $Allowlist) { $Allowlist = Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) 'tests/unraised_allowlist.txt' }
$exempt = @()
if (Test-Path -LiteralPath $Allowlist) {
    foreach ($ln in (Get-Content -LiteralPath $Allowlist -EA SilentlyContinue)) {
        $t = $ln.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $f = $t.Split('|')
        if ($f.Count -ge 3 -and $f[1].Trim()) { $exempt += $f[1].Trim() }
    }
}

$lines = $null
for ($attempt = 0; $attempt -lt 3 -and $null -eq $lines; $attempt++) {
    if ($attempt -gt 0) { Start-Sleep -Milliseconds 120 }
    if (-not (Test-Path -LiteralPath $Report)) { continue }
    try { $lines = @(Get-Content -LiteralPath $Report -EA Stop) } catch { $lines = $null }
}
if ($null -eq $lines) {
    # Same rule as block_sev: a check that could not read its input says so.
    '[WARNING] Verdict audit could not read the report, so printed-but-unraised findings were NOT checked this run.'
    if ($MarkerFile) { Set-Content -LiteralPath $MarkerFile -Value 'unreadable' -EA SilentlyContinue }
    exit 0
}

$ledgerSections = @{}
if ($Ledger -and (Test-Path -LiteralPath $Ledger)) {
    foreach ($ln in (Get-Content -LiteralPath $Ledger -EA SilentlyContinue)) {
        $f = $ln.Split('|')
        if ($f.Length -ge 2) { $ledgerSections[$f[1]] = $true }
    }
}

$bad = @()
$curSec = 0
$secFindings = 0
$firstLine = ''
foreach ($ln in $lines) {
    $banner = [regex]::Match($ln, '^\s*\[(\d{1,2})/18\]\s')
    if ($banner.Success) { $curSec = [int]$banner.Groups[1].Value; $secFindings = 0; $firstLine = ''; continue }
    if ($curSec -eq 0) { continue }
    $verdict = [regex]::Match($ln, '^\s*\[SECTION (\d{1,2})/18 RESULT:\s*(\S+)')
    if ($verdict.Success) {
        $n = $verdict.Groups[1].Value
        if ($secFindings -gt 0 -and $verdict.Groups[2].Value -notmatch '^ISSUES') {
            $bad += ("Section {0} printed {1} finding line(s) but its verdict reads '{2}'. First: {3}" -f $n, $secFindings, $verdict.Groups[2].Value, $firstLine)
        } elseif ($secFindings -gt 0 -and $Ledger -and -not $ledgerSections.ContainsKey($n)) {
            $bad += ("Section {0} printed {1} finding line(s) but has no ledger record, so it is uncounted. First: {2}" -f $n, $secFindings, $firstLine)
        }
        $curSec = 0; $secFindings = 0; $firstLine = ''
        continue
    }
    if ($ln -match '^\s*\[(CRITICAL|WARNING)\]') {
        $skip = $false
        foreach ($e in $exempt) { if ($ln.IndexOf($e, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $skip = $true; break } }
        if ($skip) { continue }
        $secFindings++
        if (-not $firstLine) { $firstLine = $ln.Trim(); if ($firstLine.Length -gt 110) { $firstLine = $firstLine.Substring(0, 110) + '...' } }
    }
}

if ($bad.Count) {
    ('[WARNING] {0} section(s) printed a finding that never reached the findings ledger. Those findings are NOT counted in FINDINGS COUNTED or the exit code:' -f $bad.Count)
    foreach ($b in $bad) { '          ' + $b }
    '          This is a defect in the audit, not in this machine. Please report it with the section number.'
    if ($MarkerFile) { Set-Content -LiteralPath $MarkerFile -Value 'hit' -EA SilentlyContinue }
} else {
    '[OK] Every section that printed a finding also raised it into the findings ledger.'
}
exit 0
