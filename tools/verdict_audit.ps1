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
# THE INVERSE, with -Ledger: a section that holds a ledger record must have
# printed SOMETHING a reader can find -- a finding line, or at least a
# [SKIPPED] line (a blind spot the tool raises on purpose). A record whose
# section printed neither is a finding counted that the report never shows.
# The standard-user field run 2026-09-24 21:03 carried two such rows
# ("records missing with no clear event", "rootkit indicator") raised from
# checks that printed only [SKIPPED] -- those are now DEFERRED on a
# standard-user token; this rule is the runtime backstop for the shape.
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
    [string]$Report,
    [string]$Ledger,
    [string]$MarkerFile,
    [string]$Allowlist,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

function Write-MarkerFile {
    # The marker IS the route to the findings ledger: a failed write turns a
    # real finding into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine failure print instead of vanishing -- the
    # bare `Set-Content -EA SilentlyContinue` this replaces is the exact
    # pattern that cost a field test its finding across twelve tools, and it
    # survived here because tests/marker_selftest.ps1 only discovered tools
    # that define a Write-Marker FUNCTION.
    param([string]$Path, [string]$Value = 'hit')
    if (-not $Path) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Value -Encoding ASCII
}
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

# PURE: the whole analysis over report lines and ledger rows. Returns the
# list of defects (empty means consistent).
function Get-VerdictDefects {
    param([string[]]$Lines, [string[]]$LedgerRows, [string[]]$Exempt)
    $ledgerSections = @{}
    foreach ($ln in @($LedgerRows)) {
        $f = ([string]$ln).Split('|')
        if ($f.Length -ge 2 -and $f[1] -match '^\d{1,2}$') { $ledgerSections[$f[1]] = $true }
    }
    $bad = @()
    $curSec = 0
    $secFindings = 0
    $secSkipped = 0
    $firstLine = ''
    foreach ($ln in @($Lines)) {
        $banner = [regex]::Match($ln, '^\s*\[(\d{1,2})/18\]\s')
        if ($banner.Success) { $curSec = [int]$banner.Groups[1].Value; $secFindings = 0; $secSkipped = 0; $firstLine = ''; continue }
        if ($curSec -eq 0) { continue }
        $verdict = [regex]::Match($ln, '^\s*\[SECTION (\d{1,2})/18 RESULT:\s*(\S+)')
        if ($verdict.Success) {
            $n = $verdict.Groups[1].Value
            if ($secFindings -gt 0 -and $verdict.Groups[2].Value -notmatch '^ISSUES') {
                $bad += ("Section {0} printed {1} finding line(s) but its verdict reads '{2}'. First: {3}" -f $n, $secFindings, $verdict.Groups[2].Value, $firstLine)
            } elseif ($secFindings -gt 0 -and $ledgerSections.Count -gt 0 -and -not $ledgerSections.ContainsKey($n)) {
                $bad += ("Section {0} printed {1} finding line(s) but has no ledger record, so it is uncounted. First: {2}" -f $n, $secFindings, $firstLine)
            } elseif ($secFindings -eq 0 -and $secSkipped -eq 0 -and $ledgerSections.ContainsKey($n)) {
                $bad += ("Section {0} holds a ledger record but printed neither a finding line nor a [SKIPPED] line -- a finding was counted that the report never shows (a deferral or a blind spot raised as a finding?)" -f $n)
            }
            $curSec = 0; $secFindings = 0; $secSkipped = 0; $firstLine = ''
            continue
        }
        if ($ln -match '^\s*\[SKIPPED\]') { $secSkipped++; continue }
        # Short spellings count: a real report printed '[WARN] Sticky Keys shortcut
        # ENABLED' in Section 13 and this audit read the section as having printed
        # nothing, so the very gap it exists to declare went undeclared.
        if ($ln -match '^\s*\[(CRITICAL|CRIT|WARNING|WARN)\]') {
            $skip = $false
            foreach ($e in @($Exempt)) { if ($e -and $ln.IndexOf($e, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $skip = $true; break } }
            if ($skip) { continue }
            $secFindings++
            if (-not $firstLine) { $firstLine = $ln.Trim(); if ($firstLine.Length -gt 110) { $firstLine = $firstLine.Substring(0, 110) + '...' } }
        }
    }
    return @($bad)
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $sec9 = @(' [9/18] DEFENDER')
    $d = @(Get-VerdictDefects -Lines ($sec9 + @('[WARNING] Key ASR rule not in Block mode: x', ' [SECTION 9/18 RESULT: CLEAN -- no issues detected]')) -LedgerRows @() -Exempt @())
    T 'printed but not raised: a [WARNING] line under a CLEAN verdict is a defect' ($d.Count -eq 1 -and $d[0] -match 'verdict reads') ($d -join ' | ')
    $d = @(Get-VerdictDefects -Lines ($sec9 + @('[WARNING] Key ASR rule not in Block mode: x', ' [SECTION 9/18 RESULT: ISSUES FOUND -- review]')) -LedgerRows @('WARNING|9|T1562.001|ASR') -Exempt @())
    T 'printed AND raised: no defect' ($d.Count -eq 0) ($d -join ' | ')
    $d = @(Get-VerdictDefects -Lines ($sec9 + @('[WARNING] Key ASR rule not in Block mode: x', ' [SECTION 9/18 RESULT: ISSUES FOUND -- review]')) -LedgerRows @('WARNING|13|T1546.008|Sticky') -Exempt @())
    T 'printed, verdict ISSUES FOUND, but no ledger record for the section: a defect' ($d.Count -eq 1 -and $d[0] -match 'no ledger record') ($d -join ' | ')
    $d = @(Get-VerdictDefects -Lines (@(' [16/18] EVENT LOG', "[SKIPPED] Log 'Security' could not be read -- gap check NOT performed", '[OK] fine', ' [SECTION 16/18 RESULT: ISSUES FOUND -- review]')) -LedgerRows @('WARNING|16|T1070.001|records missing') -Exempt @())
    T 'raised from a [SKIPPED] line (a blind spot raised on purpose): not a defect of THIS rule' ($d.Count -eq 0) ($d -join ' | ')
    $d = @(Get-VerdictDefects -Lines (@(' [17/18] NATION-STATE', '[INFO] 1 service(s) registered but not enumerable', '[OK] agree', ' [SECTION 17/18 RESULT: ISSUES FOUND -- review]')) -LedgerRows @('WARNING|17|T1014|rootkit indicator') -Exempt @())
    T 'raised with NOTHING printed (no finding line, no [SKIPPED]): the inverse defect' ($d.Count -eq 1 -and $d[0] -match 'never shows') ($d -join ' | ')
    $d = @(Get-VerdictDefects -Lines (@('[WARNING] Could not create RunOnce key', ' [1/18] SYSTEM', '[OK] fine', ' [SECTION 1/18 RESULT: CLEAN -- no issues detected]')) -LedgerRows @() -Exempt @())
    T 'anything before the first section banner is outside every section' ($d.Count -eq 0) ($d -join ' | ')
    $d = @(Get-VerdictDefects -Lines ($sec9 + @('[WARN] Sticky Keys shortcut ENABLED', ' [SECTION 9/18 RESULT: CLEAN -- no issues detected]')) -LedgerRows @() -Exempt @())
    T 'the short spelling [WARN] still counts as a printed finding' ($d.Count -eq 1) ($d -join ' | ')
    $d = @(Get-VerdictDefects -Lines ($sec9 + @('[WARNING] per-item line that aggregates elsewhere', ' [SECTION 9/18 RESULT: CLEAN -- no issues detected]')) -LedgerRows @() -Exempt @('per-item line that aggregates elsewhere'))
    T 'an allowlisted line is exempt' ($d.Count -eq 0) ($d -join ' | ')
    $d = @(Get-VerdictDefects -Lines (@(' [3/18] NETWORK', '[OK] fine', ' [SECTION 3/18 RESULT: CLEAN -- no issues detected]')) -LedgerRows @('WARNING|INIT|AUDITGAP|x') -Exempt @())
    T 'a ledger row under a non-numeric section (INIT) is ignored by the inverse rule' ($d.Count -eq 0) ($d -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails verdict_audit self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] verdict_audit self-test: a printed finding must be raised, a raised finding must be printed or at least declared [SKIPPED], and INIT lines are outside every section.'
    exit 0
}

if (-not $Report) { '[WARNING] Verdict audit was given no -Report path, so printed-but-unraised findings were NOT checked this run.'; Write-MarkerFile -Path $MarkerFile -Value 'unreadable'; exit 0 }

$lines = $null
for ($attempt = 0; $attempt -lt 3 -and $null -eq $lines; $attempt++) {
    if ($attempt -gt 0) { Start-Sleep -Milliseconds 120 }
    if (-not (Test-Path -LiteralPath $Report)) { continue }
    try { $lines = @(Get-Content -LiteralPath $Report -EA Stop) } catch { $lines = $null }
}
if ($null -eq $lines) {
    # Same rule as block_sev: a check that could not read its input says so.
    '[WARNING] Verdict audit could not read the report, so printed-but-unraised findings were NOT checked this run.'
    Write-MarkerFile -Path $MarkerFile -Value 'unreadable'
    exit 0
}

$ledgerRows = @()
if ($Ledger -and (Test-Path -LiteralPath $Ledger)) { $ledgerRows = @(Get-Content -LiteralPath $Ledger -EA SilentlyContinue) }

$bad = @(Get-VerdictDefects -Lines $lines -LedgerRows $ledgerRows -Exempt $exempt)

if ($bad.Count) {
    ('[WARNING] {0} section(s) disagree with the findings ledger -- a finding printed but never raised (NOT counted in FINDINGS COUNTED or the exit code), or a finding counted that the report never shows:' -f $bad.Count)
    foreach ($b in $bad) { '          ' + $b }
    '          This is a defect in the audit, not in this machine. Please report it with the section number.'
    Write-MarkerFile -Path $MarkerFile -Value 'hit'
} else {
    '[OK] Every section that printed a finding also raised it into the findings ledger, and every ledger record has a visible line in its section.'
}
exit 0
