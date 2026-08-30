# lint_unraised_findings.ps1 -- fail the build on any check that PRINTS a
# severity but never RAISES it.
#
# THE BUG CLASS THIS EXISTS TO KILL
# ---------------------------------
# The audit's verdicts all derive from one place, the findings ledger: the
# per-section CLEAN/ISSUES verdict, the FINDINGS COUNTED total, and the process
# exit code. A check reaches the ledger by calling :dz_finding -- directly, or
# via a marker file, or via :dz_ps_scan.
#
# A check that instead writes '[CRITICAL] ...' straight into the report reaches
# NONE of them. The line sits in the report where a human might read it, while
# the section says "CLEAN -- no issues detected", the count says 0 and the exit
# code says success. A retrospective found this on ~25 checks at once, including
# Cobalt Strike named pipes, WMI permanent-subscription persistence, IFEO
# accessibility hijacks, unsigned DLLs in system paths, AMSI-bypass traces,
# ransomware-extension files and recently installed root certificates. Someone
# being targeted could have run the tool, been told the machine looked clean,
# and acted on that.
#
# It is not enough to fix the ~25 sites: nothing stopped the 26th. This lint is
# the stop. It is deliberately structural rather than a list of known checks, so
# a check added next year is covered the day it is written.
#
# WHAT IS CHECKED
#   1. Staged PowerShell blocks. Lines are echoed into %PSRUN% and then run. If
#      any line of the staged script emits a [CRITICAL]/[WARNING], the block must
#      either be executed through `call :dz_ps_scan` (which appends the output,
#      reads the severity back and raises) or write a dz_*.txt marker the caller
#      consumes. A block that just redirects into %REPORT% is a failure.
#   2. Direct report writes. An `echo [CRITICAL]/[WARNING] ... >> "%REPORT%"`
#      must have a `call :dz_finding` within a few lines, or be listed in
#      tests/unraised_allowlist.txt with a reason.
#
# The allowlist is for lines that genuinely are not findings -- operational
# notices ("Could not set boot timeout"), and the abort paths that set the exit
# code themselves. Every entry carries a reason and is printed in the summary,
# so the exemptions stay visible rather than becoming invisible debt.
#
# Windows PowerShell 5.1 / pwsh compatible. Read-only. Exit 0 clean, 1 on any
# unraised finding. Run by the lint CI job alongside lint_batch_comments.ps1.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [string]$Allowlist = ''
)

$ErrorActionPreference = 'Stop'

if (-not $Allowlist) { $Allowlist = Join-Path $Root 'tests\unraised_allowlist.txt' }

# ---- allowlist: FILE|SUBSTRING|reason -------------------------------------
$allow = @()
if (Test-Path -LiteralPath $Allowlist) {
    foreach ($ln in (Get-Content -LiteralPath $Allowlist)) {
        $t = $ln.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $f = $t.Split('|')
        if ($f.Count -lt 3) { continue }
        $allow += [pscustomobject]@{
            File   = $f[0].Trim()
            Match  = $f[1].Trim()
            Reason = ($f[2..($f.Count - 1)] -join '|').Trim()
            Used   = $false
        }
    }
}
function Test-Allowed {
    param([string]$FileName, [string]$Line)
    foreach ($a in $allow) {
        if ($a.File -ne $FileName -and $a.File -ne '*') { continue }
        if ($Line.Contains($a.Match)) { $a.Used = $true; return $true }
    }
    return $false
}

# Two emitter tests, because the two contexts differ.
#
# Staged PowerShell is a one-liner soup -- the tag can sit anywhere inside an
# if/else, a hashtable value or a string concat -- so any occurrence counts.
function Test-StagedEmitsSeverity {
    param([string]$Line)
    $t = $Line.Trim()
    if ($t.StartsWith('::')) { return $false }
    if ($t -match '^rem(\s|$)') { return $false }
    return ($t -match '\[CRITICAL\]|\[WARNING\]')
}
#
# A direct write is a whole line of report text, so the rule is the one
# block_sev.ps1 applies when reading a block's output: the payload must OPEN
# with the tag. That keeps reporting machinery out of the results -- the STATUS
# banner ("Review [WARNING] items in report") and the divergence alarm ("Report
# has N [CRITICAL] line(s)") mention the tags without being findings.
function Test-DirectEmitsSeverity {
    param([string]$Line)
    $t = $Line.Trim()
    if ($t.StartsWith('::')) { return $false }
    if ($t -match '^rem(\s|$)') { return $false }
    if ($t -notmatch '\[CRITICAL\]|\[WARNING\]') { return $false }
    if ($t -match 'dz_finding') { return $false }
    $p = $t
    $p = $p -replace '^\s*if\s+[^(]*\(\s*', ''          # if defined X (echo ...
    $p = $p -replace '^\s*if\s+\S+\s+\S+\s+\S+\s+', ''  # if "%X%"=="2" echo ...
    $p = $p -replace '^\s*echo\s*', ''
    return ($p -match '^\[(CRITICAL|WARNING)\]')
}

$failures = @()
$blockCount = 0
$scanCount = 0

foreach ($batName in @('doze_sec.bat', 'doze_sec_noAdmin.bat')) {
    $path = Join-Path $Root $batName
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $lines = @(Get-Content -LiteralPath $path)

    # ---- 1. staged %PSRUN% blocks -----------------------------------------
    $block = @()        # (index, text) of lines staged into %PSRUN%
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        $isStage = ($l -match '>>?\s*"%PSRUN%"\s*$')
        $isRun   = ($l -match '-File\s+"%PSRUN%"') -or ($l -match 'call\s+:dz_ps_scan')

        if ($isStage) {
            # A truncating write ('> "%PSRUN%"', not '>>') starts a fresh script.
            if ($l -match '[^>]>\s*"%PSRUN%"\s*$') { $block = @() }
            $block += , @($i, $l)
            continue
        }
        if (-not $isRun) { continue }

        $blockCount++
        $viaScan = ($l -match 'call\s+:dz_ps_scan')
        if ($viaScan) { $scanCount++ }
        $emitters = @($block | Where-Object { Test-StagedEmitsSeverity $_[1] })
        $hasMarker = @($block | Where-Object { $_[1] -match 'dz_[A-Za-z0-9_]+\.txt' }).Count -gt 0
        if ($emitters.Count -gt 0 -and -not $viaScan -and -not $hasMarker) {
            $first = $emitters[0]
            if (-not (Test-Allowed $batName $first[1])) {
                $failures += [pscustomobject]@{
                    File = $batName; Line = ($first[0] + 1); Kind = 'staged-block'
                    Text = $first[1].Trim()
                    Why  = "block runs at line $($i + 1) with plain redirection -- $($emitters.Count) severity line(s) never reach the ledger. Use: call :dz_ps_scan <section> <technique> `"<message>`""
                }
            }
        }
        $block = @()
    }

    # ---- 2. direct report writes ------------------------------------------
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l -match '"%PSRUN%"') { continue }          # handled above
        if ($l -notmatch '%REPORT%') { continue }
        if (-not (Test-DirectEmitsSeverity $l)) { continue }
        # A raise close by (either side) covers this echo.
        $lo = [Math]::Max(0, $i - 8)
        $hi = [Math]::Min($lines.Count - 1, $i + 8)
        $near = $false
        for ($j = $lo; $j -le $hi; $j++) {
            if ($lines[$j] -match 'call\s+:dz_finding') { $near = $true; break }
        }
        if ($near) { continue }
        if (Test-Allowed $batName $l) { continue }
        $failures += [pscustomobject]@{
            File = $batName; Line = ($i + 1); Kind = 'direct-write'
            Text = $l.Trim()
            Why  = 'prints a severity into the report with no :dz_finding nearby -- add the raise, or allowlist it with a reason if it is not a finding'
        }
    }
}

# ---- report ----------------------------------------------------------------
"Scanned $blockCount staged PowerShell block(s); $scanCount routed through :dz_ps_scan."
$usedAllow = @($allow | Where-Object { $_.Used })
if ($usedAllow.Count -gt 0) {
    "$($usedAllow.Count) allowlisted non-finding line(s) (each exempted for a stated reason):"
    foreach ($a in $usedAllow) { "  - [$($a.File)] $($a.Match)  --  $($a.Reason)" }
}
$staleAllow = @($allow | Where-Object { -not $_.Used })
if ($staleAllow.Count -gt 0) {
    # A stale exemption is how a real gap creeps back in unnoticed, so say so.
    "[WARNING] $($staleAllow.Count) allowlist entr(y/ies) matched nothing and should be removed:"
    foreach ($a in $staleAllow) { "  - [$($a.File)] $($a.Match)" }
}

# ---- Marker writes must not be able to fail silently ----------------------
# A field test on a real Windows machine found Write-Marker doing Set-Content
# -EA SilentlyContinue into a directory it never created: the write failed, the
# failure was swallowed, and a real [WARNING] printed into the report while the
# ledger -- and so the section verdict, the findings count and the exit code --
# never heard about it. Twelve tools carried the identical function.
#
# This lint is static and cannot prove a write LANDS; tests/marker_selftest.ps1
# does that at runtime. What it can do is refuse the two shapes that made the
# write losable in the first place.
$markerBad = @()
foreach ($tf in (Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -Filter '*.ps1' | Sort-Object Name)) {
    $txt = Get-Content -LiteralPath $tf.FullName -Raw
    if ($txt -notmatch 'function\s+Write-Marker') { continue }
    if ($txt -match 'Set-Content[^\r\n]*dz_[^\r\n]*-EA\s+SilentlyContinue') {
        $markerBad += ("{0}: marker Set-Content uses -EA SilentlyContinue -- a failed write silently drops the finding" -f $tf.Name)
    }
    if ($txt -notmatch 'Test-Path\s+-LiteralPath\s+\$MarkerDir') {
        $markerBad += ("{0}: Write-Marker does not ensure its marker directory exists before writing" -f $tf.Name)
    }
}
if ($markerBad.Count) {
    ''
    "[FAIL] $($markerBad.Count) marker write(s) can lose a finding between report and ledger:"
    foreach ($m in $markerBad) { "  - $m" }
    exit 1
}
"[OK] $(@(Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -Filter '*.ps1' | Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match 'function\s+Write-Marker' }).Count) marker-writing tool(s) ensure their directory and surface write failures."

if ($failures.Count -eq 0) {
    '[OK] Every check that prints a severity also raises it into the findings ledger.'
    exit 0
}

''
"[FAIL] $($failures.Count) check(s) print a severity that never reaches the findings ledger."
'       The report would show the problem while the section verdict, the'
'       findings count and the exit code all said the machine was clean.'
''
foreach ($f in $failures) {
    "  $($f.File):$($f.Line)  [$($f.Kind)]"
    "      $($f.Text)"
    "      $($f.Why)"
    ''
}
exit 1
