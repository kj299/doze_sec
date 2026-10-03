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
# SHORT SPELLINGS COUNT. A staged block printed '[WARN] Sticky Keys shortcut
# ENABLED' into Section 13 of a real report, redirected straight into
# %REPORT% with no :dz_ps_scan and no marker -- exactly what this lint exists
# to catch -- and this lint could not see it, because it matched only the long
# spelling. The finding drove the dashboard tile and the remediation script the
# owner runs elevated, and reached the ledger, FINDINGS COUNTED and the exit
# code in none of them. tools/lint_report_echo.ps1 now bans the short forms on
# the report path outright; matching them here too means a reintroduced one is
# caught by the raise check as well, not just by the spelling check.
function Test-StagedEmitsSeverity {
    param([string]$Line)
    $t = $Line.Trim()
    if ($t.StartsWith('::')) { return $false }
    if ($t -match '^rem(\s|$)') { return $false }
    return ($t -match '\[(CRITICAL|CRIT)\]|\[(WARNING|WARN)\]')
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
    if ($t -notmatch '\[(CRITICAL|CRIT)\]|\[(WARNING|WARN)\]') { return $false }
    if ($t -match 'dz_finding') { return $false }
    $p = $t
    $p = $p -replace '^\s*if\s+[^(]*\(\s*', ''          # if defined X (echo ...
    $p = $p -replace '^\s*if\s+\S+\s+\S+\s+\S+\s+', ''  # if "%X%"=="2" echo ...
    $p = $p -replace '^\s*echo\s*', ''
    return ($p -match '^\[(CRITICAL|CRIT|WARNING|WARN)\]')
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
    # Two shapes, both legitimate: Write-Marker takes a -MarkerDir and tests it
    # directly; Write-MarkerFile takes a -MarkerFile and tests the directory it
    # derives from that path. Requiring only the first reported every
    # -MarkerFile tool as broken once they were fixed.
    if ($txt -notmatch 'Test-Path\s+-LiteralPath\s+\$MarkerDir' -and
        $txt -notmatch 'Test-Path\s+-LiteralPath\s+\$dir') {
        $markerBad += ("{0}: the marker helper does not ensure its directory exists before writing" -f $tf.Name)
    }
}
if ($markerBad.Count) {
    ''
    "[FAIL] $($markerBad.Count) marker write(s) can lose a finding between report and ledger:"
    foreach ($m in $markerBad) { "  - $m" }
    exit 1
}
"[OK] $(@(Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -Filter '*.ps1' | Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match 'function\s+Write-Marker' }).Count) marker-writing tool(s) ensure their directory and surface write failures."

# ---------------------------------------------------------------------------
# A severity tag marks a FINDING, never the sentence that explains one.
#
# A tool that prints its finding and then a gloss -- the consequence, the
# not-necessarily-malicious framing, the remedy -- and tags BOTH inflates
# every printed count while the ledger stays right, because the block
# aggregates into one row. No existing gate could see it: the block DOES
# raise, so lint_unraised_findings passed it, and the section DOES declare
# ISSUES FOUND, so verdict_audit passed it too. A real report showed 11
# [WARNING] lines against 9 counted findings.
#
# The first sweep for this was keyed on advice-shaped WORDING ("if you do
# not...", "this is normal") and found one instance. It missed five, because
# a gloss can equally be consequence-shaped ("Anyone who can reach this PC
# could...") or a remedy ("Add a TECHNIQUE|TACTIC|NAME line..."). So the rule
# is STRUCTURAL: two severity-tagged output literals emitted back to back.
# That shape is a finding plus a gloss; a block that really has two findings
# separates them with the code that discovers the second.
$glossBad = @()
foreach ($tf in (Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -Filter '*.ps1' | Sort-Object Name)) {
    $lines = @(Get-Content -LiteralPath $tf.FullName)
    # A bare emitted string literal carrying a severity tag.
    $sevRx  = '^([''"])\[(WARNING|CRITICAL)\]'
    # Lines that do not end an emission region: comments, blanks, other
    # emitted literals ([INFO]/[OK] or plain), and the one-line item echoes a
    # findings block uses to list what it found.
    $contRx = '^(#|$)|^([''"])|^foreach\s*\(.*\)\s*\{\s*["''].*\}\s*$|^if\s*\(.*\)\s*\{\s*["''].*\}\s*$'
    # Pre-formatted messages for the tagged lines seen in the current region.
    # Strings, not nested arrays: PowerShell unrolls a one-element slice of an
    # array-of-arrays into its inner elements, which turned $r[0] into a
    # character index and threw.
    $region = New-Object System.Collections.ArrayList
    for ($i = 0; $i -le $lines.Count; $i++) {
        $t = if ($i -lt $lines.Count) { $lines[$i].Trim() } else { 'END OF FILE' }
        if ($i -lt $lines.Count -and $t -match $contRx) {
            if ($t -match $sevRx -and -not (Test-Allowed -FileName $tf.Name -Line $t)) {
                [void]$region.Add(("{0}:{1}: a second severity-tagged line in the same emitted block -- if it explains the first, tag it [INFO]: {2}" -f $tf.Name, ($i + 1), $t.Substring(0, [Math]::Min(96, $t.Length))))
            }
            continue
        }
        # Region closed by real code (or end of file). Two or more severity
        # tags inside one region is a finding plus a gloss.
        if ($region.Count -ge 2) {
            for ($k = 1; $k -lt $region.Count; $k++) { $glossBad += $region[$k] }
        }
        $region = New-Object System.Collections.ArrayList
    }
}
if ($glossBad.Count) {
    ''
    "[FAIL] $($glossBad.Count) severity tag(s) sit on a gloss rather than a finding:"
    foreach ($g in $glossBad) { "  - $g" }
    '  A finding printing as two inflates every count a reader can make, while'
    '  the ledger stays right -- so the tool disagrees with itself. Tag the'
    '  explanation [INFO]; the finding above it still drives the severity.'
    exit 1
}
"[OK] No tool tags a gloss as a finding (checked $(@(Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -Filter '*.ps1').Count) tools for adjacent severity-tagged lines)."

# ---- Rule: [SKIPPED] is never raised ---------------------------------------
# Vocabulary decision 2026-10-03. A check that could not run and raises that
# as a finding (a view an administrator should have been able to open, an
# input that is simply absent) prints [WARNING] ... NOT performed, so the
# section verdict's "review [WARNING] entries above" points at a visible line
# and the summary's warning-line count agrees with the findings counted.
# [SKIPPED] is reserved for gaps that raise nothing (block_sev, verdict_audit
# and the coverage block all treat it as not-a-finding). A [SKIPPED] literal
# followed within three lines by a raise is the old shape -- 27 sites on
# 2026-10-03, three of which a hand survey had missed -- and the lint fails on it so it cannot come back one site at a
# time. Deferrals ([DEFERRED - ADMIN REQUIRED]) raise nothing and are not
# touched by this rule.
$raisedSkip = @()
$raiseRx = "Get-MaxSev[^\r\n]*'(WARNING|CRITICAL)'|\\$\w*[sS]ev\s*=\s*'(WARNING|CRITICAL)'|Write-Marker[^\r\n]*-Sev\s+'(WARNING|CRITICAL)'|Sev\s*=\s*'(WARNING|CRITICAL)'"
foreach ($tf in (Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -Filter '*.ps1')) {
    $tl = [IO.File]::ReadAllLines($tf.FullName)
    for ($i = 0; $i -lt $tl.Count; $i++) {
        $ln = $tl[$i].TrimStart()
        if ($ln.StartsWith('#')) { continue }
        if ($ln -notmatch "^(['`"]|return @\{|\[void\]\$\w+\.Add\(['`"])\[SKIPPED\]" -and $ln -notmatch "Line\s*=\s*['`"]\[SKIPPED\]") { continue }
        $win = ($tl[$i..([Math]::Min($tl.Count - 1, $i + 3))] -join "`n")
        if ($win -match $raiseRx) {
            $raisedSkip += ("{0}:{1}: a [SKIPPED] line that is raised -- a raised gap prints [WARNING] ... NOT performed; [SKIPPED] is reserved for gaps that raise nothing: {2}" -f $tf.Name, ($i + 1), $ln.Substring(0, [Math]::Min(90, $ln.Length)))
        }
    }
}
if ($raisedSkip.Count) {
    ''
    "[FAIL] $($raisedSkip.Count) [SKIPPED] line(s) are raised into the ledger:"
    foreach ($g in $raisedSkip) { "  - $g" }
    '  The section verdict says "review [WARNING] entries above" and the summary'
    '  counts warning lines; a raised [SKIPPED] is invisible to both. Tag it'
    '  [WARNING] and keep the NOT-performed wording (the coverage block counts'
    '  raised gaps by that phrase).'
    exit 1
}
"[OK] No tool raises a [SKIPPED] line (a raised gap prints [WARNING] ... NOT performed)."

# ---------------------------------------------------------------------------
# A RAISED GAP IS ITS OWN ROW (vocabulary decision 2026-10-03, second half).
# A gap used to travel through the tool's one severity marker, so the ledger
# row named the finding the check WOULD have made ("records missing with no
# clear event" for a log that could not be read). A tool that prints a gap
# line -- a [WARNING] whose text says NOT performed / NOT checked / ... --
# must write a second marker, dz_<name>_gap.txt, and every bat that reads the
# tool's finding marker must read the gap marker too and raise it under gap
# wording. Scoped to tools that define Write-Marker (the -MarkerFile tools
# take their marker path from the bat and have no raised gaps); self-test
# assertion lines (T '...') and regexes are not gap lines.
$gapRx = 'NOT (performed|checked|verified|evaluated|audited|run|graded|calibrated|inspected|determined)\b|verified nothing|could NOT run|not audited\b'
$gapDefects = @()
$gapMarkers = @{}
foreach ($tf in (Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -Filter '*.ps1' | Sort-Object Name)) {
    $txt = Get-Content -LiteralPath $tf.FullName -Raw
    if ($txt -notmatch 'function\s+Write-Marker\b') { continue }
    $lines = $txt -split "\r?\n"
    $gapLines = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        if ($ln -match '^\s*#') { continue }
        if ($ln -match "^\s*T\s+'" -or $ln -match '-match\s+[''"]' -or $ln -match '-notmatch\s+[''"]') { continue }
        if ($ln -match '[''"]\[WARNING\][^''"]*' -and $ln -match $gapRx) { $gapLines++ }
    }
    foreach ($m in [regex]::Matches($txt, "Write-Marker[^\r\n]*-Name\s+'([A-Za-z0-9_]+_gap)'")) { $gapMarkers[$m.Groups[1].Value] = $tf.Name }
    if ($gapLines -gt 0 -and $txt -notmatch "Write-Marker[^\r\n]*-Name\s+'[A-Za-z0-9_]+_gap'") {
        $gapDefects += ("{0}: prints {1} raised-gap line(s) but writes no dz_<name>_gap.txt marker -- its gap would file as the finding it could not make" -f $tf.Name, $gapLines)
    }
}
foreach ($bf in (Get-ChildItem -LiteralPath $Root -Filter '*.bat' -File | Sort-Object Name)) {
    $bt = Get-Content -LiteralPath $bf.FullName -Raw
    foreach ($gm in ($gapMarkers.Keys | Sort-Object)) {
        $base = $gm -replace '_gap$', ''
        if ($bt -match ('set /p \w+=<"%TEMP%\\dz_' + [regex]::Escape($base) + '\.txt"') -and $bt -notmatch ('if exist "%TEMP%\\dz_' + [regex]::Escape($gm) + '\.txt"')) {
            $gapDefects += ("{0}: reads dz_{1}.txt but never dz_{2}.txt -- the gap {3} writes would vanish, or file under the finding row" -f $bf.Name, $base, $gm, $gapMarkers[$gm])
        }
    }
}
if ($gapDefects.Count) {
    ''
    "[FAIL] $($gapDefects.Count) raised gap(s) have no row of their own:"
    foreach ($g in $gapDefects) { "  - $g" }
    '  A gap line ([WARNING] ... NOT performed) feeds a separate severity and a'
    '  separate marker (dz_<name>_gap.txt); both bats read it beside the finding'
    '  marker and raise it with gap wording under the same section and technique.'
    exit 1
}
"[OK] Every raised gap has its own marker and its own ledger row in both bats ($($gapMarkers.Count) gap marker(s))."

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
