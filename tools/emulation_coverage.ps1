# emulation_coverage.ps1 -- measure how much of what the audit DETECTS is
# actually exercised end-to-end by a planted adversary technique, and keep that
# measurement honest over time. The test-side companion to attack_matrix.ps1:
# that tool answers "what do we detect?"; this answers "which of those
# detections does a test actually prove still fires?"
#
# WHY: the detection harness proves that detections which HAVE a plant still
# work. It never measured which detections have NO plant at all -- a detection
# could silently break and no test would notice, because nothing triggers it.
# That is a false-negative blind spot, and this session found seven false
# POSITIVES one CI round at a time precisely because there was no systematic
# coverage view. This turns "are our detections tested?" from a feeling into a
# number, and -- like the coverage matrix -- names the untested surface as data
# rather than hiding it.
#
# THREE INPUTS, all ground truth:
#   DETECTED   ATT&CK techniques the audit references, scanned live from the
#              .bat/.ps1 sources (same scan attack_matrix uses).
#   EMULATED   techniques a test actually plants. Read from the Attack = @(...)
#              tags on the harness cases (tests/detection_selftest.ps1) plus the
#              CI-emulated declarations in the corpus file (techniques a plant
#              exercises in an isolated helpers-ps51 step rather than the full
#              audit run -- e.g. process injection, which is fragile to plant in
#              a live audit).
#   CORPUS     tests/emulation_corpus.txt: declares CORE techniques (must stay
#              emulated by a harness plant), CI techniques (emulated in an
#              isolated step), and UNTESTABLE techniques with a reason (planting
#              them on a shared machine would be destructive or unsafe).
#
# GAP = DETECTED - EMULATED - UNTESTABLE. That is the actionable backlog: real
# detections that could be tested but are not yet. It is printed, never hidden.
#
# -Strict (used by CI) fails ONLY on a broken invariant, not on the backlog:
#   * a CORE technique with no harness plant (someone deleted a plant);
#   * an Attack tag or corpus line naming a technique the audit does not detect
#     (a stale tag -- a test claiming to cover something that no longer exists).
# The backlog is allowed to be non-empty; pretending every technique is testable
# would be dishonest. What is NOT allowed is silent drift.
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [string]$SourceDir = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [string]$Harness   = '',
    [string]$Corpus    = '',
    [switch]$Strict
)

$ErrorActionPreference = 'Continue'
if (-not $Harness) { $Harness = Join-Path $SourceDir 'tests\detection_selftest.ps1' }
if (-not $Corpus)  { $Corpus  = Join-Path $SourceDir 'tests\emulation_corpus.txt' }

function Read-Techniques {
    param([string]$Text)
    $s = New-Object System.Collections.Generic.HashSet[string]
    foreach ($m in ([regex]::Matches($Text, 'T1[0-9]{3}(\.[0-9]{3})?'))) { [void]$s.Add($m.Value) }
    return $s
}

'--- ADVERSARY-EMULATION COVERAGE (which detections a test actually exercises) ---'

# 1. DETECTED: scan the audit sources.
$detected = New-Object System.Collections.Generic.HashSet[string]
$srcFiles = @()
foreach ($n in @('doze_sec.bat', 'doze_sec_noAdmin.bat')) {
    $p = Join-Path $SourceDir $n
    if (Test-Path -LiteralPath $p) { $srcFiles += $p }
}
$toolDir = Join-Path $SourceDir 'tools'
if (Test-Path -LiteralPath $toolDir) {
    $srcFiles += (Get-ChildItem -LiteralPath $toolDir -Filter '*.ps1' -File -EA SilentlyContinue | ForEach-Object { $_.FullName })
}
foreach ($f in $srcFiles) {
    try { foreach ($t in (Read-Techniques (Get-Content -LiteralPath $f -Raw -EA Stop))) { [void]$detected.Add($t) } } catch {}
}
if ($detected.Count -eq 0) {
    # Under -Strict this is a FAILURE, not a skip. A gate that returns success
    # because it found nothing to check is indistinguishable from a gate that
    # checked everything and was satisfied -- and the caller cannot tell the
    # difference from the exit code alone.
    '[SKIPPED] No audit sources found to scan -- emulation coverage not computed.'
    if ($Strict) {
        '[WARNING] -Strict was requested but no audit source was scanned, so NOTHING was verified. Check -SourceDir.'
        exit 2
    }
    exit 0
}

# 2. EMULATED (harness): pull the technique ids out of every Attack = @(...) tag.
$harnessEmu = New-Object System.Collections.Generic.HashSet[string]
if (Test-Path -LiteralPath $Harness) {
    $ht = Get-Content -LiteralPath $Harness -Raw -EA SilentlyContinue
    # Credit a technique ONLY when the case that carries the tag actually plants
    # the attack. An Invert case plants a BENIGN state and asserts the detection
    # does NOT fire -- it is a false-positive guard, the opposite of emulation.
    # Counting its tag let a CORE technique's "must stay emulated" invariant be
    # satisfied by a test that proves the detection stays silent, which is the
    # inverse of what the invariant promises.
    # `\},?` so the LAST case in the array -- which ends `}` with no trailing
    # comma -- is not silently skipped. Dropping it would make its technique
    # look unemulated and fail -Strict on a corpus that is actually correct.
    foreach ($m in ([regex]::Matches($ht, "(?s)@\{(.*?)\n\s*\},?\r?\n"))) {
        $case = $m.Groups[1].Value
        if ($case -match 'Invert\s*=\s*\$true') { continue }
        foreach ($a in ([regex]::Matches($case, "Attack\s*=\s*@\(([^)]*)\)"))) {
            foreach ($t in (Read-Techniques $a.Groups[1].Value)) { [void]$harnessEmu.Add($t) }
        }
    }
} else {
    "[SKIPPED] Harness not found at $Harness -- emulation coverage not computed."
    if ($Strict) { '[WARNING] -Strict was requested but the harness was not found, so NOTHING was verified.'; exit 2 }
    exit 0
}

# 3. CORPUS: CORE / CI / UNTESTABLE declarations.
$core = New-Object System.Collections.Generic.HashSet[string]
$ciEmu = New-Object System.Collections.Generic.HashSet[string]
$untestable = @{}   # technique -> reason
if (Test-Path -LiteralPath $Corpus) {
    foreach ($ln in (Get-Content -LiteralPath $Corpus -EA SilentlyContinue)) {
        $t = $ln.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $f = $t.Split('|')
        if ($f.Count -lt 2) { continue }
        $cls = $f[0].Trim().ToUpper()
        $id  = $f[1].Trim()
        if ($id -notmatch '^T1[0-9]{3}(\.[0-9]{3})?$') { continue }
        switch ($cls) {
            'CORE'       { [void]$core.Add($id) }
            'CI'         { [void]$ciEmu.Add($id) }
            'UNTESTABLE' { $untestable[$id] = if ($f.Count -ge 3) { $f[2].Trim() } else { '(no reason given)' } }
        }
    }
} else {
    "[SKIPPED] Corpus not found at $Corpus -- emulation coverage not computed."
    if ($Strict) { '[WARNING] -Strict was requested but the corpus was not found, so NOTHING was verified.'; exit 2 }
    exit 0
}

# 4. Reconcile.
$emulated = New-Object System.Collections.Generic.HashSet[string]
foreach ($t in $harnessEmu) { [void]$emulated.Add($t) }
foreach ($t in $ciEmu)      { [void]$emulated.Add($t) }

$gap = @($detected | Where-Object { -not $emulated.Contains($_) -and -not $untestable.ContainsKey($_) } | Sort-Object)
$testable = @($detected | Where-Object { -not $untestable.ContainsKey($_) })
$emuCount = @($detected | Where-Object { $emulated.Contains($_) }).Count
$pct = 0
if ($testable.Count -gt 0) { $pct = [math]::Round(100.0 * $emuCount / $testable.Count) }

"Detected techniques        : $($detected.Count)"
"Emulated by a plant        : $emuCount  (harness $($harnessEmu.Count) + isolated CI $($ciEmu.Count))"
"Declared untestable        : $($untestable.Count)  (destructive or unsafe to plant on a shared machine)"
"Not yet emulated (backlog) : $($gap.Count)"
"Emulation coverage of the testable surface: $pct%"
''

if ($gap.Count -gt 0) {
    'BACKLOG -- detections with no emulation test yet (safe to add a plant for):'
    foreach ($g in $gap) { "  $g" }
    ''
}
if ($untestable.Count -gt 0) {
    'UNTESTABLE by design (verified read-only or in isolation instead):'
    foreach ($k in ($untestable.Keys | Sort-Object)) { "  $k -- $($untestable[$k])" }
    ''
}

# 5. Invariants. Only these fail -Strict; the backlog is allowed to exist.
$violations = @()
# Guard the guard. Every CORE invariant below is a `foreach ($c in $core)`, so a
# corpus that parses to zero CORE entries -- a reformat, a renamed class word, a
# parser regression -- makes the loop iterate nothing and the tool report
# "consistent". The strongest promise this file makes (a core detection cannot
# lose its emulation test) would stop being checked, and -Strict would still
# exit 0. An empty CORE set is therefore a violation in its own right.
if ($core.Count -eq 0) {
    $violations += 'the corpus declared NO CORE techniques, so the core-detection invariant was not checked at all (corpus parse regression or every CORE line removed)'
}
foreach ($c in $core) {
    if (-not $harnessEmu.Contains($c)) { $violations += "CORE technique $c has no harness plant (a core detection lost its emulation test)" }
    if (-not $detected.Contains($c))   { $violations += "CORE technique $c is not detected by the audit (stale corpus entry)" }
}
foreach ($t in $harnessEmu) {
    if (-not $detected.Contains($t)) { $violations += "harness plants $t but the audit does not detect it (stale Attack tag)" }
}
foreach ($t in $ciEmu) {
    if (-not $detected.Contains($t)) { $violations += "corpus marks $t CI-emulated but the audit does not detect it (stale corpus entry)" }
}
foreach ($t in $untestable.Keys) {
    if (-not $detected.Contains($t)) { $violations += "corpus marks $t untestable but the audit does not detect it (stale corpus entry)" }
}

if ($violations.Count -gt 0) {
    foreach ($v in $violations) { "[WARNING] $v." }
    if ($Strict) { exit 2 }
} else {
    '[OK] Emulation corpus is consistent: every core detection has a plant and no test references a technique the audit no longer detects.'
}
exit 0
