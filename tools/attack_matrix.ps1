# attack_matrix.ps1 -- generate the ATT&CK coverage matrix from the audit's own
# technique references, and prove it is complete. Invoked near the end of a run
# (report-embedded), and runnable standalone for docs / CI.
#
# WHY: the tool's coverage used to be a hand-maintained paragraph in
# THREAT_MODEL that could drift from what the code actually does -- and this
# session added ~48 technique detections the mapping never mentioned. Coverage
# you assert by hand is coverage you cannot trust. This derives the matrix from
# two ground-truth sources so it cannot lie:
#   1. Which ATT&CK techniques the audit REFERENCES -- scanned live from the
#      .bat/.ps1 sources (every 'T####[.###]' that appears in the code).
#   2. What each technique IS -- tactic and name, read from
#      ThreatLists/ttp_manifest.txt (TECHNIQUE|TACTIC|NAME|ACTORS|DETECTION).
#
# The matrix groups covered techniques by ATT&CK tactic, in canonical order, and
# -- the honest part -- names the tactics with the LEAST coverage as the current
# gaps, rather than only advertising strengths.
#
# COMPLETENESS IS ENFORCED, NOT HOPED FOR: any technique the code references but
# the manifest does not map is reported as UNMAPPED, and in -Strict mode
# (used by CI) that makes the tool exit non-zero. So the day someone adds a
# detection with a new technique id and forgets to describe it, CI says so and
# the coverage claim stays truthful. The reverse -- techniques mapped in the
# manifest but not referenced by any detection -- is listed too, as documented-
# but-not-yet-detected (aspirational entries), so neither list silently rots.
#
# OPTIONAL per-run annotation: given -Report <path>, techniques whose id appears
# in this run's report are marked as having FIRED, turning the capability matrix
# into a picture of what was actually seen on this machine.
#
# This is an inventory/reporting tool. It evaluates no security condition and
# raises no finding.
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [string]$SourceDir = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [string]$Manifest  = '',
    [string]$Report    = '',
    # Authoritative source for "did this technique actually FIRE this run": the
    # findings ledger, whose CODE field is written only by an actual
    # :dz_finding raise. See the FIRED note below for why the report text is not.
    [string]$Ledger    = '',
    [switch]$Strict
)

$ErrorActionPreference = 'Continue'

if (-not $Manifest) { $Manifest = Join-Path $SourceDir 'ThreatLists\ttp_manifest.txt' }

# Canonical enterprise ATT&CK tactic order. The manifest uses short spellings
# (Priv Esc, C2); map those to the canonical labels so ordering and gap
# reporting are stable regardless of how a mapping line was written.
$tacticOrder = @(
    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Command and Control', 'Exfiltration', 'Impact'
)
$tacticAlias = @{
    'priv esc' = 'Privilege Escalation'; 'privesc' = 'Privilege Escalation'
    'c2' = 'Command and Control'; 'command & control' = 'Command and Control'
    'command and control' = 'Command and Control'
}
function Resolve-Tactic {
    param([string]$Raw)
    $t = ($Raw -replace '\s+', ' ').Trim()
    $key = $t.ToLower()
    if ($tacticAlias.ContainsKey($key)) { return $tacticAlias[$key] }
    foreach ($canon in $tacticOrder) { if ($canon.ToLower() -eq $key) { return $canon } }
    return $t   # unknown tactic spelling -- surfaced as its own group
}

'--- ATT&CK COVERAGE MATRIX (auto-derived from the audit''s own detections) ---'

# 1. Techniques the manifest maps: id -> @{Tactic; Name}
$map = @{}
if (Test-Path -LiteralPath $Manifest) {
    foreach ($ln in (Get-Content -LiteralPath $Manifest -EA SilentlyContinue)) {
        $t = $ln.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $f = $t.Split('|')
        if ($f.Count -lt 3) { continue }
        $id = $f[0].Trim()
        if ($id -notmatch '^T1[0-9]{3}(\.[0-9]{3})?$') { continue }
        if (-not $map.ContainsKey($id)) {
            $map[$id] = @{ Tactic = (Resolve-Tactic $f[1]); Name = $f[2].Trim() }
        }
    }
} else {
    "[SKIPPED] ttp_manifest.txt not found at $Manifest -- coverage matrix not generated."
    if ($Strict) { '[WARNING] -Strict was requested but the manifest was not found, so NOTHING was verified.'; exit 2 }
    exit 0
}

# 2. Techniques the audit code REFERENCES (live scan of the sources).
$referenced = @{}
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
    try {
        foreach ($m in ([regex]::Matches((Get-Content -LiteralPath $f -Raw -EA Stop), 'T1[0-9]{3}(\.[0-9]{3})?'))) {
            $referenced[$m.Value] = $true
        }
    } catch {}
}

# 3. Which techniques actually FIRED this run (optional).
#
# This MUST come from the ledger, not from the report text. The report prints
# technique ids in ~14 unconditional section headers (e.g. "--- [T1546.008] IFEO
# Debugger Hijack ---"), so substring-searching the report marks EVERY referenced
# technique as fired on every run -- including on a completely clean machine,
# which is exactly the false-assurance this tool exists to avoid. The ledger's
# CODE field is written only by a real :dz_finding raise, so it answers the
# question honestly.
$fired = @{}
$firedSource = ''
if ($Ledger -and (Test-Path -LiteralPath $Ledger)) {
    try {
        foreach ($ln in (Get-Content -LiteralPath $Ledger -EA Stop)) {
            $t = $ln.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            $f = $t.Split('|')
            if ($f.Count -lt 3) { continue }
            $code = $f[2].Trim()
            if ($code -match '^T1[0-9]{3}(\.[0-9]{3})?$') { $fired[$code] = $true }
        }
        $firedSource = 'ledger'
    } catch { $firedSource = '' }
}

# 4. Reconcile.
#
# Guard the guard first. The completeness check below is "every REFERENCED
# technique is mapped" -- which an empty $referenced satisfies trivially. A bad
# -SourceDir, a moved file or a regex regression would therefore make this tool
# print "coverage matrix is complete" and exit 0 while having verified nothing.
# The claim it exists to defend (the matrix cannot drift from the code) would be
# silently unenforced, so an empty scan is a hard failure under -Strict.
if ($referenced.Count -eq 0) {
    "[WARNING] No technique references found in the audit sources under $SourceDir -- the source scan returned nothing, so completeness was NOT verified."
    if ($Strict) { exit 2 }
}
$covered = @($referenced.Keys | Where-Object { $map.ContainsKey($_) })
$unmapped = @($referenced.Keys | Where-Object { -not $map.ContainsKey($_) } | Sort-Object)
$documentedOnly = @($map.Keys | Where-Object { -not $referenced.ContainsKey($_) } | Sort-Object)

# Group covered techniques by tactic.
$byTactic = @{}
foreach ($id in $covered) {
    $tac = $map[$id].Tactic
    if (-not $byTactic.ContainsKey($tac)) { $byTactic[$tac] = @() }
    $byTactic[$tac] += $id
}

"Techniques detected by the audit: $($covered.Count) across $((@($byTactic.Keys)).Count) ATT&CK tactic(s)."
if ($firedSource) { "Of those, $((@($fired.Keys)).Count) raised at least one finding in THIS run." }
''

$displayTactics = @($tacticOrder + (@($byTactic.Keys) | Where-Object { $tacticOrder -notcontains $_ } | Sort-Object))
foreach ($tac in $displayTactics) {
    if (-not $byTactic.ContainsKey($tac)) { continue }
    $ids = @($byTactic[$tac] | Sort-Object)
    "$tac  ($($ids.Count))"
    foreach ($id in $ids) {
        $mark = ' '
        if ($fired.ContainsKey($id)) { $mark = '*' }   # fired this run
        "  [$mark] $id  $($map[$id].Name)"
    }
    ''
}
if ($firedSource) { '  (* = this technique raised at least one finding in this run)' }
elseif ($Report) { '  (per-technique fired/not-fired needs the findings ledger; not annotated in this run)' }

# 5. Honest gaps: enterprise tactics with no coverage at all.
$gapTactics = @($tacticOrder | Where-Object { -not $byTactic.ContainsKey($_) })
if ($gapTactics.Count -gt 0) {
    "COVERAGE GAPS -- ATT&CK tactics with NO technique coverage: $($gapTactics -join ', ')."
} else {
    'Every enterprise ATT&CK tactic has at least one technique covered.'
}
if ($documentedOnly.Count -gt 0) {
    "Documented in the manifest but not yet detected by any check: $($documentedOnly.Count) technique(s) -- $($documentedOnly -join ', ')."
}

# 6. Completeness self-check. This is what keeps the matrix honest over time.
if ($unmapped.Count -gt 0) {
    "[WARNING] $($unmapped.Count) technique(s) are referenced by the audit but NOT mapped in ttp_manifest.txt: $($unmapped -join ', ')."
    '[WARNING] Add a TECHNIQUE|TACTIC|NAME line for each so the coverage matrix stays complete.'
    if ($Strict) { exit 2 }
} else {
    '[OK] Every technique the audit references is mapped in the manifest -- coverage matrix is complete.'
}

# Deterministic exit so a caller can trust $LASTEXITCODE (see note above). Only
# an unmapped technique under -Strict is a failure; everything else is success.
exit 0
