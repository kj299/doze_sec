# lint_docs_drift.ps1 -- fail the build when the documentation claims something
# the code does not do, or omits something it does.
#
# WHY THIS EXISTS
# ---------------
# A retrospective found the README's headline claiming "48 MITRE ATT&CK
# techniques" when the audit referenced 81 and the manifest mapped 104, and an
# indicator count that was one high because a malformed hash had been
# quarantined. Neither was caught by anything: no test reads the prose.
#
# Worse than a wrong number, three implemented switches -- -baseline,
# -noBaseline and -resetTTP -- were documented only in the script's own -help
# output and absent from the README's Switches table. Baseline/diff is the
# strongest signal this tool has against a targeted implant that matches no
# signature, and someone reading the project page could not discover it existed.
# An undiscoverable defence protects nobody.
#
# For a tool whose whole value is telling people the truth about their machine,
# documentation that drifts from the code is the same category of failure as a
# detection that prints a finding and never raises it: the reader is misled by
# something that looks authoritative. So the counts and the switch list are
# derived from ground truth and checked, not maintained by hand and hoped for.
#
# WHAT IS CHECKED
#   1. Switch parity -- every '-flag' the batch scripts handle appears in the
#      README Switches table, and every documented flag is really handled.
#   2. ThreatLists entry counts -- each row of the README's ThreatLists table
#      matches `grep -cv '^#'` on the file it names.
#   3. Technique counts -- the "N MITRE ATT&CK techniques" claims in README and
#      THREAT_MODEL match the number the audit actually references, and the
#      manifest row count matches the file.
#
# Windows PowerShell 5.1 / pwsh compatible. Read-only. Exit 0 clean, 1 on drift.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
)

$ErrorActionPreference = 'Stop'

$problems = @()
$checks = 0

function Get-EntryCount {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return -1 }
    return @(Get-Content -LiteralPath $Path | Where-Object { $_ -notmatch '^\s*(#|$)' }).Count
}

$readmePath = Join-Path $Root 'README.md'
$tmPath     = Join-Path $Root 'THREAT_MODEL.md'
if (-not (Test-Path -LiteralPath $readmePath)) {
    '[SKIPPED] README.md not found -- nothing to check.'
    exit 0
}
$readme = Get-Content -LiteralPath $readmePath -Raw

# ---- 1. switch parity ------------------------------------------------------
# Implemented: the argument-parsing lines in either bat, e.g. if /i "%~1"=="-vt".
$implemented = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
foreach ($n in @('doze_sec.bat', 'doze_sec_noAdmin.bat')) {
    $p = Join-Path $Root $n
    if (-not (Test-Path -LiteralPath $p)) { continue }
    foreach ($m in ([regex]::Matches((Get-Content -LiteralPath $p -Raw), '"%~1"\s*==\s*"(-[A-Za-z][A-Za-z]*)"'))) {
        [void]$implemented.Add($m.Groups[1].Value)
    }
}
# Documented: the first backticked token of each Switches-table row.
$documented = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
$inSwitches = $false
foreach ($ln in ($readme -split "`r?`n")) {
    if ($ln -match '^##\s') { $inSwitches = ($ln -match '^##\s+Switches\s*$') ; continue }
    if (-not $inSwitches) { continue }
    $m = [regex]::Match($ln, '^\|\s*`(-[A-Za-z][A-Za-z]*)')
    if ($m.Success) { [void]$documented.Add($m.Groups[1].Value) }
}

if ($implemented.Count -eq 0 -or $documented.Count -eq 0) {
    # Guard the guard: an empty side makes every comparison below trivially
    # true, so a parser regression would turn into a silent pass.
    $problems += "switch parity could not be checked -- parsed $($implemented.Count) implemented and $($documented.Count) documented switch(es); one side is empty, so the check would pass vacuously"
} else {
    $checks++
    # -h is an alias for -help and is deliberately not a separate table row.
    $aliases = @('-h')
    foreach ($f in $implemented) {
        if ($aliases -contains $f) { continue }
        if (-not $documented.Contains($f)) {
            $problems += "switch '$f' is implemented but missing from the README Switches table -- users cannot discover it"
        }
    }
    foreach ($f in $documented) {
        if (-not $implemented.Contains($f)) {
            $problems += "switch '$f' is documented in the README but no batch script handles it"
        }
    }
}

# ---- 2. ThreatLists entry counts ------------------------------------------
$rows = [regex]::Matches($readme, '(?m)^\|\s*`(ioc_[a-z_]+\.txt|ttp_manifest\.txt)`\s*\|\s*(\d+)\s*\|')
if ($rows.Count -eq 0) {
    $problems += 'no ThreatLists table rows parsed from the README -- the count check would pass vacuously'
} else {
    foreach ($r in $rows) {
        $checks++
        $file = $r.Groups[1].Value
        $claimed = [int]$r.Groups[2].Value
        $actual = Get-EntryCount (Join-Path $Root (Join-Path 'ThreatLists' $file))
        if ($actual -lt 0) {
            $problems += "README documents ThreatLists\$file but the file does not exist"
        } elseif ($actual -ne $claimed) {
            $problems += "README says ThreatLists\$file has $claimed entries; it has $actual"
        }
    }
}

# ---- 3. technique counts ---------------------------------------------------
# Ground truth: techniques the audit actually references, and manifest rows.
$referenced = New-Object System.Collections.Generic.HashSet[string]
$srcFiles = @()
foreach ($n in @('doze_sec.bat', 'doze_sec_noAdmin.bat')) {
    $p = Join-Path $Root $n
    if (Test-Path -LiteralPath $p) { $srcFiles += $p }
}
$toolDir = Join-Path $Root 'tools'
if (Test-Path -LiteralPath $toolDir) {
    $srcFiles += (Get-ChildItem -LiteralPath $toolDir -Filter '*.ps1' -File -EA SilentlyContinue | ForEach-Object { $_.FullName })
}
foreach ($f in $srcFiles) {
    try {
        foreach ($m in ([regex]::Matches((Get-Content -LiteralPath $f -Raw -EA Stop), 'T1[0-9]{3}(\.[0-9]{3})?'))) {
            [void]$referenced.Add($m.Value)
        }
    } catch {}
}
if ($referenced.Count -eq 0) {
    $problems += 'no technique ids found in the audit sources -- the technique-count check would pass vacuously'
} else {
    foreach ($doc in @(@{Path = $readmePath; Name = 'README.md'}, @{Path = $tmPath; Name = 'THREAT_MODEL.md'})) {
        if (-not (Test-Path -LiteralPath $doc.Path)) { continue }
        $txt = Get-Content -LiteralPath $doc.Path -Raw
        foreach ($m in ([regex]::Matches($txt, '(\d+)\s+MITRE ATT&CK\s+techniques'))) {
            $checks++
            $claimed = [int]$m.Groups[1].Value
            if ($claimed -ne $referenced.Count) {
                $problems += "$($doc.Name) claims $claimed MITRE ATT&CK techniques; the audit references $($referenced.Count)"
            }
        }
    }
}

# ---- report ----------------------------------------------------------------
"Checked $checks documented claim(s) against the code: $($implemented.Count) implemented switch(es), $($referenced.Count) referenced technique(s)."

if ($problems.Count -eq 0) {
    '[OK] Documentation matches the code -- switches, list counts and technique counts all agree.'
    exit 0
}
''
"[FAIL] $($problems.Count) documented claim(s) do not match the code:"
foreach ($p in $problems) { "  - $p" }
''
'       Documentation that overstates or omits what the tool does misleads the'
'       reader exactly like a finding that is printed but never raised.'
exit 1
