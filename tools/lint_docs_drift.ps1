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
#   4. Artifact parity -- every file written into the output folder is in the
#      README Output Files table, and every documented path is really written.
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

# ---------------------------------------------------------------------------
# 4. ARTIFACT PARITY -- every file the audit writes into the output folder is
#    in the README Output Files table, and every documented path is really
#    written.
#
# The table listed nine paths and the bats wrote fifteen. Undocumented were:
# the two extra remediation stages (_enforce, _undo -- the file collecting
# every reversal), the .sha256 tamper-evidence digest the report tells you to
# record off-device, baseline.snapshot, the selftest quarantine, and
# SecurityReport_<TS>.ledger -- the record EVERY verdict derives from, and the
# arbiter when the report and the summary disagree. A reader could not
# discover any of them.
#
# Same failure this lint was built for: three implemented switches existed only
# in -help and an undiscoverable defence protects nobody. Switch parity was
# gated and the artifact table was not, so it drifted instead.
$artProblems = @()
$readmeArt = @()
foreach ($ln in (Get-Content -LiteralPath $readmePath)) {
    $m = [regex]::Match($ln, '^\|\s*`C:\\SecurityAudit\\([^`]+)`')
    if ($m.Success) { $readmeArt += $m.Groups[1].Value.TrimEnd('\') }
}
if ($readmeArt.Count -lt 5) {
    $artProblems += 'the README Output Files table parsed to fewer than 5 rows -- this check is broken, not the docs'
}
$batArt = @()
$AdminBatPath = Join-Path $Root 'doze_sec.bat'
foreach ($bat in @($AdminBatPath, (Join-Path $Root 'doze_sec_noAdmin.bat'))) {
    if (-not (Test-Path -LiteralPath $bat)) { continue }
    foreach ($m in [regex]::Matches((Get-Content -LiteralPath $bat -Raw), '%OUTDIR%\\([A-Za-z0-9_!.]+)')) {
        $batArt += $m.Groups[1].Value
    }
}
if ($batArt.Count -lt 5) {
    $artProblems += 'found fewer than 5 %OUTDIR% artifacts in the bats -- this check is broken, not the docs'
}
# Normalise the run stamp so the two sides are comparable.
function Norm-Art { param([string]$n) ($n -replace '!TIMESTAMP!', '<TS>') -replace '<TS>', '<TS>' }
$batNorm    = @($batArt    | ForEach-Object { Norm-Art $_ } | Sort-Object -Unique)
$readmeNorm = @($readmeArt | ForEach-Object { Norm-Art $_ } | Sort-Object -Unique)
foreach ($a in $batNorm) {
    if ($readmeNorm -notcontains $a) {
        $artProblems += ("the audit writes C:\SecurityAudit\{0} but the README Output Files table does not list it" -f $a)
    }
}
# Two documented artifacts are real but are NOT written through %OUTDIR%\, so
# the scan above cannot see them. They are exempted BY NAME WITH A REASON, and
# each exemption is only honoured while the code that produces it still exists
# -- a blanket allowlist would let the file quietly stop being written while
# the README kept promising it.
$derived = @(
    @{ Name = 'AuditConsole_<TS>.log'
       Why  = 'written by the console-capture wrapper before the output directory is chosen'
       File = $AdminBatPath; Pattern = 'AuditConsole_' },
    @{ Name = 'SecurityReport_<TS>.txt.sha256'
       Why  = 'written by tools\report_seal.ps1 as "$Report.sha256", derived from the report path'
       File = (Join-Path $toolDir 'report_seal.ps1'); Pattern = '\$Report\.sha256' }
)
$derivedNames = @()
foreach ($d in $derived) {
    if ((Test-Path -LiteralPath $d.File) -and ((Get-Content -LiteralPath $d.File -Raw) -match $d.Pattern)) {
        $derivedNames += $d.Name
    } else {
        $artProblems += ("the README lists C:\SecurityAudit\{0} and this lint exempts it because it is {1} -- but that code is gone, so either the file is no longer written or the exemption is stale" -f $d.Name, $d.Why)
    }
}
foreach ($a in $readmeNorm) {
    if ($batNorm -notcontains $a -and $derivedNames -notcontains $a) {
        $artProblems += ("the README Output Files table lists C:\SecurityAudit\{0} but no bat writes it" -f $a)
    }
}
$problems += $artProblems

if ($problems.Count -eq 0) {
    '[OK] Documentation matches the code -- switches, list counts, technique counts and output artifacts all agree.'
    exit 0
}
''
"[FAIL] $($problems.Count) documented claim(s) do not match the code:"
foreach ($p in $problems) { "  - $p" }
''
'       Documentation that overstates or omits what the tool does misleads the'
'       reader exactly like a finding that is printed but never raised.'
exit 1
