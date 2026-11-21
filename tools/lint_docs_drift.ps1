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
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

if ($SelfTest) {
    # Each rule added on 2026-11-21 must FAIL on the drift it was written for.
    # A copy of the files the lint reads is mutated and the lint run on it.
    $src = Split-Path -Parent $PSScriptRoot
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_docs_drift_' + [guid]::NewGuid().ToString('N'))
    $fails = 0
    function Invoke-OnCopy {
        param([string]$Name, [scriptblock]$Mutate, [string]$Expect)
        $d = Join-Path $tmp ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $d 'tools') -Force | Out-Null
        foreach ($f in @('README.md', 'THREAT_MODEL.md', 'doze_sec.bat', 'doze_sec_noAdmin.bat')) { Copy-Item -LiteralPath (Join-Path $src $f) -Destination $d }
        Copy-Item -LiteralPath (Join-Path $src 'ThreatLists') -Destination $d -Recurse
        Copy-Item -Path (Join-Path $src 'tools/*.ps1') -Destination (Join-Path $d 'tools')
        & $Mutate $d
        $o = (& $PSCommandPath -Root $d 2>&1 | Out-String)
        $code = $LASTEXITCODE
        if ($Expect) { $ok = ($code -ne 0 -and $o -match $Expect) } else { $ok = ($code -eq 0) }
        if ($ok) { "[OK]   $Name" } else { "[FAIL] $Name (exit $code): " + (($o -split "`r?`n" | Where-Object { $_ -match '^\s+- ' }) -join ' | '); $script:fails++ }
    }
    function Edit-File { param([string]$Path, [string]$From, [string]$To)
        $t = [IO.File]::ReadAllText($Path)
        if (-not $t.Contains($From)) { throw "self-test anchor not found in ${Path}: $From" }
        [IO.File]::WriteAllText($Path, $t.Replace($From, $To))
    }
    try {
        Invoke-OnCopy 'the unmutated copy passes' { param($d) } ''
        Invoke-OnCopy 'a switch documented as Both that one script does not handle fails' { param($d) Edit-File (Join-Path $d 'README.md') '| `-resetTTP` | Admin only |' '| `-resetTTP` | Both |' } "switch '-resetTTP' is documented as 'Both' but doze_sec_noAdmin\.bat has no handler"
        Invoke-OnCopy 'an indicator total that does not match the lists fails' { param($d) $t = [IO.File]::ReadAllText((Join-Path $d 'THREAT_MODEL.md')); $t = [regex]::Replace($t, '(\d+)(\s+indicators\b)', { param($m) ([int]$m.Groups[1].Value + 1).ToString() + $m.Groups[2].Value }); [IO.File]::WriteAllText((Join-Path $d 'THREAT_MODEL.md'), $t) } 'THREAT_MODEL\.md says \d+ indicators; the \d+ ThreatLists\\ioc_\*\.txt files hold \d+'
        Invoke-OnCopy 'a tool whose header does not mention a -Check value it accepts fails' { param($d) $f = Join-Path $d 'tools/file_walk_check.ps1'; $t = [IO.File]::ReadAllText($f); $i = $t.IndexOf('param('); [IO.File]::WriteAllText($f, ($t.Substring(0, $i).Replace('RansomExt', 'Ransom_Ext') + $t.Substring($i))) } 'tools\\file_walk_check\.ps1 accepts -Check RansomExt but its header comment never mentions it'
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    if ($fails) { "[FAIL] $fails lint_docs_drift self-test expectation(s) unmet"; exit 1 }
    '[OK] lint_docs_drift self-test: a switch in the wrong script, a wrong indicator total and a tool header missing a mode each fail the lint, and the unmutated tree passes.'
    exit 0
}

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
        # Backslashes are dropped first: a sub-technique id written inside a
        # regex, with the dot escaped as a self-test assertion escapes it,
        # would otherwise be counted as its PARENT technique as well, and read
        # as one more technique than the audit covers. Twice now. (And no
        # technique id is spelled out in this comment: this lint scans its own
        # source, so an id named in prose here would be counted too -- which
        # is how a tool comment once raised the count by one.)
        $srcText = ((Get-Content -LiteralPath $f -Raw -EA Stop) -replace '\\', '')
        foreach ($m in ([regex]::Matches($srcText, 'T1[0-9]{3}(\.[0-9]{3})?'))) {
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
# ---- 5. a switch works in the script the README says it works in ----------
# Rule 1 asks only whether SOME bat handles a switch. The README listed
# -resetTTP as "Both" while doze_sec_noAdmin.bat had no handler for it and
# ignored it silently; rule 1 passed.
$batText = @{}
foreach ($n in @('doze_sec.bat', 'doze_sec_noAdmin.bat')) {
    $bp = Join-Path $Root $n
    if (Test-Path -LiteralPath $bp) { $batText[$n] = Get-Content -LiteralPath $bp -Raw }
}
$scopeRows = 0
$inSwitches = $false
foreach ($ln in ($readme -split "`r?`n")) {
    if ($ln -match '^##\s') { $inSwitches = ($ln -match '^##\s+Switches\s*$') ; continue }
    if (-not $inSwitches) { continue }
    $m = [regex]::Match($ln, '^\|\s*`(-[A-Za-z][A-Za-z]*)[^|]*\|\s*([^|]+?)\s*\|')
    if (-not $m.Success) { continue }
    $sw = $m.Groups[1].Value; $scope = $m.Groups[2].Value
    $need = @()
    if ($scope -match '^Both$') { $need = @('doze_sec.bat', 'doze_sec_noAdmin.bat') }
    elseif ($scope -match '^Admin only$') { $need = @('doze_sec.bat') }
    elseif ($scope -match '^noAdmin only$') { $need = @('doze_sec_noAdmin.bat') }
    else { $problems += "switch '$sw': the README's script column says '$scope', which this lint does not know (Both, Admin only, noAdmin only)"; continue }
    $scopeRows++
    foreach ($n in $need) {
        if (-not $batText.ContainsKey($n)) { continue }
        if ($batText[$n] -notmatch ('"%~1"\s*==\s*"' + [regex]::Escape($sw) + '"')) {
            $problems += "switch '$sw' is documented as '$scope' but $n has no handler for it -- it is silently ignored there"
        }
    }
}
if ($scopeRows -lt 10) { $problems += "only $scopeRows Switches-table row(s) carried a script column -- the per-script check would pass vacuously" } else { $checks++ }

# ---- 6. the indicator count in THREAT_MODEL.md -----------------------------
# "N indicators" drifted to 282 when a list lost an entry; the README's
# per-file table (rule 2) was right and nothing compared the total.
if (Test-Path -LiteralPath $tmPath) {
    $tmText = Get-Content -LiteralPath $tmPath -Raw
    $im = [regex]::Match($tmText, '(\d+)\s+indicators\b')
    $iocFiles = @(Get-ChildItem -LiteralPath (Join-Path $Root 'ThreatLists') -Filter 'ioc_*.txt' -ErrorAction SilentlyContinue)
    if (-not $im.Success) { $problems += 'THREAT_MODEL.md no longer states an "N indicators" total -- the indicator-count check has nothing to compare' }
    elseif ($iocFiles.Count -eq 0) { $problems += 'no ThreatLists\ioc_*.txt file found -- the indicator-count check would pass vacuously' }
    else {
        $checks++
        $sum = 0
        foreach ($f in $iocFiles) { $sum += (Get-EntryCount $f.FullName) }
        if ([int]$im.Groups[1].Value -ne $sum) { $problems += ("THREAT_MODEL.md says {0} indicators; the {1} ThreatLists\ioc_*.txt files hold {2}" -f $im.Groups[1].Value, $iocFiles.Count, $sum) }
    }
} else { $problems += 'THREAT_MODEL.md not found -- the indicator-count check did not run' }

# ---- 7. a tool's header names every -Check / -Part it accepts --------------
# file_walk_check grew from three checks to six and office_macro_check gained
# -Part Trust while their headers still described the first version.
$toolsDir = Join-Path $Root 'tools'
$modeTools = 0
foreach ($tf in @(Get-ChildItem -LiteralPath $toolsDir -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
    $tt = Get-Content -LiteralPath $tf.FullName -Raw
    $vm = [regex]::Match($tt, '\[ValidateSet\(([^)]*)\)\]\s*(?:\[[A-Za-z\[\]]+\]\s*)?\$(Check|Part)\b')
    if (-not $vm.Success) { continue }
    $modeTools++
    $pi = $tt.IndexOf('param(')
    $header = $(if ($pi -gt 0) { $tt.Substring(0, $pi) } else { '' })
    foreach ($v in ([regex]::Matches($vm.Groups[1].Value, "'([^']+)'"))) {
        $val = $v.Groups[1].Value
        # On a line that names the parameter, and case-sensitive: a value such
        # as Policy must not be satisfied by the word in a sentence.
        if ($header -cnotmatch ('(?m)^.*-' + $vm.Groups[2].Value + '\b.*\b' + [regex]::Escape($val) + '\b')) {
            $problems += ("tools\{0} accepts -{1} {2} but its header comment never mentions it" -f $tf.Name, $vm.Groups[2].Value, $val)
        }
    }
}
if ($modeTools -lt 3) { $problems += "only $modeTools tool(s) with a -Check/-Part ValidateSet were found -- the header check would pass vacuously" } else { $checks++ }

"Checked $checks documented claim(s) against the code: $($implemented.Count) implemented switch(es), $($referenced.Count) referenced technique(s)."
$problems += $artProblems

if ($problems.Count -eq 0) {
    '[OK] Documentation matches the code -- switches (and the script each works in), list counts, the indicator total, technique counts, output artifacts and tool headers all agree.'
    exit 0
}
''
"[FAIL] $($problems.Count) documented claim(s) do not match the code:"
foreach ($p in $problems) { "  - $p" }
''
'       Documentation that overstates or omits what the tool does misleads the'
'       reader exactly like a finding that is printed but never raised.'
exit 1
