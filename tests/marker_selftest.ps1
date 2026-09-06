# marker_selftest.ps1 -- prove every tool's marker actually reaches disk.
#
# WHY THIS EXISTS: a field test on a real Windows machine found that
# edr_presence.ps1 printed "[WARNING] ... INSTALLED BUT NOT RUNNING" into the
# report while writing NO marker -- so the findings ledger, the section verdict,
# the FINDINGS COUNTED line and the exit code never heard about it. The section
# said "CLEAN -- no issues detected" while the report carried the finding.
#
# The cause was Write-Marker doing Set-Content -EA SilentlyContinue into a
# directory it never created: if the directory was absent, the write failed and
# the failure was swallowed. Eleven other tools carried the identical function.
#
# WHY THE EXISTING LINT COULD NOT CATCH IT: lint_unraised_findings.ps1 is
# static. It proves a check ROUTES through a marker or :dz_ps_scan; it cannot
# prove the write LANDS at runtime. That is one layer below where it can see,
# which is how this survived a 55-finding retrospective and every green build.
#
# WHY CI COULD NOT CATCH IT: windows-smoke.yml pre-created the marker
# directories before invoking the tools, which papered over the fragile write.
#
# So this test does the one thing neither could: it invokes each tool's real
# Write-Marker with a marker directory that DOES NOT EXIST and asserts the file
# appears with the right severity. Pure filesystem behavior, so it runs
# identically on Windows PowerShell 5.1 and on pwsh under CI.
#
# Exit 0 = every tool's marker contract holds. Non-zero = a finding this tool
# produces would be printed and never raised.

[CmdletBinding()]
param(
    [string]$ToolsDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools')
)

$ErrorActionPreference = 'Stop'
$failures = @()
$checked  = 0

# Extract a tool's Write-Marker function body verbatim and run it in isolation.
# Extracting rather than executing the whole tool is deliberate: the tools query
# WMI, the registry and services, none of which exist on a Linux CI runner --
# but the marker contract is pure filesystem code and must hold everywhere.
function Get-WriteMarkerFunction {
    param([string]$Path)
    $src = Get-Content -LiteralPath $Path -Raw
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count) { throw ("parse errors in " + (Split-Path -Leaf $Path)) }
    $fn = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Write-Marker'
    }, $true)
    if (-not $fn -or $fn.Count -eq 0) { return $null }
    return $fn[0].Extent.Text
}

# SECOND SHAPE. This test discovered tools by finding a `Write-Marker`
# FUNCTION, so seven tools taking a -MarkerFile parameter were skipped in
# silence -- and it still printed "All N marker-writing tool(s)", which reads
# as complete coverage. Three of the seven wrote their marker with a bare
# `Set-Content -EA SilentlyContinue` into a directory they never created: the
# exact pattern this test exists to catch, sitting inside its blind spot.
function Get-MarkerFileFunction {
    param([string]$Path)
    $src = Get-Content -LiteralPath $Path -Raw
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count) { throw ("parse errors in " + (Split-Path -Leaf $Path)) }
    $fn = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -eq 'Write-MarkerFile'
    }, $true)
    if (-not $fn -or $fn.Count -eq 0) { return $null }
    return $fn[0].Extent.Text
}

# Any tool that writes $MarkerFile MUST route it through such a helper. A bare
# Set-Content on $MarkerFile is the losable pattern and fails this test outright
# -- so a future tool cannot reintroduce it and stay invisible.
$bare = @()
foreach ($t in (Get-ChildItem -LiteralPath $ToolsDir -Filter '*.ps1')) {
    $src = Get-Content -LiteralPath $t.FullName -Raw
    # Any DIRECT write, not just Set-Content -- restricting this to one cmdlet
    # would move the blind spot rather than close it (dns_probe used Out-File).
    if ($src -match '(Set-Content|Out-File|Add-Content)[^\r\n]*-LiteralPath\s+\$MarkerFile') {
        $bare += $t.Name
    }
}

$tools = Get-ChildItem -LiteralPath $ToolsDir -Filter '*.ps1' | Sort-Object Name
foreach ($t in $tools) {
    $fnText = Get-WriteMarkerFunction -Path $t.FullName
    if (-not $fnText) { continue }
    $checked++

    # A directory that does not exist -- the exact condition that lost the field
    # test its finding.
    $probe = Join-Path ([System.IO.Path]::GetTempPath()) ("dz_mst_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0,8))
    if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Recurse -Force }

    try {
        $sb = [scriptblock]::Create(@"
param(`$MarkerDir)
$fnText
Write-Marker -Name 'selftest' -Type 'selftest' -Sev 'WARNING'
"@)
        # Name/Type differ between tools (logon_persistence uses -Type); passing
        # both and letting the unused one bind nowhere is not possible, so try
        # each shape.
        try { & $sb $probe } catch {
            $sb2 = [scriptblock]::Create(@"
param(`$MarkerDir)
$fnText
Write-Marker -Name 'selftest' -Sev 'WARNING'
"@)
            try { & $sb2 $probe } catch {
                $sb3 = [scriptblock]::Create(@"
param(`$MarkerDir)
$fnText
Write-Marker -Type 'selftest' -Sev 'WARNING'
"@)
                & $sb3 $probe
            }
        }
    } catch {
        $failures += ("{0}: Write-Marker threw -- {1}" -f $t.Name, $_.Exception.Message)
        continue
    }

    $written = @()
    if (Test-Path -LiteralPath $probe) {
        $written = @(Get-ChildItem -LiteralPath $probe -Filter 'dz_*.txt' -EA SilentlyContinue)
    }
    if ($written.Count -eq 0) {
        $failures += ("{0}: NO MARKER WRITTEN into a nonexistent directory -- a finding here would print but never raise" -f $t.Name)
    } elseif ((Get-Content -LiteralPath $written[0].FullName -Raw).Trim() -ne 'WARNING') {
        $failures += ("{0}: marker content wrong -- expected WARNING, got '{1}'" -f $t.Name, (Get-Content -LiteralPath $written[0].FullName -Raw).Trim())
    }
    Remove-Item -LiteralPath $probe -Recurse -Force -EA SilentlyContinue
}

# Now the -MarkerFile shape, run the same way: a directory that does not exist.
$checkedFile = 0
foreach ($t in $tools) {
    $fnText = Get-MarkerFileFunction -Path $t.FullName
    if (-not $fnText) { continue }
    $checkedFile++
    $probe = Join-Path ([System.IO.Path]::GetTempPath()) ("dz_mstf_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0,8))
    if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Recurse -Force }
    $target = Join-Path $probe 'dz_marker.txt'
    try {
        $sb = [scriptblock]::Create(@"
param(`$Target)
$fnText
Write-MarkerFile -Path `$Target -Value 'WARNING'
"@)
        & $sb $target
    } catch {
        $failures += ("{0}: marker helper threw -- {1}" -f $t.Name, $_.Exception.Message)
        Remove-Item -LiteralPath $probe -Recurse -Force -EA SilentlyContinue
        continue
    }
    if (-not (Test-Path -LiteralPath $target)) {
        $failures += ("{0}: NO MARKER WRITTEN into a nonexistent directory -- a finding here would print but never raise" -f $t.Name)
    }
    Remove-Item -LiteralPath $probe -Recurse -Force -EA SilentlyContinue
}

if ($bare.Count) {
    foreach ($n in $bare) {
        $failures += ("{0}: writes `$MarkerFile with a bare Set-Content -- route it through a Write-MarkerFile helper that creates the directory" -f $n)
    }
}

# A vacuous pass is a failure: if the extractor silently matched nothing, this
# test would "succeed" while proving nothing -- the same class of bug it exists
# to catch. The repo's -Strict gates make the same assertion. The second floor
# is what stops the -MarkerFile pass from silently matching zero tools, which
# is how seven of them went unchecked for months.
if ($checkedFile -lt 3) {
    Write-Host ("[FAIL] marker selftest inspected only {0} -MarkerFile tool(s); the second extractor is broken, not the tools." -f $checkedFile)
    exit 1
}
if ($checked -lt 10) {
    Write-Host ("[FAIL] marker selftest inspected only {0} tool(s); the extractor is broken, not the tools." -f $checked)
    exit 1
}

if ($failures.Count) {
    Write-Host ("[FAIL] {0} of {1} tool(s) can lose a finding between report and ledger:" -f $failures.Count, ($checked + $checkedFile))
    $failures | ForEach-Object { Write-Host ("  - " + $_) }
    exit 1
}

# BOTH counts, always. "All N tool(s)" used to mean "all N of the subset I
# happened to recognise", which is the failure mode this whole file guards
# against -- stated coverage that is not real coverage.
Write-Host ("[OK] All {0} marker-writing tool(s) write their marker even when the target directory does not exist ({1} via Write-Marker, {2} via a -MarkerFile helper)." -f ($checked + $checkedFile), $checked, $checkedFile)
exit 0
