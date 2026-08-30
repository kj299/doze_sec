# manual_ci.ps1 -- the Windows half of CI, as one elevated command.
#
# WHY THIS EXISTS: the repository is private, so GitHub Actions minutes are
# metered -- and windows-smoke's five windows-latest jobs bill at 2x on every
# PR push. One heavy week exhausted the month mid-cycle and every run "failed"
# in seconds with zero compute. During that outage the verification that
# actually caught bugs was a person running the checks on a real Windows
# machine: five real defects in one afternoon, two of them false ACTIVE
# COMPROMISE indicators, none of which CI had ever caught. This script makes
# that manual pass one command instead of a chat scroll-back, and it remains
# the PR gate: windows-smoke now runs on pushes to main and manual dispatch
# only, so the reset quota survives the month.
#
# WHAT IT RUNS (mirroring the CI jobs' exact invocations, in order):
#   1. Windows PowerShell 5.1 parse of every tools/*.ps1  (helpers-ps51, parse half)
#   2. tests\marker_selftest.ps1                          (lint.yml marker job)
#   3. tests\detection_selftest.ps1 -BatPath .\doze_sec.bat         (detection-selftest)
#   4. tests\detection_selftest.ps1 -BatPath .\doze_sec_noAdmin.bat (detection-selftest-noadmin)
#
# WHAT IT DELIBERATELY DOES NOT RUN (printed at the end with exact commands):
# the full end-to-end audit (long) and the true standard-user smoke (creates a
# temporary local user). Run those when the change touches INIT, section
# plumbing, or the deferral contract.
#
# The harnesses PLANT known-bad indicators (services, registry keys) and
# remove them again in their cleanup blocks -- run this only on a machine
# where that is acceptable, and read any FAIL before re-running.
#
# Windows PowerShell 5.1 compatible. Requires elevation (the harnesses do).
# Exit 0 = every step passed. Exit 1 = something failed or nothing ran.

[CmdletBinding()]
param(
    # Only the fast checks (parse + marker selftest); skips both detection
    # harnesses. For iterating on a tools/*.ps1 change.
    [switch]$Quick
)

$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '[FAIL] This must run in an ELEVATED PowerShell -- the detection harnesses plant and remove services/registry keys.'
    exit 1
}

$root = Split-Path -Parent $PSScriptRoot
$results = @()

# The detection harnesses plant a known-bad state, run the audit, and assert the
# scanner reported exactly that state -- so they assume the machine holds still
# for the duration. Changing security settings mid-run (enabling the firewall,
# turning on audit policy, editing Defender) moves the ground truth underneath a
# harness and makes its strict checks flag a mismatch that is not a real defect.
# A field run hit exactly this. So: do not change security settings while this
# runs, and let any you just made settle first.
Write-Host ''
Write-Host 'NOTE: the detection harnesses assume a quiescent machine. Do not change'
Write-Host '      security settings (firewall, audit policy, Defender, accounts)'
Write-Host '      while this is running -- it will take ~15-25 minutes.'
Write-Host ''

function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ''
    Write-Host ("========== {0} ==========" -f $Name)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ok = $false
    try { & $Body; $ok = $true }
    catch { Write-Host ("[FAIL] {0}: {1}" -f $Name, $_.Exception.Message) }
    $sw.Stop()
    $script:results += New-Object PSObject -Property @{
        Step = $Name
        Result = $(if ($ok) { 'PASS' } else { 'FAIL' })
        Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
}

Push-Location $root
try {
    Invoke-Step '5.1 parse of tools/*.ps1' {
        $files = @(Get-ChildItem -Path (Join-Path $root 'tools') -Filter '*.ps1')
        # A vacuous pass is a failure: zero files parsed proves nothing.
        if ($files.Count -lt 10) { throw ("only {0} tool file(s) found -- wrong directory?" -f $files.Count) }
        $bad = 0
        foreach ($f in $files) {
            $errs = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
            if ($errs -and $errs.Count) {
                $bad++
                Write-Host ("[FAIL] {0} does not parse:" -f $f.Name)
                $errs | ForEach-Object { Write-Host ("    " + $_.Message) }
            }
        }
        if ($bad) { throw ("{0} file(s) failed to parse" -f $bad) }
        Write-Host ("[OK] {0} tool file(s) parse clean on this PowerShell." -f $files.Count)
    }

    Invoke-Step 'marker selftest (finding reaches the ledger)' {
        & .\tests\marker_selftest.ps1
        if ($LASTEXITCODE -ne 0) { throw ("exit code {0}" -f $LASTEXITCODE) }
    }

    if ($Quick) {
        Write-Host ''
        Write-Host '(-Quick: skipping both detection harnesses)'
    } else {
        Invoke-Step 'detection harness (doze_sec.bat)' {
            & .\tests\detection_selftest.ps1 -BatPath .\doze_sec.bat
            if ($LASTEXITCODE -ne 0) { throw ("exit code {0}" -f $LASTEXITCODE) }
        }

        Invoke-Step 'detection harness (doze_sec_noAdmin.bat, elevated adaptive path)' {
            & .\tests\detection_selftest.ps1 -BatPath .\doze_sec_noAdmin.bat
            if ($LASTEXITCODE -ne 0) { throw ("exit code {0}" -f $LASTEXITCODE) }
        }
    }
} finally { Pop-Location }

Write-Host ''
Write-Host '==================== SUMMARY ===================='
foreach ($r in $results) {
    Write-Host ("  {0,-58} {1,-4} {2,7}s" -f $r.Step, $r.Result, $r.Seconds)
}
$failed = @($results | Where-Object { $_.Result -eq 'FAIL' })
if ($results.Count -lt 2) {
    Write-Host '[FAIL] Fewer than two steps ran -- the runbook itself is broken, not the code.'
    exit 1
}
if ($failed.Count) {
    Write-Host ("[FAIL] {0} of {1} step(s) failed -- do not merge on this." -f $failed.Count, $results.Count)
    exit 1
}
Write-Host ("[OK] All {0} step(s) passed." -f $results.Count)
Write-Host ''
Write-Host 'Not run by this script (run when the change touches INIT, section plumbing,'
Write-Host 'or the deferral contract):'
Write-Host ''
Write-Host '  Full end-to-end audit (CI job: doze_sec.bat end-to-end), elevated cmd.exe:'
Write-Host '      doze_sec.bat -dev -sdu -nosrp -resetTTP -dnsprobe'
Write-Host '    then in the newest C:\SecurityAudit\SecurityReport_*.txt confirm both'
Write-Host '    an "EXIT CODE:" line and the [18/18] section banner exist.'
Write-Host ''
Write-Host '  True standard-user smoke (CI job: deferral contract) -- creates and'
Write-Host '  removes a temporary local user account:'
Write-Host '      .\tests\noadmin_smoke.ps1 -BatPath .\doze_sec_noAdmin.bat'
exit 0
