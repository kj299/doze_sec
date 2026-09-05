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
# If this run is HARD-KILLED (window closed, machine reset) mid-flight, the
# planted artifacts may be left behind. The fix is to run the standalone panic
# button once, elevated:  .\tests\cleanup_selftest.ps1
#
# Windows PowerShell 5.1 compatible. Requires elevation (the harnesses do).
# Exit 0 = every step passed. Exit 1 = something failed or nothing ran.

[CmdletBinding()]
param(
    # Only the fast checks (parse + marker selftest); skips both detection
    # harnesses. For iterating on a tools/*.ps1 change.
    [switch]$Quick,

    # Opt IN to the nine plants on the logon/unlock/authentication path
    # (credential provider, Winlogon Notify, screensaver, LSA Notification and
    # Authentication packages, network provider, logon script, AppInit and
    # AppCert DLLs). OFF by default on purpose: a real user was locked out of
    # their own machine when the screen locked while those were live. Only
    # pass this on a throwaway VM you can hard-reset.
    [switch]$AllowLockScreenRisk
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
# Safe by default: skip the lock-screen-breaking plants unless opted in.
$riskArgs = @{}
if (-not $AllowLockScreenRisk) { $riskArgs['NoLockScreenRisk'] = $true }

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
if ($AllowLockScreenRisk) {
    Write-Host '*** WARNING -- LOCK-SCREEN RISK IS ENABLED ***' -ForegroundColor Red
    Write-Host '    This run registers NINE plants on the logon path -- a credential provider,' -ForegroundColor Red
    Write-Host '    a Winlogon Notify handler, a screensaver, LSA Notification and'           -ForegroundColor Red
    Write-Host '    Authentication packages (loaded by lsass AT BOOT), a network provider,'   -ForegroundColor Red
    Write-Host '    a logon script, and AppInit/AppCert DLLs -- all pointing at files that'   -ForegroundColor Red
    Write-Host '    do not exist. If this machine LOCKS while they are live, Windows can'     -ForegroundColor Red
    Write-Host '    fail to draw a working unlock screen and Ctrl+Alt+Del will appear dead'   -ForegroundColor Red
    Write-Host '    -- you would be locked out and need a hard power-off; a reboot with the'  -ForegroundColor Red
    Write-Host '    LSA packages live can break sign-in itself. DO NOT lock, sleep, reboot,'  -ForegroundColor Red
    Write-Host '    or walk away. Run this only on a machine you can afford to hard-reset.'   -ForegroundColor Red
    Write-Host ''
} else {
    Write-Host 'SAFE MODE (default): the nine plants on the logon/unlock/authentication'
    Write-Host '      path (credential provider, Winlogon Notify, screensaver, LSA packages,'
    Write-Host '      network provider, logon script, AppInit/AppCert DLLs) are SKIPPED and'
    Write-Host '      reported as such. The harness prints its full blast radius before it'
    Write-Host '      plants anything. Pass -AllowLockScreenRisk only on a throwaway VM.'
    Write-Host ''
}

# Hold the display on for the duration. The idle lock is what actually bit a
# real user: the run was started, the machine was left alone as the runbook
# instructed, the screen locked while a bogus credential provider was
# registered, and LogonUI could not draw an unlock UI. This does not stop a
# MANUAL Win+L -- hence the warning above -- but it stops the timer that
# caused the incident.
$script:esSet = $false
try {
    if (-not ([System.Management.Automation.PSTypeName]'DozeSec.Power').Type) {
        Add-Type -Namespace DozeSec -Name Power -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern uint SetThreadExecutionState(uint esFlags);
'@
    }
    # ES_CONTINUOUS(0x80000000) | ES_SYSTEM_REQUIRED(0x1) | ES_DISPLAY_REQUIRED(0x2)
    [void][DozeSec.Power]::SetThreadExecutionState([uint32]2147483651)
    $script:esSet = $true
    Write-Host 'Display kept awake for the duration (idle lock suppressed).'
    Write-Host ''
} catch {
    Write-Host 'NOTE: could not suppress the idle lock -- do not let this machine lock while it runs.'
    Write-Host ''
}

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
    # FIRST, before anything touches the machine: prove the harness cannot lock
    # this user out. If this fails, stop -- do not plant anything.
    Invoke-Step 'safety invariants (harness cannot lock you out)' {
        & .\tests\safety_invariants.ps1
        if ($LASTEXITCODE -ne 0) { throw ("exit code {0}" -f $LASTEXITCODE) }
        # A check that cannot fail is not a check: prove it fails on a
        # mutated copy (undeclared plant, missing reason, missing cleanup).
        & .\tests\safety_invariants.ps1 -SelfTest
        if ($LASTEXITCODE -ne 0) { throw ("self-test exit code {0}" -f $LASTEXITCODE) }
        # -readonly's promise (nothing changed outside OUTDIR/TEMP, no network)
        # rests on every mutation/egress site staying gated; and every known
        # false positive must be catalogued with the test that proves it.
        & .\tools\lint_readonly.ps1
        if ($LASTEXITCODE -ne 0) { throw ("lint_readonly exit code {0}" -f $LASTEXITCODE) }
        & .\tools\lint_readonly.ps1 -SelfTest
        if ($LASTEXITCODE -ne 0) { throw ("lint_readonly self-test exit code {0}" -f $LASTEXITCODE) }
        & .\tools\benign_corpus_check.ps1 -Mode Lint
        if ($LASTEXITCODE -ne 0) { throw ("benign_corpus_check exit code {0}" -f $LASTEXITCODE) }
        # The remediation script is the one artifact a person runs elevated.
        & .\tools\lint_remediation.ps1
        if ($LASTEXITCODE -ne 0) { throw ("lint_remediation exit code {0}" -f $LASTEXITCODE) }
        & .\tools\lint_remediation.ps1 -SelfTest
        if ($LASTEXITCODE -ne 0) { throw ("lint_remediation self-test exit code {0}" -f $LASTEXITCODE) }
    }
    if ($results | Where-Object { $_.Step -like 'safety invariants*' -and $_.Result -eq 'FAIL' }) {
        Write-Host ''
        Write-Host '[ABORT] Safety invariants are broken -- refusing to plant anything on this machine.'
        exit 1
    }

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
        # Parsing is not enough: an orphaned else parses as a command and only
        # fails at runtime. The AST lint catches it.
        & .\tools\lint_orphan_else.ps1
        if ($LASTEXITCODE -ne 0) { throw ("orphaned else/elseif detected (exit {0})" -f $LASTEXITCODE) }
    }

    Invoke-Step 'marker selftest (finding reaches the ledger)' {
        & .\tests\marker_selftest.ps1
        if ($LASTEXITCODE -ne 0) { throw ("exit code {0}" -f $LASTEXITCODE) }
    }

    if ($Quick) {
        Write-Host ''
        Write-Host '(-Quick: skipping both detection harnesses)'
    } else {
        # The harnesses plant known-bad artifacts. Whatever happens to the
        # assertions -- pass, fail, or an exception mid-run -- the teardown must
        # run so the machine is never left carrying a plant. (A hard kill of this
        # process, e.g. closing the window, still bypasses this; the fix then is
        # to run tests\cleanup_selftest.ps1 by hand -- see the note at the top.)
        try {
            Invoke-Step 'detection harness (doze_sec.bat)' {
                & .\tests\detection_selftest.ps1 -BatPath .\doze_sec.bat @riskArgs
                if ($LASTEXITCODE -ne 0) { throw ("exit code {0}" -f $LASTEXITCODE) }
            }

            Invoke-Step 'detection harness (doze_sec_noAdmin.bat, elevated adaptive path)' {
                & .\tests\detection_selftest.ps1 -BatPath .\doze_sec_noAdmin.bat @riskArgs
                if ($LASTEXITCODE -ne 0) { throw ("exit code {0}" -f $LASTEXITCODE) }
            }
        } finally {
            Write-Host ''
            Write-Host '== Post-run teardown (planted artifacts) =='
            # Hygiene, not a graded step: a teardown problem is printed loudly
            # but does not by itself flip the suite verdict.
            try { & .\tests\cleanup_selftest.ps1 -Quiet }
            catch { Write-Host ("[WARNING] teardown raised: {0} -- run tests\cleanup_selftest.ps1 by hand" -f $_.Exception.Message) }
            if ($LASTEXITCODE -ne 0) {
                Write-Host '[WARNING] teardown reported an error -- run tests\cleanup_selftest.ps1 by hand and review.'
            } else {
                Write-Host '[OK] planted artifacts removed (or already absent).'
            }
        }
    }
} finally { Pop-Location }

# Release the display-awake request; the OS resumes its normal idle timers.
if ($script:esSet) { try { [void][DozeSec.Power]::SetThreadExecutionState([uint32]2147483648) } catch {} }
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
Write-Host 'Test-run reports from the harnesses above are quarantined under'
Write-Host '  C:\SecurityAudit\selftest\  and are banner-stamped TEST RUN -- every'
Write-Host '  finding in them was planted. Real audits stay in C:\SecurityAudit\.'
Write-Host ''
Write-Host 'On the machine you are sitting at, do NOT run this script -- run'
Write-Host '  .\tests\field_test.ps1'
Write-Host '  instead: read-only, no plants, no network. It runs the audit with -readonly,'
Write-Host '  proves nothing changed, and hands you every finding to adjudicate against'
Write-Host '  tests\benign_corpus.txt. This script (the plant harness) is for a VM or CI.'
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
