# detection_selftest.ps1 -- end-to-end detection regression harness.
#
# WHY: CI's full-run proves the audit COMPLETES; it never proved the audit
# DETECTS anything. Every false-clean in the code review shipped green because
# nothing planted a known-bad artifact and checked the verdict. This harness
# closes that gap: it plants a battery of indicators, runs the audit once, and
# asserts each expected finding appears in the report.
#
# TWO TIERS:
#   required -- detections that work today. A required case that STOPS firing
#               is a regression and FAILS the job (exit 1).
#   pending  -- gaps the code review found (Run-key backdoor has no detection
#               logic, Section 2 never evaluates the Guest account, IFEO on a
#               non-accessibility binary is printed but never escalated, and
#               CRITICAL severity depends on a single fragile summary block).
#               A pending case NEVER fails the job. When a fix lands and the
#               case starts passing, the harness says "PROMOTE" -- move it to
#               the required tier so it can never regress again.
#
# This is the safety net for the exit-code/finding-model rework: it lets that
# change proceed knowing the detections that work today keep working, and it
# is the running scoreboard of which gaps are still open.
#
# Windows only, requires admin (plants HKLM keys, edits the HOSTS file, toggles
# the Guest account). Every artifact is removed in the finally block, even on
# failure, so the runner is left clean. Windows PowerShell 5.1 compatible.
#
# Usage (from CI, on a real Windows runner):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\detection_selftest.ps1 -BatPath .\doze_sec.bat

[CmdletBinding()]
param(
    [string]$BatPath = '.\doze_sec.bat',
    [string]$OutDir  = 'C:\SecurityAudit'
)

$ErrorActionPreference = 'Stop'

# A unique marker so planted artifacts are unmistakably ours and cleanup is safe.
$MARK      = 'dz_selftest_evil'
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$wdigestKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$runKey     = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$ifeoKey    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe'

# Each case: Name, Tier, Plant/Cleanup script blocks, and Expect -- a regex that
# must appear in the final report text for the detection to count as firing.
$cases = @(
    @{
        Name   = 'WDigest UseLogonCredential=1 -> CRITICAL (plaintext creds in RAM)'
        Tier   = 'required'
        Expect = 'WDigest ENABLED'
        Plant  = { New-Item -Path $wdigestKey -Force | Out-Null
                   Set-ItemProperty -Path $wdigestKey -Name UseLogonCredential -Value 1 -Type DWord -Force }
        Cleanup= { Remove-ItemProperty -Path $wdigestKey -Name UseLogonCredential -EA SilentlyContinue }
    },
    @{
        Name   = 'HOSTS entry mapping a domain to a public IP -> WARNING (DNS hijack)'
        Tier   = 'required'
        Expect = 'Non-standard entries found in HOSTS'
        Plant  = { Add-Content -LiteralPath $hostsPath -Value ("203.0.113.5 {0}.example" -f $MARK) }
        Cleanup= { $keep = Get-Content -LiteralPath $hostsPath | Where-Object { $_ -notmatch $MARK }
                   Set-Content -LiteralPath $hostsPath -Value $keep -Encoding ASCII }
    },
    @{
        Name   = 'Run-key backdoor (encoded PowerShell) -> flagged as suspicious'
        Tier   = 'pending'   # Section 5 raw-dumps Run keys with no evaluation logic
        Expect = ('(?im)(\[(WARNING|CRITICAL)\][^\r\n]*{0}|{0}[^\r\n]*(suspicious|encoded|backdoor))' -f $MARK)
        Plant  = { Set-ItemProperty -Path $runKey -Name $MARK -Value 'powershell -w hidden -enc ZQBjAGgAbwA=' -Force }
        Cleanup= { Remove-ItemProperty -Path $runKey -Name $MARK -EA SilentlyContinue }
    },
    @{
        Name   = 'IFEO Debugger on a NON-accessibility binary (notepad) -> escalated'
        Tier   = 'pending'   # Section 5 prints [IFEO HIT] but only accessibility bins escalate
        Expect = '(?im)IFEO Debugger hijack[^\r\n]*notepad'
        Plant  = { New-Item -Path $ifeoKey -Force | Out-Null
                   Set-ItemProperty -Path $ifeoKey -Name Debugger -Value 'cmd.exe' -Force }
        Cleanup= { Remove-Item -Path $ifeoKey -Recurse -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'Guest account enabled -> WARNING'
        Tier   = 'pending'   # Section 2 raw-dumps `net user guest` with no verdict
        Expect = '(?im)\[(WARNING|CRITICAL)\][^\r\n]*guest'
        Plant  = { & net user guest /active:yes | Out-Null }
        Cleanup= { & net user guest /active:no  | Out-Null }
    }
)

function Get-LatestReport {
    param([string]$Dir)
    Get-ChildItem -LiteralPath $Dir -Filter 'SecurityReport_*.txt' -EA SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

$planted = @()
$runExit = $null
try {
    Write-Host "== Planting known-bad artifacts =="
    foreach ($c in $cases) {
        & $c.Plant
        $planted += $c
        Write-Host ("  planted: {0}" -f $c.Name)
    }

    Write-Host "== Running the audit (this takes a few minutes) =="
    # PowerShell launches the .bat directly and captures its exit code in
    # $LASTEXITCODE (no cmd /c quoting hazard). -noConsoleLog skips the
    # self-tee re-exec so the exit code is the audit's own, not Tee-Object's.
    & $BatPath -dev -sdu -nosrp -resetTTP -noConsoleLog | Out-Null
    $runExit = $LASTEXITCODE
    Write-Host ("  audit exit code: {0}" -f $runExit)

    $report = Get-LatestReport -Dir $OutDir
    if (-not $report) { Write-Host "FAIL: no SecurityReport_*.txt produced"; exit 1 }
    $text = Get-Content -LiteralPath $report.FullName -Raw
    Write-Host ("  report: {0}" -f $report.FullName)

    Write-Host ""
    Write-Host "== Detection scoreboard =="
    $requiredFail = 0
    $promote = 0
    foreach ($c in $cases) {
        $hit = [bool]([regex]::IsMatch($text, $c.Expect))
        if ($c.Tier -eq 'required') {
            if ($hit) { Write-Host ("  [ OK       ] {0}" -f $c.Name) }
            else      { Write-Host ("  [ REGRESS  ] {0}  -- required detection no longer fires" -f $c.Name); $requiredFail++ }
        } else {
            if ($hit) { Write-Host ("  [ PROMOTE  ] {0}  -- now detected; move to the required tier" -f $c.Name); $promote++ }
            else      { Write-Host ("  [ gap      ] {0}  -- still a known gap (see code review)" -f $c.Name) }
        }
    }

    # Exit-code architecture (code-review W1-W3): a planted CRITICAL (WDigest=1)
    # should drive the process exit code to 8. Today CRITICAL comes only from a
    # fragile end-of-run summary block, so treat 8 as pending and "not clean" as
    # required.
    Write-Host ""
    Write-Host "== Exit-code accounting =="
    if ($runExit -ne 0 -and $runExit -ne $null) { Write-Host ("  [ OK       ] audit did not report a clean exit with planted findings (code {0})" -f $runExit) }
    else { Write-Host "  [ REGRESS  ] audit exited clean (0) despite planted findings"; $requiredFail++ }
    if ($runExit -eq 8) { Write-Host "  [ PROMOTE  ] exit code 8 (CRITICAL) surfaced -- make it a required guarantee" }
    else { Write-Host ("  [ gap      ] planted CRITICAL did not raise exit code to 8 (got {0}) -- see W1-W3" -f $runExit) }

    Write-Host ""
    if ($requiredFail -gt 0) {
        Write-Host ("FAIL: {0} required detection(s) regressed." -f $requiredFail)
        exit 1
    }
    if ($promote -gt 0) {
        Write-Host ("OK (with {0} case(s) ready to PROMOTE from pending to required)." -f $promote)
    } else {
        Write-Host "OK: all required detections fired; known gaps unchanged."
    }
    exit 0
}
finally {
    Write-Host ""
    Write-Host "== Cleanup =="
    foreach ($c in $planted) {
        try { & $c.Cleanup; Write-Host ("  removed: {0}" -f $c.Name) }
        catch { Write-Host ("  WARNING: cleanup failed for {0}: {1}" -f $c.Name, $_.Exception.Message) }
    }
}
