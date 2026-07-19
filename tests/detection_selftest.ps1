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
#               is a regression and FAILS the job (exit 1). Cases with
#               Invert=$true are FALSE-POSITIVE guards: they plant a benign
#               state and fail the job if the audit flags it anyway.
#   pending  -- gaps not yet closed. A pending case NEVER fails the job. When
#               a fix lands and the case starts passing, the harness says
#               "PROMOTE" -- move it to the required tier so it can never
#               regress again.
#
# History: the issue #138 gaps (Run-key backdoor eval, Guest-account verdict,
# IFEO escalation on non-accessibility binaries) were promoted to required on
# 2026-07-19 once persistence_eval.ps1 and the Section 2 SID -501 check
# landed. Exit code 8 on planted CRITICAL and the report-filename timestamp
# were promoted 2026-07-18. There are currently no pending cases.
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
$sblKey     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$fpSvcName  = 'dz_selftest_fp_svc'
$fpSvcDir   = 'C:\Program Files\dz selftest fp'

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
        Tier   = 'required'  # persistence_eval.ps1 evaluates Run keys (issue #138)
        Expect = ('(?im)(\[(WARNING|CRITICAL)\][^\r\n]*{0}|{0}[^\r\n]*(suspicious|encoded|backdoor))' -f $MARK)
        Plant  = { New-Item -Path $runKey -Force | Out-Null
                   Set-ItemProperty -Path $runKey -Name $MARK -Value 'powershell -w hidden -enc ZQBjAGgAbwA=' -Force }
        Cleanup= { Remove-ItemProperty -Path $runKey -Name $MARK -EA SilentlyContinue }
    },
    @{
        Name   = 'IFEO Debugger on a NON-accessibility binary (notepad) -> escalated'
        Tier   = 'required'  # persistence_eval.ps1 escalates ANY IFEO Debugger (issue #138)
        Expect = '(?im)IFEO Debugger hijack[^\r\n]*notepad'
        Plant  = { New-Item -Path $ifeoKey -Force | Out-Null
                   Set-ItemProperty -Path $ifeoKey -Name Debugger -Value 'cmd.exe' -Force }
        Cleanup= { Remove-Item -Path $ifeoKey -Recurse -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'Guest account enabled -> WARNING'
        Tier   = 'required'  # Section 2 now emits a SID -501 verdict (issue #138)
        Expect = '(?im)\[(WARNING|CRITICAL)\][^\r\n]*guest'
        Plant  = { & net user guest /active:yes | Out-Null }
        Cleanup= { & net user guest /active:no  | Out-Null }
    },
    @{
        Name   = 'netsh portproxy rule active -> WARNING (Volt Typhoon C2 tunnel IOC)'
        Tier   = 'required'
        Expect = '(?im)\[WARNING\] netsh portproxy rules ACTIVE'
        Plant  = { $r = & netsh interface portproxy add v4tov4 listenport=53219 listenaddress=127.0.0.1 connectport=80 connectaddress=127.0.0.1
                   if ($LASTEXITCODE -ne 0) { throw ("netsh portproxy add failed: {0}" -f ($r -join ' ')) } }
        Cleanup= { & netsh interface portproxy delete v4tov4 listenport=53219 listenaddress=127.0.0.1 | Out-Null }
    },
    # ---- Section-verdict unmasking (exit-code rework, review W1) ----
    # Verdicts were derived from EXIT_CODE deltas; because the code saturates
    # at 2, every section after the first finding printed "CLEAN" even when it
    # found something. Verdicts now count findings per section, so BOTH the
    # HOSTS section (3) and the portproxy section (17) must report ISSUES
    # FOUND in the same run. No plant of their own -- they piggyback on the
    # HOSTS and portproxy artifacts planted above.
    @{
        Name   = 'Section 3 verdict reflects the HOSTS finding (verdict unmasking)'
        Tier   = 'required'
        Expect = '\[SECTION 3/18 RESULT: ISSUES FOUND'
        Plant  = { }
        Cleanup= { }
    },
    @{
        Name   = 'Section 17 verdict reflects the portproxy finding (verdict unmasking)'
        Tier   = 'required'
        Expect = '\[SECTION 17/18 RESULT: ISSUES FOUND'
        Plant  = { }
        Cleanup= { }
    },
    # ---- False-positive guards: plant a BENIGN state, assert NOT flagged ----
    @{
        Name   = 'ScriptBlockLogging ON -> audit must NOT flag its own AMSI scan'
        Tier   = 'required'
        Invert = $true       # regex must be ABSENT from the report
        # With 4104 logging on, the audit's own script blocks contain the AMSI
        # pattern list; without the self-exclusion filter the CTI section
        # reported the audit itself as an AMSI bypass on every hardened host.
        Expect = '(?im)\[WARNING\]\[T1562\.001\] AMSI bypass attempts'
        Plant  = { New-Item -Path $sblKey -Force | Out-Null
                   Set-ItemProperty -Path $sblKey -Name EnableScriptBlockLogging -Value 1 -Type DWord -Force }
        Cleanup= { Remove-ItemProperty -Path $sblKey -Name EnableScriptBlockLogging -EA SilentlyContinue }
    },
    @{
        Name   = 'Signed service at unquoted spaced path -> must NOT be "no-file"'
        Tier   = 'required'
        Invert = $true
        # The old parser split the unquoted PathName at the first space
        # ("C:\Program"), failed to find the binary, and reported signed
        # vendor services as no-file. (The unquoted path itself is still
        # legitimately listed by the unquoted-service-path check.)
        Expect = ('(?im){0}[^\r\n]*no-file' -f $fpSvcName)
        Plant  = { New-Item -ItemType Directory -Path $fpSvcDir -Force | Out-Null
                   Copy-Item (Join-Path $env:SystemRoot 'System32\cmd.exe') (Join-Path $fpSvcDir 'dzsvc.exe') -Force
                   $r = & sc.exe create $fpSvcName 'binPath=' "$fpSvcDir\dzsvc.exe" 'start=' 'demand'
                   if ($LASTEXITCODE -ne 0) { throw ("sc create failed: {0}" -f ($r -join ' ')) } }
        Cleanup= { & sc.exe delete $fpSvcName | Out-Null
                   Remove-Item -LiteralPath $fpSvcDir -Recurse -Force -EA SilentlyContinue }
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
    # Plant per-case with a catch so one bad plant cannot abort the whole run
    # (and only cases that actually planted get asserted / cleaned up).
    Write-Host "== Planting known-bad artifacts =="
    foreach ($c in $cases) {
        try {
            & $c.Plant
            $c.Planted = $true
            $planted += $c
            Write-Host ("  planted: {0}" -f $c.Name)
        } catch {
            $c.Planted = $false
            Write-Host ("  WARNING: could not plant [{0}] {1}: {2}" -f $c.Tier, $c.Name, $_.Exception.Message)
        }
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

    # REQUIRED: the report filename must carry a real timestamp. On wmic-less
    # systems (Win11 24H2+/Server 2025) the old fallback produced garbage like
    # "SecurityReport_ =_.txt"; the wildcard match above would happily accept
    # that, so assert the shape explicitly. (NODATE_* is the script's
    # last-ditch fallback for a broken PowerShell -- on this runner PowerShell
    # provably works, so NODATE here would also be a regression.)
    $badName = $report.Name -notmatch '^SecurityReport_\d{8}_\d{6}\.txt$'

    # REQUIRED: the exit handler must report a non-zero findings count when
    # findings were planted -- this is the accumulator the section verdicts
    # and exit code now read from.
    $badFind = $text -notmatch '(?m)^\s*FINDINGS COUNTED: [1-9]'

    Write-Host ""
    Write-Host "== Detection scoreboard =="
    $requiredFail = 0
    $promote = 0
    foreach ($c in $cases) {
        if (-not $c.Planted) {
            Write-Host ("  [ SKIP     ] {0}  -- could not be planted (harness issue, not a detection regression)" -f $c.Name)
            continue
        }
        $hit  = [bool]([regex]::IsMatch($text, $c.Expect))
        # Invert cases plant a BENIGN state: the pattern must be ABSENT
        # (false-positive guard); a match means the audit cried wolf.
        $pass = if ($c.Invert) { -not $hit } else { $hit }
        if ($c.Tier -eq 'required') {
            if ($pass) { Write-Host ("  [ OK       ] {0}" -f $c.Name) }
            elseif ($c.Invert) { Write-Host ("  [ REGRESS  ] {0}  -- false positive fired on a benign state" -f $c.Name); $requiredFail++ }
            else       { Write-Host ("  [ REGRESS  ] {0}  -- required detection no longer fires" -f $c.Name); $requiredFail++ }
        } else {
            if ($pass) { Write-Host ("  [ PROMOTE  ] {0}  -- now detected; move to the required tier" -f $c.Name); $promote++ }
            else       { Write-Host ("  [ gap      ] {0}  -- still a known gap (see code review)" -f $c.Name) }
        }
    }

    Write-Host ""
    Write-Host "== Report integrity =="
    if ($badName) { Write-Host ("  [ REGRESS  ] report filename lacks a valid timestamp: '{0}' -- timestamp derivation broke (see the wmic-less fallback fix)" -f $report.Name); $requiredFail++ }
    else          { Write-Host ("  [ OK       ] report filename timestamp is well-formed ({0})" -f $report.Name) }
    if ($badFind) { Write-Host "  [ REGRESS  ] FINDINGS COUNTED missing or zero despite planted findings -- findings accumulator broke"; $requiredFail++ }
    else          { Write-Host "  [ OK       ] exit handler reports a non-zero findings count" }

    # False-positive guard with a dynamic expectation: the summary's firewall
    # verdict must agree with what Get-NetFirewallProfile actually reports.
    # The old netsh text-scrape said "Firewall DISABLED" on any non-English
    # Windows (localized State strings); comparing against ground truth
    # catches any such divergence on whatever state this runner is in.
    Write-Host ""
    Write-Host "== False-positive guards (ground truth) =="
    $fwp = @(Get-NetFirewallProfile -EA SilentlyContinue)
    if ($fwp.Count -gt 0) {
        $fwAllOn = (@($fwp | Where-Object { -not $_.Enabled }).Count -eq 0)
        $saysOn  = [bool]([regex]::IsMatch($text, 'All firewall profiles enabled'))
        $saysOff = [bool]([regex]::IsMatch($text, 'Firewall DISABLED on'))
        if (($fwAllOn -and $saysOn -and -not $saysOff) -or (-not $fwAllOn -and $saysOff -and -not $saysOn)) {
            Write-Host ("  [ OK       ] firewall verdict matches Get-NetFirewallProfile ground truth (all profiles on: {0})" -f $fwAllOn)
        } else {
            Write-Host ("  [ REGRESS  ] firewall verdict disagrees with ground truth (all on: {0}; report says PASS: {1}, CRIT: {2})" -f $fwAllOn, $saysOn, $saysOff)
            $requiredFail++
        }
    } else {
        Write-Host "  [ SKIP     ] Get-NetFirewallProfile unavailable on this host -- consistency check skipped"
    }

    # Exit-code architecture (code-review W1-W3): a planted CRITICAL (WDigest=1)
    # must drive the process exit code to 8. PROMOTED to required 2026-07-18
    # after it fired on CI -- the path is exactly the fragile summary block W3
    # warns about, which is why it needs a tripwire: anyone touching that block
    # and losing CRITICAL propagation fails this job immediately.
    Write-Host ""
    Write-Host "== Exit-code accounting =="
    if ($runExit -eq 8) { Write-Host "  [ OK       ] planted CRITICAL drove the exit code to 8" }
    elseif ($runExit -ne 0 -and $runExit -ne $null) { Write-Host ("  [ REGRESS  ] audit exited {0}, not 8 -- CRITICAL severity was lost on the way to the exit code" -f $runExit); $requiredFail++ }
    else { Write-Host "  [ REGRESS  ] audit exited clean (0) despite planted findings"; $requiredFail++ }

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
