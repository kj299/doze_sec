# noadmin_smoke.ps1 -- run doze_sec_noAdmin.bat as a REAL standard (non-admin)
# user and assert the non-admin contract. The detection harness covers the
# elevated/adaptive path of both bats; this covers the path CI never executed
# before (design memo section 7): IS_ADMIN=0, checks deferred, PARTIAL section
# verdicts, exit-code 6/8 semantics, and the Option B ledger consistency net
# under deferral.
#
# Runs elevated (it creates the user and plants HKLM state); the AUDIT itself
# runs as the standard user via Start-Process -Credential (CreateProcessWithLogonW,
# needs the seclogon service).
#
# Two audit runs:
#   Run 1 (no plant): exit code must honor the partial-audit contract --
#          6 when ledger MAXSEV is not CRITICAL, 8 when it is -- and at least
#          one section must report PARTIAL (deferred checks).
#   Run 2 (WDigest UseLogonCredential=1 planted as admin): HKLM is world-
#          readable, so the NON-ADMIN audit must still detect it, raise
#          CRITICAL|12| in the ledger, and exit 8 (CRITICAL outranks 6).
#
# Windows PowerShell 5.1 compatible. Never touches Userinit/UAC/event logs.

param(
    [string]$BatPath  = '.\doze_sec_noAdmin.bat',
    [string]$UserName = 'dzsmoke',
    [int]$TimeoutSec  = 900
)

$ErrorActionPreference = 'Stop'

# Blast-radius manifest (checked by tests\safety_invariants.ps1): everything
# this smoke test changes on the host, and which risk axes it can touch. A
# plant verb below (New-LocalUser, icacls, Set-Service, WDigest) with no
# matching kind here fails the build.
$Touches = @(
    'account:local user dzsmoke (created for the run, removed in finally; a pre-existing user of that name is REMOVED first)',
    'service:seclogon startup type -> Manual and started (not reverted; Manual is the Windows default)',
    'file:<repo> ACL grant BUILTIN\Users (OI)(CI)RX (not reverted; read/execute on a checkout)',
    'registry:HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential (restored to the prior value in finally)'
)
$Affects = @('defense')

$fail = 0

$bat  = (Resolve-Path -LiteralPath $BatPath).Path
$repo = Split-Path -Parent $bat

function Invoke-NonAdminAudit {
    param([System.Management.Automation.PSCredential]$Cred, [string]$Label)
    $out = Join-Path $env:TEMP ("dz_noadmin_{0}_out.txt" -f $Label)
    $err = Join-Path $env:TEMP ("dz_noadmin_{0}_err.txt" -f $Label)
    Remove-Item $out, $err -Force -EA SilentlyContinue
    # cmd /c "<bat>" <flags>: -noAdmin selects the partial-audit path (without
    # it a non-elevated run aborts FATAL); -dev because CI runners are Server
    # SKUs; -noConsoleLog avoids the tee re-exec so the exit code is direct.
    $p = Start-Process -FilePath $env:ComSpec `
        -ArgumentList '/c', ('"{0}" -noAdmin -dev -sdu -nosrp -noConsoleLog -selftest' -f $bat) `
        -Credential $Cred -LoadUserProfile -WorkingDirectory $repo `
        -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    # Cache the handle NOW: a -PassThru Process object acquires it lazily, and
    # once the process has exited it cannot -- ExitCode then reads as $null.
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        & taskkill /T /F /PID $p.Id 2>$null | Out-Null
        throw ("audit run '{0}' hung past {1}s -- killed" -f $Label, $TimeoutSec)
    }
    return $p.ExitCode
}

function Get-NewestFile {
    param([string]$Dir, [string]$Filter)
    Get-ChildItem -LiteralPath $Dir -Filter $Filter -EA SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Assert {
    param([bool]$Cond, [string]$OkMsg, [string]$FailMsg)
    if ($Cond) { Write-Host ("  [ OK       ] {0}" -f $OkMsg) }
    else       { Write-Host ("  [ REGRESS  ] {0}" -f $FailMsg); $script:fail++ }
}

# Shared ledger-vs-report consistency net (Option B), same rules as the
# detection harness but tolerant of PARTIAL verdicts (deferral is clean).
function Assert-LedgerConsistency {
    param([string]$Text, [string[]]$Ledger, [string]$Label)
    $secBad = 0
    for ($n = 1; $n -le 18; $n++) {
        $inLedger = [bool](@($Ledger | Where-Object { $_ -match ('^(CRITICAL|WARNING)\|{0}\|' -f $n) }).Count)
        $issues = [bool]([regex]::IsMatch($Text, ('\[SECTION {0}/18 RESULT: ISSUES FOUND' -f $n)))
        if ($inLedger -ne $issues) {
            Write-Host ("  [ REGRESS  ] {0}: Section {1} ledger findings={2} but verdict issues={3}" -f $Label, $n, $inLedger, $issues)
            $secBad++
        }
    }
    Assert ($secBad -eq 0) ("{0}: all 18 section verdicts agree with the ledger (PARTIAL counts as clean)" -f $Label) `
                           ("{0}: {1} section verdict(s) diverged from the ledger" -f $Label, $secBad)
    $fcM = [regex]::Match($Text, '(?m)^\s*FINDINGS COUNTED:\s*(\d+)')
    Assert ($fcM.Success -and ([int]$fcM.Groups[1].Value) -eq @($Ledger).Count) `
        ("{0}: FINDINGS COUNTED ({1}) equals the ledger line count" -f $Label, @($Ledger).Count) `
        ("{0}: FINDINGS COUNTED '{1}' != ledger line count {2}" -f $Label, $fcM.Groups[1].Value, @($Ledger).Count)
    $lgMax = 'NONE'
    if (@($Ledger | Where-Object { $_ -like 'CRITICAL|*' }).Count) { $lgMax = 'CRITICAL' }
    elseif (@($Ledger).Count) { $lgMax = 'WARNING' }
    $ftMax = [regex]::Match($Text, '(?m)^\s*LEDGER MAXSEV:\s*(\S+)')
    Assert ($ftMax.Success -and $ftMax.Groups[1].Value -eq $lgMax) `
        ("{0}: footer LEDGER MAXSEV ({1}) matches ledger contents" -f $Label, $lgMax) `
        ("{0}: footer LEDGER MAXSEV '{1}' disagrees with ledger '{2}'" -f $Label, $ftMax.Groups[1].Value, $lgMax)
    Assert (-not ($Text -match 'a raise is missing|an in-section raise is missing')) `
        ("{0}: no ledger-divergence alarm fired" -f $Label) `
        ("{0}: a ledger-divergence alarm fired under non-admin deferral" -f $Label)
    return $lgMax
}

$wdKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$wdPrior = (Get-ItemProperty -LiteralPath $wdKey -Name UseLogonCredential -EA SilentlyContinue).UseLogonCredential
$userCreated = $false
$artDir = Join-Path $repo 'noadmin-smoke-output'

try {
    # CreateProcessWithLogonW is backed by the Secondary Logon service.
    Set-Service seclogon -StartupType Manual -EA SilentlyContinue
    Start-Service seclogon -EA SilentlyContinue

    $pwPlain = 'Dz1!' + [guid]::NewGuid().ToString('N')
    $pw = ConvertTo-SecureString $pwPlain -AsPlainText -Force
    if (Get-LocalUser -Name $UserName -EA SilentlyContinue) { Remove-LocalUser -Name $UserName }
    New-LocalUser -Name $UserName -Password $pw -PasswordNeverExpires -AccountNeverExpires | Out-Null
    Add-LocalGroupMember -Group 'Users' -Member $UserName
    $userCreated = $true
    # BUILTIN\Users (S-1-5-32-545) needs read+execute on the checkout to run
    # the bat and its tools\*.ps1 helpers. Inherited grant at the repo root.
    & icacls $repo /grant '*S-1-5-32-545:(OI)(CI)RX' /Q | Out-Null
    $cred = New-Object System.Management.Automation.PSCredential($UserName, $pw)

    Write-Host ""
    Write-Host "== Run 1: standard user, no plants (partial-audit contract) =="
    $code1 = Invoke-NonAdminAudit -Cred $cred -Label 'run1'
    $sid = (Get-LocalUser -Name $UserName).SID.Value
    $prof = (Get-CimInstance Win32_UserProfile -Filter "SID='$sid'").LocalPath
    if (-not $prof) { throw "no profile materialized for $UserName -- -LoadUserProfile failed" }
    $outDir = Join-Path $prof 'SecurityAudit\selftest'   # -selftest quarantines test output
    $report1 = Get-NewestFile -Dir $outDir -Filter 'SecurityReport_*.txt'
    if (-not $report1) { throw "run 1 produced no report under $outDir (exit $code1)" }
    $text1 = Get-Content -LiteralPath $report1.FullName -Raw
    $ledger1File = Get-NewestFile -Dir $outDir -Filter 'SecurityReport_*.ledger'
    $ledger1 = if ($ledger1File) { @(Get-Content -LiteralPath $ledger1File.FullName -EA SilentlyContinue) } else { @() }

    Assert ($text1 -match '(?m)^\s*Admin\s+:\s+0') `
        'audit really ran non-admin (report says Admin : 0)' `
        'report does not say Admin : 0 -- the run was NOT non-admin; job is testing the wrong path'
    Assert ($text1 -match '\[SECTION \d+/18 RESULT: PARTIAL') `
        'at least one section reports PARTIAL (deferred non-admin checks)' `
        'no PARTIAL section verdict -- the deferral path did not engage'
    $max1 = Assert-LedgerConsistency -Text $text1 -Ledger $ledger1 -Label 'run 1'
    if ($max1 -eq 'CRITICAL') {
        Assert ($code1 -eq 8) 'exit code 8 with an organic CRITICAL (outranks partial-audit 6)' `
                              ("exit code {0} despite ledger CRITICAL (expected 8)" -f $code1)
    } else {
        Assert ($code1 -eq 6) ("exit code 6 (partial audit, MAXSEV={0})" -f $max1) `
                              ("exit code {0} expected 6 for a non-admin run with MAXSEV={1}" -f $code1, $max1)
    }

    Write-Host ""
    Write-Host "== Run 2: standard user, WDigest planted as admin (HKLM-read detection) =="
    if (-not (Test-Path -LiteralPath $wdKey)) { New-Item -Path $wdKey -Force | Out-Null }
    Set-ItemProperty -LiteralPath $wdKey -Name UseLogonCredential -Value 1 -Type DWord
    # Run 1's report stays in place (timestamped filenames never collide);
    # newest-file selection plus the inequality check below pick out run 2's.
    $code2 = Invoke-NonAdminAudit -Cred $cred -Label 'run2'
    $report2 = Get-NewestFile -Dir $outDir -Filter 'SecurityReport_*.txt'
    if (-not $report2) { throw "run 2 produced no report under $outDir (exit $code2)" }
    if ($report2.FullName -eq $report1.FullName) { throw "run 2 produced no NEW report (newest is still run 1's, exit $code2)" }
    $text2 = Get-Content -LiteralPath $report2.FullName -Raw
    $ledger2File = Get-NewestFile -Dir $outDir -Filter 'SecurityReport_*.ledger'
    $ledger2 = if ($ledger2File) { @(Get-Content -LiteralPath $ledger2File.FullName -EA SilentlyContinue) } else { @() }

    Assert ($text2 -match 'WDigest ENABLED') `
        'planted WDigest detected by the NON-ADMIN audit (HKLM is world-readable)' `
        'planted WDigest not detected without admin -- non-admin detection regressed'
    Assert ([bool](@($ledger2 | Where-Object { $_ -like 'CRITICAL|12|*' }).Count)) `
        'ledger carries CRITICAL|12| for the planted WDigest' `
        'no CRITICAL|12| ledger entry for the planted WDigest'
    Assert ($code2 -eq 8) 'exit code 8 (CRITICAL outranks partial-audit 6)' `
                          ("exit code {0} expected 8 with a planted CRITICAL" -f $code2)
    [void](Assert-LedgerConsistency -Text $text2 -Ledger $ledger2 -Label 'run 2')

    # Stage artifacts where the workflow can upload them.
    New-Item -ItemType Directory -Path $artDir -Force | Out-Null
    Copy-Item (Join-Path $outDir '*') $artDir -Force -EA SilentlyContinue
}
finally {
    if ($null -eq $wdPrior) {
        Remove-ItemProperty -LiteralPath $wdKey -Name UseLogonCredential -EA SilentlyContinue
    } else {
        Set-ItemProperty -LiteralPath $wdKey -Name UseLogonCredential -Value $wdPrior -Type DWord -EA SilentlyContinue
    }
    if ($userCreated) { Remove-LocalUser -Name $UserName -EA SilentlyContinue }
}

Write-Host ""
if ($fail -gt 0) { Write-Host ("FAIL: {0} non-admin contract assertion(s) regressed." -f $fail); exit 1 }
Write-Host "OK: non-admin contract holds (deferral, detection without admin, exit codes, ledger consistency)."
exit 0
