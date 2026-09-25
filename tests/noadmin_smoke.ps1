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
#   Run 1 (no plant) goes THROUGH tests\field_test.ps1, launched as the standard
#          user -- the script a person runs on their own machine, on the path
#          a standard user takes. CI had only ever run field_test elevated, and
#          the script's own standard-user path carried two bugs no runner had
#          seen: it demanded the read-only restore-point skip that the token
#          can never reach (FAIL on every standard-user field run), and an
#          explicit -BatPath doze_sec_noAdmin.bat dropped -noAdmin. field_test
#          must exit 0 and print its proof lines; then the report it produced
#          is held to the contract below. Its exit code must honor the partial-audit contract as the
#          bat defines it -- 8 when ledger MAXSEV is CRITICAL; else 6 when
#          a reboot is pending (4, escalated); else 2 when it is WARNING (the
#          ledger-derived verdict is never discarded); else 6 (nothing
#          raised, escalated from 0) -- and at least one section must report
#          PARTIAL (deferred checks). Every ledger row must have a printed
#          [CRITICAL]/[WARNING] line in its section: a check the token cannot
#          perform is DEFERRED, never a finding.
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
    'registry:HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential (restored to the prior value in finally)',
    'service:dzsmoke_dacl (a demand-start service whose DACL denies BUILTIN\Users, never started; deleted in finally)',
    'registry:HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dzsmoke_ifeo.exe (an empty IFEO subkey whose DACL denies BUILTIN\Users ReadKey; no Debugger value; deleted in finally)'
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

# tests\field_test.ps1 as the standard user: -readonly, no -selftest (a real
# run, as a person would make it), output under the user's own SecurityAudit.
function Invoke-NonAdminFieldTest {
    param([System.Management.Automation.PSCredential]$Cred, [string]$Label)
    $out = Join-Path $env:TEMP ("dz_noadmin_{0}_ft_out.txt" -f $Label)
    $err = Join-Path $env:TEMP ("dz_noadmin_{0}_ft_err.txt" -f $Label)
    Remove-Item $out, $err -Force -EA SilentlyContinue
    $ft = Join-Path $repo 'tests\field_test.ps1'
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $p = Start-Process -FilePath $ps `
        -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $ft), '-NoConsoleLog' `
        -Credential $Cred -LoadUserProfile -WorkingDirectory $repo `
        -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        & taskkill /T /F /PID $p.Id 2>$null | Out-Null
        throw ("field_test run '{0}' hung past {1}s -- killed" -f $Label, $TimeoutSec)
    }
    $text = ''
    if (Test-Path -LiteralPath $out) { $text = [IO.File]::ReadAllText($out) }
    if (Test-Path -LiteralPath $err) { $text += "`n" + [IO.File]::ReadAllText($err) }
    return @{ Exit = $p.ExitCode; Out = $text }
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
    # THE INVERSE of "printed but not raised": every ledger row must be
    # visible in its section as a [CRITICAL]/[WARNING] line. The standard-user
    # field run 2026-09-24 21:03 carried two rows -- "records missing with no
    # clear event" and "rootkit indicator" -- raised from checks that printed
    # only [SKIPPED] (needs admin). A check the token cannot perform is a
    # deferral, never a finding; a row nobody can see is a finding the reader
    # cannot act on. Section bodies are walked from the line-anchored banner
    # to the verdict, so the TOP FINDINGS block cannot satisfy this.
    $printed = @{}
    $cur = 0
    foreach ($ln in ($Text -split "\r?\n")) {
        $b = [regex]::Match($ln, '^\s*\[(\d{1,2})/18\]\s')
        if ($b.Success) { $cur = [int]$b.Groups[1].Value; continue }
        if ($cur -eq 0) { continue }
        if ($ln -match '^\s*\[SECTION (\d{1,2})/18 RESULT:') { $cur = 0; continue }
        if ($ln -match '^\s*\[(CRITICAL|WARNING)\]') { $printed[[string]$cur] = $true }
    }
    $unseen = @()
    foreach ($row in @($Ledger)) {
        $f = $row.Split('|')
        if ($f.Length -lt 3) { continue }
        if ($f[0] -notmatch '^(CRITICAL|WARNING)$' -or $f[1] -notmatch '^\d{1,2}$') { continue }
        if (-not $printed.ContainsKey($f[1])) { $unseen += $row }
    }
    Assert ($unseen.Count -eq 0) ("{0}: every ledger row has a printed [CRITICAL]/[WARNING] line in its section" -f $Label) `
                                ("{0}: {1} ledger row(s) raised from a check that printed no finding line (a deferral or a [SKIPPED] reported as a finding): {2}" -f $Label, $unseen.Count, ($unseen -join ' ; '))
    return $lgMax
}

$wdKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$wdPrior = (Get-ItemProperty -LiteralPath $wdKey -Name UseLogonCredential -EA SilentlyContinue).UseLogonCredential
$userCreated = $false
$daclCreated = $false
$ifeoCreated = $false
$ifeoKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dzsmoke_ifeo.exe'
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

    # A service whose DACL denies BUILTIN\Users is in the registry and absent
    # from Get-Service and Win32_Service for a standard user -- the rootkit
    # shape. Windows 11's own ZTHelper ships this way, and the first
    # standard-user field run (2026-09-24) reported it as CRITICAL, exit 8.
    # Never started; demand-start; deleted in finally.
    & sc.exe create dzsmoke_dacl binPath= 'C:\Windows\System32\cmd.exe /c rem dz_selftest_dacl' start= demand | Out-Null
    & sc.exe sdset dzsmoke_dacl 'D:(D;;CCLCSWRPWPDTLOCRRC;;;BU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)' | Out-Null
    $daclCreated = $true

    # An IFEO subkey a standard user cannot open. persistence_eval enumerated
    # with -EA Stop, so one such subkey lost the whole Debugger-hijack check
    # ([SKIPPED]) on both standard-user field runs of 2026-09-24. No Debugger
    # value: the plant is the ACL, not a hijack. Removed in finally.
    New-Item -Path $ifeoKey -Force | Out-Null
    $ifeoAcl = Get-Acl -Path $ifeoKey
    $ifeoAcl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule('BUILTIN\Users', 'ReadKey', 'Deny')))
    Set-Acl -Path $ifeoKey -AclObject $ifeoAcl
    $ifeoCreated = $true

    Write-Host ""
    Write-Host "== Run 1: standard user, no plants, through tests\field_test.ps1 (the script a person runs) =="
    $ft1 = Invoke-NonAdminFieldTest -Cred $cred -Label 'run1'
    $ftLines = @($ft1.Out -split "\r?\n")
    foreach ($ln in $ftLines) { if ($ln -match '^\s*(\[OK     \]|\[FAIL   \]|\[SKIP   \]|\[ADVISE \]|== |FAIL:|OK:)') { Write-Host ("    ft| " + $ln.TrimEnd()) } }
    $m = [regex]::Match($ft1.Out, '== Audit finished: exit code (\d+)')
    if (-not $m.Success) { throw ("field_test did not report the audit's exit code (field_test exit {0}); output starts: {1}" -f $ft1.Exit, (($ftLines | Select-Object -First 20) -join ' | ')) }
    $code1 = [int]$m.Groups[1].Value
    $sid = (Get-LocalUser -Name $UserName).SID.Value
    $prof = (Get-CimInstance Win32_UserProfile -Filter "SID='$sid'").LocalPath
    if (-not $prof) { throw "no profile materialized for $UserName -- -LoadUserProfile failed" }
    $outDir1 = Join-Path $prof 'SecurityAudit'           # field_test's real run (no -selftest): the path a person takes
    $outDir  = Join-Path $prof 'SecurityAudit\selftest'  # run 2 plants, so it is quarantined
    $report1 = Get-NewestFile -Dir $outDir1 -Filter 'SecurityReport_*.txt'
    if (-not $report1) { throw "run 1 produced no report under $outDir1 (audit exit $code1, field_test exit $($ft1.Exit))" }
    $text1 = Get-Content -LiteralPath $report1.FullName -Raw
    $ledger1File = Get-NewestFile -Dir $outDir1 -Filter 'SecurityReport_*.ledger'
    $ledger1 = if ($ledger1File) { @(Get-Content -LiteralPath $ledger1File.FullName -EA SilentlyContinue) } else { @() }

    # field_test's own verdict on the standard-user path: exit 0, no [FAIL]
    # line, and its proof lines actually executed (not skipped).
    Assert ($ft1.Exit -eq 0) 'field_test.ps1 (the script a person runs) passed on the standard-user path' `
                             ("field_test.ps1 exited {0} on the standard-user path (see the ft| lines above)" -f $ft1.Exit)
    Assert ($ft1.Out -notmatch '\[FAIL') 'field_test printed no [FAIL] line' 'field_test printed a [FAIL] line (see the ft| lines above)'
    foreach ($must in @('RunOnce resume key: absent after the run', 'report carries the READ-ONLY banner', 'report carries no TEST RUN banner',
                        'read-only skip declared: RunOnce resume key not created', 'read-only skip declared: restore point deferred (needs admin)',
                        'no known benign look-alike is reported above')) {
        Assert ($ft1.Out -match [regex]::Escape($must)) ("field_test proof line executed: {0}" -f $must) ("field_test output lacks the proof line: {0}" -f $must)
    }

    Assert ($text1 -match '(?m)^\s*Admin\s+:\s+0') `
        'audit really ran non-admin (report says Admin : 0)' `
        'report does not say Admin : 0 -- the run was NOT non-admin; job is testing the wrong path'
    Assert ($text1 -match '\[SECTION \d+/18 RESULT: PARTIAL') `
        'at least one section reports PARTIAL (deferred non-admin checks)' `
        'no PARTIAL section verdict -- the deferral path did not engage'
    # The DACL-restricted service: named as not enumerable, never CRITICAL.
    Assert ($text1 -match '\[INFO\] \d+ service\(s\) registered but not enumerable from a standard-user token: [^\r\n]*dzsmoke_dacl') `
        'a DACL-restricted service is stated as not enumerable from this token, by name' `
        'the DACL-restricted service was not reported as not-enumerable (silently cleared, or absent)'
    Assert ($text1 -notmatch '\[CRITICAL\] Service present in the registry') `
        'no rootkit CRITICAL for a service the token merely cannot enumerate' `
        'a DACL-restricted service was reported as a hidden service (CRITICAL) on a standard-user run'
    # Section 16 declares what it could not do, and the coverage block does
    # not certify auditing it never checked.
    Assert ($text1 -match 'DEFERRED - ADMIN REQUIRED\] auditpol') `
        'audit-policy check declared DEFERRED (auditpol needs admin)' `
        'audit-policy check skipped silently on the standard-user path'
    Assert ($text1 -match 'Audit visibility\s+: NOT VERIFIED') `
        'coverage block reads Audit visibility : NOT VERIFIED' `
        'coverage block certifies audit visibility for a check that did not run'
    Assert ($text1 -match 'record numbering is consistent') `
        'the event-log gap check ran unelevated (readable logs graded)' `
        'the event-log gap check did not run on the standard-user path'
    # A check the token cannot perform is DEFERRED -- named, counted, never a
    # ledger row. The field run raised "records missing with no clear event"
    # (Section 16) and "rootkit indicator" (Section 17) for the Security log
    # and the TaskCache a standard user cannot read, with nothing printed.
    Assert ($text1 -match '\[DEFERRED - ADMIN REQUIRED\] Log ''Security'' needs administrator rights') `
        'the Security log is declared DEFERRED on the standard-user path, not skipped-and-raised' `
        'the Security log was not declared DEFERRED (it was skipped silently, or raised as a finding)'
    Assert ($text1 -match '\[DEFERRED - ADMIN REQUIRED\] TaskCache registry or Task Scheduler not readable from a standard-user token') `
        'the TaskCache hidden-task check is declared DEFERRED on the standard-user path' `
        'the TaskCache hidden-task check was not declared DEFERRED (skipped silently, or raised as a rootkit indicator)'
    Assert (-not @($ledger1 | Where-Object { $_ -match '^\w+\|16\|T1070\.001\|' }).Count) `
        'no T1070.001 row for a Security log the token cannot list' `
        ("a T1070.001 row was raised on a standard-user run with nothing printed: {0}" -f (($ledger1 | Where-Object { $_ -match '\|16\|T1070\.001\|' }) -join ' ; '))
    Assert (-not @($ledger1 | Where-Object { $_ -match '^\w+\|17\|T1014\|' }).Count) `
        'no T1014 row for a TaskCache the token cannot read' `
        ("a T1014 row was raised on a standard-user run with nothing printed: {0}" -f (($ledger1 | Where-Object { $_ -match '\|17\|T1014\|' }) -join ' ; '))
    # One restricted IFEO subkey must not lose the check: the readable
    # subkeys are graded and the unreadable one is named.
    Assert ($text1 -notmatch '\[SKIPPED\] IFEO enumeration failed') `
        'the IFEO Debugger-hijack check still ran with one subkey unreadable' `
        'one unreadable IFEO subkey lost the whole Debugger-hijack check ([SKIPPED])'
    Assert ($text1 -match '\[INFO\] \d+ IFEO entr(y|ies) not readable from this token: [^\r\n]*dzsmoke_ifeo\.exe') `
        'the unreadable IFEO subkey is named as not graded from this token' `
        'the unreadable IFEO subkey was not named (silently cleared, or absent)'
    $max1 = Assert-LedgerConsistency -Text $text1 -Ledger $ledger1 -Label 'run 1'
    # The bat escalates to 6 ONLY from 0 and 4: 2 is the ledger-derived
    # "findings were raised" verdict and is never discarded (its rem block
    # says why). This branch used to expect 6 for WARNING and had never run:
    # on every main run the runner carried a DACL-restricted service that the
    # pre-#218 probe reported as a hidden service, so run 1 always read
    # "organic CRITICAL", exit 8, and the branch that accepted it accepted
    # the false positive. A clean runner's expected MAXSEV is a claim to pin,
    # not a variable to branch on: no plant means no CRITICAL.
    Assert ($max1 -ne 'CRITICAL') 'run 1 (no plant) raised no CRITICAL on a clean runner' `
                                  ("run 1 ledger MAXSEV is CRITICAL with nothing planted -- a false positive on a clean runner: {0}" -f (($ledger1 | Where-Object { $_ -like 'CRITICAL|*' }) -join ' ; '))
    # The bat's rule, whole: a CRITICAL raise sets 8; a pending reboot sets 4
    # and a WARNING raise only lifts a code that is still below 2, so the
    # reboot wins and non-admin then turns 4 into 6; otherwise WARNING is 2
    # and nothing raised is 6. The owner's laptop had a reboot pending on the
    # 21:03 field run and read 6 with MAXSEV WARNING -- correct per the bat,
    # and not what the first version of this rule expected.
    $reboot1 = [bool](@($ledger1 | Where-Object { $_ -match '^\w+\|1\|REBOOT\|' }).Count)
    $want1 = if ($max1 -eq 'CRITICAL') { 8 } elseif ($reboot1) { 6 } elseif ($max1 -eq 'WARNING') { 2 } else { 6 }
    Assert ($code1 -eq $want1) ("exit code {0} (bat rule: CRITICAL->8, reboot pending->6, WARNING->2, nothing raised->6; MAXSEV={1}, reboot={2})" -f $want1, $max1, $reboot1) `
                               ("exit code {0} expected {1} for a non-admin run with MAXSEV={2}, reboot pending={3}" -f $code1, $want1, $max1, $reboot1)

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

    # Stage artifacts where the workflow can upload them: run 1 (field_test,
    # real-run directory), run 2 (quarantined), and field_test's own output.
    New-Item -ItemType Directory -Path $artDir -Force | Out-Null
    Copy-Item (Join-Path $outDir1 'SecurityReport_*') $artDir -Force -EA SilentlyContinue
    Copy-Item (Join-Path $outDir '*') $artDir -Force -EA SilentlyContinue
    Copy-Item (Join-Path $env:TEMP 'dz_noadmin_run1_ft_out.txt') (Join-Path $artDir 'field_test_run1_output.txt') -Force -EA SilentlyContinue
}
finally {
    if ($null -eq $wdPrior) {
        Remove-ItemProperty -LiteralPath $wdKey -Name UseLogonCredential -EA SilentlyContinue
    } else {
        Set-ItemProperty -LiteralPath $wdKey -Name UseLogonCredential -Value $wdPrior -Type DWord -EA SilentlyContinue
    }
    if ($userCreated) { Remove-LocalUser -Name $UserName -EA SilentlyContinue }
    if ($daclCreated) { & sc.exe delete dzsmoke_dacl 2>&1 | Out-Null }
    if ($ifeoCreated) { Remove-Item -Path $ifeoKey -Recurse -Force -EA SilentlyContinue }
}

Write-Host ""
if ($fail -gt 0) { Write-Host ("FAIL: {0} non-admin contract assertion(s) regressed." -f $fail); exit 1 }
Write-Host "OK: non-admin contract holds (deferral, detection without admin, exit codes, ledger consistency)."
exit 0
