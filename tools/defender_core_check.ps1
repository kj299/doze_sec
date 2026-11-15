# defender_core_check.ps1 -- Section 9: is Defender's core protection on, and if
# not, is that because another antivirus owns protection (passive mode)?
#
# Extracted from the staged block that lived inline in both bats. The block
# read two live objects, Get-MpComputerStatus and Get-MpPreference, and its
# passive-mode judgement was the last benign twin in tests\benign_corpus.txt
# with no test at all ([defender-passive-mode]): a second registered antivirus
# cannot be installed on a runner, and Microsoft documents that "Microsoft
# Defender Antivirus can run in passive mode only when the device is onboarded
# to Microsoft Defender for Endpoint", so the ForceDefenderPassiveMode policy
# value does not flip an un-onboarded runner either. The judgement now lives in
# a pure function, Get-DefenderCoreReport, that a self-test drives with injected
# status objects.
#
# THE RULE. AMRunningMode is Defender's own statement of who is in control:
# 'Normal' (active), 'Passive Mode' and 'EDR Block Mode' (another product is
# the primary antivirus; Defender for Endpoint onboarded), 'SxS Passive Mode'
# (a client with a third-party antivirus, limited periodic scanning). Anything
# that is not 'Normal' -- and is not EMPTY -- means Defender's own real-time
# and antivirus flags are EXPECTED to read off, so those two CRITICALs are
# suppressed and an [INFO] line says why. An empty mode is NOT passive: no
# answer is not "another product has it", so the CRITICALs still fire (fail
# closed). The explicit DisableRealtimeMonitoring flag, tamper protection,
# signature age and the other Get-MpPreference flags are graded whatever the
# mode: passive mode explains the flags reading off, not a policy that turned
# them off.
#
# Output goes to the report; the highest severity goes to the marker
# dz_defcore.txt (the bat raises it into the ledger), and one line goes to
# the state file for the dashboard tiles:
#   <mode>|<realtime 0/1>|<graded 0/1>|<tamper 0/1>|<signature age days, -1 unknown>
# -- the tile states the verdict this section reached instead of calling
# Get-MpComputerStatus a second time (a tile that re-measures is a second
# opinion, not a summary; the old tile had no passive handling at all and
# read CRIT on a passive-mode machine while this section printed INFO).
#
# Usage:
#   powershell -File tools\defender_core_check.ps1 [-MarkerDir <dir>] [-StateFile <path>]
#   powershell -File tools\defender_core_check.ps1 -SelfTest   (no Defender calls)
#
# Windows PowerShell 5.1 compatible; pure ASCII.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    # 1/0 from the caller, or -1: ask the token. A query refused to a
    # standard-user token is a deferral; elevated, the same refusal is a gap.
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_defcore_state.txt' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function Get-MaxSev {
    param([string]$A, [string]$B)
    $rank = @{ 'OK' = 0; 'WARNING' = 1; 'CRITICAL' = 2 }
    if ($rank[$B] -gt $rank[$A]) { return $B }
    return $A
}

# The state line the dashboard reads. The mode becomes part of an `echo` into
# the bat's staged PowerShell, so it is reduced to letters and spaces and capped.
function Get-DefenderStateLine {
    param([string]$Mode, [bool]$RealTime, [bool]$Graded, [bool]$Tamper = $false, [int]$SigAgeDays = -1)
    $m = ($Mode -replace '[^A-Za-z ]', '').Trim()
    if ($m.Length -gt 32) { $m = $m.Substring(0, 32) }
    if (-not $m) { $m = 'unknown' }
    # Five fields, every one always present (cmd's for /f leaves the literal
    # token text in a variable when a field is missing): mode | real-time 0/1 |
    # graded 0/1 | tamper protection 0/1 | signature age in whole days, -1 when
    # Defender did not report one.
    return ('{0}|{1}|{2}|{3}|{4}' -f $m, $(if ($RealTime) { '1' } else { '0' }), $(if ($Graded) { '1' } else { '0' }), $(if ($Tamper) { '1' } else { '0' }), $SigAgeDays)
}

# PURE. One Defender query that did not answer. A standard-user token that was
# DENIED is the token's limit, not the machine's: a deferral, counted. Any
# other failure is a raised gap -- unless Windows Security Center names another
# enabled antivirus, which is the documented reason Defender's own interface
# can be absent: then the line says so as [INFO]. A query that could not be
# made is never [OK] and never [SKIPPED]-and-silent.
# $Av: @{ Asked = <Security Center answered>; Names = <other ENABLED antivirus> },
# or $null. "Could not be asked" and "names none" are worded apart: Windows
# Server has no Security Center, and saying it named nothing would be untrue.
# Returns @{ Line; Gap; Deferred; Reason = deferred|otherav|gap }.
function Get-DefenderQueryFailure {
    param([string]$Query, [string]$What, [string]$Err, [bool]$Denied, [bool]$IsElevated, $Av)
    $e = (([string]$Err) -replace '[\x00-\x1F\x7F]', '?'); if ($e.Length -gt 200) { $e = $e.Substring(0, 200) + '...' }
    if ($Denied -and -not $IsElevated) {
        return @{ Line = ('[DEFERRED - ADMIN REQUIRED] ' + $Query + ' was refused to this standard-user token -- ' + $What + ' not read; an audit run as administrator reads it.'); Gap = $false; Deferred = 1; Reason = 'deferred' }
    }
    $names = @(); $asked = $false
    if ($Av) { $asked = [bool]$Av.Asked; $names = @($Av.Names | Where-Object { [string]$_ }) }
    if ($names.Count -gt 0) {
        return @{ Line = ('[INFO] ' + $Query + ' did not answer (' + $e + '); Windows Security Center names ' + (($names | ForEach-Object { (([string]$_) -replace '[\x00-\x1F\x7F]', '?') }) -join ', ') + ' as the enabled antivirus on this PC, so Defender''s own ' + $What + ' is not the protection in force. Verify that product is running and current.'); Gap = $false; Deferred = 0; Reason = 'otherav' }
    }
    $sc = $(if ($asked) { 'Windows Security Center names no other enabled antivirus' } else { 'Windows Security Center could not be asked (it is absent on Windows Server), so no other antivirus is known' })
    return @{ Line = ('[WARNING] Defender ' + $What + ' check NOT performed -- ' + $Query + ' failed (' + $e + ') and ' + $sc + ', so Defender switched off would go unseen (T1562.001).'); Gap = $true; Deferred = 0; Reason = 'gap' }
}

# Live. Was this exception an access refusal? Walks the inner exceptions:
# UnauthorizedAccessException, a CIM AccessDenied, or the Win32/WMI access
# HRESULTs (0x80070005, 0x80041003). The message text is localized and is
# never read.
function Test-DefenderAccessDenied {
    param($Exception)
    $x = $Exception
    for ($i = 0; $x -and $i -lt 6; $i++) {
        if ($x -is [System.UnauthorizedAccessException]) { return $true }
        try { if ([string]$x.NativeErrorCode -eq 'AccessDenied') { return $true } } catch {}
        try { if ($x.HResult -eq -2147024891 -or $x.HResult -eq -2147217405) { return $true } } catch {}
        try { if ([string]$x.ErrorData.CimClass.CimClassName -eq 'MSFT_WmiError' -and [int]$x.ErrorData.CimInstanceProperties['error_Code'].Value -eq -2147024891) { return $true } } catch {}
        $x = $x.InnerException
    }
    return $false
}

# Live. Other ENABLED antivirus products Windows Security Center knows of:
# @{ Asked; Names }. Asked is $false when Security Center could not be asked
# (it is absent on Windows Server). The state bits 12-15 are 1 when the
# product's protection is on (0 off, 2 snoozed, 3 expired: not counted).
function Get-OtherAntivirus {
    try {
        $p = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
        $n = @($p | Where-Object { [string]$_.displayName -notmatch 'Windows Defender|Microsoft Defender' -and ((([int]$_.productState) -band 0xF000) -eq 0x1000) } | ForEach-Object { [string]$_.displayName })
        return @{ Asked = $true; Names = $n }
    } catch { return @{ Asked = $false; Names = @() } }
}

# Pure. $Status / $Pref are whatever Get-MpComputerStatus / Get-MpPreference
# returned (or any object with the same property names); $StatusOk / $PrefOk
# say whether the call succeeded at all. Returns the report lines, the
# severity to raise, and what the tile needs.
function Get-DefenderCoreReport {
    param(
        [bool]$StatusOk, $Status,
        [bool]$PrefOk, $Pref,
        [datetime]$Now = (Get-Date),
        [string]$StatusErr = '', [bool]$StatusDenied = $false,
        [string]$PrefErr = '', [bool]$PrefDenied = $false,
        [bool]$IsElevated = $true, $OtherAv = $null
    )
    $gap = $false; $gapStatus = $false; $gapPref = $false; $deferred = 0; $whyStatus = 'ok'; $whyPref = 'ok'
    $out = New-Object System.Collections.Generic.List[string]
    $sev = 'OK'
    $mode = ''
    $passive = $false
    $rt = $false
    $tamper = $false
    $ageDays = -1
    $findings = 0
    if ($StatusOk) {
        try { $mode = [string]$Status.AMRunningMode } catch { $mode = '' }
        # Not 'Normal' AND not empty: another product is in control. Empty is
        # no answer, and no answer is not passive mode.
        $passive = ($mode -ne '' -and $mode -notmatch 'Normal')
        $rt = [bool]$Status.RealTimeProtectionEnabled
        if ($passive) {
            [void]$out.Add('[INFO] Defender is running in ' + $mode + ' -- another antivirus product is in control, so Defender own real-time flags are EXPECTED to read as disabled. Verify that other product is running and current.')
        }
        if (-not $Status.AMServiceEnabled) {
            [void]$out.Add('[WARNING] Defender antimalware service is not enabled (T1562.001).'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
        }
        if (-not $passive) {
            if (-not $Status.RealTimeProtectionEnabled) {
                [void]$out.Add('[CRITICAL] Defender real-time protection is OFF (T1562.001) -- files are not scanned as they are written or run. Fix: Set-MpPreference -DisableRealtimeMonitoring $false'); $sev = Get-MaxSev $sev 'CRITICAL'; $findings++
            }
            if (-not $Status.AntivirusEnabled) {
                [void]$out.Add('[CRITICAL] Defender antivirus is OFF (T1562.001) and no other AV reported control of this machine.'); $sev = Get-MaxSev $sev 'CRITICAL'; $findings++
            }
            if (-not $Status.AntispywareEnabled) {
                [void]$out.Add('[WARNING] Defender antispyware protection is off.'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
            }
            if (-not $Status.OnAccessProtectionEnabled) {
                [void]$out.Add('[WARNING] Defender on-access protection is off -- files are not scanned when opened.'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
            }
        }
        $tamper = [bool]$Status.IsTamperProtected
        if (-not $Status.IsTamperProtected) {
            [void]$out.Add('[WARNING] Tamper Protection is OFF -- an attacker who gains admin can silently disable Defender and its logging. Fix: Windows Security > Virus & threat protection > Manage settings > Tamper Protection On'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
        }
        $age = $null
        try { $age = ($Now - [datetime]$Status.AntivirusSignatureLastUpdated).TotalDays } catch { $age = $null }
        if ($null -ne $age) { $ageDays = [int][math]::Floor([double]$age); if ($ageDays -lt 0) { $ageDays = 0 } }
        if ($null -ne $age -and $age -gt 7) {
            [void]$out.Add('[WARNING] Defender signatures are ' + [int]$age + ' day(s) old -- updates are not arriving, which is itself a tampering indicator.'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
        }
    } else {
        $f = Get-DefenderQueryFailure -Query 'Get-MpComputerStatus' -What 'core status (real-time, antivirus, tamper protection, signatures)' -Err $StatusErr -Denied $StatusDenied -IsElevated $IsElevated -Av $OtherAv
        [void]$out.Add($f.Line); if ($f.Gap) { $gap = $true; $gapStatus = $true }; $deferred += [int]$f.Deferred; $whyStatus = [string]$f.Reason
    }
    if ($PrefOk) {
        if ($Pref.DisableRealtimeMonitoring) {
            [void]$out.Add('[CRITICAL] DisableRealtimeMonitoring is SET (T1562.001) -- real-time monitoring was explicitly turned off.'); $sev = Get-MaxSev $sev 'CRITICAL'; $findings++
        }
        if ($Pref.DisableBehaviorMonitoring) {
            [void]$out.Add('[WARNING] DisableBehaviorMonitoring is set -- behavioural detection is off.'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
        }
        if ($Pref.DisableScriptScanning) {
            [void]$out.Add('[WARNING] DisableScriptScanning is set -- malicious scripts are not scanned.'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
        }
        if ($Pref.DisableIOAVProtection) {
            [void]$out.Add('[WARNING] DisableIOAVProtection is set -- downloaded files are not scanned.'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
        }
        if ($Pref.DisableBlockAtFirstSeen) {
            [void]$out.Add('[WARNING] DisableBlockAtFirstSeen is set -- cloud first-sight blocking is off.'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
        }
    } else {
        $f = Get-DefenderQueryFailure -Query 'Get-MpPreference' -What 'disable-flags' -Err $PrefErr -Denied $PrefDenied -IsElevated $IsElevated -Av $OtherAv
        [void]$out.Add($f.Line); if ($f.Gap) { $gap = $true; $gapPref = $true }; $deferred += [int]$f.Deferred; $whyPref = [string]$f.Reason
    }
    if ($StatusOk -and $PrefOk -and $findings -eq 0) {
        if ($passive) {
            [void]$out.Add('[OK] Defender itself is tamper-protected, current and not policy-disabled; protection belongs to the other product above.')
        } else {
            [void]$out.Add('[OK] Defender core protection on: real-time, antivirus, on-access and tamper protection enabled; signatures current; no disable flags set.')
        }
    }
    return @{ Lines = @($out.ToArray()); Sev = $sev; Gap = $gap; GapStatus = $gapStatus; GapPref = $gapPref; Why = ($whyStatus + '|' + $whyPref); Deferred = $deferred; Mode = $mode; Passive = $passive; RealTime = $rt; Graded = $StatusOk; State = (Get-DefenderStateLine -Mode $mode -RealTime $rt -Graded $StatusOk -Tamper $tamper -SigAgeDays $ageDays) }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $now = Get-Date '2026-09-27'
    function St { param([string]$Mode = 'Normal', [bool]$Rt = $true, [bool]$Av = $true, [bool]$As = $true, [bool]$Oa = $true, [bool]$Tp = $true, [bool]$Svc = $true, [int]$AgeDays = 1)
        return [pscustomobject]@{ AMRunningMode = $Mode; RealTimeProtectionEnabled = $Rt; AntivirusEnabled = $Av; AntispywareEnabled = $As; OnAccessProtectionEnabled = $Oa; IsTamperProtected = $Tp; AMServiceEnabled = $Svc; AntivirusSignatureLastUpdated = $now.AddDays(-$AgeDays) }
    }
    function Pr { param([bool]$Rtm = $false, [bool]$Bm = $false, [bool]$Ss = $false, [bool]$Ioav = $false, [bool]$Bafs = $false)
        return [pscustomobject]@{ DisableRealtimeMonitoring = $Rtm; DisableBehaviorMonitoring = $Bm; DisableScriptScanning = $Ss; DisableIOAVProtection = $Ioav; DisableBlockAtFirstSeen = $Bafs }
    }
    $j = { param($r) ($r.Lines -join "`n") }

    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -Rt $false -Av $false) -PrefOk $true -Pref (Pr) -Now $now
    T 'Normal mode with real-time OFF: CRITICAL, names T1562.001 and the fix' ($r.Sev -eq 'CRITICAL' -and (& $j $r) -match '\[CRITICAL\] Defender real-time protection is OFF \(T1562.001\).*Set-MpPreference -DisableRealtimeMonitoring \$false' -and (& $j $r) -match '\[CRITICAL\] Defender antivirus is OFF') (& $j $r)
    foreach ($m in 'Passive Mode', 'EDR Block Mode', 'SxS Passive Mode') {
        $r = Get-DefenderCoreReport -StatusOk $true -Status (St -Mode $m -Rt $false -Av $false -As $false -Oa $false) -PrefOk $true -Pref (Pr) -Now $now
        T ("{0} with real-time OFF: INFO 'another antivirus product is in control', no CRITICAL, no WARNING for the flags Defender is expected to read off" -f $m) ($r.Passive -and $r.Sev -eq 'OK' -and (& $j $r) -match ('\[INFO\] Defender is running in ' + [regex]::Escape($m) + ' -- another antivirus product is in control') -and (& $j $r) -notmatch '\[CRITICAL\]' -and (& $j $r) -notmatch '\[WARNING\]') (& $j $r)
    }
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -Mode '' -Rt $false) -PrefOk $true -Pref (Pr) -Now $now
    T 'EMPTY mode with real-time OFF is not passive: CRITICAL (no answer is not "another product has it")' ((-not $r.Passive) -and $r.Sev -eq 'CRITICAL' -and (& $j $r) -notmatch 'another antivirus product') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -Mode 'Passive Mode' -Rt $false) -PrefOk $true -Pref (Pr -Rtm $true) -Now $now
    T 'passive mode does not excuse an explicit DisableRealtimeMonitoring policy: still CRITICAL' ($r.Sev -eq 'CRITICAL' -and (& $j $r) -match '\[CRITICAL\] DisableRealtimeMonitoring is SET') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -Mode 'Passive Mode' -Rt $false -Tp $false) -PrefOk $true -Pref (Pr) -Now $now
    T 'passive mode with Tamper Protection OFF: WARNING (tamper protection is graded whatever the mode)' ($r.Sev -eq 'WARNING' -and (& $j $r) -match '\[WARNING\] Tamper Protection is OFF') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -AgeDays 9) -PrefOk $true -Pref (Pr) -Now $now
    T 'signatures 9 days old: WARNING with the age' ($r.Sev -eq 'WARNING' -and (& $j $r) -match '\[WARNING\] Defender signatures are 9 day\(s\) old') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -AgeDays 3) -PrefOk $true -Pref (Pr) -Now $now
    T 'signatures 3 days old: nothing raised, the OK line prints' ($r.Sev -eq 'OK' -and (& $j $r) -match '^\[OK\] Defender core protection on:' -and (& $j $r) -notmatch '\[WARNING\]') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $false -Status $null -PrefOk $true -Pref (Pr) -Now $now
    T 'Get-MpComputerStatus failed, no other antivirus: a raised gap (never [SKIPPED]-and-silent), not graded, state says ungraded' ($r.Sev -eq 'OK' -and $r.Gap -and (-not $r.Graded) -and (& $j $r) -match '^\[WARNING\] Defender core status \(real-time, antivirus, tamper protection, signatures\) check NOT performed -- Get-MpComputerStatus failed' -and (& $j $r) -notmatch '\[SKIPPED\]' -and $r.State -eq 'unknown|0|0|0|-1') ((& $j $r) + ' / ' + $r.State)
    $r = Get-DefenderCoreReport -StatusOk $false -Status $null -StatusErr 'CimException: Access denied' -StatusDenied $true -IsElevated $false -PrefOk $true -Pref (Pr) -Now $now
    T 'Get-MpComputerStatus REFUSED to a standard-user token: a counted deferral, no gap' ($r.Deferred -eq 1 -and (-not $r.Gap) -and (& $j $r) -match '^\[DEFERRED - ADMIN REQUIRED\] Get-MpComputerStatus was refused to this standard-user token') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $false -Status $null -StatusErr 'CimException: Access denied' -StatusDenied $true -IsElevated $true -PrefOk $true -Pref (Pr) -Now $now
    T 'the same refusal ELEVATED: a raised gap (the token does not explain it)' ($r.Gap -and $r.Deferred -eq 0) (& $j $r)
    T 'the reason travels to the tile: status gap, flags fine' ($r.Why -eq 'gap|ok' -and $r.GapStatus -and (-not $r.GapPref)) $r.Why
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St) -PrefOk $false -Pref $null -PrefErr 'x' -IsElevated $true -OtherAv @{ Asked = $true; Names = @() } -Now $now
    T 'only Get-MpPreference failed: the FLAGS gap marker, never the core-status one' ($r.GapPref -and (-not $r.GapStatus) -and $r.Why -eq 'ok|gap' -and (& $j $r) -match 'names no other enabled antivirus') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $false -Status $null -StatusErr 'x' -IsElevated $true -OtherAv @{ Asked = $false; Names = @() } -PrefOk $true -Pref (Pr) -Now $now
    T 'Security Center could not be asked (Windows Server): the line says so, never "names no other"' ($r.GapStatus -and (& $j $r) -match 'Windows Security Center could not be asked' -and (& $j $r) -notmatch 'names no other') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $false -Status $null -StatusErr 'CimException: Access denied' -StatusDenied $true -IsElevated $false -PrefOk $true -Pref (Pr) -Now $now
    T 'a standard-user refusal is the reason the tile states: deferred' ($r.Why -eq 'deferred|ok') $r.Why
    $r = Get-DefenderCoreReport -StatusOk $false -Status $null -StatusErr 'CimException: Invalid namespace' -IsElevated $true -OtherAv @{ Asked = $true; Names = @('Contoso AV') } -PrefOk $false -Pref $null -PrefErr 'x' -Now $now
    T 'Defender does not answer and Security Center names another enabled antivirus: INFO naming it, no gap' ((-not $r.Gap) -and (& $j $r) -match '^\[INFO\] Get-MpComputerStatus did not answer \(CimException: Invalid namespace\); Windows Security Center names Contoso AV as the enabled antivirus') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St) -PrefOk $false -Pref $null -Now $now
    T 'Get-MpPreference failed: a raised gap for the flags, the status half still grades, no all-clear' ($r.Sev -eq 'OK' -and $r.Gap -and (& $j $r) -match '\[WARNING\] Defender disable-flags check NOT performed -- Get-MpPreference failed' -and (& $j $r) -notmatch '^\[OK\]') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -Svc $false) -PrefOk $true -Pref (Pr -Bm $true) -Now $now
    T 'service not enabled + behaviour monitoring disabled: two WARNINGs, Sev WARNING' ($r.Sev -eq 'WARNING' -and (& $j $r) -match 'antimalware service is not enabled' -and (& $j $r) -match 'DisableBehaviorMonitoring is set') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -Mode 'Passive Mode' -Rt $false -Av $false) -PrefOk $true -Pref (Pr) -Now $now
    T 'state line for the tile: mode, real-time, graded, tamper, signature age' ($r.State -eq 'Passive Mode|0|1|1|1') $r.State
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St) -PrefOk $true -Pref (Pr) -Now $now
    T 'state line, all good: Normal|1|1|1|1' ($r.State -eq 'Normal|1|1|1|1') $r.State
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -Tp $false -AgeDays 9) -PrefOk $true -Pref (Pr) -Now $now
    T 'state line carries tamper OFF and the signature age the section graded: Normal|1|1|0|9' ($r.State -eq 'Normal|1|1|0|9') $r.State
    T 'a mode with shell-significant characters is sanitised before it reaches the bat' ((Get-DefenderStateLine -Mode 'Passive & Mode | x %y% !z!' -RealTime $false -Graded $true) -eq 'Passive  Mode  x y z|0|1|0|-1') (Get-DefenderStateLine -Mode 'Passive & Mode | x %y% !z!' -RealTime $false -Graded $true)
    T 'Get-MaxSev never lowers a CRITICAL' ((Get-MaxSev 'CRITICAL' 'WARNING') -eq 'CRITICAL') ''
    if ($fails) { Write-Output "[FAIL] $fails defender_core_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] defender_core_check self-test: another antivirus in control is INFO and suppresses only the flags it explains; real-time off with no other product, an empty mode, or an explicit disable policy is CRITICAL.'
    exit 0
}

if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$stOk = $true; $st = $null; $stErr = ''; $stDen = $false
try { $st = Get-MpComputerStatus -ErrorAction Stop } catch { $stOk = $false; $stErr = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); $stDen = Test-DefenderAccessDenied $_.Exception }
$pfOk = $true; $pr = $null; $pfErr = ''; $pfDen = $false
try { $pr = Get-MpPreference -ErrorAction Stop } catch { $pfOk = $false; $pfErr = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); $pfDen = Test-DefenderAccessDenied $_.Exception }
$other = $null
if (-not ($stOk -and $pfOk)) { $other = Get-OtherAntivirus }
$rep = Get-DefenderCoreReport -StatusOk $stOk -Status $st -PrefOk $pfOk -Pref $pr -StatusErr $stErr -StatusDenied $stDen -PrefErr $pfErr -PrefDenied $pfDen -IsElevated ($Elevated -eq 1) -OtherAv $other
$rep.Lines
Write-Marker -Name 'defcore' -Sev $rep.Sev
# Two checks, two gap markers: the ledger row names the one that was not done.
if ($rep.GapStatus) { Write-Marker -Name 'defcore_gap' -Sev 'WARNING' }
if ($rep.GapPref) { Write-Marker -Name 'defflags_gap' -Sev 'WARNING' }
# Why each half was not graded (ok|deferred|otherav|gap), for the tiles and
# the ASR block: a tile that knows WHY must say it (the RDP-tile rule).
try { Set-Content -LiteralPath (Join-Path $MarkerDir 'dz_defcore_why.txt') -Value $rep.Why -Encoding ASCII } catch {}
if ([int]$rep.Deferred -gt 0) { Write-Marker -Name 'defcore_deferred' -Sev ([string][int]$rep.Deferred) }
try {
    $d = Split-Path -Parent $StateFile
    if ($d -and -not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath $StateFile -Value $rep.State -Encoding ASCII
} catch {
    '[INFO] Could not write the Defender state file for the dashboard; the real-time tile will read NOT graded.'
}
