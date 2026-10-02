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
# the state file for the dashboard tile:  <mode>|<realtime 0/1>|<graded 0/1>
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
    param([string]$Mode, [bool]$RealTime, [bool]$Graded)
    $m = ($Mode -replace '[^A-Za-z ]', '').Trim()
    if ($m.Length -gt 32) { $m = $m.Substring(0, 32) }
    if (-not $m) { $m = 'unknown' }
    return ('{0}|{1}|{2}' -f $m, $(if ($RealTime) { '1' } else { '0' }), $(if ($Graded) { '1' } else { '0' }))
}

# Pure. $Status / $Pref are whatever Get-MpComputerStatus / Get-MpPreference
# returned (or any object with the same property names); $StatusOk / $PrefOk
# say whether the call succeeded at all. Returns the report lines, the
# severity to raise, and what the tile needs.
function Get-DefenderCoreReport {
    param(
        [bool]$StatusOk, $Status,
        [bool]$PrefOk, $Pref,
        [datetime]$Now = (Get-Date)
    )
    $out = New-Object System.Collections.Generic.List[string]
    $sev = 'OK'
    $mode = ''
    $passive = $false
    $rt = $false
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
        if (-not $Status.IsTamperProtected) {
            [void]$out.Add('[WARNING] Tamper Protection is OFF -- an attacker who gains admin can silently disable Defender and its logging. Fix: Windows Security > Virus & threat protection > Manage settings > Tamper Protection On'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
        }
        $age = $null
        try { $age = ($Now - [datetime]$Status.AntivirusSignatureLastUpdated).TotalDays } catch { $age = $null }
        if ($null -ne $age -and $age -gt 7) {
            [void]$out.Add('[WARNING] Defender signatures are ' + [int]$age + ' day(s) old -- updates are not arriving, which is itself a tampering indicator.'); $sev = Get-MaxSev $sev 'WARNING'; $findings++
        }
    } else {
        [void]$out.Add('[SKIPPED] Get-MpComputerStatus failed -- Defender core status NOT evaluated. Either a third-party AV owns protection or Defender itself is disabled; confirm manually which one it is.')
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
        [void]$out.Add('[SKIPPED] Get-MpPreference failed -- the Defender disable flags were NOT evaluated.')
    }
    if ($StatusOk -and $PrefOk -and $findings -eq 0) {
        if ($passive) {
            [void]$out.Add('[OK] Defender itself is tamper-protected, current and not policy-disabled; protection belongs to the other product above.')
        } else {
            [void]$out.Add('[OK] Defender core protection on: real-time, antivirus, on-access and tamper protection enabled; signatures current; no disable flags set.')
        }
    }
    return @{ Lines = @($out.ToArray()); Sev = $sev; Mode = $mode; Passive = $passive; RealTime = $rt; Graded = $StatusOk; State = (Get-DefenderStateLine -Mode $mode -RealTime $rt -Graded $StatusOk) }
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
    T 'Get-MpComputerStatus failed: [SKIPPED], not graded, no severity invented, state says ungraded' ($r.Sev -eq 'OK' -and (-not $r.Graded) -and (& $j $r) -match '^\[SKIPPED\] Get-MpComputerStatus failed' -and $r.State -eq 'unknown|0|0') ((& $j $r) + ' / ' + $r.State)
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St) -PrefOk $false -Pref $null -Now $now
    T 'Get-MpPreference failed: the flags are declared [SKIPPED], the status half still grades' ($r.Sev -eq 'OK' -and (& $j $r) -match '\[SKIPPED\] Get-MpPreference failed' -and (& $j $r) -notmatch '^\[OK\]') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -Svc $false) -PrefOk $true -Pref (Pr -Bm $true) -Now $now
    T 'service not enabled + behaviour monitoring disabled: two WARNINGs, Sev WARNING' ($r.Sev -eq 'WARNING' -and (& $j $r) -match 'antimalware service is not enabled' -and (& $j $r) -match 'DisableBehaviorMonitoring is set') (& $j $r)
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St -Mode 'Passive Mode' -Rt $false -Av $false) -PrefOk $true -Pref (Pr) -Now $now
    T 'state line for the tile: mode, real-time flag, graded' ($r.State -eq 'Passive Mode|0|1') $r.State
    $r = Get-DefenderCoreReport -StatusOk $true -Status (St) -PrefOk $true -Pref (Pr) -Now $now
    T 'state line, all good: Normal|1|1' ($r.State -eq 'Normal|1|1') $r.State
    T 'a mode with shell-significant characters is sanitised before it reaches the bat' ((Get-DefenderStateLine -Mode 'Passive & Mode | x %y% !z!' -RealTime $false -Graded $true) -eq 'Passive  Mode  x y z|0|1') (Get-DefenderStateLine -Mode 'Passive & Mode | x %y% !z!' -RealTime $false -Graded $true)
    T 'Get-MaxSev never lowers a CRITICAL' ((Get-MaxSev 'CRITICAL' 'WARNING') -eq 'CRITICAL') ''
    if ($fails) { Write-Output "[FAIL] $fails defender_core_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] defender_core_check self-test: another antivirus in control is INFO and suppresses only the flags it explains; real-time off with no other product, an empty mode, or an explicit disable policy is CRITICAL.'
    exit 0
}

$stOk = $true; $st = $null
try { $st = Get-MpComputerStatus -ErrorAction Stop } catch { $stOk = $false }
$pfOk = $true; $pr = $null
try { $pr = Get-MpPreference -ErrorAction Stop } catch { $pfOk = $false }
$rep = Get-DefenderCoreReport -StatusOk $stOk -Status $st -PrefOk $pfOk -Pref $pr
$rep.Lines
Write-Marker -Name 'defcore' -Sev $rep.Sev
try {
    $d = Split-Path -Parent $StateFile
    if ($d -and -not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath $StateFile -Value $rep.State -Encoding ASCII
} catch {
    '[INFO] Could not write the Defender state file for the dashboard; the real-time tile will read NOT graded.'
}
