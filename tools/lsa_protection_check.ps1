# lsa_protection_check.ps1 -- does LSASS run as a protected process (LSA
# Protection, "RunAsPPL")? Decided on the BOOT EVENT first and the registry
# value second: the event is the fact, the value is the intent.
#
# WHY. Both consumers of this answer used to read HKLM\...\Lsa\RunAsPPL alone
# (Section 12's inline block, and module_inspect's lsass-denied judgement in
# Section 4). Microsoft Learn, "Configure added LSA protection" (read
# 2026-10-03): a clean-installed, enterprise-joined, HVCI-capable Windows 11
# 22H2+ client runs LSASS protected BY DEFAULT with NO RunAsPPL value at all,
# so a registry-only rule reports exactly that machine as unprotected and
# raises (a T1003.001 row, a WARN tile, and -- elevated -- a T1055 row for the
# lsass denial that the protection itself causes). The signal Microsoft names
# for verification is WinInit Event 12 in the System log: "LSASS.exe was
# started as a protected process with level: 4". The System log is readable
# from a standard-user token, so the verdict is the same on both paths.
#
# THE RULE (positive and negative evidence are not symmetric -- the psv2 rule):
#   - Event 12 logged SINCE THIS BOOT        -> ON, by event. Proof.
#   - no event since boot, log reaches the boot, RunAsPPL 1|2
#                                            -> PENDING: the intent is set but
#       LSASS did not start protected (reboot pending, or value 2 on a build
#       before Windows 11 22H2, where it is not enforced). WARNING.
#   - no event since boot, log does NOT reach the boot, RunAsPPL 1|2
#                                            -> ON, by registry; the event
#       could not confirm it and the line says so.
#   - no event since boot, RunAsPPL 0|absent -> OFF. WARNING (unchanged).
#   - registry unreadable: the event decides when the log reaches the boot;
#     otherwise UNKNOWN, which is a raised gap ([WARNING] ... NOT evaluated),
#     never an all-clear.
# RunAsPPL 1 = enabled with the UEFI lock, 2 = enabled without it (Windows 11
# 22H2+); both are "on" (same Microsoft page).
#
# ONE MEASUREMENT, TWO CONSUMERS. Section 4 runs before Section 12 and both
# need the verdict, so `-Mode Measure` runs once in Section 4 (before
# module_inspect) and writes two files; `-Mode Report` runs in Section 12,
# prints the stored lines and raises the stored severity; module_inspect reads
# the state file's first field. A tile that re-measures is a second opinion,
# not a summary (CLAUDE.md), and so is a second tool.
#   state file (dz_lsa_state.txt):  <verdict>|<sev>|<source>|<registry>|<event>
#     verdict on|off|pending|unknown; sev OK|WARNING; source event12|registry|none;
#     registry 1|2|0|absent|unreadable|<other>; event level4@<ISO time>|none|
#     unreadable|notthisboot@<ISO time>. Every field sanitised to [A-Za-z0-9:.@-].
#   lines file (dz_lsa_lines.txt):  the report lines, verbatim.
#   marker (dz_lsa.txt):            written by Report; the bat raises it.
# Measure prints nothing on success and still writes `unknown` on any
# failure, so a failed measurement surfaces in Section 12 as a raised gap
# rather than as silence.
#
# Usage:
#   powershell -File tools\lsa_protection_check.ps1 -Mode Measure [-MarkerDir <dir>]
#   powershell -File tools\lsa_protection_check.ps1 -Mode Report  [-MarkerDir <dir>]
#   powershell -File tools\lsa_protection_check.ps1 -SelfTest   (no registry or log access)
#
# Windows PowerShell 5.1 compatible; pure ASCII; read-only.

[CmdletBinding()]
param(
    [ValidateSet('Measure', 'Report')]
    [string]$Mode = 'Report',
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [string]$LinesFile,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_lsa_state.txt' }
if (-not $LinesFile) { $LinesFile = Join-Path $MarkerDir 'dz_lsa_lines.txt' }

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

# A state-line field: letters, digits, colon, dot, at-sign and dash only
# (the first field becomes part of an `echo` into the bat's staged PowerShell).
function ConvertTo-StateField {
    param([string]$Value)
    $v = ($Value -replace '[^A-Za-z0-9:.@-]', '')
    if ($v.Length -gt 40) { $v = $v.Substring(0, 40) }
    if (-not $v) { $v = 'none' }
    return $v
}

function Format-StateTime {
    param($Time)
    try { return ([datetime]$Time).ToString('yyyy-MM-ddTHH:mm:ss') } catch { return 'unknown' }
}

# PURE. Every input is injectable so the self-test can drive every row of
# the rule above without a registry or a System log.
#   -PplReadable  the Lsa key could be read; -Ppl the RunAsPPL value ($null = absent)
#   -Event12      $null, or @{ Time = [datetime]; Level = [int] } for the NEWEST
#                 WinInit Event 12 in the System log
#   -BootTime     [datetime] or $null when unknown
#   -OldestRecord [datetime] of the oldest surviving System record, or $null
#   -LogReadable  the System log could be queried; -LogError why not
function Get-LsaProtectionVerdict {
    param(
        [bool]$PplReadable = $true, $Ppl,
        $Event12,
        $BootTime,
        $OldestRecord,
        [bool]$LogReadable = $true,
        [string]$LogError = ''
    )
    $out = New-Object System.Collections.Generic.List[string]
    $pv = -1
    try { if ($null -ne $Ppl) { $pv = [int]$Ppl } } catch { $pv = -1 }
    $regOn = ($pv -eq 1 -or $pv -eq 2)
    $regText = if (-not $PplReadable) { 'unreadable' } elseif ($null -eq $Ppl) { 'absent' } else { ConvertTo-StateField ([string]$Ppl) }
    $bootKnown = ($null -ne $BootTime)
    $eventText = 'none'
    $eventThisBoot = $false
    $eventSeen = ($null -ne $Event12 -and $null -ne $Event12.Time)
    if (-not $LogReadable) { $eventText = 'unreadable' }
    if ($eventSeen) {
        $lvl = -1
        try { $lvl = [int]$Event12.Level } catch { $lvl = -1 }
        $when = Format-StateTime $Event12.Time
        if ($bootKnown) {
            # LastBootUpTime is the kernel's start; WinInit logs Event 12 a
            # little later, so anything at or after boot minus a small clock
            # tolerance is this boot's record.
            $eventThisBoot = ([datetime]$Event12.Time -ge ([datetime]$BootTime).AddMinutes(-5))
        }
        $eventText = $(if ($eventThisBoot) { 'level' + $lvl + '@' + $when } else { 'notthisboot@' + $when })
    }
    $logCoversBoot = ($LogReadable -and $bootKnown -and $null -ne $OldestRecord -and ([datetime]$OldestRecord -le [datetime]$BootTime))

    $verdict = 'unknown'; $source = 'none'; $sev = 'OK'
    if ($eventThisBoot) {
        $verdict = 'on'; $source = 'event12'
        [void]$out.Add(('[OK] LSASS started as a protected process this boot (WinInit Event 12, level {0}, {1}); RunAsPPL={2}.' -f $lvl, (Format-StateTime $Event12.Time), $regText))
        if ($regText -eq 'absent') {
            [void]$out.Add('[INFO] No RunAsPPL value in the registry: LSA Protection is on by default here (a clean-installed, enterprise-joined, HVCI-capable Windows 11 22H2+ client) or by policy. The boot event is the fact; the value is only the intent.')
        } elseif ($pv -eq 0) {
            [void]$out.Add('[INFO] RunAsPPL=0 in the registry, yet LSASS started protected this boot: a UEFI-locked setting or policy overrides the value. The registry alone would have read this machine as unprotected.')
        }
    } elseif ($regOn) {
        if ($logCoversBoot) {
            $verdict = 'pending'; $source = 'registry'; $sev = 'WARNING'
            [void]$out.Add(('[WARNING] RunAsPPL={0} is set but LSASS did NOT start protected this boot -- no WinInit Event 12 since boot, and the System log reaches back to it. A reboot is pending, or value 2 is not enforced on this build (it needs Windows 11 22H2 or later). Until then LSASS memory can be dumped (T1003.001).' -f $regText))
        } else {
            $verdict = 'on'; $source = 'registry'
            $why = $(if (-not $LogReadable) { 'the System log could not be read' + $(if ($LogError) { ' (' + $LogError + ')' } else { '' }) } elseif (-not $bootKnown) { 'the boot time is unknown' } else { 'the System log no longer reaches back to this boot' })
            [void]$out.Add(('[OK] LSASS runs as a protected process by registry (RunAsPPL={0}).' -f $regText))
            [void]$out.Add(('[INFO] WinInit Event 12 could not confirm it: {0}. Verify after the next boot: wevtutil qe System /q:"*[System[Provider[@Name=''Microsoft-Windows-Wininit''] and (EventID=12)]]" /c:1 /rd:true /f:text' -f $why))
        }
    } elseif ($PplReadable) {
        $verdict = 'off'; $source = 'registry'; $sev = 'WARNING'
        [void]$out.Add(('[WARNING] LSASS PPL not enabled -- LSASS memory can be dumped (T1003.001). RunAsPPL={0}{1}.' -f $regText, $(if ($logCoversBoot) { '; no WinInit Event 12 since boot confirms LSASS is not protected' } elseif ($LogReadable) { '; the System log no longer reaches back to this boot, so the boot event could not be consulted' } else { '; the System log could not be read' })))
    } elseif ($logCoversBoot) {
        $verdict = 'off'; $source = 'event12'; $sev = 'WARNING'
        [void]$out.Add('[WARNING] LSASS PPL not enabled -- LSASS memory can be dumped (T1003.001). The Lsa registry key could not be read, but no WinInit Event 12 was logged since boot and the System log reaches back to it.')
    } else {
        $verdict = 'unknown'; $source = 'none'; $sev = 'WARNING'
        [void]$out.Add(('[WARNING] LSA Protection state could NOT be determined -- the Lsa registry key could not be read and WinInit Event 12 could not be consulted ({0}). LSASS protection NOT evaluated; verify: reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL' -f $(if (-not $LogReadable) { 'System log unreadable' + $(if ($LogError) { ': ' + $LogError } else { '' }) } elseif (-not $bootKnown) { 'boot time unknown' } else { 'the System log no longer reaches back to this boot' })))
    }
    $state = ('{0}|{1}|{2}|{3}|{4}' -f (ConvertTo-StateField $verdict), $sev, (ConvertTo-StateField $source), (ConvertTo-StateField $regText), (ConvertTo-StateField $eventText))
    return @{ Verdict = $verdict; Source = $source; Sev = $sev; Lines = @($out.ToArray()); State = $state }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $boot = Get-Date '2026-10-03 06:00:00'
    $ev = @{ Time = $boot.AddSeconds(40); Level = 4 }
    $old = $boot.AddDays(-3)
    $j = { param($r) ($r.Lines -join "`n") }

    $r = Get-LsaProtectionVerdict -Ppl $null -Event12 $ev -BootTime $boot -OldestRecord $old
    T 'Event 12 this boot with NO RunAsPPL value: ON by event, [OK], the default-on INFO, Sev OK' ($r.Verdict -eq 'on' -and $r.Source -eq 'event12' -and $r.Sev -eq 'OK' -and (& $j $r) -match '^\[OK\] LSASS started as a protected process this boot \(WinInit Event 12, level 4' -and (& $j $r) -match '\[INFO\] No RunAsPPL value' -and (& $j $r) -notmatch '\[WARNING\]') ((& $j $r) + ' / ' + $r.State)
    $r = Get-LsaProtectionVerdict -Ppl 0 -Event12 $ev -BootTime $boot -OldestRecord $old
    T 'Event 12 this boot with RunAsPPL=0: ON by event (UEFI lock or policy overrides the value), INFO says so' ($r.Verdict -eq 'on' -and (& $j $r) -match 'RunAsPPL=0 in the registry, yet LSASS started protected') (& $j $r)
    $r = Get-LsaProtectionVerdict -Ppl 2 -Event12 $null -BootTime $boot -OldestRecord $old
    T 'RunAsPPL=2 with no Event 12 and a log that covers the boot: PENDING, WARNING names the two causes' ($r.Verdict -eq 'pending' -and $r.Sev -eq 'WARNING' -and (& $j $r) -match '^\[WARNING\] RunAsPPL=2 is set but LSASS did NOT start protected this boot' -and (& $j $r) -match 'reboot is pending, or value 2 is not enforced') (& $j $r)
    $r = Get-LsaProtectionVerdict -Ppl 1 -Event12 $null -BootTime $boot -OldestRecord $boot.AddHours(2)
    T 'no Event 12, log rolled past the boot, RunAsPPL=1: ON by registry, the INFO says the event could not confirm it' ($r.Verdict -eq 'on' -and $r.Source -eq 'registry' -and $r.Sev -eq 'OK' -and (& $j $r) -match '^\[OK\] LSASS runs as a protected process by registry \(RunAsPPL=1\)' -and (& $j $r) -match 'no longer reaches back to this boot') (& $j $r)
    $r = Get-LsaProtectionVerdict -Ppl 2 -Event12 @{ Time = $boot.AddDays(-1); Level = 4 } -BootTime $boot -OldestRecord $old
    T 'an Event 12 from a PREVIOUS boot is not this boot: with RunAsPPL=2 and the log covering the boot it is PENDING' ($r.Verdict -eq 'pending' -and $r.State -match '\|notthisboot@') ((& $j $r) + ' / ' + $r.State)
    $r = Get-LsaProtectionVerdict -Ppl $null -Event12 $null -BootTime $boot -OldestRecord $old
    T 'no Event 12, RunAsPPL absent, log covers the boot: OFF, WARNING, the event absence named as confirmation' ($r.Verdict -eq 'off' -and $r.Sev -eq 'WARNING' -and (& $j $r) -match '^\[WARNING\] LSASS PPL not enabled' -and (& $j $r) -match 'no WinInit Event 12 since boot confirms') (& $j $r)
    $r = Get-LsaProtectionVerdict -Ppl 0 -Event12 $null -BootTime $boot -OldestRecord $boot.AddHours(1)
    T 'no Event 12, RunAsPPL=0, log rolled: still OFF (the value is readable and says off), the line says the event could not be consulted' ($r.Verdict -eq 'off' -and (& $j $r) -match 'could not be consulted') (& $j $r)
    $r = Get-LsaProtectionVerdict -Ppl 1 -Event12 $null -BootTime $boot -OldestRecord $old -LogReadable $false -LogError 'access denied'
    T 'System log unreadable with RunAsPPL=1: ON by registry, the INFO names the log error' ($r.Verdict -eq 'on' -and $r.Source -eq 'registry' -and (& $j $r) -match 'could not be read \(access denied\)') (& $j $r)
    $r = Get-LsaProtectionVerdict -PplReadable $false -Ppl $null -Event12 $null -BootTime $boot -OldestRecord $old
    T 'registry unreadable, no Event 12, log covers the boot: OFF by event absence (negative evidence with coverage), WARNING' ($r.Verdict -eq 'off' -and $r.Source -eq 'event12' -and $r.Sev -eq 'WARNING') (& $j $r)
    $r = Get-LsaProtectionVerdict -PplReadable $false -Ppl $null -Event12 $null -BootTime $boot -OldestRecord $boot.AddHours(1)
    T 'registry unreadable, no Event 12, log rolled: UNKNOWN is a raised gap ([WARNING] ... NOT evaluated), never OK' ($r.Verdict -eq 'unknown' -and $r.Sev -eq 'WARNING' -and (& $j $r) -match '^\[WARNING\] LSA Protection state could NOT be determined' -and (& $j $r) -match 'NOT evaluated') (& $j $r)
    $r = Get-LsaProtectionVerdict -Ppl 2 -Event12 $ev -BootTime $null -OldestRecord $old
    T 'boot time unknown: an Event 12 cannot be placed, so RunAsPPL=2 decides (ON by registry) and the INFO says why' ($r.Verdict -eq 'on' -and $r.Source -eq 'registry' -and (& $j $r) -match 'boot time is unknown') (& $j $r)
    $r = Get-LsaProtectionVerdict -Ppl 'junk' -Event12 $null -BootTime $boot -OldestRecord $old
    T 'an unreadable RunAsPPL value (junk) is not ON: OFF' ($r.Verdict -eq 'off' -and $r.Sev -eq 'WARNING') (& $j $r)
    $r = Get-LsaProtectionVerdict -Ppl $null -Event12 $ev -BootTime $boot -OldestRecord $old
    T 'state line: verdict|sev|source|registry|event, every field sanitised' ($r.State -match '^on\|OK\|event12\|absent\|level4@2026-10-03T06:00:40$') $r.State
    T 'a state field with shell-significant characters is reduced to the allowlist' ((ConvertTo-StateField 'ab & c | d %e% !f!') -eq 'abcdef') (ConvertTo-StateField 'ab & c | d %e% !f!')
    T 'Get-MaxSev never lowers a WARNING' ((Get-MaxSev 'WARNING' 'OK') -eq 'WARNING') ''
    if ($fails) { Write-Output "[FAIL] $fails lsa_protection_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] lsa_protection_check self-test: the boot event is the fact and the registry value the intent; on by event with no value, pending when the value is set but LSASS did not start protected, off only on evidence, unknown is a raised gap.'
    exit 0
}

if ($Mode -eq 'Measure') {
    $pplOk = $true; $ppl = $null
    try {
        $item = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop
        $ppl = $item.RunAsPPL
    } catch { $pplOk = $false }
    $boot = $null
    try { $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { $boot = $null }
    $logOk = $true; $logErr = ''; $oldest = $null; $ev = $null
    try {
        $o = Get-WinEvent -LogName System -Oldest -MaxEvents 1 -ErrorAction Stop
        if ($o) { $oldest = $o.TimeCreated }
    } catch { $logOk = $false; $logErr = $_.Exception.Message }
    if ($logOk) {
        try {
            $e = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Wininit'; Id = 12 } -MaxEvents 1 -ErrorAction Stop
            if ($e) {
                $lvl = -1
                try { $m = [regex]::Match([string]$e.Message, 'level:\s*(\d+)'); if ($m.Success) { $lvl = [int]$m.Groups[1].Value } } catch {}
                $ev = @{ Time = $e.TimeCreated; Level = $lvl }
            }
        } catch {
            # "No events were found that match the specified selection criteria"
            # is the normal answer on an unprotected machine, not a read failure.
            if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound' -and $_.Exception.Message -notmatch 'No events were found') { $logOk = $false; $logErr = $_.Exception.Message }
        }
    }
    $rep = $null
    try { $rep = Get-LsaProtectionVerdict -PplReadable $pplOk -Ppl $ppl -Event12 $ev -BootTime $boot -OldestRecord $oldest -LogReadable $logOk -LogError $logErr } catch { $rep = $null }
    if ($null -eq $rep) {
        $rep = @{ Verdict = 'unknown'; Source = 'none'; Sev = 'WARNING'; State = 'unknown|WARNING|none|unreadable|unreadable'; Lines = @('[WARNING] LSA Protection state could NOT be determined -- the measurement itself failed. LSASS protection NOT evaluated; verify: reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL') }
    }
    try {
        if (-not (Test-Path -LiteralPath $MarkerDir)) { New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null }
        Set-Content -LiteralPath $StateFile -Value $rep.State -Encoding ASCII
        Set-Content -LiteralPath $LinesFile -Value $rep.Lines -Encoding ASCII
    } catch {
        '[WARNING] LSA Protection measurement could not be stored for Section 12 -- NOT evaluated there.'
    }
    exit 0
}

# Report: print what Measure stored and raise its severity. No measurement here.
if (-not (Test-Path -LiteralPath $StateFile)) {
    '[WARNING] LSA Protection state NOT evaluated -- the Section 4 measurement (tools\lsa_protection_check.ps1 -Mode Measure) left no state file. Verify: reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL'
    Write-Marker -Name 'lsa' -Sev 'WARNING'
    exit 0
}
$state = ''
try { $state = [string](Get-Content -LiteralPath $StateFile -ErrorAction Stop | Select-Object -First 1) } catch { $state = '' }
$f = $state.Split('|')
$sev = $(if ($f.Length -ge 2 -and $f[1] -match '^(OK|WARNING|CRITICAL)$') { $f[1] } else { 'WARNING' })
$printed = $false
if (Test-Path -LiteralPath $LinesFile) {
    try { $ls = @(Get-Content -LiteralPath $LinesFile -ErrorAction Stop); if ($ls.Count -gt 0) { $ls; $printed = $true } } catch {}
}
if (-not $printed) {
    ('[WARNING] LSA Protection verdict {0} was measured but its report lines were lost -- treat as NOT evaluated and verify: reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL' -f $(if ($f[0]) { $f[0] } else { 'unknown' }))
    $sev = Get-MaxSev $sev 'WARNING'
}
Write-Marker -Name 'lsa' -Sev $sev
