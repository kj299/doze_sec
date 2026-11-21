# defender_detections_check.ps1 -- what Microsoft Defender itself has caught
# on this PC (Section 9, T1204.002).
#
# WHY. Section 9 printed a raw Get-MpThreatDetection table with no verdict,
# no marker and no row, so Defender recording a Severe Trojan on the owner's
# WIN11-02 (2026-11-20) raised nothing -- and malware Defender found and
# FAILED to remove read exactly the same. Defender is the one engine on most
# PCs that can name malware; its own record is the strongest compromise
# signal this audit can read.
#
# THE RULE (owner's decision, 2026-11-20; pure, in Get-DetectionVerdict,
# pinned by -SelfTest):
#   * a detection Defender did NOT remove is CRITICAL: ActionSuccess false,
#     the threat still active, or a status that leaves it on the machine
#     (Detected, Allowed, QuarantineFailed, RemoveFailed, AllowFailed,
#     Abandoned, BlockFailed). Allowed counts: someone told Defender to
#     leave it. A status code this tool does not know is graded the same --
#     "I could not tell" belongs with the risky half;
#   * a detection it removed (Cleaned, Quarantined, Removed, Blocked, with
#     ActionSuccess true) is a WARNING: something malicious reached this PC;
#   * none on record is [OK], naming how far back the history reaches;
#   * a history that could not be read is a raised gap, never [OK]; refused
#     on a standard-user token it is a counted deferral (the history needs
#     administrator).
# Nothing is excluded by path or name: a detection of a file you recognise
# is still a detection, and the line names the file so you can judge it.
#
# Markers: dz_mpdet_crit / dz_mpdet_warn / dz_mpdet_gap / dz_mpdet_deferred.
# State: dz_mpdet_state.txt  det=<none|removed|active|gap|deferred|otherav>,n=<count>
#
# Usage:
#   powershell -File tools\defender_detections_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1]
#   powershell -File tools\defender_detections_check.ps1 -SelfTest   (queries nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # Section 9 found Defender's own status unreadable AND another antivirus
    # registered as the one in force (defender_core_check's "otherav"). The
    # history is still asked for; only a failure is read differently.
    [switch]$OtherAv,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_mpdet_state.txt' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -ErrorAction Stop
}

function ConvertTo-PrintableText {
    param([string]$s, [int]$Max = 260)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

# ThreatStatusID, as Microsoft documents it for MSFT_MpThreatDetection.
$script:StatusName = @{
    0 = 'Unknown'; 1 = 'Detected'; 2 = 'Cleaned'; 3 = 'Quarantined'; 4 = 'Removed'
    5 = 'Allowed'; 6 = 'Blocked'; 102 = 'QuarantineFailed'; 103 = 'RemoveFailed'
    104 = 'AllowFailed'; 105 = 'Abandoned'; 107 = 'BlockFailed'
}
$script:Remediated = @(2, 3, 4, 6)
$script:SeverityName = @{ 0 = 'Unknown'; 1 = 'Low'; 2 = 'Moderate'; 4 = 'High'; 5 = 'Severe' }

function Test-RefusedError {
    param($Exception)
    $x = $Exception; $depth = 0
    while ($null -ne $x -and $depth -lt 8) {
        if ($x -is [System.UnauthorizedAccessException] -or $x -is [System.Security.SecurityException]) { return $true }
        $hr = 0
        try { $hr = [int]$x.HResult } catch { }
        if ($hr -eq -2147024891) { return $true }   # 0x80070005 E_ACCESSDENIED
        if ([string]$x.Message -match '(?i)access (is )?denied|0x80070005') { return $true }
        $x = $x.InnerException; $depth++
    }
    return $false
}

# Whether a detection's file is on disk now: present | gone | unknown. Gone
# only when the parent folder ANSWERS without it (CLAUDE.md, "File.Exists is
# not 'not installed'"); a path that is not a file, or a parent that refuses,
# is unknown. $script:PresenceHook lets the self-test supply answers.
$script:PresenceHook = $null
function Get-FilePresence {
    param([string]$Resource)
    if ($script:PresenceHook) { return (& $script:PresenceHook $Resource) }
    $p = ([string]$Resource) -replace '^[A-Za-z]+:_', ''
    if ($p -notmatch '^[A-Za-z]:\\') { return 'unknown' }
    try { $null = Get-Item -LiteralPath $p -Force -ErrorAction Stop; return 'present' } catch { }
    try {
        $parent = Split-Path -Parent $p
        $names = @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop | ForEach-Object { $_.Name })
        if ($names -notcontains (Split-Path -Leaf $p)) { return 'gone' }
        return 'unknown'
    } catch {
        if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { return 'gone' }
        return 'unknown'
    }
}

# PURE: one detection, graded. $D: @{ Name; Severity; Status; Success; Active; Paths; Time; User; Process }
function Get-DetectionGrade {
    param($D)
    $st = $null
    try { $st = [int]$D.Status } catch { $st = $null }
    $known = ($null -ne $st) -and $script:StatusName.ContainsKey($st)
    $removed = $known -and ($script:Remediated -contains $st) -and ($D.Success -eq $true) -and ($D.Active -ne $true)
    $stText = $(if ($known) { $script:StatusName[$st] } elseif ($null -ne $st) { 'status code ' + $st + ', not one this check knows' } else { 'no status recorded' })
    return @{ Removed = $removed; StatusText = $stText }
}

# PURE: the whole history, graded. $Read: @{ Error; Denied; Detections }
function Get-DetectionVerdict {
    param($Read, [bool]$IsElevated = $true, [bool]$OtherAv = $false)
    $out = New-Object System.Collections.ArrayList
    $crit = 0; $warn = 0; $gap = $false; $deferred = 0
    if ([string]$Read.Error) {
        if ($Read.Denied -and -not $IsElevated) {
            [void]$out.Add('[DEFERRED - ADMIN REQUIRED] Defender''s detection history was not read: Get-MpThreatDetection needs an administrator token (' + (ConvertTo-PrintableText $Read.Error 160) + ').')
            $deferred = 1
            return @{ Lines = @($out.ToArray()); Crit = 0; Warn = 0; Gap = $false; Deferred = $deferred; State = 'det=deferred,n=-' }
        }
        if ($OtherAv) {
            [void]$out.Add('[INFO] Defender''s detection history did not answer (' + (ConvertTo-PrintableText $Read.Error 160) + '), and Section 9 found another antivirus registered as the one in force, so Defender is not what is scanning here. That product keeps its own history; this audit does not read it.')
            return @{ Lines = @($out.ToArray()); Crit = 0; Warn = 0; Gap = $false; Deferred = 0; State = 'det=otherav,n=-' }
        }
        [void]$out.Add('[WARNING] Defender detection history NOT checked -- Get-MpThreatDetection did not answer (' + (ConvertTo-PrintableText $Read.Error 200) + '), so malware Defender found, and malware it failed to remove, would go unseen here. Look in Windows Security > Virus & threat protection > Protection history.')
        return @{ Lines = @($out.ToArray()); Crit = 0; Warn = 0; Gap = $true; Deferred = 0; State = 'det=gap,n=-' }
    }
    $dets = @(@($Read.Detections) | Where-Object { $null -ne $_ })
    if ($dets.Count -eq 0) {
        # On a standard-user token an EMPTY answer is not evidence: Defender
        # already shows that token masked status and preference values
        # (CLAUDE.md, "an answer is not a truthful answer"), and its history
        # needs administrator. A record it DID show is still graded below.
        if (-not $IsElevated) {
            [void]$out.Add('[DEFERRED - ADMIN REQUIRED] Defender''s detection history was not read: it answered this standard-user token with nothing, and Defender does not show such a token its full record -- an audit run as administrator reads it.')
            return @{ Lines = @($out.ToArray()); Crit = 0; Warn = 0; Gap = $false; Deferred = 1; State = 'det=deferred,n=-' }
        }
        [void]$out.Add('[OK] Defender has no detection on record (Defender keeps this history for a limited time, so an older detection may have aged out).')
        return @{ Lines = @($out.ToArray()); Crit = 0; Warn = 0; Gap = $false; Deferred = 0; State = 'det=none,n=0' }
    }
    $cap = 15; $i = 0
    # Not removed first: those are what the reader must act on.
    $graded = @($dets | ForEach-Object { $g = Get-DetectionGrade $_; @{ D = $_; G = $g } } | Sort-Object @{ Expression = { [int][bool]$_.G.Removed } }, @{ Expression = { $tt = [datetime]::MinValue; try { if ($_.D.Time) { $tt = [datetime]$_.D.Time } } catch { }; $tt }; Descending = $true })
    foreach ($e in $graded) {
        $d = $e.D; $g = $e.G
        if ($g.Removed) { $warn++ } else { $crit++ }
        $i++
        if ($i -gt $cap) { continue }
        $sev = '?'
        try { $sv = [int]$d.Severity; if ($script:SeverityName.ContainsKey($sv)) { $sev = $script:SeverityName[$sv] } else { $sev = [string]$sv } } catch { $sev = 'unknown' }
        $paths = @(@($d.Paths) | Where-Object { [string]$_ } | ForEach-Object { ConvertTo-PrintableText ([string]$_) 200 })
        $where = $(if ($paths.Count) { ($paths | Select-Object -First 3) -join '; ' } else { 'no path recorded' })
        if ($paths.Count -gt 3) { $where += ('; and ' + ($paths.Count - 3) + ' more') }
        $who = @()
        if ([string]$d.User) { $who += ('user ' + (ConvertTo-PrintableText $d.User 80)) }
        if ([string]$d.Process) { $who += ('process ' + (ConvertTo-PrintableText $d.Process 160)) }
        $whoText = $(if ($who.Count) { ', ' + ($who -join ', ') } else { '' })
        $when = $(if ($d.Time) { try { ([datetime]$d.Time).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z' } catch { [string]$d.Time } } else { 'an unknown time' })
        $name = ConvertTo-PrintableText $d.Name 120
        if ($g.Removed) {
            [void]$out.Add('[WARNING] Defender detected and removed ' + $name + ' (severity ' + $sev + '): ' + $where + ' (' + $g.StatusText + ', ' + $when + $whoText + ') -- something malicious reached this PC (T1204.002).')
        } else {
            $why = $(if ($d.Active -eq $true) { 'still active' } elseif ($d.Success -ne $true) { 'the action did not succeed' } else { $g.StatusText })
            # A failed action is common when the file was already gone (a
            # browser temp download deleted first). The grade stays the
            # owner's; the line says what is on disk now, so the reader can
            # tell "still here" from "gone before Defender acted".
            $gone = @(@($d.Paths) | ForEach-Object { Get-FilePresence ([string]$_) })
            if ($gone.Count -and @($gone | Where-Object { $_ -ne 'gone' }).Count -eq 0) { $why += '; the file is no longer present at that path' }
            elseif (@($gone | Where-Object { $_ -eq 'present' }).Count) { $why += '; the file is still present' }
            [void]$out.Add('[CRITICAL] Defender detected ' + $name + ' (severity ' + $sev + ') and did NOT remove it: ' + $where + ' (' + $g.StatusText + '; ' + $why + ', ' + $when + $whoText + ') (T1204.002).')
        }
    }
    if ($graded.Count -gt $cap) { [void]$out.Add('    ...and ' + ($graded.Count - $cap) + ' more detection(s), counted above; Get-MpThreatDetection lists them all.') }
    [void]$out.Add('[INFO] Defender names what it detected; a test file or a tool you recognise can be one. Check each path above, and see Windows Security > Virus & threat protection > Protection history. Never answer a detection by adding an exclusion.')
    $state = $(if ($crit) { 'det=active,n=' + $graded.Count } else { 'det=removed,n=' + $graded.Count })
    return @{ Lines = @($out.ToArray()); Crit = $crit; Warn = $warn; Gap = $false; Deferred = 0; State = $state }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function D { param([int]$St, $Ok = $true, $Act = $false, [string]$P = 'C:\Users\a\Downloads\x.exe', [string]$N = 'Trojan:Win32/Test')
        @{ Name = $N; Severity = 5; Status = $St; Success = $Ok; Active = $Act; Paths = @('file:_' + $P); Time = '2026-11-20T10:00:00Z'; User = 'PC\a'; Process = 'C:\Windows\explorer.exe' } }
    function V { param($Dets, [string]$Err = '', [bool]$Den = $false, [bool]$Adm = $true)
        Get-DetectionVerdict -Read @{ Error = $Err; Denied = $Den; Detections = $Dets } -IsElevated $Adm }

    $v = V @(); $t = $v.Lines -join "`n"
    T 'no detection on record is [OK], and says the history is kept for a limited time' ($v.Crit -eq 0 -and $v.Warn -eq 0 -and -not $v.Gap -and $t -match '(?m)^\[OK\] Defender has no detection on record' -and $v.State -eq 'det=none,n=0') $t
    $v = V @((D 3)); $t = $v.Lines -join "`n"
    T 'a quarantined detection is a WARNING naming the threat, the file and the action' ($v.Warn -eq 1 -and $v.Crit -eq 0 -and $t -match '(?m)^\[WARNING\] Defender detected and removed Trojan:Win32/Test \(severity Severe\): file:_C:\\Users\\a\\Downloads\\x\.exe \(Quarantined, 2026-11-20 10:00:00Z' -and $v.State -eq 'det=removed,n=1') $t
    $v = V @((D 3 $false)); $t = $v.Lines -join "`n"
    T 'an action that did not succeed is CRITICAL, whatever the status says' ($v.Crit -eq 1 -and $t -match '(?m)^\[CRITICAL\] Defender detected .* and did NOT remove it: .*the action did not succeed') $t
    $v = V @((D 5)); $t = $v.Lines -join "`n"
    T 'Allowed (someone told Defender to leave it) is CRITICAL' ($v.Crit -eq 1 -and $t -match 'did NOT remove it: .*\(Allowed;') $t
    $v = V @((D 102)); T 'QuarantineFailed is CRITICAL' ($v.Crit -eq 1 -and ($v.Lines -join ' ') -match 'QuarantineFailed') ($v.Lines -join ' | ')
    $v = V @((D 1)); T 'Detected with no action taken is CRITICAL' ($v.Crit -eq 1) ($v.Lines -join ' | ')
    $v = V @((D 999)); $t = $v.Lines -join "`n"
    T 'a status code this check does not know is CRITICAL, and says so' ($v.Crit -eq 1 -and $t -match 'status code 999, not one this check knows') $t
    $v = V @((D 3 $true $true)); $t = $v.Lines -join "`n"
    T 'a threat still active is CRITICAL even when the record says Quarantined' ($v.Crit -eq 1 -and $t -match 'still active') $t
    $v = V @((D 4), (D 103 $true $false 'C:\ProgramData\evil.dll' 'Backdoor:Win32/Other')); $t = $v.Lines -join "`n"
    T 'a removed and an unremoved detection: both counted, the unremoved one first, the state active' ($v.Crit -eq 1 -and $v.Warn -eq 1 -and ($v.Lines[0] -match '^\[CRITICAL\].*Backdoor:Win32/Other') -and $v.State -eq 'det=active,n=2') $t
    $v = V @() 'The WS-Management service cannot process the request.'; $t = $v.Lines -join "`n"
    T 'a history that could not be read is a raised gap, never [OK]' ($v.Gap -and $t -match '(?m)^\[WARNING\] Defender detection history NOT checked -- ' -and $t -notmatch '\[OK\]' -and $v.State -eq 'det=gap,n=-') $t
    $v = V @() '' $false $false; $t = $v.Lines -join "`n"
    T 'an EMPTY answer on a standard-user token is a deferral, never [OK] (Defender masks what that token is shown)' ($v.Deferred -eq 1 -and -not $v.Gap -and $t -notmatch '\[OK\]' -and $v.State -eq 'det=deferred,n=-') $t
    $v = V @((D 3)) '' $false $false
    T 'a record a standard-user token WAS shown is still graded' ($v.Warn -eq 1 -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $script:PresenceHook = { param($r) 'gone' }
    $v = V @((D 102 $false)); $t = $v.Lines -join "`n"
    T 'a failed action on a file already gone stays CRITICAL and says the file is no longer present' ($v.Crit -eq 1 -and $t -match 'the file is no longer present at that path') $t
    $script:PresenceHook = { param($r) 'present' }
    $v = V @((D 102 $false)); T 'a failed action on a file still there says it is still present' (($v.Lines -join ' ') -match 'the file is still present') ($v.Lines -join ' | ')
    $script:PresenceHook = { param($r) 'unknown' }
    $v = V @((D 102 $false)); T 'presence that could not be established adds nothing' (($v.Lines -join ' ') -notmatch 'no longer present|still present') ($v.Lines -join ' | ')
    $script:PresenceHook = $null
    $old = D 3; $old.Time = '2026-01-02T00:00:00Z'; $new = D 3; $new.Time = '2026-11-02T00:00:00Z'; $new.Name = 'Trojan:Win32/Newest'
    $v = V @($old, $new); T 'the newest detection comes first (sorted as a date, not as text)' ($v.Lines[0] -match 'Newest') ($v.Lines -join ' | ')
    $v = V @() 'Access denied' $true $false; $t = $v.Lines -join "`n"
    T 'refused on a standard-user token: a counted deferral, no row, no [OK]' ($v.Deferred -eq 1 -and -not $v.Gap -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] ' -and $t -notmatch '\[OK\]') $t
    $v = V @() 'Access denied' $true $true
    T 'the same refusal elevated is a gap: the token explains nothing there' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = V @((D 3 $true $false ('C:\a' + [char]10 + '[OK] fake'))); $t = $v.Lines -join "`n"
    T 'a control character in a path cannot start a report line' ($t -notmatch '(?m)^\[OK\] fake') $t
    $many = @(); foreach ($k in 1..20) { $many += (D 3 $true $false ('C:\x\f' + $k + '.exe')) }
    $v = V $many; $t = $v.Lines -join "`n"
    T 'the list is capped, and the rest are counted' (@($v.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 15 -and $t -match '\.\.\.and 5 more detection' -and $v.Warn -eq 20) $t
    $v = Get-DetectionVerdict -Read @{ Error = 'The service cannot be started'; Denied = $false; Detections = @() } -OtherAv $true
    T 'another antivirus in force and Defender not answering: INFO, no gap, never [OK]' ((-not $v.Gap) -and $v.State -eq 'det=otherav,n=-' -and ($v.Lines -join ' ') -match '^\[INFO\]' -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-DetectionVerdict -Read @{ Error = ''; Denied = $false; Detections = @((D 3 $false)) } -OtherAv $true
    T 'another antivirus in force does not soften a detection Defender did record' ($v.Crit -eq 1) ($v.Lines -join ' | ')
    T 'Test-RefusedError: an access denial is a refusal; a broken service is not' ((Test-RefusedError (New-Object System.UnauthorizedAccessException 'x')) -and -not (Test-RefusedError (New-Object System.InvalidOperationException 'The service is not running.'))) ''

    if ($fails) { Write-Output "[FAIL] $fails defender_detections_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] defender_detections_check self-test: a detection Defender did not remove is CRITICAL, one it removed a WARNING, an unknown status counts as not removed, and a history that could not be read is a raised gap.'
    exit 0
}

if ($Elevated -lt 0) {
    $Elevated = 0
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 }
    } catch { }
}

'--- Defender Threat Detection History (what Defender itself has caught here) ---'
$read = @{ Error = ''; Denied = $false; Detections = @() }
try {
    $hist = @(Get-MpThreatDetection -ErrorAction Stop)
    $threats = @{}
    if ($hist.Count) {
        try {
            foreach ($t in @(Get-MpThreat -ErrorAction Stop)) { $threats[[string]$t.ThreatID] = $t }
        } catch {
            # The names and severities come from here; without them each line
            # says so, and the grade still comes from the detection itself.
            "[INFO] Get-MpThreat did not answer ($(ConvertTo-PrintableText $_.Exception.Message 160)); threat names and severities are shown by id."
        }
    }
    $dets = New-Object System.Collections.ArrayList
    foreach ($h in $hist) {
        $th = $threats[[string]$h.ThreatID]
        [void]$dets.Add(@{
            Name     = $(if ($th -and [string]$th.ThreatName) { [string]$th.ThreatName } else { 'threat id ' + [string]$h.ThreatID })
            Severity = $(if ($th) { $th.SeverityID } else { $null })
            Status   = $h.ThreatStatusID
            Success  = $h.ActionSuccess
            Active   = $(if ($th) { $th.IsActive } else { $null })
            Paths    = @($h.Resources)
            Time     = $h.InitialDetectionTime
            User     = [string]$h.DomainUser
            Process  = [string]$h.ProcessName
        })
    }
    $read.Detections = @($dets.ToArray())
} catch {
    $read.Error = $_.Exception.Message
    $read.Denied = (Test-RefusedError $_.Exception)
}
$v = Get-DetectionVerdict -Read $read -IsElevated ($Elevated -eq 1) -OtherAv ([bool]$OtherAv)
foreach ($l in $v.Lines) { $l }
try {
    if ($v.Crit) { Write-Marker -Name 'mpdet_crit' -Sev 'CRITICAL' }
    if ($v.Warn) { Write-Marker -Name 'mpdet_warn' -Sev 'WARNING' }
    if ($v.Gap) { Write-Marker -Name 'mpdet_gap' -Sev 'WARNING' }
    if ($v.Deferred) { Write-Marker -Name 'mpdet_deferred' -Sev ([string]$v.Deferred) }
    Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop
} catch {
    "[WARNING] Defender detection history: the verdict could not be written for the audit to read ($(ConvertTo-PrintableText $_.Exception.Message 160)) -- NOT performed."
}
exit 0
