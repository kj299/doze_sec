# defender_exclusions_check.ps1 -- Section 9: which paths, processes and file
# extensions has Defender been told NOT to scan?
#
# An exclusion is the quietest way to blind an antivirus (T1562.001): nothing
# is disabled, every status flag still reads on, and whatever lives under the
# excluded path or runs as the excluded process is simply never looked at.
# Every exclusion is therefore printed and raised as a WARNING for a person
# to adjudicate; this tool does not decide that any of them is legitimate.
#
# Extracted from three staged blocks that lived inline in both bats. The
# dashboard tile then called Get-MpPreference AGAIN and graded that second
# measurement -- a tile that re-measures is a second opinion, not a summary
# (CLAUDE.md) -- and it had two further defects: when Get-MpPreference
# returned nothing it printed NO tile at all (an all-clear by omission), and
# extension exclusions never reached the dashboard. The tile now reads this
# section's verdict from the state file:
#   <graded 0/1>|<path count>|<process count>|<extension count>
# -- four integers, every field always present (cmd's for /f leaves the
# literal token text in a variable when a field is missing).
#
# Each excluded item is printed on its own line as '    path: <item>' (or
# process: / extension:), never as the bare value, so an item that happens to
# start with a severity tag cannot write a finding line into the report.
#
# Output goes to the report; the highest severity goes to the marker
# dz_defexcl.txt (the bat raises it into the ledger as "Defender exclusions
# configured"). When Get-MpPreference cannot be queried it is a raised gap
# (dz_defexcl_gap.txt), a counted deferral when a standard-user token was
# refused, or [INFO] when Windows Security Center names another antivirus.
# A STANDARD USER is not refused the call: Get-MpPreference answers, and puts
# the text "N/A: Must be an administrator to view exclusions" in place of each
# list. That text is never an exclusion: on a standard-user token it is a
# counted deferral (dz_defexcl_deferred.txt); elevated, it is a gap (Defender
# withheld the list from an administrator). In both cases the tile reads NOT
# graded, because the counts are unknown.
#
# Usage:
#   powershell -File tools\defender_exclusions_check.ps1 [-MarkerDir <dir>] [-StateFile <path>]
#   powershell -File tools\defender_exclusions_check.ps1 -SelfTest   (no Defender calls)
#
# Windows PowerShell 5.1 compatible; pure ASCII.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    # 1/0 from the caller, or -1: ask the token.
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_defexcl_state.txt' }

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

# Blank and null entries are not exclusions. A single value comes back from
# Get-MpPreference as a string, not an array; @() wraps either shape.
function Get-ExclusionItems {
    param($Value)
    $items = @()
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        $s = [string]$v
        if ($s.Trim() -eq '') { continue }
        $items += $s
    }
    return @($items)
}

# The state line the dashboard reads: four integers, always present.
function Get-ExclusionStateLine {
    param([bool]$Graded, [int]$Paths, [int]$Processes, [int]$Extensions)
    return ('{0}|{1}|{2}|{3}' -f $(if ($Graded) { '1' } else { '0' }), $Paths, $Processes, $Extensions)
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

# PURE. Defender's placeholder for a list this token may not see. The
# wording has varied ("Must be and administrator" in some builds), so only
# the shape is matched: N/A, then the word administrator.
function Test-WithheldList {
    param([string]$Item)
    return ([string]$Item -imatch '^\s*N/A\b.*administrator')
}

# Pure. $Pref is whatever Get-MpPreference returned (or any object with
# ExclusionPath / ExclusionProcess / ExclusionExtension); $PrefOk says whether
# the call succeeded at all. Returns the report lines, the severity to raise,
# and what the tiles need.
function Get-DefenderExclusionReport {
    param([bool]$PrefOk, $Pref, [string]$PrefErr = '', [bool]$PrefDenied = $false, [bool]$IsElevated = $true, $OtherAv = $null)
    $out = New-Object System.Collections.Generic.List[string]
    $sev = 'OK'; $gap = $false; $deferred = 0; $withheld = $false; $why = 'ok'
    $counts = @{ path = 0; process = 0; extension = 0 }
    if ($PrefOk) {
        $kinds = @(
            @{ Key = 'path';      Prop = 'ExclusionPath';      Plural = 'paths';      OkText = 'No path exclusions.' },
            @{ Key = 'process';   Prop = 'ExclusionProcess';   Plural = 'processes';  OkText = 'No process exclusions.' },
            @{ Key = 'extension'; Prop = 'ExclusionExtension'; Plural = 'extensions'; OkText = 'No extension exclusions.' }
        )
        foreach ($k in $kinds) {
            $raw = $null
            try { $raw = $Pref.($k.Prop) } catch { $raw = $null }
            $all = Get-ExclusionItems $raw
            if (@($all | Where-Object { Test-WithheldList $_ }).Count -gt 0) {
                $withheld = $true
                if (-not $IsElevated) {
                    [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] Defender withholds its exclusion {0} from a standard-user token ("N/A: Must be an administrator") -- they were not read; an audit run as administrator reads them.' -f $k.Plural))
                    $deferred++; $why = 'deferred'
                } else {
                    [void]$out.Add(('[WARNING] Defender exclusions check NOT performed in full -- the exclusion {0} were withheld even from this administrator token ("N/A ... administrator"), so a folder or program Defender skips would go unseen (T1562.001).' -f $k.Plural))
                    $gap = $true; $why = 'gap'
                }
                continue
            }
            $items = $all
            $counts[$k.Key] = $items.Count
            if ($items.Count -gt 0) {
                [void]$out.Add(('[WARNING] Exclusion {0} found ({1}) -- Defender never scans these; verify each one is yours and still needed (T1562.001):' -f $k.Plural, $items.Count))
                foreach ($it in $items) { [void]$out.Add(('    {0}: {1}' -f $k.Key, $it)) }
                $sev = Get-MaxSev $sev 'WARNING'
            } else {
                [void]$out.Add('[OK] ' + $k.OkText)
            }
        }
    } else {
        $f = Get-DefenderQueryFailure -Query 'Get-MpPreference' -What 'exclusions (paths, processes, extensions)' -Err $PrefErr -Denied $PrefDenied -IsElevated $IsElevated -Av $OtherAv
        [void]$out.Add($f.Line); if ($f.Gap) { $gap = $true }; $deferred += [int]$f.Deferred; $why = [string]$f.Reason
    }
    $graded = ($PrefOk -and -not $withheld)
    return @{
        Lines = @($out.ToArray()); Sev = $sev; Graded = $graded; Gap = $gap; Deferred = $deferred; Why = $why
        Paths = $counts['path']; Processes = $counts['process']; Extensions = $counts['extension']
        State = (Get-ExclusionStateLine -Graded $graded -Paths $counts['path'] -Processes $counts['process'] -Extensions $counts['extension'])
    }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    function Pr { param($P = $null, $X = $null, $E = $null)
        return [pscustomobject]@{ ExclusionPath = $P; ExclusionProcess = $X; ExclusionExtension = $E }
    }
    $j = { param($r) ($r.Lines -join "`n") }

    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr)
    T 'no exclusions: three [OK] lines, Sev OK, state 1|0|0|0' ($r.Sev -eq 'OK' -and $r.Graded -and (& $j $r) -match '^\[OK\] No path exclusions\.' -and (& $j $r) -match '\[OK\] No process exclusions\.' -and (& $j $r) -match '\[OK\] No extension exclusions\.' -and (& $j $r) -notmatch '\[WARNING\]' -and $r.State -eq '1|0|0|0') ((& $j $r) + ' / ' + $r.State)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -P @('C:\dz_selftest_excl_dir'))
    T 'one path: WARNING naming T1562.001, the item on its own "path:" line, count 1, state 1|1|0|0' ($r.Sev -eq 'WARNING' -and $r.Paths -eq 1 -and (& $j $r) -match '^\[WARNING\] Exclusion paths found \(1\).*T1562.001' -and (& $j $r) -match '(?m)^    path: C:\\dz_selftest_excl_dir$' -and $r.State -eq '1|1|0|0') ((& $j $r) + ' / ' + $r.State)
    T 'one path: the other two kinds still print their [OK] lines' ((& $j $r) -match '\[OK\] No process exclusions\.' -and (& $j $r) -match '\[OK\] No extension exclusions\.') (& $j $r)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -X @('a.exe', 'b.exe') -E @('.tmp'))
    T 'two processes and one extension: both WARNING lines with counts, state 1|0|2|1' ($r.Sev -eq 'WARNING' -and $r.Processes -eq 2 -and $r.Extensions -eq 1 -and (& $j $r) -match '\[WARNING\] Exclusion processes found \(2\)' -and (& $j $r) -match '\[WARNING\] Exclusion extensions found \(1\)' -and (& $j $r) -match '(?m)^    process: a\.exe$' -and (& $j $r) -match '(?m)^    extension: \.tmp$' -and $r.State -eq '1|0|2|1') ((& $j $r) + ' / ' + $r.State)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -P 'C:\single')
    T 'a single string (not an array) is one exclusion, not a character count' ($r.Paths -eq 1 -and $r.State -eq '1|1|0|0') $r.State
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -P @('', $null, '   ', 'C:\real'))
    T 'blank and null entries are not exclusions: one path counted' ($r.Paths -eq 1 -and (& $j $r) -match 'found \(1\)' -and (& $j $r) -notmatch '(?m)^    path: \s*$') ((& $j $r) + ' / ' + $r.State)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -P @('[CRITICAL] not a finding'))
    T 'an item that starts with a severity tag never starts a report line with one' ((& $j $r) -notmatch '(?m)^\s*\[CRITICAL\]' -and (& $j $r) -match '(?m)^    path: \[CRITICAL\] not a finding$') (& $j $r)
    $r = Get-DefenderExclusionReport -PrefOk $false -Pref $null
    T 'Get-MpPreference failed, no other antivirus: a raised gap (never [SKIPPED]-and-silent), not graded, no all-clear, state 0|0|0|0' ($r.Sev -eq 'OK' -and $r.Gap -and (-not $r.Graded) -and (& $j $r) -match '^\[WARNING\] Defender exclusions \(paths, processes, extensions\) check NOT performed -- Get-MpPreference failed' -and (& $j $r) -notmatch '\[OK\]' -and (& $j $r) -notmatch '\[SKIPPED\]' -and $r.State -eq '0|0|0|0') ((& $j $r) + ' / ' + $r.State)
    $na = 'N/A: Must be an administrator to view exclusions'
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -P @($na) -X @($na) -E @($na)) -IsElevated $false
    T 'a standard user sees "N/A: Must be an administrator": three counted deferrals, NO exclusion WARNING, not graded' ($r.Sev -eq 'OK' -and $r.Deferred -eq 3 -and (-not $r.Gap) -and (-not $r.Graded) -and (& $j $r) -notmatch 'Exclusion paths found' -and (& $j $r) -match '^\[DEFERRED - ADMIN REQUIRED\] Defender withholds its exclusion paths' -and $r.State -eq '0|0|0|0') ((& $j $r) + ' / ' + $r.State)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -P @('N/A: Must be and administrator to view exclusions')) -IsElevated $false
    T 'the older wording ("Must be and administrator") is the same placeholder, never a path' ($r.Deferred -eq 1 -and $r.Sev -eq 'OK' -and $r.Why -eq 'deferred') (& $j $r)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -P @($na)) -IsElevated $true
    T 'the placeholder on an ADMINISTRATOR token: a raised gap, never an exclusion and never a deferral' ($r.Gap -and $r.Deferred -eq 0 -and $r.Sev -eq 'OK' -and (& $j $r) -notmatch 'Exclusion paths found') (& $j $r)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -P @('C:\N/A administrator stuff'))
    T 'a real path that merely contains the words is still an exclusion' ($r.Sev -eq 'WARNING' -and $r.Paths -eq 1) (& $j $r)
    $r = Get-DefenderExclusionReport -PrefOk $false -Pref $null -PrefErr 'CimException: Access denied' -PrefDenied $true -IsElevated $false
    T 'Get-MpPreference REFUSED to a standard-user token: a counted deferral, no gap' ($r.Deferred -eq 1 -and (-not $r.Gap)) (& $j $r)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref ([pscustomobject]@{ Something = 1 })
    T 'an object without the exclusion properties grades as no exclusions, not as a crash' ($r.Sev -eq 'OK' -and $r.State -eq '1|0|0|0') ((& $j $r) + ' / ' + $r.State)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -P @('C:\a', 'C:\b', 'C:\c') -X @('x.exe') -E @('.a', '.b'))
    T 'every kind at once: Sev stays WARNING (never CRITICAL), state 1|3|1|2' ($r.Sev -eq 'WARNING' -and $r.State -eq '1|3|1|2') $r.State
    T 'the state line is four integers' ((Get-ExclusionStateLine -Graded $true -Paths 12 -Processes 0 -Extensions 3) -match '^[01]\|\d+\|\d+\|\d+$') (Get-ExclusionStateLine -Graded $true -Paths 12 -Processes 0 -Extensions 3)
    T 'Get-MaxSev never lowers a WARNING to OK' ((Get-MaxSev 'WARNING' 'OK') -eq 'WARNING') ''
    if ($fails) { Write-Output "[FAIL] $fails defender_exclusions_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] defender_exclusions_check self-test: every exclusion is printed on its own line and raised WARNING; none is OK per kind; an unqueryable Get-MpPreference is a raised gap (or a deferral on a refused standard-user token), never OK; the standard user''s "N/A: Must be an administrator" placeholder is a deferral, never an exclusion.'
    exit 0
}

if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$pfOk = $true; $pr = $null; $pfErr = ''; $pfDen = $false
try { $pr = Get-MpPreference -ErrorAction Stop } catch { $pfOk = $false; $pfErr = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); $pfDen = Test-DefenderAccessDenied $_.Exception }
$other = $null
if (-not $pfOk) { $other = Get-OtherAntivirus }
$rep = Get-DefenderExclusionReport -PrefOk $pfOk -Pref $pr -PrefErr $pfErr -PrefDenied $pfDen -IsElevated ($Elevated -eq 1) -OtherAv $other
$rep.Lines
Write-Marker -Name 'defexcl' -Sev $rep.Sev
if ($rep.Gap) { Write-Marker -Name 'defexcl_gap' -Sev 'WARNING' }
if ([int]$rep.Deferred -gt 0) { Write-Marker -Name 'defexcl_deferred' -Sev ([string][int]$rep.Deferred) }
# Why the lists were not graded (ok|deferred|otherav|gap), for the tiles.
try { Set-Content -LiteralPath (Join-Path $MarkerDir 'dz_defexcl_why.txt') -Value $rep.Why -Encoding ASCII } catch {}
try {
    $d = Split-Path -Parent $StateFile
    if ($d -and -not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath $StateFile -Value $rep.State -Encoding ASCII
} catch {
    '[INFO] Could not write the Defender exclusion state file for the dashboard; the exclusion tiles will read NOT graded.'
}
