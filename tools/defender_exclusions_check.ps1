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
# configured"). When Get-MpPreference cannot be queried the single [SKIPPED]
# line is a gap that raises nothing (the core check beside it declares the
# same condition), and the tile reads NOT graded.
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

# Pure. $Pref is whatever Get-MpPreference returned (or any object with
# ExclusionPath / ExclusionProcess / ExclusionExtension); $PrefOk says whether
# the call succeeded at all. Returns the report lines, the severity to raise,
# and what the tiles need.
function Get-DefenderExclusionReport {
    param([bool]$PrefOk, $Pref)
    $out = New-Object System.Collections.Generic.List[string]
    $sev = 'OK'
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
            $items = Get-ExclusionItems $raw
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
        [void]$out.Add('[SKIPPED] Get-MpPreference failed -- Defender exclusions (paths, processes, extensions) NOT evaluated. Either a third-party AV owns protection or Defender itself is disabled; confirm manually which one it is.')
    }
    return @{
        Lines = @($out.ToArray()); Sev = $sev; Graded = $PrefOk
        Paths = $counts['path']; Processes = $counts['process']; Extensions = $counts['extension']
        State = (Get-ExclusionStateLine -Graded $PrefOk -Paths $counts['path'] -Processes $counts['process'] -Extensions $counts['extension'])
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
    T 'Get-MpPreference failed: one [SKIPPED], not graded, no severity invented, state 0|0|0|0' ($r.Sev -eq 'OK' -and (-not $r.Graded) -and (& $j $r) -match '^\[SKIPPED\] Get-MpPreference failed' -and (& $j $r) -notmatch '\[OK\]' -and (& $j $r) -notmatch '\[WARNING\]' -and $r.State -eq '0|0|0|0') ((& $j $r) + ' / ' + $r.State)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref ([pscustomobject]@{ Something = 1 })
    T 'an object without the exclusion properties grades as no exclusions, not as a crash' ($r.Sev -eq 'OK' -and $r.State -eq '1|0|0|0') ((& $j $r) + ' / ' + $r.State)
    $r = Get-DefenderExclusionReport -PrefOk $true -Pref (Pr -P @('C:\a', 'C:\b', 'C:\c') -X @('x.exe') -E @('.a', '.b'))
    T 'every kind at once: Sev stays WARNING (never CRITICAL), state 1|3|1|2' ($r.Sev -eq 'WARNING' -and $r.State -eq '1|3|1|2') $r.State
    T 'the state line is four integers' ((Get-ExclusionStateLine -Graded $true -Paths 12 -Processes 0 -Extensions 3) -match '^[01]\|\d+\|\d+\|\d+$') (Get-ExclusionStateLine -Graded $true -Paths 12 -Processes 0 -Extensions 3)
    T 'Get-MaxSev never lowers a WARNING to OK' ((Get-MaxSev 'WARNING' 'OK') -eq 'WARNING') ''
    if ($fails) { Write-Output "[FAIL] $fails defender_exclusions_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] defender_exclusions_check self-test: every exclusion is printed on its own line and raised WARNING; none is OK per kind; an unqueryable Get-MpPreference is SKIPPED and not graded, never OK.'
    exit 0
}

$pfOk = $true; $pr = $null
try { $pr = Get-MpPreference -ErrorAction Stop } catch { $pfOk = $false }
$rep = Get-DefenderExclusionReport -PrefOk $pfOk -Pref $pr
$rep.Lines
Write-Marker -Name 'defexcl' -Sev $rep.Sev
try {
    $d = Split-Path -Parent $StateFile
    if ($d -and -not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath $StateFile -Value $rep.State -Encoding ASCII
} catch {
    '[INFO] Could not write the Defender exclusion state file for the dashboard; the exclusion tiles will read NOT graded.'
}
