# named_pipe_check.ps1 -- default C2 named pipes (T1071): the Cobalt Strike
# set (Section 17) and the Sliver / Havoc / Brute Ratel set (Section 18).
#
# Extracted from two inline blocks in both bats that read
#   try{ $pipes = Get-ChildItem \\.\pipe\ -EA SilentlyContinue | ... }
#   catch{ '[SKIPPED] Named pipe enumeration failed -- ... NOT performed.' }
# With -EA SilentlyContinue a failed listing is not an exception, so the catch
# never ran: a pipe list that could not be read printed "[OK] No Cobalt Strike
# default named pipes." having looked at nothing -- the "try/catch without
# -EA Stop is not error handling" mistake CLAUDE.md records for the PSv2
# check. And had the catch run, its [SKIPPED] raises nothing. The dashboard
# tile re-listed the pipes itself, with a SHORTER pattern list than the
# section's, and graded a hit CRIT where the section raised WARNING.
#
# THE RULE (pure, in Get-PipeVerdict, pinned by -SelfTest):
#   * a pipe name matching the set's patterns -> the names, then the WARNING
#     line the bats always printed, and a hit marker the bat raises with the
#     row it always raised;
#   * none -> [OK], the same wording;
#   * the list could not be read, or came back EMPTY (Windows always has
#     pipes) -> "[WARNING] ... NOT performed in full", its own gap marker. Hits
#     already listed before an error are still graded and raised. Any token
#     can list \\.\pipe\, so a failure is never a deferral.
# The patterns are the sections' own, unchanged. State line for the dashboard:
#   <set>=<count|gap>
#
# Usage:
#   powershell -File tools\named_pipe_check.ps1 -Set CobaltStrike|NextGenC2 [-MarkerDir <dir>] [-StateFile <path>]
#   powershell -File tools\named_pipe_check.ps1 -SelfTest   (lists nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [ValidateSet('CobaltStrike', 'NextGenC2')]
    [string]$Set = 'CobaltStrike',
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    # The directory to list. Only CI changes it, to one that does not exist, so
    # the could-not-read path runs through the real reader.
    [string]$PipeDir = '\\.\pipe\',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }

$script:PipeSets = @{
    CobaltStrike = @{ Key = 'cs'; Rx = 'postex_|msagent_|MSSE-|metsvc|beacon|cobaltstrike|status_'
        Found = '[WARNING] Possible Cobalt Strike pipes detected.'
        None = '[OK] No Cobalt Strike default named pipes.'
        What = 'Cobalt Strike named-pipe check' }
    NextGenC2 = @{ Key = 'c2'; Rx = 'sliverpb|havoc|bruteratel|badger_|b4_|_krbtgt|dcetest|systemd-|svc_pivot'
        Found = '[WARNING] Possible next-gen C2 named pipes detected.'
        None = '[OK] No Sliver/Havoc/BruteRatel default pipes.'
        What = 'Sliver/Havoc/Brute Ratel named-pipe check' }
}
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir ('dz_pipes_{0}_state.txt' -f $script:PipeSets[$Set].Key) }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintableText {
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

# PURE. $Names: every pipe name listed (possibly only part of the list);
# $ReadError: '' when the whole list was read, else why some or all of it
# could not be. Returns @{ Lines; Hit; Gap; State }.
#   * names that match are graded even when the listing failed part-way: a
#     postex_ pipe already listed must not be lost to a later error;
#   * any error, or an EMPTY list, is also a raised gap -- Windows always has
#     pipes (lsass, ntsvcs, InitShutdown), so zero entries means nothing was
#     read, never that nothing is there.
function Get-PipeVerdict {
    param([string]$SetName, [string[]]$Names = @(), [string]$ReadError = '')
    $s = $script:PipeSets[$SetName]
    $out = New-Object System.Collections.ArrayList
    $all = @($Names | Where-Object { $_ })
    if (-not $ReadError -and $all.Count -eq 0) { $ReadError = 'the pipe list came back empty, and Windows always has named pipes' }
    $hits = @($all | Where-Object { $_ -match $s.Rx } | Sort-Object -Unique)
    if ($all.Count -gt 0) { [void]$out.Add(('[INFO] Listed ' + $all.Count + ' named pipe(s).')) }
    if ($hits.Count -gt 0) {
        # The names first, as the inline check printed them (a Name column).
        [void]$out.Add('Name')
        [void]$out.Add('----')
        foreach ($h in $hits) { [void]$out.Add((ConvertTo-PrintableText $h)) }
        [void]$out.Add($s.Found)
    } elseif (-not $ReadError) {
        [void]$out.Add($s.None)
    }
    if ($ReadError) {
        $part = if ($all.Count -gt 0) { 'not all of the pipe list could be read' } else { 'the pipe list could not be read' }
        [void]$out.Add(('[WARNING] ' + $s.What + ' NOT performed in full -- ' + $part + ' (' + (ConvertTo-PrintableText $ReadError) + '), so a C2 pipe could go unseen (T1071).'))
    }
    $state = if ($hits.Count -gt 0) { $s.Key + '=' + $hits.Count } elseif ($ReadError) { $s.Key + '=gap' } else { $s.Key + '=0' }
    return @{ Lines = @($out.ToArray()); Hit = ($hits.Count -gt 0); Gap = [bool]$ReadError; State = $state }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $benign = @('InitShutdown', 'lsass', 'ntsvcs', 'scerpc', 'epmapper', 'LSM_API_service', 'eventlog', 'wkssvc', 'spoolss')
    $v = Get-PipeVerdict -SetName CobaltStrike -Names $benign
    T 'ordinary Windows pipes: [OK], nothing raised, the old wording kept' ((-not $v.Hit) -and (-not $v.Gap) -and $v.State -eq 'cs=0' -and ($v.Lines -join "`n") -match '(?m)^\[OK\] No Cobalt Strike default named pipes\.$' -and ($v.Lines -join "`n") -match '(?m)^\[INFO\] Listed 9 named pipe\(s\)\.$') ($v.Lines -join ' | ')
    $v = Get-PipeVerdict -SetName CobaltStrike -Names ($benign + @('MSSE-1234-server', 'postex_ssh_5678'))
    $t = $v.Lines -join "`n"
    T 'Cobalt Strike default pipes: named, then the WARNING line, and a hit' ($v.Hit -and $v.State -eq 'cs=2' -and $t -match '(?m)^MSSE-1234-server$' -and $t -match '(?m)^postex_ssh_5678$' -and $t -match '(?m)^\[WARNING\] Possible Cobalt Strike pipes detected\.$' -and $t -notmatch 'lsass') $t
    $v = Get-PipeVerdict -SetName NextGenC2 -Names ($benign + @('sliverpb_abc'))
    T 'the next-gen set uses its own patterns and wording' ($v.Hit -and $v.State -eq 'c2=1' -and ($v.Lines -join "`n") -match '(?m)^\[WARNING\] Possible next-gen C2 named pipes detected\.$') ($v.Lines -join ' | ')
    $v = Get-PipeVerdict -SetName NextGenC2 -Names ($benign + @('MSSE-1234-server'))
    T 'a Cobalt Strike pipe is not graded by the next-gen set (each set its own section)' ((-not $v.Hit) -and $v.State -eq 'c2=0') ($v.Lines -join ' | ')
    $v = Get-PipeVerdict -SetName CobaltStrike -ReadError 'IOException: The device is not ready'
    $t = $v.Lines -join "`n"
    T 'a pipe list that could not be read is a raised gap, never [OK] and never an unraised [SKIPPED]' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'cs=gap' -and $t -match '(?m)^\[WARNING\] Cobalt Strike named-pipe check NOT performed' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[SKIPPED\]') $t
    $v = Get-PipeVerdict -SetName CobaltStrike -Names @()
    T 'an EMPTY pipe list is a raised gap, never [OK] (Windows always has pipes)' ($v.Gap -and $v.State -eq 'cs=gap' -and ($v.Lines -join "`n") -notmatch '\[OK\]' -and ($v.Lines -join "`n") -match 'came back empty') ($v.Lines -join ' | ')
    $v = Get-PipeVerdict -SetName CobaltStrike -Names ($benign + @('postex_1234')) -ReadError 'ArgumentException: Illegal characters in path.'
    $t = $v.Lines -join "`n"
    T 'a listing that failed part-way keeps the hit it already listed AND raises the gap' ($v.Hit -and $v.Gap -and $v.State -eq 'cs=1' -and $t -match '(?m)^postex_1234$' -and $t -match '(?m)^\[WARNING\] Possible Cobalt Strike pipes detected\.$' -and $t -match 'not all of the pipe list could be read') $t
    $v = Get-PipeVerdict -SetName CobaltStrike -Names @(('postex_' + [char]10 + '[OK] fine'))
    T 'a control character in a pipe name cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails named_pipe_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] named_pipe_check self-test: a default C2 pipe is WARNING, none is OK, and a pipe list that could not be read is a raised gap, never an all-clear.'
    exit 0
}

# --- live ---------------------------------------------------------------------
# Names are collected as they come, so an error part-way loses none of the
# ones already listed; every error is kept and declared, never silenced.
$names = New-Object System.Collections.Generic.List[string]; $err = ''; $errs = $null
try {
    Get-ChildItem -LiteralPath $PipeDir -ErrorAction SilentlyContinue -ErrorVariable errs | ForEach-Object { $names.Add([string]$_.Name) }
} catch { $err = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
if (-not $err -and $errs -and @($errs).Count -gt 0) { $e0 = @($errs)[0]; $err = ($e0.Exception.GetType().Name + ': ' + $e0.Exception.Message) }
$v = $null
try { $v = Get-PipeVerdict -SetName $Set -Names @($names.ToArray()) -ReadError $err } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^(cs|c2)=(\d+|gap)$') {
    'named_pipe_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($Set -eq 'CobaltStrike') {
    if ($v.Hit) { Write-Marker -Name 'pipes_cs_hit' -Sev 'WARNING' }
    if ($v.Gap) { Write-Marker -Name 'pipes_cs_gap' -Sev 'WARNING' }
} else {
    if ($v.Hit) { Write-Marker -Name 'pipes_c2_hit' -Sev 'WARNING' }
    if ($v.Gap) { Write-Marker -Name 'pipes_c2_gap' -Sev 'WARNING' }
}
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('named_pipe_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
