# exec_probe.ps1 -- can this machine run the audit's helper scripts at all?
#
# Every check that uses a tools\*.ps1 helper, and every staged block, runs as
# `powershell -ExecutionPolicy Bypass -File ...`. Three things on a managed
# machine defeat that, and all of them used to read as CLEAN:
#
#   * an execution policy set by Group Policy (MachinePolicy / UserPolicy,
#     e.g. AllSigned) OVERRIDES -ExecutionPolicy Bypass, so every -File call
#     is refused; a refused helper writes no marker, and no marker means OK;
#   * AppLocker / WDAC script rules run PowerShell in ConstrainedLanguage,
#     where Add-Type and most .NET types throw inside the checks;
#   * a Group Policy RemoteSigned or Unrestricted policy lets an unmarked
#     script run, which is all this probe used to prove about ITSELF. A copy
#     unzipped from a download carries the Mark of the Web (a Zone.Identifier
#     stream) on its files: RemoteSigned refuses each marked helper, and
#     Unrestricted stops to ask about each one -- a question nobody sees,
#     because every helper's output goes to the report. Microsoft:
#     about_Execution_Policies ("Manage signed and unsigned scripts").
#
# The bat runs this ONCE, early, with -File and -NonInteractive. If no state
# file appears, scripts are refused; if the state names a language mode other
# than FullLanguage, the checks would run crippled; if the Mark of the Web
# verdict is not `ok`, some helpers would be refused or held at a prompt.
# Each way the audit says so and stops instead of printing CLEAN for checks
# that never ran.
#
# Only cmdlets and syntax that ConstrainedLanguage allows on the live path,
# so the probe itself can report that mode. Pure ASCII, Windows PowerShell 5.1.

[CmdletBinding()]
param(
    [string]$StateFile = '',
    [string]$MotwFile = '',
    [string]$MotwLinesFile = '',
    [string]$ToolsDir = '',
    [switch]$SelfTest
)

$script:Modes = @('FullLanguage', 'ConstrainedLanguage', 'RestrictedLanguage', 'NoLanguage')
$script:Verdicts = @('ok', 'refused', 'prompt', 'unknown', 'policy')
$script:NameCap = 12

function Get-ExecState {
    # 'ok|<LanguageMode>' -- the mode is always one of $script:Modes.
    $m = [string]$ExecutionContext.SessionState.LanguageMode
    if ($script:Modes -notcontains $m) { $m = 'Unknown' }
    return ('ok|' + $m)
}

function Get-ZoneFromStreamText {
    # The zone a Zone.Identifier stream assigns, read the way Windows reads
    # it: the first ZoneId= under a [ZoneTransfer] header. -1 = no zone (no
    # header, no ZoneId, empty): the file is not marked. -2 = a ZoneId that
    # is not a number, which this probe will not guess at.
    param([string]$Text)
    if (-not $Text) { return -1 }
    $inSection = $false
    foreach ($raw in ($Text -split "`r?`n")) {
        $l = $raw.Trim()
        if ($l -match '^\[(.*)\]$') { $inSection = ($Matches[1].Trim() -eq 'ZoneTransfer'); continue }
        if (-not $inSection) { continue }
        if ($l -match '^ZoneId\s*=\s*(.*)$') {
            $v = $Matches[1].Trim()
            if ($v -match '^\d{1,9}$') { return [int]$v }
            return -2
        }
    }
    return -1
}

function Get-ZoneMap {
    # 'tools\<name>.ps1' -> zone, for every helper script in $Dir. A stream
    # that cannot be opened (none, a FAT/exFAT stick, access denied) is -1:
    # PowerShell's own zone check opens the same stream with the same token
    # and reads an unopenable one as local. This reads the STREAM only;
    # Windows also zones a file by its path (a network share named by IP or
    # FQDN is Internet). This probe sits in the same folder, so that case
    # refuses or prompts the probe itself, and the bat names it.
    param([string]$Dir)
    $map = @{}
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -Filter '*.ps1' -File -EA Stop)) {
        # -Filter '*.ps1' also matches '.ps1xml' through 8.3 short names.
        if ($f.Extension -ne '.ps1') { continue }
        $z = -1
        try {
            $t = Get-Content -LiteralPath $f.FullName -Stream 'Zone.Identifier' -Raw -EA Stop
            $z = Get-ZoneFromStreamText ([string]$t)
        } catch { $z = -1 }
        $map[('tools\' + $f.Name)] = $z
    }
    return $map
}

function Get-GpoExecutionPolicy {
    # The policy Group Policy imposes, or 'Undefined'. Every helper runs with
    # -ExecutionPolicy Bypass, and only MachinePolicy and UserPolicy outrank
    # the Process scope that sets, so this -- not however this probe was
    # started -- is the policy the helpers run under.
    $m = [string](Get-ExecutionPolicy -Scope MachinePolicy)
    if ($m -and $m -ne 'Undefined') { return $m }
    $u = [string](Get-ExecutionPolicy -Scope UserPolicy)
    if ($u -and $u -ne 'Undefined') { return $u }
    return 'Undefined'
}

function ConvertTo-SafeText {
    # Report text the bat types verbatim: printable ASCII, no '*' (field_test
    # reads the banner up to the next '*'), capped.
    param([string]$s, [int]$Max = 200)
    $t = ($s -replace '[^\x20-\x7E]', '?') -replace '\*', ''
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

function Format-ZoneNames {
    param([string[]]$Names, [hashtable]$Zones)
    $out = @()
    $i = 0
    foreach ($n in $Names) {
        if ($i -ge $script:NameCap) { $out += ('    ...and {0} more' -f ($Names.Count - $script:NameCap)); break }
        $z = [int]$Zones[$n]
        $zt = 'zone ' + $z
        if ($z -eq -2) { $zt = 'ZoneId is not a number' }
        $out += ('    {0} ({1})' -f ($n -replace '[^A-Za-z0-9_.\\-]', ''), $zt)
        $i++
    }
    return $out
}

function Get-MotwVerdict {
    # Pure. GpoPolicy: what Get-GpoExecutionPolicy returned. Zones: what
    # Get-ZoneMap returned, or $null with ScanError when it threw.
    # Zones 0, 1 and 2 (this computer, intranet, trusted sites) are local to
    # PowerShell; 3 and 4 (internet, restricted sites) are downloaded; any
    # other value is one this probe will not guess at. Both rules are
    # measured on a real runner under both policies (windows-smoke,
    # readonly-field-test).
    param([string]$GpoPolicy, [hashtable]$Zones, [string]$ScanError = '')
    $lines = @()
    $harmless = (-not $GpoPolicy) -or (@('Undefined', 'Bypass') -contains $GpoPolicy)
    $checked = @('RemoteSigned', 'Unrestricted') -contains $GpoPolicy
    $pol = ConvertTo-SafeText $GpoPolicy 40

    if ($null -eq $Zones) {
        if ($harmless) {
            $lines += ('[INFO] The helper scripts could not be checked for the Mark of the Web (' + (ConvertTo-SafeText $ScanError) + '). Harmless here: no Group Policy script policy applies, so -ExecutionPolicy Bypass holds.')
            return @{ Verdict = 'ok'; Lines = $lines }
        }
        $lines += ''
        $lines += '*** AUDIT NOT PERFORMED -- the helper scripts could not be checked for the Mark of the Web, under a script policy that checks it ***'
        $lines += (' Group Policy sets the execution policy to ' + $pol + '. The check stopped with: ' + (ConvertTo-SafeText $ScanError))
        return @{ Verdict = 'unknown'; Lines = $lines }
    }

    $names = @($Zones.Keys | Sort-Object)
    $total = $names.Count
    $remote = @()
    $odd = @()
    foreach ($n in $names) {
        $z = [int]$Zones[$n]
        if (@(-1, 0, 1, 2) -contains $z) { continue }
        if ($z -eq 3 -or $z -eq 4) { $remote += $n } else { $odd += $n }
    }
    $marked = $remote.Count + $odd.Count

    if ($harmless) {
        if ($marked -gt 0) {
            $lines += ('[INFO] ' + $marked + ' of the ' + $total + ' helper scripts in tools carry the Mark of the Web. Harmless here: no Group Policy script policy applies, so -ExecutionPolicy Bypass holds. On a PC whose IT sets RemoteSigned or Unrestricted they would be refused or held at a prompt, so carry the tool there on a stick made by tools\make_usb_stick.ps1.')
        }
        return @{ Verdict = 'ok'; Lines = $lines }
    }

    if (-not $checked) {
        $lines += ''
        $lines += ('*** AUDIT NOT PERFORMED -- this machine''s script policy (' + $pol + ', set by Group Policy) does not run this audit''s unsigned helper scripts ***')
        $lines += (' Group Policy sets the execution policy to ' + $pol + ', which overrides -ExecutionPolicy Bypass. The helper scripts are not signed.')
        return @{ Verdict = 'policy'; Lines = $lines }
    }

    if ($marked -eq 0) {
        $lines += ('[INFO] Group Policy sets the execution policy to ' + $pol + '; none of the ' + $total + ' helper scripts carries the Mark of the Web, so PowerShell runs them all.')
        return @{ Verdict = 'ok'; Lines = $lines }
    }

    $lines += ''
    if ($remote.Count -gt 0) {
        if ($GpoPolicy -eq 'RemoteSigned') {
            $verdict = 'refused'
            $lines += ('*** AUDIT NOT PERFORMED -- ' + $remote.Count + ' of this audit''s helper scripts carry the Mark of the Web, and this machine''s script policy refuses them ***')
            $lines += ' Group Policy sets the execution policy to RemoteSigned. That overrides -ExecutionPolicy Bypass, and RemoteSigned refuses an unsigned script marked as downloaded from the internet. A refused helper writes nothing, and its check would read as clean. These are marked:'
        } else {
            $verdict = 'prompt'
            $lines += ('*** AUDIT NOT PERFORMED -- ' + $remote.Count + ' of this audit''s helper scripts carry the Mark of the Web, and this machine''s script policy stops to ask before running them ***')
            $lines += ' Group Policy sets the execution policy to Unrestricted. That overrides -ExecutionPolicy Bypass, and Unrestricted stops to ask before it runs a script marked as downloaded from the internet. The helpers write into the report, so that question would wait where nobody sees it. These are marked:'
        }
        $lines += @(Format-ZoneNames $remote $Zones)
        if ($odd.Count -gt 0) {
            $lines += ' These carry a mark whose zone this probe will not guess at:'
            $lines += @(Format-ZoneNames $odd $Zones)
        }
    } else {
        $verdict = 'unknown'
        $lines += ('*** AUDIT NOT PERFORMED -- ' + $odd.Count + ' of this audit''s helper scripts carry a Mark of the Web this probe cannot read, under a script policy that checks it ***')
        $lines += (' Group Policy sets the execution policy to ' + $pol + ', which checks this mark. These carry a zone this probe will not guess at, so it cannot tell whether PowerShell would run them:')
        $lines += @(Format-ZoneNames $odd $Zones)
    }
    $lines += ' They came from a downloaded ZIP, or were copied from one. Carry the tool on a stick made by tools\make_usb_stick.ps1 on your own laptop instead: it copies file contents only, so the mark does not travel. On a work machine, ask IT first (docs\second-machine.md).'
    return @{ Verdict = $verdict; Lines = $lines }
}

function Invoke-ExecProbe {
    # Writes the lines file, then the verdict, then the state line LAST: a
    # state line on disk means the probe finished.
    param([string]$Dir, [string]$State, [string]$Motw, [string]$MotwLines)
    $v = $null
    try {
        $gpo = Get-GpoExecutionPolicy
        $zones = $null
        $err = ''
        try { $zones = Get-ZoneMap $Dir } catch { $err = [string]$_.Exception.Message }
        $v = Get-MotwVerdict -GpoPolicy $gpo -Zones $zones -ScanError $err
    } catch {
        $v = @{ Verdict = 'unknown'; Lines = @('', '*** AUDIT NOT PERFORMED -- the script-policy probe could not check the helper scripts for the Mark of the Web ***', (' The check stopped with: ' + (ConvertTo-SafeText ([string]$_.Exception.Message)))) }
    }
    Set-Content -LiteralPath $MotwLines -Value @($v.Lines) -Encoding ASCII
    Set-Content -LiteralPath $Motw -Value $v.Verdict -Encoding ASCII
    Set-Content -LiteralPath $State -Value (Get-ExecState) -Encoding ASCII
}

if ($SelfTest) {
    $script:fails = 0
    $script:oks = 0
    function T([string]$Name, [bool]$Cond, [string]$Detail = '') {
        if ($Cond) { Write-Output ('[OK]   ' + $Name); $script:oks++ }
        else { Write-Output ('[FAIL] ' + $Name + $(if ($Detail) { ' -- ' + $Detail } else { '' })); $script:fails++ }
    }
    $banner = '\*\*\* AUDIT NOT PERFORMED -- ([^*]+)\*\*\*'
    function Text($v) { return (@($v.Lines) -join "`n") }

    $s = Get-ExecState
    T 'the state line is ok|<language mode>' ($s -match '^ok\|(FullLanguage|ConstrainedLanguage|RestrictedLanguage|NoLanguage|Unknown)$') $s
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_exec_probe_selftest_{0}.txt' -f $PID)
    Set-Content -LiteralPath $tmp -Value $s -Encoding ASCII
    $back = (Get-Content -LiteralPath $tmp -TotalCount 1)
    Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue
    T 'the state file round-trips as one ASCII line (read by set /p)' ($back -eq $s) $back

    # --- the stream text, read the way Windows reads it ---
    T 'ZoneId=3 under [ZoneTransfer] is zone 3' ((Get-ZoneFromStreamText "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://x/") -eq 3)
    T 'spaces around the ZoneId value are tolerated' ((Get-ZoneFromStreamText "[ZoneTransfer]`nZoneId = 4") -eq 4)
    T 'the header is matched case-insensitively' ((Get-ZoneFromStreamText "[zonetransfer]`nzoneid=3") -eq 3)
    T 'the FIRST ZoneId under the header wins' ((Get-ZoneFromStreamText "[ZoneTransfer]`nZoneId=2`nZoneId=3") -eq 2)
    T 'a ZoneId with no [ZoneTransfer] header is no mark' ((Get-ZoneFromStreamText "ZoneId=3") -eq -1)
    T 'a ZoneId under another section is no mark' ((Get-ZoneFromStreamText "[Other]`nZoneId=3") -eq -1)
    T 'an empty stream is no mark' ((Get-ZoneFromStreamText '') -eq -1)
    T 'a ZoneId that is not a number is -2, not a guess' ((Get-ZoneFromStreamText "[ZoneTransfer]`nZoneId=x") -eq -2)

    # --- the verdict ---
    $z2 = @{ 'tools\a.ps1' = -1; 'tools\b.ps1' = 3; 'tools\c.ps1' = 2 }
    $none = @{ 'tools\a.ps1' = -1; 'tools\b.ps1' = 0; 'tools\c.ps1' = 1; 'tools\d.ps1' = 2 }
    $v = Get-MotwVerdict -GpoPolicy 'Undefined' -Zones $none
    T 'no Group Policy, nothing marked: ok, nothing printed' ($v.Verdict -eq 'ok' -and @($v.Lines).Count -eq 0) (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'Undefined' -Zones $z2
    T 'no Group Policy, a marked helper: ok with an INFO line (Bypass holds)' ($v.Verdict -eq 'ok' -and (Text $v) -match '^\[INFO\] 1 of the 3 helper scripts' -and (Text $v) -notmatch 'AUDIT NOT PERFORMED') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'Bypass' -Zones $z2
    T 'a Group Policy value of Bypass is harmless too' ($v.Verdict -eq 'ok') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones $none
    T 'RemoteSigned, zones 0/1/2 and unmarked only: ok, INFO names the policy' ($v.Verdict -eq 'ok' -and (Text $v) -match 'Group Policy sets the execution policy to RemoteSigned; none of the 4 helper scripts') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'Unrestricted' -Zones $none
    T 'Unrestricted, nothing marked: ok (the stick case the docs call go)' ($v.Verdict -eq 'ok' -and (Text $v) -match 'to Unrestricted; none of the 4') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones $z2
    $t = Text $v
    T 'RemoteSigned, a zone-3 helper: refused, the banner counts it' ($v.Verdict -eq 'refused' -and $t -match '\*\*\* AUDIT NOT PERFORMED -- 1 of this audit''s helper scripts carry the Mark of the Web, and this machine''s script policy refuses them') $t
    T 'the refused helper is named with its zone' ($t -match '(?m)^    tools\\b\.ps1 \(zone 3\)$') $t
    T 'the zone-2 helper is NOT named (trusted sites are local to PowerShell)' ($t -notmatch 'c\.ps1') $t
    T 'the remedy names the stick' ($t -match 'tools\\make_usb_stick\.ps1') $t
    $v = Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones @{ 'tools\a.ps1' = 4 }
    T 'RemoteSigned, zone 4 (restricted sites): refused' ($v.Verdict -eq 'refused') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'Unrestricted' -Zones $z2
    T 'Unrestricted, a zone-3 helper: prompt, the banner says it stops to ask' ($v.Verdict -eq 'prompt' -and (Text $v) -match 'stops to ask before running them \*\*\*') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones @{ 'tools\a.ps1' = 5; 'tools\b.ps1' = -1 }
    T 'RemoteSigned, zone 5: unknown, never ok (fail closed)' ($v.Verdict -eq 'unknown' -and (Text $v) -match 'tools\\a\.ps1 \(zone 5\)') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'Unrestricted' -Zones @{ 'tools\a.ps1' = -2 }
    T 'Unrestricted, a ZoneId that is not a number: unknown' ($v.Verdict -eq 'unknown' -and (Text $v) -match 'ZoneId is not a number') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones @{ 'tools\a.ps1' = 3; 'tools\b.ps1' = 7 }
    T 'a zone-3 helper beside an odd zone: refused, and both are named' ($v.Verdict -eq 'refused' -and (Text $v) -match 'b\.ps1 \(zone 7\)') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'AllSigned' -Zones $none
    T 'AllSigned (an unsigned probe cannot get here): policy, blocked' ($v.Verdict -eq 'policy' -and (Text $v) -match 'AUDIT NOT PERFORMED') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'SomethingNew' -Zones $none
    T 'a policy name this probe does not know: blocked, never ok' ($v.Verdict -eq 'policy') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones $null -ScanError 'denied'
    T 'RemoteSigned and the scan threw: unknown, blocked' ($v.Verdict -eq 'unknown' -and (Text $v) -match 'denied') (Text $v)
    $v = Get-MotwVerdict -GpoPolicy 'Undefined' -Zones $null -ScanError 'denied'
    T 'no Group Policy and the scan threw: ok with an INFO line' ($v.Verdict -eq 'ok' -and (Text $v) -match '^\[INFO\]') (Text $v)

    $many = @{}
    foreach ($i in 1..15) { $many[('tools\m{0:D2}.ps1' -f $i)] = 3 }
    $many['tools\bad&|>name.ps1'] = 3
    $v = Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones $many
    $t = Text $v
    T 'the list is capped, and says how many more' ($t -match '(?m)^    \.\.\.and 4 more$') $t
    $v = Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones @{ 'tools\bad&|>name.ps1' = 3 }
    T 'a name is sanitised before cmd types it into the report' ((Text $v) -match 'tools\\badname\.ps1 \(zone 3\)' -and (Text $v) -notmatch '[&|>]') (Text $v)

    # Every block verdict: field_test's banner regex reads it, nothing in it
    # is a severity tag (this is not a finding), and every line is ASCII.
    $all = @(
        (Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones $z2),
        (Get-MotwVerdict -GpoPolicy 'Unrestricted' -Zones $z2),
        (Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones @{ 'tools\a.ps1' = 5 }),
        (Get-MotwVerdict -GpoPolicy 'AllSigned' -Zones $none),
        (Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones $null -ScanError 'x*y'),
        (Get-MotwVerdict -GpoPolicy 'Undefined' -Zones $z2),
        (Get-MotwVerdict -GpoPolicy 'RemoteSigned' -Zones $none)
    )
    $bannersOk = $true; $tagsOk = $true; $asciiOk = $true; $vocabOk = $true
    foreach ($r in $all) {
        $t = Text $r
        if ($script:Verdicts -notcontains $r.Verdict) { $vocabOk = $false }
        if ($r.Verdict -ne 'ok' -and $t -notmatch $banner) { $bannersOk = $false }
        if ($t -match '\[(WARNING|CRITICAL|WARN|CRIT|SKIPPED)\]') { $tagsOk = $false }
        if ($t -match '[^\x09\x0A\x20-\x7E]') { $asciiOk = $false }
    }
    T 'every verdict is in the vocabulary the bat reads' $vocabOk
    T 'every block verdict carries a banner field_test can read' $bannersOk
    T 'no line carries a severity tag (a blocked run is not a finding)' $tagsOk
    T 'every line is printable ASCII (cmd types it into the report)' $asciiOk

    # --- the live path ---
    $work = Join-Path ([IO.Path]::GetTempPath()) ('dz_exec_probe_live_{0}' -f $PID)
    $tdir = Join-Path $work 'tools'
    New-Item -ItemType Directory -Path $tdir -Force | Out-Null
    try {
        foreach ($n in 'a.ps1', 'b.ps1', 'c.ps1', 'd.ps1xml') { Set-Content -LiteralPath (Join-Path $tdir $n) -Value "'x'" -Encoding ASCII }
        $isWin = ([Environment]::OSVersion.Platform -eq 'Win32NT')
        if ($isWin) {
            Set-Content -LiteralPath (Join-Path $tdir 'b.ps1') -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3"
            Set-Content -LiteralPath (Join-Path $tdir 'c.ps1') -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=2"
            $m = Get-ZoneMap $tdir
            T 'live: an unmarked helper reads -1' ($m['tools\a.ps1'] -eq -1) ([string]$m['tools\a.ps1'])
            T 'live: a ZoneId=3 stream reads 3' ($m['tools\b.ps1'] -eq 3) ([string]$m['tools\b.ps1'])
            T 'live: a ZoneId=2 stream reads 2' ($m['tools\c.ps1'] -eq 2) ([string]$m['tools\c.ps1'])
            T 'live: a .ps1xml file is not a helper script' (-not $m.ContainsKey('tools\d.ps1xml') -and $m.Count -eq 3) (($m.Keys | Sort-Object) -join ',')
        } else {
            Write-Output '[SKIP] live Mark of the Web streams: NTFS alternate data streams exist only on Windows (windows-smoke runs these cases)'
        }
        $sf = Join-Path $work 'state.txt'; $mf = Join-Path $work 'motw.txt'; $lf = Join-Path $work 'lines.txt'
        Invoke-ExecProbe -Dir $tdir -State $sf -Motw $mf -MotwLines $lf
        $st = Get-Content -LiteralPath $sf -TotalCount 1
        $vd = Get-Content -LiteralPath $mf -TotalCount 1
        T 'live: the probe writes its state line' ($st -match '^ok\|') $st
        T 'live: the probe writes a verdict from the vocabulary' ($script:Verdicts -contains $vd) $vd
        T 'live: the probe writes the lines file the bat types' (Test-Path -LiteralPath $lf)
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
    }

    if ($script:fails -gt 0) { Write-Output ('FAILED: ' + $script:fails); exit 1 }
    Write-Output ('exec_probe self-test: all ' + $script:oks + ' cases passed')
    exit 0
}

if (-not $ToolsDir) { $ToolsDir = $PSScriptRoot }
if (-not $StateFile) { $StateFile = Join-Path $env:TEMP 'dz_exec_state.txt' }
if (-not $MotwFile) { $MotwFile = Join-Path $env:TEMP 'dz_exec_motw.txt' }
if (-not $MotwLinesFile) { $MotwLinesFile = Join-Path $env:TEMP 'dz_exec_motw_lines.txt' }
Invoke-ExecProbe -Dir $ToolsDir -State $StateFile -Motw $MotwFile -MotwLines $MotwLinesFile
