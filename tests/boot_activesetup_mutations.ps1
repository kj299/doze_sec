# boot_activesetup_mutations.ps1 -- every rule of tools\boot_activesetup_check.ps1,
# weakened one at a time, must FAIL that tool's own self-test.
#
# WHY: that check was wrong twice with a green self-test (PR #317: 11 of 17
# hostile lines read [OK]; its rework: eleven more classes). A test that still
# passes when the rule it names is removed is not testing the rule. Writing
# these mutations found two such tests in the third version before it was
# pushed (the component cap, and a guard another guard covered).
#
# Each entry replaces ONE exact piece of the tool's source with a weaker one,
# writes the copy to a scratch folder, and runs its -SelfTest. The copy must
# exit non-zero with at least one [FAIL]. An entry whose text is no longer in
# the tool exactly once fails too: whoever rewrites a rule rewrites its
# mutation, which is the point.
#
# -Canary adds a change that weakens nothing (a comment); the run must then
# report it as a survivor and exit 1. lint.yml runs both, so this file is
# shown to fail when a weakened rule goes unnoticed.
#
# Reads the tool, writes only under the temp folder, runs the copies'
# self-tests (pure: a pretend disk). Windows PowerShell 5.1 and pwsh.
[CmdletBinding()]
param(
    [switch]$Canary,
    [string[]]$Only = @(),
    [int]$Throttle = 0
)
$ErrorActionPreference = 'Stop'
$tool = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\boot_activesetup_check.ps1'
if (-not (Test-Path -LiteralPath $tool)) { $tool = Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools') 'boot_activesetup_check.ps1' }
$src = ([IO.File]::ReadAllText($tool)) -replace "`r`n", "`n"

# (Named apart from the loop variable below: PowerShell names are
# case-insensitive, and `foreach ($m in $M)` leaves $M holding its last item.)
$Mutations = @(
    @{ Id = 'M01'; What = '''.'' in a path is not collapsed'; Old = @'
if ($seg -eq '' -or $seg -eq '.') { continue }
'@; New = @'
if ($seg -eq '') { continue }
'@ },
    @{ Id = 'M02'; What = 'staging text is not normalised'; Old = @'
        if (((Get-NormalWinPath $t.Substring($m.Index, $end - $m.Index)) + '\') -match $script:StagingRx) { return $true }
'@; New = @'
        if ($false) { return $true }
'@ },
    @{ Id = 'M03'; What = 'device names may be opened'; Old = @'
        if ($seg -match $script:DeviceNameRx) { return $false }
    }
    $k = ''
'@; New = @'
        if ($false) { return $false }
    }
    $k = ''
'@ },
    @{ Id = 'M04'; What = 'any drive may be opened'; Old = @'
    return ($k -eq 'Fixed')
'@; New = @'
    return $true
'@ },
    @{ Id = 'M05'; What = 'a try that looks like an argument ends the search'; Old = @'
        if ($c.ArgLike) { $sawArg = $true }
'@; New = @'
        if ($c.ArgLike) { $sawArg = $true; if ($i -gt 0) { break } }
'@ },
    @{ Id = 'M06'; What = 'a forward slash is not a separator'; Old = @'
    $t = ([string]$Prefix) -replace '/', '\'
    if ((Get-WinLeaf $t) -notmatch '\.') { $t = $t + '.exe' }
'@; New = @'
    $t = ([string]$Prefix)
    if ((Get-WinLeaf $t) -notmatch '\.') { $t = $t + '.exe' }
'@ },
    @{ Id = 'M07'; What = 'every unopenable later reading is called impossible'; Old = @'
            if (Test-ImpossibleName $real) { break }
'@; New = @'
            if ($true) { break }
'@ },
    @{ Id = 'M08'; What = 'the argument-only text is matched without case'; Old = @'
$script:StockArgOnly -ccontains $raw
'@; New = @'
$script:StockArgOnly -contains $raw
'@ },
    @{ Id = 'M09'; What = 'a renamed Microsoft program is not noticed'; Old = @'
        $out.Renamed = $true; $out.Name = $orig
'@; New = @'
        $out.Renamed = $false
'@ },
    @{ Id = 'M10'; What = 'any other Microsoft program is graded like a vendor''s'; Old = @'
    $out.Kind = 'ms-other'

'@; New = @'
    $out.Kind = 'vendor'

'@ },
    @{ Id = 'M11'; What = 'a known program takes any argument'; Old = @'
            if ($k.Quoted -or ($x -notmatch $script:RxSwitch -and $x -notmatch $script:RxWord)) { $out.Ok = $false; $out.Why = $x; return $out }
'@; New = @'
            if ($false) { $out.Ok = $false; $out.Why = $x; return $out }
'@ },
    @{ Id = 'M12'; What = 'text after an entry point is allowed'; Old = @'
        if ($d.Tail -and -not $out.Known) { $out.Ok = $false; $out.Why = [string]$d.Tail; return $out }
'@; New = @'
        if ($false) { $out.Ok = $false; $out.Why = [string]$d.Tail; return $out }
'@ },
    @{ Id = 'M13'; What = 'every rundll32 call is a known one'; Old = @'
        $out.Known = ($script:KnownDllCalls -contains $key)
'@; New = @'
        $out.Known = $true
'@ },
    @{ Id = 'M14'; What = 'a signed vendor program anywhere is fine'; Old = @'
        if (-not (Test-AdminOnlyPath $p $SystemRoot)) {
            return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs $pv (signed by $($f.CN)) from a folder
'@; New = @'
        if ($false) {
            return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs $pv (signed by $($f.CN)) from a folder
'@ },
    @{ Id = 'M15'; What = 'a program file under a data name is not judged'; Old = @'
if (($code -or $g.Pe) -and $g.State -ne 'signed')
'@; New = @'
if (($code) -and $g.State -ne 'signed')
'@ },
    @{ Id = 'M16'; What = 'a host named in a vendor''s arguments is not seen'; Old = @'
        if ($h.Success) { return @{ Kind = 'host'; Text = $h.Value } }
'@; New = @'
        if ($false) { return @{ Kind = 'host'; Text = $h.Value } }
'@ },
    @{ Id = 'M17'; What = 'a network endpoint in a vendor''s arguments is not seen'; Old = @'
        if ($ep.Success) { return @{ Kind = 'endpoint'; Text = $ep.Value } }
'@; New = @'
        if ($false) { return @{ Kind = 'endpoint'; Text = $ep.Value } }
'@ },
    @{ Id = 'M18'; What = 'cmd start takes a name without its folder'; Old = @'
/C[ \t]+start[ \t]+([A-Za-z]:\\[^ \t,;=]*\.exe)((?:[ \t].*)?)$')
            if ($c.Success) {
                $inner = Get-FileFacts $c.Groups[1].Value $Probe $DriveKind
                if (@('signed', 'unsigned', 'unverified', 'unread') -contains [string]$inner.State) {
'@; New = @'
/C[ \t]+start[ \t]+([^ \t,;=]*\.exe)((?:[ \t].*)?)$')
            if ($c.Success) {
                $inner = @{ State = 'signed' }
                if (@('signed', 'unsigned', 'unverified', 'unread') -contains [string]$inner.State) {
'@ },
    @{ Id = 'M19'; What = 'cmd start is unwrapped more than once'; Old = @'
if ($Depth -eq 0 -and $leaf -eq 'cmd.exe'
'@; New = @'
if ($Depth -lt 5 -and $leaf -eq 'cmd.exe'
'@ },
    @{ Id = 'M20'; What = 'a Microsoft native in BootExecute is INFO'; Old = @'
        return @{ Sev = 'WARNING'; Line = "[WARNING] $run -- signed by $($Facts.CN), but it is not the disk check.
'@; New = @'
        return @{ Sev = 'OK'; Line = "[INFO] $run -- signed by $($Facts.CN), but it is not the disk check.
'@ },
    @{ Id = 'M21'; What = 'any Unicode space separates autochk''s arguments'; Old = @'
'^(?i)[ \t]*(autocheck[ \t]+)?autochk(\.exe)?([ \t]+(
'@; New = @'
'^(?i)\s*(autocheck\s+)?autochk(\.exe)?(\s+(
'@ },
    @{ Id = 'M22'; What = 'a BootExecute of another kind is read as text'; Old = @'
        if ($kind -and @('MultiString', 'String', 'ExpandString') -notcontains $kind) {
'@; New = @'
        if ($false) {
'@ },
    @{ Id = 'M23'; What = 'registry text is printed as it is'; Old = @'
    return ((([string]$Text) -replace '[\x00-\x1F\x7F-\x9F\u2028\u2029\u200E\u200F\u202A-\u202E\u2066-\u2069]+', ' ').Trim())
'@; New = @'
    return ([string]$Text)
'@ },
    @{ Id = 'M24'; What = 'an over-long StubPath is parsed'; Old = @'
    if ($raw.Length -gt $script:MaxStubLength) {
'@; New = @'
    if ($false) {
'@ },
    @{ Id = 'M25'; What = 'a StubPath of another kind is read as text'; Old = @'
    if ($Kind -and @('String', 'ExpandString') -notcontains $Kind) {
'@; New = @'
    if ($false) {
'@ },
    @{ Id = 'M26'; What = 'a per-user path is graded on this account''s copy'; Old = @'
    if ((Test-PerUserText $p $pu) -or (Test-PerUserText (Get-FirstToken $x) $pu)) {
'@; New = @'
    if ($false) {
'@ },
    @{ Id = 'M27'; What = 'the door opens whatever it is given'; Old = @'
    if (-not (Test-OpenablePath $p $DriveKind)) { return @{ State = 'notlocal'; RealPath = $p } }
'@; New = @'
    if ($false) { return @{ State = 'notlocal'; RealPath = $p } }
'@ },
    @{ Id = 'M28'; What = 'a line with more words than are tried can still be stale'; Old = @'
        if ($tries.Count -ge $script:MaxTries) { $out.Truncated = $true }
'@; New = @'
        if ($false) { $out.Truncated = $true }
'@ },
    @{ Id = 'M29'; What = 'a DLL named without a folder and found nowhere is stale'; Old = @'
    if ($bare) { return @{ State = 'unplaced'; RealPath = $t } }
'@; New = @'
    if ($false) { return @{ State = 'unplaced'; RealPath = $t } }
'@ },
    @{ Id = 'M30'; What = 'an msiexec property may hold a server name'; Old = @'
$script:RxMsiProp = '^[A-Z][A-Z0-9_]*=[A-Za-z0-9_-]*$'
'@; New = @'
$script:RxMsiProp = '^[A-Z][A-Z0-9_]*=[A-Za-z0-9_.-]*$'
'@ },
    @{ Id = 'M31'; What = 'a signed file handed from a user-writable folder is fine'; Old = @'
        if (-not (Test-AdminOnlyPath ([string]$g.RealPath) $SystemRoot)) { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a file (signed by
'@; New = @'
        if ($false) { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a file (signed by
'@ },
    @{ Id = 'M32'; What = 'any number of components is graded'; Old = @'
            if ($seen -gt $script:MaxEntries) { continue }
'@; New = @'
            if ($false) { continue }
'@ },
    @{ Id = 'M33'; What = 'a pure function touches a file'; Old = @'
function Get-FirstToken {
    param([string]$Line)

'@; New = @'
function Get-FirstToken {
    param([string]$Line)
    if ($false) { [void](Test-Path -LiteralPath $Line) }

'@ },
    @{ Id = 'M34'; What = 'another vendor''s program is called [OK]'; Old = @'
Line = "[INFO] $label runs $pv (signed by $($f.CN)), another vendor's program:
'@; New = @'
Line = "[OK] $label runs $pv (signed by $($f.CN)), another vendor's program:
'@ },
    @{ Id = 'M35'; What = 'a signed line that is not on record is called [OK]'; Old = @'
    return @{ Sev = 'OK'; File = $p; Line = "[INFO] $label runs $pv (signed by $($f.CN))$detail -- validly signed, but not a line
'@; New = @'
    return @{ Sev = 'OK'; File = $p; Line = "[OK] $label runs $pv (signed by $($f.CN))$detail -- validly signed, but not a line
'@ },
    @{ Id = 'M36'; What = 'a known switch set is not required'; Old = @'
            if ($known -notcontains $x) { $all = $false }
'@; New = @'
            if ($false) { $all = $false }
'@ },
    @{ Id = 'M37'; What = 'a staging path that is not on disk yet is only a WARNING'; Old = @'
        if ($r.Shape -eq 'notfound' -and $stg.Count) { return @{ Sev = 'CRITICAL';
'@; New = @'
        if ($false) { return @{ Sev = 'CRITICAL';
'@ },
    @{ Id = 'M38'; What = 'the long name of the program is not used for the staging test'; Old = @'
    if (Test-StagingText $p) { return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath runs $pv from a staging path ${tail}: $s (T1547.014)" } }
'@; New = @'

'@ },
    @{ Id = 'M39'; What = 'a relative path is looked up as if it had no folder'; Old = @'
            if ($i -eq 0) { $out.Shape = 'relative'; $out.Program = $text }
            break
'@; New = @'
            [void]$tried.Add($text); continue
'@ },
    @{ Id = 'M40'; What = 'a file probe calls the disk outside the door'; Old = @'
    $f = Get-FileFacts $path $Probe $DriveKind
        $real
'@; New = @'
    $f = & $Probe $path
        $real
'@ },
    @{ Id = 'M41'; What = 'a link on the path is followed'; Old = @'
        if ($f.State -eq 'reparse') {
            $out.Shape = 'notlocal'; $out.Program = $real; $out.Facts = $f
            break
        }
'@; New = @'

'@ },
    @{ Id = 'M42'; What = 'the search-path lookup takes any name'; Old = @'
    if (-not (Test-PlainName $Name)) { return '' }
'@; New = @'

'@ },
    @{ Id = 'M43'; What = 'more than 64 boot entries are graded silently'; Old = @'
        if ($entries.Count -gt $script:MaxBootEntries) {
'@; New = @'
        if ($false) {
'@ },
    @{ Id = 'M44'; What = 'a known DLL call is [OK] wherever the DLL is'; Old = @'
            if ($h.Must) { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv something this check cannot account for (text after the entry point of $gp) ${tail}: $s -- read what it is (T1547.014)." } }
            $known = $false
'@; New = @'
            $known = $true
'@ }
)
if ($Canary) {
    $Mutations += @{ Id = 'C00'; What = 'a change that weakens nothing (the canary: it must survive, and be reported)'; Old = @'
# PURE. The first word of a command line: a quoted path, or up to the space.
'@; New = @'
# PURE. The first word of a command line: a quoted path or up to the space.
'@ }
}
# `-File ... -Only A,B` hands over ONE string; split it. And a run that
# tested nothing is a failure, never "[OK] each of 0 rules".
$want = @($Only | ForEach-Object { ([string]$_) -split '[,; ]+' } | Where-Object { $_ })
$total = $Mutations.Count
if ($want.Count) { $Mutations = @($Mutations | Where-Object { $want -contains $_.Id }) }
if ($Mutations.Count -eq 0 -or ($want.Count -eq 0 -and $total -lt 40)) {
    Write-Output ("[FAIL] boot_activesetup_mutations: {0} mutation(s) selected of {1} -- nothing, or too little, would be tested" -f $Mutations.Count, $total)
    exit 1
}
if ($Throttle -lt 1) { $Throttle = [Math]::Max(2, [Environment]::ProcessorCount) }

$exe = (Get-Process -Id $PID).Path
$dir = Join-Path ([IO.Path]::GetTempPath()) ("dz_bas_mut_{0}" -f $PID)
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$bad = New-Object System.Collections.Generic.List[string]
$jobs = New-Object System.Collections.Generic.List[object]
try {
    foreach ($mu in $Mutations) {
        $old = ([string]$mu.Old) -replace "`r`n", "`n"
        $new = ([string]$mu.New) -replace "`r`n", "`n"
        $n = ([regex]::Matches($src, [regex]::Escape($old))).Count
        if ($n -ne 1) { $bad.Add(("{0} ({1}): its text is in the tool {2} time(s), not once -- the rule was rewritten; rewrite its mutation" -f $mu.Id, $mu.What, $n)); continue }
        $f = Join-Path $dir ($mu.Id + '.ps1')
        [IO.File]::WriteAllText($f, $src.Replace($old, $new))
        $jobs.Add(@{ Mu = $mu; File = $f; Out = ($f + '.out'); Err = ($f + '.err') })
    }
    for ($i = 0; $i -lt $jobs.Count; $i += $Throttle) {
        $batch = @($jobs[$i..([Math]::Min($i + $Throttle, $jobs.Count) - 1)])
        foreach ($j in $batch) {
            $j.Proc = Start-Process -FilePath $exe -ArgumentList @('-NoProfile', '-NonInteractive', '-File', ('"' + $j.File + '"'), '-SelfTest') -RedirectStandardOutput $j.Out -RedirectStandardError $j.Err -PassThru -NoNewWindow
            # Without this the exit code of a finished process cannot be read on Windows.
            $null = $j.Proc.Handle
        }
        foreach ($j in $batch) {
            # A weakened rule must not make the self-test hang either.
            if (-not $j.Proc.WaitForExit(600000)) { try { $j.Proc.Kill() } catch {}; $bad.Add(("{0} ({1}): the weakened copy's self-test did not end within 10 minutes" -f $j.Mu.Id, $j.Mu.What)); continue }
            $j.Proc.WaitForExit()
            $text = ''
            try { $text = [IO.File]::ReadAllText($j.Out) } catch {}
            $fails = @($text -split "`r?`n" | Where-Object { $_ -match '^\[FAIL\] ' })
            # The summary line counts as one; a real kill has a named case too.
            if ($j.Proc.ExitCode -ne 0 -and $fails.Count -ge 2) { Write-Output ("[OK]   {0} {1} -- caught: {2}" -f $j.Mu.Id, $j.Mu.What, ([string]$fails[0]).Substring(0, [Math]::Min(110, ([string]$fails[0]).Length))) }
            else { $bad.Add(("{0} ({1}): the weakened copy still PASSES its self-test (exit {2}, {3} [FAIL] line(s)) -- no case tests this rule" -f $j.Mu.Id, $j.Mu.What, $j.Proc.ExitCode, $fails.Count)) }
        }
    }
} finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}
if ($bad.Count) {
    foreach ($b in $bad) { Write-Output "[FAIL] $b" }
    Write-Output ("[FAIL] {0} of {1} weakened rule(s) went unnoticed by boot_activesetup_check -SelfTest" -f $bad.Count, $Mutations.Count)
    exit 1
}
Write-Output ("[OK] boot_activesetup_mutations: each of {0} rules, weakened, fails the self-test." -f $Mutations.Count)
exit 0
