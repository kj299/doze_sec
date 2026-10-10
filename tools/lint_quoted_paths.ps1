# lint_quoted_paths.ps1 -- a path never goes between single quotes in the
# PowerShell the batch files run.
#
# WHY: the bats build PowerShell as text -- lines echoed into %PSRUN%, inline
# -Command "..." strings -- and several pasted a path into it between single
# quotes: $scf='%SUMCODE%'. A Windows user named O'Brien has the profile folder
# C:\Users\O'Brien, and %TEMP%, %APPDATA% and (for a standard user) the whole
# output folder live under it. The pasted apostrophe ends the PowerShell string
# early, the script is a parse error, and it prints and raises nothing: such a
# user got no dashboard, no remediation script, no Section 11 history, and five
# Section 18 matches that silently never ran. PowerShell also reads the
# typographic apostrophe as a quote, so O'Brien typed on a phone breaks it too.
#
# RULE, both bats:
#   - In PowerShell source (an echo line written into %PSRUN%, or a line that
#     runs powershell -Command "..."), a path-valued variable must be read from
#     the environment ($env:REPORT); cmd's variables are the child's
#     environment. Pasting %X% or !X! between single quotes fails.
#   - In a printed Command: line, which a reader pastes, a path-valued
#     variable between single quotes must be written %X:'=''%: cmd doubles any
#     apostrophe, and a doubled apostrophe is a literal one inside a
#     single-quoted PowerShell string.
# A variable is path-valued when it is one Windows sets under the user's
# profile (TEMP, TMP, USERPROFILE, APPDATA, LOCALAPPDATA, HOMEPATH, USERNAME,
# OneDrive) or when any set line gives it a value holding a backslash, a drive,
# a %~ modifier, or another path-valued variable -- iterated to a fixpoint, so
# a new path variable is covered the day it is added. Values the bats set
# themselves from fixed vocabularies (PPL_STATE, IOC_HITS...) are not paths.
#
# -SelfTest proves it fails on each defect it exists for, stays quiet on a
# state value and on a comment, and covers a path variable added later.
#
# Windows PowerShell 5.1 and pwsh 7; pure ASCII; no dependencies.

[CmdletBinding()]
param(
    [string]$Root = '',
    [switch]$SelfTest
)

# The root is derived in the body: Windows PowerShell 5.1 run with -File leaves
# $PSCommandPath empty while the param block is evaluated.
if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }

$ErrorActionPreference = 'Stop'

$script:Seeds = @('TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'HOMEPATH', 'USERNAME', 'OneDrive', 'OneDriveConsumer', 'OneDriveCommercial')

function Test-Comment {
    param([string]$Line)
    return ($Line -match '^\s*(::|rem\s|rem$|@rem\s)')
}

function Get-PathVars {
    # The set of path-valued variable names (upper-cased) for one bat's lines.
    param([string[]]$Lines)
    $vars = @{}
    foreach ($v in $script:Seeds) { $vars[$v.ToUpperInvariant()] = $true }
    $sets = New-Object System.Collections.Generic.List[object]
    foreach ($l in $Lines) {
        if (Test-Comment $l) { continue }
        foreach ($m in [regex]::Matches($l, '(?i)\bset\s+"([A-Za-z_][A-Za-z0-9_]*)=([^"]*)"')) { $sets.Add(@($m.Groups[1].Value.ToUpperInvariant(), $m.Groups[2].Value)) }
        foreach ($m in [regex]::Matches($l, '(?i)\bset\s+(?!/[ap]\b)([A-Za-z_][A-Za-z0-9_]*)=([^\s"&|)]*)')) { $sets.Add(@($m.Groups[1].Value.ToUpperInvariant(), $m.Groups[2].Value)) }
    }
    do {
        $grew = $false
        foreach ($p in $sets) {
            $name = $p[0]; $val = $p[1]
            if ($vars.ContainsKey($name)) { continue }
            $isPath = ($val -match '\\') -or ($val -match '(?i)^[a-z]:') -or ($val -match '%~')
            if (-not $isPath) {
                foreach ($r in [regex]::Matches($val, '[%!]([A-Za-z_][A-Za-z0-9_]*)(?::[^%!]*)?[%!]')) {
                    if ($vars.ContainsKey($r.Groups[1].Value.ToUpperInvariant())) { $isPath = $true; break }
                }
            }
            if ($isPath) { $vars[$name] = $true; $grew = $true }
        }
    } while ($grew)
    return $vars
}

function Get-QuotedRefs {
    # The variable references inside single-quoted spans of $Text, as
    # @{ Name; Form } with Form 'plain' (%X% or !X!) or 'doubled' (%X:'=''%).
    param([string]$Text)
    $out = @()
    # The doubling form holds apostrophes of its own; take it out first.
    $t = [regex]::Replace($Text, "%([A-Za-z_][A-Za-z0-9_]*):'=''%", { param($m) ('@@DOUBLED_' + $m.Groups[1].Value + '@@') })
    foreach ($span in [regex]::Matches($t, "'([^']*)'")) {
        $body = $span.Groups[1].Value
        foreach ($m in [regex]::Matches($body, '@@DOUBLED_([A-Za-z_][A-Za-z0-9_]*)@@')) { $out += @{ Name = $m.Groups[1].Value; Form = 'doubled' } }
        foreach ($m in [regex]::Matches($body, '[%!]([A-Za-z_][A-Za-z0-9_]*)(?::[^%!]*)?[%!]')) { $out += @{ Name = $m.Groups[1].Value; Form = 'plain' } }
    }
    return $out
}

function Get-Defects {
    # @{ Bad; Code; Display; Vars } for one bat's text; $Name labels it.
    param([string]$Text, [string]$Name)
    $lines = $Text -split "\r?\n"
    $vars = Get-PathVars $lines
    $bad = @()
    $nCode = 0; $nDisp = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if (Test-Comment $l) { continue }
        $isDisplay = ($l -match '^\s*echo\s+Command:')
        $isCode = (-not $isDisplay) -and (($l -match '^\s*echo\s.*>>?\s*"%PSRUN%"\s*$') -or ($l -match '(?i)-Command\s+"'))
        if (-not ($isDisplay -or $isCode)) { continue }
        if ($isDisplay) { $nDisp++ } else { $nCode++ }
        foreach ($r in (Get-QuotedRefs $l)) {
            if (-not $vars.ContainsKey($r.Name.ToUpperInvariant())) { continue }
            if ($isCode) {
                $bad += ("{0}:{1}: PowerShell source pastes the path %{2}% between single quotes -- an apostrophe in it (C:\Users\O'Brien) ends the string and the whole script never runs; read `$env:{2}" -f $Name, ($i + 1), $r.Name)
            } elseif ($r.Form -eq 'plain') {
                $bad += ("{0}:{1}: the printed Command: line pastes the path %{2}% between single quotes, so a reader whose path holds an apostrophe cannot run it; write %{2}:'=''%" -f $Name, ($i + 1), $r.Name)
            }
        }
    }
    return @{ Bad = $bad; Code = $nCode; Display = $nDisp; Vars = $vars }
}

function Get-AllDefects {
    param([hashtable]$Texts)
    $all = @()
    foreach ($k in ($Texts.Keys | Sort-Object)) {
        $r = Get-Defects $Texts[$k] $k
        $all += $r.Bad
        # Vacuity: a lint that scanned nothing, or derived no paths, is broken.
        if ($r.Code -lt 150) { $all += ("{0}: only {1} PowerShell source line(s) scanned -- the scanner is broken, not the code" -f $k, $r.Code) }
        if ($r.Display -lt 100) { $all += ("{0}: only {1} Command: line(s) scanned -- the scanner is broken, not the code" -f $k, $r.Display) }
        foreach ($must in 'REPORT', 'LEDGER', 'SUMCODE', 'IOCDIR', 'OUTDIR', 'PSRUN', 'SCRIPT_DIR') {
            if (-not $r.Vars.ContainsKey($must)) { $all += ("{0}: {1} was not derived as a path variable -- the derivation is broken" -f $k, $must) }
        }
    }
    return ,$all
}

$bats = @('doze_sec.bat', 'doze_sec_noAdmin.bat')

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ': ' + $Got })"; $script:fails++ }
    }
    function Mutate { param([string]$Text, [string]$From, [string]$To, [string]$Label)
        $i = $Text.IndexOf($From)
        if ($i -lt 0) { throw ("mutation '{0}' found nothing to change -- the self-test no longer looks at the code it was written for" -f $Label) }
        return $Text.Substring(0, $i) + $To + $Text.Substring($i + $From.Length)
    }
    $base = [IO.File]::ReadAllText((Join-Path $Root 'doze_sec.bat')) -replace "`r`n", "`n"
    $d = @((Get-Defects $base 'doze_sec.bat').Bad)
    T 'the shipped doze_sec.bat passes' ($d.Count -eq 0) ($d -join ' | ')
    T 'a state value between single quotes stays quiet (the dashboard reads PPL_STATE that way)' ($base.Contains("echo `$v='%PPL_STATE%'")) 'the PPL_STATE line moved; pick another state-value line'
    foreach ($c in @(
        @{ L = 'the dashboard SUMCODE back between quotes'; F = 'echo $scf=$env:SUMCODE >> "%PSRUN%"'; T = "echo `$scf='%SUMCODE%' >> `"%PSRUN%`""; Need = 'pastes the path %SUMCODE%' },
        @{ L = 'the census REPORT back between quotes'; F = '-LiteralPath $env:REPORT -Pattern'; T = "-LiteralPath '%REPORT%' -Pattern"; Need = 'pastes the path %REPORT%' },
        @{ L = 'the Section 11 history APPDATA back between quotes'; F = "Get-Content -LiteralPath (Join-Path `$env:APPDATA 'Microsoft"; T = "Get-Content -LiteralPath ('%APPDATA%\Microsoft"; Need = 'pastes the path %APPDATA%' },
        @{ L = 'a printed 18e Command: line without the apostrophe doubling'; F = "Get-Content '%IOCDIR:'=''%\ioc_scheduled_tasks.txt'"; T = "Get-Content '%IOCDIR%\ioc_scheduled_tasks.txt'"; Need = "write %IOCDIR:'=''%" },
        @{ L = 'a delayed !REPORT! between quotes'; F = '-LiteralPath $env:REPORT -Pattern'; T = "-LiteralPath '!REPORT!' -Pattern"; Need = 'pastes the path %REPORT%' })) {
        $m = Mutate $base $c.F $c.T $c.L
        $d = @((Get-Defects $m 'mutated').Bad)
        T ("{0} fails" -f $c.L) (@($d | Where-Object { $_.Contains($c.Need) }).Count -gt 0) ($d -join ' | ')
    }
    $m = $base + "`n:: echo `$x='%TEMP%\dz' >> `"%PSRUN%`"`nrem echo `$y='%REPORT%' >> `"%PSRUN%`"`n"
    $d = @((Get-Defects $m 'mutated').Bad)
    T 'a pasted path in a comment stays quiet' ($d.Count -eq 0) ($d -join ' | ')
    $m = $base + "`nset `"DZ_NEWER=%DZ_NEW%\x`"`nset `"DZ_NEW=%OUTDIR%`"`necho `$n='%DZ_NEWER%' >> `"%PSRUN%`"`n"
    $d = @((Get-Defects $m 'mutated').Bad)
    T 'a path variable added later, derived through another, is covered' (@($d | Where-Object { $_.Contains('%DZ_NEWER%') }).Count -gt 0) ($d -join ' | ')
    if ($fails) { Write-Output "FAILED: $fails"; exit 1 }
    Write-Output '[OK] lint_quoted_paths self-test: each pasted path fails, a state value and a comment do not, a new path variable is covered.'
    exit 0
}

$texts = @{}
foreach ($b in $bats) { $texts[$b] = [IO.File]::ReadAllText((Join-Path $Root $b)) }
$all = Get-AllDefects $texts
if ($all.Count) {
    foreach ($x in $all) { Write-Output ("[FAIL] " + $x) }
    Write-Output ("FAIL: {0} place(s) where a path can break the PowerShell it is pasted into." -f $all.Count)
    exit 1
}
Write-Output '[OK] lint_quoted_paths: no path is pasted between single quotes in the PowerShell either bat runs, and every printed Command: line doubles the apostrophe.'
exit 0
