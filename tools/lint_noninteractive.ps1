# lint_noninteractive.ps1 -- every PowerShell the bats start runs -NonInteractive.
#
# A PowerShell that stops to ask a question waits for an answer. Every helper
# the bats start writes into the report, into >nul, into the console-log
# tee or into field_test's pipe, so nobody sees the question, and the audit
# looks hung. PR #245 met this for real: under a Group Policy Unrestricted
# policy a script carrying the Mark of the Web stops at "Run only scripts that
# you trust", and the readonly CI job measured a marked probe still waiting
# after 20 seconds. -NonInteractive makes any question fail at once instead,
# with an error the report shows. Other questions exist too: a cmdlet's
# confirmation (Remove-Item on a folder holding files, without -Recurse), a
# provider bootstrap, a Read-Host a future helper adds.
#
# The flag must come BEFORE -File or -Command. PowerShell hands everything
# after -File to the script as its arguments, and after -Command it is the
# command, so a flag placed there protects nothing (measured in windows-smoke,
# helpers job).
#
# A launch is a line that starts PowerShell ("%PWSH%", %PWSH%, powershell,
# powershell.exe followed by a switch) and is not printed text: a launch
# after an `echo` on the same line is a Command: line or report text a
# person pastes, and stays exactly as printed. `::` and `rem` lines are not
# launches. A floor on the count keeps a broken scanner from passing.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_noninteractive.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_noninteractive.ps1 -SelfTest
# Pure ASCII, Windows PowerShell 5.1 and pwsh.

[CmdletBinding()]
param(
    [switch]$SelfTest,
    [string]$Root = ''
)

$ErrorActionPreference = 'Stop'
$script:Bats = @('doze_sec.bat', 'doze_sec_noAdmin.bat')
$script:Floor = 120
# The program token, followed (not consumed) by whitespace and a switch.
$script:ExeRx = '(?i)("%PWSH%"|%PWSH%|"?\bpowershell(\.exe)?"?)(?=\s+-)'
# The switch that ends PowerShell's own options.
$script:PayloadRx = '(?i)\s-(File|Command|EncodedCommand|ec|f|c)\b'

function Get-PowerShellLaunches {
    # Pure. One record per launch: @{ Line; Text; Has; Late }.
    param([string[]]$Lines)
    $out = @()
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $l = $Lines[$i]
        if ($l -match '^\s*@?(::|rem(\s|$))') { continue }
        foreach ($m in [regex]::Matches($l, $script:ExeRx)) {
            $before = $l.Substring(0, $m.Index)
            # Printed, not run: an echo earlier on the line.
            if ($before -match '(?i)(^|[\s(&|])echo([\s.(:]|$)') { continue }
            $after = $l.Substring($m.Index + $m.Length)
            $cut = [regex]::Match($after, $script:PayloadRx)
            $head = $after
            if ($cut.Success) { $head = $after.Substring(0, $cut.Index) }
            $has = $head -match '(?i)\s-NonInteractive\b'
            $late = (-not $has) -and ($after -match '(?i)\s-NonInteractive\b')
            $out += @{ Line = ($i + 1); Text = $l.Trim(); Has = $has; Late = $late }
        }
    }
    return $out
}

function Invoke-Lint {
    # Returns @{ Defects = string[]; Counts = hashtable name -> launches }.
    param([string]$Dir)
    $defects = @()
    $counts = @{}
    foreach ($b in $script:Bats) {
        $p = Join-Path $Dir $b
        if (-not (Test-Path -LiteralPath $p)) { $defects += ('{0}: not found' -f $b); continue }
        $launches = @(Get-PowerShellLaunches @(Get-Content -LiteralPath $p))
        $counts[$b] = $launches.Count
        if ($launches.Count -lt $script:Floor) {
            $defects += ('{0}: only {1} PowerShell launch(es) found, expected at least {2} -- the scanner is broken, not the code' -f $b, $launches.Count, $script:Floor)
        }
        foreach ($x in $launches) {
            if ($x.Has) { continue }
            $t = $x.Text
            if ($t.Length -gt 140) { $t = $t.Substring(0, 140) + '...' }
            if ($x.Late) {
                $defects += ('{0}:{1}: -NonInteractive comes after -File or -Command, where PowerShell hands it to the script (or it is part of the command) -- it protects nothing: {2}' -f $b, $x.Line, $t)
            } else {
                $defects += ('{0}:{1}: PowerShell starts without -NonInteractive -- a question it asks would wait where nobody sees it: {2}' -f $b, $x.Line, $t)
            }
        }
    }
    return @{ Defects = $defects; Counts = $counts }
}

if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }

if ($SelfTest) {
    $fails = 0
    function T([string]$Name, [bool]$Cond, [string]$Detail = '') {
        if ($Cond) { Write-Output ('[OK]   ' + $Name) }
        else { Write-Output ('[FAIL] ' + $Name + $(if ($Detail) { ' -- ' + $Detail } else { '' })); $script:fails++ }
    }
    $work = Join-Path ([IO.Path]::GetTempPath()) ('dz_lint_noni_{0}' -f $PID)
    function Reset-Copy {
        Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        foreach ($b in $script:Bats) { Copy-Item -LiteralPath (Join-Path $Root $b) -Destination (Join-Path $work $b) }
    }
    function Edit-Copy([string]$Bat, [scriptblock]$Change) {
        $p = Join-Path $work $Bat
        $lines = @(Get-Content -LiteralPath $p)
        $new = & $Change $lines
        Set-Content -LiteralPath $p -Value $new -Encoding ASCII
    }
    try {
        Reset-Copy
        $r = Invoke-Lint $work
        T 'the shipped bats: every launch runs -NonInteractive, before -File/-Command' ($r.Defects.Count -eq 0) ($r.Defects -join ' | ')
        $base = $r.Counts['doze_sec.bat']

        # A -File "%PSRUN%" launch loses the flag.
        Reset-Copy
        $script:hit = 0
        Edit-Copy 'doze_sec.bat' { param($L) $done = $false; foreach ($l in $L) { if (-not $done -and $l -match '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%PSRUN%"') { $done = $true; $script:hit = 1; $l -replace ' -NonInteractive', '' } else { $l } } }
        $r = Invoke-Lint $work
        T 'a staged-block launch without the flag fails, named' ($script:hit -eq 1 -and @($r.Defects | Where-Object { $_ -match '^doze_sec\.bat:\d+: PowerShell starts without -NonInteractive' }).Count -eq 1) ($r.Defects -join ' | ')

        # The flag moved after -File: the script's argument, not PowerShell's.
        Reset-Copy
        $script:hit = 0
        Edit-Copy 'doze_sec.bat' { param($L) $done = $false; foreach ($l in $L) { if (-not $done -and $l -match '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%PSRUN%"') { $done = $true; $script:hit = 1; ($l -replace ' -NonInteractive', '') -replace '-File "%PSRUN%"', '-File "%PSRUN%" -NonInteractive' } else { $l } } }
        $r = Invoke-Lint $work
        T 'the flag after -File fails as protecting nothing' ($script:hit -eq 1 -and @($r.Defects | Where-Object { $_ -match 'comes after -File or -Command' }).Count -eq 1) ($r.Defects -join ' | ')

        # A for /f launch loses the flag.
        Reset-Copy
        $script:hit = 0
        Edit-Copy 'doze_sec_noAdmin.bat' { param($L) $done = $false; foreach ($l in $L) { if (-not $done -and $l -match 'in \(`powershell -NoProfile -NonInteractive') { $done = $true; $script:hit = 1; $l -replace ' -NonInteractive', '' } else { $l } } }
        $r = Invoke-Lint $work
        T 'a for /f launch without the flag fails' ($script:hit -eq 1 -and @($r.Defects | Where-Object { $_ -match '^doze_sec_noAdmin\.bat:\d+: PowerShell starts without' }).Count -eq 1) ($r.Defects -join ' | ')

        # Printed text and non-launches stay quiet and are not counted.
        Reset-Copy
        Edit-Copy 'doze_sec.bat' { param($L) $L + @(
            'echo  Command: powershell -NoProfile -Command "Get-Date">> "%REPORT%"',
            'if "%X%"=="1" echo  Command: powershell -Command "Get-Date">> "%REPORT%"',
            '(echo   PS Engine : %PWSH% -NoProfile)>> "%REPORT%"',
            'where powershell >nul 2>&1',
            'rem powershell -NoProfile -File x.ps1',
            ':: "%PWSH%" -NoProfile -File x.ps1',
            'set "PWSH=powershell"') }
        $r = Invoke-Lint $work
        T 'printed Command: lines, comments, where and set are not launches' ($r.Defects.Count -eq 0 -and $r.Counts['doze_sec.bat'] -eq $base) (($r.Defects -join ' | ') + ' count=' + $r.Counts['doze_sec.bat'])

        # A file the scanner barely reads trips the floor.
        Reset-Copy
        Edit-Copy 'doze_sec.bat' { param($L) @('"%PWSH%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%PSRUN%"') }
        $r = Invoke-Lint $work
        T 'too few launches found fails as a broken scanner' (@($r.Defects | Where-Object { $_ -match 'the scanner is broken' }).Count -eq 1) ($r.Defects -join ' | ')

        # CRLF and LF copies read the same.
        Reset-Copy
        foreach ($b in $script:Bats) {
            $p = Join-Path $work $b
            $txt = [IO.File]::ReadAllText($p) -replace "`r?`n", "`r`n"
            [IO.File]::WriteAllText($p, $txt)
        }
        $r = Invoke-Lint $work
        T 'a CRLF checkout reads the same' ($r.Defects.Count -eq 0 -and $r.Counts['doze_sec.bat'] -eq $base) ($r.Defects -join ' | ')
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
    }
    if ($fails -gt 0) { Write-Output ('[FAIL] lint_noninteractive self-test: ' + $fails + ' case(s) failed'); exit 1 }
    Write-Output '[OK] lint_noninteractive self-test: a launch without the flag fails, one with it after -File fails, printed text and comments stay quiet, and a broken scanner trips the floor.'
    exit 0
}

$r = Invoke-Lint $Root
if ($r.Defects.Count -gt 0) {
    $r.Defects | ForEach-Object { Write-Output ('[FAIL] ' + $_) }
    Write-Output ('[FAIL] lint_noninteractive: {0} defect(s)' -f $r.Defects.Count)
    exit 1
}
Write-Output ('[OK] lint_noninteractive: every PowerShell the bats start runs -NonInteractive before -File/-Command ({0}).' -f (($script:Bats | ForEach-Object { '{0} x{1}' -f $_, $r.Counts[$_] }) -join ', '))
exit 0
