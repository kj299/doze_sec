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
# A launch is a line that starts PowerShell ("%PWSH%", %PWSH%, !PWSH!,
# powershell, powershell.exe, pwsh followed by a switch) and is not printed
# text: a launch after an `echo` on the same line is a Command: line or report
# text a person pastes, and stays exactly as printed -- unless an unquoted,
# unescaped & or | after the echo starts a second command. `::` and `rem`
# lines are not launches. Two backstops keep a launch the scanner cannot read
# from passing: a line that runs a tools\ script or %PSRUN% but holds no
# launch it recognised fails, and so does a launch continued onto the next
# line with ^. A floor on the count keeps a broken scanner from passing.
#
# The generator of ttp_generated_checks.bat (tools\ttp_merge.ps1, which writes
# launch lines Section 18 later calls) is checked too: every "%PWSH%" ...
# -NoProfile line it emits carries the flag.
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
# Well under today's 133 and 127: fewer means the scanner broke, or launches
# were removed on purpose, and then the floor is lowered on purpose too.
$script:Floor = 100
# Scripts that WRITE launch lines into a batch file the bats call, and how many
# such lines each must hold (fewer: the check is reading nothing).
$script:Generators = @{ 'tools\ttp_merge.ps1' = 3 }
# The program token, followed (not consumed) by whitespace and a switch.
$script:ExeRx = '(?i)("%PWSH%"|%PWSH%|!PWSH!|"?\bpowershell(\.exe)?"?|"?\bpwsh(\.exe)?"?)(?=\s+-)'
# The switch that ends PowerShell's own options: everything after -File is the
# script's, everything after -Command is the command. (-EncodedCommand takes
# one value and switches may follow it, so it does not end them.)
$script:PayloadRx = '(?i)\s-(File|Command|f|c)\b'
# A line that runs a helper or a staged block: it must hold a launch.
$script:RunsRx = '(?i)-File\s+"(%SCRIPT_DIR%tools\\|%PSRUN%)'

function Test-Printed {
    # Pure. Is the launch at $Index printed text rather than run? Yes when an
    # echo comes earlier on the line and nothing between them starts another
    # command: an unquoted & or | that is not escaped with ^.
    param([string]$Line, [int]$Index)
    $before = $Line.Substring(0, $Index)
    $e = [regex]::Matches($before, '(?i)(^|[\s(&|@])echo([\s.(:]|$)')
    if ($e.Count -eq 0) { return $false }
    $last = $e[$e.Count - 1]
    $between = $before.Substring($last.Index + $last.Length)
    $bare = ($between -replace '\^.', '') -replace '"[^"]*"', ''
    return ($bare -notmatch '[&|]')
}

function Get-PowerShellLaunches {
    # Pure. One record per launch: @{ Line; Text; Has; Late; Cont }, plus one
    # record per line that runs a helper but holds no launch it could read
    # (@{ Line; Text; Unread = $true }).
    param([string[]]$Lines)
    $out = @()
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $l = $Lines[$i]
        if ($l -match '^\s*@?(::|rem(\s|$))') { continue }
        $ms = @([regex]::Matches($l, $script:ExeRx) | Where-Object { -not (Test-Printed $l $_.Index) })
        for ($k = 0; $k -lt $ms.Count; $k++) {
            $m = $ms[$k]
            $end = $l.Length
            if ($k + 1 -lt $ms.Count) { $end = $ms[$k + 1].Index }
            $after = $l.Substring($m.Index + $m.Length, $end - ($m.Index + $m.Length))
            $cut = [regex]::Match($after, $script:PayloadRx)
            $head = $after
            if ($cut.Success) { $head = $after.Substring(0, $cut.Index) }
            $has = $head -match '(?i)\s-NonInteractive\b'
            $late = (-not $has) -and ($after -match '(?i)\s-NonInteractive\b')
            $cont = ($l -match '\^\s*$')
            $out += @{ Line = ($i + 1); Text = $l.Trim(); Has = ($has -and -not $cont); Late = $late; Cont = $cont; Unread = $false }
        }
        if ($ms.Count -eq 0 -and $l -match $script:RunsRx -and -not (Test-Printed $l ($l.Length))) {
            $out += @{ Line = ($i + 1); Text = $l.Trim(); Has = $false; Late = $false; Cont = $false; Unread = $true }
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
        $counts[$b] = @($launches | Where-Object { -not $_.Unread }).Count
        if ($counts[$b] -lt $script:Floor) {
            $defects += ('{0}: only {1} PowerShell launch(es) found, expected at least {2} -- the scanner is broken, or launches were removed (then lower the floor on purpose)' -f $b, $counts[$b], $script:Floor)
        }
        foreach ($x in $launches) {
            if ($x.Has) { continue }
            $t = $x.Text
            if ($t.Length -gt 140) { $t = $t.Substring(0, 140) + '...' }
            if ($x.Unread) {
                $defects += ('{0}:{1}: this line runs a helper or a staged block, but no PowerShell launch the scanner can read starts it -- start it with "%PWSH%" -NoProfile -NonInteractive: {2}' -f $b, $x.Line, $t)
            } elseif ($x.Cont) {
                $defects += ('{0}:{1}: a PowerShell launch continued onto the next line with ^ -- put it on one line so its switches can be checked: {2}' -f $b, $x.Line, $t)
            } elseif ($x.Late) {
                $defects += ('{0}:{1}: -NonInteractive comes after -File or -Command, where PowerShell hands it to the script (or it is part of the command) -- it protects nothing: {2}' -f $b, $x.Line, $t)
            } else {
                $defects += ('{0}:{1}: PowerShell starts without -NonInteractive (spelled in full) -- a question it asks would wait where nobody sees it: {2}' -f $b, $x.Line, $t)
            }
        }
    }
    foreach ($g in $script:Generators.Keys) {
        $p = Join-Path $Dir $g
        if (-not (Test-Path -LiteralPath $p)) { $defects += ('{0}: not found' -f $g); continue }
        $gl = @(Get-Content -LiteralPath $p)
        $hits = @(for ($i = 0; $i -lt $gl.Count; $i++) { if ($gl[$i] -notmatch '^\s*#' -and $gl[$i] -match '%PWSH%\W{0,3}\s+-NoProfile') { $i } })
        $counts[$g] = $hits.Count
        if ($hits.Count -lt $script:Generators[$g]) { $defects += ('{0}: only {1} generated PowerShell launch line(s) found, expected at least {2} -- the check is reading nothing' -f $g, $hits.Count, $script:Generators[$g]) }
        foreach ($i in $hits) {
            if ($gl[$i] -notmatch '-NoProfile -NonInteractive') { $defects += ('{0}:{1}: a launch line this script writes into a batch file the bats call has no -NonInteractive right after -NoProfile' -f $g, ($i + 1)) }
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
        foreach ($g in $script:Generators.Keys) {
            $gd = Join-Path $work (Split-Path -Parent $g)
            New-Item -ItemType Directory -Path $gd -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $Root $g) -Destination (Join-Path $work $g)
        }
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
        Edit-Copy 'doze_sec.bat' { param($L) $done = $false; foreach ($l in $L) { if (-not $done -and $l -match '^"%PWSH%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%PSRUN%">>') { $done = $true; $script:hit = 1; $l -replace ' -NonInteractive', '' } else { $l } } }
        $r = Invoke-Lint $work
        T 'a staged-block launch (the commonest shape) without the flag fails, named' ($script:hit -eq 1 -and @($r.Defects | Where-Object { $_ -match '^doze_sec\.bat:\d+: PowerShell starts without -NonInteractive' }).Count -eq 1) ($r.Defects -join ' | ')

        # The flag moved after -File: the script's argument, not PowerShell's.
        Reset-Copy
        $script:hit = 0
        Edit-Copy 'doze_sec.bat' { param($L) $done = $false; foreach ($l in $L) { if (-not $done -and $l -match '^"%PWSH%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%PSRUN%">>') { $done = $true; $script:hit = 1; ($l -replace ' -NonInteractive', '') -replace '-File "%PSRUN%"', '-File "%PSRUN%" -NonInteractive' } else { $l } } }
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
            '@echo  Command: powershell -NoProfile -Command "Get-Date">> "%REPORT%"',
            'echo  Command: powershell -Command "Get-Process | Select-Object -First 1">> "%REPORT%"',
            'echo Get-Date ^| Out-String ^& powershell -NoProfile -File x.ps1 >> "%PSRUN%"',
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

        # Shapes the program-name scan alone would miss.
        $more = @(
            @{ N = 'a !PWSH! launch (delayed expansion) without the flag fails'; L = '    !PWSH! -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1'; Want = 'starts without -NonInteractive' },
            @{ N = 'a pwsh launch without the flag fails'; L = 'pwsh -NoProfile -File "%SCRIPT_DIR%tools\x.ps1"'; Want = 'starts without -NonInteractive' },
            @{ N = 'a helper started through a variable the scanner does not know fails as unreadable'; L = '%DZPS% -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tools\x.ps1"'; Want = 'no PowerShell launch the scanner can read' },
            @{ N = 'a launch chained after an echo with an unquoted | is run, not printed, and fails'; L = 'echo x | "%PWSH%" -NoProfile -Command -'; Want = 'starts without -NonInteractive' },
            @{ N = 'a launch chained after an echo with & fails'; L = 'echo hi & "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%"'; Want = 'starts without -NonInteractive' },
            @{ N = 'two launches on one line cannot share one flag'; L = '"%PWSH%" -NoProfile -ExecutionPolicy Bypass & "%PWSH%" -NoProfile -NonInteractive -Command "Get-Date"'; Want = 'starts without -NonInteractive' },
            @{ N = 'a launch continued onto the next line with ^ fails'; L = '"%PWSH%" -NoProfile -NonInteractive ^'; Want = 'continued onto the next line' }
        )
        foreach ($c in $more) {
            Reset-Copy
            $line = $c.L
            Edit-Copy 'doze_sec.bat' { param($L) $L + @($line) }
            $r = Invoke-Lint $work
            T $c.N (@($r.Defects | Where-Object { $_ -like ('*' + $c.Want + '*') }).Count -eq 1) ($r.Defects -join ' | ')
        }

        # The generator: a launch line it writes without the flag fails.
        Reset-Copy
        New-Item -ItemType Directory -Path (Join-Path $work 'tools') -Force | Out-Null
        $gsrc = @(Get-Content -LiteralPath (Join-Path $Root 'tools\ttp_merge.ps1'))
        Set-Content -LiteralPath (Join-Path $work 'tools\ttp_merge.ps1') -Value $gsrc -Encoding ASCII
        $r = Invoke-Lint $work
        T 'the shipped generator writes every launch with the flag' ($r.Defects.Count -eq 0 -and $r.Counts['tools\ttp_merge.ps1'] -ge 3) ($r.Defects -join ' | ')
        $script:hit = 0
        $mut = foreach ($l in $gsrc) { if ($script:hit -eq 0 -and $l -match '-NoProfile -NonInteractive') { $script:hit = 1; $l -replace ' -NonInteractive', '' } else { $l } }
        Set-Content -LiteralPath (Join-Path $work 'tools\ttp_merge.ps1') -Value $mut -Encoding ASCII
        $r = Invoke-Lint $work
        T 'a generated launch line without the flag fails' ($script:hit -eq 1 -and @($r.Defects | Where-Object { $_ -match 'ttp_merge\.ps1:\d+: a launch line this script writes' }).Count -eq 1) ($r.Defects -join ' | ')
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue
    }
    if ($fails -gt 0) { Write-Output ('[FAIL] lint_noninteractive self-test: ' + $fails + ' case(s) failed'); exit 1 }
    Write-Output '[OK] lint_noninteractive self-test: a launch without the flag fails, one with it after -File fails, shapes the name scan would miss are caught, printed text and comments stay quiet, the generator is checked, and a broken scanner trips the floor.'
    exit 0
}

$r = Invoke-Lint $Root
if ($r.Defects.Count -gt 0) {
    $r.Defects | ForEach-Object { Write-Output ('[FAIL] ' + $_) }
    Write-Output ('[FAIL] lint_noninteractive: {0} defect(s)' -f $r.Defects.Count)
    exit 1
}
Write-Output ('[OK] lint_noninteractive: every PowerShell the bats start runs -NonInteractive before -File/-Command ({0}).' -f ((@($script:Bats) + @($script:Generators.Keys) | ForEach-Object { '{0} x{1}' -f $_, $r.Counts[$_] }) -join ', '))
exit 0
