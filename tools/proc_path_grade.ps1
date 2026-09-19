# proc_path_grade.ps1 -- grade processes running from user-profile paths.
#
# WHY: Section 4 matched a path list and raised WARNING "Investigate now" for
# every hit, while the summary dashboard graded the SAME processes on their
# signature and reported "[INFO] Processes from user-profile paths, all validly
# signed". One field report carried both verdicts about the same six brave.exe
# processes. A reader cannot act on a tool that contradicts itself, and the
# alarming half was the wrong one: Brave, Chrome, Edge, Slack, Teams and VS Code
# all install per-user under \AppData\ by design, so \AppData\ alone is not a
# signal -- treating it as one is how a tool trains its reader to ignore it.
#
# THE RULE (graded here ONCE; the dashboard reads the verdict, it does not
# re-derive it -- see Get-StateLine for why sharing the rule was not enough):
#   * \Temp\, \Downloads\, \Users\Public\, \$Recycle -- suspicious whatever the
#     signature says. Nothing legitimate runs its main binary from there.
#   * \AppData\ -- only suspicious when the binary is NOT validly signed.
#
# An unreadable or unsignable file is reported as unsigned: for this decision
# "I could not verify it" belongs with the risky half, not the safe half.
#
# Read-only. Windows PowerShell 5.1 and pwsh.

[CmdletBinding()]
param(
    # NOT Mandatory: a mandatory parameter makes -SelfTest sit at an
    # interactive prompt instead of running, which in CI is a hang rather than
    # an error. Validated below, where it is actually needed.
    [string]$Path,
    [string]$MarkerFile,
    # Where this tool's verdict is left for the SUMMARY DASHBOARD to read. See
    # Get-StateLine below for why the dashboard must not work it out again.
    [string]$StateFile,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
function Write-MarkerFile {
    # The marker IS the route to the findings ledger: a failed write turns a
    # real finding into a CLEAN section. Create the directory rather than
    # assume it, and NO -EA SilentlyContinue -- a swallowed failure here is
    # exactly how a field test lost its finding. Kept as a LOCAL function in
    # each tool, like Write-Marker: a shared file would add a missing-file
    # mode that breaks every tool at once, and the test is the propagation
    # mechanism.
    param([string]$Path, [string]$Value = 'hit')
    if (-not $Path) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Value -Encoding ASCII
}

# ONE MEASUREMENT, CARRIED -- never a second opinion.
#
# The summary dashboard used to re-enumerate Win32_Process and grade it with
# its own inline copy of this rule, roughly eight minutes later in the run. On
# 2026-09-19 that produced two verdicts about the same machine:
#
#   Section 4:  [WARNING] 2 of 3 user-profile process path(s) are suspicious
#   Dashboard:  [INFO] Processes from user-profile paths, all validly signed: 1
#
# Neither was wrong. An Ollama install finished mid-audit, so the installer
# processes existed for the first measurement and not for the second. The
# header above already claimed the rule was "shared so the two cannot drift
# apart"; it was not shared, and the tile's copy had also quietly dropped
# $Recycle from both its regexes and graded CRIT where this raises WARNING.
#
# But sharing the rule would not have been enough. IDENTICAL RULES STILL
# CONTRADICT WHEN THEY ARE TWO MEASUREMENTS. So the tile no longer measures:
# this tool writes its verdict once, the bat reads it into PROCPATH_STATE, and
# the dashboard prints that -- the same idiom DNSPROBE_STATE already uses.
function Get-StateLine {
    param([string]$State, [int]$Bad, [int]$Total, [int]$Seen, [string[]]$Names)
    # The names cross into cmd.exe. A & | > < ^ % or ! in a filename is a
    # command-injection surface there that does not exist while the tile
    # builds its own text in PowerShell, so allow only letters, digits and a
    # few safe separators and cap the length -- one absurd filename must not
    # be able to reach the shell or blow the command-line limit.
    $safe = @()
    foreach ($n in @($Names)) {
        $t = ([regex]::Replace([string]$n, '[^A-Za-z0-9._+ -]', '_')).Trim()
        if ($t) { $safe += $t }
    }
    $joined = ($safe -join ', ')
    if ($joined.Length -gt 120) { $joined = $joined.Substring(0, 117) + '...' }
    # NEVER an empty trailing field. cmd's `for /f` does not define a token
    # that is not there, and leaves the text %%e in the command verbatim -- so
    # an empty name list would set PROCPATH_NAMES to the literal string "%e".
    # The bat blanks this placeholder again after parsing.
    if (-not $joined) { $joined = '-' }
    return ('{0}|{1}|{2}|{3}|{4}' -f $State, $Bad, $Total, $Seen, $joined)
}

function Write-StateFile {
    param([string]$Path, [string]$Line)
    if (-not $Path) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
    }
    # No -EA SilentlyContinue: a swallowed failure here leaves the dashboard
    # with no state, which it reports as "not graded" rather than as calm.
    Set-Content -LiteralPath $Path -Value $Line -Encoding ASCII
}

# IN SCOPE: the user-profile locations this check is about. Everything else --
# Program Files, System32, WindowsApps -- is NOT graded at all.
#
# This filter is the fix for a regression I shipped in #198. The caller passes
# the FULL Win32_Process dump (doze_sec.bat:1916); select_lines.ps1 filters it
# for display, and I pointed this grader at the unfiltered dump. It therefore
# graded all 110 running processes and reported seven Microsoft Store binaries
# under C:\Program Files\WindowsApps as suspicious on a clean machine -- they
# are MSIX/catalog-signed, so Get-AuthenticodeSignature on the inner .exe does
# not return Valid. Worse than the contradiction it replaced.
#
# The tool now decides its own scope rather than trusting the caller to have
# filtered: one implementation of the whole rule, filter and grade together.
$script:InScope = '\\Temp\\|\\AppData\\|\\Downloads\\|\\Recycle|\\Users\\Public\\'

# Within scope, paths where a running binary is suspicious regardless of signer.
$script:HighRisk = '\\Temp\\|\\Downloads\\|\\Users\\Public\\|\$Recycle'

function Get-PathsFromDump {
    param([string]$File)
    $out = @()
    foreach ($line in (Get-Content -LiteralPath $File -EA SilentlyContinue)) {
        # A path may contain spaces, so take everything from the drive letter on
        # rather than splitting on whitespace.
        $m = [regex]::Match($line, '[A-Za-z]:\\.*$')
        if ($m.Success) { $out += $m.Value.Trim() }
    }
    return ($out | Sort-Object -Unique)
}

function Get-Verdict {
    param([string[]]$Paths, [scriptblock]$SigCheck)
    $bad = @()
    foreach ($p in $Paths) {
        if ($p -notmatch $script:InScope) { continue }
        if ($p -match $script:HighRisk) { $bad += $p; continue }
        $status = & $SigCheck $p
        if ($status -ne 'Valid') { $bad += $p }
    }
    $inScope = @($Paths | Where-Object { $_ -match $script:InScope })
    return @{ Bad = @($bad); InScope = @($inScope); Total = $inScope.Count; Seen = @($Paths).Count }
}

$script:RealSigCheck = {
    param([string]$File)
    try {
        if (-not (Test-Path -LiteralPath $File)) { return 'Missing' }
        return [string](Get-AuthenticodeSignature -LiteralPath $File -EA Stop).Status
    } catch { return 'Unverifiable' }
}

if ($SelfTest) {
    $fails = 0
    $sig = { param($f) if ($f -like '*signed*') { 'Valid' } else { 'NotSigned' } }
    $cases = @(
        @{ Name = 'AppData + validly signed is NOT a finding'
           Paths = @('C:\Users\u\AppData\Local\BraveSoftware\signed-brave.exe'); ExpectBad = 0 },
        @{ Name = 'AppData + unsigned IS a finding'
           Paths = @('C:\Users\u\AppData\Local\Evil\dropper.exe');               ExpectBad = 1 },
        @{ Name = 'Temp is a finding even when validly signed'
           Paths = @('C:\Users\u\AppData\Local\Temp\signed-thing.exe');          ExpectBad = 1 },
        @{ Name = 'Downloads is a finding even when validly signed'
           Paths = @('C:\Users\u\Downloads\signed-thing.exe');                   ExpectBad = 1 },
        @{ Name = 'Users\Public is a finding even when validly signed'
           Paths = @('C:\Users\Public\signed-thing.exe');                        ExpectBad = 1 },
        # The #198 regression, pinned by its real-world instances. These are
        # NOT user-profile paths, so they must never be graded at all -- and
        # both are catalog-signed, so a signature check on them returns
        # NotSigned and would flag them if scope were not enforced first.
        @{ Name = 'Program Files is out of scope, unsigned or not'
           Paths = @('C:\Program Files\WiFiman Desktop\wifiman-desktopd.exe');   ExpectBad = 0 },
        @{ Name = 'WindowsApps (MSIX, catalog-signed) is out of scope'
           Paths = @('C:\Program Files\WindowsApps\Microsoft.StorePurchaseApp_22607.1401.4.0_x64__8wekyb3d8bbwe\StoreExperienceHost.exe'); ExpectBad = 0 },
        @{ Name = 'System32 is out of scope'
           Paths = @('C:\Windows\System32\svchost.exe');                         ExpectBad = 0 },
        # And scope must not swallow a real finding sitting beside them.
        @{ Name = 'a mixed dump grades only the user-profile paths'
           Paths = @('C:\Windows\System32\svchost.exe',
                     'C:\Program Files\WindowsApps\Whatever\app.exe',
                     'C:\Users\u\AppData\Local\Temp\dropper.exe');            ExpectBad = 1 }
    )
    foreach ($c in $cases) {
        $r = Get-Verdict -Paths $c.Paths -SigCheck $sig
        if ($r.Bad.Count -eq $c.ExpectBad) { Write-Output "[OK]   $($c.Name)" }
        else { Write-Output "[FAIL] $($c.Name): got $($r.Bad.Count) finding(s), expected $($c.ExpectBad)"; $fails++ }
    }
    # An unverifiable file must land with the risky half, never the safe half.
    $r = Get-Verdict -Paths @('C:\Users\u\AppData\Local\App\gone.exe') -SigCheck { param($f) 'Unverifiable' }
    if ($r.Bad.Count -eq 1) { Write-Output '[OK]   a signature that cannot be verified counts as unsigned' }
    else { Write-Output '[FAIL] an unverifiable signature was treated as clean'; $fails++ }
    # The dump parser must survive a path containing spaces.
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('dz_ppg_' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.txt')
    Set-Content -LiteralPath $tmp -Value 'winword.exe  777  C:\Program Files\Microsoft Office\winword.exe'
    $got = @(Get-PathsFromDump -File $tmp)
    Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue
    if ($got.Count -eq 1 -and $got[0] -eq 'C:\Program Files\Microsoft Office\winword.exe') {
        Write-Output '[OK]   a path containing spaces is parsed whole'
    } else { Write-Output "[FAIL] path with spaces parsed as: $($got -join ' | ')"; $fails++ }

    # The field instances from SecurityReport_20260919_181422, verbatim. Both
    # are TRUE positives by the documented rule -- winget stages under
    # \Temp\WinGet\ and Inno Setup extracts into \Temp\is-XXXXXXXX.tmp\ --
    # and they must stay findings. tests/benign_corpus.txt carries the ADVISE
    # entry that tells the reader to ask whether they were installing software.
    $r = Get-Verdict -SigCheck $sig -Paths @(
        'C:\Users\khali\AppData\Local\Temp\is-0X2Z2LGMY8.tmp\OllamaSetup.tmp',
        'C:\Users\khali\AppData\Local\Temp\WinGet\Ollama.Ollama.0.34.2\OllamaSetup.exe',
        'C:\Users\khali\AppData\Local\BraveSoftware\Brave-Browser\Application\signed-brave.exe')
    if ($r.Bad.Count -eq 2 -and $r.Total -eq 3) { Write-Output '[OK]   the 2026-09-19 installer-in-Temp shape stays a finding, and only it' }
    else { Write-Output "[FAIL] installer-in-Temp: $($r.Bad.Count) of $($r.Total), expected 2 of 3"; $fails++ }

    # --- the state line the summary dashboard reads -------------------------
    $sl = Get-StateLine -State 'warn' -Bad 2 -Total 3 -Seen 118 -Names @('OllamaSetup.exe', 'OllamaSetup.tmp')
    if ($sl -eq 'warn|2|3|118|OllamaSetup.exe, OllamaSetup.tmp') { Write-Output '[OK]   the state line carries state, counts and names' }
    else { Write-Output "[FAIL] state line was: $sl"; $fails++ }
    if ((Get-StateLine -State 'ok' -Bad 0 -Total 0 -Seen 9 -Names @()) -eq 'ok|0|0|9|-') { Write-Output '[OK]   an empty name list becomes a placeholder, never an absent field' }
    else { Write-Output "[FAIL] clean state line was: $(Get-StateLine -State 'ok' -Bad 0 -Total 0 -Seen 9 -Names @())"; $fails++ }
    foreach ($st in @('ok', 'info', 'warn')) {
        $line = Get-StateLine -State $st -Bad 0 -Total 0 -Seen 0 -Names @()
        if ($line.Split('|').Count -eq 5 -and ($line.Split('|') | Where-Object { $_ -eq '' }).Count -eq 0) {
            Write-Output "[OK]   the $st state line has five non-empty fields, so no for /f token can go missing"
        } else { Write-Output "[FAIL] $st state line has an empty field: $line"; $fails++ }
    }
    # A filename cannot reach cmd.exe as syntax. Every one of these characters
    # would be an operator or an expansion there.
    $sl = Get-StateLine -State 'warn' -Bad 1 -Total 1 -Seen 1 -Names @('a&b|c>d<e^f%g!h"i''j.exe')
    if ($sl -match '^warn\|1\|1\|1\|[A-Za-z0-9._+ -]*$') { Write-Output '[OK]   shell metacharacters in a filename are sanitised out of the state line' }
    else { Write-Output "[FAIL] state line was not sanitised: $sl"; $fails++ }
    # ...and the pipe separator itself, or the line could not be parsed back.
    if ((Get-StateLine -State 'warn' -Bad 1 -Total 1 -Seen 1 -Names @('a|b.exe')).Split('|').Count -eq 5) {
        Write-Output '[OK]   a pipe in a filename cannot add a field to the state line'
    } else { Write-Output '[FAIL] a filename pipe broke the state line into extra fields'; $fails++ }
    $sl = Get-StateLine -State 'warn' -Bad 1 -Total 1 -Seen 1 -Names @(('x' * 400) + '.exe')
    if ($sl.Length -lt 200) { Write-Output '[OK]   an absurd filename is capped before it reaches the command line' }
    else { Write-Output "[FAIL] state line length $($sl.Length) is uncapped"; $fails++ }

    if ($fails) { Write-Output "[FAIL] $fails proc_path_grade self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] proc_path_grade self-test: AppData alone is context, Temp/Downloads/Public are findings, unverifiable counts as unsigned, and the state line the dashboard reads is shell-safe.'
    exit 0
}

if (-not $Path) { Write-Output '[SKIPPED] proc_path_grade: -Path <process dump> is required (or -SelfTest); the suspicious-path check was NOT graded.'; exit 1 }
if (-not (Test-Path -LiteralPath $Path)) { Write-Output "[SKIPPED] proc_path_grade: dump not found at $Path; the suspicious-path check was NOT graded."; exit 1 }
$paths = @(Get-PathsFromDump -File $Path)
$v = Get-Verdict -Paths $paths -SigCheck $script:RealSigCheck
if ($v.Total -eq 0) {
    Write-Output ("[OK] No processes running from user-profile locations ({0} process path(s) examined; Program Files, System32 and WindowsApps are out of scope for this check)." -f $v.Seen)
    Write-StateFile -Path $StateFile -Line (Get-StateLine -State 'ok' -Bad 0 -Total 0 -Seen $v.Seen -Names @())
    exit 0
}
if ($v.Bad.Count -eq 0) {
    Write-Output ("[INFO] {0} of {1} process path(s) are under user-profile locations, all validly signed -- per-user installs (Brave, Chrome, Edge, Slack, Teams, VS Code) live there by design. Context, not a finding." -f $v.Total, $v.Seen)
    Write-StateFile -Path $StateFile -Line (Get-StateLine -State 'info' -Bad 0 -Total $v.Total -Seen $v.Seen -Names @($v.InScope | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object -Unique))
    exit 0
}
Write-Output ("[WARNING] {0} of {1} user-profile process path(s) are suspicious -- running from \Temp\, \Downloads\, \Users\Public\ or \`$Recycle, or not validly signed:" -f $v.Bad.Count, $v.Total)
$v.Bad | ForEach-Object { Write-Output ('  ' + $_) }
Write-MarkerFile -Path $MarkerFile
Write-StateFile -Path $StateFile -Line (Get-StateLine -State 'warn' -Bad $v.Bad.Count -Total $v.Total -Seen $v.Seen -Names @($v.Bad | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object -Unique))
exit 0
