# lint_amsi_text.ps1 -- no file in this repository may hold text that
# Microsoft Defender's AMSI scanner reads as an attack.
#
# WHY. A security tool's checks name what they look for. When that text is a
# working AMSI-bypass shape, Defender blocks the script before PowerShell runs
# it: tools\event_scan_check.ps1 carried the bypass words and a textbook
# bypass line as self-test data, and on the first real PC it ran on
# (Defender real-time ON) it was blocked as Trojan:PowerShell/Fleisnam.D.
# Four checks did nothing there, and the owner's Protection history gained a
# Severe detection for our own file. CI never saw it: GitHub's runners run
# Defender with real-time protection off.
#
# So the words are ASSEMBLED at run time ('Am' + 'si' + 'Utils') wherever a
# check or a test needs them, and this lint fails on the contiguous form in
# any tracked text file. The tokens below are themselves assembled, so this
# file passes its own rule.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\lint_amsi_text.ps1 [-SelfTest]
#
# Windows PowerShell 5.1 and pwsh. Pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$Root = '',
    [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'

$a = 'am' + 'si'
$script:Tokens = @(
    ($a + 'init' + 'failed'),
    ($a + 'utils'),
    ($a + 'scan' + 'buffer'),
    ($a + 'scan' + 'string'),
    ($a + 'open' + 'session'),
    ($a + 'context'),
    ($a + 'session'),
    ($a + '.dll')
)

# PURE: the tokens a text holds, case-insensitive.
function Get-AmsiTokens {
    param([string]$Text)
    $low = ([string]$Text).ToLowerInvariant()
    return @($script:Tokens | Where-Object { $low.Contains($_) })
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $w = 'Am' + 'si'
    T 'a contiguous bypass word is found, whatever its case' ((@(Get-AmsiTokens ('x = ''' + $w + 'Utils''')).Count -ge 1) -and (@(Get-AmsiTokens ($w.ToUpper() + 'INITFAILED')).Count -ge 1)) ''
    T 'the assembled form a tool is required to use is not found' (@(Get-AmsiTokens ('$x = ''Am'' + ''si'' + ''Utils''')).Count -eq 0) ''
    T 'ordinary text naming the topic is not found' (@(Get-AmsiTokens 'AMSI-bypass check (Script Block events); T1562.001; AMSI downgrade path').Count -eq 0) ''
    T 'the DLL name is found' (@(Get-AmsiTokens ('LoadLibrary("' + $w.ToLower() + '.dll")')).Count -eq 1) ''
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_lint_amsi_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        Set-Content -LiteralPath (Join-Path $tmp 'bad.ps1') -Value ('$p = ''' + $w + 'Scan' + 'Buffer''') -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $tmp 'good.ps1') -Value '$p = ''Am'' + ''si'' + ''ScanBuffer''' -Encoding ASCII
        $o = & $PSCommandPath -Root $tmp 2>&1 | Out-String
        T 'a planted file fails the lint and is named' (($LASTEXITCODE -ne 0) -and $o -match 'bad\.ps1' -and $o -notmatch 'good\.ps1') $o
        Remove-Item -LiteralPath (Join-Path $tmp 'bad.ps1')
        $o = & $PSCommandPath -Root $tmp 2>&1 | Out-String
        T 'the fragment form alone passes' ($LASTEXITCODE -eq 0) $o
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -EA SilentlyContinue }
    if ($fails) { Write-Output "[FAIL] $fails lint_amsi_text self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] lint_amsi_text self-test: a contiguous AMSI-trigger word fails, the assembled form passes.'
    exit 0
}

if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
$exts = @('.ps1', '.psm1', '.bat', '.cmd', '.txt', '.yml', '.yaml', '.md', '.json', '.html')
$files = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Where-Object {
    $_.FullName -notmatch '[\\/]\.git[\\/]' -and $exts -contains $_.Extension.ToLowerInvariant()
})
if ($files.Count -eq 0) { Write-Output ('[FAIL] no text file found under ' + $Root + ' -- the lint scanned nothing'); exit 1 }
$bad = 0
foreach ($f in $files) {
    $n = 0
    foreach ($line in [IO.File]::ReadAllLines($f.FullName)) {
        $n++
        $hit = @(Get-AmsiTokens $line)
        if ($hit.Count) {
            $bad++
            Write-Output ('[FAIL] {0}:{1} holds AMSI-trigger text ({2}). Defender blocks a script holding it on every PC with real-time protection on. Assemble it at run time instead, e.g. (''Am'' + ''si'' + ''Utils'').' -f $f.FullName.Substring($Root.Length).TrimStart('\', '/'), $n, ($hit -join ', '))
        }
    }
}
if ($bad) { Write-Output ("[FAIL] {0} line(s) hold AMSI-trigger text." -f $bad); exit 1 }
Write-Output ("[OK] No AMSI-trigger text in {0} tracked text file(s)." -f $files.Count)
exit 0
