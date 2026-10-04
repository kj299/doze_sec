# exec_probe.ps1 -- can this machine run the audit's helper scripts at all?
#
# Every check that uses a tools\*.ps1 helper, and every staged block, runs as
# `powershell -ExecutionPolicy Bypass -File ...`. Two things on a managed
# machine defeat that, and both used to read as CLEAN:
#
#   * an execution policy set by Group Policy (MachinePolicy / UserPolicy,
#     e.g. AllSigned) OVERRIDES -ExecutionPolicy Bypass, so every -File call
#     is refused; a refused helper writes no marker, and no marker means OK;
#   * AppLocker / WDAC script rules run PowerShell in ConstrainedLanguage,
#     where Add-Type and most .NET types throw inside the checks.
#
# The bat runs this ONCE, early, with -File. If no state file appears, scripts
# are refused; if the state names a language mode other than FullLanguage, the
# checks would run crippled. Either way the audit says so and stops instead of
# printing CLEAN for checks that never ran.
#
# Only cmdlets and syntax that ConstrainedLanguage allows, so the probe itself
# can report that mode. Pure ASCII, Windows PowerShell 5.1.

[CmdletBinding()]
param(
    [string]$StateFile = '',
    [switch]$SelfTest
)

$script:Modes = @('FullLanguage', 'ConstrainedLanguage', 'RestrictedLanguage', 'NoLanguage')

function Get-ExecState {
    # 'ok|<LanguageMode>' -- the mode is always one of $script:Modes.
    $m = [string]$ExecutionContext.SessionState.LanguageMode
    if ($script:Modes -notcontains $m) { $m = 'Unknown' }
    return ('ok|' + $m)
}

if ($SelfTest) {
    $fails = 0
    $s = Get-ExecState
    if ($s -match '^ok\|(FullLanguage|ConstrainedLanguage|RestrictedLanguage|NoLanguage|Unknown)$') { Write-Output "[OK]   the state line is ok|<language mode>: $s" }
    else { Write-Output "[FAIL] the state line is malformed: $s"; $fails++ }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_exec_probe_selftest_{0}.txt' -f $PID)
    Set-Content -LiteralPath $tmp -Value $s -Encoding ASCII
    $back = (Get-Content -LiteralPath $tmp -TotalCount 1)
    Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue
    if ($back -eq $s) { Write-Output '[OK]   the state file round-trips as one ASCII line (read by set /p)' }
    else { Write-Output "[FAIL] the state file read back as '$back'"; $fails++ }
    if ($fails -gt 0) { Write-Output "FAILED: $fails"; exit 1 }
    Write-Output 'exec_probe self-test: all cases passed'
    exit 0
}

if (-not $StateFile) { $StateFile = Join-Path $env:TEMP 'dz_exec_state.txt' }
Set-Content -LiteralPath $StateFile -Value (Get-ExecState) -Encoding ASCII
