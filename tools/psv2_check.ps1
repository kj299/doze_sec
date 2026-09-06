# psv2_check.ps1 -- is the PowerShell v2 engine available on this machine?
#
# WHY THIS EXISTS: PSv2 predates AMSI. An attacker who can launch
# `powershell -Version 2` runs script that Defender's script scanner never
# sees -- the AMSI downgrade path, T1059.001. So "is v2 available" is a real
# security question, and the honest answers are YES and NO, not "unavailable".
#
# THE DEFECT THIS REPLACES: the two inline blocks in the bats never once
# produced a verdict on a real Windows 11 machine -- five audits across two
# dates, elevated, all reporting `[SKIPPED] PSv2 state unavailable.`
#
#   * `try{ Get-WindowsOptionalFeature -Online ... }catch{ '...' }` had no
#     -ErrorAction Stop, so the failure was NON-TERMINATING, the catch never
#     ran, and the block emitted nothing at all -- not the data, not the
#     fallback. Its output was simply absent from the report.
#   * `Get-CimInstance Win32_OptionalFeature -Filter Name='...V2Root'`
#     returned nothing, so the else branch printed [SKIPPED].
#
# One silent failure and one empty result, and the section still read CLEAN.
#
# SO: five methods, most authoritative first, and the report says WHICH one
# answered. [SKIPPED] only when all five are inconclusive, and then it lists
# what was tried -- an unavailable answer must never look like a clean one.
#
# The behavioural probe is split in two on purpose. "v2 launched" proves the
# downgrade path exists and outranks every declarative source. "v2 did not
# launch" proves much less -- .NET 3.5 absent, a policy, any startup error
# looks the same -- so it is the LAST method consulted, never the first, and
# the verdict says it was inferred. False reassurance is the worse error here.
#
# Read-only. Windows PowerShell 5.1 and pwsh.

[CmdletBinding()]
param(
    [string]$MarkerFile,
    # One word -- ENABLED / DISABLED / UNKNOWN -- for the summary dashboard, so
    # the dashboard and Section 11 cannot disagree about what was determined.
    [string]$StateFile,
    # Test hook: force a method to report a given result so the three verdicts
    # can be exercised without a machine in that state. Never set in the bats.
    [ValidateSet('', 'Enabled', 'Disabled', 'Inconclusive')]
    [string]$ForceResult = '',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

function Test-Psv2Launches {
    # POSITIVE-ONLY, deliberately. If v2 launches, the downgrade path exists --
    # that is definitive and outranks every declarative source. But a FAILURE to
    # launch is NOT proof the feature is off: .NET 3.5 absent, a policy, or any
    # unrelated startup error would look identical. Concluding "disabled" from
    # that would be false reassurance, which is the worse error for this tool,
    # so a non-launch returns $null and lets the declarative methods answer.
    # Test-Psv2LaunchFailed below is the last-resort reading of the same signal.
    try {
        $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $exe)) { return $null }
        $out = & $exe -Version 2 -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.Major' 2>&1
        if ($LASTEXITCODE -eq 0 -and ("$out" -match '(?m)^\s*2\s*$')) { return $true }
        return $null
    } catch { return $null }
}

function Test-Psv2LaunchFailed {
    # Last resort, only after every declarative source came back inconclusive:
    # v2 does not start, so the downgrade path is not usable here. Reported as
    # disabled BECAUSE that is the security-relevant answer, and the verdict
    # names this method so the reader knows it was inferred, not read.
    try {
        $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $exe)) { return $null }
        & $exe -Version 2 -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.Major' 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { return $false }
        return $null
    } catch { return $null }
}

function Test-Psv2Dism {
    # -ErrorAction Stop is the whole point: without it the failure is
    # non-terminating, the catch never fires, and this returns silence.
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
        if ($null -eq $f) { return $null }
        return ([string]$f.State -eq 'Enabled')
    } catch { return $null }
}

function Test-Psv2Cim {
    try {
        $c = Get-CimInstance Win32_OptionalFeature -Filter "Name='MicrosoftWindowsPowerShellV2Root'" -ErrorAction Stop
        if ($null -eq $c) { return $null }
        return ([int]$c.InstallState -eq 1)
    } catch { return $null }
}

function Test-Psv2Registry {
    # The v2 engine registers under PowerShell\1 with PowerShellVersion 2.0.
    # This key is Microsoft's own worked example for Get-ItemProperty.
    try {
        # An absent HKLM: drive means there is no registry to read -- not that
        # the engine is absent. Without this the tool answered "disabled" off
        # Windows, which is the false reassurance the split probe above exists
        # to prevent, reintroduced one function later.
        if (-not (Get-PSDrive -Name HKLM -ErrorAction SilentlyContinue)) { return $null }
        $k = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
        if (-not (Test-Path -LiteralPath $k)) { return $false }
        $v = (Get-ItemProperty -LiteralPath $k -Name PowerShellVersion -ErrorAction Stop).PowerShellVersion
        return ([string]$v -like '2.*')
    } catch { return $null }
}

function Get-Psv2Verdict {
    param([string]$Force = '')

    $methods = @(
        @{ Name = 'powershell -Version 2 launched successfully';      Run = { Test-Psv2Launches } },
        @{ Name = 'Get-WindowsOptionalFeature (DISM)';                Run = { Test-Psv2Dism } },
        @{ Name = 'Win32_OptionalFeature (CIM)';                      Run = { Test-Psv2Cim } },
        @{ Name = 'HKLM\SOFTWARE\Microsoft\PowerShell\1 engine key';  Run = { Test-Psv2Registry } },
        @{ Name = 'powershell -Version 2 would not start (inferred)'; Run = { Test-Psv2LaunchFailed } }
    )
    $tried = @()
    foreach ($m in $methods) {
        $r = if ($Force -eq 'Enabled')      { $true }
             elseif ($Force -eq 'Disabled') { $false }
             elseif ($Force -eq 'Inconclusive') { $null }
             else { & $m.Run }
        $tried += $m.Name
        if ($null -ne $r) { return @{ Enabled = [bool]$r; By = $m.Name; Tried = $tried } }
    }
    return @{ Enabled = $null; By = $null; Tried = $tried }
}

if ($SelfTest) {
    $fails = 0
    foreach ($case in @(
        @{ Force = 'Enabled';      Sev = 'WARNING';  Needle = 'PowerShell v2 ENABLED';   Marker = $true;  State = 'ENABLED'  },
        @{ Force = 'Disabled';     Sev = 'OK';       Needle = 'PowerShell v2 disabled';  Marker = $false; State = 'DISABLED' },
        @{ Force = 'Inconclusive'; Sev = 'SKIPPED';  Needle = 'all 5 method';            Marker = $false; State = 'UNKNOWN'  }
    )) {
        $mk = Join-Path ([System.IO.Path]::GetTempPath()) ('dz_psv2_st_' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.txt')
        $sf = "$mk.state"
        $out = (& $PSCommandPath -MarkerFile $mk -StateFile $sf -ForceResult $case.Force) -join "`n"
        $ok = $true
        if ($out -notlike ('*' + $case.Needle + '*')) { $ok = $false; Write-Output "[FAIL] $($case.Force): output lacks '$($case.Needle)' -- got: $out" }
        $has = Test-Path -LiteralPath $mk
        if ($has -ne $case.Marker) { $ok = $false; Write-Output "[FAIL] $($case.Force): marker present=$has, expected $($case.Marker)" }
        $word = (Get-Content -LiteralPath $sf -EA SilentlyContinue | Select-Object -First 1)
        if ($word -ne $case.State) { $ok = $false; Write-Output "[FAIL] $($case.Force): state file says '$word', expected '$($case.State)'" }
        Remove-Item -LiteralPath $mk, $sf -Force -EA SilentlyContinue
        if ($ok) { Write-Output "[OK]   $($case.Force) -> $($case.Sev), marker=$($case.Marker)" } else { $fails++ }
    }
    # The inconclusive case must NAME what it tried; "unavailable" with no
    # detail is the failure mode this tool exists to end.
    $out = (& $PSCommandPath -ForceResult Inconclusive) -join "`n"
    foreach ($n in @('powershell -Version 2', 'DISM', 'CIM', 'engine key', 'inferred')) {
        if ($out -notlike ('*' + $n + '*')) { Write-Output "[FAIL] inconclusive output does not name the method '$n'"; $fails++ }
    }
    if ($fails -eq 0) { Write-Output "[OK]   an inconclusive result names all five methods it tried" }
    if ($fails) { Write-Output "[FAIL] $fails psv2_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] psv2_check self-test: enabled raises, disabled is clean, inconclusive is declared and itemised.'
    exit 0
}

$v = Get-Psv2Verdict -Force $ForceResult

if ($StateFile) {
    $word = if ($null -eq $v.Enabled) { 'UNKNOWN' } elseif ($v.Enabled) { 'ENABLED' } else { 'DISABLED' }
    $sdir = Split-Path -Parent $StateFile
    if ($sdir -and -not (Test-Path -LiteralPath $sdir)) { New-Item -ItemType Directory -Path $sdir -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath $StateFile -Value $word -Encoding ASCII -EA SilentlyContinue
}

if ($null -eq $v.Enabled) {
    Write-Output ("[SKIPPED] PSv2 state undetermined -- all {0} methods were inconclusive: {1}. This is NOT a clean result: an AMSI-downgrade path may exist and this run could not tell." -f $v.Tried.Count, ($v.Tried -join '; '))
    exit 0
}
if ($v.Enabled) {
    Write-Output ("[WARNING] PowerShell v2 ENABLED -- AMSI downgrade possible (determined by: {0}). An attacker running 'powershell -Version 2' executes script Defender's script scanner never sees. Fix: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root" -f $v.By)
    if ($MarkerFile) {
        $dir = Split-Path -Parent $MarkerFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null }
        # No -EA SilentlyContinue: a failed write here turns a real WARNING into
        # a CLEAN section, which is exactly how a field test lost its finding.
        Set-Content -LiteralPath $MarkerFile -Value 'hit' -Encoding ASCII
    }
    exit 0
}
Write-Output ("[OK] PowerShell v2 disabled -- no AMSI downgrade path (determined by: {0})." -f $v.By)
exit 0
