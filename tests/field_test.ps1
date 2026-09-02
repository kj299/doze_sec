# field_test.ps1 -- false-positive hunting on the machine you are sitting at.
#
# READ-ONLY. NO PLANTS. NO NETWORK. This runs the audit with -readonly, which
# changes nothing on this machine outside the output folder and the temp
# folder and opens no network connections, then checks the report against the
# benign look-alike corpus (tests\benign_corpus.txt) and hands you every
# finding to adjudicate. It never runs the plant harness; that belongs on a
# throwaway VM or CI (tests\manual_ci.ps1).
#
# It also PROVES the read-only claim on this machine: the RunOnce key, the
# boot configuration and the restore-point count are captured before and
# after, and must be unchanged.
#
# Exit 0 unless the read-only proof, the report's integrity or the corpus
# check fails. The audit's own findings never fail this script -- they are the
# state of your machine, and the point is to read them.
#
# Windows PowerShell 5.1 compatible.

[CmdletBinding()]
param(
    [string]$BatPath,
    [string]$OutDir,
    [switch]$NoConsoleLog
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$batArgs = @('-dev', '-readonly')
if (-not $BatPath) {
    if ($elevated) { $BatPath = Join-Path $root 'doze_sec.bat' }
    else { $BatPath = Join-Path $root 'doze_sec_noAdmin.bat'; $batArgs += '-noAdmin' }
} elseif ((Split-Path -Leaf $BatPath) -ieq 'doze_sec.bat' -and -not $elevated) {
    Write-Host '[FAIL] doze_sec.bat needs an elevated PowerShell. Re-run elevated, or omit -BatPath to use doze_sec_noAdmin.bat -noAdmin.'
    exit 1
}
if (-not (Test-Path -LiteralPath $BatPath)) { Write-Host ("[FAIL] not found: {0}" -f $BatPath); exit 1 }
if ($NoConsoleLog) { $batArgs += '-noConsoleLog' }
if (-not $OutDir) {
    if ($batArgs -contains '-noAdmin') { $OutDir = Join-Path $env:USERPROFILE 'SecurityAudit' } else { $OutDir = 'C:\SecurityAudit' }
}
$scriptName = [IO.Path]::GetFileNameWithoutExtension($BatPath)
$runOnceKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
$runOnceVal = "*{0}_resume" -f $scriptName

Write-Host ''
Write-Host '== Field test: false-positive hunting, READ-ONLY =='
Write-Host ('   audit   : {0} {1}' -f (Split-Path -Leaf $BatPath), ($batArgs -join ' '))
Write-Host ('   writes  : {0} and the temp folder -- nothing else' -f $OutDir)
Write-Host '   network : none'
Write-Host '   plants  : none -- every finding below is the real state of this machine'
Write-Host '   This takes a few minutes. You can keep using the machine.'
Write-Host ''

function Get-Snapshot {
    $s = @{}
    $s.RunOnce = $null
    try { $s.RunOnce = (Get-ItemProperty -LiteralPath $runOnceKey -Name $runOnceVal -EA Stop).$runOnceVal } catch {}
    $s.Bcd = $null
    if ($elevated) { try { $s.Bcd = ((& bcdedit /enum '{bootmgr}' 2>$null) -join "`n") } catch {} }
    $s.Rp = $null
    if ($elevated) { try { $s.Rp = @(Get-ComputerRestorePoint -EA Stop).Count } catch {} }
    return $s
}

$fail = 0
function Check { param([bool]$Ok, [string]$Label, [string]$Why)
    if ($Ok) { Write-Host ("  [OK     ] {0}" -f $Label) } else { Write-Host ("  [FAIL   ] {0} -- {1}" -f $Label, $Why); $script:fail++ }
}

$before = Get-Snapshot
$t0 = Get-Date
Push-Location $root
# The audit writes ordinary diagnostics to stderr (e.g. a reg query on an
# absent key). Under $ErrorActionPreference='Stop' with redirection, Windows
# PowerShell 5.1 turns each such line into a terminating NativeCommandError,
# so relax it for the invocation only and stream everything as text.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & $BatPath @batArgs 2>&1 | ForEach-Object { "$_" }
    $auditExit = $LASTEXITCODE
} finally { $ErrorActionPreference = $prevEap; Pop-Location }
$after = Get-Snapshot
Write-Host ''
Write-Host ("== Audit finished: exit code {0} in {1:n0}s ==" -f $auditExit, ((Get-Date) - $t0).TotalSeconds)
Write-Host ''
Write-Host '== Read-only proof (this machine, before vs after) =='
Check ($null -eq $after.RunOnce) 'RunOnce resume key: absent after the run' ("value '{0}' exists: the run wrote to HKCU RunOnce" -f $runOnceVal)
if ($null -ne $before.Bcd -and $null -ne $after.Bcd) { Check ($before.Bcd -eq $after.Bcd) 'boot configuration (bcdedit /enum {bootmgr}): unchanged' 'bcdedit output differs -- the run changed the boot manager' }
else { Write-Host '  [SKIP   ] boot configuration: bcdedit needs an elevated PowerShell (or is unavailable here); not compared' }
if ($null -ne $before.Rp -and $null -ne $after.Rp) { Check ($before.Rp -eq $after.Rp) 'restore points: count unchanged' ("count went {0} -> {1}: the run created a restore point" -f $before.Rp, $after.Rp) }
else { Write-Host '  [SKIP   ] restore points: Get-ComputerRestorePoint unavailable here (server OS, or not elevated); not compared' }

Write-Host ''
Write-Host '== Report integrity =='
$report = Get-ChildItem -LiteralPath $OutDir -Filter 'SecurityReport_*.txt' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $report) { Write-Host ("  [FAIL   ] no SecurityReport_*.txt under {0}" -f $OutDir); $fail++ }
else {
    Write-Host ("  report: {0}" -f $report.FullName)
    if ($report.LastWriteTime -lt $t0) { Write-Host '  [FAIL   ] the newest report predates this run -- the audit produced no report'; $fail++ }
    $text = [IO.File]::ReadAllText($report.FullName)
    Check ($report.DirectoryName -notmatch '\\selftest$') 'report is a REAL report (not under selftest\)' 'landed in the test quarantine'
    Check ($text -notmatch 'TEST RUN -- every finding below was planted') 'report carries no TEST RUN banner' 'a real run was stamped as a test run'
    Check ($text -match 'READ-ONLY RUN -- this audit makes no changes') 'report carries the READ-ONLY banner' 'the -readonly switch did not take effect'
    Check ($text -match '(?m)^\s*EXIT CODE:') 'report has an EXIT CODE line (the audit completed)' 'no EXIT CODE line -- the audit aborted'
    Check ($text -match '\[18/18\]') 'report reached section [18/18]' 'the audit did not reach the last section'
    foreach ($step in @('RunOnce resume key not created', 'network check not performed', 'self-update check and threat-list sync not performed', 'no restore point created')) {
        Check ($text -match [regex]::Escape($step)) ("read-only skip declared: {0}" -f $step) 'the report does not declare this skip'
    }
    if ($elevated -and ($batArgs -notcontains '-noAdmin')) { Check ($text -match 'boot menu left as found') 'read-only skip declared: boot menu left as found' 'the report does not declare the bcdedit skip' }

    Write-Host ''
    $bc = Join-Path $root 'tools\benign_corpus_check.ps1'
    & $bc -Mode Report -Report $report.FullName
    if ($LASTEXITCODE -ne 0) { $fail++ }

    Write-Host ''
    Write-Host '== Adjudication worksheet: every finding on this machine =='
    $ledger = Get-ChildItem -LiteralPath $OutDir -Filter 'SecurityReport_*.ledger' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $rows = @()
    if ($ledger) { $rows = @(Get-Content -LiteralPath $ledger.FullName -EA SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' }) }
    if ($rows.Count -eq 0) { Write-Host '   (no CRITICAL or WARNING findings in the ledger)' }
    else {
        $n = 0
        foreach ($rw in $rows) { $n++; $f = $rw.Split('|'); Write-Host ("   {0,3}. [{1}] section {2}{3}  {4}" -f $n, $f[0], $f[1], $(if ($f.Count -gt 2 -and $f[2]) { " " + $f[2] } else { '' }), $(if ($f.Count -gt 3) { ($f[3..($f.Count - 1)] -join '|') } else { '' })) }
    }
    Write-Host ''
    Write-Host '   For each line decide: REAL (act on it -- see the report''s remediation section),'
    Write-Host '   or a BENIGN LOOK-ALIKE (something legitimate on this machine that the tool'
    Write-Host '   mistook). A benign look-alike is a bug in the tool, not in your machine:'
    Write-Host '   record it so it cannot come back -- add a block to tests\benign_corpus.txt:'
    Write-Host ''
    Write-Host '     [short-id]'
    Write-Host '     class     = ADVISE            (or QUIET with maxsev = INFO once the tool reports it as context)'
    Write-Host '     proof     = field:<why it cannot be planted on a runner>'
    Write-Host '     signature = <regex matching the report line above>'
    Write-Host '     note      = <what it really is, and the command that verifies it>'
    Write-Host ''
    Write-Host '   then open an issue or PR with the report line and the block.'
}

Write-Host ''
if ($fail -gt 0) { Write-Host ("FAIL: {0} read-only / integrity / corpus check(s) failed. The audit's own findings are NOT counted here." -f $fail); exit 1 }
Write-Host 'OK: read-only run verified, report intact, no known benign look-alike reported as a finding.'
exit 0
