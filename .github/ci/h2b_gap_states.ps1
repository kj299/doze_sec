# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It creates scratch folders (two with a deny ACL) and points USERPROFILE and
# TEMP at scratch folders for its own process; do not run it on a machine you
# use. It lives in .github/ so it never reaches a USB stick.
#
# PR H2b's checks through their real readers on Windows PowerShell 5.1:
#   vt_check / vt_ip_check with no key      -> NOT performed, gap marker (no network used)
#   vt_self_check with an empty key         -> exit 2, NOT performed
#   baseline_diff on the runner             -> every category captured, ADMIN by SID, no gap
#   baseline_diff vs a baseline missing SVC -> SVC compared in neither direction, a raised gap
#   proc_snapshot -ScopeFile, elevated      -> an [INFO] path scope, no deferral
#   account_files_check, a denied folder    -> a raised gap, never "not found"; the runner's own: no gap
$ErrorActionPreference = 'Stop'
foreach ($t in 'vt_check', 'vt_self_check', 'vt_ip_check', 'proc_snapshot', 'account_files_check') {
  $o = (& ".\tools\$t.ps1" -SelfTest) -join "`n"
  if ($LASTEXITCODE -ne 0) { Write-Host $o; throw "$t -SelfTest failed" }
}
$o = (& .\tools\baseline_diff.ps1 -Mode Diff -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $o; throw 'baseline_diff -SelfTest failed' }

$scr = Join-Path $env:TEMP ("dz_ci_h2b_{0}" -f $PID)
$md = Join-Path $scr 'm'
New-Item -ItemType Directory -Path $md -Force | Out-Null
$denied = @()
function Deny([string]$Dir) {
  # Through .NET, not Get-Acl: the provider resolves the path first, which can
  # trip on the very ACE this plants (the F1 cleanup lesson).
  $di = New-Object IO.DirectoryInfo $Dir
  $acl = $di.GetAccessControl('Access'); $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, 'ListDirectory, ReadData, ReadAttributes, ReadExtendedAttributes', 'ContainerInherit, ObjectInherit', 'None', 'Deny')))
  $script:denied += $Dir
  $di.SetAccessControl($acl)
}
function Undeny([string]$Dir) {
  $di = New-Object IO.DirectoryInfo $Dir
  $acl = $di.GetAccessControl('Access')
  foreach ($r in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Deny' })) { [void]$acl.RemoveAccessRuleSpecific($r) }
  $di.SetAccessControl($acl)
}
$oldProfile = $env:USERPROFILE; $oldTemp = $env:TEMP
try {
  # ---- VirusTotal: no key is a check NOT performed, raised. No network. ----
  $prof = Join-Path $scr 'p'; $tmp = Join-Path $scr 't'
  New-Item -ItemType Directory -Path $prof, $tmp -Force | Out-Null
  $env:USERPROFILE = $prof; $env:TEMP = $tmp
  $o = (& .\tools\vt_check.ps1) -join "`n"; Write-Host $o
  if ($o -notmatch '\[WARNING\] VirusTotal check NOT performed' -or -not (Test-Path (Join-Path $tmp 'dz_iochit_18j_gap.txt'))) { throw 'vt_check with no key was not a raised gap' }
  if ($o -match '\[OK\]') { throw 'vt_check printed an [OK] with no key' }
  $o = (& .\tools\vt_ip_check.ps1) -join "`n"; Write-Host $o
  if ($o -notmatch '\[WARNING\] VirusTotal IP check NOT performed' -or -not (Test-Path (Join-Path $tmp 'dz_iochit_18l_gap.txt'))) { throw 'vt_ip_check with no key was not a raised gap' }
  Set-Content -LiteralPath (Join-Path $prof '.vt_token') -Value '' -Encoding ASCII
  $o = (& .\tools\vt_self_check.ps1 -Binaries "$env:SystemRoot\System32\reg.exe") -join "`n"; $rc = $LASTEXITCODE; Write-Host $o
  if ($rc -ne 2 -or $o -notmatch '\[WARNING\] VT pre-flight integrity check NOT performed') { throw "vt_self_check with an empty key exited $rc without the NOT-performed line" }
  $env:USERPROFILE = $oldProfile; $env:TEMP = $oldTemp

  # ---- baseline_diff on the runner: every category read; ADMIN by SID. ----
  $bl = Join-Path $scr 'b.snapshot'
  $o = (& .\tools\baseline_diff.ps1 -Mode Save -Path $bl -MarkerDir $md) -join "`n"; Write-Host $o
  $snap = Get-Content -LiteralPath $bl
  if (@($snap | Where-Object { $_ -match '^# NotCaptured:' }).Count) { throw ('the runner baseline left categories out: ' + (@($snap | Where-Object { $_ -match '^# NotCaptured:' }) -join ' ')) }
  if (Test-Path (Join-Path $md 'dz_baseline_gap.txt')) { throw 'a clean runner baseline raised a gap' }
  foreach ($cat in 'DRV', 'SVC', 'TASK', 'PORT', 'ADMIN', 'CERT') {
    if (-not @($snap | Where-Object { $_ -like "$cat|*" }).Count) { throw "the runner baseline holds no $cat record" }
  }
  $o = (& .\tools\baseline_diff.ps1 -Mode Diff -Path $bl -MarkerDir $md) -join "`n"; Write-Host $o
  if (Test-Path (Join-Path $md 'dz_baseline_gap.txt')) { throw 'a clean runner diff raised a gap' }
  if ($o -match 'NOT performed') { throw 'a clean runner diff printed a NOT-performed line' }
  # A baseline that did not capture SVC: compared in neither direction.
  $noSvc = @($snap | Where-Object { $_ -notlike 'SVC|*' }) + '# NotCaptured: SVC'
  Set-Content -LiteralPath $bl -Value $noSvc -Encoding UTF8
  $o = (& .\tools\baseline_diff.ps1 -Mode Diff -Path $bl -MarkerDir $md) -join "`n"; Write-Host $o
  if (-not (Test-Path (Join-Path $md 'dz_baseline_gap.txt'))) { throw 'a baseline that did not capture SVC raised no gap' }
  if ($o -notmatch '\[WARNING\] Baseline comparison NOT performed for 1 categor\(ies\) -- service\.') { throw 'the uncaptured category was not named' }
  if ($o -match 'NEW service since baseline') { throw 'a category the baseline never held came back as NEW services (the defect)' }
  Remove-Item -LiteralPath (Join-Path $md 'dz_baseline_gap.txt') -Force

  # ---- proc_snapshot: the path scope, from the same query. ----
  $sf = Join-Path $scr 'scope.txt'; $df = Join-Path $scr 'deferred.txt'
  $null = & .\tools\proc_snapshot.ps1 -ScopeFile $sf -DeferredFile $df
  $sc = Get-Content -LiteralPath $sf -Raw; Write-Host $sc
  if ($sc -notmatch '^\[INFO\] Path scope: ') { throw 'an elevated snapshot did not write the [INFO] path scope' }
  if (Test-Path $df) { throw 'an elevated snapshot counted a deferral' }
  $null = & .\tools\proc_snapshot.ps1 -ScopeFile $sf -DeferredFile $df -Elevated 0
  $sc = Get-Content -LiteralPath $sf -Raw; Write-Host $sc
  if ($sc -notmatch '^\[DEFERRED - ADMIN REQUIRED\] Path scope:' -or -not (Test-Path $df)) { throw 'a standard-user path scope (System and Idle expose no path) was not a counted deferral' }

  # ---- account_files_check: a denied folder is a gap; the runner's own is not. ----
  foreach ($c in 'PsHistory', 'CloudCreds') {
    Get-ChildItem -LiteralPath $md -Filter 'dz_*' | Remove-Item -Force
    $o = (& .\tools\account_files_check.ps1 -Check $c -MarkerDir $md) -join "`n"; Write-Host $o
    if ((Get-ChildItem -LiteralPath $md -Filter 'dz_*_gap.txt').Count) { throw "the runner's own $c raised a gap" }
  }
  $cr = Join-Path $scr 'cr'
  New-Item -ItemType Directory -Path (Join-Path $cr '.aws'), (Join-Path $cr '.kube') -Force | Out-Null
  Set-Content -LiteralPath (Join-Path $cr '.aws\credentials') -Value '[default]' -Encoding ASCII
  $o = (& .\tools\account_files_check.ps1 -Check CloudCreds -CredRoot $cr -MarkerDir $md) -join "`n"; Write-Host $o
  if ($o -notmatch 'AWS CLI: ' -or (Test-Path (Join-Path $md 'dz_cloudcred_gap.txt'))) { throw 'a readable credential file was not listed, or raised a gap' }
  if ($o -match 'kubectl') { throw 'an empty .kube folder (no config) was reported as a credential file' }
  Deny (Join-Path $cr '.aws')
  $o = (& .\tools\account_files_check.ps1 -Check CloudCreds -CredRoot $cr -MarkerDir $md) -join "`n"; Write-Host $o
  if ($o -notmatch '\[WARNING\] Cloud CLI credential check NOT performed in full' -or -not (Test-Path (Join-Path $md 'dz_cloudcred_gap.txt'))) { throw 'a credential folder this account may not read was not a raised gap' }
  if ($o -match '\[OK\] No cloud CLI credential files') { throw 'the all-clear was printed over a folder that could not be read (the defect)' }
  $hd = Join-Path $scr 'hist'
  New-Item -ItemType Directory -Path $hd -Force | Out-Null
  Set-Content -LiteralPath (Join-Path $hd 'ConsoleHost_history.txt') -Value '[CRITICAL] typed', 'Get-Date' -Encoding ASCII
  Set-Content -LiteralPath (Join-Path $hd 'Visual Studio Code Host_history.txt') -Value 'code-cmd' -Encoding ASCII
  Get-ChildItem -LiteralPath $md -Filter 'dz_*' | Remove-Item -Force
  $o = (& .\tools\account_files_check.ps1 -Check PsHistory -HistoryDir $hd -MarkerDir $md) -join "`n"; Write-Host $o
  if ($o -notmatch '(?m)^    > code-cmd\r?$' -or $o -notmatch '(?m)^    > \[CRITICAL\] typed\r?$') { throw 'both history files were not read, or a line was not indented' }
  if ($o -match '(?m)^\[CRITICAL\]') { throw 'a history line was printed as a severity tag' }
  Deny $hd
  $o = (& .\tools\account_files_check.ps1 -Check PsHistory -HistoryDir $hd -MarkerDir $md) -join "`n"; Write-Host $o
  if ($o -notmatch '\[WARNING\] PowerShell history check NOT performed in full' -or -not (Test-Path (Join-Path $md 'dz_pshist_gap.txt'))) { throw 'a history folder this account may not read was not a raised gap' }
  if ($o -match 'No PowerShell history saved') { throw '"no history" was printed over a folder that could not be read (the defect)' }
  Write-Host '[OK] H2b: VT with no key, a baseline category not captured, a denied credential or history folder: each a raised gap, never an all-clear; the runner itself raised none.'
} finally {
  $env:USERPROFILE = $oldProfile; $env:TEMP = $oldTemp
  foreach ($d in $denied) {
    try { Undeny $d } catch {
      Write-Host "undeny failed for ${d}: $($_.Exception.Message) -- resetting with icacls"
      & icacls.exe $d /reset /T /C /Q | Out-Null
    }
  }
  Remove-Item -LiteralPath $scr -Recurse -Force -EA SilentlyContinue
  if (Test-Path -LiteralPath $scr) { throw "cleanup failed: $scr remains" }
}
