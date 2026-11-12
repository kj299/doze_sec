# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It installs and removes one service whose image path carries a staging
# folder, so the System log holds a real Event 7045 to find; do not run it on
# a machine you use. It lives in .github/ so it never reaches a USB stick.
$ErrorActionPreference = 'Stop'
$st = (.\tools\event_scan_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'event_scan_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 22) { throw "event_scan_check self-test ran only $n case(s)" }
function RunE([string]$Check, [hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_evscan_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\event_scan_check.ps1 -Check $Check -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    if (-not @(Get-ChildItem $md -Filter 'dz_*_done.txt').Count) { throw "$Check wrote no done marker: $o" }
    return @{ Out = $o; Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_done.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
# LIVE: the runner's real logs. Each check must ANSWER (an administrator can
# read both logs): a verdict line, and never a gap.
foreach ($c in 'AmsiBypass', 'ServiceInstalls', 'ScriptBlockList') {
  $r = RunE $c @{}
  Write-Host ("MEASURED: {0} on the runner's own log: markers [{1}]" -f $c, $r.Markers)
  if ($r.Markers -match '_gap|_deferred' -or $r.Out -match 'NOT performed') { throw "$c could not read a log an administrator can read: $($r.Out)" }
  if ($r.Out -notmatch '(?m)^\[INFO\] \d+ event\(s\) read from the ') { throw "$c did not say how many events it read: $($r.Out)" }
}
# THE READ THAT FAILS, through the real reader: a log that does not exist.
foreach ($c in @(@('AmsiBypass', 'dz_amsiev_gap'), @('ServiceInstalls', 'dz_svc7045_gap'), @('ScriptBlockList', 'dz_sblist_gap'))) {
  $r = RunE $c[0] @{ LogName = 'dz-ci-no-such-log/Operational' }
  if ($r.Markers -ne $c[1] -or $r.Out -match '(?m)^\[OK\]' -or $r.Out -notmatch '(?m)^\[WARNING\] .* NOT performed -- ') { throw "$($c[0]): a log that cannot be read was not a raised gap: [$($r.Markers)] $($r.Out)" }
}
Write-Host 'event scan: a log that cannot be read is a raised gap for all three checks, never an all-clear'
# A REAL 7045, both directions. The malign twin: a service whose image path
# is under C:\Users\Public. The benign twin: the same install carrying the
# harness MARKER in its image path, which must be excluded and counted.
# Touches: service:dz_ci_evscan_bad, service:dz_ci_evscan_own (both deleted
# in finally; the System log keeps the two install records, as it does for
# every harness plant).
$bad = 'dz_ci_evscan_bad'; $own = 'dz_ci_evscan_own'
try {
  & sc.exe create $bad binPath= 'C:\Users\Public\dz_ci_evscan_absent.exe' start= demand | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "sc create $bad failed ($LASTEXITCODE)" }
  & sc.exe create $own binPath= 'C:\Users\Public\dz_selftest_evscan_absent.exe' start= demand | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "sc create $own failed ($LASTEXITCODE)" }
  $r = $null
  for ($i = 0; $i -lt 10; $i++) { $r = RunE 'ServiceInstalls' @{}; if ($r.Out -match 'dz_ci_evscan_absent\.exe') { break }; Start-Sleep -Seconds 1 }
  if ($r.Markers -notmatch 'dz_svc7045_hit' -or $r.Out -notmatch '(?m)^\[WARNING\]\[T1543\.003\] Suspicious service installations found:' -or $r.Out -notmatch 'dz_ci_evscan_absent\.exe') { throw "a service installed from C:\Users\Public was not the finding: [$($r.Markers)] $($r.Out)" }
  if ($r.Out -match 'dz_selftest_evscan_absent') { throw "the harness's own install was listed as a finding: $($r.Out)" }
  if ($r.Out -notmatch '(?m)^\[INFO\] \d+ service-install event\(s\) were doze_sec''s own test harness') { throw "the excluded install was not declared with a count: $($r.Out)" }
  Write-Host 'event scan: a real Event 7045 from a staging path is the finding; the marked twin is excluded and counted'
} finally {
  $ErrorActionPreference = 'Continue'
  & sc.exe delete $bad | Out-Null; & sc.exe delete $own | Out-Null
  $global:LASTEXITCODE = 0
}
exit 0
