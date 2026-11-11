# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   cross_api_check.ps1 -SelfTest + live (rootkit discrepancy; race-tolerance + Tarrask logic)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
$st = (.\tools\cross_api_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'cross_api_check.ps1 -SelfTest failed' }
$nst = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($nst -lt 28) { throw "cross_api_check self-test ran only $nst case(s)" }
if ($st -notmatch 'TaskCache unreadable as a standard user is DEFERRED') { throw 'cross_api_check self-test no longer covers the standard-user TaskCache deferral' }
if ($st -notmatch 'GONE at the final liveness check is a race') { throw 'cross_api_check self-test no longer covers the process race (corpus: cross-api-race)' }
Write-Host "cross_api_check -SelfTest OK ($nst cases)"
$md = Join-Path $env:TEMP ("dz_ca_ci_{0}" -f $PID)
New-Item -ItemType Directory -Path $md -Force | Out-Null
$tc = "HKCU:\Software\dz_ci_taskcache_$PID"
try {
  # Clean runner: processes/services churn constantly, so this is the
  # real false-positive gate -- if race re-verification is broken, a
  # healthy machine reports a phantom hidden process every run.
  $out = (.\tools\cross_api_check.ps1 -MarkerDir $md) -join "`n"
  Write-Host $out
  if ($out -match '\[CRITICAL\]') { throw "cross_api_check reported CRITICAL on a clean runner (race handling or enumeration bug)" }
  # A WARNING marker is allowed here: reading TaskCache SD values can
  # require SYSTEM, and reporting that blindness as [SKIPPED]+WARNING is
  # the honest outcome. A CRITICAL marker is not -- that is a false
  # accusation, which is what this gate exists to prevent.
  $cm = Join-Path $md 'dz_crossapi.txt'
  if (Test-Path $cm) {
    $cv = (Get-Content $cm).Trim()
    if ($cv -eq 'CRITICAL') { throw "crossapi wrote a CRITICAL marker on a clean runner" }
    Write-Host ("  note: clean-runner marker is {0} (acceptable -- a skipped check, not an accusation)" -f $cv)
  }
  if ($out -notmatch 'Process lists agree') { throw 'process cross-check did not run' }
  if ($out -notmatch 'Service views agree') { throw 'service cross-check did not run' }
  # The by-name probe against a REAL SCM answer, on 5.1, under the
  # token this job has (elevated). A service whose DACL denies
  # Administrators SERVICE_QUERY_STATUS is omitted from enumeration
  # ("If the caller does not have the SERVICE_QUERY_STATUS access
  # right to a service, the service is silently omitted from the
  # list of services returned" -- EnumServicesStatusEx remarks,
  # learn.microsoft.com) and OpenService by name fails with error 5.
  # The first probe read that code from the wrong exception layer
  # and defaulted to 1060; the second read .NET ServiceController's
  # HARD-CODED 1060 (it resolves the name via GetServiceDisplayName
  # and discards the real error). Both graded this very plant as a
  # rootkit. The probe is now `sc.exe query`, whose exit code is the
  # SCM's own. The verdict here must be the elevated 'refuses an
  # administrator' WARNING: not CRITICAL, and not the 'no Win32
  # error code' fallback. DELETE and WRITE_DAC stay granted to
  # Administrators so cleanup works.
  $md5 = Join-Path $md 'dacl'
  New-Item -ItemType Directory -Path $md5 -Force | Out-Null
  & sc.exe create dz_ci_dacl_admin binPath= 'C:\Windows\System32\cmd.exe /c rem dz_selftest_dacl' start= demand | Out-Null
  try {
    & sc.exe sdset dz_ci_dacl_admin 'D:(D;;LC;;;BA)(A;;CCDCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)' | Out-Null
    $t5 = (.\tools\cross_api_check.ps1 -MarkerDir $md5) -join "`n"
    Write-Host ($t5 -split "`n" | Where-Object { $_ -match 'dz_ci_dacl_admin|Service views|T1014' })
    if ($t5 -match '\[CRITICAL\] Service present in the registry') { throw 'a DACL-restricted service was graded as a hidden service (CRITICAL) -- the by-name probe did not read error 5' }
    if ($t5 -match 'no Win32 error code') { throw 'the by-name probe could not read a Win32 code from sc.exe on 5.1 (the probe regressed)' }
    if ($t5 -notmatch "\[WARNING\] Service dz_ci_dacl_admin refuses an administrator's query") {
      if ($t5 -match 'Service views agree across SCM, WMI and registry \(\d+ Win32 services graded\)') { throw 'the DACL plant was enumerated after all -- the SERVICE_QUERY_STATUS omission assumption did not hold on this runner; the by-name probe was not exercised' }
      throw 'the DACL-restricted service was not reported as refusing an administrator'
    }
  } finally {
    & sc.exe delete dz_ci_dacl_admin 2>&1 | Out-Null
  }
  # Tarrask logic against a SYNTHETIC hive -- never touches the real
  # TaskCache, so the live Task Scheduler is unaffected.
  $guid = '{dead0000-0000-0000-0000-00000000cafe}'
  New-Item -Path "$tc\Tree\dz_ci_hidden" -Force | Out-Null
  Set-ItemProperty -Path "$tc\Tree\dz_ci_hidden" -Name 'Id' -Value $guid -Force
  New-Item -Path "$tc\Tasks\$guid" -Force | Out-Null
  # (a) Tasks entry WITHOUT an SD value AND absent from the real Task
  # Scheduler (it only exists in this synthetic hive) = both signals
  # Tarrask requires, so it must be reported.
  $md2 = Join-Path $md 'tarrask'
  New-Item -ItemType Directory -Path $md2 -Force | Out-Null
  $t1 = (.\tools\cross_api_check.ps1 -MarkerDir $md2 -TreeRoot "$tc\Tree" -TasksRoot "$tc\Tasks") -join "`n"
  Write-Host ($t1 -split "`n" | Where-Object { $_ -match 'Tarrask|security descriptor|dz_ci_hidden' })
  if ($t1 -notmatch 'NO security descriptor') { throw 'missing-SD task was not reported as Tarrask-style hidden' }
  if ((Get-Content (Join-Path $md2 'dz_crossapi.txt')).Trim() -ne 'CRITICAL') { throw 'Tarrask finding did not write a CRITICAL marker' }
  # (b) Same task WITH an SD value must be clean -- proves the check
  # keys on the missing descriptor, not merely on the task existing.
  Set-ItemProperty -Path "$tc\Tasks\$guid" -Name 'SD' -Value ([byte[]](1,2,3,4)) -Type Binary -Force
  $md3 = Join-Path $md 'withsd'
  New-Item -ItemType Directory -Path $md3 -Force | Out-Null
  $t2 = (.\tools\cross_api_check.ps1 -MarkerDir $md3 -TreeRoot "$tc\Tree" -TasksRoot "$tc\Tasks") -join "`n"
  if ($t2 -match 'NO security descriptor') { throw 'task WITH an SD was still reported as hidden (false positive)' }
  # (c) SCHEDULER UNAVAILABLE = the check CANNOT run. The rule is
  # "missing SD AND absent from the scheduler", so without the
  # scheduler no hit is reachable -- yet the tool used to print
  # "[INFO] ... ran without its second signal" and then "[OK] No
  # hidden scheduled tasks ... all carry a security descriptor". Two
  # false statements on exactly the host an implant that just planted
  # a hidden task would produce. It must now decline to claim a clean
  # result and raise the blind spot instead.
  $md4 = Join-Path $md 'nolive'
  New-Item -ItemType Directory -Path $md4 -Force | Out-Null
  $t3 = (.\tools\cross_api_check.ps1 -MarkerDir $md4 -TreeRoot "$tc\Tree" -TasksRoot "$tc\Tasks" -SkipLiveTaskCompare) -join "`n"
  Write-Host ($t3 -split "`n" | Where-Object { $_ -match 'hidden|scheduler|Scheduler' })
  if ($t3 -match '\[OK\] No hidden scheduled tasks') { throw 'claimed a clean hidden-task result while the check could not run' }
  # The proportion guard is the OTHER path that empties $noSd and
  # declares the check not performed; it used to print the SKIPPED
  # line and then, one branch later, "all carry a security
  # descriptor" -- contradicting itself in adjacent lines.
  $src = Get-Content .\tools\cross_api_check.ps1 -Raw
  if ($src -notmatch '\$sdSuppressed') { throw 'the proportion-guard suppression flag is gone -- the self-contradicting [OK] can return' }
  if ($src -notmatch '\$noSd\.Count -eq 0 -and \$liveOk -and -not \$sdSuppressed') { throw 'the hidden-task [OK] is no longer guarded on both degradation paths' }
  # A raised gap prints [WARNING] (vocabulary decision 2026-10-03): the
  # degraded path says the check could NOT run and raises it.
  if ($t3 -notmatch '\[WARNING\][^\r\n]*hidden-task[^\r\n]*could NOT run') { throw 'degraded hidden-task path did not report itself as a raised gap ([WARNING] ... could NOT run)' }
  # A GAP IS ITS OWN ROW (2026-10-03): the degraded path writes the GAP
  # marker, never the finding marker, so its ledger row reads "check NOT
  # performed", not "rootkit indicator".
  if (-not (Test-Path (Join-Path $md4 'dz_crossapi_gap.txt'))) { throw 'degraded hidden-task path raised no gap at all -- it would vanish from the ledger' }
  if (Test-Path (Join-Path $md4 'dz_crossapi.txt')) { throw 'degraded hidden-task path wrote the FINDING marker -- its ledger row would claim a rootkit indicator for a scheduler it could not open' }
} finally {
  Remove-Item $tc -Recurse -Force -EA SilentlyContinue
  Remove-Item $md -Recurse -Force -EA SilentlyContinue
}
Write-Host "cross_api_check.ps1 OK (incl. honest degradation when the scheduler is unavailable)"
exit 0
