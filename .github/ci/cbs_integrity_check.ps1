# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   cbs_integrity_check.ps1 (Windows' own record of corrupt system binaries)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
# THE VERDICT, PROVEN. Corrupting a protected system binary to make
# Windows log it is destructive, so the decision lives in pure
# functions and -SelfTest drives them over fixed inputs -- including
# the REAL CBS lines from the 2026-09-07 bthmodem.sys field case and
# Microsoft's own documented benign example from KB 954402. Without
# this the live run below would only prove the script executes.
$st = (.\tools\cbs_integrity_check.ps1 -SelfTest) -join "`n"
Write-Host $st
if ($LASTEXITCODE -ne 0) { throw 'cbs_integrity_check -SelfTest failed: the corrupt-file verdict is wrong' }
if ($st -notmatch 'corrupt-then-repaired raises NOTHING') { throw 'self-test no longer covers the repaired case -- a file Windows already fixed could be reported as live corruption' }
if ($st -notmatch 'KB 954402') { throw 'self-test no longer covers the KB 954402 benign class -- wallpaper hash mismatches can be reported as compromise again' }
if ($st -notmatch 'verifying NOW is resolved context') { throw 'self-test no longer proves the log is treated as history and the present is verified' }
if ($st -notmatch 'unrepaired AND still unverifiable is a WARNING') { throw 'self-test no longer proves the check can fire at all' }
$cases = ([regex]::Matches($st, '(?m)^\[OK\]')).Count
if ($cases -lt 10) { throw "self-test ran only $cases case(s) -- it is not exercising the verdict" }

# LIVE RUN against the runner's real CBS logs. A clean CI image has no
# unrepaired corruption, so a finding here would be a false positive
# of exactly the kind this check was designed to avoid.
$md = Join-Path $env:TEMP ("dz_cbs_ci_{0}" -f $PID)
New-Item -ItemType Directory -Path $md -Force | Out-Null
try {
  # A generous budget for the live read, so a slow runner is not a
  # gap; then ANY gap on an elevated runner is a failure, not a pass.
  $out = (.\tools\cbs_integrity_check.ps1 -MarkerDir $md -BudgetSeconds 120) -join "`n"
  Write-Host $out
  if ($out -notmatch '\[(OK|INFO|WARNING|SKIPPED)\]') { throw 'the live run emitted no graded line at all' }
  if ($out -match '\[BUDGET\]') { throw 'the [BUDGET] tag is back -- a raised gap prints [WARNING] ... NOT performed' }
  # A [SKIPPED] here is a FAILURE, not an acceptable outcome. This job
  # runs elevated on a Windows runner, so %WINDIR%\Logs\CBS IS
  # readable and the tool's state is knowable -- the same reason
  # psv2_check's [SKIPPED] fails CI. Tolerating it is not hypothetical:
  # a [datetime]::TryParse with an untyped [ref] threw, sent every file
  # read into the catch, and reported a perfectly readable log as
  # SKIPPED -- and the earlier version of THIS assertion accepted it.
  if ($out -match '\[SKIPPED\]' -or $out -match 'system-file integrity NOT checked') { throw "cbs_integrity_check reported a gap on an elevated runner, where the CBS logs are readable: $out" }
  # The all-clear must state the window it covers. CBS rotates and can
  # hold less than a week, so an unbounded "no corrupt system files"
  # claims far more than it knows.
  if ($out -notmatch 'covering (back to \d{4}-\d{2}-\d{2}|an undetermined period)') { throw 'the live run did not state the log window it actually covered' }

  # FIXTURE ROUND-TRIP through the real reader. The self-test drives
  # only the pure functions, so the file-reading path -- accounting,
  # timestamp window, wording -- had no coverage at all, and two bugs
  # in it passed the self-test untouched.
  $fx = Join-Path $env:TEMP ("dz_cbs_fx_{0}.log" -f $PID)
  Set-Content -LiteralPath $fx -Encoding ASCII -Value @(
    '2026-09-01 08:00:00, Info                  CBS    Starting TrustedInstaller initialization.',
    '2026-09-07 15:24:17, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\system32\drivers\bthmodem.sys',
    '2026-09-07 16:17:40, Info                  DEPLOY [Pnp] Repaired file: C:\WINDOWS\System32\drivers\bthmodem.sys'
  )
  $mdF = Join-Path $env:TEMP ("dz_cbs_fx_md_{0}" -f $PID)
  New-Item -ItemType Directory -Path $mdF -Force | Out-Null
  try {
    $outF = (.\tools\cbs_integrity_check.ps1 -Path $fx -MarkerDir $mdF) -join "`n"
    Write-Host $outF
    if ($outF -match '\[SKIPPED\]') { throw "the reader reported SKIPPED on a readable fixture: $outF" }
    if ($outF -notmatch 'were repaired, or verify correctly now') { throw 'the real reader did not treat corrupt-then-repaired as resolved context' }
    if ($outF -notmatch 'covering back to 2026-09-01') { throw 'the reader did not report the window from the fixture''s first timestamp' }
    if (Test-Path (Join-Path $mdF 'dz_cbs.txt')) { throw 'a corrupt-then-repaired fixture wrote a marker -- it would raise a finding for a file Windows already fixed' }
  } finally {
    Remove-Item $fx, $mdF -Recurse -Force -EA SilentlyContinue
  }
  # A GAP IS ITS OWN ROW: a CBS log that cannot be read writes
  # dz_cbs_gap.txt and NO finding marker, so the ledger row reads
  # "NOT checked", never "corrupt system binary"; no all-clear prints.
  $mdG = Join-Path $env:TEMP ("dz_cbs_gap_md_{0}" -f $PID)
  New-Item -ItemType Directory -Path $mdG -Force | Out-Null
  try {
    $outG = (.\tools\cbs_integrity_check.ps1 -Path (Join-Path $env:TEMP ("dz_no_such_cbs_{0}.log" -f $PID)) -MarkerDir $mdG) -join "`n"
    Write-Host $outG
    if ($outG -notmatch '\[WARNING\] CBS log\(s\) could not be read') { throw 'an unreadable CBS log was not declared as a raised gap' }
    if (-not (Test-Path (Join-Path $mdG 'dz_cbs_gap.txt'))) { throw 'the unreadable-CBS gap wrote no gap marker -- it would vanish from the ledger' }
    if (Test-Path (Join-Path $mdG 'dz_cbs.txt')) { throw 'the unreadable-CBS gap wrote the FINDING marker -- its ledger row would claim a corrupt binary' }
    if ($outG -match '(?m)^\[OK\]') { throw 'a gap-only run printed an all-clear line' }
  } finally { Remove-Item $mdG -Recurse -Force -EA SilentlyContinue }
  # A TIME BUDGET THAT RAN OUT IS A GAP, never the finding. WIN11-02
  # (2026-10-24) printed only "[BUDGET] 1 CBS log file(s) cut short"
  # and its ledger read "Windows servicing recorded a corrupt system
  # binary that was never repaired": the tool raised its FINDING
  # severity for missing coverage. The never-opened path through the
  # real reader here (budget 0); the cut-short path is driven by the
  # self-test's fake clock, deterministically.
  $fxB = Join-Path $env:TEMP ("dz_cbs_budget_{0}.log" -f $PID)
  Set-Content -LiteralPath $fxB -Encoding ASCII -Value '2026-09-01 08:00:00, Info                  CBS    Starting TrustedInstaller initialization.'
  $mdB = Join-Path $env:TEMP ("dz_cbs_budget_md_{0}" -f $PID)
  New-Item -ItemType Directory -Path $mdB -Force | Out-Null
  try {
    $outB = (.\tools\cbs_integrity_check.ps1 -Path $fxB -MarkerDir $mdB -BudgetSeconds 0) -join "`n"
    Write-Host $outB
    if ($outB -notmatch '(?m)^\[WARNING\] System-file integrity check NOT performed -- the 0s wall-clock budget ran out before any of 1 CBS log file') { throw 'budget 0: the exhausted budget was not declared as a NOT-performed gap' }
    if (-not (Test-Path (Join-Path $mdB 'dz_cbs_gap.txt'))) { throw 'budget 0: no gap marker -- the gap would vanish from the ledger' }
    if (Test-Path (Join-Path $mdB 'dz_cbs.txt')) { throw 'budget 0: the FINDING marker was written -- its ledger row would claim a corrupt system binary the tool never found' }
    if ($outB -match '(?m)^\[OK\]') { throw 'budget 0: an all-clear printed over a log that was never opened' }
  } finally { Remove-Item $fxB, $mdB -Recurse -Force -EA SilentlyContinue }
  # THE DEFAULT BUDGET COVERS A LARGE LOG. WIN11-02 ran out of the
  # 20 s budget on both runs: the old reader walked the log one line
  # at a time in PowerShell. A 150 MB CBS-shaped log -- noise, and one
  # corrupt-file line at the very END -- must be read IN FULL within
  # the default budget on 5.1, and that last line must be found.
  $fxS = Join-Path $env:TEMP ("dz_cbs_speed_{0}.log" -f $PID)
  $noiseLine = "2026-10-18 05:21:00, Info                  CSI    00000001 Noise line for the servicing stack with some ordinary content here`r`n"
  $block = [Text.Encoding]::ASCII.GetBytes(($noiseLine * [int](1MB / $noiseLine.Length)))
  $fsS = [IO.File]::Open($fxS, 'Create', 'Write', 'None')
  try {
    $head = [Text.Encoding]::ASCII.GetBytes("2026-10-18 05:21:00, Info                  CBS    Starting TrustedInstaller initialization.`r`n")
    $fsS.Write($head, 0, $head.Length)
    for ($k = 0; $k -lt 150; $k++) { $fsS.Write($block, 0, $block.Length) }
    $tail = [Text.Encoding]::ASCII.GetBytes("2026-10-24 09:00:00, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\System32\dz_ci_cbs_speed_absent_$PID.dll`r`n")
    $fsS.Write($tail, 0, $tail.Length)
  } finally { $fsS.Dispose() }
  $mdS = Join-Path $env:TEMP ("dz_cbs_speed_md_{0}" -f $PID)
  New-Item -ItemType Directory -Path $mdS -Force | Out-Null
  try {
    $outS = (.\tools\cbs_integrity_check.ps1 -Path $fxS -MarkerDir $mdS) -join "`n"
    Write-Host $outS
    if ($outS -match 'NOT performed' -or (Test-Path (Join-Path $mdS 'dz_cbs_gap.txt'))) { throw "a 150 MB CBS log did not fit the default 20 s budget on 5.1 -- the reader is too slow for a real machine's log: $outS" }
    if ($outS -notmatch '1 file\(s\) recorded as corrupt are no longer on disk') { throw 'the corrupt-file line at the END of the 150 MB log was not found' }
    $sp = [regex]::Match($outS, 'Scanned ([\d.,]+) MB of CBS log in ([\d.,]+) s')
    if (-not $sp.Success) { throw 'the reader did not print what it scanned and how long it took' }
    Write-Host ("MEASURED: the 150 MB fixture scanned in {0} s on Windows PowerShell 5.1" -f $sp.Groups[2].Value)
  } finally { Remove-Item $fxS, $mdS -Recurse -Force -EA SilentlyContinue }
  # ONE FILE READ, ONE NOT: the unread one is part of the window NOT
  # examined, so it is a raised gap and withholds the all-clear (it
  # used to print only an [INFO] line beneath an [OK]).
  $fxM = Join-Path $env:TEMP ("dz_cbs_mixed_{0}.log" -f $PID)
  Set-Content -LiteralPath $fxM -Encoding ASCII -Value '2026-09-01 08:00:00, Info                  CBS    Starting TrustedInstaller initialization.'
  $mdM = Join-Path $env:TEMP ("dz_cbs_mixed_md_{0}" -f $PID)
  New-Item -ItemType Directory -Path $mdM -Force | Out-Null
  try {
    $outM = (.\tools\cbs_integrity_check.ps1 -Path $fxM, (Join-Path $env:TEMP ("dz_no_such_cbs_m_{0}.log" -f $PID)) -MarkerDir $mdM) -join "`n"
    Write-Host $outM
    if ($outM -notmatch '(?m)^\[WARNING\] System-file integrity check NOT performed in full -- 0 CBS log file\(s\) denied and 1 unreadable') { throw 'a CBS log that could not be opened beside a readable one was not declared as a gap' }
    if (-not (Test-Path (Join-Path $mdM 'dz_cbs_gap.txt'))) { throw 'the partly-unread window wrote no gap marker' }
    if ($outM -match '(?m)^\[OK\]') { throw 'an all-clear printed over a window with an unread log' }
  } finally { Remove-Item $fxM, $mdM -Recurse -Force -EA SilentlyContinue }
  # A CLEAN RUNNER WRITES NO FINDING MARKER. This used to accept a
  # WARNING "because the runner may run out of budget" -- the branch
  # that accepted the misworded row above. A budget or access gap
  # now writes only dz_cbs_gap.txt, so a finding marker here is a
  # false positive (measured: the runner reads its CBS logs in full).
  $spL = [regex]::Match($out, 'Scanned ([\d.,]+) MB of CBS log in ([\d.,]+) s')
  if ($spL.Success) { Write-Host ("MEASURED: the runner's own CBS logs: {0} MB in {1} s" -f $spL.Groups[1].Value, $spL.Groups[2].Value) } else { throw 'the live read did not print what it scanned' }
  if ((Test-Path (Join-Path $md 'dz_cbs_gap.txt')) -or $out -match 'NOT performed') { throw "cbs_integrity_check declared a gap on an elevated runner with a 120 s budget, where every CBS log is readable: $out" }
  $m = Join-Path $md 'dz_cbs.txt'
  if (Test-Path $m) { throw ("cbs_integrity_check wrote a {0} finding marker on a clean runner (false positive): {1}" -f (Get-Content $m).Trim(), $out) }
  # An unreadable log must never be graded OK, and budget exhaustion
  # must never read as a pass. Both framings are load-bearing.
  $src = Get-Content .\tools\cbs_integrity_check.ps1 -Raw
  if ($src -notmatch 'missing coverage, not a pass') { throw 'the budget-exhaustion framing was removed' }
  if ($src -notmatch 'a LEAD, not a') { throw 'the "log is history, verify the present" framing was removed' }
} finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
Write-Host "cbs_integrity_check.ps1 OK"
exit 0
