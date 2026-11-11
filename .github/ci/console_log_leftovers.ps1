# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   Console-log leftovers from an interrupted run are cleared, and no run reuses another run's timestamp (both bats, real runs through the wrapper)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
# A Ctrl+C answered "Terminate batch job? Y" in the window that started
# the console-log wrapper leaves its DOZE_* variables set there. Each
# run below plants exactly that state, plus the interrupted run's
# ChangeLog and Undo file, then starts the bat the way a person does
# (no -noConsoleLog). The runner is a Server image, so without -dev
# both bats stop at the OS check with exit 3 right after creating
# their ChangeLog, Undo file and report: seconds, and -readonly.
# Then the same plant as a REAL child (-dzTeeChild typed, the shape
# of a genuine child) proves the second guard: a timestamp another
# run's files carry is never reused.
# Touches: file:C:\SecurityAudit\ and file:%USERPROFILE%\SecurityAudit\
#   (the two planted 19990101_000000 files and this step's own run
#   files are removed in finally; the output subfolders the runs
#   create, and an HTML report a viewer holds open, stay -- a runner
#   is discarded after the job)
$stale = '19990101_000000'
$t0 = (Get-Date).AddSeconds(-2)
$cases = @(
  @{ Bat = 'doze_sec.bat'; Args = '-readonly'; Out = 'C:\SecurityAudit' },
  @{ Bat = 'doze_sec_noAdmin.bat'; Args = '-noAdmin -readonly'; Out = (Join-Path $env:USERPROFILE 'SecurityAudit') }
)
function Invoke-Planted {
  param($c, [string]$Extra, [string]$Tag)
  $rcFile = Join-Path $env:RUNNER_TEMP ('dz_rc_stale_' + $Tag + '.tmp')
  Remove-Item -LiteralPath $rcFile -Force -EA SilentlyContinue
  $cmdf = Join-Path $env:RUNNER_TEMP ('dz_stale_' + $Tag + '.cmd')
  $outf = Join-Path $env:RUNNER_TEMP ('dz_stale_' + $Tag + '.out')
  @(
    '@echo off',
    'set "DOZE_TEED=1"',
    ('set "DOZE_LOG_TS=' + $stale + '"'),
    ('set "DOZE_CONSOLE_LOG=' + (Join-Path $c.Out ('AuditConsole_' + $stale + '.log')) + '"'),
    ('set "DOZE_EXIT_FILE=' + $rcFile + '"'),
    ('call "' + (Join-Path $PWD $c.Bat) + '" ' + $Extra + $c.Args),
    'exit /b %ERRORLEVEL%'
  ) | Set-Content -LiteralPath $cmdf -Encoding ASCII
  # Start-Process, not a pipe: the end of the run opens the report,
  # and a viewer inheriting a pipe would hold this step open.
  $p = Start-Process -FilePath $env:ComSpec -ArgumentList '/c', ('"' + $cmdf + '"') -RedirectStandardOutput $outf -RedirectStandardError ($outf + '.err') -PassThru -WindowStyle Hidden
  $null = $p.Handle
  if (-not $p.WaitForExit(300000)) { & taskkill /T /F /PID $p.Id 2>$null | Out-Null; throw "$($c.Bat) $Tag hung" }
  $o = (Get-Content -LiteralPath $outf -Raw -EA SilentlyContinue)
  Write-Host ("---- {0} {1}: exit {2}" -f $c.Bat, $Tag, $p.ExitCode)
  Write-Host $o
  return @{ Rc = $p.ExitCode; Out = [string]$o; RcFile = $rcFile }
}
try {
  foreach ($c in $cases) {
    New-Item -ItemType Directory -Path $c.Out -Force | Out-Null
    $cl = Join-Path $c.Out ('ChangeLog_' + $stale + '.txt'); $ub = Join-Path $c.Out ('Undo_' + $stale + '.bat')
    Set-Content -LiteralPath $cl -Value 'dz_ci_stale interrupted run changelog' -Encoding ASCII
    Set-Content -LiteralPath $ub -Value 'rem dz_ci_stale interrupted run undo' -Encoding ASCII
    # (1) The leftover state, started the way a person starts it.
    $r = Invoke-Planted $c '' 'leftover'
    if ($r.Rc -ne 3) { throw ("{0}: expected exit 3 (Server image, no -dev) back through the wrapper, got {1}" -f $c.Bat, $r.Rc) }
    if ($r.Out -notmatch 'Console-log settings left behind by an interrupted audit in this window were cleared') { throw "$($c.Bat): the leftover console-log settings were not detected" }
    if ($r.Out -notmatch 'Console output also being captured to: .*AuditConsole_(\d{8}_\d{6}(?:_r\d+)?)\.log') { throw "$($c.Bat): the run skipped its console capture -- the leftover DOZE_TEED was trusted" }
    $fresh = $Matches[1]
    if ($fresh -eq $stale) { throw "$($c.Bat): the console capture reused the interrupted run's timestamp" }
    if (-not (Test-Path -LiteralPath (Join-Path $c.Out ('AuditConsole_' + $fresh + '.log')))) { throw "$($c.Bat): no console log was written for the fresh run" }
    if ((Get-Content -LiteralPath $cl -Raw).Trim() -ne 'dz_ci_stale interrupted run changelog') { throw "$($c.Bat): the interrupted run's ChangeLog was overwritten" }
    if ((Get-Content -LiteralPath $ub -Raw).Trim() -ne 'rem dz_ci_stale interrupted run undo') { throw "$($c.Bat): the interrupted run's Undo file was overwritten" }
    if (Test-Path -LiteralPath $r.RcFile) { throw "$($c.Bat): the run wrote its exit code into the interrupted run's exit file" }
    if (-not (Test-Path -LiteralPath (Join-Path $c.Out ('ChangeLog_' + $fresh + '.txt')))) { throw "$($c.Bat): the fresh run's ChangeLog is not named by its own timestamp $fresh" }
    Write-Host ("{0}: leftover cleared, fresh run {1} captured, the interrupted run's ChangeLog and Undo file untouched, exit 3 back through the wrapper" -f $c.Bat, $fresh)
    # (2) A real child handed a timestamp another run's files carry.
    $r = Invoke-Planted $c '-dzTeeChild ' 'child'
    if ($r.Rc -ne 3) { throw ("{0}: the child run exited {1}, not 3" -f $c.Bat, $r.Rc) }
    if ((Get-Content -LiteralPath $cl -Raw).Trim() -ne 'dz_ci_stale interrupted run changelog') { throw "$($c.Bat): a child handed a taken timestamp overwrote that run's ChangeLog" }
    if ((Get-Content -LiteralPath $ub -Raw).Trim() -ne 'rem dz_ci_stale interrupted run undo') { throw "$($c.Bat): a child handed a taken timestamp overwrote that run's Undo file" }
    $rep = @(Get-ChildItem -LiteralPath $c.Out -Filter ('SecurityReport_' + $stale + '_r*.txt'))
    if ($rep.Count -ne 1) { throw ("{0}: expected one report renamed off the taken timestamp, found {1}" -f $c.Bat, $rep.Count) }
    if (-not (Select-String -LiteralPath $rep[0].FullName -SimpleMatch -Pattern ('Files named with timestamp ' + $stale + ' already existed in the output folder') -Quiet)) { throw "$($c.Bat): the report does not say its timestamp was replaced" }
    if (-not (Test-Path -LiteralPath $r.RcFile)) { throw "$($c.Bat): a real child did not write its exit code for the wrapper" }
    Write-Host ("{0}: a real child handed a taken timestamp named its files {1} and said so in the report" -f $c.Bat, $rep[0].BaseName)
  }
  Write-Host 'console-log leftovers OK in both bats'
} finally {
  foreach ($c in $cases) {
    if (-not (Test-Path -LiteralPath $c.Out)) { continue }
    Get-ChildItem -LiteralPath $c.Out -File -EA SilentlyContinue | Where-Object { $_.Name -match ('^(ChangeLog|Undo|SecurityReport|AuditConsole|Remediation)_') -and ($_.Name -like ('*' + $stale + '*') -or $_.LastWriteTime -ge $t0) } | Remove-Item -Force -EA SilentlyContinue
  }
  Remove-Item -Path (Join-Path $env:RUNNER_TEMP 'dz_stale_*'), (Join-Path $env:RUNNER_TEMP 'dz_rc_stale_*') -Force -EA SilentlyContinue
}
exit 0
