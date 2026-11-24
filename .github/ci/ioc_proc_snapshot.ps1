# CI ONLY -- run by .github/workflows/windows-smoke.yml. Read-only: it lists
# processes and writes only its own temp files. It lives in .github/ so it
# never reaches a USB stick.
#
# tools\ioc_proc_snapshot.ps1, the snapshot Sections 18a and 18g match against:
# its lines must be the former one-liner's byte for byte (select_lines reads
# them), and an administrator's scope line must be an [INFO] count, never a
# deferral.
$ErrorActionPreference = 'Stop'
$st = (.\tools\ioc_proc_snapshot.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'ioc_proc_snapshot -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 7) { throw "ioc_proc_snapshot self-test ran only $n case(s)" }
$snap = (Resolve-Path .\tools\ioc_proc_snapshot.ps1).Path
foreach ($f in 'CommandLine', 'ExecutablePath') {
  $out = Join-Path $env:TEMP "dz_ci_iocsnap_$f.tmp"; $sc = Join-Path $env:TEMP "dz_ci_iocsnap_$f.scope"; $df = Join-Path $env:TEMP "dz_ci_iocsnap_$f.def"
  $old = Join-Path $env:TEMP "dz_ci_iocsnap_$f.old"; $cf = Join-Path $env:TEMP 'dz_ci_iocsnap.cmd'
  Remove-Item $out, $sc, $df, $old -Force -EA SilentlyContinue
  # From cmd, as the bats call it, and the bats' former one-liner beside it.
  Set-Content -LiteralPath $cf -Encoding ASCII -Value @(
    '@echo off',
    ('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Field {1} -OutFile "{2}" -ScopeFile "{3}" -DeferredFile "{4}" 2>nul' -f $snap, $f, $out, $sc, $df),
    'echo EXIT=%errorlevel%',
    ('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {{ $_.Name+''  ''+$_.ProcessId+''  ''+$_.{0} }}" > "{1}" 2>nul' -f $f, $old))
  $ErrorActionPreference = 'Continue'
  $co = (& cmd /c $cf) -join "`n"
  $global:LASTEXITCODE = 0
  $ErrorActionPreference = 'Stop'
  Remove-Item -LiteralPath $cf -Force -EA SilentlyContinue
  if ($co -notmatch 'EXIT=0') { throw "ioc_proc_snapshot -Field $f did not exit 0: $co" }
  $dl = @(Get-Content -LiteralPath $out); $ol = @(Get-Content -LiteralPath $old)
  $scope = (Get-Content -LiteralPath $sc -Raw).Trim()
  Write-Host ("MEASURED: -Field {0}: {1} line(s); scope: {2}" -f $f, $dl.Count, $scope)
  if ($dl.Count -lt 30) { throw "ioc_proc_snapshot -Field $f wrote only $($dl.Count) line(s)" }
  if ($scope -notmatch '^\[INFO\] ') { throw "an administrator's scope line is not an [INFO] count: $scope" }
  if (Test-Path -LiteralPath $df) { throw "an administrator was counted as a deferral for -Field $f" }
  $oldBy = @{}; foreach ($l in $ol) { if ($l -match '^(\S.*?)\s{2,}(\d+)') { $oldBy[$Matches[2]] = @{ Name = $Matches[1]; Line = $l } } }
  $same = 0; $diff = @()
  foreach ($l in $dl) {
    if ($l -notmatch '^(\S.*?)\s{2,}(\d+)') { continue }
    $o = $oldBy[$Matches[2]]
    if (-not $o -or $o.Name -cne $Matches[1]) { continue }
    # A command line can change between two queries (a process's own args do
    # not, but a short-lived one can exit); compare those that match by name.
    if ($o.Line -ceq $l) { $same++ } else { $diff += $l }
  }
  if ($same -lt 20 -or $diff.Count -gt 3) { throw ("ioc_proc_snapshot -Field {0}: its lines differ from the former one-liner's ({1} same): {2}" -f $f, $same, ($diff -join ' | ')) }
  Remove-Item $out, $sc, $df, $old -Force -EA SilentlyContinue
}
Write-Host 'ioc_proc_snapshot: the former lines, and an administrator''s scope stated as an [INFO] count'
exit 0
