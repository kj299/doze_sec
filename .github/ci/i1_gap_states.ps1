# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It writes scratch files under TEMP and runs a small cmd harness; do not run
# it on a machine you use. It lives in .github/ so it never reaches a USB stick.
#
# Group I1 through the real readers on Windows PowerShell 5.1 and cmd.exe:
#   masquerade_check: no snapshot / no tree / an unreadable tree -> a raised gap
#     plus the done marker, never an unraised [SKIPPED]; a snapshot with no
#     system-process path on a standard-user token -> a counted deferral; the
#     runner's own snapshot -> no gap.
#   psv2_check and edr_presence on the runner -> no gap (both are knowable).
#   :dz_section_clean, cut from each bat and run by cmd.exe: a ledger that is
#     absent while findings were counted is "NOT determined", never CLEAN.
$ErrorActionPreference = 'Stop'
$scr = Join-Path $env:TEMP ("dz_ci_i1_{0}" -f $PID)
New-Item -ItemType Directory -Path $scr -Force | Out-Null
try {
  # ---- masquerade_check ----
  function RunMQ([hashtable]$A) {
    foreach ($n in 'gap', 'def', 'done') { Remove-Item -LiteralPath (Join-Path $scr $n) -Force -EA SilentlyContinue }
    $o = (& .\tools\masquerade_check.ps1 @A -GapFile (Join-Path $scr 'gap') -DeferredFile (Join-Path $scr 'def') -DoneFile (Join-Path $scr 'done')) -join "`n"
    Write-Host $o
    return @{ Out = $o; Gap = (Test-Path (Join-Path $scr 'gap')); Def = (Test-Path (Join-Path $scr 'def')); Done = (Test-Path (Join-Path $scr 'done')) }
  }
  $snap = Join-Path $scr 'snap.tmp'; $tree = Join-Path $scr 'tree.tmp'
  $null = & .\tools\proc_snapshot.ps1 -TreePath $tree | Set-Content -LiteralPath $snap -Encoding UTF8
  $r = RunMQ @{ Path = (Join-Path $scr 'none.tmp') }
  if (-not ($r.Gap -and $r.Done) -or $r.Out -match '\[SKIPPED\]' -or $r.Out -notmatch '\[WARNING\] Masquerading check NOT performed') { throw 'a missing snapshot was not a raised gap with its done marker' }
  $r = RunMQ @{ Path = $snap; TreePath = (Join-Path $scr 'notree.tmp') }
  if (-not ($r.Gap -and $r.Done) -or $r.Out -notmatch '\[WARNING\] Masquerading-by-parent check NOT performed -- the process tree .* was not found') { throw 'a missing process tree (the LSASS-copy signal lost) was not a raised gap' }
  $fs = [IO.File]::Open($tree, 'Open', 'Read', 'None')
  try {
    $r = RunMQ @{ Path = $snap; TreePath = $tree }
    if (-not ($r.Gap -and $r.Done) -or $r.Out -notmatch 'process tree could not be read') { throw 'a process tree held open with no sharing was not a raised gap' }
  } finally { $fs.Close() }
  $r = RunMQ @{ Path = $snap; TreePath = $tree }
  if ($r.Gap -or $r.Def -or -not $r.Done -or $r.Out -match 'NOT performed') { throw "the runner's own snapshot and tree raised a gap or a deferral" }
  # Every system-process path hidden, as a standard-user token sees them.
  $nopath = @(Get-Content -LiteralPath $snap | ForEach-Object { if ($_ -match '^(\S+)\s+(\d+)\s') { $Matches[1] + '  ' + $Matches[2] + '  ' } })
  $np = Join-Path $scr 'nopath.tmp'; Set-Content -LiteralPath $np -Value $nopath -Encoding UTF8
  $r = RunMQ @{ Path = $np; TreePath = $tree; Elevated = 0 }
  if (-not $r.Def -or $r.Gap -or $r.Out -notmatch '\[DEFERRED - ADMIN REQUIRED\] Masquerading-by-name check not performed from this token') { throw 'a standard-user token shown no system-process path was not a counted deferral' }
  $r = RunMQ @{ Path = $np; TreePath = $tree; Elevated = 1 }
  if (-not $r.Gap -or $r.Def) { throw 'an elevated token shown no system-process path was not a raised gap' }

  # ---- psv2_check and edr_presence: no gap on a runner ----
  $g = Join-Path $scr 'psv2gap'
  $o = (& .\tools\psv2_check.ps1 -StateFile (Join-Path $scr 'psv2state') -GapFile $g) -join "`n"; Write-Host $o
  if (Test-Path $g) { throw 'psv2_check raised a gap on a runner, where PSv2 state is knowable' }
  $o = (& .\tools\edr_presence.ps1 -MarkerDir $scr) -join "`n"; Write-Host $o
  if ($o -match 'Security Center check NOT performed') { throw 'root\SecurityCenter2 could not be queried on a client runner' }

  # ---- :dz_section_clean, the real subroutine, under cmd.exe ----
  foreach ($bat in 'doze_sec.bat', 'doze_sec_noAdmin.bat') {
    $L = [IO.File]::ReadAllLines((Resolve-Path $bat))
    $a = [array]::IndexOf($L, ':dz_section_clean'); $u = [array]::IndexOf($L, ':dz_section_clean_unread')
    if ($a -lt 0 -or $u -lt $a) { throw "${bat}: :dz_section_clean not found" }
    $b = $u; while ($L[$b] -ne 'goto :eof') { $b++ }
    $h = Join-Path $scr 'h.cmd'; $rep = Join-Path $scr 'r.txt'; $led = Join-Path $scr 'x.ledger'
    Remove-Item -LiteralPath $rep, $led -Force -EA SilentlyContinue
    $body = @('@echo off', 'setlocal EnableDelayedExpansion', ('set "REPORT=' + $rep + '"'), ('set "LEDGER=' + $led + '"'),
      'set "FINDINGS=3"', 'call :dz_section_clean 4', 'echo A=!DZ_SEC_CLEAN!',
      'set "FINDINGS=0"', 'call :dz_section_clean 4', 'echo B=!DZ_SEC_CLEAN!',
      '>>"%LEDGER%" echo WARNING^|4^|T1036^|x', 'set "FINDINGS=1"',
      'call :dz_section_clean 4', 'echo C=!DZ_SEC_CLEAN!', 'call :dz_section_clean 5', 'echo D=!DZ_SEC_CLEAN!',
      'exit /b 0') + $L[$a..$b]
    [IO.File]::WriteAllLines($h, [string[]]$body)
    $o = (& cmd.exe /d /c "`"$h`"") -join "`n"; Write-Host "${bat}: $o"
    if ($o -notmatch 'A=0' -or $o -notmatch 'B=1' -or $o -notmatch 'C=0' -or $o -notmatch 'D=1') { throw "${bat}: :dz_section_clean answered wrongly (want A=0 B=1 C=0 D=1): $o" }
    if ((Get-Content -LiteralPath $rep -Raw) -notmatch '\[WARNING\] Section 4 verdict NOT determined') { throw "${bat}: an absent ledger with findings counted did not say NOT determined" }
    # Measured, not assumed: what findstr exits for a ledger held open with no sharing.
    $fs = [IO.File]::Open($led, 'Open', 'Read', 'None')
    try { $null = & cmd.exe /d /c "findstr /b /c:`"WARNING|4|`" `"$led`" >nul 2>&1"; Write-Host "[MEASURED] findstr on a ledger held open with no sharing exits $LASTEXITCODE" } finally { $fs.Close() }
  }
  Write-Host '[OK] I1: a masquerade check that could not run is a raised gap (a deferral where the token explains it), the runner raised none, and a ledger that could not be read never makes a section CLEAN.'
} finally {
  Remove-Item -LiteralPath $scr -Recurse -Force -EA SilentlyContinue
}
