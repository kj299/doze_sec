# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   proc_path_grade.ps1 (a section and the dashboard must not contradict each other)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
# One field report raised WARNING "Investigate now" in Section 4 and
# reported "[INFO] ... all validly signed" in the dashboard about the
# same six brave.exe processes. \AppData\ alone is not a signal --
# Brave, Chrome, Edge, Slack, Teams and VS Code all install per-user.
.\tools\proc_path_grade.ps1 -SelfTest
if ($LASTEXITCODE -ne 0) { throw 'proc_path_grade self-test failed' }
# Against a real dump: a signed per-user browser must not be a finding,
# an unsigned binary under \Temp\ must be.
$dump = Join-Path $env:TEMP 'dz_ci_proc4.tmp'
$mk   = Join-Path $env:TEMP 'dz_ci_proc4_hit.txt'
Remove-Item $mk -Force -EA SilentlyContinue
$signed = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
Set-Content $dump -Value ("powershell.exe  111  " + $signed)
$out = (.\tools\proc_path_grade.ps1 -Path $dump -MarkerFile $mk) -join "`n"
Write-Host $out
if (Test-Path $mk) { throw "a validly signed system binary was reported as suspicious: $out" }
$evil = Join-Path $env:TEMP 'dz_ci_unsigned.exe'
Set-Content $evil -Value 'not a real binary'
Set-Content $dump -Value ("evil.exe  222  " + $evil)
$out = (.\tools\proc_path_grade.ps1 -Path $dump -MarkerFile $mk) -join "`n"
Write-Host $out
if (-not (Test-Path $mk)) { throw "an unsigned binary under TEMP was NOT reported: $out" }
Remove-Item $mk -Force -EA SilentlyContinue
# SCOPE. The caller passes the FULL Win32_Process dump, so anything
# outside user-profile paths must not be graded at all. #198 shipped
# without this and reported seven catalog-signed Microsoft Store
# binaries under Program Files\WindowsApps as suspicious on a clean
# machine. Feed real out-of-scope binaries and require silence.
$lines = @()
Get-ChildItem 'C:\Program Files\WindowsApps' -Filter *.exe -Recurse -Depth 2 -EA SilentlyContinue |
  Select-Object -First 3 | ForEach-Object { $lines += ("app.exe  30" + $lines.Count + "  " + $_.FullName) }
$lines += ("svchost.exe  399  " + (Join-Path $env:SystemRoot 'System32\svchost.exe'))
Set-Content $dump -Value $lines
$out = (.\tools\proc_path_grade.ps1 -Path $dump -MarkerFile $mk) -join "`n"
Write-Host $out
if (Test-Path $mk) { throw "out-of-scope binaries (Program Files / System32 / WindowsApps) were reported: $out" }
if ($out -notmatch 'out of scope') { throw "the out-of-scope case did not say so: $out" }
# THE STATE FILE the summary dashboard reads. The tile used to
# re-enumerate Win32_Process itself, roughly eight minutes later in
# the run, and on 2026-09-19 the two disagreed about the same machine
# -- an Ollama install finished between the two enumerations. The
# tile now prints THIS verdict, so its shape is a contract.
$st = Join-Path $env:TEMP 'dz_ci_proc4_state.txt'
foreach ($case in @(
    @{ Lines = @("svchost.exe  399  " + (Join-Path $env:SystemRoot 'System32\svchost.exe')); State = 'ok' },
    @{ Lines = @("powershell.exe  111  " + $signed);                                         State = 'ok' },
    @{ Lines = @("evil.exe  222  " + $evil);                                                 State = 'warn' })) {
  Remove-Item $st, $mk -Force -EA SilentlyContinue
  Set-Content $dump -Value $case.Lines
  $out = (.\tools\proc_path_grade.ps1 -Path $dump -MarkerFile $mk -StateFile $st) -join "`n"
  if (-not (Test-Path $st)) { throw "no state file was written, so the dashboard has no verdict to print: $out" }
  $line = (Get-Content $st -Raw).Trim()
  Write-Host "state: $line"
  $f = $line.Split('|')
  if ($f.Count -ne 5) { throw "the state line must have exactly 5 fields or cmd's for /f mis-parses it: $line" }
  # An EMPTY trailing field is the trap: cmd does not define a token
  # that is not there and leaves the text %%e in the command, so
  # PROCPATH_NAMES would become the literal string '%e'.
  foreach ($fld in $f) { if ($fld -eq '') { throw "the state line has an empty field: $line" } }
  if ($f[0] -ne $case.State) { throw "expected state '$($case.State)', got '$($f[0])': $line" }
  # Scoped to the NAME field. The first version of this ran the
  # class over the WHOLE line and included '|' in it -- the field
  # separator, present in every valid state line -- so the check
  # threw on its own correct output.
  if ($f[4] -match '[&<>^%!"|]') { throw "a shell metacharacter reached the name field of the state line: $line" }
}
# And the WARNING state must agree with the marker -- the tile and
# the ledger row must never be able to say different things.
if (-not (Test-Path $mk)) { throw 'the warn state file was written but no marker: the tile would warn while the ledger stays silent' }
Remove-Item $st, $mk -Force -EA SilentlyContinue

# The 2026-09-19 field instances, verbatim. winget stages under
# \Temp\WinGet\ and Inno Setup extracts into \Temp\is-XXXXXXXX.tmp\.
# Both are TRUE positives and must stay findings;
# tests/benign_corpus.txt carries the ADVISE note that tells the
# reader to ask whether they were installing something.
Set-Content $dump -Value @(
  'OllamaSetup.exe  5420  C:\Users\alice\AppData\Local\Temp\WinGet\Ollama.Ollama.0.34.2\OllamaSetup.exe',
  'OllamaSetup.tmp  20636  C:\Users\alice\AppData\Local\Temp\is-0X2Z2LGMY8.tmp\OllamaSetup.tmp',
  ("svchost.exe  399  " + (Join-Path $env:SystemRoot 'System32\svchost.exe')))
$out = (.\tools\proc_path_grade.ps1 -Path $dump -MarkerFile $mk -StateFile $st) -join "`n"
Write-Host $out
if ($out -notmatch '\[WARNING\] 2 of 2 user-profile process path') {
  throw "the installer-in-Temp field shape is no longer graded as 2 findings: $out"
}
if (-not (Test-Path $mk)) { throw 'the installer-in-Temp finding wrote no marker' }
$names = ((Get-Content $st -Raw).Trim() -split '\|')[4]
if ($names -notmatch 'OllamaSetup\.exe' -or $names -notmatch 'OllamaSetup\.tmp') {
  throw "the state line does not name the flagged binaries: $names"
}

# THE TILE MUST NOT MEASURE AGAIN. Sharing the rule was not enough --
# the inline copy in the bats was already near-identical (it had
# merely dropped $Recycle) and still disagreed, because it was a
# SECOND ENUMERATION at a different moment.
foreach ($bat in @('doze_sec.bat', 'doze_sec_noAdmin.bat')) {
  $txt = Get-Content $bat -Raw
  if ($txt -match "ck 'INFO' \('Processes from user-profile paths") {
    throw "$bat rebuilt the dashboard tile from its own process enumeration -- it must print PROCPATH_STATE, which Section 4 already graded"
  }
  foreach ($needle in @('-StateFile "%TEMP%\dz_proc4_state.txt"',
                        'set /p PROCPATH_LINE=',
                        'if "%PROCPATH_STATE%"=="ungraded"')) {
    if ($txt -notmatch [regex]::Escape($needle)) { throw "$bat is missing the PROCPATH_STATE plumbing: $needle" }
  }
}
Remove-Item $dump, $mk, $evil, $st -Force -EA SilentlyContinue
Write-Host "proc_path_grade.ps1 OK (one measurement, carried to the dashboard)"
