# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   lsass_dump_config.ps1 -SelfTest + a planted dump-on-exit setting (on a test image, never the runner's LSASS)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
$st = (.\tools\lsass_dump_config.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'lsass_dump_config.ps1 -SelfTest failed' }
$nst = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($nst -lt 36) { throw "lsass_dump_config self-test ran only $nst case(s)" }
Write-Host "lsass_dump_config -SelfTest OK ($nst cases)"
# The runner's real LSASS: nothing configured, nothing on disk.
$md = Join-Path $env:TEMP 'dz_ci_lsadump'
Remove-Item $md -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory -Path $md | Out-Null
$out = (.\tools\lsass_dump_config.ps1 -MarkerDir $md) -join "`n"
Write-Host $out
if ($out -match 'Exception|is not recognized|CategoryInfo') { throw "PowerShell error text in the output: $out" }
if (Test-Path (Join-Path $md 'dz_lsadump.txt')) { throw "the runner's LSASS was reported as configured for a dump: $out" }
if ($out -notmatch '\[OK\] Nothing is configured to write a memory dump of lsass\.exe') { throw "no OK line for a clean runner: $out" }
if ($out -notmatch 'and no such dump was found in .+(Temp|CrashDumps)' -and $out -notmatch 'no such dump was found in any of the documented dump folders \(.+do not exist on this machine\)') { throw 'the OK line does not say where it looked, nor which folders were absent' }
# The grading, proven on a HARMLESS test image: the real LSASS keys are
# never written, so a runner cannot be left watching its own LSASS exit.
# Touches: registry HKLM\...\Image File Execution Options\dz_ci_dumpcfg.exe
# and HKLM\...\SilentProcessExit\dz_ci_dumpcfg.exe, both removed in finally.
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dz_ci_dumpcfg.exe'
$spe  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\dz_ci_dumpcfg.exe'
$dumpDir = Join-Path $env:TEMP 'dz_ci_dumpcfg_dumps'
try {
  New-Item -Path $ifeo -Force | Out-Null
  New-ItemProperty -Path $ifeo -Name 'GlobalFlag' -Value 512 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $ifeo -Name 'AuditLevel' -Value 8 -PropertyType DWord -Force | Out-Null
  New-Item -Path $spe -Force | Out-Null
  New-ItemProperty -Path $spe -Name 'ReportingMode' -Value 2 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $spe -Name 'LocalDumpFolder' -Value $dumpDir -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $spe -Name 'DumpType' -Value 2 -PropertyType DWord -Force | Out-Null
  New-Item -ItemType Directory -Path $dumpDir -Force | Out-Null
  # 'MDMP' first: the check grades the HEADER, so a file without it
  # is reported as named-like-a-dump rather than as one. Both shapes
  # are asserted below.
  Set-Content -LiteralPath (Join-Path $dumpDir 'dz_ci_dumpcfg-1234.dmp') -Value 'MDMP not a real dump' -Encoding ASCII -NoNewline
  Set-Content -LiteralPath (Join-Path $dumpDir 'dz_ci_dumpcfg-notadump.dmp') -Value 'plain text, not a dump' -Encoding ASCII -NoNewline
  Remove-Item $md -Recurse -Force -EA SilentlyContinue
  New-Item -ItemType Directory -Path $md | Out-Null
  $p = (.\tools\lsass_dump_config.ps1 -MarkerDir $md -ImageName 'dz_ci_dumpcfg.exe') -join "`n"
  Write-Host $p
  if ($p -notmatch '\[WARNING\] Silent-process-exit monitoring is ENABLED for dz_ci_dumpcfg\.exe: .*GlobalFlag = 0x200 has the 0x200 flag set') { throw "the planted GlobalFlag was not read from a real REG_DWORD: $p" }
  if ($p -notmatch ('\[WARNING\] dz_ci_dumpcfg\.exe is configured to have its memory DUMPED when it exits: .*writing to ' + [regex]::Escape($dumpDir))) { throw "the planted dump setting was not reported with its folder: $p" }
  if ($p -notmatch '\[CRITICAL\] A memory dump of dz_ci_dumpcfg\.exe is on disk: .*dz_ci_dumpcfg-1234\.dmp') { throw "the planted dump file was not found where the setting points: $p" }
  if ($p -notmatch '\[WARNING\] A file named like a memory dump of dz_ci_dumpcfg\.exe is on disk, but it is not one: .*dz_ci_dumpcfg-notadump\.dmp') { throw "a file named like a dump without a minidump header was not reported as that: $p" }
  if ($p -notmatch '\[INFO\] Image File Execution Options\\dz_ci_dumpcfg\.exe\\AuditLevel = 8 -- the LSA-protection audit setting') { throw "AuditLevel was not named as the ordinary setting: $p" }
  if ((Get-Content (Join-Path $md 'dz_lsadump.txt')).Trim() -ne 'CRITICAL') { throw 'the dump file did not drive a CRITICAL marker' }
  if ($p -match 'credential|LSASS') { throw 'the test image borrowed LSASS''s wording' }
  Write-Host 'lsass_dump_config live OK: a real REG_DWORD GlobalFlag, a dump setting and a dump file are all graded, on a test image'
} finally {
  Remove-Item -Path $ifeo, $spe -Recurse -Force -EA SilentlyContinue
  Remove-Item -Path $dumpDir -Recurse -Force -EA SilentlyContinue
  Remove-Item $md -Recurse -Force -EA SilentlyContinue
}
# This step's own cleanup is CHECKED, not assumed: -EA
# SilentlyContinue hides a failed removal, and a leftover key would
# make every later run of this job start dirty.
foreach ($k in @($ifeo, $spe)) { if (Test-Path $k) { throw "this step did not clean up after itself: $k still exists" } }
if (Test-Path $dumpDir) { throw "this step did not clean up after itself: $dumpDir still exists" }
# The real LSASS keys must be untouched by this step.
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe') { throw 'this step must never create the SilentProcessExit key for the real lsass.exe' }
exit 0
