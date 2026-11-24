# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It plants a scratch folder (one subfolder with a deny-ListDirectory ACE) and
# a scratch HKCU key; do not run it on a machine you use. It lives in .github/
# so it never reaches a USB stick.
#
# The -updateTTP pipeline end to end: tools\ttp_merge.ps1 writes blocks from a
# small feed, cmd runs the generated file the way Section 18 does, and every
# block's verdict is checked in the report and in the ledger rows it leaves:
#   planted file              -> CRITICAL row, "[CRITICAL] ... IOC found"
#   missing file              -> "[OK] ... check clear.", no row
#   file in a folder we may not list -> a WARNING gap row, never "clear"
#   planted HKCU key          -> WARNING row
#   invalid WMI query         -> a WARNING gap row (it used to read "clear")
#   a pipe that does not exist -> "[OK] ... check clear."
$ErrorActionPreference = 'Stop'
foreach ($t in 'ttp_detect', 'ttp_merge') {
  $st = (& ".\tools\$t.ps1" -SelfTest) -join "`n"
  if ($LASTEXITCODE -ne 0) { Write-Host $st; throw "$t -SelfTest failed" }
}
$base = Join-Path $env:TEMP ("dz_ci_ttp_{0}" -f $PID)
$shut = Join-Path $base 'shut'
$keySub = "Software\dz_ci_ttp_$PID"
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User
$rule = New-Object Security.AccessControl.FileSystemAccessRule($me, 'ListDirectory', 'Deny')
try {
  New-Item -ItemType Directory -Path $base, $shut, (Join-Path $base 'lists') -Force | Out-Null
  $hitFile = Join-Path $base 'dzci_ttp_hit.dll'
  Set-Content -LiteralPath $hitFile -Value 'x' -Encoding ASCII
  New-Item -Path "HKCU:\$keySub" -Force | Out-Null
  Set-ItemProperty -Path "HKCU:\$keySub" -Name 'DzCi' -Value 'x'
  $denied = $false
  try { $a = Get-Acl -LiteralPath $shut; $a.AddAccessRule($rule); Set-Acl -LiteralPath $shut -AclObject $a; try { $null = [IO.Directory]::GetFileSystemEntries($shut) } catch { $denied = $true } } catch { Write-Host "[ SKIP ] deny ACL could not be set: $($_.Exception.Message)" }
  $feed = Join-Path $base 'feed.txt'
  Set-Content -LiteralPath $feed -Encoding ASCII -Value @(
    "T1055|DzHit|file path|$hitFile|CRITICAL|CI",
    "T1055|DzMissing|file path|$(Join-Path $base 'dzci_absent.dll')|CRITICAL|CI",
    "T1074|DzDenied|file path|$(Join-Path $shut 'dzci_absent.dll')|WARNING|CI",
    "T1112|DzKey|registry key|HKCU\$keySub|WARNING|CI",
    "T1047|DzWmi|wmi query|SELECT * FROM Dz_No_Such_Class_$PID|WARNING|CI",
    "T1071|DzPipe|named pipe|dzci_no_such_pipe_$PID|WARNING|CI")
  $blocks = Join-Path $base 'ttp_generated_checks.bat'
  Set-Content -LiteralPath $blocks -Encoding ASCII -Value '@echo off'
  $mo = (& .\tools\ttp_merge.ps1 -TtpOutput $feed -BlocksFile $blocks -ThreatListsDir (Join-Path $base 'lists')) -join "`n"
  Write-Host $mo
  if ($mo -notmatch '6 detection block\(s\) written') { throw "ttp_merge did not write the six blocks: $mo" }
  $gen = Get-Content -LiteralPath $blocks -Raw
  if ($gen -match 'check clear|SilentlyContinue') { throw 'a generated block still carries the old all-clear shape' }
  # Run it as Section 18 does: the bat's own variables, and `call`.
  $report = Join-Path $base 'report.txt'; $rows = Join-Path $env:TEMP 'dz_ttpauto_rows.txt'
  Remove-Item -LiteralPath $rows -Force -EA SilentlyContinue
  $cmdf = Join-Path $base 'run.cmd'
  $pwsh = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
  Set-Content -LiteralPath $cmdf -Encoding ASCII -Value @(
    '@echo off', 'setlocal enabledelayedexpansion',
    ('set "REPORT={0}"' -f $report), ('set "PWSH={0}"' -f $pwsh), ('set "SCRIPT_DIR={0}\"' -f (Resolve-Path .).Path),
    ('call "{0}"' -f $blocks))
  $ErrorActionPreference = 'Continue'
  & cmd.exe /c $cmdf | Out-Null
  $ErrorActionPreference = 'Stop'
  $rep = Get-Content -LiteralPath $report -Raw
  $rw = @(Get-Content -LiteralPath $rows -EA SilentlyContinue)
  Write-Host $rep; Write-Host ('ROWS:' + "`n" + ($rw -join "`n"))
  if ($rep -notmatch '(?m)^\[CRITICAL\] DzHit IOC found: ' -or -not @($rw | Where-Object { $_ -like 'CRITICAL|T1055|DzHit*' }).Count) { throw 'the planted file was not a raised CRITICAL' }
  if ($rep -notmatch '(?m)^\[OK\] DzMissing check clear\.\r?$' -or @($rw | Where-Object { $_ -match 'DzMissing' }).Count) { throw 'a missing file was not a clean [OK] with no row' }
  if ($rep -notmatch '(?m)^\[WARNING\] DzKey IOC found: ' -or -not @($rw | Where-Object { $_ -like 'WARNING|T1112|DzKey*' }).Count) { throw 'the planted key was not a raised WARNING' }
  if ($rep -notmatch '(?m)^\[WARNING\] DzWmi check NOT performed -- ' -or $rep -match 'DzWmi check clear' -or -not @($rw | Where-Object { $_ -like 'WARNING|T1047|DzWmi check NOT performed*' }).Count) { throw 'an invalid WMI query was not a raised gap (the old block read "check clear")' }
  if ($rep -notmatch '(?m)^\[OK\] DzPipe check clear\.\r?$') { throw 'a pipe that does not exist was not [OK]' }
  if ($denied) {
    if ($rep -notmatch '(?m)^\[WARNING\] DzDenied check NOT performed -- .* could not be listed' -or $rep -match 'DzDenied check clear' -or -not @($rw | Where-Object { $_ -like 'WARNING|T1074|DzDenied check NOT performed*' }).Count) { throw 'a folder that refused to list was not a raised gap' }
  } else { Write-Host '[ SKIP ] denied-folder case: this account can still list the folder through the deny rule' }
  Write-Host 'CTI-AUTO blocks: hits and gaps reach the ledger rows; nothing there is [OK]; a query that failed is never "check clear"'
} finally {
  $ErrorActionPreference = 'Continue'
  try { $a = Get-Acl -LiteralPath $shut; [void]$a.RemoveAccessRule($rule); Set-Acl -LiteralPath $shut -AclObject $a } catch {}
  Remove-Item -LiteralPath $base -Recurse -Force -EA SilentlyContinue
  Remove-Item -Path "HKCU:\$keySub" -Recurse -Force -EA SilentlyContinue
  Remove-Item -LiteralPath (Join-Path $env:TEMP 'dz_ttpauto_rows.txt') -Force -EA SilentlyContinue
  if ((Test-Path -LiteralPath $base) -or (Test-Path "HKCU:\$keySub")) { throw 'cleanup failed: a CI test folder or key remains' }
}
exit 0
