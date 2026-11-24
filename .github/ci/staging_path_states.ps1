# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It creates a scratch folder under TEMP and puts a deny-ListDirectory ACL on
# one subfolder; do not run it on a machine you use. It lives in .github/ so
# it never reaches a USB stick.
#
# Section 18d through the REAL staged block (tests\section18_gaps.ps1 -Mode Run
# renders it exactly as cmd writes it), on a list naming throwaway paths:
#   hit       a file that exists                           -> matched
#   absent    a file its folder answers without            -> nothing (an answer)
#   noparent  a file whose folder does not exist           -> nothing (an answer)
#   deniedhit a file that exists in a folder we may not list -> matched by name
#   denied    a file absent from a folder we may not list  -> named, raised gap
# The old block was Test-Path, which reads "access denied" as "not there", so
# the last case printed [OK] having looked at nothing.
$ErrorActionPreference = 'Stop'
$base = Join-Path $env:TEMP ("dz_ci_18d_{0}" -f $PID)
$lists = Join-Path $base 'lists'
$open = Join-Path $base 'open'
$shut = Join-Path $base 'shut'
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User
$rule = New-Object Security.AccessControl.FileSystemAccessRule($me, 'ListDirectory', 'Deny')
try {
  foreach ($d in $lists, $open, $shut) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
  Set-Content -LiteralPath (Join-Path $open 'dzci_hit.exe') -Value 'x' -Encoding ASCII
  Set-Content -LiteralPath (Join-Path $shut 'dzci_deniedhit.exe') -Value 'x' -Encoding ASCII
  $denied = $false
  try {
    $acl = Get-Acl -LiteralPath $shut; $acl.AddAccessRule($rule); Set-Acl -LiteralPath $shut -AclObject $acl
    try { $null = [IO.Directory]::GetFileSystemEntries($shut) } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  Set-Content -LiteralPath (Join-Path $lists 'ioc_file_paths.txt') -Encoding ASCII -Value @(
    '# CI list',
    (Join-Path $open 'dzci_hit.exe'),
    (Join-Path $open 'dzci_absent.exe'),
    (Join-Path $base 'nofolder\dzci_noparent.exe'),
    (Join-Path $shut 'dzci_deniedhit.exe'),
    (Join-Path $shut 'dzci_denied.exe')
  )
  $ErrorActionPreference = 'Continue'
  $o = (powershell -NoProfile -ExecutionPolicy Bypass -File tests\section18_gaps.ps1 -Mode Run -ListDir $lists -Sections '18d' 2>&1 | ForEach-Object { "$_" }) -join "`n"
  $ErrorActionPreference = 'Stop'
  Write-Host $o
  if ($o -notmatch [regex]::Escape((Join-Path $open 'dzci_hit.exe'))) { throw "18d did not print the file it matched: $o" }
  if ($o -match 'dzci_absent|dzci_noparent') { throw "18d named a path its folder answered without, or whose folder does not exist -- that is an answer, not a gap: $o" }
  if ($o -notmatch '(?m)^\[CRITICAL\] Known malware staging files found:$') { throw "18d did not raise the match: $o" }
  if ($denied) {
    if ($o -notmatch 'S18 18d hit=1 gap=0 done=1 unread=1') { throw "18d did not report the match AND the path it could not check (or did not reach its verdict): $o" }
    if ($o -notmatch [regex]::Escape((Join-Path $shut 'dzci_deniedhit.exe'))) { throw "18d did not find a file by name in a folder it may not list: $o" }
    if ($o -notmatch ('(?m)^\[WARNING\] Staging file IOC match NOT performed in full -- 1 of 5 path\(s\) could not be checked, .*' + [regex]::Escape((Join-Path $shut 'dzci_denied.exe')) + ' - UnauthorizedAccessException')) { throw "18d did not name the path in the folder it may not list: $o" }
    if ($o -match '(?m)^\[OK\]') { throw "18d printed [OK] beside a path it could not check: $o" }
    Write-Host 'Section 18d: a path in a folder that refuses to list is named and raised beside the match; a missing file or folder is an answer'
  } else {
    if ($o -notmatch 'S18 18d hit=1 gap=0 done=1 unread=0') { throw "18d did not report the match: $o" }
    Write-Host '[ SKIP ] denied-folder case not run: this account can still list the folder through the deny rule; the match and the absent cases still ran'
  }
  # The runner's own state, the shipped list: nothing a standard user or an
  # administrator cannot check. A clean runner must raise no gap.
  $ErrorActionPreference = 'Continue'
  $o2 = (powershell -NoProfile -ExecutionPolicy Bypass -File tests\section18_gaps.ps1 -Mode Run -Sections '18d' 2>&1 | ForEach-Object { "$_" }) -join "`n"
  $ErrorActionPreference = 'Stop'
  Write-Host $o2
  if ($o2 -notmatch 'S18 18d hit=0 gap=0 done=1 unread=0') { throw "18d on the shipped list raised a match or a gap on a clean runner: $o2" }
  if ($o2 -notmatch '(?m)^\[OK\] No known malware staging files found \(\d+ path\(s\) checked\)\.$') { throw "18d on the shipped list did not say how many paths it checked: $o2" }
} finally {
  $ErrorActionPreference = 'Continue'
  try { $acl = Get-Acl -LiteralPath $shut; [void]$acl.RemoveAccessRule($rule); Set-Acl -LiteralPath $shut -AclObject $acl } catch { Write-Host ("cleanup: could not reset the test folder's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -LiteralPath $base -Recurse -Force -EA SilentlyContinue
  if (Test-Path -LiteralPath $base) { throw "the CI test folder $base could not be removed" }
}
exit 0
