# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It plants a scratch folder with a deny-ListDirectory subfolder and a file
# held open with no sharing; do not run it on a machine you use. It lives in
# .github/ so it never reaches a USB stick.
#
# tools\ioc_hash_check.ps1 (18k) through its real walk, with -ScanDir pointed
# at the scratch folders:
#   a file whose SHA256 is on the list           -> the CRITICAL match
#   a file held open with FileShare.None         -> named, raised gap
#   a priority folder this account may not list -> named, raised gap
# It used to skip both silently and print "[OK] ... no matches".
$ErrorActionPreference = 'Stop'
$st = (.\tools\ioc_hash_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'ioc_hash_check -SelfTest failed' }
$base = Join-Path $env:TEMP ("dz_ci_18k_{0}" -f $PID)
$open = Join-Path $base 'open'; $shut = Join-Path $base 'shut'
$gm = Join-Path $env:TEMP 'dz_iochit_18k_gap.txt'; $hm = Join-Path $env:TEMP 'dz_iochit_18k.txt'
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User
$rule = New-Object Security.AccessControl.FileSystemAccessRule($me, 'ListDirectory', 'Deny')
$fs = $null
try {
  New-Item -ItemType Directory -Path $open, $shut -Force | Out-Null
  $bad = Join-Path $open 'dzci_known_bad.exe'
  Set-Content -LiteralPath $bad -Value ('dz ci known bad ' + $PID) -Encoding ASCII
  $h = (Get-FileHash -LiteralPath $bad -Algorithm SHA256).Hash.ToLower()
  $list = Join-Path $base 'hashes.txt'
  Set-Content -LiteralPath $list -Value @('# CI list', ($h + '|DzCiFamily|CI')) -Encoding ASCII
  Remove-Item $gm, $hm -Force -EA SilentlyContinue
  $o = (.\tools\ioc_hash_check.ps1 -IocFile $list -ScanDir $open) -join "`n"
  Write-Host $o
  if ($o -notmatch [regex]::Escape($bad) -or -not (Test-Path $hm)) { throw 'a file on the list was not the CRITICAL match' }
  if (Test-Path $gm) { throw "a clean walk raised a gap: $o" }
  # A file held open with no sharing cannot be hashed.
  $locked = Join-Path $open 'dzci_locked.dll'
  Set-Content -LiteralPath $locked -Value 'x' -Encoding ASCII
  $fs = [IO.File]::Open($locked, 'Open', 'Read', 'None')
  $denied = $false
  try { $a = Get-Acl -LiteralPath $shut; $a.AddAccessRule($rule); Set-Acl -LiteralPath $shut -AclObject $a; try { $null = [IO.Directory]::GetFileSystemEntries($shut) } catch { $denied = $true } } catch { Write-Host "[ SKIP ] deny ACL could not be set: $($_.Exception.Message)" }
  Remove-Item $gm, $hm -Force -EA SilentlyContinue
  $o = (.\tools\ioc_hash_check.ps1 -IocFile $list -ScanDir $open, $shut) -join "`n"
  Write-Host $o
  if (-not (Test-Path $gm)) { throw "a file that could not be hashed (or a folder that refused to list) wrote no gap marker: $o" }
  if ($o -notmatch ('(?m)^\[WARNING\] File hash IOC match NOT performed in full -- .*could not be hashed: .*' + [regex]::Escape($locked))) { throw "the locked file was not named: $o" }
  if ($denied -and $o -notmatch ('could not be listed: ' + [regex]::Escape($shut))) { throw "the folder that refused to list was not named: $o" }
  if (-not (Test-Path $hm)) { throw 'the match beside the gap was lost: a hit and a gap are both raised' }
  Write-Host '18k: a locked file and a folder that refuses to list are named and raised beside the match'
} finally {
  $ErrorActionPreference = 'Continue'
  if ($fs) { $fs.Dispose() }
  try { $a = Get-Acl -LiteralPath $shut; [void]$a.RemoveAccessRule($rule); Set-Acl -LiteralPath $shut -AclObject $a } catch {}
  Remove-Item -LiteralPath $base -Recurse -Force -EA SilentlyContinue
  Remove-Item $gm, $hm -Force -EA SilentlyContinue
  if (Test-Path -LiteralPath $base) { throw "cleanup failed: $base remains" }
}
exit 0
