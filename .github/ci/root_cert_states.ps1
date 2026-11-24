# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It creates scratch HKCU keys (one with a deny ACL); do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick.
#
# tools\root_cert_check.ps1 through its real reader (-StoreRoot points it at
# the scratch keys, laid out like a certificate store: one subkey per
# thumbprint):
#   one key written now              -> the WARNING finding
#   six keys written together now    -> [INFO], the update/image-build shape
#   a store this account may not read -> a raised gap
# Then the runner's own stores: no gap, and what it found is MEASURED.
$ErrorActionPreference = 'Stop'
$st = (.\tools\root_cert_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'root_cert_check -SelfTest failed' }
$sub = "Software\dz_ci_rc_$PID"; $root = "HKCU:\$sub"
$md = Join-Path $env:TEMP ("dz_ci_rc_{0}" -f $PID)
function RunRC([string[]]$Roots) {
  New-Item -ItemType Directory -Path $md -Force | Out-Null
  Get-ChildItem -LiteralPath $md -Filter 'dz_rootcert_*' -EA SilentlyContinue | Remove-Item -Force
  $o = (& .\tools\root_cert_check.ps1 -MarkerDir $md -StoreRoot $Roots) -join "`n"; Write-Host $o
  return @{ Out = $o; Hit = (Test-Path (Join-Path $md 'dz_rootcert_hit.txt')); Gap = (Test-Path (Join-Path $md 'dz_rootcert_gap.txt')); Done = (Test-Path (Join-Path $md 'dz_rootcert_done.txt')) }
}
try {
  New-Item -Path "$root\One\AAAA000000000000000000000000000000000001" -Force | Out-Null
  1..6 | ForEach-Object { New-Item -Path ("$root\Batch\BBBB00000000000000000000000000000000000{0}" -f $_) -Force | Out-Null }
  $r = RunRC @("$root\One")
  if (-not $r.Hit -or $r.Gap -or $r.Out -notmatch 'AAAA000000000000000000000000000000000001') { throw 'a root key written now was not the finding' }
  $r = RunRC @("$root\Batch")
  if ($r.Hit -or $r.Out -notmatch '(?m)^\[INFO\] 6 root certificate\(s\) were written together') { throw 'six roots written together were not the [INFO] batch' }
  New-Item -Path "$root\Shut\CCCC000000000000000000000000000000000001" -Force | Out-Null
  $denied = $false
  try {
    $acl = Get-Acl -Path "$root\Shut"; $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'EnumerateSubKeys', 'Deny'))); Set-Acl -Path "$root\Shut" -AclObject $acl
    try { $null = @(Get-ChildItem -LiteralPath "$root\Shut" -ErrorAction Stop) } catch { $denied = $true }
  } catch { Write-Host "[ SKIP ] deny ACL could not be set: $($_.Exception.Message)" }
  if ($denied) {
    $r = RunRC @("$root\Shut")
    if (-not $r.Gap -or $r.Out -notmatch 'Root certificate check NOT performed in full') { throw 'a store this account may not read was not a raised gap' }
    if ($r.Out -match '(?m)^\[OK\] No root certificate installed in the last 90 days \(') { throw 'the full [OK] was printed over a store that could not be read' }
  } else { Write-Host '[ SKIP ] denied-store case not run' }
  # The runner's own stores.
  New-Item -ItemType Directory -Path $md -Force | Out-Null
  Get-ChildItem -LiteralPath $md -Filter 'dz_rootcert_*' -EA SilentlyContinue | Remove-Item -Force
  $o = (& .\tools\root_cert_check.ps1 -MarkerDir $md) -join "`n"; Write-Host $o
  if (Test-Path (Join-Path $md 'dz_rootcert_gap.txt')) { throw "the runner's own certificate stores raised a gap: $o" }
  Write-Host ("MEASURED: the runner's own stores: " + $(if (Test-Path (Join-Path $md 'dz_rootcert_hit.txt')) { 'a recent root was reported' } else { 'no recent root reported' }))
} finally {
  $ErrorActionPreference = 'Continue'
  try {
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$sub\Shut", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]'ReadPermissions, ChangePermissions')
    if ($k) { $a = $k.GetAccessControl(); foreach ($rule in @($a.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Deny' })) { [void]$a.RemoveAccessRuleSpecific($rule) }; $k.SetAccessControl($a); $k.Close() }
  } catch {}
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  Remove-Item -LiteralPath $md -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "cleanup failed: $root remains" }
}
exit 0
