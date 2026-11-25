# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It creates scratch folders (one with a deny ACL) and a throwaway HKCU
# policy key (one with a deny ACL); do not run it on a machine you use. It
# lives in .github/ so it never reaches a USB stick.
#
# tools\browser_extensions.ps1 through its real reader, pointed at planted
# profiles and a throwaway policy root by its CI hooks:
#   a sideloaded extension with nativeMessaging + <all_urls> -> the WARNING hit
#   a corrupt Preferences                                    -> a raised gap, never [SKIPPED]
#   a User Data folder this account may not list             -> a raised gap
#   a force-install policy value                             -> a WARNING
#   the same policy key with QueryValues denied              -> a raised gap
#   the runner's own profiles and policies                   -> no gap, a done marker
$ErrorActionPreference = 'Stop'
$o = (& .\tools\browser_extensions.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $o; throw 'browser_extensions -SelfTest failed' }
$scr = Join-Path $env:TEMP ("dz_ci_i3_{0}" -f $PID)
$md = Join-Path $scr 'm'; $la = Join-Path $scr 'la'; $ad = Join-Path $scr 'ad'
$sub = "Software\dz_ci_i3_$PID"; $hk = "HKCU:\$sub"
$deniedDirs = @(); $deniedKey = $false
New-Item -ItemType Directory -Path $md, $ad -Force | Out-Null
function Run-BE([string[]]$Pol = @($scr)) {
  Get-ChildItem -LiteralPath $md -Filter 'dz_*' -EA SilentlyContinue | Remove-Item -Force
  $out = (& .\tools\browser_extensions.ps1 -MarkerDir $md -LocalAppData $la -AppData $ad -PolicyRoots $Pol) -join "`n"
  Write-Host $out
  return @{ Out = $out; Hit = (Test-Path (Join-Path $md 'dz_browserext_hit.txt')); Gap = (Test-Path (Join-Path $md 'dz_browserext_gap.txt')); Done = (Test-Path (Join-Path $md 'dz_browserext_done.txt')) }
}
try {
  $ud = Join-Path $la 'Google\Chrome\User Data'
  New-Item -ItemType Directory -Path (Join-Path $ud 'Default'), (Join-Path $ud 'Profile 1') -Force | Out-Null
  Set-Content -LiteralPath (Join-Path $ud 'Default\Preferences') -Encoding ASCII -Value '{"extensions":{"settings":{"abcdefghijklmnopabcdefghijklmnop":{"location":4,"from_webstore":false,"manifest":{"name":"Helper","version":"1.0","permissions":["nativeMessaging","<all_urls>"]}}}}}'
  $r = Run-BE
  if (-not $r.Hit -or $r.Gap -or -not $r.Done) { throw 'a sideloaded extension with nativeMessaging was not the hit, or a gap was raised' }
  Set-Content -LiteralPath (Join-Path $ud 'Profile 1\Preferences') -Encoding ASCII -Value '{not json'
  $r = Run-BE
  if (-not $r.Gap -or $r.Out -match '\[SKIPPED\]' -or $r.Out -notmatch 'NOT performed for Chrome/Profile 1') { throw 'a corrupt Preferences was not a raised gap' }
  Remove-Item -LiteralPath (Join-Path $ud 'Profile 1') -Recurse -Force

  # A User Data folder this account may not list.
  $di = New-Object IO.DirectoryInfo $ud
  $acl = $di.GetAccessControl('Access'); $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, 'ListDirectory, ReadData', 'None', 'None', 'Deny')))
  $deniedDirs += $ud; $di.SetAccessControl($acl)
  $r = Run-BE
  if (-not $r.Gap -or $r.Out -notmatch 'NOT performed for Chrome') { throw 'a User Data folder this account may not list was not a raised gap' }
  if ($r.Out -match 'No browser profiles with extensions found') { throw '"No browser profiles" was printed over a folder that could not be read (the defect)' }

  # A force-install policy value, then the key denied.
  New-Item -Path "$hk\Google\Chrome\ExtensionInstallForcelist" -Force | Out-Null
  Set-ItemProperty -Path "$hk\Google\Chrome\ExtensionInstallForcelist" -Name '1' -Value 'abcdefghijklmnopabcdefghijklmnop;https://example.invalid/crx'
  $r = Run-BE @($hk)
  if ($r.Out -notmatch '\[WARNING\] Policy force-install .*example\.invalid') { throw 'a force-install policy value was not the WARNING' }
  $kacl = Get-Acl -Path "$hk\Google\Chrome\ExtensionInstallForcelist"
  $kacl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues', 'Deny')))
  Set-Acl -Path "$hk\Google\Chrome\ExtensionInstallForcelist" -AclObject $kacl; $deniedKey = $true
  $r = Run-BE @($hk)
  if (-not $r.Gap -or $r.Out -notmatch 'NOT performed for force-install policy') { throw 'a force-install key this account may not read was not a raised gap' }

  # The runner itself.
  Get-ChildItem -LiteralPath $md -Filter 'dz_*' -EA SilentlyContinue | Remove-Item -Force
  $o = (& .\tools\browser_extensions.ps1 -MarkerDir $md) -join "`n"; Write-Host $o
  if ((Test-Path (Join-Path $md 'dz_browserext_gap.txt')) -or -not (Test-Path (Join-Path $md 'dz_browserext_done.txt'))) { throw "the runner's own browser profiles or policies raised a gap" }
  Write-Host '[OK] I3: a sideloaded extension is the hit; a corrupt profile, a denied User Data folder and a denied policy key are raised gaps; the runner raised none.'
} finally {
  foreach ($d in $deniedDirs) {
    try {
      $di = New-Object IO.DirectoryInfo $d; $a = $di.GetAccessControl('Access')
      foreach ($rule in @($a.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Deny' })) { [void]$a.RemoveAccessRuleSpecific($rule) }
      $di.SetAccessControl($a)
    } catch { Write-Host "undeny failed for ${d}: $($_.Exception.Message) -- resetting with icacls"; & icacls.exe $d /reset /T /C /Q | Out-Null }
  }
  if ($deniedKey) {
    # Through .NET with only the rights an owner always holds (#303's lesson).
    try {
      $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$sub\Google\Chrome\ExtensionInstallForcelist", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]'ReadPermissions, ChangePermissions')
      $a = $k.GetAccessControl()
      foreach ($rule in @($a.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Deny' })) { [void]$a.RemoveAccessRuleSpecific($rule) }
      $k.SetAccessControl($a); $k.Close()
    } catch { Write-Host "registry undeny failed: $($_.Exception.Message)" }
  }
  Remove-Item -LiteralPath $hk -Recurse -Force -EA SilentlyContinue
  Remove-Item -LiteralPath $scr -Recurse -Force -EA SilentlyContinue
  if (Test-Path -LiteralPath $hk) { throw "cleanup failed: $hk remains" }
  if (Test-Path -LiteralPath $scr) { throw "cleanup failed: $scr remains" }
}
