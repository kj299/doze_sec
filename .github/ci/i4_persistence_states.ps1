# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It creates scratch folders and throwaway HKCU keys, some with a deny ACL;
# do not run it on a machine you use. It lives in .github/ so it never
# reaches a USB stick.
#
# Group I4a through the real readers on Windows PowerShell 5.1, pointed at
# planted folders and keys by the tools' CI-only hooks:
#   persistence_extra -- an ISE profile with an encoded command is graded (it
#     was never read); a profile folder this account may not open is a gap,
#     never "No PowerShell profile scripts present"; a Print\Monitors or
#     TimeProviders stand-in that is missing or denied is a gap, never
#     "All 0 registered ... [OK]".
#   startup_eval -- a Startup folder this account may not open is a gap,
#     never "Startup folder not present"; a missing AppCertDlls key is still
#     stock Windows ([OK]).
#   The runner's own run of both raises no gap.
$ErrorActionPreference = 'Stop'
foreach ($t in 'persistence_extra', 'startup_eval', 'persistence_eval') {
  $o = (& ".\tools\$t.ps1" -SelfTest) -join "`n"
  if ($LASTEXITCODE -ne 0) { Write-Host $o; throw "$t -SelfTest failed" }
}
$scr = Join-Path $env:TEMP ("dz_ci_i4_{0}" -f $PID)
$md = Join-Path $scr 'm'
$sub = "Software\dz_ci_i4_$PID"; $hk = "HKCU:\$sub"
$deniedDirs = @(); $deniedKeys = @()
New-Item -ItemType Directory -Path $md -Force | Out-Null
function Clear-M { Get-ChildItem -LiteralPath $md -Filter 'dz_*' -EA SilentlyContinue | Remove-Item -Force }
function Has([string]$n) { Test-Path (Join-Path $md "dz_$n.txt") }
function Deny-Dir([string]$Dir) {
  $di = New-Object IO.DirectoryInfo $Dir; $a = $di.GetAccessControl('Access'); $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, 'ListDirectory, ReadData, ReadAttributes, ReadExtendedAttributes', 'ContainerInherit, ObjectInherit', 'None', 'Deny')))
  $script:deniedDirs += $Dir; $di.SetAccessControl($a)
}
function Deny-Key([string]$Rel) {
  $a = Get-Acl -Path "HKCU:\$Rel"; $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $a.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'ReadKey', 'Deny')))
  $script:deniedKeys += $Rel; Set-Acl -Path "HKCU:\$Rel" -AclObject $a
}
try {
  # ---- PowerShell profiles ----
  $pdir = Join-Path $scr 'Documents\WindowsPowerShell'
  New-Item -ItemType Directory -Path $pdir -Force | Out-Null
  $ise = Join-Path $pdir 'Microsoft.PowerShellISE_profile.ps1'
  Set-Content -LiteralPath $ise -Value 'powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAA' -Encoding ASCII
  Clear-M
  $o = (& .\tools\persistence_extra.ps1 -MarkerDir $md -CiProfilePaths @($ise, (Join-Path $pdir 'profile.ps1'))) -join "`n"
  if ($o -notmatch '\[CRITICAL\] PowerShell profile .*Microsoft\.PowerShellISE_profile\.ps1') { Write-Host $o; throw 'an ISE host profile with an encoded command was not graded (it was never read before)' }
  $ddir = Join-Path $scr 'Denied\WindowsPowerShell'
  New-Item -ItemType Directory -Path $ddir -Force | Out-Null
  Set-Content -LiteralPath (Join-Path $ddir 'profile.ps1') -Value 'Get-Date' -Encoding ASCII
  Deny-Dir $ddir
  Clear-M
  $o = (& .\tools\persistence_extra.ps1 -MarkerDir $md -CiProfilePaths @((Join-Path $ddir 'profile.ps1'))) -join "`n"
  if (-not (Has 'psprofile_gap') -or $o -match 'No PowerShell profile scripts present') { Write-Host $o; throw 'a profile folder this account may not open was not a raised gap' }

  # ---- keys Windows always has ----
  Clear-M
  $o = (& .\tools\persistence_extra.ps1 -MarkerDir $md -CiMonitorRoot "$hk\Monitors" -CiTimeProvRoot "$hk\TimeProviders" -CiNetshKey "$hk\Netsh") -join "`n"
  foreach ($n in 'portmon_gap', 'timeprov_gap', 'netsh_gap') { if (-not (Has $n)) { Write-Host $o; throw "a missing always-there key did not raise $n" } }
  if ($o -match 'All 0 registered port monitor|All 0 registered time provider|No netsh helper DLLs registered') { Write-Host $o; throw 'a missing always-there key read as an empty [OK] (the defect)' }
  New-Item -Path "$hk\Monitors\Standard TCP-IP Port" -Force | Out-Null
  Deny-Key "$sub\Monitors"
  Clear-M
  $o = (& .\tools\persistence_extra.ps1 -MarkerDir $md -CiMonitorRoot "$hk\Monitors") -join "`n"
  if (-not (Has 'portmon_gap') -or $o -match 'All 0 registered port monitor') { Write-Host $o; throw 'a Monitors key this account may not read was not a raised gap' }

  # ---- Startup folder and AppCertDlls ----
  # The deny goes on the PARENT: Windows answers a folder's own attributes
  # from its parent's listing, so a deny on the folder itself is caught by
  # the later enumeration, not by the absence test this case is about.
  $sp = Join-Path $scr 'SP'
  $sdir = Join-Path $sp 'Startup'
  New-Item -ItemType Directory -Path $sdir -Force | Out-Null
  Deny-Dir $sp
  Clear-M
  $o = (& .\tools\startup_eval.ps1 -MarkerDir $md -CiStartupFolders @($sdir) -CiAppCertKey "$hk\AppCertDlls") -join "`n"
  if (-not (Has 'startup_folder_gap') -or $o -match 'Startup folder not present' -or $o -notmatch 'Startup folder check NOT performed') { Write-Host $o; throw 'a Startup folder under a parent this account may not list was not the raised gap (Test-Path read it as not present)' }
  if ((Has 'appcert_gap') -or $o -notmatch 'AppCertDlls not present or empty') { Write-Host $o; throw 'a missing AppCertDlls key (stock Windows) was not the [OK]' }

  # ---- the runner itself ----
  Clear-M
  $o = (& .\tools\persistence_extra.ps1 -MarkerDir $md) -join "`n"
  foreach ($n in 'psprofile_gap', 'portmon_gap', 'timeprov_gap', 'netsh_gap') { if (Has $n) { Write-Host $o; throw "the runner's own run raised $n" } }
  Clear-M
  $o = (& .\tools\startup_eval.ps1 -MarkerDir $md) -join "`n"
  foreach ($n in 'startup_folder_gap', 'appcert_gap') { if (Has $n) { Write-Host $o; throw "the runner's own run raised $n" } }
  Write-Host '[OK] I4a: an ISE profile is graded; a denied profile folder, Startup folder or Monitors key and a missing always-there key are raised gaps; a missing AppCertDlls key stays stock; the runner raised none.'
} finally {
  foreach ($d in $deniedDirs) {
    try {
      $di = New-Object IO.DirectoryInfo $d; $a = $di.GetAccessControl('Access')
      foreach ($r in @($a.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Deny' })) { [void]$a.RemoveAccessRuleSpecific($r) }
      $di.SetAccessControl($a)
    } catch { Write-Host "undeny failed for ${d}: $($_.Exception.Message) -- resetting with icacls"; & icacls.exe $d /reset /T /C /Q | Out-Null }
  }
  foreach ($rel in $deniedKeys) {
    try {
      $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($rel, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]'ReadPermissions, ChangePermissions')
      $a = $k.GetAccessControl()
      foreach ($r in @($a.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Deny' })) { [void]$a.RemoveAccessRuleSpecific($r) }
      $k.SetAccessControl($a); $k.Close()
    } catch { Write-Host "registry undeny failed for ${rel}: $($_.Exception.Message)" }
  }
  Remove-Item -LiteralPath $hk -Recurse -Force -EA SilentlyContinue
  Remove-Item -LiteralPath $scr -Recurse -Force -EA SilentlyContinue
  if (Test-Path -LiteralPath $hk) { throw "cleanup failed: $hk remains" }
  if (Test-Path -LiteralPath $scr) { throw "cleanup failed: $scr remains" }
}
