# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It creates throwaway HKCU keys, one with a deny ACL; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick.
# Nothing here writes the real Session Manager or Active Setup keys: a
# BootExecute entry runs at the next boot.
#
# Group I4b through the real reader on Windows PowerShell 5.1, pointed at
# planted keys by the tool's CI-only hooks:
#   - the runner's own BootExecute and Active Setup are graded, logged, and
#     raise no finding and no gap (Windows' own entries are the benign set);
#   - a BootExecute entry beside autochk is raised; a StubPath in
#     C:\Users\Public is raised CRITICAL; a rundll32 StubPath loading a
#     Microsoft-signed System32 DLL stays [OK] (real Authenticode, catalog-
#     signed file);
#   - a component key this account may not read, and a Session Manager stand-in
#     that is not there, are raised gaps, never an all-clear.
$ErrorActionPreference = 'Stop'
$o = (& .\tools\boot_activesetup_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $o; throw 'boot_activesetup_check -SelfTest failed' }
$scr = Join-Path $env:TEMP ("dz_ci_i4b_{0}" -f $PID)
$md = Join-Path $scr 'm'
$sub = "Software\dz_ci_i4b_$PID"; $hk = "HKCU:\$sub"
$deniedKeys = @()
New-Item -ItemType Directory -Path $md -Force | Out-Null
function Clear-M { Get-ChildItem -LiteralPath $md -Filter 'dz_*' -EA SilentlyContinue | Remove-Item -Force }
function Has([string]$n) { Test-Path (Join-Path $md "dz_$n.txt") }
function Sev([string]$n) { (Get-Content -LiteralPath (Join-Path $md "dz_$n.txt") -TotalCount 1).Trim() }
function Deny-Key([string]$Rel) {
  $a = Get-Acl -Path "HKCU:\$Rel"; $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $a.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'ReadKey', 'Deny')))
  $script:deniedKeys += $Rel; Set-Acl -Path "HKCU:\$Rel" -AclObject $a
}
try {
  # ---- the runner itself ----
  Clear-M
  $o = (& .\tools\boot_activesetup_check.ps1 -MarkerDir $md) -join "`n"
  Write-Host '---- the runner''s own BootExecute and Active Setup, as graded ----'
  Write-Host $o
  foreach ($n in 'bootexec', 'bootexec_gap', 'activesetup', 'activesetup_gap') { if (Has $n) { throw "the runner's own run raised $n ($(Sev $n)) -- a benign Windows entry graded as a finding, or a read that failed" } }
  if (-not (Has 'bootas_done')) { throw 'the runner run wrote no done marker' }
  # Any stock autochk form (the runner's own is 'autocheck autochk /q /v *'),
  # and the all-clear having graded at least one entry -- never an exact value.
  if ($o -notmatch "(?m)^\[OK\] BootExecute: autocheck autochk\b[^\r\n]*\(Windows' boot-time disk check, the stock entry\)\r?$" -or
      $o -notmatch "(?m)^\[OK\] BootExecute and its sibling values hold only Windows' own entries \([1-9]\d* graded\)\.") {
    Write-Host (($o -split "`r?`n" | Where-Object { $_ -match 'BootExecute' }) -join "`n")
    throw "the runner's BootExecute was not read as Windows' own autochk entry"
  }
  if ($o -notmatch '(?m)^\[OK\] Active Setup: ([1-9]\d*) StubPath command\(s\) graded, none suspicious\.') { throw "the runner's Active Setup StubPaths were not graded (none read: the check looked at nothing)" }

  # ---- planted Session Manager stand-in ----
  New-Item -Path "$hk\SM" -Force | Out-Null
  New-ItemProperty -Path "$hk\SM" -Name BootExecute -PropertyType MultiString -Value @('autocheck autochk *', 'autocheck dz_ci_native') -Force | Out-Null
  New-Item -Path "$hk\AS\{dz-ok}" -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\{dz-ok}" -Name StubPath -PropertyType String -Value ('"' + $env:SystemRoot + '\System32\rundll32.exe" "' + $env:SystemRoot + '\System32\shell32.dll",Control_RunDLL') -Force | Out-Null
  Clear-M
  $o = (& .\tools\boot_activesetup_check.ps1 -MarkerDir $md -CiSessionKey "$hk\SM" -CiActiveSetupRoots @("$hk\AS")) -join "`n"
  if (-not (Has 'bootexec') -or $o -notmatch "(?m)^\[WARNING\] BootExecute entry 'autocheck dz_ci_native' names .*dz_ci_native\.exe, which is not on disk") { Write-Host $o; throw 'a BootExecute entry beside autochk was not raised' }
  if ((Has 'activesetup') -or $o -notmatch "(?m)^\[OK\] Active Setup '\{dz-ok\}': .*\\shell32\.dll \(signed by Microsoft") { Write-Host $o; throw 'a rundll32 StubPath loading a Microsoft-signed System32 DLL was not the [OK] (the benign twin, real Authenticode)' }

  New-Item -Path "$hk\AS\{dz-evil}" -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\{dz-evil}" -Name StubPath -PropertyType String -Value 'C:\Users\Public\dz_ci_evil.exe /s' -Force | Out-Null
  Clear-M
  $o = (& .\tools\boot_activesetup_check.ps1 -MarkerDir $md -CiSessionKey "$hk\SM" -CiActiveSetupRoots @("$hk\AS")) -join "`n"
  if (-not (Has 'activesetup') -or (Sev 'activesetup') -ne 'CRITICAL' -or $o -notmatch "(?m)^\[CRITICAL\] Active Setup '\{dz-evil\}' StubPath runs C:\\Users\\Public\\dz_ci_evil\.exe from a staging path") { Write-Host $o; throw 'a StubPath in C:\Users\Public was not raised CRITICAL' }

  # ---- gaps ----
  New-Item -Path "$hk\AS\{dz-deny}" -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\{dz-deny}" -Name StubPath -PropertyType String -Value 'C:\Users\Public\hidden.exe' -Force | Out-Null
  Deny-Key "$sub\AS\{dz-deny}"
  Clear-M
  $o = (& .\tools\boot_activesetup_check.ps1 -MarkerDir $md -CiSessionKey "$hk\NoSuchSM" -CiActiveSetupRoots @("$hk\AS")) -join "`n"
  if (-not (Has 'activesetup_gap') -or $o -notmatch 'Active Setup check NOT performed for 1 component\(s\) under .* that could not be read: \{dz-deny\}') { Write-Host $o; throw 'a component key this account may not read was not a raised gap naming it' }
  if (-not (Has 'bootexec_gap') -or $o -match "(?m)^\[OK\] BootExecute and its sibling") { Write-Host $o; throw 'a Session Manager key that is not there was not a raised gap' }
  if (-not (Has 'bootas_done')) { throw 'the gap run wrote no done marker' }
  Write-Host '[OK] I4b: the runner''s BootExecute and Active Setup read clean; a planted BootExecute entry and a staged StubPath are raised; a signed System32 DLL stays OK; a denied component and a missing Session Manager key are raised gaps.'
} finally {
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
