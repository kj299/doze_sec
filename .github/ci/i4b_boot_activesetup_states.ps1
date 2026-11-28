# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It creates throwaway HKCU keys (one with a deny ACL) and a scratch folder
# under C:\ProgramData holding unsigned files; do not run it on a machine you
# use. It lives in .github/ so it never reaches a USB stick.
# Nothing here writes the real Session Manager or Active Setup keys: a
# BootExecute entry runs at the next boot.
#
# Group I4b through the real reader on Windows PowerShell 5.1 -- real disk,
# real Authenticode -- pointed at planted keys by the tool's CI-only hooks:
#   - the runner's own BootExecute and Active Setup are graded, logged with
#     their raw commands, and raise no finding and no gap;
#   - benign twins stay [OK]: rundll32 with a signed System32 DLL, ie4uinit,
#     the same behind `cmd /D /C start`, msiexec repairing by product code;
#   - hostile lines are raised: a host behind `cmd /D /C start` with an
#     unsigned DLL, a Windows program handed an unsigned file, an unquoted
#     path to an unsigned file with no .exe name, a copied Windows program
#     outside the Windows folder, a Windows tool with no Active Setup use, a
#     network path (named, not opened), a staged StubPath (CRITICAL);
#   - a component key this account may not read, and a Session Manager
#     stand-in that is not there, are raised gaps, never an all-clear.
# Every expectation is checked and reported together (lib\expect.ps1): one round
# shows every failure.
$ErrorActionPreference = 'Stop'
. .\.github\ci\lib\expect.ps1
$o = (& .\tools\boot_activesetup_check.ps1 -SelfTest) -join "`n"
Expect ($LASTEXITCODE -eq 0) 'boot_activesetup_check -SelfTest passes on Windows PowerShell 5.1' (($o -split "`r?`n" | Where-Object { $_ -match '^\[FAIL\]' }) -join "`n")
$scr = Join-Path $env:TEMP ("dz_ci_i4b_{0}" -f $PID)
$md = Join-Path $scr 'm'
# Unsigned payloads live OUTSIDE every staging folder (%TEMP% is one), so the
# rules under test are the signature rules, not the staging rule.
$pd = Join-Path $env:ProgramData ("dz_ci_i4b_{0}" -f $PID)
$sub = "Software\dz_ci_i4b_$PID"; $hk = "HKCU:\$sub"
$sys32 = Join-Path $env:SystemRoot 'System32'
$deniedKeys = @()
New-Item -ItemType Directory -Path $md -Force | Out-Null
function Clear-M { Get-ChildItem -LiteralPath $md -Filter 'dz_*' -EA SilentlyContinue | Remove-Item -Force }
function Has([string]$n) { Test-Path (Join-Path $md "dz_$n.txt") }
function Sev([string]$n) { if (Has $n) { (Get-Content -LiteralPath (Join-Path $md "dz_$n.txt") -TotalCount 1).Trim() } else { '(no marker)' } }
function Plant([string]$Name, [string]$Stub) {
  New-Item -Path "$hk\AS\$Name" -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\$Name" -Name StubPath -PropertyType String -Value $Stub -Force | Out-Null
}
function LineOf([string]$Text, [string]$Name) { (($Text -split "`r?`n") | Where-Object { $_ -match [regex]::Escape("'$Name'") }) -join "`n" }
function Deny-Key([string]$Rel) {
  $a = Get-Acl -Path "HKCU:\$Rel"; $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $a.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'ReadKey', 'Deny')))
  $script:deniedKeys += $Rel; Set-Acl -Path "HKCU:\$Rel" -AclObject $a
}
try {
  # ---- the runner itself ----
  Clear-M
  $o = (& .\tools\boot_activesetup_check.ps1 -MarkerDir $md) -join "`n"
  Write-Host '---- MEASURED: the runner''s own BootExecute and Active Setup, as graded (raw command after "<-") ----'
  Write-Host $o
  Write-Host '---- end of the runner''s own entries ----'
  $raised = ($o -split "`r?`n" | Where-Object { $_ -match '^\[(WARNING|CRITICAL)\]' }) -join "`n"
  foreach ($n in 'bootexec', 'bootexec_gap', 'activesetup', 'activesetup_gap') {
    Expect (-not (Has $n)) "the runner's own run does not raise $n (a benign Windows entry graded as a finding, or a read that failed)" $raised
  }
  Expect (Has 'bootas_done') 'the runner run wrote its done marker'
  # Any stock autochk form (the runner's is 'autocheck autochk /q /v *'), and
  # the all-clear having graded at least one entry -- never an exact value.
  Expect ($o -match "(?m)^\[OK\] BootExecute: autocheck autochk\b[^\r\n]*\(Windows' boot-time disk check, the stock entry\)\r?$") "the runner's BootExecute is read as Windows' own autochk entry" (($o -split "`r?`n" | Where-Object { $_ -match 'BootExecute' }) -join "`n")
  Expect ($o -match "(?m)^\[OK\] BootExecute and its sibling values hold only Windows' own entries \([1-9]\d* graded\)\.") 'the BootExecute all-clear graded at least one entry'
  Expect ($o -match '(?m)^\[OK\] Active Setup: ([1-9]\d*) StubPath command\(s\) graded, none suspicious\.') "the runner's Active Setup StubPaths were graded (not zero: the check looked at something)"
  Expect ($o -match "(?m)^\[OK\] Active Setup '[^']+': .+ \(signed by [^)]+\) <- \S") 'an [OK] Active Setup line carries the raw command, so this log holds measured values'

  # ---- planted Session Manager stand-in, benign twins, hostile lines ----
  New-Item -ItemType Directory -Path (Join-Path $pd 'Common Files') -Force | Out-Null
  Set-Content -LiteralPath (Join-Path $pd 'evil.dll') -Value 'not a signed file' -Encoding ASCII
  Set-Content -LiteralPath (Join-Path $pd 'evil.exe') -Value 'not a signed file' -Encoding ASCII
  Set-Content -LiteralPath (Join-Path $pd 'Common Files\cache.dat') -Value 'not a signed file' -Encoding ASCII
  Copy-Item -LiteralPath (Join-Path $sys32 'ie4uinit.exe') -Destination (Join-Path $pd 'ie4uinit.exe')
  New-Item -Path "$hk\SM" -Force | Out-Null
  New-ItemProperty -Path "$hk\SM" -Name BootExecute -PropertyType MultiString -Value @('autocheck autochk *', 'autocheck dz_ci_native') -Force | Out-Null
  $benign = @{
    '{dz-ok}'   = ('"' + $sys32 + '\rundll32.exe" "' + $sys32 + '\shell32.dll",Control_RunDLL')
    '{dz-ie}'   = ($sys32 + '\ie4uinit.exe -UserConfig')
    '{dz-wrapok}' = ($sys32 + '\cmd.exe /D /C start ' + $sys32 + '\ie4uinit.exe -ClearIconCache')
    '{dz-msi}'  = 'msiexec.exe /fup {11111111-2222-3333-4444-555555555555} /qn'
  }
  foreach ($k in $benign.Keys) { Plant $k $benign[$k] }
  Clear-M
  $o = (& .\tools\boot_activesetup_check.ps1 -MarkerDir $md -CiSessionKey "$hk\SM" -CiActiveSetupRoots @("$hk\AS")) -join "`n"
  Expect ((Has 'bootexec') -and $o -match "(?m)^\[WARNING\] BootExecute entry 'autocheck dz_ci_native' names .*dz_ci_native\.exe, which is not on disk") 'a BootExecute entry beside autochk is raised' (($o -split "`r?`n" | Where-Object { $_ -match 'BootExecute' }) -join "`n")
  Expect (-not (Has 'activesetup')) 'the benign twins alone raise no Active Setup finding (real Authenticode)' $o
  Expect ($o -match "(?m)^\[OK\] Active Setup '\{dz-ok\}': .*\\shell32\.dll \(signed by Microsoft") 'rundll32 loading a Microsoft-signed System32 DLL is [OK] on the DLL' (LineOf $o '{dz-ok}')
  Expect ($o -match "(?m)^\[OK\] Active Setup '\{dz-ie\}': .*\\ie4uinit\.exe \(signed by Microsoft") 'ie4uinit -UserConfig is [OK]' (LineOf $o '{dz-ie}')
  Expect ($o -match "(?m)^\[OK\] Active Setup '\{dz-wrapok\}': .*\\ie4uinit\.exe \(signed by Microsoft") 'cmd /D /C start ie4uinit is graded as ie4uinit: [OK]' (LineOf $o '{dz-wrapok}')
  Expect ($o -match "(?m)^\[OK\] Active Setup '\{dz-msi\}': .*\\msiexec\.exe \(signed by Microsoft") 'msiexec repairing by product code is [OK]' (LineOf $o '{dz-msi}')

  $hostile = @(
    @('{dz-wrap}',  ($sys32 + '\cmd.exe /D /C start ' + $sys32 + '\rundll32.exe ' + $pd + '\evil.dll,Run'), 'WARNING', 'hands rundll32\.exe a file that is not validly signed', 'a host behind cmd /D /C start with an unsigned DLL'),
    @('{dz-hand}',  ($sys32 + '\conhost.exe --headless ' + $pd + '\evil.exe'), 'WARNING', 'hands conhost\.exe a file that is not validly signed', 'a Windows program handed an unsigned file'),
    @('{dz-dat}',   ($pd + '\Common Files\cache.dat -k'), 'WARNING', 'cache\.dat at every user.s next sign-in, and it is not validly signed', 'an unquoted path with a space to an unsigned file with no .exe name'),
    @('{dz-reloc}', ($pd + '\ie4uinit.exe -BaseSettings'), 'WARNING', 'a Microsoft-signed program from outside Windows and Program Files', 'a copied Windows program outside the Windows folder (catalog-signed, so still validly signed)'),
    @('{dz-tool}',  ($sys32 + '\reg.exe add HKCU\Software\dz_ci_never /v x /d 1 /f'), 'WARNING', 'runs reg\.exe, a Windows tool this check knows no Active Setup use for', 'a Windows tool with no Active Setup use'),
    @('{dz-net}',   '\\127.0.0.1\dz_ci_none\x.exe /s', 'WARNING', 'not a plain file on a local fixed drive \(\\\\127\.0\.0\.1\\dz_ci_none\\x\.exe\) -- not opened', 'a network path is named, not opened'),
    @('{dz-evil}',  'C:\Users\Public\dz_ci_evil.exe /s', 'CRITICAL', 'StubPath runs C:\\Users\\Public\\dz_ci_evil\.exe from a staging path', 'a StubPath in C:\Users\Public'))
  foreach ($h in $hostile) { Plant $h[0] $h[1] }
  Clear-M
  $o = (& .\tools\boot_activesetup_check.ps1 -MarkerDir $md -CiSessionKey "$hk\SM" -CiActiveSetupRoots @("$hk\AS")) -join "`n"
  Write-Host '---- the planted entries, as graded ----'
  Write-Host (($o -split "`r?`n" | Where-Object { $_ -match "Active Setup '\{dz-" }) -join "`n")
  foreach ($h in $hostile) {
    $rx = '(?m)^\[' + $h[2] + "\] Active Setup '" + [regex]::Escape($h[0]) + "' .*" + $h[3]
    Expect ($o -match $rx) ("hostile: " + $h[4] + " is raised " + $h[2]) (LineOf $o $h[0])
  }
  Expect ((Sev 'activesetup') -eq 'CRITICAL') 'the Active Setup marker carries the highest severity printed (CRITICAL)' (Sev 'activesetup')
  foreach ($k in $benign.Keys) {
    Expect ($o -match ("(?m)^\[OK\] Active Setup '" + [regex]::Escape($k) + "': ")) "the benign twin $k is still [OK] beside the hostile ones" (LineOf $o $k)
  }

  # ---- gaps ----
  New-Item -Path "$hk\AS\{dz-deny}" -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\{dz-deny}" -Name StubPath -PropertyType String -Value 'C:\Users\Public\hidden.exe' -Force | Out-Null
  Deny-Key "$sub\AS\{dz-deny}"
  Clear-M
  $o = (& .\tools\boot_activesetup_check.ps1 -MarkerDir $md -CiSessionKey "$hk\NoSuchSM" -CiActiveSetupRoots @("$hk\AS")) -join "`n"
  Expect ((Has 'activesetup_gap') -and $o -match 'Active Setup check NOT performed for 1 component\(s\) under .* that could not be read: \{dz-deny\}') 'a component key this account may not read is a raised gap naming it' (($o -split "`r?`n" | Where-Object { $_ -match 'NOT performed' }) -join "`n")
  Expect ((Has 'bootexec_gap') -and $o -notmatch "(?m)^\[OK\] BootExecute and its sibling") 'a Session Manager key that is not there is a raised gap, never the all-clear' (($o -split "`r?`n" | Where-Object { $_ -match 'BootExecute' }) -join "`n")
  Expect (Has 'bootas_done') 'the gap run wrote its done marker'
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
  Remove-Item -LiteralPath $pd -Recurse -Force -EA SilentlyContinue
  Expect (-not (Test-Path -LiteralPath $hk)) "cleanup removed $hk"
  Expect (-not (Test-Path -LiteralPath $scr)) "cleanup removed $scr"
  Expect (-not (Test-Path -LiteralPath $pd)) "cleanup removed $pd"
}
Complete-Expectations 'the I4b BootExecute and Active Setup step'
