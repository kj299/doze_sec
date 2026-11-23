# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   logon_persistence / com_clsid_check / persistence_extra: a key or profile that cannot be read is a raised gap, never [OK]
# It plants throwaway HKCU keys with a deny ACE and a PowerShell profile held
# open with no sharing; every plant is removed in finally. Do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick.
$ErrorActionPreference = 'Stop'
foreach ($t in 'logon_persistence', 'com_clsid_check') {
  $st = (& ".\tools\$t.ps1" -SelfTest) -join "`n"
  if ($LASTEXITCODE -ne 0) { Write-Host $st; throw "$t -SelfTest failed" }
}
function Run([string]$Tool, [hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_pg_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& ".\tools\$Tool.ps1" -MarkerDir $md @Extra) -join "`n"
    return @{ Out = $o; Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Deny([string]$Path) {
  $acl = Get-Acl -Path $Path
  $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule([Security.Principal.WindowsIdentity]::GetCurrent().Name, 'QueryValues', 'Deny')))
  Set-Acl -Path $Path -AclObject $acl
  $d = $false; try { $null = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop } catch { $d = $true }
  return $d
}
# LIVE: the runner's own keys. An administrator can read every one of them.
foreach ($t in 'logon_persistence', 'com_clsid_check') {
  $r = Run $t @{}
  Write-Host ("MEASURED: {0} on the runner's own keys: markers [{1}]" -f $t, $r.Markers)
  if ($r.Markers -match '_gap') { throw ("a clean runner raised a gap from {0}: {1}" -f $t, (($r.Out -split "`n" | Where-Object { $_ -match 'NOT performed' }) -join ' | ')) }
  if ($r.Markers -notmatch '_done') { throw "$t wrote no done marker" }
}
$root = "HKCU:\Software\dz_ci_pg_$PID"
$prof = $null; $profMade = $false; $fs = $null
try {
  # logon_persistence: a Winlogon\Notify key that cannot be read.
  $nk = "$root\lk\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
  New-Item -Path $nk -Force | Out-Null
  if (Deny $nk) {
    $r = Run 'logon_persistence' @{ KeyRoot = "$root\lk"; UserRoot = "$root\lu" }
    Write-Host ($r.Out -split "`n" | Where-Object { $_ -match 'Notify|NOT performed' })
    if ($r.Out -match 'No Winlogon Notify packages') { throw 'a Notify key that could not be read printed the all-clear' }
    if ($r.Out -notmatch '\[WARNING\] Winlogon Notify check NOT performed in full') { throw "a Notify key that could not be read was not a raised gap: $($r.Out)" }
    if ($r.Markers -notmatch 'logon_gap') { throw "no dz_logon_gap marker: [$($r.Markers)]" }
    Write-Host 'logon_persistence: an unreadable Notify key is a raised gap, never "No Winlogon Notify packages"'
  } else { Write-Host '[ SKIP ] the deny rule did not stop this account reading the Notify key; the self-test pins the judgement' }
  # com_clsid_check: a CLSID entry whose InprocServer32 cannot be read.
  $ck = "$root\clsid\{dz-ci-0000}\InprocServer32"
  New-Item -Path $ck -Force | Out-Null
  Set-ItemProperty -Path $ck -Name '(default)' -Value 'C:\Users\Public\dz_ci_never.dll'
  if (Deny $ck) {
    $r = Run 'com_clsid_check' @{ Root = "$root\clsid" }
    Write-Host ($r.Out -split "`n" | Where-Object { $_ -match 'CLSID|NOT performed' })
    if ($r.Out -match 'No user-level COM CLSID overrides') { throw 'an unreadable CLSID entry printed the all-clear' }
    if ($r.Out -notmatch '\[WARNING\] COM CLSID override check NOT performed in full -- 1 key') { throw "an unreadable CLSID entry was not a raised gap: $($r.Out)" }
    if ($r.Markers -notmatch 'com_gap') { throw "no dz_com_gap marker: [$($r.Markers)]" }
    Write-Host 'com_clsid_check: an unreadable CLSID entry is a raised gap, never "No user-level COM CLSID overrides"'
  } else { Write-Host '[ SKIP ] the deny rule did not stop this account reading the CLSID key; the self-test pins the judgement' }
  # persistence_extra: a PowerShell profile held open with no sharing.
  $docs = [Environment]::GetFolderPath('MyDocuments')
  $prof = Join-Path $docs 'WindowsPowerShell\profile.ps1'
  if (Test-Path -LiteralPath $prof) { Write-Host "[ SKIP ] the runner already has $prof; it is not replaced" ; $prof = $null }
  else {
    New-Item -ItemType Directory -Path (Split-Path $prof) -Force | Out-Null
    Set-Content -LiteralPath $prof -Value '# dz_ci profile' -Encoding ASCII; $profMade = $true
    $fs = [IO.File]::Open($prof, 'Open', 'Read', 'None')
    $r = Run 'persistence_extra' @{}
    $fs.Dispose(); $fs = $null
    $pl = @($r.Out -split "`n" | Where-Object { $_ -match 'PowerShell profile' })
    Write-Host ("MEASURED: profile lines while it was locked: " + ($pl -join ' | '))
    if ($r.Out -match 'PowerShell profile present but empty') { throw 'a profile that could not be read printed "present but empty"' }
    if ($r.Out -notmatch '\[WARNING\] PowerShell profile check NOT performed in full') { throw "a locked profile was not a raised gap" }
    if ($r.Markers -notmatch 'psprofile_gap') { throw "no dz_psprofile_gap marker: [$($r.Markers)]" }
    Write-Host 'persistence_extra: a profile that cannot be read is a raised gap, never "present but empty"'
  }
} finally {
  $ErrorActionPreference = 'Continue'
  if ($fs) { $fs.Dispose() }
  foreach ($p in @("$root\lk\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify", "$root\clsid\{dz-ci-0000}\InprocServer32")) {
    if (Test-Path $p) { try { $a = Get-Acl -Path $p; foreach ($rule in @($a.Access | Where-Object { $_.AccessControlType -eq 'Deny' })) { [void]$a.RemoveAccessRule($rule) }; Set-Acl -Path $p -AclObject $a } catch { Write-Host ("cleanup: " + $_.Exception.Message) } }
  }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if ($profMade -and $prof) { Remove-Item -LiteralPath $prof -Force -EA SilentlyContinue }
  if (Test-Path $root) { throw "cleanup failed: $root remains" }
}
exit 0
