# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It plants values under a scratch HKCU key and puts a deny ACL on one
# subkey; do not run it on a machine you use. It lives in .github/ so it
# never reaches a USB stick.
#
# tools\policy_value_check.ps1, through its real reader, with -KeyRoot and
# -UserRoot pointed at the scratch key:
#   MotW off      SaveZoneInformation=1 under the user root        -> the hit
#   MotW denied   the machine-root Attachments key, QueryValues denied
#                 -> the gap beside the hit (a finding and a gap are both raised)
#   SmartScreen   SmartScreenEnabled=Off                           -> the hit
#   LsaCfg        no Lsa key at all under the scratch root         -> a gap:
#                 the key exists on every Windows
#   KerbEnc       no policy key                                    -> "not pinned", no gap
# Then every check against the runner's own registry: no gap.
$ErrorActionPreference = 'Stop'
$st = (.\tools\policy_value_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'policy_value_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 18) { throw "policy_value_check self-test ran only $n case(s)" }
$sub = "Software\dz_ci_pv_$PID"
$root = "HKCU:\$sub"
$md = Join-Path $env:TEMP ("dz_ci_pv_{0}" -f $PID)
function RunPV([string]$Check) {
  New-Item -ItemType Directory -Path $md -Force | Out-Null
  Get-ChildItem -LiteralPath $md -Filter 'dz_polval_*' -EA SilentlyContinue | Remove-Item -Force
  $o = (& .\tools\policy_value_check.ps1 -Check $Check -MarkerDir $md -KeyRoot "$root\M" -UserRoot "$root\U") -join "`n"
  Write-Host "--- $Check"; Write-Host $o
  if (-not (Test-Path -LiteralPath (Join-Path $md 'dz_polval_done.txt'))) { throw "$Check wrote no done marker" }
  return @{ Out = $o; Hit = (Test-Path -LiteralPath (Join-Path $md 'dz_polval_hit.txt')); Gap = (Test-Path -LiteralPath (Join-Path $md 'dz_polval_gap.txt')) }
}
try {
  $att = 'Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
  New-Item -Path "$root\U\$att" -Force | Out-Null
  Set-ItemProperty -Path "$root\U\$att" -Name 'SaveZoneInformation' -Value 1 -Type DWord
  New-Item -Path "$root\M\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null
  Set-ItemProperty -Path "$root\M\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name 'SmartScreenEnabled' -Value 'Off'
  $r = RunPV 'MotW'
  if (-not $r.Hit -or $r.Gap -or $r.Out -notmatch '(?m)^\[WARNING\] SaveZoneInformation=1 -- ') { throw "SaveZoneInformation=1 was not the finding: $($r.Out)" }
  $r = RunPV 'SmartScreen'
  if (-not $r.Hit -or $r.Out -notmatch '(?m)^\[WARNING\] SmartScreen is OFF') { throw "SmartScreenEnabled=Off was not the finding: $($r.Out)" }
  $r = RunPV 'LsaCfg'
  if (-not $r.Gap -or $r.Out -match 'LsaCfgFlags not set') { throw "a missing Lsa key read as 'not set' instead of a gap: $($r.Out)" }
  $r = RunPV 'KerbEnc'
  if ($r.Gap -or $r.Out -notmatch '(?m)^\[INFO\] SupportedEncryptionTypes not pinned') { throw "a policy key no policy created was not 'not pinned': $($r.Out)" }
  # The denied key, through the real reader.
  $mAtt = "$root\M\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
  New-Item -Path $mAtt -Force | Out-Null
  Set-ItemProperty -Path $mAtt -Name 'SaveZoneInformation' -Value 2 -Type DWord
  $denied = $false
  try {
    $acl = Get-Acl -Path $mAtt
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues', 'Deny')))
    Set-Acl -Path $mAtt -AclObject $acl
    try { $null = (Get-Item -LiteralPath $mAtt -ErrorAction Stop).GetValueNames() } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    $r = RunPV 'MotW'
    if (-not ($r.Hit -and $r.Gap)) { throw "MotW off beside a key that could not be read must raise the hit AND the gap: $($r.Out)" }
    if ($r.Out -notmatch 'Mark-of-the-Web check NOT performed in full -- HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments /v SaveZoneInformation: ') { throw "the key that could not be read was not named: $($r.Out)" }
    if ($r.Out -match '\[OK\]') { throw "an [OK] was printed beside a key that could not be read: $($r.Out)" }
    Write-Host 'policy_value_check: a key this account may not read is named and raised beside the finding'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the missing-Lsa-key gap still proves the gap path' }
  # The runner's own registry: every check answers, no gap.
  foreach ($c in 'PsLogging', 'LsaCfg', 'AutoRun', 'Wsh', 'MotW', 'SmartScreen', 'KerbEnc') {
    New-Item -ItemType Directory -Path $md -Force | Out-Null
    Get-ChildItem -LiteralPath $md -Filter 'dz_polval_*' -EA SilentlyContinue | Remove-Item -Force
    $o = (& .\tools\policy_value_check.ps1 -Check $c -MarkerDir $md) -join "`n"
    Write-Host "--- live $c"; Write-Host $o
    if (Test-Path -LiteralPath (Join-Path $md 'dz_polval_gap.txt')) { throw "$c raised a gap on the runner's own registry: $o" }
    if (-not (Test-Path -LiteralPath (Join-Path $md 'dz_polval_done.txt'))) { throw "$c wrote no done marker on the runner" }
  }
} finally {
  $ErrorActionPreference = 'Continue'
  try {
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$sub\M\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]'ReadPermissions, ChangePermissions')
    if ($k) {
      $a = $k.GetAccessControl()
      foreach ($rule in @($a.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Deny' })) { [void]$a.RemoveAccessRuleSpecific($rule) }
      $k.SetAccessControl($a); $k.Close()
    }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  Remove-Item -LiteralPath $md -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "cleanup failed: the CI test key $root remains" }
}
exit 0
