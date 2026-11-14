# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It plants registry values under a scratch HKCU key and puts a deny ACL on
# one subkey; do not run it on a machine you use. It lives in .github/ so it
# never reaches a USB stick.
#
# Section 18h through the REAL staged block (tests\section18_gaps.ps1 -Mode Run
# renders it exactly as cmd writes it), on a list naming throwaway keys:
#   hit      a value the list names                       -> matched
#   twin     a value whose name only CONTAINS that name   -> not matched
#   badval   a value whose data is not the listed bad one -> not matched
#   missing  a key that does not exist                    -> nothing (an answer)
#   denied   a key this account may not read              -> named, raised gap
#   badhive  an entry under a hive the check cannot read  -> named, raised gap
# The old block wrapped every read in catch{}, so the last two vanished.
$ErrorActionPreference = 'Stop'
$root = "HKCU:\Software\dz_ci_rioc_$PID"
$lists = Join-Path $env:TEMP ("dz_ci_rioc_lists_{0}" -f $PID)
$reg = "HKCU\Software\dz_ci_rioc_$PID"
try {
  New-Item -ItemType Directory -Path $lists -Force | Out-Null
  New-Item -Path "$root\Run" -Force | Out-Null
  Set-ItemProperty -Path "$root\Run" -Name 'DzCiUpdate' -Value 'C:\dz_ci_does_not_exist.exe'
  Set-ItemProperty -Path "$root\Run" -Name 'DzCiUpdateHelper' -Value 'C:\dz_ci_does_not_exist.exe'
  Set-ItemProperty -Path "$root\Run" -Name 'DzCiFlag' -Value 0 -Type DWord
  New-Item -Path "$root\Denied" -Force | Out-Null
  Set-ItemProperty -Path "$root\Denied" -Name 'DzCiHidden' -Value 'x'
  $denied = $false
  try {
    $acl = Get-Acl -Path "$root\Denied"
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path "$root\Denied" -AclObject $acl
    try { $null = (Get-Item -LiteralPath "$root\Denied" -ErrorAction Stop).GetValueNames() } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  Set-Content -LiteralPath (Join-Path $lists 'ioc_registry.txt') -Encoding ASCII -Value @(
    '# CI list',
    "$reg\Run|DzCiUpdate",
    "$reg\Run|DzCiFlag|1",
    "$reg\Missing|DzCiNothing",
    "$reg\Denied|DzCiHidden",
    'HKU\.DEFAULT\Software\dz_ci_rioc|DzCiOther'
  )
  $ErrorActionPreference = 'Continue'
  $o = (powershell -NoProfile -ExecutionPolicy Bypass -File tests\section18_gaps.ps1 -Mode Run -ListDir $lists -Sections '18h' 2>&1 | ForEach-Object { "$_" }) -join "`n"
  $ErrorActionPreference = 'Stop'
  Write-Host $o
  if ($o -notmatch 'S18 18h hit=1 gap=0 done=1 unread=1') { throw "18h did not report the match AND the unread entries (or did not reach its verdict): $o" }
  if ($o -notmatch [regex]::Escape("$reg\Run\DzCiUpdate = C:\dz_ci_does_not_exist.exe")) { throw "18h did not print the value it matched: $o" }
  if ($o -match 'DzCiUpdateHelper') { throw "18h matched the twin, whose name only contains a listed name: $o" }
  if ($o -match 'DzCiFlag =') { throw "18h matched a value whose data is not the listed bad value: $o" }
  if ($o -match 'DzCiNothing') { throw "18h named a key that does not exist as unread -- a missing key is an answer: $o" }
  if ($o -notmatch [regex]::Escape('HKU\.DEFAULT\Software\dz_ci_rioc\DzCiOther - the entry must start HKLM\ or HKCU\')) { throw "18h did not name the entry under a hive it cannot read: $o" }
  if ($denied) {
    if ($o -notmatch ([regex]::Escape("$reg\Denied\DzCiHidden - ") + '(SecurityException|UnauthorizedAccessException)')) { throw "18h did not name the key this account is denied: $o" }
    Write-Host 'Section 18h: a denied key and a bad entry are named and raised beside the match; the twin and the safe value are not matches'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the bad-hive entry still proves the unread path' }
} finally {
  $ErrorActionPreference = 'Continue'
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_rioc_$PID\Denied", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  Remove-Item -LiteralPath $lists -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "the CI test key $root could not be removed" }
}
exit 0
