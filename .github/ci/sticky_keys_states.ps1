# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It reads the runner's real Sticky Keys settings and writes throwaway keys
# under HKCU\Software\dz_ci_sk_<pid> (removed in finally and proven gone). It
# changes no real accessibility setting. It lives in .github/ so it never
# reaches a USB stick.
$ErrorActionPreference = 'Stop'
$st = (.\tools\sticky_keys_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'sticky_keys_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 11) { throw "sticky_keys_check self-test ran only $n case(s)" }
function RunK([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_sk_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\sticky_keys_check.ps1 -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $sf = Join-Path $md 'dz_sticky_state.txt'
    return @{ Out = $o; State = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' }); Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_state.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$State, [string]$Markers, [string]$Pattern, [string]$What) {
  if ($r.State -notlike ($State + '*') -or $r.Markers -ne $Markers -or $r.Out -notmatch $Pattern) { throw ("{0}: expected {1} [{2}] matching {3}; got {4} [{5}] {6}" -f $What, $State, $Markers, $Pattern, $r.State, $r.Markers, $r.Out) }
  Write-Host ("sticky keys: {0} -> {1} [{2}]" -f $What, $r.State, $r.Markers)
}
# LIVE: the runner's own logon-screen setting, MEASURED, and graded -- an
# administrator can always read HKEY_USERS\.DEFAULT, so never a gap.
$r = RunK @{}
Write-Host "MEASURED: the runner's logon-screen Sticky Keys state is $($r.State) [$($r.Markers)]"
if ($r.State -notmatch '^sticky=(on|off),lf=(\d+|-),uf=(\d+|-)$') { throw "the runner's logon-screen setting was not graded: $($r.State) [$($r.Markers)] $($r.Out)" }
if (($r.State -like 'sticky=on,*') -ne ($r.Markers -eq 'dz_sticky_hit')) { throw "the state and its marker disagree: $($r.State) [$($r.Markers)]" }
$root = "HKCU:\Software\dz_ci_sk_$PID"
try {
  New-Item -Path "$root\logon" -Force | Out-Null; New-Item -Path "$root\user" -Force | Out-Null
  $base = @{ LogonKey = "$root\logon"; UserKey = "$root\user"; Elevated = 1 }
  New-ItemProperty -Path "$root\logon" -Name Flags -Value '510' -PropertyType String | Out-Null
  New-ItemProperty -Path "$root\user" -Name Flags -Value '506' -PropertyType String | Out-Null
  Expect (RunK $base) 'sticky=on' 'dz_sticky_hit' '(?m)^\[WARNING\] Sticky Keys shortcut ENABLED at the logon screen .*Flags 510' 'the logon screen on (510), this user off'
  Set-ItemProperty -Path "$root\logon" -Name Flags -Value '506'; Set-ItemProperty -Path "$root\user" -Name Flags -Value '510'
  Expect (RunK $base) 'sticky=off' '' '(?m)^\[OK\] Sticky Keys shortcut disabled at the logon screen' 'the logon screen off (506) while this user is on -- the logon screen decides'
  Remove-ItemProperty -Path "$root\logon" -Name Flags
  Expect (RunK $base) 'sticky=on,lf=-,' 'dz_sticky_hit' 'Windows'' default applies, which is on' 'the logon value absent (Windows'' default), recorded as not set for the undo'
  New-ItemProperty -Path "$root\logon" -Name Flags -Value 'abc' -PropertyType String | Out-Null
  Expect (RunK $base) 'sticky=gap' 'dz_sticky_gap' '(?m)^\[WARNING\] Sticky Keys check NOT performed -- the logon screen''s Flags value is not a number' 'a Flags value that is not a number'
  Set-ItemProperty -Path "$root\logon" -Name Flags -Value '510'
  $denied = $false
  try {
    $acl = Get-Acl -Path "$root\logon"
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path "$root\logon" -AclObject $acl
    try { $null = (Get-Item -LiteralPath "$root\logon" -ErrorAction Stop).GetValueNames() } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    Expect (RunK $base) 'sticky=gap' 'dz_sticky_gap' '(?m)^\[WARNING\] Sticky Keys check NOT performed -- the logon screen''s setting' 'the logon key refused to an administrator (a gap)'
    $b2 = $base.Clone(); $b2.Elevated = 0
    Expect (RunK $b2) 'sticky=gap' 'dz_sticky_gap' '(?m)^\[WARNING\] Sticky Keys check NOT performed' 'the logon key refused on a standard-user token is still a gap (Users can read .DEFAULT)'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the self-test pins the judgement' }
  Write-Host 'sticky keys: the logon screen decides, absent is the default (on), a value that is not a number or a key that cannot be read is a gap'
} catch {
  Write-Host ("::error::" + $_.Exception.Message); throw
} finally {
  $ErrorActionPreference = 'Continue'
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_sk_$PID\logon", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "cleanup failed: the CI test key $root could not be removed" }
}
exit 0
