# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It writes throwaway keys under HKCU\Software\dz_ci_sb_<pid> (removed in
# finally and proven gone) and reads the runner's real Secure Boot state. It
# changes no firmware or boot setting. It lives in .github/ so it never
# reaches a USB stick.
$ErrorActionPreference = 'Stop'
$st = (.\tools\secure_boot_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'secure_boot_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 13) { throw "secure_boot_check self-test ran only $n case(s)" }
function RunS([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_sb_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\secure_boot_check.ps1 -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $sf = Join-Path $md 'dz_secboot_state.txt'
    return @{ Out = $o; State = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' }); Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_state.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$State, [string]$Markers, [string]$Pattern, [string]$What) {
  if ($r.State -ne $State -or $r.Markers -ne $Markers -or $r.Out -notmatch $Pattern) { throw ("{0}: expected {1} [{2}] matching {3}; got {4} [{5}] {6}" -f $What, $State, $Markers, $Pattern, $r.State, $r.Markers, $r.Out) }
  Write-Host ("secure boot: {0} -> {1} [{2}]" -f $What, $r.State, $r.Markers)
}

# LIVE: the runner's own Secure Boot, MEASURED, and graded -- never a gap: an
# administrator on a runner can read it. Then the same read with the
# firmware query left out, so the registry record answers on its own, as it
# does for a standard user; the two must agree.
$r = RunS @{}
Write-Host "MEASURED: the runner's Secure Boot state is $($r.State) [$($r.Markers)]"
if ($r.State -notmatch '^sb=(on|off|bios)$') { throw "an administrator could not grade the runner's Secure Boot: $($r.State) [$($r.Markers)] $($r.Out)" }
if (($r.State -eq 'sb=off') -ne ($r.Markers -eq 'dz_secboot_hit')) { throw "the state and its marker disagree: $($r.State) [$($r.Markers)]" }
$live = $r.State
if ($live -ne 'sb=bios') {
  $r = RunS @{ NoConfirm = $true }
  Write-Host "MEASURED: from the registry record alone: $($r.State)"
  if ($r.State -ne $live) { throw "the registry record alone reads $($r.State) where the firmware query read $live -- a standard user would be told something else: $($r.Out)" }
}
# As the bats call it: a new powershell, no -Elevated.
$md = Join-Path $env:TEMP ("dz_ci_sb_auto_{0}" -f $PID); New-Item -ItemType Directory -Path $md -Force | Out-Null
try {
  $o = (& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tools\secure_boot_check.ps1 -MarkerDir $md) -join "`n"; $rc = $LASTEXITCODE
  $sf = Join-Path $md 'dz_secboot_state.txt'; $s = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' })
  if ($rc -ne 0 -or $s -ne $live) { throw "the tool called as the bats call it gave '$s' (exit $rc), not $live : $o" }
  Write-Host "secure boot: called as the bats call it -> $s"
} finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }

$root = "HKCU:\Software\dz_ci_sb_$PID"
try {
  # Every state through the real registry reader, with the firmware type
  # forced to UEFI and the firmware query left out.
  $base = @{ StateKey = "$root\State"; FirmwareType = 2; NoConfirm = $true; Elevated = 1 }
  New-Item -Path "$root\State" -Force | Out-Null
  New-ItemProperty -Path "$root\State" -Name UEFISecureBootEnabled -Value 1 -PropertyType DWord | Out-Null
  Expect (RunS $base) 'sb=on' '' '(?m)^\[OK\] Secure Boot ENABLED\.$' 'the record says on'
  Set-ItemProperty -Path "$root\State" -Name UEFISecureBootEnabled -Value 0
  Expect (RunS $base) 'sb=off' 'dz_secboot_hit' '(?m)^\[WARNING\] Secure Boot DISABLED\.$' 'the record says off'
  Remove-ItemProperty -Path "$root\State" -Name UEFISecureBootEnabled
  Expect (RunS $base) 'sb=gap' 'dz_secboot_gap' '(?m)^\[WARNING\] Secure Boot check NOT performed -- this PC boots in UEFI mode' 'UEFI with no record (never "may be legacy BIOS")'
  $b2 = $base.Clone(); $b2.FirmwareType = 1
  Expect (RunS $b2) 'sb=bios' '' '(?m)^\[INFO\] This PC boots in legacy BIOS mode' 'legacy BIOS'
  # THE READ THAT FAILS: the State key denied to this account.
  New-ItemProperty -Path "$root\State" -Name UEFISecureBootEnabled -Value 1 -PropertyType DWord | Out-Null
  $denied = $false
  try {
    $acl = Get-Acl -Path "$root\State"
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path "$root\State" -AclObject $acl
    try { $null = (Get-Item -LiteralPath "$root\State" -ErrorAction Stop).GetValueNames() } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    Expect (RunS $base) 'sb=gap' 'dz_secboot_gap' 'could not be read' 'the record refused to an administrator (a gap)'
    $b3 = $base.Clone(); $b3.Elevated = 0
    Expect (RunS $b3) 'sb=deferred' 'dz_secboot_deferred' '(?m)^\[DEFERRED - ADMIN REQUIRED\] Secure Boot check' 'the record refused to a standard-user token (a counted deferral)'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the self-test pins the judgement' }
  Write-Host 'secure boot: on is OK, off is the WARNING, legacy BIOS is INFO, a missing or refused record is a gap (a deferral for a refused standard user)'
} catch {
  Write-Host ("::error::" + $_.Exception.Message); throw
} finally {
  $ErrorActionPreference = 'Continue'
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_sb_$PID\State", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "cleanup failed: the CI test key $root could not be removed" }
}
exit 0
