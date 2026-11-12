# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It plants registry values under a scratch HKCU key, puts a deny ACL on one
# of them, and copies system binaries into a scratch folder; do not run it on
# a machine you use. It lives in .github/ so it never reaches a USB stick.
$ErrorActionPreference = 'Stop'
$st = (.\tools\accessibility_backdoor_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'accessibility_backdoor_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 23) { throw "accessibility_backdoor_check self-test ran only $n case(s)" }
function RunA([string]$Part, [hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_accbd_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\accessibility_backdoor_check.ps1 -Part $Part -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $sf = Join-Path $md $(if ($Part -eq 'Ifeo') { 'dz_accifeo_state.txt' } else { 'dz_accbin_state.txt' })
    return @{ Out = $o; State = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' }); Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_state.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$State, [string]$Markers, [string]$What) { if ($r.State -ne $State -or $r.Markers -ne $Markers) { throw ("{0}: expected {1} [{2}], got {3} [{4}] -- {5}" -f $What, $State, $Markers, $r.State, $r.Markers, $r.Out) } }
# LIVE: this runner's real registry and System32. A clean image: no Debugger,
# all seven binaries Microsoft-signed.
$i = RunA 'Ifeo' @{}
Expect $i 'ifeo=clean' '' 'the runner''s own IFEO keys'
$b = RunA 'Binaries' @{ IfeoState = $i.State; DefenderMode = 'unknown' }
Write-Host "MEASURED: the runner's accessibility binaries and Defender history: $($b.State) [$($b.Markers)]"
if ($b.State -notmatch '^bins=ok,def=(none|na|gap)$') { throw "a clean runner's accessibility binaries did not read clean: $($b.State) [$($b.Markers)] $($b.Out)" }
if ($b.Out -notmatch '(?m)^sethc\.exe SHA256: [0-9A-F]{64}$') { throw "the sethc.exe hash line is gone: $($b.Out)" }
# Another antivirus owns protection: Defender history is not applicable, not a gap and not an all-clear.
$r = RunA 'Binaries' @{ IfeoState = 'ifeo=clean'; DefenderMode = 'Passive Mode' }
if ($r.State -ne 'bins=ok,def=na' -or $r.Out -match 'detections on record') { throw "passive-mode Defender was not 'not applicable': $($r.State) $($r.Out)" }
# EVERY IFEO STATE through the real reader, on throwaway HKCU keys.
# Touches: registry:HKCU:\Software\dz_ci_accbd_<pid> (removed in finally).
$root = "HKCU:\Software\dz_ci_accbd_$PID"; $k = @{ KeyRoot = $root }
$ifeo = "$root\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$tmpBase = $env:RUNNER_TEMP; if (-not $tmpBase) { $tmpBase = $env:TEMP }
$scratch = Join-Path $tmpBase "dz_ci_accbd_$PID"
try {
  Expect (RunA 'Ifeo' $k) 'ifeo=gap' 'dz_accifeo_gap' 'no IFEO key at all (it exists on every Windows)'
  New-Item -Path $ifeo -Force | Out-Null
  Expect (RunA 'Ifeo' $k) 'ifeo=clean' '' 'the IFEO key with no accessibility subkeys'
  # The benign twin: a subkey with another value and no Debugger.
  New-Item -Path "$ifeo\osk.exe" -Force | Out-Null; Set-ItemProperty -Path "$ifeo\osk.exe" -Name MitigationOptions -Value 0 -Type DWord
  Expect (RunA 'Ifeo' $k) 'ifeo=clean' '' 'a subkey with no Debugger value (the benign twin)'
  # The malign twin.
  New-Item -Path "$ifeo\sethc.exe" -Force | Out-Null; Set-ItemProperty -Path "$ifeo\sethc.exe" -Name Debugger -Value 'C:\Windows\System32\cmd.exe'
  $r = RunA 'Ifeo' $k; Expect $r 'ifeo=hijack' 'dz_accifeo_hit' 'a Debugger on sethc.exe'
  if ($r.Out -notmatch '(?m)^\[CRITICAL\] IFEO Debugger hijack: sethc\.exe -> C:\\Windows\\System32\\cmd\.exe\r?$') { throw 'the IFEO finding wording changed' }
  # Section 17 states that verdict; it does not read the registry.
  $r = RunA 'Binaries' @{ IfeoState = 'ifeo=hijack'; DefenderMode = 'Passive Mode' }
  if ($r.Markers -notmatch 'dz_accbin_hit' -or $r.Out -notmatch '(?m)^\[CRITICAL\]\[T1546\.008\] IFEO Debugger hijack on an accessibility binary') { throw "Section 17 did not carry Section 13's hijack: [$($r.Markers)] $($r.Out)" }
  # THE READ THAT FAILS: one subkey denied to this account, beside the hijack.
  New-Item -Path "$ifeo\utilman.exe" -Force | Out-Null
  $denied = $false
  try {
    $acl = Get-Acl -Path "$ifeo\utilman.exe"
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path "$ifeo\utilman.exe" -AclObject $acl
    try { $null = Get-Item -LiteralPath "$ifeo\utilman.exe" -ErrorAction Stop } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    $r = RunA 'Ifeo' $k
    Expect $r 'ifeo=hijack+gap' 'dz_accifeo_gap,dz_accifeo_hit' 'a hijack beside a key that cannot be read'
    if ($r.Out -notmatch 'could not be read: utilman\.exe' -or $r.Out -match '(?m)^\[OK\]') { throw "the unreadable key was not named, or an [OK] was printed: $($r.Out)" }
    Write-Host 'accessibility: a key this account is denied is a raised gap beside the finding, never an all-clear'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the self-test pins the judgement' }
  # THE BINARIES through the real signature reader, on a scratch "System32".
  New-Item -ItemType Directory -Path $scratch -Force | Out-Null
  $sys = Join-Path $env:SystemRoot 'System32'
  foreach ($n in 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') { Copy-Item -LiteralPath (Join-Path $sys $n) -Destination $scratch }
  # sethc.exe is absent from the scratch folder: MISSING, never silence.
  $r = RunA 'Binaries' @{ IfeoState = 'ifeo=clean'; DefenderMode = 'Passive Mode'; SystemDir = $scratch }
  Write-Host "MEASURED: copies of the system binaries outside System32 read as: $($r.State) [$($r.Markers)]"
  if ($r.Markers -notmatch 'dz_accbin_missing' -or $r.Out -notmatch '(?m)^\[WARNING\] sethc\.exe is MISSING from the system directory') { throw "a missing sethc.exe was not the missing-binary warning: [$($r.Markers)] $($r.Out)" }
  # The swap an attacker makes: an unsigned file under the name sethc.exe.
  Set-Content -LiteralPath (Join-Path $scratch 'sethc.exe') -Value 'not a real binary'
  $r = RunA 'Binaries' @{ IfeoState = 'ifeo=clean'; DefenderMode = 'Passive Mode'; SystemDir = $scratch }
  if ($r.Markers -notmatch 'dz_accbin_hit' -or $r.Out -notmatch '(?m)^\[CRITICAL\] sethc\.exe may have been replaced with a non-Microsoft binary!') { throw "an unsigned sethc.exe was not the replaced-binary finding: [$($r.Markers)] $($r.Out)" }
  if ($r.State -notmatch '^bins=bad,') { throw "the state does not say the binary is bad: $($r.State)" }
  Write-Host 'accessibility: a missing binary is a warning and a replaced one is CRITICAL, through the real signature reader'
} finally {
  $ErrorActionPreference = 'Continue'
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_accbd_$PID\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  Remove-Item -LiteralPath $scratch -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "the CI test key $root could not be removed" }
}
exit 0
