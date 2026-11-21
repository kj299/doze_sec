# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# Reads the runner's real Defender ASR rules, then drives the standard-user
# path through the real readers on throwaway keys under
# HKCU\Software\dz_ci_asr_<pid> (removed in finally and proven gone). It
# changes no Defender setting. It lives in .github/ so it never reaches a USB
# stick.
$ErrorActionPreference = 'Stop'
$st = (.\tools\asr_rules_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'asr_rules_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 19) { throw "asr_rules_check self-test ran only $n case(s)" }
function RunA([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_asr_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\asr_rules_check.ps1 -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $rd = { param($f) $p = Join-Path $md $f; if (Test-Path $p) { (Get-Content $p -Raw).Trim() } else { '' } }
    return @{ Out = $o; State = (& $rd 'dz_asr_state.txt'); Mode = (& $rd 'dz_asr_lsass_mode.txt'); Markers = (@(Get-ChildItem $md -Filter 'dz_asr_*.txt' | Where-Object { $_.Name -notmatch '_state|_lsass_mode' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$State, [string]$Markers, [string]$Mode, [string]$Pattern, [string]$What) {
  if ($r.State -ne $State -or $r.Markers -ne $Markers -or $r.Mode -ne $Mode -or $r.Out -notmatch $Pattern) { throw ("{0}: expected {1} [{2}] mode {3} matching {4}; got {5} [{6}] mode {7}: {8}" -f $What, $State, $Markers, $Mode, $Pattern, $r.State, $r.Markers, $r.Mode, $r.Out) }
  Write-Host ("asr rules: {0} -> {1} [{2}] mode {3}" -f $What, $r.State, $r.Markers, $r.Mode)
}
# LIVE, elevated: Get-MpPreference decides. An administrator is answered, so
# a gap or a deferral here is a defect.
$live = RunA @{}
Write-Host ("MEASURED: the runner's ASR rules read {0} [{1}], LSASS rule mode {2}" -f $live.State, $live.Markers, $live.Mode)
if ($live.State -notmatch '^asr=(block|notblock|none)$' -or $live.Markers -match 'gap|deferred') { throw "the runner's ASR rules were not graded for an administrator: $($live.State) [$($live.Markers)]" }
$shown = @((Get-MpPreference).AttackSurfaceReductionRules_Ids | Where-Object { $_ }).Count
$L = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
$root = "HKCU:\Software\dz_ci_asr_$PID"
try {
  New-Item -Path "$root\pol" -Force | Out-Null; New-Item -Path "$root\loc" -Force | Out-Null
  $base = @{ Elevated = 0; PolicyKey = "$root\pol\Rules"; LocalKey = "$root\loc\Rules"; MdmKey = "$root\mdm"; MdmKey2 = "$root\mdm2" }
  if ($shown -eq 0) {
    # No store exists, their parents answer, no MDM: the absence is KNOWN.
    Expect (RunA $base) 'asr=none' 'dz_asr_hit' 'notconfigured' '(?m)^\[WARNING\] No ASR rules configured' 'standard path, every store answered with nothing'
    # The benign twin beside it: the local store REFUSED. Same empty answer,
    # and it must be a deferral, never "No ASR rules configured".
    New-Item -Path "$root\loc\Rules" -Force | Out-Null
    $acl = Get-Acl -Path "$root\loc\Rules"
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys, ReadKey', 'Deny')))
    Set-Acl -Path "$root\loc\Rules" -AclObject $acl
    $denied = $false
    try { $null = (Get-Item -LiteralPath "$root\loc\Rules" -ErrorAction Stop).GetValueNames() } catch { $denied = $true }
    if ($denied) {
      Expect (RunA $base) 'asr=deferred' 'dz_asr_deferred' 'ungraded' '(?m)^\[DEFERRED - ADMIN REQUIRED\] 5 key ASR rule\(s\) not graded' 'standard path, the local store refused'
      # A rule Group Policy sets is graded even then; the other four defer.
      New-Item -Path "$root\pol\Rules" -Force | Out-Null
      New-ItemProperty -Path "$root\pol\Rules" -Name $L -Value '2' -PropertyType String | Out-Null
      Expect (RunA $base) 'asr=notblock' 'dz_asr_deferred,dz_asr_hit' 'audit' 'Key ASR rule not in Block mode: Block credential stealing from LSASS' 'standard path, the LSASS rule in Audit by policy, the local store refused'
    } else { Write-Host '[ SKIP ] refused-store cases not run: this account can still read the key through the deny rule; the self-test pins the judgement' }
    # An MDM-managed PC: a rule not found is deferred.
    New-Item -Path "$root\mdm" -Force | Out-Null
    New-ItemProperty -Path "$root\mdm" -Name 'AllowRealtimeMonitoring' -Value 1 -PropertyType DWord | Out-Null
    $r = RunA $base
    if ($r.Out -notmatch 'device management' -or $r.Out -match 'No ASR rules configured') { throw "an MDM-managed standard path did not defer: $($r.Out)" }
    Write-Host 'asr rules: an MDM-managed standard path defers what it cannot find'
  } else { Write-Host "[ SKIP ] store cases not run: this runner already lists $shown ASR rule(s), which the standard path would also use; the self-test pins the judgement" }
} catch {
  Write-Host ("::error::" + $_.Exception.Message); throw
} finally {
  $ErrorActionPreference = 'Continue'
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_asr_$PID\loc\Rules", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "cleanup failed: the CI test key $root could not be removed" }
}
exit 0
