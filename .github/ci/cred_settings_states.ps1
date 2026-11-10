# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It plants registry values under a scratch HKCU key and puts a deny ACL on
# one of them; do not run it on a machine you use. It lives in .github/ so it
# never reaches a USB stick (make_usb_stick.ps1 excludes the directory), and
# outside the workflow file because GitHub refuses to run a workflow file
# over its size limit -- silently: the jobs simply never appear.
$ErrorActionPreference = 'Stop'
$st = (.\tools\cred_settings_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'cred_settings_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 22) { throw "cred_settings_check self-test ran only $n case(s)" }
function RunC([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_cred_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\cred_settings_check.ps1 -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $sf = Join-Path $md 'dz_cred_state.txt'
    return @{ Out = $o; State = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' }); Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -ne 'dz_cred_state.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
# LIVE: this runner's real HKLM. A clean image neither caches WDigest
# plaintext nor permits NTLMv1 -- a claim to pin.
$live = RunC @{}
Write-Host "MEASURED: the runner's own state is $($live.State)"
if ($live.State -notmatch '^wdigest=(off|absent),ntlm=(ok|default),level=([3-5]|-)$' -or $live.Markers) { throw "a clean runner did not read WDigest off and NTLM at the default or better: $($live.State) [$($live.Markers)]" }
# EVERY STATE through the real reader, on throwaway HKCU keys.
# Touches: registry:HKCU:\Software\dz_ci_cred_<pid> (removed in finally).
$root = "HKCU:\Software\dz_ci_cred_$PID"
$wk = "$root\WDigest"; $lk = "$root\Lsa"
try {
  New-Item -Path $wk -Force | Out-Null; New-Item -Path $lk -Force | Out-Null
  $k = @{ WDigestKey = $wk; LsaKey = $lk }
  $r = RunC $k
  if ($r.State -ne 'wdigest=absent,ntlm=default,level=-' -or $r.Markers) { throw "keys present, values absent, was not the default with nothing raised: $($r.State) [$($r.Markers)]" }
  Set-ItemProperty -Path $wk -Name UseLogonCredential -Value 1 -Type DWord; Set-ItemProperty -Path $lk -Name LmCompatibilityLevel -Value 1 -Type DWord
  $r = RunC $k
  if ($r.State -ne 'wdigest=on,ntlm=weak,level=1' -or $r.Markers -ne 'dz_ntlm_hit,dz_wdigest_hit') { throw "the malign twin (WDigest 1, NTLM level 1) was not raised: $($r.State) [$($r.Markers)]" }
  if ($r.Out -notmatch '(?m)^\[CRITICAL\] WDigest ENABLED' -or $r.Out -notmatch '(?m)^\[WARNING\] NTLMv1/LM permitted \(LmCompatibilityLevel=1\)') { throw 'the finding wording changed' }
  Set-ItemProperty -Path $wk -Name UseLogonCredential -Value 0 -Type DWord; Set-ItemProperty -Path $lk -Name LmCompatibilityLevel -Value 3 -Type DWord
  $r = RunC $k
  if ($r.State -ne 'wdigest=off,ntlm=ok,level=3' -or $r.Markers) { throw "the benign twin (WDigest 0, NTLM level 3 -- the Windows default) raised something: $($r.State) [$($r.Markers)]" }
  Remove-ItemProperty -Path $wk -Name UseLogonCredential; Set-ItemProperty -Path $wk -Name UseLogonCredential -Value '1' -Type String
  $r = RunC $k
  if ($r.State -notlike 'wdigest=on,*') { throw "WDigest stored as REG_SZ '1' dodged the finding: $($r.State)" }
  Set-ItemProperty -Path $wk -Name UseLogonCredential -Value 2 -Type DWord -Force
  $r = RunC $k
  if ($r.State -notlike 'wdigest=on,*') { throw "WDigest 2 (nonzero) dodged the finding: $($r.State)" }
  Remove-Item -Path $wk -Recurse -Force; Remove-Item -Path $lk -Recurse -Force
  $r = RunC $k
  if ($r.State -ne 'wdigest=absent,ntlm=gap,level=-' -or $r.Markers -ne 'dz_ntlm_gap') { throw "missing keys: WDigest should be absent and the Lsa key a gap: $($r.State) [$($r.Markers)]" }
  # THE READ THAT FAILS: a key this account is DENIED. If the deny
  # does not hold on this image (an administrator can read through
  # some ACLs), say so -- the self-test pins the judgement.
  New-Item -Path $wk -Force | Out-Null
  $denied = $false
  try {
    $acl = Get-Acl -Path $wk
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    # Deny reading values and subkeys only -- not READ_CONTROL or
    # WRITE_DAC -- so the cleanup below can always take the rule off.
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path $wk -AclObject $acl
    try { $null = Get-Item -LiteralPath $wk -ErrorAction Stop } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    $r = RunC $k
    if ($r.State -notlike 'wdigest=gap,*' -or $r.Markers -notmatch 'dz_wdigest_gap' -or $r.Out -match 'WDigest not caching') { throw "a WDigest key that cannot be read was not a raised gap: $($r.State) [$($r.Markers)] $($r.Out)" }
    Write-Host 'cred settings: a key this account is denied is a raised gap, never an all-clear'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the self-test pins the judgement' }
} finally {
  # Take the deny rule off FIRST, through a handle that asks only to
  # change permissions and without reading the old ACL (reading is
  # what the rule denies): a fresh, unprotected ACL inherits the
  # parent's. Then the removal can open the key.
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_cred_$PID\WDigest", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "the CI test key $root could not be removed" }
}
Write-Host 'cred settings: every state read through the real registry reader; absent is the default, a missing Lsa key or a denied key is a gap'
exit 0
