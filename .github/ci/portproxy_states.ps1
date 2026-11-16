# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It adds one portproxy rule on 127.0.0.1:53220 with netsh (removed in
# finally and proven gone by the same reader) and writes throwaway keys under
# HKCU\Software\dz_ci_pp_<pid>. It lives in .github/ so it never reaches a USB
# stick.
$ErrorActionPreference = 'Stop'
$st = (.\tools\portproxy_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'portproxy_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 14) { throw "portproxy_check self-test ran only $n case(s)" }
function RunP([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_pp_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\portproxy_check.ps1 -MarkerDir $md -Elevated 1 @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $sf = Join-Path $md 'dz_portproxy_state.txt'
    return @{ Out = $o; State = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' }); Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_state.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$State, [string]$Markers, [string]$Pattern, [string]$What) {
  if ($r.State -ne $State -or $r.Markers -ne $Markers -or $r.Out -notmatch $Pattern) { throw ("{0}: expected {1} [{2}] matching {3}; got {4} [{5}] {6}" -f $What, $State, $Markers, $Pattern, $r.State, $r.Markers, $r.Out) }
  Write-Host ("portproxy: {0} -> {1} [{2}]" -f $What, $r.State, $r.Markers)
}

# LIVE: the runner's own rules, MEASURED. A hosted runner has none; a rule
# here would be a false positive or a runner we must not plant on.
$r = RunP @{}
Write-Host "MEASURED: the runner's portproxy state is $($r.State) [$($r.Markers)]"
Expect $r 'pp=none,n=0' '' '(?m)^\[OK\] No portproxy rules \(read from the registry' "the runner's own PortProxy key"

$root = "HKCU:\Software\dz_ci_pp_$PID"
$planted = $false
try {
  # THROWAWAY KEYS laid out like PortProxy, through the real reader.
  New-Item -Path "$root\a" -Force | Out-Null
  Expect (RunP @{ KeyRoot = "$root\a" }) 'pp=none,n=0' '' '(?m)^\[OK\] No portproxy rules' 'a PortProxy key that does not hold any kind'
  # The empty leftover Windows keeps once the rules are deleted: not a finding.
  New-Item -Path "$root\a\v4tov4\tcp" -Force | Out-Null
  Expect (RunP @{ KeyRoot = "$root\a" }) 'pp=none,n=0' '' '(?m)^\[OK\] No portproxy rules' 'the empty v4tov4\tcp key left behind'
  # Its malign twin: a rule in that key, and one in v6tov4 (not only v4tov4 is read).
  New-ItemProperty -Path "$root\a\v4tov4\tcp" -Name '0.0.0.0/4444' -Value '203.0.113.7/443' -PropertyType String | Out-Null
  New-Item -Path "$root\a\v6tov4\tcp" -Force | Out-Null
  New-ItemProperty -Path "$root\a\v6tov4\tcp" -Name '::/8080' -Value '10.0.0.5/80' -PropertyType String | Out-Null
  $r = RunP @{ KeyRoot = "$root\a" }
  Expect $r 'pp=rules,n=2' 'dz_portproxy_hit' '(?m)^\[WARNING\] netsh portproxy rules ACTIVE\. Volt Typhoon C2 tunnel IOC\.$' 'two rules in two kinds'
  if ($r.Out -notmatch 'v4tov4: 0\.0\.0\.0/4444 -> 203\.0\.113\.7/443' -or $r.Out -notmatch 'v6tov4: ::/8080 -> 10\.0\.0\.5/80') { throw "the rules were found but not named listen -> connect: $($r.Out)" }
  # THE READ THAT FAILS: one kind's key denied to this account.
  $denied = $false
  try {
    $acl = Get-Acl -Path "$root\a\v6tov4\tcp"
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path "$root\a\v6tov4\tcp" -AclObject $acl
    try { $null = (Get-Item -LiteralPath "$root\a\v6tov4\tcp" -ErrorAction Stop).GetValueNames() } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    $r = RunP @{ KeyRoot = "$root\a" }
    Expect $r 'pp=rules,n=1' 'dz_portproxy_gap,dz_portproxy_hit' 'Portproxy check NOT performed in full -- the PortProxy registry key could not be read for v6tov4' 'a rule beside a kind this account is denied (both raised)'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the self-test pins the judgement' }

  # A REAL RULE, added with netsh: it must be found where the tool reads.
  . {
    $ErrorActionPreference = 'Continue'
    $o = & netsh.exe interface portproxy add v4tov4 listenport=53220 listenaddress=127.0.0.1 connectport=80 connectaddress=127.0.0.1 2>&1
    $rc = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
    if ($rc -ne 0) { throw "netsh could not add the portproxy rule (exit $rc): $o" }
    $planted = $true
  }
  $r = RunP @{}
  Expect $r 'pp=rules,n=1' 'dz_portproxy_hit' 'v4tov4: 127\.0\.0\.1/53220 -> 127\.0\.0\.1/80' 'a real rule added with netsh, read from the registry'
  Write-Host "MEASURED: IP Helper and the listener for the planted rule: $(@($r.Out -split "`n" | Where-Object { $_ -match 'IP Helper|53220' }) -join ' | ')"
  # And deleted with netsh: gone from where the tool reads.
  . {
    $ErrorActionPreference = 'Continue'
    & netsh.exe interface portproxy delete v4tov4 listenport=53220 listenaddress=127.0.0.1 | Out-Null
    $rc = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
    if ($rc -ne 0) { throw "netsh could not delete the planted portproxy rule (exit $rc)" }
    $planted = $false
  }
  Expect (RunP @{}) 'pp=none,n=0' '' '(?m)^\[OK\] No portproxy rules' 'the real rule deleted with netsh'
  Write-Host 'portproxy: a rule in any kind is the finding, an empty leftover key is not, a denied kind is a raised gap, and netsh writes where the tool reads'
} catch {
  Write-Host ("::error::" + $_.Exception.Message); throw
} finally {
  $ErrorActionPreference = 'Continue'
  $fail = @()
  if ($planted) {
    & netsh.exe interface portproxy delete v4tov4 listenport=53220 listenaddress=127.0.0.1 | Out-Null
    $pp = (& netsh.exe interface portproxy show v4tov4 2>$null | Out-String)
    if ($pp -match '53220') { $fail += 'the planted portproxy rule on 127.0.0.1:53220 is still there' }
  }
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_pp_$PID\a\v6tov4\tcp", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { $fail += "the CI test key $root could not be removed" }
  if ($fail.Count) { throw ("cleanup failed: " + ($fail -join '; ')) }
}
exit 0
