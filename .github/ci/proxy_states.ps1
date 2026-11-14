# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It plants proxy settings under a scratch HKCU key, puts a deny ACL on one,
# and sets the runner's real machine-wide WinHTTP proxy to a dead loopback
# port, resetting it in finally. Do not run it on a machine you use: a
# WinHTTP proxy left behind stops Windows Update and Defender's cloud lookups.
# It lives in .github/ so it never reaches a USB stick.
#
# What it proves, through tools\proxy_check.ps1 and its real readers:
#   * the runner's own settings, MEASURED, read clean: no proxy, WinHTTP direct;
#   * a proxy server or an auto-config script in the record is the WARNING; the
#     benign twin beside it -- automatic detection only, the Windows default --
#     is not, and neither is a ProxyServer that is not switched on;
#   * a record that does not parse, and a key this account is denied, are a
#     raised gap, never "no proxy";
#   * Group Policy ProxySettingsPerUser=0 grades the machine setting instead;
#   * a real WinHTTP proxy, set with netsh, is found by asking Windows;
#   * a real per-user proxy in the runner's OWN HKCU (backed up and restored
#     in finally) is found by asking Windows, and the record Settings leaves
#     when a proxy is switched off (address kept, flag cleared) is not one;
#   * the record parser reads the runner's REAL records without a gap.
$ErrorActionPreference = 'Stop'
$st = (.\tools\proxy_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'proxy_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 43) { throw "proxy_check self-test ran only $n case(s)" }
function RunP([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_proxy_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    # Errors merged in, as the bat merges them into the report: an error record
    # in the output is a defect even when the verdict looks right.
    $raw = @(& .\tools\proxy_check.ps1 -MarkerDir $md @Extra 2>&1)
    $o = ($raw | ForEach-Object { [string]$_ }) -join "`n"; Write-Host $o
    if (@($raw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }).Count -or $o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    if (-not (Test-Path (Join-Path $md 'dz_proxy_done.txt'))) { throw "no done marker: $o" }
    return @{ Out = $o; Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_done.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$Markers, [string]$Pattern, [string]$What) { if ($r.Markers -ne $Markers -or $r.Out -notmatch $Pattern) { throw ("{0}: expected [{1}] and /{2}/, got [{3}] -- {4}" -f $What, $Markers, $Pattern, $r.Markers, $r.Out) } }
function Blob([uint32]$Flags, [string]$Proxy = '', [string]$Bypass = '', [string]$Pac = '') {
  $ms = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter($ms)
  $w.Write([uint32]0x46); $w.Write([uint32]1); $w.Write($Flags)
  foreach ($s in @($Proxy, $Bypass, $Pac)) { $bs = [Text.Encoding]::ASCII.GetBytes($s); $w.Write([uint32]$bs.Length); $w.Write($bs) }
  $w.Write([uint32]0); $w.Flush(); return ,($ms.ToArray())
}

# LIVE: the runner's own settings, MEASURED. A clean image has no proxy.
$live = RunP @{}
Write-Host ("MEASURED: the runner's own proxy settings: markers [{0}]" -f $live.Markers)
if ($live.Markers -match 'dz_proxy_gap') { throw "a clean runner could not read its own proxy settings: $($live.Out)" }
if ($live.Out -notmatch '(?m)^\[INFO\] These are the proxy settings of ') { throw "the line naming whose settings were read is gone: $($live.Out)" }
if ($live.Out -notmatch '(?m)^\[(OK|WARNING)\] (No web proxy in effect for this account|Web proxy in effect for this account)') { throw "the audit's own account was not graded: $($live.Out)" }
if ($live.Out -notmatch '(?m)^\[(OK|WARNING)\] (WinHTTP \(machine-wide\)|Machine-wide WinHTTP proxy)') { throw "WinHTTP was not graded: $($live.Out)" }
if ($live.Out -notmatch 'read by WinHttpGetDefaultProxyConfiguration') { throw "Windows was not asked for the WinHTTP proxy (the API path did not run on 5.1): $($live.Out)" }
if ($live.Markers) { throw "a clean runner did not read clean for proxy settings: [$($live.Markers)] $($live.Out)" }
if ($live.Out -notmatch 'what Windows reports for this account' -and $live.Out -notmatch '(?m)^\[INFO\] Windows could not be asked which proxy is in force for this account \(') { throw "the audit's own account was graded from the registry without saying why Windows was not asked: $($live.Out)" }
# The parser on the runner's REAL records, Windows not asked: no gap.
$isKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
foreach ($rk in @(@{ K = $isKey; N = 'DefaultConnectionSettings' }, @{ K = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'; N = 'WinHttpSettings' })) {
  $b = $null; try { $b = (Get-ItemProperty -LiteralPath $rk.K -Name $rk.N -ErrorAction Stop).($rk.N) } catch {}
  Write-Host ("MEASURED: the runner's real {0}: {1}" -f $rk.N, $(if ($b -is [byte[]]) { '{0} bytes, flags 0x{1:X}' -f $b.Length, $(if ($b.Length -ge 12) { [BitConverter]::ToUInt32($b, 8) } else { 0 }) } else { 'not present' }))
}
$real = RunP @{ NoApi = $true }
# Windows just reported this runner clean, so the records must read clean too:
# a misread as a proxy would be a false WARNING for every other account.
if ($real.Markers) { throw "the record parser misread the runner's real records (Windows reports them clean): [$($real.Markers)] $($real.Out)" }
if ($real.Out -notmatch '(?m)^\[OK\] No web proxy in effect for this account \(read from ') { throw "the runner's real records were not graded from the registry: $($real.Out)" }

# EVERY STATE through the real reader, on throwaway HKCU keys.
# Touches: registry:HKCU:\Software\dz_ci_proxy_<pid> (removed in finally).
$root = "HKCU:\Software\dz_ci_proxy_$PID"
$user = "$root\u"; $mach = "$root\m"
$uis = "$user\Microsoft\Windows\CurrentVersion\Internet Settings"
$k = @{ KeyRoot = $user; MachineRoot = $mach; NoApi = $true }
$winSet = $false
# The runner's own HKCU proxy values, backed up before the real-HKCU plant.
$hk = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$saved = @{}
foreach ($pair in @(@($hk, 'ProxyEnable'), @($hk, 'ProxyServer'), @($hk, 'ProxyOverride'), @("$hk\Connections", 'DefaultConnectionSettings'))) {
  $kk = $pair[0]; $nn = $pair[1]; $item = Get-Item -LiteralPath $kk -EA SilentlyContinue
  $saved["$kk|$nn"] = $(if ($item -and (@($item.GetValueNames()) -contains $nn)) { @{ Had = $true; Value = $item.GetValue($nn, $null, 'DoNotExpandEnvironmentNames'); Kind = [string]$item.GetValueKind($nn) } } else { @{ Had = $false } })
}
$hkcuPlanted = $false
# The few seconds a real plant lives, the runner's own traffic to GitHub
# bypasses it; the bypass list is [INFO] and never decides a grade.
$ciBypass = '<local>;*.github.com;*.githubusercontent.com;*.actions.githubusercontent.com;*.blob.core.windows.net;*.windows.net'
try {
  New-Item -Path "$uis\Connections" -Force | Out-Null
  New-Item -Path "$mach\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Force | Out-Null
  # The benign twin: automatic detection only, the Windows default.
  Set-ItemProperty -Path "$uis\Connections" -Name DefaultConnectionSettings -Value (Blob 9) -Type Binary
  Expect (RunP $k) '' '(?m)^\[OK\] No web proxy in effect for this account \(read from the connection settings record\)\.' 'automatic detection only'
  # A ProxyServer that is not switched on: dormant, no WARNING.
  Set-ItemProperty -Path $uis -Name ProxyEnable -Value 0 -Type DWord; Set-ItemProperty -Path $uis -Name ProxyServer -Value 'old.example:80'
  Expect (RunP $k) '' 'ProxyServer holds old\.example:80 but it is not switched on \(dormant\)' 'a dormant ProxyServer'
  # The malign twin: a proxy server in the record.
  Set-ItemProperty -Path "$uis\Connections" -Name DefaultConnectionSettings -Value (Blob 3 '127.0.0.1:8888' '<local>') -Type Binary
  Expect (RunP $k) 'dz_proxy_hit' '(?m)^\[WARNING\] Web proxy in effect for this account: proxy server 127\.0\.0\.1:8888 \(read from the connection settings record\)' 'a proxy server in the record'
  # An auto-config script, set only in the AutoConfigURL value.
  Set-ItemProperty -Path "$uis\Connections" -Name DefaultConnectionSettings -Value (Blob 9) -Type Binary
  Set-ItemProperty -Path $uis -Name AutoConfigURL -Value 'http://dz-ci.invalid/p.pac'
  Expect (RunP $k) 'dz_proxy_hit' 'auto-config script http://dz-ci\.invalid/p\.pac' 'an AutoConfigURL value'
  Remove-ItemProperty -Path $uis -Name AutoConfigURL
  # A record that does not parse: a gap.
  Set-ItemProperty -Path "$uis\Connections" -Name DefaultConnectionSettings -Value ([byte[]](0x46, 0, 0, 0, 1)) -Type Binary
  Expect (RunP $k) 'dz_proxy_gap' '(?m)^\[WARNING\] Proxy-settings check NOT performed in full -- this account: its DefaultConnectionSettings record could not be parsed' 'a record cut short'
  Set-ItemProperty -Path "$uis\Connections" -Name DefaultConnectionSettings -Value (Blob 9) -Type Binary
  # Group Policy machine-wide: the machine setting is graded, the user's is not.
  New-Item -Path "$mach\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Force | Out-Null
  Set-ItemProperty -Path "$mach\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxySettingsPerUser -Value 0 -Type DWord
  Set-ItemProperty -Path "$mach\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name DefaultConnectionSettings -Value (Blob 3 'corp.dz-ci.invalid:8080') -Type Binary
  Expect (RunP $k) 'dz_proxy_hit' 'Web proxy in effect for every account on this PC \(machine-wide, by Group Policy\): proxy server corp\.dz-ci\.invalid:8080' 'Group Policy machine-wide'
  Remove-Item -Path "$mach\Policies" -Recurse -Force
  Set-ItemProperty -Path "$mach\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name DefaultConnectionSettings -Value (Blob 1) -Type Binary
  # The WinHTTP record, read when Windows is not asked.
  Set-ItemProperty -Path "$mach\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings -Value (Blob 3 'win.dz-ci.invalid:1') -Type Binary
  Expect (RunP $k) 'dz_winhttp_hit' '(?m)^\[WARNING\] Machine-wide WinHTTP proxy in effect: win\.dz-ci\.invalid:1 \(read from the WinHttpSettings record\)' 'the WinHttpSettings record'
  Remove-ItemProperty -Path "$mach\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings
  # THE READ THAT FAILS: the user's Internet Settings key denied.
  $denied = $false
  try {
    $acl = Get-Acl -Path $uis
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path $uis -AclObject $acl
    try { $null = (Get-Item -LiteralPath $uis -ErrorAction Stop).GetValueNames() } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    $r = RunP $k
    if ($r.Markers -notmatch 'dz_proxy_gap' -or $r.Out -match '(?m)^\[OK\] No web proxy in effect for this account') { throw "an Internet Settings key this account is denied was not a raised gap: [$($r.Markers)] $($r.Out)" }
    Write-Host 'proxy: an Internet Settings key this account is denied is a raised gap, never "no proxy"'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the self-test pins the judgement' }

  # THE REAL WINHTTP PROXY, found by asking Windows. A runner that already
  # had a proxy, of either kind, failed the clean-runner pin above, so no
  # plant below can overwrite one that is not ours.
  . {
    $ErrorActionPreference = 'Continue'
    & netsh.exe winhttp set proxy proxy-server="127.0.0.1:1" bypass-list="$ciBypass" | Out-Null
    $rc = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
    if ($rc -ne 0) { throw "netsh could not set the WinHTTP proxy (exit $rc)" }
    $winSet = $true
    $r = RunP @{}
    Expect $r 'dz_winhttp_hit' '(?m)^\[WARNING\] Machine-wide WinHTTP proxy in effect: 127\.0\.0\.1:1 \(read by WinHttpGetDefaultProxyConfiguration\)' 'a real WinHTTP proxy set with netsh'
    Write-Host 'proxy: a real WinHTTP proxy is found by asking Windows'
    # Reset now, so the per-user plant below runs with WinHTTP direct and its
    # marker set is its own (finally retries the reset if this one fails).
    $ErrorActionPreference = 'Continue'
    & netsh.exe winhttp reset proxy | Out-Null
    $rc = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
    if ($rc -ne 0) { throw "netsh winhttp reset proxy exited $rc after the WinHTTP plant" }
    $winSet = $false
  }
  # A REAL per-user proxy in this account's own HKCU, Windows asked. Settings
  # writes the record and the values together; so does this plant.
  . {
    $hkcuPlanted = $true
    if (-not (Test-Path -LiteralPath "$hk\Connections")) { New-Item -Path "$hk\Connections" -Force | Out-Null }
    Set-ItemProperty -Path "$hk\Connections" -Name DefaultConnectionSettings -Value (Blob 3 '127.0.0.1:1' $ciBypass) -Type Binary
    Set-ItemProperty -Path $hk -Name ProxyOverride -Value $ciBypass
    Set-ItemProperty -Path $hk -Name ProxyEnable -Value 1 -Type DWord; Set-ItemProperty -Path $hk -Name ProxyServer -Value '127.0.0.1:1'
    Expect (RunP @{}) 'dz_proxy_hit' '(?m)^\[WARNING\] Web proxy in effect for this account: proxy server 127\.0\.0\.1:1 \(read from what Windows reports for this account\)' 'a real per-user proxy, Windows asked'
    # Its twin: what Settings leaves when the proxy is switched off -- the
    # address kept, the proxy flag cleared, ProxyEnable 0. Not a proxy.
    Set-ItemProperty -Path "$hk\Connections" -Name DefaultConnectionSettings -Value (Blob 1 '127.0.0.1:1' $ciBypass) -Type Binary
    Set-ItemProperty -Path $hk -Name ProxyEnable -Value 0 -Type DWord
    Expect (RunP @{}) '' '(?m)^\[OK\] No web proxy in effect for this account \(read from what Windows reports for this account\)' 'a per-user proxy switched off, Windows asked'
    Write-Host 'proxy: a real per-user proxy is found by asking Windows, and one switched off is not'
  }
  Write-Host 'proxy: a proxy in effect is the finding, automatic detection and a dormant value are not, an unread key is a gap'
} catch {
  # Printed first: a failure in finally below would otherwise replace it.
  Write-Host ("::error::" + $_.Exception.Message); throw
} finally {
  $ErrorActionPreference = 'Continue'
  $restoreFail = @()
  if ($hkcuPlanted) {
    foreach ($key in $saved.Keys) {
      $kk, $nn = $key -split '\|', 2; $sv = $saved[$key]
      try {
        if ($sv.Had) { Set-ItemProperty -LiteralPath $kk -Name $nn -Value $sv.Value -Type $sv.Kind -ErrorAction Stop }
        elseif (Get-ItemProperty -LiteralPath $kk -Name $nn -EA SilentlyContinue) { Remove-ItemProperty -LiteralPath $kk -Name $nn -ErrorAction Stop }
      } catch { $restoreFail += ("{0}\{1}: {2}" -f $kk, $nn, $_.Exception.Message) }
    }
  }
  if ($winSet) {
    & netsh.exe winhttp reset proxy | Out-Null
    if ($LASTEXITCODE -ne 0) { $restoreFail += "netsh winhttp reset proxy exited $LASTEXITCODE" }
  }
  if ($hkcuPlanted -or $winSet) {
    # Proven gone, by the same reader: a later step must not inherit a dead proxy.
    try { $after = RunP @{}; if ($after.Markers -match 'dz_proxy_hit|dz_winhttp_hit') { $restoreFail += "a proxy is still in effect after the restore: [$($after.Markers)]" } } catch { $restoreFail += ("the post-restore check failed: " + $_.Exception.Message) }
  }
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_proxy_$PID\u\Microsoft\Windows\CurrentVersion\Internet Settings", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { $restoreFail += "the CI test key $root could not be removed" }
  if ($restoreFail.Count) { throw ("cleanup failed -- the runner's proxy settings may not be restored, and later steps would run behind a dead proxy: " + ($restoreFail -join '; ')) }
}
exit 0
