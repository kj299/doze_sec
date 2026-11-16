# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It creates a scratch folder C:\dz_ci_uq_<pid> (its permissions set with
# icacls) and throwaway keys under HKCU\Software\dz_ci_uq_<pid>, all removed
# in finally and proven gone. No real service is created or changed. It lives
# in .github/ so it never reaches a USB stick; not for a person's own machine.
$ErrorActionPreference = 'Stop'
$st = (.\tools\unquoted_service_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'unquoted_service_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 34) { throw "unquoted_service_check self-test ran only $n case(s)" }
function RunU([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_uq_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\unquoted_service_check.ps1 -MarkerDir $md -Elevated 1 @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $sf = Join-Path $md 'dz_unquoted_state.txt'
    return @{ Out = $o; State = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' }); Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_state.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$State, [string]$Markers, [string]$Pattern, [string]$What) {
  if ($r.State -ne $State -or $r.Markers -ne $Markers -or $r.Out -notmatch $Pattern) { throw ("{0}: expected {1} [{2}] matching {3}; got {4} [{5}] {6}" -f $What, $State, $Markers, $Pattern, $r.State, $r.Markers, $r.Out) }
  Write-Host ("unquoted: {0} -> {1} [{2}]" -f $What, $r.State, $r.Markers)
}
function Icacls([string[]]$ArgList) {
  $ErrorActionPreference = 'Continue'
  $o = & icacls.exe @ArgList 2>&1; $rc = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  if ($rc -ne 0) { throw "icacls $($ArgList -join ' ') exited $rc : $o" }
}

# LIVE: the runner's own services, MEASURED. A clean image has nothing a
# non-administrator can hijack; an INFO (a vendor's unquoted path under
# Program Files) is allowed and printed.
$r = RunU @{}
Write-Host "MEASURED: the runner's unquoted-service-path state is $($r.State) [$($r.Markers)]"
if ($r.State -notmatch '^uq=(none|info),n=\d+$' -or $r.Markers) { throw "the runner's own services read as hijackable or were not read: $($r.State) [$($r.Markers)] $($r.Out)" }
# As the bats call it: a new powershell, no -Elevated.
$md = Join-Path $env:TEMP ("dz_ci_uq_auto_{0}" -f $PID); New-Item -ItemType Directory -Path $md -Force | Out-Null
try {
  $o = (& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tools\unquoted_service_check.ps1 -MarkerDir $md) -join "`n"; $rc = $LASTEXITCODE
  $sf = Join-Path $md 'dz_unquoted_state.txt'; $s = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' })
  if ($rc -ne 0 -or $s -notmatch '^uq=(none|info),n=\d+$') { throw "the tool called as the bats call it gave no verdict: exit $rc, state '$s': $o" }
  Write-Host "unquoted: called as the bats call it -> $s"
} finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }

$dir = "C:\dz_ci_uq_$PID"
$root = "HKCU:\Software\dz_ci_uq_$PID"
try {
  # A real folder tree: C:\dz_ci_uq_<pid>\A B\svc.exe. Windows would try
  # C:\dz_ci_uq_<pid>\A.exe first. Inheritance removed; only Administrators
  # and SYSTEM may write -- the benign case.
  New-Item -ItemType Directory -Path "$dir\A B" -Force | Out-Null
  Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\whoami.exe') -Destination "$dir\A B\svc.exe"
  Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\whoami.exe') -Destination "$dir\svc2.exe"
  Icacls @($dir, '/inheritance:r', '/grant:r', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F')
  # The owner counts too (an owner can rewrite the permissions): make it
  # Administrators explicitly rather than trust the runner's default owner.
  Icacls @($dir, '/setowner', '*S-1-5-32-544')
  New-Item -Path "$root\a" -Force | Out-Null
  function Svc([string]$Name, [string]$Image, [int]$Type = 16) {
    New-Item -Path "$root\a\$Name" -Force | Out-Null
    New-ItemProperty -Path "$root\a\$Name" -Name ImagePath -Value $Image -PropertyType ExpandString | Out-Null
    New-ItemProperty -Path "$root\a\$Name" -Name Type -Value $Type -PropertyType DWord | Out-Null
  }
  Svc 'dzci_unquoted' "$dir\A B\svc.exe"
  Svc 'dzci_quoted' "`"$dir\A B\svc.exe`""
  Svc 'dzci_argsonly' "$dir\svc2.exe -k some args"
  Svc 'dzci_driver' "$dir\A B\svc.exe" 1
  Expect (RunU @{ ServicesRoot = "$root\a" }) 'uq=info,n=1' '' ('(?m)^\[INFO\] Unquoted service path, not exploitable as installed: service dzci_unquoted runs ' + [regex]::Escape("$dir\A B\svc.exe")) 'only administrators can write where Windows looks first'
  # Its malign twin: Users may create files in that folder.
  Icacls @($dir, '/grant', '*S-1-5-32-545:(W)')
  $r = RunU @{ ServicesRoot = "$root\a" }
  Expect $r 'uq=warn,n=1' 'dz_unquoted_warn' ('(?m)^\[WARNING\] Unquoted service path a non-administrator can hijack -- service dzci_unquoted') 'Users may create files where Windows looks first'
  if ($r.Out -notmatch ([regex]::Escape("$dir\A.exe") + ' -- its folder lets [^;]*Users create it')) { throw "the WARNING does not name the place and who can write it: $($r.Out)" }
  # The attack done: a file at C:\dz_ci_uq_<pid>\A.exe.
  Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\whoami.exe') -Destination "$dir\A.exe"
  $r = RunU @{ ServicesRoot = "$root\a" }
  Expect $r 'uq=crit,n=1' 'dz_unquoted_crit' '(?m)^\[CRITICAL\] Unquoted service path: a file already sits where Windows looks first -- service dzci_unquoted' 'a file already where Windows looks first'
  if ($r.Out -notmatch ('(?m)^\[INFO\]   that file: ' + [regex]::Escape("$dir\A.exe") + ', \d+ bytes, created ')) { throw "the CRITICAL does not carry the planted file's details: $($r.Out)" }
  # THE READ THAT FAILS: one service key denied to this account.
  New-Item -Path "$root\b\dzci_locked" -Force | Out-Null
  New-ItemProperty -Path "$root\b\dzci_locked" -Name ImagePath -Value "$dir\A B\svc.exe" -PropertyType ExpandString | Out-Null
  $denied = $false
  try {
    $acl = Get-Acl -Path "$root\b\dzci_locked"
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path "$root\b\dzci_locked" -AclObject $acl
    try { $null = (Get-Item -LiteralPath "$root\b\dzci_locked" -ErrorAction Stop).GetValueNames() } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    Expect (RunU @{ ServicesRoot = "$root\b" }) 'uq=gap,n=0' 'dz_unquoted_gap' '(?m)^\[WARNING\] Unquoted service path check NOT performed -- 1 service\(s\) could not be graded: dzci_locked \(its service key' 'a service key this account is denied'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the self-test pins the judgement' }
  # The Services root itself missing: a raised gap, never [OK].
  Expect (RunU @{ ServicesRoot = "$root\nosuch" }) 'uq=gap,n=0' 'dz_unquoted_gap' '(?m)^\[WARNING\] Unquoted service path check NOT performed -- the service registry' 'a Services root that cannot be listed'
  Write-Host 'unquoted: a planted file is CRITICAL, a folder Users can write is a WARNING, an admin-only folder is INFO, quoted/arguments-only/driver twins are not graded, an unread key is a gap'
} catch {
  Write-Host ("::error::" + $_.Exception.Message); throw
} finally {
  $ErrorActionPreference = 'Continue'
  $fail = @()
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_uq_$PID\b\dzci_locked", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { $fail += "the CI test key $root could not be removed" }
  if (Test-Path -LiteralPath $dir) { & icacls.exe $dir /reset /T /Q | Out-Null; Remove-Item -LiteralPath $dir -Recurse -Force -EA SilentlyContinue }
  if (Test-Path -LiteralPath $dir) { $fail += "the scratch folder $dir could not be removed" }
  if ($fail.Count) { throw ("cleanup failed: " + ($fail -join '; ')) }
}
exit 0
