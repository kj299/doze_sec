# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It creates a local account, signs it in once so it gets a profile, mounts
# that account's REAL registry to plant Run values in it, and deletes the
# account and its profile in finally. Do not run it on a machine you use. It
# lives in .github/ so it never reaches a USB stick.
#
# What it proves, through tools\persistence_eval.ps1 -Part OtherAccounts:
#   * a signed-out account's malign Run value is found, named by account,
#     from a COPY of its registry (-LoadSignedOut), and its benign twin is not;
#   * without -LoadSignedOut the account is NAMED as not read, never silent;
#   * afterwards no HKU\dz_sec_* mount and no dz_hive_<pid> copy remains, and
#     the account's own NTUSER.DAT was never mounted or copied directly: it is
#     held OPEN by this script while the tool runs, so a mount of it, or a
#     plain copy of it, would fail -- only a copy from a snapshot succeeds --
#     and its hash is unchanged afterwards.
$ErrorActionPreference = 'Stop'
$st = (.\tools\persistence_eval.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'persistence_eval -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 58) { throw "persistence_eval self-test ran only $n case(s)" }
function RunO([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_oa_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $raw = @(& .\tools\persistence_eval.ps1 -Part OtherAccounts -MarkerFile (Join-Path $md 'hit.txt') -GapFile (Join-Path $md 'gap.txt') -DeferredFile (Join-Path $md 'def.txt') -DoneFile (Join-Path $md 'done.txt') @Extra 2>&1)
    $o = ($raw | ForEach-Object { [string]$_ }) -join "`n"; Write-Host $o
    if (@($raw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }).Count) { throw "PowerShell error text: $o" }
    if (-not (Test-Path (Join-Path $md 'done.txt'))) { throw "no done marker: $o" }
    return @{ Out = $o; Hit = (Test-Path (Join-Path $md 'hit.txt')); Gap = (Test-Path (Join-Path $md 'gap.txt')) }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Assert-NoLeftovers([string]$What) {
  $m = @([Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match '^dz_sec_\d+_\d+$' })
  if ($m.Count) { throw "$What left a registry copy mounted: $($m -join ', ')" }
  $d = @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter 'dz_hive_*' -EA SilentlyContinue)
  if ($d.Count) { throw "$What left a registry copy folder: $($d.FullName -join ', ')" }
}
# LIVE: the runner's own accounts, MEASURED. Nothing on a clean image is a
# finding; whether the image holds signed-out profiles is printed, not pinned.
$r = RunO @{ LoadSignedOut = $true }
Write-Host ("MEASURED: other accounts on the runner: hit={0} gap={1}" -f $r.Hit, $r.Gap)
if ($r.Hit) { throw "a clean runner had a suspicious autorun in another account: $($r.Out)" }
Assert-NoLeftovers 'the live run'
# THE PLANT. Touches: account:dzciru<pid>, its profile folder, its NTUSER.DAT
# (mounted as HKU\dz_ci_plant_<pid> only while planting); all removed in finally.
$user = ('dzciru' + ($PID % 100000))
$pw = 'Dz!' + [guid]::NewGuid().ToString('N').Substring(0, 16) + 'aA1'
$sec = ConvertTo-SecureString $pw -AsPlainText -Force
$plant = ('dz_ci_plant_' + $PID)
$sid = ''
try {
  # Start-Process -Credential runs through the Secondary Logon service.
  Set-Service seclogon -StartupType Manual -EA SilentlyContinue
  Start-Service seclogon -EA SilentlyContinue
  New-LocalUser -Name $user -Password $sec -PasswordNeverExpires -AccountNeverExpires -Description 'doze_sec CI throwaway' | Out-Null
  Add-LocalGroupMember -Group 'Users' -Member $user
  $cred = New-Object System.Management.Automation.PSCredential($user, $sec)
  # One sign-in creates the profile and its NTUSER.DAT.
  Start-Process -FilePath 'cmd.exe' -ArgumentList '/c exit 0' -Credential $cred -LoadUserProfile -WorkingDirectory $env:SystemRoot -WindowStyle Hidden -Wait
  $sid = (New-Object Security.Principal.NTAccount($user)).Translate([Security.Principal.SecurityIdentifier]).Value
  # Wait for Windows to unload the profile: the account is then signed out.
  for ($i = 0; $i -lt 60 -and (@([Microsoft.Win32.Registry]::Users.GetSubKeyNames()) -contains $sid); $i++) { Start-Sleep -Seconds 1 }
  if (@([Microsoft.Win32.Registry]::Users.GetSubKeyNames()) -contains $sid) { throw "the throwaway account's registry stayed loaded after its sign-in ended" }
  $prof = [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + $sid)).ProfileImagePath)
  $hive = Join-Path $prof 'NTUSER.DAT'
  # Native tools write to stderr; under 'Stop' 5.1 would end a retry loop.
  $ErrorActionPreference = 'Continue'
  & reg.exe load ("HKU\" + $plant) $hive 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "could not mount the throwaway account's registry to plant in it" }
  try {
    & reg.exe add ("HKU\$plant\Software\Microsoft\Windows\CurrentVersion\Run") /v 'DzCiUpdater' /t REG_SZ /d 'powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' /f | Out-Null
    & reg.exe add ("HKU\$plant\Software\Microsoft\Windows\CurrentVersion\Run") /v 'DzCiOneDrive' /t REG_SZ /d '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background' /f | Out-Null
  } finally {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    for ($i = 0; $i -lt 5; $i++) { & reg.exe unload ("HKU\" + $plant) 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { break }; Start-Sleep -Seconds 1 }
  }
  $ErrorActionPreference = 'Stop'
  $before = (Get-FileHash -LiteralPath $hive -Algorithm SHA256).Hash
  # Without -LoadSignedOut: named, not read.
  $r = RunO @{}
  if ($r.Hit -or $r.Out -notmatch ('signed-out account\(s\) not read: [^\r\n]*' + [regex]::Escape($user))) { throw "without -LoadSignedOut the signed-out account was not named as unread: $($r.Out)" }
  # With it: the malign value is the finding, named by account; the twin is
  # not. The account's own file is held open meanwhile (no sharing for
  # writers or deleters, and Windows needs exclusive access to mount it), so
  # the tool can succeed only by copying from a snapshot.
  $hold = [IO.File]::Open($hive, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try { $r = RunO @{ LoadSignedOut = $true } } finally { $hold.Dispose() }
  if (-not $r.Hit -or $r.Out -notmatch ('(?m)^\[WARNING\] Suspicious Run-key autorun in another account \[[^\]]*' + [regex]::Escape($user) + '[^\]]*signed out, read from a copy\\Microsoft\\Windows\\CurrentVersion\\Run\\DzCiUpdater\]')) { throw "the planted autorun in the signed-out account was not found and named: $($r.Out)" }
  if ($r.Out -match 'WARNING[^\r\n]*DzCiOneDrive') { throw "the benign twin was graded as a finding: $($r.Out)" }
  if ($r.Out -match ('(?m)^\[WARNING\] Other accounts'' Run-key check NOT performed[^\r\n]*' + [regex]::Escape($user))) { throw "reading the signed-out account raised a gap for it: $($r.Out)" }
  Assert-NoLeftovers 'the planted run'
  if ((Get-FileHash -LiteralPath $hive -Algorithm SHA256).Hash -ne $before) { throw "the account's own NTUSER.DAT changed: the tool must read a COPY, never the file" }
  Write-Host 'other accounts: a signed-out account is read from a copy, its autorun found and named, its file untouched, nothing left mounted'
} finally {
  $ErrorActionPreference = 'Continue'
  if (@([Microsoft.Win32.Registry]::Users.GetSubKeyNames()) -contains $plant) { & reg.exe unload ("HKU\" + $plant) 2>&1 | Out-Null }
  & .\tools\unload_audit_hives.ps1 | Out-Null
  if ($sid) { Get-CimInstance Win32_UserProfile -Filter ("SID='" + $sid + "'") -EA SilentlyContinue | Remove-CimInstance -EA SilentlyContinue }
  Remove-LocalUser -Name $user -EA SilentlyContinue
}
exit 0
