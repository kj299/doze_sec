# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It starts two copies of ping.exe under remote-access-tool names in a scratch
# folder and writes throwaway HKCU keys; do not run it on a machine you use.
# It lives in .github/ so it never reaches a USB stick.
$ErrorActionPreference = 'Stop'
$st = (.\tools\rmm_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'rmm_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 32) { throw "rmm_check self-test ran only $n case(s)" }
function Snap {
  $t = Join-Path $env:TEMP ("dz_ci_rmm_tree_{0}.tmp" -f [guid]::NewGuid().ToString('N').Substring(0, 6))
  & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tools\proc_snapshot.ps1 -TreePath $t | Out-Null
  $global:LASTEXITCODE = 0
  return $t
}
function RunR([string]$Tree, [hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_rmm_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\rmm_check.ps1 -TreePath $Tree -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $sf = Join-Path $md 'dz_rmm_state.txt'
    return @{ Out = $o; State = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' }); Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_state.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$State, [string]$Markers, [string]$What) { if ($r.State -ne $State -or $r.Markers -ne $Markers) { throw ("{0}: expected {1} [{2}], got {3} [{4}] -- {5}" -f $What, $State, $Markers, $r.State, $r.Markers, $r.Out) } }
# LIVE: the runner's own processes and Uninstall keys, MEASURED. Whatever is
# there, an administrator can read both: it must be GRADED, never a gap.
$tree = Snap
try {
  $r = RunR $tree @{}
  Write-Host "MEASURED: the runner's own remote-access tools: $($r.State) [$($r.Markers)]"
  if ($r.State -notmatch '^run=\d+,inst=\d+$' -or $r.Markers -match 'rmm_gap') { throw "an administrator could not grade remote-access tools on the runner: $($r.State) [$($r.Markers)] $($r.Out)" }
  # The snapshot missing: a raised gap, never "[OK] No known remote-access tool running".
  $r = RunR (Join-Path $env:TEMP 'dz_ci_rmm_no_such_tree.tmp') @{}
  if ($r.State -notlike 'run=gap,*' -or $r.Markers -notmatch 'dz_rmm_gap' -or $r.Out -match 'tool running \(') { throw "a missing process snapshot was not a raised gap: $($r.State) [$($r.Markers)] $($r.Out)" }
} finally { Remove-Item -LiteralPath $tree -Force -EA SilentlyContinue }
# EVERY INSTALLED STATE through the real reader, on throwaway HKCU keys.
# Touches: registry:HKCU:\Software\dz_ci_rmm_<pid> (removed in finally).
$root = "HKCU:\Software\dz_ci_rmm_$PID"; $un = "$root\Uninstall"
$empty = Join-Path $env:TEMP "dz_ci_rmm_empty_$PID.tmp"
'1|0|0|0|C:\Windows\explorer.exe|explorer.exe' | Set-Content -LiteralPath $empty
$k = @{ UninstallRoots = @($un) }
try {
  Expect (RunR $empty $k) 'run=0,inst=gap' 'dz_rmm_gap' 'the Uninstall key not found (the first root is the one that exists on every Windows)'
  New-Item -Path $un -Force | Out-Null
  # The benign twins: names that hold a product name INSIDE a word.
  foreach ($x in @(@('c1', 'Collateral Manager'), @('c2', 'Lateral Tools 2.1'))) { New-Item -Path "$un\$($x[0])" -Force | Out-Null; Set-ItemProperty -Path "$un\$($x[0])" -Name DisplayName -Value $x[1] }
  $r = RunR $empty $k; Expect $r 'run=0,inst=0' '' 'Collateral Manager and Lateral Tools (the benign twins)'
  if ($r.Out -notmatch '(?m)^\[OK\] No known remote-access tool installed \(2 installed-program') { throw "the [OK] did not say how many entries it examined: $($r.Out)" }
  # The malign twin.
  New-Item -Path "$un\a1" -Force | Out-Null; Set-ItemProperty -Path "$un\a1" -Name DisplayName -Value 'AnyDesk'; Set-ItemProperty -Path "$un\a1" -Name DisplayVersion -Value '9.0.1'; Set-ItemProperty -Path "$un\a1" -Name Publisher -Value 'AnyDesk Software GmbH'
  $r = RunR $empty $k; Expect $r 'run=0,inst=1' 'dz_rmm_inst_hit' 'AnyDesk installed (the malign twin)'
  if ($r.Out -notmatch '(?m)^\[WARNING\] Remote-access tool INSTALLED: AnyDesk 9\.0\.1, publisher AnyDesk Software GmbH \(T1219\)\r?$') { throw "the installed line does not name the version and publisher: $($r.Out)" }
  # THE READ THAT FAILS: one entry denied to this account, beside the finding.
  $denied = $false
  try {
    $acl = Get-Acl -Path "$un\c2"
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys, ReadKey', 'Deny')))
    Set-Acl -Path "$un\c2" -AclObject $acl
    try { $null = Get-ItemProperty -LiteralPath "$un\c2" -ErrorAction Stop } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    $r = RunR $empty $k; Expect $r 'run=0,inst=1+gap' 'dz_rmm_gap,dz_rmm_inst_hit' 'a finding beside an entry that cannot be read'
    if ($r.Out -notmatch 'could not be read \(c2\)') { throw "the unreadable entry was not named: $($r.Out)" }
    Write-Host 'rmm: an Uninstall entry this account is denied is a raised gap beside the finding, and is named'
  } else { Write-Host '[ SKIP ] denied-entry case not run: this account can still read the entry through the deny rule; the self-test pins the judgement' }
} finally {
  $ErrorActionPreference = 'Continue'
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_rmm_$PID\Uninstall\c2", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  Remove-Item -LiteralPath $empty -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "the CI test key $root could not be removed" }
  $ErrorActionPreference = 'Stop'
}
# A REAL RUNNING PROCESS, both directions, read from a real snapshot. The
# malign twin: a copy of ping.exe named AnyDesk.exe. The benign twin: the same
# copy named LateralHelper.exe, which the old substring match called Atera.
# Touches: file:C:\dz_ci_rmm_<pid>\ and two processes (stopped and removed in finally).
$dir = "C:\dz_ci_rmm_$PID"; $procs = @()
try {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  $ping = Join-Path $env:SystemRoot 'System32\PING.EXE'
  foreach ($nm in 'AnyDesk.exe', 'LateralHelper.exe') {
    Copy-Item -LiteralPath $ping -Destination (Join-Path $dir $nm)
    $procs += Start-Process -FilePath (Join-Path $dir $nm) -ArgumentList '-n', '60', '127.0.0.1' -WindowStyle Hidden -PassThru
  }
  Start-Sleep -Seconds 2
  $tree = Snap
  try {
    $r = RunR $tree @{}
    $want = [regex]::Escape((Join-Path $dir 'AnyDesk.exe'))
    if ($r.Markers -notmatch 'dz_rmm_run_hit' -or $r.Out -notmatch ('(?m)^\[WARNING\] Remote-access tool RUNNING: AnyDesk -- AnyDesk\.exe \(PID \d+\), ' + $want + '; ')) { throw "a process named AnyDesk.exe was not the running finding with its path: [$($r.Markers)] $($r.Out)" }
    if ($r.Out -match 'LateralHelper') { throw "LateralHelper.exe was matched as a remote-access tool: $($r.Out)" }
    if ($r.Out -notmatch 'AnyDesk\.exe[^\r\n]*Microsoft') { Write-Host 'MEASURED: the copy of ping.exe did not read as Microsoft-signed under its new name (catalog signature)' } else { Write-Host 'MEASURED: the copy of ping.exe still reads as Microsoft-signed under its new name -- the signature is context, and the finding stands' }
    Write-Host 'rmm: a real process named like a remote-access tool is the finding with its path; a look-alike inside a word is not'
  } finally { Remove-Item -LiteralPath $tree -Force -EA SilentlyContinue }
} finally {
  $ErrorActionPreference = 'Continue'
  foreach ($p in $procs) { try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {} }
  Start-Sleep -Seconds 1
  Remove-Item -LiteralPath $dir -Recurse -Force -EA SilentlyContinue
  if (Test-Path -LiteralPath $dir) { throw "the CI scratch folder $dir could not be removed" }
}
exit 0
