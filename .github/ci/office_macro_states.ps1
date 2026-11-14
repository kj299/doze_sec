# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It plants Office macro settings under a scratch HKCU key and puts a deny ACL
# on one of them; do not run it on a machine you use. It lives in .github/ so
# it never reaches a USB stick.
$ErrorActionPreference = 'Stop'
$st = (.\tools\office_macro_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'office_macro_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 20) { throw "office_macro_check self-test ran only $n case(s)" }
function RunM([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_macro_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\office_macro_check.ps1 -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    if (-not (Test-Path (Join-Path $md 'dz_macro_done.txt'))) { throw "no done marker: $o" }
    return @{ Out = $o; Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_done.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$Markers, [string]$Pattern, [string]$What) { if ($r.Markers -ne $Markers -or $r.Out -notmatch $Pattern) { throw ("{0}: expected [{1}] and /{2}/, got [{3}] -- {4}" -f $What, $Markers, $Pattern, $r.Markers, $r.Out) } }
# LIVE: this runner's own Office settings, MEASURED. A clean image weakens
# nothing and every key it has answers: no hit, no gap.
$r = RunM @{}
Write-Host ("MEASURED: the runner's own Office macro settings: markers [{0}]" -f $r.Markers)
if ($r.Markers) { throw "a clean runner did not read clean for Office macro settings: [$($r.Markers)] $($r.Out)" }
if ($r.Out -notmatch '(?m)^\[INFO\] These are the Office settings of ') { throw "the line naming whose settings were read is gone: $($r.Out)" }
# EVERY STATE through the real reader, on throwaway HKCU keys.
# Touches: registry:HKCU:\Software\dz_ci_macro_<pid> (removed in finally).
$root = "HKCU:\Software\dz_ci_macro_$PID"; $k = @{ KeyRoot = $root }
$user = "$root\Microsoft\Office\16.0\Word\Security"
$gpo = "$root\Policies\Microsoft\Office\16.0\Word\Security"
$cloud = "$root\Policies\Microsoft\Cloud\Office\16.0\Excel\Security"
try {
  Expect (RunM $k) '' '(?m)^\[OK\] No Office settings for this account' 'no Office key at all'
  # The benign twin: the default, set explicitly by the user.
  New-Item -Path $user -Force | Out-Null; Set-ItemProperty -Path $user -Name VBAWarnings -Value 2 -Type DWord
  Expect (RunM $k) '' '(?m)^\[OK\] Word 16\.0: VBAWarnings=2 \(set by the user setting\)' 'VBAWarnings=2, the default'
  # The malign twin beside it, and a Group Policy that overrides it back to safe.
  Set-ItemProperty -Path $user -Name VBAWarnings -Value 1 -Type DWord
  $r = RunM $k; Expect $r 'dz_macro_hit' '(?m)^\[WARNING\] Word 16\.0: VBAWarnings=1 \(set by the user setting\) -- ALL macros run with no prompt' 'VBAWarnings=1 in the user setting'
  New-Item -Path $gpo -Force | Out-Null; Set-ItemProperty -Path $gpo -Name VBAWarnings -Value 4 -Type DWord
  $r = RunM $k; Expect $r '' '(?m)^\[OK\] Word 16\.0: VBAWarnings=4 \(set by Group Policy\)' 'a Group Policy that overrides the user setting'
  if ($r.Out -notmatch '(?m)^\[INFO\] Word 16\.0: the user setting holds VBAWarnings=1, but Group Policy sets 4, which is in force') { throw "the overridden user value was not stated: $($r.Out)" }
  # Cloud Policy is read, and outranks Group Policy (here: the block turned off for Excel).
  New-Item -Path $cloud -Force | Out-Null; Set-ItemProperty -Path $cloud -Name blockcontentexecutionfrominternet -Value 0 -Type DWord
  New-Item -Path "$root\Policies\Microsoft\Office\16.0\Excel\Security" -Force | Out-Null; Set-ItemProperty -Path "$root\Policies\Microsoft\Office\16.0\Excel\Security" -Name blockcontentexecutionfrominternet -Value 1 -Type DWord
  $r = RunM $k; Expect $r 'dz_macro_hit' '(?m)^\[WARNING\] Excel 16\.0: blockcontentexecutionfrominternet=0 \(set by Cloud Policy\)' 'Cloud Policy turning the internet-macro block off over a Group Policy that turns it on'
  Remove-Item -Path "$root\Policies\Microsoft\Cloud" -Recurse -Force
  # THE READ THAT FAILS: the Group Policy key above the user's 1 is denied, so
  # what is in force is unknown -- a raised gap, never the user's value.
  $denied = $false
  try {
    $acl = Get-Acl -Path $gpo
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path $gpo -AclObject $acl
    try { $null = (Get-Item -LiteralPath $gpo -ErrorAction Stop).GetValueNames() } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    $r = RunM $k
    Expect $r 'dz_macro_gap' '(?m)^\[WARNING\] Office macro policy check NOT performed in full -- Word 16\.0 VBAWarnings: Group Policy could not be read' 'the Group Policy key denied above a user value'
    if ($r.Out -match '(?m)^\[OK\] (No Office|Word 16\.0: VBAWarnings)') { throw "an unread policy produced an all-clear: $($r.Out)" }
    Write-Host 'office macro: a policy key this account is denied is a raised gap, never the value below it'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the self-test pins the judgement' }
} finally {
  $ErrorActionPreference = 'Continue'
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_macro_$PID\Policies\Microsoft\Office\16.0\Word\Security", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "the CI test key $root could not be removed" }
}
exit 0
