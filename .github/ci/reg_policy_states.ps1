# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It plants registry values under a scratch HKCU key and puts a deny ACL on
# one of them; do not run it on a machine you use. It lives in .github/ so it
# never reaches a USB stick (make_usb_stick.ps1 excludes the directory), and
# outside the workflow file because GitHub refuses to run a workflow file
# over its size limit -- silently: the jobs simply never appear.
$ErrorActionPreference = 'Stop'
$st = (.\tools\reg_policy_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'reg_policy_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 58) { throw "reg_policy_check self-test ran only $n case(s)" }
$stateFile = @{ Winlogon = 'dz_winlogon_state.txt'; ScriptBlockLogging = 'dz_sbl_state.txt'; Uac = 'dz_uac_state.txt'; Rdp = 'dz_rdp_state.txt' }
function RunP([string]$Check, [hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_regpol_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\reg_policy_check.ps1 -Check $Check -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $sf = Join-Path $md $stateFile[$Check]
    return @{ Out = $o; State = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' }); Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_state.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
# LIVE: this runner's real HKLM. Winlogon and AppInit are pinned (a
# clean image); UAC and logging are measured, and must be GRADED.
$w = RunP 'Winlogon' @{}; $u = RunP 'Uac' @{}; $l = RunP 'ScriptBlockLogging' @{}; $d = RunP 'Rdp' @{}
Write-Host "MEASURED: the runner's own state is $($w.State) ; $($u.State) ; $($l.State) ; $($d.State) [$($d.Markers)]"
# A hosted runner is reached over RDP, so on or off, with or without NLA, is
# measured -- but it must be GRADED, with the service context line.
if ($d.State -notmatch '^rdp=(off|nla|nonla|nonla-policy)$') { throw "the runner's RDP state was not graded: $($d.State) [$($d.Markers)] $($d.Out)" }
if ($d.Out -notmatch '(?m)^\[INFO\] (Remote Desktop service \(TermService\): |The Remote Desktop service state or its listener could not be read)') { throw "the RDP check printed no service context line: $($d.Out)" }
if (($d.State -like 'rdp=nonla*') -ne ($d.Markers -match '^dz_rdpnla_(hit|pol)$')) { throw "the RDP state and its marker disagree: $($d.State) [$($d.Markers)]" }
if ($w.State -ne 'userinit=ok,shell=ok,appinit=empty' -or $w.Markers) { throw "a clean runner did not read Winlogon and AppInit_DLLs clean: $($w.State) [$($w.Markers)]" }
if ($u.State -notmatch '^uac=(on|noprompt|off),cpb=[0-5]$') { throw "the runner's UAC state was not graded: $($u.State) [$($u.Markers)]" }
if ($l.State -notmatch '^sbl=(on|off)$') { throw "the runner's Script Block Logging state was not graded: $($l.State)" }
# EVERY STATE through the real reader, on throwaway HKCU keys.
# Touches: registry:HKCU:\Software\dz_ci_regpol_<pid> (removed in finally).
$root = "HKCU:\Software\dz_ci_regpol_$PID"; $k = @{ KeyRoot = $root }
$wl = "$root\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$nat = "$root\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
$wow = "$root\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
$pol = "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$sbl = "$root\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$ts = "$root\SYSTEM\CurrentControlSet\Control\Terminal Server"; $tcp = "$ts\WinStations\RDP-Tcp"; $gp = "$root\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$good = (Join-Path $env:SystemRoot 'system32\userinit.exe') + ','
function Expect($r, [string]$State, [string]$Markers, [string]$What) { if ($r.State -ne $State -or $r.Markers -ne $Markers) { throw ("{0}: expected {1} [{2}], got {3} [{4}] -- {5}" -f $What, $State, $Markers, $r.State, $r.Markers, $r.Out) } }
try {
  # Nothing there at all: every check is a gap, none an all-clear --
  # except Script Block Logging, where no policy key is the ordinary
  # "not configured" machine.
  Expect (RunP 'Winlogon' $k) 'userinit=gap,shell=gap,appinit=gap' 'dz_appinit_gap,dz_winlogon_gap' 'no keys'
  Expect (RunP 'Uac' $k) 'uac=gap,cpb=-' 'dz_uac_gap' 'no keys'
  Expect (RunP 'ScriptBlockLogging' $k) 'sbl=off' 'dz_sbl_hit' 'no policy key'
  Expect (RunP 'Rdp' $k) 'rdp=gap' 'dz_rdp_gap' 'no Terminal Server key'
  foreach ($p in $wl, $nat, $pol, $sbl, $tcp) { New-Item -Path $p -Force | Out-Null }
  # RDP, every state. No policy key is the ordinary unmanaged machine.
  Expect (RunP 'Rdp' $k) 'rdp=missing' 'dz_rdp_missing' 'fDenyTSConnections absent'
  Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 1 -Type DWord
  Expect (RunP 'Rdp' $k) 'rdp=off' '' 'RDP off (the benign twin)'
  Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 0 -Type DWord
  $r = RunP 'Rdp' $k; Expect $r 'rdp=nonla' 'dz_rdpnla_hit' 'RDP on, UserAuthentication absent (the malign twin)'
  if ($r.Out -notmatch '(?m)^\[WARNING\] RDP enabled WITHOUT NLA\r?$') { throw 'the RDP finding wording changed' }
  Set-ItemProperty -Path $tcp -Name UserAuthentication -Value 1 -Type DWord
  Expect (RunP 'Rdp' $k) 'rdp=nla' '' 'RDP on with NLA'
  # Group Policy outranks the local setting, in both directions.
  New-Item -Path $gp -Force | Out-Null; Set-ItemProperty -Path $gp -Name UserAuthentication -Value 0 -Type DWord
  Expect (RunP 'Rdp' $k) 'rdp=nonla-policy' 'dz_rdpnla_pol' 'policy switches NLA off over a local 1 (its own marker: no local fix)'
  Set-ItemProperty -Path $gp -Name fDenyTSConnections -Value 1 -Type DWord
  $r = RunP 'Rdp' $k; Expect $r 'rdp=off' '' 'policy turns RDP off over a local 0'
  if ($r.Out -notmatch 'differs from Group Policy') { throw "the policy/local difference was not said: $($r.Out)" }
  Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 7 -Type DWord; Remove-ItemProperty -Path $gp -Name fDenyTSConnections
  Expect (RunP 'Rdp' $k) 'rdp=gap' 'dz_rdp_gap' 'a value Windows does not define'
  # The benign twin: defaults everywhere.
  Set-ItemProperty -Path $wl -Name Userinit -Value $good; Set-ItemProperty -Path $wl -Name Shell -Value 'explorer.exe'
  Set-ItemProperty -Path $nat -Name AppInit_DLLs -Value ''
  Set-ItemProperty -Path $pol -Name EnableLUA -Value 1 -Type DWord; Set-ItemProperty -Path $pol -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord
  Set-ItemProperty -Path $sbl -Name EnableScriptBlockLogging -Value 1 -Type DWord
  Expect (RunP 'Winlogon' $k) 'userinit=ok,shell=ok,appinit=empty' '' 'the benign twin (no Wow6432Node key)'
  Expect (RunP 'Uac' $k) 'uac=on,cpb=5' '' 'the benign twin'
  Expect (RunP 'ScriptBlockLogging' $k) 'sbl=on' '' 'the benign twin'
  # The malign twin.
  Set-ItemProperty -Path $wl -Name Userinit -Value ($good + 'C:\Users\Public\dz_ci_evil.exe'); Set-ItemProperty -Path $wl -Name Shell -Value 'explorer.exe, C:\ProgramData\dz_ci_evil.exe'
  New-Item -Path $wow -Force | Out-Null; Set-ItemProperty -Path $wow -Name AppInit_DLLs -Value 'C:\Users\Public\dz_ci_evil.dll'
  Set-ItemProperty -Path $pol -Name EnableLUA -Value 0 -Type DWord
  Set-ItemProperty -Path $sbl -Name EnableScriptBlockLogging -Value 0 -Type DWord
  $r = RunP 'Winlogon' $k; Expect $r 'userinit=modified,shell=modified,appinit=set' 'dz_appinit_hit,dz_winlogon_hit' 'the malign twin'
  if ($r.Out -notmatch '(?m)^\[CRITICAL\] Winlogon Userinit MODIFIED \(T1547\.004\): ' -or $r.Out -notmatch '(?m)^\[CRITICAL\] AppInit_DLLs is set \(T1546\.010\)') { throw 'the finding wording changed' }
  Expect (RunP 'Uac' $k) 'uac=off,cpb=5' 'dz_uac_hit' 'EnableLUA 0'
  Expect (RunP 'ScriptBlockLogging' $k) 'sbl=off' 'dz_sbl_hit' 'logging 0'
  Set-ItemProperty -Path $pol -Name EnableLUA -Value 1 -Type DWord; Set-ItemProperty -Path $pol -Name ConsentPromptBehaviorAdmin -Value 0 -Type DWord
  Expect (RunP 'Uac' $k) 'uac=noprompt,cpb=0' 'dz_uacprompt_hit' 'prompt 0'
  # Values removed: per value, not globally.
  Remove-ItemProperty -Path $wl -Name Userinit; Remove-ItemProperty -Path $pol -Name ConsentPromptBehaviorAdmin
  $r = RunP 'Winlogon' $k; if ($r.State -notlike 'userinit=missing,*' -or $r.Markers -notmatch 'dz_winlogon_missing') { throw "a missing Userinit value was not the missing-value warning: $($r.State) [$($r.Markers)]" }
  Expect (RunP 'Uac' $k) 'uac=missing,cpb=-' 'dz_uac_cpbmissing' 'prompt value removed'
  # THE READ THAT FAILS: the Winlogon key denied to this account.
  Set-ItemProperty -Path $wl -Name Userinit -Value $good
  $denied = $false
  try {
    $acl = Get-Acl -Path $wl
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    # Deny reading values and subkeys only, so the cleanup can always take the rule off.
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path $wl -AclObject $acl
    try { $null = Get-Item -LiteralPath $wl -ErrorAction Stop } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    $r = RunP 'Winlogon' $k
    if ($r.State -notlike 'userinit=gap,shell=gap,*' -or $r.Markers -notmatch 'dz_winlogon_gap' -or $r.Out -match 'is the default' -or $r.Out -match '\[SKIPPED\]') { throw "a Winlogon key that cannot be read was not a raised gap: $($r.State) [$($r.Markers)] $($r.Out)" }
    Write-Host 'reg policy: a key this account is denied is a raised gap, never an all-clear'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the self-test pins the judgement' }
} finally {
  # Take the deny rule off FIRST, through a handle that asks only to
  # change permissions and without reading the old ACL.
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_regpol_$PID\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "the CI test key $root could not be removed" }
}
Write-Host 'reg policy: every state read through the real registry reader for all four checks'
exit 0
