# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It plants Office Trusted Locations and Trusted Documents records under a
# scratch HKCU key and puts a deny ACL on one of them; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick.
#
# What it proves, through tools\office_macro_check.ps1 -Part Trust and its real
# readers, each benign twin beside its malign one:
#   * Office's own default location (the user Templates folder) is INFO;
#     Downloads as a Trusted Location is the WARNING, with its shape named;
#   * a network share is not in force (INFO) while network locations are not
#     allowed, and is the WARNING once they are;
#   * Group Policy disabling all trusted locations makes the entry INFO;
#   * a Trusted Documents record with macros enabled for a file in Downloads is
#     the WARNING; the same for the person's own Documents is INFO; a record
#     without the macros flag is only counted; a record too short is named;
#   * a Trusted Locations key this account is denied is a raised gap.
$ErrorActionPreference = 'Stop'
$st = (.\tools\office_macro_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'office_macro_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 85) { throw "office_macro_check self-test ran only $n case(s)" }
function RunT([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_trust_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $raw = @(& .\tools\office_macro_check.ps1 -Part Trust -MarkerDir $md @Extra 2>&1)
    $o = ($raw | ForEach-Object { [string]$_ }) -join "`n"; Write-Host $o
    if (@($raw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }).Count -or $o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    if (-not (Test-Path (Join-Path $md 'dz_trustloc_done.txt'))) { throw "no done marker: $o" }
    return @{ Out = $o; Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_done.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$Markers, [string]$Pattern, [string]$What) { if ($r.Markers -ne $Markers -or $r.Out -notmatch $Pattern) { throw ("{0}: expected [{1}] and /{2}/, got [{3}] -- {4}" -f $What, $Markers, $Pattern, $r.Markers, $r.Out) } }
function Rec([string]$Name, [uint32]$Flag = 0x7FFFFFFF, [int]$Len = 24) {
  $b = New-Object byte[] $Len
  if ($Len -ge 12) { [BitConverter]::GetBytes([DateTime]::UtcNow.ToFileTimeUtc()).CopyTo($b, 0); [BitConverter]::GetBytes($Flag).CopyTo($b, $Len - 4) }
  return ,$b
}
# LIVE: the runner's own Office settings, MEASURED. A clean image has no
# Trusted Location outside Office's defaults and no macros enabled.
$live = RunT @{}
Write-Host ("MEASURED: the runner's own Trusted Locations and Trusted Documents: markers [{0}]" -f $live.Markers)
if ($live.Markers) { throw "a clean runner did not read clean: [$($live.Markers)] $($live.Out)" }
if ($live.Out -notmatch '(?m)^\[INFO\] These are the Office Trusted Locations and Trusted Documents of ') { throw "the line naming whose settings were read is gone: $($live.Out)" }

# EVERY STATE through the real reader, on throwaway HKCU keys.
# Touches: registry:HKCU:\Software\dz_ci_trust_<pid> (removed in finally).
$root = "HKCU:\Software\dz_ci_trust_$PID"
$user = "$root\u"; $mach = "$root\m"
$k = @{ KeyRoot = $user; MachineRoot = $mach }
$tl = "$user\Microsoft\Office\16.0\Word\Security\Trusted Locations"
$tr = "$user\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords"
$gp = "$user\Policies\Microsoft\Office\16.0\Word\Security\Trusted Locations"
try {
  Expect (RunT $k) '' '(?m)^\[OK\] No Office settings for this account' 'no Office key at all'
  # The benign twin: Office's own default, written the way Office writes it.
  New-Item -Path "$tl\Location0" -Force | Out-Null
  New-ItemProperty -Path "$tl\Location0" -Name Path -Value '%APPDATA%\Microsoft\Templates' -PropertyType ExpandString -Force | Out-Null
  Expect (RunT $k) '' 'Word 16\.0: 1 of Office''s own default Trusted Location' 'the user Templates default'
  # The malign twin beside it: Downloads, subfolders included.
  New-Item -Path "$tl\Location9" -Force | Out-Null
  New-ItemProperty -Path "$tl\Location9" -Name Path -Value '%USERPROFILE%\Downloads' -PropertyType ExpandString -Force | Out-Null
  New-ItemProperty -Path "$tl\Location9" -Name AllowSubfolders -Value 1 -PropertyType DWord -Force | Out-Null
  Expect (RunT $k) 'dz_trustloc_hit' '(?m)^\[WARNING\] Office Trusted Location outside Office''s defaults \(Word 16\.0, set by the user setting\): %USERPROFILE%\\Downloads \(subfolders included\) -- Downloads' 'Downloads as a Trusted Location'
  Remove-Item -Path "$tl\Location9" -Recurse -Force
  # A network share: not in force while network locations are not allowed.
  New-Item -Path "$tl\Location8" -Force | Out-Null
  New-ItemProperty -Path "$tl\Location8" -Name Path -Value '\\dz-ci.invalid\share' -PropertyType String -Force | Out-Null
  Expect (RunT $k) '' 'is a network location, which Office ignores' 'a network share, network locations not allowed'
  New-ItemProperty -Path $tl -Name AllowNetworkLocations -Value 1 -PropertyType DWord -Force | Out-Null
  Expect (RunT $k) 'dz_trustloc_hit' 'a network location, which anyone who can write to it controls' 'a network share, network locations allowed'
  # Group Policy disables all trusted locations: the entry is not in force.
  New-Item -Path $gp -Force | Out-Null
  New-ItemProperty -Path $gp -Name AllLocationsDisabled -Value 1 -PropertyType DWord -Force | Out-Null
  Expect (RunT $k) '' 'is not in force: Group Policy disables all trusted locations' 'all trusted locations disabled by policy'
  Remove-Item -Path "$user\Policies" -Recurse -Force
  Remove-Item -Path "$tl\Location8" -Recurse -Force; Remove-ItemProperty -Path $tl -Name AllowNetworkLocations
  # A Templates folder under the PUBLIC profile only looks like Office's
  # default: every account can write there. It must raise.
  New-Item -Path "$tl\Location7" -Force | Out-Null
  New-ItemProperty -Path "$tl\Location7" -Name Path -Value 'C:\Users\Public\AppData\Roaming\Microsoft\Templates' -PropertyType String -Force | Out-Null
  Expect (RunT $k) 'dz_trustloc_hit' 'C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Templates -- the Public folder' 'a look-alike default under the Public profile'
  Remove-Item -Path "$tl\Location7" -Recurse -Force
  # Policy allows only Trusted Locations defined by policy ("allow user
  # locations" = 0 in Common): the user's Downloads entry is not in force,
  # while a Group Policy entry beside it still raises.
  $cm = "$user\Policies\Microsoft\Office\16.0\Common\Security\Trusted Locations"
  New-Item -Path $cm -Force | Out-Null
  New-ItemProperty -Path $cm -Name 'allow user locations' -Value 0 -PropertyType DWord -Force | Out-Null
  New-Item -Path "$tl\Location6" -Force | Out-Null
  New-ItemProperty -Path "$tl\Location6" -Name Path -Value 'C:\Users\dzci\Downloads' -PropertyType String -Force | Out-Null
  Expect (RunT $k) '' 'Downloads \(set by the user setting\) is not in force: Group Policy allows only Trusted Locations defined by policy' 'a user entry under the policy-only setting'
  Set-ItemProperty -Path $cm -Name 'allow user locations' -Value 1
  Expect (RunT $k) 'dz_trustloc_hit' 'Word 16\.0, set by the user setting\): C:\\Users\\dzci\\Downloads' 'the same user entry with user locations allowed'
  Set-ItemProperty -Path $cm -Name 'allow user locations' -Value 0
  New-Item -Path "$gp\Location2" -Force | Out-Null
  New-ItemProperty -Path "$gp\Location2" -Name Path -Value 'C:\dz_ci_policy_only' -PropertyType String -Force | Out-Null
  Expect (RunT $k) 'dz_trustloc_hit' 'Word 16\.0, set by Group Policy\): C:\\dz_ci_policy_only' 'a policy entry under the policy-only setting'
  Remove-Item -Path "$user\Policies" -Recurse -Force
  Remove-Item -Path "$tl\Location6" -Recurse -Force
  # Every other source through the real reader: a Group Policy entry, the
  # machine key and its 32-bit twin, and another signed-in account.
  New-Item -Path "$gp\Location1" -Force | Out-Null
  New-ItemProperty -Path "$gp\Location1" -Name Path -Value 'C:\dz_ci_policy_folder' -PropertyType String -Force | Out-Null
  Expect (RunT $k) 'dz_trustloc_hit' 'Word 16\.0, set by Group Policy\): C:\\dz_ci_policy_folder' 'a Group Policy Trusted Location'
  Remove-Item -Path "$user\Policies" -Recurse -Force
  foreach ($mk in @(@{ P = "$mach\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location5"; N = 'the machine setting' }, @{ P = "$mach\WOW6432Node\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location5"; N = 'the machine setting \(32-bit\)' })) {
    New-Item -Path $mk.P -Force | Out-Null
    New-ItemProperty -Path $mk.P -Name Path -Value 'C:\dz_ci_machine_folder' -PropertyType String -Force | Out-Null
    Expect (RunT $k) 'dz_trustloc_hit' ('Excel 16\.0, set by ' + $mk.N + '\): C:\\dz_ci_machine_folder') ('a Trusted Location in ' + $mk.N)
    Remove-Item -Path $mk.P -Recurse -Force
  }
  $oth = "$root\o"
  New-Item -Path "$oth\Microsoft\Office\16.0\Word\Security\Trusted Locations\Location3" -Force | Out-Null
  New-ItemProperty -Path "$oth\Microsoft\Office\16.0\Word\Security\Trusted Locations\Location3" -Name Path -Value 'C:\dz_ci_other_folder' -PropertyType String -Force | Out-Null
  Expect (RunT @{ KeyRoot = $user; MachineRoot = $mach; OtherKeyRoot = @($oth) }) 'dz_trustloc_hit' ('Word 16\.0 \(settings of ' + [regex]::Escape($oth) + '\), set by the user setting\): C:\\dz_ci_other_folder') 'another signed-in account''s Trusted Location'
  Expect (RunT @{ KeyRoot = $user; MachineRoot = $mach; OtherKeyRoot = @("$root\nosuch") }) 'dz_trustloc_gap' 'the registry of .*nosuch could not be listed \(it is not loaded\)' 'another account whose registry is not loaded'
  Remove-Item -Path $oth -Recurse -Force
  # Trusted Documents: macros enabled for a download (malign) beside the
  # person's own spreadsheet (benign), one without the flag, one too short.
  New-Item -Path $tr -Force | Out-Null
  New-ItemProperty -Path $tr -Name '%USERPROFILE%/Documents/budget.xlsm' -Value (Rec 'b') -PropertyType Binary -Force | Out-Null
  New-ItemProperty -Path $tr -Name '%USERPROFILE%/Downloads/report.docx' -Value (Rec 'r' 1) -PropertyType Binary -Force | Out-Null
  New-ItemProperty -Path $tr -Name '%USERPROFILE%/Downloads/short.docm' -Value ([byte[]](1, 2, 3, 4, 5)) -PropertyType Binary -Force | Out-Null
  $r = RunT $k
  Expect $r '' '\[INFO\] Word 16\.0: macros were enabled in %USERPROFILE%/Documents/budget\.xlsm' 'macros enabled in the person''s own Documents'
  if ($r.Out -notmatch '1 other Trusted Documents record\(s\) enable editing') { throw "a record without the macros flag was not counted: $($r.Out)" }
  if ($r.Out -notmatch 'short\.docm could not be read \(its data is 5 bytes') { throw "a record too short was not named: $($r.Out)" }
  New-ItemProperty -Path $tr -Name '%USERPROFILE%/Downloads/invoice.docm' -Value (Rec 'i') -PropertyType Binary -Force | Out-Null
  Expect (RunT $k) 'dz_trustdoc_hit' '(?m)^\[WARNING\] Macros were enabled in a document from Downloads \(Word 16\.0\): %USERPROFILE%/Downloads/invoice\.docm \(trusted ' 'macros enabled in a download'
  Remove-Item -Path $tr -Recurse -Force
  # THE READ THAT FAILS: the Trusted Locations key denied.
  $denied = $false
  try {
    $acl = Get-Acl -Path $tl
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'QueryValues, EnumerateSubKeys', 'Deny')))
    Set-Acl -Path $tl -AclObject $acl
    try { $null = (Get-Item -LiteralPath $tl -ErrorAction Stop).GetSubKeyNames() } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    $r = RunT $k
    if ($r.Markers -notmatch 'dz_trustloc_gap' -or $r.Out -match '(?m)^\[OK\] No Office Trusted Location') { throw "a Trusted Locations key this account is denied was not a raised gap: [$($r.Markers)] $($r.Out)" }
    Write-Host 'office trust: a Trusted Locations key this account is denied is a raised gap, never an all-clear'
  } else { Write-Host '[ SKIP ] denied-key case not run: this account can still read the key through the deny rule; the self-test pins the judgement' }
  Write-Host 'office trust: a non-default Trusted Location and macros enabled in a download are the findings; Office''s defaults, a share Office ignores and the person''s own documents are not'
} finally {
  $ErrorActionPreference = 'Continue'
  try {
    $sk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\dz_ci_trust_$PID\u\Microsoft\Office\16.0\Word\Security\Trusted Locations", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::ChangePermissions)
    if ($sk) { $fresh = New-Object Security.AccessControl.RegistrySecurity; $fresh.SetAccessRuleProtection($false, $false); $sk.SetAccessControl($fresh); $sk.Close() }
  } catch { Write-Host ("cleanup: could not reset the test key's ACL ({0})" -f $_.Exception.Message) }
  Remove-Item -Path $root -Recurse -Force -EA SilentlyContinue
  if (Test-Path $root) { throw "the CI test key $root could not be removed" }
}
exit 0
