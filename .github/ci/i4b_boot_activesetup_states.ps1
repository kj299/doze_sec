# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It creates throwaway HKCU keys (one with a deny ACL, one whose name holds a
# line break), a scratch folder under C:\ProgramData holding unsigned files,
# copies of signed programs and a junction, and it lets Windows try (and
# fail) to reach an address that routes nowhere; do not run it on a machine
# you use. It lives in .github/ so it never reaches a USB stick.
# Nothing here writes the real Session Manager or Active Setup keys: a
# BootExecute entry runs at the next boot.
#
# Group I4b through the real reader on Windows PowerShell 5.1 -- real disk,
# real Authenticode, real version resources, real links -- pointed at planted
# keys by the tool's CI-only hooks:
#   - MEASURED FIRST: the facts the rules lean on are printed before anything
#     is asserted (signer and built-in name of each known program);
#   - the runner's own BootExecute and Active Setup are graded, logged with
#     their raw commands, and raise no finding and no gap;
#   - [OK] is only a line Windows, Edge or Chrome keeps: ie4uinit, a known
#     rundll32 call, the same behind `cmd /D /C start`;
#   - [INFO], listed and not cleared: a signed line that is not on record,
#     another vendor's signed program, msiexec by product code, a stale entry
#     (quoted, and unquoted with a switch), an entry switched off;
#   - raised: a host behind `cmd /D /C start` with an unsigned DLL, text after
#     a rundll32 entry point, a Microsoft program with no Active Setup use, a
#     copied Microsoft program outside the Windows folder, cmd.exe under
#     another name, an unquoted path to an unsigned file with no .exe name, a
#     signed program in a folder users can write to, a path through a
#     junction (not followed), a network path (named, not opened -- and
#     measured: the run is not slowed by an address that routes nowhere), a
#     StubPath that is not text, a staged StubPath under its short name and
#     under its own (CRITICAL);
#   - a key name holding a line break cannot write a report line of its own;
#   - a component key this account may not read, and a Session Manager
#     stand-in that is not there, are raised gaps, never an all-clear.
# Every expectation is checked and reported together (lib\expect.ps1): one round
# shows every failure. A check this runner cannot stage is a declared [SKIP].
$ErrorActionPreference = 'Stop'
. .\.github\ci\lib\expect.ps1
function Skip([string]$What, [string]$Why) { Write-Host "[SKIP] $What -- $Why" }

$o = (& .\tools\boot_activesetup_check.ps1 -SelfTest) -join "`n"
Expect ($LASTEXITCODE -eq 0) 'boot_activesetup_check -SelfTest passes on Windows PowerShell 5.1' (($o -split "`r?`n" | Where-Object { $_ -match '^\[FAIL\]' }) -join "`n")
$nCases = @($o -split "`r?`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
Expect ($nCases -ge 300) "the self-test ran its cases on 5.1 (at least 300; $nCases ran)"

$scr = Join-Path $env:TEMP ("dz_ci_i4b_{0}" -f $PID)
$md = Join-Path $scr 'm'
# Unsigned payloads live OUTSIDE every staging folder (%TEMP% is one), so the
# rules under test are the signature rules, not the staging rule.
$pd = Join-Path $env:ProgramData ("dz_ci_i4b_{0}" -f $PID)
$sub = "Software\dz_ci_i4b_$PID"; $hk = "HKCU:\$sub"
$sys32 = Join-Path $env:SystemRoot 'System32'
$deniedKeys = @()
$junction = Join-Path $pd 'link'
New-Item -ItemType Directory -Path $md -Force | Out-Null
function Clear-M { Get-ChildItem -LiteralPath $md -Filter 'dz_*' -EA SilentlyContinue | Remove-Item -Force }
function Has([string]$n) { Test-Path (Join-Path $md "dz_$n.txt") }
function Sev([string]$n) { if (Has $n) { (Get-Content -LiteralPath (Join-Path $md "dz_$n.txt") -TotalCount 1).Trim() } else { '(no marker)' } }
function Plant([string]$Name, [string]$Stub, [string]$Root = 'AS') {
  New-Item -Path "$hk\$Root\$Name" -Force | Out-Null
  New-ItemProperty -Path "$hk\$Root\$Name" -Name StubPath -PropertyType String -Value $Stub -Force | Out-Null
}
function LineOf([string]$Text, [string]$Name) { (($Text -split "`r?`n") | Where-Object { $_ -match [regex]::Escape("'$Name") }) -join "`n" }
function Deny-Key([string]$Rel) {
  $a = Get-Acl -Path "HKCU:\$Rel"; $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $a.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me, 'ReadKey', 'Deny')))
  $script:deniedKeys += $Rel; Set-Acl -Path "HKCU:\$Rel" -AclObject $a
}
# The tool, with whatever it wrote to the error stream kept apart: an error
# the tool did not expect must not pass unseen.
$script:toolErrors = @()
function Run-Tool([hashtable]$With) {
  $all = @(& .\tools\boot_activesetup_check.ps1 @With 2>&1)
  $script:toolErrors = @($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
  return ((@($all | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) | ForEach-Object { [string]$_ }) -join "`n")
}
function Signer([string]$Path) {
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $Path
    $cn = [string]$s.SignerCertificate.Subject
    if ($cn -match '(?:^|,\s*)CN=(.+?)(?:,\s*[A-Za-z]+=|$)') { $cn = $Matches[1].Trim().Trim('"') }
    return @{ Status = [string]$s.Status; CN = $cn }
  } catch { return @{ Status = 'error: ' + $_.Exception.Message; CN = '' } }
}

try {
  # ---- MEASURED FIRST: what the rules lean on, before anything is asserted ----
  Write-Host '---- MEASURED: signer and built-in (version resource) name of the known programs on this runner ----'
  $stock = @()
  foreach ($d in @($sys32, (Join-Path $env:SystemRoot 'SysWOW64'))) { foreach ($n in 'ie4uinit.exe', 'unregmp2.exe', 'rundll32.exe', 'regsvr32.exe', 'msiexec.exe', 'cmd.exe', 'poqexec.exe', 'autofmt.exe', 'iesetup.dll', 'mscories.dll', 'iedkcs32.dll', 'themeui.dll', 'shell32.dll') { $stock += (Join-Path $d $n) } }
  $stock += @(Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\*\Installer\setup.exe'), (Join-Path $env:ProgramFiles 'Google\Chrome\Application\*\Installer\chrmstp.exe'), (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'), (Join-Path $env:ProgramFiles 'Windows Mail\WinMail.exe') -EA SilentlyContinue | ForEach-Object { $_.FullName })
  foreach ($f in $stock) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Write-Host ("  {0}: not on this runner" -f $f); continue }
    $sg = Signer $f
    $on = ''
    try { $on = [string][System.Diagnostics.FileVersionInfo]::GetVersionInfo($f).OriginalFilename } catch { $on = 'error: ' + $_.Exception.Message }
    Write-Host ("  {0}: {1}, signed by '{2}', built as '{3}', attributes {4}" -f $f, $sg.Status, $sg.CN, $on, [string][IO.File]::GetAttributes($f))
  }
  Write-Host '---- end of measured facts ----'

  # ---- the runner itself ----
  Clear-M
  $o = Run-Tool @{ MarkerDir = $md }
  Write-Host '---- MEASURED: the runner''s own BootExecute and Active Setup, as graded (raw command after "<-") ----'
  Write-Host $o
  Write-Host '---- end of the runner''s own entries ----'
  Expect ($script:toolErrors.Count -eq 0) 'the run on the runner''s own keys wrote nothing to the error stream' (($script:toolErrors | ForEach-Object { [string]$_ }) -join "`n")
  $raised = ($o -split "`r?`n" | Where-Object { $_ -match '^\[(WARNING|CRITICAL)\]' }) -join "`n"
  foreach ($n in 'bootexec', 'bootexec_gap', 'activesetup', 'activesetup_gap') {
    Expect (-not (Has $n)) "the runner's own run does not raise $n (a benign Windows entry graded as a finding, or a read that failed)" $raised
  }
  Expect (Has 'bootas_done') 'the runner run wrote its done marker'
  # Any stock autochk form (the runner's is 'autocheck autochk /q /v *'), and
  # the all-clear having graded at least one entry -- never an exact value.
  Expect ($o -match "(?m)^\[OK\] BootExecute: autocheck autochk\b[^\r\n]*\(Windows' boot-time disk check, the stock entry\)\r?$") "the runner's BootExecute is read as Windows' own autochk entry" (($o -split "`r?`n" | Where-Object { $_ -match 'BootExecute' }) -join "`n")
  Expect ($o -match "(?m)^\[OK\] BootExecute and its sibling values hold only Windows' own entries \([1-9]\d* graded\)\.") 'the BootExecute all-clear graded at least one entry'
  Expect ($o -match '(?m)^\[OK\] Active Setup: ([1-9]\d*) StubPath command\(s\) graded, none suspicious\.') "the runner's Active Setup StubPaths were graded (not zero: the check looked at something)"
  Expect ($o -match "(?m)^\[OK\] Active Setup '[^']+': .+ \(signed by [^)]+\) <- \S") 'an [OK] Active Setup line carries the raw command, so this log holds measured values'
  # Each line is a tagged line, a section header, an indented note or empty:
  # nothing else may reach the report.
  $stray = @($o -split "`r?`n" | Where-Object { $_ -and $_ -notmatch '^(\[(OK|INFO|WARNING|CRITICAL)\] |--- \[T1547\.|  )' })
  Expect ($stray.Count -eq 0) 'every line the tool printed is a tagged line, a section header or an indented note' ($stray -join "`n")

  # ---- planted Session Manager stand-in, the three tiers, hostile lines ----
  New-Item -ItemType Directory -Path (Join-Path $pd 'Common Files') -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $pd 'real') -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $pd 'Downloads') -Force | Out-Null
  Set-Content -LiteralPath (Join-Path $pd 'evil.dll') -Value 'not a signed file' -Encoding ASCII
  Set-Content -LiteralPath (Join-Path $pd 'evil.exe') -Value 'not a signed file' -Encoding ASCII
  Set-Content -LiteralPath (Join-Path $pd 'Common Files\cache.dat') -Value 'not a signed file' -Encoding ASCII
  Set-Content -LiteralPath (Join-Path $pd 'Downloads\x.exe') -Value 'not a signed file' -Encoding ASCII
  Copy-Item -LiteralPath (Join-Path $sys32 'ie4uinit.exe') -Destination (Join-Path $pd 'ie4uinit.exe')
  Copy-Item -LiteralPath (Join-Path $sys32 'ie4uinit.exe') -Destination (Join-Path $pd 'real\ie4uinit.exe')
  Copy-Item -LiteralPath (Join-Path $sys32 'cmd.exe') -Destination (Join-Path $pd 'helper.exe')
  $hs = Signer (Join-Path $pd 'helper.exe'); $ho = ''
  try { $ho = [string][System.Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $pd 'helper.exe')).OriginalFilename } catch {}
  Write-Host ("MEASURED: a copy of cmd.exe named helper.exe outside the Windows folder: {0}, signed by '{1}', built as '{2}'" -f $hs.Status, $hs.CN, $ho)
  New-Item -Path "$hk\SM" -Force | Out-Null
  New-ItemProperty -Path "$hk\SM" -Name BootExecute -PropertyType MultiString -Value @('autocheck autochk *', 'autocheck dz_ci_native', 'autocheck autofmt \??\Q: /FS:NTFS /Q') -Force | Out-Null
  New-ItemProperty -Path "$hk\SM" -Name SetupExecute -PropertyType MultiString -Value @($sys32 + '\poqexec.exe /display_progress \SystemRoot\WinSxS\pending.xml') -Force | Out-Null
  New-Item -Path "$hk\SMB" -Force | Out-Null
  New-ItemProperty -Path "$hk\SMB" -Name BootExecute -PropertyType Binary -Value ([byte[]](97, 0, 98, 0, 0, 0)) -Force | Out-Null

  $gone = "dz_ci_gone_$PID"
  $ok = @{
    '{dz-ie}'     = ($sys32 + '\ie4uinit.exe -UserConfig')
    '{dz-wrapok}' = ($sys32 + '\cmd.exe /D /C start ' + $sys32 + '\ie4uinit.exe -ClearIconCache')
  }
  if (Test-Path -LiteralPath (Join-Path $sys32 'iesetup.dll')) { $ok['{dz-ok}'] = ('"' + $sys32 + '\rundll32.exe" "' + $sys32 + '\iesetup.dll",IEHardenUser') }
  else { Skip 'a known rundll32 call reads [OK]' 'iesetup.dll is not on this runner' }
  $info = @(
    @('{dz-unknown}', ('"' + $sys32 + '\rundll32.exe" "' + $sys32 + '\shell32.dll",Control_RunDLL'), 'validly signed, but not a line this check has on record for Windows, Edge or Chrome: listed, not cleared', 'a signed rundll32 call that is not on record'),
    @('{dz-switch}',  ($sys32 + '\ie4uinit.exe -dz_ci_unknown'), 'validly signed, but not a line this check has on record', 'a known program with a switch that is not on record'),
    @('{dz-msi}',     'msiexec.exe /fup {11111111-2222-3333-4444-555555555555} /qn', 'by its product code .* is not traced by this check', 'msiexec repairing by product code'),
    @('{dz-stale1}',  ('"' + $env:ProgramFiles + '\' + $gone + '\gone.exe" /x'), 'gone\.exe, which is not on disk -- a stale entry', 'a quoted program that is gone from Program Files'),
    @('{dz-stale2}',  ($sys32 + '\' + $gone + '.exe /x'), ([regex]::Escape($gone) + '\.exe, which is not on disk -- a stale entry'), 'an unquoted program that is gone from System32, followed by a switch (every longer reading of the line is ruled out on the real disk)'))
  $chrome = Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'
  $vendorOk = $false
  if (Test-Path -LiteralPath $chrome -PathType Leaf) { $cs = Signer $chrome; $vendorOk = ($cs.Status -eq 'Valid' -and $cs.CN -and $cs.CN -notmatch '^Microsoft\b') }
  if ($vendorOk) {
    $info += ,@('{dz-vendor}', ('"' + $chrome + '" --no-first-run'), "\(signed by [^)]+\), another vendor's program", "another vendor's signed program under Program Files")
    Copy-Item -LiteralPath $chrome -Destination (Join-Path $pd 'dz_vendor_copy.exe')
  } else { Skip "another vendor's signed program is [INFO] under Program Files and a WARNING in a folder users can write to" 'no validly signed non-Microsoft program was found at the Chrome path on this runner' }

  foreach ($k in $ok.Keys) { Plant $k $ok[$k] }
  foreach ($i in $info) { Plant $i[0] $i[1] }
  New-Item -Path "$hk\AS\{dz-off}" -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\{dz-off}" -Name StubPath -PropertyType String -Value 'C:\Users\Public\dz_ci_off.exe' -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\{dz-off}" -Name IsInstalled -PropertyType DWord -Value 0 -Force | Out-Null
  Clear-M
  $o = Run-Tool @{ MarkerDir = $md; CiSessionKey = "$hk\SM"; CiActiveSetupRoots = @("$hk\AS") }
  Write-Host '---- the planted benign entries and the Session Manager stand-in, as graded ----'
  Write-Host $o
  Expect ($script:toolErrors.Count -eq 0) 'the planted benign run wrote nothing to the error stream' (($script:toolErrors | ForEach-Object { [string]$_ }) -join "`n")
  $bl = ($o -split "`r?`n" | Where-Object { $_ -match 'BootExecute|SetupExecute' }) -join "`n"
  Expect ((Sev 'bootexec') -eq 'WARNING') 'the planted boot entries raise a WARNING (none is unsigned or staged)' (Sev 'bootexec')
  Expect ($o -match "(?m)^\[WARNING\] BootExecute entry 'autocheck dz_ci_native' names .*dz_ci_native\.exe, which is not on disk") 'a BootExecute entry beside autochk is raised' $bl
  if (Test-Path -LiteralPath (Join-Path $sys32 'autofmt.exe')) { Expect ($o -match "(?m)^\[WARNING\] BootExecute entry 'autocheck autofmt [^\r\n]*autofmt\.exe before Windows starts, as SYSTEM -- signed by Microsoft[^\r\n]*but it is not the disk check") "Microsoft's own autofmt in BootExecute is a WARNING, never INFO" $bl }
  else { Skip "Microsoft's own autofmt in BootExecute is a WARNING" 'autofmt.exe is not on this runner' }
  if (Test-Path -LiteralPath (Join-Path $sys32 'poqexec.exe')) { Expect ($o -match "(?m)^\[WARNING\] SetupExecute entry [^\r\n]*poqexec\.exe before Windows starts[^\r\n]*Windows servicing can leave a program here while an update waits for a restart: restart, then run the audit again") "Windows servicing's poqexec in SetupExecute is a WARNING that says to restart and run the audit again" $bl }
  else { Skip "poqexec in SetupExecute is a WARNING that says to restart" 'poqexec.exe is not on this runner' }
  Expect ($o -notmatch "(?m)^\[OK\] BootExecute and its sibling") 'no BootExecute all-clear beside a raised entry' $bl
  Expect (-not (Has 'activesetup')) 'the [OK] and [INFO] entries alone raise no Active Setup finding (real Authenticode)' (($o -split "`r?`n" | Where-Object { $_ -match '^\[(WARNING|CRITICAL)\] Active Setup' }) -join "`n")
  if ($ok.ContainsKey('{dz-ok}')) { Expect ($o -match "(?m)^\[OK\] Active Setup '\{dz-ok\}': .*\\iesetup\.dll \(signed by Microsoft") 'a known rundll32 call (iesetup.dll,IEHardenUser) is [OK] on the DLL' (LineOf $o '{dz-ok}') }
  Expect ($o -match "(?m)^\[OK\] Active Setup '\{dz-ie\}': .*\\ie4uinit\.exe \(signed by Microsoft") 'ie4uinit -UserConfig is [OK]' (LineOf $o '{dz-ie}')
  Expect ($o -match "(?m)^\[OK\] Active Setup '\{dz-wrapok\}': .*\\ie4uinit\.exe \(signed by Microsoft") 'cmd /D /C start <full path>\ie4uinit.exe is graded as ie4uinit: [OK]' (LineOf $o '{dz-wrapok}')
  foreach ($i in $info) {
    Expect ($o -match ("(?m)^\[INFO\] Active Setup '" + [regex]::Escape($i[0]) + "' [^\r\n]*" + $i[2])) ("listed, not cleared and not raised: " + $i[3]) (LineOf $o $i[0])
  }
  Expect ($o -match "(?m)^\[INFO\] Active Setup '\{dz-off\}' is switched off \(IsInstalled=0\)") 'an entry with a DWORD IsInstalled of 0 is [INFO]: Windows does not run it' (LineOf $o '{dz-off}')

  Clear-M
  $o2 = Run-Tool @{ MarkerDir = $md; CiSessionKey = "$hk\SMB"; CiActiveSetupRoots = @("$hk\AS") }
  $bl2 = @($o2 -split "`r?`n" | Where-Object { $_ -match 'BootExecute' -and $_ -notmatch '^--- ' })
  Expect ((Sev 'bootexec') -eq 'WARNING' -and $bl2.Count -eq 1 -and $bl2[0] -match '^\[WARNING\] BootExecute entry is not text: the value is stored as Binary') 'a BootExecute stored as bytes is ONE WARNING that it is not text' ($bl2 -join "`n")

  # ---- hostile lines ----
  $hostile = @(
    @('{dz-wrap}',    ($sys32 + '\cmd.exe /D /C start ' + $sys32 + '\rundll32.exe ' + $pd + '\evil.dll,Run'), 'WARNING', 'hands rundll32\.exe a file that is not validly signed', 'a host behind cmd /D /C start with an unsigned DLL'),
    @('{dz-tail}',    ('"' + $sys32 + '\rundll32.exe" "' + $sys32 + '\shell32.dll",Control_RunDLL ' + $pd + '\evil.dll'), 'WARNING', 'hands rundll32\.exe something this check cannot account for', 'text after a rundll32 entry point'),
    @('{dz-hand}',    ($sys32 + '\conhost.exe --headless ' + $pd + '\evil.exe'), 'WARNING', 'conhost\.exe, a Microsoft program this check knows no Active Setup use for', 'a Microsoft program with no Active Setup use, whatever it is handed'),
    @('{dz-tool}',    ($sys32 + '\reg.exe add HKCU\Software\dz_ci_never /v x /d 1 /f'), 'WARNING', 'reg\.exe, a Microsoft program this check knows no Active Setup use for', 'reg.exe (what a managed PC might use: named, for a person to adjudicate)'),
    @('{dz-dat}',     ($pd + '\Common Files\cache.dat -k'), 'WARNING', 'cache\.dat at every user.s next sign-in, and it is not validly signed', 'an unquoted path with a space to an unsigned file with no .exe name'),
    @('{dz-reloc}',   ($pd + '\ie4uinit.exe -BaseSettings'), 'WARNING', 'a Microsoft program this check knows no Active Setup use for.*outside the Windows and Program Files folders of the system drive', 'a copied Windows program outside the Windows folder (catalog-signed, so still validly signed)'),
    @('{dz-renamed}', ('"' + $pd + '\helper.exe" /c echo hi'), 'WARNING', "which is Microsoft's cmd\.exe under another name", 'cmd.exe copied under another name (read from its version resource)'),
    @('{dz-link}',    ($pd + '\link\ie4uinit.exe -UserConfig'), 'WARNING', 'names a program whose path runs through a link or a placeholder \([^)]*\\link\) -- not followed', 'a program reached through a junction is named, never followed'),
    @('{dz-net}',     '\\127.0.0.1\dz_ci_none\x.exe /s', 'WARNING', 'not a plain file on a local fixed drive \(\\\\127\.0\.0\.1\\dz_ci_none\\x\.exe\) -- not opened', 'a network path is named, not opened'),
    @('{dz-evil}',    'C:\Users\Public\dz_ci_evil.exe /s', 'CRITICAL', 'StubPath runs C:\\Users\\Public\\dz_ci_evil\.exe from a staging path', 'a StubPath in C:\Users\Public'),
    @('{dz-dots}',    'C:\Users\.\Public\dz_ci_evil.exe /s', 'CRITICAL', 'StubPath runs C:\\Users\\Public\\dz_ci_evil\.exe from a staging path', 'the same folder spelled C:\Users\.\Public'))
  if ($vendorOk) { $hostile += ,@('{dz-side}', ('"' + $pd + '\dz_vendor_copy.exe" --no-first-run'), 'WARNING', 'dz_vendor_copy\.exe \(signed by [^)]+\) from a folder a standard user may be able to write to', "another vendor's signed program in a folder users can write to") }
  # A junction to a folder of this script's own making (never to a system
  # folder: an old PowerShell deletes THROUGH a junction). The redirection is
  # cmd's: under 'Stop', PowerShell 5.1 turns a native program's error text
  # into an exception. ($pd holds no space.)
  $jOut = (& cmd.exe /c "mklink /J $junction $pd\real 2>&1" | Out-String).Trim()
  $linkOk = ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath (Join-Path $junction 'ie4uinit.exe')))
  if (-not $linkOk) { Skip 'a program reached through a junction is named, never followed' ("the junction could not be made: " + $jOut); $hostile = @($hostile | Where-Object { $_[0] -ne '{dz-link}' }) }
  # The short (8.3) name of a staging folder: nothing in the text says
  # Downloads; the real path does.
  $short = ''
  try { $short = [string](New-Object -ComObject Scripting.FileSystemObject).GetFolder((Join-Path $pd 'Downloads')).ShortPath } catch { $short = '' }
  if ($short -and $short -notmatch '(?i)\\Downloads$') { $hostile += ,@('{dz-short}', ($short + '\x.exe'), 'CRITICAL', 'StubPath runs [^\r\n]*\\Downloads\\x\.exe from a staging path', ("a staging folder under its short name ($short)")) }
  else { Skip 'a staging folder under its short (8.3) name is CRITICAL' ("this volume gave no short name for the folder (got '$short')") }
  foreach ($h in $hostile) { Plant $h[0] $h[1] }
  New-Item -Path "$hk\AS\{dz-kind}" -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\{dz-kind}" -Name StubPath -PropertyType Binary -Value ([Text.Encoding]::Unicode.GetBytes($pd + '\evil.exe')) -Force | Out-Null
  New-Item -Path "$hk\AS\{dz-offsz}" -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\{dz-offsz}" -Name StubPath -PropertyType String -Value 'C:\Users\Public\dz_ci_offsz.exe' -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\{dz-offsz}" -Name IsInstalled -PropertyType String -Value '0' -Force | Out-Null
  Clear-M
  $o = Run-Tool @{ MarkerDir = $md; CiSessionKey = "$hk\SM"; CiActiveSetupRoots = @("$hk\AS") }
  Write-Host '---- the planted entries, as graded ----'
  Write-Host (($o -split "`r?`n" | Where-Object { $_ -match "Active Setup '\{dz-" }) -join "`n")
  Expect ($script:toolErrors.Count -eq 0) 'the hostile run wrote nothing to the error stream' (($script:toolErrors | ForEach-Object { [string]$_ }) -join "`n")
  foreach ($h in $hostile) {
    $rx = '(?m)^\[' + $h[2] + "\] Active Setup '" + [regex]::Escape($h[0]) + "' (StubPath|runs|names) [^\r\n]*" + $h[3]
    Expect ($o -match $rx) ("hostile: " + $h[4] + " is raised " + $h[2]) (LineOf $o $h[0])
  }
  Expect ($o -match "(?m)^\[WARNING\] Active Setup '\{dz-kind\}' StubPath is not text: the value is stored as Binary") 'a StubPath stored as bytes is a WARNING that it is not text' (LineOf $o '{dz-kind}')
  Expect ($o -match "(?m)^\[CRITICAL\] Active Setup '\{dz-offsz\}' StubPath runs C:\\Users\\Public\\dz_ci_offsz\.exe from a staging path") 'an IsInstalled of "0" stored as text does not switch an entry off: it is graded (CRITICAL)' (LineOf $o '{dz-offsz}')
  Expect ((Sev 'activesetup') -eq 'CRITICAL') 'the Active Setup marker carries the highest severity printed (CRITICAL)' (Sev 'activesetup')
  foreach ($k in $ok.Keys) {
    Expect ($o -match ("(?m)^\[OK\] Active Setup '" + [regex]::Escape($k) + "': ")) "the known line $k is still [OK] beside the hostile ones" (LineOf $o $k)
  }
  $okLines = @($o -split "`r?`n" | Where-Object { $_ -match "^\[OK\] Active Setup '" })
  Expect ($okLines.Count -eq $ok.Count) "[OK] was printed for the known lines and for nothing else ($($ok.Count) expected)" ($okLines -join "`n")
  $stray = @($o -split "`r?`n" | Where-Object { $_ -and $_ -notmatch '^(\[(OK|INFO|WARNING|CRITICAL)\] |--- \[T1547\.|  )' })
  Expect ($stray.Count -eq 0) 'every line of the hostile run is a tagged line, a section header or an indented note' ($stray -join "`n")

  # ---- a key name holding a line break cannot write a report line ----
  $forged = "{dz-lf}`r`n[OK] Active Setup: 9 StubPath command(s) graded, none suspicious."
  $lfMade = $false
  try {
    $fk = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("$sub\ASLF\$forged")
    $fk.SetValue('StubPath', ($pd + "\evil.exe`r`n[OK] forged"), [Microsoft.Win32.RegistryValueKind]::String); $fk.Close(); $lfMade = $true
  } catch { Skip 'a key name holding a line break cannot write a report line' ("the registry refused the name: " + $_.Exception.Message) }
  if ($lfMade) {
    Clear-M
    $o3 = Run-Tool @{ MarkerDir = $md; CiSessionKey = "$hk\SM"; CiActiveSetupRoots = @("$hk\ASLF") }
    $l3 = @($o3 -split "`r?`n" | Where-Object { $_ -match 'Active Setup' -and $_ -notmatch '^(--- |  )' })
    Expect ($l3.Count -eq 1 -and $l3[0] -match "^\[WARNING\] Active Setup '\{dz-lf\} \[OK\] Active Setup: 9 " -and @($o3 -split "`r?`n" | Where-Object { $_ -match '^\[OK\] (Active Setup: 9|forged)' }).Count -eq 0) 'a key name and a StubPath holding line breaks stay on ONE raised line: no forged [OK] line' ($o3)
  }

  # ---- a network path is not opened: measured, not only worded ----
  # 192.0.2.1 (TEST-NET-1) routes nowhere, so anything that opens a path on
  # it waits for the connection to time out. The control shows how long that
  # is on this runner; the tool, handed the same path, must not wait.
  New-Item -Path "$hk\ASNET" -Force | Out-Null
  Plant '{dz-net2}' '\\192.0.2.1\dz_ci_none\x.exe /s' 'ASNET'
  Plant '{dz-net3}' ('"' + $sys32 + '\rundll32.exe" \\192.0.2.1\dz_ci_none\x.dll,Run') 'ASNET'
  Clear-M
  $swT = [Diagnostics.Stopwatch]::StartNew()
  $o4 = Run-Tool @{ MarkerDir = $md; CiSessionKey = "$hk\SM"; CiActiveSetupRoots = @("$hk\ASNET") }
  $swT.Stop()
  $swC = [Diagnostics.Stopwatch]::StartNew()
  try { [void](Test-Path -LiteralPath '\\192.0.2.1\dz_ci_none\x.exe') } catch {}
  $swC.Stop()
  Write-Host ("MEASURED: opening \\192.0.2.1\... took {0:n1} s on this runner; the tool's run over two entries naming it took {1:n1} s" -f $swC.Elapsed.TotalSeconds, $swT.Elapsed.TotalSeconds)
  Expect (@($o4 -split "`r?`n" | Where-Object { $_ -match "^\[WARNING\] Active Setup '\{dz-net[23]\}' StubPath [^\r\n]*not a plain file on a local fixed drive" }).Count -eq 2) 'both entries naming the unreachable network path are raised as not opened' (($o4 -split "`r?`n" | Where-Object { $_ -match 'dz-net' }) -join "`n")
  if ($swC.Elapsed.TotalSeconds -ge 8) { Expect ($swT.Elapsed.TotalSeconds -lt ($swC.Elapsed.TotalSeconds - 4)) ("the tool did not wait on the network path (one open costs {0:n1} s here; the whole run took {1:n1} s)" -f $swC.Elapsed.TotalSeconds, $swT.Elapsed.TotalSeconds) }
  else { Skip 'the tool is measured not to wait on a network path' ("opening it fails within {0:n1} s on this runner, too fast to tell an attempt from none" -f $swC.Elapsed.TotalSeconds) }

  # ---- gaps ----
  New-Item -Path "$hk\AS\{dz-deny}" -Force | Out-Null
  New-ItemProperty -Path "$hk\AS\{dz-deny}" -Name StubPath -PropertyType String -Value 'C:\Users\Public\hidden.exe' -Force | Out-Null
  Deny-Key "$sub\AS\{dz-deny}"
  Clear-M
  $o = Run-Tool @{ MarkerDir = $md; CiSessionKey = "$hk\NoSuchSM"; CiActiveSetupRoots = @("$hk\AS") }
  Expect ((Has 'activesetup_gap') -and $o -match 'Active Setup check NOT performed for 1 component\(s\) under .* that could not be read: \{dz-deny\}') 'a component key this account may not read is a raised gap naming it' (($o -split "`r?`n" | Where-Object { $_ -match 'NOT performed' }) -join "`n")
  Expect ((Has 'bootexec_gap') -and $o -notmatch "(?m)^\[OK\] BootExecute and its sibling") 'a Session Manager key that is not there is a raised gap, never the all-clear' (($o -split "`r?`n" | Where-Object { $_ -match 'BootExecute' }) -join "`n")
  Expect (Has 'bootas_done') 'the gap run wrote its done marker'
} finally {
  foreach ($rel in $deniedKeys) {
    try {
      $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($rel, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]'ReadPermissions, ChangePermissions')
      $a = $k.GetAccessControl()
      foreach ($r in @($a.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Deny' })) { [void]$a.RemoveAccessRuleSpecific($r) }
      $k.SetAccessControl($a); $k.Close()
    } catch { Write-Host "registry undeny failed for ${rel}: $($_.Exception.Message)" }
  }
  # Through .NET: a key whose name holds a line break is not something the
  # registry provider can be trusted to walk.
  try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($sub, $false) } catch { Write-Host "registry cleanup failed: $($_.Exception.Message)" }
  Remove-Item -LiteralPath $scr -Recurse -Force -EA SilentlyContinue
  # The junction first, by itself, and nothing below $pd is deleted while it
  # is still there.
  if (Test-Path -LiteralPath $junction) { & cmd.exe /c "rmdir $junction 2>&1" | Out-Null }
  if (-not (Test-Path -LiteralPath $junction)) { Remove-Item -LiteralPath $pd -Recurse -Force -EA SilentlyContinue }
  Expect (-not (Test-Path -LiteralPath $hk)) "cleanup removed $hk"
  Expect (-not (Test-Path -LiteralPath $scr)) "cleanup removed $scr"
  Expect (-not (Test-Path -LiteralPath $junction)) "cleanup removed the junction $junction"
  Expect (-not (Test-Path -LiteralPath $pd)) "cleanup removed $pd"
}
Complete-Expectations 'the I4b BootExecute and Active Setup step'
