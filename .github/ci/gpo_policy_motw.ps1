# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   GPO RemoteSigned and Unrestricted with the Mark of the Web: the audit names the marked helpers and stops, and never hangs at a hidden prompt
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$sentinel = Join-Path $env:RUNNER_TEMP 'dz_ci_motw_planted.txt'
$w = Join-Path $env:RUNNER_TEMP 'dz_motw'
$zdir = Join-Path $env:RUNNER_TEMP 'dz_motw_zones'
$tools = Join-Path $w 'tools'
$had = Test-Path -LiteralPath $k
$prior = $null
if ($had) { $prior = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue }
$z3 = "[ZoneTransfer]`r`nZoneId=3"
$z2 = "[ZoneTransfer]`r`nZoneId=2"
function Set-Mark([string]$Path, [string]$Text) { Set-Content -LiteralPath $Path -Stream 'Zone.Identifier' -Value $Text }
# taskkill /T writes to stderr when part of the tree is already gone,
# and under Stop on 5.1 a native stderr line throws: Continue here.
function Stop-Tree([int]$Id) {
  $ErrorActionPreference = 'Continue'
  $null = @(& taskkill /PID $Id /T /F 2>&1)
  $global:LASTEXITCODE = 0
}
function Set-Policy([string]$P) {
  New-Item -Path $k -Force | Out-Null
  Set-Content -LiteralPath $sentinel -Value 'planted' -Encoding ASCII
  Set-ItemProperty -LiteralPath $k -Name EnableScripts -Value 1 -Type DWord
  Set-ItemProperty -LiteralPath $k -Name ExecutionPolicy -Value $P -Type String
}
# Which marks does the planted policy treat as downloaded? Each case
# runs in a child with -NonInteractive, so under Unrestricted a
# question fails at once instead of waiting on this step's stdin.
# exec_probe reads zones 0/1/2, a stream with no header and an empty
# stream as local, 3 and 4 as downloaded, and blocks on anything else.
$cases = [ordered]@{
  'zone0' = "[ZoneTransfer]`r`nZoneId=0"; 'zone1' = "[ZoneTransfer]`r`nZoneId=1"; 'zone2' = $z2
  'zone3' = $z3; 'zone4' = "[ZoneTransfer]`r`nZoneId=4"; 'zone5' = "[ZoneTransfer]`r`nZoneId=5"
  'noheader' = 'ZoneId=3'; 'empty' = ''
}
function Assert-Zones([string]$Policy) {
  $ErrorActionPreference = 'Continue'
  $ran = @(); $refused = @()
  foreach ($n in $cases.Keys) {
    $f = Join-Path $zdir ('dz_zone_{0}_{1}.ps1' -f $Policy, $n)
    Set-Content -LiteralPath $f -Value "'DZ_RAN'" -Encoding ASCII
    Set-Mark $f $cases[$n]
    $r = (& powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $f 2>&1 | Out-String)
    if ($r -match 'DZ_RAN') { $ran += $n } else { $refused += $n }
    if ($n -eq 'zone3') {
      $said = (@($r -split "`r?`n" | Where-Object { $_.Trim() }) | Select-Object -First 2) -join ' / '
      Write-Host ("{0}: PowerShell's words for a refused zone-3 script: {1}" -f $Policy, $said)
    }
  }
  $global:LASTEXITCODE = 0
  Write-Host ("{0}: Windows ran [{1}] and refused [{2}]" -f $Policy, ($ran -join ', '), ($refused -join ', '))
  if ($refused -notcontains 'zone3') { return $false }
  # The silent gap: a mark the probe reads as local that Windows refuses.
  foreach ($n in 'zone0', 'zone1', 'zone2', 'noheader', 'empty') {
    if ($refused -contains $n) { throw ("under {0} Windows refused a script marked '{1}', which exec_probe reads as local -- its verdict would be ok while that helper is refused: fix Get-MotwVerdict / Get-ZoneFromStreamText" -f $Policy, $n) }
  }
  if ($refused -notcontains 'zone4') { throw ("under {0} Windows ran a zone-4 script; exec_probe blocks on it -- the rule is not what Windows does" -f $Policy) }
  Write-Host ("{0}: a zone-5 script {1}; exec_probe blocks on that zone either way (fail closed)" -f $Policy, $(if ($ran -contains 'zone5') { 'ran' } else { 'was refused' }))
  return $true
}
function Invoke-Bat([string]$Bat, [string]$BatArgs, [switch]$NewConsole) {
  $ErrorActionPreference = 'Continue'
  $t0 = Get-Date
  if ($NewConsole) {
    # Its own console, as a person runs it: a prompt there waits on
    # real console input, so a hang would show as a timeout here.
    $p = Start-Process -FilePath 'cmd.exe' -ArgumentList ('/c {0} {1}' -f $Bat, $BatArgs) -WorkingDirectory $w -WindowStyle Hidden -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit(180000)) {
      Stop-Tree $p.Id
      throw ("{0} {1}: still running after 3 minutes -- the audit hung (a prompt nobody can see?)" -f $Bat, $BatArgs)
    }
    $rc = $p.ExitCode
  } else {
    Push-Location $w
    try { $null = @(& cmd /c ('{0} {1}' -f $Bat, $BatArgs) 2>&1 | ForEach-Object { "$_" }); $rc = $LASTEXITCODE } finally { Pop-Location }
  }
  $global:LASTEXITCODE = 0
  $rep = @(Get-ChildItem 'C:\SecurityAudit\SecurityReport_*.txt', (Join-Path $env:USERPROFILE 'SecurityAudit\SecurityReport_*.txt') -EA SilentlyContinue |
           Where-Object { $_.LastWriteTime -ge $t0 } | Sort-Object LastWriteTime -Descending) | Select-Object -First 1
  if (-not $rep) { throw ("{0} {1}: no report written -- the refusal must be declared in a report" -f $Bat, $BatArgs) }
  $text = [IO.File]::ReadAllText($rep.FullName)
  Write-Host ("--- {0} {1} (exit {2}) ---" -f $Bat, $BatArgs, $rc)
  Write-Host (($text -split "`r?`n" | Where-Object { $_ -match 'AUDIT NOT PERFORMED|Group Policy sets|\(zone \d\)|Mark of the Web|Under that policy|PowerShell refused|MachinePolicy|STATUS:' }) -join "`n")
  return @{ Rc = $rc; Text = $text }
}
function Assert-Blocked($r, [string]$Who) {
  if ($r.Rc -ne 1) { throw ("{0}: exit {1}, expected 1 -- a blind run must not exit as a completed audit" -f $Who, $r.Rc) }
  if ($r.Text -match '\[SECTION \d+/18 RESULT') { throw ("{0}: the audit reached a section verdict while helpers would be refused" -f $Who) }
  if ($r.Text -match 'CLEAN -- no issues detected') { throw ("{0}: a section read CLEAN on a run that could not run its checks" -f $Who) }
  if ($r.Text -notmatch 'STATUS: Nothing was audited') { throw ("{0}: the STATUS line does not say nothing was audited" -f $Who) }
}
function Assert-Named($r, [string]$Who) {
  foreach ($n in 'driver_audit', 'hosts_check') {
    if ($r.Text -notmatch ('(?m)^    tools\\{0}\.ps1 \(zone 3\)' -f $n)) { throw ("{0}: {1}.ps1 (zone 3) is not named" -f $Who, $n) }
  }
  if ($r.Text -match 'edr_presence') { throw ("{0}: the zone-2 helper was named -- trusted sites are local to PowerShell, so it runs" -f $Who) }
  if ($r.Text -match 'PowerShell refused to run a script file here') { throw ("{0}: the probe was refused -- it is unmarked here and must have run" -f $Who) }
}
try {
  New-Item -ItemType Directory -Path $zdir -Force | Out-Null
  # The checkout's own bytes (CRLF), so cmd runs the bats as it would
  # from a Windows checkout. robocopy: 1-7 are success codes.
  & robocopy . $w /E /XD .git /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -ge 8) { throw ("robocopy of the checkout failed with {0}" -f $LASTEXITCODE) }
  $global:LASTEXITCODE = 0
  $nPs1 = @(Get-ChildItem -LiteralPath $tools -Filter '*.ps1' -File | Where-Object { $_.Extension -eq '.ps1' }).Count

  # a. RemoteSigned, some helpers marked, the probe not.
  Set-Policy 'RemoteSigned'
  # The AllSigned step before this one shows a Group Policy plant takes
  # on this runner, so one that does not take here is a failure: a
  # skip would pass every case below having tested none of them.
  if (-not (Assert-Zones 'RemoteSigned')) { throw 'the Group Policy RemoteSigned policy did not take (a zone-3 script still ran under -ExecutionPolicy Bypass)' }
  Set-Mark (Join-Path $tools 'hosts_check.ps1') $z3
  Set-Mark (Join-Path $tools 'driver_audit.ps1') $z3
  Set-Mark (Join-Path $tools 'edr_presence.ps1') $z2
  foreach ($run in @(@{ Bat = 'doze_sec.bat'; Args = '-dev -readonly -noConsoleLog' }, @{ Bat = 'doze_sec_noAdmin.bat'; Args = '-dev -readonly -noAdmin -noConsoleLog' })) {
    $who = 'RemoteSigned, two helpers marked: ' + $run.Bat
    $r = Invoke-Bat $run.Bat $run.Args
    Assert-Blocked $r $who
    if ($r.Text -notmatch "\*\*\* AUDIT NOT PERFORMED -- 2 of this audit's helper scripts carry the Mark of the Web, and this machine's script policy refuses them \*\*\*") { throw ("{0}: no Mark of the Web banner counting the two zone-3 helpers" -f $who) }
    Assert-Named $r $who
    if ($r.Text -notmatch 'MachinePolicy = RemoteSigned') { throw ("{0}: the policy evidence is missing" -f $who) }
  }

  # b. RemoteSigned, the probe marked too: PowerShell refuses even the
  # probe, so cmd counts the marks. The zone-2 helper is not counted.
  Set-Mark (Join-Path $tools 'exec_probe.ps1') $z3
  $who = 'RemoteSigned, the probe marked too'
  $r = Invoke-Bat 'doze_sec.bat' '-dev -readonly -noConsoleLog'
  Assert-Blocked $r $who
  if ($r.Text -notmatch 'PowerShell refused to run a script file here') { throw ("{0}: the marked probe was not refused" -f $who) }
  $want = 'Mark of the Web: 3 of the {0} helper scripts in tools are marked as downloaded from the internet.' -f $nPs1
  if (-not $r.Text.Contains($want)) { throw ("{0}: expected the cmd count line '{1}'" -f $who, $want) }
  if ($r.Text -notmatch 'Under that policy the mark is why PowerShell would not run them') { throw ("{0}: the count is not named as the cause under RemoteSigned" -f $who) }

  # c. Unrestricted. Which marks prompt, then the hang itself: the
  # marked probe in its own console, without and with -NonInteractive.
  Set-Policy 'Unrestricted'
  if (-not (Assert-Zones 'Unrestricted')) { throw 'under Unrestricted a zone-3 script ran under -NonInteractive -- expected it to stop at the prompt and fail' }
  $hs = Join-Path $zdir 'hang_state.txt'
  $probeArgs = '-ExecutionPolicy Bypass -File "{0}" -StateFile "{1}" -MotwFile "{2}" -MotwLinesFile "{3}"' -f (Join-Path $tools 'exec_probe.ps1'), $hs, (Join-Path $zdir 'hang_motw.txt'), (Join-Path $zdir 'hang_lines.txt')
  Remove-Item -LiteralPath $hs -Force -EA SilentlyContinue
  $p = Start-Process -FilePath 'powershell.exe' -ArgumentList ('-NoProfile ' + $probeArgs) -WindowStyle Hidden -PassThru
  $null = $p.Handle
  $waited = -not $p.WaitForExit(20000)
  if ($waited) { Stop-Tree $p.Id }
  $ranAnyway = Test-Path -LiteralPath $hs
  Write-Host ("without -NonInteractive the marked probe {0}" -f $(if ($waited) { 'was still waiting after 20 s (killed): the prompt nobody sees' } elseif ($ranAnyway) { 'ran without asking' } else { 'exited within 20 s without running' }))
  Remove-Item -LiteralPath $hs -Force -EA SilentlyContinue
  $p = Start-Process -FilePath 'powershell.exe' -ArgumentList ('-NoProfile -NonInteractive ' + $probeArgs) -WindowStyle Hidden -PassThru
  $null = $p.Handle
  if (-not $p.WaitForExit(20000)) { Stop-Tree $p.Id; throw 'with -NonInteractive the marked probe was still running after 20 s' }
  if (Test-Path -LiteralPath $hs) { throw 'with -NonInteractive the marked probe RAN under Unrestricted -- expected the prompt to fail at once' }
  Write-Host 'with -NonInteractive the marked probe was refused at once (no state file)'
  # Every helper marked: the downloaded-ZIP case, run as a person runs
  # it (its own console, the console log on). threat_list_seed runs
  # before the probe and is marked too.
  foreach ($f in @(Get-ChildItem -LiteralPath $tools -Filter '*.ps1' -File)) { Set-Mark $f.FullName $z3 }
  $who = 'Unrestricted, every helper marked, own console'
  $r = Invoke-Bat 'doze_sec.bat' '-dev -readonly' -NewConsole
  Assert-Blocked $r $who
  if ($r.Text -notmatch 'PowerShell refused to run a script file here') { throw ("{0}: the marked probe was not refused" -f $who) }
  $want = 'Mark of the Web: {0} of the {0} helper scripts in tools are marked as downloaded from the internet.' -f $nPs1
  if (-not $r.Text.Contains($want)) { throw ("{0}: expected the cmd count line '{1}'" -f $who, $want) }
  if ($r.Text -notmatch 'Under that policy the mark is why PowerShell would not run them') { throw ("{0}: the count is not named as the cause under Unrestricted" -f $who) }
  if (-not $waited) { Write-Host '[ SKIP ] the hidden prompt did not wait on this runner, so this run does not prove -NonInteractive is what prevents the hang (the refusal itself is proven above)' }

  # d. Unrestricted, the probe and threat_list_seed unmarked, two
  # helpers marked zone 3 and one zone 2.
  foreach ($f in @(Get-ChildItem -LiteralPath $tools -Filter '*.ps1' -File)) { Remove-Item -LiteralPath $f.FullName -Stream 'Zone.Identifier' -EA SilentlyContinue }
  Set-Mark (Join-Path $tools 'hosts_check.ps1') $z3
  Set-Mark (Join-Path $tools 'driver_audit.ps1') $z3
  Set-Mark (Join-Path $tools 'edr_presence.ps1') $z2
  $who = 'Unrestricted, two helpers marked, own console'
  $r = Invoke-Bat 'doze_sec.bat' '-dev -readonly -noConsoleLog' -NewConsole
  Assert-Blocked $r $who
  if ($r.Text -notmatch "\*\*\* AUDIT NOT PERFORMED -- 2 of this audit's helper scripts carry the Mark of the Web, and this machine's script policy stops to ask before running them \*\*\*") { throw ("{0}: no Mark of the Web banner saying the policy stops to ask" -f $who) }
  Assert-Named $r $who
  if ($r.Text -notmatch 'MachinePolicy = Unrestricted') { throw ("{0}: the policy evidence is missing" -f $who) }
  Write-Host 'both bats name the marked helpers and stop under RemoteSigned and Unrestricted, and a fully marked copy stops instead of hanging'
} finally {
  if ($had) {
    foreach ($n in 'EnableScripts', 'ExecutionPolicy') {
      if ($prior -and ($prior.PSObject.Properties.Name -contains $n)) { Set-ItemProperty -LiteralPath $k -Name $n -Value $prior.$n }
      else { Remove-ItemProperty -LiteralPath $k -Name $n -EA SilentlyContinue }
    }
  } else { Remove-Item -LiteralPath $k -Recurse -Force -EA SilentlyContinue }
  Remove-Item -LiteralPath $sentinel -Force -EA SilentlyContinue
  Remove-Item -LiteralPath $w, $zdir -Recurse -Force -EA SilentlyContinue
}
# The last bat run returned 1 ON PURPOSE -- that is the assertion above passing.
exit 0
