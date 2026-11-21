# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# Reads the runner's real Defender detection history, then plants a REAL
# detection: the industry-standard antivirus test file (harmless by design,
# detected by every engine) written into a scratch folder and scanned with a
# Defender file scan (MpCmdRun). Defender quarantines it. The scratch folder is removed
# in finally; the DETECTION RECORD stays in this runner's Defender history
# (Remove-MpThreat acts only on active threats), so no later step in this job
# may run the full audit and expect a clean Section 9. A Defender path
# exclusion this runner carries over the scratch folder is lifted for the
# scan and put back in finally. It lives in .github/ so it never
# reaches a USB stick. The test string is assembled for the reason
# tools\lint_amsi_text.ps1 gives.
$ErrorActionPreference = 'Stop'
$st = (.\tools\defender_detections_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'defender_detections_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 23) { throw "defender_detections_check self-test ran only $n case(s)" }
function RunD {
  $md = Join-Path $env:TEMP ("dz_ci_mpdet_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\defender_detections_check.ps1 -MarkerDir $md) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $sf = Join-Path $md 'dz_mpdet_state.txt'
    return @{ Out = $o; State = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' }); Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_state.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
# LIVE: the runner's own history, MEASURED and graded. An administrator can
# always read it, so a gap or a deferral here is a defect.
$r = RunD
Write-Host "MEASURED: the runner's Defender detection history reads $($r.State) [$($r.Markers)]"
if ($r.State -notmatch '^det=(none|removed|active|otherav),n=') { throw "the runner's detection history was not graded: $($r.State) [$($r.Markers)] $($r.Out)" }
$before = $r.State

$dir = "C:\dz_ci_mpdet_$PID"
$planted = $false
$lifted = @()
try {
  # GitHub's images may exclude whole drives from Defender; a scan of an
  # excluded folder finds nothing and would make this test vacuous.
  $ex = @()
  try { $ex = @((Get-MpPreference -ErrorAction Stop).ExclusionPath | Where-Object { $_ }) } catch { Write-Host ("MEASURED: Get-MpPreference did not answer: {0}" -f $_.Exception.Message) }
  Write-Host ("MEASURED: the runner's Defender path exclusions: [{0}]" -f ($ex -join '; '))
  foreach ($e in $ex) {
    $ep = ([string]$e).TrimEnd('\') + '\'
    if (($dir + '\').StartsWith($ep, [StringComparison]::OrdinalIgnoreCase)) {
      Remove-MpPreference -ExclusionPath $e -ErrorAction Stop; $lifted += $e
      Write-Host ("MEASURED: lifted the exclusion {0} for the scan" -f $e)
    }
  }
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  $f = Join-Path $dir 'dz_test_sample.com'
  $t = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR' + '-STANDARD' + '-ANTIVIRUS' + '-TEST-FILE!$H+H*'
  [IO.File]::WriteAllText($f, $t, [Text.Encoding]::ASCII)
  # MEASURE the engine before reading anything into an empty history: the
  # first run found nothing after a custom scan and could not say why.
  $cs = $null
  try { $cs = Get-MpComputerStatus -ErrorAction Stop } catch { Write-Host ("MEASURED: Get-MpComputerStatus did not answer: {0}" -f $_.Exception.Message) }
  if ($cs) { Write-Host ("MEASURED: AMRunningMode={0} AntivirusEnabled={1} AMServiceEnabled={2} RealTimeProtectionEnabled={3} signatures {4}" -f $cs.AMRunningMode, $cs.AntivirusEnabled, $cs.AMServiceEnabled, $cs.RealTimeProtectionEnabled, $cs.AntivirusSignatureVersion) }
  try { Write-Host ("MEASURED: exclusions after the lift: [{0}]" -f ((@((Get-MpPreference -ErrorAction Stop).ExclusionPath) | Where-Object { $_ }) -join '; ')) } catch { }
  # The plant: MpCmdRun with remediation ON, so Defender quarantines the file
  # and writes its record. It is the FIRST scan of each file: a measuring
  # scan (-DisableRemediation) used to run just before it, and on one run the
  # remediation scan then answered "was skipped" 30 ms later and left the
  # file in place -- the engine had only just scanned that file. So each
  # attempt scans a file nothing has scanned yet, and a skipped scan is
  # retried with a new file. Start-MpScan's custom scan was measured to leave
  # the file with no record at all.
  $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
  $mpExit = $null
  if (Test-Path -LiteralPath $mp) {
    foreach ($try in 1..3) {
      if ($try -gt 1) { Start-Sleep -Seconds 5; $f = Join-Path $dir ("dz_test_sample_{0}.com" -f $try); [IO.File]::WriteAllText($f, $t, [Text.Encoding]::ASCII) }
      $mpOut = & $mp -Scan -ScanType 3 -File $f 2>&1
      $txt = (@($mpOut) | Select-Object -Last 3) -join ' | '
      Write-Host ("MEASURED: MpCmdRun file scan with remediation, attempt {0}, exit {1}: {2}" -f $try, $LASTEXITCODE, $txt)
      if ($txt -match 'found [1-9]\d* threat' -or $LASTEXITCODE -eq 2) { $mpExit = 2; break }
    }
  } else { Write-Host ("MEASURED: {0} not found" -f $mp) }
  $hit = $null
  foreach ($i in 1..40) {
    $hit = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { @($_.Resources) -match [regex]::Escape($dir) })
    if ($hit.Count) { break }
    Start-Sleep -Seconds 3
  }
  $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117; StartTime = (Get-Date).AddMinutes(-10) } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match [regex]::Escape($dir) })
  Write-Host ("MEASURED: Defender events 1116/1117 naming the folder: {0}; the test file still exists: {1}" -f $ev.Count, (Test-Path -LiteralPath $f))
  $engineOff = (-not $cs) -or ($cs.AntivirusEnabled -ne $true) -or ([string]$cs.AMRunningMode -ne 'Normal') -or ($mpExit -ne 2)
  if (-not $hit -or -not $hit.Count) {
    if ($engineOff) {
      Write-Host '[ SKIP ] Defender''s engine did not detect the test file on this runner (the MEASURED lines above say why), so there is no real record to read; the self-test pins the judgement'
    } else {
      throw 'Defender''s engine detected the test file (MpCmdRun found a threat) but no record reached the detection history the check reads -- its live path would go untested'
    }
  } else {
    $planted = $true
    Write-Host ("MEASURED: Defender recorded the test file: status {0}, ActionSuccess {1}" -f $hit[0].ThreatStatusID, $hit[0].ActionSuccess)
    $r = RunD
    $line = @($r.Out -split "`n" | Where-Object { $_ -match [regex]::Escape($dir) })
    if (-not $line.Count) { throw "the planted detection is not named by its path: $($r.Out)" }
    $removed = (@(2, 3, 4, 6) -contains [int]$hit[0].ThreatStatusID) -and $hit[0].ActionSuccess
    $want = $(if ($removed) { 'dz_mpdet_warn' } else { 'dz_mpdet_crit' })
    if ($r.Markers -notmatch $want) { throw "the planted detection (status $($hit[0].ThreatStatusID), success $($hit[0].ActionSuccess)) did not raise [$want]: [$($r.Markers)] $($line -join ' | ')" }
    if ($removed -and $line[0] -notmatch '^\[WARNING\] Defender detected and removed ') { throw "a removed detection was not the WARNING wording: $($line[0])" }
    Write-Host ("defender detections: the planted test file reads {0} [{1}]" -f $r.State, $r.Markers)
  }
} catch {
  Write-Host ("::error::" + $_.Exception.Message); throw
} finally {
  $ErrorActionPreference = 'Continue'
  foreach ($e in $lifted) {
    try { Add-MpPreference -ExclusionPath $e -ErrorAction Stop; Write-Host ("put the exclusion {0} back" -f $e) } catch { Write-Host ("::warning::could not put the exclusion {0} back: {1}" -f $e, $_.Exception.Message) }
  }
  if ($planted) {
    foreach ($h in @(Get-MpThreatDetection -EA SilentlyContinue | Where-Object { @($_.Resources) -match [regex]::Escape($dir) })) {
      try { Remove-MpThreat -ThreatID $h.ThreatID -EA Stop } catch { Write-Host ("cleanup: Remove-MpThreat said: {0}" -f $_.Exception.Message) }
    }
  }
  Remove-Item -LiteralPath $dir -Recurse -Force -EA SilentlyContinue
  if (Test-Path -LiteralPath $dir) { throw "cleanup failed: the scratch folder $dir could not be removed" }
}
exit 0
