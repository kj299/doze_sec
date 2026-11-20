# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# Reads the runner's real Defender detection history, then plants a REAL
# detection: the industry-standard antivirus test file (harmless by design,
# detected by every engine) written into a scratch folder and scanned with a
# Defender custom scan. Defender quarantines it. The scratch folder is removed
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
  Start-MpScan -ScanType CustomScan -ScanPath $dir -ErrorAction Stop
  $hit = $null
  foreach ($i in 1..20) {
    $hit = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { @($_.Resources) -match [regex]::Escape($dir) })
    if ($hit.Count) { break }
    Start-Sleep -Seconds 3
  }
  if (-not $hit -or -not $hit.Count) {
    throw 'Defender recorded no detection for the test file after a custom scan of a folder no exclusion covers -- the live path of the check would go untested'
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
