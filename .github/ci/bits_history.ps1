# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   bits_history.ps1 -SelfTest + the runner's real channel and a real planted record
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
$out = (.\tools\bits_history.ps1 -SelfTest) -join "`n"
Write-Host $out
if ($LASTEXITCODE -ne 0) { throw 'bits_history self-test failed' }
$n = @($out -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 72) { throw "bits_history self-test ran only $n case(s)" }

# THE RUNNER'S REAL CHANNEL, which is the benign twin at scale: a
# windows-latest image has done Windows Update and browser-updater
# transfers, all of them to NAMED hosts from programs under Program
# Files. None of that may raise, and the check must say what it
# covered rather than going quiet.
$md = Join-Path $env:TEMP ("dz_bh_live_{0}" -f $PID)
$live = (.\tools\bits_history.ps1 -MarkerDir $md) -join "`n"
Write-Host $live
if ($live -match 'Exception|ParserError|is not recognized') { throw "bits_history errored on the live channel: $live" }
foreach ($m in @('dz_bitshist.txt', 'dz_bitshist_up.txt', 'dz_bitshist_gap.txt')) {
  if (Test-Path (Join-Path $md $m)) { throw ("{0} written on a clean runner: {1}" -f $m, (Get-Content (Join-Path $md $m))) }
}
# THE RUNNER IS NOT A CLEAN MACHINE, and that is the point of this
# pair of assertions. Earlier steps in this same job plant BITS jobs
# aimed at documentation addresses (TEST-NET-2 and TEST-NET-3) to
# prove the bare-address rule fires. The jobs are cancelled; the
# records BITS wrote about them are not, so without the harness-plant
# exclusion this check would report its own tests as transfers to a
# bare address -- on this runner, and for ever on any real machine
# where the harness has run. It did exactly that on the first run of
# this step, which is how the exclusion came to exist.
if ($live -match 'dz_ci_|dz_selftest') {
  if ($live -notmatch "name this audit's own test plants") {
    throw 'the channel holds records from this job''s own plants and the report did not declare them as excluded -- it would report its own tests as findings'
  }
  Write-Host 'the earlier steps'' plants are in this channel and were excluded with a declared count'
}
# It must have reached a verdict: the all-clear naming its span, the
# empty-log line, or one of the declared gaps. Silence is the one
# outcome that would mean nothing was checked and nothing said.
if ($live -notmatch 'BITS transfer record\(s\) read,|holds no transfer records|was NOT checked|NOT graded') {
  throw "bits_history printed no verdict on the live channel: $live"
}
# MEASURED, and now asserted where it can be: the provider's own
# event table. #250's step printed this and asserted nothing; the
# schema is what this check reads field names from, so its absence
# is a real condition the tool has to survive.
Write-Host '--- measured: the Bits-Client provider schema on this engine ---'
try {
  $pm = Get-WinEvent -ListProvider 'Microsoft-Windows-Bits-Client' -EA Stop
  $withTmpl = @($pm.Events | Where-Object { $_.Template })
  Write-Host ("events defined: {0}; with a data template: {1}" -f @($pm.Events).Count, $withTmpl.Count)
  foreach ($em in @($withTmpl | Select-Object -First 8)) {
    $names = @()
    try { foreach ($d in @(([xml]$em.Template).template.data)) { if ($d.name) { $names += [string]$d.name } } } catch { }
    Write-Host ("  Id={0}: {1}" -f $em.Id, ($names -join ', '))
  }
} catch {
  Write-Host ("  the provider schema could not be read here: " + $_.Exception.Message)
}

# A REAL RECORD, with nothing leaving the runner. An upload job
# RESUMED against a port where nothing listens fails immediately, so
# no data is transferred and no receiving server is needed -- but
# BITS writes genuine records about it, which is the only way to
# prove this check parses what Windows really writes rather than what
# a self-test hands it.
# Touches: bits-job:dz_selftest_bits_hist, file:%TEMP%\dz_ci_hist_payload.bin
$job = 'dz_selftest_bits_hist'
$payload = Join-Path $env:TEMP 'dz_ci_hist_payload.bin'
& bitsadmin /cancel $job 2>&1 | Out-Null
try {
  Set-Content -LiteralPath $payload -Value 'dz_selftest history payload' -Encoding ASCII
  & bitsadmin /create /upload $job 2>&1 | Out-Null
  & bitsadmin /addfile $job 'http://127.0.0.1:1/dz_ci_hist.bin' $payload 2>&1 | Out-Null
  & bitsadmin /setminretrydelay $job 60 2>&1 | Out-Null
  & bitsadmin /resume $job 2>&1 | Out-Null
  $deadline = (Get-Date).AddSeconds(60)
  $seen = @()
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    try {
      $seen = @(Get-WinEvent -LogName 'Microsoft-Windows-Bits-Client/Operational' -MaxEvents 80 -EA Stop |
                Where-Object { $_.Message -and ($_.Message -match 'dz_selftest_bits_hist|dz_ci_hist\.bin') })
    } catch { $seen = @() }
    if ($seen.Count -gt 0) { break }
  }
  if ($seen.Count -eq 0) {
    # Declared, never silent. The tool's own paths are still proven
    # by the self-test and by the live read above; what this cannot
    # then prove is that it parses a REAL record, and that is said.
    Write-Host '[ SKIP ] this runner wrote no Bits-Client record naming the planted job within 60s, so the real-record parse is unproven here'
  } else {
    Write-Host ("records naming the plant: {0}" -f $seen.Count)
    foreach ($e in @($seen | Select-Object -First 5)) {
      Write-Host ("  Id={0} {1:yyyy-MM-dd HH:mm:ss} {2}" -f $e.Id, $e.TimeCreated, (($e.Message -split "`r?`n")[0]))
    }
    # The tool must resolve the planted URL out of those real
    # records, and say which field name the machine gave it. If it
    # cannot, its declared could-not-name path is what ships, and the
    # step asserts THAT instead -- either way the report is honest.
    $md2 = Join-Path $env:TEMP ("dz_bh_plant_{0}" -f $PID)
    $after = (.\tools\bits_history.ps1 -MarkerDir $md2) -join "`n"
    Write-Host $after
    $sawUrl = ($after -match 'dz_ci_hist\.bin')
    $saidSo = ($after -match 'carried no value describing a transfer|none of their fields could be named')
    if (-not $sawUrl -and -not $saidSo) {
      throw 'the planted transfer was neither resolved nor declared unnameable -- a record was read and silently graded as nothing'
    }
    # THE DIRECTION, MEASURED. The tool's header says CI measures
    # whether this channel records it rather than assuming either
    # way, and the plant is a real UPLOAD job -- so this is the one
    # place that can settle it. Declared either way; when a machine
    # does record it, the upload rule bites and the T1048 row fires.
    if ($after -match "direction='") {
      Write-Host ('MEASURED: this channel DOES record a transfer direction -- ' + ([regex]::Match($after, "direction='[^']+'").Value))
      if ($after -notmatch 'BITS recorded an UPLOAD that has already happened') {
        throw 'the direction was recorded for a real UPLOAD job and no upload finding was raised'
      }
    } else {
      Write-Host 'MEASURED: this channel records NO transfer direction, so the tool states that limitation instead of guessing'
      # Measured 2026-10-15 on windows-latest: 126 events defined, 94
      # with data templates, and no direction field in any of them --
      # so this branch is the expected one until a build proves
      # otherwise, and the report must carry the limitation.
      if ($after -notmatch 'cannot say whether a file was sent OUT or fetched in') {
        throw 'the direction is unrecorded and the report did not say what it therefore cannot answer'
      }
      if ($after -notmatch 'carried a readable transfer DIRECTION') {
        throw 'no direction was recorded and the report did not say so -- the limitation must be stated, not implied'
      }
    }
    if ($sawUrl) {
      Write-Host 'PROVEN: a real Bits-Client record was parsed and its URL resolved'
      # 127.0.0.1 is private, so the planted transfer must NOT raise
      # the bare-public-address finding: the judgement, not just the
      # mechanism.
      if ($after -match '\[WARNING\] BITS transferred to or from a bare IP address with no name behind it: http://127\.0\.0\.1') {
        throw 'a loopback collector was raised as a bare PUBLIC address -- the private-range carve-out is broken'
      }
    } else {
      Write-Host 'DECLARED: this provider names no field this check can identify, and the report says so'
    }
    Remove-Item $md2 -Recurse -Force -EA SilentlyContinue
  }
} finally {
  & bitsadmin /cancel $job 2>&1 | Out-Null
  Remove-Item $payload -Force -EA SilentlyContinue
  $left = @()
  try { $left = @(Get-BitsTransfer -AllUsers -EA SilentlyContinue | Where-Object { $_.DisplayName -eq $job }) } catch { }
  if ($left.Count) { throw 'the planted history job survived cleanup' }
}
Remove-Item $md -Recurse -Force -EA SilentlyContinue
Write-Host 'bits_history OK (self-test, the runner real channel raises nothing, and the provider schema measured)'
exit 0
