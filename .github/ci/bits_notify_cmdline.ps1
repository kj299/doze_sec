# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   persistence_extra.ps1 BITS notify command line (both directions)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
# The BITS arm has NEVER had its true-positive direction tested: no
# harness case plants a BITS job, and the only live contract is
# "dz_bits.txt must not exist on a clean runner". Meanwhile the
# false-positive direction fired on every ordinary Edge/Windows Update
# job, because Get-BitsTransfer returns NotifyCmdLine as a two-element
# array and @('','') -join ' ' is a single SPACE -- truthy.
# Microsoft: GetNotifyCmdLine "sets pProgram and pParameters to an
# empty string if SetNotifyCmdLine has not been called."
$job = 'dz_selftest_bits_probe'
& bitsadmin /cancel $job 2>&1 | Out-Null
try {
  & bitsadmin /create $job 2>&1 | Out-Null
  & bitsadmin /addfile $job 'http://localhost/dz_ci_nonexistent' "$env:TEMP\dz_ci_bits_probe.bin" 2>&1 | Out-Null

  # (a) NO notify command line -- must NOT be a finding. This is the
  # shape every real Edge/Windows Update job has.
  $mdA = Join-Path $env:TEMP ("dz_pe_bits_a_{0}" -f $PID)
  $outA = (.\tools\persistence_extra.ps1 -MarkerDir $mdA) -join "`n"
  $bitsLines = @($outA -split "`n" | Where-Object { $_ -match 'BITS job' })
  Write-Host ($bitsLines -join "`n")
  foreach ($l in $bitsLines) {
    if ($l -match "^\[(WARNING|CRITICAL)\].*$job.*notify command line:\s*$") {
      throw "a BITS job with NO notify command line was raised, with empty evidence: $l"
    }
  }

  # (b) a REAL notify command line -- must still fire.
  & bitsadmin /SetNotifyCmdLine $job 'C:\Windows\System32\cmd.exe' 'cmd.exe /c rem dz_selftest' 2>&1 | Out-Null
  $mdB = Join-Path $env:TEMP ("dz_pe_bits_b_{0}" -f $PID)
  $outB = (.\tools\persistence_extra.ps1 -MarkerDir $mdB) -join "`n"
  Write-Host (($outB -split "`n" | Where-Object { $_ -match 'BITS job' }) -join "`n")
  if ($outB -notmatch "BITS job '$job'.*has a notify command line: \S") {
    throw 'a BITS job WITH a real notify command line was not reported (or was reported with empty evidence)'
  }
  if (-not (Test-Path (Join-Path $mdB 'dz_bits.txt'))) {
    throw 'the BITS finding wrote no marker -- it never reaches the ledger'
  }
  # (c) THE AGE ARM, both directions. It used to raise a WARNING on
  # age alone, which fired for Microsoft Edge's own updater on the
  # owner's machine purely because the job crossed 30 days between two
  # runs -- a birthday, not a behaviour, and the same benign job the
  # notify arm had already been fixed for. Age now only raises when
  # the DESTINATION says something. -BitsAgeDays 0 makes the fresh
  # probe job count as old so both directions are reachable here.
  #
  # This probe's remote is http://localhost/... -- PLAIN HTTP TO A
  # HOSTNAME, which must NOT raise. This case used to assert the
  # opposite. Microsoft documents *.dl.delivery.mp.microsoft.com as
  # HTTP on port 80 for Edge content delivery -- "Be sure not to use
  # HTTPS for those endpoints that specify HTTP, and vice versa. The
  # connection will fail." -- so on 2026-09-19 the plain-HTTP signal
  # flagged Microsoft Edge's own updater, the THIRD rule to flag that
  # same benign job. This case proved the rule FIRED; it never asked
  # whether firing was correct.
  & bitsadmin /SetNotifyCmdLine $job 'NULL' 'NULL' 2>&1 | Out-Null
  $mdC = Join-Path $env:TEMP ("dz_pe_bits_c_{0}" -f $PID)
  $outC = (.\tools\persistence_extra.ps1 -MarkerDir $mdC -BitsAgeDays 0) -join "`n"
  Write-Host (($outC -split "`n" | Where-Object { $_ -match 'BITS job' }) -join "`n")
  if ($outC -match "\[(WARNING|CRITICAL)\] BITS job '$job'") {
    throw 'an old BITS job fetching over plain HTTP to a HOSTNAME was raised -- the plain-HTTP false positive is back'
  }
  if ($outC -match 'plain HTTP') {
    throw 'the deleted plain-HTTP branch has been reinstated somewhere in persistence_extra.ps1'
  }
  if ($outC -notmatch "\[INFO\] BITS job '$job'[^\r\n]*age alone is not a finding") {
    throw 'the plain-HTTP job was neither raised nor reported as context -- it vanished from the report'
  }

  # (c2) A bare PUBLIC IP still has no routine cause, and raises.
  # 203.0.113.0/24 is TEST-NET-3: documentation space, so the queued
  # job cannot reach anything real.
  $jobIp = 'dz_selftest_bits_pubip'
  & bitsadmin /cancel $jobIp 2>&1 | Out-Null
  & bitsadmin /create $jobIp 2>&1 | Out-Null
  & bitsadmin /addfile $jobIp 'http://203.0.113.10/dz_ci_nonexistent' "$env:TEMP\dz_ci_bits_pubip.bin" 2>&1 | Out-Null
  $mdC2 = Join-Path $env:TEMP ("dz_pe_bits_c2_{0}" -f $PID)
  $outC2 = (.\tools\persistence_extra.ps1 -MarkerDir $mdC2 -BitsAgeDays 0) -join "`n"
  Write-Host (($outC2 -split "`n" | Where-Object { $_ -match 'BITS job' }) -join "`n")
  if ($outC2 -notmatch "\[WARNING\] BITS job '$jobIp'[^\r\n]*bare public IP address") {
    throw 'an old BITS job fetching from a bare PUBLIC IP was not raised -- the destination signal is dead'
  }
  if (-not (Test-Path (Join-Path $mdC2 'dz_bits.txt'))) {
    throw 'the bare-public-IP finding wrote no marker -- it never reaches the ledger'
  }

  # (c3) ...but a bare PRIVATE one is an on-prem WSUS server, an SCCM
  # distribution point or a Connected Cache node. Context, with the
  # cause named, never an all-clear that hides the address.
  $jobLan = 'dz_selftest_bits_lanip'
  & bitsadmin /cancel $jobLan 2>&1 | Out-Null
  & bitsadmin /create $jobLan 2>&1 | Out-Null
  & bitsadmin /addfile $jobLan 'http://192.168.77.77/dz_ci_nonexistent' "$env:TEMP\dz_ci_bits_lanip.bin" 2>&1 | Out-Null
  $mdC3 = Join-Path $env:TEMP ("dz_pe_bits_c3_{0}" -f $PID)
  $outC3 = (.\tools\persistence_extra.ps1 -MarkerDir $mdC3 -BitsAgeDays 0) -join "`n"
  Write-Host (($outC3 -split "`n" | Where-Object { $_ -match 'BITS job' }) -join "`n")
  if ($outC3 -match "\[(WARNING|CRITICAL)\] BITS job '$jobLan'") {
    throw 'a bare PRIVATE LAN destination was raised -- WSUS/SCCM/Connected Cache is the ordinary cause'
  }
  if ($outC3 -notmatch "\[INFO\] BITS job '$jobLan'[^\r\n]*private LAN address") {
    throw 'the private LAN destination was not reported as context with its cause named'
  }

  # (d) an ORDINARY https destination, same age. Must be context, not
  # a finding: this is the Edge-updater shape and the false positive
  # being fixed.
  $job2 = 'dz_selftest_bits_https'
  & bitsadmin /cancel $job2 2>&1 | Out-Null
  & bitsadmin /create $job2 2>&1 | Out-Null
  & bitsadmin /addfile $job2 'https://example.invalid/dz_ci_nonexistent' "$env:TEMP\dz_ci_bits_https.bin" 2>&1 | Out-Null
  $mdD = Join-Path $env:TEMP ("dz_pe_bits_d_{0}" -f $PID)
  $outD = (.\tools\persistence_extra.ps1 -MarkerDir $mdD -BitsAgeDays 0) -join "`n"
  Write-Host (($outD -split "`n" | Where-Object { $_ -match 'BITS job' }) -join "`n")
  # Note the local destination is under $env:TEMP -- i.e. it contains
  # \Temp\, which $badPathRx (used by every other arm in that file)
  # matches. A BITS job writing to the temp folder is what a
  # downloader DOES, Edge's updater included, so raising on it would
  # replace one false positive with a broader one. This case is the
  # guard against that.
  if ($outD -match "\[(WARNING|CRITICAL)\] BITS job '$job2'") {
    throw "an old BITS job with an ordinary https destination, no notify command, and a temp-folder download path was RAISED -- either the Edge-updater false positive is back or the local-path signal was broadened to \Temp\ again"
  }
  if ($outD -notmatch "\[INFO\] BITS job '$job2'[^\r\n]*age alone is not a finding") {
    throw 'the long-lived job was neither raised nor reported as context -- it vanished from the report entirely'
  }
  Remove-Item $mdA, $mdB, $mdC, $mdD -Recurse -Force -EA SilentlyContinue
} finally {
  & bitsadmin /cancel $job 2>&1 | Out-Null
  & bitsadmin /cancel 'dz_selftest_bits_https' 2>&1 | Out-Null
  & bitsadmin /cancel 'dz_selftest_bits_pubip' 2>&1 | Out-Null
  & bitsadmin /cancel 'dz_selftest_bits_lanip' 2>&1 | Out-Null
  Remove-Item "$env:TEMP\dz_ci_bits_pubip.bin" -Force -EA SilentlyContinue
  Remove-Item "$env:TEMP\dz_ci_bits_lanip.bin" -Force -EA SilentlyContinue
  Remove-Item "$env:TEMP\dz_ci_bits_probe.bin" -Force -EA SilentlyContinue
  Remove-Item "$env:TEMP\dz_ci_bits_https.bin" -Force -EA SilentlyContinue
}
Write-Host "BITS OK (empty notify is not a finding; a real one is; age alone is context; a bad destination raises)"
exit 0
