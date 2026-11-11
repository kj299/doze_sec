# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   driver_audit.ps1 (BYOVD by hash + unsigned catch-all; renamed cannot evade)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
$md = Join-Path $env:TEMP ("dz_drv_ci_{0}" -f $PID)
New-Item -ItemType Directory -Path $md -Force | Out-Null
# Clean runner: every loaded/inbox driver is Microsoft- or vendor-signed,
# so no marker should be written. A CRITICAL here is a signature-gate bug.
$out = (.\tools\driver_audit.ps1 -MarkerDir $md) -join "`n"
Write-Host ($out -split "`n" | Select-Object -First 40)
if (Test-Path (Join-Path $md 'dz_driver.txt')) {
  throw ("driver marker written on a clean runner: {0}" -f (Get-Content (Join-Path $md 'dz_driver.txt')))
}
# Plant an unsigned "driver" in a drop location: the signature catch-all
# (not a name/hash match) must flag it -- this is what defeats renaming.
$plant = 'C:\Users\Public\dz_ci_probe_driver.sys'
Set-Content -LiteralPath $plant -Value 'MZ not a real driver' -Encoding ASCII
try {
  $out2 = (.\tools\driver_audit.ps1 -MarkerDir $md) -join "`n"
  Write-Host ($out2 -split "`n" | Where-Object { $_ -match 'dz_ci_probe_driver' })
  if ($out2 -notmatch 'dz_ci_probe_driver\.sys') { throw 'planted unsigned driver not reported' }
  $m = Join-Path $md 'dz_driver.txt'
  if (-not (Test-Path $m)) { throw 'planted unsigned driver wrote no marker' }

  # A signature finding must carry the Memory Integrity context, so a
  # reader can judge urgency instead of inferring it from a different
  # section. Exactly one such line, whatever this runner's DeviceGuard
  # state is -- the note has an answer for on, off and unknown.
  $hv = @($out2 -split "`n" | Where-Object { $_ -match 'Memory Integrity \(HVCI\)' })
  if ($hv.Count -ne 1) { throw "expected exactly one Memory Integrity context line beside the finding, got $($hv.Count)" }
  if ($hv[0] -notmatch '^\[INFO\]') { throw "the Memory Integrity context must be [INFO] -- it is context, not a finding: $($hv[0])" }
  Write-Host ("  HVCI context: {0}" -f $hv[0].Trim())
  # And it must not have changed the grade. The marker is the severity
  # that reaches the ledger; a downgrade would show up here first.
  $mv2 = (Get-Content $m).Trim()
  if ($mv2 -notmatch '^(WARNING|CRITICAL)$') { throw "the planted unsigned driver graded '$mv2' -- the HVCI context must never downgrade a finding" }

  # ATTACK SURFACE vs EVIDENCE OF COMPROMISE. A known-abusable driver
  # name that is VALIDLY SIGNED and in the normal drivers directory is
  # most likely legitimate software (VirtualBox ships vboxdrv.sys,
  # Sysinternals ships procexp152.sys). The old rule set CRITICAL on
  # the name alone and skipped the signature check entirely, so a
  # developer machine got "CRITICAL findings present -- review NOW"
  # and exit code 8. Copy a real signed Microsoft driver to a
  # known-abusable NAME in each location and check the severities.
  $srcSigned = Join-Path $env:SystemRoot 'System32\drivers\tcpip.sys'
  $inPlace = Join-Path $env:SystemRoot 'System32\drivers\gdrv.sys'
  $staged  = 'C:\Users\Public\gdrv.sys'
  $md2 = Join-Path $env:TEMP ("dz_drv_ci2_{0}" -f $PID)
  New-Item -ItemType Directory -Path $md2 -Force | Out-Null
  try {
    Copy-Item -LiteralPath $srcSigned -Destination $inPlace -Force
    $o3 = (.\tools\driver_audit.ps1 -MarkerDir $md2) -join "`n"
    $l3 = (($o3 -split "`n") | Where-Object { $_ -match 'gdrv\.sys' } | Select-Object -First 1)
    if (-not $l3) { throw 'signed known-abusable driver in the normal location was not reported at all' }
    if ($l3 -match '^\[CRITICAL\]') { throw ("validly signed driver in System32\drivers was reported CRITICAL (false positive): $l3") }
    if ($l3 -notmatch '^\[WARNING\]') { throw ("expected WARNING for signed known-abusable driver, got: $l3") }
    # The finding carries its triage facts directly beneath it: the
    # FULL hash (a truncated one cannot be looked up), whether the
    # driver is in the kernel, who signed it, and the install answer.
    # The plant is a file no driver service references, so it must
    # read 'on disk only'.
    if ($l3 -notmatch ':$') { throw "the finding line must end with ':' so its evidence is carried with it: $l3" }
    $a3 = @($o3 -split "`n")
    $i3 = [array]::IndexOf($a3, $l3)
    $ev3 = ($a3[($i3 + 1)..($i3 + 6)]) -join "`n"
    Write-Host $ev3
    $h3 = (Get-FileHash -LiteralPath $inPlace -Algorithm SHA256).Hash.ToLower()
    if ($ev3 -notmatch ('(?m)^    sha256: ' + $h3 + '\b')) { throw "full sha256 $h3 not printed under the finding" }
    if ($ev3 -notmatch '(?m)^    kernel: on disk only') { throw 'the on-disk-only plant did not read kernel: on disk only' }
    if ($ev3 -notmatch '(?m)^    signer: \S') { throw 'no signer line under the finding' }
    if ($ev3 -notmatch '(?m)^    install: ') { throw 'no install-event line under the finding' }
    if ($ev3 -notmatch '(?m)^    verify: Get-FileHash') { throw 'no verify line under the finding' }
    if ($o3 -match 'gdrv\.sys \[[0-9a-f]{16}\.\.\.\]') { throw 'a truncated hash is still printed' }
    Remove-Item -LiteralPath $inPlace -Force -EA SilentlyContinue
    # Same name, same valid signature, but STAGED outside the drivers
    # directory -- that is the real BYOVD pattern and must stay CRITICAL.
    Copy-Item -LiteralPath $srcSigned -Destination $staged -Force
    $md3 = Join-Path $env:TEMP ("dz_drv_ci3_{0}" -f $PID)
    New-Item -ItemType Directory -Path $md3 -Force | Out-Null
    $o4 = (.\tools\driver_audit.ps1 -MarkerDir $md3) -join "`n"
    $l4 = (($o4 -split "`n") | Where-Object { $_ -match 'Public\\gdrv\.sys' } | Select-Object -First 1)
    if (-not $l4) { throw 'staged known-abusable driver was not reported' }
    if ($l4 -notmatch '^\[CRITICAL\]') { throw ("staged known-abusable driver must stay CRITICAL, got: $l4") }
    Remove-Item $md3 -Recurse -Force -EA SilentlyContinue
  } finally {
    Remove-Item -LiteralPath $inPlace -Force -EA SilentlyContinue
    Remove-Item -LiteralPath $staged -Force -EA SilentlyContinue
    Remove-Item $md2 -Recurse -Force -EA SilentlyContinue
  }
} finally {
  Remove-Item $plant -Force -EA SilentlyContinue
  Remove-Item $md -Recurse -Force -EA SilentlyContinue
}
Write-Host "driver_audit.ps1 OK (incl. signed-vendor-driver severity split)"
exit 0
