# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   baseline_diff.ps1 -SelfTest + live (save/diff round-trip; new item must be detected; a loopback-only listener is INFO, an all-interfaces one WARNING)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
# The pure verdicts on real Windows PowerShell 5.1 (the engine this ships to).
$st = (.\tools\baseline_diff.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'baseline_diff.ps1 -SelfTest failed' }
$nst = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($nst -lt 84) { throw "baseline_diff self-test ran only $nst case(s)" }
Write-Host "baseline_diff -SelfTest OK ($nst cases)"
$md = Join-Path $env:TEMP ("dz_bl_ci_{0}" -f $PID)
New-Item -ItemType Directory -Path $md -Force | Out-Null
$snap = Join-Path $md 'baseline.snapshot'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
try {
  # No baseline yet -> must guide, never fail and never fake a clean pass.
  $none = (.\tools\baseline_diff.ps1 -Mode Diff -Path $snap -MarkerDir $md) -join "`n"
  if ($none -notmatch 'No baseline found') { throw 'missing-baseline path did not report guidance' }
  if (Test-Path (Join-Path $md 'dz_baseline.txt')) { throw 'missing baseline wrote a marker' }
  # Save, then diff with no changes -> must be quiet.
  $save = (.\tools\baseline_diff.ps1 -Mode Save -Path $snap -MarkerDir $md) -join "`n"
  Write-Host $save
  if (-not (Test-Path $snap)) { throw 'baseline snapshot not written' }
  if ($save -notmatch 'not proof the current state is clean') { throw 'save output missing the honest-limitation note' }
  # The Winlogon logon/logoff counters are excluded by name, and the
  # exclusion is declared, not silent.
  if ($save -notmatch 'Excluded by design: Winlogon LastLogOffEndTimePerfCounter and LastLogOnEndTimePerfCounter') { throw 'save output did not declare the Winlogon counter exclusion' }
  # Snapshot must be deterministic: re-saving yields identical records
  # (header carries the timestamp, so compare only record lines).
  $recs1 = @(Get-Content $snap | Where-Object { $_ -notmatch '^#' })
  if ($recs1.Count -lt 10) { throw ("snapshot suspiciously small: {0} records" -f $recs1.Count) }
  if (@($recs1 | Where-Object { $_ -match '^RUN\|.*\\Winlogon\\LastLog(Off|On)EndTimePerfCounter\|' }).Count) { throw 'a Winlogon logon/logoff counter was snapshotted as a persistence value' }
  # PORT records carry the bind address, so loopback-only can be told
  # from network-reachable at diff time.
  $portRecs = @($recs1 | Where-Object { $_ -match '^PORT\|' })
  if ($portRecs.Count -eq 0) { throw 'snapshot holds no PORT records' }
  $noBind = @($portRecs | Where-Object { $_ -notmatch ' bind=\S+$' })
  if ($noBind.Count) { throw ("PORT record(s) without a bind address: {0}" -f ($noBind -join '; ')) }
  # Plant a NEW autorun and confirm the diff reports it as NEW+WARNING.
  if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
  Set-ItemProperty -Path $runKey -Name 'dz_ci_baseline_probe' -Value 'C:\Windows\Temp\dz_ci_probe.exe' -Force
  $diff = (.\tools\baseline_diff.ps1 -Mode Diff -Path $snap -MarkerDir $md) -join "`n"
  Write-Host ($diff -split "`n" | Where-Object { $_ -match 'dz_ci_baseline_probe|summary' })
  if ($diff -notmatch 'NEW autorun/persistence value since baseline') { throw 'planted autorun not reported as NEW' }
  if ($diff -notmatch 'dz_ci_baseline_probe') { throw 'planted autorun name missing from diff' }
  $m = Join-Path $md 'dz_baseline.txt'
  if (-not (Test-Path $m)) { throw 'baseline diff wrote no marker for a new persistence value' }
  if ((Get-Content $m).Trim() -ne 'WARNING') { throw ("expected WARNING marker, got {0}" -f (Get-Content $m)) }

  # WHAT CHANGES BY DESIGN, IN AN OLD SNAPSHOT. A field run carried 48
  # lines for one logon: every per-user service instance renamed
  # <template>_<suffix>. Re-suffix this runner's own instances in a
  # copy of the snapshot (a "previous logon"), and add records the
  # diff must not compare (a Winlogon counter, our own resume entry)
  # beside the malign twin it MUST still report (the resume NAME
  # pointing at someone else's binary).
  $snapOld = Join-Path $md 'baseline_oldlogon.snapshot'
  $tplNames = @()
  foreach ($k in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services')) {
    $ty = (Get-ItemProperty -LiteralPath $k.PSPath -Name Type -EA SilentlyContinue).Type
    if ($ty -and ($ty -band 0x40) -and -not ($ty -band 0x80)) { $tplNames += $k.PSChildName }
  }
  $inst = @($recs1 | Where-Object { $_ -match '^SVC\|([^|]+)_[0-9a-f]{4,8}\|' -and ($tplNames -contains ($_ -replace '^SVC\|([^|]+)_[0-9a-f]{4,8}\|.*$', '$1')) })
  Write-Host ("per-user service instance record(s) on this runner: {0}" -f $inst.Count)
  $oldRecs = @($recs1 | ForEach-Object { if ($inst -contains $_) { $_ -replace '^(SVC\|[^|]+_)[0-9a-f]{4,8}(\|)', '${1}fdf7a$2' } else { $_ } })
  $oldRecs += 'RUN|HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LastLogOffEndTimePerfCounter|1804345906204'
  $oldRecs += 'RUN|HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*WIN11_SecurityAudit_resume|"C:\src\doze_sec\doze_sec.bat" -resume'
  $oldRecs += 'RUN|HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*dz_ci_twin_resume|C:\Users\Public\dz_ci_twin.exe -resume'
  Set-Content -LiteralPath $snapOld -Value $oldRecs -Encoding UTF8
  $dOld = (.\tools\baseline_diff.ps1 -Mode Diff -Path $snapOld -MarkerDir $md) -join "`n"
  if ($dOld -match 'LastLogOffEndTimePerfCounter') { throw 'an OLD Winlogon counter record was still compared' }
  if ($dOld -match 'WIN11_SecurityAudit_resume') { throw 'our own resume entry in an old snapshot was still compared' }
  if ($dOld -notmatch 'REMOVED autorun/persistence value since baseline: \S*\*dz_ci_twin_resume') { throw 'the resume NAME with a foreign binary was excluded -- the exclusion must key on the marker, not the name' }
  if ($dOld -notmatch 'Excluded by design: 2 value\(s\) in the saved baseline') { throw 'the old-snapshot exclusion was not declared with its count' }
  if ($inst.Count -gt 0) {
    $instNames = @($inst | ForEach-Object { ($_ -split '\|')[1] -replace '_[0-9a-f]{4,8}$', '' })
    $tplLines = @(($dOld -split "`n") | Where-Object { $l = $_; $l -match '(NEW|REMOVED) service since baseline' -and @($instNames | Where-Object { $l -match ('\b' + [regex]::Escape($_) + '_') }).Count })
    if ($tplLines.Count) { throw ("per-user service instances still reported after a re-suffix: " + ($tplLines -join ' | ')) }
    if ($dOld -notmatch 'Per-user service instances compared by template') { throw 'the template comparison was not declared' }
  } else {
    Write-Host '[ SKIP ] no per-user service instance on this runner -- the template rule is proven by the self-test cases only'
  }

  # A NEW SERVICE HOSTED BY A SIGNED LOLBIN MUST NOT BE DOWNGRADED.
  # The signature gate keyed on the host binary only, so
  # `rundll32.exe <staging>\x.dll,Run` resolved to a Microsoft-signed
  # image, became INFO, was excluded from the WARNING set, raised no
  # severity and wrote no marker -- and the INFO line omitted the
  # command line, so the malicious argument never even appeared. That
  # is LOLBin persistence rendered as a Windows-update notice in the
  # check that exists to catch implants matching no signature.
  & sc.exe create dz_selftest_ci_lolbin binPath= 'C:\Windows\System32\rundll32.exe C:\ProgramData\dz_selftest_ci_stage\x.dll,Run' start= demand | Out-Null
  # Two listeners the baseline has not seen, owned by this
  # powershell (not a system RPC owner, so the owner rule cannot
  # forgive either): one bound to loopback only (INFO -- unreachable
  # from the network; the owner's jhi_service on [::1] was WARNING
  # on 2026-10-03), one bound to every address (WARNING).
  $lb  = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $lb.Start()
  $any = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, 0);      $any.Start()
  $lbPort = $lb.LocalEndpoint.Port; $anyPort = $any.LocalEndpoint.Port
  Write-Host ("planted listeners: loopback tcp/{0}, all-interfaces tcp/{1}" -f $lbPort, $anyPort)
  $diff2 = (.\tools\baseline_diff.ps1 -Mode Diff -Path $snap -MarkerDir $md) -join "`n"
  $lbLine  = @(($diff2 -split "`n") | Where-Object { $_ -match ('since baseline.*\btcp/{0}\b' -f $lbPort) })
  $anyLine = @(($diff2 -split "`n") | Where-Object { $_ -match ('since baseline.*\btcp/{0}\b' -f $anyPort) })
  Write-Host ($lbLine + $anyLine)
  if ($lbLine.Count -ne 1) { throw ("loopback listener tcp/{0}: expected one diff line, got {1}" -f $lbPort, $lbLine.Count) }
  if ($lbLine[0] -notmatch '^\[INFO\] NEW listening port since baseline \(loopback-only listener, unreachable from the network\)') { throw ("loopback-only listener was not INFO: " + $lbLine[0]) }
  if ($lbLine[0] -notmatch 'bind=127\.0\.0\.1') { throw ("the bind address is missing from the line: " + $lbLine[0]) }
  if ($anyLine.Count -ne 1) { throw ("all-interfaces listener tcp/{0}: expected one diff line, got {1}" -f $anyPort, $anyLine.Count) }
  if ($anyLine[0] -notmatch '^\[WARNING\] NEW listening port since baseline \(new listener\)') { throw ("all-interfaces listener by powershell was not WARNING: " + $anyLine[0]) }
  Write-Host ($diff2 -split "`n" | Where-Object { $_ -match 'dz_selftest_ci_lolbin' })
  if ($diff2 -notmatch 'dz_selftest_ci_lolbin') { throw 'new LOLBin-hosted service missing from the diff entirely' }
  $line = (($diff2 -split "`n") | Where-Object { $_ -match 'dz_selftest_ci_lolbin' } | Select-Object -First 1)
  if ($line -notmatch '^\[WARNING\]') { throw ("LOLBin-hosted service was not raised as WARNING: $line") }
  if ($line -notmatch 'rundll32') { throw ("the command line was omitted from the finding: $line") }
} finally {
  & sc.exe delete dz_selftest_ci_lolbin 2>&1 | Out-Null
  Remove-ItemProperty -Path $runKey -Name 'dz_ci_baseline_probe' -EA SilentlyContinue
  if ($lb)  { try { $lb.Stop() }  catch {} }
  if ($any) { try { $any.Stop() } catch {} }
  Remove-Item $md -Recurse -Force -EA SilentlyContinue
}
Write-Host "baseline_diff.ps1 OK (incl. signed-LOLBin service not downgraded; loopback listener INFO, all-interfaces WARNING)"
exit 0
