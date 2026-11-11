# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   stalkerware_check.ps1 (covert monitoring; consent inventory must not accuse)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
# The pure grading, on the engine this tool ships to. lint.yml runs
# the same suite on pwsh for fast feedback; a 5.1-only divergence has
# already cost this repo a silent false negative, so this is the
# authoritative run. The live planted cases below are not replaced
# by it -- they cover the registry and UEFI reads it cannot.
$stOut = (.\tools\stalkerware_check.ps1 -SelfTest) -join "`n"
Write-Host $stOut
if ($LASTEXITCODE -ne 0) { throw 'stalkerware_check.ps1 -SelfTest failed' }
$stOk = @($stOut -split "`n" | Where-Object { $_ -match '^\[OK\]' }).Count
if ($stOk -lt 24) { throw "only $stOk [OK] line(s) from the stalkerware_check.ps1 self-test; cases have gone missing" }
foreach ($needle in @(
    'the CodexSandbox pair is a finding, at WARNING and never CRITICAL',
    'an account named psadmin is NOT swallowed by the note-property skip',
    'an EMPTY string value is not a hide-flag',
    'Shadow=unset requires consent, so it is not a finding',
    'ordinary software is not a monitoring product')) {
  if ($stOut -notmatch ('\[OK\]\s+' + [regex]::Escape($needle))) { throw "the stalkerware_check.ps1 self-test no longer covers: $needle" }
}

$ErrorActionPreference = 'Stop'
$md = Join-Path $env:TEMP ("dz_sw_ci_{0}" -f $PID)
New-Item -ItemType Directory -Path $md -Force | Out-Null
$ul = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$madeUl = $false
try {
  # Clean runner: camera/mic permissions are ordinary, so the consent
  # inventory must stay INFORMATIONAL. Any CRITICAL here means the
  # module is accusing a healthy machine -- the failure mode that
  # matters most for the people this check is written for.
  $out = (.\tools\stalkerware_check.ps1 -MarkerDir $md) -join "`n"
  Write-Host $out
  if ($out -match '\[CRITICAL\]') { throw "stalkerware_check reported CRITICAL on a clean runner" }
  if ($out -notmatch 'sign-in screen') { throw 'hidden-account check did not run' }
  if ($out -notmatch 'shadowing') { throw 'RDP shadowing check did not run' }
  if ($out -notmatch 'monitoring/spouseware|monitoring another person') { throw 'monitoring-product check did not run' }
  # Plant a hidden account entry: must be reported, and must be worded
  # as something to review rather than as an accusation.
  if (-not (Test-Path $ul)) { New-Item -Path $ul -Force | Out-Null; $madeUl = $true }
  Set-ItemProperty -Path $ul -Name 'dz_ci_probe_user' -Value 0 -Type DWord -Force
  $md2 = Join-Path $md 'hidden'
  New-Item -ItemType Directory -Path $md2 -Force | Out-Null
  $out2 = (.\tools\stalkerware_check.ps1 -MarkerDir $md2) -join "`n"
  Write-Host ($out2 -split "`n" | Where-Object { $_ -match 'dz_ci_probe_user|HIDDEN' })
  if ($out2 -notmatch 'dz_ci_probe_user') { throw 'planted hidden account not reported' }
  $m = Join-Path $md2 'dz_stalkerware.txt'
  if (-not (Test-Path $m)) { throw 'planted hidden account wrote no marker' }
  if ((Get-Content $m).Trim() -ne 'WARNING') { throw ("expected WARNING, got {0}" -f (Get-Content $m)) }
  # A hidden account is suspicious, not proof -- legitimate software
  # hides service accounts. The wording must not condemn.
  if ($out2 -notmatch 'legitimate software') { throw 'hidden-account finding lacks the not-necessarily-malicious framing' }
  # ...and that framing is CONTEXT, not a second finding. It carried a
  # [WARNING] tag until a real report showed 11 [WARNING] lines
  # against 9 counted findings: both lines aggregate into the one
  # ledger row, so the tag changed no verdict and simply made one
  # finding print as two -- in the check written for someone who may
  # be in danger. The tag is what every gate reads; it marks a
  # finding, never the sentence explaining one.
  $warnLines = @($out2 -split "`n" | Where-Object { $_ -match '^\[WARNING\]' })
  if ($warnLines.Count -ne 1) {
    throw ("the hidden-account block printed {0} [WARNING] line(s), expected exactly 1:`n{1}" -f $warnLines.Count, ($warnLines -join "`n"))
  }
  if ($warnLines[0] -notmatch 'HIDDEN from the sign-in screen') {
    throw ("the one [WARNING] line is not the finding: {0}" -f $warnLines[0])
  }
  if ($out2 -notmatch '\[INFO\][^\r\n]*legitimate software hides its own service accounts') {
    throw 'the not-necessarily-malicious framing is no longer tagged [INFO] -- a second WARNING inflates every printed count'
  }

  # A JUNK VALUE MUST NOT KILL THE SCAN. `[int]$p.Value` threw on any
  # non-numeric UserList value and the try/catch wrapped the WHOLE
  # loop, so one REG_SZ entry aborted the scan and the tool then
  # printed "No accounts are hidden from the sign-in screen" on a
  # machine that had one. This is the check that models an abusive
  # partner; a silent false clean here is the worst outcome in the
  # tool. Plant junk ALONGSIDE the real hidden account.
  Set-ItemProperty -Path $ul -Name 'dz_ci_junk_value' -Value 'n/a' -Type String -Force
  $md3 = Join-Path $md 'junk'
  New-Item -ItemType Directory -Path $md3 -Force | Out-Null
  $out3 = (.\tools\stalkerware_check.ps1 -MarkerDir $md3) -join "`n"
  Write-Host ($out3 -split "`n" | Where-Object { $_ -match 'dz_ci_probe_user|hidden from the sign-in' })
  if ($out3 -notmatch 'dz_ci_probe_user') { throw 'a non-numeric UserList value aborted the hidden-account scan -- the real hidden account was not reported' }
  if ($out3 -match 'No accounts are hidden from the sign-in screen') { throw 'reported a clean hidden-account verdict while an account was hidden' }
  Remove-ItemProperty -Path $ul -Name 'dz_ci_junk_value' -EA SilentlyContinue
} finally {
  Remove-ItemProperty -Path $ul -Name 'dz_ci_junk_value' -EA SilentlyContinue
  Remove-ItemProperty -Path $ul -Name 'dz_ci_probe_user' -EA SilentlyContinue
  if ($madeUl) { Remove-Item $ul -Force -EA SilentlyContinue }
  Remove-Item $md -Recurse -Force -EA SilentlyContinue
}
Write-Host "stalkerware_check.ps1 OK (incl. junk-value resilience)"
exit 0
