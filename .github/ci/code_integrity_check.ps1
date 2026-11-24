# CI ONLY -- run by .github/workflows/windows-smoke.yml. Read-only: it asks the
# kernel and bcdedit, and writes only its own temp files. It lives in .github/
# so it never reaches a USB stick.
#
# tools\code_integrity_check.ps1 asks the RUNNING KERNEL whether unsigned
# kernel drivers can load. On a runner the kernel must answer (no gap), and
# its test-signing bit must agree with what bcdedit -- the old, English-only
# source -- says this runner boots with: the windows-latest image boots with
# testsigning on, which is why the old tile read WARN here.
$ErrorActionPreference = 'Stop'
$st = (.\tools\code_integrity_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'code_integrity_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 8) { throw "code_integrity_check self-test ran only $n case(s)" }
$md = Join-Path $env:TEMP ("dz_ci_codeint_{0}" -f $PID)
New-Item -ItemType Directory -Path $md -Force | Out-Null
try {
  $sf = Join-Path $md 'state.txt'
  $out = (& .\tools\code_integrity_check.ps1 -MarkerDir $md -StateFile $sf) -join "`n"
  Write-Host $out
  if (-not (Test-Path -LiteralPath (Join-Path $md 'dz_codeint_done.txt'))) { throw 'no done marker' }
  if (Test-Path -LiteralPath (Join-Path $md 'dz_codeint_gap.txt')) { throw "the running kernel did not answer on a runner: $out" }
  $state = (Get-Content -LiteralPath $sf -Raw).Trim()
  if ($out -notmatch '(?m)^\[INFO\] Code-integrity options reported by the running kernel: 0x[0-9A-F]{8}') { throw "the options were not printed: $out" }
  if ($state -like '*nointegrity*') { throw "a runner reported kernel code integrity NOT enforced -- a runner image never boots that way; the read is wrong: $out" }
  $bcd = ''
  $ErrorActionPreference = 'Continue'
  $bcd = (& bcdedit /enum '{current}' 2>$null | Out-String)
  $ErrorActionPreference = 'Stop'
  $setting = [bool]($bcd -match '(?im)^\s*testsigning\s+Yes\b')
  Write-Host ("MEASURED: kernel state '{0}'; bcdedit {{current}} testsigning = {1}" -f $state, $(if ($setting) { 'Yes' } else { 'not set' }))
  if ($bcd -notmatch '(?im)^\s*identifier\s+\{') { Write-Host '[ SKIP ] bcdedit gave no English output here; the agreement check needs it' }
  elseif ($setting -ne ($state -like '*testsign*')) {
    $sb = $null; try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sb = $null }
    Write-Host "MEASURED: Secure Boot on this runner: $sb"
    # Windows ignores testsigning while Secure Boot is on, so a stored Yes the
    # kernel does not honour is both reads being right. Declared, not passed.
    if ($sb -eq $true -and $setting -and -not ($state -like '*testsign*')) { Write-Host '[ SKIP ] agreement check not applicable: Secure Boot is on, so the stored testsigning Yes is not in effect -- the kernel is right to report it off' }
    else { throw "the kernel's test-signing bit ($state) disagrees with this runner's boot configuration (testsigning $setting) -- one of the two reads is wrong" }
  } else { Write-Host 'code_integrity_check: the kernel answered, and its test-signing bit agrees with the boot configuration' }
} finally { Remove-Item -LiteralPath $md -Recurse -Force -EA SilentlyContinue }
exit 0
