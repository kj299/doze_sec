# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It reads service state only and writes one scratch file. It lives in
# .github/ so it never reaches a USB stick.
$ErrorActionPreference = 'Stop'
$st = (.\tools\sshd_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'sshd_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 12) { throw "sshd_check self-test ran only $n case(s)" }
function RunS([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_sshd_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\sshd_check.ps1 -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    $sf = Join-Path $md 'dz_sshd_state.txt'
    return @{ Out = $o; State = $(if (Test-Path $sf) { (Get-Content $sf -Raw).Trim() } else { '' }); Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_state.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
# LIVE: the runner's own sshd, MEASURED. Whatever it is, it must be GRADED,
# and the state and the marker must agree.
$r = RunS @{}
Write-Host "MEASURED: the runner's OpenSSH Server state is $($r.State) [$($r.Markers)]"
if ($r.State -notmatch '^sshd=(running|stopped|absent)$') { throw "an administrator could not grade the sshd service: $($r.State) [$($r.Markers)] $($r.Out)" }
if (($r.State -eq 'sshd=running') -ne ($r.Markers -eq 'dz_sshd_hit')) { throw "the sshd state and its marker disagree: $($r.State) [$($r.Markers)]" }
# A NAME THE SERVICE MANAGER DOES NOT KNOW, through the real readers:
# Get-Service fails, sc.exe says 1060, and only that reads "not installed".
$r = RunS @{ ServiceName = 'dz_ci_nosuchsshd' }
if ($r.State -ne 'sshd=absent' -or $r.Markers -or $r.Out -notmatch '(?m)^\[OK\] OpenSSH Server not installed\.' -or $r.Out -notmatch 'exit 1060') { throw "a service that does not exist was not 'not installed' by the service manager's own answer: $($r.State) [$($r.Markers)] $($r.Out)" }
# A RUNNING service read through the real readers, with a scratch keys file:
# the Windows Update or DHCP client service stands in for sshd.
$running = @(Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1)[0].Name
$kf = Join-Path $env:TEMP "dz_ci_sshd_keys_$PID"
try {
  Set-Content -LiteralPath $kf -Value @('# a comment', 'ssh-ed25519 AAAA one', '', 'ssh-ed25519 AAAA two')
  $r = RunS @{ ServiceName = $running; KeysFile = $kf }
  if ($r.State -ne 'sshd=running' -or $r.Markers -ne 'dz_sshd_hit' -or $r.Out -notmatch '(?m)^\[WARNING\] OpenSSH Server \(sshd\) is RUNNING' -or $r.Out -notmatch 'administrators_authorized_keys has 2 key\(s\)') { throw "a running service with two keys was not the finding with its count: $($r.State) [$($r.Markers)] $($r.Out)" }
} finally { Remove-Item -LiteralPath $kf -Force -EA SilentlyContinue }
Write-Host 'sshd: running is the finding with its key count; a name the service manager does not know is "not installed"; both through the real readers'
exit 0
