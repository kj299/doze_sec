# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   A process-isolated Windows container is graded inside its own container (server silo); an impostor lsass.exe beside it is still flagged
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
# A process-isolated Windows container runs its own smss, csrss,
# wininit, services and lsass on the host. Measured on this image
# (PR #258, build 26100): they sit in a session of their own (the
# runner's desktop is another), their image paths read the
# container's own view (C:\Windows\system32\...), and the kernel
# reports a non-zero server silo ID for every one of them.
# masquerade_check credits a process to a container only by that
# silo ID, a matching creation time, a session the silo owns and a
# running vmcompute.exe. Both directions: the real container raises
# nothing and is named; a copy of PING.EXE named lsass.exe, started
# in the runner's own session beside it, is still flagged, and the
# container's processes appear in no finding line.
# Touches: container:dz_ci_ctr (removed in finally),
# file:C:\dz_ci_ctr_impostor\ (its process stopped and the folder
# removed in finally). The base image stays in the runner's image
# store, discarded with the runner. Every check is an explicit throw;
# the preference stays Continue so docker's stderr is not an error.
$ErrorActionPreference = 'Continue'
$build = [Environment]::OSVersion.Version.Build
if ($build -lt 22621) { throw "host build $build predates ProcessMembershipInformation; this proof needs Windows Server 2025 (windows-latest)" }
if (-not (Get-Command docker -EA SilentlyContinue)) { throw 'no docker on this image: the container proof did not run' }
$img = 'mcr.microsoft.com/windows/nanoserver:ltsc2025'
$impDir = 'C:\dz_ci_ctr_impostor'
$imp = $null
$md = Join-Path $env:TEMP 'dz_ci_ctr'
function Invoke-MasqCheck {
  Remove-Item $md -Recurse -Force -EA SilentlyContinue
  New-Item -ItemType Directory -Path $md | Out-Null
  $d = Join-Path $md 'dump.tmp'; $t = Join-Path $md 'tree.tmp'
  & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tools\proc_snapshot.ps1 -TreePath $t > $d 2>$null
  $global:LASTEXITCODE = 0
  return ((.\tools\masquerade_check.ps1 -Path $d -MarkerFile (Join-Path $md 'm1.txt') -TreePath $t -ParentMarkerFile (Join-Path $md 'm2.txt') -CountMarkerFile (Join-Path $md 'm3.txt') -LsassCopyMarkerFile (Join-Path $md 'm4.txt') -CopyMarkerFile (Join-Path $md 'm5.txt')) -join "`n")
}
# The daemon is not always up on a fresh runner (seen: 'failed to
# connect to the docker API'). Start it and wait; say so if it will not.
$sv = Get-Service docker -EA SilentlyContinue
if ($sv -and $sv.Status -ne 'Running') { Write-Host "MEASURED: the docker service was $($sv.Status); starting it"; Start-Service docker -EA SilentlyContinue }
for ($i = 0; $i -lt 30; $i++) { & docker version 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { break }; Start-Sleep -Seconds 2 }
if ($LASTEXITCODE -ne 0) { throw 'the docker daemon did not answer within 60 s: the container proof did not run' }
try {
  & docker pull $img 2>&1 | Select-Object -Last 2 | Write-Host
  & docker rm -f dz_ci_ctr 2>&1 | Out-Null
  $cid = (& docker run -d --isolation=process --name dz_ci_ctr $img ping -t localhost 2>&1) -join ' '
  $global:LASTEXITCODE = 0
  Write-Host "docker run: $cid"
  # The container's lsass.exe is the one outside session 0.
  $ctrLsass = $null
  for ($i = 0; $i -lt 30 -and -not $ctrLsass; $i++) {
    Start-Sleep -Seconds 2
    $ctrLsass = @(Get-CimInstance Win32_Process -Filter "Name='lsass.exe'" | Where-Object { $_.SessionId -ne 0 }) | Select-Object -First 1
  }
  if (-not $ctrLsass) { throw "the container's lsass.exe never appeared on the host: $cid" }
  Start-Sleep -Seconds 10   # its services finish starting
  $ctrSession = [int]$ctrLsass.SessionId
  $ctrPids = @(Get-CimInstance Win32_Process | Where-Object { $_.SessionId -eq $ctrSession } | ForEach-Object { [int]$_.ProcessId })
  Write-Host ("container session {0}: {1} process(es), its lsass.exe is PID {2}" -f $ctrSession, $ctrPids.Count, $ctrLsass.ProcessId)
  $named = '(?m)^\[INFO\] A process-isolated Windows container \(server silo [1-9]\d*\) runs \d+ process\(es\) in session ' + $ctrSession + ', its own .*lsass\.exe'
  # 1. The real container alone: named, and nothing raised. A process
  # the container starts or ends between the snapshot and the
  # kernel read voids the credit for that run (fail closed), so a
  # run that reads "graded as host processes" is retried, twice.
  $o1 = ''
  for ($try = 1; $try -le 3; $try++) {
    $o1 = Invoke-MasqCheck
    if ($o1 -match $named) { break }
    Write-Host ("attempt {0}: the container was not credited; retrying in 5 s" -f $try)
    Start-Sleep -Seconds 5
  }
  Write-Host $o1
  if ($o1 -match 'Exception|is not recognized|CategoryInfo') { throw "PowerShell error text in the output: $o1" }
  if ($o1 -notmatch $named) { throw "the container was not named by its server silo: $o1" }
  if ($o1 -match 'Container membership could not be read|graded as host processes') { throw "the container's membership was not credited: $o1" }
  foreach ($m in 1..5) { if (Test-Path (Join-Path $md ("m{0}.txt" -f $m))) { throw ("a process-isolated container on a clean runner wrote marker m{0}: {1}" -f $m, $o1) } }
  # 2. The impostor beside it, in the runner's own session.
  New-Item -ItemType Directory -Path $impDir -Force | Out-Null
  Copy-Item (Join-Path $env:SystemRoot 'System32\PING.EXE') (Join-Path $impDir 'lsass.exe') -Force
  $imp = Start-Process -FilePath (Join-Path $impDir 'lsass.exe') -ArgumentList '-t', 'localhost' -WindowStyle Hidden -PassThru
  Start-Sleep -Seconds 3
  # A process named lsass.exe outside System32 may be stopped by
  # Defender; a dead impostor would read as session 0 and fail
  # for the wrong reason.
  $impProc = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $imp.Id)
  if (-not $impProc) { throw "the impostor lsass.exe (PID $($imp.Id)) is no longer running -- stopped before it could be checked (Defender?)" }
  $impSession = [int]$impProc.SessionId
  Write-Host ("impostor lsass.exe: PID {0}, session {1}" -f $imp.Id, $impSession)
  if ($impSession -eq $ctrSession) { throw "the impostor started in the container's session $ctrSession; the proof needs it in the runner's own" }
  $o2 = ''
  for ($try = 1; $try -le 3; $try++) {
    $o2 = Invoke-MasqCheck
    if ($o2 -match $named) { break }
    Write-Host ("attempt {0}: the container was not credited; retrying in 5 s" -f $try)
    Start-Sleep -Seconds 5
  }
  Write-Host $o2
  if (-not (Get-Process -Id $imp.Id -EA SilentlyContinue)) { throw "the impostor lsass.exe (PID $($imp.Id)) stopped during the check (Defender?); the result does not test it" }
  if ($o2 -notmatch '(?m)^\[WARNING\] Windows runs one lsass\.exe; this snapshot holds 2 -- all but one are impostors') { throw "the impostor beside a container was not counted as a second lsass.exe: $o2" }
  if ($o2 -notmatch ('(?m)^    instance: PID ' + $imp.Id + ',')) { throw "the impostor's PID is not named: $o2" }
  if ($impSession -ne 0 -and $o2 -notmatch ('(?m)^\[WARNING\] Process lsass\.exe \(PID ' + $imp.Id + '\) runs in session ' + $impSession + ' -- Windows runs lsass\.exe only in session 0')) { throw "the impostor's session line is missing: $o2" }
  if (-not (Test-Path (Join-Path $md 'm3.txt')) -or (Get-Content (Join-Path $md 'm3.txt') -Raw).Trim() -ne 'WARNING') { throw 'no WARNING one-of-each marker for the impostor' }
  if (-not (Test-Path (Join-Path $md 'm1.txt'))) { throw "the impostor outside System32 was not flagged by path: $o2" }
  if ($o2 -notmatch $named) { throw "the container lost its credit beside the impostor: $o2" }
  foreach ($cp in $ctrPids) {
    if ($o2 -match ('\(PID ' + $cp + '\)') -or $o2 -match ('(?m)^    instance: PID ' + $cp + ',')) { throw "container process PID $cp is named in a finding: $o2" }
  }
  Write-Host 'container rule OK: the real container is graded inside its own server silo and named; an impostor lsass.exe beside it is flagged, by path and as a second lsass.exe'
} finally {
  if ($imp) { Stop-Process -Id $imp.Id -Force -EA SilentlyContinue; Start-Sleep -Seconds 1 }
  Remove-Item $impDir -Recurse -Force -EA SilentlyContinue
  & docker rm -f dz_ci_ctr 2>&1 | Out-Null
  Remove-Item $md -Recurse -Force -EA SilentlyContinue
  $global:LASTEXITCODE = 0
}
if (Test-Path $impDir) { throw "the impostor folder $impDir was left behind" }
exit 0
