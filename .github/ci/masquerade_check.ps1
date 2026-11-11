# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   masquerade_check.ps1 -SelfTest + live (a system-process name outside its directory, or started by the wrong parent)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
$st = (.\tools\masquerade_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'masquerade_check.ps1 -SelfTest failed' }
$nst = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($nst -lt 158) { throw "masquerade_check self-test ran only $nst case(s)" }
Write-Host "masquerade_check -SelfTest OK ($nst cases)"
$sp = (.\tools\proc_snapshot.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $sp; throw 'proc_snapshot.ps1 -SelfTest failed' }
Write-Host "proc_snapshot -SelfTest OK"
# Against a dump in the exact shape Section 4 writes, with the RUNNER'S
# real paths: its own svchost and explorer must not raise, a copy of
# ping.exe named svchost.exe under Users\Public must.
$dump = Join-Path $env:TEMP 'dz_ci_masq.tmp'
$mk   = Join-Path $env:TEMP 'dz_ci_masq_hit.txt'
Remove-Item $mk -Force -EA SilentlyContinue
$real = @()
foreach ($n in 'svchost', 'explorer', 'lsass', 'csrss', 'WmiPrvSE') {
  $p = Get-Process -Name $n -EA SilentlyContinue | Where-Object { $_.Path } | Select-Object -First 1
  if ($p) { $real += ($p.ProcessName + '.exe  ' + $p.Id + '  ' + $p.Path) }
}
if ($real.Count -lt 2) { throw 'could not read the paths of the runner''s own system processes' }
Set-Content $dump -Value $real
$out = (.\tools\masquerade_check.ps1 -Path $dump -MarkerFile $mk) -join "`n"
Write-Host $out
if (Test-Path $mk) { throw "the runner's own system processes were reported as masquerading: $out" }
if ($out -notmatch '\[OK\] \d+ system-process name\(s\) run from their canonical directories') { throw 'the clean snapshot did not print the OK line' }
$md = 'C:\Users\Public\dz_ci_masq'
New-Item -ItemType Directory -Path $md -Force | Out-Null
Copy-Item (Join-Path $env:SystemRoot 'System32\ping.exe') (Join-Path $md 'svchost.exe') -Force
try {
  Set-Content $dump -Value ($real + ('svchost.exe  4242  ' + (Join-Path $md 'svchost.exe')))
  $out = (.\tools\masquerade_check.ps1 -Path $dump -MarkerFile $mk) -join "`n"
  Write-Host $out
  if (-not (Test-Path $mk)) { throw "svchost.exe under Users\Public was NOT reported: $out" }
  if ((Get-Content $mk).Trim() -ne 'WARNING') { throw ("expected WARNING marker, got " + (Get-Content $mk)) }
  if ($out -notmatch '\[WARNING\] Process svchost\.exe \(PID 4242\) runs from C:\\Users\\Public\\dz_ci_masq --') { throw 'the WARNING line does not name the process, PID and directory' }
} finally {
  Remove-Item $md, $dump, $mk -Recurse -Force -EA SilentlyContinue
}
Write-Host 'masquerade_check live OK (by path)'

# BY PARENT, on the runner's WHOLE live tree, written the way Section 4
# writes it: proc_snapshot from cmd, stdout redirected into the dump
# and the tree from the same query. Every real process must pass.
$d2 = Join-Path $env:TEMP 'dz_ci_proc4.tmp'
$t2 = Join-Path $env:TEMP 'dz_ci_proc4_tree.tmp'
$old = Join-Path $env:TEMP 'dz_ci_proc4_old.tmp'
$pm = Join-Path $env:TEMP 'dz_ci_masq_parent.txt'
$cm = Join-Path $env:TEMP 'dz_ci_masq_count.txt'
$lc = Join-Path $env:TEMP 'dz_ci_masq_lsacopy.txt'
$oc = Join-Path $env:TEMP 'dz_ci_masq_copy.txt'
$snap = (Resolve-Path .\tools\proc_snapshot.ps1).Path
Remove-Item $d2, $t2, $old, $pm, $cm, $lc, $oc, $mk -Force -EA SilentlyContinue
# A .cmd file, so the lines reach cmd exactly as a bat holds them (no
# argument re-quoting by PowerShell on the way): the new call, and the
# bats' former one-liner to compare the bytes against.
$cf = Join-Path $env:TEMP 'dz_ci_proc4.cmd'
Set-Content -LiteralPath $cf -Encoding ASCII -Value @(
  '@echo off',
  ('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -TreePath "{1}" > "{2}" 2>nul' -f $snap, $t2, $d2),
  ('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {{ $_.Name+''  ''+$_.ProcessId+''  ''+$_.ExecutablePath }}" > "{0}" 2>nul' -f $old))
$ErrorActionPreference = 'Continue'
& cmd /c $cf
$global:LASTEXITCODE = 0
$ErrorActionPreference = 'Stop'
Remove-Item -LiteralPath $cf -Force -EA SilentlyContinue
$dl = @(Get-Content $d2); $tl = @(Get-Content $t2); $ol = @(Get-Content $old)
if ($dl.Count -lt 30 -or $tl.Count -ne $dl.Count) { throw ("proc_snapshot wrote {0} dump line(s) and {1} tree line(s); expected the same count, >= 30" -f $dl.Count, $tl.Count) }
$dumpPids = @($dl | ForEach-Object { if ($_ -match '^\S.*?\s{2,}(\d+)') { $Matches[1] } }) | Sort-Object
$treePids = @($tl | ForEach-Object { $_.Split('|')[0] }) | Sort-Object
if (($dumpPids -join ',') -ne ($treePids -join ',')) { throw 'the dump and the tree list different processes -- they must come from one query' }
# Same PID and same name in both runs (a PID can be reused between
# them): the line must be identical, byte for byte.
$oldBy = @{}; foreach ($l in $ol) { if ($l -match '^(\S.*?)\s{2,}(\d+)') { $oldBy[$Matches[2]] = @{ Name = $Matches[1]; Line = $l } } }
$same = 0; $diff = @()
foreach ($l in $dl) {
  if ($l -notmatch '^(\S.*?)\s{2,}(\d+)') { continue }
  $o = $oldBy[$Matches[2]]
  if (-not $o -or $o.Name -cne $Matches[1]) { continue }
  if ($o.Line -ceq $l) { $same++ } else { $diff += $l }
}
if ($diff.Count -gt 0 -or $same -lt 20) { throw ("proc_snapshot's lines differ from the former one-liner's for the same processes ({0} same): {1}" -f $same, ($diff -join ' | ')) }
$noTicks = @($tl | Where-Object { $_.Split('|')[2] -eq '' })
Write-Host ("tree: {0} processes, {1} without a creation time: {2}" -f $tl.Count, $noTicks.Count, ($noTicks -join ', '))
if ($noTicks.Count -gt [math]::Max(3, [int]($tl.Count / 20))) { throw 'too many processes without a creation time for the parent rule to grade' }
$out = (.\tools\masquerade_check.ps1 -Path $d2 -MarkerFile $mk -TreePath $t2 -ParentMarkerFile $pm -CountMarkerFile $cm -LsassCopyMarkerFile $lc -CopyMarkerFile $oc) -join "`n"
Write-Host (($out -split "`n" | Where-Object { $_ -match 'by parent|wrong parent|child:|parent:|instance:|copy:|is a copy|started by the parent|whose parent|creation time|clock moved|holds no' }) -join "`n")
if ((Test-Path $pm) -or (Test-Path $cm) -or (Test-Path $lc) -or (Test-Path $oc)) { throw "the runner's own process tree was reported as masquerading by parent, or as holding a copy of a system process: $out" }
if ($out -notmatch '\[OK\] \d+ system-process name\(s\) were started by the parent Windows uses') { throw 'the real tree did not print the parent OK line' }

# Synthetic children against the LIVE tree (their parents are real):
#  - a canonical-path System32 svchost.exe whose parent PID belongs to
#    this step's own PowerShell: a parent WARNING while the path rule
#    stays clean;
#  - an svchost.exe whose parent PID belongs to no process: WARNING;
#  - an svchost.exe recorded just BEFORE the PowerShell holding its
#    parent PID (a reused PID): still WARNING -- services.exe never
#    exits, so its PID was never free -- and told as a reused number;
#  - a csrss.exe with no parent, and one whose parent PID was reused
#    by this PowerShell: quiet (a session's smss.exe exits by design).
#    Each in a session of its own: one csrss.exe per session;
#  - a second services.exe, started by the runner's real wininit.exe:
#    WARNING, Windows runs one;
#  - a dwm.exe with no parent in a session with no winlogon.exe: quiet
#    (a session that is ending), and the same in the session of the
#    runner's real winlogon.exe: WARNING;
#  - a dwm.exe in session 0 under the runner's real services.exe:
#    WARNING (session 0 never ends, and Windows never runs dwm there);
#  - an lsass.exe whose parent is the runner's real LSASS, with its
#    image: a COPY of LSASS, CRITICAL on its own row, and neither a
#    wrong parent nor a second instance (one finding, not three).
#    A tree line only: nothing is copied.
$meTicks = ([datetime](Get-CimInstance Win32_Process -Filter ("ProcessId=" + $PID)).CreationDate).ToUniversalTime().Ticks
$now = (Get-Date).ToUniversalTime().Ticks
$win = $env:SystemRoot
$wininit = @($tl | Where-Object { $_ -match '\|wininit\.exe$' } | ForEach-Object { $_.Split('|')[0] })[0]
if (-not $wininit) { throw 'the runner''s tree holds no wininit.exe' }
$wlSession = @($tl | Where-Object { $_ -match '\|winlogon\.exe$' } | ForEach-Object { $_.Split('|')[3] } | Where-Object { $_ -ne '' })[0]
if (-not $wlSession) { throw 'the runner''s tree holds no winlogon.exe with a session -- the per-session case needs one' }
$servicesPid = @($tl | Where-Object { $_ -match '\|services\.exe$' } | ForEach-Object { $_.Split('|')[0] })[0]
if (-not $servicesPid) { throw 'the runner''s tree holds no services.exe' }
$lsassRec = @($tl | Where-Object { $_ -match '\|lsass\.exe$' })[0]
if (-not $lsassRec) { throw 'the runner''s tree holds no lsass.exe' }
$lsassPid = $lsassRec.Split('|')[0]; $lsassPath = $lsassRec.Split('|')[4]; $lsassSession = $lsassRec.Split('|')[3]
$before = $meTicks - 10000000
Set-Content $t2 -Value ($tl + @(
  ("9000001|{0}|{1}|0|{2}\System32\svchost.exe|svchost.exe" -f $PID, $now, $win),
  ("9000002|9999991|{0}|0|{1}\System32\svchost.exe|svchost.exe" -f $now, $win),
  ("9000003|9999992|{0}|999||csrss.exe" -f $now),
  ("9000004|{0}|{1}|0|{2}\System32\svchost.exe|svchost.exe" -f $PID, $before, $win),
  ("9000005|{0}|{1}|998||csrss.exe" -f $PID, $before),
  ("9000006|{0}|{1}|0|{2}\System32\services.exe|services.exe" -f $wininit, $now, $win),
  ("9000007|9999993|{0}|997|{1}\System32\dwm.exe|dwm.exe" -f $now, $win),
  ("9000008|9999994|{0}|{1}|{2}\System32\dwm.exe|dwm.exe" -f $now, $wlSession, $win),
  ("9000009|{0}|{1}|0|{2}\System32\dwm.exe|dwm.exe" -f $servicesPid, $now, $win),
  ("9000010|{0}|{1}|{2}|{3}|lsass.exe" -f $lsassPid, $now, $lsassSession, $lsassPath))) -Encoding ASCII
Set-Content $d2 -Value ($dl + @(("svchost.exe  9000001  {0}\System32\svchost.exe" -f $win), ("svchost.exe  9000002  {0}\System32\svchost.exe" -f $win), 'csrss.exe  9000003  ', ("svchost.exe  9000004  {0}\System32\svchost.exe" -f $win), 'csrss.exe  9000005  ', ("services.exe  9000006  {0}\System32\services.exe" -f $win), ("dwm.exe  9000007  {0}\System32\dwm.exe" -f $win), ("dwm.exe  9000008  {0}\System32\dwm.exe" -f $win), ("dwm.exe  9000009  {0}\System32\dwm.exe" -f $win), ("lsass.exe  9000010  {0}" -f $lsassPath)))
Remove-Item $pm, $cm, $lc, $oc, $mk -Force -EA SilentlyContinue
$out = (.\tools\masquerade_check.ps1 -Path $d2 -MarkerFile $mk -TreePath $t2 -ParentMarkerFile $pm -CountMarkerFile $cm -LsassCopyMarkerFile $lc -CopyMarkerFile $oc) -join "`n"
Write-Host (($out -split "`n" | Where-Object { $_ -match '9000\d{3}|9999\d{3}|Windows runs one|clock moved' }) -join "`n")
if (Test-Path $mk) { throw "the canonical-path copies were reported by PATH -- the path rule must stay clean: $out" }
if (-not (Test-Path $pm)) { throw "no parent marker: $out" }
if (-not (Test-Path $cm)) { throw "no one-of-each marker for the second services.exe (its own ledger row): $out" }
$warn = @($out -split "`n" | Where-Object { $_ -match '^\[WARNING\] Process \S+ \(PID 9000\d{3}\) has the wrong parent' })
if ($warn.Count -ne 5) { throw ("expected exactly 5 wrong-parent WARNINGs (9000001, 9000002, 9000004, 9000008, 9000009), got {0}: {1}" -f $warn.Count, ($warn -join ' | ')) }
if ($out -notmatch ('\[WARNING\] Process svchost\.exe \(PID 9000001\) has the wrong parent: PID {0} belongs to .+? -- Windows starts svchost\.exe only from services\.exe, which runs until shutdown' -f $PID)) { throw 'the svchost.exe whose parent PID is this step''s PowerShell was not named with it' }
if ($out -notmatch '\(PID 9000002\) has the wrong parent: the process that started it \(PID 9999991\) is no longer running') { throw 'the svchost.exe with an absent parent was not reported' }
# Worded as a reused number only while the runner's own tree shows
# the clock did not move; under a moved clock "younger" cannot be
# told, and the line names the holder instead. A WARNING either way.
$reusedOk = ($out -match ('\(PID 9000004\) has the wrong parent: the process that started it \(PID {0}\) is no longer running' -f $PID) -and $out -match ('(?m)^    parent: PID {0} is no longer running; the number now belongs to a later process, powershell\.exe ' -f $PID))
if ($out -match 'The clock moved backward') { $reusedOk = $reusedOk -or ($out -match ('\(PID 9000004\) has the wrong parent: PID {0} belongs to powershell\.exe -- ' -f $PID)) }
if (-not $reusedOk) { throw 'the svchost.exe recorded before the process holding its parent PID was not reported as a reused number' }
if ($out -match '\(PID 900000[357]\)') { throw 'a csrss.exe whose parent exited by design, or a dwm.exe of a session that is ending, was reported' }
if ($out -notmatch ('\(PID 9000009\) has the wrong parent: PID {0} belongs to services\.exe -- Windows starts dwm\.exe only from the winlogon\.exe of its own session' -f $servicesPid)) { throw 'the dwm.exe in session 0 under services.exe was not reported -- session 0 never ends' }
if ($out -notmatch ('\(PID 9000008\) has the wrong parent: the process that started it \(PID 9999994\) is no longer running -- Windows starts dwm\.exe only from the winlogon\.exe of its own session, which runs as long as that session')) { throw ('the dwm.exe with no parent in session {0}, whose winlogon.exe runs, was not reported' -f $wlSession) }
if ($out -notmatch '\[WARNING\] Windows runs one services\.exe; this snapshot holds 2' -or $out -notmatch '(?m)^    instance: PID 9000006, parent wininit\.exe') { throw 'the second services.exe was not reported as one Windows never runs twice' }
if ($out -notmatch ('(?m)^\[CRITICAL\] Process lsass\.exe \(PID 9000010\) is a copy of LSASS \(PID {0}\), same (image|name) -- ' -f $lsassPid)) { throw 'the copy of the runner''s LSASS was not named as one' }
if (-not (Test-Path $lc) -or (Get-Content $lc).Trim() -ne 'CRITICAL') { throw 'no CRITICAL LSASS-copy marker (its own ledger row)' }
if ($out -match 'Windows runs one lsass' -or $out -match 'PID 9000010\) has the wrong parent') { throw 'the LSASS copy was also graded as a wrong parent or a second instance -- one finding, not three' }
if (Test-Path $oc) { throw 'the LSASS copy also wrote the other-copy marker' }
Remove-Item $d2, $t2, $old, $pm, $cm, $lc, $oc, $mk -Force -EA SilentlyContinue
Write-Host 'masquerade_check live OK (by parent: the real tree is clean, the impostors are named, exited-by-design parents are quiet, a copy of LSASS is CRITICAL)'
exit 0
