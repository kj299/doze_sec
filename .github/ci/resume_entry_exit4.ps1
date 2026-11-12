# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   The resume entry pointed at the bat, the planted reboot reached the ledger, and the entry is gone after the exit-4 run
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
# THE REPORT THIS JOB'S OWN RUN WROTE -- the OLDEST, not the newest.
# The step above explains why at length: the RunOnce resume entry can
# be executed by the runner's session while the audit is still going,
# and that second run writes a newer, truncated report. Sorting
# newest-first would hand every assertion below the wrong file.
$all = @(Get-ChildItem 'C:\SecurityAudit\SecurityReport_*.txt' | Sort-Object Name)
if ($all.Count -eq 0) { throw 'no report to check' }
$rep = $all[0]
if ($all.Count -gt 1) {
  Write-Host ("NOTE: {0} reports present; asserting on {1}, the one this job started. Also present: {2}" -f $all.Count, $rep.Name, (($all | Select-Object -Skip 1 | ForEach-Object { $_.Name }) -join ', '))
}
$text = [IO.File]::ReadAllText($rep.FullName)
# Everything else this step reads must come from the SAME run, so it
# is matched on that report's timestamp stem rather than by time.
$stem = ($rep.Name -replace '^SecurityReport_', '') -replace '\.txt$', ''
# THE RESUME ENTRY MUST POINT AT THE BAT. cmd's shift moves %0 too, and the bat
# expanded %~f0 after its parse loop, so the value it wrote on the owner's
# 2026-09-26 run was "<checkout>\-noVtSelf" -resume: a file that does not
# exist. INIT 8 prints the reg add it ran with every %VAR% expanded; on this
# job the old code printed a path ending in \-dnsprobe. Same regex as
# tests\field_test.ps1, which asserts it on every machine.
$m = [regex]::Match($text, '(?m)^\s*Command: reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v "(\*[^"]+_resume)" /t REG_SZ /d "\\"([^"]*?)\\" -resume" /f')
if (-not $m.Success) { throw 'the report has no INIT 8 "Command: reg add ... RunOnce ... -resume" line' }
Write-Host ("INIT 8 wrote value {0} = {1}" -f $m.Groups[1].Value, $m.Groups[2].Value)
if ($m.Groups[1].Value -ne '*WIN11_SecurityAudit_resume') { throw ("the audit names its resume value '{0}', not '*WIN11_SecurityAudit_resume' -- update the proofs" -f $m.Groups[1].Value) }
if ($m.Groups[2].Value -notmatch '\\doze_sec\.bat$') { throw ("the resume entry would run '{0}', not the bat -- %0 read after the parse loop's shift" -f $m.Groups[2].Value) }
# THE PLANT WAS SEEN: Section 1 raised the REBOOT row from PendingFileRenameOperations.
$led = Get-ChildItem 'C:\SecurityAudit\SecurityReport_*.ledger' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $led) { throw 'no ledger beside the report' }
if (-not (Select-String -LiteralPath $led.FullName -Pattern '\|REBOOT\|' -Quiet)) { throw 'the planted pending reboot did not reach the ledger -- exit 4 came from somewhere else' }
if ($text -notmatch 'PendingFileRenameOperations is set') { throw 'Section 1 did not report PendingFileRenameOperations' }
# WHAT IS PENDING IS NAMED. The old check only tested that the value existed;
# the owner's flag survived a boot and the advice was to reboot again.
if ($text -notmatch '(?m)^    delete: C:\\dz_ci_pending_rename\.tmp \(source missing\)') { throw 'Section 1 did not list the planted file operation beneath the finding' }
if ($text -notmatch '(?m)^    delete: C:\\dz_ci_pending_rename2\.tmp \(source missing\)  \[marker \*1\]') { throw 'Section 1 did not list the marker-prefixed plant with a clean path and its marker' }
if ($text -notmatch '(?m)^\[INFO\] PendingFileRenameOperations: Session Manager key last written \S+, last boot \S+ -- written AFTER the last boot') { throw 'Section 1 did not say whether the flag was written before or after the last boot (the plant postdates the boot)' }
if ($text -notmatch '(?m)^\[EXIT 4\] A reboot is pending\. Restart the system -- not Shut down -- then re-run the audit\.') { throw 'the fresh-flag [EXIT 4] advice is missing' }
# THE ENTRY IS GONE AFTER A COMPLETED RUN, WHATEVER THE CODE. Deleted only on
# 0/2/8 until 2026-09-26; on the owner's laptop (always 4) it survived every run.
$ro = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -EA SilentlyContinue
if ($ro -and ($ro.PSObject.Properties.Name -contains '*WIN11_SecurityAudit_resume')) { throw 'the RunOnce resume entry survived a completed exit-4 run' }
Write-Host 'RunOnce resume entry: pointed at the bat during the run, absent after the exit-4 run.'
# THE REPORT IS PLAIN TEXT. wevtutil /f:text leaves NUL-terminated fields in
# the Section 16 event blocks; report_format strips them and the summary
# declares the count. A NUL in the final report is a regression.
if ([IO.File]::ReadAllBytes($rep.FullName) -contains [byte]0) { throw 'the final report contains NUL bytes -- report_format did not strip the wevtutil text' }
$hyg = [regex]::Match($text, '(?m)^\s*REPORT HYGIENE: (\d+) NUL bytes removed')
if ($hyg.Success) { Write-Host ("report hygiene: {0} NUL byte(s) removed by report_format" -f $hyg.Groups[1].Value); if ([int]$hyg.Groups[1].Value -lt 1) { throw 'the hygiene line reads 0 -- it must not print for 0' } } else { Write-Host 'report hygiene: no NUL bytes in this run (no line printed)' }
# EVERY FINDING HAS AN ANALYST NOTE. The 19:16 field report carried five
# "No specific analyst note mapped" entries in TOP FINDINGS; a finding the
# tool raises without a note on what it means is half a finding.
$unmapped = @(($text -split "`n") | Where-Object { $_ -match 'No specific analyst note mapped' }).Count
if ($unmapped -gt 0) {
  $lines = @(($text -split "`n") | Where-Object { $_ -match '^\s*Finding: ' })
  Write-Host ("findings on this runner:`n" + ($lines -join "`n"))
  throw ("{0} TOP FINDINGS entr(y|ies) have no analyst note -- add a whyTable entry in tools\top_findings.ps1 for the Finding: line(s) above" -f $unmapped)
}
Write-Host 'TOP FINDINGS: every finding carries an analyst note'
# A HEALTHY RUNNER RAISES NO SECTION 18 GAP. Each IOC match that cannot run
# now prints NOT performed and raises a gap row; every list ships with the
# tool and every listing works here, so a gap row is a false WARNING. 18e
# moved off schtasks' English column names to Get-ScheduledTask: it must
# print its [OK] or a match, never nothing.
$s18gap = @(Get-Content -LiteralPath $led.FullName | Where-Object { $_ -match '^\w+\|18\|[^|]*\|.*NOT performed' })
if ($s18gap.Count) { throw ("Section 18 raised gap row(s) on a healthy runner: {0}" -f ($s18gap -join ' ; ')) }
if ($text -notmatch '(?m)^\[OK\] No scheduled task IOC matches\.|^\[WARNING\] Scheduled task IOC matches found\.') { throw 'Section 18e printed neither its [OK] nor a match' }
Write-Host 'Section 18: no gap row on a healthy runner; 18e compared the tasks'
# 18h's bad-value judgement on real machine state: UAC is on on every
# runner (EnableLUA=1), and the list names only EnableLUA=0. A runtime
# list that lost its bad-value column once turned UAC ON into an IOC
# (standard-user field run 2026-09-24); the harness plants a Run value
# for the match itself, this pins the judgement.
$m18h = [regex]::Match($text, '(?s)--- \[18h\] Registry IOC Check ---(.*?)--- \[18i\]')
if (-not $m18h.Success) { throw 'Section 18h was not found in the report' }
if ($m18h.Groups[1].Value -match 'EnableLUA') { throw ('Section 18h listed EnableLUA on a runner with UAC on: {0}' -f $m18h.Groups[1].Value.Trim()) }
Write-Host 'Section 18h: UAC on (EnableLUA=1) is not reported as the listed EnableLUA=0'
# Section 4's parent rule on the runner's real process tree, in the
# real audit: nothing has the wrong parent, and the check graded it
# (the OK line), so a silent skip cannot pass for a clean tree.
if ($text -match 'has the wrong parent:|\[WARNING\] Windows runs one |\) runs in session \d+ -- Windows runs') { throw ('Section 4 reported a parent, one-of-each or session finding on a clean runner: {0}' -f (($text -split "`r?`n" | Where-Object { $_ -match 'has the wrong parent:|Windows runs one|runs in session|^\s+(child|parent|instance):' }) -join ' | ')) }
if ($text -notmatch '\[OK\] \d+ system-process name\(s\) were started by the parent Windows uses') { throw 'Section 4 did not grade the process tree by parent (no OK line)' }
Write-Host 'Section 4: the runner''s real process tree passes the parent rule'
# A copy of a system process: none on a clean runner, live (Section 4)
# or in the Security log (Section 12). Section 12 must say which: the
# OK line, or the declared SKIPPED when the log holds no 4688.
if ($text -match 'is a copy of LSASS|is a copy of its parent|lsass\.exe was copied at|lsass\.exe was started at .* by ') { throw ('a copy of a system process was reported on a clean runner: {0}' -f (($text -split "`r?`n" | Where-Object { $_ -match 'is a copy of|was copied at|lsass\.exe was started at' }) -join ' | ')) }
if ($text -notmatch '\[OK\] No copy of lsass\.exe in the Security log|\[SKIPPED\] Copies of lsass\.exe in the Security log NOT checked') { throw 'Section 12 printed neither the LSASS-copy OK line nor its declared SKIPPED' }
# Defender's record of an LSASS read, and the settings that would dump
# it: nothing on a clean runner, and each check says which it is.
if ($text -match 'tried to read LSASS memory|is EXCLUDED from Defender|Silent-process-exit monitoring is ENABLED|configured to have its memory DUMPED|A memory dump of \S+ is on disk') { throw ('an LSASS-read record or a dump setting was reported on a clean runner: {0}' -f (($text -split "`r?`n" | Where-Object { $_ -match 'tried to read LSASS|EXCLUDED from Defender|Silent-process-exit|memory DUMPED|memory dump of' }) -join ' | ')) }
if ($text -notmatch '\[OK\] Nothing is configured to write a memory dump of lsass\.exe') { throw 'Section 12 did not grade the LSASS dump settings' }
if ($text -notmatch '\[OK\] No program tried to read LSASS memory|\[SKIPPED\] .* records NOT checked|NOT checked.*the Defender Operational log') { throw 'Section 12 printed no verdict for Defender''s LSASS-read records' }
Write-Host ('Section 12 (LSASS reads and dump settings): ' + (($text -split "`r?`n" | Where-Object { $_ -match 'tried to read LSASS memory|records NOT checked|Nothing is configured to write' }) -join ' | '))
Write-Host ('Section 12: ' + (($text -split "`r?`n" | Where-Object { $_ -match 'No copy of lsass\.exe|Copies of lsass\.exe in the Security log' }) -join ' | '))
# A file queued to LEAVE the machine over BITS (Section 5, T1048).
# Every BITS job on a clean runner is a download, so there must be no
# upload line and no T1048 row -- and Section 5 must say it looked:
# either the all-clear that now names the upload direction, or the
# no-jobs line, or the declared gap. An all-clear by omission is what
# the old wording was.
if ($text -match 'is queued to UPLOAD a file off this machine') { throw ('a BITS upload job was reported on a clean runner: {0}' -f (($text -split "`r?`n" | Where-Object { $_ -match 'queued to UPLOAD|^\s+(file|to|why):' }) -join ' | ')) }
if ($text -notmatch 'a file queued to leave this machine|\[OK\] No BITS transfer jobs queued|NOT checked for it|BITS job check NOT performed') { throw 'Section 5 printed no verdict on the direction of its BITS jobs' }
Write-Host ('Section 5 (BITS): ' + (($text -split "`r?`n" | Where-Object { $_ -match 'BITS job\(s\) queued|No BITS transfer jobs|readable transfer direction' }) -join ' | '))
# And what BITS RECORDED (Section 5, the history check). A clean
# runner's channel is full of Windows Update and updater transfers to
# NAMED hosts, so nothing may raise -- and the check must have
# reached a verdict rather than gone quiet, which is the failure mode
# an all-clear by omission would look like.
if ($text -match 'BITS recorded an UPLOAD that has already happened|BITS wrote a file straight into an autostart folder|BITS transferred to or from a bare IP address|A BITS transfer was driven by a program running from a staging folder') { throw ('the BITS history check raised on a clean runner: {0}' -f (($text -split "`r?`n" | Where-Object { $_ -match 'BITS recorded an UPLOAD|autostart folder|bare IP address|staging folder' }) -join ' | ')) }
if ($text -notmatch 'BITS transfer record\(s\) read,|holds no transfer records|What BITS recorded about finished transfers was NOT checked|carried no value describing a transfer') { throw 'the BITS history check printed no verdict in the real audit' }
Write-Host ('Section 5 (BITS history): ' + (($text -split "`r?`n" | Where-Object { $_ -match 'BITS transfer record\(s\) read|holds no transfer records|recorded about finished transfers' }) -join ' | '))
# Archives made on this machine (Section 14, T1560). A runner's Temp
# holds plain tool archives and Office/MSIX packages, none of which
# is graded; the check must have reached a verdict naming what it
# read, and no row may exist with nothing planted.
if ($text -match '\[(WARNING|CRITICAL)\] An archive made on this machine ') { throw ('the archive-staging check raised on a clean runner: {0}' -f (($text -split "`r?`n" | Where-Object { $_ -match 'An archive made on this machine|^\s+(format|download mark|packs):' }) -join ' | ')) }
if ($text -notmatch '\[OK\] (\d+ archive\(s\) examined across|No archives in the) \d+ staging folder\(s\)|\[INFO\] (\d+ archive\(s\) examined across|No archives in the) \d+ staging folder\(s\)[^\r\n]*before [^\r\n]* stopped it') { throw 'the archive-staging check printed no coverage verdict in the real audit (elevated: every staging folder must be readable)' }
if ($text -match 'could not be listed by an administrator -- archives there were NOT checked|could not be read by an administrator -- they were NOT checked') { throw ('an administrator could not read a staging folder or file on a clean runner: {0}' -f (($text -split "`r?`n" | Where-Object { $_ -match 'by an administrator' }) -join ' | ')) }
$ledArch = Join-Path 'C:\SecurityAudit' ('SecurityReport_' + $stem + '.ledger')
if ((Test-Path -LiteralPath $ledArch) -and @(Get-Content -LiteralPath $ledArch | Where-Object { $_ -match '\|14\|T1560\|' }).Count) { throw 'a T1560 ledger row on a clean runner' }
Write-Host ('Section 14 (archives): ' + (($text -split "`r?`n" | Where-Object { $_ -match 'staging folder\(s\)|plain archive\(s\)|package\(s\) that are ZIP' }) -join ' | '))
# THE APOSTROPHE RUN. TEMP held an apostrophe and APPDATA an apostrophe and
# a space: the dashboard (its script and SUMCODE/SUMCOUNT in TEMP) must
# have printed, the stage-1 remediation script must exist and parse, and
# Section 11 must show the planted history.
if ($text -notmatch 'DASHBOARD CHECKS PASSED') { throw "no dashboard status line: the dashboard script did not run with an apostrophe in TEMP" }
if ($text -notmatch 'dz_ci_history_marker_7c1') { throw "Section 11 did not show the planted PowerShell history from an APPDATA holding an apostrophe and a space" }
$rem = @(Get-ChildItem -LiteralPath 'C:\SecurityAudit' -Filter ('Remediation_' + $stem + '.ps1') -File)[0]
if (-not $rem) { throw 'no stage-1 remediation script was written with an apostrophe in TEMP' }
$rt = $null; $re = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($rem.FullName, [ref]$rt, [ref]$re)
if ($re -and $re.Count) { throw ("the remediation script does not parse: {0}" -f $re[0].Message) }
# cmd writes the script's safety header before the dashboard runs, so
# the file existing proves nothing; only the dashboard writes this line.
if ([IO.File]::ReadAllText($rem.FullName) -notmatch 'All queued commands applied') { throw 'the remediation script holds only the header cmd writes: the dashboard never filled it in' }
Write-Host ("apostrophe paths: dashboard printed and filled in {0}, which parses; Section 11 showed the planted history" -f $rem.Name)
# THE BITLOCKER TILE STATES SECTION 13'S VERDICT. It re-ran
# Get-BitLockerVolume until 2026-10-04 -- the sixth tile that measured
# twice. Section 13's evaluated line and the tile must agree.
$blSec  = [regex]::Match($text, '(?m)^\[(OK|WARNING|SKIPPED)\] BitLocker (ON|OFF|status unavailable)')
$blTile = [regex]::Match($text, '(?m)^\s*\[\s*(OK|PASS|WARNING|WARN|INFO)\s*\]\s+BitLocker (ON for \S+ \(Section 13\)|OFF for \S+ \(Section 13\)|status unavailable -- see Section 13|: NOT graded)')
if (-not $blSec.Success)  { throw 'Section 13 printed no evaluated BitLocker line' }
if (-not $blTile.Success) { throw 'no BitLocker dashboard tile naming Section 13' }
$want = @{ 'OK' = 'ON for'; 'WARNING' = 'OFF for'; 'SKIPPED' = 'status unavailable' }[$blSec.Groups[1].Value]
if ($blTile.Groups[2].Value -notlike "$want*") { throw ("BitLocker tile '{0}' disagrees with Section 13 '{1}'" -f $blTile.Value.Trim(), $blSec.Value) }
Write-Host ("BitLocker: Section 13 '{0}' == tile '{1}'" -f $blSec.Value, $blTile.Value.Trim())
if ((Get-Content -LiteralPath .\doze_sec.bat -Raw) -match "ck '\w+' \('BitLocker[^\r\n]*Get-BitLockerVolume|Get-BitLockerVolume[^\r\n]*ck '(PASS|WARN|INFO)'") { throw 'a dashboard tile in doze_sec.bat calls Get-BitLockerVolume again' }
if ((Get-Content -LiteralPath .\doze_sec_noAdmin.bat -Raw) -match "Get-BitLockerVolume[^\r\n]*ck '(PASS|WARN|INFO)'") { throw 'a dashboard tile in doze_sec_noAdmin.bat calls Get-BitLockerVolume again' }
# THE PLANTED FOOTPRINTS ARE INFO, NEVER A FINDING (corpus adfs-present /
# aadconnect-present).
foreach ($needle in 'ADFS detected', 'Azure AD Connect detected') {
  $hits = @($text -split "`n" | Where-Object { $_ -match [regex]::Escape($needle) })
  if (-not @($hits | Where-Object { $_ -match '^\s*\[INFO\]' }).Count) { throw ("'{0}' was not printed as [INFO] -- the planted footprint was missed or graded differently" -f $needle) }
  foreach ($hl in $hits) { if ($hl -match '^\s*\[(WARNING|CRITICAL)\]') { throw ("installed software raised as a finding: " + $hl) } }
  Write-Host ("planted footprint reported: " + (@($hits | Where-Object { $_ -match '^\s*\[INFO\]' })[0]).Trim())
}
# SECTION 9 AND THE DASHBOARD MUST AGREE ON DEFENDER EXCLUSIONS. The tiles
# used to call Get-MpPreference again, printed nothing when that failed,
# and never showed extension exclusions; they now read Section 9's
# state line, so an [OK] line must have its PASS tile and a WARNING its
# WARN tile with the same count.
if ($text -match 'Defender exclusions: NOT graded') { throw 'the dashboard says Defender exclusions were NOT graded while this runner can query Get-MpPreference' }
$plural = @{ path = 'paths'; process = 'processes'; extension = 'extensions' }
foreach ($kind in 'path', 'process', 'extension') {
  $okLine = [regex]::IsMatch($text, ('(?m)^\s*\[OK\] No ' + $kind + ' exclusions\.'))
  $wl = [regex]::Match($text, ('(?m)^\s*\[WARNING\] Exclusion ' + $plural[$kind] + ' found \((\d+)\)'))
  $passTile = [regex]::IsMatch($text, ('No Defender ' + $kind + ' exclusions configured \(Section 9\)'))
  $warnTile = [regex]::Match($text, ('Defender ' + $kind + ' exclusions configured: (\d+) \(Section 9\)'))
  if (-not $okLine -and -not $wl.Success) { throw ("Section 9 printed neither an [OK] nor a [WARNING] line for {0} exclusions" -f $kind) }
  if ($okLine -and -not $passTile) { throw ("Section 9 says no {0} exclusions but the dashboard has no PASS tile for them" -f $kind) }
  if ($wl.Success -and (-not $warnTile.Success -or $warnTile.Groups[1].Value -ne $wl.Groups[1].Value)) { throw ("Section 9 lists {0} {1} exclusion(s) but the dashboard tile disagrees" -f $wl.Groups[1].Value, $kind) }
  Write-Host ("Defender {0} exclusions: Section 9 and the dashboard agree" -f $kind)
}
# A LEDGER ROW NAMES WHAT THE TOOL OBSERVED. A row worded as a finding
# must have a non-gap [CRITICAL]/[WARNING] line in its section; a
# section that printed only gap lines may carry only gap-worded rows
# (dz_<name>_gap.txt). The inverse of "printed but not raised".
$gapRx = 'NOT (performed|checked|verified|evaluated|audited|run|graded|calibrated|inspected|determined)\b|verified nothing|could NOT run|not audited\b'
$printedNonGap = @{}
$cur = 0
foreach ($ln in ($text -split "\r?\n")) {
  $b = [regex]::Match($ln, '^\s*\[(\d{1,2})/18\]\s')
  if ($b.Success) { $cur = [int]$b.Groups[1].Value; continue }
  if ($cur -eq 0) { continue }
  if ($ln -match '^\s*\[SECTION (\d{1,2})/18 RESULT:') { $cur = 0; continue }
  if ($ln -match '^\s*\[(CRITICAL|WARNING)\]' -and $ln -notmatch $gapRx) { $printedNonGap[[string]$cur] = $true }
}
$badRows = @()
$gapRows = 0
foreach ($row in (Get-Content -LiteralPath $led.FullName)) {
  $f = $row.Split('|')
  if ($f.Length -lt 4) { continue }
  if ($f[0] -notmatch '^(CRITICAL|WARNING)$' -or $f[1] -notmatch '^\d{1,2}$') { continue }
  if ($f[3] -match $gapRx) { $gapRows++; continue }
  if (-not $printedNonGap.ContainsKey($f[1])) { $badRows += $row }
}
if ($badRows.Count) { throw ("ledger row(s) worded as findings whose section printed only gap lines (the row names a finding the tool never made): " + ($badRows -join ' ; ')) }
Write-Host ("every finding-worded ledger row has a non-gap finding line in its section ({0} gap-worded row(s) on this runner)" -f $gapRows)
# And the corpus grader agrees, on the real report of a real run: every
# catalogued benign twin this runner shows is at or below its allowed
# severity. The readonly job runs this through field_test; the full run
# never did, so a plant here was graded by nothing.
# The grader prints with Write-Host (the Information stream), so capture
# every stream, as the readonly job does for field_test; a plain
# assignment captured nothing and the assertion below threw on a run
# whose grader had in fact reported "observed 17 of 56".
$bc = (& .\tools\benign_corpus_check.ps1 -Mode Report -Report $rep.FullName *>&1 | ForEach-Object { "$_" }) -join "`n"
$bcRc = $LASTEXITCODE
Write-Host $bc
if ($bcRc -ne 0) { throw 'benign_corpus_check -Mode Report failed on the full-run report' }
if ($bc -notmatch 'observed (\d+) of') { throw 'the corpus grader did not report what it observed' }
foreach ($id in 'adfs-present', 'aadconnect-present') { if ($bc -notmatch ('\[OK\s*\] ' + $id + ':')) { throw ("the corpus grader did not grade {0} OK on this report" -f $id) } }
