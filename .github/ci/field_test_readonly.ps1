# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   Run the field test (read-only audit + read-only proof + corpus check)
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
# Continue, not Stop: the audit writes diagnostics to stderr, and 5.1
# would turn them into terminating errors under redirection. The
# script's exit code and its printed proof lines are the verdict.
$ErrorActionPreference = 'Continue'
# Run it the way docs\second-machine.md says: from a stick-equivalent
# copy made by tools\make_usb_stick.ps1 (the reduced file set, harness
# left off), not from the checkout. Same audit, same assertions, no
# extra run.
#
# And make that copy from the HARDER source, the one the GitHub
# "Download ZIP" route hands a person: every file LF-only except the
# bats and the threat lists, which the repo stores CRLF
# (.gitattributes -text; this runner's checkout is CRLF, so a stick
# made from it never exercised the conversion), every file carrying
# Mark of the Web (Explorer's Extract All copies the ZIP's onto each
# file), inside a nested folder that is not named doze_sec. The stick
# it makes must be the same as one made from a checkout.
$zip = Join-Path $env:RUNNER_TEMP 'dz_src.zip'
$zipRoot = Join-Path $env:RUNNER_TEMP 'dz_zipsrc'
git -c core.autocrlf=false archive --format=zip --prefix=doze_sec-ci-branch/ -o $zip HEAD
if ($LASTEXITCODE -ne 0) { throw 'git archive failed' }
Expand-Archive -LiteralPath $zip -DestinationPath $zipRoot
$src = Join-Path $zipRoot 'doze_sec-ci-branch'
foreach ($probe in 'tests\field_test.ps1', 'tools\exec_probe.ps1', 'README.md') {
  if ([Array]::IndexOf([IO.File]::ReadAllBytes((Join-Path $src $probe)), [byte]13) -ge 0) {
    throw ("{0} in the archive holds a CR -- the source is not LF-only, so this step would test nothing it means to" -f $probe)
  }
}
# .gitattributes: the archive -- what GitHub's Download ZIP serves --
# carries the bats and the lists with CRLF, so a person running the
# bat straight from a downloaded ZIP gets one cmd.exe can run. The
# owner's 2026-10-24 second-machine run, from an LF-only ZIP, died at
# INIT 8 with "The system cannot find the batch label specified".
foreach ($probe in 'doze_sec.bat', 'doze_sec_noAdmin.bat', 'ThreatLists\ttp_manifest.txt') {
  $pb = [IO.File]::ReadAllBytes((Join-Path $src $probe))
  for ($i = 0; $i -lt $pb.Length; $i++) { if ($pb[$i] -eq 10 -and ($i -eq 0 -or $pb[$i - 1] -ne 13)) { throw ("{0} in the archive has a bare LF -- a downloaded ZIP would hand cmd.exe a file it cannot run" -f $probe) } }
}
# And an LF-only copy of either bat (an old ZIP) refuses at once,
# before any goto, with the reason -- and writes nothing.
$lfDir = Join-Path $env:RUNNER_TEMP 'dz_lf_bat'
New-Item -ItemType Directory -Path $lfDir -Force | Out-Null
$before = @(Get-ChildItem 'C:\SecurityAudit' -Filter 'SecurityReport_*' -EA SilentlyContinue).Count
foreach ($bn in 'doze_sec.bat', 'doze_sec_noAdmin.bat') {
  $lfPath = Join-Path $lfDir $bn
  [IO.File]::WriteAllText($lfPath, ([IO.File]::ReadAllText((Join-Path $PWD $bn)) -replace "`r`n", "`n"))
  # Unquoted: cmd /c strips the outer quotes of a line that starts
  # with one, and RUNNER_TEMP has no space.
  if ($lfPath -match ' ') { throw "the LF-only test path holds a space: $lfPath" }
  $lo = (& cmd.exe /d /c $lfPath -dev -readonly -noConsoleLog 2>&1 | ForEach-Object { "$_" }) -join "`n"
  $lrc = $LASTEXITCODE
  if ($lrc -ne 1 -or $lo -notmatch [regex]::Escape('[FATAL] This copy of ' + $bn + ' has Unix (LF-only) line endings')) { throw ("an LF-only {0} was not refused with the FATAL line (exit {1}): {2}" -f $bn, $lrc, $lo) }
}
$global:LASTEXITCODE = 0
if (@(Get-ChildItem 'C:\SecurityAudit' -Filter 'SecurityReport_*' -EA SilentlyContinue).Count -ne $before) { throw 'a refused LF-only bat still wrote a report' }
Remove-Item -LiteralPath $lfDir -Recurse -Force
Write-Host 'the archive bats and lists are CRLF; an LF-only copy of either bat is refused before it does anything'
$srcFiles = @(Get-ChildItem -LiteralPath $src -Recurse -File)
foreach ($f in $srcFiles) { Set-Content -LiteralPath $f.FullName -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3" }
Write-Host ("source: {0} file(s), LF-only but for the bats and lists, each marked with Mark of the Web" -f $srcFiles.Count)
$stickRoot = Join-Path $env:RUNNER_TEMP 'dz_stick'
$store = Join-Path $env:RUNNER_TEMP 'dz_stick_manifests'
# Started the way a person starts it -- powershell -ExecutionPolicy
# Bypass -File -- since the script itself carries Mark of the Web here:
# under this runner's own policy a marked script started with & could
# be refused or prompt, which is not what is under test.
$mk = (& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $src 'tools\make_usb_stick.ps1') -ToFolder $stickRoot -ManifestStore $store 2>&1 | ForEach-Object { "$_" }) -join "`n"
Write-Host $mk
if ($LASTEXITCODE -ne 0) { throw 'make_usb_stick -ToFolder failed' }
if ($mk -notmatch '\[INFO\] (\d+) text file\(s\) had LF line endings' -or [int]$matches[1] -lt 90) { throw 'the stick script did not convert the LF-only text files (expected >= 90)' }
if ($mk -notmatch '\[INFO\] (\d+) source file\(s\) carried Mark of the Web' -or [int]$matches[1] -lt 90) { throw 'the stick script did not count the marked source files (expected >= 90)' }
$stick = Join-Path $stickRoot 'doze_sec'
$bare = @(); $marked = @()
foreach ($f in (Get-ChildItem -LiteralPath $stick -Recurse -File)) {
  if ($f.Name -match '\.(bat|cmd|ps1|txt|md)$') {
    $b = [IO.File]::ReadAllBytes($f.FullName)
    for ($i = 0; $i -lt $b.Length; $i++) { if ($b[$i] -eq 10 -and ($i -eq 0 -or $b[$i - 1] -ne 13)) { $bare += $f.FullName; break } }
  }
  if (Get-Item -LiteralPath $f.FullName -Stream 'Zone.Identifier' -EA SilentlyContinue) { $marked += $f.FullName }
}
if ($bare.Count) { throw ("text file(s) on the stick still hold a bare LF: {0}" -f ($bare -join ', ')) }
if ($marked.Count) { throw ("Mark of the Web travelled onto the stick: {0}" -f ($marked -join ', ')) }
Write-Host 'stick made from an LF-only, marked download: every text file CRLF, no Mark of the Web on the copy.'
foreach ($h in 'tests\manual_ci.ps1', 'tests\detection_selftest.ps1', 'tests\cleanup_selftest.ps1', 'tests\noadmin_smoke.ps1', '.git', '.github') {
  if (Test-Path -LiteralPath (Join-Path $stick $h)) { throw ("the stick copy carries {0} -- the harness must stay off it" -f $h) }
}
# The same download made into a READ-ONLY ISO image (make_usb_stick
# -Iso, Windows' own IMAPI2), and the audit runs FROM THE MOUNTED
# IMAGE: strictly harder than a folder or a write-protected stick --
# nothing can be written there -- and the path -Iso tells a person to
# take. Touches: disk-image:RUNNER_TEMP\dz_ci.iso (mounted read-only,
# dismounted in finally).
$iso = Join-Path $env:RUNNER_TEMP 'dz_ci.iso'
$mi = (& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $src 'tools\make_usb_stick.ps1') -Iso $iso -ManifestStore $store 2>&1 | ForEach-Object { "$_" }) -join "`n"
Write-Host $mi
if ($LASTEXITCODE -ne 0) { throw 'make_usb_stick -Iso failed' }
if ($mi -notmatch 'no boot record' -or $mi -notmatch '\[OK\] SHA-256 of the image: [0-9a-f]{64}') { throw 'the image was not reported as built without a boot record' }
$leftStage = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'dz_iso_stage_*' -EA SilentlyContinue)
if ($leftStage.Count) { throw ("the staging folder was left behind: {0}" -f ($leftStage.FullName -join ', ')) }
$head = New-Object byte[] 131072
$fs = [IO.File]::OpenRead($iso); try { [void]$fs.Read($head, 0, $head.Length) } finally { $fs.Dispose() }
for ($sec = 16; $sec -lt 64; $sec++) {
  $o = $sec * 2048
  if ([Text.Encoding]::ASCII.GetString($head, $o + 1, 5) -cne 'CD001') { throw ("sector {0} of the image is not a volume descriptor" -f $sec) }
  if ($head[$o] -eq 0) { throw 'the image holds an El Torito boot record -- it must never be bootable' }
  if ($head[$o] -eq 255) { break }
}
$iv = (& .\tools\make_usb_stick.ps1 -Iso $iso -ManifestStore $store -Verify *>&1 | ForEach-Object { "$_" }) -join "`n"
if ($LASTEXITCODE -ne 0 -or $iv -notmatch '\[OK\] .* is exactly the image this laptop made') { throw ("a fresh image did not verify: {0}" -f $iv) }
$img = Mount-DiskImage -ImagePath $iso -Access ReadOnly -PassThru
try {
  $letter = $null
  for ($t = 0; $t -lt 10 -and -not $letter; $t++) { $letter = (Get-DiskImage -ImagePath $iso | Get-Volume).DriveLetter; if (-not $letter) { Start-Sleep -Seconds 1 } }
  if (-not $letter) { throw 'the mounted image has no drive letter after 10 s' }
  $isoStick = $letter + ':\doze_sec'
  # The image holds exactly the files its manifest lists, byte for byte.
  $man = @{}
  foreach ($ln in [IO.File]::ReadAllLines((Join-Path $isoStick 'STICK_MANIFEST.sha256'))) { if ($ln -match '^([0-9a-f]{64})  (.+)$') { $man[$matches[2]] = $matches[1] } }
  $onImg = @(Get-ChildItem -LiteralPath $isoStick -Recurse -File | Where-Object { $_.Name -ne 'STICK_MANIFEST.sha256' })
  if ($man.Count -lt 90 -or $onImg.Count -ne $man.Count) { throw ("the image holds {0} file(s), its manifest lists {1}" -f $onImg.Count, $man.Count) }
  foreach ($f in $onImg) {
    $rel = $f.FullName.Substring($isoStick.Length + 1)
    if (-not $man.ContainsKey($rel)) { throw ("a file on the image is not in its manifest: {0}" -f $rel) }
    if ((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower() -ne $man[$rel]) { throw ("a file on the image differs from its manifest: {0}" -f $rel) }
  }
  Write-Host ("the mounted image holds exactly the {0} files its manifest lists, byte for byte" -f $man.Count)
  $probe = Get-Item -LiteralPath (Join-Path $isoStick 'ThreatLists\ioc_hashes.txt')
  Write-Host ("MEASURED: a file on the mounted image: ReadOnly={0}, attributes={1}" -f $probe.IsReadOnly, $probe.Attributes)
  if (-not $probe.IsReadOnly) { throw 'a file on the mounted image is not ReadOnly -- the seed fix this step proves would be untested' }
  # Measured on the first run: the image's file system has no
  # alternate data streams at all -- asking for one throws "The
  # parameter is incorrect" (a terminating Win32Exception, whatever
  # -ErrorAction says) -- so no Mark of the Web can sit on its files.
  $mk2 = @(); $noStreams = 0
  foreach ($f in (Get-ChildItem -LiteralPath $isoStick -Recurse -File)) {
    try { if (Get-Item -LiteralPath $f.FullName -Stream 'Zone.Identifier' -EA Stop) { $mk2 += $f.FullName } }
    catch { if ($_.Exception -is [System.ComponentModel.Win32Exception]) { $noStreams++ } }
  }
  Write-Host ("MEASURED: {0} file(s) on the mounted image refuse a stream query (no alternate data streams on that file system); {1} carry Mark of the Web" -f $noStreams, $mk2.Count)
  if ($mk2.Count) { throw ("Mark of the Web reached the files on the image: {0}" -f (($mk2 | Select-Object -First 3) -join ', ')) }
  $wrote = $true
  try { [IO.File]::WriteAllText((Join-Path $isoStick 'dz_ci_write_probe.txt'), 'x') } catch { $wrote = $false }
  if ($wrote) { throw 'the mounted image accepted a write -- it is not read-only' }
  $out = (& (Join-Path $isoStick 'tests\field_test.ps1') -BatPath (Join-Path $isoStick 'doze_sec.bat') -NoConsoleLog *>&1 | ForEach-Object { "$_" }) -join "`n"
  $rc = $LASTEXITCODE
} finally {
  Dismount-DiskImage -ImagePath $iso | Out-Null
}
Write-Host $out
Write-Host ("field_test.ps1 (from the mounted read-only image) exit code: {0}" -f $rc)
if ($rc -ne 0) { throw "field_test.ps1 failed (see above)" }
$rep1 = Get-ChildItem 'C:\SecurityAudit\SecurityReport_*.txt' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ([IO.File]::ReadAllText($rep1.FullName) -notmatch 'ThreatLists: (\d+) seeded, (\d+) replaced' -or ([int]$matches[1] + [int]$matches[2]) -lt 1) { throw 'this run seeded or replaced no list from the image, so it does not test that the copies come out writable' }
$roLists = @(Get-ChildItem 'C:\SecurityAudit\ThreatLists' -File -EA SilentlyContinue | Where-Object { $_.IsReadOnly })
if ($roLists.Count) { throw ("runtime IOC list(s) seeded from the read-only image came out ReadOnly, so -updateTTP could never refresh them: {0}" -f (($roLists | ForEach-Object Name) -join ', ')) }
$iv2 = (& .\tools\make_usb_stick.ps1 -Iso $iso -ManifestStore $store -Verify *>&1 | ForEach-Object { "$_" }) -join "`n"
if ($LASTEXITCODE -ne 0) { throw ("the image no longer verifies after the run: {0}" -f $iv2) }
$isoT = Join-Path $env:RUNNER_TEMP 'dz_ci_changed.iso'
$ib = [IO.File]::ReadAllBytes($iso); $ib[$ib.Length - 1] = [byte](($ib[$ib.Length - 1] + 1) % 256); [IO.File]::WriteAllBytes($isoT, $ib)
$iv3 = (& .\tools\make_usb_stick.ps1 -Iso $isoT -ManifestStore $store -Verify *>&1 | ForEach-Object { "$_" }) -join "`n"
$ivrc = $LASTEXITCODE
Write-Host $iv3
if ($ivrc -ne 2 -or $iv3 -notmatch '\[UNVERIFIED\]') { throw ("an image with one changed byte must read UNVERIFIED, exit 2 (got {0})" -f $ivrc) }
Remove-Item -LiteralPath $isoT -Force
# The same change made to the image this laptop made, in place: CHANGED, exit 1.
[IO.File]::WriteAllBytes($iso, $ib)
$iv4 = (& .\tools\make_usb_stick.ps1 -Iso $iso -ManifestStore $store -Verify *>&1 | ForEach-Object { "$_" }) -join "`n"
$ivrc = $LASTEXITCODE
Write-Host $iv4
if ($ivrc -ne 1 -or $iv4 -notmatch '\[WARNING\] .* changed after this laptop made it') { throw ("the laptop's own image, changed in place, must read changed, exit 1 (got {0})" -f $ivrc) }
Remove-Item -LiteralPath $iso -Force
# MEASURED, declared either way: does Windows pass a downloaded image's
# Mark of the Web to the files inside it, and can a stream read on the
# mounted file system see it? (The docs say only "can": this prints
# what this build does.)
$isoM = Join-Path $env:RUNNER_TEMP 'dz_ci_marked.iso'
$mm = (& powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\make_usb_stick.ps1 -Iso $isoM -ManifestStore (Join-Path $env:RUNNER_TEMP 'dz_iso_m_store') 2>&1 | ForEach-Object { "$_" }) -join "`n"
if ($LASTEXITCODE -ne 0) { throw ("could not build the image for the Mark of the Web measurement: {0}" -f $mm) }
Set-Content -LiteralPath $isoM -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3"
$imgM = Mount-DiskImage -ImagePath $isoM -Access ReadOnly -PassThru
try {
  $lm = $null
  for ($t = 0; $t -lt 10 -and -not $lm; $t++) { $lm = (Get-DiskImage -ImagePath $isoM | Get-Volume).DriveLetter; if (-not $lm) { Start-Sleep -Seconds 1 } }
  $inner = $lm + ':\doze_sec\tools\exec_probe.ps1'
  $zs = $null; try { $zs = (Get-Content -LiteralPath $inner -Stream 'Zone.Identifier' -Raw -EA Stop) } catch { $zs = '(no stream readable: ' + $_.Exception.GetType().Name + ')' }
  Write-Host ("MEASURED: a marked image mounted; a file inside it reads Zone.Identifier as: {0}" -f (($zs -replace "`r?`n", ' ') ))
} finally { Dismount-DiskImage -ImagePath $isoM | Out-Null; Remove-Item -LiteralPath $isoM -Force -EA SilentlyContinue }
Write-Host 'ISO: built with no boot record, mounted read-only (writes refused), the audit ran from it, the runtime lists came out writable, and a one-byte change reads UNVERIFIED.'
# The proof lines must have actually executed -- not skipped -- on this elevated runner.
foreach ($must in @('RunOnce resume key: absent after the run', 'boot configuration (bcdedit /enum {bootmgr}): unchanged',
                    'report carries the READ-ONLY banner', 'report carries no TEST RUN banner',
                    'read-only skip declared: boot menu left as found', 'no known benign look-alike is reported above',
                    'RunOnce proof targets the value the audit writes (*WIN11_SecurityAudit_resume)',
                    'RunOnce resume path ends in \doze_sec.bat',
                    'PowerShell ran the audit''s helper scripts here (FullLanguage, policy allows them)')) {
  if ($out -notmatch [regex]::Escape($must)) { throw ("field_test output lacks the proof line: {0}" -f $must) }
}
if ($out -match '\[FAIL') { throw 'field_test printed a FAIL line' }
# Independent check, not trusting the script under test: the key is really absent.
# The value is named after the bat's SCRIPT_NAME, not its file name. This
# line (and field_test itself) looked for '*doze_sec_resume' -- a value the
# audit never writes -- so it could never have fired. Pinned by name, and
# field_test now cross-checks the name against the INIT 8 line the report
# prints, so a rename fails loudly instead of passing vacuously.
$ro = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -EA SilentlyContinue
if ($ro -and ($ro.PSObject.Properties.Name -contains '*WIN11_SecurityAudit_resume')) { throw 'RunOnce resume value exists after a -readonly run' }
# The stick copy is exactly what make_usb_stick put there (the audit
# ran from the read-only image above, which proves the stronger claim:
# it writes nothing into its own folder).
# (-Verify runs from the CHECKOUT's copy of the script, not the one in
# the download: a different copy of the checker must find the manifest
# the first one kept on this machine.)
$vf = (& .\tools\make_usb_stick.ps1 -ToFolder $stickRoot -ManifestStore $store -Verify *>&1 | ForEach-Object { "$_" }) -join "`n"
Write-Host $vf
if ($LASTEXITCODE -ne 0) { throw 'the audit changed files in its own folder (make_usb_stick -Verify differs) -- a write-protected stick would break' }
# Windows can give a stick a new volume ID in another USB port, so the
# recorded target no longer names it. A folder in a new place is the same shape
# here: -Verify must match it by content and say so, and a changed copy
# with no matching target must be UNVERIFIED (exit 2), never OK. (A
# copy, so the stick the audit ran from stays where later steps expect.)
$moved = Join-Path $env:RUNNER_TEMP 'dz_stick_moved'
Copy-Item -LiteralPath $stickRoot -Destination $moved -Recurse
$vm = (& .\tools\make_usb_stick.ps1 -ToFolder $moved -ManifestStore $store -Verify *>&1 | ForEach-Object { "$_" }) -join "`n"
Write-Host $vm
if ($LASTEXITCODE -ne 0 -or $vm -notmatch 'but it matches, file for file') { throw 'an unchanged copy in a new place was not matched by content' }
Add-Content -LiteralPath (Join-Path $moved 'doze_sec\tools\exec_probe.ps1') -Value '# changed on a visited machine'
$vt = (& .\tools\make_usb_stick.ps1 -ToFolder $moved -ManifestStore $store -Verify *>&1 | ForEach-Object { "$_" }) -join "`n"
$vrc = $LASTEXITCODE
Write-Host $vt
if ($vrc -ne 2 -or $vt -notmatch '\[UNVERIFIED\]' -or $vt -notmatch ': 1 difference\(s\) from this copy' -or $vt -match '\[OK\] The tool') { throw ("a copy in a new place that was ALSO changed must read UNVERIFIED with the difference count, exit 2 (got {0})" -f $vrc) }
Write-Host 'read-only field test: proven on this runner, run from a read-only ISO image made from an LF-only marked download; the stick folder from the same download is CRLF with no mark; a copy in a new place is matched by content, and one that also changed is UNVERIFIED.'
# The last call above is the deliberately UNVERIFIED -Verify (exit 2).
# This step's verdict is its throws; the runner's PowerShell wrapper
# would otherwise report that exit code as the step's (the #237 lesson).
$global:LASTEXITCODE = 0
exit 0
