# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It builds a scratch folder under RUNNER_TEMP, plants files in it and puts a
# deny ACL on one subfolder; do not run it on a machine you use. It lives in
# .github/ so it never reaches a USB stick (make_usb_stick.ps1 excludes the
# directory), and outside the workflow file because GitHub refuses to run a
# workflow file over its size limit -- silently: the jobs simply never appear.
$ErrorActionPreference = 'Stop'
$st = (.\tools\file_walk_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'file_walk_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 36) { throw "file_walk_check self-test ran only $n case(s)" }
function RunW([string]$Check, [hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_walk_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\file_walk_check.ps1 -Check $Check -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    # Every run must reach its end marker; the bat raises a row without it.
    if (-not @(Get-ChildItem $md -Filter 'dz_*_done.txt').Count) { throw "$Check wrote no done marker: $o" }
    return @{ Out = $o; Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_done.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
function Expect($r, [string]$Markers, [string]$Pattern, [string]$What) { if ($r.Markers -ne $Markers -or $r.Out -notmatch $Pattern) { throw ("{0}: expected [{1}] and /{2}/, got [{3}] -- {4}" -f $What, $Markers, $Pattern, $r.Markers, $r.Out) } }
# LIVE: this runner's real TEMP and Outlook folder, MEASURED. Whatever is
# there, each check must state a verdict and print no PowerShell error.
foreach ($c in 'TempAds', 'TempHtml', 'OutlookMsg') {
  $sw = [Diagnostics.Stopwatch]::StartNew(); $r = RunW $c @{}
  Write-Host ("MEASURED: {0} on the runner's own folder: markers [{1}] in {2:N1}s" -f $c, $r.Markers, $sw.Elapsed.TotalSeconds)
  if ($r.Out -notmatch '(?m)^\[(OK|WARNING|DEFERRED - ADMIN REQUIRED)\]') { throw "$c printed no verdict on the runner: $($r.Out)" }
  if ($r.Out -match '(?m)^\[OK\]' -and $r.Markers) { throw "$c printed [OK] and wrote a marker: [$($r.Markers)]" }
}
# EVERY STATE through the real walker, on a scratch tree.
# Touches: file:%RUNNER_TEMP%\dz_ci_walk_<pid> (removed in finally).
$base = $env:RUNNER_TEMP; if (-not $base) { $base = $env:TEMP }
$root = Join-Path $base "dz_ci_walk_$PID"; $k = @{ Root = $root }
$locked = Join-Path $root 'locked'; $outside = $null
try {
  # The folder is not there: TEMP missing is a gap; no Outlook folder is an answer.
  Expect (RunW 'TempAds' $k) 'dz_ads_gap' '(?m)^\[WARNING\] Alternate-data-stream check NOT performed' 'root missing'
  Expect (RunW 'OutlookMsg' $k) '' '(?m)^\[OK\] No Outlook data folder for this user' 'no Outlook folder'
  New-Item -ItemType Directory -Path (Join-Path $root 'sub [1]\deep') -Force | Out-Null
  # The benign twins: a downloaded file's Zone.Identifier, a small page, an old message.
  $ben = Join-Path $root 'sub [1]\downloaded.txt'; Set-Content -LiteralPath $ben -Value 'x'
  Set-Content -LiteralPath $ben -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3"
  Set-Content -LiteralPath (Join-Path $root 'small.html') -Value '<html></html>'
  $old = Join-Path $root 'old.msg'; Set-Content -LiteralPath $old -Value 'x'; (Get-Item -LiteralPath $old).LastWriteTime = (Get-Date).AddDays(-200)
  Expect (RunW 'TempAds' $k) '' '(?m)^\[OK\] No suspicious ADS in Temp\.' 'benign: Zone.Identifier only'
  Expect (RunW 'TempHtml' $k) '' '(?m)^\[OK\] No oversized HTML/HTA files in user TEMP\.' 'benign: a small page'
  Expect (RunW 'OutlookMsg' $k) '' '(?m)^\[OK\] No recent Outlook \.msg/\.oft artefacts\.' 'benign: an old message'
  # The malign twins, in a folder whose name holds brackets.
  $evil = Join-Path $root 'sub [1]\deep\note.txt'; Set-Content -LiteralPath $evil -Value 'x'
  Set-Content -LiteralPath $evil -Stream 'dz_ci_payload' -Value 'hidden'
  [IO.File]::WriteAllBytes((Join-Path $root 'sub [1]\deep\big.HTA'), (New-Object byte[] 300000))
  Set-Content -LiteralPath (Join-Path $root 'sub [1]\new.oft') -Value 'x'
  Expect (RunW 'TempAds' $k) 'dz_ads_hit' '(?m)^\[WARNING\] Alternate data stream \(T1564\.004\): .*note\.txt :: dz_ci_payload' 'a planted stream'
  # A hit beside an incomplete walk: BOTH markers, so one hit cannot hide the rest.
  $r = RunW 'TempAds' (@{ Root = $root; BudgetSeconds = 0 })
  if ($r.Out -match '(?m)^\[OK\]' -or $r.Markers -notmatch 'dz_ads_gap') { throw "an out-of-time stream walk was not a raised gap: [$($r.Markers)] $($r.Out)" }
  Expect (RunW 'TempHtml' $k) 'dz_htmltemp_hit' '(?m)^\[WARNING\] Large HTML/HTA files in Temp:' 'a 300 KB .HTA'
  $r = RunW 'TempHtml' $k; if ($r.Out -notmatch 'big\.HTA') { throw "the large file was not listed: $($r.Out)" }
  Expect (RunW 'OutlookMsg' $k) 'dz_outlookmsg_hit' '(?m)^\[WARNING\] Recent Outlook \.msg/\.oft artefacts' 'a recent .oft'
  # A junction is NOT followed (it can loop, or lead to a whole drive), and that is said.
  $outside = Join-Path $base "dz_ci_walk_out_$PID"; New-Item -ItemType Directory -Path $outside -Force | Out-Null
  [IO.File]::WriteAllBytes((Join-Path $outside 'elsewhere.html'), (New-Object byte[] 300000))
  & cmd.exe /c mklink /J (Join-Path $root 'jn') $outside | Out-Null
  $r = RunW 'TempHtml' $k
  if ($r.Out -notmatch '(?m)^\[INFO\] 1 link\(s\) to another folder .* NOT followed' -or $r.Out -match 'elsewhere\.html') { throw "a junction was followed, or skipped without a word: $($r.Out)" }
  & cmd.exe /c rmdir (Join-Path $root 'jn') | Out-Null
  # A tree deeper than 260 characters is read, not reported as unreadable.
  $deep = $root; while ($deep.Length -lt 300) { $deep = Join-Path $deep ('d' * 40) }
  try {
    [void][IO.Directory]::CreateDirectory('\\?\' + $deep); [IO.File]::WriteAllBytes('\\?\' + (Join-Path $deep 'deep.html'), (New-Object byte[] 300000))
    $r = RunW 'TempHtml' $k
    Write-Host ("MEASURED: a {0}-character folder path: markers [{1}]" -f $deep.Length, $r.Markers)
    # Read it (the hit) or say it could not be (the gap): never [OK] past a file that was not examined.
    $read = ($r.Markers -eq 'dz_htmltemp_hit' -and $r.Out -match 'deep\.html'); $said = ($r.Markers -eq 'dz_htmltemp_gap' -and $r.Out -notmatch '(?m)^\[OK\]')
    if (-not ($read -or $said)) { throw "a file under a long path was neither read nor declared unread: [$($r.Markers)] $($r.Out)" }
  } finally { & cmd.exe /c rmdir /s /q ('\\?\' + (Join-Path $root ('d' * 40))) | Out-Null }
  # Out of time: a declared gap beside nothing, never [OK].
  Remove-Item -LiteralPath (Join-Path $root 'sub [1]') -Recurse -Force
  $r = RunW 'TempHtml' (@{ Root = $root; BudgetSeconds = 0 }); Expect $r 'dz_htmltemp_gap' '(?m)^\[WARNING\] Oversized HTML/HTA check NOT performed in full' 'budget 0'
  if ($r.Out -match '(?m)^\[OK\]') { throw "an out-of-time walk printed [OK]: $($r.Out)" }
  # THE READ THAT FAILS: a subfolder this account is denied.
  New-Item -ItemType Directory -Path $locked -Force | Out-Null
  [IO.File]::WriteAllBytes((Join-Path $locked 'hidden.html'), (New-Object byte[] 300000))
  $denied = $false
  try {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $locked /deny ("{0}:(OI)(CI)(RD)" -f $me) | Out-Null
    try { $null = Get-ChildItem -LiteralPath $locked -Force -ErrorAction Stop } catch { $denied = $true }
  } catch { Write-Host ("[ SKIP ] the deny ACL could not be set on this image ({0})" -f $_.Exception.Message) }
  if ($denied) {
    $r = RunW 'TempHtml' $k
    if ($r.Markers -ne 'dz_htmltemp_gap' -or $r.Out -match '(?m)^\[OK\]' -or $r.Out -notmatch 'NOT performed in full') { throw "a folder that cannot be read was not a raised gap: [$($r.Markers)] $($r.Out)" }
    Write-Host 'file walk: a folder this account is denied is a raised gap, never an all-clear'
    # A FILE whose streams cannot be read: Get-Item -Stream reports that as a bare Win32 error.
    & icacls.exe $locked /reset /T /C /Q | Out-Null; Remove-Item -LiteralPath $locked -Recurse -Force
    $nf = Join-Path $root 'noread.txt'; Set-Content -LiteralPath $nf -Value 'x'
    & icacls.exe $nf /deny ("{0}:(R)" -f $me) | Out-Null
    $r = RunW 'TempAds' $k
    Write-Host ("MEASURED: a file this account may not read, in the stream check: markers [{0}]" -f $r.Markers)
    # Windows may still list a file's stream names without read access; then [OK] is a real answer.
    $gap = ($r.Markers -eq 'dz_ads_gap' -and $r.Out -notmatch '(?m)^\[OK\]'); $ok = ($r.Markers -eq '' -and $r.Out -match '(?m)^\[OK\] No suspicious ADS')
    if (-not ($gap -or $ok)) { throw "a file this account may not read gave neither a raised gap nor a clean answer: [$($r.Markers)] $($r.Out)" }
    & icacls.exe $nf /reset /C /Q | Out-Null
  } else { Write-Host '[ SKIP ] denied-folder case not run: this account can still list the folder through the deny rule; the self-test pins the judgement' }
} finally {
  # Native tools write to stderr; under 'Stop' that would end the cleanup early.
  $ErrorActionPreference = 'Continue'
  if (Test-Path -LiteralPath $locked) { & icacls.exe $locked /reset /T /C /Q | Out-Null }
  Get-ChildItem -LiteralPath $root -Force -EA SilentlyContinue | ForEach-Object { & icacls.exe $_.FullName /reset /C /Q | Out-Null }
  if (Test-Path -LiteralPath (Join-Path $root 'jn')) { & cmd.exe /c rmdir (Join-Path $root 'jn') | Out-Null }
  Remove-Item -LiteralPath $root -Recurse -Force -EA SilentlyContinue
  if ($outside) { Remove-Item -LiteralPath $outside -Recurse -Force -EA SilentlyContinue }
  if (Test-Path -LiteralPath $root) { throw "the CI scratch folder $root could not be removed" }
}
Write-Host 'file walk: every state read through the real walker for all three checks'
# LIVE, the three later checks on the runner's own folders, MEASURED: each
# must state a verdict, and the ransomware walk must not raise on a clean image.
foreach ($c in 'RansomExt', 'TokenCache', 'CredStores') {
  $sw = [Diagnostics.Stopwatch]::StartNew(); $r = RunW $c @{}
  Write-Host ("MEASURED: {0} on the runner's own folders: markers [{1}] in {2:N1}s" -f $c, $r.Markers, $sw.Elapsed.TotalSeconds)
  if ($r.Out -notmatch '(?m)^\[(OK|INFO|WARNING|CRITICAL)') { throw "$c printed no verdict on the runner: $($r.Out)" }
}
$r = RunW 'RansomExt' @{}
if ($r.Markers -match 'ransom_hit') { throw "a clean runner raised the ransomware finding: $($r.Out)" }
# THE RANSOMWARE WALK, both directions, on a scratch tree.
# Touches: file:%RUNNER_TEMP%\dz_ci_ransom_<pid> (removed in finally).
$rr = Join-Path $base "dz_ci_ransom_$PID"
try {
  New-Item -ItemType Directory -Path (Join-Path $rr 'a\b\c\d') -Force | Out-Null
  # The benign twins: a name that holds a ransomware word but not as the extension.
  Set-Content -LiteralPath (Join-Path $rr 'a\lockbit-report.txt') -Value 'x'
  Set-Content -LiteralPath (Join-Path $rr 'a\b\black.pdf') -Value 'x'
  Expect (RunW 'RansomExt' @{ Root = $rr }) '' '(?m)^\[OK\] No files with known ransomware extensions in user directories\.' 'benign: ransomware words that are not the extension'
  # Deeper than the walk looks: said, never silently examined or passed.
  Set-Content -LiteralPath (Join-Path $rr 'a\b\c\d\deep.akira') -Value 'x'
  $r = RunW 'RansomExt' @{ Root = $rr }
  if ($r.Markers -or $r.Out -notmatch '3 folder levels deep; deeper files were not examined') { throw "the depth limit was not stated, or a file below it was graded: [$($r.Markers)] $($r.Out)" }
  # The malign twin, three levels down.
  Set-Content -LiteralPath (Join-Path $rr 'a\b\c\budget.xlsx.akira') -Value 'x'
  $r = RunW 'RansomExt' @{ Root = $rr }
  Expect $r 'dz_ransom_hit' '(?m)^\[CRITICAL\]\[T1486\] Files with ransomware-associated extensions found:' 'an .akira file three levels down'
  if ($r.Out -notmatch 'budget\.xlsx\.akira') { throw "the encrypted file was not listed by name: $($r.Out)" }
  # The read that fails: TEMP-style missing root.
  Expect (RunW 'RansomExt' @{ Root = (Join-Path $rr 'no_such_folder') }) 'dz_ransom_gap' '(?m)^\[WARNING\] Ransomware-extension check NOT performed -- ' 'the folder not found'
  # Token cache: recent activity is an INFO listing, never a counted finding.
  Set-Content -LiteralPath (Join-Path $rr 'a\cache.dat') -Value 'x'
  $r = RunW 'TokenCache' @{ Root = $rr }
  if ($r.Markers -or $r.Out -notmatch '(?m)^\[INFO\] Recent AAD/token cache activity') { throw "recent token-cache activity was not an INFO listing: [$($r.Markers)] $($r.Out)" }
} finally {
  Remove-Item -LiteralPath $rr -Recurse -Force -EA SilentlyContinue
  if (Test-Path -LiteralPath $rr) { throw "the CI scratch folder $rr could not be removed" }
}
Write-Host 'file walk: ransomware extensions found by extension at the stated depth; words that are not the extension are not'
exit 0
