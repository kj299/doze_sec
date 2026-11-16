# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner.
# It reads the runner's real system folders and builds a scratch folder
# C:\dz_ci_dll_<pid> holding look-alike DLLs (removed in finally and proven
# gone). Nothing in a real system folder is touched. It lives in .github/ so
# it never reaches a USB stick.
$ErrorActionPreference = 'Stop'
$st = (.\tools\system_dll_sig_check.ps1 -SelfTest) -join "`n"
if ($LASTEXITCODE -ne 0) { Write-Host $st; throw 'system_dll_sig_check -SelfTest failed' }
$n = @($st -split "`n" | Where-Object { $_ -match '^\[OK\]   ' }).Count
if ($n -lt 13) { throw "system_dll_sig_check self-test ran only $n case(s)" }
function RunD([hashtable]$Extra) {
  $md = Join-Path $env:TEMP ("dz_ci_dll_{0}_{1}" -f $PID, [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory -Path $md -Force | Out-Null
  try {
    $o = (& .\tools\system_dll_sig_check.ps1 -MarkerDir $md @Extra) -join "`n"; Write-Host $o
    if ($o -match 'is not recognized|CategoryInfo') { throw "PowerShell error text: $o" }
    if (-not (Test-Path (Join-Path $md 'dz_sysdll_done.txt'))) { throw "no done marker: $o" }
    return @{ Out = $o; Markers = (@(Get-ChildItem $md -Filter 'dz_*.txt' | Where-Object { $_.Name -notlike '*_done.txt' } | ForEach-Object { $_.BaseName } | Sort-Object) -join ',') }
  } finally { Remove-Item $md -Recurse -Force -EA SilentlyContinue }
}
# LIVE: the runner's real System32, SysWOW64 and Program Files. Every DLL
# there is Microsoft's, and an administrator can read every signature: no hit,
# no gap, and [OK] names how many it checked.
$r = RunD @{}
Write-Host "MEASURED: the runner's system-path DLLs: markers [$($r.Markers)]"
if ($r.Markers -or $r.Out -notmatch '(?m)^\[OK\] No suspicious unsigned DLLs found in system paths \((\d+) file') { throw "the runner's own system DLLs did not read clean and fully checked: [$($r.Markers)] $($r.Out)" }
if ([int]$Matches[1] -lt 5) { throw "only $($Matches[1]) system DLL(s) were checked on the runner -- System32 holds most of the nine names" }
$dir = "C:\dz_ci_dll_$PID"
try {
  New-Item -ItemType Directory -Path "$dir\a" -Force | Out-Null
  # The benign twin: a real Microsoft-signed version.dll.
  Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\version.dll') -Destination "$dir\a\version.dll"
  $r = RunD @{ Dirs = @("$dir\a") }
  if ($r.Markers -or $r.Out -notmatch '(?m)^\[OK\] No suspicious unsigned DLLs found in system paths \(1 file') { throw "a Microsoft-signed version.dll did not read clean: [$($r.Markers)] $($r.Out)" }
  Write-Host 'system dll: a Microsoft-signed version.dll reads clean'
  # Its malign twin: the same file with one byte changed -- the signature no
  # longer matches (HashMismatch), the shape of a tampered DLL.
  $bytes = [IO.File]::ReadAllBytes((Join-Path $env:SystemRoot 'System32\winhttp.dll'))
  $mid = [int]($bytes.Length / 2); $bytes[$mid] = $bytes[$mid] -bxor 0xFF
  [IO.File]::WriteAllBytes("$dir\a\winhttp.dll", $bytes)
  $r = RunD @{ Dirs = @("$dir\a") }
  Write-Host "MEASURED: a winhttp.dll with one byte changed reads: $(@($r.Out -split "`n" | Where-Object { $_ -match 'winhttp' }) -join ' | ')"
  if ($r.Markers -ne 'dz_sysdll_hit' -or $r.Out -notmatch '(?m)^\[WARNING\]\[T1574\.001\] Unsigned/suspicious DLLs in system paths:' -or $r.Out -notmatch 'winhttp\.dll \[SIG: (HashMismatch|NotSigned)\]') { throw "a tampered winhttp.dll was not the WARNING naming it: [$($r.Markers)] $($r.Out)" }
  # A file Windows cannot evaluate (not a PE image), ALONE in its folder so
  # the tampered twin above cannot supply the marker: never [OK], never
  # silent. Windows decides the status; it is MEASURED and must land in the
  # bucket the rule gives it (UnknownError and the like: a gap; NotSigned: a hit).
  New-Item -ItemType Directory -Path "$dir\b" -Force | Out-Null
  Set-Content -LiteralPath "$dir\b\dbghelp.dll" -Value 'not a dll' -Encoding ASCII
  $sig = [string](Get-AuthenticodeSignature -LiteralPath "$dir\b\dbghelp.dll").Status
  $r = RunD @{ Dirs = @("$dir\b") }
  Write-Host "MEASURED: a text file named dbghelp.dll: Windows says $sig; the tool reads [$($r.Markers)] $(@($r.Out -split "`n" | Where-Object { $_ -match 'dbghelp' }) -join ' | ')"
  $want = $(if (@('NotSigned', 'HashMismatch', 'NotTrusted') -contains $sig) { 'dz_sysdll_hit' } else { 'dz_sysdll_gap' })
  if ($r.Markers -ne $want -or $r.Out -notmatch 'dbghelp\.dll' -or $r.Out -match '(?m)^\[OK\]') { throw "a non-PE dbghelp.dll (status $sig) was not [$want] naming it: [$($r.Markers)] $($r.Out)" }
  # A folder this account is refused: a gap, never [OK].
  New-Item -ItemType Directory -Path "$dir\locked" -Force | Out-Null
  & icacls.exe "$dir\locked" /deny ('*' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value + ':(RD)') | Out-Null
  $r = RunD @{ Dirs = @("$dir\locked") }
  if ($r.Markers -eq 'dz_sysdll_gap' -and $r.Out -match 'could not be listed') { Write-Host 'system dll: a folder this account is refused is a raised gap' }
  elseif ($r.Out -match '(?m)^\[OK\]' -and -not $r.Markers) { Write-Host '[ SKIP ] the deny rule did not hold for an administrator here (listing still worked); the self-test pins the judgement' }
  else { throw "a refused folder was neither a gap nor a declared skip: [$($r.Markers)] $($r.Out)" }
} catch {
  Write-Host ("::error::" + $_.Exception.Message); throw
} finally {
  $ErrorActionPreference = 'Continue'
  if (Test-Path -LiteralPath $dir) { & icacls.exe $dir /reset /T /Q | Out-Null; Remove-Item -LiteralPath $dir -Recurse -Force -EA SilentlyContinue }
  if (Test-Path -LiteralPath $dir) { throw "cleanup failed: the scratch folder $dir could not be removed" }
}
exit 0
