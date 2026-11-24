# ioc_hash_check.ps1 -- Local SHA256 hash matching against ioc_hashes.txt
#
# Invoked from doze_sec.bat / doze_sec_noAdmin.bat as Section 18k. Reads
# the SENTINEL-X malware hash list from ThreatLists/ioc_hashes.txt, hashes
# a priority candidate set on disk, and emits [CRITICAL] for any match.
# This is the offline-only complement to Section 18j (-vt VirusTotal
# network lookup): no API key required, no rate limit, no network.
#
# IMPORTANT: This script computes SHA256 hashes of files ALREADY on disk.
# It does NOT download any payloads, does NOT submit anything over the
# network, and does NOT touch the files themselves.
#
# Format of ioc_hashes.txt: pipe-delimited rows, one per line:
#   SHA256|Family|Source
# Lines starting with # are comments and ignored.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File ioc_hash_check.ps1 -IocFile <path> [-MaxFiles N]
#
# Writes "$env:TEMP\dz_iochit_18k.txt" if any file is flagged so the .bat
# can increment IOC_HITS via the same marker-file pattern as 18b/c/d/e/h/j.
# A list that is missing or holds no valid row means the match did NOT run:
# it prints a [WARNING] ... NOT performed line and writes
# "$env:TEMP\dz_iochit_18k_gap.txt", which the .bat raises as its own
# gap-worded ledger row. It used to print "[INFO] ... skipped", which raised
# nothing and which Section 18's summary did not count as a gap, so the
# summary could call the sweep an all-clear.
#
# WHAT IT COULD NOT SEE IS SAID (2026-11-24). The walks ran with
# -EA SilentlyContinue and a file whose hash failed was skipped with
# `catch { continue }`, so a folder that refused to list, or a locked file,
# printed "[OK] ... no matches" over files nobody hashed. Get-HashCoverage
# holds the rule (-SelfTest pins it): a priority folder that could not be
# listed, or a file that could not be hashed, is "[WARNING] ... NOT performed
# in full" and the 18k gap marker -- on a standard-user token a folder outside
# the profile (C:\Windows\Temp) is a counted deferral instead
# (dz_iochit_18k_deferred.txt); a subfolder that refused is counted context;
# and the candidate cap is declared when it cut files off.

param(
    [string]$IocFile = '',
    [int]$MaxFiles = 500,
    [int]$RecentDriverDays = 90,
    [int]$RecentUserDays = 14,
    [string[]]$ScanDir = @(),
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

function ConvertTo-LineText {
    param([string]$s, [int]$Max = 200)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

# PURE. $Unlisted: @{ Dir; Error; Own } for priority folders that refused to
# list. Returns @{ Lines; Gap; Deferred }.
function Get-HashCoverage {
    param($Unlisted = @(), [int]$SubErrors = 0, [string[]]$HashFailed = @(), [int]$Capped = 0, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $gapDirs = @(); $defDirs = @()
    foreach ($u in @($Unlisted)) { if ($null -eq $u) { continue }; if ((-not $IsElevated) -and (-not $u.Own)) { $defDirs += $u } else { $gapDirs += $u } }
    $hf = @($HashFailed | Where-Object { $_ })
    $parts = @()
    if ($gapDirs.Count) { $parts += ([string]$gapDirs.Count + ' folder(s) could not be listed: ' + ((@($gapDirs | ForEach-Object { (ConvertTo-LineText ([string]$_.Dir)) + ' (' + (ConvertTo-LineText ([string]$_.Error) 80) + ')' })) -join '; ')) }
    if ($hf.Count) { $parts += ([string]$hf.Count + ' file(s) could not be hashed: ' + ((@($hf | Select-Object -First 5 | ForEach-Object { ConvertTo-LineText $_ })) -join '; ') + $(if ($hf.Count -gt 5) { '; and ' + ($hf.Count - 5) + ' more' } else { '' })) }
    $gap = ($parts.Count -gt 0)
    if ($gap) { [void]$out.Add(('[WARNING] File hash IOC match NOT performed in full -- ' + ($parts -join '; ') + ', so a known-bad file there would go unseen (T1105).')) }
    $def = 0
    if ($defDirs.Count) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] ' + $defDirs.Count + ' priority folder(s) cannot be listed from a standard-user token: ' + ((@($defDirs | ForEach-Object { ConvertTo-LineText ([string]$_.Dir) })) -join '; ') + ' -- re-run as administrator to hash them.'))
        $def = 1
    }
    if ($SubErrors -gt 0) { [void]$out.Add(('[INFO] ' + $SubErrors + ' subfolder(s) inside the priority folders could not be listed; their own folders were hashed.')) }
    if ($Capped -gt 0) { [void]$out.Add(('[INFO] ' + $Capped + ' more candidate file(s) were not hashed: the check stops at ' + $script:MaxFilesShown + ' files (-MaxFiles).')) }
    return @{ Lines = @($out.ToArray()); Gap = $gap; Deferred = $def }
}
$script:MaxFilesShown = $MaxFiles

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $c = Get-HashCoverage
    T 'every folder listed and every file hashed: nothing to say' ((-not $c.Gap) -and $c.Lines.Count -eq 0) ($c.Lines -join ' | ')
    $c = Get-HashCoverage -HashFailed @('C:\Users\me\Downloads\a.exe')
    T 'a file that could not be hashed is named and raised (the defect: catch { continue })' ($c.Gap -and ($c.Lines -join ' ') -match '^\[WARNING\] File hash IOC match NOT performed in full -- 1 file\(s\) could not be hashed: C:\\Users') ($c.Lines -join ' | ')
    $c = Get-HashCoverage -Unlisted @(@{ Dir = 'C:\Users\me\Downloads'; Error = 'UnauthorizedAccessException'; Own = $true }) -IsElevated $false
    T 'the user''s own Downloads refusing to list is a gap on any token' ($c.Gap -and $c.Deferred -eq 0) ($c.Lines -join ' | ')
    $c = Get-HashCoverage -Unlisted @(@{ Dir = 'C:\Windows\Temp'; Error = 'UnauthorizedAccessException'; Own = $false }) -IsElevated $false
    T 'a standard user refused C:\Windows\Temp: a counted deferral, never a row' ((-not $c.Gap) -and $c.Deferred -eq 1) ($c.Lines -join ' | ')
    $c = Get-HashCoverage -Unlisted @(@{ Dir = 'C:\Windows\Temp'; Error = 'denied'; Own = $false }) -IsElevated $true
    T 'an administrator refused a priority folder: a gap' ($c.Gap) ($c.Lines -join ' | ')
    $c = Get-HashCoverage -SubErrors 4 -Capped 12
    T 'refused subfolders and the cap are declared as context, not raised' ((-not $c.Gap) -and ($c.Lines -join ' ') -match '4 subfolder' -and ($c.Lines -join ' ') -match '12 more candidate file') ($c.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails ioc_hash_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] ioc_hash_check self-test: a folder that refused to list or a file that could not be hashed is a raised gap (a deferral for C:\Windows\Temp on a standard-user token), never under an [OK] that says nothing matched.'
    exit 0
}
if (-not $IocFile) { 'ioc_hash_check: -IocFile is required.'; exit 1 }
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.SecurityIdentifier]'S-1-5-32-544')) { $Elevated = 1 } } catch {}
}

if (-not (Test-Path -LiteralPath $IocFile)) {
    "[WARNING] File hash IOC match NOT performed -- $IocFile not found."
    New-Item "$env:TEMP\dz_iochit_18k_gap.txt" -Force | Out-Null
    return
}

# Parse SHA256|Family|Source rows. Skip comments + blank lines.
$hashTable = @{}
$rowCount = 0
foreach ($line in (Get-Content -LiteralPath $IocFile -EA SilentlyContinue)) {
    $t = $line.Trim()
    if (-not $t -or $t.StartsWith('#')) { continue }
    $parts = $t -split '\|', 3
    if ($parts.Count -lt 1) { continue }
    $h = $parts[0].Trim().ToLower()
    if ($h.Length -ne 64) { continue }  # SHA256 is 64 hex chars
    if ($h -notmatch '^[0-9a-f]{64}$') { continue }
    $family = if ($parts.Count -ge 2) { $parts[1].Trim() } else { '' }
    $source = if ($parts.Count -ge 3) { $parts[2].Trim() } else { '' }
    $hashTable[$h] = "$family ($source)"
    $rowCount++
}

if ($rowCount -eq 0) {
    "[WARNING] File hash IOC match NOT performed -- $IocFile holds no valid SHA256 rows."
    New-Item "$env:TEMP\dz_iochit_18k_gap.txt" -Force | Out-Null
    return
}

# Build candidate file list. Each priority folder must answer when asked to
# list itself; a subfolder that refuses is counted. -ScanDir is a CI-only hook
# that replaces the user folders.
$candidates = New-Object System.Collections.Generic.List[object]
$unlisted = @(); $subErrors = 0
$ownRoots = @(@($env:USERPROFILE, $env:TEMP, $env:LOCALAPPDATA) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' })
function Test-ListDir {
    param([string]$Dir)
    try { $null = [IO.Directory]::GetFileSystemEntries($Dir); return $true }
    catch [System.IO.DirectoryNotFoundException] { return $false }
    catch {
        $x = $_.Exception; if ($x.InnerException) { $x = $x.InnerException }
        $own = @($script:ownRoots | Where-Object { ($Dir.TrimEnd('\') + '\').StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
        $script:unlisted += @{ Dir = $Dir; Error = $x.GetType().Name; Own = $own }
        return $false
    }
}
$script:ownRoots = $ownRoots
$driverDir = Join-Path $env:SystemRoot 'System32\drivers'
if (-not $ScanDir.Count -and (Test-ListDir $driverDir)) {
    Get-ChildItem -LiteralPath $driverDir -Filter *.sys -EA SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-$RecentDriverDays) } |
        ForEach-Object { $candidates.Add($_) }
}
$userDirs = if ($ScanDir.Count) { $ScanDir } else { @(
    $env:TEMP,
    (Join-Path $env:USERPROFILE 'Downloads'),
    (Join-Path $env:LOCALAPPDATA 'Temp'),
    (Join-Path $env:SystemRoot 'Temp')
) }
$exts = @('.exe', '.dll', '.sys', '.ps1', '.vbs')
foreach ($d in ($userDirs | Where-Object { $_ } | Select-Object -Unique)) {
    if (-not (Test-ListDir $d)) { continue }
    $we = $null
    Get-ChildItem -LiteralPath $d -Recurse -File -EA SilentlyContinue -ErrorVariable we |
        Where-Object { $exts -contains $_.Extension.ToLower() -and $_.LastWriteTime -gt (Get-Date).AddDays(-$RecentUserDays) -and $_.Length -lt 650MB } |
        ForEach-Object { $candidates.Add($_) }
    # A subfolder removed mid-walk is churn, not a refusal.
    $subErrors += @($we | Where-Object { $_ -and $_.Exception -isnot [System.Management.Automation.ItemNotFoundException] -and $_.Exception -isnot [System.IO.DirectoryNotFoundException] }).Count
}
$unlisted = @($script:unlisted)

$all = @($candidates | Sort-Object FullName -Unique)
$capped = [Math]::Max(0, $all.Count - $MaxFiles)
$candidates = @($all | Select-Object -First $MaxFiles)
"[INFO] Local hash IOC check: $($candidates.Count) candidate file(s) vs $rowCount IOC hashes."

$hits = @()
$hashFailed = @()
foreach ($f in $candidates) {
    try {
        $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -EA Stop).Hash.ToLower()
    } catch {
        # Removed since it was listed: churn. Anything else was not hashed.
        if (-not (Test-Path -LiteralPath $f.FullName)) { continue }
        $hashFailed += $f.FullName; continue
    }
    if ($hashTable.ContainsKey($h)) {
        $hits += "  [CRITICAL] $($f.FullName) -- IOC HASH MATCH: $($hashTable[$h]) (sha256 $h)"
    }
}

$cov = Get-HashCoverage -Unlisted $unlisted -SubErrors $subErrors -HashFailed $hashFailed -Capped $capped -IsElevated ($Elevated -eq 1)
if ($hits.Count -gt 0) {
    $hits
    "[CRITICAL] Local hash IOC: $($hits.Count) file(s) matched a known-bad hash from ioc_hashes.txt. QUARANTINE IMMEDIATELY."
    New-Item "$env:TEMP\dz_iochit_18k.txt" -Force | Out-Null
} elseif ($cov.Gap) {
    "[OK] Local hash IOC: no matches among the $($candidates.Count - $hashFailed.Count) file(s) that could be hashed."
} else {
    "[OK] Local hash IOC: no matches against $rowCount known-bad SHA256 hashes ($($candidates.Count) file(s) hashed)."
}
foreach ($l in $cov.Lines) { $l }
if ($cov.Gap) { New-Item "$env:TEMP\dz_iochit_18k_gap.txt" -Force | Out-Null }
if ($cov.Deferred -gt 0) { Set-Content -LiteralPath (Join-Path $env:TEMP 'dz_iochit_18k_deferred.txt') -Value '1' -Encoding ASCII }
