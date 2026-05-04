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

param(
    [Parameter(Mandatory=$true)]
    [string]$IocFile,
    [int]$MaxFiles = 500,
    [int]$RecentDriverDays = 90,
    [int]$RecentUserDays = 14
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path -LiteralPath $IocFile)) {
    "[INFO] Local hash IOC check skipped -- $IocFile not found."
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
    "[INFO] Local hash IOC check skipped -- $IocFile contains no valid SHA256 rows."
    return
}

# Build candidate file list. Driver enumeration requires admin; PS will
# silently skip unreadable files via -EA SilentlyContinue.
$candidates = New-Object System.Collections.Generic.List[object]
$driverDir = Join-Path $env:SystemRoot 'System32\drivers'
if (Test-Path $driverDir) {
    Get-ChildItem $driverDir -Filter *.sys -EA SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-$RecentDriverDays) } |
        ForEach-Object { $candidates.Add($_) }
}
$userDirs = @(
    $env:TEMP,
    (Join-Path $env:USERPROFILE 'Downloads'),
    (Join-Path $env:LOCALAPPDATA 'Temp'),
    (Join-Path $env:SystemRoot 'Temp')
)
foreach ($d in $userDirs) {
    if (-not (Test-Path $d)) { continue }
    Get-ChildItem $d -Recurse -Include '*.exe','*.dll','*.sys','*.ps1','*.vbs' -EA SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-$RecentUserDays) -and $_.Length -lt 650MB } |
        ForEach-Object { $candidates.Add($_) }
}

$candidates = @($candidates | Sort-Object FullName -Unique | Select-Object -First $MaxFiles)
if ($candidates.Count -eq 0) {
    "[OK] Local hash IOC check: no candidate files in priority directories. ($rowCount IOC hashes loaded)"
    return
}

"[INFO] Local hash IOC check: $($candidates.Count) candidate file(s) vs $rowCount IOC hashes."

$hits = @()
foreach ($f in $candidates) {
    try {
        $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -EA Stop).Hash.ToLower()
    } catch { continue }
    if ($hashTable.ContainsKey($h)) {
        $hits += "  [CRITICAL] $($f.FullName) -- IOC HASH MATCH: $($hashTable[$h]) (sha256 $h)"
    }
}

if ($hits.Count -gt 0) {
    $hits
    "[CRITICAL] Local hash IOC: $($hits.Count) file(s) matched a known-bad hash from ioc_hashes.txt. QUARANTINE IMMEDIATELY."
    New-Item "$env:TEMP\dz_iochit_18k.txt" -Force | Out-Null
} else {
    "[OK] Local hash IOC: no matches against $rowCount known-bad SHA256 hashes."
}
