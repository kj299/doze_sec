# vt_check.ps1 -- VirusTotal SHA256 reputation lookup for doze_sec Section 18j
#
# Invoked by doze_sec.bat / doze_sec_noAdmin.bat when -vt is passed.
# Reads the VT API key from $env:USERPROFILE\.vt_token (single line).
# Hashes a small priority candidate set on disk and queries
# https://www.virustotal.com/api/v3/files/{sha256} for each.
# Writes findings to stdout (the .bat captures into the report).
# Writes "$env:TEMP\dz_iochit_18j.txt" if any file is flagged so the .bat
# can increment IOC_HITS.
#
# IMPORTANT: this script computes SHA256 hashes of files ALREADY on disk
# and submits only the hash to the VT API. It does NOT upload file
# contents and does NOT download any payloads.
#
# Free-tier VT API limits: 4 lookups/min, 500/day, 15.5K/month. Sleep 16s
# between calls to stay under the per-minute cap.
#
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File vt_check.ps1 [-MaxFiles N]

param(
    [int]$MaxFiles = 20,
    [int]$RecentDriverDays = 30,
    [int]$RecentUserDays = 7,
    [int]$SleepSeconds = 16,
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Continue'

$tokenFile = Join-Path $env:USERPROFILE '.vt_token'
if (-not (Test-Path $tokenFile)) {
    '[INFO] VT check skipped -- $env:USERPROFILE\.vt_token not found.'
    '       Create the file with your VT API key (single line, no quotes) to enable this check.'
    return
}
$token = (Get-Content $tokenFile -Raw -EA SilentlyContinue)
if ($token) { $token = $token.Trim() }
if (-not $token) {
    '[INFO] VT check skipped -- .vt_token is empty.'
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
    Get-ChildItem $d -Recurse -Include '*.exe','*.dll','*.ps1','*.vbs' -EA SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-$RecentUserDays) -and $_.Length -lt 650MB } |
        ForEach-Object { $candidates.Add($_) }
}

$candidates = @($candidates | Sort-Object FullName -Unique | Select-Object -First $MaxFiles)
if ($candidates.Count -eq 0) {
    '[OK] VT check: no candidate files in priority directories.'
    return
}

$total = $candidates.Count
$est = [math]::Round(($total * $SleepSeconds) / 60.0, 1)
"[INFO] VT check: $total candidate file(s). Estimated runtime: ~$est min (free-tier rate limit, $SleepSeconds s/file)."

$malCount = 0
$idx = 0
$abortReason = $null
foreach ($f in $candidates) {
    $idx++
    $hash = $null
    try {
        $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -EA Stop).Hash.ToLower()
    } catch {
        "  [SKIP] $($f.FullName) -- hash failed: $($_.Exception.Message)"
        continue
    }

    try {
        $resp = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/files/$hash" `
            -Headers @{ 'x-apikey' = $token } `
            -UseBasicParsing `
            -TimeoutSec $TimeoutSeconds `
            -EA Stop
        $stats = ($resp.Content | ConvertFrom-Json).data.attributes.last_analysis_stats
        $mal = [int]$stats.malicious
        $tot = ($stats.PSObject.Properties | ForEach-Object { [int]$_.Value } | Measure-Object -Sum).Sum
        if ($mal -gt 0) {
            "  [CRITICAL] $($f.FullName) -- VT $mal/$tot engines flagged (sha256 $hash)"
            $malCount++
        } else {
            "  [OK] $($f.FullName) -- VT 0/$tot clean"
        }
    } catch {
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        if ($statusCode -eq 404) {
            "  [INFO] $($f.FullName) -- not in VT corpus (sha256 $hash)"
        } elseif ($statusCode -eq 401) {
            "  [ERROR] VT API key rejected (HTTP 401) -- check ~/.vt_token contents"
            $abortReason = '401 unauthorized'
            break
        } elseif ($statusCode -eq 429) {
            "  [WARNING] VT rate limit exceeded (HTTP 429) -- aborting after $($idx - 1) successful lookup(s)"
            $abortReason = '429 rate limit'
            break
        } else {
            "  [ERROR] VT lookup failed for $($f.FullName) (HTTP $statusCode): $($_.Exception.Message)"
        }
    }

    if ($idx -lt $total) { Start-Sleep -Seconds $SleepSeconds }
}

if ($malCount -gt 0) {
    "[CRITICAL] VirusTotal: $malCount file(s) flagged as malicious. Quarantine and investigate."
    New-Item "$env:TEMP\dz_iochit_18j.txt" -Force | Out-Null
} elseif ($abortReason) {
    "[INFO] VirusTotal check aborted ($abortReason). Partial results above."
} else {
    "[OK] VirusTotal: no malicious matches in $total candidate files."
}
