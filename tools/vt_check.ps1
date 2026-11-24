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
# WHAT WAS NOT LOOKED UP IS SAID (2026-11-24). It printed "[OK] VirusTotal:
# no malicious matches in N candidate files." when every lookup had failed
# (no network, TLS, a 5xx), and "[INFO] ... skipped" or "[INFO] ... aborted"
# when the key was missing, rejected or rate-limited -- all after the person
# had asked for this check with -vt. Get-VtSummary holds the rule (-SelfTest
# pins it): every candidate answered (a verdict, or VT has never seen it) is
# the [OK]; anything not answered is "[WARNING] VirusTotal check NOT
# performed" with dz_iochit_18j_gap.txt; a hit and a gap are both raised.
#
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File vt_check.ps1 [-MaxFiles N]

param(
    [int]$MaxFiles = 20,
    [int]$RecentDriverDays = 30,
    [int]$RecentUserDays = 7,
    [int]$SleepSeconds = 16,
    [int]$TimeoutSeconds = 30,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# PURE. $Total candidates; $Mal flagged; $Clean answered clean; $Unknown not
# in VT's corpus (an answer, said); $Failed not answered; $Why the reason
# ('' when nothing failed). Returns @{ Lines; Hit; Gap }.
function Get-VtSummary {
    param([int]$Total, [int]$Mal, [int]$Clean, [int]$Unknown, [int]$Failed, [string]$Why = '')
    $out = @()
    if ($Mal -gt 0) { $out += "[CRITICAL] VirusTotal: $Mal file(s) flagged as malicious. Quarantine and investigate." }
    if ($Failed -gt 0) {
        $out += ('[WARNING] VirusTotal check NOT performed in full -- ' + $Failed + ' of ' + $Total + ' candidate file(s) were not looked up' + $(if ($Why) { ' (' + $Why + ')' } else { '' }) + ', so a known-bad file among them would go unseen (T1105).')
    }
    if ($Mal -eq 0) {
        if ($Failed -eq 0) { $out += "[OK] VirusTotal: no malicious matches in $Total candidate file(s)$(if ($Unknown) { " ($Unknown not in VirusTotal's corpus)" })." }
        elseif ($Clean + $Unknown -gt 0) { $out += ('[OK] VirusTotal: no malicious matches among the ' + ($Clean + $Unknown) + ' file(s) it answered for.') }
    }
    return @{ Lines = $out; Hit = ($Mal -gt 0); Gap = ($Failed -gt 0) }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $v = Get-VtSummary -Total 5 -Mal 0 -Clean 4 -Unknown 1 -Failed 0
    T 'every candidate answered: the [OK], saying how many VT had never seen' ((-not ($v.Hit -or $v.Gap)) -and ($v.Lines -join ' ') -match '^\[OK\] VirusTotal: no malicious matches in 5 candidate file\(s\) \(1 not in') ($v.Lines -join ' | ')
    $v = Get-VtSummary -Total 5 -Mal 0 -Clean 0 -Unknown 0 -Failed 5 -Why 'no network'
    T 'every lookup failed: a raised gap, never "[OK] no malicious matches in 5" (the defect)' ($v.Gap -and ($v.Lines -join ' ') -notmatch '\[OK\]' -and ($v.Lines -join ' ') -match 'NOT performed in full -- 5 of 5 .*no network') ($v.Lines -join ' | ')
    $v = Get-VtSummary -Total 5 -Mal 1 -Clean 2 -Unknown 0 -Failed 2 -Why '429 rate limit'
    T 'a hit and a gap are both raised' ($v.Hit -and $v.Gap) ($v.Lines -join ' | ')
    $v = Get-VtSummary -Total 5 -Mal 0 -Clean 3 -Unknown 0 -Failed 2
    T 'a partial run says what it covered' ($v.Gap -and ($v.Lines -join ' ') -match 'among the 3 file\(s\) it answered for') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails vt_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] vt_check self-test: every candidate answered is [OK]; anything not looked up is a raised gap, never an all-clear.'
    exit 0
}
Remove-Item -LiteralPath (Join-Path $env:TEMP 'dz_iochit_18j_gap.txt') -Force -EA SilentlyContinue

$tokenFile = Join-Path $env:USERPROFILE '.vt_token'
# -vt asked for this check: no key is a check not performed, raised.
$token = $null
try { $token = (Get-Content -LiteralPath $tokenFile -Raw -ErrorAction Stop) } catch {}
if ($token) { $token = $token.Trim() }
if (-not $token) {
    '[WARNING] VirusTotal check NOT performed -- %USERPROFILE%\.vt_token is missing, empty or unreadable. Create it with your VT API key (one line, no quotes) to enable this check.'
    New-Item "$env:TEMP\dz_iochit_18j_gap.txt" -Force | Out-Null
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
$cleanCount = 0
$unknownCount = 0
$failedCount = 0
$failWhy = @()
$idx = 0
$abortReason = $null
foreach ($f in $candidates) {
    $idx++
    $hash = $null
    try {
        $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -EA Stop).Hash.ToLower()
    } catch {
        "  [INFO] $($f.FullName) -- hash failed, not looked up: $($_.Exception.Message)"
        $failedCount++; if ($failWhy -notcontains 'a file could not be hashed') { $failWhy += 'a file could not be hashed' }
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
            $cleanCount++
        }
    } catch {
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        if ($statusCode -eq 404) {
            "  [INFO] $($f.FullName) -- not in VT corpus (sha256 $hash)"
            $unknownCount++
        } elseif ($statusCode -eq 401) {
            "  [INFO] VT API key rejected (HTTP 401) -- check ~/.vt_token contents"
            $abortReason = '401 unauthorized'
            break
        } elseif ($statusCode -eq 429) {
            "  [INFO] VT rate limit exceeded (HTTP 429) -- stopping after $($idx - 1) lookup(s)"
            $abortReason = '429 rate limit'
            break
        } else {
            "  [INFO] VT lookup failed for $($f.FullName) (HTTP $statusCode): $($_.Exception.Message)"
            $failedCount++; if ($failWhy -notcontains 'a lookup failed') { $failWhy += 'a lookup failed' }
        }
    }

    if ($idx -lt $total) { Start-Sleep -Seconds $SleepSeconds }
}

# A run that stopped early (401, 429) did not look up the rest.
if ($abortReason) {
    $failedCount = $total - $cleanCount - $unknownCount - $malCount
    $failWhy += $abortReason
}
$sum = Get-VtSummary -Total $total -Mal $malCount -Clean $cleanCount -Unknown $unknownCount -Failed $failedCount -Why ($failWhy -join '; ')
$sum.Lines
if ($sum.Hit) { New-Item "$env:TEMP\dz_iochit_18j.txt" -Force | Out-Null }
if ($sum.Gap) { New-Item "$env:TEMP\dz_iochit_18j_gap.txt" -Force | Out-Null }
