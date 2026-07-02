# vt_self_check.ps1 -- Pre-flight VirusTotal integrity check for the
# binaries doze_sec relies on during the audit.
#
# Invoked from doze_sec.bat / doze_sec_noAdmin.bat early in pre-flight
# when (a) network is available and (b) ~/.vt_token exists. Hashes the
# critical binaries the audit will invoke (PWSH host, wmic, wevtutil,
# reg) and queries the VirusTotal v3 file-info API for each. Aborts
# the audit if any are flagged as malicious -- a compromised system
# binary would invalidate every downstream finding.
#
# IMPORTANT: This script computes SHA256 hashes of binaries already
# on disk and submits only the hash to VT. It does NOT upload file
# contents and does NOT download any payloads.
#
# Exit codes:
#   0 = all checked binaries clean (or unknown to VT)
#   1 = at least one binary flagged malicious -- HARD FAIL, audit aborts
#   2 = no token / no network / cannot proceed (caller treats as skip)
#
# Free-tier VT API limits: 4 lookups/min, 500/day. With 4 default
# binaries this completes in ~50 seconds (3 sleeps x 16 s + 4 calls).

param(
    [string[]]$Binaries,
    [int]$SleepSeconds = 16,
    [int]$TimeoutSeconds = 20
)

$ErrorActionPreference = 'Continue'

# powershell.exe -File binds a cmd-side comma list (-Binaries "a","b","c") as
# ONE [string[]] element containing literal commas -- no array splitting is
# performed for -File arguments. Split here so both binding shapes work. The
# call sites pass fixed system-binary paths, which never contain commas.
$Binaries = @($Binaries |
    ForEach-Object { $_ -split ',' } |
    ForEach-Object { $_.Trim().Trim('"') } |
    Where-Object { $_ })

if (-not $Binaries -or $Binaries.Count -eq 0) {
    '[INFO] VT self-check: no binaries supplied -- nothing to verify.'
    exit 2
}

$tokenFile = Join-Path $env:USERPROFILE '.vt_token'
if (-not (Test-Path $tokenFile)) {
    '[INFO] VT self-check skipped -- $env:USERPROFILE\.vt_token not found.'
    exit 2
}
$token = (Get-Content $tokenFile -Raw -EA SilentlyContinue)
if ($token) { $token = $token.Trim() }
if (-not $token) {
    '[INFO] VT self-check skipped -- .vt_token is empty.'
    exit 2
}

# Resolve binary paths and hash them up front so a single missing
# file does not waste rate-limited VT calls on the others.
$entries = @()
foreach ($b in $Binaries) {
    if (-not $b) { continue }
    $resolved = $null
    if (Test-Path -LiteralPath $b) {
        $resolved = (Resolve-Path -LiteralPath $b).Path
    } else {
        # Try PATH lookup
        $cmd = Get-Command $b -EA SilentlyContinue
        if ($cmd -and $cmd.Source) { $resolved = $cmd.Source }
    }
    if (-not $resolved) {
        "  [INFO] $b -- not found, skipped"
        continue
    }
    try {
        $h = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256 -EA Stop).Hash.ToLower()
        $entries += [pscustomobject]@{ Path = $resolved; Hash = $h }
    } catch {
        "  [INFO] $resolved -- hash failed: $($_.Exception.Message)"
    }
}

if ($entries.Count -eq 0) {
    '[INFO] VT self-check: no resolvable binaries to verify.'
    exit 2
}

"[INFO] VT self-check: verifying $($entries.Count) critical binar(ies). Free-tier rate limit applies (~$SleepSeconds s/file)."

$malicious = @()
$idx = 0
foreach ($e in $entries) {
    $idx++
    try {
        $resp = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/files/$($e.Hash)" `
            -Headers @{ 'x-apikey' = $token } `
            -UseBasicParsing `
            -TimeoutSec $TimeoutSeconds `
            -EA Stop
        $stats = ($resp.Content | ConvertFrom-Json).data.attributes.last_analysis_stats
        $mal = [int]$stats.malicious
        $tot = ($stats.PSObject.Properties | ForEach-Object { [int]$_.Value } | Measure-Object -Sum).Sum
        if ($mal -gt 0) {
            "  [CRITICAL] $($e.Path) -- VT $mal/$tot engines flagged (sha256 $($e.Hash))"
            $malicious += $e
        } else {
            "  [OK] $($e.Path) -- VT 0/$tot clean"
        }
    } catch {
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        if ($statusCode -eq 404) {
            "  [INFO] $($e.Path) -- not in VT corpus (sha256 $($e.Hash))"
        } elseif ($statusCode -eq 401) {
            "  [ERROR] VT API key rejected (HTTP 401) -- aborting integrity check"
            exit 2
        } elseif ($statusCode -eq 429) {
            "  [WARNING] VT rate limit (HTTP 429) -- aborting integrity check after $($idx - 1) lookup(s)"
            exit 2
        } else {
            "  [INFO] $($e.Path) -- VT lookup failed (HTTP $statusCode); cannot verify"
        }
    }
    if ($idx -lt $entries.Count) { Start-Sleep -Seconds $SleepSeconds }
}

if ($malicious.Count -gt 0) {
    ""
    "[CRITICAL] $($malicious.Count) script-critical binar(ies) flagged as malicious by VirusTotal."
    "[CRITICAL] Audit results from this system CANNOT be trusted. Aborting before any check runs."
    "[CRITICAL] Investigate via independent forensics; do not act on prior reports from this host."
    exit 1
}

'[OK] VT self-check: all critical script binaries clean.'
exit 0
