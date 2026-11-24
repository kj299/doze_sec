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
#   2 = NOT performed in full: a binary could not be hashed or looked up,
#       the key was missing/rejected, or VT rate-limited us. The caller
#       RAISES it (2026-11-24): it used to read as a skip, and a run where
#       every lookup failed printed "[OK] ... all critical script binaries
#       clean" and exited 0 -- an integrity check that checked nothing,
#       reading as a pass.
#   A binary that does not exist on this Windows (wmic on 24H2+) is not a
#   gap: the audit cannot be running it.
#
# Free-tier VT API limits: 4 lookups/min, 500/day. With 4 default
# binaries this completes in ~50 seconds (3 sleeps x 16 s + 4 calls).

param(
    [string[]]$Binaries,
    [int]$SleepSeconds = 16,
    [int]$TimeoutSeconds = 20,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# PURE. The closing verdict and exit code from the counts.
function Get-VtSelfVerdict {
    param([int]$Checked, [int]$Malicious, [int]$Unverified, [string]$Why = '')
    if ($Malicious -gt 0) { return @{ Exit = 1; Line = '' } }
    if ($Unverified -gt 0) {
        return @{ Exit = 2; Line = ('[WARNING] VT pre-flight integrity check NOT performed in full -- ' + $Unverified + ' of ' + $Checked + ' script-critical binar(ies) could not be verified' + $(if ($Why) { ' (' + $Why + ')' } else { '' }) + '. The audit continues, but a tampered binary among them would go unseen.') }
    }
    return @{ Exit = 0; Line = '[OK] VT self-check: all critical script binaries clean.' }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $v = Get-VtSelfVerdict -Checked 3 -Malicious 0 -Unverified 3 -Why 'a lookup failed'
    T 'every lookup failed: exit 2 and a NOT-performed line, never the [OK] and exit 0 (the defect)' ($v.Exit -eq 2 -and $v.Line -match '^\[WARNING\] .*NOT performed in full -- 3 of 3 ') "$($v.Exit) $($v.Line)"
    $v = Get-VtSelfVerdict -Checked 3 -Malicious 0 -Unverified 0
    T 'every binary answered clean: exit 0 and the [OK]' ($v.Exit -eq 0 -and $v.Line -match '^\[OK\]') "$($v.Exit) $($v.Line)"
    $v = Get-VtSelfVerdict -Checked 3 -Malicious 1 -Unverified 2
    T 'a flagged binary is exit 1 whatever else failed' ($v.Exit -eq 1) "$($v.Exit)"
    if ($fails) { Write-Output "[FAIL] $fails vt_self_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] vt_self_check self-test: an unverified binary is exit 2 with a NOT-performed line, never exit 0.'
    exit 0
}

# powershell.exe -File binds a cmd-side comma list (-Binaries "a","b","c") as
# ONE [string[]] element containing literal commas -- no array splitting is
# performed for -File arguments. Split here so both binding shapes work. The
# call sites pass fixed system-binary paths, which never contain commas.
$Binaries = @($Binaries |
    ForEach-Object { $_ -split ',' } |
    ForEach-Object { $_.Trim().Trim('"') } |
    Where-Object { $_ })

if (-not $Binaries -or $Binaries.Count -eq 0) {
    '[WARNING] VT pre-flight integrity check NOT performed -- no binaries were supplied.'
    exit 2
}

# The bat runs this only when %USERPROFILE%\.vt_token exists, so a key that
# cannot be read here is a check the person set up and did not get.
$tokenFile = Join-Path $env:USERPROFILE '.vt_token'
$token = $null
$tokErr = ''
try { $token = (Get-Content -LiteralPath $tokenFile -Raw -ErrorAction Stop) } catch { $tokErr = $_.Exception.Message }
if ($token) { $token = $token.Trim() }
if (-not $token) {
    '[WARNING] VT pre-flight integrity check NOT performed -- %USERPROFILE%\.vt_token is ' + $(if ($tokErr) { 'unreadable (' + $tokErr + ')' } else { 'empty' }) + '.'
    exit 2
}

# Resolve binary paths and hash them up front so a single missing
# file does not waste rate-limited VT calls on the others.
$entries = @()
$unverified = 0
$hashFailed = 0
$why = @()
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
        "  [INFO] $resolved -- hash failed, not verified: $($_.Exception.Message)"
        $unverified++; $hashFailed++; if ($why -notcontains 'a binary could not be hashed') { $why += 'a binary could not be hashed' }
    }
}

if ($entries.Count -eq 0) {
    if ($unverified -gt 0) { (Get-VtSelfVerdict -Checked $unverified -Malicious 0 -Unverified $unverified -Why ($why -join '; ')).Line; exit 2 }
    '[WARNING] VT pre-flight integrity check NOT performed -- none of the supplied binaries could be found.'
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
            "  [INFO] VT API key rejected (HTTP 401) -- stopping the integrity check"
            $unverified += ($entries.Count - $idx + 1); $why += '401 unauthorized'
            break
        } elseif ($statusCode -eq 429) {
            "  [INFO] VT rate limit (HTTP 429) -- stopping the integrity check after $($idx - 1) lookup(s)"
            $unverified += ($entries.Count - $idx + 1); $why += '429 rate limit'
            break
        } else {
            "  [INFO] $($e.Path) -- VT lookup failed (HTTP $statusCode); not verified"
            $unverified++; if ($why -notcontains 'a lookup failed') { $why += 'a lookup failed' }
        }
    }
    if ($idx -lt $entries.Count) { Start-Sleep -Seconds $SleepSeconds }
}

if ($malicious.Count -gt 0) {
    ""
    "[CRITICAL] $($malicious.Count) script-critical binar(ies) flagged as malicious by VirusTotal."
    # Consequence and next step, both [INFO]: the finding is the line above.
    # This block aborts the whole audit, so its weight comes from that, not
    # from repeating the tag three times.
    "[INFO] Audit results from this system CANNOT be trusted. Aborting before any check runs."
    "[INFO] Investigate via independent forensics; do not act on prior reports from this host."
    exit 1
}

$v = Get-VtSelfVerdict -Checked ($entries.Count + $hashFailed) -Malicious 0 -Unverified $unverified -Why ($why -join '; ')
$v.Line
exit $v.Exit
