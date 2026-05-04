# vt_ip_check.ps1 -- VirusTotal IP reputation lookup for doze_sec Section 18l
#
# Invoked by doze_sec.bat / doze_sec_noAdmin.bat when -vt is passed.
# Enumerates active TCP connections via Get-NetTCPConnection (falls back
# to netstat -ano), filters out RFC1918 / link-local / loopback / IPv4-
# multicast addresses, deduplicates, caps at -MaxIps, and queries the
# VirusTotal v3 IP-info API for each:
#   GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
#
# IMPORTANT: Only IP literals are submitted to VT. No connection
# metadata, no hostnames, no payloads. Same privacy guarantee as the
# file-hash check in vt_check.ps1.
#
# Free-tier VT API limits: 4 lookups/min, 500/day. With the default
# cap of 10 IPs this completes in ~2.5 minutes (9 sleeps x 16 s + 10
# calls). Combined with vt_check.ps1's 20 hashes and vt_self_check.ps1's
# 4 binaries, a full -vt run uses ~34 of the 500 daily lookups.
#
# Writes "$env:TEMP\dz_iochit_18l.txt" if any IP is flagged so the .bat
# can increment IOC_HITS.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File vt_ip_check.ps1 [-MaxIps N]

param(
    [int]$MaxIps = 10,
    [int]$SleepSeconds = 16,
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Continue'

$tokenFile = Join-Path $env:USERPROFILE '.vt_token'
if (-not (Test-Path $tokenFile)) {
    '[INFO] VT IP check skipped -- $env:USERPROFILE\.vt_token not found.'
    return
}
$token = (Get-Content $tokenFile -Raw -EA SilentlyContinue)
if ($token) { $token = $token.Trim() }
if (-not $token) {
    '[INFO] VT IP check skipped -- .vt_token is empty.'
    return
}

# Filter out non-routable / uninteresting addresses
function Test-PublicIp {
    param([string]$Ip)
    if (-not $Ip) { return $false }
    if ($Ip -eq '0.0.0.0' -or $Ip -eq '::' -or $Ip -eq '*') { return $false }
    # IPv4 literal check (very permissive; netstat output is well-formed)
    if ($Ip -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        $a = [int]$matches[1]; $b = [int]$matches[2]
        if ($a -eq 10) { return $false }                       # 10.0.0.0/8
        if ($a -eq 127) { return $false }                      # loopback
        if ($a -eq 169 -and $b -eq 254) { return $false }      # link-local
        if ($a -eq 172 -and ($b -ge 16 -and $b -le 31)) { return $false }  # 172.16/12
        if ($a -eq 192 -and $b -eq 168) { return $false }      # 192.168/16
        if ($a -ge 224) { return $false }                      # multicast/reserved
        if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return $false }  # CGNAT
        return $true
    }
    # IPv6: skip link-local (fe80::), loopback (::1), ULA (fc00::/7), multicast (ff00::/8)
    if ($Ip -match '^(::1|fe80:|fc[0-9a-f][0-9a-f]?:|fd[0-9a-f][0-9a-f]?:|ff[0-9a-f][0-9a-f]?:)') { return $false }
    if ($Ip -match ':') { return $true }
    return $false
}

# Collect remote IPs from active TCP connections
$remoteIps = New-Object System.Collections.Generic.HashSet[string]

# Try Get-NetTCPConnection first (Win8+, cleaner output)
try {
    $conns = Get-NetTCPConnection -State Established -EA Stop
    foreach ($c in $conns) {
        if (Test-PublicIp $c.RemoteAddress) {
            [void]$remoteIps.Add($c.RemoteAddress)
        }
    }
} catch {
    # Fallback: netstat -ano | parse ESTABLISHED rows
    $netstat = & netstat -ano 2>$null
    foreach ($line in $netstat) {
        if ($line -match '^\s*TCP\s+\S+\s+(\S+):\d+\s+ESTABLISHED') {
            $remote = $matches[1]
            if (Test-PublicIp $remote) { [void]$remoteIps.Add($remote) }
        }
    }
}

if ($remoteIps.Count -eq 0) {
    '[OK] VT IP check: no public-routable established TCP remote endpoints.'
    return
}

$ips = @($remoteIps | Sort-Object | Select-Object -First $MaxIps)
$total = $ips.Count
$est = [math]::Round((($total - 1) * $SleepSeconds) / 60.0, 1)
"[INFO] VT IP check: $($remoteIps.Count) public remote IP(s) seen, querying $total (cap=$MaxIps). Estimated runtime: ~$est min (free-tier rate limit, $SleepSeconds s/IP)."

$malCount = 0
$idx = 0
$abortReason = $null
foreach ($ip in $ips) {
    $idx++
    try {
        $resp = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/$ip" `
            -Headers @{ 'x-apikey' = $token } `
            -UseBasicParsing `
            -TimeoutSec $TimeoutSeconds `
            -EA Stop
        $data = $resp.Content | ConvertFrom-Json
        $stats = $data.data.attributes.last_analysis_stats
        $mal = [int]$stats.malicious
        $sus = [int]$stats.suspicious
        $tot = ($stats.PSObject.Properties | ForEach-Object { [int]$_.Value } | Measure-Object -Sum).Sum
        $country = $data.data.attributes.country
        $asn = $data.data.attributes.asn
        $owner = $data.data.attributes.as_owner
        if ($mal -gt 0) {
            "  [CRITICAL] $ip -- VT $mal malicious / $sus suspicious / $tot engines (AS$asn $owner, $country)"
            $malCount++
        } elseif ($sus -gt 0) {
            "  [WARNING] $ip -- VT $sus suspicious / $tot engines (AS$asn $owner, $country)"
        } else {
            "  [OK] $ip -- VT 0/$tot clean (AS$asn $owner, $country)"
        }
    } catch {
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        if ($statusCode -eq 404) {
            "  [INFO] $ip -- not in VT IP corpus"
        } elseif ($statusCode -eq 401) {
            "  [ERROR] VT API key rejected (HTTP 401) -- check ~/.vt_token contents"
            $abortReason = '401 unauthorized'
            break
        } elseif ($statusCode -eq 429) {
            "  [WARNING] VT rate limit (HTTP 429) -- aborting after $($idx - 1) IP lookup(s)"
            $abortReason = '429 rate limit'
            break
        } else {
            "  [INFO] $ip -- VT lookup failed (HTTP $statusCode)"
        }
    }
    if ($idx -lt $total) { Start-Sleep -Seconds $SleepSeconds }
}

if ($malCount -gt 0) {
    "[CRITICAL] VirusTotal IP: $malCount remote endpoint(s) flagged as malicious. Investigate the connections (netstat -ano + Get-Process) to identify the local processes."
    New-Item "$env:TEMP\dz_iochit_18l.txt" -Force | Out-Null
} elseif ($abortReason) {
    "[INFO] VirusTotal IP check aborted ($abortReason). Partial results above."
} else {
    "[OK] VirusTotal IP: no malicious matches in $total remote endpoint(s)."
}
