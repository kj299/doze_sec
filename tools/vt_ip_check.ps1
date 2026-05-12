# vt_ip_check.ps1 -- VirusTotal IP reputation lookup for doze_sec Section 18l
#
# Invoked by doze_sec.bat / doze_sec_noAdmin.bat when -vt is passed.
# Enumerates active TCP connections via Get-NetTCPConnection (falls back
# to netstat -ano), filters out RFC1918 / link-local / loopback / IPv4-
# multicast addresses, deduplicates, caps at -MaxIps, and queries the
# VirusTotal v3 IP-info API for each:
#   GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
#
# Per-IP output includes:
#   - Credibility tier (HIGH / MED / LOW) based on engine flag count,
#     boosted one tier when a curated top-tier engine flags the IP
#   - The top 3 engines that flagged it (engine name + verdict text)
#   - Local PROCESS(es) connecting to that IP (PID + name from
#     Get-NetTCPConnection.OwningProcess), so the analyst doesn't have
#     to manually pivot from IP back to local process
#
# IMPORTANT: Only IP literals are submitted to VT. No connection
# metadata, no hostnames, no payloads. last_analysis_results is part
# of the metadata response the API already returns -- no additional
# data submitted upstream.
#
# Free-tier VT API limits: 4 lookups/min, 500/day. With the default
# cap of 10 IPs this completes in ~2.5 minutes (9 sleeps x 16 s + 10
# calls).
#
# Writes "$env:TEMP\dz_iochit_18l.txt" if any IP is flagged at MED or
# HIGH credibility so the .bat can increment IOC_HITS.
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

# Top-tier AV/EDR engines: a hit from any of these boosts credibility one tier.
# Curated based on industry FP rates + research reputation; not exhaustive.
$topTier = @('Kaspersky','ESET','BitDefender','Sophos','Microsoft','McAfee',
             'CrowdStrike-Falcon','Symantec','TrendMicro','Avast','AVG',
             'GData','F-Secure','Emsisoft','MalwareBytes','SentinelOne',
             'Fortinet','Webroot','VirusTotal') | ForEach-Object { $_.ToLower() }

# Filter out non-routable / uninteresting addresses
function Test-PublicIp {
    param([string]$Ip)
    if (-not $Ip) { return $false }
    if ($Ip -eq '0.0.0.0' -or $Ip -eq '::' -or $Ip -eq '*') { return $false }
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
    if ($Ip -match '^(::1|fe80:|fc[0-9a-f][0-9a-f]?:|fd[0-9a-f][0-9a-f]?:|ff[0-9a-f][0-9a-f]?:)') { return $false }
    if ($Ip -match ':') { return $true }
    return $false
}

# Build IP -> list of "process (PID)" map. Try Get-NetTCPConnection first.
$ipToProc = @{}
$usedNetstat = $false
try {
    $conns = Get-NetTCPConnection -State Established -EA Stop
    foreach ($c in $conns) {
        if (-not (Test-PublicIp $c.RemoteAddress)) { continue }
        $procName = 'unknown'
        if ($c.OwningProcess) {
            $p = Get-Process -Id $c.OwningProcess -EA SilentlyContinue
            if ($p) { $procName = $p.Name }
        }
        $key = $c.RemoteAddress
        if (-not $ipToProc.ContainsKey($key)) { $ipToProc[$key] = New-Object System.Collections.Generic.HashSet[string] }
        [void]$ipToProc[$key].Add("$procName (PID $($c.OwningProcess))")
    }
} catch {
    $usedNetstat = $true
    # netstat fallback. -b would give the process but requires admin; -n -o gives PID.
    $netstat = & netstat -ano 2>$null
    foreach ($line in $netstat) {
        if ($line -match '^\s*TCP\s+\S+\s+(\S+):\d+\s+ESTABLISHED\s+(\d+)') {
            $remote = $matches[1]; $pid_ = [int]$matches[2]
            if (-not (Test-PublicIp $remote)) { continue }
            $procName = 'unknown'
            $p = Get-Process -Id $pid_ -EA SilentlyContinue
            if ($p) { $procName = $p.Name }
            if (-not $ipToProc.ContainsKey($remote)) { $ipToProc[$remote] = New-Object System.Collections.Generic.HashSet[string] }
            [void]$ipToProc[$remote].Add("$procName (PID $pid_)")
        }
    }
}

if ($ipToProc.Count -eq 0) {
    '[OK] VT IP check: no public-routable established TCP remote endpoints.'
    return
}

$ips = @($ipToProc.Keys | Sort-Object | Select-Object -First $MaxIps)
$total = $ips.Count
$est = [math]::Round((($total - 1) * $SleepSeconds) / 60.0, 1)
"[INFO] VT IP check: $($ipToProc.Count) public remote IP(s) seen, querying $total (cap=$MaxIps). Estimated runtime: ~$est min (free-tier rate limit, $SleepSeconds s/IP)."
if ($usedNetstat) { '[INFO] Get-NetTCPConnection unavailable; using netstat -ano fallback (process correlation still works).' }

$malCount = 0
$abortReason = $null
$idx = 0
foreach ($ip in $ips) {
    $idx++
    $procs = if ($ipToProc.ContainsKey($ip)) { ($ipToProc[$ip] | Sort-Object) -join ', ' } else { 'unknown' }
    try {
        $resp = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/$ip" `
            -Headers @{ 'x-apikey' = $token } `
            -UseBasicParsing `
            -TimeoutSec $TimeoutSeconds `
            -EA Stop
        $data = $resp.Content | ConvertFrom-Json
        $stats = $data.data.attributes.last_analysis_stats
        $results = $data.data.attributes.last_analysis_results
        $mal = [int]$stats.malicious
        $sus = [int]$stats.suspicious
        $tot = ($stats.PSObject.Properties | ForEach-Object { [int]$_.Value } | Measure-Object -Sum).Sum
        $country = $data.data.attributes.country
        $asn = $data.data.attributes.asn
        $owner = $data.data.attributes.as_owner

        if ($mal -eq 0 -and $sus -eq 0) {
            "  [OK] $ip -- VT 0/$tot clean (AS$asn $owner, $country)"
            "         local process(es): $procs"
            continue
        }

        # Extract malicious-flagging engines for attribution
        $malEngines = @()
        $topTierHit = $false
        if ($results) {
            foreach ($prop in $results.PSObject.Properties) {
                $r = $prop.Value
                if ($r.category -eq 'malicious') {
                    $engine = $prop.Name
                    $verdict = if ($r.result) { $r.result } else { 'malicious' }
                    $malEngines += [pscustomobject]@{ Engine = $engine; Verdict = $verdict }
                    if ($topTier -contains $engine.ToLower()) { $topTierHit = $true }
                }
            }
        }

        # Credibility tier
        $tier = 'LOW'
        if ($mal -ge 5) { $tier = 'HIGH' }
        elseif ($mal -ge 2) { $tier = 'MED' }
        # Boost one level if a top-tier engine flagged
        if ($topTierHit) {
            if ($tier -eq 'LOW') { $tier = 'MED' }
            elseif ($tier -eq 'MED') { $tier = 'HIGH' }
        }

        # Map tier to output prefix
        $prefix = switch ($tier) {
            'HIGH' { '[CRITICAL]' }
            'MED'  { '[WARNING]' }
            default { '[INFO]' }
        }

        # Build summary line
        $boostNote = if ($topTierHit) { ' (top-tier engine flagged: tier boosted)' } else { '' }
        "  $prefix $ip -- VT $tier credibility: $mal malicious / $sus suspicious / $tot engines$boostNote"
        "         AS$asn $owner, $country"
        "         local process(es): $procs"
        if ($malEngines.Count -gt 0) {
            $top3 = $malEngines | Sort-Object Engine | Select-Object -First 3
            '         flagged by:'
            foreach ($e in $top3) {
                $tag = if ($topTier -contains $e.Engine.ToLower()) { ' [top-tier]' } else { '' }
                "           - $($e.Engine)$tag : $($e.Verdict)"
            }
            if ($malEngines.Count -gt 3) {
                "           ...and $($malEngines.Count - 3) more engine(s)"
            }
        }

        # Count toward IOC_HITS only at MED or HIGH credibility
        if ($tier -eq 'HIGH' -or $tier -eq 'MED') { $malCount++ }
    } catch {
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        if ($statusCode -eq 404) {
            "  [INFO] $ip -- not in VT IP corpus"
            "         local process(es): $procs"
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
            "         local process(es): $procs"
        }
    }
    if ($idx -lt $total) { Start-Sleep -Seconds $SleepSeconds }
}

if ($malCount -gt 0) {
    "[CRITICAL] VirusTotal IP: $malCount remote endpoint(s) flagged at MED or HIGH credibility. Investigate the listed local processes (Get-Process -Id <PID>) to identify what is connecting."
    "[INFO] LOW-credibility hits (1 engine, non-top-tier) are reported above as [INFO] only -- often false positives."
    New-Item "$env:TEMP\dz_iochit_18l.txt" -Force | Out-Null
} elseif ($abortReason) {
    "[INFO] VirusTotal IP check aborted ($abortReason). Partial results above."
} else {
    "[OK] VirusTotal IP: no MED-or-HIGH credibility malicious matches in $total remote endpoint(s)."
}
