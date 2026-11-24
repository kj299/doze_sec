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
# WHAT WAS NOT LOOKED UP IS SAID (2026-11-24), as in vt_check: a failed
# lookup, a 401 or a 429 left "[OK] VirusTotal IP: no ... matches in N remote
# endpoint(s)" or an [INFO]; a missing key after -vt was an [INFO]. Any of
# them is now "[WARNING] VirusTotal IP check NOT performed" with
# dz_iochit_18l_gap.txt. And the connection list: Get-NetTCPConnection
# -State Established THROWS when no connection matches, so a quiet machine
# fell back to netstat, whose fallback matched the English word ESTABLISHED
# (German Windows prints HERGESTELLT) and read [OK] having parsed nothing.
# The CIM query now asks for every connection and filters by the State
# property; netstat is parsed by COLUMN (Get-NetstatTcpRows), and a fallback
# that recovers no TCP row at all -- every Windows has listening sockets --
# is a gap, not an empty list.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File vt_ip_check.ps1 [-MaxIps N]
#   pwsh -NoProfile -ExecutionPolicy Bypass -File vt_ip_check.ps1 -SelfTest   (no token, no network)

param(
    [int]$MaxIps = 10,
    [int]$SleepSeconds = 16,
    [int]$TimeoutSeconds = 30,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# Top-tier AV/EDR engines: a hit from any of these boosts credibility one tier.
# Curated based on industry FP rates + research reputation; not exhaustive.
$topTier = @('Kaspersky','ESET','BitDefender','Sophos','Microsoft','McAfee',
             'CrowdStrike-Falcon','Symantec','TrendMicro','Avast','AVG',
             'GData','F-Secure','Emsisoft','MalwareBytes','SentinelOne',
             'Fortinet','Webroot','VirusTotal') | ForEach-Object { $_.ToLower() }

# Credibility tier (pure): weighted combination of malicious + suspicious
# counts, malicious at twice the weight; a curated top-tier engine flagging
# the IP boosts one tier. HIGH -> [CRITICAL], MED -> [WARNING], LOW -> [INFO];
# only MED and HIGH count toward IOC_HITS. The corpus entry
# [vt-low-credibility] catalogues the LOW half: a single non-top-tier engine is
# usually a false positive and is context, never a finding. This tool needs a
# VirusTotal token and -vt (which -readonly refuses), so it never runs in CI;
# the judgement lives here so -SelfTest can, without a token or the network.
function Get-VtCredibility {
    param([int]$Malicious, [int]$Suspicious, [bool]$TopTierHit)
    $score = ($Malicious * 2) + $Suspicious
    $tier = 'LOW'
    if ($score -ge 10) { $tier = 'HIGH' }       # e.g. 5 malicious, or 3 malicious + 4 suspicious
    elseif ($score -ge 4) { $tier = 'MED' }     # e.g. 2 malicious, or 1 malicious + 2 suspicious, or 4 suspicious
    if ($TopTierHit) {
        if ($tier -eq 'LOW') { $tier = 'MED' }
        elseif ($tier -eq 'MED') { $tier = 'HIGH' }
    }
    $prefix = switch ($tier) {
        'HIGH' { '[CRITICAL]' }
        'MED'  { '[WARNING]' }
        default { '[INFO]' }
    }
    return @{ Tier = $tier; Prefix = $prefix; Counts = ($tier -eq 'HIGH' -or $tier -eq 'MED') }
}

# PURE. netstat -ano lines -> TCP rows @{ Remote; Pid; Listening }, by column:
# Proto, Local, Foreign, State, PID. The state WORD is localized, so it is
# never matched; a row whose foreign address is the unspecified one
# (0.0.0.0:0, [::]:0) is a listener, anything else had a remote peer.
function Get-NetstatTcpRows {
    param([string[]]$Lines)
    $rows = @()
    foreach ($line in $Lines) {
        $t = @(([string]$line).Trim() -split '\s+')
        if ($t.Count -lt 5 -or $t[0] -ne 'TCP' -or $t[-1] -notmatch '^\d+$') { continue }
        $f = $t[2]
        $remote = $null
        if ($f -match '^\[([0-9a-fA-F:.%]+)\]:\d+$') { $remote = ($matches[1] -replace '%.*$', '') }
        elseif ($f -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$') { $remote = $matches[1] }
        else { continue }
        $rows += [pscustomobject]@{ Remote = $remote; Pid = [int]$t[-1]; Listening = ($remote -eq '0.0.0.0' -or $remote -eq '::') }
    }
    return ,$rows
}

# PURE. The closing lines, as vt_check's Get-VtSummary.
function Get-VtIpSummary {
    param([int]$Total, [int]$Flagged, [int]$Answered, [int]$Failed, [string]$Why = '')
    $out = @()
    if ($Flagged -gt 0) {
        $out += "[CRITICAL] VirusTotal IP: $Flagged remote endpoint(s) flagged at MED or HIGH credibility. Investigate the listed local processes (Get-Process -Id <PID>) to identify what is connecting."
        $out += '[INFO] LOW-credibility hits (1 engine, non-top-tier) are reported above as [INFO] only -- often false positives.'
    }
    if ($Failed -gt 0) {
        $out += ('[WARNING] VirusTotal IP check NOT performed in full -- ' + $Failed + ' of ' + $Total + ' remote endpoint(s) were not looked up' + $(if ($Why) { ' (' + $Why + ')' } else { '' }) + ', so a known-bad address among them would go unseen (T1071).')
    }
    if ($Flagged -eq 0) {
        if ($Failed -eq 0) { $out += "[OK] VirusTotal IP: no MED-or-HIGH credibility malicious matches in $Total remote endpoint(s)." }
        elseif ($Answered -gt 0) { $out += "[OK] VirusTotal IP: no MED-or-HIGH credibility malicious matches among the $Answered endpoint(s) it answered for." }
    }
    return @{ Lines = $out; Hit = ($Flagged -gt 0); Gap = ($Failed -gt 0) }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $c = Get-VtCredibility -Malicious 1 -Suspicious 0 -TopTierHit $false
    T 'one non-top-tier engine: LOW credibility, [INFO], does not count toward IOC_HITS' ($c.Tier -eq 'LOW' -and $c.Prefix -eq '[INFO]' -and -not $c.Counts) ($c.Tier + '/' + $c.Prefix)
    $c = Get-VtCredibility -Malicious 0 -Suspicious 3 -TopTierHit $false
    T 'three suspicious-only non-top-tier engines: still LOW' ($c.Tier -eq 'LOW' -and -not $c.Counts) $c.Tier
    $c = Get-VtCredibility -Malicious 1 -Suspicious 0 -TopTierHit $true
    T 'one engine, but top-tier: boosted to MED, [WARNING], counts' ($c.Tier -eq 'MED' -and $c.Prefix -eq '[WARNING]' -and $c.Counts) ($c.Tier + '/' + $c.Prefix)
    $c = Get-VtCredibility -Malicious 2 -Suspicious 0 -TopTierHit $false
    T 'two malicious: MED' ($c.Tier -eq 'MED' -and $c.Counts) $c.Tier
    $c = Get-VtCredibility -Malicious 0 -Suspicious 4 -TopTierHit $false
    T 'four suspicious: MED (suspicious weighs half of malicious)' ($c.Tier -eq 'MED') $c.Tier
    $c = Get-VtCredibility -Malicious 5 -Suspicious 0 -TopTierHit $false
    T 'five malicious: HIGH, [CRITICAL]' ($c.Tier -eq 'HIGH' -and $c.Prefix -eq '[CRITICAL]' -and $c.Counts) ($c.Tier + '/' + $c.Prefix)
    $c = Get-VtCredibility -Malicious 2 -Suspicious 0 -TopTierHit $true
    T 'MED with a top-tier hit: boosted to HIGH' ($c.Tier -eq 'HIGH') $c.Tier
    $c = Get-VtCredibility -Malicious 5 -Suspicious 5 -TopTierHit $true
    T 'HIGH stays HIGH (no tier above it)' ($c.Tier -eq 'HIGH') $c.Tier
    T 'the top-tier list holds the curated engines (lower-cased, as the live loop compares them)' (($topTier -contains 'kaspersky') -and ($topTier -contains 'crowdstrike-falcon') -and (@($topTier | Where-Object { $_ -cne $_.ToLower() }).Count -eq 0)) ''
    $ns = @(
        '',
        'Active Connections',
        '',
        '  Proto  Local Address          Foreign Address        State           PID',
        '  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1044',
        '  TCP    10.0.0.5:50123         52.96.1.10:443         ESTABLISHED     4120',
        '  TCP    [::]:445               [::]:0                 LISTENING       4',
        '  TCP    [2001:db8::5]:50200    [2606:4700::1111]:443  ESTABLISHED     5300',
        '  UDP    0.0.0.0:5353           *:*                                    2200')
    $r = Get-NetstatTcpRows $ns
    T 'netstat by column: four TCP rows, UDP and headers ignored' ($r.Count -eq 4) "$($r.Count)"
    T 'a listener is told by its unspecified foreign address, not the state word' (@($r | Where-Object { $_.Listening }).Count -eq 2) ''
    T 'IPv4 and IPv6 remotes come out bare, with their PID' (@($r | Where-Object { -not $_.Listening } | ForEach-Object { $_.Remote + '/' + $_.Pid }) -join ',' -ceq '52.96.1.10/4120,2606:4700::1111/5300') (@($r | ForEach-Object { $_.Remote }) -join ',')
    $de = @('  Proto  Lokale Adresse         Remoteadresse          Status           PID', '  TCP    10.0.0.5:50123         52.96.1.10:443         HERGESTELLT     4120')
    $r = Get-NetstatTcpRows $de
    T 'a German netstat row (HERGESTELLT) is read -- the English-word match read none (the defect)' ($r.Count -eq 1 -and $r[0].Remote -eq '52.96.1.10' -and -not $r[0].Listening) "$($r.Count)"
    T 'output with no TCP row at all yields zero rows (the caller raises it as a gap)' ((Get-NetstatTcpRows @('netstat: error', '')).Count -eq 0) ''
    $v = Get-VtIpSummary -Total 4 -Flagged 0 -Answered 0 -Failed 4 -Why 'a lookup failed'
    T 'every lookup failed: a raised gap, never the [OK] (the defect)' ($v.Gap -and ($v.Lines -join ' ') -notmatch '\[OK\]' -and ($v.Lines -join ' ') -match 'NOT performed in full -- 4 of 4') ($v.Lines -join ' | ')
    $v = Get-VtIpSummary -Total 4 -Flagged 1 -Answered 2 -Failed 2 -Why '429 rate limit'
    T 'a hit and a gap are both raised' ($v.Hit -and $v.Gap) ''
    $v = Get-VtIpSummary -Total 4 -Flagged 0 -Answered 4 -Failed 0
    T 'all answered and clean: the [OK]' ((-not ($v.Hit -or $v.Gap)) -and $v.Lines[0] -match '^\[OK\]') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails vt_ip_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] vt_ip_check self-test: a single non-top-tier engine is INFO and never counted; malicious weighs twice suspicious; a top-tier engine boosts one tier.'
    exit 0
}

Remove-Item -LiteralPath (Join-Path $env:TEMP 'dz_iochit_18l_gap.txt') -Force -EA SilentlyContinue
function Write-IpGap { New-Item "$env:TEMP\dz_iochit_18l_gap.txt" -Force | Out-Null }

# -vt asked for this check: no key is a check not performed, raised.
$tokenFile = Join-Path $env:USERPROFILE '.vt_token'
$token = $null
try { $token = (Get-Content -LiteralPath $tokenFile -Raw -ErrorAction Stop) } catch {}
if ($token) { $token = $token.Trim() }
if (-not $token) {
    '[WARNING] VirusTotal IP check NOT performed -- %USERPROFILE%\.vt_token is missing, empty or unreadable. Create it with your VT API key (one line, no quotes) to enable this check.'
    Write-IpGap
    return
}

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
    # No -State filter: with one, a machine with no established connection
    # THROWS (no matching object) and was sent to the fallback.
    $conns = @(Get-NetTCPConnection -ErrorAction Stop)
    foreach ($c in $conns) {
        if ([string]$c.State -ne 'Established') { continue }
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
    # IPv4 lines render as "host:port". IPv6 renders as "[addr]:port". Match
    # both shapes -- the greedy `(\S+):\d+` regex used previously captured up to
    # the LAST colon, which mangles IPv6 addresses (everything inside the
    # brackets was kept, including the brackets themselves, and Test-PublicIp
    # then rejected the bracketed form).
    # Parsed by column (Get-NetstatTcpRows): the state word is localized.
    # A row with a remote peer counts whatever its state, so a TIME_WAIT or
    # CLOSE_WAIT peer is looked up too -- a recent connection is as worth
    # checking as a live one.
    $netstat = @(& netstat -ano 2>$null)
    $nsRows = Get-NetstatTcpRows $netstat
    if ($nsRows.Count -eq 0) {
        "[WARNING] VirusTotal IP check NOT performed -- Get-NetTCPConnection failed ($($_.Exception.Message)) and netstat -ano returned no TCP row to read."
        Write-IpGap
        return
    }
    foreach ($row in $nsRows) {
        if ($row.Listening) { continue }
        $remote = $row.Remote; $pid_ = $row.Pid
        if (-not (Test-PublicIp $remote)) { continue }
        $procName = 'unknown'
        $p = Get-Process -Id $pid_ -EA SilentlyContinue
        if ($p) { $procName = $p.Name }
        if (-not $ipToProc.ContainsKey($remote)) { $ipToProc[$remote] = New-Object System.Collections.Generic.HashSet[string] }
        [void]$ipToProc[$remote].Add("$procName (PID $pid_)")
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
$answered = 0
$failedCount = 0
$failWhy = @()
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
            $answered++
            continue
        }

        # Extract flagging engines for attribution. Track malicious + suspicious
        # separately so the output can show both categories with distinct tags.
        $flagEngines = @()
        $topTierHit = $false
        if ($results) {
            foreach ($prop in $results.PSObject.Properties) {
                $r = $prop.Value
                if ($r.category -eq 'malicious' -or $r.category -eq 'suspicious') {
                    $engine = $prop.Name
                    $verdict = if ($r.result) { $r.result } else { $r.category }
                    $flagEngines += [pscustomobject]@{
                        Engine = $engine
                        Verdict = $verdict
                        Category = $r.category
                    }
                    if ($topTier -contains $engine.ToLower()) { $topTierHit = $true }
                }
            }
        }

        # Credibility tier (Get-VtCredibility, above): weighted counts, boosted
        # one tier by a top-tier engine.
        $cred = Get-VtCredibility -Malicious $mal -Suspicious $sus -TopTierHit $topTierHit
        $tier = $cred.Tier
        $prefix = $cred.Prefix

        # Build summary line
        $boostNote = if ($topTierHit) { ' (top-tier engine flagged: tier boosted)' } else { '' }
        "  $prefix $ip -- VT $tier credibility: $mal malicious / $sus suspicious / $tot engines$boostNote"
        "         AS$asn $owner, $country"
        "         local process(es): $procs"
        if ($flagEngines.Count -gt 0) {
            # Sort: malicious before suspicious, then alphabetical within each.
            $top3 = $flagEngines | Sort-Object @{ Expression = { if ($_.Category -eq 'malicious') { 0 } else { 1 } } }, Engine | Select-Object -First 3
            '         flagged by:'
            foreach ($e in $top3) {
                $tier_tag = if ($topTier -contains $e.Engine.ToLower()) { ' [top-tier]' } else { '' }
                $cat_tag = if ($e.Category -eq 'suspicious') { ' [suspicious]' } else { '' }
                "           - $($e.Engine)$tier_tag$cat_tag : $($e.Verdict)"
            }
            if ($flagEngines.Count -gt 3) {
                "           ...and $($flagEngines.Count - 3) more engine(s)"
            }
        }

        # Count toward IOC_HITS only at MED or HIGH credibility
        if ($cred.Counts) { $malCount++ }
        # Counted only once the answer was fully processed: an error above
        # lands in the catch as a failure, and must not be both.
        $answered++
    } catch {
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        if ($statusCode -eq 404) {
            "  [INFO] $ip -- not in VT IP corpus"
            "         local process(es): $procs"
            $answered++
        } elseif ($statusCode -eq 401) {
            "  [INFO] VT API key rejected (HTTP 401) -- check ~/.vt_token contents"
            $abortReason = '401 unauthorized'
            break
        } elseif ($statusCode -eq 429) {
            "  [INFO] VT rate limit (HTTP 429) -- stopping after $($idx - 1) IP lookup(s)"
            $abortReason = '429 rate limit'
            break
        } else {
            "  [INFO] $ip -- VT lookup failed (HTTP $statusCode), not looked up"
            "         local process(es): $procs"
            $failedCount++; if ($failWhy -notcontains 'a lookup failed') { $failWhy += 'a lookup failed' }
        }
    }
    if ($idx -lt $total) { Start-Sleep -Seconds $SleepSeconds }
}

# A run that stopped early (401, 429) did not look up the rest.
if ($abortReason) {
    $failedCount = $total - $answered
    $failWhy += $abortReason
}
$sum = Get-VtIpSummary -Total $total -Flagged $malCount -Answered $answered -Failed $failedCount -Why ($failWhy -join '; ')
$sum.Lines
if ($sum.Hit) { New-Item "$env:TEMP\dz_iochit_18l.txt" -Force | Out-Null }
if ($sum.Gap) { Write-IpGap }
