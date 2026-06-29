# dns_probe.ps1 -- active DNS integrity probe (Section 3, behind the -dnsprobe
# opt-in switch).
#
# SAFE BY DESIGN. It resolves a fixed list of LEGITIMATE Windows / Defender /
# connectivity domains and flags any that fail to resolve or resolve to a
# non-public IP (0.0.0.0 / loopback / private / link-local) -- the signature of
# malware blackholing security/update traffic via a DNS or HOSTS hijack
# (T1562.001). It NEVER resolves attacker / ioc_domains.txt entries, so it does
# not generate outbound DNS queries to C2 infrastructure. That higher-fidelity
# but OPSEC-risky variant stays deferred by design -- see THREAT_MODEL.md.
#
# Also inventories the configured DNS servers (informational); a loopback
# resolver is reported (could be a legit DoH/local proxy), not failed.
#
# Writes $MarkerFile when any blackhole/hijack signature is found so the caller
# can bump the audit exit code. Never throws. Windows PowerShell 5.1 compatible.

param(
    [string]$MarkerFile = (Join-Path $env:TEMP 'dz_dnsprobe_warn.txt')
)

$ErrorActionPreference = 'Continue'
if (Test-Path -LiteralPath $MarkerFile) { Remove-Item -LiteralPath $MarkerFile -Force -EA SilentlyContinue }

# Domains that MUST resolve to a public IP on a healthy, un-tampered host.
$targets = @(
    'windowsupdate.microsoft.com',
    'update.microsoft.com',
    'download.windowsupdate.com',
    'sls.update.microsoft.com',
    'ctldl.windowsupdate.com',          # certificate trust list
    'definitionupdates.microsoft.com',  # Defender signature updates
    'wdcp.microsoft.com',               # Defender cloud-delivered protection
    'www.msftconnecttest.com',          # NCSI connectivity probe
    'go.microsoft.com'
)

function Test-PublicIp([string]$ip) {
    if (-not $ip) { return $false }
    if ($ip -eq '0.0.0.0') { return $false }
    if ($ip -like '127.*') { return $false }
    if ($ip -like '10.*') { return $false }
    if ($ip -like '192.168.*') { return $false }
    if ($ip -like '169.254.*') { return $false }
    if ($ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $false }
    return $true
}

$flagged = @()
foreach ($d in $targets) {
    $ans = @(Resolve-DnsName -Name $d -Type A -EA SilentlyContinue | Where-Object { $_.IPAddress })
    if (-not $ans -or $ans.Count -eq 0) {
        Write-Output ('[WARNING] ' + $d + ' -> no A record resolved (possible DNS/HOSTS blackhole)')
        $flagged += $d
        continue
    }
    $ips = @($ans | ForEach-Object { $_.IPAddress })
    $public = @($ips | Where-Object { Test-PublicIp $_ })
    if ($public.Count -eq 0) {
        Write-Output ('[WARNING] ' + $d + ' -> ' + ($ips -join ', ') + ' (non-public IP -- blackhole/hijack signature)')
        $flagged += $d
    } else {
        Write-Output ('[OK] ' + $d + ' -> ' + ($public -join ', '))
    }
}

# Resolver inventory (informational).
$servers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue |
    Where-Object { $_.ServerAddresses } |
    ForEach-Object { $_.ServerAddresses } |
    Sort-Object -Unique)
if ($servers.Count -gt 0) {
    Write-Output ('[INFO] Configured IPv4 DNS servers: ' + ($servers -join ', '))
    $loop = @($servers | Where-Object { $_ -like '127.*' })
    if ($loop.Count -gt 0) {
        Write-Output '[INFO] A loopback DNS resolver is configured -- normal for DoH / local proxies, but verify you installed it.'
    }
}

if ($flagged.Count -gt 0) {
    Write-Output ('[WARNING] ' + $flagged.Count + ' security/update domain(s) did not resolve to a public IP -- review for DNS/HOSTS blackhole (T1562.001).')
    'dnsprobe blackhole' | Out-File -LiteralPath $MarkerFile -Encoding ASCII
} else {
    Write-Output '[OK] All probed security/update domains resolve to public IPs -- no DNS/HOSTS blackhole detected.'
}
