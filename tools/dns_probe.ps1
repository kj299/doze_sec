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
# "ALL FAIL" IS A DIFFERENT CLAIM FROM "SOME FAIL". A laptop on a plane, a VPN
# that has not come up, a resolver that is down: every one of the nine domains
# fails, and the old rule printed nine [WARNING] blackhole lines, wrote the
# marker, and put "DNS or HOSTS blackhole of update/security domains" in the
# findings ledger of a machine with nothing wrong but no network. That is not a
# blackhole; it is an unverified probe, and the report says so: [SKIPPED], the
# marker value 'unverified', and a dashboard tile that reads NOT VERIFIED rather
# than PASS. Selective failure -- some resolve, some do not -- is the actual
# hijack shape and stays a WARNING.
#
# Also inventories the configured DNS servers (informational); a loopback
# resolver is reported (could be a legit DoH/local proxy), not failed.
#
# MARKER: $MarkerFile carries a VALUE the caller reads with set /p:
#   blackhole    at least one domain resolved and at least one did not, or
#                resolved only to a non-public address -> the caller raises
#   unverified   nothing resolved at all -> the caller states NOT VERIFIED
#   (absent)     every domain resolved to a public address
# Never throws. Windows PowerShell 5.1 compatible.

param(
    [string]$MarkerFile = '',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
# Resolved here, not in the param default: $env:TEMP is null on the Linux
# runner that executes -SelfTest, and Join-Path throws on a null path before
# the script body runs. GetTempPath() is %TEMP%\ on Windows, so the bat's
# contract (dz_dnsprobe_warn.txt under TEMP) is unchanged.
if (-not $MarkerFile) { $MarkerFile = Join-Path ([System.IO.Path]::GetTempPath()) 'dz_dnsprobe_warn.txt' }
function Write-MarkerFile {
    # The marker IS the route to the findings ledger: a failed write turns a
    # real finding into a CLEAN section. Create the directory rather than
    # assume it, and no -EA SilentlyContinue -- a swallowed failure here is how
    # a field test lost its finding. Local to each tool, like Write-Marker.
    param([string]$Path, [string]$Value = 'hit')
    if (-not $Path) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Value -Encoding ASCII
}

# Domains that MUST resolve to a public IP on a healthy, un-tampered host.
$script:Targets = @(
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

# A "public" answer is one a real update server could live at. Everything a
# HOSTS blackhole or a sinkhole resolver hands back is on this list: the null
# route, loopback, RFC1918, link-local, the 0/8 block, broadcast, multicast.
function Test-PublicIp([string]$ip) {
    if (-not $ip) { return $false }
    if ($ip -eq '0.0.0.0') { return $false }
    if ($ip -eq '255.255.255.255') { return $false }
    if ($ip -like '0.*') { return $false }
    if ($ip -like '127.*') { return $false }
    if ($ip -like '10.*') { return $false }
    if ($ip -like '192.168.*') { return $false }
    if ($ip -like '169.254.*') { return $false }
    if ($ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $false }
    if ($ip -match '^(22[4-9]|23[0-9])\.') { return $false }
    return $true
}

# ---------------------------------------------------------------------------
# PURE VERDICTS. No DNS, no network, no clock: plain values in, lines out, so
# the judgement can be pinned against real answers and real failures.
# ---------------------------------------------------------------------------

# One domain: what the resolver handed back, graded.
function Get-DnsTargetVerdict {
    param([string]$Name, [string[]]$Addresses)
    $addr = @($Addresses | Where-Object { $_ })
    if ($addr.Count -eq 0) {
        return @{ Line = ('[WARNING] ' + $Name + ' -> no A record resolved (possible DNS/HOSTS blackhole)'); Flagged = $true; Resolved = $false }
    }
    $public = @($addr | Where-Object { Test-PublicIp $_ })
    if ($public.Count -eq 0) {
        return @{ Line = ('[WARNING] ' + $Name + ' -> ' + ($addr -join ', ') + ' (non-public IP -- blackhole/hijack signature)'); Flagged = $true; Resolved = $true }
    }
    return @{ Line = ('[OK] ' + $Name + ' -> ' + ($public -join ', ')); Flagged = $false; Resolved = $true }
}

# The whole probe: every target's answer plus the resolver inventory, graded
# into report lines and a marker value ('blackhole', 'unverified' or $null).
function Get-DnsProbeVerdict {
    param([array]$Results, [string[]]$Servers)
    $lines = New-Object System.Collections.ArrayList
    $verdicts = @()
    $resolvedAny = $false
    foreach ($r in @($Results)) {
        $v = Get-DnsTargetVerdict -Name ([string]$r.Name) -Addresses @($r.Addresses)
        $verdicts += ,@($r.Name, $v)
        if ($v.Resolved) { $resolvedAny = $true }
    }

    $marker = $null
    if (-not $resolvedAny) {
        # Nothing answered. That is the resolver or the link, not nine hijacks.
        foreach ($pair in $verdicts) { [void]$lines.Add('[INFO] ' + $pair[0] + ' -> no answer') }
        [void]$lines.Add(('[SKIPPED] none of the {0} probed domain(s) resolved -- the machine is offline or its resolver is unreachable; DNS/HOSTS blackholing was NOT verified. Re-run with -dnsprobe once connected.' -f @($Results).Count))
        $marker = 'unverified'
    } else {
        $flagged = @()
        foreach ($pair in $verdicts) {
            [void]$lines.Add($pair[1].Line)
            if ($pair[1].Flagged) { $flagged += $pair[0] }
        }
        if ($flagged.Count -gt 0) { $marker = 'blackhole' }
    }

    $srv = @($Servers | Where-Object { $_ })
    if ($srv.Count -gt 0) {
        [void]$lines.Add('[INFO] Configured IPv4 DNS servers: ' + ($srv -join ', '))
        $loop = @($srv | Where-Object { $_ -like '127.*' })
        if ($loop.Count -gt 0) {
            [void]$lines.Add('[INFO] A loopback DNS resolver is configured -- normal for DoH / local proxies, but verify you installed it.')
        }
    }

    if ($marker -eq 'blackhole') {
        [void]$lines.Add(('[WARNING] ' + $flagged.Count + ' security/update domain(s) did not resolve to a public IP -- review for DNS/HOSTS blackhole (T1562.001).'))
    } elseif ($null -eq $marker) {
        [void]$lines.Add('[OK] All probed security/update domains resolve to public IPs -- no DNS/HOSTS blackhole detected.')
    }
    return @{ Lines = @($lines.ToArray()); Marker = $marker }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    # Real answers, pinned VERBATIM from the helpers-ps51 job on a GitHub
    # windows-latest runner, 2026-09-20 (Azure resolver 168.63.129.16). Note
    # wdcp.microsoft.com -> 172.178.160.22: a 172.x address that is NOT in
    # 172.16/12, which the private-range rule must not swallow.
    $real = @(
        @{ Name = 'windowsupdate.microsoft.com';     Addresses = @('128.85.102.70') },
        @{ Name = 'update.microsoft.com';            Addresses = @('128.85.102.70') },
        @{ Name = 'download.windowsupdate.com';      Addresses = @('23.220.73.3', '23.220.73.7') },
        @{ Name = 'sls.update.microsoft.com';        Addresses = @('20.165.94.63') },
        @{ Name = 'ctldl.windowsupdate.com';         Addresses = @('109.61.38.38') },
        @{ Name = 'definitionupdates.microsoft.com'; Addresses = @('23.222.205.40') },
        @{ Name = 'wdcp.microsoft.com';              Addresses = @('172.178.160.22') },
        @{ Name = 'www.msftconnecttest.com';         Addresses = @('23.62.226.78', '23.62.226.83') },
        @{ Name = 'go.microsoft.com';                Addresses = @('23.199.1.215') }
    )
    $ok = Get-DnsProbeVerdict -Results $real -Servers @('168.63.129.16')
    T 'nine real public answers raise nothing and write no marker' ($null -eq $ok.Marker -and @($ok.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 0) ($ok.Lines -join ' | ')
    T 'the all-clear summary is printed' (($ok.Lines -join "`n") -match '\[OK\] All probed security/update domains resolve to public IPs') ''
    T 'the resolver inventory is printed as INFO' (($ok.Lines -join "`n") -match '\[INFO\] Configured IPv4 DNS servers: 168\.63\.129\.16') ''

    # Per-domain judgement.
    $v = Get-DnsTargetVerdict -Name 'go.microsoft.com' -Addresses @('23.44.174.9')
    T 'a public answer is OK' ($v.Line -match '^\[OK\]' -and -not $v.Flagged) $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('0.0.0.0')
    T '0.0.0.0 is the HOSTS null route -- WARNING' ($v.Flagged -and $v.Line -match 'non-public') $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('127.0.0.1')
    T 'loopback is a blackhole answer -- WARNING' ($v.Flagged) $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('10.0.0.5')
    T 'an RFC1918 answer for a public update host -- WARNING' ($v.Flagged) $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('172.20.1.1')
    T '172.16/12 is private -- WARNING' ($v.Flagged) $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('172.32.1.1')
    T '172.32 is NOT private -- OK' (-not $v.Flagged) $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('172.178.160.22')
    T 'the REAL wdcp answer 172.178.160.22 is public (172.16/12 ends at 172.31)' (-not $v.Flagged) $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('169.254.1.1')
    T 'link-local is not a public answer -- WARNING' ($v.Flagged) $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('0.0.0.1')
    T 'the 0/8 block is a sinkhole answer -- WARNING' ($v.Flagged) $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('255.255.255.255')
    T 'broadcast is a sinkhole answer -- WARNING' ($v.Flagged) $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('224.0.0.1')
    T 'multicast is a sinkhole answer -- WARNING' ($v.Flagged) $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('10.0.0.5', '20.190.147.9')
    T 'a split answer with one public address is OK (one working route suffices)' (-not $v.Flagged -and $v.Line -match '20\.190\.147\.9' -and $v.Line -notmatch '10\.0\.0\.5') $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @()
    T 'no answer at all, in isolation, is the no-A-record WARNING' ($v.Flagged -and -not $v.Resolved -and $v.Line -match 'no A record') $v.Line
    $v = Get-DnsTargetVerdict -Name 'wdcp.microsoft.com' -Addresses @('', $null)
    T 'empty strings from a CNAME-only answer are not addresses' ($v.Flagged -and -not $v.Resolved) $v.Line

    # ALL FAIL is offline / resolver down, not nine blackholes. This is the
    # judgement a laptop on a plane would have tripped.
    $none = @($real | ForEach-Object { @{ Name = $_.Name; Addresses = @() } })
    $off = Get-DnsProbeVerdict -Results $none -Servers @('192.168.1.1')
    T 'ALL FAIL: marker is unverified, never blackhole' ($off.Marker -eq 'unverified') ("marker=" + $off.Marker)
    T 'ALL FAIL: no [WARNING] line is printed' (@($off.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 0) ($off.Lines -join ' | ')
    T 'ALL FAIL: the SKIPPED line names the count and says NOT verified' (($off.Lines -join "`n") -match '\[SKIPPED\] none of the 9 probed domain\(s\) resolved.*NOT verified') ''
    T 'ALL FAIL: the all-clear line is NOT printed' (($off.Lines -join "`n") -notmatch 'no DNS/HOSTS blackhole detected') ''
    T 'ALL FAIL: each domain is listed as INFO no answer' (@($off.Lines | Where-Object { $_ -match '^\[INFO\] .* -> no answer$' }).Count -eq 9) ''
    $empty = Get-DnsProbeVerdict -Results @() -Servers @()
    T 'an empty probe list is unverified too (nothing was asked)' ($empty.Marker -eq 'unverified') ("marker=" + $empty.Marker)

    # SELECTIVE failure is the hijack shape.
    $one = @($real | ForEach-Object { if ($_.Name -eq 'wdcp.microsoft.com') { @{ Name = $_.Name; Addresses = @() } } else { $_ } })
    $bh = Get-DnsProbeVerdict -Results $one -Servers @()
    T 'ONE of nine fails while eight resolve: marker is blackhole' ($bh.Marker -eq 'blackhole') ("marker=" + $bh.Marker)
    T 'ONE of nine: the summary counts exactly one' (($bh.Lines -join "`n") -match '\[WARNING\] 1 security/update domain\(s\) did not resolve') ''
    $two = @($real | ForEach-Object { if ($_.Name -eq 'wdcp.microsoft.com') { @{ Name = $_.Name; Addresses = @('0.0.0.0') } } else { $_ } })
    $bh2 = Get-DnsProbeVerdict -Results $two -Servers @()
    T 'a null-routed Defender endpoint beside eight healthy answers: blackhole' ($bh2.Marker -eq 'blackhole' -and (($bh2.Lines -join "`n") -match 'wdcp\.microsoft\.com -> 0\.0\.0\.0 \(non-public')) ($bh2.Lines -join ' | ')

    # Resolver inventory.
    $lb = Get-DnsProbeVerdict -Results $real -Servers @('127.0.0.1')
    T 'a loopback resolver is INFO, and the probe stays clean (corpus [loopback-dns])' ($null -eq $lb.Marker -and (($lb.Lines -join "`n") -match '\[INFO\] A loopback DNS resolver is configured')) ($lb.Lines -join ' | ')
    $ns = Get-DnsProbeVerdict -Results $real -Servers @()
    T 'no configured servers prints no inventory line' (@($ns.Lines | Where-Object { $_ -match 'DNS servers' }).Count -eq 0) ''
    T 'an IPv6 literal counts as public (only A records are asked for; the rule must not choke on one)' (Test-PublicIp '2600:1408:c400::1') ''

    if ($fails) { Write-Output "[FAIL] $fails dns_probe self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] dns_probe self-test: real public answers are clean, sinkhole answers raise, and a probe that resolved NOTHING is unverified, not a blackhole.'
    exit 0
}

if (Test-Path -LiteralPath $MarkerFile) { Remove-Item -LiteralPath $MarkerFile -Force -EA SilentlyContinue }

$results = @()
foreach ($d in $script:Targets) {
    $ans = @(Resolve-DnsName -Name $d -Type A -EA SilentlyContinue | Where-Object { $_.IPAddress })
    $results += @{ Name = $d; Addresses = @($ans | ForEach-Object { [string]$_.IPAddress }) }
}

# Resolver inventory (informational).
$servers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue |
    Where-Object { $_.ServerAddresses } |
    ForEach-Object { $_.ServerAddresses } |
    Sort-Object -Unique)

$verdict = Get-DnsProbeVerdict -Results $results -Servers $servers
foreach ($l in $verdict.Lines) { Write-Output $l }
if ($verdict.Marker) { Write-MarkerFile -Path $MarkerFile -Value $verdict.Marker }
