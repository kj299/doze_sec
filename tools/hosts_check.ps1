# hosts_check.ps1 -- grade the HOSTS file by what each entry DOES (T1071.004 /
# T1562.001). Invoked from Section 3.
#
# WHY THIS REPLACED A findstr PIPELINE. The old check was:
#
#   type hosts | findstr /v /r "^#" | findstr /v /r "^$"
#              | findstr /v /c:"127.0.0.1" /c:"::1" | findstr /r "[0-9]"
#
# -- anything left is "[WARNING] Non-standard entries found in HOSTS file".
# That is wrong in both directions at once.
#
# FALSE POSITIVE: it has no notion of a benign entry. Docker Desktop writes
#   192.168.50.71 host.docker.internal
#   192.168.50.71 gateway.docker.internal
#   127.0.0.1     kubernetes.docker.internal
# on every machine it is installed on, and the first two survive every filter.
# A field report (2026-09-06) raised a DNS-hijacking warning on exactly those.
# WSL, VirtualBox, Lando and most dev tooling do the same thing.
#
# FALSE NEGATIVE, and the worse half: `findstr /v /c:"127.0.0.1"` drops any line
# CONTAINING that substring, so
#   127.0.0.1 windowsupdate.microsoft.com
#   127.0.0.1 www.update.microsoft.com
# were invisible. Blackholing Windows Update or an AV vendor to loopback is a
# standard defence-evasion move (T1562.001), and the check that exists to read
# this file could not see it. Silencing the Docker noise without closing that
# gap would have fixed the cosmetic half of the problem.
#
# THE RULE -- an entry is graded on its EFFECT, never on a vendor comment above
# it (an attacker can write "# Added by Docker Desktop") and never on the target
# address alone (loopback is precisely how blackholing is done):
#
#   loopback/null-route -> a SECURITY or UPDATE domain    WARNING  blackholing
#   loopback/null-route -> anything else                  INFO     ad-blocking, dev tooling
#   private/link-local  -> a local-only name              INFO     Docker/WSL/VirtualBox
#   private/link-local  -> a real public domain           WARNING  LAN MitM shape
#   public IP           -> any domain                     WARNING  DNS hijack
#
# The security-domain list only ever ESCALATES. It is never an allowlist, so a
# domain it does not know is never silently trusted -- it is still graded by
# address, and a public-IP redirect of an unknown domain is still a finding.
#
# MARKER: severity word to $MarkerDir\dz_hosts.txt; caller raises via
# :dz_finding. No marker when nothing is raised.
#
# Windows PowerShell 5.1 compatible. Read-only (reads one file). Executed by
# the helpers-ps51 CI job.

[CmdletBinding()]
param(
    [string]$Path,
    [string]$MarkerDir = $env:TEMP,
    [int]$MaxReport = 15,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write here turns
    # a real finding into a CLEAN section. Create the directory rather than
    # assume it -- an -EA SilentlyContinue on this write cost a field test its
    # finding.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir 'dz_hosts.txt') -Value $Sev -Encoding ASCII
}

# Security / update infrastructure. Blackholing any of these is defence
# evasion, whatever the address it is pointed at. Matched as a substring of the
# lower-cased hostname, so 'windowsupdate' catches every regional variant.
$script:SecurityDomains = @(
    'windowsupdate', 'update.microsoft', 'updates.microsoft', 'definitionupdates',
    'download.microsoft', 'msftconnecttest',
    'msftncsi', 'defender', 'wdcp.microsoft', 'wdcpalt.microsoft', 'smartscreen',
    'microsoftupdate', 'sls.microsoft', 'activation.sls',
    'clamav', 'virustotal',
    'mcafee', 'symantec', 'norton', 'sophos', 'kaspersky', 'avast', 'avg.com',
    'bitdefender', 'malwarebytes', 'eset.com', 'trendmicro', 'crowdstrike',
    'sentinelone', 'carbonblack', 'cylance', 'paloaltonetworks', 'fireeye',
    'sucuri', 'webroot', 'f-secure', 'gdatasoftware', 'drweb', 'comodo'
)

# Names that only ever exist inside a local environment. A private-address
# mapping for one of these is infrastructure, not a redirect of anything a
# person would otherwise reach on the internet.
$script:LocalOnlyRx = '(\.internal|\.local|\.localdomain|\.test|\.localhost|\.home\.arpa|\.lan|\.example)$'

function Test-SecurityDomain {
    param([string]$Name)
    $n = $Name.ToLowerInvariant()
    foreach ($d in $script:SecurityDomains) { if ($n -like ('*' + $d + '*')) { return $true } }
    return $false
}

function Get-AddressClass {
    # 'loopback' (incl. the null route -- both mean "you cannot reach it"),
    # 'private' (RFC1918, CGNAT, link-local, ULA), or 'public'.
    param([string]$Ip)
    $a = $Ip.Trim()
    if ($a -match '^(?i)0\.0\.0\.0$|^::$|^(?i)::0$')          { return 'loopback' }
    if ($a -match '^127\.')                                    { return 'loopback' }
    if ($a -match '^(?i)::1$|^(?i)0*:0*:0*:0*:0*:0*:0*:0*1$')  { return 'loopback' }
    if ($a -match '^10\.')                                     { return 'private' }
    if ($a -match '^192\.168\.')                               { return 'private' }
    if ($a -match '^172\.(1[6-9]|2[0-9]|3[01])\.')             { return 'private' }
    if ($a -match '^169\.254\.')                               { return 'private' }
    if ($a -match '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.') { return 'private' }
    if ($a -match '^(?i)f[cd]')                                { return 'private' }
    if ($a -match '^(?i)fe[89ab]')                             { return 'private' }
    return 'public'
}

function Get-HostsEntries {
    # Emits one object per hostname. A HOSTS line may carry several names for
    # one address, and a trailing '#' comment.
    #
    # Entries are written STRAIGHT TO THE PIPELINE rather than accumulated and
    # returned. `return $out` on an empty array yields $NULL (the pipeline
    # unrolls it), and the caller's @($null) is a one-element array holding
    # null -- which fell through Get-AddressClass into the redirect bucket and
    # invented a DNS-hijack finding on a HOSTS file containing only comments.
    # That is the trap that shipped in module_inspect (#201).
    #
    # `return ,$out` is NOT the fix here: the comma operator survives @(), so
    # @(Get-HostsEntries ...) would be 1 for an empty parse AND 1 for a
    # two-entry parse. Emitting directly gives 0 and 2, with no wrapper and no
    # null to guard. Get-HostsVerdict still skips a null element as a backstop.
    param([string[]]$Lines)
    foreach ($raw in $Lines) {
        if ($null -eq $raw) { continue }
        # Strip a UTF-8 BOM on the first line, and any trailing comment.
        #
        # BOTH forms, and BOTH patterns written in pure ASCII. Get-Content
        # usually consumes a leading BOM itself, but not always: 5.1 reading a
        # file whose BOM was not detected yields the MOJIBAKE form (the three
        # UTF-8 bytes decoded as Windows-1252, U+00EF U+00BB U+00BF), while a
        # UTF-8-aware read yields the single character U+FEFF.
        #
        # The second pattern used to be the raw BOM bytes typed into this
        # (BOM-less) file. Windows PowerShell 5.1 decodes a BOM-less .ps1 as
        # ANSI, so those three bytes became U+00EF U+00BB U+00BF and the line
        # compiled to a DUPLICATE of the one above it -- leaving a real U+FEFF
        # unstripped on the one engine this tool must run on. The first HOSTS
        # entry would then fail the address test and be dropped silently: a
        # blackholed windowsupdate.microsoft.com on line 1 would be INVISIBLE.
        # \uFEFF is a .NET regex escape and \ is not a PowerShell string
        # escape, so this source stays ASCII and means the same on 5.1 and 7.
        $l = $raw -replace "^\xEF\xBB\xBF", ''
        $l = $l -replace "^\uFEFF", ''
        $hash = $l.IndexOf('#')
        if ($hash -ge 0) { $l = $l.Substring(0, $hash) }
        $l = $l.Trim()
        if (-not $l) { continue }
        $parts = @($l -split '\s+' | Where-Object { $_ })
        if ($parts.Count -lt 2) { continue }
        $ip = $parts[0]
        # Must actually look like an address, or it is not an entry.
        if ($ip -notmatch '^[0-9A-Fa-f:.]+$') { continue }
        if ($ip -notmatch '[0-9A-Fa-f]') { continue }
        foreach ($n in $parts[1..($parts.Count - 1)]) {
            New-Object PSObject -Property @{ Ip = $ip; Name = $n }
        }
    }
}

# ---------------------------------------------------------------------------
# The machine's own name.
#
# A real Azure runner's stock HOSTS file carries the line every cloud VM and
# most domain-joined laptops carry:
#
#   10.1.0.100  runnervmeef0v.<vnet>.bx.internal.cloudapp.net  runnervmeef0v
#
# The short name has no dot, so it graded as local-only context. The FQDN ends
# in .cloudapp.net, not one of the LocalOnlyRx suffixes, so it fell through to
# 'redirect' and the tool told its owner that a real domain had been pointed
# somewhere -- "Review for DNS hijacking" -- about the machine describing
# itself. CI on a real runner is what surfaced it; no synthetic fixture would
# have.
#
# The machine's own name is not a domain anyone is trying to reach, so pointing
# it at the machine's own private address redirects nothing.
#
# OFFLINE SOURCES ONLY. -readonly forbids network connections and
# tests\field_test.ps1 proves that claim before/after, so resolving the FQDN
# via DNS is not available here -- and would be the wrong thing anyway, since
# the question is what this machine calls itself, not what a resolver says.
#
# Two tiers, and the verdict says which one answered:
#   exact    the name equals <computername>.<one of the machine's own DNS
#            suffixes>. An attacker cannot pick the victim's DNS suffix.
#   inferred no suffix could be discovered at all, so only the FIRST LABEL is
#            compared. Weaker: a machine literally named 'login' would exempt
#            login.<anything>. Accepted only as a fallback, never preferred,
#            and the entry is still PRINTED and adjudicable -- INFO naming it,
#            never folded into the [OK].
#
# Scope: private and link-local addresses only. A machine's own name pointed at
# a PUBLIC address stays a finding -- that is rare on an endpoint and false
# reassurance is the worse error here.
$script:OwnNameProbe = {
    $cn = ''
    if ($env:COMPUTERNAME) { $cn = $env:COMPUTERNAME }
    $suffixes = New-Object System.Collections.ArrayList
    $addSuffix = {
        param($s)
        if ($s -and ($s -is [string]) -and $s.Trim() -and $s -notmatch '^(?i)workgroup$' -and $s -match '\.') {
            $null = $suffixes.Add($s.Trim().Trim('.').ToLowerInvariant())
        }
    }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -EA Stop
        if ($cs) {
            if (-not $cn -and $cs.Name) { $cn = [string]$cs.Name }
            & $addSuffix ([string]$cs.Domain)
            if ($cs.DNSHostName -and $cs.Domain) { & $addSuffix ([string]$cs.Domain) }
        }
    } catch {}
    try {
        foreach ($a in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -EA Stop |
                         Where-Object { $_.IPEnabled })) {
            & $addSuffix ([string]$a.DNSDomain)
        }
    } catch {}
    # The DHCP-assigned suffix, which is where a cloud VM's really lives.
    foreach ($v in @('Domain', 'NV Domain', 'DhcpDomain')) {
        try {
            $p = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name $v -EA Stop
            & $addSuffix ([string]$p.$v)
        } catch {}
    }
    return @{
        ComputerName = ([string]$cn).ToLowerInvariant()
        Suffixes     = @($suffixes | Select-Object -Unique)
    }
}

function Get-OwnNameInfo {
    if ($null -ne $script:OwnNameCache) { return $script:OwnNameCache }
    $r = $null
    try { $r = & $script:OwnNameProbe } catch {}
    if (-not $r) { $r = @{ ComputerName = ''; Suffixes = @() } }
    $cn = [string]$r.ComputerName
    $names = @()
    foreach ($s in @($r.Suffixes)) { if ($cn -and $s) { $names += ('{0}.{1}' -f $cn, $s) } }
    $script:OwnNameCache = @{
        ComputerName = $cn
        Names        = @($names)
        SuffixKnown  = ([bool](@($names).Count -gt 0))
    }
    return $script:OwnNameCache
}

function Test-OwnName {
    # '' (not ours), 'exact', or 'inferred'.
    param([string]$Name)
    if (-not $Name) { return '' }
    $info = Get-OwnNameInfo
    if (-not $info.ComputerName) { return '' }
    $n = $Name.ToLowerInvariant().TrimEnd('.')
    if ($n -eq $info.ComputerName) { return 'exact' }
    foreach ($o in @($info.Names)) { if ($n -eq $o) { return 'exact' } }
    # Fallback ONLY when no suffix was discoverable. Compare the first label,
    # never a prefix: 'runnervmeef0v-evil.attacker.com' must stay a finding.
    if (-not $info.SuffixKnown) {
        if ($n.Split('.')[0] -eq $info.ComputerName) { return 'inferred' }
    }
    return ''
}

function Get-HostsVerdict {
    param($Entries)
    $blackhole = @()   # WARNING -- security/update domain made unreachable
    $redirect  = @()   # WARNING -- a real domain pointed somewhere
    $context   = @()   # INFO    -- local-only names, ordinary ad-blocking
    foreach ($e in @($Entries)) {
        if ($null -eq $e -or -not $e.Ip -or -not $e.Name) { continue }
        $cls = Get-AddressClass -Ip $e.Ip
        $sec = Test-SecurityDomain -Name $e.Name
        $localOnly = ($e.Name -match $script:LocalOnlyRx) -or ($e.Name -notmatch '\.')
        $line = ('{0} -> {1}' -f $e.Name, $e.Ip)
        if ($cls -eq 'loopback') {
            # Loopback is how blackholing is done, so the target is what
            # decides -- not the address.
            if ($sec) { $blackhole += $line } else { $context += $line }
            continue
        }
        if ($cls -eq 'private') {
            if ($sec) { $blackhole += $line; continue }
            if ($localOnly) { $context += $line; continue }
            $own = Test-OwnName -Name $e.Name
            if ($own) {
                $context += ($line + $(if ($own -eq 'exact') { '  [this machine''s own name]' } else { '  [matches this machine''s name; no DNS suffix was discoverable, so inferred from the first label]' }))
                continue
            }
            $redirect += $line
            continue
        }
        # Public address: a redirect to somewhere reachable. Always a finding,
        # which is what keeps the harness plant (203.0.113.5) firing.
        $redirect += $line
    }
    return @{ Blackhole = @($blackhole); Redirect = @($redirect); Context = @($context) }
}

# ---------------------------------------------------------------------------
if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    function V { param([string[]]$Lines) return (Get-HostsVerdict -Entries (Get-HostsEntries -Lines $Lines)) }

    # The owner's actual file, verbatim -- the false positive being fixed.
    $docker = @(
        '# Copyright (c) 1993-2009 Microsoft Corp.',
        '#	127.0.0.1       localhost',
        '# Added by Docker Desktop',
        '192.168.50.71 host.docker.internal',
        '192.168.50.71 gateway.docker.internal',
        '# To allow the same kube context to work on the host and the container:',
        '127.0.0.1 kubernetes.docker.internal',
        '# End of section'
    )
    $r = V $docker
    T "Docker Desktop's own entries raise nothing" `
      ($r.Blackhole.Count -eq 0 -and $r.Redirect.Count -eq 0 -and $r.Context.Count -eq 3) `
      ("blackhole=$($r.Blackhole.Count) redirect=$($r.Redirect.Count) context=$($r.Context.Count)")

    # The harness plant. This MUST keep firing.
    $r = V @('203.0.113.5 dz_selftest_evil.example')
    T 'the harness plant (public IP) is still a finding' ($r.Redirect.Count -eq 1) ("redirect=$($r.Redirect.Count)")

    # The false negative: invisible to the old findstr pipeline.
    $r = V @('127.0.0.1 windowsupdate.microsoft.com')
    T 'blackholing Windows Update to loopback is a finding' ($r.Blackhole.Count -eq 1) ("blackhole=$($r.Blackhole.Count)")
    $r = V @('0.0.0.0 definitionupdates.microsoft.com')
    T 'blackholing Defender definitions to the null route is a finding' ($r.Blackhole.Count -eq 1) ("blackhole=$($r.Blackhole.Count)")
    $r = V @('127.0.0.1 www.sophos.com', '0.0.0.0 crowdstrike.com')
    T 'blackholing AV/EDR vendors is a finding' ($r.Blackhole.Count -eq 2) ("blackhole=$($r.Blackhole.Count)")

    # Ordinary loopback entries are not findings -- ad-blocking lists are huge.
    $r = V @('127.0.0.1 ads.example.com', '0.0.0.0 tracker.example.net')
    T 'ordinary loopback ad-blocking is context, not a finding' `
      ($r.Blackhole.Count -eq 0 -and $r.Redirect.Count -eq 0 -and $r.Context.Count -eq 2) ("context=$($r.Context.Count)")

    # A private address pointed at a REAL domain is a MitM shape.
    $r = V @('192.168.1.50 login.microsoftonline.com')
    T 'a private IP pointed at a real public domain is a finding' ($r.Redirect.Count -eq 1) ("redirect=$($r.Redirect.Count)")

    # ...and a private address pointed at a security domain is blackholing too.
    $r = V @('10.0.0.5 windowsupdate.microsoft.com')
    T 'a private IP pointed at an update domain is blackholing' ($r.Blackhole.Count -eq 1) ("blackhole=$($r.Blackhole.Count)")

    # Parsing.
    # A file of nothing but comments must produce NOTHING. This case failed on
    # the first run of this very self-test, for the #201 reason above.
    $r = V @('', '   ', '# just a comment', "`t# tabbed comment")
    T 'comments and blank lines produce no entries' `
      ($r.Blackhole.Count -eq 0 -and $r.Redirect.Count -eq 0 -and $r.Context.Count -eq 0) `
      ("blackhole=$($r.Blackhole.Count) redirect=$($r.Redirect.Count) context=$($r.Context.Count)")
    # @() around an empty parse must be 0 -- not 1 holding $null (a plain
    # `return $out`), and not 1 holding an empty array (`return ,$out`).
    T 'an empty parse yields zero entries under @()' `
      (@(Get-HostsEntries -Lines @('# only a comment')).Count -eq 0) `
      ("count=" + @(Get-HostsEntries -Lines @('# only a comment')).Count)
    $e = @(Get-HostsEntries -Lines @('203.0.113.5  a.example b.example  # two names'))
    T 'one line with several names yields one entry each' ($e.Count -eq 2) ("count=$($e.Count)")
    # BOTH BOM forms, built from character codes so this source stays ASCII.
    # This case used to be written with `u{FEFF}, which is PowerShell 6+ only:
    # 5.1 has no such escape and drops the backtick, so the case tested the
    # literal string "u{FEFF}127.0.0.1" and could not fail for its own reason.
    # CI on real 5.1 is what caught it.
    $bom = [string][char]0xFEFF
    $e = @(Get-HostsEntries -Lines @($bom + "127.0.0.1 localhost"))
    T 'a UTF-8 BOM (U+FEFF) on the first line does not eat the entry' ($e.Count -eq 1) ("count=$($e.Count)")
    # The mojibake form: the BOM bytes decoded as Windows-1252, which is what a
    # 5.1 read of a UTF-8 file whose BOM was not detected actually yields.
    $moji = -join @([char]0x00EF, [char]0x00BB, [char]0x00BF)
    $e = @(Get-HostsEntries -Lines @($moji + "127.0.0.1 localhost"))
    T 'a mis-decoded UTF-8 BOM on the first line does not eat the entry' ($e.Count -eq 1) ("count=$($e.Count)")
    # Neither strip may run away with a real entry.
    $e = @(Get-HostsEntries -Lines @($bom + "127.0.0.1 windowsupdate.microsoft.com"))
    T 'a BOM does not hide a blackholed update domain' `
      ($e.Count -eq 1 -and $e[0].Name -eq 'windowsupdate.microsoft.com') `
      ("count=$($e.Count) name=$(if($e.Count){$e[0].Name})")
    # --- the machine's own name -----------------------------------------
    # A real Azure runner failed on its own stock HOSTS line; no synthetic
    # fixture would have produced it. A domain-joined laptop has the same shape.
    $script:OwnNameCache = $null
    $script:OwnNameProbe = { @{ ComputerName = 'runnervmeef0v'; Suffixes = @('igb3cs02yymuxlog0fzrenhqpd.bx.internal.cloudapp.net') } }
    $r = V @('10.1.0.100 runnervmeef0v.igb3cs02yymuxlog0fzrenhqpd.bx.internal.cloudapp.net runnervmeef0v')
    T "the machine's own FQDN at its own private address is context" `
      ($r.Redirect.Count -eq 0 -and $r.Blackhole.Count -eq 0 -and $r.Context.Count -eq 2) `
      ("redirect=$($r.Redirect.Count) context=$($r.Context.Count)")
    T 'and the verdict declares that the FQDN matched exactly' `
      ((@($r.Context) -join '; ') -match "own name\]") ((@($r.Context) -join '; '))

    # When the suffix IS known, only that suffix answers. An attacker who
    # registers <victim-hostname>.evil.com must not inherit the exemption --
    # this is the case that keeps the first-label fallback strictly a
    # fallback rather than a second, weaker rule running all the time.
    $script:OwnNameCache = $null
    $r = V @('10.1.0.100 runnervmeef0v.attacker.com')
    T 'the own name under a DIFFERENT suffix is still a finding' `
      ($r.Redirect.Count -eq 1) ("redirect=$($r.Redirect.Count)")

    # A PREFIX of the computer name must NOT be exempt.
    $script:OwnNameCache = $null
    $r = V @('10.1.0.100 runnervmeef0v-evil.attacker.com')
    T 'a name merely STARTING with the computer name is still a finding' `
      ($r.Redirect.Count -eq 1) ("redirect=$($r.Redirect.Count)")

    # The LAN-MitM shape this rule must not weaken.
    $script:OwnNameCache = $null
    $r = V @('192.168.1.66 login.microsoftonline.com')
    T 'a private IP pointed at someone elses domain is still a finding' `
      ($r.Redirect.Count -eq 1) ("redirect=$($r.Redirect.Count)")

    # The own name at a PUBLIC address stays a finding: out of scope on purpose.
    $script:OwnNameCache = $null
    $r = V @('203.0.113.5 runnervmeef0v.igb3cs02yymuxlog0fzrenhqpd.bx.internal.cloudapp.net')
    T "the machine's own name at a PUBLIC address is still a finding" `
      ($r.Redirect.Count -eq 1) ("redirect=$($r.Redirect.Count)")

    # A security domain outranks the own-name exemption.
    $script:OwnNameCache = $null
    $script:OwnNameProbe = { @{ ComputerName = 'windowsupdate'; Suffixes = @('microsoft.com') } }
    $r = V @('10.1.0.100 windowsupdate.microsoft.com')
    T 'a security domain is blackholing even when it matches the own name' `
      ($r.Blackhole.Count -eq 1 -and $r.Redirect.Count -eq 0 -and $r.Context.Count -eq 0) `
      ("blackhole=$($r.Blackhole.Count) context=$($r.Context.Count)")

    # No suffix discoverable: first-label fallback, declared as inferred.
    $script:OwnNameCache = $null
    $script:OwnNameProbe = { @{ ComputerName = 'z4nee52'; Suffixes = @() } }
    $r = V @('10.1.0.100 z4nee52.corp.example.com')
    T 'with no discoverable suffix the first label answers, and says so' `
      ($r.Redirect.Count -eq 0 -and ((@($r.Context) -join '; ') -match 'inferred from the first label')) `
      ("redirect=$($r.Redirect.Count) ctx=" + (@($r.Context) -join '; '))

    # ...but the fallback is still a whole-label match, not a prefix.
    $script:OwnNameCache = $null
    $r = V @('10.1.0.100 z4nee52x.corp.example.com')
    T 'the inferred fallback still refuses a prefix match' `
      ($r.Redirect.Count -eq 1) ("redirect=$($r.Redirect.Count)")

    # An unusable probe must not exempt anything.
    $script:OwnNameCache = $null
    $script:OwnNameProbe = { throw 'no CIM here' }
    $r = V @('10.1.0.100 anything.example.com')
    T 'a probe that throws exempts nothing (fails closed)' `
      ($r.Redirect.Count -eq 1) ("redirect=$($r.Redirect.Count)")
    $script:OwnNameCache = $null
    $script:OwnNameProbe = { @{ ComputerName = 'runnervmeef0v'; Suffixes = @('igb3cs02yymuxlog0fzrenhqpd.bx.internal.cloudapp.net') } }

    $r = V @('::1 localhost', 'fe80::1 host.docker.internal')
    T 'IPv6 loopback and link-local are handled' `
      ($r.Blackhole.Count -eq 0 -and $r.Redirect.Count -eq 0) ("redirect=$($r.Redirect.Count)")
    $e = @(Get-HostsEntries -Lines @('not-an-address hostname', 'orphan'))
    T 'a malformed line is not treated as an entry' ($e.Count -eq 0) ("count=$($e.Count)")

    # The mixed real-world case: Docker's entries beside a genuine hijack.
    $r = V ($docker + @('203.0.113.5 login.microsoftonline.com'))
    T 'a real hijack beside Docker entries is still found, alone' `
      ($r.Redirect.Count -eq 1 -and $r.Context.Count -eq 3) `
      ("redirect=$($r.Redirect.Count) context=$($r.Context.Count)")

    # Vacuity: the grader must actually examine entries.
    $e = @(Get-HostsEntries -Lines $docker)
    T 'the parser is not vacuous (it found the Docker entries to grade)' ($e.Count -eq 3) ("count=$($e.Count)")

    if ($fails) { Write-Output "[FAIL] $fails hosts_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] hosts_check self-test: Docker/WSL local names are context, blackholed security domains and public redirects are findings.'
    exit 0
}

# ---------------------------------------------------------------------------
if (-not $Path) {
    # Join-Path validates the drive, which throws on a non-Windows host where
    # this file legitimately does not exist; concatenation lets the missing-file
    # branch below report honestly instead of dying.
    $Path = if ($env:SystemRoot) { $env:SystemRoot.TrimEnd('\') + '\System32\drivers\etc\hosts' } else { '/etc/hosts' }
}

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    # Not "clean": the file could not be read, so nothing was checked.
    "[SKIPPED] HOSTS file not found at $Path -- DNS-hijack check NOT performed."
    Write-Marker -Sev 'WARNING'
    return
}
$lines = $null
try { $lines = Get-Content -LiteralPath $Path -EA Stop } catch {
    "[SKIPPED] HOSTS file could not be read ($($_.Exception.Message)) -- DNS-hijack check NOT performed."
    Write-Marker -Sev 'WARNING'
    return
}

$entries = @(Get-HostsEntries -Lines $lines)
$v = Get-HostsVerdict -Entries $entries
$sev = 'OK'

if ($v.Blackhole.Count -gt 0) {
    $sev = 'WARNING'
    "[WARNING] Non-standard entries found in HOSTS file: $($v.Blackhole.Count) entry(ies) make a SECURITY or UPDATE domain unreachable (T1562.001). This is how malware stops antivirus and Windows Update from working:"
    $v.Blackhole | Select-Object -First $MaxReport | ForEach-Object { '    ' + $_ }
    if ($v.Blackhole.Count -gt $MaxReport) { "    ...and $($v.Blackhole.Count - $MaxReport) more not listed (report cap $MaxReport)." }
}
if ($v.Redirect.Count -gt 0) {
    $sev = 'WARNING'
    "[WARNING] Non-standard entries found in HOSTS file: $($v.Redirect.Count) entry(ies) redirect a real domain to another address. Review for DNS hijacking:"
    $v.Redirect | Select-Object -First $MaxReport | ForEach-Object { '    ' + $_ }
    if ($v.Redirect.Count -gt $MaxReport) { "    ...and $($v.Redirect.Count - $MaxReport) more not listed (report cap $MaxReport)." }
}
if ($v.Context.Count -gt 0) {
    "[INFO] $($v.Context.Count) HOSTS entry(ies) map a local-only name, this machine's own name, or point at loopback -- Docker Desktop, WSL, VirtualBox, cloud and domain-joined hosts, and ad-blocking lists all write these by design. Context, not a finding:"
    $v.Context | Select-Object -First $MaxReport | ForEach-Object { '    ' + $_ }
    if ($v.Context.Count -gt $MaxReport) { "    ...and $($v.Context.Count - $MaxReport) more not listed (report cap $MaxReport)." }
}
if ($v.Blackhole.Count -eq 0 -and $v.Redirect.Count -eq 0 -and $v.Context.Count -eq 0) {
    "[OK] HOSTS file contains only standard entries ($($entries.Count) entry(ies) examined)."
}

Write-Marker -Sev $sev
