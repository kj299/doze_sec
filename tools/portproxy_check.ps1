# portproxy_check.ps1 -- does this PC forward a local port somewhere else
# (netsh interface portproxy; T1090)? Volt Typhoon uses portproxy rules to
# tunnel its command-and-control traffic through a compromised machine, so a
# connection to this PC's port is relayed to an address the attacker chose.
#
# The check was:
#   netsh interface portproxy show all | findstr /c:"Listen"
# and printed "[OK] No netsh portproxy rules." when findstr found nothing.
# netsh's column headers come from its language files, so on a non-English
# Windows a rule never matched "Listen" -- and a netsh that failed printed
# nothing either. Both read as clean, having compared nothing. The no-admin
# bat also skipped the check on a standard-user token, although the rules are
# kept in a registry key a standard user can normally read.
#
# WHERE THE RULES LIVE: netsh writes each rule as a value under
#   HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\<kind>\tcp
# kind = v4tov4 | v4tov6 | v6tov4 | v6tov6; value NAME = listen address/port,
# value DATA = connect address/port. The IP Helper service (iphlpsvc) reads
# them and listens. CI proves the path: a rule added with netsh must be found
# here, and must be gone when netsh deletes it.
#
# THE RULE (pure, in Get-PortProxyVerdict, pinned by -SelfTest):
#   * any rule is the WARNING the bats always printed, one line per rule;
#   * the IP Helper state and whether each listen port is listening are
#     [INFO] context and never decide -- a stopped service applies the rules
#     again the next time it starts;
#   * a key or subkey that does not exist is an answer: no rules (Windows
#     leaves an EMPTY PortProxy key behind once the rules are removed, and
#     that is not a finding either);
#   * a subkey this token was DENIED is a counted deferral on a standard-user
#     token and a raised gap for an administrator; any other failure to read
#     is a raised gap. A hit and a gap are independent: both are raised.
# Markers: dz_portproxy_hit / dz_portproxy_gap / dz_portproxy_deferred.
# State: dz_portproxy_state.txt  pp=<rules|none|gap|deferred>,n=<count>.
#
# Usage:
#   powershell -File tools\portproxy_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1]
#   powershell -File tools\portproxy_check.ps1 -SelfTest   (queries nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # Only CI changes this: a throwaway key laid out like PortProxy, so every
    # state runs through the real reader.
    [string]$KeyRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_portproxy_state.txt' }

$script:Kinds = @('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6')
$script:MaxListed = 25

function Write-Marker {
    param([string]$Name, [string]$Sev)
    # An empty value is no verdict, never a marker.
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintableText {
    # Registry text goes into the report: no control characters, capped.
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt 200) { $t = $t.Substring(0, 200) + '...' }
    return $t
}

# PURE. "address/port" -> @{ Addr; Port } (Port '' when there is no slash).
function Split-ProxyEndpoint {
    param([string]$s)
    $i = ([string]$s).LastIndexOf('/')
    if ($i -lt 0) { return @{ Addr = [string]$s; Port = '' } }
    return @{ Addr = $s.Substring(0, $i); Port = $s.Substring($i + 1) }
}

# PURE. $Keys: @( @{ Kind; State = ok|nokey|denied|unreadable; Error;
# Rules = @( @{ Listen; Connect } ) } ). $Iphlp: $null (not asked) or
# @{ Status; Error }. $Listening: $null (could not be read) or an array of
# listening port numbers (as strings). Returns @{ Lines; Hit; Gap; Deferred;
# State; Count }.
function Get-PortProxyVerdict {
    param($Keys, $Iphlp = $null, $Listening = $null, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $rules = New-Object System.Collections.ArrayList
    $denied = New-Object System.Collections.ArrayList
    $failed = New-Object System.Collections.ArrayList
    foreach ($k in @($Keys)) {
        $kind = [string]$k.Kind
        switch ([string]$k.State) {
            'ok' { foreach ($r in @($k.Rules)) { [void]$rules.Add(@{ Kind = $kind; Listen = [string]$r.Listen; Connect = [string]$r.Connect }) } }
            'nokey' { }
            'denied' { [void]$denied.Add(($kind + ' (' + (ConvertTo-PrintableText ([string]$k.Error)) + ')')) }
            default { [void]$failed.Add(($kind + ' (' + (ConvertTo-PrintableText ([string]$k.Error)) + ')')) }
        }
    }
    # On a standard-user token a denial is the token's limit; for an
    # administrator a denied PortProxy key is how a rule would be hidden.
    if ($IsElevated) { foreach ($d in $denied) { [void]$failed.Add($d) }; $denied.Clear() }
    $hit = ($rules.Count -gt 0)
    $gap = ($failed.Count -gt 0)
    $deferred = $(if ($denied.Count -gt 0) { 1 } else { 0 })
    if ($hit) {
        [void]$out.Add('[WARNING] netsh portproxy rules ACTIVE. Volt Typhoon C2 tunnel IOC.')
        $n = 0
        foreach ($r in $rules) {
            $n++
            if ($n -gt $script:MaxListed) { break }
            $le = Split-ProxyEndpoint $r.Listen
            $lport = ConvertTo-PrintableText $le.Port
            $state = ''
            if ($null -ne $Listening -and $lport) {
                $state = $(if (@($Listening) -contains $lport) { ' -- a process is listening on port ' + $lport + ' now' } else { ' -- nothing is listening on port ' + $lport + ' now' })
            }
            [void]$out.Add(('[INFO]   ' + $r.Kind + ': ' + (ConvertTo-PrintableText $r.Listen) + ' -> ' + (ConvertTo-PrintableText $r.Connect) + $state))
        }
        if ($rules.Count -gt $script:MaxListed) { [void]$out.Add(('[INFO]   ... and ' + ($rules.Count - $script:MaxListed) + ' more rule(s).')) }
        if ($null -eq $Iphlp) { }
        elseif ([string]$Iphlp.Status) { [void]$out.Add(('[INFO] IP Helper (iphlpsvc), the service that applies these rules, is ' + (ConvertTo-PrintableText ([string]$Iphlp.Status)) + '; a stopped service applies them again when it starts.')) }
        else { [void]$out.Add(('[INFO] The IP Helper service (iphlpsvc) could not be queried (' + (ConvertTo-PrintableText ([string]$Iphlp.Error)) + '); whether the rules are applied now is not known.')) }
        if ($null -eq $Listening) { [void]$out.Add('[INFO] The listening ports could not be read, so whether each rule is listening now is not shown.') }
        [void]$out.Add('[INFO] WSL2, Docker and Hyper-V set portproxy rules on purpose. If you did not, someone may be relaying traffic through this PC: delete only the rule you do not recognise (netsh interface portproxy delete <kind> listenport=<port> listenaddress=<addr>).')
    }
    if ($gap) {
        $lead = $(if ($hit) { '[WARNING] Portproxy check NOT performed in full -- ' } else { '[WARNING] Portproxy check NOT performed -- ' })
        [void]$out.Add(($lead + 'the PortProxy registry key could not be read for ' + ($failed -join '; ') + ', so a port-forwarding rule there would go unseen (T1090).'))
    }
    if ($deferred) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] Portproxy rules of kind ' + ($denied -join '; ') + ' were refused to this standard-user token -- not read; an audit run as administrator reads them.'))
    }
    if (-not ($hit -or $gap -or $deferred)) {
        [void]$out.Add('[OK] No portproxy rules (read from the registry, where netsh stores them).')
    }
    $st = $(if ($hit) { 'rules' } elseif ($gap) { 'gap' } elseif ($deferred) { 'deferred' } else { 'none' })
    return @{ Lines = @($out.ToArray()); Hit = $hit; Gap = $gap; Deferred = $deferred; State = ('pp=' + $st + ',n=' + $rules.Count); Count = $rules.Count }
}

# Live. One <kind>\tcp subkey: @{ Kind; State; Error; Rules }.
function Read-ProxyKind {
    param([string]$Kind)
    $path = $KeyRoot.TrimEnd('\') + '\' + $Kind + '\tcp'
    try {
        $k = Get-Item -LiteralPath $path -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        return @{ Kind = $Kind; State = 'nokey'; Error = ''; Rules = @() }
    } catch {
        $e = $_.Exception
        $den = ($e -is [System.Security.SecurityException] -or $e -is [System.UnauthorizedAccessException] -or $e.InnerException -is [System.Security.SecurityException] -or $e.InnerException -is [System.UnauthorizedAccessException])
        return @{ Kind = $Kind; State = $(if ($den) { 'denied' } else { 'unreadable' }); Error = ($e.GetType().Name + ': ' + $e.Message); Rules = @() }
    }
    try {
        $rules = New-Object System.Collections.ArrayList
        foreach ($n in @($k.GetValueNames())) {
            if (-not $n) { continue }
            [void]$rules.Add(@{ Listen = [string]$n; Connect = [string]$k.GetValue($n) })
        }
        return @{ Kind = $Kind; State = 'ok'; Error = ''; Rules = @($rules.ToArray()) }
    } catch {
        return @{ Kind = $Kind; State = 'unreadable'; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Rules = @() }
    } finally { try { $k.Close() } catch {} }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function K { param([string]$Kind, [string]$State = 'nokey', $Rules = @(), [string]$Err = '') @{ Kind = $Kind; State = $State; Error = $Err; Rules = @($Rules) } }
    function NoKeys { @(K 'v4tov4'; K 'v4tov6'; K 'v6tov4'; K 'v6tov6') }
    $one = @{ Listen = '0.0.0.0/4444'; Connect = '203.0.113.7/443' }

    $v = Get-PortProxyVerdict -Keys (NoKeys); $t = $v.Lines -join "`n"
    T 'no PortProxy key at all: [OK], nothing raised' ((-not ($v.Hit -or $v.Gap)) -and $v.Deferred -eq 0 -and $v.State -eq 'pp=none,n=0' -and $t -match '(?m)^\[OK\] No portproxy rules \(read from the registry') $t
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'ok'; K 'v4tov6' 'ok'; K 'v6tov4'; K 'v6tov6')
    T 'the EMPTY key Windows leaves behind once the rules are gone: [OK], not a finding' ((-not $v.Hit) -and $v.State -eq 'pp=none,n=0') ($v.Lines -join ' | ')
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'ok' @($one); K 'v4tov6'; K 'v6tov4'; K 'v6tov6') -Iphlp @{ Status = 'Running'; Error = '' } -Listening @('4444', '135'); $t = $v.Lines -join "`n"
    T 'a v4tov4 rule: the WARNING the bats always printed, the rule named listen -> connect, listening said' ($v.Hit -and $v.State -eq 'pp=rules,n=1' -and $t -match '(?m)^\[WARNING\] netsh portproxy rules ACTIVE\. Volt Typhoon C2 tunnel IOC\.$' -and $t -match 'v4tov4: 0\.0\.0\.0/4444 -> 203\.0\.113\.7/443 -- a process is listening on port 4444 now' -and $t -match 'IP Helper \(iphlpsvc\).*is Running') $t
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4'; K 'v4tov6'; K 'v6tov4' 'ok' @(@{ Listen = '::/8080'; Connect = '10.0.0.5/80' }); K 'v6tov6')
    T 'a rule in v6tov4 alone is found (all four kinds are read, not only v4tov4)' ($v.Hit -and ($v.Lines -join ' ') -match 'v6tov4: ::/8080 -> 10\.0\.0\.5/80') ($v.Lines -join ' | ')
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'ok' @($one); K 'v4tov6'; K 'v6tov4'; K 'v6tov6') -Iphlp @{ Status = 'Stopped'; Error = '' } -Listening @('135')
    T 'IP Helper stopped and the port not listening: still the WARNING (the rule comes back when it starts)' ($v.Hit -and ($v.Lines -join ' ') -match 'nothing is listening on port 4444 now' -and ($v.Lines -join ' ') -match 'is Stopped; a stopped service applies them again') ($v.Lines -join ' | ')
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'unreadable' -Err 'IOException: x'; K 'v4tov6'; K 'v6tov4'; K 'v6tov6')
    T 'a subkey that could not be read: a raised gap, never [OK]' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'pp=gap,n=0' -and ($v.Lines -join ' ') -match '^\[WARNING\] Portproxy check NOT performed -- the PortProxy registry key could not be read for v4tov4' -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'denied' -Err 'SecurityException: denied'; K 'v4tov6'; K 'v6tov4'; K 'v6tov6') -IsElevated $false; $t = $v.Lines -join "`n"
    T 'denied on a standard-user token: a counted deferral, not a row, never [OK]' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.State -eq 'pp=deferred,n=0' -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] Portproxy rules of kind v4tov4' -and $t -notmatch '\[OK\]') $t
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'denied' -Err 'SecurityException: denied'; K 'v4tov6'; K 'v6tov4'; K 'v6tov6') -IsElevated $true
    T 'the same denial for an administrator: a raised gap (a deny ACL is how a rule would be hidden)' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'ok' @($one); K 'v4tov6' 'unreadable' -Err 'x'; K 'v6tov4'; K 'v6tov6')
    T 'a rule AND an unreadable subkey: both raised, and the gap says "in full"' ($v.Hit -and $v.Gap -and $v.State -eq 'pp=rules,n=1' -and ($v.Lines -join ' ') -match 'NOT performed in full') ($v.Lines -join ' | ')
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'ok' @($one); K 'v4tov6'; K 'v6tov4'; K 'v6tov6') -Iphlp @{ Status = ''; Error = 'denied' } -Listening $null
    T 'IP Helper and the listening ports unreadable: said, and the rule is still the WARNING' ($v.Hit -and ($v.Lines -join ' ') -match 'could not be queried' -and ($v.Lines -join ' ') -match 'listening ports could not be read') ($v.Lines -join ' | ')
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'ok' @(@{ Listen = ('1.2.3.4/1' + [char]13 + [char]10 + '[OK] No portproxy rules'); Connect = 'x/1' }); K 'v4tov6'; K 'v6tov4'; K 'v6tov6')
    T 'a line break inside a value name cannot forge an [OK] line' ($v.Hit -and @($v.Lines | Where-Object { $_ -match '^\[OK\]' }).Count -eq 0) ($v.Lines -join ' | ')
    $many = @(1..30 | ForEach-Object { @{ Listen = ('127.0.0.1/' + (50000 + $_)); Connect = '127.0.0.1/80' } })
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'ok' $many; K 'v4tov6'; K 'v6tov4'; K 'v6tov6')
    T 'thirty rules: 25 listed and the rest counted, never dropped silently' ($v.Count -eq 30 -and ($v.Lines -join ' ') -match '\.\.\. and 5 more rule' -and @($v.Lines | Where-Object { $_ -match '^\[INFO\]   v4tov4:' }).Count -eq 25) ($v.Lines -join ' | ')
    $e = Split-ProxyEndpoint '::1/8080'
    T 'an IPv6 listen address splits at the LAST slash' ($e.Addr -eq '::1' -and $e.Port -eq '8080') ($e.Addr + ' / ' + $e.Port)
    $v = Get-PortProxyVerdict -Keys @(K 'v4tov4' 'ok' @($one); K 'v4tov6'; K 'v6tov4'; K 'v6tov6')
    T 'the WSL2/Docker/Hyper-V note rides under every hit' (($v.Lines -join ' ') -match 'WSL2, Docker and Hyper-V set portproxy rules on purpose') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails portproxy_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] portproxy_check self-test: a rule in any of the four kinds is the WARNING, no key or an empty key is [OK], and a key that could not be read is a raised gap (or a deferral for a denied standard user), never [OK].'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$keys = @($script:Kinds | ForEach-Object { Read-ProxyKind $_ })
if (@($keys | Where-Object { $_ -and $_.Kind }).Count -ne $script:Kinds.Count) {
    # An [OK] must mean every kind was read; anything less is no verdict.
    'portproxy_check: not every portproxy kind was read; no verdict was written.'
    exit 1
}
$iphlp = $null
$listening = $null
if (@($keys | Where-Object { $_.State -eq 'ok' -and @($_.Rules).Count -gt 0 }).Count -gt 0) {
    try { $s = Get-Service -Name iphlpsvc -ErrorAction Stop; $iphlp = @{ Status = [string]$s.Status; Error = '' } }
    catch { $iphlp = @{ Status = ''; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
    try { $listening = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object { [string]$_.LocalPort } | Sort-Object -Unique) }
    catch { $listening = $null }
}
$v = $null
try { $v = Get-PortProxyVerdict -Keys $keys -Iphlp $iphlp -Listening $listening -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^pp=(rules|none|gap|deferred),n=\d+$') {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'portproxy_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
# The state first: when it cannot be saved the bat raises "produced no
# verdict", and a marker written before it would raise the hit beside that.
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('portproxy_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
if ($v.Hit) { Write-Marker -Name 'portproxy_hit' -Sev 'hit' }
if ($v.Gap) { Write-Marker -Name 'portproxy_gap' -Sev 'WARNING' }
if ($v.Deferred -gt 0) { Write-Marker -Name 'portproxy_deferred' -Sev ([string]$v.Deferred) }
exit 0
