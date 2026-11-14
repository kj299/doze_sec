# proxy_check.ps1 -- Section 3, web proxy settings (T1090).
#
# The inline block it replaces read Internet Settings with -EA SilentlyContinue
# and printed "[OK] No proxy settings in registry" when that read FAILED, and
# "HKLM ProxyServer: [OK] Not configured" for a machine key it never opened.
# It printed no severity at all, so a proxy pointing every web request of the
# person at this PC through a stranger's server was an [INFO]-level listing
# that reached no ledger row. It read only the audit's own account, and never
# read the machine-wide WinHTTP proxy Windows Update and services use.
#
# THE RULE (pure functions, pinned by -SelfTest).
#   PER ACCOUNT. Windows keeps a user's proxy in two places:
#     Internet Settings\Connections\DefaultConnectionSettings, the binary
#       record WinINet loads (flags 0x02 = a proxy server, 0x04 = an
#       auto-config (PAC) script address, 0x08 = automatic detection); and
#     the ProxyEnable / ProxyServer / AutoConfigURL values beside it.
#   For the audit's own account Windows is ASKED what is in force
#   (WinHttpGetIEProxyConfigForCurrentUser): that is the effect, and it
#   decides; a registry store that disagrees is [INFO]. For every other
#   account, and when the question cannot be asked, a proxy or PAC set in
#   EITHER store is graded, and the line names the store: the two are the
#   same setting, so where they disagree the tool cannot know which one an
#   application will use, and false reassurance is the worse error.
#   A proxy server or a PAC address in effect -> WARNING (dz_proxy_hit). The
#   owner decided: any proxy, because a proxy set by someone else reads or
#   redirects every web request. One [INFO] line beside it says who sets one
#   on purpose. Automatic detection alone (the Windows default) is [INFO]; a
#   ProxyServer value that is not switched on is [INFO] dormant.
#   GROUP POLICY ProxySettingsPerUser=0 makes the machine's Internet Settings
#   the ones in force for every account: they are then graded, and each
#   account's own settings are [INFO], not in force. That policy key could not
#   be read -> a gap (which setting is in force is unknown).
#   WINHTTP (machine-wide; Windows Update, Defender's cloud lookups and many
#   services). Windows is asked (WinHttpGetDefaultProxyConfiguration); when it
#   cannot be, the Connections\WinHttpSettings record is read instead, and the
#   line says so. A named proxy -> WARNING (dz_winhttp_hit). The 32-bit copy
#   under WOW6432Node is read too: 32-bit programs use it.
#   A key or record that could not be read, or a record that does not parse,
#   is a raised gap (dz_proxy_gap) naming it -- never "no proxy". A hit and a
#   gap are independent; both are raised.
#
# The settings are per user. The audit's own account is read through HKCU and
# named. Every OTHER account signed in at this PC (the owners of explorer.exe,
# the idiom office_macro_check uses) is read through HKEY_USERS\<SID>: an
# elevated audit is often run from a separate administrator account, and the
# proxy that carries the traffic of the person at this PC is theirs. Another
# account's registry refused to a standard-user token is [DEFERRED - ADMIN
# REQUIRED] (counted); elevated, it is a gap.
#
# Markers (in -MarkerDir): dz_proxy_hit.txt, dz_winhttp_hit.txt,
# dz_proxy_gap.txt, dz_proxy_deferred.txt (a count, for DEFERRED_COUNT), and
# dz_proxy_done.txt when the tool reached its end (the bat raises "produced no
# verdict" without it).
#
# Usage:
#   powershell -File tools\proxy_check.ps1 [-MarkerDir <dir>]
#   powershell -File tools\proxy_check.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only: it reads the
# registry and asks Windows; it changes no setting.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    # Only CI changes these, to throwaway keys, so every state runs through
    # the real reader. The per-user keys hang off KeyRoot, the machine ones
    # off MachineRoot.
    [string]$KeyRoot = 'HKCU:\Software',
    [string]$MachineRoot = 'HKLM:\SOFTWARE',
    # CI only: more roots read as if each were another signed-in account.
    [string[]]$OtherKeyRoot = @(),
    # CI only: do not ask Windows; read the registry records instead.
    [switch]$NoApi,
    # 1/0 from the caller, or -1: ask the token.
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }

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
    # Registry data and error text go into the report: no control characters,
    # and capped so a huge value cannot flood a line.
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt 200) { $t = $t.Substring(0, 200) + '...' }
    return $t
}

# PURE. The whole number a registry value holds, or $null when it is not one.
function ConvertTo-RegNumber {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [array]) { return $null }
    $n = [long]0
    if ([long]::TryParse(([string]$Value).Trim(), [ref]$n)) { return $n }
    return $null
}

# PURE. One connection record (DefaultConnectionSettings or WinHttpSettings):
# a version DWORD, a counter DWORD, a flags DWORD, then length-prefixed
# strings -- the proxy server, the bypass list and, in DefaultConnectionSettings
# only, the auto-config script address. Returns @{ Ok; Error; Flags; Proxy;
# Bypass; Pac }. A record that is cut short, or whose lengths run past its end,
# is an error: it is never read as "no proxy".
function ConvertFrom-ConnectionBlob {
    param($Bytes, [bool]$HasPac = $true)
    $r = @{ Ok = $false; Error = ''; Flags = 0; Proxy = ''; Bypass = ''; Pac = '' }
    if ($null -eq $Bytes -or -not ($Bytes -is [byte[]])) { $r.Error = 'the record is not binary data'; return $r }
    $b = [byte[]]$Bytes
    if ($b.Length -lt 16) { $r.Error = ('the record is ' + $b.Length + ' bytes, too short to hold its flags and proxy field'); return $r }
    $r.Flags = [BitConverter]::ToUInt32($b, 8)
    $pos = 12
    $fields = @('Proxy', 'Bypass')
    if ($HasPac) { $fields += 'Pac' }
    foreach ($f in $fields) {
        if ($pos + 4 -gt $b.Length) {
            # Older records end after the bypass list; a PAC field that is
            # simply not there is empty -- unless the flags say it is in use.
            if ($f -eq 'Pac' -and -not ($r.Flags -band 4)) { break }
            $r.Error = ('the record ends before its ' + $f.ToLower() + ' field'); return $r
        }
        $len = [BitConverter]::ToUInt32($b, $pos); $pos += 4
        if ($len -gt 65536 -or $pos + $len -gt $b.Length) { $r.Error = ('its ' + $f.ToLower() + ' field claims ' + $len + ' bytes and runs past the end of the record'); return $r }
        $r[$f] = [Text.Encoding]::ASCII.GetString($b, $pos, [int]$len).TrimEnd([char]0)
        $pos += [int]$len
    }
    $r.Ok = $true
    return $r
}

# PURE. What one account's registry stores put in effect.
# $Read: @{ Key = @{ State = ok|nokey|denied|unreadable; Error }; Enable;
#   Server; Pac; Bypass; Blob } -- the last five are Read-RegValueState states.
# $Api: $null, or @{ Ok; AutoDetect; Pac; Proxy; Bypass; Error } for the
#   audit's own account when Windows answered.
# Returns @{ Proxy; Pac; Server; PacUrl; Bypass; From; Info; Gaps; Denied; Read }.
function Get-AccountProxy {
    param($Read, $Api = $null)
    $a = @{ Proxy = $false; Pac = $false; Server = ''; PacUrl = ''; Bypass = ''; From = ''; Info = (New-Object System.Collections.ArrayList); Gaps = (New-Object System.Collections.ArrayList); Denied = $false; Read = $false; AutoDetect = $false }
    $ks = [string]$Read.Key.State
    $asked = ($null -ne $Api -and $Api.Ok)
    if (($ks -eq 'denied' -or $ks -eq 'unreadable') -and -not $asked) {
        $a.Denied = ($ks -eq 'denied')
        [void]$a.Gaps.Add(('its Internet Settings key could not be read (' + (ConvertTo-PrintableText ([string]$Read.Key.Error)) + ')'))
        return $a
    }
    if ($ks -eq 'nokey' -and $null -eq $Api) {
        # The key Windows keeps the setting in does not exist: an answer.
        $a.Read = $true; $a.From = 'no Internet Settings key: Windows defaults apply'
        return $a
    }
    # --- the registry stores ---
    $vals = @{}
    foreach ($n in 'Enable', 'Server', 'Pac', 'Bypass', 'Blob') {
        $s = $Read[$n]
        if ($null -eq $s) { $s = @{ State = 'absent' } }
        if ([string]$s.State -eq 'unreadable') {
            $nm = @{ Enable = 'ProxyEnable'; Server = 'ProxyServer'; Pac = 'AutoConfigURL'; Bypass = 'ProxyOverride'; Blob = 'DefaultConnectionSettings' }[$n]
            [void]$a.Gaps.Add(('its ' + $nm + ' value could not be read (' + (ConvertTo-PrintableText ([string]$s.Error)) + ')'))
            $vals[$n] = $null
        } elseif ([string]$s.State -eq 'present') { $vals[$n] = $s.Value } else { $vals[$n] = $null }
    }
    $vEnable = ConvertTo-RegNumber $vals.Enable
    $vServer = ([string]$vals.Server).Trim()
    $vPac = ([string]$vals.Pac).Trim()
    $valProxy = ($vEnable -eq 1 -and $vServer -ne '')
    $valPac = ($vPac -ne '')
    $blob = $null
    if ($null -ne $vals.Blob) {
        $blob = ConvertFrom-ConnectionBlob -Bytes $vals.Blob -HasPac $true
        if (-not $blob.Ok) { [void]$a.Gaps.Add(('its DefaultConnectionSettings record could not be parsed (' + $blob.Error + ')')); $blob = $null }
    }
    $bProxy = $false; $bPac = $false
    if ($blob) {
        $bProxy = (($blob.Flags -band 2) -and $blob.Proxy.Trim() -ne '')
        $bPac = (($blob.Flags -band 4) -and $blob.Pac.Trim() -ne '')
        if ($blob.Flags -band 8) { $a.AutoDetect = $true }
    }
    $regProxy = ($bProxy -or $valProxy); $regPac = ($bPac -or $valPac)
    $regServer = $(if ($bProxy) { $blob.Proxy.Trim() } elseif ($valProxy) { $vServer } else { '' })
    $regPacUrl = $(if ($bPac) { $blob.Pac.Trim() } elseif ($valPac) { $vPac } else { '' })
    $regBypass = $(if ($blob -and $blob.Bypass) { $blob.Bypass } else { [string]$vals.Bypass })
    $stores = New-Object System.Collections.ArrayList
    if ($bProxy -or $bPac) { [void]$stores.Add('the connection settings record') }
    if ($valProxy -or $valPac) { [void]$stores.Add('the ProxyEnable/ProxyServer/AutoConfigURL values') }
    # --- the effect ---
    if ($Api -and $Api.Ok) {
        $a.Read = $true
        $a.Proxy = ([string]$Api.Proxy).Trim() -ne ''
        $a.Pac = ([string]$Api.Pac).Trim() -ne ''
        $a.Server = ([string]$Api.Proxy).Trim(); $a.PacUrl = ([string]$Api.Pac).Trim(); $a.Bypass = [string]$Api.Bypass
        $a.AutoDetect = [bool]$Api.AutoDetect
        $a.From = 'as Windows reports it for this account'
        if ($a.Proxy -ne $regProxy -or $a.Pac -ne $regPac) {
            [void]$a.Info.Add(('the registry ' + $(if ($regProxy -or $regPac) { 'names ' + $(if ($regProxy) { 'proxy server ' + (ConvertTo-PrintableText $regServer) } else { 'auto-config script ' + (ConvertTo-PrintableText $regPacUrl) }) } else { 'no proxy' }) + ', but Windows reports ' + $(if ($a.Proxy -or $a.Pac) { 'one in force' } else { 'none in force' }) + '; what Windows reports is graded'))
        }
        # A store that could not be read does not matter when Windows answered.
        $a.Gaps.Clear()
    } else {
        $a.Read = ($a.Gaps.Count -eq 0) -or ($null -ne $blob) -or ($null -ne $vEnable)
        $a.Proxy = $regProxy; $a.Pac = $regPac; $a.Server = $regServer; $a.PacUrl = $regPacUrl; $a.Bypass = $regBypass
        if ($stores.Count) { $a.From = ($stores -join ' and ') }
        elseif ($blob) { $a.From = 'the connection settings record' }
        else { $a.From = 'the ProxyEnable/ProxyServer/AutoConfigURL values (no connection settings record)' }
        if ($blob -and ($bProxy -ne $valProxy -or $bPac -ne $valPac)) {
            [void]$a.Info.Add('the connection settings record and the ProxyEnable/ProxyServer/AutoConfigURL values disagree; a proxy in either one is graded, because which one a program reads cannot be known from here')
        }
    }
    if (-not $a.Proxy -and $vServer -ne '') { [void]$a.Info.Add(('ProxyServer holds ' + (ConvertTo-PrintableText $vServer) + ' but it is not switched on (dormant)')) }
    return $a
}

# PURE. One account's lines. $Label names the account; $Owner is set for an
# account other than the audit's own. $NotInForce: Group Policy makes the
# machine-wide settings apply, so this account's own are context only.
# Returns @{ Lines; Hit; Gap; Deferred }.
function Get-ProxyAccountVerdict {
    param($Acct, [string]$Label, [string]$Owner = '', [bool]$IsElevated = $true, [bool]$NotInForce = $false)
    $out = New-Object System.Collections.ArrayList
    $r = @{ Lines = @(); Hit = $false; Gap = $false; Deferred = 0; Gaps = @() }
    $who = ConvertTo-PrintableText $Label
    if ($Owner -and $Acct.Denied -and -not $IsElevated) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] Proxy settings of ' + $who + ', also signed in at this PC, not read: another account''s registry needs administrator.'))
        $r.Deferred = 1; $r.Lines = @($out.ToArray()); return $r
    }
    $what = New-Object System.Collections.ArrayList
    if ($Acct.Proxy) { [void]$what.Add(('proxy server ' + (ConvertTo-PrintableText $Acct.Server))) }
    if ($Acct.Pac) { [void]$what.Add(('auto-config script ' + (ConvertTo-PrintableText $Acct.PacUrl))) }
    if ($NotInForce) {
        if ($what.Count) { [void]$out.Add(('[INFO] ' + $who + ' has its own ' + ($what -join ' and ') + ', not in force: Group Policy makes the machine-wide setting apply to every account.')) }
        $r.Lines = @($out.ToArray()); return $r
    }
    if ($what.Count) {
        [void]$out.Add(('[WARNING] Web proxy in effect for ' + $who + ': ' + ($what -join ' and ') + ' (set by ' + $Acct.From + ') -- this account''s web traffic goes through it, so whoever runs it can read or redirect that traffic (T1090).'))
        $r.Hit = $true
        if ([string]$Acct.Bypass) { [void]$out.Add(('[INFO] ' + $who + ': addresses that bypass the proxy: ' + (ConvertTo-PrintableText ([string]$Acct.Bypass)) + '.')) }
    } elseif ($Acct.Read) {
        [void]$out.Add(('[OK] No web proxy in effect for ' + $who + ' (' + $Acct.From + ').'))
        if ($Acct.AutoDetect) { [void]$out.Add(('[INFO] ' + $who + ': automatic proxy detection is on, the Windows default; no proxy was found configured.')) }
    }
    foreach ($i in @($Acct.Info)) { [void]$out.Add(('[INFO] ' + $who + ': ' + $i + '.')) }
    $r.Gaps = @($Acct.Gaps | ForEach-Object { $who + ': ' + $_ })
    $r.Lines = @($out.ToArray())
    return $r
}

# PURE. The machine-wide WinHTTP proxy.
# $Api: $null, or @{ Ok; Access; Proxy; Bypass; Error }.
# $Native / $Wow: Read-RegValueState states of Connections\WinHttpSettings
#   (64-bit, and the WOW6432Node copy 32-bit programs read).
# Returns @{ Lines; Hit; Gaps }.
function Get-WinHttpVerdict {
    param($Api, $Native, $Wow)
    $out = New-Object System.Collections.ArrayList
    $gaps = New-Object System.Collections.ArrayList
    $r = @{ Lines = @(); Hit = $false; Gaps = @() }
    function Read-Store { param($S, [string]$Name)
        $st = [string]$S.State
        if ($st -eq 'unreadable') { return @{ Gap = ($Name + ' could not be read (' + (ConvertTo-PrintableText ([string]$S.Error)) + ')') } }
        if ($st -ne 'present') { return @{ Proxy = '' } }
        $p = ConvertFrom-ConnectionBlob -Bytes $S.Value -HasPac $false
        if (-not $p.Ok) { return @{ Gap = ($Name + ' could not be parsed (' + $p.Error + ')') } }
        if (($p.Flags -band 2) -and $p.Proxy.Trim() -ne '') { return @{ Proxy = $p.Proxy.Trim(); Bypass = $p.Bypass } }
        return @{ Proxy = '' }
    }
    $proxy = ''; $bypass = ''; $src = ''
    if ($Api -and $Api.Ok) {
        $src = 'read by WinHttpGetDefaultProxyConfiguration'
        if (([string]$Api.Proxy).Trim() -ne '') { $proxy = ([string]$Api.Proxy).Trim(); $bypass = [string]$Api.Bypass }
    } else {
        $n = Read-Store $Native 'the WinHttpSettings record'
        if ($n.Gap) { [void]$gaps.Add($n.Gap) }
        else {
            $src = $(if ($Api) { 'Windows could not be asked (' + (ConvertTo-PrintableText ([string]$Api.Error)) + '), so read from the WinHttpSettings record' } else { 'read from the WinHttpSettings record' })
            if ([string]$Native.State -ne 'present') { $src += '; there is none, which is direct access, the Windows default' }
            $proxy = [string]$n.Proxy; $bypass = [string]$n.Bypass
        }
    }
    if ($proxy) {
        [void]$out.Add(('[WARNING] Machine-wide WinHTTP proxy in effect: ' + (ConvertTo-PrintableText $proxy) + ' (' + $src + ') -- Windows Update, Defender''s cloud lookups and other services connect through it, so whoever runs it can read, block or redirect them (T1090).'))
        $r.Hit = $true
        if ($bypass) { [void]$out.Add(('[INFO] WinHTTP: addresses that bypass the proxy: ' + (ConvertTo-PrintableText $bypass) + '.')) }
    } elseif ($src) {
        [void]$out.Add(('[OK] WinHTTP (machine-wide): direct access, no proxy (' + $src + ').'))
    }
    $w = Read-Store $Wow 'the 32-bit (WOW6432Node) WinHttpSettings record'
    if ($w.Gap) { [void]$gaps.Add($w.Gap) }
    elseif ($w.Proxy) {
        [void]$out.Add(('[WARNING] Machine-wide WinHTTP proxy in effect for 32-bit programs: ' + (ConvertTo-PrintableText $w.Proxy) + ' (read from the WOW6432Node WinHttpSettings record) -- 32-bit services and updaters connect through it (T1090).'))
        $r.Hit = $true
    }
    $r.Gaps = @($gaps.ToArray() | ForEach-Object { 'WinHTTP: ' + $_ })
    $r.Lines = @($out.ToArray())
    return $r
}

# PURE. Everything together. $Context: @{ Account; Others; Unresolved } or
# $null. $Accounts: @( @{ Label; Owner; Acct } ). $Policy: the
# ProxySettingsPerUser reader state. $Machine: the machine account's
# Get-AccountProxy result (read only when Group Policy makes it apply).
# Returns @{ Lines; Hit; WinHit; Gap; Deferred }.
function Get-ProxyVerdict {
    param($Context, $Accounts, $Policy, $Machine, $WinHttp, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $gaps = New-Object System.Collections.ArrayList
    $v = @{ Lines = @(); Hit = $false; WinHit = $false; Gap = $false; Deferred = 0 }
    if ($Context -and $Context.Account) {
        [void]$out.Add(('[INFO] These are the proxy settings of ' + (ConvertTo-PrintableText ([string]$Context.Account)) + ', the account this audit ran as.'))
        foreach ($o in @($Context.Others | Where-Object { [string]$_ })) { [void]$out.Add(('[INFO] ' + (ConvertTo-PrintableText ([string]$o)) + ' is also signed in at this PC: its proxy settings follow, on the lines that name it.')) }
    }
    $unres = $(if ($Context) { [int]$Context.Unresolved } else { 0 })
    if ($unres -gt 0 -and $IsElevated) { [void]$gaps.Add(([string]$unres + ' desktop session(s) at this PC belong to an account that could not be identified, so their proxy settings were not read')) }
    elseif ($unres -gt 0) { [void]$out.Add(('[INFO] ' + $unres + ' desktop session(s) at this PC belong to an account this token could not identify, so their proxy settings were not read. An audit run as administrator reads them.')) }
    $machineWide = $false
    $ps = [string]$Policy.State
    if ($ps -eq 'unreadable') { [void]$gaps.Add(('the Group Policy key that decides whether the proxy is per user or machine-wide could not be read (' + (ConvertTo-PrintableText ([string]$Policy.Error)) + '), so which setting is in force is unknown')) }
    elseif ($ps -eq 'present' -and (ConvertTo-RegNumber $Policy.Value) -eq 0) { $machineWide = $true }
    if ($machineWide) {
        [void]$out.Add('[INFO] Group Policy sets ProxySettingsPerUser=0: the machine''s Internet Settings apply to every account on this PC, and are graded below.')
        $m = Get-ProxyAccountVerdict -Acct $Machine -Label 'every account on this PC (machine-wide, by Group Policy)' -IsElevated $IsElevated
        foreach ($l in $m.Lines) { [void]$out.Add($l) }
        if ($m.Hit) { $v.Hit = $true }
        foreach ($g in @($m.Gaps)) { [void]$gaps.Add($g) }
    }
    foreach ($ac in @($Accounts)) {
        $r = Get-ProxyAccountVerdict -Acct $ac.Acct -Label $ac.Label -Owner $ac.Owner -IsElevated $IsElevated -NotInForce $machineWide
        foreach ($l in $r.Lines) { [void]$out.Add($l) }
        if ($r.Hit) { $v.Hit = $true }
        $v.Deferred += [int]$r.Deferred
        if (-not $machineWide) { foreach ($g in @($r.Gaps)) { [void]$gaps.Add($g) } }
    }
    foreach ($l in @($WinHttp.Lines)) { [void]$out.Add($l) }
    if ($WinHttp.Hit) { $v.WinHit = $true }
    foreach ($g in @($WinHttp.Gaps)) { [void]$gaps.Add($g) }
    if ($v.Hit -or $v.WinHit) {
        [void]$out.Add('[INFO] Workplaces, VPNs, some antivirus products and developer tools (Fiddler, Burp) set a proxy on purpose. If neither you nor whoever manages this PC set this one, treat it as someone able to read your web traffic. Settings > Network and internet > Proxy shows the per-user setting; netsh winhttp show proxy shows the machine-wide one.')
    }
    if ($gaps.Count -gt 0) {
        $names = (@($gaps | Select-Object -First 3) -join '; ') + $(if ($gaps.Count -gt 3) { ('; and ' + ($gaps.Count - 3) + ' more') } else { '' })
        $some = (@($out | Where-Object { $_ -match '^\[(OK|WARNING)\] ' }).Count -gt 0)
        [void]$out.Add(('[WARNING] Proxy-settings check NOT performed' + $(if ($some) { ' in full' } else { '' }) + ' -- ' + $names + ', so a proxy that intercepts web traffic would go unseen (T1090).'))
        $v.Gap = $true
    }
    $v.Lines = @($out.ToArray())
    return $v
}

# Live. Four states, never two: see THE RULE.
function Read-RegValueState {
    param([string]$KeyPath, [string]$Name)
    $k = $null
    try { $k = Get-Item -LiteralPath $KeyPath -ErrorAction Stop }
    catch {
        if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { return @{ State = 'nokey'; Value = $null; Kind = ''; Error = '' } }
        return @{ State = 'unreadable'; Value = $null; Kind = ''; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
    }
    try {
        if (@($k.GetValueNames()) -notcontains $Name) { return @{ State = 'absent'; Value = $null; Kind = ''; Error = '' } }
        return @{ State = 'present'; Value = $k.GetValue($Name, $null); Kind = [string]$k.GetValueKind($Name); Error = '' }
    } catch { return @{ State = 'unreadable'; Value = $null; Kind = ''; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
}

# Live. One account's (or the machine's) Internet Settings, every value through
# the four-state reader. The key itself is told apart as denied, so a standard
# user refused another account's registry can be a deferral.
function Read-InetSettings {
    param([string]$Root)
    $is = ($Root.TrimEnd('\') + '\Microsoft\Windows\CurrentVersion\Internet Settings')
    $key = @{ State = 'ok'; Error = '' }
    try { $null = Get-Item -LiteralPath $is -ErrorAction Stop }
    catch {
        if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { $key = @{ State = 'nokey'; Error = '' } }
        else {
            $den = ($_.Exception -is [System.Security.SecurityException] -or $_.Exception -is [System.UnauthorizedAccessException])
            $key = @{ State = $(if ($den) { 'denied' } else { 'unreadable' }); Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
        }
    }
    $r = @{ Key = $key }
    if ($key.State -ne 'ok') { return $r }
    $r.Enable = Read-RegValueState -KeyPath $is -Name 'ProxyEnable'
    $r.Server = Read-RegValueState -KeyPath $is -Name 'ProxyServer'
    $r.Pac = Read-RegValueState -KeyPath $is -Name 'AutoConfigURL'
    $r.Bypass = Read-RegValueState -KeyPath $is -Name 'ProxyOverride'
    $r.Blob = Read-RegValueState -KeyPath ($is + '\Connections') -Name 'DefaultConnectionSettings'
    return $r
}

# Live. Ask Windows. Add-Type refused, or the call failing, is "not asked":
# the registry records then decide, and the lines say so.
function Get-ApiAnswers {
    $res = @{ User = @{ Ok = $false; Error = 'not asked' }; Machine = @{ Ok = $false; Error = 'not asked' } }
    try {
        if (-not ('DozeSec.WinHttpProxy' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace DozeSec {
public static class WinHttpProxy {
    [StructLayout(LayoutKind.Sequential)]
    struct IEConfig { public bool fAutoDetect; public IntPtr lpszAutoConfigUrl; public IntPtr lpszProxy; public IntPtr lpszProxyBypass; }
    [StructLayout(LayoutKind.Sequential)]
    struct ProxyInfo { public uint dwAccessType; public IntPtr lpszProxy; public IntPtr lpszProxyBypass; }
    [DllImport("winhttp.dll", SetLastError = true)]
    static extern bool WinHttpGetIEProxyConfigForCurrentUser(ref IEConfig c);
    [DllImport("winhttp.dll", SetLastError = true)]
    static extern bool WinHttpGetDefaultProxyConfiguration(ref ProxyInfo p);
    [DllImport("kernel32.dll")]
    static extern IntPtr GlobalFree(IntPtr h);
    static string Take(IntPtr p) { if (p == IntPtr.Zero) { return ""; } string s = Marshal.PtrToStringUni(p); GlobalFree(p); return s ?? ""; }
    public static string[] User() {
        IEConfig c = new IEConfig();
        if (!WinHttpGetIEProxyConfigForCurrentUser(ref c)) { return new string[] { "error", Marshal.GetLastWin32Error().ToString() }; }
        return new string[] { "ok", c.fAutoDetect ? "1" : "0", Take(c.lpszAutoConfigUrl), Take(c.lpszProxy), Take(c.lpszProxyBypass) };
    }
    public static string[] Machine() {
        ProxyInfo p = new ProxyInfo();
        if (!WinHttpGetDefaultProxyConfiguration(ref p)) { return new string[] { "error", Marshal.GetLastWin32Error().ToString() }; }
        return new string[] { "ok", p.dwAccessType.ToString(), Take(p.lpszProxy), Take(p.lpszProxyBypass) };
    }
}
}
'@
        }
    } catch { $e = ('Add-Type refused: ' + $_.Exception.Message); $res.User.Error = $e; $res.Machine.Error = $e; return $res }
    try {
        $u = [DozeSec.WinHttpProxy]::User()
        if ($u[0] -eq 'ok') { $res.User = @{ Ok = $true; AutoDetect = ($u[1] -eq '1'); Pac = $u[2]; Proxy = $u[3]; Bypass = $u[4]; Error = '' } }
        else { $res.User = @{ Ok = $false; Error = ('WinHttpGetIEProxyConfigForCurrentUser failed, Win32 error ' + $u[1]) } }
    } catch { $res.User = @{ Ok = $false; Error = $_.Exception.Message } }
    try {
        $m = [DozeSec.WinHttpProxy]::Machine()
        if ($m[0] -eq 'ok') { $res.Machine = @{ Ok = $true; Access = $m[1]; Proxy = $m[2]; Bypass = $m[3]; Error = '' } }
        else { $res.Machine = @{ Ok = $false; Error = ('WinHttpGetDefaultProxyConfiguration failed, Win32 error ' + $m[1]) } }
    } catch { $res.Machine = @{ Ok = $false; Error = $_.Exception.Message } }
    return $res
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function Blob { param([uint32]$Flags, [string]$Proxy = '', [string]$Bypass = '', [string]$Pac = '', [switch]$NoPac)
        $ms = New-Object IO.MemoryStream
        $w = New-Object IO.BinaryWriter($ms)
        $w.Write([uint32]0x46); $w.Write([uint32]1); $w.Write($Flags)
        $parts = @($Proxy, $Bypass); if (-not $NoPac) { $parts += $Pac }
        foreach ($s in $parts) { $bs = [Text.Encoding]::ASCII.GetBytes($s); $w.Write([uint32]$bs.Length); $w.Write($bs) }
        $w.Write([uint32]0); $w.Flush()
        return ,($ms.ToArray())
    }
    function P { param($v, [string]$k = 'String') @{ State = 'present'; Value = $v; Kind = $k; Error = '' } }
    function PB { param([byte[]]$b) @{ State = 'present'; Value = $b; Kind = 'Binary'; Error = '' } }
    $A = @{ State = 'absent'; Value = $null; Kind = ''; Error = '' }
    $N = @{ State = 'nokey'; Value = $null; Kind = ''; Error = '' }
    $U = @{ State = 'unreadable'; Value = $null; Kind = ''; Error = 'SecurityException: Requested registry access is not allowed.' }
    function NewRead { param($Blob = $A, $Enable = $A, $Server = $A, $Pac = $A, $Bypass = $A, $Key = @{ State = 'ok'; Error = '' })
        @{ Key = $Key; Blob = $Blob; Enable = $Enable; Server = $Server; Pac = $Pac; Bypass = $Bypass }
    }
    $direct = PB (Blob 1)
    $auto = PB (Blob 9)
    $wDirect = @{ Lines = @('[OK] WinHTTP (machine-wide): direct access, no proxy (test).'); Hit = $false; Gaps = @() }
    function V { param($Accts, $Policy = $N, $Machine = $null, $Win = $wDirect, $Ctx = $null, [bool]$El = $true)
        $x = Get-ProxyVerdict -Context $Ctx -Accounts $Accts -Policy $Policy -Machine $Machine -WinHttp $Win -IsElevated $El
        $x.Text = ($x.Lines -join "`n"); return $x
    }
    function Me { param($Read, $Api = $null) ,@(@{ Label = 'this account'; Owner = ''; Acct = (Get-AccountProxy -Read $Read -Api $Api) }) }

    # --- the record parser ---
    $p = ConvertFrom-ConnectionBlob -Bytes (Blob 3 'proxy.example:8080' '<local>' '')
    T 'record: flags, proxy and bypass list read' ($p.Ok -and $p.Flags -eq 3 -and $p.Proxy -eq 'proxy.example:8080' -and $p.Bypass -eq '<local>') ("{0} {1} {2}" -f $p.Ok, $p.Flags, $p.Error)
    $p = ConvertFrom-ConnectionBlob -Bytes (Blob 5 '' '' 'http://wpad.example/proxy.pac')
    T 'record: an auto-config script address read' ($p.Ok -and $p.Pac -eq 'http://wpad.example/proxy.pac') $p.Error
    $p = ConvertFrom-ConnectionBlob -Bytes ([byte[]](0x46, 0, 0, 0, 1, 0, 0, 0))
    T 'record: cut short is an error, never "no proxy"' ((-not $p.Ok) -and $p.Error -match 'too short') $p.Error
    $b = Blob 3 'proxy.example:8080'; $b[12] = 0xFF; $b[13] = 0xFF
    $p = ConvertFrom-ConnectionBlob -Bytes $b
    T 'record: a length that runs past the end is an error' ((-not $p.Ok) -and $p.Error -match 'runs past the end') $p.Error
    $p = ConvertFrom-ConnectionBlob -Bytes (Blob 3 'p:1' '' -NoPac) -HasPac $false
    T 'WinHttpSettings: no PAC field, read' ($p.Ok -and $p.Proxy -eq 'p:1') $p.Error
    $p = ConvertFrom-ConnectionBlob -Bytes 'not bytes'
    T 'record: a value that is not binary is an error' (-not $p.Ok) $p.Error

    # --- one account, from the registry ---
    $v = V (Me (NewRead -Blob $direct))
    T 'direct access only: [OK], nothing raised' ((-not $v.Hit) -and (-not $v.Gap) -and $v.Text -match '(?m)^\[OK\] No web proxy in effect for this account \(the connection settings record\)\.$') $v.Text
    $v = V (Me (NewRead -Blob $auto))
    T 'automatic detection only (the Windows default): [OK] plus INFO, never a WARNING' ((-not $v.Hit) -and $v.Text -match 'automatic proxy detection is on, the Windows default' -and $v.Text -notmatch '\[WARNING\]') $v.Text
    $v = V (Me (NewRead -Blob (PB (Blob 3 '127.0.0.1:8888' '<local>'))))
    T 'a proxy server in the record: the WARNING, naming it and the store, plus the bypass list and the who-sets-one INFO' ($v.Hit -and $v.Text -match '(?m)^\[WARNING\] Web proxy in effect for this account: proxy server 127\.0\.0\.1:8888 \(set by the connection settings record\)' -and $v.Text -match 'bypass the proxy: <local>' -and $v.Text -match 'Fiddler, Burp') $v.Text
    $v = V (Me (NewRead -Blob (PB (Blob 5 '' '' 'http://evil.example/p.pac'))))
    T 'an auto-config (PAC) script: the WARNING' ($v.Hit -and $v.Text -match 'auto-config script http://evil\.example/p\.pac') $v.Text
    $v = V (Me (NewRead -Blob $direct -Enable (P 1 'DWord') -Server (P 'evil.example:3128')))
    T 'the values switch a proxy on while the record says direct: graded, the disagreement said' ($v.Hit -and $v.Text -match 'set by the ProxyEnable/ProxyServer/AutoConfigURL values' -and $v.Text -match 'disagree') $v.Text
    $v = V (Me (NewRead -Blob $direct -Pac (P 'http://evil.example/x.pac')))
    T 'AutoConfigURL alone (the value adware sets): the WARNING' ($v.Hit -and $v.Text -match 'auto-config script http://evil\.example/x\.pac') $v.Text
    $v = V (Me (NewRead -Blob $direct -Enable (P 0 'DWord') -Server (P 'old.example:80')))
    T 'a ProxyServer that is not switched on: [OK] plus INFO dormant, no WARNING' ((-not $v.Hit) -and $v.Text -match 'not switched on \(dormant\)' -and $v.Text -match '\[OK\] No web proxy') $v.Text
    $v = V (Me (NewRead -Enable (P 1 'DWord') -Server (P 'evil.example:3128')))
    T 'no record at all, the values switch a proxy on: the WARNING' ($v.Hit) $v.Text
    $v = V (Me (NewRead -Enable (P 0 'DWord')))
    T 'no record, nothing switched on: [OK] naming the values' ((-not $v.Hit) -and $v.Text -match 'no connection settings record') $v.Text
    $v = V (Me (NewRead -Enable (P 1 'DWord') -Server (P '   ')))
    T 'ProxyEnable 1 with a blank server is no proxy' (-not $v.Hit) $v.Text
    $v = V (Me (NewRead -Key @{ State = 'nokey'; Error = '' }))
    T 'no Internet Settings key: [OK], Windows defaults' ((-not $v.Hit) -and (-not $v.Gap) -and $v.Text -match 'Windows defaults apply') $v.Text

    # --- reads that fail ---
    $v = V (Me (NewRead -Key @{ State = 'unreadable'; Error = 'IOException: x' }))
    T 'the Internet Settings key could not be read: a raised gap, never "[OK] No proxy" (the old block)' ($v.Gap -and (-not $v.Hit) -and $v.Text -match '(?m)^\[WARNING\] Proxy-settings check NOT performed in full -- this account: its Internet Settings key could not be read' -and $v.Text -notmatch 'No web proxy in effect for this account') $v.Text
    $v = V (Me (NewRead -Blob $U))
    T 'the record could not be read: a gap, never [OK]' ($v.Gap -and $v.Text -match 'DefaultConnectionSettings value could not be read' -and $v.Text -notmatch '\[OK\] No web proxy in effect for this account') $v.Text
    $v = V (Me (NewRead -Blob (PB ([byte[]](1, 2, 3)))))
    T 'a record that does not parse: a gap' ($v.Gap -and $v.Text -match 'could not be parsed') $v.Text
    $v = V (Me (NewRead -Blob (PB (Blob 3 'evil.example:1')) -Server $U))
    T 'a proxy found AND a value unreadable: both raised' ($v.Hit -and $v.Gap) $v.Text

    # --- the audit's own account, Windows asked ---
    $api = @{ Ok = $true; AutoDetect = $false; Pac = ''; Proxy = 'evil.example:3128'; Bypass = ''; Error = '' }
    $v = V (Me (NewRead -Blob $direct) $api)
    T 'Windows reports a proxy the registry does not hold: the WARNING, the difference said' ($v.Hit -and $v.Text -match 'as Windows reports it' -and $v.Text -match 'Windows reports one in force') $v.Text
    $api0 = @{ Ok = $true; AutoDetect = $true; Pac = ''; Proxy = ''; Bypass = ''; Error = '' }
    $v = V (Me (NewRead -Blob (PB (Blob 3 'stale.example:1'))) $api0)
    T 'Windows reports none while the registry holds one: [OK] -- the effect decides, the difference is INFO' ((-not $v.Hit) -and $v.Text -match 'names proxy server stale\.example:1, but Windows reports none in force') $v.Text
    $v = V (Me (NewRead -Blob $U) $api0)
    T 'a store unreadable while Windows answered: no gap -- the effect was read' ((-not $v.Gap) -and (-not $v.Hit)) $v.Text
    $v = V (Me (NewRead -Key @{ State = 'unreadable'; Error = 'x' }) $api)
    T 'the whole key unreadable while Windows answered a proxy: the WARNING, no gap -- Windows reported the effect' ($v.Hit -and (-not $v.Gap)) $v.Text

    # --- other accounts, tokens ---
    $oth = @{ Label = 'PC\alice'; Owner = 'PC\alice'; Acct = (Get-AccountProxy -Read (NewRead -Key @{ State = 'denied'; Error = 'SecurityException: denied' })) }
    $v = V @((Me (NewRead -Blob $direct))[0], $oth) -El $false
    T 'another account refused to a standard-user token: DEFERRED and counted, no gap' ($v.Deferred -eq 1 -and (-not $v.Gap) -and $v.Text -match '\[DEFERRED - ADMIN REQUIRED\] Proxy settings of PC\\alice') $v.Text
    $v = V @((Me (NewRead -Blob $direct))[0], $oth) -El $true
    T 'the same refusal when elevated: a raised gap naming the account' ($v.Gap -and $v.Deferred -eq 0 -and $v.Text -match 'PC\\alice: its Internet Settings key could not be read') $v.Text
    $oh = @{ Label = 'PC\alice'; Owner = 'PC\alice'; Acct = (Get-AccountProxy -Read (NewRead -Blob (PB (Blob 3 'evil.example:1')))) }
    $v = V @((Me (NewRead -Blob $direct))[0], $oh) -Ctx @{ Account = 'PC\admin'; Others = @('PC\alice'); Unresolved = 0 }
    T 'another signed-in account''s proxy: the WARNING names that account; the audit''s own is [OK]' ($v.Hit -and $v.Text -match 'Web proxy in effect for PC\\alice' -and $v.Text -match '\[OK\] No web proxy in effect for this account' -and $v.Text -match 'These are the proxy settings of PC\\admin') $v.Text
    $v = V (Me (NewRead -Blob $direct)) -Ctx @{ Account = 'PC\admin'; Others = @(); Unresolved = 2 } -El $true
    T 'desktop sessions whose account could not be told, elevated: a gap' ($v.Gap -and $v.Text -match '2 desktop session') $v.Text
    $v = V (Me (NewRead -Blob $direct)) -Ctx @{ Account = 'PC\u'; Others = @(); Unresolved = 2 } -El $false
    T 'the same on a standard-user token: INFO, no gap' ((-not $v.Gap) -and $v.Text -match '\[INFO\] 2 desktop session') $v.Text

    # --- Group Policy machine-wide ---
    $mach = Get-AccountProxy -Read (NewRead -Blob (PB (Blob 3 'corp.example:8080')))
    $v = V (Me (NewRead -Blob (PB (Blob 3 'mine.example:1')))) -Policy (P 0 'DWord') -Machine $mach
    T 'ProxySettingsPerUser=0: the machine setting is graded, the account''s own is INFO not in force' ($v.Hit -and $v.Text -match 'Web proxy in effect for every account on this PC \(machine-wide, by Group Policy\): proxy server corp\.example:8080' -and $v.Text -match '\[INFO\] this account has its own proxy server mine\.example:1, not in force' -and $v.Text -notmatch 'Web proxy in effect for this account') $v.Text
    $v = V (Me (NewRead -Blob $direct)) -Policy (P 0 'DWord') -Machine (Get-AccountProxy -Read (NewRead -Blob $direct))
    T 'machine-wide and direct: [OK] for every account' ((-not $v.Hit) -and $v.Text -match '\[OK\] No web proxy in effect for every account on this PC') $v.Text
    $v = V (Me (NewRead -Blob $direct)) -Policy $U
    T 'the policy key could not be read: a gap (which setting is in force is unknown)' ($v.Gap -and $v.Text -match 'which setting is in force is unknown') $v.Text
    $v = V (Me (NewRead -Blob (PB (Blob 3 'evil.example:1')))) -Policy (P 1 'DWord')
    T 'ProxySettingsPerUser=1: per user, graded as usual' ($v.Hit -and $v.Text -match 'Web proxy in effect for this account') $v.Text

    # --- WinHTTP ---
    $w = Get-WinHttpVerdict -Api @{ Ok = $true; Access = '1'; Proxy = ''; Bypass = '' } -Native $A -Wow $N
    T 'WinHTTP asked, no proxy: [OK] naming the API' ((-not $w.Hit) -and $w.Lines[0] -match '^\[OK\] WinHTTP \(machine-wide\): direct access, no proxy \(read by WinHttpGetDefaultProxyConfiguration\)') ($w.Lines -join ' | ')
    $w = Get-WinHttpVerdict -Api @{ Ok = $true; Access = '3'; Proxy = '127.0.0.1:1'; Bypass = '<local>' } -Native $A -Wow $N
    T 'WinHTTP asked, a named proxy: the WARNING naming it and what it reaches' ($w.Hit -and ($w.Lines -join "`n") -match '(?m)^\[WARNING\] Machine-wide WinHTTP proxy in effect: 127\.0\.0\.1:1 \(read by WinHttpGetDefaultProxyConfiguration\) -- Windows Update') ($w.Lines -join ' | ')
    $w = Get-WinHttpVerdict -Api @{ Ok = $false; Error = 'Add-Type refused: x' } -Native (PB (Blob 3 'evil.example:1' '' -NoPac)) -Wow $N
    T 'WinHTTP not asked: the record decides, and the line says why' ($w.Hit -and ($w.Lines -join "`n") -match 'Windows could not be asked \(Add-Type refused: x\), so read from the WinHttpSettings record') ($w.Lines -join ' | ')
    $w = Get-WinHttpVerdict -Api $null -Native $A -Wow $N
    T 'no WinHttpSettings record: direct access, the Windows default, said' ((-not $w.Hit) -and ($w.Lines -join "`n") -match 'there is none, which is direct access, the Windows default') ($w.Lines -join ' | ')
    $w = Get-WinHttpVerdict -Api $null -Native $U -Wow $N
    T 'WinHttpSettings unreadable and Windows not asked: a gap, never [OK]' ($w.Gaps.Count -eq 1 -and ($w.Lines -join "`n") -notmatch '\[OK\]') ($w.Lines -join ' | ')
    $w = Get-WinHttpVerdict -Api @{ Ok = $true; Access = '1'; Proxy = ''; Bypass = '' } -Native $A -Wow (PB (Blob 3 'evil32.example:1' '' -NoPac))
    T 'the 32-bit WOW6432Node record holds a proxy: its own WARNING' ($w.Hit -and ($w.Lines -join "`n") -match 'for 32-bit programs: evil32\.example:1') ($w.Lines -join ' | ')
    $v = V (Me (NewRead -Blob $direct)) -Win (Get-WinHttpVerdict -Api $null -Native $U -Wow $N)
    T 'a WinHTTP gap is one raised gap row, beside the [OK] for the account' ($v.Gap -and (-not $v.WinHit) -and $v.Text -match 'Proxy-settings check NOT performed in full -- WinHTTP: the WinHttpSettings record could not be read') $v.Text
    $v = V (Me (NewRead -Blob $direct)) -Win (Get-WinHttpVerdict -Api @{ Ok = $true; Access = '3'; Proxy = 'x:1'; Bypass = '' } -Native $A -Wow $N)
    T 'a WinHTTP proxy raises its own marker, not the per-user one' ($v.WinHit -and (-not $v.Hit)) $v.Text

    # --- printing ---
    $v = V (Me (NewRead -Blob (PB (Blob 3 ("x:1" + [char]13 + [char]10 + '[OK] No web proxy in effect for this account')))))
    T 'a line break inside a proxy value cannot forge an [OK] line' ($v.Hit -and @($v.Lines | Where-Object { $_ -match '^\[OK\] No web proxy' }).Count -eq 0) $v.Text
    $v = V (Me (NewRead -Key @{ State = 'unreadable'; Error = 'x' })) -Win (Get-WinHttpVerdict -Api $null -Native $U -Wow $N)
    T 'nothing could be read at all: NOT performed (not "in full"), and no [OK] anywhere' ($v.Gap -and $v.Text -match 'Proxy-settings check NOT performed -- ' -and $v.Text -notmatch '\[OK\]') $v.Text

    if ($fails) { Write-Output "[FAIL] $fails proxy_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] proxy_check self-test: a proxy or auto-config script in effect is a WARNING naming the account and the store, the machine-wide WinHTTP proxy is read, automatic detection and dormant values are INFO, and a key or record that could not be read is a raised gap, never "no proxy".'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$v = $null; $why = ''
try {
    $realUser = ($KeyRoot -ieq 'HKCU:\Software')
    $realMachine = ($MachineRoot -ieq 'HKLM:\SOFTWARE')
    $api = $null
    if (-not $NoApi -and ($realUser -or $realMachine)) { $api = Get-ApiAnswers }
    # The other accounts signed in at this PC: the owners of explorer.exe
    # (the office_macro_check idiom, with its race handling).
    $others = New-Object System.Collections.ArrayList
    foreach ($ok in @($OtherKeyRoot | Where-Object { [string]$_ })) { [void]$others.Add(@{ Name = [string]$ok; Root = [string]$ok }) }
    $ctx = $null
    if ($realUser) {
        $acct = ''; $mySid = ''
        try { $id = [Security.Principal.WindowsIdentity]::GetCurrent(); $acct = $id.Name; $mySid = $id.User.Value } catch {}
        $unresolved = 0; $seen = @{}
        try {
            foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop)) {
                $sid = ''; $nm = ''
                try { $sr = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop; if ([int]$sr.ReturnValue -eq 0) { $sid = [string]$sr.Sid } } catch {}
                try { $or = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop; if ([int]$or.ReturnValue -eq 0 -and $or.User) { $nm = $(if ($or.Domain) { [string]$or.Domain + '\' + [string]$or.User } else { [string]$or.User }) } } catch {}
                if (-not $sid) {
                    $still = $null; try { $still = Get-CimInstance Win32_Process -Filter ("ProcessId=" + [int]$p.ProcessId) -ErrorAction Stop } catch {}
                    if ($still) { $unresolved++ }
                    continue
                }
                if ($sid -eq $mySid -or $seen.ContainsKey($sid)) { continue }
                $seen[$sid] = $true
                [void]$others.Add(@{ Name = $(if ($nm) { $nm } else { $sid }); Root = ('Registry::HKEY_USERS\' + $sid + '\Software') })
            }
        } catch {}
        $ctx = @{ Account = $acct; Others = @($others | ForEach-Object { $_.Name }); Unresolved = $unresolved }
    }
    $userApi = $(if ($realUser -and $api -and $api.User.Ok) { $api.User } else { $null })
    $accts = New-Object System.Collections.ArrayList
    [void]$accts.Add(@{ Label = 'this account'; Owner = ''; Acct = (Get-AccountProxy -Read (Read-InetSettings -Root $KeyRoot) -Api $userApi) })
    foreach ($o in $others) { [void]$accts.Add(@{ Label = $o.Name; Owner = $o.Name; Acct = (Get-AccountProxy -Read (Read-InetSettings -Root $o.Root)) }) }
    $mr = $MachineRoot.TrimEnd('\')
    $policy = Read-RegValueState -KeyPath ($mr + '\Policies\Microsoft\Windows\CurrentVersion\Internet Settings') -Name 'ProxySettingsPerUser'
    $machine = Get-AccountProxy -Read (Read-InetSettings -Root $mr)
    $wConn = '\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
    $wNative = Read-RegValueState -KeyPath ($mr + $wConn) -Name 'WinHttpSettings'
    $wWow = Read-RegValueState -KeyPath ($mr + '\WOW6432Node' + $wConn) -Name 'WinHttpSettings'
    $machApi = $(if ($realMachine -and $api) { $api.Machine } else { $null })
    $win = Get-WinHttpVerdict -Api $machApi -Native $wNative -Wow $wWow
    $v = Get-ProxyVerdict -Context $ctx -Accounts @($accts.ToArray()) -Policy $policy -Machine $machine -WinHttp $win -IsElevated ($Elevated -eq 1)
} catch { $v = $null; $why = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
if ($null -eq $v -or -not $v.Lines) {
    ('proxy_check: the grading step failed (' + (ConvertTo-PrintableText $why) + '); no verdict was written.')
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.Hit) { Write-Marker -Name 'proxy_hit' -Sev 'WARNING' }
if ($v.WinHit) { Write-Marker -Name 'winhttp_hit' -Sev 'WARNING' }
if ($v.Gap) { Write-Marker -Name 'proxy_gap' -Sev 'WARNING' }
if ([int]$v.Deferred -gt 0) { Write-Marker -Name 'proxy_deferred' -Sev ([string][int]$v.Deferred) }
Write-Marker -Name 'proxy_done' -Sev 'done'
exit 0
