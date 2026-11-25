# firewall_rules_list.ps1 -- Section 8: the enabled inbound ALLOW and outbound
# BLOCK firewall rules, from the firewall's own objects.
#
# WHY (2026-11-25, group I2). The bats listed these with
#   netsh advfirewall firewall show rule ... | findstr "Rule Name" "LocalPort" ...
# netsh prints its labels in the system language ("Regelname" on German
# Windows), so on a non-English PC both listings were EMPTY -- an inbound
# rule holding a backdoor open read as "no allow rules" -- and a netsh that
# failed printed nothing either. A standard-user token skipped them outright
# ("netsh requires admin").
#
# This reads Get-NetFirewallRule (the ActiveStore: Group Policy included) and
# its application, port and address filters, all by property, never by
# printed label. A query that fails is a raised gap (dz_fwrules_gap.txt); a
# refusal on a standard-user token is a counted deferral
# (dz_fwrules_deferred.txt); dz_fwrules_done.txt is written on every path
# that reached a verdict. Listing only: no rule is graded here.
#
# Read-only. Windows PowerShell 5.1 and pwsh. Pure ASCII.
#
# Usage:
#   powershell -File tools\firewall_rules_list.ps1 -View InboundAllow|OutboundBlock [-MarkerDir <dir>] [-Elevated 0|1]
#   powershell -File tools\firewall_rules_list.ps1 -SelfTest

[CmdletBinding()]
param(
    [ValidateSet('InboundAllow', 'OutboundBlock', '')]
    [string]$View = '',
    [string]$MarkerDir = $env:TEMP,
    [int]$Elevated = -1,
    [int]$Max = 150,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) { New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-Field {
    param($Value)
    $t = ((@($Value) | ForEach-Object { [string]$_ }) -join ',')
    $t = ($t -replace '[\x00-\x1F\x7F|]', ' ').Trim()
    if ($t.Length -gt 160) { $t = $t.Substring(0, 160) + '...' }
    if (-not $t) { return 'Any' }
    return $t
}

function Test-AccessDenied {
    # Access denied anywhere in the exception chain, or a CIM/WMI access code.
    param($Err)
    $x = $Err.Exception
    while ($x) {
        if ($x -is [System.UnauthorizedAccessException]) { return $true }
        if ([string]$x.Message -match 'Access is denied|0x80070005|0x80041003') { return $true }
        $x = $x.InnerException
    }
    return $false
}

# PURE. Rule objects plus filter maps (InstanceID -> filter) into lines.
# $Rules: objects with InstanceID, DisplayName, Profile; each map may be
# $null when that filter could not be read.
function Get-FwRuleLines {
    param($Rules, $Apps, $Ports, $Addrs, [string]$Label, [int]$Max = 150)
    $out = New-Object System.Collections.ArrayList
    $rs = @($Rules | Sort-Object { [string]$_.DisplayName })
    foreach ($r in @($rs | Select-Object -First $Max)) {
        $id = [string]$r.InstanceID
        $prog = if ($null -ne $Apps) { ConvertTo-Field $Apps[$id].Program } else { '?' }
        $lp = if ($null -ne $Ports) { ConvertTo-Field $Ports[$id].LocalPort } else { '?' }
        $proto = if ($null -ne $Ports) { ConvertTo-Field $Ports[$id].Protocol } else { '?' }
        $ra = if ($null -ne $Addrs) { ConvertTo-Field $Addrs[$id].RemoteAddress } else { '?' }
        [void]$out.Add(('  ' + (ConvertTo-Field $r.DisplayName) + ' | program=' + $prog + ' | protocol=' + $proto + ' | localport=' + $lp + ' | remote=' + $ra + ' | profile=' + (ConvertTo-Field $r.Profile)))
    }
    if ($rs.Count -eq 0) { [void]$out.Add(('[INFO] No enabled ' + $Label + ' rules.')) }
    else {
        [void]$out.Add(('[INFO] ' + $rs.Count + ' enabled ' + $Label + ' rule(s)' + $(if ($rs.Count -gt $Max) { (', the first ' + $Max + ' listed') } else { '' }) + '. Listed for review; read from the firewall''s own rule objects, in any Windows language.'))
    }
    if ($null -eq $Apps -or $null -eq $Ports -or $null -eq $Addrs) {
        [void]$out.Add('[INFO] Some rule details (program, port or address filters) could not be read and show as "?".')
    }
    return @($out.ToArray())
}

# PURE. What a failed rule query means, by token.
function Get-FwFailVerdict {
    param([string]$Label, [string]$Err, [bool]$Denied, [bool]$IsElevated)
    if ($Denied -and -not $IsElevated) {
        return @{ Line = ('[DEFERRED - ADMIN REQUIRED] Firewall ' + $Label + ' rule listing: the rules are not readable from a standard-user token (' + $Err + ') -- re-run as administrator.'); Gap = $false; Deferred = 1 }
    }
    return @{ Line = ('[WARNING] Firewall ' + $Label + ' rule listing NOT performed -- the firewall rules could not be read (' + $Err + '), so a rule holding a port open would go unseen (T1562.004).'); Gap = $true; Deferred = 0 }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $r1 = [pscustomobject]@{ InstanceID = 'a'; DisplayName = 'Remote Desktop - Benutzermodus (TCP eingehend)'; Profile = 'Domain' }
    $r2 = [pscustomobject]@{ InstanceID = 'b'; DisplayName = 'zz backdoor'; Profile = 'Any' }
    $apps = @{ a = [pscustomobject]@{ Program = '%SystemRoot%\system32\svchost.exe' }; b = [pscustomobject]@{ Program = 'C:\Users\Public\svc.exe' } }
    $ports = @{ a = [pscustomobject]@{ LocalPort = '3389'; Protocol = 'TCP' }; b = [pscustomobject]@{ LocalPort = @('4444', '4445'); Protocol = 'TCP' } }
    $addrs = @{ a = [pscustomobject]@{ RemoteAddress = 'Any' }; b = [pscustomobject]@{ RemoteAddress = '203.0.113.7' } }
    $l = (Get-FwRuleLines -Rules @($r2, $r1) -Apps $apps -Ports $ports -Addrs $addrs -Label 'inbound ALLOW') -join "`n"
    T 'a rule on a German Windows is listed from its objects, with program, port and remote address (the findstr on "Rule Name" listed nothing)' ($l -match '(?m)^  Remote Desktop - Benutzermodus \(TCP eingehend\) \| program=%SystemRoot%\\system32\\svchost\.exe \| protocol=TCP \| localport=3389 \| remote=Any') $l
    T 'several ports are joined, and rules are sorted by name' ($l -match 'localport=4444,4445' -and $l.IndexOf('Remote Desktop') -lt $l.IndexOf('zz backdoor')) $l
    T 'the count line says what was read' ($l -match '(?m)^\[INFO\] 2 enabled inbound ALLOW rule\(s\)\.') $l
    $l = (Get-FwRuleLines -Rules @() -Apps @{} -Ports @{} -Addrs @{} -Label 'outbound BLOCK') -join "`n"
    T 'no rules is said, never silence' ($l -match '(?m)^\[INFO\] No enabled outbound BLOCK rules\.$') $l
    $l = (Get-FwRuleLines -Rules @($r1) -Apps $null -Ports $ports -Addrs $addrs -Label 'x') -join "`n"
    T 'a filter that could not be read shows "?" and says so' ($l -match 'program=\?' -and $l -match 'could not be read and show as "\?"') $l
    $l = (Get-FwRuleLines -Rules @([pscustomobject]@{ InstanceID = 'c'; DisplayName = ('x' + [char]10 + '[CRITICAL] forged'); Profile = 'Any' }) -Apps @{} -Ports @{} -Addrs @{} -Label 'x') -join "`n"
    T 'a rule name holding a newline cannot forge a severity line' ($l -notmatch '(?m)^\[CRITICAL\]') $l
    $l = @(Get-FwRuleLines -Rules @(1..5 | ForEach-Object { [pscustomobject]@{ InstanceID = [string]$_; DisplayName = "r$_"; Profile = 'Any' } }) -Apps @{} -Ports @{} -Addrs @{} -Label 'x' -Max 2)
    T 'a long list is capped and the cap is said' ((@($l | Where-Object { $_ -like '  r*' }).Count -eq 2) -and ($l -join ' ') -match '5 enabled x rule\(s\), the first 2 listed') ($l -join ' | ')
    $v = Get-FwFailVerdict -Label 'inbound ALLOW' -Err 'denied' -Denied $true -IsElevated $false
    T 'a standard-user token refused the rules: a counted deferral' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.Line -match '^\[DEFERRED - ADMIN REQUIRED\]') $v.Line
    $v = Get-FwFailVerdict -Label 'inbound ALLOW' -Err 'denied' -Denied $true -IsElevated $true
    T 'an administrator refused the rules: a raised gap' ($v.Gap -and $v.Line -match '^\[WARNING\] Firewall inbound ALLOW rule listing NOT performed') $v.Line
    $v = Get-FwFailVerdict -Label 'x' -Err 'RPC unavailable' -Denied $false -IsElevated $false
    T 'a failure that is not access denied is a gap on either token' ($v.Gap) $v.Line
    if ($fails) { Write-Output "[FAIL] $fails firewall_rules_list self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] firewall_rules_list self-test: rules are listed from their objects in any language; no rules is said; a failed read is a gap, a standard-user refusal a deferral.'
    exit 0
}

if (-not $View) { '[WARNING] Firewall rule listing NOT performed -- -View is required.'; Write-Marker -Name 'fwrules_gap' -Sev 'WARNING'; exit 0 }
foreach ($n in 'fwrules_gap', 'fwrules_deferred', 'fwrules_done') { Remove-Item -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $n)) -Force -EA SilentlyContinue }
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.SecurityIdentifier]'S-1-5-32-544')) { $Elevated = 1 } } catch {}
}
$dir = if ($View -eq 'InboundAllow') { 'Inbound' } else { 'Outbound' }
$act = if ($View -eq 'InboundAllow') { 'Allow' } else { 'Block' }
$label = if ($View -eq 'InboundAllow') { 'inbound ALLOW' } else { 'outbound BLOCK' }
$rules = $null
try {
    # Filtered by PROPERTY: the -Direction/-Action parameters would throw when
    # nothing matches, the shape that sent vt_ip_check to an English fallback.
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { [string]$_.Enabled -eq 'True' -and [string]$_.Direction -eq $dir -and [string]$_.Action -eq $act })
} catch {
    $v = Get-FwFailVerdict -Label $label -Err ((([string]$_.Exception.Message) -replace '\s+', ' ').Trim()) -Denied (Test-AccessDenied $_) -IsElevated ($Elevated -eq 1)
    $v.Line
    if ($v.Gap) { Write-Marker -Name 'fwrules_gap' -Sev 'WARNING' }
    if ($v.Deferred -gt 0) { Write-Marker -Name 'fwrules_deferred' -Sev '1' }
    Write-Marker -Name 'fwrules_done' -Sev 'done'
    exit 0
}
function Get-FilterMap {
    param([scriptblock]$Query)
    try {
        $m = @{}
        foreach ($f in @(& $Query)) { $m[[string]$f.InstanceID] = $f }
        return $m
    } catch { return $null }
}
$apps = $null; $ports = $null; $addrs = $null
if ($rules.Count -gt 0) {
    $apps = Get-FilterMap { Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore -ErrorAction Stop }
    $ports = Get-FilterMap { Get-NetFirewallPortFilter -All -PolicyStore ActiveStore -ErrorAction Stop }
    $addrs = Get-FilterMap { Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore -ErrorAction Stop }
} else { $apps = @{}; $ports = @{}; $addrs = @{} }
Get-FwRuleLines -Rules $rules -Apps $apps -Ports $ports -Addrs $addrs -Label $label -Max $Max
Write-Marker -Name 'fwrules_done' -Sev 'done'
exit 0
