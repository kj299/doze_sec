# edr_presence.ps1 -- what endpoint telemetry does this machine actually have,
# and is it running? Invoked from Section 9.
#
# WHY: Section 9 asks whether DEFENDER is healthy and never whether anything
# richer exists. "Sysmon" appeared nowhere in this repository. Two different
# things follow from that, and only one of them is a finding:
#
#   1. INVENTORY (informational). Whether this machine has telemetry beyond
#      Defender at all. Most consumer machines have none, so absence is NOT a
#      fault -- but it is exactly the context a reader needs to weigh a clean
#      result, and it belongs beside the COVERAGE & CONFIDENCE framing this tool
#      already commits to. A clean audit on a box with no EDR and no Sysmon
#      means less than the same result on a box with both.
#
#   2. A STOPPED AGENT (a real finding). An EDR service or the Sysmon driver
#      that is INSTALLED BUT NOT RUNNING says something changed: either it was
#      disabled -- the first thing an intruder does after gaining admin
#      (T1562.001) -- or it is broken, and the user believes they are protected
#      when they are not. Either way they need to know.
#
# SEVERITY IS DELIBERATELY RESTRAINED. "No EDR installed" is [INFO], the same
# call already made for ADFS / Azure AD Connect and the default screensaver:
# installed software is context or attack surface, not evidence of compromise.
# Raising it would fire on nearly every home machine and teach the reader to
# skip Section 9 entirely.
#
# WHAT THIS DELIBERATELY DOES NOT DO: grade Sysmon's CONFIG QUALITY -- which
# event types are covered, which hashing algorithms, how the include/exclude
# rules are written. That needs `sysmon -c`, i.e. executing the vendor binary on
# a machine under suspicion, which this tool should not do: it is an execution
# an operator watching process creation would see. The check stops at "is a
# config loaded at all", and the report says so, so nobody reads more into the
# result than was actually measured.
#
# MARKER: severity word to $env:TEMP\dz_edr.txt; the caller raises via
# :dz_finding. No marker when nothing is installed-but-stopped.
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -EA SilentlyContinue
}
function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

'--- [T1562.001] Endpoint telemetry: what is installed, and is it running? ---'
$sev = 'OK'
$inspected = 0

# Known EDR/AV agent services. Matched by SERVICE NAME, and the signal is
# presence-vs-running -- not the vendor. The list is a convenience for naming
# what was found; an agent not listed here still shows up through
# SecurityCenter2 below.
$edrServices = @{
    'CSFalconService'   = 'CrowdStrike Falcon'
    'CSAgent'           = 'CrowdStrike Falcon (driver service)'
    'SentinelAgent'     = 'SentinelOne'
    'SentinelStaticEngine' = 'SentinelOne (static engine)'
    'Sense'             = 'Microsoft Defender for Endpoint (EDR sensor)'
    'CarbonBlack'       = 'VMware Carbon Black'
    'CbDefense'         = 'VMware Carbon Black Cloud'
    'CylanceSvc'        = 'BlackBerry Cylance'
    'cyserver'          = 'Palo Alto Cortex XDR'
    'CyveraService'     = 'Palo Alto Cortex XDR (Cyvera)'
    'elastic-agent'     = 'Elastic Agent'
    'elastic-endpoint'  = 'Elastic Defend'
    'TaniumClient'      = 'Tanium'
    'masvc'             = 'Trellix/McAfee Agent'
    'macmnsvc'          = 'Trellix/McAfee Agent (management)'
    'SAVService'        = 'Sophos Anti-Virus'
    'Sophos Endpoint Defense Service' = 'Sophos Endpoint Defense'
    'AMSP'              = 'Trend Micro'
    'ds_agent'          = 'Trend Micro Deep Security'
    'HealthService'     = 'Microsoft Monitoring Agent / MMA'
    'WazuhSvc'          = 'Wazuh'
    'VelociraptorService' = 'Velociraptor'
}

$found = @()
foreach ($svcName in $edrServices.Keys) {
    $svc = $null
    try { $svc = Get-Service -Name $svcName -EA Stop } catch { continue }
    if (-not $svc) { continue }
    $inspected++
    $label = $edrServices[$svcName]
    if ($svc.Status -eq 'Running') {
        $found += $label
        "[OK] $label is installed and RUNNING (service '$svcName')."
    } else {
        # THIS is the finding: installed means someone chose to protect this
        # machine; not running means that protection is not happening now.
        "[WARNING] $label is INSTALLED BUT NOT RUNNING (service '$svcName' is $($svc.Status)) -- endpoint protection that is present but stopped is either disabled deliberately (T1562.001, a standard post-compromise step) or broken. Either way this machine is not being watched the way its owner expects."
        $sev = Get-MaxSev $sev 'WARNING'
    }
}

# Registered security products, as Windows itself sees them. Catches agents not
# in the list above.
$scOk = $true
try {
    $av = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -EA Stop)
    foreach ($p in $av) {
        $inspected++
        $nm = [string]$p.displayName
        # productState is a bitfield; bits 0x1000 in the second byte mean
        # "enabled". Decoding it exactly across Windows versions is unreliable,
        # so report the product and its raw state rather than asserting a
        # verdict the encoding may not support.
        $state = 0
        try { $state = [int]$p.productState } catch {}
        $enabled = (($state -band 0x1000) -ne 0)
        if ($enabled) {
            "[INFO] Security Center lists '$nm' as an active antivirus product."
        } else {
            "[WARNING] Security Center lists '$nm' but reports it as NOT active (productState 0x$('{0:X}' -f $state)) -- a registered protection product that is switched off."
            $sev = Get-MaxSev $sev 'WARNING'
        }
    }
    if ($av.Count -eq 0) { '[INFO] Security Center lists no registered antivirus product.' }
} catch { $scOk = $false }
if (-not $scOk) {
    '[SKIPPED] root\SecurityCenter2 could not be queried -- registered security products NOT enumerated (this namespace is absent on Server editions).'
}

# ---- Sysmon ---------------------------------------------------------------
$sysmonSvc = $null
foreach ($n in @('Sysmon', 'Sysmon64')) {
    try { $s = Get-Service -Name $n -EA Stop; if ($s) { $sysmonSvc = $s; break } } catch {}
}
$sysmonDrv = $null
try { $sysmonDrv = Get-Service -Name 'SysmonDrv' -EA Stop } catch {}

if (-not $sysmonSvc -and -not $sysmonDrv) {
    '[INFO] Sysmon is not installed. It is free from Microsoft and records process creation with command lines and hashes, network connections, and image loads -- the evidence that makes an intrusion reconstructable after the fact. Windows does not record most of that by default. Not a fault; worth knowing when weighing a clean result.'
} else {
    $inspected++
    $running = ($sysmonSvc -and $sysmonSvc.Status -eq 'Running') -or ($sysmonDrv -and $sysmonDrv.Status -eq 'Running')
    if ($running) {
        '[OK] Sysmon is installed and running.'
    } else {
        "[WARNING] Sysmon is INSTALLED BUT NOT RUNNING -- the telemetry someone deliberately set up on this machine is not being collected (T1562.001)."
        $sev = Get-MaxSev $sev 'WARNING'
    }

    # Is a config actually loaded? Sysmon with the bare default logs very
    # little, so "installed" and "usefully configured" are different claims.
    $rules = $null
    try { $rules = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters' -Name 'Rules' -EA Stop).Rules } catch {}
    if ($rules -and $rules.Length -gt 0) {
        "[INFO] Sysmon has a rules configuration loaded ($($rules.Length) bytes). This check does not grade WHAT that config covers -- doing so needs 'sysmon -c', i.e. running the vendor binary, which this audit will not do on a machine under suspicion."
    } else {
        '[INFO] Sysmon appears to have no rules configuration loaded. The default configuration records very little; a curated config is what makes Sysmon useful.'
    }

    $log = $null
    try { $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -EA Stop } catch {}
    if ($log) {
        "[INFO] Sysmon operational log: $($log.RecordCount) record(s), $([math]::Round($log.MaximumSizeInBytes/1MB,1)) MB cap."
    }
}

# ---- Summary --------------------------------------------------------------
if ($found.Count -gt 0) {
    "[INFO] Endpoint telemetry beyond Defender: $($found -join ', ')."
} else {
    '[INFO] No third-party EDR agent was detected. Defender alone is the whole of this machine''s endpoint telemetry, so a clean result here rests on Defender being healthy and honest -- see the Defender checks above.'
}
"[INFO] $inspected security product/agent(s) inspected."

Write-Marker -Name 'edr' -Sev $sev
