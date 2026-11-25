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
# A service Get-Service cannot find is asked of the service manager itself
# (sc.exe query): ServiceController answers "does not exist" for ANY failure
# (CLAUDE.md, the ZTHelper case), so a service whose DACL hides it from this
# token would read as "not installed". Exit 1060 is the SCM's own "does not
# exist"; anything else is a service this token could not check. On a
# standard-user token that is a counted deferral (dz_edr_deferred.txt);
# elevated it is a raised gap (dz_edr_gap.txt).
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    # 1/0 from the caller, or -1: ask the token.
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write here turns
    # a real WARNING into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine write failure print instead of vanishing --
    # an -EA SilentlyContinue on this write cost a field test its finding.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}
# PURE. What an unreadable root\SecurityCenter2 means, by product type
# (1 workstation, 2 domain controller, 3 server; $null unread).
function Get-SecurityCenterGap {
    param($ProductType, [string]$Err = '')
    if ($null -ne $ProductType -and [int]$ProductType -ne 1) {
        return @{ Gap = $false; Line = '[INFO] Security Center does not exist on Server editions (root\SecurityCenter2 is a client feature) -- registered security products were not listed from it.' }
    }
    return @{ Gap = $true; Line = ('[WARNING] Security Center check NOT performed -- root\SecurityCenter2 could not be queried' + $(if ($Err) { ' (' + $Err + ')' } else { '' }) + ', so a registered antivirus that is switched off would go unseen (T1562.001).') }
}

function Test-MdeOnboarded {
    # OnboardingState = 1 under this key is how Defender for Endpoint records a
    # completed enrollment; the key is absent on machines never onboarded.
    try {
        return ((Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OnboardingState' -EA Stop).OnboardingState -eq 1)
    } catch { return $false }
}
# PURE. What the service manager's own answer to `sc.exe query <name>` means:
# 1060 (ERROR_SERVICE_DOES_NOT_EXIST) is the only "not installed"; any other
# code (5 = a DACL that hides it from this token, or no code at all) is a
# service this token could not check -- never "not installed".
function Get-ScmAbsence {
    param($Code)
    if ($null -ne $Code -and [int]$Code -eq 1060) { return 'absent' }
    return 'unprobed'
}
function Get-ScmCode {
    param([string]$Name)
    try { $null = & sc.exe query $Name 2>&1; return $LASTEXITCODE } catch { return -1 }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok) if ($Ok) { "[OK]   $N" } else { "[FAIL] $N"; $script:fails++ } }
    T 'the service manager''s 1060 is "not installed"' ((Get-ScmAbsence 1060) -eq 'absent')
    T 'access denied (5) is a service this token could not check, never "not installed"' ((Get-ScmAbsence 5) -eq 'unprobed')
    T 'no exit code at all is unprobed, never "not installed"' ((Get-ScmAbsence $null) -eq 'unprobed')
    T 'a failed sc.exe launch (-1) is unprobed' ((Get-ScmAbsence -1) -eq 'unprobed')
    T 'Security Center unreadable on client Windows is a raised gap' ((Get-SecurityCenterGap -ProductType 1 -Err 'x').Gap)
    T 'Security Center unreadable with the product type unread is a raised gap' ((Get-SecurityCenterGap -ProductType $null).Gap)
    T 'a Server edition (a CI runner) has no Security Center: said, never a gap' (-not (Get-SecurityCenterGap -ProductType 3).Gap -and (Get-SecurityCenterGap -ProductType 3).Line -match '^\[INFO\] Security Center does not exist on Server editions')
    if ($fails) { "[FAIL] edr_presence self-test: $fails case(s) failed"; exit 1 }
    '[OK] edr_presence self-test: only the service manager''s own 1060 reads as not installed.'
    exit 0
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

if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$found = @()
$unprobed = New-Object System.Collections.ArrayList
foreach ($svcName in $edrServices.Keys) {
    $svc = $null
    try { $svc = Get-Service -Name $svcName -EA Stop } catch {
        # Ask the SCM: only its own 1060 means the service is not there.
        $code = Get-ScmCode $svcName
        if ((Get-ScmAbsence $code) -ne 'absent') { [void]$unprobed.Add(('{0} ({1}, sc.exe exit {2})' -f $edrServices[$svcName], $svcName, $code)) }
        continue
    }
    if (-not $svc) { continue }
    $inspected++
    $label = $edrServices[$svcName]
    if ($svc.Status -eq 'Running') {
        $found += $label
        "[OK] $label is installed and RUNNING (service '$svcName')."
    } elseif ($svcName -eq 'Sense' -and -not (Test-MdeOnboarded)) {
        # Windows ships the Defender for Endpoint sensor service inert on every
        # machine never onboarded to MDE, so a stopped 'Sense' is the NORM on
        # consumer PCs, not tampering -- a field test on a real home PC hit
        # exactly this false positive. Stopped AFTER onboarding is the finding.
        "[INFO] The Microsoft Defender for Endpoint sensor service ('Sense') exists but this machine has never been onboarded to Defender for Endpoint, so it has never run -- that is how Windows ships. Not a fault."
    } else {
        # THIS is the finding: installed means someone chose to protect this
        # machine; not running means that protection is not happening now.
        $found += "$label (present but STOPPED)"
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
} catch { $scOk = $false; $scErr = (([string]$_.Exception.Message) -replace '\s+', ' ').Trim() }
if (-not $scOk) {
    # Server editions have no Security Center at all (ProductType 2 or 3):
    # said, not raised -- the audit refuses Server except under -dev, which
    # is how CI runs on Windows Server runners. On client Windows (1) the
    # namespace always exists and a standard user can read it, so failing to
    # ask it is a raised gap (2026-11-25): an antivirus registered but
    # switched off would otherwise go unseen. A product type that cannot be
    # read is a client until shown otherwise.
    $ptype = $null
    try { $ptype = [int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType } catch {}
    $scv = Get-SecurityCenterGap -ProductType $ptype -Err $scErr
    $scv.Line
    if ($scv.Gap) { Write-Marker -Name 'edr_gap' -Sev 'WARNING' }
}

# ---- Sysmon ---------------------------------------------------------------
# The same rule as the agents above: a name Get-Service cannot find is asked
# of the service manager, and only its 1060 means "not installed". A Sysmon
# whose service DACL hides it from this token used to read "not installed".
$sysmonSvc = $null
$sysmonDrv = $null
$sysmonUnprobed = 0
foreach ($n in @('Sysmon', 'Sysmon64', 'SysmonDrv')) {
    $s = $null
    try { $s = Get-Service -Name $n -EA Stop } catch {
        $code = Get-ScmCode $n
        if ((Get-ScmAbsence $code) -ne 'absent') { [void]$unprobed.Add(('Sysmon ({0}, sc.exe exit {1})' -f $n, $code)); $sysmonUnprobed++ }
        continue
    }
    if ($n -eq 'SysmonDrv') { $sysmonDrv = $s } elseif (-not $sysmonSvc) { $sysmonSvc = $s }
}

if (-not $sysmonSvc -and -not $sysmonDrv -and $sysmonUnprobed -gt 0) {
    '[INFO] Whether Sysmon is installed could not be determined: its service could not be checked from here (see the line below).'
} elseif (-not $sysmonSvc -and -not $sysmonDrv) {
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
if ($unprobed.Count -gt 0) {
    $names = (@($unprobed | Select-Object -First 5) -join '; ') + $(if ($unprobed.Count -gt 5) { ('; and ' + ($unprobed.Count - 5) + ' more') } else { '' })
    if ($Elevated -ne 1) {
        ('[DEFERRED - ADMIN REQUIRED] ' + $unprobed.Count + ' endpoint-agent service(s) could not be checked from this standard-user token: ' + $names + '. An audit run as administrator checks them.')
        Write-Marker -Name 'edr_deferred' -Sev ([string]$unprobed.Count)
    } else {
        ('[WARNING] Endpoint-agent check NOT performed in full -- ' + $unprobed.Count + ' service(s) could not be queried: ' + $names + ', so an agent installed but stopped would go unseen (T1562.001).')
        Write-Marker -Name 'edr_gap' -Sev 'WARNING'
    }
}
if ($found.Count -gt 0) {
    "[INFO] Endpoint telemetry beyond Defender: $($found -join ', ')."
} elseif ($unprobed.Count -gt 0) {
    '[INFO] No third-party EDR agent was detected among the services that could be checked (see the line above).'
} else {
    '[INFO] No third-party EDR agent was detected. Defender alone is the whole of this machine''s endpoint telemetry, so a clean result here rests on Defender being healthy and honest -- see the Defender checks above.'
}
"[INFO] $inspected security product/agent(s) inspected."

Write-Marker -Name 'edr' -Sev $sev
# Written last: the caller raises "produced no verdict" when it is absent.
Write-Marker -Name 'edr_done' -Sev 'done'
