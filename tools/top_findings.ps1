# top_findings.ps1 -- Prepend a TOP FINDINGS summary block to the audit report.
#
# Walks the report after all sections complete, collects every [CRITICAL]
# and [WARNING] finding, looks up an analyst-friendly "Why it matters"
# explanation, sorts by severity, and prepends a summary block right
# before Section 1 (after pre-flight INIT headers).
#
# Output looks like:
#
#   ====================================================================
#    TOP FINDINGS (highest severity first) -- review these first
#   ====================================================================
#
#    1. [CRITICAL] Section: [17/18] NATION-STATE THREAT INDICATORS
#       Finding: [CRITICAL] Non-default WMI EventFilter subscriptions present: 2
#       Why it matters: Non-default WMI persistence subscription. Survives
#         reboots without an EXE on disk -- stealthy, common in APT toolkits.
#
#    2. [WARNING] Section: [12/18] CREDENTIAL AND LSASS PROTECTION
#       Finding: [WARNING] LSASS PPL not configured
#       Why it matters: LSASS Protected Process Light is disabled or unset.
#         Without PPL, Mimikatz can dump cleartext credentials from LSASS.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File top_findings.ps1 -Report <path>

param(
    [Parameter(Mandatory=$true)]
    [string]$Report,
    [int]$MaxFindings = 10
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path -LiteralPath $Report)) { return }
$lines = Get-Content -LiteralPath $Report
if (-not $lines -or $lines.Count -eq 0) { return }

# Why-it-matters lookup table. Pattern -> explanation. Patterns are
# regex matched against the FULL finding line (case-insensitive).
# Add to this table as new findings are introduced.
$whyTable = [ordered]@{
    'LSASS PPL DISABLED|LSASS PPL not configured' = 'LSASS Protected Process Light is disabled or unset. Without PPL, Mimikatz can dump cleartext credentials directly from LSASS memory.'
    'WDigest ENABLED'      = 'WDigest plaintext credential caching is on. Attackers extract cleartext passwords from LSASS using documented techniques.'
    'NTLMv1 allowed'       = 'NTLMv1 is crackable in minutes via Responder + hashcat. Set LmCompatibilityLevel=5 to require NTLMv2.'
    'Firewall DISABLED'    = 'Windows Firewall is off, removing host-level network filtering. Lateral movement and inbound C2 become easier.'
    'SMBv1 ENABLED'        = 'SMBv1 is the protocol exploited by EternalBlue / WannaCry. It must be disabled in 2024+.'
    'UAC DISABLED'         = 'No prompt before privilege elevation. Any malware running as user gets silent admin via auto-elevating processes.'
    'portproxy tunnel rules are ACTIVE' = 'netsh portproxy rules are an active Volt Typhoon TTP for hiding C2 traffic behind the local interface.'
    'WMI EventFilter|WMI permanent EventFilter|EventFilter subscriptions present' = 'Non-default WMI permanent subscription. Survives reboots without an EXE on disk -- stealthy, common in APT toolkits (APT29, FIN8).'
    'ActiveScript.*Consumer' = 'WMI ActiveScript consumer hosts an inline VBScript/JScript payload. Even stealthier than CommandLineEventConsumer.'
    'Cobalt Strike named pipes detected' = 'Active Cobalt Strike C2 beacon. Treat as live compromise -- isolate the host immediately.'
    'Sliver|Brute Ratel|Havoc'           = 'Next-gen post-exploitation C2 framework named pipe detected. Treat as live compromise.'
    'Suspicious process paths|Suspicious paths' = 'Process running from \Temp\, \AppData\, \Downloads\, \Public\, or \Recycle -- attacker-favored staging directory.'
    'IFEO Debugger hijack' = 'Image File Execution Options Debugger redirect = accessibility-binary hijack (T1546.008). SYSTEM shell on login screen via Shift x5.'
    'testsigning.*[Yy]es|Test.Signing.*[Ee]nabled' = 'testsigning=yes allows unsigned kernel driver loads. Often used by BYOVD (Bring Your Own Vulnerable Driver) adversaries.'
    'Service .* failed Authenticode'    = 'Service binary failed Authenticode gating. Unsigned / unexpected-signer / bad-path services are common T1543.003 persistence indicators.'
    'BYOVD'                = 'Known vulnerable driver present on disk. Attackers load these to disable EDR from kernel mode.'
    'Security event log was CLEARED|System event log was CLEARED' = 'Event log clearing (1102/104) is a textbook anti-forensics move. Treat as evidence of recent attacker activity.'
    'COM CLSID overrides|COM Object Hijacking' = 'HKCU CLSID InprocServer32 overrides are a T1546.015 persistence technique. Often paired with DLL search-order hijacking.'
    'flagged by:' = 'VirusTotal flagged this IP / file across multiple engines. Cross-reference with the per-IP local process owner above.'
    'PendingFileRenameOperations' = 'A pending file rename is queued for next reboot -- could be malware completing install or a legit installer mid-flow. Verify the queued file.'
    'WindowsUpdate requires a reboot' = 'Windows Update is pending. Run the audit after reboot for a complete picture.'
    'AppInit_DLLs set'    = 'AppInit_DLLs causes a DLL to be injected into every GUI process. Legacy persistence technique; should be empty on modern Windows.'
    'Sticky Keys'          = 'Sticky Keys shortcut at the login screen is a remote unauthenticated trigger for sethc.exe (which attackers commonly hijack to launch cmd.exe as SYSTEM).'
    'New root certificate'  = 'A new root CA cert was installed in the last 90 days. DPRK Ruby Sleet drops fake roots to MITM TLS-secured channels.'
    'KrbRelayUp|Kerberos RC4' = 'Kerberos misconfig that enables relay / ticket-forging attacks (Forest Blizzard / NTLM relay).'
}

function Get-WhyMatters {
    param([string]$Line)
    foreach ($pat in $whyTable.Keys) {
        if ($Line -match $pat) { return $whyTable[$pat] }
    }
    return $null
}

# Walk the report and collect findings with their parent section context
$currentSection = '(pre-section)'
$findings = New-Object System.Collections.Generic.List[object]
foreach ($L in $lines) {
    if ($L -match '^---\s(.+?)\s---\s*$') {
        $currentSection = $matches[1]
        continue
    }
    if ($L -match '^\s*\[(CRITICAL|WARNING)\]') {
        $sev = $matches[1]
        $findings.Add([pscustomobject]@{
            Severity = $sev
            Section  = $currentSection
            Line     = $L.Trim()
            Why      = (Get-WhyMatters -Line $L)
        }) | Out-Null
    }
}

# Build TOP FINDINGS block (always emitted, even for clean reports)
$block = New-Object System.Collections.Generic.List[string]
$block.Add('====================================================================')

if ($findings.Count -eq 0) {
    $block.Add(' TOP FINDINGS: CLEAN')
    $block.Add('====================================================================')
    $block.Add('')
    $block.Add(' No CRITICAL or WARNING findings detected.')
    $block.Add(' System security posture is good. Recommendation: re-run monthly.')
    $block.Add('')
    $block.Add('====================================================================')
    $block.Add('')
} else {
    $block.Add(' TOP FINDINGS (highest severity first) -- review these first')
    $block.Add('====================================================================')
    $block.Add('')
    $sevOrder = @{ 'CRITICAL' = 0; 'WARNING' = 1 }
    $top = $findings | Sort-Object { $sevOrder[$_.Severity] } | Select-Object -First $MaxFindings
    $rank = 0
    foreach ($f in $top) {
        $rank++
        $shortLine = $f.Line
        if ($shortLine.Length -gt 160) { $shortLine = $shortLine.Substring(0,157) + '...' }
        $block.Add(" $rank. [$($f.Severity)] Section: $($f.Section)")
        $block.Add("    Finding: $shortLine")
        if ($f.Why) {
            # Wrap "Why" text at ~75 chars per line for readability
            $why = $f.Why
            $wrapped = New-Object System.Collections.Generic.List[string]
            while ($why.Length -gt 75) {
                $split = $why.LastIndexOf(' ', 75)
                if ($split -lt 1) { $split = 75 }
                $wrapped.Add($why.Substring(0, $split))
                $why = $why.Substring($split).TrimStart()
            }
            if ($why.Length -gt 0) { $wrapped.Add($why) }
            $first = $true
            foreach ($w in $wrapped) {
                if ($first) { $block.Add("    Why it matters: $w"); $first = $false }
                else        { $block.Add("                    $w") }
            }
        }
        $block.Add('')
    }
    if ($findings.Count -gt $MaxFindings) {
        $block.Add(" ...$($findings.Count - $MaxFindings) more finding(s) below. Full detail in the per-section body.")
        $block.Add('')
    }
    $block.Add('====================================================================')
    $block.Add('')
}

# Find insertion point: right before the [1/18] section header.
$prependIndex = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^={5,}\s*$' -and $i + 1 -lt $lines.Count -and $lines[$i + 1] -match '^\s*\[1/18\]') {
        $prependIndex = $i
        break
    }
}

if ($prependIndex -eq 0) {
    # Fallback: append at the END if we can't find Section 1
    $newReport = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) { $newReport.Add($l) }
    $newReport.Add('')
    foreach ($l in $block) { $newReport.Add($l) }
} else {
    $newReport = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $prependIndex; $i++) { $newReport.Add($lines[$i]) }
    foreach ($l in $block) { $newReport.Add($l) }
    for ($i = $prependIndex; $i -lt $lines.Count; $i++) { $newReport.Add($lines[$i]) }
}

[System.IO.File]::WriteAllLines($Report, $newReport.ToArray(), (New-Object System.Text.UTF8Encoding $false))
