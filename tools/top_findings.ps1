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
# Detect line-ending style from raw bytes so we can preserve it on write.
# Get-Content strips \r, so we can't infer CRLF vs LF from the parsed lines.
$rawBytes = [System.IO.File]::ReadAllBytes($Report)
$rawText = [System.Text.Encoding]::UTF8.GetString($rawBytes)
$useCRLF = ($rawText -match "`r`n")
$nl = if ($useCRLF) { "`r`n" } else { "`n" }
$lines = $rawText -split "`r?`n"
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
    '\bflagged by:\s*\d+\s*engine' = 'VirusTotal flagged this IP / file across multiple engines. Cross-reference with the per-IP local process owner above.'
    'PendingFileRenameOperations' = 'A pending file rename is queued for next reboot -- could be malware completing install or a legit installer mid-flow. Verify the queued file.'
    'WindowsUpdate requires a reboot' = 'Windows Update is pending. Run the audit after reboot for a complete picture.'
    'AppInit_DLLs set'    = 'AppInit_DLLs causes a DLL to be injected into every GUI process. Legacy persistence technique; should be empty on modern Windows.'
    'Sticky Keys'          = 'Sticky Keys shortcut at the login screen is a remote unauthenticated trigger for sethc.exe (which attackers commonly hijack to launch cmd.exe as SYSTEM).'
    'New root certificate'  = 'A new root CA cert was installed in the last 90 days. DPRK Ruby Sleet drops fake roots to MITM TLS-secured channels.'
    'KrbRelayUp|Kerberos RC4' = 'Kerberos misconfig that enables relay / ticket-forging attacks (Forest Blizzard / NTLM relay).'
    'AutoRun.*Default|NoDriveTypeAutoRun'  = 'AutoRun for removable media is not restricted to the safe default. USB worms (Lazarus DTrack, older banking trojans) abuse this.'
    'BitLocker.*[Dd]isabled|BitLocker.*OFF' = 'Disk encryption is off. Lost / stolen device exposes all data, and offline attacks against the OS are trivial.'
    '[Ss]ecure ?Boot.*[Dd]isabled|SecureBoot.*OFF' = 'Secure Boot is disabled. Bootkits and pre-OS rootkits can persist below Windows defenses.'
    'RDP enabled WITHOUT NLA|Network Level Authentication.*disabled' = 'RDP without NLA exposes the pre-auth attack surface to network-reachable adversaries (BlueKeep family).'
    '[Aa]udit [Pp]olicy.*[Mm]issing|advaudit.*not [Ss]et' = 'Critical audit subcategory is not logging. Detection-blind for this event class going forward.'
    'USB ?Storage.*[Ee]nabled|RemovableStorage' = 'USB mass-storage class is enabled. Data-exfil and worm-spread risk.'
    'AlwaysInstallElevated' = 'AlwaysInstallElevated is set -- any user-launched MSI runs as SYSTEM. T1548.002 privilege escalation.'
    'Defender.*[Dd]isabled|RealTimeProtection.*[Ff]alse|MpPreference.*[Dd]isabled' = 'Microsoft Defender real-time protection is off. Hosts running without AV/EDR are far more likely to be compromised.'
    'PSReadLine .* history|ConsoleHost_history' = 'PowerShell command history file is readable. Often contains plaintext credentials accidentally typed into scripts.'
    'WinRM RUNNING' = 'WinRM is listening. Combined with low-priv credentials, enables lateral movement via PSRemoting and PowerShell over WinRM.'
    'sshd.*[Rr]unning|OpenSSH Server.*RUNNING' = 'OpenSSH Server is running on Windows. Verify authorized_keys lists are legit; check sshd_config for password-auth and root-login policy.'
    'cert-(invalid|expired|revoked)' = 'Authenticode signing cert failed validation. Stolen-cert malware (3CX, CCleaner) is the canonical scenario.'
    'unsigned bad-path|trusted-signer bad-path|unexpected-signer bad-path' = 'Service binary in an adversary-favored path (\Temp\, \AppData\, \Downloads\, \Public\). Investigate service install timestamp + parent process.'
}

function Get-WhyMatters {
    param([string]$Line)
    foreach ($pat in $whyTable.Keys) {
        if ($Line -match $pat) { return $whyTable[$pat] }
    }
    return $null
}

# Walk the report and collect findings with their parent section context.
# Track BOTH the most recent main section header (`[N/18] TITLE` inside a
# `=====` box) and the most recent sub-section header (`--- Title ---`).
# Findings are tagged with `MainSection > SubSection` so the analyst sees
# both levels of context in the summary.
$currentMain = '(pre-section)'
$currentSub = $null
$findings = New-Object System.Collections.Generic.List[object]
$skipped = 0
foreach ($L in $lines) {
    # Main section: a bracketed [N/18] or [INIT N/14] inside a ===== box
    if ($L -match '^\s*\[(\d+/18|INIT \d+/14)\]\s+(.+?)\s*$') {
        $currentMain = "[$($matches[1])] $($matches[2])"
        $currentSub = $null  # reset sub when entering a new main section
        continue
    }
    # Sub-section: --- Title ---
    if ($L -match '^---\s(.+?)\s---\s*$') {
        $currentSub = $matches[1]
        continue
    }
    if ($L -match '^\s*\[SKIPPED\]') {
        $skipped++
        continue
    }
    if ($L -match '^\s*\[(CRITICAL|WARNING)\]') {
        $sev = $matches[1]
        $sect = if ($currentSub) { "$currentMain > $currentSub" } else { $currentMain }
        $findings.Add([pscustomobject]@{
            Severity = $sev
            Section  = $sect
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
    $fallbackWhy = 'No specific analyst note mapped for this finding. Consult the full section body below for context.'
    foreach ($f in $top) {
        $rank++
        # Default truncation cap of 220 chars to keep the summary block scannable.
        # Skip truncation entirely for findings that contain a backslash -- these
        # are Windows file paths or registry paths, and cutting them mid-string
        # destroys the most actionable information the analyst needs (the exact
        # path to the artifact). HTML rendering wraps long lines via the
        # word-break CSS on `pre` and the severity divs, so a long path stays
        # visible without horizontal scrolling.
        $shortLine = $f.Line
        $hasPath = ($shortLine -match '\\')
        if (-not $hasPath -and $shortLine.Length -gt 220) {
            $shortLine = $shortLine.Substring(0,217) + '...'
        }
        $block.Add(" $rank. [$($f.Severity)] Section: $($f.Section)")
        $block.Add("    Finding: $shortLine")
        # Why-It-Matters text. Use the mapped explanation when present, otherwise
        # emit a generic fallback so the analyst is never left wondering whether
        # the absence of a note means "low severity" or "unmapped pattern".
        $why = if ($f.Why) { $f.Why } else { $fallbackWhy }
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
        $block.Add('')
    }
    if ($findings.Count -gt $MaxFindings) {
        $block.Add(" ...$($findings.Count - $MaxFindings) more finding(s) below. Full detail in the per-section body.")
        $block.Add('')
    }
    $block.Add('====================================================================')
    $block.Add('')
}

# Coverage transparency: checks that could not run announce themselves with
# [SKIPPED] lines. Surface the count here so a "CLEAN" verdict is never read
# as full coverage when parts of the audit silently could not execute.
if ($skipped -gt 0) {
    $block.Add(" COVERAGE NOTE: $skipped check(s) reported [SKIPPED] and were NOT performed.")
    $block.Add(' The verdict above covers only the checks that ran. Search the report')
    $block.Add(' for [SKIPPED] to see which checks were missed and why.')
    $block.Add('')
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

# Write with preserved line endings (CRLF on Windows-generated reports).
$bytes = [System.Text.Encoding]::UTF8.GetBytes(($newReport -join $nl) + $nl)
[System.IO.File]::WriteAllBytes($Report, $bytes)
