# stalkerware_check.ps1 -- detect covert monitoring of the person using this PC.
# Invoked from Section 10.
#
# WHY THIS EXISTS: every other check in this audit models an attacker who wants
# the MACHINE -- ransomware, C2, credential theft, nation-state persistence. This
# one models an attacker who wants the PERSON: an abusive partner, family member,
# or ex with physical access and the password. That threat looks completely
# different. There is usually no malware and no exploit. The tooling is often
# commercial, digitally signed, and working exactly as designed -- which is
# precisely why the rest of the audit walks straight past it.
#
# The report already refers at-risk users to the Coalition Against Stalkerware.
# Until this module existed, the tool pointed people toward help for a threat it
# made no attempt to detect.
#
# WHAT IS CHECKED
#   Hidden accounts (T1564.002)  SpecialAccounts\UserList entries set to 0 hide
#                                an account from the sign-in screen and from
#                                Settings. Some legitimate software does this for
#                                service accounts, so it is reported for review
#                                rather than called malicious -- but an account
#                                hidden on a personal machine deserves an answer.
#   Camera / microphone / location consent (T1125 / T1123 / T1430)
#                                Which applications hold access, and when each
#                                last used it. This is the single most useful
#                                thing a person being monitored can see.
#   Silent RDP shadowing (T1113) The Shadow policy values 2 and 4 permit another
#                                user to view or control this session WITHOUT
#                                prompting for consent. There is no ordinary
#                                home reason for that.
#   Consumer monitoring products Known "parental control" / "employee
#                                monitoring" / spouseware families by process,
#                                service, install entry and scheduled task.
#                                Deliberately separate from the enterprise RMM
#                                list Section 4 already covers.
#
# FALSE POSITIVES AND HOW THIS DIFFERS FROM THE REST OF THE AUDIT: a webcam
# permission is not evidence of anything -- Zoom, Teams, Discord and every
# browser legitimately hold one. Producing a verdict here would be dishonest, so
# the consent inventory is presented as INFORMATION the user reviews against
# their own knowledge of what they installed. Only genuinely anomalous states are
# raised: an unsigned or staging-path binary holding camera/mic access, a hidden
# account, silent shadowing, or a known monitoring product.
#
# TONE MATTERS HERE. A person reading this may be in danger from someone with
# physical access to this machine. Monitoring software is frequently INSTALLED BY
# A PARENT OR EMPLOYER LEGITIMATELY, so findings say "present" and ask whether
# the user knows about it -- they never accuse. And the audit's READ THIS FIRST
# block already warns that removing this software can alert whoever installed it,
# and that evidence should be preserved first; findings here point back to that.
#
# MARKER: severity word to $env:TEMP\dz_stalkerware.txt; caller raises via
# :dz_finding. No marker when nothing anomalous is found.
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [int]$MaxList = 30
)

$ErrorActionPreference = 'Continue'

# PowerShell adds these note-properties to every Get-ItemProperty result; they
# are not registry values. Matched by EXACT name -- a '^PS' prefix match would
# also swallow real values whose names start with "PS".
$psNoteProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write here turns
    # a real finding into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine write failure print instead of vanishing --
    # an -EA SilentlyContinue on this write cost a field test its finding.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}
function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

$sev = 'OK'
$badPathRx = '\\Temp\\|\\Downloads\\|\\Public\\|\\ProgramData\\update'

# Consumer monitoring / "spouseware" families. Distinct from the enterprise RMM
# list in Section 4: these are sold to individuals to watch other individuals.
# Matched as substrings against process, service, install and task names.
$monitorNames = @(
    'mspy', 'flexispy', 'cocospy', 'spyzie', 'hoverwatch', 'thetruthspy',
    'ikeymonitor', 'spyera', 'mobistealth', 'highster', 'webwatcher',
    'spyrix', 'refog', 'actualspy', 'ardamax', 'perfectkeylogger',
    'elitekeylogger', 'realtime-spy', 'spytech', 'netvizor', 'spyagent',
    'kidlogger', 'micro keylogger', 'blurspy', 'xnspy', 'clevguard',
    'kidsguard', 'umobix', 'eyezy', 'hellospy', 'snoopza', 'talklog',
    'activtrak', 'teramind', 'veriato', 'interguard', 'workexaminer',
    'staffcop', 'kickidler', 'hubstaff', 'timedoctor', 'controlio'
)

function Test-MonitorName {
    param([string]$Text)
    if (-not $Text) { return $null }
    $t = $Text.ToLower()
    foreach ($n in $monitorNames) { if ($t -like ("*{0}*" -f $n)) { return $n } }
    return $null
}

'--- [T1564.002/T1125/T1123/T1113] Covert-monitoring check (is someone watching this person?) ---'

# ---- 1. Accounts hidden from the sign-in screen (T1564.002) ---------------
$hidden = @()
$hlKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
try {
    if (Test-Path $hlKey) {
        foreach ($p in (Get-ItemProperty -Path $hlKey -EA Stop).PSObject.Properties) {
            # Exact-name skip, not a '^PS' prefix match (see
            # persistence_eval.ps1). This one mattered most: a hidden account
            # named "psadmin" was hidden from the sign-in screen AND from this
            # check, which is precisely the account someone monitoring a
            # partner or employee would create.
            if ($psNoteProps -contains $p.Name) { continue }
            # -as [int], not a hard [int] cast. The cast THROWS on a REG_SZ or
            # REG_BINARY value, and the try/catch wraps this whole loop -- so a
            # single junk entry aborted the entire scan and the code below then
            # printed "[OK] No accounts are hidden from the sign-in screen" on a
            # machine that had one. Anything non-numeric simply is not a
            # hide-flag, so skip that value and keep going.
            $flag = $p.Value -as [int]
            if ($null -ne $flag -and $flag -eq 0) { $hidden += $p.Name }
        }
    }
} catch {}
if ($hidden.Count -gt 0) {
    "[WARNING] $($hidden.Count) account(s) are HIDDEN from the sign-in screen and from Settings (T1564.002): $($hidden -join ', ')"
    '[WARNING] Some legitimate software hides its own service accounts this way. If you do not recognise one of these, someone may have created an account to access this PC without appearing on the login screen.'
    $sev = Get-MaxSev $sev 'WARNING'
} else {
    '[OK] No accounts are hidden from the sign-in screen.'
}

# ---- 2. Silent RDP shadowing (T1113) --------------------------------------
$shadow = $null
try { $shadow = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'Shadow' -EA SilentlyContinue).Shadow } catch {}
if ($null -ne $shadow -and ($shadow -eq 2 -or $shadow -eq 4)) {
    $what = 'view'
    if ($shadow -eq 2) { $what = 'view AND control' }
    "[CRITICAL] Remote session shadowing is set to $what this session WITHOUT asking permission (Shadow=$shadow, T1113)."
    '[CRITICAL] Anyone who can reach this PC remotely could watch what you do with no prompt and no visible indication. There is no ordinary reason for this on a personal computer.'
    $sev = Get-MaxSev $sev 'CRITICAL'
} elseif ($null -ne $shadow) {
    "[OK] Remote session shadowing requires the user's permission (Shadow=$shadow)."
} else {
    '[OK] Remote session shadowing is not configured (default: permission required).'
}

# ---- 3. Camera / microphone / location access -----------------------------
# Presented as an inventory, NOT a verdict: an app holding a webcam permission
# is completely normal. Only an unsigned or staging-path binary is raised.
$capRoots = @(
    @{ Hive = 'HKCU:'; Label = 'this user' },
    @{ Hive = 'HKLM:'; Label = 'all users' }
)
$caps = @('webcam', 'microphone', 'location')
$grants = @()
foreach ($r in $capRoots) {
    foreach ($cap in $caps) {
        $base = "$($r.Hive)\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$cap"
        foreach ($sub in @($base, "$base\NonPackaged")) {
            if (-not (Test-Path $sub)) { continue }
            try {
                foreach ($k in (Get-ChildItem -LiteralPath $sub -EA SilentlyContinue)) {
                    $val = $null
                    try { $val = (Get-ItemProperty -LiteralPath $k.PSPath -Name 'Value' -EA SilentlyContinue).Value } catch {}
                    if ($val -ne 'Allow') { continue }
                    $last = $null
                    try {
                        $lu = (Get-ItemProperty -LiteralPath $k.PSPath -Name 'LastUsedTimeStop' -EA SilentlyContinue).LastUsedTimeStop
                        if ($lu -and $lu -gt 0) { $last = [datetime]::FromFileTime($lu) }
                    } catch {}
                    # NonPackaged keys encode the exe path with # instead of \.
                    $app = $k.PSChildName -replace '#', '\'
                    $grants += New-Object PSObject -Property @{ Cap = $cap; App = $app; Scope = $r.Label; Last = $last }
                }
            } catch {}
        }
    }
}
if ($grants.Count -gt 0) {
    "[INFO] $($grants.Count) application permission(s) to camera, microphone or location are currently ALLOWED."
    '[INFO] This is normal -- video calling, browsers and voice apps all need these. Read the list against what YOU installed; anything you do not recognise is worth asking about.'
    $shown = 0
    foreach ($g in ($grants | Sort-Object Cap, App)) {
        $shown++
        if ($shown -gt $MaxList) { continue }
        $when = 'never recorded'
        if ($g.Last) { $when = $g.Last.ToString('yyyy-MM-dd HH:mm') }
        "  [$($g.Cap)] $($g.App)   (last used: $when, scope: $($g.Scope))"
    }
    if ($grants.Count -gt $MaxList) { "  ...and $($grants.Count - $MaxList) more not listed (cap $MaxList)." }
    # Raise ONLY on a genuinely anomalous holder: an unsigned binary or one
    # running from a staging path with access to camera or microphone.
    foreach ($g in $grants) {
        if ($g.App -notmatch '\\') { continue }
        $exe = $g.App
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { continue }
        $bad = ($exe -match $badPathRx)
        $unsigned = $false
        try {
            $sig = Get-AuthenticodeSignature -FilePath $exe -EA Stop
            $unsigned = (-not $sig -or $sig.Status -ne 'Valid')
        } catch { $unsigned = $true }
        if ($bad -or $unsigned) {
            $why = 'is not validly signed'
            if ($bad) { $why = 'runs from a temporary/staging folder' }
            "[WARNING] An application that $why holds $($g.Cap) access: $exe"
            $sev = Get-MaxSev $sev 'WARNING'
        }
    }
} else {
    '[OK] No applications currently hold camera, microphone or location permission.'
}

# ---- 4. Known consumer monitoring products --------------------------------
$hits = @()
try {
    foreach ($p in (Get-Process -EA SilentlyContinue)) {
        $m = Test-MonitorName $p.ProcessName
        if ($m) { $hits += "running process: $($p.ProcessName)" }
    }
} catch {}
try {
    foreach ($s in (Get-CimInstance Win32_Service -EA SilentlyContinue)) {
        $m = Test-MonitorName ([string]$s.Name + ' ' + [string]$s.DisplayName)
        if ($m) { $hits += "service: $($s.Name) ($($s.DisplayName))" }
    }
} catch {}
foreach ($uk in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) {
    if (-not (Test-Path $uk)) { continue }
    try {
        foreach ($k in (Get-ChildItem -LiteralPath $uk -EA SilentlyContinue)) {
            $dn = $null
            try { $dn = (Get-ItemProperty -LiteralPath $k.PSPath -Name 'DisplayName' -EA SilentlyContinue).DisplayName } catch {}
            $m = Test-MonitorName $dn
            if ($m) { $hits += "installed program: $dn" }
        }
    } catch {}
}
try {
    foreach ($t in (Get-ScheduledTask -EA SilentlyContinue)) {
        $m = Test-MonitorName ([string]$t.TaskName)
        if ($m) { $hits += "scheduled task: $($t.TaskPath)$($t.TaskName)" }
    }
} catch {}

$hits = @($hits | Sort-Object -Unique)
if ($hits.Count -gt 0) {
    '[WARNING] Software commonly sold for monitoring another person is present on this PC:'
    foreach ($h in ($hits | Select-Object -First $MaxList)) { "  $h" }
    if ($hits.Count -gt $MaxList) { "  ...and $($hits.Count - $MaxList) more." }
    '[WARNING] These products are also sold legitimately for parental control and workplace monitoring, so this is NOT proof of wrongdoing -- but if you did not install it and were not told it was here, treat it seriously.'
    '[WARNING] Before removing it, read the READ THIS FIRST section at the top of this report: removing it can alert whoever installed it, and you may want to preserve evidence first.'
    $sev = Get-MaxSev $sev 'WARNING'
} else {
    '[OK] No known consumer monitoring/spouseware products detected.'
}

Write-Marker -Name 'stalkerware' -Sev $sev
