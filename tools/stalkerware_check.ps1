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
    [int]$MaxList = 30,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# PowerShell adds these note-properties to every Get-ItemProperty result; they
# are not registry values. Matched by EXACT name -- a '^PS' prefix match would
# also swallow real values whose names start with "PS".
$script:PsNoteProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

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
$badPathRx = '\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\ProgramData\\update'

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


# ---------------------------------------------------------------------------
# The two grading rules of this check, as PURE functions.
#
# Every input is a plain value -- no registry, no CIM -- so both are
# exercisable by -SelfTest on any platform. This check had no seam and no
# self-test at all, which for the one check written for someone who may be in
# danger is the wrong place for that gap to be: a false accusation and a false
# all-clear are both serious here, and neither direction was tested.
# ---------------------------------------------------------------------------

function Get-HiddenAccountVerdict {
    # $Values is the raw name -> value map from the UserList key, PowerShell's
    # note-properties INCLUDED: filtering them is part of the rule, not part of
    # reading the registry, and the self-test has to be able to reach it.
    param([hashtable]$Values)
    $r = @{ Lines = @(); Sev = 'OK'; Hidden = @() }
    $hidden = @()
    foreach ($name in @($Values.Keys)) {
        # EXACT-name skip, never a '^PS' prefix match. A hidden account named
        # "psadmin" was hidden from the sign-in screen AND from this check --
        # precisely the account someone monitoring a partner would create.
        if ($script:PsNoteProps -contains $name) { continue }
        # -as [int], not a hard [int] cast. Historically the cast THREW on a
        # REG_SZ or REG_BINARY value and the caller's try/catch wrapped the
        # whole loop, so one junk entry aborted the scan and the tool printed
        # "[OK] No accounts are hidden" on a machine that had one. That
        # try/catch is gone, and under $ErrorActionPreference='Continue' the
        # cast no longer unwinds the loop -- so the ABORT is now prevented
        # structurally, and a self-test case on the cast style alone cannot
        # fail. What the hard cast still does is write an error record, and
        # the caller redirects stderr into the report (2>&1), so it would put
        # a raw .NET conversion error in front of the reader. That is what
        # the self-test asserts on.
        # NOT `-as [int]` on its own: PowerShell converts an EMPTY STRING to
        # 0, so an empty REG_SZ under UserList was reported as a hidden
        # account -- a false accusation, in the check written for someone who
        # may be in danger. Found by a self-test case that fed several junk
        # shapes at once; the earlier case used only 'n/a', which -as rejects.
        # Require a value that is genuinely numeric: a REG_DWORD/REG_QWORD, or
        # a string of digits. Anything else is not a hide-flag.
        $raw = $Values[$name]
        $flag = $null
        if ($raw -is [int] -or $raw -is [long] -or $raw -is [uint32] -or $raw -is [uint64]) {
            $flag = [int]$raw
        } elseif ($raw -is [string] -and $raw.Trim() -match '^-?[0-9]+$') {
            $flag = [int]$raw.Trim()
        }
        if ($null -ne $flag -and $flag -eq 0) { $hidden += $name }
    }
    $hidden = @($hidden | Sort-Object)
    if ($hidden.Count -gt 0) {
        $r.Hidden = $hidden
        $r.Lines += "[WARNING] $($hidden.Count) account(s) are HIDDEN from the sign-in screen and from Settings (T1564.002): $($hidden -join ', ')"
        # [INFO], not [WARNING]: context for the finding above, not a second
        # finding. Both aggregate into one ledger row, so the tag changes no
        # verdict -- only the count a reader can make.
        $r.Lines += '[INFO] Some legitimate software hides its own service accounts this way. If you do not recognise one of these, someone may have created an account to access this PC without appearing on the login screen.'
        $r.Sev = 'WARNING'
    } else {
        $r.Lines += '[OK] No accounts are hidden from the sign-in screen.'
    }
    return $r
}

function Get-ShadowVerdict {
    # $Shadow is the raw Terminal Services 'Shadow' policy value, or $null when
    # the value is not set. 0 and 1 require the user's consent; 2 and 4 do not.
    param($Shadow)
    $r = @{ Lines = @(); Sev = 'OK' }
    $v = $null
    if ($null -ne $Shadow) { $v = $Shadow -as [int] }
    if ($null -ne $v -and ($v -eq 2 -or $v -eq 4)) {
        $what = 'view'
        if ($v -eq 2) { $what = 'view AND control' }
        $r.Lines += "[CRITICAL] Remote session shadowing is set to $what this session WITHOUT asking permission (Shadow=$v, T1113)."
        $r.Lines += '[INFO] Anyone who can reach this PC remotely could watch what you do with no prompt and no visible indication. There is no ordinary reason for this on a personal computer.'
        $r.Sev = 'CRITICAL'
    } elseif ($null -ne $v) {
        $r.Lines += "[OK] Remote session shadowing requires the user's permission (Shadow=$v)."
    } else {
        $r.Lines += '[OK] Remote session shadowing is not configured (default: permission required).'
    }
    return $r
}

if ($SelfTest) {
    $script:stFails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name :: $Got"; $script:stFails++ } }
    $J = { param($v) ($v.Lines -join ' | ') }
    $W = { param($v) @($v.Lines | Where-Object { $_ -match '^\[(WARNING|CRITICAL)\]' }).Count }

    # (1) THE FIELD INSTANCE, verbatim. CONFIRMED on the owner's machine since
    # 2026-09-05: OpenAI Codex's sandbox hides these two via SpecialAccounts.
    # tests/benign_corpus.txt catalogues them as ADVISE -- a real finding with
    # a known benign cause, which the person adjudicates. It must stay a
    # finding, must stay WARNING, and must carry the framing.
    $v = Get-HiddenAccountVerdict -Values @{ 'CodexSandboxOffline' = 0; 'CodexSandboxOnline' = 0 }
    T 'the CodexSandbox pair is a finding, at WARNING and never CRITICAL' `
      ($v.Sev -eq 'WARNING' -and (& $J $v) -match 'CodexSandboxOffline, CodexSandboxOnline') (& $J $v)
    T 'it carries the not-necessarily-malicious framing' ((& $J $v) -match 'legitimate software hides its own service accounts') (& $J $v)
    T 'the framing is [INFO], so one finding does not print as two' `
      ((& $W $v) -eq 1 -and (& $J $v) -match '\[INFO\][^|]*legitimate software') ("warns=$(& $W $v)")

    # (2) The exact-name skip. '^PS' as a prefix match would hide "psadmin".
    $v = Get-HiddenAccountVerdict -Values @{ 'PSPath' = 0; 'PSParentPath' = 0; 'PSProvider' = 0; 'psadmin' = 0 }
    T 'an account named psadmin is NOT swallowed by the note-property skip' `
      ($v.Hidden.Count -eq 1 -and $v.Hidden[0] -eq 'psadmin') ($v.Hidden -join ',')
    $v = Get-HiddenAccountVerdict -Values @{ 'PSPath' = 0; 'PSParentPath' = 0; 'PSChildName' = 0; 'PSDrive' = 0; 'PSProvider' = 0 }
    T 'the note-properties alone are not accounts' ($v.Sev -eq 'OK' -and $v.Hidden.Count -eq 0) (& $J $v)

    # (3) A junk value must not abort the scan. The hard [int] cast threw, the
    # caller's try/catch swallowed it, and the tool printed a clean verdict on
    # a machine that had a hidden account. A silent false clean is the worst
    # outcome this check can produce.
    $Error.Clear()
    $v = Get-HiddenAccountVerdict -Values @{ 'dz_junk' = 'n/a'; 'dz_bin' = @(1, 2, 3); 'dz_empty' = ''; 'realhidden' = 0 }
    T 'no junk value of any shape hides a real account from the scan' `
      ($v.Hidden.Count -eq 1 -and $v.Hidden[0] -eq 'realhidden') ($v.Hidden -join ',')
    T 'a junk value is not itself read as hidden' ((& $J $v) -notmatch 'dz_junk|dz_bin|dz_empty') (& $J $v)
    # The specific one that bit: '' -as [int] is 0, so an empty REG_SZ read as
    # a hide-flag and the tool named it as a hidden account.
    T 'an EMPTY string value is not a hide-flag' `
      ((Get-HiddenAccountVerdict -Values @{ 'dz_empty' = '' }).Sev -eq 'OK') 'empty string was read as hidden'
    T 'a numeric STRING value is still a hide-flag (REG_SZ "0")' `
      ((Get-HiddenAccountVerdict -Values @{ 'sz_hidden' = '0' }).Hidden -contains 'sz_hidden') 'REG_SZ 0 was missed'
    # stderr is redirected into the report, so a raw .NET conversion error
    # would print in front of the reader. -as is silent; [int] is not.
    T 'grading a junk value emits no error record into the report' ($Error.Count -eq 0) ("errors=$($Error.Count): $(($Error | Select-Object -First 1) -replace '\s+', ' ')")

    # (4) Only flag=0 hides an account; 1 is visible.
    $v = Get-HiddenAccountVerdict -Values @{ 'visible' = 1 }
    T 'flag=1 is a visible account, not a finding' ($v.Sev -eq 'OK') (& $J $v)
    $v = Get-HiddenAccountVerdict -Values @{}
    T 'an empty UserList key is [OK], not a finding' ($v.Sev -eq 'OK' -and (& $J $v) -match '^\[OK\]') (& $J $v)

    # (5) Shadow. 0 and 1 ask permission; 2 and 4 do not. The benign half here
    # matters most -- Shadow is unset on essentially every home machine.
    foreach ($s in @($null, 0, 1)) {
        $v = Get-ShadowVerdict -Shadow $s
        T ("Shadow={0} requires consent, so it is not a finding" -f $(if ($null -eq $s) { 'unset' } else { $s })) `
          ($v.Sev -eq 'OK' -and (& $W $v) -eq 0) (& $J $v)
    }
    foreach ($s in @(2, 4)) {
        $v = Get-ShadowVerdict -Shadow $s
        T "Shadow=$s is silent shadowing and raises CRITICAL" `
          ($v.Sev -eq 'CRITICAL' -and (& $J $v) -match 'WITHOUT asking permission') (& $J $v)
        T "Shadow=$s prints exactly one severity line, the consequence being [INFO]" ((& $W $v) -eq 1) ("warns=$(& $W $v)")
    }

    # (6) The monitoring-product matcher: substring, case-insensitive, and it
    # must not fire on ordinary software.
    T 'a spouseware product name matches'        ((Test-MonitorName 'C:\Program Files\mSpy\agent.exe') -eq 'mspy') 'no match'
    T 'matching is case-insensitive'             ((Test-MonitorName 'FLEXISPY_SERVICE') -eq 'flexispy') 'no match'
    foreach ($ordinary in @('C:\Program Files\Google\Chrome\chrome.exe', 'Microsoft.Teams.exe',
                            'C:\Windows\System32\svchost.exe', 'Dropbox', 'OneDrive.exe', '')) {
        T "ordinary software is not a monitoring product: '$ordinary'" ($null -eq (Test-MonitorName $ordinary)) 'matched'
    }

    if ($script:stFails) { Write-Output "[FAIL] $($script:stFails) stalkerware_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] stalkerware_check self-test: the CodexSandbox pair stays a WARNING finding with its framing, psadmin is not swallowed, a junk value cannot fake a clean verdict, an unset Shadow is not a finding, and no block prints two severity lines.'
    exit 0
}

'--- [T1564.002/T1125/T1123/T1113] Covert-monitoring check (is someone watching this person?) ---'

# ---- 1. Accounts hidden from the sign-in screen (T1564.002) ---------------
$ulValues = @{}
$hlKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
try {
    if (Test-Path $hlKey) {
        foreach ($p in (Get-ItemProperty -Path $hlKey -EA Stop).PSObject.Properties) { $ulValues[$p.Name] = $p.Value }
    }
} catch {}
# Reading is above; the RULE is in Get-HiddenAccountVerdict, which takes the
# raw map including PowerShell's note-properties so the self-test reaches the
# exact-name skip and the junk-value path.
$hv = Get-HiddenAccountVerdict -Values $ulValues
foreach ($l in $hv.Lines) { $l }
$sev = Get-MaxSev $sev $hv.Sev

# ---- 2. Silent RDP shadowing (T1113) --------------------------------------
$shadow = $null
try { $shadow = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'Shadow' -EA SilentlyContinue).Shadow } catch {}
$sv = Get-ShadowVerdict -Shadow $shadow
foreach ($l in $sv.Lines) { $l }
$sev = Get-MaxSev $sev $sv.Sev

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
    # Both of these are CONTEXT for the finding above. They print in the same
    # place and carry the same weight to a reader; what the tag changes is the
    # count, and one finding was printing as three.
    '[INFO] These products are also sold legitimately for parental control and workplace monitoring, so this is NOT proof of wrongdoing -- but if you did not install it and were not told it was here, treat it seriously.'
    '[INFO] Before removing it, read the READ THIS FIRST section at the top of this report: removing it can alert whoever installed it, and you may want to preserve evidence first.'
    $sev = Get-MaxSev $sev 'WARNING'
} else {
    '[OK] No known consumer monitoring/spouseware products detected.'
}

Write-Marker -Name 'stalkerware' -Sev $sev
