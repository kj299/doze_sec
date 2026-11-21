# asr_rules_check.ps1 -- Defender's attack-surface-reduction (ASR) rules
# (Section 9, T1562.001), and the LSASS rule's mode for Section 12.
#
# WHY A TOOL. The check was a staged block that asked Get-MpPreference and
# graded whatever came back. On a standard-user token Defender ANSWERS that
# cmdlet with masked values -- its exclusion lists come back as "N/A: Must be
# an administrator" and DisableRealtimeMonitoring reads True whatever the
# setting (CLAUDE.md, "an answer is not a truthful answer") -- so an empty
# rule list there is not evidence. The block printed "No ASR rules
# configured" and "Key ASR rule not in Block mode" from it, raised a row, and
# handed Section 12 "notconfigured" as the LSASS rule's mode: three
# statements the token never observed.
#
# THE RULE (pure, in Get-AsrVerdict, pinned by -SelfTest):
#   * ELEVATED: Get-MpPreference is the effect and decides, exactly as the
#     block did. A failed query is a raised gap (INFO when Section 9 found
#     another antivirus in force).
#   * STANDARD-USER TOKEN: a rule Get-MpPreference SHOWS is used (masking
#     only ever hides), and the rules are also read from where Windows
#     stores them: the Group Policy key, the MDM (Intune) policy value and
#     Defender's local key. A rule found anywhere is graded. A rule found
#     NOWHERE is "not in Block" only when every store answered and the PC is
#     not MDM-managed for Defender; when a store refused, or MDM is present,
#     its absence is not known and it is a counted deferral, never a row.
#   * the LSASS rule's mode is "ungraded" whenever its absence is not known.
# Precedence where a rule is in several stores: Group Policy, then MDM, then
# the local key, then what Get-MpPreference showed. The MDM value's name
# (PolicyManager\current\device\Defender, AttackSurfaceReductionRules) comes
# from the Policy CSP's name for the setting, not from a first-party registry
# reference; a wrong name can only leave a rule "not found", and an
# MDM-managed PC then defers rather than warns.
#
# Markers: dz_asr_hit / dz_asr_gap / dz_asr_deferred; dz_asr_lsass_mode.txt
# (block|audit|warn|off|notconfigured|ungraded) for Section 12.
# State: dz_asr_state.txt  asr=<block|notblock|none|deferred|gap|otherav>
#
# Usage:
#   powershell -File tools\asr_rules_check.ps1 [-MarkerDir <dir>] [-Elevated 0|1] [-OtherAv]
#   powershell -File tools\asr_rules_check.ps1 -SelfTest   (queries nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    [switch]$OtherAv,
    # Only CI changes these: throwaway keys standing in for the three stores.
    [string]$PolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
    [string]$LocalKey = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
    [string]$MdmKey = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender',
    # Defender's own copy of settings pushed by Intune or Defender security
    # settings management (value ASRRules, same guid=n form). The name is
    # from memory, not a first-party reference: any value in this key marks
    # the PC as managed, so a wrong value name defers rather than warns.
    [string]$MdmKey2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_asr_state.txt' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -ErrorAction Stop
}

function ConvertTo-PrintableText {
    param([string]$s, [int]$Max = 200)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

$script:RuleNames = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables unless they meet prevalence, age, or trusted-list criteria'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps from creating child processes'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PSExec and WMI commands'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block webshell creation for servers'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
}
# The five whose absence is the finding, in a fixed order.
$script:KeyRules = @(
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
    '56a863a9-875e-4185-98a7-b882c64b5ce5',
    '3b576869-a4ec-4529-8536-b80a7769e899',
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b',
    'c1db55ab-c21a-4637-bb3f-a12568109d35'
)
$script:LsassRule = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
$script:ModeMap = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit'; 6 = 'Warn' }
$script:GuidRx = '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$'

# PURE: (id, action) pairs -> @{ guid = int }. Anything that is not a GUID
# with a whole-number action is dropped: a placeholder such as "N/A: Must be
# an administrator" must never become a rule.
function ConvertTo-RuleMap {
    param($Ids, $Actions)
    $m = @{}
    $i = @($Ids); $a = @($Actions)
    for ($k = 0; $k -lt $i.Count; $k++) {
        $id = ([string]$i[$k]).Trim()
        if ($id -notmatch $script:GuidRx) { continue }
        if ($k -ge $a.Count) { continue }
        $n = 0
        if (-not [int]::TryParse(([string]$a[$k]).Trim(), [ref]$n)) { continue }
        $m[$id.Trim('{', '}').ToLowerInvariant()] = $n
    }
    return $m
}

# PURE: the MDM value "guid=1|guid=2" -> @{ guid = int }.
function ConvertFrom-MdmRules {
    param([string]$Text)
    $ids = @(); $acts = @()
    foreach ($pair in (([string]$Text) -split '\|')) {
        $kv = $pair -split '=', 2
        if ($kv.Count -eq 2) { $ids += $kv[0]; $acts += $kv[1] }
    }
    return (ConvertTo-RuleMap $ids $acts)
}

# One store, read: @{ State = ok|nokey|denied|error; Rules; Error }.
function Read-RuleKey {
    param([string]$Path)
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        $ids = @(); $acts = @()
        foreach ($n in @($k.GetValueNames())) { $ids += $n; $acts += [string]$k.GetValue($n, $null) }
        return @{ State = 'ok'; Rules = (ConvertTo-RuleMap $ids $acts); Error = '' }
    } catch [System.Management.Automation.ItemNotFoundException] {
        # Absent only when the PARENT answers; a parent that refuses hides
        # whether the key exists.
        try { $null = Get-Item -LiteralPath (Split-Path -Parent $Path) -ErrorAction Stop; return @{ State = 'nokey'; Rules = @{}; Error = '' } }
        catch [System.Management.Automation.ItemNotFoundException] { return @{ State = 'nokey'; Rules = @{}; Error = '' } }
        catch { return @{ State = 'denied'; Rules = @{}; Error = $_.Exception.Message } }
    } catch [System.Security.SecurityException] { return @{ State = 'denied'; Rules = @{}; Error = $_.Exception.Message }
    } catch [System.UnauthorizedAccessException] { return @{ State = 'denied'; Rules = @{}; Error = $_.Exception.Message }
    } catch { return @{ State = 'error'; Rules = @{}; Error = $_.Exception.Message } }
}

# PURE: the verdict.
#   $In: @{ MpError; Shown (map); Policy/Local (Read-RuleKey shape);
#           Mdm = @{ State; Present (bool); Rules } }
function Get-AsrVerdict {
    param($In, [bool]$IsElevated = $true, [bool]$OtherAv = $false)
    $out = New-Object System.Collections.ArrayList
    $hit = $false; $gap = $false; $deferred = 0
    $rules = @{}; $known = $true; $why = @()

    if ($IsElevated) {
        if ([string]$In.MpError) {
            if ($OtherAv) {
                [void]$out.Add('[INFO] Get-MpPreference did not answer (' + (ConvertTo-PrintableText $In.MpError 160) + '), and Section 9 found another antivirus registered as the one in force, so Defender''s ASR rules are not the protection here.')
                return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 0; State = 'asr=otherav'; LsassMode = 'ungraded' }
            }
            [void]$out.Add('[WARNING] Defender ASR rules check NOT performed -- Get-MpPreference did not answer (' + (ConvertTo-PrintableText $In.MpError 160) + '), so ASR rules switched off would go unseen.')
            return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0; State = 'asr=gap'; LsassMode = 'ungraded' }
        }
        $rules = $In.Shown
    } else {
        # Defender did not answer at all and another antivirus is the one in
        # force: the same INFO the elevated path gives, never "no rules".
        if ([string]$In.MpError -and $OtherAv) {
            [void]$out.Add('[INFO] Get-MpPreference did not answer (' + (ConvertTo-PrintableText $In.MpError 160) + '), and Section 9 found another antivirus registered as the one in force, so Defender''s ASR rules are not the protection here.')
            return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 0; State = 'asr=otherav'; LsassMode = 'ungraded' }
        }
        # Lowest precedence first, so a later store overwrites.
        foreach ($k in @($In.Shown.Keys)) { $rules[$k] = $In.Shown[$k] }
        foreach ($src in @(@{ N = 'Defender''s local settings'; R = $In.Local }, @{ N = 'the MDM policy'; R = $In.Mdm }, @{ N = 'the Group Policy key'; R = $In.Policy })) {
            if ($src.R.State -eq 'ok') { foreach ($k in @($src.R.Rules.Keys)) { $rules[$k] = $src.R.Rules[$k] } }
            elseif ($src.R.State -ne 'nokey') { $known = $false; $why += ($src.N + ' could not be read') }
        }
        if ($In.Mdm.Present) { $known = $false; $why += 'this PC takes Defender settings from device management, whose rules this token cannot confirm' }
        $seen = @()
        $seen += ('Group Policy key: ' + $In.Policy.State)
        $seen += ('MDM policy: ' + $(if ($In.Mdm.Present) { 'present' } else { $In.Mdm.State }))
        $seen += ('local settings: ' + $In.Local.State)
        $seen += ('Get-MpPreference: ' + $(if ([string]$In.MpError) { 'did not answer' } else { 'showed ' + $In.Shown.Count + ' rule(s)' }))
        [void]$out.Add('[INFO] Standard-user token: Defender does not show this token its full settings, so the rules were read from where Windows stores them (' + ($seen -join '; ') + ').')
    }

    if ($rules.Count -eq 0 -and $known) {
        [void]$out.Add('[WARNING] No ASR rules configured. All Defender attack-surface-reduction rules are inactive.')
        [void]$out.Add('          Enable per rule: Add-MpPreference -AttackSurfaceReductionRules_Ids GUID -AttackSurfaceReductionRules_Actions Enabled')
        [void]$out.Add('          (Add-, not Set-: Set-MpPreference replaces the whole rule array.)')
        $hit = $true
    }
    foreach ($id in @($rules.Keys | Sort-Object)) {
        $nm = $script:RuleNames[$id]; if (-not $nm) { $nm = 'Unknown or custom rule ' + (ConvertTo-PrintableText $id 40) }
        $ac = [int]$rules[$id]
        $md = $script:ModeMap[$ac]; if (-not $md) { $md = 'Mode ' + $ac }
        $tag = '[INFO]'; if ($ac -eq 1) { $tag = '[OK]  ' }
        [void]$out.Add($tag + ' ' + $md.PadRight(8) + ' ' + $nm)
    }
    $notBlock = @(); $unknown = @()
    foreach ($k in $script:KeyRules) {
        if ($rules.ContainsKey($k)) { if ([int]$rules[$k] -ne 1) { $notBlock += $script:RuleNames[$k] } }
        elseif ($known) { $notBlock += $script:RuleNames[$k] }
        else { $unknown += $script:RuleNames[$k] }
    }
    foreach ($n in $notBlock) { [void]$out.Add('[WARNING] Key ASR rule not in Block mode: ' + $n); $hit = $true }
    if ($unknown.Count) {
        [void]$out.Add('[DEFERRED - ADMIN REQUIRED] ' + $unknown.Count + ' key ASR rule(s) not graded on this standard-user token: ' + ($unknown -join '; ') + ' -- ' + (($why | Select-Object -Unique) -join '; ') + '. An audit run as administrator grades them.')
        $deferred = 1
    }
    if (-not $notBlock.Count -and -not $unknown.Count) { [void]$out.Add('[OK] All five key ASR rules are in Block mode.') }

    $lsass = 'ungraded'
    if ($rules.ContainsKey($script:LsassRule)) {
        $la = [int]$rules[$script:LsassRule]
        $lsass = 'off'; if ($la -eq 1) { $lsass = 'block' }; if ($la -eq 2) { $lsass = 'audit' }; if ($la -eq 6) { $lsass = 'warn' }
    } elseif ($known) { $lsass = 'notconfigured' }

    $state = 'asr=block'
    if ($hit) { $state = $(if ($rules.Count -eq 0) { 'asr=none' } else { 'asr=notblock' }) }
    elseif ($deferred) { $state = 'asr=deferred' }
    return @{ Lines = @($out.ToArray()); Hit = $hit; Gap = $gap; Deferred = $deferred; State = $state; LsassMode = $lsass }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $L = $script:LsassRule
    $all = @{}; foreach ($k in $script:KeyRules) { $all[$k] = 1 }
    function K { param([string]$State = 'nokey', $Rules = @{}) @{ State = $State; Rules = $Rules; Error = $(if ($State -eq 'denied') { 'Requested registry access is not allowed.' } else { '' }) } }
    function Std { param($Shown = @{}, $Policy = (K), $Local = (K), $MdmPresent = $false, $MdmRules = @{}, [string]$MpErr = '')
        Get-AsrVerdict -IsElevated $false -In @{ MpError = $MpErr; Shown = $Shown; Policy = $Policy; Local = $Local; Mdm = @{ State = $(if ($MdmPresent) { 'ok' } else { 'nokey' }); Present = $MdmPresent; Rules = $MdmRules } } }
    function Adm { param($Shown = @{}, [string]$MpErr = '', [bool]$Oa = $false)
        Get-AsrVerdict -IsElevated $true -OtherAv $Oa -In @{ MpError = $MpErr; Shown = $Shown; Policy = (K); Local = (K); Mdm = @{ State = 'nokey'; Present = $false; Rules = @{} } } }

    $v = Adm @{}; $t = $v.Lines -join "`n"
    T 'elevated, no rules: the WARNING wording the block always printed, five key-rule lines, mode notconfigured' ($v.Hit -and $t -match '(?m)^\[WARNING\] No ASR rules configured\. All Defender attack-surface-reduction rules are inactive\.$' -and @($v.Lines | Where-Object { $_ -match '^\[WARNING\] Key ASR rule not in Block mode: ' }).Count -eq 5 -and $v.LsassMode -eq 'notconfigured' -and $v.State -eq 'asr=none') $t
    $v = Adm $all; $t = $v.Lines -join "`n"
    T 'elevated, all five in Block: OK, no hit, mode block' ((-not $v.Hit) -and $t -match '(?m)^\[OK\] All five key ASR rules are in Block mode\.$' -and $v.LsassMode -eq 'block' -and $v.State -eq 'asr=block') $t
    $one = $all.Clone(); $one[$L] = 2
    $v = Adm $one; $t = $v.Lines -join "`n"
    T 'elevated, the LSASS rule in Audit: one key-rule WARNING naming it, mode audit' ($v.Hit -and @($v.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 1 -and $t -match 'Key ASR rule not in Block mode: Block credential stealing from LSASS' -and $t -match '(?m)^\[INFO\] Audit    Block credential stealing from LSASS$' -and $v.LsassMode -eq 'audit') $t
    $v = Adm @{} 'The service cannot be started'; $t = $v.Lines -join "`n"
    T 'elevated, Get-MpPreference failed: a raised gap, never "No ASR rules configured"' ($v.Gap -and (-not $v.Hit) -and $t -match '(?m)^\[WARNING\] Defender ASR rules check NOT performed -- ' -and $t -notmatch 'No ASR rules configured' -and $v.LsassMode -eq 'ungraded') $t
    $v = Adm @{} 'x' $true
    T 'elevated, failed with another antivirus in force: INFO, no gap' ((-not $v.Gap) -and ($v.Lines -join ' ') -match '^\[INFO\]' -and $v.State -eq 'asr=otherav') ($v.Lines -join ' | ')

    $v = Std @{} (K) (K 'denied'); $t = $v.Lines -join "`n"
    T 'standard token, an empty answer and the local store refused: a counted deferral, no row, never "No ASR rules configured", mode ungraded' ((-not $v.Hit) -and (-not $v.Gap) -and $v.Deferred -eq 1 -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] 5 key ASR rule\(s\) not graded' -and $t -notmatch 'No ASR rules configured' -and $t -notmatch 'Key ASR rule not in Block' -and $v.LsassMode -eq 'ungraded' -and $v.State -eq 'asr=deferred') $t
    $v = Std @{} (K) (K 'ok' @{}); $t = $v.Lines -join "`n"
    T 'standard token, every store answered with nothing: the absence is known, so the WARNING stands' ($v.Hit -and $t -match 'No ASR rules configured' -and $v.Deferred -eq 0 -and $v.LsassMode -eq 'notconfigured') $t
    $v = Std @{} (K) (K 'nokey')
    T 'standard token, the stores do not exist (their parents answered): known, the WARNING stands' ($v.Hit -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Std @{} (K 'ok' @{ $L = 2 }) (K 'denied'); $t = $v.Lines -join "`n"
    T 'standard token, the LSASS rule in Audit by Group Policy while the local store is refused: that rule is the finding, the other four deferred' ($v.Hit -and $v.Deferred -eq 1 -and @($v.Lines | Where-Object { $_ -match '^\[WARNING\] Key ASR' }).Count -eq 1 -and $t -match '4 key ASR rule\(s\) not graded' -and $v.LsassMode -eq 'audit') $t
    $v = Std @{} (K 'ok' $all) (K 'denied'); $t = $v.Lines -join "`n"
    T 'standard token, all five in Block by Group Policy: OK even with the local store refused' ((-not $v.Hit) -and $v.Deferred -eq 0 -and $t -match 'All five key ASR rules are in Block mode' -and $v.LsassMode -eq 'block') $t
    $v = Std @{ $L = 1 } (K 'ok' @{ $L = 2 }) (K 'ok' @{ $L = 1 })
    T 'Group Policy outranks the local store and what Get-MpPreference showed' ($v.LsassMode -eq 'audit') ($v.Lines -join ' | ')
    $v = Std $all (K) (K 'denied')
    T 'standard token, a rule Get-MpPreference SHOWED is used (masking only hides)' ((-not $v.Hit) -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Std @{} (K) (K 'ok' @{}) $true; $t = $v.Lines -join "`n"
    T 'standard token on an MDM-managed PC: a rule not found is deferred, never "not in Block"' ((-not $v.Hit) -and $v.Deferred -eq 1 -and $t -match 'device management') $t
    $v = Std @{} (K) (K 'ok' @{}) $true $all
    T 'standard token, all five in Block by MDM: OK' ((-not $v.Hit) -and $v.Deferred -eq 0) ($v.Lines -join ' | ')

    $v = Get-AsrVerdict -IsElevated $false -OtherAv $true -In @{ MpError = 'The service cannot be started'; Shown = @{}; Policy = (K); Local = (K); Mdm = @{ State = 'nokey'; Present = $false; Rules = @{} } }
    T 'standard token, Defender not answering with another antivirus in force: INFO, never "No ASR rules configured"' ((-not $v.Hit) -and $v.State -eq 'asr=otherav' -and ($v.Lines -join ' ') -notmatch 'No ASR rules') ($v.Lines -join ' | ')
    $m = ConvertTo-RuleMap @('N/A: Must be an administrator', $L, 'not-a-guid') @('1', '2', '1')
    T 'a placeholder or a non-GUID is never a rule' ($m.Count -eq 1 -and $m[$L] -eq 2) ''
    $m = ConvertTo-RuleMap @($L.ToUpper(), ('{' + $script:KeyRules[1] + '}')) @(1, 'x')
    T 'a GUID is matched in any case; an action that is not a number is dropped' ($m.Count -eq 1 -and $m[$L] -eq 1) ''
    $m = ConvertFrom-MdmRules ($L + '=1|' + $script:KeyRules[1] + '=2|junk')
    T 'the MDM value is split into rules' ($m.Count -eq 2 -and $m[$script:KeyRules[1]] -eq 2) ''
    $v = Adm @{ ('aaaaaaaa-0000-0000-0000-00000000000' + [char]10) = 1 }
    T 'a control character in a rule id cannot start a report line' (($v.Lines -join "`n") -notmatch "(?m)^\s*$") ''

    if ($fails) { Write-Output "[FAIL] $fails asr_rules_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] asr_rules_check self-test: elevated, Get-MpPreference decides; on a standard-user token a rule is graded where a store shows it, and a rule no readable store shows is deferred unless every store answered.'
    exit 0
}

if ($Elevated -lt 0) {
    $Elevated = 0
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 }
    } catch { }
}

$in = @{ MpError = ''; Shown = @{}; Policy = @{ State = 'nokey'; Rules = @{}; Error = '' }; Local = @{ State = 'nokey'; Rules = @{}; Error = '' }; Mdm = @{ State = 'nokey'; Present = $false; Rules = @{} } }
try {
    $p = Get-MpPreference -ErrorAction Stop
    $in.Shown = ConvertTo-RuleMap $p.AttackSurfaceReductionRules_Ids $p.AttackSurfaceReductionRules_Actions
} catch { $in.MpError = $_.Exception.Message }
if ($Elevated -ne 1) {
    $in.Policy = Read-RuleKey $PolicyKey
    $in.Local = Read-RuleKey $LocalKey
    foreach ($src in @(@{ P = $MdmKey2; V = 'ASRRules' }, @{ P = $MdmKey; V = 'AttackSurfaceReductionRules' })) {
        try {
            $mk = Get-Item -LiteralPath $src.P -ErrorAction Stop
            $names = @($mk.GetValueNames())
            if ($in.Mdm.State -ne 'denied') { $in.Mdm.State = 'ok' }
            if ($names.Count -gt 0) { $in.Mdm.Present = $true }
            if ($names -contains $src.V) { $mr = ConvertFrom-MdmRules ([string]$mk.GetValue($src.V, '')); foreach ($k in @($mr.Keys)) { $in.Mdm.Rules[$k] = $mr[$k] } }
        } catch [System.Management.Automation.ItemNotFoundException] {
        } catch { $in.Mdm.State = 'denied' }
    }
}
$v = Get-AsrVerdict -In $in -IsElevated ($Elevated -eq 1) -OtherAv ([bool]$OtherAv)
foreach ($l in $v.Lines) { $l }
try {
    if ($v.Hit) { Write-Marker -Name 'asr_hit' -Sev 'WARNING' }
    if ($v.Gap) { Write-Marker -Name 'asr_gap' -Sev 'WARNING' }
    if ($v.Deferred) { Write-Marker -Name 'asr_deferred' -Sev ([string]$v.Deferred) }
    Set-Content -LiteralPath (Join-Path $MarkerDir 'dz_asr_lsass_mode.txt') -Value $v.LsassMode -Encoding ASCII -ErrorAction Stop
    Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop
} catch {
    "[WARNING] Defender ASR rules check: the verdict could not be written for the audit to read ($(ConvertTo-PrintableText $_.Exception.Message 160)) -- NOT performed."
}
exit 0
