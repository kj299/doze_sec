# cred_settings_check.ps1 -- Section 12: WDigest plaintext caching (T1003.001)
# and the NTLM level (T1550.002), read from the registry.
#
# Extracted from two inline lines in both bats that read
#   (Get-ItemProperty <key> -Name <value> -EA SilentlyContinue).<value>
# A read that FAILED and a value that is ABSENT both came back empty, and
# empty printed "[OK] WDigest not caching plaintext credentials." /
# "[OK] LmCompatibilityLevel not set". The raw dump above them had the same
# hole in cmd ("reg query ... 2>nul" then "if errorlevel 1 echo [OK]"), and
# the dashboard re-read both values; its NTLM tile graded level 3-4 WARN
# where the section printed [OK].
#
# THE RULE (pure, in Get-CredSettingsVerdict, pinned by -SelfTest). For a
# registry VALUE, absent is a real answer -- so the reader tells four states
# apart: value present, value absent under a key that was read, key does not
# exist, key could not be read. Only the last is "NOT performed".
#   WDigest UseLogonCredential (SecurityProviders\WDigest):
#     1                    -> the CRITICAL finding (wording kept; marker
#                             dz_wdigest_hit.txt the bat already raises);
#     0                    -> [OK];
#     absent, or no key    -> [OK]: off by default on Windows 8.1 and later;
#     anything else        -> WARNING, an unexpected value (dz_wdigest_odd.txt);
#     key unreadable       -> a raised gap (dz_wdigest_gap.txt).
#   LmCompatibilityLevel (Control\Lsa). Microsoft, "Network security: LAN
#   Manager authentication level": the default on Windows Vista and later is
#   "Send NTLMv2 response only" (level 3); levels 0-2 let this PC send LM or
#   NTLMv1 responses; 4 and 5 additionally make it REFUSE them from others.
#     0-2                  -> the WARNING finding (wording kept; dz_ntlm_hit.txt);
#     3-4                  -> [OK], plus an [INFO] line on what level 5 adds;
#     5                    -> [OK];
#     absent               -> [OK]: the default applies;
#     not a number, or >5  -> WARNING, an unexpected value (dz_ntlm_odd.txt);
#     key unreadable, or the Lsa key itself missing (it always exists, so a
#     read that cannot find it cannot be trusted) -> a raised gap
#     (dz_ntlm_gap.txt).
# HKLM is readable by a standard user, so a failed read is a gap on either
# token, never a deferral.
# State line (dz_cred_state.txt):
#   wdigest=<on|off|absent|odd|gap>,ntlm=<weak|ok|default|odd|gap>,level=<n|->
# (commas only: the dashboard pastes it into a cmd echo.)
#
# Usage:
#   powershell -File tools\cred_settings_check.ps1 [-MarkerDir <dir>] [-StateFile <path>]
#   powershell -File tools\cred_settings_check.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    # Only CI changes these, to throwaway keys, so every state runs through
    # the real reader.
    [string]$WDigestKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
    [string]$LsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_cred_state.txt' }

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
    if ($t.Length -gt 80) { $t = $t.Substring(0, 80) + '...' }
    return $t
}

# PURE. The whole number a registry value holds, or $null when it is not one.
# Windows reads these settings as numbers, so a REG_SZ "1" counts as 1: the
# finding must not be dodged by storing the value under another type.
function ConvertTo-RegNumber {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [array]) { return $null }
    $n = [long]0
    if ([long]::TryParse(([string]$Value).Trim(), [ref]$n)) { return $n }
    return $null
}

# PURE. $WDigest / $Ntlm: @{ State = present|absent|nokey|unreadable; Value;
# Kind; Error }. Returns @{ Lines; WdHit; WdOdd; WdGap; NtHit; NtOdd; NtGap; State }.
function Get-CredSettingsVerdict {
    param($WDigest, $Ntlm)
    $out = New-Object System.Collections.ArrayList
    $r = @{ WdHit = $false; WdOdd = $false; WdGap = $false; NtHit = $false; NtOdd = $false; NtGap = $false }

    $wdState = ''
    switch ([string]$WDigest.State) {
        'present' {
            $n = ConvertTo-RegNumber $WDigest.Value
            if ($n -eq 1) {
                [void]$out.Add('[CRITICAL] WDigest ENABLED -- plaintext passwords cached in RAM (T1003.001)')
                $r.WdHit = $true; $wdState = 'on'
            } elseif ($n -eq 0) {
                [void]$out.Add('[OK] WDigest not caching plaintext credentials (UseLogonCredential=0).')
                $wdState = 'off'
            } else {
                [void]$out.Add(('[WARNING] WDigest UseLogonCredential holds an unexpected value (' + (ConvertTo-PrintableText ([string]$WDigest.Value)) + ', type ' + (ConvertTo-PrintableText ([string]$WDigest.Kind)) + ') -- only 0 and 1 are defined; a value nobody documents on a credential setting is worth explaining (T1003.001).'))
                $r.WdOdd = $true; $wdState = 'odd'
            }
        }
        { $_ -eq 'absent' -or $_ -eq 'nokey' } {
            [void]$out.Add(('[OK] WDigest not caching plaintext credentials: UseLogonCredential is not set' + $(if ($WDigest.State -eq 'nokey') { ' (the WDigest key does not exist)' } else { '' }) + ', and caching is off by default on Windows 8.1 and later.'))
            $wdState = 'absent'
        }
        default {
            [void]$out.Add(('[WARNING] WDigest check NOT performed -- the WDigest registry key could not be read (' + (ConvertTo-PrintableText ([string]$WDigest.Error)) + '), so plaintext credential caching would go unseen (T1003.001).'))
            $r.WdGap = $true; $wdState = 'gap'
        }
    }

    $ntState = ''; $level = '-'
    switch ([string]$Ntlm.State) {
        'present' {
            $n = ConvertTo-RegNumber $Ntlm.Value
            if ($null -ne $n -and $n -ge 0 -and $n -le 2) {
                [void]$out.Add(('[WARNING] NTLMv1/LM permitted (LmCompatibilityLevel=' + $n + ') -- downgrade/relay exposure'))
                $r.NtHit = $true; $ntState = 'weak'; $level = [string]$n
            } elseif ($null -ne $n -and $n -ge 3 -and $n -le 5) {
                [void]$out.Add(('[OK] NTLM level ' + $n + ' (NTLMv2).'))
                if ($n -lt 5) { [void]$out.Add('[INFO] At this level the PC sends only NTLMv2. Level 5 would also make it refuse LM and NTLMv1 from other machines; that can break sign-in from old devices, so it is a choice, not a finding.') }
                $ntState = 'ok'; $level = [string]$n
            } else {
                [void]$out.Add(('[WARNING] LmCompatibilityLevel holds an unexpected value (' + (ConvertTo-PrintableText ([string]$Ntlm.Value)) + ', type ' + (ConvertTo-PrintableText ([string]$Ntlm.Kind)) + ') -- only 0 to 5 are defined, so which NTLM versions this PC uses cannot be stated (T1550.002).'))
                $r.NtOdd = $true; $ntState = 'odd'
            }
        }
        'absent' {
            [void]$out.Add('[OK] LmCompatibilityLevel not set (the Windows default applies: NTLMv2 responses only).')
            $ntState = 'default'
        }
        default {
            $why = if ($Ntlm.State -eq 'nokey') { 'the Lsa registry key was not found, and it exists on every Windows' } else { ConvertTo-PrintableText ([string]$Ntlm.Error) }
            [void]$out.Add(('[WARNING] NTLM level check NOT performed -- the Lsa registry key could not be read (' + $why + '), so a PC that still sends LM or NTLMv1 would go unseen (T1550.002).'))
            $r.NtGap = $true; $ntState = 'gap'
        }
    }
    $r.Lines = @($out.ToArray())
    $r.State = ('wdigest=' + $wdState + ',ntlm=' + $ntState + ',level=' + $level)
    return $r
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

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function P { param($v, [string]$k = 'DWord') @{ State = 'present'; Value = $v; Kind = $k; Error = '' } }
    $abs = @{ State = 'absent'; Value = $null; Kind = ''; Error = '' }
    $nok = @{ State = 'nokey'; Value = $null; Kind = ''; Error = '' }
    $bad = @{ State = 'unreadable'; Value = $null; Kind = ''; Error = 'SecurityException: Requested registry access is not allowed.' }

    $v = Get-CredSettingsVerdict -WDigest (P 1) -Ntlm $abs; $t = $v.Lines -join "`n"
    T 'WDigest 1: the CRITICAL wording the bats always printed, and a hit' ($v.WdHit -and $v.State -eq 'wdigest=on,ntlm=default,level=-' -and $t -match '(?m)^\[CRITICAL\] WDigest ENABLED -- plaintext passwords cached in RAM \(T1003\.001\)$') $t
    $v = Get-CredSettingsVerdict -WDigest (P 0) -Ntlm $abs; $t = $v.Lines -join "`n"
    T 'WDigest 0: [OK], nothing raised' ((-not $v.WdHit) -and (-not $v.WdGap) -and $v.State -like 'wdigest=off,*' -and $t -match '(?m)^\[OK\] WDigest not caching plaintext credentials \(UseLogonCredential=0\)\.$') $t
    $v = Get-CredSettingsVerdict -WDigest $abs -Ntlm $abs; $t = $v.Lines -join "`n"
    T 'both values absent (a clean Windows 11): two [OK] lines that say "not set", nothing raised' ((-not ($v.WdHit -or $v.WdGap -or $v.WdOdd -or $v.NtHit -or $v.NtGap -or $v.NtOdd)) -and $v.State -eq 'wdigest=absent,ntlm=default,level=-' -and $t -match 'UseLogonCredential is not set' -and $t -match 'LmCompatibilityLevel not set \(the Windows default applies' -and $t -notmatch '\[WARNING\]') $t
    $v = Get-CredSettingsVerdict -WDigest $nok -Ntlm $abs
    T 'the WDigest key does not exist: [OK] and says so (absent is an answer)' ((-not $v.WdGap) -and $v.State -like 'wdigest=absent,*' -and ($v.Lines -join "`n") -match 'the WDigest key does not exist') ($v.Lines -join ' | ')
    $v = Get-CredSettingsVerdict -WDigest $bad -Ntlm $abs; $t = $v.Lines -join "`n"
    T 'the WDigest key could not be read: a raised gap, never "[OK] not caching"' ($v.WdGap -and (-not $v.WdHit) -and $v.State -like 'wdigest=gap,*' -and $t -match '(?m)^\[WARNING\] WDigest check NOT performed' -and $t -match 'SecurityException' -and $t -notmatch 'WDigest not caching') $t
    $v = Get-CredSettingsVerdict -WDigest (P '1' 'String') -Ntlm $abs
    T 'WDigest stored as the string "1": still ENABLED -- another type must not dodge the finding' ($v.WdHit -and (-not $v.WdOdd)) ($v.Lines -join ' | ')
    $v = Get-CredSettingsVerdict -WDigest (P 2) -Ntlm $abs; $t = $v.Lines -join "`n"
    T 'WDigest 2: a WARNING naming the unexpected value, neither CRITICAL nor [OK]' ($v.WdOdd -and (-not $v.WdHit) -and $v.State -like 'wdigest=odd,*' -and $t -match 'unexpected value \(2, type DWord\)' -and $t -notmatch 'WDigest not caching') $t
    foreach ($lv in 0, 1, 2) {
        $v = Get-CredSettingsVerdict -WDigest $abs -Ntlm (P $lv); $t = $v.Lines -join "`n"
        T ("NTLM level {0}: the WARNING wording the bats always printed, and a hit" -f $lv) ($v.NtHit -and $v.State -eq ("wdigest=absent,ntlm=weak,level={0}" -f $lv) -and $t -match ("(?m)^\[WARNING\] NTLMv1/LM permitted \(LmCompatibilityLevel={0}\) -- downgrade/relay exposure$" -f $lv)) $t
    }
    foreach ($lv in 3, 4) {
        $v = Get-CredSettingsVerdict -WDigest $abs -Ntlm (P $lv); $t = $v.Lines -join "`n"
        T ("NTLM level {0} (3 is the Windows default): [OK] plus an INFO on level 5, never a WARNING" -f $lv) ((-not $v.NtHit) -and (-not $v.NtOdd) -and $v.State -eq ("wdigest=absent,ntlm=ok,level={0}" -f $lv) -and $t -match ("(?m)^\[OK\] NTLM level {0} \(NTLMv2\)\.$" -f $lv) -and $t -match '\[INFO\] At this level' -and $t -notmatch '\[WARNING\]') $t
    }
    $v = Get-CredSettingsVerdict -WDigest $abs -Ntlm (P 5); $t = $v.Lines -join "`n"
    T 'NTLM level 5: [OK], no INFO needed' ($v.State -eq 'wdigest=absent,ntlm=ok,level=5' -and $t -notmatch 'At this level') $t
    $v = Get-CredSettingsVerdict -WDigest $abs -Ntlm (P 9); $t = $v.Lines -join "`n"
    T 'NTLM level 9: a WARNING naming the unexpected value, never [OK]' ($v.NtOdd -and (-not $v.NtHit) -and $v.State -eq 'wdigest=absent,ntlm=odd,level=-' -and $t -notmatch '\[OK\] NTLM') $t
    $v = Get-CredSettingsVerdict -WDigest $abs -Ntlm (P 'abc' 'String')
    T 'NTLM level that is not a number: unexpected, never read as 0 or as [OK]' ($v.NtOdd -and (-not $v.NtHit) -and $v.State -like '*ntlm=odd,*') ($v.Lines -join ' | ')
    $v = Get-CredSettingsVerdict -WDigest $abs -Ntlm $bad; $t = $v.Lines -join "`n"
    T 'the Lsa key could not be read: a raised gap, never "[OK] not set"' ($v.NtGap -and $v.State -eq 'wdigest=absent,ntlm=gap,level=-' -and $t -match '(?m)^\[WARNING\] NTLM level check NOT performed' -and $t -notmatch 'LmCompatibilityLevel not set') $t
    $v = Get-CredSettingsVerdict -WDigest $nok -Ntlm $nok; $t = $v.Lines -join "`n"
    T 'both keys missing: WDigest is [OK] (the key is optional), the Lsa key is a gap (it always exists)' ((-not $v.WdGap) -and $v.NtGap -and $t -match 'exists on every Windows') $t
    $v = Get-CredSettingsVerdict -WDigest $bad -Ntlm $bad
    T 'both unreadable: two gaps, and no [OK] line at all' ($v.WdGap -and $v.NtGap -and $v.State -eq 'wdigest=gap,ntlm=gap,level=-' -and ($v.Lines -join "`n") -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-CredSettingsVerdict -WDigest @{ State = 'unreadable'; Error = ('bad' + [char]10 + '[OK] fine') } -Ntlm (P ('7' + [char]13 + [char]10 + '[OK] NTLM level 5') 'String')
    T 'a control character in an error or in the value itself cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\]' }).Count -eq 0) ($v.Lines -join ' | ')
    T 'every state line is commas only and ends in a level or "-"' ((Get-CredSettingsVerdict -WDigest (P 1) -Ntlm (P 1)).State -match '^wdigest=[a-z]+,ntlm=[a-z]+,level=([0-5]|-)$') ''
    if ($fails) { Write-Output "[FAIL] $fails cred_settings_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] cred_settings_check self-test: WDigest 1 is CRITICAL and NTLM 0-2 is WARNING, an absent value is the Windows default and says so, level 3-4 is OK, an undefined value is named, and a key that could not be read is a raised gap, never an all-clear.'
    exit 0
}

# --- live ---------------------------------------------------------------------
$wd = Read-RegValueState -KeyPath $WDigestKey -Name 'UseLogonCredential'
$nt = Read-RegValueState -KeyPath $LsaKey -Name 'LmCompatibilityLevel'
$v = $null
try { $v = Get-CredSettingsVerdict -WDigest $wd -Ntlm $nt } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^wdigest=(on|off|absent|odd|gap),ntlm=(weak|ok|default|odd|gap),level=([0-5]|-)$') {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'cred_settings_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.WdHit) { Write-Marker -Name 'wdigest_hit' -Sev 'hit' }
if ($v.WdOdd) { Write-Marker -Name 'wdigest_odd' -Sev 'WARNING' }
if ($v.WdGap) { Write-Marker -Name 'wdigest_gap' -Sev 'WARNING' }
if ($v.NtHit) { Write-Marker -Name 'ntlm_hit' -Sev 'hit' }
if ($v.NtOdd) { Write-Marker -Name 'ntlm_odd' -Sev 'WARNING' }
if ($v.NtGap) { Write-Marker -Name 'ntlm_gap' -Sev 'WARNING' }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('cred_settings_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
