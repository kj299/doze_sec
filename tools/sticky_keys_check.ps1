# sticky_keys_check.ps1 -- can Sticky Keys be opened at the logon screen with
# Shift pressed five times (T1546.008)? That shortcut starts sethc.exe before
# anyone signs in; when sethc.exe has been replaced (the classic backdoor,
# graded separately by accessibility_backdoor_check), it is a SYSTEM shell on
# the logon screen with no password.
#
# The check was an inline block that read only the CURRENT USER's setting
# (HKCU) while saying "activates at login screen", with errors silenced: a
# read that failed printed "[INFO] Sticky Keys flags not set in registry".
# The logon screen does not use HKCU. It runs in the system's default profile,
# HKEY_USERS\.DEFAULT -- the key the remediation already changes.
#
# THE RULE (pure, in Get-StickyVerdict, pinned by -SelfTest; the owner's
# choice, 2026-11-16: the logon screen decides):
#   * Flags is a number stored as text; bit 0x04 (SKF_HOTKEYACTIVE) is the
#     Shift x5 shortcut;
#   * logon screen bit set -> the WARNING the bats always printed; clear ->
#     [OK]; value or key absent -> Windows' default applies, which is the
#     shortcut ON, said so; not a number -> a gap;
#   * the logon key could not be read -> a raised gap on any token (Users can
#     read HKEY_USERS\.DEFAULT, so a refusal is not the token's limit);
#   * this user's own setting is one [INFO] line and never grades.
# Markers: dz_sticky_hit / dz_sticky_gap / dz_sticky_deferred, written before
# the state. State: dz_sticky_state.txt
#   sticky=<on|off|gap>,lf=<logon Flags|->,uf=<user Flags|->
#
# Usage:
#   powershell -File tools\sticky_keys_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1]
#   powershell -File tools\sticky_keys_check.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # Only CI changes these: throwaway keys laid out like StickyKeys.
    [string]$LogonKey = 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys',
    [string]$UserKey = 'HKCU:\Control Panel\Accessibility\StickyKeys',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_sticky_state.txt' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -ErrorAction Stop | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -ErrorAction Stop
}

function ConvertTo-PrintableText {
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt 200) { $t = $t.Substring(0, 200) + '...' }
    return $t
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

# PURE. One Read-RegValueState result -> @{ Kind = on|off|default|odd|unreadable; Flags; Error }.
function Get-StickyFlagState {
    param($R)
    switch ([string]$R.State) {
        'present' {
            $n = 0
            if (-not [int]::TryParse(([string]$R.Value).Trim(), [ref]$n)) { return @{ Kind = 'odd'; Flags = [string]$R.Value; Error = '' } }
            return @{ Kind = $(if (($n -band 0x04) -ne 0) { 'on' } else { 'off' }); Flags = [string]$n; Error = '' }
        }
        'absent' { return @{ Kind = 'default'; Flags = ''; Error = '' } }
        'nokey' { return @{ Kind = 'default'; Flags = ''; Error = '' } }
        default { return @{ Kind = 'unreadable'; Flags = ''; Error = [string]$R.Error } }
    }
}

# PURE. $Logon / $User: Read-RegValueState results. Returns @{ Lines; Hit; Gap; Deferred; State }.
function Get-StickyVerdict {
    param($Logon, $User, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $l = Get-StickyFlagState $Logon
    $u = Get-StickyFlagState $User
    $userLine = switch ($u.Kind) {
        'on' { '[INFO] This account''s own setting: the shortcut is on (Flags ' + $u.Flags + '). It applies after sign-in only; the logon screen uses the system default above.' }
        'off' { '[INFO] This account''s own setting: the shortcut is off (Flags ' + $u.Flags + ').' }
        'default' { '[INFO] This account''s own setting is not set (Windows'' default: the shortcut on, after sign-in).' }
        'odd' { '[INFO] This account''s own Flags value is not a number (' + (ConvertTo-PrintableText $u.Flags) + ').' }
        default { '[INFO] This account''s own setting could not be read (' + (ConvertTo-PrintableText $u.Error) + ').' }
    }
    $hit = $false; $gap = $false; $deferred = 0; $st = ''
    switch ($l.Kind) {
        'on' { [void]$out.Add(('[WARNING] Sticky Keys shortcut ENABLED at the logon screen (Shift x5 opens it before anyone signs in; Flags ' + $l.Flags + ' in the system default profile) (T1546.008)')); $hit = $true; $st = 'on' }
        'default' { [void]$out.Add('[WARNING] Sticky Keys shortcut ENABLED at the logon screen (Shift x5 opens it before anyone signs in; not set in the system default profile, so Windows'' default applies, which is on) (T1546.008)'); $hit = $true; $st = 'on' }
        'off' { [void]$out.Add(('[OK] Sticky Keys shortcut disabled at the logon screen (Flags ' + $l.Flags + ' in the system default profile).')); $st = 'off' }
        'odd' { [void]$out.Add(('[WARNING] Sticky Keys check NOT performed -- the logon screen''s Flags value is not a number (' + (ConvertTo-PrintableText $l.Flags) + '), so whether Shift x5 opens it there is not known (T1546.008).')); $gap = $true; $st = 'gap' }
        default {
            # Users can read HKEY_USERS\.DEFAULT on every Windows, so a refusal is
            # not explained by the token: a deny entry there is the shape of
            # tampering. A gap on any token, never a deferral.
            $why = ConvertTo-PrintableText $l.Error
            [void]$out.Add(('[WARNING] Sticky Keys check NOT performed -- the logon screen''s setting (HKEY_USERS\.DEFAULT) could not be read (' + $why + '), so a Shift x5 shortcut there would go unseen (T1546.008).'))
            $gap = $true; $st = 'gap'
        }
    }
    [void]$out.Add($userLine)
    if ($hit) { [void]$out.Add('[INFO] The shortcut alone opens only Sticky Keys; it becomes a password-free SYSTEM shell when sethc.exe has been replaced, which Section 17 checks. Turning it off removes the trigger: Settings > Accessibility > Keyboard > Sticky Keys shortcut.') }
    # The observed values ride in the state, digits or '-', so the
    # remediation's undo can put back exactly what the audit saw.
    $lf = $(if ($l.Kind -eq 'on' -or $l.Kind -eq 'off') { $l.Flags } else { '-' })
    $uf = $(if ($u.Kind -eq 'on' -or $u.Kind -eq 'off') { $u.Flags } else { '-' })
    return @{ Lines = @($out.ToArray()); Hit = $hit; Gap = $gap; Deferred = $deferred; State = ('sticky=' + $st + ',lf=' + $lf + ',uf=' + $uf) }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function Rg { param([string]$State = 'present', $Value = '510', [string]$Err = '') @{ State = $State; Value = $Value; Kind = 'String'; Error = $Err } }
    $v = Get-StickyVerdict (Rg -Value '510') (Rg -Value '506'); $t = $v.Lines -join "`n"
    T 'logon screen Flags 510 (Windows ships it): the WARNING, keeping the signature the contract test pins' ($v.Hit -and $v.State -eq 'sticky=on,lf=510,uf=506' -and $t -match '(?m)^\[WARNING\] Sticky Keys shortcut ENABLED at the logon screen' -and $t -match 'Flags 510') $t
    $v = Get-StickyVerdict (Rg -Value '506') (Rg -Value '510'); $t = $v.Lines -join "`n"
    T 'logon screen off (506) while this user has it on: [OK] -- the logon screen decides, the user line is INFO' ((-not $v.Hit) -and $v.State -eq 'sticky=off,lf=506,uf=510' -and $t -match '(?m)^\[OK\] Sticky Keys shortcut disabled at the logon screen' -and $t -match '(?m)^\[INFO\] This account''s own setting: the shortcut is on') $t
    $v = Get-StickyVerdict (Rg -State 'absent') (Rg -Value '506'); $t = $v.Lines -join "`n"
    T 'logon value absent: Windows'' default applies, which is on -- the WARNING, said so' ($v.Hit -and $t -match 'Windows'' default applies, which is on') $t
    $v = Get-StickyVerdict (Rg -State 'nokey') (Rg -State 'nokey')
    T 'logon key absent: the default-on WARNING too, and the state records it as not set (the undo removes what the fix writes)' ($v.Hit -and $v.State -eq 'sticky=on,lf=-,uf=-') ($v.Lines -join ' | ')
    $v = Get-StickyVerdict (Rg -Value 'abc') (Rg)
    T 'a Flags value that is not a number: a gap, not on or off' ($v.Gap -and -not $v.Hit -and $v.State -like 'sticky=gap,*') ($v.Lines -join ' | ')
    $v = Get-StickyVerdict (Rg -State 'unreadable' -Err 'IOException: x') (Rg); $t = $v.Lines -join "`n"
    T 'the logon key could not be read: a raised gap, never "[INFO] ... not set in registry"' ($v.Gap -and $t -match '(?m)^\[WARNING\] Sticky Keys check NOT performed -- the logon screen' -and $t -notmatch 'not set in registry' -and $t -notmatch '\[OK\]') $t
    $v = Get-StickyVerdict (Rg -State 'unreadable' -Err 'SecurityException: Requested registry access is not allowed.') (Rg) -IsElevated $false
    T 'refused to a standard-user token: a raised gap, not a deferral (Users can read HKEY_USERS\.DEFAULT; a refusal there is the tampering shape)' ($v.Gap -and $v.Deferred -eq 0 -and $v.State -like 'sticky=gap,*') ($v.Lines -join ' | ')
    $v = Get-StickyVerdict (Rg -State 'unreadable' -Err 'SecurityException: denied') (Rg) -IsElevated $true
    T 'the same refusal for an administrator: a raised gap' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-StickyVerdict (Rg -Value '506') (Rg -State 'unreadable' -Err 'x')
    T 'this user''s setting unreadable: said as INFO, never a grade' ((-not ($v.Gap -or $v.Hit)) -and ($v.Lines -join ' ') -match 'could not be read') ($v.Lines -join ' | ')
    $v = Get-StickyVerdict (Rg -Value ' 510 ') (Rg)
    T 'a value with spaces around the number still reads' ($v.Hit) ($v.Lines -join ' | ')
    $v = Get-StickyVerdict (Rg -Value ('x' + [char]10 + '[OK] Sticky Keys shortcut disabled')) (Rg)
    T 'a control character in the value cannot forge an [OK] line' ($v.Gap -and @($v.Lines | Where-Object { $_ -match '^\[OK\]' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails sticky_keys_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] sticky_keys_check self-test: the logon screen decides (HKEY_USERS\.DEFAULT), absent is Windows'' default (on), this user''s setting is INFO, and a key that could not be read is a raised gap on any token.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$logon = Read-RegValueState -KeyPath $LogonKey -Name 'Flags'
$user = Read-RegValueState -KeyPath $UserKey -Name 'Flags'
$v = $null
try { $v = Get-StickyVerdict -Logon $logon -User $user -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^sticky=(on|off|gap|deferred),lf=(\d+|-),uf=(\d+|-)$') {
    'sticky_keys_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
try {
    if ($v.Hit) { Write-Marker -Name 'sticky_hit' -Sev 'hit' }
    if ($v.Gap) { Write-Marker -Name 'sticky_gap' -Sev 'WARNING' }
    if ($v.Deferred -gt 0) { Write-Marker -Name 'sticky_deferred' -Sev ([string]$v.Deferred) }
    Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop
} catch { ('sticky_keys_check: the verdict above could not be saved for the bat (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
