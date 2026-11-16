# secure_boot_check.ps1 -- is Secure Boot on (T1542.001, pre-OS boot)? With it
# off, a bootkit loads before Windows and every check after it reads what the
# bootkit lets it read.
#
# The check was an inline block:
#   try { $sb = Confirm-SecureBootUEFI; ... } catch { '[INFO] Secure Boot
#   query not supported (may be legacy BIOS).' }
# so ANY failure -- refused, broken, or a real legacy-BIOS PC -- printed the
# same calm INFO, and "Secure Boot switched off" went unseen whenever the
# query failed. The no-admin bat skipped it on a standard-user token, although
# Windows records the state at each boot in a registry value that token reads.
#
# SOURCES, each named in the line that uses it:
#   * firmware type: kernel32 GetFirmwareType (no administrator needed);
#     1 = legacy BIOS, 2 = UEFI;
#   * Confirm-SecureBootUEFI (administrator): the firmware's own variable;
#   * HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
#     UEFISecureBootEnabled: what Windows read from the same firmware at boot.
# Elevated, Confirm-SecureBootUEFI decides and the registry is compared; on a
# standard-user token the registry decides. A difference is [INFO], never a
# grade in either direction.
#
# THE RULE (pure, in Get-SecureBootVerdict, pinned by -SelfTest):
#   on -> [OK]; off -> the WARNING the bats always printed; legacy BIOS -> the
#   INFO it always was, said as a fact; nothing answered -> a raised gap, or a
#   counted deferral when a refused standard-user token is the whole reason.
# Markers: dz_secboot_hit / dz_secboot_gap / dz_secboot_deferred, written
# before the state. State: dz_secboot_state.txt  sb=<on|off|bios|gap|deferred>
#
# Usage:
#   powershell -File tools\secure_boot_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1]
#   powershell -File tools\secure_boot_check.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # Only CI changes these: a throwaway key laid out like SecureBoot\State,
    # and a forced firmware type (0 = ask Windows), so every state runs
    # through the real readers. -NoConfirm leaves Confirm-SecureBootUEFI out.
    [string]$StateKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State',
    [int]$FirmwareType = 0,
    [switch]$NoConfirm,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_secboot_state.txt' }

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

# PURE. $Fw: 1 (BIOS), 2 (UEFI) or 0 (unknown). $Confirm: $null (not asked)
# or @{ Value = $true|$false|$null; Error; Denied }. $Reg: a Read-RegValueState
# result for UEFISecureBootEnabled. Returns @{ Lines; Hit; Gap; Deferred; State }.
function Get-SecureBootVerdict {
    param([int]$Fw, $Confirm, $Reg, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    if ($Fw -eq 1) {
        [void]$out.Add('[INFO] This PC boots in legacy BIOS mode (read by GetFirmwareType), so Secure Boot does not exist on it: nothing checks the boot loader before Windows starts. Switching to UEFI with Secure Boot is a firmware setting and needs the disk converted to GPT first.')
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 0; State = 'sb=bios' }
    }
    $regVal = $null; $regWhy = ''
    $regDenied = $false
    switch ([string]$Reg.State) {
        'present' { try { $regVal = ([int]$Reg.Value -ne 0) } catch { $regWhy = ('UEFISecureBootEnabled holds ' + (ConvertTo-PrintableText ([string]$Reg.Value)) + ', not a number') } }
        'absent' { $regWhy = 'UEFISecureBootEnabled is not set' }
        'nokey' { $regWhy = 'the SecureBoot\State key does not exist' }
        default { $regWhy = ('the SecureBoot\State key could not be read (' + (ConvertTo-PrintableText ([string]$Reg.Error)) + ')'); $regDenied = ([string]$Reg.Error -match 'SecurityException|UnauthorizedAccess') }
    }
    $cVal = $null; $cWhy = 'not asked'
    $cDenied = $false
    if ($null -ne $Confirm -and $Confirm.NotSupported -and $null -eq $regVal) {
        [void]$out.Add('[INFO] This PC''s firmware does not support Secure Boot (Confirm-SecureBootUEFI: not supported on this platform), so nothing checks the boot loader before Windows starts. It is a property of the hardware, not a setting someone turned off.')
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 0; State = 'sb=bios' }
    }
    if ($null -ne $Confirm) {
        if ($null -ne $Confirm.Value) { $cVal = [bool]$Confirm.Value }
        else { $cWhy = ('failed: ' + (ConvertTo-PrintableText ([string]$Confirm.Error))); $cDenied = [bool]$Confirm.Denied }
    }
    $val = $null; $src = ''
    if ($null -ne $cVal) { $val = $cVal; $src = 'Confirm-SecureBootUEFI, the firmware''s own setting' }
    elseif ($null -ne $regVal) { $val = $regVal; $src = 'UEFISecureBootEnabled, what Windows read from the firmware at boot' }
    if ($null -eq $val) {
        $why = ('Confirm-SecureBootUEFI ' + $cWhy + '; ' + $(if ($regWhy) { $regWhy } else { 'no registry value' }))
        $fwNote = $(if ($Fw -eq 2) { 'this PC boots in UEFI mode' } else { 'the firmware type could not be read' })
        if ((-not $IsElevated) -and $regDenied -and ($null -eq $Confirm -or $cDenied)) {
            [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] Secure Boot check: this standard-user token was refused (' + $why + ') -- an audit run as administrator reads it.'))
            return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $false; Deferred = 1; State = 'sb=deferred' }
        }
        [void]$out.Add(('[WARNING] Secure Boot check NOT performed -- ' + $fwNote + ', and its Secure Boot state could not be read (' + $why + '), so Secure Boot switched off would go unseen (T1542.001).'))
        return @{ Lines = @($out.ToArray()); Hit = $false; Gap = $true; Deferred = 0; State = 'sb=gap' }
    }
    if ($val) { [void]$out.Add('[OK] Secure Boot ENABLED.') } else { [void]$out.Add('[WARNING] Secure Boot DISABLED.') }
    [void]$out.Add(('[INFO] Read from ' + $src + '.'))
    if ($null -ne $cVal -and $null -ne $regVal -and $cVal -ne $regVal) {
        [void]$out.Add(('[INFO] The registry record disagrees: UEFISecureBootEnabled says ' + $(if ($regVal) { 'on' } else { 'off' }) + '. The two should always agree -- Secure Boot cannot change without a restart -- so a difference means the record was rewritten after boot (administrators can write it) or the firmware is in Setup Mode. The firmware''s own setting above is what is in force.'))
    }
    return @{ Lines = @($out.ToArray()); Hit = (-not $val); Gap = $false; Deferred = 0; State = $(if ($val) { 'sb=on' } else { 'sb=off' }) }
}

# Live. kernel32 GetFirmwareType: 1 BIOS, 2 UEFI; 0 when it cannot be asked.
function Get-FirmwareTypeLive {
    try {
        if (-not ('DzFirmware' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class DzFirmware { [DllImport("kernel32.dll")] public static extern bool GetFirmwareType(out uint t); }'
        }
        $t = [uint32]0
        if ([DzFirmware]::GetFirmwareType([ref]$t)) { return [int]$t }
    } catch {}
    return 0
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function Rg { param([string]$State = 'present', $Value = 1, [string]$Err = '') @{ State = $State; Value = $Value; Kind = 'DWord'; Error = $Err } }
    function Cf { param($Value = $true, [string]$Err = '', [bool]$Denied = $false, [bool]$NotSupported = $false) @{ Value = $Value; Error = $Err; Denied = $Denied; NotSupported = $NotSupported } }
    $v = Get-SecureBootVerdict 2 (Cf $true) (Rg); $t = $v.Lines -join "`n"
    T 'UEFI, the firmware says on: [OK] ENABLED, naming the source' ($v.State -eq 'sb=on' -and -not $v.Hit -and $t -match '(?m)^\[OK\] Secure Boot ENABLED\.$' -and $t -match 'Confirm-SecureBootUEFI') $t
    $v = Get-SecureBootVerdict 2 (Cf $false) (Rg -Value 0); $t = $v.Lines -join "`n"
    T 'UEFI, the firmware says off: the WARNING the bats always printed, and a hit' ($v.Hit -and $v.State -eq 'sb=off' -and $t -match '(?m)^\[WARNING\] Secure Boot DISABLED\.$') $t
    $v = Get-SecureBootVerdict 1 $null (Rg -State 'nokey'); $t = $v.Lines -join "`n"
    T 'legacy BIOS: the INFO it always was, said as a fact, nothing raised' ((-not ($v.Hit -or $v.Gap)) -and $v.State -eq 'sb=bios' -and $t -match '(?m)^\[INFO\] This PC boots in legacy BIOS mode' -and $t -notmatch 'may be') $t
    $v = Get-SecureBootVerdict 2 $null (Rg -Value 1) -IsElevated $false; $t = $v.Lines -join "`n"
    T 'a standard-user token: the registry decides, on' ($v.State -eq 'sb=on' -and $t -match 'UEFISecureBootEnabled, what Windows read') $t
    $v = Get-SecureBootVerdict 2 $null (Rg -Value 0) -IsElevated $false
    T 'a standard-user token, the registry says off: the WARNING' ($v.Hit -and $v.State -eq 'sb=off') ($v.Lines -join ' | ')
    $v = Get-SecureBootVerdict 2 (Cf $true) (Rg -Value 0); $t = $v.Lines -join "`n"
    T 'the firmware and the registry disagree: the firmware decides, the difference is INFO, never a grade' ($v.State -eq 'sb=on' -and -not $v.Hit -and $t -match '(?m)^\[INFO\] The registry record disagrees: UEFISecureBootEnabled says off') $t
    $v = Get-SecureBootVerdict 2 (Cf $null 'InvalidOperationException: x') (Rg -Value 0)
    T 'Confirm-SecureBootUEFI failed when elevated: the registry answers, and off is still the WARNING' ($v.Hit -and $v.State -eq 'sb=off' -and ($v.Lines -join ' ') -match 'UEFISecureBootEnabled, what Windows read') ($v.Lines -join ' | ')
    $v = Get-SecureBootVerdict 2 (Cf $null 'PlatformNotSupportedException: Cmdlet not supported on this platform' -NotSupported $true) (Rg -State 'absent'); $t = $v.Lines -join "`n"
    T 'UEFI firmware that does not support Secure Boot (the platform says so): INFO, a fact, not a gap' ((-not ($v.Gap -or $v.Hit)) -and $t -match 'firmware does not support Secure Boot') $t
    $v = Get-SecureBootVerdict 2 (Cf $null 'InvalidOperationException: x') (Rg -State 'absent'); $t = $v.Lines -join "`n"
    T 'UEFI and nothing answered: a raised gap, never "[INFO] ... may be legacy BIOS"' ($v.Gap -and $v.State -eq 'sb=gap' -and $t -match '(?m)^\[WARNING\] Secure Boot check NOT performed -- this PC boots in UEFI mode' -and $t -notmatch 'legacy BIOS' -and $t -notmatch '\[OK\]') $t
    $v = Get-SecureBootVerdict 0 (Cf $null 'x') (Rg -State 'unreadable' -Err 'IOException: y')
    T 'firmware type unknown and nothing answered: a gap that says the type was not read' ($v.Gap -and ($v.Lines -join ' ') -match 'firmware type could not be read') ($v.Lines -join ' | ')
    $v = Get-SecureBootVerdict 2 $null (Rg -State 'unreadable' -Err 'SecurityException: Requested registry access is not allowed.') -IsElevated $false; $t = $v.Lines -join "`n"
    T 'a standard-user token refused the key: a counted deferral, not a row' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.State -eq 'sb=deferred' -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] Secure Boot check') $t
    $v = Get-SecureBootVerdict 2 (Cf $null 'UnauthorizedAccessException: d' $true) (Rg -State 'unreadable' -Err 'SecurityException: d') -IsElevated $true
    T 'the same refusals for an administrator: a raised gap' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-SecureBootVerdict 2 $null (Rg -State 'present' -Value 'yes')
    T 'a registry value that is not a number: not graded as on or off -- a gap' ($v.Gap -and ($v.Lines -join ' ') -match 'not a number') ($v.Lines -join ' | ')
    $v = Get-SecureBootVerdict 2 (Cf $null ('bad' + [char]10 + '[OK] Secure Boot ENABLED.')) (Rg -State 'absent')
    T 'a control character in an error message cannot forge an [OK] line' ($v.Gap -and @($v.Lines | Where-Object { $_ -match '^\[OK\]' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails secure_boot_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] secure_boot_check self-test: on is [OK], off is the WARNING, legacy BIOS is INFO said as a fact, and a state nobody could read is a raised gap (or a deferral for a refused standard user), never "may be legacy BIOS".'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$fw = $(if ($FirmwareType -gt 0) { $FirmwareType } else { Get-FirmwareTypeLive })
$confirm = $null
if ($Elevated -eq 1 -and $fw -ne 1 -and -not $NoConfirm) {
    try { $confirm = @{ Value = [bool](Confirm-SecureBootUEFI -ErrorAction Stop); Error = ''; Denied = $false } }
    catch { $confirm = @{ Value = $null; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Denied = ($_.Exception -is [System.UnauthorizedAccessException]); NotSupported = ($_.Exception -is [System.PlatformNotSupportedException]) } }
}
$reg = Read-RegValueState -KeyPath $StateKey -Name 'UEFISecureBootEnabled'
$v = $null
try { $v = Get-SecureBootVerdict -Fw $fw -Confirm $confirm -Reg $reg -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^sb=(on|off|bios|gap|deferred)$') {
    'secure_boot_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
# Markers first, then the state: a marker that cannot be written leaves no
# state, and the bat raises "produced no verdict" -- never a saved state over
# a finding that did not reach the ledger.
try {
    if ($v.Hit) { Write-Marker -Name 'secboot_hit' -Sev 'hit' }
    if ($v.Gap) { Write-Marker -Name 'secboot_gap' -Sev 'WARNING' }
    if ($v.Deferred -gt 0) { Write-Marker -Name 'secboot_deferred' -Sev ([string]$v.Deferred) }
    Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop
} catch { ('secure_boot_check: the verdict above could not be saved for the bat (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
