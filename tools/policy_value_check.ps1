# policy_value_check.ps1 -- the registry settings the bats read with
#   reg query "<key>" /v <name> >> "%REPORT%" 2>nul
#   if errorlevel 1 (echo [INFO] <name> not set -- ...)
# reg.exe exits 1 for "the value is not there" AND for "access denied" (and
# its error text went to 2>nul), so a setting this account could not read
# printed "[INFO] ... not set -- the default applies", and the checks built on
# the same reads printed "[OK] ... -- default." (Mark-of-the-Web) or nothing
# at all (SmartScreen off). Section 11's Module/Transcription logging read
# printed "[OK] Not configured (optional)" over -EA SilentlyContinue.
#
#   -Check PsLogging    Section 11  ModuleLogging, Transcription (T1562.002)
#   -Check LsaCfg       Section 12  LsaCfgFlags, Credential Guard (T1003.001)
#   -Check AutoRun      Section 13  NoDriveTypeAutoRun, HKLM and HKCU (T1204.002)
#   -Check Wsh          Section 13  Windows Script Host Enabled (T1059)
#   -Check MotW         Section 13  SaveZoneInformation, HKCU and HKLM (T1553.005)
#   -Check SmartScreen  Section 13  SmartScreenEnabled + EnableSmartScreen (T1562.001)
#   -Check KerbEnc      Section 17  Kerberos SupportedEncryptionTypes (T1558.003)
#
# THE RULE (pure, in Get-PolicyValueVerdict, pinned by -SelfTest): each value
# is read in four states (Read-RegValueState, the pinned shared copy):
#   present    -> the value is printed, and graded where the check grades;
#   absent     -> the "not set -- default applies" line it always printed;
#   nokey      -> the same, for a policy key no policy has created; for a key
#                 Windows always has (Lsa, Explorer) it is a gap;
#   unreadable -> "[WARNING] <check> NOT performed -- <key> could not be read"
#                 and the gap marker, never "not set" and never [OK].
# A finding beside a gap raises both.
#
# Markers (in -MarkerDir), one set per run, so the bat reads them by fixed
# name: dz_polval_hit.txt, dz_polval_gap.txt, dz_polval_done.txt (last).
#
# Usage:
#   powershell -File tools\policy_value_check.ps1 -Check <name> [-MarkerDir <dir>] [-KeyRoot <HKLM:-like root, CI only>] [-UserRoot <HKCU:-like root, CI only>]
#   powershell -File tools\policy_value_check.ps1 -SelfTest   (reads no registry)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [ValidateSet('PsLogging', 'LsaCfg', 'AutoRun', 'Wsh', 'MotW', 'SmartScreen', 'KerbEnc')]
    [string]$Check,
    [string]$MarkerDir = $env:TEMP,
    [string]$KeyRoot = 'HKLM:',
    [string]$UserRoot = 'HKCU:',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
# The bats read markers from %TEMP%. GetTempPath() reads TMP first, and the
# two differ on some machines: the default is $env:TEMP, as in every tool.
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) { New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintableText {
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]+', ' ').Trim()
    if ($t.Length -gt 300) { $t = $t.Substring(0, 300) + '...' }
    return $t
}

function ConvertTo-RegNumber {
    param($v)
    if ($null -eq $v) { return $null }
    try { return [long]$v } catch { return $null }
}

# The checks: which values, how each is labelled, and what "not set" says.
# Key: 'M' = under -KeyRoot, 'U' = under -UserRoot. NoKeyGap: the key exists on
# every Windows, so its absence is not "not configured".
$script:Checks = @{
    PsLogging   = @{ What = 'PowerShell logging policy check'; Miss = 'whether PowerShell module use and sessions are recorded cannot be stated (T1562.002)'; Values = @(
        @{ Id = 'ml'; Hive = 'M'; Key = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name = 'EnableModuleLogging'; NoKeyGap = $false; NotSet = 'ModuleLogging       : [OK] Not configured (optional)' },
        @{ Id = 'tr'; Hive = 'M'; Key = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableTranscripting'; NoKeyGap = $false; NotSet = 'Transcription       : [OK] Not configured (optional)' }) }
    LsaCfg      = @{ What = 'Credential Guard setting check'; Miss = 'whether Credential Guard is configured cannot be stated (T1003.001)'; Values = @(
        @{ Id = 'lsa'; Hive = 'M'; Key = 'SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LsaCfgFlags'; NoKeyGap = $true; NotSet = '[INFO] LsaCfgFlags not set -- Credential Guard not explicitly configured (may still be on if VBS-managed).' }) }
    AutoRun     = @{ What = 'AutoRun policy check'; Miss = 'whether AutoRun is restricted by policy cannot be stated (T1204.002)'; Values = @(
        @{ Id = 'arm'; Hive = 'M'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoDriveTypeAutoRun'; NoKeyGap = $false; NotSet = '' },
        @{ Id = 'aru'; Hive = 'U'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoDriveTypeAutoRun'; NoKeyGap = $false; NotSet = '' }); AllNotSet = '[INFO] NoDriveTypeAutoRun not pinned via policy -- default OS behavior applies.' }
    Wsh         = @{ What = 'Windows Script Host setting check'; Miss = 'whether .vbs/.js scripts can run cannot be stated (T1059)'; Values = @(
        @{ Id = 'wsh'; Hive = 'M'; Key = 'SOFTWARE\Microsoft\Windows Script Host\Settings'; Name = 'Enabled'; NoKeyGap = $false; NotSet = '[INFO] WSH Enabled value not set -- default is enabled. Disable via policy if .vbs/.js execution is not required.' }) }
    MotW        = @{ What = 'Mark-of-the-Web check'; Miss = 'whether downloads keep their zone data cannot be stated (T1553.005)'; Values = @(
        @{ Id = 'mu'; Hive = 'U'; Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name = 'SaveZoneInformation'; NoKeyGap = $false; NotSet = '' },
        @{ Id = 'mm'; Hive = 'M'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name = 'SaveZoneInformation'; NoKeyGap = $false; NotSet = '' }) }
    SmartScreen = @{ What = 'SmartScreen check'; Miss = 'whether downloaded-file reputation checks are on cannot be stated (T1562.001)'; Values = @(
        @{ Id = 'sse'; Hive = 'M'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'; Name = 'SmartScreenEnabled'; NoKeyGap = $true; NotSet = '[INFO] SmartScreenEnabled not set -- Windows Security app default applies.' },
        @{ Id = 'ssp'; Hive = 'M'; Key = 'SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableSmartScreen'; NoKeyGap = $false; NotSet = '[INFO] EnableSmartScreen policy not set -- not pinned via GPO.' }) }
    KerbEnc     = @{ What = 'Kerberos encryption-type check'; Miss = 'whether RC4 is still allowed cannot be stated (T1558.003)'; Values = @(
        @{ Id = 'krb'; Hive = 'M'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name = 'SupportedEncryptionTypes'; NoKeyGap = $false; NotSet = '[INFO] SupportedEncryptionTypes not pinned -- Kerberos uses defaults (may include RC4-HMAC). To restrict to AES, set value 0x18.' }) }
}

function Get-HiveLabel { param([string]$Hive) if ($Hive -eq 'U') { 'HKCU' } else { 'HKLM' } }

function Format-RegValue {
    param($S)
    $n = ConvertTo-RegNumber $S.Value
    # A DWORD with its top bit set comes back as a negative Int32.
    if ($null -ne $n -and [string]$S.Kind -eq 'DWord') { return ('0x{0:x}' -f ($n -band 0xFFFFFFFFL)) }
    if ($null -ne $n -and [string]$S.Kind -eq 'QWord') { return ('0x{0:x}' -f $n) }
    return (ConvertTo-PrintableText ([string]$S.Value))
}

# PURE. $States: @{ <Id> = reader state }. Returns @{ Lines; Hit; Gap }.
function Get-PolicyValueVerdict {
    param([string]$Check, $States)
    $c = $script:Checks[$Check]
    $out = New-Object System.Collections.ArrayList
    $r = @{ Hit = $false; Gap = $false }
    $unread = New-Object System.Collections.ArrayList
    $anySet = $false
    foreach ($v in $c.Values) {
        $s = $States[$v.Id]
        $label = (Get-HiveLabel $v.Hive) + '\' + $v.Key + ' /v ' + $v.Name
        $st = if ($null -eq $s) { '' } else { [string]$s.State }
        if ($st -eq 'present') {
            $anySet = $true
            if ($Check -eq 'PsLogging') {
                $on = ((ConvertTo-RegNumber $s.Value) -eq 1)
                $nm = if ($v.Id -eq 'ml') { 'ModuleLogging       ' } else { 'Transcription       ' }
                [void]$out.Add($(if ($on) { $nm + ': [OK] ENABLED (GPO)' } else { $nm + ': [OK] Not configured (optional) -- the policy value is ' + (Format-RegValue $s) }))
            } else {
                [void]$out.Add(('  ' + $label + ' = ' + (Format-RegValue $s)))
            }
            continue
        }
        if ($st -eq 'absent' -or ($st -eq 'nokey' -and -not $v.NoKeyGap)) {
            if ($v.NotSet) { [void]$out.Add($v.NotSet) }
            continue
        }
        $why = if ($st -eq 'nokey') { 'the key was not found, and it exists on every Windows' } elseif ($st -eq 'unreadable') { ConvertTo-PrintableText ([string]$s.Error) } else { 'no result' }
        [void]$unread.Add(($label + ': ' + $why))
    }
    if ($Check -eq 'AutoRun' -and -not $anySet -and $unread.Count -eq 0) { [void]$out.Add($c.AllNotSet) }
    if ($Check -eq 'MotW') {
        $off = $false
        # AttachmentManager.admx, "Do not preserve zone information in file
        # attachments": Enabled writes 1 (downloads are NOT marked), Disabled
        # writes 2 (they are). Microsoft's Policy CSP page states what Enabled
        # means. This check used to read 2 as the off value: the protective
        # setting raised, and the common "SaveZoneInformation=1" tweak that
        # silences "This file came from another computer" read [OK].
        foreach ($id in 'mu', 'mm') { $s = $States[$id]; if ($s -and [string]$s.State -eq 'present' -and (ConvertTo-RegNumber $s.Value) -eq 1) { $off = $true } }
        if ($off) {
            [void]$out.Add('[WARNING] SaveZoneInformation=1 -- Mark-of-the-Web is NOT recorded on downloads (the policy "Do not preserve zone information" is enabled). SmartScreen and Office macro MOTW protections are blinded.')
            $r.Hit = $true
        } elseif ($unread.Count -eq 0) {
            [void]$out.Add('[OK] Mark-of-the-Web zone data preserved on downloaded files -- default.')
        }
    }
    if ($Check -eq 'SmartScreen') {
        $off = $false
        $e = $States['sse']; if ($e -and [string]$e.State -eq 'present' -and ([string]$e.Value).Trim() -ieq 'Off') { $off = $true }
        $p = $States['ssp']; if ($p -and [string]$p.State -eq 'present' -and (ConvertTo-RegNumber $p.Value) -eq 0) { $off = $true }
        if ($off) { [void]$out.Add('[WARNING] SmartScreen is OFF -- downloaded-file reputation checks are disabled.'); $r.Hit = $true }
    }
    if ($unread.Count -gt 0) {
        [void]$out.Add(('[WARNING] ' + $c.What + ' NOT performed' + $(if ($unread.Count -lt @($c.Values).Count) { ' in full' } else { '' }) + ' -- ' + ($unread.ToArray() -join '; ') + ', so ' + $c.Miss + '.'))
        $r.Gap = $true
    }
    $r.Lines = @($out.ToArray())
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
    function P { param($V, $K = 'DWord') @{ State = 'present'; Value = $V; Kind = $K; Error = '' } }
    $A = @{ State = 'absent'; Value = $null; Kind = ''; Error = '' }
    $N = @{ State = 'nokey'; Value = $null; Kind = ''; Error = '' }
    $U = @{ State = 'unreadable'; Value = $null; Kind = ''; Error = 'SecurityException: Requested registry access is not allowed.' }
    function V { param([string]$C, $St) $v = Get-PolicyValueVerdict -Check $C -States $St; @{ V = $v; T = ($v.Lines -join "`n") } }

    $x = V 'LsaCfg' @{ lsa = $A }
    T 'LsaCfgFlags absent: the [INFO] not-set line the bats always printed, no gap' ((-not $x.V.Gap) -and $x.T -match '^\[INFO\] LsaCfgFlags not set -- ') $x.T
    $x = V 'LsaCfg' @{ lsa = $U }
    T 'LsaCfgFlags unreadable: a raised gap, never "not set" (the defect: reg.exe exits 1 for denied too)' ($x.V.Gap -and $x.T -match '^\[WARNING\] Credential Guard setting check NOT performed -- HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LsaCfgFlags: SecurityException' -and $x.T -notmatch 'not set') $x.T
    $x = V 'LsaCfg' @{ lsa = $N }
    T 'the Lsa key missing is a gap: it exists on every Windows' ($x.V.Gap -and $x.T -match 'the key was not found, and it exists on every Windows') $x.T
    $x = V 'LsaCfg' @{ lsa = (P 1) }
    T 'LsaCfgFlags present: the value is printed' ((-not $x.V.Gap) -and $x.T -match 'LsaCfgFlags = 0x1$') $x.T
    $x = V 'KerbEnc' @{ krb = $N }
    T 'a policy key no policy created is "not configured", never a gap' ((-not $x.V.Gap) -and $x.T -match '^\[INFO\] SupportedEncryptionTypes not pinned') $x.T
    $x = V 'AutoRun' @{ arm = $N; aru = $A }
    T 'AutoRun pinned nowhere: the one [INFO] line' ((-not $x.V.Gap) -and $x.T -eq '[INFO] NoDriveTypeAutoRun not pinned via policy -- default OS behavior applies.') $x.T
    $x = V 'AutoRun' @{ arm = $U; aru = $A }
    T 'AutoRun with HKLM unreadable: a gap "in full", and no "not pinned" line over it' ($x.V.Gap -and $x.T -match 'AutoRun policy check NOT performed in full' -and $x.T -notmatch 'not pinned') $x.T
    $x = V 'MotW' @{ mu = $A; mm = $N }
    T 'MotW default: the [OK] the bats printed' ((-not ($x.V.Hit -or $x.V.Gap)) -and $x.T -match '^\[OK\] Mark-of-the-Web zone data preserved') $x.T
    $x = V 'MotW' @{ mu = (P 1); mm = $A }
    T 'MotW off (SaveZoneInformation=1, "do not preserve" enabled): the WARNING and a hit' ($x.V.Hit -and $x.T -match '(?m)^\[WARNING\] SaveZoneInformation=1 -- ' -and $x.T -notmatch '\[OK\]') $x.T
    $x = V 'MotW' @{ mu = $U; mm = $U }
    T 'MotW with both keys unreadable: a gap, never "[OK] ... -- default."' ($x.V.Gap -and -not $x.V.Hit -and $x.T -notmatch '\[OK\]' -and $x.T -match 'Mark-of-the-Web check NOT performed -- ') $x.T
    $x = V 'MotW' @{ mu = (P 1); mm = $U }
    T 'MotW off with the other key unreadable: the hit AND the gap' ($x.V.Hit -and $x.V.Gap) $x.T
    $x = V 'MotW' @{ mu = (P 2); mm = $A }
    T 'SaveZoneInformation=2 (the policy disabled: zone data preserved) is not a hit' ((-not $x.V.Hit) -and $x.T -match '\[OK\]') $x.T
    $x = V 'SmartScreen' @{ sse = (P 'Off' 'String'); ssp = $N }
    T 'SmartScreenEnabled=Off: the WARNING and a hit' ($x.V.Hit -and $x.T -match '(?m)^\[WARNING\] SmartScreen is OFF') $x.T
    $x = V 'SmartScreen' @{ sse = (P 'Warn' 'String'); ssp = (P 0) }
    T 'EnableSmartScreen=0 by policy: a hit' ($x.V.Hit) $x.T
    $x = V 'SmartScreen' @{ sse = $U; ssp = $U }
    T 'SmartScreen with both reads failing: a raised gap (the old test printed nothing at all)' ($x.V.Gap -and -not $x.V.Hit -and $x.T -match 'SmartScreen check NOT performed -- ') $x.T
    $x = V 'SmartScreen' @{ sse = (P 'RequireAdmin' 'String'); ssp = $N }
    T 'SmartScreen RequireAdmin, no policy: neither a hit nor a gap' ((-not ($x.V.Hit -or $x.V.Gap)) -and $x.T -match 'EnableSmartScreen policy not set') $x.T
    $x = V 'PsLogging' @{ ml = $N; tr = (P 1) }
    T 'PS logging: not configured and enabled read as the bats printed them' ((-not $x.V.Gap) -and $x.T -match '(?m)^ModuleLogging       : \[OK\] Not configured \(optional\)$' -and $x.T -match '(?m)^Transcription       : \[OK\] ENABLED \(GPO\)$') $x.T
    $x = V 'PsLogging' @{ ml = $U; tr = $N }
    T 'PS logging unreadable: a gap, never "[OK] Not configured" for that value' ($x.V.Gap -and $x.T -notmatch 'ModuleLogging       : \[OK\]' -and $x.T -match 'PowerShell logging policy check NOT performed in full') $x.T
    $x = V 'Wsh' @{ wsh = (P '0' 'String') }
    T 'WSH Enabled=0 is printed' ($x.T -match 'Enabled = 0$') $x.T
    $x = V 'KerbEnc' @{ krb = (P -2147483620) }
    T 'a DWORD with its top bit set prints as the 32-bit value' ($x.T -match '= 0x8000001c$') $x.T
    $x = V 'KerbEnc' @{ krb = @{ State = 'unreadable'; Value = $null; Kind = ''; Error = ('bad' + [char]10 + '[OK] fine') } }
    T 'an error text cannot forge a line' ($x.T -notmatch '(?m)^\[OK\] fine') $x.T
    if ($fails) { Write-Output "[FAIL] $fails policy_value_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] policy_value_check self-test: a value that is not set says so as before; a key that could not be read is a raised gap, never "not set" and never [OK]; Mark-of-the-Web and SmartScreen off are still the findings.'
    exit 0
}

if (-not $Check) { 'policy_value_check: -Check is required.'; exit 1 }
foreach ($n in 'hit', 'gap', 'done') { Remove-Item -LiteralPath (Join-Path $MarkerDir ("dz_polval_{0}.txt" -f $n)) -Force -EA SilentlyContinue }
$c = $script:Checks[$Check]
$states = @{}
foreach ($v in $c.Values) {
    $root = if ($v.Hive -eq 'U') { $UserRoot.TrimEnd('\') } else { $KeyRoot.TrimEnd('\') }
    $states[$v.Id] = Read-RegValueState -KeyPath ($root + '\' + $v.Key) -Name $v.Name
}
$r = Get-PolicyValueVerdict -Check $Check -States $states
foreach ($l in $r.Lines) { $l }
if ($r.Hit) { Write-Marker -Name 'polval_hit' -Sev 'hit' }
if ($r.Gap) { Write-Marker -Name 'polval_gap' -Sev 'WARNING' }
Write-Marker -Name 'polval_done' -Sev 'done'
exit 0
