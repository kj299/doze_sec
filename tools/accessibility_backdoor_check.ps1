# accessibility_backdoor_check.ps1 -- the login-screen backdoor checks
# (T1546.008): a Debugger planted on an accessibility binary, or the binary
# itself replaced. Pressing Shift five times or Win+U at the logon screen then
# gives a SYSTEM shell with no password.
#
#   -Part Ifeo      Section 13. The Image File Execution Options Debugger
#                   value on seven accessibility binaries.
#   -Part Binaries  Section 17. Defender's record of a past
#                   Win32/AccessibilityEscalation detection, and the
#                   signatures of the binaries themselves.
#
# Both were inline blocks, and the registry part was read THREE times (twice
# in sections, once in a dashboard tile), each with
#   Get-ItemProperty ... -Name Debugger -EA SilentlyContinue
# A key that could not be read printed "[OK] No IFEO Debugger hijacks on
# accessibility binaries." -- the same line as a key with nothing in it.
# The Defender part printed "[OK] No ... detections on record" when Defender
# could not be asked, and a MISSING sethc.exe printed nothing at all.
#
# THE RULE (pure, pinned by -SelfTest):
#   * a Debugger value present -> the CRITICAL the bats always printed;
#   * a key that does not exist, or has no Debugger value, is the ordinary
#     machine; a key that could not be READ is a raised gap that names it.
#     A hit and a gap are independent: both are raised;
#   * the registry is read ONCE (Section 13). Section 17 and the dashboard
#     state that verdict from its state line; they do not measure again;
#   * Defender's history: always asked (it keeps its record in passive
#     mode). A failed query is a raised gap when Section 9 found Defender to
#     be the active antivirus, and [INFO] not consulted otherwise. A standard-user token cannot ask at all:
#     [DEFERRED - ADMIN REQUIRED], counted, never a row;
#   * a binary whose signature is not valid Microsoft -> CRITICAL (kept).
#     A binary MISSING -> WARNING (as Section 13's signature check grades
#     it). A signature that could not be read is a gap, never a pass.
# Markers: dz_accifeo_hit / _gap ; dz_accbin_hit / _missing / _gap /
# _deferred. State files: dz_accifeo_state.txt  ifeo=<clean|hijack|gap|
# hijack+gap> ; dz_accbin_state.txt  bins=<ok|bad|missing|gap>,def=<none|
# found|na|gap|deferred>.
#
# Usage:
#   powershell -File tools\accessibility_backdoor_check.ps1 -Part Ifeo [-MarkerDir <dir>] [-StateFile <path>]
#   powershell -File tools\accessibility_backdoor_check.ps1 -Part Binaries [-IfeoState <ifeo=...>] [-DefenderMode <mode>] [-Elevated 0|1]
#   powershell -File tools\accessibility_backdoor_check.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [ValidateSet('Ifeo', 'Binaries')]
    [string]$Part,
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # Section 13's verdict and Section 9's Defender mode, as the bat holds them.
    [string]$IfeoState = '',
    [string]$DefenderMode = 'unknown',
    # Only CI changes these: a throwaway registry root and a scratch folder
    # standing in for System32, so every state runs through the real readers.
    [string]$KeyRoot = 'HKLM:',
    [string]$SystemDir,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
$script:AccBins = @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe')
# The two whose hash and signer are printed, as the old block did.
$script:MustExist = @('sethc.exe', 'utilman.exe')

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
    # A registry value or an error message goes into the report as text: no
    # control characters, and capped.
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt 300) { $t = $t.Substring(0, 300) + '...' }
    return $t
}

# PURE. $Base: the read of the IFEO key itself (it exists on every Windows).
# $Reads: @( @{ Bin; S = <Read-RegValueState result> } ).
function Get-IfeoVerdict {
    param($Base, $Reads)
    $out = New-Object System.Collections.ArrayList
    $r = @{ Hit = $false; Gap = $false }
    if ($null -eq $Base -or [string]$Base.State -eq 'unreadable' -or [string]$Base.State -eq 'nokey' -or -not [string]$Base.State) {
        $why = if ($null -ne $Base -and [string]$Base.State -eq 'nokey') { 'the key was not found, and it exists on every Windows' } elseif ($null -ne $Base -and [string]$Base.Error) { ConvertTo-PrintableText ([string]$Base.Error) } else { 'no result' }
        [void]$out.Add(('[WARNING] Accessibility IFEO check NOT performed -- the Image File Execution Options key could not be read (' + $why + '), so a Debugger planted on an accessibility binary would go unseen (T1546.008).'))
        $r.Gap = $true; $r.Lines = @($out.ToArray()); $r.State = 'ifeo=gap'; return $r
    }
    $bad = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($x in @($Reads)) {
        if ($null -eq $x) { continue }
        $seen[[string]$x.Bin] = $true
        $st = [string]$x.S.State
        if ($st -eq 'present') {
            $r.Hit = $true
            [void]$out.Add(('[CRITICAL] IFEO Debugger hijack: ' + [string]$x.Bin + ' -> ' + (ConvertTo-PrintableText ([string]$x.S.Value))))
        } elseif ($st -ne 'absent' -and $st -ne 'nokey') {
            [void]$bad.Add(([string]$x.Bin + ' (' + $(if ([string]$x.S.Error) { ConvertTo-PrintableText ([string]$x.S.Error) } else { 'no result' }) + ')'))
        }
    }
    # A binary that was never read is not a binary that is clean.
    foreach ($b in $script:AccBins) { if (-not $seen.ContainsKey($b)) { [void]$bad.Add(($b + ' (no result)')) } }
    if ($r.Hit) { [void]$out.Add('[INFO] An accessibility IFEO hijack is a SYSTEM-level login-screen backdoor. Remove the Debugger value, then find out what put it there.') }
    if ($bad.Count -gt 0) {
        $r.Gap = $true
        [void]$out.Add(('[WARNING] Accessibility IFEO check NOT performed in full -- ' + [string]$bad.Count + ' key(s) could not be read: ' + ($bad.ToArray() -join '; ') + ', so a Debugger planted there would go unseen (T1546.008).'))
    }
    if (-not ($r.Hit -or $r.Gap)) { [void]$out.Add('[OK] No IFEO Debugger hijacks on accessibility binaries.') }
    $r.Lines = @($out.ToArray())
    $r.State = if ($r.Hit -and $r.Gap) { 'ifeo=hijack+gap' } elseif ($r.Hit) { 'ifeo=hijack' } elseif ($r.Gap) { 'ifeo=gap' } else { 'ifeo=clean' }
    return $r
}

# PURE. $Ifeo: Section 13's state line. $Def: @{ State = none|found|failed|
# na|deferred; Rows; Error }. $Bins: @( @{ Name; Exists; Status; Signer;
# Hash; Error } ).
function Get-BinariesVerdict {
    param([string]$Ifeo, $Def, $Bins)
    $out = New-Object System.Collections.ArrayList
    $r = @{ Hit = $false; Missing = $false; Gap = $false; Deferred = 0 }
    # Section 13 read the registry; this states its verdict, it does not
    # measure again.
    if ($Ifeo -match '^ifeo=hijack') {
        $r.Hit = $true
        [void]$out.Add('[CRITICAL][T1546.008] IFEO Debugger hijack on an accessibility binary -- found by the check in Section 13, which lists the binary and the value.')
    } elseif ($Ifeo -eq 'ifeo=clean') {
        [void]$out.Add('[OK] No IFEO accessibility backdoor entries found (Linen/Violet Typhoon check; read once, in Section 13).')
    } else {
        [void]$out.Add('[INFO] IFEO accessibility backdoor entries: NOT graded here -- Section 13 could not read the registry keys, and raises that there.')
    }
    [void]$out.Add('')
    $defState = 'none'
    $ds = if ($null -eq $Def) { 'failed' } else { [string]$Def.State }
    if ($ds -eq 'found') {
        $r.Hit = $true; $defState = 'found'
        [void]$out.Add('[CRITICAL] Defender previously detected Win32/AccessibilityEscalation on this system.')
        foreach ($row in @($Def.Rows)) { [void]$out.Add(('    ' + (ConvertTo-PrintableText ([string]$row)))) }
    } elseif ($ds -eq 'none') {
        [void]$out.Add('[OK] No Win32/AccessibilityEscalation Defender detections on record.')
    } elseif ($ds -eq 'na') {
        $defState = 'na'
        [void]$out.Add(('[INFO] Defender detection history not consulted: Defender would not answer' + $(if ($null -ne $Def -and [string]$Def.Error) { ' (' + (ConvertTo-PrintableText ([string]$Def.Error)) + ')' } else { '' }) + ', and Section 9 did not find it to be the active antivirus on this PC. A past detection, if there was one, is NOT shown here.'))
    } elseif ($ds -eq 'deferred') {
        $defState = 'deferred'; $r.Deferred = 1
        [void]$out.Add('[DEFERRED - ADMIN REQUIRED] Get-MpThreatDetection requires admin.')
    } else {
        $defState = 'gap'; $r.Gap = $true
        $why = if ($null -ne $Def -and [string]$Def.Error) { ConvertTo-PrintableText ([string]$Def.Error) } else { 'no result' }
        [void]$out.Add(('[WARNING] Defender detection-history check NOT performed -- Defender could not be asked (' + $why + '), so a past Win32/AccessibilityEscalation detection would go unseen (T1546.008).'))
    }
    [void]$out.Add('')
    $binState = 'ok'
    $unread = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($b in @($Bins)) {
        if ($null -eq $b) { continue }
        $n = [string]$b.Name; $seen[$n] = $true
        if (-not $b.Exists) {
            # Any of the seven, as Section 13's signature check already grades it:
            # the two sections must not disagree about the same file.
            $r.Missing = $true
            [void]$out.Add(('[WARNING] ' + $n + ' is MISSING from the system directory -- Windows ships it, so something removed it (T1546.008).'))
            continue
        }
        if ([string]$b.Error) { [void]$unread.Add(($n + ' (' + (ConvertTo-PrintableText ([string]$b.Error)) + ')')); continue }
        if ($script:MustExist -contains $n) {
            [void]$out.Add(($n + ' SHA256: ' + [string]$b.Hash))
            [void]$out.Add(($n + ' Signature: ' + [string]$b.Status + ' / ' + (ConvertTo-PrintableText ([string]$b.Signer))))
        }
        if ([string]$b.Status -ne 'Valid' -or [string]$b.Signer -notmatch 'Microsoft') {
            $r.Hit = $true
            [void]$out.Add(('[CRITICAL] ' + $n + ' may have been replaced with a non-Microsoft binary! (signature: ' + [string]$b.Status + ')'))
        }
    }
    foreach ($n in $script:AccBins) { if (-not $seen.ContainsKey($n)) { [void]$unread.Add(($n + ' (no result)')) } }
    if ($unread.Count -gt 0) {
        $r.Gap = $true
        [void]$out.Add(('[WARNING] Accessibility binary signature check NOT performed in full -- ' + [string]$unread.Count + ' binary(ies) could not be read: ' + ($unread.ToArray() -join '; ') + ', so a replaced binary among them would go unseen (T1546.008).'))
    }
    $anyBad = @($out | Where-Object { $_ -match '^\[CRITICAL\] .* may have been replaced' }).Count -gt 0
    if ($anyBad) { $binState = 'bad' } elseif ($unread.Count -gt 0) { $binState = 'gap' } elseif ($r.Missing) { $binState = 'missing' }
    elseif (-not $anyBad) { [void]$out.Add('[OK] The accessibility binaries present carry a valid Microsoft signature.') }
    $r.Lines = @($out.ToArray()); $r.State = ('bins=' + $binState + ',def=' + $defState)
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
    $ok = @{ State = 'absent'; Value = $null; Error = '' }; $nok = @{ State = 'nokey'; Value = $null; Error = '' }
    $den = @{ State = 'unreadable'; Value = $null; Error = 'SecurityException: Requested registry access is not allowed.' }
    function IfeoReads { param([hashtable]$Over = @{})
        $l = @(); foreach ($b in $script:AccBins) { $l += @{ Bin = $b; S = $(if ($Over.ContainsKey($b)) { $Over[$b] } else { @{ State = 'nokey'; Value = $null; Error = '' } }) } }
        return $l
    }
    $v = Get-IfeoVerdict -Base $ok -Reads (IfeoReads); $t = $v.Lines -join "`n"
    T 'no IFEO subkey for any accessibility binary (the ordinary machine): the [OK] wording the bats always printed' ((-not ($v.Hit -or $v.Gap)) -and $v.State -eq 'ifeo=clean' -and $t -match '(?m)^\[OK\] No IFEO Debugger hijacks on accessibility binaries\.$') $t
    $v = Get-IfeoVerdict -Base $ok -Reads (IfeoReads @{ 'osk.exe' = $ok })
    T 'a subkey that exists with no Debugger value is clean too' ($v.State -eq 'ifeo=clean') ($v.Lines -join ' | ')
    $v = Get-IfeoVerdict -Base $ok -Reads (IfeoReads @{ 'sethc.exe' = @{ State = 'present'; Value = 'C:\Windows\System32\cmd.exe'; Error = '' } }); $t = $v.Lines -join "`n"
    T 'a Debugger on sethc.exe: the CRITICAL wording the harness greps, and a hit' ($v.Hit -and (-not $v.Gap) -and $v.State -eq 'ifeo=hijack' -and $t -match '(?m)^\[CRITICAL\] IFEO Debugger hijack: sethc\.exe -> C:\\Windows\\System32\\cmd\.exe$') $t
    $v = Get-IfeoVerdict -Base $ok -Reads (IfeoReads @{ 'utilman.exe' = $den }); $t = $v.Lines -join "`n"
    T 'a key that could not be read: a raised gap that names it, never "[OK] No IFEO Debugger hijacks"' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'ifeo=gap' -and $t -match '(?m)^\[WARNING\] Accessibility IFEO check NOT performed in full -- 1 key\(s\) could not be read: utilman\.exe \(' -and $t -notmatch '\[OK\]') $t
    $v = Get-IfeoVerdict -Base $ok -Reads (IfeoReads @{ 'sethc.exe' = @{ State = 'present'; Value = 'x.exe'; Error = '' }; 'utilman.exe' = $den })
    T 'a hijack AND an unreadable key: both raised -- one finding cannot hide what was not read' ($v.Hit -and $v.Gap -and $v.State -eq 'ifeo=hijack+gap') ($v.Lines -join ' | ')
    $v = Get-IfeoVerdict -Base $den -Reads (IfeoReads); $t = $v.Lines -join "`n"
    T 'the IFEO key itself unreadable: a raised gap, never an all-clear' ($v.Gap -and $v.State -eq 'ifeo=gap' -and $t -notmatch '\[OK\]') $t
    $v = Get-IfeoVerdict -Base $nok -Reads (IfeoReads)
    T 'the IFEO key itself not found (it exists on every Windows): a gap, not "nothing there"' ($v.Gap -and ($v.Lines -join ' ') -match 'exists on every Windows') ($v.Lines -join ' | ')
    $v = Get-IfeoVerdict -Base $ok -Reads @(@{ Bin = 'sethc.exe'; S = $nok })
    T 'a binary that was never read is not a binary that is clean' ($v.Gap -and ($v.Lines -join ' ') -match 'utilman\.exe \(no result\)') ($v.Lines -join ' | ')
    $v = Get-IfeoVerdict -Base $ok -Reads (IfeoReads @{ 'sethc.exe' = @{ State = 'present'; Value = ('a' + [char]10 + '[OK] fine'); Error = '' } })
    T 'a line break inside a Debugger value cannot forge an [OK] line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')

    function BinList { param([hashtable]$Over = @{})
        $l = @(); foreach ($n in $script:AccBins) { $l += $(if ($Over.ContainsKey($n)) { $Over[$n] } else { @{ Name = $n; Exists = $true; Status = 'Valid'; Signer = 'CN=Microsoft Windows, O=Microsoft Corporation'; Hash = 'AB12'; Error = '' } }) }
        return $l
    }
    $none = @{ State = 'none'; Rows = @(); Error = '' }
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def $none -Bins (BinList); $t = $v.Lines -join "`n"
    T 'everything clean: three [OK] lines, the state says so, nothing raised' ((-not ($v.Hit -or $v.Gap -or $v.Missing)) -and $v.State -eq 'bins=ok,def=none' -and $t -match '(?m)^\[OK\] No Win32/AccessibilityEscalation Defender detections on record\.$' -and $t -match 'sethc\.exe SHA256: AB12') $t
    $v = Get-BinariesVerdict -Ifeo 'ifeo=hijack' -Def $none -Bins (BinList); $t = $v.Lines -join "`n"
    T 'Section 13 found a hijack: Section 17 states it as CRITICAL and raises its row, without reading the registry again' ($v.Hit -and $t -match '(?m)^\[CRITICAL\]\[T1546\.008\] IFEO Debugger hijack on an accessibility binary') $t
    $v = Get-BinariesVerdict -Ifeo 'ifeo=gap' -Def $none -Bins (BinList); $t = $v.Lines -join "`n"
    T 'Section 13 could not read the keys: Section 17 says NOT graded, never "[OK] No IFEO accessibility backdoor"' ($t -match 'NOT graded here' -and $t -notmatch 'No IFEO accessibility backdoor entries found') $t
    $v = Get-BinariesVerdict -Ifeo '' -Def $none -Bins (BinList)
    T 'no Section 13 verdict at all: NOT graded, never clean' (($v.Lines -join ' ') -match 'NOT graded here') ($v.Lines -join ' | ')
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def @{ State = 'found'; Rows = @('Win32/AccessibilityEscalation.A  2026-10-01'); Error = '' } -Bins (BinList); $t = $v.Lines -join "`n"
    T 'a past Defender detection: the CRITICAL wording kept, and a hit' ($v.Hit -and $v.State -eq 'bins=ok,def=found' -and $t -match '(?m)^\[CRITICAL\] Defender previously detected Win32/AccessibilityEscalation on this system\.$') $t
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def @{ State = 'failed'; Rows = @(); Error = 'CimException: provider load failure' } -Bins (BinList); $t = $v.Lines -join "`n"
    T 'Defender is the active antivirus and could not be asked: a raised gap, never "[OK] No ... detections on record"' ($v.Gap -and $v.State -eq 'bins=ok,def=gap' -and $t -match '(?m)^\[WARNING\] Defender detection-history check NOT performed -- ' -and $t -notmatch 'detections on record') $t
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def @{ State = 'na'; Rows = @(); Error = '' } -Bins (BinList); $t = $v.Lines -join "`n"
    T 'Defender would not answer and is not the active antivirus: [INFO] not consulted -- neither a gap nor an all-clear' ((-not $v.Gap) -and $v.State -eq 'bins=ok,def=na' -and $t -match '\[INFO\] Defender detection history not consulted' -and $t -match 'NOT shown here' -and $t -notmatch 'detections on record') $t
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def @{ State = 'deferred'; Rows = @(); Error = '' } -Bins (BinList); $t = $v.Lines -join "`n"
    T 'a standard-user token cannot ask Defender: the deferral line the noAdmin bat always printed, counted, never a row' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $t -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] Get-MpThreatDetection requires admin\.$') $t
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def $none -Bins (BinList @{ 'sethc.exe' = @{ Name = 'sethc.exe'; Exists = $true; Status = 'NotSigned'; Signer = ''; Hash = 'CD34'; Error = '' } }); $t = $v.Lines -join "`n"
    T 'sethc.exe replaced by an unsigned binary: the CRITICAL wording kept' ($v.Hit -and $v.State -eq 'bins=bad,def=none' -and $t -match '(?m)^\[CRITICAL\] sethc\.exe may have been replaced with a non-Microsoft binary!') $t
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def $none -Bins (BinList @{ 'osk.exe' = @{ Name = 'osk.exe'; Exists = $true; Status = 'Valid'; Signer = 'CN=Evil Corp'; Hash = 'x'; Error = '' } })
    T 'a validly signed binary that is not Microsoft''s is still the finding (cmd.exe copied over it would be Microsoft''s; a third party''s is not)' ($v.Hit) ($v.Lines -join ' | ')
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def $none -Bins (BinList @{ 'utilman.exe' = @{ Name = 'utilman.exe'; Exists = $false; Status = ''; Signer = ''; Hash = ''; Error = '' } }); $t = $v.Lines -join "`n"
    T 'utilman.exe MISSING: a WARNING of its own -- the old block printed nothing' ($v.Missing -and (-not $v.Hit) -and $v.State -eq 'bins=missing,def=none' -and $t -match '(?m)^\[WARNING\] utilman\.exe is MISSING from the system directory') $t
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def $none -Bins (BinList @{ 'Narrator.exe' = @{ Name = 'Narrator.exe'; Exists = $false; Status = ''; Signer = ''; Hash = ''; Error = '' } })
    T 'Narrator.exe missing is the same WARNING Section 13 gives it: the two sections cannot disagree about one file' ($v.Missing -and ($v.Lines -join ' ') -match '\[WARNING\] Narrator\.exe is MISSING') ($v.Lines -join ' | ')
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def $none -Bins (BinList @{ 'sethc.exe' = @{ Name = 'sethc.exe'; Exists = $true; Status = ''; Signer = ''; Hash = ''; Error = 'IOException: sharing violation' } }); $t = $v.Lines -join "`n"
    T 'a signature that could not be read is a raised gap, never a pass' ($v.Gap -and $v.State -eq 'bins=gap,def=none' -and $t -match 'NOT performed in full -- 1 binary\(ies\) could not be read: sethc\.exe' -and $t -notmatch 'carry a valid Microsoft signature') $t
    $v = Get-BinariesVerdict -Ifeo 'ifeo=clean' -Def $none -Bins @()
    T 'no binary results at all is a gap, never "[OK] ... valid Microsoft signature"' ($v.Gap -and ($v.Lines -join ' ') -notmatch 'carry a valid') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails accessibility_backdoor_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] accessibility_backdoor_check self-test: a Debugger or a replaced binary keeps its CRITICAL wording; a key, a binary or Defender that could not be read is a raised gap, never an all-clear; and Section 17 states Section 13''s verdict instead of measuring again.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if (-not $Part) { 'accessibility_backdoor_check: -Part is required (Ifeo or Binaries).'; exit 1 }
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$root = ([string]$KeyRoot).TrimEnd('\')
$v = $null; $stateName = ''; $stateRx = ''
try {
    if ($Part -eq 'Ifeo') {
        $stateName = 'dz_accifeo_state.txt'; $stateRx = '^ifeo=(clean|hijack|gap|hijack\+gap)$'
        $ifeo = "$root\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $base = Read-RegValueState -KeyPath $ifeo -Name 'Debugger'
        $reads = @(); foreach ($b in $script:AccBins) { $reads += @{ Bin = $b; S = (Read-RegValueState -KeyPath (Join-Path $ifeo $b) -Name 'Debugger') } }
        $v = Get-IfeoVerdict -Base $base -Reads $reads
    } else {
        $stateName = 'dz_accbin_state.txt'; $stateRx = '^bins=(ok|bad|missing|gap),def=(none|found|na|gap|deferred)$'
        $def = $null
        if ($Elevated -ne 1) { $def = @{ State = 'deferred'; Rows = @(); Error = '' } }
        else {
            # Always ASKED: Defender keeps its history in passive mode, and a
            # detection from before another antivirus took over is exactly
            # the evidence wanted. Only a FAILED query looks at the mode.
            try {
                $d = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { [string]$_.ThreatName -match 'AccessibilityEscalation' })
                if ($d.Count -gt 0) { $def = @{ State = 'found'; Rows = @($d | ForEach-Object { ([string]$_.ThreatName + '  action succeeded: ' + [string]$_.ActionSuccess + '  first seen: ' + [string]$_.InitialDetectionTime) }); Error = '' } }
                else { $def = @{ State = 'none'; Rows = @(); Error = '' } }
            } catch {
                $err = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message)
                # Section 9 said Defender is the active antivirus: it should
                # have answered, so this is a gap. Anything else (another
                # antivirus, or a mode Section 9 could not establish): said
                # as not consulted, never as a clean history.
                $def = @{ State = $(if ($DefenderMode -eq 'Normal') { 'failed' } else { 'na' }); Rows = @(); Error = $err }
            }
        }
        $sys = $SystemDir; if (-not $sys) { $sys = Join-Path $env:SystemRoot 'System32' }
        $bins = @()
        foreach ($n in $script:AccBins) {
            $f = Join-Path $sys $n
            $b = @{ Name = $n; Exists = $false; Status = ''; Signer = ''; Hash = ''; Error = '' }
            # The folder's own listing says whether the file is there:
            # Test-Path answers "no" for a file it may not see.
            try { $b.Exists = (@([IO.Directory]::GetFiles($sys, $n)).Count -gt 0) } catch { $b.Exists = $true; $b.Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
            if ($b.Exists -and -not $b.Error) {
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $f -ErrorAction Stop
                    $b.Status = [string]$sig.Status
                    if ($sig.SignerCertificate) { $b.Signer = [string]$sig.SignerCertificate.Subject }
                    if ($script:MustExist -contains $n) { $b.Hash = [string](Get-FileHash -LiteralPath $f -Algorithm SHA256 -ErrorAction Stop).Hash }
                } catch { $b.Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
            }
            $bins += $b
        }
        $v = Get-BinariesVerdict -Ifeo $IfeoState -Def $def -Bins $bins
    }
} catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch $stateRx) {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'accessibility_backdoor_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir $stateName }
if ($Part -eq 'Ifeo') {
    if ($v.Hit) { Write-Marker -Name 'accifeo_hit' -Sev 'CRITICAL' }
    if ($v.Gap) { Write-Marker -Name 'accifeo_gap' -Sev 'WARNING' }
} else {
    if ($v.Hit) { Write-Marker -Name 'accbin_hit' -Sev 'CRITICAL' }
    if ($v.Missing) { Write-Marker -Name 'accbin_missing' -Sev 'WARNING' }
    if ($v.Gap) { Write-Marker -Name 'accbin_gap' -Sev 'WARNING' }
    if ($v.Deferred -gt 0) { Write-Marker -Name 'accbin_deferred' -Sev ([string]$v.Deferred) }
}
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('accessibility_backdoor_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
