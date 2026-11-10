# reg_policy_check.ps1 -- three registry-backed verdicts that used to be
# inline lines in both bats, each of which read a FAILED registry read as an
# answer:
#   -Check Winlogon            Section 5: Winlogon Userinit and Shell
#                              (T1547.004) and AppInit_DLLs (T1546.010).
#                              A failed AppInit read printed "[OK]
#                              AppInit_DLLs empty."; a failed Userinit/Shell
#                              read printed an unraised "[SKIPPED] not
#                              readable".
#   -Check ScriptBlockLogging  Section 11 (T1562.002). A failed read printed
#                              the finding, "NOT enabled" -- loud, but a
#                              statement the tool had not observed.
#   -Check Uac                 Section 13 (T1548.002). Both reads failing
#                              printed "[OK] UAC enabled with elevation
#                              prompt."
# The dashboard re-read all five values and disagreed with its sections (a
# failed Userinit read was "CRIT ... MODIFIED:", a failed AppInit read PASS,
# and ConsentPromptBehaviorAdmin 1, 3 or 4 "WARN not fully hardened" where
# Section 13 printed [OK]).
#
# THE RULE (pure functions, pinned by -SelfTest). The reader tells four
# states apart -- value present, value absent under a key that was read, key
# does not exist, key could not be read -- and what ABSENT means is decided
# per value, never globally:
#   Userinit, Shell     exist on every Windows. Default -> [OK]; anything
#                       else -> the CRITICAL (wording kept, dz_winlogon_hit);
#                       absent -> WARNING, value missing (dz_winlogon_missing);
#                       Winlogon key missing or unreadable -> a raised gap
#                       (dz_winlogon_gap).
#   AppInit_DLLs        (native and Wow6432Node keys) non-blank -> the
#                       CRITICAL (wording kept, dz_appinit_hit), with an
#                       [INFO] line on LoadAppInit_DLLs /
#                       RequireSignedAppInit_DLLs: context, never a downgrade;
#                       blank, absent, or no Wow6432Node key -> [OK];
#                       a key that could not be read, or the native key
#                       missing -> a raised gap (dz_appinit_gap), unless the
#                       other key already shows the finding.
#   EnableScriptBlockLogging  1 -> on; any other value, absent, or no policy
#                       key -> not configured, the existing WARNING (wording
#                       kept, dz_sbl_hit); key unreadable -> a raised gap
#                       (dz_sbl_gap).
#   EnableLUA           0 -> the CRITICAL (wording kept, dz_uac_hit); any
#                       other number -> on; absent -> the existing "value
#                       MISSING" WARNING (dz_uac_luamissing).
#   ConsentPromptBehaviorAdmin  0 -> the WARNING (wording kept,
#                       dz_uacprompt_hit); 1-5 -> prompts (5 is the Windows
#                       default; Microsoft, "User Account Control: Behavior
#                       of the elevation prompt for administrators"); absent
#                       -> the existing "value MISSING" WARNING
#                       (dz_uac_cpbmissing).
#                       Policies\System missing or unreadable, or either
#                       value not a defined number -> a raised gap
#                       (dz_uac_gap).
# HKLM is readable by a standard user, so a failed read is a gap on either
# token, never a deferral.
# State lines (commas only: the dashboard pastes them into a cmd echo):
#   dz_winlogon_state.txt  userinit=<ok|modified|missing|gap>,shell=<same>,appinit=<empty|set|gap>
#   dz_sbl_state.txt       sbl=<on|off|gap>
#   dz_uac_state.txt       uac=<on|off|noprompt|missing|gap>,cpb=<0-5|->
#
# Usage:
#   powershell -File tools\reg_policy_check.ps1 -Check <Winlogon|ScriptBlockLogging|Uac> [-MarkerDir <dir>] [-StateFile <path>]
#   powershell -File tools\reg_policy_check.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [ValidateSet('Winlogon', 'ScriptBlockLogging', 'Uac')]
    [string]$Check,
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    # Only CI changes it, to a throwaway key, so every state runs through the
    # real reader. The paths below hang off it.
    [string]$KeyRoot = 'HKLM:',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }

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
    if ($t.Length -gt 200) { $t = $t.Substring(0, 200) + '...' }
    return $t
}

# PURE. The whole number a registry value holds, or $null when it is not one.
function ConvertTo-RegNumber {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [array]) { return $null }
    $n = [long]0
    if ([long]::TryParse(([string]$Value).Trim(), [ref]$n)) { return $n }
    return $null
}

function Get-ReadFailure {
    # Why a key could not be used, as text for a gap line.
    param($S, [string]$MissingKeyText)
    if ([string]$S.State -eq 'nokey') { return $MissingKeyText }
    return (ConvertTo-PrintableText ([string]$S.Error))
}

# PURE. One Winlogon string value against its expected default.
# Returns @{ Line; Verdict = ok|modified|missing|gap }.
function Get-WinlogonValueVerdict {
    param([string]$Name, $S, [string]$Expected, [string]$DefaultText)
    switch ([string]$S.State) {
        'present' {
            $raw = [string]$S.Value
            if ($S.Value -is [array]) { $raw = (@($S.Value) -join ' ') }
            $norm = $raw.Trim().TrimEnd(',').Trim()
            if ($Expected -and $norm -ieq $Expected) { return @{ Line = ('[OK] Winlogon ' + $Name + ' is the default ' + $DefaultText + '.'); Verdict = 'ok' } }
            $shown = if ($raw.Trim()) { ConvertTo-PrintableText $raw } else { '(empty)' }
            return @{ Line = ('[CRITICAL] Winlogon ' + $Name + ' MODIFIED (T1547.004): ' + $shown); Verdict = 'modified' }
        }
        'absent' {
            return @{ Line = ('[WARNING] Winlogon ' + $Name + ' value is MISSING -- it exists on every Windows, so a deleted value is worth explaining; Windows falls back to a built-in default (T1547.004).'); Verdict = 'missing' }
        }
        default {
            return @{ Line = ('[WARNING] Winlogon ' + $Name + ' check NOT performed -- the Winlogon registry key could not be read (' + (Get-ReadFailure $S 'the key was not found, and it exists on every Windows') + '), so a hijacked ' + $Name + ' would go unseen (T1547.004).'); Verdict = 'gap' }
        }
    }
}

# PURE. $Userinit / $Shell: reader states. $AppInit: @( @{ Label; Native
# (bool); S } ), one per key. $Load / $Signed: reader states for
# LoadAppInit_DLLs / RequireSignedAppInit_DLLs on the native key (context).
# Returns @{ Lines; WlHit; WlMissing; WlGap; AiHit; AiGap; State }.
function Get-WinlogonVerdict {
    param($Userinit, $Shell, [object[]]$AppInit = @(), $Load = $null, $Signed = $null, [string]$SystemRoot = $env:SystemRoot)
    $out = New-Object System.Collections.ArrayList
    $r = @{ WlHit = $false; WlMissing = $false; WlGap = $false; AiHit = $false; AiGap = $false }
    # With no Windows directory to compare against there is no default to
    # match: Get-WinlogonValueVerdict never treats an empty expectation as met.
    $expUi = if ($SystemRoot) { (($SystemRoot.TrimEnd('\')) + '\system32\userinit.exe') } else { '' }
    $u = Get-WinlogonValueVerdict -Name 'Userinit' -S $Userinit -Expected $expUi -DefaultText 'userinit.exe'
    $s = Get-WinlogonValueVerdict -Name 'Shell' -S $Shell -Expected 'explorer.exe' -DefaultText 'explorer.exe'
    foreach ($x in @($u, $s)) {
        [void]$out.Add($x.Line)
        if ($x.Verdict -eq 'modified') { $r.WlHit = $true }
        if ($x.Verdict -eq 'missing') { $r.WlMissing = $true }
        if ($x.Verdict -eq 'gap') { $r.WlGap = $true }
    }
    $set = New-Object System.Collections.ArrayList
    $bad = New-Object System.Collections.ArrayList
    foreach ($a in @($AppInit)) {
        $st = [string]$a.S.State
        if ($st -eq 'present') {
            $v = [string]$a.S.Value
            if ($a.S.Value -is [array]) { $v = (@($a.S.Value) -join ' ') }
            if ($v.Trim()) { [void]$set.Add((ConvertTo-PrintableText $v.Trim())) }
        } elseif ($st -eq 'absent') {
        } elseif ($st -eq 'nokey' -and -not $a.Native) {
        } else {
            [void]$bad.Add(([string]$a.Label + ': ' + (Get-ReadFailure $a.S 'the key was not found, and it exists on every Windows')))
        }
    }
    $ai = 'empty'
    if ($set.Count -gt 0) {
        [void]$out.Add(('[CRITICAL] AppInit_DLLs is set (T1546.010) -- DLL loaded into every GUI process: ' + ($set.ToArray() -join '; ')))
        $ln = if ($null -ne $Load -and [string]$Load.State -eq 'present') { [string](ConvertTo-RegNumber $Load.Value) } else { 'not set' }
        $sg = if ($null -ne $Signed -and [string]$Signed.State -eq 'present') { [string](ConvertTo-RegNumber $Signed.Value) } else { 'not set' }
        [void]$out.Add(('[INFO] LoadAppInit_DLLs=' + $ln + ', RequireSignedAppInit_DLLs=' + $sg + '. Windows loads the DLLs only when LoadAppInit_DLLs is 1 (and not at all with Secure Boot on); the value being set is the finding either way.'))
        if ($bad.Count -gt 0) { [void]$out.Add(('[INFO] Not every AppInit_DLLs key could be read: ' + ($bad.ToArray() -join '; ') + '.')) }
        $r.AiHit = $true; $ai = 'set'
    } elseif ($bad.Count -gt 0 -or @($AppInit).Count -eq 0) {
        $why = if ($bad.Count -gt 0) { ($bad.ToArray() -join '; ') } else { 'no key was read' }
        [void]$out.Add(('[WARNING] AppInit_DLLs check NOT performed -- the registry key could not be read (' + $why + '), so a DLL injected into every GUI process would go unseen (T1546.010).'))
        $r.AiGap = $true; $ai = 'gap'
    } else {
        [void]$out.Add('[OK] AppInit_DLLs empty.')
    }
    $r.Lines = @($out.ToArray())
    $r.State = ('userinit=' + $u.Verdict + ',shell=' + $s.Verdict + ',appinit=' + $ai)
    return $r
}

# PURE. Returns @{ Lines; Hit; Gap; State }.
function Get-SblVerdict {
    param($S)
    $st = [string]$S.State
    if ($st -eq 'present' -and (ConvertTo-RegNumber $S.Value) -eq 1) {
        return @{ Lines = @('ScriptBlockLogging  : [OK] ENABLED (GPO)'); Hit = $false; Gap = $false; State = 'sbl=on' }
    }
    if ($st -eq 'present' -or $st -eq 'absent' -or $st -eq 'nokey') {
        # No policy key at all is the ordinary "not configured" machine.
        return @{ Lines = @('[WARNING] PS Script Block Logging NOT enabled -- PowerShell commands are not recorded to Event 4104 (T1562.002)'); Hit = $true; Gap = $false; State = 'sbl=off' }
    }
    return @{ Lines = @(('[WARNING] Script Block Logging check NOT performed -- the policy registry key could not be read (' + (ConvertTo-PrintableText ([string]$S.Error)) + '), so whether PowerShell commands are recorded cannot be stated (T1562.002).')); Hit = $false; Gap = $true; State = 'sbl=gap' }
}

# PURE. $Lua / $Cpb / $Latfp: reader states under Policies\System.
# Returns @{ Lines; Hit; Prompt; LuaMissing; CpbMissing; Gap; State }.
function Get-UacVerdict {
    param($Lua, $Cpb, $Latfp = $null)
    $out = New-Object System.Collections.ArrayList
    $r = @{ Hit = $false; Prompt = $false; LuaMissing = $false; CpbMissing = $false; Gap = $false }
    $cpbTxt = '-'
    foreach ($x in @($Lua, $Cpb)) {
        if (@('nokey', 'unreadable') -contains [string]$x.State -or -not [string]$x.State) {
            [void]$out.Add(('[WARNING] UAC check NOT performed -- the Policies\System registry key could not be read (' + (Get-ReadFailure $x 'the key was not found, and it exists on every Windows') + '), so a disabled or silent UAC would go unseen (T1548.002).'))
            $r.Gap = $true; $r.Lines = @($out.ToArray()); $r.State = 'uac=gap,cpb=-'
            return $r
        }
    }
    $luaOn = $false; $odd = New-Object System.Collections.ArrayList
    if ([string]$Lua.State -eq 'absent') {
        [void]$out.Add('[WARNING] EnableLUA registry value MISSING -- unusual on Win10/11; investigate for tampering.')
        $r.LuaMissing = $true
    } else {
        $n = ConvertTo-RegNumber $Lua.Value
        if ($null -eq $n) { [void]$odd.Add(('EnableLUA holds a value that is not a number (' + (ConvertTo-PrintableText ([string]$Lua.Value)) + ')')) }
        elseif ($n -eq 0) {
            [void]$out.Add('[CRITICAL] UAC DISABLED (EnableLUA=0) -- all processes auto-elevate silently (T1548.002)')
            $r.Hit = $true
        } else { $luaOn = $true }
    }
    $prompts = $false
    if ([string]$Cpb.State -eq 'absent') {
        [void]$out.Add('[WARNING] ConsentPromptBehaviorAdmin registry value MISSING -- unusual on Win10/11; investigate for tampering.')
        $r.CpbMissing = $true
    } else {
        $c = ConvertTo-RegNumber $Cpb.Value
        if ($null -eq $c -or $c -lt 0 -or $c -gt 5) { [void]$odd.Add(('ConsentPromptBehaviorAdmin holds a value outside 0-5 (' + (ConvertTo-PrintableText ([string]$Cpb.Value)) + ')')) }
        else {
            $cpbTxt = [string]$c
            if ($c -eq 0) {
                # With UAC off altogether the prompt setting is moot: one finding, the CRITICAL.
                if (-not $r.Hit) { [void]$out.Add('[WARNING] UAC auto-elevates without prompting (ConsentPromptBehaviorAdmin=0)'); $r.Prompt = $true }
            } else { $prompts = $true }
        }
    }
    if ($odd.Count -gt 0) {
        [void]$out.Add(('[WARNING] UAC check NOT performed in full -- ' + ($odd.ToArray() -join '; ') + ', so how this PC elevates cannot be stated (T1548.002).'))
        $r.Gap = $true
    }
    if ($luaOn -and $prompts -and $odd.Count -eq 0) { [void]$out.Add('[OK] UAC enabled with elevation prompt.') }
    if ($null -ne $Latfp) {
        if ([string]$Latfp.State -eq 'present') { [void]$out.Add(('[INFO] LocalAccountTokenFilterPolicy=' + (ConvertTo-PrintableText ([string]$Latfp.Value)) + '. At 1, local administrator accounts keep full rights over the network (remote UAC filtering is off).')) }
        elseif ([string]$Latfp.State -eq 'absent') { [void]$out.Add('[OK] LocalAccountTokenFilterPolicy not set -- default remote-admin token filtering applies.') }
    }
    $u = if ($r.Hit) { 'off' } elseif ($r.Gap) { 'gap' } elseif ($r.Prompt) { 'noprompt' } elseif ($r.LuaMissing -or $r.CpbMissing) { 'missing' } else { 'on' }
    $r.Lines = @($out.ToArray()); $r.State = ('uac=' + $u + ',cpb=' + $cpbTxt)
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
    function P { param($v, [string]$k = 'String') @{ State = 'present'; Value = $v; Kind = $k; Error = '' } }
    $abs = @{ State = 'absent'; Value = $null; Kind = ''; Error = '' }
    $nok = @{ State = 'nokey'; Value = $null; Kind = ''; Error = '' }
    $bad = @{ State = 'unreadable'; Value = $null; Kind = ''; Error = 'SecurityException: Requested registry access is not allowed.' }
    $sr = 'C:\Windows'
    $uiOk = P 'C:\Windows\system32\userinit.exe,'; $shOk = P 'explorer.exe'
    function AI { param($native, $wow) @(@{ Label = 'native'; Native = $true; S = $native }, @{ Label = 'Wow6432Node'; Native = $false; S = $wow }) }
    $aiOk = AI (P '') (P '')

    # --- Winlogon ---
    $v = Get-WinlogonVerdict -Userinit $uiOk -Shell $shOk -AppInit $aiOk -SystemRoot $sr; $t = $v.Lines -join "`n"
    T 'a clean machine: three [OK] lines with the wording the bats always printed, nothing raised' ((-not ($v.WlHit -or $v.WlMissing -or $v.WlGap -or $v.AiHit -or $v.AiGap)) -and $v.State -eq 'userinit=ok,shell=ok,appinit=empty' -and $t -match '(?m)^\[OK\] Winlogon Userinit is the default userinit\.exe\.$' -and $t -match '(?m)^\[OK\] Winlogon Shell is the default explorer\.exe\.$' -and $t -match '(?m)^\[OK\] AppInit_DLLs empty\.$') $t
    $v = Get-WinlogonVerdict -Userinit (P 'c:\WINDOWS\System32\userinit.exe') -Shell (P ' Explorer.EXE ') -AppInit $aiOk -SystemRoot $sr
    T 'Userinit in another casing with no trailing comma, Shell in another casing: still the default' ($v.State -eq 'userinit=ok,shell=ok,appinit=empty') ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit $uiOk -Shell $shOk -AppInit $aiOk -SystemRoot 'D:\WinNT\'
    T 'the default is judged against THIS Windows directory, not a hardcoded C:\Windows' ($v.WlHit -and $v.State -like 'userinit=modified,*') ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit (P 'C:\Windows\system32\userinit.exe,C:\Users\Public\evil.exe') -Shell $shOk -AppInit $aiOk -SystemRoot $sr; $t = $v.Lines -join "`n"
    T 'a second program appended to Userinit: the CRITICAL wording the bats always printed, with the value' ($v.WlHit -and $v.State -eq 'userinit=modified,shell=ok,appinit=empty' -and $t -match '(?m)^\[CRITICAL\] Winlogon Userinit MODIFIED \(T1547\.004\): C:\\Windows\\system32\\userinit\.exe,C:\\Users\\Public\\evil\.exe$') $t
    $v = Get-WinlogonVerdict -Userinit $uiOk -Shell (P 'explorer.exe, C:\ProgramData\x.exe') -AppInit $aiOk -SystemRoot $sr
    T 'a second program appended to Shell: CRITICAL' ($v.WlHit -and $v.State -eq 'userinit=ok,shell=modified,appinit=empty' -and ($v.Lines -join "`n") -match '(?m)^\[CRITICAL\] Winlogon Shell MODIFIED \(T1547\.004\): ') ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit (P '') -Shell $shOk -AppInit $aiOk -SystemRoot $sr
    T 'an EMPTY Userinit is modified, shown as (empty), never the default' ($v.WlHit -and ($v.Lines -join "`n") -match 'Userinit MODIFIED \(T1547\.004\): \(empty\)') ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit (P '') -Shell $shOk -AppInit $aiOk -SystemRoot ''
    T 'no Windows directory known: an empty Userinit still cannot match a default' ($v.WlHit -and $v.State -like 'userinit=modified,*') ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit $abs -Shell $shOk -AppInit $aiOk -SystemRoot $sr; $t = $v.Lines -join "`n"
    T 'Userinit value absent: a WARNING that it is missing, neither [OK] nor CRITICAL' ($v.WlMissing -and (-not $v.WlHit) -and (-not $v.WlGap) -and $v.State -like 'userinit=missing,*' -and $t -match '(?m)^\[WARNING\] Winlogon Userinit value is MISSING' -and $t -notmatch 'Userinit is the default') $t
    $v = Get-WinlogonVerdict -Userinit $bad -Shell $bad -AppInit $aiOk -SystemRoot $sr; $t = $v.Lines -join "`n"
    T 'the Winlogon key could not be read: two raised gaps, never [SKIPPED] and never "is the default"' ($v.WlGap -and (-not $v.WlHit) -and $v.State -eq 'userinit=gap,shell=gap,appinit=empty' -and $t -match '(?m)^\[WARNING\] Winlogon Userinit check NOT performed' -and $t -match '(?m)^\[WARNING\] Winlogon Shell check NOT performed' -and $t -notmatch '\[SKIPPED\]' -and $t -notmatch 'is the default') $t
    $v = Get-WinlogonVerdict -Userinit $nok -Shell $nok -AppInit $aiOk -SystemRoot $sr
    T 'the Winlogon key missing altogether: a gap (it exists on every Windows), not "value missing"' ($v.WlGap -and (-not $v.WlMissing) -and ($v.Lines -join "`n") -match 'exists on every Windows') ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit (P ('x' + [char]13 + [char]10 + '[OK] Winlogon Userinit is the default userinit.exe.')) -Shell $shOk -AppInit $aiOk -SystemRoot $sr
    T 'a line break inside a Userinit value cannot forge an [OK] line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] Winlogon Userinit' }).Count -eq 0 -and $v.WlHit) ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit $uiOk -Shell $shOk -AppInit (AI (P 'C:\Users\Public\evil.dll') (P '')) -Load (P 1 'DWord') -Signed (P 0 'DWord') -SystemRoot $sr; $t = $v.Lines -join "`n"
    T 'AppInit_DLLs set: the CRITICAL wording the harness greps, plus the load setting as INFO' ($v.AiHit -and $v.State -eq 'userinit=ok,shell=ok,appinit=set' -and $t -match '(?m)^\[CRITICAL\] AppInit_DLLs is set \(T1546\.010\) -- DLL loaded into every GUI process: C:\\Users\\Public\\evil\.dll$' -and $t -match '\[INFO\] LoadAppInit_DLLs=1, RequireSignedAppInit_DLLs=0') $t
    $v = Get-WinlogonVerdict -Userinit $uiOk -Shell $shOk -AppInit (AI (P '') (P 'C:\x\y.dll')) -Load (P 0 'DWord') -SystemRoot $sr
    T 'AppInit_DLLs set only under Wow6432Node, with loading switched off: still CRITICAL -- context never downgrades' ($v.AiHit -and ($v.Lines -join "`n") -match 'LoadAppInit_DLLs=0') ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit $uiOk -Shell $shOk -AppInit (AI (P '   ') $abs) -SystemRoot $sr
    T 'AppInit_DLLs blank or absent: [OK] empty' ((-not $v.AiHit) -and (-not $v.AiGap) -and $v.State -like '*,appinit=empty') ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit $uiOk -Shell $shOk -AppInit (AI (P '') $nok) -SystemRoot $sr
    T 'no Wow6432Node key (32-bit Windows): [OK], not a gap' ((-not $v.AiGap) -and $v.State -like '*,appinit=empty') ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit $uiOk -Shell $shOk -AppInit (AI $bad (P '')) -SystemRoot $sr; $t = $v.Lines -join "`n"
    T 'the native AppInit key could not be read: a raised gap, never "[OK] AppInit_DLLs empty."' ($v.AiGap -and (-not $v.AiHit) -and $v.State -like '*,appinit=gap' -and $t -match '(?m)^\[WARNING\] AppInit_DLLs check NOT performed' -and $t -notmatch 'AppInit_DLLs empty') $t
    $v = Get-WinlogonVerdict -Userinit $uiOk -Shell $shOk -AppInit (AI $nok (P '')) -SystemRoot $sr
    T 'the native AppInit key missing: a gap (it exists on every Windows)' ($v.AiGap) ($v.Lines -join ' | ')
    $v = Get-WinlogonVerdict -Userinit $uiOk -Shell $shOk -AppInit (AI $bad (P 'C:\x\y.dll')) -SystemRoot $sr; $t = $v.Lines -join "`n"
    T 'one key unreadable, the other SET: the finding, with the unread key said -- not a gap' ($v.AiHit -and (-not $v.AiGap) -and $t -match 'Not every AppInit_DLLs key could be read') $t

    # --- Script Block Logging ---
    $v = Get-SblVerdict -S (P 1 'DWord')
    T 'Script Block Logging 1: on, the line the bats always printed' ((-not $v.Hit) -and $v.State -eq 'sbl=on' -and $v.Lines[0] -eq 'ScriptBlockLogging  : [OK] ENABLED (GPO)') ($v.Lines -join ' | ')
    foreach ($c in @(@{ N = 'value 0'; S = (P 0 'DWord') }, @{ N = 'value absent'; S = $abs }, @{ N = 'no policy key (the ordinary machine)'; S = $nok })) {
        $v = Get-SblVerdict -S $c.S
        T ("Script Block Logging, {0}: the WARNING wording the bats always printed, and a hit" -f $c.N) ($v.Hit -and (-not $v.Gap) -and $v.State -eq 'sbl=off' -and $v.Lines[0] -eq '[WARNING] PS Script Block Logging NOT enabled -- PowerShell commands are not recorded to Event 4104 (T1562.002)') ($v.Lines -join ' | ')
    }
    $v = Get-SblVerdict -S $bad
    T 'the Script Block Logging key could not be read: a raised gap, not "NOT enabled" (the tool did not observe that)' ($v.Gap -and (-not $v.Hit) -and $v.State -eq 'sbl=gap' -and $v.Lines[0] -match '^\[WARNING\] Script Block Logging check NOT performed' -and ($v.Lines -join "`n") -notmatch 'NOT enabled') ($v.Lines -join ' | ')

    # --- UAC ---
    function D { param($n) P $n 'DWord' }
    $v = Get-UacVerdict -Lua (D 1) -Cpb (D 5) -Latfp $abs; $t = $v.Lines -join "`n"
    T 'UAC on with the Windows default prompt (5): [OK], nothing raised' ((-not ($v.Hit -or $v.Prompt -or $v.Gap -or $v.LuaMissing -or $v.CpbMissing)) -and $v.State -eq 'uac=on,cpb=5' -and $t -match '(?m)^\[OK\] UAC enabled with elevation prompt\.$' -and $t -match 'LocalAccountTokenFilterPolicy not set') $t
    foreach ($c in 1, 2, 3, 4) {
        $v = Get-UacVerdict -Lua (D 1) -Cpb (D $c)
        T ("ConsentPromptBehaviorAdmin {0} prompts: [OK], never the old 'not fully hardened' WARN" -f $c) ($v.State -eq ("uac=on,cpb={0}" -f $c) -and ($v.Lines -join "`n") -notmatch '\[WARNING\]') ($v.Lines -join ' | ')
    }
    $v = Get-UacVerdict -Lua (D 1) -Cpb (D 0); $t = $v.Lines -join "`n"
    T 'ConsentPromptBehaviorAdmin 0: the WARNING wording the bats always printed, never [OK]' ($v.Prompt -and (-not $v.Hit) -and $v.State -eq 'uac=noprompt,cpb=0' -and $t -match '(?m)^\[WARNING\] UAC auto-elevates without prompting \(ConsentPromptBehaviorAdmin=0\)$' -and $t -notmatch '\[OK\] UAC') $t
    $v = Get-UacVerdict -Lua (D 0) -Cpb (D 0); $t = $v.Lines -join "`n"
    T 'EnableLUA 0: the CRITICAL wording the bats always printed, and one finding, not two' ($v.Hit -and (-not $v.Prompt) -and $v.State -eq 'uac=off,cpb=0' -and $t -match '(?m)^\[CRITICAL\] UAC DISABLED \(EnableLUA=0\) -- all processes auto-elevate silently \(T1548\.002\)$' -and $t -notmatch 'auto-elevates without') $t
    $v = Get-UacVerdict -Lua $abs -Cpb (D 5); $t = $v.Lines -join "`n"
    T 'EnableLUA absent: the existing MISSING warning, and no [OK]' ($v.LuaMissing -and $v.State -eq 'uac=missing,cpb=5' -and $t -match '(?m)^\[WARNING\] EnableLUA registry value MISSING' -and $t -notmatch '\[OK\] UAC') $t
    $v = Get-UacVerdict -Lua (D 1) -Cpb $abs
    T 'ConsentPromptBehaviorAdmin absent: the existing MISSING warning, and no [OK]' ($v.CpbMissing -and $v.State -eq 'uac=missing,cpb=-' -and ($v.Lines -join "`n") -notmatch '\[OK\] UAC') ($v.Lines -join ' | ')
    $v = Get-UacVerdict -Lua $bad -Cpb $bad; $t = $v.Lines -join "`n"
    T 'Policies\System could not be read: a raised gap, never "[OK] UAC enabled" and never "value MISSING"' ($v.Gap -and (-not $v.LuaMissing) -and $v.State -eq 'uac=gap,cpb=-' -and $t -match '(?m)^\[WARNING\] UAC check NOT performed -- the Policies\\System registry key could not be read \(SecurityException' -and $t -notmatch '\[OK\]' -and $t -notmatch 'MISSING' -and $t -notmatch 'not a number') $t
    $v = Get-UacVerdict -Lua $nok -Cpb $nok
    T 'Policies\System missing altogether: a gap, not two "value MISSING" findings' ($v.Gap -and (-not $v.LuaMissing) -and (-not $v.CpbMissing)) ($v.Lines -join ' | ')
    $v = Get-UacVerdict -Lua (D 1) -Cpb (D 9); $t = $v.Lines -join "`n"
    T 'ConsentPromptBehaviorAdmin 9 (undefined): NOT performed in full, never [OK]' ($v.Gap -and $v.State -eq 'uac=gap,cpb=-' -and $t -match 'outside 0-5 \(9\)' -and $t -notmatch '\[OK\] UAC') $t
    $v = Get-UacVerdict -Lua (P 'yes') -Cpb (D 5)
    T 'EnableLUA that is not a number: NOT performed in full, never [OK]' ($v.Gap -and ($v.Lines -join "`n") -notmatch '\[OK\] UAC') ($v.Lines -join ' | ')
    $v = Get-UacVerdict -Lua (D 0) -Cpb (D 9)
    T 'EnableLUA 0 with an undefined prompt value: still the CRITICAL (state off)' ($v.Hit -and $v.State -like 'uac=off,*') ($v.Lines -join ' | ')
    $v = Get-UacVerdict -Lua (D 1) -Cpb (D 5) -Latfp (D 1)
    T 'LocalAccountTokenFilterPolicy=1 is said as INFO' (($v.Lines -join "`n") -match '\[INFO\] LocalAccountTokenFilterPolicy=1') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails reg_policy_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] reg_policy_check self-test: the existing findings keep their wording; what an absent value means is decided per value; and a key that could not be read is a raised gap for Winlogon, AppInit_DLLs, Script Block Logging and UAC, never an all-clear and never a finding the tool did not observe.'
    exit 0
}

# --- live ---------------------------------------------------------------------
if (-not $Check) { 'reg_policy_check: -Check is required (Winlogon, ScriptBlockLogging or Uac).'; exit 1 }
$root = $KeyRoot.TrimEnd('\')
$v = $null; $stateRx = ''; $stateName = ''
try {
    if ($Check -eq 'Winlogon') {
        $stateName = 'dz_winlogon_state.txt'; $stateRx = '^userinit=(ok|modified|missing|gap),shell=(ok|modified|missing|gap),appinit=(empty|set|gap)$'
        $wl = "$root\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $nat = "$root\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        $wow = "$root\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
        $ai = @(@{ Label = 'native'; Native = $true; S = (Read-RegValueState -KeyPath $nat -Name 'AppInit_DLLs') }, @{ Label = 'Wow6432Node'; Native = $false; S = (Read-RegValueState -KeyPath $wow -Name 'AppInit_DLLs') })
        $v = Get-WinlogonVerdict -Userinit (Read-RegValueState -KeyPath $wl -Name 'Userinit') -Shell (Read-RegValueState -KeyPath $wl -Name 'Shell') -AppInit $ai -Load (Read-RegValueState -KeyPath $nat -Name 'LoadAppInit_DLLs') -Signed (Read-RegValueState -KeyPath $nat -Name 'RequireSignedAppInit_DLLs')
    } elseif ($Check -eq 'ScriptBlockLogging') {
        $stateName = 'dz_sbl_state.txt'; $stateRx = '^sbl=(on|off|gap)$'
        $v = Get-SblVerdict -S (Read-RegValueState -KeyPath "$root\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name 'EnableScriptBlockLogging')
    } else {
        $stateName = 'dz_uac_state.txt'; $stateRx = '^uac=(on|off|noprompt|missing|gap),cpb=([0-5]|-)$'
        $pol = "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $v = Get-UacVerdict -Lua (Read-RegValueState -KeyPath $pol -Name 'EnableLUA') -Cpb (Read-RegValueState -KeyPath $pol -Name 'ConsentPromptBehaviorAdmin') -Latfp (Read-RegValueState -KeyPath $pol -Name 'LocalAccountTokenFilterPolicy')
    }
} catch { $v = $null }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir $stateName }
if ($null -eq $v -or [string]$v.State -notmatch $stateRx) {
    # No verdict is never a verdict: write no state, and the bat raises the
    # gap for a tool that ran without one.
    'reg_policy_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($Check -eq 'Winlogon') {
    if ($v.WlHit) { Write-Marker -Name 'winlogon_hit' -Sev 'hit' }
    if ($v.WlMissing) { Write-Marker -Name 'winlogon_missing' -Sev 'WARNING' }
    if ($v.WlGap) { Write-Marker -Name 'winlogon_gap' -Sev 'WARNING' }
    if ($v.AiHit) { Write-Marker -Name 'appinit_hit' -Sev 'hit' }
    if ($v.AiGap) { Write-Marker -Name 'appinit_gap' -Sev 'WARNING' }
} elseif ($Check -eq 'ScriptBlockLogging') {
    if ($v.Hit) { Write-Marker -Name 'sbl_hit' -Sev 'hit' }
    if ($v.Gap) { Write-Marker -Name 'sbl_gap' -Sev 'WARNING' }
} else {
    if ($v.Hit) { Write-Marker -Name 'uac_hit' -Sev 'hit' }
    if ($v.Prompt) { Write-Marker -Name 'uacprompt_hit' -Sev 'hit' }
    if ($v.LuaMissing) { Write-Marker -Name 'uac_luamissing' -Sev 'WARNING' }
    if ($v.CpbMissing) { Write-Marker -Name 'uac_cpbmissing' -Sev 'WARNING' }
    if ($v.Gap) { Write-Marker -Name 'uac_gap' -Sev 'WARNING' }
}
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('reg_policy_check: the verdict above could not be saved for the dashboard (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
