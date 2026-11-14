# office_macro_check.ps1 -- Section 13, Office macro policy (T1204.002).
#
# The inline block it replaces read every value with -EA SilentlyContinue and
# skipped an Office version whose key Test-Path could not see. A key this
# account could not read was therefore "not set", and the block printed
# "[INFO] No explicit per-app macro settings found ... defaults apply" --
# reassurance about settings it had never read. It also read only two of the
# three places Office takes the setting from, and five of the seven
# applications Microsoft's internet-macro block covers.
#
# THE RULE (pure functions, pinned by -SelfTest).
#   SOURCES, in the order Office applies them (Microsoft, "Overview of Cloud
#   Policy service for Microsoft 365": Cloud Policy settings are stored under
#   HKCU\Software\Policies\Microsoft\Cloud\Office\16.0 and "take precedence
#   over policy settings implemented by using Group Policy ... and over ...
#   locally applied policy settings"):
#     Cloud Policy (16.0 only) > Group Policy (Policies\Microsoft\Office) >
#     the user's own setting (Microsoft\Office\<ver>\<app>\Security).
#   The first source that HOLDS the value decides, and the line names it. A
#   lower source that disagrees is [INFO], never a grade, in either direction:
#   it is not in force.
#   A source above the deciding one that could not be read means the setting
#   in force is unknown: a raised gap (dz_macro_gap), never a default.
#   VBAWarnings: 1 = all macros run with no prompt -> WARNING (dz_macro_hit);
#     2 (the default), 3, 4 -> [OK]; any other value -> WARNING, a value Office
#     does not define.
#   blockcontentexecutionfrominternet: 1 -> [OK] blocked; 0 -> WARNING, the
#     block on macros in files from the internet is turned off; any other
#     value -> WARNING.
#   Nothing set anywhere -> Office's defaults: macros disabled with
#   notification, and macros in files from the internet blocked in Microsoft
#   365 Apps (rolled out 2022-2024, by app and update channel). Office 2013 and 2010 settings (15.0, 14.0) predate that
#   block, and the line says so.
#   VERSIONS are those present under ANY of the three roots, so a policy
#   written for an Office that has not been started yet is still read. A root
#   that does not exist is an answer; one that could not be listed is a gap.
#
# The settings are per user. The audit's own account is read through HKCU and
# named. Every OTHER account signed in at this PC (the owners of explorer.exe)
# is read through HKEY_USERS\<SID>, and its lines name it: an elevated audit is
# often run from a separate administrator account, and the settings that
# protect the person at this PC are theirs. A signed-in account whose registry
# could not be opened is a raised gap; a desktop session whose account this
# token cannot identify (a standard-user token cannot) is [INFO].
#
# Markers (in -MarkerDir): dz_macro_hit.txt, dz_macro_gap.txt,
# dz_macro_deferred.txt (a count, for DEFERRED_COUNT: another account's
# registry refused to a standard-user token), and dz_macro_done.txt when the
# tool reached its end (the bat raises "produced no verdict" without it).
#
# Usage:
#   powershell -File tools\office_macro_check.ps1 [-MarkerDir <dir>]
#   powershell -File tools\office_macro_check.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    # Only CI changes it, to a throwaway key, so every state runs through the
    # real reader. The three roots hang off it.
    [string]$KeyRoot = 'HKCU:\Software',
    # CI only: more roots read as if each were another signed-in account.
    [string[]]$OtherKeyRoot = @(),
    # 1/0 from the caller, or -1: ask the token.
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }

# The seven applications Microsoft's internet-macro block covers ("Macros from
# the internet are blocked by default in Office"). Outlook is not one of them,
# and its own macro setting is a different value (Level) whose registry
# meanings Microsoft does not document; grading it would be a guess.
$script:Apps = @('Word', 'Excel', 'PowerPoint', 'Access', 'Publisher', 'Visio', 'MS Project')
$script:Versions = @('16.0', '15.0', '14.0')
$script:VbaText = @{ 2 = 'macros disabled with notification, the default'; 3 = 'only digitally signed macros run'; 4 = 'all macros disabled without notification' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
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

# Live. Four states, never two: absent under a key that was read, key missing,
# key unreadable, value present.
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

# PURE. One value for one app across its sources, highest first.
# $Sources: @( @{ Name; S = <Read-RegValueState result> } ). Returns
# @{ Decided = $true|$false; Gap = '' | <why>; From; Value; Others = @(@{From;Value}) }.
function Select-InForce {
    param($Sources)
    $r = @{ Decided = $false; Gap = ''; From = ''; Value = $null; Others = @() }
    $others = New-Object System.Collections.ArrayList
    foreach ($x in @($Sources)) {
        $st = [string]$x.S.State
        if ($r.Decided) {
            if ($st -eq 'present') { [void]$others.Add(@{ From = [string]$x.Name; Value = $x.S.Value }) }
            continue
        }
        if ($st -eq 'present') { $r.Decided = $true; $r.From = [string]$x.Name; $r.Value = $x.S.Value; continue }
        if ($st -eq 'absent' -or $st -eq 'nokey') { continue }
        # Unreadable, or no state at all: what is in force is unknown.
        $r.Gap = ([string]$x.Name + ' could not be read (' + (ConvertTo-PrintableText ([string]$x.S.Error)) + ')')
        $r.Others = @($others.ToArray()); return $r
    }
    $r.Others = @($others.ToArray())
    return $r
}

# PURE. $Reads: @( @{ App; Ver; Vba = <sources>; Blk = <sources> } ), one per
# app and version. $Roots: @( @{ Name; State = ok|nokey|unreadable; Error } ).
# $Owner: '' for the account this audit ran as, else the other signed-in
# account these settings belong to (named on every line that grades).
# $Context (own account only): @{ Account; Others = @(names read too);
# Unresolved = <desktop sessions whose account this token could not tell> }.
# $IsElevated: another account's registry refused to a standard-user token is
# the token's limit, not the machine's -- a deferral, never a gap or a row.
# Returns @{ Lines; Hit; Gap; Deferred; Examined; Read }.
function Get-MacroVerdict {
    param($Reads, $Roots, $Context = $null, [string]$Owner = '', [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $gaps = New-Object System.Collections.ArrayList
    $r = @{ Hit = $false; Gap = $false; Deferred = 0; Examined = 0; Read = 0 }
    if ($Owner -and -not $IsElevated -and @($Roots | Where-Object { [string]$_.State -eq 'denied' }).Count) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] Office macro settings of ' + (ConvertTo-PrintableText $Owner) + ', also signed in at this PC, not read: another account''s registry needs administrator.'))
        $r.Deferred = 1; $r.Lines = @($out.ToArray()); return $r
    }
    $who = $(if ($Owner) { ' (settings of ' + (ConvertTo-PrintableText $Owner) + ')' } else { '' })
    if ($Context -and $Context.Account) {
        [void]$out.Add(('[INFO] These are the Office settings of ' + (ConvertTo-PrintableText ([string]$Context.Account)) + ', the account this audit ran as.'))
        foreach ($o in @($Context.Others | Where-Object { [string]$_ })) { [void]$out.Add(('[INFO] ' + (ConvertTo-PrintableText ([string]$o)) + ' is also signed in at this PC: its Office settings follow, on the lines that name it.')) }
    }
    # A session whose account could not be told: the token explains it only
    # when it is a standard user's. As administrator it is a gap.
    $unres = $(if ($Context) { [int]$Context.Unresolved } else { 0 })
    if ($unres -gt 0 -and $IsElevated) { [void]$gaps.Add(([string]$unres + ' desktop session(s) at this PC belong to an account that could not be identified, so their Office settings were not read')) }
    elseif ($unres -gt 0) { [void]$out.Add(('[INFO] ' + $unres + ' desktop session(s) at this PC belong to an account this token could not identify, so their Office settings were not read. An audit run as administrator reads them.')) }
    # The process list failing is not the token (any account may list
    # processes): the other signed-in accounts are unknown, a gap.
    if ($Context -and [string]$Context.ListError) { [void]$gaps.Add(('not every account signed in at this PC could be listed (' + (ConvertTo-PrintableText ([string]$Context.ListError)) + '), so some accounts'' Office settings may not have been read')) }
    foreach ($x in @($Roots)) { if ([string]$x.State -ne 'ok' -and [string]$x.State -ne 'nokey') { [void]$gaps.Add(([string]$x.Name + ' could not be listed (' + (ConvertTo-PrintableText ([string]$x.Error)) + ')')) } }
    $explicit = 0
    $vers = New-Object System.Collections.ArrayList
    foreach ($a in @($Reads)) {
        if (-not $vers.Contains([string]$a.Ver)) { [void]$vers.Add([string]$a.Ver) }
        $tag = ([string]$a.App + ' ' + [string]$a.Ver + $who)
        foreach ($kind in 'Vba', 'Blk') {
            $r.Examined++
            $name = $(if ($kind -eq 'Vba') { 'VBAWarnings' } else { 'blockcontentexecutionfrominternet' })
            $p = Select-InForce $a[$kind]
            if ($p.Gap) { [void]$gaps.Add(($tag + ' ' + $name + ': ' + $p.Gap)); continue }
            $r.Read++
            if (-not $p.Decided) { continue }
            $explicit++
            $n = ConvertTo-RegNumber $p.Value
            $shown = ConvertTo-PrintableText ([string]$p.Value)
            $src = ('set by ' + $p.From)
            if ($kind -eq 'Vba') {
                if ($n -eq 1) { [void]$out.Add(('[WARNING] ' + $tag + ': VBAWarnings=1 (' + $src + ') -- ALL macros run with no prompt, so a macro in any document runs the moment it is opened (T1204.002).')); $r.Hit = $true }
                elseif ($null -ne $n -and $n -ge 2 -and $n -le 4) { [void]$out.Add(('[OK] ' + $tag + ': VBAWarnings=' + $n + ' (' + $src + ') -- ' + $script:VbaText[[int]$n] + '.')) }
                else { [void]$out.Add(('[WARNING] ' + $tag + ': VBAWarnings holds a value Office does not define (' + $shown + ', ' + $src + ') -- investigate for tampering (T1204.002).')); $r.Hit = $true }
            } else {
                if ($n -eq 1) { [void]$out.Add(('[OK] ' + $tag + ': macros in files from the internet are blocked (blockcontentexecutionfrominternet=1, ' + $src + ').')) }
                elseif ($n -eq 0) { [void]$out.Add(('[WARNING] ' + $tag + ': blockcontentexecutionfrominternet=0 (' + $src + ') -- the block on macros in files from the internet is turned OFF, so a macro in a downloaded document or email attachment can be enabled (T1204.002).')); $r.Hit = $true }
                else { [void]$out.Add(('[WARNING] ' + $tag + ': blockcontentexecutionfrominternet holds a value Office does not define (' + $shown + ', ' + $src + ') -- investigate for tampering (T1204.002).')); $r.Hit = $true }
            }
            foreach ($o in @($p.Others)) {
                $ov = ConvertTo-PrintableText ([string]$o.Value)
                if ($ov -ne $shown) { [void]$out.Add(('[INFO] ' + $tag + ': ' + $o.From + ' holds ' + $name + '=' + $ov + ', but ' + $p.From + ' sets ' + $shown + ', which is in force.')) }
            }
        }
    }
    foreach ($old in @('15.0', '14.0')) {
        if ($vers.Contains($old)) { [void]$out.Add(('[INFO] Office ' + $(if ($old -eq '15.0') { '2013' } else { '2010' }) + ' (' + $old + ') settings are present' + $who + ': that version predates Microsoft''s default block of macros in files from the internet, and no longer receives security updates.')) }
    }
    if ($gaps.Count -gt 0) {
        $names = (@($gaps | Select-Object -First 3) -join '; ') + $(if ($gaps.Count -gt 3) { ('; and ' + ($gaps.Count - 3) + ' more') } else { '' })
        [void]$out.Add(('[WARNING] Office macro policy check NOT performed' + $(if ($r.Read -gt 0) { ' in full' } else { '' }) + ' -- ' + $names + ', so a setting that lets macros in malicious documents run would go unseen (T1204.002).'))
        $r.Gap = $true
    }
    $vlist = (@($vers.ToArray()) -join ', ')
    if (-not $r.Hit -and -not $r.Gap) {
        if ($vers.Count -eq 0) { [void]$out.Add($(if ($Owner) { ('[OK] No Office settings for ' + (ConvertTo-PrintableText $Owner) + ' (Office has never been started by that account): Office''s defaults apply.') } else { '[OK] No Office settings for this account (Office is not installed, or has never been started by it): Office''s defaults apply.' })) }
        else { [void]$out.Add(('[OK] No Office macro setting weakens protection' + $(if ($Owner) { ' for ' + (ConvertTo-PrintableText $Owner) } else { '' }) + ': ' + $r.Read + ' setting(s) read for Office ' + $vlist + ', ' + $explicit + ' set explicitly. Where nothing is set, Office''s defaults apply: macros disabled with notification, and, in Microsoft 365 Apps updated since 2022-2024 (the date depends on the app and update channel), macros in files from the internet blocked.')) }
    } elseif (-not $r.Hit -and $r.Read -gt 0) {
        [void]$out.Add(('[INFO] Nothing weakening was found in what could be read' + $who + ': ' + $r.Read + ' setting(s) for Office ' + $vlist + '.'))
    }
    $r.Lines = @($out.ToArray())
    return $r
}

# PURE. One verdict per account, merged: the lines in order, a hit or a gap
# from any account raises.
function Merge-AccountVerdicts {
    param($Verdicts)
    $m = @{ Lines = (New-Object System.Collections.ArrayList); Hit = $false; Gap = $false; Deferred = 0 }
    foreach ($v in @($Verdicts)) {
        if ($null -eq $v) { continue }
        foreach ($l in @($v.Lines)) { [void]$m.Lines.Add($l) }
        if ($v.Hit) { $m.Hit = $true }
        if ($v.Gap) { $m.Gap = $true }
        $m.Deferred += [int]$v.Deferred
    }
    $m.Lines = @($m.Lines.ToArray())
    return $m
}

# Live. Which version keys exist under one root. @{ State = ok|nokey|unreadable; Error; Names }.
function Read-VersionList {
    param([string]$Path)
    try { $k = Get-Item -LiteralPath $Path -ErrorAction Stop }
    catch {
        if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { return @{ State = 'nokey'; Error = ''; Names = @() } }
        $den = ($_.Exception -is [System.Security.SecurityException] -or $_.Exception -is [System.UnauthorizedAccessException])
        return @{ State = $(if ($den) { 'denied' } else { 'unreadable' }); Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Names = @() }
    }
    try { return @{ State = 'ok'; Error = ''; Names = @($k.GetSubKeyNames() | Where-Object { $script:Versions -contains [string]$_ }) } }
    catch { return @{ State = 'unreadable'; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Names = @() } }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $P = { param($v) @{ State = 'present'; Value = $v; Kind = 'DWord'; Error = '' } }
    $A = @{ State = 'absent'; Value = $null; Kind = ''; Error = '' }
    $N = @{ State = 'nokey'; Value = $null; Kind = ''; Error = '' }
    $U = @{ State = 'unreadable'; Value = $null; Kind = ''; Error = 'SecurityException: Requested registry access is not allowed.' }
    function Src { param($c, $g, $u) @(@{ Name = 'Cloud Policy'; S = $c }, @{ Name = 'Group Policy'; S = $g }, @{ Name = 'the user setting'; S = $u }) }
    function One { param($vba, $blk, [string]$ver = '16.0', [string]$app = 'Word') @{ App = $app; Ver = $ver; Vba = $vba; Blk = $blk } }
    $okRoots = @(@{ Name = 'Office'; State = 'ok' }, @{ Name = 'Group Policy'; State = 'nokey' }, @{ Name = 'Cloud Policy'; State = 'nokey' })
    $none = Src $N $N $N
    function V { param($reads, $roots = $okRoots, $ctx = $null) $v = Get-MacroVerdict -Reads $reads -Roots $roots -Context $ctx; $v.Text = ($v.Lines -join "`n"); return $v }

    $v = V @(One $none $none)
    T 'nothing set anywhere: [OK], defaults named, no marker' ((-not $v.Hit) -and (-not $v.Gap) -and $v.Text -match '(?m)^\[OK\] No Office macro setting weakens protection: 2 setting\(s\) read for Office 16\.0, 0 set explicitly') $v.Text
    $v = V @() @(@{ Name = 'Office'; State = 'nokey' }, @{ Name = 'Group Policy'; State = 'nokey' }, @{ Name = 'Cloud Policy'; State = 'nokey' })
    T 'no Office key at all: [OK] no Office settings for this account' ((-not $v.Hit) -and (-not $v.Gap) -and $v.Text -match '(?m)^\[OK\] No Office settings for this account') $v.Text
    $v = V @(One (Src $N $N (& $P 1)) $none)
    T 'the user setting VBAWarnings=1: the WARNING, naming the source' ($v.Hit -and $v.Text -match '(?m)^\[WARNING\] Word 16\.0: VBAWarnings=1 \(set by the user setting\) -- ALL macros run with no prompt' -and $v.Text -notmatch '(?m)^\[OK\]') $v.Text
    $v = V @(One (Src $N (& $P 2) (& $P 1)) $none)
    T 'Group Policy 2 over a user 1: [OK] in force, the user value is [INFO], never a grade' ((-not $v.Hit) -and $v.Text -match '(?m)^\[OK\] Word 16\.0: VBAWarnings=2 \(set by Group Policy\)' -and $v.Text -match '(?m)^\[INFO\] Word 16\.0: the user setting holds VBAWarnings=1, but Group Policy sets 2, which is in force') $v.Text
    $v = V @(One (Src (& $P 1) (& $P 4) $N) $none)
    T 'Cloud Policy 1 over Group Policy 4: the WARNING -- Cloud Policy takes precedence' ($v.Hit -and $v.Text -match 'VBAWarnings=1 \(set by Cloud Policy\)' -and $v.Text -match '(?m)^\[INFO\] Word 16\.0: Group Policy holds VBAWarnings=4, but Cloud Policy sets 1') $v.Text
    $v = V @(One $none (Src $N (& $P 0) $N))
    T 'Group Policy blockcontentexecutionfrominternet=0: the WARNING (block turned off)' ($v.Hit -and $v.Text -match '(?m)^\[WARNING\] Word 16\.0: blockcontentexecutionfrominternet=0 \(set by Group Policy\) -- the block on macros in files from the internet is turned OFF') $v.Text
    $v = V @(One $none (Src $N (& $P 1) $N))
    T 'blockcontentexecutionfrominternet=1: [OK] blocked' ((-not $v.Hit) -and $v.Text -match '(?m)^\[OK\] Word 16\.0: macros in files from the internet are blocked') $v.Text
    $v = V @(One (Src $N $N (& $P 7)) $none)
    T 'a VBAWarnings value Office does not define: WARNING, never [INFO]' ($v.Hit -and $v.Text -match '(?m)^\[WARNING\] Word 16\.0: VBAWarnings holds a value Office does not define \(7') $v.Text
    $v = V @(One (Src $N (& $P '1') $N) $none)
    T 'a REG_SZ "1" is still all-macros-enabled' ($v.Hit -and $v.Text -match 'VBAWarnings=1 \(set by Group Policy\)') $v.Text
    $v = V @(One (Src $N $U (& $P 2)) $none)
    T 'Group Policy unreadable above a user 2: a raised gap, never the user value as the answer (the old block printed defaults)' ($v.Gap -and (-not $v.Hit) -and $v.Text -match '(?m)^\[WARNING\] Office macro policy check NOT performed in full -- Word 16\.0 VBAWarnings: Group Policy could not be read \(SecurityException' -and $v.Text -notmatch '(?m)^\[OK\] (No Office|Word)') $v.Text
    $v = V @(One (Src $N (& $P 3) $U) $none)
    T 'a user key unreadable BELOW a Group Policy value is not a gap: the policy is in force' ((-not $v.Gap) -and $v.Text -match '(?m)^\[OK\] Word 16\.0: VBAWarnings=3 \(set by Group Policy\)') $v.Text
    $v = V @(One (Src $N $N $U) $none)
    T 'the user key unreadable with no policy above it: a raised gap' ($v.Gap -and $v.Text -match 'the user setting could not be read') $v.Text
    $v = V @(One (Src $N $N (& $P 1)) (Src $N $N $U))
    T 'a hit AND a gap: both raised -- one finding cannot hide an unread setting' ($v.Hit -and $v.Gap -and $v.Text -match '(?m)^\[WARNING\] Word 16\.0: VBAWarnings=1' -and $v.Text -match '(?m)^\[WARNING\] Office macro policy check NOT performed in full') $v.Text
    $v = V @() @(@{ Name = 'Office'; State = 'unreadable'; Error = 'SecurityException: denied' }, @{ Name = 'Group Policy'; State = 'nokey' }, @{ Name = 'Cloud Policy'; State = 'nokey' })
    T 'the Office root could not be listed: a raised gap, never "[OK] No Office settings" (the old Test-Path read it as absent)' ($v.Gap -and $v.Text -match '(?m)^\[WARNING\] Office macro policy check NOT performed -- Office could not be listed' -and $v.Text -notmatch '(?m)^\[OK\]') $v.Text
    $v = V @(One $none $none '15.0')
    T 'Office 2013 settings: [INFO] that it predates the internet-macro block' ((-not $v.Hit) -and $v.Text -match '(?m)^\[INFO\] Office 2013 \(15\.0\) settings are present') $v.Text
    $v = V @(One (Src $N $N (& $P 2)) $none '16.0' 'MS Project')
    T 'Project is read too (Microsoft lists it among the apps the block covers)' ($v.Text -match '(?m)^\[OK\] MS Project 16\.0: VBAWarnings=2') $v.Text
    $v = V @(One $none $none) $okRoots @{ Account = 'PC\admin'; Others = @('PC\alice'); Unresolved = 0 }
    T 'run as an administrator account with another account signed in: that account is named' ($v.Text -match '(?m)^\[INFO\] PC\\alice is also signed in at this PC: its Office settings follow' -and -not $v.Gap) $v.Text
    $o = Get-MacroVerdict -Reads @(One (Src $N $N (& $P 1)) $none) -Roots $okRoots -Owner 'PC\alice'
    T 'the other account''s VBAWarnings=1 is the WARNING, and the line names whose setting it is' ($o.Hit -and (($o.Lines -join "`n") -match '(?m)^\[WARNING\] Word 16\.0 \(settings of PC\\alice\): VBAWarnings=1')) ($o.Lines -join ' | ')
    $o = Get-MacroVerdict -Reads @() -Roots @(@{ Name = 'the registry of PC\alice'; State = 'unreadable'; Error = 'it is not loaded' }) -Owner 'PC\alice'
    T 'another signed-in account whose registry could not be opened: a raised gap, never "[OK] No Office settings"' ($o.Gap -and (($o.Lines -join "`n") -match '(?m)^\[WARNING\] Office macro policy check NOT performed -- the registry of PC\\alice could not be listed') -and (($o.Lines -join "`n") -notmatch '(?m)^\[OK\]')) ($o.Lines -join ' | ')
    $o = Get-MacroVerdict -Reads @() -Roots @(@{ Name = 'the registry of PC\alice'; State = 'denied'; Error = 'SecurityException: denied' }) -Owner 'PC\alice' -IsElevated $false
    T 'another account''s registry refused to a standard-user token: a deferral, never a gap or a row' ((-not $o.Gap) -and $o.Deferred -eq 1 -and (($o.Lines -join "`n") -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] Office macro settings of PC\\alice')) ($o.Lines -join ' | ')
    $o = Get-MacroVerdict -Reads @() -Roots @(@{ Name = 'the registry of PC\alice'; State = 'denied'; Error = 'SecurityException: denied' }) -Owner 'PC\alice' -IsElevated $true
    T 'the same refusal to an administrator: a raised gap (the token does not explain it)' ($o.Gap -and $o.Deferred -eq 0) ($o.Lines -join ' | ')
    $v = V @(One $none $none) @(@{ Name = 'Office'; State = 'denied'; Error = 'SecurityException: denied' }, @{ Name = 'Group Policy'; State = 'nokey' }, @{ Name = 'Cloud Policy'; State = 'nokey' })
    $o = Get-MacroVerdict -Reads @(One $none $none) -Roots @(@{ Name = 'Office'; State = 'denied'; Error = 'SecurityException: denied' }, @{ Name = 'Group Policy'; State = 'nokey' }, @{ Name = 'Cloud Policy'; State = 'nokey' }) -IsElevated $false
    T 'the user''s OWN settings refused: a raised gap whatever the token -- the token never explains its own registry' ($v.Gap -and $o.Gap -and $o.Deferred -eq 0) ($o.Lines -join ' | ')
    $m = Merge-AccountVerdicts @((V @(One $none $none)), (Get-MacroVerdict -Reads @(One (Src $N $N (& $P 1)) $none) -Roots $okRoots -Owner 'PC\alice'))
    T 'merged: a clean own account and a weakened other account still raise the WARNING' ($m.Hit -and -not $m.Gap -and (($m.Lines -join "`n") -match 'settings of PC\\alice')) (($m.Lines) -join ' | ')
    $o = Get-MacroVerdict -Reads @(One $none $none) -Roots $okRoots -Context @{ Account = 'PC\bob'; Others = @(); Unresolved = 2 } -IsElevated $false
    T 'desktop sessions a standard-user token could not identify: said, as [INFO]' ((($o.Lines -join "`n") -match '(?m)^\[INFO\] 2 desktop session\(s\) at this PC belong to an account this token could not identify') -and -not $o.Gap) ($o.Lines -join ' | ')
    $o = Get-MacroVerdict -Reads @(One $none $none) -Roots $okRoots -Context @{ Account = 'PC\bob'; Others = @(); Unresolved = 1 } -IsElevated $true
    T 'a session an ADMINISTRATOR could not identify: a raised gap -- the token does not explain it' ($o.Gap -and (($o.Lines -join "`n") -match '(?m)^\[WARNING\] Office macro policy check NOT performed in full -- 1 desktop session\(s\) at this PC belong to an account that could not be identified') -and (($o.Lines -join "`n") -notmatch 'An audit run as administrator')) ($o.Lines -join ' | ')
    $o = Get-MacroVerdict -Reads @(One $none $none) -Roots $okRoots -Context @{ Account = 'PC\bob'; Others = @(); Unresolved = 0; ListError = 'CimException: Invalid class' } -IsElevated $false
    T 'the signed-in accounts could not be listed: a raised gap on any token, never only this account read in silence' ($o.Gap -and (($o.Lines -join "`n") -match 'not every account signed in at this PC could be listed \(CimException: Invalid class\)')) ($o.Lines -join ' | ')
    $v = V @(One (Src $N $N (& $P ([long]4294967297))) $none)
    T 'a value too large for an Int32 is a value Office does not define, never a crash that voids the verdict' ($v.Hit -and $v.Text -match 'VBAWarnings holds a value Office does not define \(4294967297') $v.Text
    $v = V @((One (Src $N $N (& $P 2)) $none), (One (Src $N $U $N) $none '16.0' 'Excel'))
    T 'the count of settings read leaves out the ones that could not be read' ($v.Gap -and $v.Text -match '(?m)^\[INFO\] Nothing weakening was found in what could be read: 3 setting\(s\)') $v.Text
    T 'Outlook is not graded on values it does not use; the seven apps of Microsoft''s list are' (($script:Apps -notcontains 'Outlook') -and $script:Apps.Count -eq 7 -and ($script:Apps -contains 'Visio')) ($script:Apps -join ',')
    $v = V @(One (Src $N $N (& $P ("1`r`n[OK] forged"))) $none)
    T 'control characters in a registry value cannot start a report line' ($v.Hit -and $v.Text -notmatch '(?m)^\[OK\] forged') $v.Text
    $v = V @(One (Src $N $U $N) $none)
    T 'no gap line ever carries [OK]' (@($v.Lines | Where-Object { $_ -match 'NOT performed' -and $_ -match '^\[OK\]' }).Count -eq 0 -and $v.Gap) $v.Text
    if ($fails) { Write-Output "[FAIL] $fails office_macro_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] office_macro_check self-test passed'
    exit 0
}

# Live. The three sources for every version and app under one account's
# Software root. $MustExist: the root is another account's registry, which
# must be there (it is loaded while that account is signed in).
function Read-AccountSettings {
    param([string]$Root, [string]$Label, [bool]$MustExist)
    if ($MustExist) {
        $st = Read-VersionList $Root
        if ([string]$st.State -ne 'ok') { return @{ Reads = @(); Roots = @(@{ Name = ('the registry of ' + $Label); State = $(if ([string]$st.State -eq 'denied') { 'denied' } else { 'unreadable' }); Error = $(if ([string]$st.State -eq 'nokey') { 'it is not loaded' } else { [string]$st.Error }) }) } }
    }
    $roots = @(
        @{ Name = 'Cloud Policy'; Path = ($Root.TrimEnd('\') + '\Policies\Microsoft\Cloud\Office') },
        @{ Name = 'Group Policy'; Path = ($Root.TrimEnd('\') + '\Policies\Microsoft\Office') },
        @{ Name = 'the user setting'; Path = ($Root.TrimEnd('\') + '\Microsoft\Office') }
    )
    $rootStates = New-Object System.Collections.ArrayList
    $vers = New-Object System.Collections.ArrayList
    foreach ($rt in $roots) {
        $l = Read-VersionList $rt.Path
        [void]$rootStates.Add(@{ Name = ($rt.Name + ' (' + $rt.Path + ')'); State = $l.State; Error = $l.Error })
        foreach ($n in $l.Names) { if (-not $vers.Contains([string]$n)) { [void]$vers.Add([string]$n) } }
    }
    $reads = New-Object System.Collections.ArrayList
    foreach ($ver in $script:Versions) {
        if (-not $vers.Contains($ver)) { continue }
        foreach ($app in $script:Apps) {
            $src = New-Object System.Collections.ArrayList
            foreach ($rt in $roots) {
                # Cloud Policy exists for 16.0 only.
                if ($rt.Name -eq 'Cloud Policy' -and $ver -ne '16.0') { continue }
                [void]$src.Add(@{ Name = $rt.Name; Key = ($rt.Path + '\' + $ver + '\' + $app + '\Security') })
            }
            $vb = @($src | ForEach-Object { @{ Name = $_.Name; S = (Read-RegValueState -KeyPath $_.Key -Name 'VBAWarnings') } })
            $bk = @($src | ForEach-Object { @{ Name = $_.Name; S = (Read-RegValueState -KeyPath $_.Key -Name 'blockcontentexecutionfrominternet') } })
            [void]$reads.Add(@{ App = $app; Ver = $ver; Vba = $vb; Blk = $bk })
        }
    }
    return @{ Reads = @($reads.ToArray()); Roots = @($rootStates.ToArray()) }
}

if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$v = $null; $why = ''
try {
    # The other accounts signed in at this PC: the owners of explorer.exe. An
    # elevated audit is often run from a separate administrator account, and
    # the settings that protect the person at this PC are theirs.
    $others = New-Object System.Collections.ArrayList
    foreach ($ok in @($OtherKeyRoot | Where-Object { [string]$_ })) { [void]$others.Add(@{ Name = [string]$ok; Root = [string]$ok }) }
    $ctx = $null
    if ($KeyRoot -ieq 'HKCU:\Software') {
        $acct = ''; $mySid = ''
        try { $id = [Security.Principal.WindowsIdentity]::GetCurrent(); $acct = $id.Name; $mySid = $id.User.Value } catch {}
        $unresolved = 0; $seen = @{}; $listErr = ''
        try {
            foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop)) {
                $sid = ''; $nm = ''
                try { $sr = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop; if ([int]$sr.ReturnValue -eq 0) { $sid = [string]$sr.Sid } } catch {}
                try { $or = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop; if ([int]$or.ReturnValue -eq 0 -and $or.User) { $nm = $(if ($or.Domain) { [string]$or.Domain + '\' + [string]$or.User } else { [string]$or.User }) } } catch {}
                if (-not $sid) {
                    # Gone between the listing and the call: an ordinary race, not a session.
                    $still = $null; try { $still = Get-CimInstance Win32_Process -Filter ("ProcessId=" + [int]$p.ProcessId) -ErrorAction Stop } catch {}
                    if ($still) { $unresolved++ }
                    continue
                }
                if ($sid -eq $mySid -or $seen.ContainsKey($sid)) { continue }
                $seen[$sid] = $true
                [void]$others.Add(@{ Name = $(if ($nm) { $nm } else { $sid }); Root = ('Registry::HKEY_USERS\' + $sid + '\Software') })
            }
        } catch { $listErr = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
        $ctx = @{ Account = $acct; Others = @($others | ForEach-Object { $_.Name }); Unresolved = $unresolved; ListError = $listErr }
    }
    $mine = Read-AccountSettings -Root $KeyRoot -Label 'this account' -MustExist $false
    $all = New-Object System.Collections.ArrayList
    [void]$all.Add((Get-MacroVerdict -Reads $mine.Reads -Roots $mine.Roots -Context $ctx -IsElevated ($Elevated -eq 1)))
    foreach ($o in $others) {
        $t = Read-AccountSettings -Root $o.Root -Label $o.Name -MustExist $true
        [void]$all.Add((Get-MacroVerdict -Reads $t.Reads -Roots $t.Roots -Owner $o.Name -IsElevated ($Elevated -eq 1)))
    }
    $v = Merge-AccountVerdicts @($all.ToArray())
} catch { $v = $null; $why = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
if ($null -eq $v -or -not $v.Lines) {
    ('office_macro_check: the grading step failed (' + (ConvertTo-PrintableText $why) + '); no verdict was written.')
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.Hit) { Write-Marker -Name 'macro_hit' -Sev 'WARNING' }
if ($v.Gap) { Write-Marker -Name 'macro_gap' -Sev 'WARNING' }
if ([int]$v.Deferred -gt 0) { Write-Marker -Name 'macro_deferred' -Sev ([string][int]$v.Deferred) }
Write-Marker -Name 'macro_done' -Sev 'done'
exit 0
