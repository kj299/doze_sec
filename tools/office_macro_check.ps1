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
#   notification, and (Microsoft 365 Apps since 2022) macros in files from the
#   internet blocked. Office 2013 and 2010 settings (15.0, 14.0) predate that
#   block, and the line says so.
#   VERSIONS are those present under ANY of the three roots, so a policy
#   written for an Office that has not been started yet is still read. A root
#   that does not exist is an answer; one that could not be listed is a gap.
#
# The settings are per user (HKCU). The line names whose they are, and when a
# different account is signed in at this PC it says that person's settings
# were not read -- [INFO], since an audit run from a separate administrator
# account is ordinary on a managed PC.
#
# Markers (in -MarkerDir): dz_macro_hit.txt, dz_macro_gap.txt, and
# dz_macro_done.txt when the tool reached its end (the bat raises "produced no
# verdict" without it).
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
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }

$script:Apps = @('Word', 'Excel', 'PowerPoint', 'Access', 'Publisher', 'Outlook', 'Visio', 'MS Project')
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
# $Context: @{ Account; Interactive = @(names) | $null }.
# Returns @{ Lines; Hit; Gap; Examined }.
function Get-MacroVerdict {
    param($Reads, $Roots, $Context = $null)
    $out = New-Object System.Collections.ArrayList
    $gaps = New-Object System.Collections.ArrayList
    $r = @{ Hit = $false; Gap = $false; Examined = 0 }
    foreach ($x in @($Roots)) { if ([string]$x.State -ne 'ok' -and [string]$x.State -ne 'nokey') { [void]$gaps.Add(([string]$x.Name + ' could not be listed (' + (ConvertTo-PrintableText ([string]$x.Error)) + ')')) } }
    $explicit = 0
    $vers = New-Object System.Collections.ArrayList
    foreach ($a in @($Reads)) {
        if (-not $vers.Contains([string]$a.Ver)) { [void]$vers.Add([string]$a.Ver) }
        $tag = ([string]$a.App + ' ' + [string]$a.Ver)
        foreach ($kind in 'Vba', 'Blk') {
            $r.Examined++
            $name = $(if ($kind -eq 'Vba') { 'VBAWarnings' } else { 'blockcontentexecutionfrominternet' })
            $p = Select-InForce $a[$kind]
            if ($p.Gap) { [void]$gaps.Add(($tag + ' ' + $name + ': ' + $p.Gap)); continue }
            if (-not $p.Decided) { continue }
            $explicit++
            $n = ConvertTo-RegNumber $p.Value
            $shown = ConvertTo-PrintableText ([string]$p.Value)
            $src = ('set by ' + $p.From)
            if ($kind -eq 'Vba') {
                if ($n -eq 1) { [void]$out.Add(('[WARNING] ' + $tag + ': VBAWarnings=1 (' + $src + ') -- ALL macros run with no prompt, so a macro in any document runs the moment it is opened (T1204.002).')); $r.Hit = $true }
                elseif ($null -ne $n -and $script:VbaText.ContainsKey([int]$n)) { [void]$out.Add(('[OK] ' + $tag + ': VBAWarnings=' + $n + ' (' + $src + ') -- ' + $script:VbaText[[int]$n] + '.')) }
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
        if ($vers.Contains($old)) { [void]$out.Add(('[INFO] Office ' + $(if ($old -eq '15.0') { '2013' } else { '2010' }) + ' (' + $old + ') settings are present: that version predates Microsoft''s default block of macros in files from the internet, and no longer receives security updates.')) }
    }
    if ($gaps.Count -gt 0) {
        $names = (@($gaps | Select-Object -First 3) -join '; ') + $(if ($gaps.Count -gt 3) { ('; and ' + ($gaps.Count - 3) + ' more') } else { '' })
        [void]$out.Add(('[WARNING] Office macro policy check NOT performed' + $(if ($r.Examined -gt 0) { ' in full' } else { '' }) + ' -- ' + $names + ', so a setting that lets macros in malicious documents run would go unseen (T1204.002).'))
        $r.Gap = $true
    }
    if (-not $r.Hit -and -not $r.Gap) {
        if ($vers.Count -eq 0) { [void]$out.Add('[OK] No Office settings for this account (Office is not installed, or has never been started by it): Office''s defaults apply.') }
        else { [void]$out.Add(('[OK] No Office macro setting weakens protection: ' + $r.Examined + ' setting(s) read for Office ' + (@($vers.ToArray()) -join ', ') + ', ' + $explicit + ' set explicitly. Where nothing is set, Office''s defaults apply: macros disabled with notification, and (Microsoft 365 Apps since 2022) macros in files from the internet blocked.')) }
    } elseif (-not $r.Hit -and $r.Examined -gt 0) {
        [void]$out.Add(('[INFO] Nothing weakening was found in what could be read: ' + $r.Examined + ' setting(s) for Office ' + (@($vers.ToArray()) -join ', ') + '.'))
    }
    if ($Context -and $Context.Account) {
        [void]$out.Add(('[INFO] These are the Office settings of ' + (ConvertTo-PrintableText ([string]$Context.Account)) + ', the account this audit ran as.'))
        $int = @($Context.Interactive | Where-Object { [string]$_ })
        if ($int.Count -gt 0 -and -not (@($int | Where-Object { [string]$_ -ieq [string]$Context.Account }).Count)) {
            [void]$out.Add(('[INFO] The account signed in at this PC is ' + (ConvertTo-PrintableText ((@($int | Select-Object -First 3)) -join ', ')) + ': its Office settings were NOT read here. Run the audit from that account to check them.'))
        }
    }
    $r.Lines = @($out.ToArray())
    return $r
}

# Live. Which version keys exist under one root. @{ State = ok|nokey|unreadable; Error; Names }.
function Read-VersionList {
    param([string]$Path)
    try { $k = Get-Item -LiteralPath $Path -ErrorAction Stop }
    catch {
        if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { return @{ State = 'nokey'; Error = ''; Names = @() } }
        return @{ State = 'unreadable'; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Names = @() }
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
    $v = V @(One $none $none) $okRoots @{ Account = 'PC\admin'; Interactive = @('PC\alice') }
    T 'run as another account than the one signed in: [INFO] that person''s settings were NOT read' ($v.Text -match '(?m)^\[INFO\] The account signed in at this PC is PC\\alice: its Office settings were NOT read here' -and -not $v.Gap) $v.Text
    $v = V @(One $none $none) $okRoots @{ Account = 'PC\alice'; Interactive = @('pc\ALICE') }
    T 'run as the signed-in account: no such line (names compared without case)' ($v.Text -notmatch 'signed in at this PC') $v.Text
    $v = V @(One (Src $N $N (& $P ("1`r`n[OK] forged"))) $none)
    T 'control characters in a registry value cannot start a report line' ($v.Hit -and $v.Text -notmatch '(?m)^\[OK\] forged') $v.Text
    $v = V @(One (Src $N $U $N) $none)
    T 'no gap line ever carries [OK]' (@($v.Lines | Where-Object { $_ -match 'NOT performed' -and $_ -match '^\[OK\]' }).Count -eq 0 -and $v.Gap) $v.Text
    if ($fails) { Write-Output "[FAIL] $fails office_macro_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] office_macro_check self-test passed'
    exit 0
}

$v = $null
try {
    $roots = @(
        @{ Name = 'Cloud Policy'; Path = (Join-Path $KeyRoot 'Policies\Microsoft\Cloud\Office') },
        @{ Name = 'Group Policy'; Path = (Join-Path $KeyRoot 'Policies\Microsoft\Office') },
        @{ Name = 'the user setting'; Path = (Join-Path $KeyRoot 'Microsoft\Office') }
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
                [void]$src.Add(@{ Name = $rt.Name; Key = (Join-Path $rt.Path ($ver + '\' + $app + '\Security')) })
            }
            $vb = @($src | ForEach-Object { @{ Name = $_.Name; S = (Read-RegValueState -KeyPath $_.Key -Name 'VBAWarnings') } })
            $bk = @($src | ForEach-Object { @{ Name = $_.Name; S = (Read-RegValueState -KeyPath $_.Key -Name 'blockcontentexecutionfrominternet') } })
            [void]$reads.Add(@{ App = $app; Ver = $ver; Vba = $vb; Blk = $bk })
        }
    }
    $ctx = $null
    if ($KeyRoot -ieq 'HKCU:\Software') {
        $acct = ''; try { $acct = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch {}
        # Context only: who owns the desktop shell. $null when it cannot be told.
        $int = $null
        try {
            $int = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | ForEach-Object {
                $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($o -and $o.User) { $(if ($o.Domain) { [string]$o.Domain + '\' + [string]$o.User } else { [string]$o.User }) }
            } | Sort-Object -Unique)
        } catch {}
        $ctx = @{ Account = $acct; Interactive = $int }
    }
    $v = Get-MacroVerdict -Reads @($reads.ToArray()) -Roots @($rootStates.ToArray()) -Context $ctx
} catch { $v = $null }
if ($null -eq $v -or -not $v.Lines) {
    'office_macro_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
if ($v.Hit) { Write-Marker -Name 'macro_hit' -Sev 'WARNING' }
if ($v.Gap) { Write-Marker -Name 'macro_gap' -Sev 'WARNING' }
Write-Marker -Name 'macro_done' -Sev 'done'
exit 0
