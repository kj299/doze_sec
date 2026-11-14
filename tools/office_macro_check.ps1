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
    # Policy: the macro settings (the default, Section 13's first block).
    # Trust: Trusted Locations and Trusted Documents.
    [ValidateSet('Policy', 'Trust')]
    [string]$Part = 'Policy',
    # Only CI changes it: the machine-wide keys -Part Trust reads.
    [string]$MachineRoot = 'HKLM:\SOFTWARE',
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

# ===== -Part Trust: Trusted Locations and Trusted Documents (T1204.002) =====
#
# A Trusted Location is a folder Office runs every macro in with no prompt.
# Microsoft ("Trusted Locations for Office files"): files there "bypass threat
# protection services, bypass file block settings, and all active content is
# enabled", and the check for Mark of the Web is skipped. So a Trusted Location
# on Downloads defeats every protection -Part Policy grades.
#   DEFAULTS, from Microsoft's tables on that page (Access, Excel, PowerPoint,
#   Word; Project and Visio have none): the Templates, Startup, XLSTART, Addins
#   and Document Themes folders under %APPDATA%\Microsoft and under the Office
#   install directory. A default is [INFO]. ANY other entry is a counted
#   WARNING (the owner decided: any non-default entry), with a note when its
#   shape is one an attacker or a careless install uses -- Downloads, Desktop,
#   Temp, Public, the profile itself, a drive root, a network share.
#   NOT IN FORCE, said and not graded: a network (\\ or http) entry while no
#   source allows network locations (Microsoft: Office ignores it), and every
#   entry when Group Policy disables all trusted locations, and every entry the
#   USER set when policy allows only Trusted Locations defined by policy
#   (Microsoft: "Allow mix of policy and user locations" Disabled -- "Only
#   Trusted Locations defined by policy are allowed"; Not Configured behaves as
#   Enabled). Microsoft's page names the policies, not their registry values;
#   the value names come from the Office ADMX as the DISA Office STIG checks
#   quote it: allownetworklocations and alllocationsdisabled under
#   <app>\Security\Trusted Locations, and "allow user locations" under
#   Common\Security\Trusted Locations (V-223293). A machine-setting entry stays
#   graded under that policy: whether Office ignores it is not documented. If a
#   name were wrong, the value would never be read as set and every entry would
#   be graded -- the safe direction.
# Trusted Documents (Security\Trusted Documents\TrustRecords) is Office's record
# of each document whose content the person enabled: the value NAME is the
# document's path or URL, the data starts with a FILETIME (when it was trusted)
# and ends with a DWORD that is 0x7FFFFFFF when macros were enabled. That
# layout is documented by forensic practice, not by Microsoft, and the lines
# say "as the record says". Macros enabled -> [INFO] with the path and date;
# in a document under Downloads, Temp or an email-attachment cache -> WARNING
# (the owner decided), the usual first step of a macro attack. A record this
# tool cannot read the layout of is named, never guessed.
$script:TrustApps = @('Word', 'Excel', 'PowerPoint', 'Access', 'Visio', 'MS Project')
$script:RecordApps = @('Word', 'Excel', 'PowerPoint', 'Access', 'Visio')

# PURE. Is this path one of Office's own default Trusted Locations? Read on
# the raw value AND its expansion, with no environment needed, so another
# account's %APPDATA% is recognised without expanding it as ours.
function Test-OfficeDefaultLocation {
    # $AppDataRoots: the account's Roaming AppData folder(s), as paths;
    # $ProgramRoots: this PC's Program Files folders. A default must sit under
    # one of THOSE -- never any drive or any user name: C:\Users\Public\AppData
    # \Roaming\Microsoft\Templates and D:\Program Files\Microsoft Office\root\
    # Templates are not Office's defaults, and either one would hide a
    # planted Trusted Location as "as installed". A . or .. segment is never a
    # default. The literal %APPDATA% / %ProgramFiles% forms are what Office
    # writes, and Windows expands them to exactly those roots.
    param([string]$Path, [string[]]$AppDataRoots = @(), [string[]]$ProgramRoots = @())
    $p = ([string]$Path).Trim().Replace('/', '\').TrimEnd('\')
    if (-not $p) { return $false }
    if (@($p -split '\\' | Where-Object { $_ -eq '.' -or $_ -eq '..' }).Count) { return $false }
    $ad = @('%appdata%') + @($AppDataRoots | Where-Object { [string]$_ } | ForEach-Object { ([string]$_).TrimEnd('\') })
    $pf = @('%programfiles%', '%programfiles(x86)%', '%programw6432%') + @($ProgramRoots | Where-Object { [string]$_ } | ForEach-Object { ([string]$_).TrimEnd('\') })
    foreach ($r in $ad) {
        if ($p -imatch ('^' + [regex]::Escape($r) + '\\microsoft\\(templates|word\\startup|excel\\xlstart|addins)$')) { return $true }
    }
    foreach ($r in $pf) {
        # Office 2013 Click-to-Run installs under "Microsoft Office 15".
        if ($p -imatch ('^' + [regex]::Escape($r) + '\\microsoft office( 15)?\\(root\\)?(templates|document themes 1[4-6]|office1[4-6]\\(xlstart|startup|library|accwiz))$')) { return $true }
    }
    return $false
}

# PURE. The shape note for a non-default location, or '' when it has none.
function Get-LocationShape {
    param([string]$Path)
    $p = ([string]$Path).Trim().Replace('/', '\')
    if ($p -match '^\\\\' -or $p -imatch '^https?:') { return 'a network location, which anyone who can write to it controls' }
    if ($p -imatch '^[a-z]:\\?$') { return 'a whole drive' }
    if ($p -imatch '^(%userprofile%|[a-z]:\\users\\[^\\]+)\\?$') { return 'the whole user profile' }
    if ($p -imatch '\\downloads(\\|$)') { return 'Downloads, where browsers save every file' }
    if ($p -imatch '\\desktop(\\|$)') { return 'the Desktop, where downloads and attachments are often saved' }
    if ($p -imatch '(^%temp%|^%tmp%|\\temp(\\|$)|\\windows\\temp)') { return 'a Temp folder, where any program writes' }
    if ($p -imatch '\\users\\public(\\|$)') { return 'the Public folder, which every account can write' }
    if ($p -imatch 'inetcache|content\.outlook|\\olk\\') { return 'an email-attachment or browser cache' }
    return ''
}

# PURE. Where a Trusted Documents record's path says the document came from,
# when that is a download or an attachment; '' otherwise.
function Get-RecordRisk {
    param([string]$Name)
    $p = ([string]$Name).Replace('/', '\')
    if ($p -imatch '\\downloads\\') { return 'Downloads' }
    if ($p -imatch 'content\.outlook\\|\\olk\\attachments\\|\\outlook temp\\') { return 'an email attachment' }
    if ($p -imatch 'inetcache\\|content\.mso\\|temporary internet files\\') { return 'a browser or Office download cache' }
    if ($p -imatch '(%temp%|\\temp\\|\\tmp\\)') { return 'a Temp folder' }
    return ''
}

# PURE. One Trusted Documents record. Returns @{ Ok; Macros; When; Why }.
function ConvertFrom-TrustRecord {
    param($Bytes)
    $r = @{ Ok = $false; Macros = $false; When = ''; Why = '' }
    if ($null -eq $Bytes -or -not ($Bytes -is [byte[]])) { $r.Why = 'its data is not binary'; return $r }
    $b = [byte[]]$Bytes
    if ($b.Length -lt 12) { $r.Why = ('its data is ' + $b.Length + ' bytes, shorter than the layout this tool knows'); return $r }
    try { $r.When = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($b, 0)).ToString('yyyy-MM-dd HH:mm') + ' UTC' } catch { $r.When = 'an unreadable date' }
    $r.Macros = ([BitConverter]::ToUInt32($b, $b.Length - 4) -eq 0x7FFFFFFF)
    $r.Ok = $true
    return $r
}

# PURE. One account's Trusted Locations and Trusted Documents.
# $Entries: @( @{ App; Ver; Source; Raw; Path; Sub } ) -- Sub $true/$false/$null.
# $Gates: @{ '<App>|<Ver>' = @{ Net = <Select-InForce result>; Off = <Select-InForce result> } }.
# $Records: @( @{ App; Ver; Name; Bytes } ). $Gaps: @( '<what could not be read>' ).
# Returns @{ Lines; Hit; DocHit; Gap; Deferred; Gaps }.
function Get-TrustVerdict {
    param($Entries, $Gates, $Records, $Gaps, [string]$Owner = '', [bool]$IsElevated = $true, [bool]$Denied = $false, [bool]$OfficeSeen = $true, [string[]]$AppDataRoots = @(), [string[]]$ProgramRoots = @(), $UserLocs = @{})
    $out = New-Object System.Collections.ArrayList
    $r = @{ Lines = @(); Hit = $false; DocHit = $false; Gap = $false; Deferred = 0; Gaps = @() }
    $who = $(if ($Owner) { ' (settings of ' + (ConvertTo-PrintableText $Owner) + ')' } else { '' })
    if ($Owner -and $Denied -and -not $IsElevated) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] Office Trusted Locations of ' + (ConvertTo-PrintableText $Owner) + ', also signed in at this PC, not read: another account''s registry needs administrator.'))
        $r.Deferred = 1; $r.Lines = @($out.ToArray()); return $r
    }
    $gapList = New-Object System.Collections.ArrayList
    foreach ($g in @($Gaps)) { if ([string]$g) { [void]$gapList.Add([string]$g) } }
    $defaults = @{}; $nonDefault = 0
    foreach ($e in @($Entries)) {
        $tag = ([string]$e.App + ' ' + [string]$e.Ver + $who)
        $shown = ConvertTo-PrintableText $(if ([string]$e.Raw) { [string]$e.Raw } else { [string]$e.Path })
        if ((Test-OfficeDefaultLocation $e.Raw $AppDataRoots $ProgramRoots) -or (Test-OfficeDefaultLocation $e.Path $AppDataRoots $ProgramRoots)) {
            $defaults[$tag] = 1 + [int]$defaults[$tag]; continue
        }
        $nonDefault++
        $gate = $Gates[([string]$e.App + '|' + [string]$e.Ver)]
        $off = $gate -and $gate.Off -and $gate.Off.Decided -and (ConvertTo-RegNumber $gate.Off.Value) -eq 1
        $isNet = (([string]$e.Path -match '^\\\\') -or ([string]$e.Raw -match '^\\\\') -or ([string]$e.Path -imatch '^https?:'))
        $netOn = $gate -and $gate.Net -and $gate.Net.Decided -and (ConvertTo-RegNumber $gate.Net.Value) -eq 1
        $netGap = $gate -and $gate.Net -and [string]$gate.Net.Gap
        $ul = $(if ($UserLocs) { $UserLocs[[string]$e.Ver] } else { $null })
        if ([string]$e.Source -eq 'the user setting' -and $ul -and $ul.Decided -and (ConvertTo-RegNumber $ul.Value) -eq 0) { [void]$out.Add(('[INFO] ' + $tag + ': Trusted Location ' + $shown + ' (set by the user setting) is not in force: ' + [string]$ul.From + ' allows only Trusted Locations defined by policy.')); continue }
        if ($off) { [void]$out.Add(('[INFO] ' + $tag + ': Trusted Location ' + $shown + ' (set by ' + [string]$e.Source + ') is not in force: ' + [string]$gate.Off.From + ' disables all trusted locations.')); continue }
        if ($isNet -and -not $netOn -and -not $netGap) { [void]$out.Add(('[INFO] ' + $tag + ': Trusted Location ' + $shown + ' (set by ' + [string]$e.Source + ') is a network location, which Office ignores while network locations are not allowed (the default).')); continue }
        $shape = Get-LocationShape $(if ([string]$e.Path) { [string]$e.Path } else { [string]$e.Raw })
        $sub = $(if ($e.Sub -eq $true) { ' (subfolders included)' } else { '' })
        [void]$out.Add(('[WARNING] Office Trusted Location outside Office''s defaults (' + $tag + ', set by ' + [string]$e.Source + '): ' + $shown + $sub + $(if ($shape) { ' -- ' + $shape } else { '' }) + ' -- every document saved there runs its macros with no prompt (T1204.002).'))
        $r.Hit = $true
    }
    foreach ($k in @($Gates.Keys)) {
        $g = $Gates[$k]
        if ($g.Net -and $g.Net.Decided -and (ConvertTo-RegNumber $g.Net.Value) -eq 1) { [void]$out.Add(('[INFO] ' + ($k -replace '\|', ' ') + $who + ': network locations are allowed as Trusted Locations (set by ' + [string]$g.Net.From + '; Microsoft recommends against it).')) }
        # A gate that could not be read is already a gap from the reader (its
        # key could not be opened); its entries are graded, the safe direction.
    }
    foreach ($k in @($defaults.Keys | Sort-Object)) { [void]$out.Add(('[INFO] ' + $k + ': ' + $defaults[$k] + ' of Office''s own default Trusted Location(s), as installed.')) }
    # --- Trusted Documents ---
    $macroDocs = 0; $otherDocs = 0
    foreach ($d in @($Records)) {
        $tag = ([string]$d.App + ' ' + [string]$d.Ver + $who)
        $name = ConvertTo-PrintableText ([string]$d.Name)
        $p = ConvertFrom-TrustRecord $d.Bytes
        if (-not $p.Ok) { [void]$out.Add(('[INFO] ' + $tag + ': a Trusted Documents record for ' + $name + ' could not be read (' + $p.Why + ').')); continue }
        if (-not $p.Macros) { $otherDocs++; continue }
        $macroDocs++
        $risk = Get-RecordRisk ([string]$d.Name)
        if ($risk) {
            [void]$out.Add(('[WARNING] Macros were enabled in a document from ' + $risk + ' (' + $tag + '): ' + $name + ' (trusted ' + $p.When + ', as the record says) -- its macros run every time it is opened, with no prompt (T1204.002).'))
            $r.DocHit = $true
        } else {
            [void]$out.Add(('[INFO] ' + $tag + ': macros were enabled in ' + $name + ' (trusted ' + $p.When + ', as the record says).'))
        }
    }
    if ($otherDocs -gt 0) { [void]$out.Add(('[INFO] ' + $otherDocs + ' other Trusted Documents record(s)' + $who + ' enable editing or other content, not macros.')) }
    if ($gapList.Count -gt 0) {
        $names = (@($gapList | Select-Object -First 3) -join '; ') + $(if ($gapList.Count -gt 3) { ('; and ' + ($gapList.Count - 3) + ' more') } else { '' })
        $some = (@($Entries).Count + @($Records).Count) -gt 0 -or $OfficeSeen
        [void]$out.Add(('[WARNING] Office Trusted Locations check NOT performed' + $(if ($some) { ' in full' } else { '' }) + ' -- ' + $names + ', so a Trusted Location that runs macros with no prompt, or a record of macros enabled in a downloaded document, would go unseen (T1204.002).'))
        $r.Gap = $true
    }
    if (-not $r.Hit -and -not $r.DocHit) {
        if (-not $OfficeSeen -and $nonDefault -eq 0 -and @($Records).Count -eq 0 -and -not $r.Gap) {
            [void]$out.Add($(if ($Owner) { ('[OK] No Office settings for ' + (ConvertTo-PrintableText $Owner) + ': no Trusted Location and no Trusted Documents record.') } else { '[OK] No Office settings for this account: no Trusted Location and no Trusted Documents record.' }))
        } elseif ($r.Gap) {
            # A gap is never an all-clear: what was read is said, as [INFO].
            [void]$out.Add(('[INFO] Nothing outside Office''s defaults was found in what could be read' + $who + ': ' + @($Entries).Count + ' location(s) and ' + @($Records).Count + ' record(s).'))
        } else {
            [void]$out.Add(('[OK] No Office Trusted Location outside Office''s defaults, and no macros enabled in a downloaded or attached document' + $(if ($Owner) { ' for ' + (ConvertTo-PrintableText $Owner) } else { ' for this account' }) + ' (' + @($Entries).Count + ' location(s) and ' + @($Records).Count + ' record(s) read).'))
            if ($macroDocs -eq 0 -and @($Records).Count -gt 0) { [void]$out.Add(('[INFO] No Trusted Documents record' + $who + ' has its macros enabled.')) }
        }
    }
    $r.Gaps = @($gapList.ToArray())
    $r.Lines = @($out.ToArray())
    return $r
}

# Live. One key, told apart: @{ State = ok|nokey|denied|unreadable; Error; Key }.
function Open-KeyState {
    param([string]$Path)
    try { return @{ State = 'ok'; Error = ''; Key = (Get-Item -LiteralPath $Path -ErrorAction Stop) } }
    catch {
        if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { return @{ State = 'nokey'; Error = ''; Key = $null } }
        $den = ($_.Exception -is [System.Security.SecurityException] -or $_.Exception -is [System.UnauthorizedAccessException])
        return @{ State = $(if ($den) { 'denied' } else { 'unreadable' }); Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Key = $null }
    }
}

# Live. An account's Roaming AppData folder(s), for recognising Office's
# defaults in its expanded form. The audit's own account asks Windows; another
# account is read from its profile record and its Shell Folders, never from
# our environment (its %APPDATA% is not ours).
function Get-AccountAppData {
    param([string]$Root, [bool]$Own)
    $out = New-Object System.Collections.ArrayList
    if ($Own) { try { $a = [Environment]::GetFolderPath('ApplicationData'); if ($a) { [void]$out.Add($a) } } catch {} ; return @($out.ToArray()) }
    if ($Root -match '^Registry::HKEY_USERS\\(S-1-[0-9-]+)\\Software$') {
        $sid = $Matches[1]
        try { $pi = [string](Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid) -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath; if ($pi) { [void]$out.Add(([Environment]::ExpandEnvironmentVariables($pi).TrimEnd('\') + '\AppData\Roaming')) } } catch {}
        try { $sf = [string](Get-ItemProperty -LiteralPath ($Root + '\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders') -Name AppData -ErrorAction Stop).AppData; if ($sf) { [void]$out.Add($sf) } } catch {}
    }
    return @($out.ToArray())
}

# Live. Every Trusted Location and Trusted Documents record under one account
# (and, for the audit's own account, the machine-wide keys).
function Read-TrustAccount {
    param([string]$Root, [string]$MachineRoot, [string]$Label, [bool]$MustExist, [bool]$Expand)
    $res = @{ Entries = (New-Object System.Collections.ArrayList); Gates = @{}; Records = (New-Object System.Collections.ArrayList); Gaps = (New-Object System.Collections.ArrayList); Denied = $false; OfficeSeen = $false }
    if ($MustExist) {
        $st = Read-VersionList $Root
        if ([string]$st.State -ne 'ok') {
            $res.Denied = ([string]$st.State -eq 'denied')
            [void]$res.Gaps.Add(('the registry of ' + $Label + ' could not be listed (' + $(if ([string]$st.State -eq 'nokey') { 'it is not loaded' } else { ConvertTo-PrintableText ([string]$st.Error) }) + ')'))
            return $res
        }
    }
    $R = $Root.TrimEnd('\')
    # Highest precedence first, for the two gate values.
    $srcs = @(
        @{ Name = 'Cloud Policy'; Path = ($R + '\Policies\Microsoft\Cloud\Office'); Policy = $true; User = $false },
        @{ Name = 'Group Policy'; Path = ($R + '\Policies\Microsoft\Office'); Policy = $true; User = $false }
    )
    if ($MachineRoot) { $M = $MachineRoot.TrimEnd('\'); $srcs += @(@{ Name = 'machine-wide Group Policy'; Path = ($M + '\Policies\Microsoft\Office'); Policy = $true; User = $false }) }
    $srcs += @(@{ Name = 'the user setting'; Path = ($R + '\Microsoft\Office'); Policy = $false; User = $true })
    if ($MachineRoot) {
        # 32-bit Office on 64-bit Windows keeps its machine keys under
        # WOW6432Node, in both the MSI and the Click-to-Run layout.
        $srcs += @(@{ Name = 'the machine setting'; Path = ($M + '\Microsoft\Office'); Policy = $false; User = $false },
            @{ Name = 'the machine setting (32-bit)'; Path = ($M + '\WOW6432Node\Microsoft\Office'); Policy = $false; User = $false },
            @{ Name = 'the machine setting (Click-to-Run)'; Path = ($M + '\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office'); Policy = $false; User = $false },
            @{ Name = 'the machine setting (Click-to-Run, 32-bit)'; Path = ($M + '\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\Microsoft\Office'); Policy = $false; User = $false })
    }
    $gateSrc = @{}
    $ulSrc = @{}
    foreach ($s in $srcs) {
        $vl = Read-VersionList $s.Path
        if ([string]$vl.State -eq 'nokey') { continue }
        if ([string]$vl.State -ne 'ok') { [void]$res.Gaps.Add(($s.Name + ' (' + $s.Path + ') could not be listed (' + (ConvertTo-PrintableText ([string]$vl.Error)) + ')')); continue }
        foreach ($ver in @($vl.Names)) {
            if ($s.Name -eq 'Cloud Policy' -and $ver -ne '16.0') { continue }
            $res.OfficeSeen = $true
            $apps = @($script:TrustApps); if ($s.Policy) { $apps += 'Common' }
            foreach ($app in $apps) {
                $tlPath = ($s.Path + '\' + $ver + '\' + $app + '\Security\Trusted Locations')
                $ks = Open-KeyState $tlPath
                $gk = ($(if ($app -eq 'Common') { 'all Office apps' } else { $app }) + '|' + $ver)
                if (-not $gateSrc.ContainsKey($gk)) { $gateSrc[$gk] = @{ Net = (New-Object System.Collections.ArrayList); Off = (New-Object System.Collections.ArrayList) } }
                if ($ks.State -eq 'nokey') {
                    [void]$gateSrc[$gk].Net.Add(@{ Name = $s.Name; S = @{ State = 'nokey' } })
                    if ($s.Policy) { [void]$gateSrc[$gk].Off.Add(@{ Name = $s.Name; S = @{ State = 'nokey' } }) }
                } elseif ($ks.State -ne 'ok') {
                    [void]$res.Gaps.Add(($app + ' ' + $ver + ' Trusted Locations (' + $s.Name + ') could not be read (' + (ConvertTo-PrintableText $ks.Error) + ')'))
                    [void]$gateSrc[$gk].Net.Add(@{ Name = $s.Name; S = @{ State = 'unreadable'; Error = $ks.Error } })
                    if ($s.Policy) { [void]$gateSrc[$gk].Off.Add(@{ Name = $s.Name; S = @{ State = 'unreadable'; Error = $ks.Error } }) }
                } else {
                    [void]$gateSrc[$gk].Net.Add(@{ Name = $s.Name; S = (Read-RegValueState -KeyPath $tlPath -Name 'AllowNetworkLocations') })
                    if ($s.Policy) { [void]$gateSrc[$gk].Off.Add(@{ Name = $s.Name; S = (Read-RegValueState -KeyPath $tlPath -Name 'AllLocationsDisabled') }) }
                    if ($s.Policy -and $app -eq 'Common') {
                        if (-not $ulSrc.ContainsKey($ver)) { $ulSrc[$ver] = New-Object System.Collections.ArrayList }
                        [void]$ulSrc[$ver].Add(@{ Name = $s.Name; S = (Read-RegValueState -KeyPath $tlPath -Name 'allow user locations') })
                    }
                    $subs = @()
                    try { $subs = @($ks.Key.GetSubKeyNames()) } catch { [void]$res.Gaps.Add(($app + ' ' + $ver + ' Trusted Locations (' + $s.Name + ') could not be listed (' + (ConvertTo-PrintableText $_.Exception.Message) + ')')) }
                    foreach ($sn in $subs) {
                        $sk = $null
                        try {
                            $sk = $ks.Key.OpenSubKey($sn)
                            if ($null -eq $sk) { continue }
                            $raw = [string]$sk.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                            if (-not $raw) { continue }
                            $exp = $(if ($Expand) { [Environment]::ExpandEnvironmentVariables($raw) } else { $raw })
                            $subv = ConvertTo-RegNumber ($sk.GetValue('AllowSubfolders', $null))
                            [void]$res.Entries.Add(@{ App = $(if ($app -eq 'Common') { 'all Office apps' } else { $app }); Ver = $ver; Source = $s.Name; Raw = $raw; Path = $exp; Sub = $(if ($null -eq $subv) { $null } else { $subv -eq 1 }) })
                        } catch { [void]$res.Gaps.Add(($app + ' ' + $ver + ' Trusted Location ' + $sn + ' (' + $s.Name + ') could not be read (' + (ConvertTo-PrintableText $_.Exception.Message) + ')')) }
                        finally { if ($sk) { $sk.Close() } }
                    }
                }
                if ($s.User -and $script:RecordApps -contains $app) {
                    $trPath = ($s.Path + '\' + $ver + '\' + $app + '\Security\Trusted Documents\TrustRecords')
                    $tk = Open-KeyState $trPath
                    if ($tk.State -eq 'ok') {
                        try {
                            foreach ($vn in @($tk.Key.GetValueNames())) {
                                if (-not [string]$vn) { continue }
                                [void]$res.Records.Add(@{ App = $app; Ver = $ver; Name = [string]$vn; Bytes = $tk.Key.GetValue($vn, $null) })
                            }
                        } catch { [void]$res.Gaps.Add(($app + ' ' + $ver + ' Trusted Documents could not be read (' + (ConvertTo-PrintableText $_.Exception.Message) + ')')) }
                    } elseif ($tk.State -ne 'nokey') { [void]$res.Gaps.Add(($app + ' ' + $ver + ' Trusted Documents could not be read (' + (ConvertTo-PrintableText $tk.Error) + ')')) }
                }
            }
        }
    }
    foreach ($gk in $gateSrc.Keys) { $res.Gates[$gk] = @{ Net = (Select-InForce @($gateSrc[$gk].Net.ToArray())); Off = (Select-InForce @($gateSrc[$gk].Off.ToArray())) } }
    $res.UserLocs = @{}
    foreach ($ver in $ulSrc.Keys) { $res.UserLocs[$ver] = Select-InForce @($ulSrc[$ver].ToArray()) }
    return $res
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

    # --- -Part Trust ---
    function TE { param([string]$Raw, [string]$Path = '', [string]$App = 'Word', [string]$Src = 'the user setting', $Sub = $null) @{ App = $App; Ver = '16.0'; Source = $Src; Raw = $Raw; Path = $(if ($Path) { $Path } else { $Raw }); Sub = $Sub } }
    function TG { param($Net = $null, $Off = $null) $g = @{}; $g['Word|16.0'] = @{ Net = $(if ($null -ne $Net) { @{ Decided = $true; From = 'the user setting'; Value = $Net; Gap = '' } } else { @{ Decided = $false; Gap = '' } }); Off = $(if ($null -ne $Off) { @{ Decided = $true; From = 'Group Policy'; Value = $Off; Gap = '' } } else { @{ Decided = $false; Gap = '' } }) }; return $g }
    function TRec { param([string]$Name, [uint32]$Flag = 0x7FFFFFFF, [int]$Len = 24) $b = New-Object byte[] $Len; if ($Len -ge 12) { [BitConverter]::GetBytes([long]133400000000000000).CopyTo($b, 0); [BitConverter]::GetBytes($Flag).CopyTo($b, $Len - 4) }; @{ App = 'Word'; Ver = '16.0'; Name = $Name; Bytes = $b } }
    $tAD = @('C:\Users\bob\AppData\Roaming'); $tPF = @('C:\Program Files', 'C:\Program Files (x86)')
    function TV { param($E = @(), $G = (TG), $Rec = @(), $Gaps = @(), [string]$Owner = '', [bool]$El = $true, [bool]$Den = $false, [bool]$Seen = $true, $UL = @{}) $x = Get-TrustVerdict -Entries $E -Gates $G -Records $Rec -Gaps $Gaps -Owner $Owner -IsElevated $El -Denied $Den -OfficeSeen $Seen -AppDataRoots $tAD -ProgramRoots $tPF -UserLocs $UL; $x.Text = ($x.Lines -join "`n"); return $x }
    function TUL { param($v) $h = @{}; $h['16.0'] = @{ Decided = $true; From = 'Group Policy'; Value = $v; Gap = '' }; return $h }
    foreach ($d in @('%APPDATA%\Microsoft\Templates', 'C:\Users\bob\AppData\Roaming\Microsoft\Word\Startup\', '%appdata%\Microsoft\Excel\XLSTART', 'C:\Program Files\Microsoft Office\root\Templates\', 'C:\Program Files (x86)\Microsoft Office\root\Office16\STARTUP', 'C:\Program Files\Microsoft Office\Office15\XLSTART', 'C:\Program Files\Microsoft Office\root\Document Themes 16\', '%APPDATA%\Microsoft\Addins', 'C:\Program Files\Microsoft Office\root\Office16\ACCWIZ', 'C:\Program Files\Microsoft Office 15\root\Templates\', 'C:\Program Files\Microsoft Office 15\root\Office15\XLSTART', '%ProgramFiles%\Microsoft Office\root\Templates')) {
        T ("default Trusted Location recognised (Microsoft's table): " + $d) (Test-OfficeDefaultLocation $d $tAD $tPF) ''
    }
    foreach ($nd in @('C:\Users\bob\Downloads', '%APPDATA%\Microsoft\Templates\Evil', 'C:\Users\bob\AppData\Roaming\Microsoft\Word', 'D:\Program Files\Microsoft Office\root\Templates\..\..\x', 'C:\Program Files\Microsoft Office\root\Office16', 'C:\', '\\server\share\Templates', 'C:\Users\Public\AppData\Roaming\Microsoft\Templates', 'C:\Users\..\AppData\Roaming\Microsoft\Word\Startup', 'D:\Users\x\AppData\Roaming\Microsoft\Templates', 'E:\Program Files\Microsoft Office\root\Templates', 'C:\Users\alice\AppData\Roaming\Microsoft\Templates')) {
        T ("not a default (another account's or another drive's folder, or a .. segment): " + $nd) (-not (Test-OfficeDefaultLocation $nd $tAD $tPF)) ''
    }
    $v = TV @(TE '%APPDATA%\Microsoft\Templates' 'C:\Users\bob\AppData\Roaming\Microsoft\Templates')
    T 'Office''s own defaults only: [OK] plus an INFO count, no WARNING' ((-not $v.Hit) -and (-not $v.Gap) -and $v.Text -match '\[INFO\] Word 16\.0: 1 of Office''s own default Trusted Location' -and $v.Text -match '(?m)^\[OK\] No Office Trusted Location outside Office''s defaults') $v.Text
    $v = TV @(TE '%USERPROFILE%\Downloads' 'C:\Users\bob\Downloads' -Sub $true)
    T 'Downloads as a Trusted Location: the WARNING, the raw path, subfolders and the shape note' ($v.Hit -and $v.Text -match '(?m)^\[WARNING\] Office Trusted Location outside Office''s defaults \(Word 16\.0, set by the user setting\): %USERPROFILE%\\Downloads \(subfolders included\) -- Downloads, where browsers save every file -- every document saved there runs its macros with no prompt \(T1204\.002\)\.$') $v.Text
    $v = TV @(TE 'C:\Projects\Macros')
    T 'any other non-default folder: the WARNING with no shape note (the owner''s "any non-default")' ($v.Hit -and $v.Text -match 'C:\\Projects\\Macros -- every document saved there' ) $v.Text
    $v = TV @(TE '\\fileserver\finance')
    T 'a network location while network locations are not allowed: INFO not in force, no WARNING' ((-not $v.Hit) -and $v.Text -match 'is a network location, which Office ignores') $v.Text
    $v = TV @(TE '\\fileserver\finance') (TG 1)
    T 'the same network location with network locations allowed: the WARNING, and the allowance said' ($v.Hit -and $v.Text -match 'a network location, which anyone who can write to it controls' -and $v.Text -match 'network locations are allowed as Trusted Locations') $v.Text
    $v = TV @(TE 'C:\Users\bob\Downloads') (TG $null 1)
    T 'Group Policy disables all trusted locations: the entry is INFO not in force, no WARNING' ((-not $v.Hit) -and $v.Text -match 'is not in force: Group Policy disables all trusted locations') $v.Text
    $v = TV @(TE 'C:\Users\bob\Downloads') -UL (TUL 0)
    T 'policy allows only policy-defined locations (allow user locations=0): a user-set entry is INFO not in force' ((-not $v.Hit) -and $v.Text -match 'is not in force: Group Policy allows only Trusted Locations defined by policy') $v.Text
    $v = TV @(TE 'C:\Users\bob\Downloads' -Src 'Group Policy') -UL (TUL 0)
    T 'the same policy leaves a Group Policy entry a WARNING' ($v.Hit) $v.Text
    $v = TV @(TE 'C:\Users\bob\Downloads' -Src 'the machine setting') -UL (TUL 0)
    T 'the same policy leaves a machine-setting entry a WARNING (undocumented either way: the safe direction)' ($v.Hit) $v.Text
    $v = TV @(TE 'C:\Users\bob\Downloads') -UL (TUL 1)
    T 'allow user locations=1: a user-set entry is graded' ($v.Hit) $v.Text
    $v = TV @(TE 'C:\Users\bob\Downloads' -App 'Word') -UL @{ '15.0' = @{ Decided = $true; From = 'Group Policy'; Value = 0; Gap = '' } }
    T 'the policy for another Office version does not reach a 16.0 entry' ($v.Hit) $v.Text
    $v = TV @(TE 'C:\Users\bob\Downloads') (TG $null 0)
    T 'AllLocationsDisabled=0: the entry is graded' ($v.Hit) $v.Text
    foreach ($c in @(@{ P = 'C:\'; S = 'a whole drive' }, @{ P = 'C:\Users\bob'; S = 'the whole user profile' }, @{ P = 'C:\Users\bob\AppData\Local\Temp'; S = 'a Temp folder' }, @{ P = 'C:\Users\Public\Documents'; S = 'the Public folder' }, @{ P = 'C:\Users\bob\Desktop'; S = 'the Desktop' })) {
        $v = TV @(TE $c.P)
        T ("shape note for " + $c.P + ": " + $c.S) ($v.Hit -and $v.Text -match [regex]::Escape($c.S)) $v.Text
    }
    $v = TV @() (TG) @() @('Word 16.0 Trusted Locations (the user setting) could not be read (SecurityException: x)')
    T 'a Trusted Locations key that could not be read: a raised gap, never [OK]' ($v.Gap -and $v.Text -match '(?m)^\[WARNING\] Office Trusted Locations check NOT performed in full -- Word 16\.0 Trusted Locations' -and $v.Text -notmatch '\[OK\]') $v.Text
    $v = TV @(TE 'C:\Users\bob\Downloads') (TG) @() @('x could not be read')
    T 'a hit AND a gap: both raised' ($v.Hit -and $v.Gap) $v.Text
    $v = TV @() (TG) @() @('the registry of PC\alice could not be listed (denied)') -Owner 'PC\alice' -El $false -Den $true
    T 'another account refused to a standard-user token: DEFERRED and counted, no gap' ($v.Deferred -eq 1 -and (-not $v.Gap) -and $v.Text -match '\[DEFERRED - ADMIN REQUIRED\] Office Trusted Locations of PC\\alice') $v.Text
    $v = TV @() (TG) @() @('the registry of PC\alice could not be listed (denied)') -Owner 'PC\alice' -El $true -Den $true
    T 'the same refusal when elevated: a raised gap' ($v.Gap -and $v.Deferred -eq 0) $v.Text
    $v = TV @(TE 'C:\Temp\x' -Src 'Group Policy') -Owner 'PC\alice'
    T 'another account''s entry names the account and the source' ($v.Hit -and $v.Text -match 'Word 16\.0 \(settings of PC\\alice\), set by Group Policy') $v.Text
    $v = TV -Seen $false
    T 'no Office at all: [OK] no Office settings' ((-not $v.Hit) -and $v.Text -match '(?m)^\[OK\] No Office settings for this account') $v.Text
    # --- Trusted Documents ---
    $v = TV -Rec @(TRec '%USERPROFILE%/Downloads/invoice.docm')
    T 'macros enabled in a document from Downloads: the WARNING with the path and the date' ($v.DocHit -and (-not $v.Hit) -and $v.Text -match '(?m)^\[WARNING\] Macros were enabled in a document from Downloads \(Word 16\.0\): %USERPROFILE%/Downloads/invoice\.docm \(trusted 20\d\d-\d\d-\d\d \d\d:\d\d UTC, as the record says\)') $v.Text
    $v = TV -Rec @(TRec 'C:\Users\bob\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\AB12CD34\order.xlsm')
    T 'macros enabled in an Outlook attachment: the WARNING' ($v.DocHit -and $v.Text -match 'from an email attachment') $v.Text
    $v = TV -Rec @(TRec 'C:/Temp/run.docm')
    T 'macros enabled in a document under C:\Temp: the WARNING' ($v.DocHit -and $v.Text -match 'from a Temp folder') $v.Text
    $v = TV @(TE 'C:\Users\Public\AppData\Roaming\Microsoft\Templates')
    T 'a Templates folder under the Public profile is NOT a default: the WARNING' ($v.Hit -and $v.Text -match 'the Public folder') $v.Text
    $v = TV -Rec @(TRec '%USERPROFILE%/Documents/budget.xlsm')
    T 'macros enabled in the person''s own Documents: INFO with the path, never a WARNING' ((-not $v.DocHit) -and $v.Text -match '\[INFO\] Word 16\.0: macros were enabled in %USERPROFILE%/Documents/budget\.xlsm') $v.Text
    $v = TV -Rec @(TRec '%USERPROFILE%/Downloads/report.docx' -Flag 1)
    T 'a record without the macros flag, even from Downloads: counted, never a WARNING' ((-not $v.DocHit) -and $v.Text -match '1 other Trusted Documents record\(s\) enable editing or other content, not macros') $v.Text
    $v = TV -Rec @(TRec '%USERPROFILE%/Downloads/x.docm' -Len 5)
    T 'a record too short for the known layout: named, never guessed' ((-not $v.DocHit) -and $v.Text -match 'could not be read \(its data is 5 bytes') $v.Text
    $p = ConvertFrom-TrustRecord ([byte[]](1, 2, 3)) ; T 'a record of 3 bytes is not read' (-not $p.Ok) $p.Why
    $p = ConvertFrom-TrustRecord 'text' ; T 'a record that is not binary is not read' (-not $p.Ok) $p.Why
    $v = TV @(TE ('C:\x' + [char]13 + [char]10 + '[OK] No Office Trusted Location outside'))
    T 'a line break inside a path cannot forge an [OK] line' ($v.Hit -and @($v.Lines | Where-Object { $_ -match '^\[OK\] No Office Trusted' }).Count -eq 0) $v.Text
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
# Live. The other accounts signed in at this PC, and the context line data.
function Get-SignedInAccounts {
    $others = $null; $ctx = $null
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
    return @{ Others = $others; Ctx = $ctx }
}

$v = $null; $why = ''
try {
    $sa = Get-SignedInAccounts
    $others = $sa.Others; $ctx = $sa.Ctx
    if ($Part -eq 'Trust') {
        $own = ($KeyRoot -ieq 'HKCU:\Software')
        $all = New-Object System.Collections.ArrayList
        $mine = Read-TrustAccount -Root $KeyRoot -MachineRoot $MachineRoot -Label 'this account' -MustExist $false -Expand $own
        $head = New-Object System.Collections.ArrayList
        if ($ctx -and $ctx.Account) {
            [void]$head.Add(('[INFO] These are the Office Trusted Locations and Trusted Documents of ' + (ConvertTo-PrintableText ([string]$ctx.Account)) + ', the account this audit ran as, and this PC''s machine-wide settings.'))
            foreach ($o in @($ctx.Others | Where-Object { [string]$_ })) { [void]$head.Add(('[INFO] ' + (ConvertTo-PrintableText ([string]$o)) + ' is also signed in at this PC: its settings follow, on the lines that name it.')) }
        }
        $ctxGaps = New-Object System.Collections.ArrayList
        if ($ctx) {
            $unres = [int]$ctx.Unresolved
            if ($unres -gt 0 -and $Elevated -eq 1) { [void]$ctxGaps.Add(([string]$unres + ' desktop session(s) at this PC belong to an account that could not be identified, so their settings were not read')) }
            elseif ($unres -gt 0) { [void]$head.Add(('[INFO] ' + $unres + ' desktop session(s) at this PC belong to an account this token could not identify, so their settings were not read. An audit run as administrator reads them.')) }
            if ([string]$ctx.ListError) { [void]$ctxGaps.Add(('not every account signed in at this PC could be listed (' + (ConvertTo-PrintableText ([string]$ctx.ListError)) + '), so some accounts'' settings may not have been read')) }
        }
        $pfRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432 | Where-Object { [string]$_ })
        [void]$all.Add((Get-TrustVerdict -Entries @($mine.Entries.ToArray()) -Gates $mine.Gates -Records @($mine.Records.ToArray()) -Gaps (@($mine.Gaps.ToArray()) + @($ctxGaps.ToArray())) -IsElevated ($Elevated -eq 1) -OfficeSeen $mine.OfficeSeen -UserLocs $mine.UserLocs -AppDataRoots (Get-AccountAppData -Root $KeyRoot -Own $true) -ProgramRoots $pfRoots))
        foreach ($o in $others) {
            $t = Read-TrustAccount -Root $o.Root -MachineRoot '' -Label $o.Name -MustExist $true -Expand $false
            [void]$all.Add((Get-TrustVerdict -Entries @($t.Entries.ToArray()) -Gates $t.Gates -Records @($t.Records.ToArray()) -Gaps @($t.Gaps.ToArray()) -Owner $o.Name -IsElevated ($Elevated -eq 1) -Denied $t.Denied -OfficeSeen $t.OfficeSeen -UserLocs $t.UserLocs -AppDataRoots (Get-AccountAppData -Root $o.Root -Own $false) -ProgramRoots $pfRoots))
        }
        $tv = @{ Lines = (New-Object System.Collections.ArrayList); Hit = $false; DocHit = $false; Gap = $false; Deferred = 0 }
        foreach ($l in $head) { [void]$tv.Lines.Add($l) }
        foreach ($x in $all) { foreach ($l in @($x.Lines)) { [void]$tv.Lines.Add($l) }; if ($x.Hit) { $tv.Hit = $true }; if ($x.DocHit) { $tv.DocHit = $true }; if ($x.Gap) { $tv.Gap = $true }; $tv.Deferred += [int]$x.Deferred }
        if ($tv.Hit -or $tv.DocHit) { [void]$tv.Lines.Add('[INFO] A workplace sometimes trusts a shared folder on purpose, and people enable macros in their own spreadsheets. If neither you nor whoever manages this PC set the location, or you did not mean to enable that document''s macros, remove it: File > Options > Trust Center > Trust Center Settings > Trusted Locations (or Trusted Documents > Clear).') }
        foreach ($l in $tv.Lines) { $l }
        if ($tv.Hit) { Write-Marker -Name 'trustloc_hit' -Sev 'WARNING' }
        if ($tv.DocHit) { Write-Marker -Name 'trustdoc_hit' -Sev 'WARNING' }
        if ($tv.Gap) { Write-Marker -Name 'trustloc_gap' -Sev 'WARNING' }
        if ([int]$tv.Deferred -gt 0) { Write-Marker -Name 'trustloc_deferred' -Sev ([string][int]$tv.Deferred) }
        Write-Marker -Name 'trustloc_done' -Sev 'done'
        exit 0
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
