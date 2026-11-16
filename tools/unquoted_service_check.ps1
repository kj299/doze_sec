# unquoted_service_check.ps1 -- can a service be made to run someone else's
# program (T1574.009, path interception by unquoted path)?
#
# A service whose ImagePath is NOT quoted and has a space inside the program's
# own path -- C:\Program Files\Acme Agent\agent.exe -- is started by
# CreateProcess, which cannot tell where the path ends. Microsoft documents
# the order (CreateProcessW, lpApplicationName NULL): for
# "c:\program files\sub dir\program name" it tries c:\program.exe, then
# c:\program files\sub.exe, then c:\program files\sub dir\program.exe, then
# c:\program files\sub dir\program name.exe; and "if the file name does not
# contain an extension, .exe is appended". A file at one of the earlier
# places runs as the service's account (often SYSTEM) at its next start.
#
# The check was an inline block that matched any service path containing a
# space anywhere (arguments included), printed a bare table with no severity
# and raised nothing, and printed an unraised [SKIPPED] when the service query
# failed. Win32_Service also leaves out a service whose DACL denies this
# token, so the source is now what Windows itself runs: each service's
# ImagePath in the registry, which a standard user can read.
#
# THE MODEL (pure, Get-CreateProcessTries / Resolve-ServicePath): every
# whitespace-separated prefix of the command line is one try, taken as-is
# when its last path component has a dot and with .exe appended when it has
# none. The program Windows was meant to run is the LAST try that exists (the
# longest path); any earlier try that exists is a file planted in front of
# it; the earlier tries that do not exist are the places one could be put.
# When no try exists the program is missing, and the tries up to the first
# argument-looking token (- or /) are all places a program could be put.
#
# THE RULE (pure, pinned by -SelfTest; the owner's choice, 2026-11-16):
#   * only services that run as a PROCESS are graded (Type 0x10/0x20, the
#     0x50/0x60 per-user templates, with or without the 0x100 interactive
#     bit). A driver is loaded by exact path and is not searched; a quoted
#     ImagePath is not graded; a \??\ or relative path is counted as a form
#     this check does not grade, never silently;
#   * CRITICAL: a file already sits at one of the earlier tries;
#   * WARNING: someone other than an administrator may put a file there --
#     an allow entry for any principal outside SYSTEM, Administrators,
#     TrustedInstaller and the per-service NT SERVICE accounts, granting
#     CreateFiles, WRITE_DAC, WRITE_OWNER or GENERIC_WRITE/ALL on the folder,
#     or a folder owned by such a principal. When the folder does not exist
#     yet, the nearest folder that does is read, and "create subfolders"
#     (AppendData) counts too: whoever creates the folder owns it. Deny
#     entries are not subtracted (the safe direction, said in the line);
#   * INFO: only administrators can -- a careless install, listed with path;
#   * a folder whose permissions could not be read is a raised gap for that
#     service (a counted deferral when a standard-user token was refused),
#     never "only administrators"; the Services key that could not be listed
#     is a raised gap; a service key refused to a standard-user token is a
#     counted deferral, and to an administrator a raised gap. A finding and
#     a gap are both raised.
# Markers: dz_unquoted_crit / dz_unquoted_warn / dz_unquoted_gap /
# dz_unquoted_deferred, written BEFORE the state: a marker that cannot be
# written ends the tool with no state, which the bat raises as "produced no
# verdict" -- a finding is never lost behind a saved state.
# State: dz_unquoted_state.txt  uq=<crit|warn|gap|deferred|info|none>,n=<graded>
#
# Usage:
#   powershell -File tools\unquoted_service_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1]
#   powershell -File tools\unquoted_service_check.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # Only CI changes this: a throwaway key laid out like Services, so every
    # state runs through the real reader.
    [string]$ServicesRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_unquoted_state.txt' }
$script:MaxListed = 25
$script:MaxTries = 24
# SYSTEM, Administrators, TrustedInstaller, CREATOR OWNER (applies only to
# what is created below, never to the folder itself).
$script:AdminSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-3-0')

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -ErrorAction Stop | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -ErrorAction Stop
}

function ConvertTo-PrintableText {
    # Registry text goes into the report: no control characters, capped.
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt 260) { $t = $t.Substring(0, 260) + '...' }
    return $t
}

# PURE. The folder a file would be created in, by string, so the answer does
# not depend on the engine's path separator: C:\Program.exe -> C:\ (the drive
# root), C:\Program Files\A.exe -> C:\Program Files.
function Get-ParentDir {
    param([string]$Path)
    $i = ([string]$Path).LastIndexOf('\')
    if ($i -lt 0) { return '' }
    if ($i -eq 2 -and $Path[1] -eq ':') { return $Path.Substring(0, 3) }
    return $Path.Substring(0, $i)
}

# PURE. Does this service type run as a process (so CreateProcess searches
# its path)? Own process 0x10, shared 0x20, per-user templates 0x50/0x60,
# with or without the 0x100 interactive bit. A driver (0x1, 0x2) is not.
function Test-ProcessServiceType {
    param($Type)
    if ($null -eq $Type) { return $false }
    $t = 0; try { $t = [int]$Type } catch { return $false }
    return (@(0x10, 0x20, 0x50, 0x60) -contains ($t -band 0xFF))
}

# PURE. The tries CreateProcess makes for an UNQUOTED command line, in order:
# one per whitespace-separated prefix (space or tab), taken as-is when its
# last path component has a dot, with .exe appended when it has none.
# Returns @( @{ Try; ArgLike } ): ArgLike when the prefix's last token starts
# with - or / (the command line is into its arguments by then).
function Get-CreateProcessTries {
    param([string]$CommandLine)
    $out = New-Object System.Collections.ArrayList
    $s = ([string]$CommandLine).TrimEnd()
    if (-not $s -or $s.StartsWith('"')) { return @() }
    $ends = New-Object System.Collections.ArrayList
    for ($i = 1; $i -lt $s.Length; $i++) {
        if (($s[$i] -eq ' ' -or $s[$i] -eq "`t") -and $s[$i - 1] -ne ' ' -and $s[$i - 1] -ne "`t") { [void]$ends.Add($i) }
    }
    [void]$ends.Add($s.Length)
    foreach ($e in $ends) {
        if ($out.Count -ge $script:MaxTries) { break }
        $pre = $s.Substring(0, $e)
        if ($pre.EndsWith('\')) { continue }
        $last = $pre.Substring($pre.LastIndexOf('\') + 1)
        $tok = @($pre -split '[ \t]+')[-1]
        $try = $(if ($last.Contains('.')) { $pre } else { $pre + '.exe' })
        [void]$out.Add(@{ Try = $try; ArgLike = ($tok -match '^[-/]') })
    }
    return @($out.ToArray())
}

# PURE. Which try is the program, which tries hold a planted file, and which
# are places one could be put. $Exists: a scriptblock that says whether a
# path is a file (injectable so the walk is pinned without a disk).
# Returns @{ Program; ProgramExists; Planted = @(paths); Open = @(paths) }.
function Resolve-ServicePath {
    param([string]$CommandLine, [scriptblock]$Exists)
    $tries = @(Get-CreateProcessTries $CommandLine)
    $hit = @()
    for ($i = 0; $i -lt $tries.Count; $i++) {
        $ok = $false; try { $ok = [bool](& $Exists $tries[$i].Try) } catch { $ok = $false }
        if ($ok) { $hit += $i }
    }
    if ($hit.Count -gt 0) {
        $p = $hit[-1]
        $planted = @($hit | Where-Object { $_ -lt $p } | ForEach-Object { $tries[$_].Try })
        $open = @(0..($p) | Where-Object { $_ -lt $p -and $hit -notcontains $_ } | ForEach-Object { $tries[$_].Try })
        return @{ Program = $tries[$p].Try; ProgramExists = $true; Planted = $planted; Open = $open }
    }
    $open = New-Object System.Collections.ArrayList
    foreach ($t in $tries) { if ($t.ArgLike) { break }; [void]$open.Add($t.Try) }
    $prog = $(if ($open.Count) { $open[$open.Count - 1] } else { '' })
    return @{ Program = $prog; ProgramExists = $false; Planted = @(); Open = @($open.ToArray()) }
}

# PURE. Who other than an administrator may put a file at a place whose
# folder is (Mode 'file') or whose nearest existing ancestor is (Mode
# 'folder') described by $Aces / $OwnerSid. $Aces: @( @{ Sid; Name; Allow;
# Rights = <int>; InheritOnly } ). Counted: CreateFiles 0x2, WRITE_DAC
# 0x40000, WRITE_OWNER 0x80000, GENERIC_WRITE 0x40000000, GENERIC_ALL
# 0x10000000 -- and in 'folder' mode AppendData 0x4 (create a subfolder,
# which its creator then owns). Not counted: SYSTEM, Administrators,
# TrustedInstaller, CREATOR OWNER, and the per-service NT SERVICE\* accounts.
# A folder OWNED by anyone else counts too (an owner can rewrite the DACL).
# Returns @(names), or @() when only administrators may.
function Get-NonAdminWriters {
    param($Aces, [string]$OwnerSid = '', [string]$OwnerName = '', [string]$Mode = 'file')
    $who = New-Object System.Collections.ArrayList
    $mask = 0x2 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    if ($Mode -eq 'folder') { $mask = $mask -bor 0x4 }
    $isAdmin = { param([string]$sid) ($script:AdminSids -contains $sid) -or $sid.StartsWith('S-1-5-80-') }
    foreach ($a in @($Aces)) {
        if (-not $a.Allow -or $a.InheritOnly) { continue }
        $r = 0; try { $r = [long]$a.Rights } catch { continue }
        if (($r -band $mask) -eq 0) { continue }
        $s = [string]$a.Sid
        if (-not $s -or (& $isAdmin $s)) { continue }
        $n = $(if ([string]$a.Name) { [string]$a.Name } else { $s })
        if ($who -notcontains $n) { [void]$who.Add($n) }
    }
    if ($OwnerSid -and -not (& $isAdmin $OwnerSid)) {
        $n = 'the folder''s owner ' + $(if ($OwnerName) { $OwnerName } else { $OwnerSid })
        if ($who -notcontains $n) { [void]$who.Add($n) }
    }
    return @($who.ToArray())
}

# PURE. $List: @{ State = ok|unreadable; Error }. $Services: @( @{ Name;
# State = ok|denied|unreadable; Error; Graded; Shape = ''|'nt'|'relative';
# Raw; Program; ProgramExists; Planted = @( @{ Path; File } ); Open = @( @{
# Path; Dir; Mode; Writers = @(..); AclError; AclDenied } ) } ).
# Returns @{ Lines; Crit; Warn; Gap; Deferred; State }.
function Get-UnquotedVerdict {
    param($List, $Services, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    if ([string]$List.State -ne 'ok') {
        [void]$out.Add(('[WARNING] Unquoted service path check NOT performed -- the service registry (HKLM\SYSTEM\CurrentControlSet\Services) could not be listed (' + (ConvertTo-PrintableText ([string]$List.Error)) + '), so a service Windows could be tricked into running the wrong program for would go unseen (T1574.009).'))
        return @{ Lines = @($out.ToArray()); Crit = $false; Warn = $false; Gap = $true; Deferred = 0; State = 'uq=gap,n=0' }
    }
    $crit = New-Object System.Collections.ArrayList
    $warn = New-Object System.Collections.ArrayList
    $info = New-Object System.Collections.ArrayList
    $failed = New-Object System.Collections.ArrayList
    $denied = New-Object System.Collections.ArrayList
    $shapes = New-Object System.Collections.ArrayList
    $nCrit = 0; $nWarn = 0; $nInfo = 0; $read = 0
    foreach ($s in @($Services)) {
        $name = ConvertTo-PrintableText ([string]$s.Name)
        $st = [string]$s.State
        if ($st -eq 'denied' -and -not $IsElevated) { [void]$denied.Add(($name + ' (its service key)')); continue }
        if ($st -ne 'ok') { [void]$failed.Add(($name + ' (its service key: ' + (ConvertTo-PrintableText ([string]$s.Error)) + ')')); continue }
        $read++
        if ([string]$s.Shape) { [void]$shapes.Add($name); continue }
        if (-not $s.Graded) { continue }
        $img = ConvertTo-PrintableText ([string]$s.Raw)
        $progNote = $(if ($s.ProgramExists) { '' } else { ' (the program it names does not exist, so each place below is somewhere a program could be put)' })
        if (@($s.Planted).Count -gt 0) {
            $nCrit++
            $p = @($s.Planted)[0]
            [void]$crit.Add(('[CRITICAL] Unquoted service path: a file already sits where Windows looks first -- service ' + $name + ' runs ' + $img + ', and Windows tries ' + (ConvertTo-PrintableText ([string]$p.Path)) + ' before ' + (ConvertTo-PrintableText ([string]$s.Program)) + '; it runs as the service account at the next start (T1574.009).'))
            [void]$crit.Add(('[INFO]   that file: ' + (ConvertTo-PrintableText ([string]$p.File))))
            continue
        }
        $writable = @($s.Open | Where-Object { @($_.Writers).Count -gt 0 })
        $unread = @($s.Open | Where-Object { [string]$_.AclError })
        if ($writable.Count -gt 0) {
            $nWarn++
            $parts = @($writable | ForEach-Object {
                $who = ((@($_.Writers) | ForEach-Object { ConvertTo-PrintableText ([string]$_) }) -join ', ')
                if ([string]$_.Mode -eq 'folder') { (ConvertTo-PrintableText ([string]$_.Path)) + ' -- its folder does not exist yet, and ' + (ConvertTo-PrintableText ([string]$_.Dir)) + ' lets ' + $who + ' create it' }
                else { (ConvertTo-PrintableText ([string]$_.Path)) + ' -- its folder lets ' + $who + ' create it' }
            })
            [void]$warn.Add(('[WARNING] Unquoted service path a non-administrator can hijack -- service ' + $name + ' runs ' + $img + $progNote + '. Windows tries these before the program, and the folder permissions allow someone other than an administrator to put a program there: ' + ($parts -join '; ') + ' (T1574.009).'))
        }
        if ($unread.Count -gt 0) {
            $why = (@($unread | ForEach-Object { (ConvertTo-PrintableText ([string]$_.Dir)) + ': ' + (ConvertTo-PrintableText ([string]$_.AclError)) }) -join '; ')
            if ((-not $IsElevated) -and @($unread | Where-Object { -not $_.AclDenied }).Count -eq 0) { [void]$denied.Add(($name + ' (who can write ' + $why + ')')) }
            else { [void]$failed.Add(($name + ' (who can write ' + $why + ')')) }
            continue
        }
        if ($writable.Count -eq 0) {
            $nInfo++
            [void]$info.Add(('[INFO] Unquoted service path, not exploitable as installed: service ' + $name + ' runs ' + $img + $progNote + '; only administrators can put a program at ' + ((@($s.Open | ForEach-Object { ConvertTo-PrintableText ([string]$_.Path) })) -join ', ') + '. The vendor should quote it.'))
        }
    }
    foreach ($l in $crit) { [void]$out.Add($l) }
    $k = 0; foreach ($l in $warn) { $k++; if ($k -le $script:MaxListed) { [void]$out.Add($l) } }
    if ($warn.Count -gt $script:MaxListed) { [void]$out.Add(('[INFO] ... and ' + ($warn.Count - $script:MaxListed) + ' more hijackable service(s).')) }
    $k = 0; foreach ($l in $info) { $k++; if ($k -le $script:MaxListed) { [void]$out.Add($l) } }
    if ($info.Count -gt $script:MaxListed) { [void]$out.Add(('[INFO] ... and ' + ($info.Count - $script:MaxListed) + ' more unquoted path(s) only administrators can exploit.')) }
    if ($nCrit -or $nWarn) {
        [void]$out.Add('[INFO] Deny entries are not subtracted, so a folder can read as writable when a deny rule blocks it. Verify: (Get-ItemProperty ''HKLM:\SYSTEM\CurrentControlSet\Services\<name>'').ImagePath, and icacls on the folder named above. A file you do not recognise at one of those places is the attack; quoting the path is the vendor''s fix.')
    }
    if ($shapes.Count) {
        [void]$out.Add(('[INFO] ' + $shapes.Count + ' service(s) with an unquoted path in a form this check does not grade (\??\ or relative): ' + ((@($shapes | Select-Object -First 10)) -join ', ') + $(if ($shapes.Count -gt 10) { ', ...' } else { '' }) + '.'))
    }
    $gap = ($failed.Count -gt 0)
    if ($gap) {
        $lead = $(if ($nCrit -or $nWarn -or $nInfo) { '[WARNING] Unquoted service path check NOT performed in full -- ' } else { '[WARNING] Unquoted service path check NOT performed -- ' })
        $more = $(if ($failed.Count -gt 10) { '; and ' + ($failed.Count - 10) + ' more' } else { '' })
        [void]$out.Add(($lead + $failed.Count + ' service(s) could not be graded: ' + ((@($failed | Select-Object -First 10)) -join '; ') + $more + ' (T1574.009).'))
    }
    $deferred = $(if ($denied.Count) { 1 } else { 0 })
    if ($deferred) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] ' + $denied.Count + ' service(s) were not graded because this standard-user token was refused: ' + ((@($denied | Select-Object -First 10)) -join '; ') + '; an audit run as administrator reads them.'))
    }
    if (-not ($nCrit -or $nWarn -or $gap -or $deferred)) {
        $lead = $(if ($nInfo) { '[OK] No unquoted service path a non-administrator can exploit' } else { '[OK] No service runs from an unquoted path with a space in its program path' })
        [void]$out.Add(($lead + ' (' + $read + ' service key(s) read from the registry).'))
    }
    $state = $(if ($nCrit) { 'crit' } elseif ($nWarn) { 'warn' } elseif ($gap) { 'gap' } elseif ($deferred) { 'deferred' } elseif ($nInfo) { 'info' } else { 'none' })
    return @{ Lines = @($out.ToArray()); Crit = ($nCrit -gt 0); Warn = ($nWarn -gt 0); Gap = $gap; Deferred = $deferred; State = ('uq=' + $state + ',n=' + ($nCrit + $nWarn + $nInfo)) }
}

# Live. Facts about a file that sits at an interception point.
function Get-FileFacts {
    param([string]$Path)
    try {
        $f = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $sig = 'signature not read'
        try { $a = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop; $sig = $(if ([string]$a.Status -eq 'Valid' -and $a.SignerCertificate) { 'validly signed by ' + [string]$a.SignerCertificate.Subject } else { 'NOT validly signed (' + [string]$a.Status + ')' }) } catch {}
        return ('{0}, {1} bytes, created {2:yyyy-MM-dd HH:mm} UTC, modified {3:yyyy-MM-dd HH:mm} UTC, {4}' -f $Path, $f.Length, $f.CreationTimeUtc, $f.LastWriteTimeUtc, $sig)
    } catch { return ($Path + ' (its details could not be read: ' + $_.Exception.Message + ')') }
}

function Get-SidName {
    param([string]$Sid)
    try { return [string](New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { return $Sid }
}

# Live. One open place: read the permissions of its folder, or of the nearest
# folder that exists when its own does not.
function Read-OpenPlace {
    param([string]$Path)
    $c = @{ Path = $Path; Dir = (Get-ParentDir $Path); Mode = 'file'; Writers = @(); AclError = ''; AclDenied = $false }
    $d = $c.Dir
    while ($d -and -not (Test-Path -LiteralPath $d -PathType Container)) {
        $up = Get-ParentDir $d
        if (-not $up -or $up -eq $d) { $d = ''; break }
        $d = $up; $c.Mode = 'folder'
    }
    if (-not $d) { $c.AclError = 'no existing folder above it could be found'; return $c }
    $c.Dir = $d
    try {
        $acl = Get-Acl -LiteralPath $d -ErrorAction Stop
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
            $sid = [string]$_.IdentityReference.Value
            @{ Sid = $sid; Name = (Get-SidName $sid); Allow = ([string]$_.AccessControlType -eq 'Allow'); Rights = [long][int]$_.FileSystemRights; InheritOnly = ((([int]$_.PropagationFlags) -band 2) -ne 0) }
        })
        $own = ''; try { $own = [string]$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch {}
        $c.Writers = @(Get-NonAdminWriters -Aces $rules -OwnerSid $own -OwnerName $(if ($own) { Get-SidName $own } else { '' }) -Mode $c.Mode)
    } catch {
        $e = $_.Exception
        $c.AclError = ($e.GetType().Name + ': ' + $e.Message)
        $c.AclDenied = ($e -is [System.UnauthorizedAccessException] -or $e.InnerException -is [System.UnauthorizedAccessException])
    }
    return $c
}

# Live. One service key.
function Read-ServiceEntry {
    param($Base, [string]$Name)
    $k = $null
    try {
        try { $k = $Base.OpenSubKey($Name, $false) }
        catch {
            $e = $_.Exception; $den = ($e -is [System.Security.SecurityException] -or $e -is [System.UnauthorizedAccessException] -or $e.InnerException -is [System.Security.SecurityException])
            return @{ Name = $Name; State = $(if ($den) { 'denied' } else { 'unreadable' }); Error = ($e.GetType().Name + ': ' + $e.Message) }
        }
        if ($null -eq $k) { return @{ Name = $Name; State = 'ok'; Graded = $false } }
        $type = $k.GetValue('Type', $null)
        $raw = [string]$k.GetValue('ImagePath', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $e = @{ Name = $Name; State = 'ok'; Graded = $false; Shape = ''; Raw = $raw }
        $t = $raw.Trim()
        if (-not (Test-ProcessServiceType $type) -or -not $t -or $t.StartsWith('"') -or $t -notmatch '[ \t]') { return $e }
        # The SCM expands only a REG_EXPAND_SZ ImagePath.
        $kind = ''; try { $kind = [string]$k.GetValueKind('ImagePath') } catch {}
        $cl = $(if ($kind -eq 'ExpandString') { [Environment]::ExpandEnvironmentVariables($t) } else { $t })
        if ($cl -match '^\\\?\?\\') { $e.Shape = 'nt'; return $e }
        if ($cl -notmatch '^[A-Za-z]:\\') { $e.Shape = 'relative'; return $e }
        $r = Resolve-ServicePath -CommandLine $cl -Exists { param([string]$p) Test-Path -LiteralPath $p -PathType Leaf }
        if (@($r.Planted).Count -eq 0 -and @($r.Open).Count -eq 0) { return $e }
        $e.Graded = $true
        $e.Program = $r.Program
        $e.ProgramExists = $r.ProgramExists
        $e.Planted = @($r.Planted | ForEach-Object { @{ Path = $_; File = (Get-FileFacts $_) } })
        $e.Open = @($r.Open | ForEach-Object { Read-OpenPlace $_ })
        return $e
    } catch {
        return @{ Name = $Name; State = 'unreadable'; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
    } finally { if ($k) { $k.Close() } }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    # A plain scriptblock reading a script-scoped set (no closure: 5.1 rule).
    function OnDisk { param([string[]]$Files) $script:DiskSet = @($Files); return { param([string]$p) $script:DiskSet -contains $p } }
    function Place { param([string]$Path, $Writers = @(), [string]$AclError = '', [bool]$Denied = $false, [string]$Mode = 'file') @{ Path = $Path; Dir = (Get-ParentDir $Path); Mode = $Mode; Writers = @($Writers); AclError = $AclError; AclDenied = $Denied } }
    function Svc { param([string]$Name = 'AcmeAgent', $Open = @(), $Planted = @(), [bool]$ProgramExists = $true) @{ Name = $Name; State = 'ok'; Graded = $true; Shape = ''; Raw = 'C:\Program Files\Acme Agent\agent.exe -k run'; Program = 'C:\Program Files\Acme Agent\agent.exe'; ProgramExists = $ProgramExists; Planted = @($Planted); Open = @($Open) } }
    $okList = @{ State = 'ok'; Error = '' }
    $adminOnly = @((Place 'C:\Program.exe'), (Place 'C:\Program Files\Acme.exe'))

    # --- the CreateProcess walk (Microsoft's documented order) ---
    $t = @(Get-CreateProcessTries 'c:\program files\sub dir\program name' | ForEach-Object { $_.Try })
    T 'Microsoft''s own example: program.exe, sub.exe, sub dir\program.exe, program name.exe, in that order' (($t -join '|') -eq 'c:\program.exe|c:\program files\sub.exe|c:\program files\sub dir\program.exe|c:\program files\sub dir\program name.exe') ($t -join '|')
    $r = Resolve-ServicePath 'C:\Program Files\A B\svc.exe -k run' (OnDisk @('C:\Program Files\A B\svc.exe'))
    T 'C:\Program Files\A B\svc.exe: the program found, C:\Program.exe and C:\Program Files\A.exe are the open places' ($r.ProgramExists -and $r.Program -eq 'C:\Program Files\A B\svc.exe' -and (@($r.Open) -join '|') -eq 'C:\Program.exe|C:\Program Files\A.exe' -and @($r.Planted).Count -eq 0) ((@($r.Open) -join '|') + ' / ' + $r.Program)
    $r = Resolve-ServicePath 'C:\Windows\system32\svchost -k netsvcs' (OnDisk @('C:\Windows\system32\svchost.exe'))
    T 'svchost -k netsvcs (no .exe, arguments, no space in the path): nothing to intercept, the real program is never "planted"' ($r.ProgramExists -and @($r.Open).Count -eq 0 -and @($r.Planted).Count -eq 0) ((@($r.Open) + @($r.Planted)) -join '|')
    $r = Resolve-ServicePath 'C:\Program Files\Acme Agent\agent -service' (OnDisk @('C:\Program Files\Acme Agent\agent.exe'))
    T 'no .exe and arguments: agent.exe is the program, not a planted file' ($r.Program -eq 'C:\Program Files\Acme Agent\agent.exe' -and @($r.Planted).Count -eq 0 -and (@($r.Open) -join '|') -eq 'C:\Program.exe|C:\Program Files\Acme.exe') ((@($r.Open) -join '|') + ' / ' + (@($r.Planted) -join '|'))
    $r = Resolve-ServicePath 'C:\Program Files\A B\svc.exe' (OnDisk @('C:\Program.exe', 'C:\Program Files\A B\svc.exe'))
    T 'a file at C:\Program.exe in front of the real program: planted' ((@($r.Planted) -join '|') -eq 'C:\Program.exe' -and $r.Program -eq 'C:\Program Files\A B\svc.exe') (@($r.Planted) -join '|')
    $r = Resolve-ServicePath 'C:\Tools\App v1.2 beta\svc.exe' (OnDisk @('C:\Tools\App v1.2 beta\svc.exe', 'C:\Tools\App v1.2'))
    T 'a folder name with a dot: Windows tries C:\Tools\App v1.2 as-is, so a file there is planted' ((@($r.Planted) -join '|') -eq 'C:\Tools\App v1.2') (@($r.Planted) -join '|')
    $r = Resolve-ServicePath 'C:\Tools\svc.exe -k netsvcs -p' (OnDisk @('C:\Tools\svc.exe'))
    T 'a space only in the ARGUMENTS: nothing to intercept' (@($r.Open).Count -eq 0 -and @($r.Planted).Count -eq 0) (@($r.Open) -join '|')
    $r = Resolve-ServicePath 'C:\Program Files\A B\svc.exe -k x' (OnDisk @())
    T 'the program missing: the open places stop before the first argument, and include the program''s own path' ((@($r.Open) -join '|') -eq 'C:\Program.exe|C:\Program Files\A.exe|C:\Program Files\A B\svc.exe' -and -not $r.ProgramExists) (@($r.Open) -join '|')
    $t = @(Get-CreateProcessTries ("C:\Program Files\A" + [char]9 + "B\svc.exe") | ForEach-Object { $_.Try })
    T 'a tab separates like a space' ($t[0] -eq 'C:\Program.exe' -and $t[1] -eq 'C:\Program Files\A.exe') ($t -join '|')
    T 'a quoted command line: no tries' (@(Get-CreateProcessTries '"C:\Program Files\A\svc.exe" -k').Count -eq 0) ''
    T 'the folder for C:\Program.exe is the drive root C:\' ((Get-ParentDir 'C:\Program.exe') -eq 'C:\' -and (Get-ParentDir 'C:\Program Files\A.exe') -eq 'C:\Program Files') ''
    T 'a service Type 0x10 runs as a process, a per-user template 0x160 too, a kernel driver (1) does not' ((Test-ProcessServiceType 16) -and (Test-ProcessServiceType 0x160) -and -not (Test-ProcessServiceType 1)) ''

    # --- who can write ---
    $w = @(Get-NonAdminWriters @(@{ Sid = 'S-1-5-32-545'; Name = 'BUILTIN\Users'; Allow = $true; Rights = 0x2; InheritOnly = $false }))
    T 'Users granted CreateFiles on the folder: named' ($w.Count -eq 1 -and $w[0] -eq 'BUILTIN\Users') ($w -join ',')
    $root = @(@{ Sid = 'S-1-5-11'; Name = 'NT AUTHORITY\Authenticated Users'; Allow = $true; Rights = 0x4; InheritOnly = $false }, @{ Sid = 'S-1-5-11'; Name = 'x'; Allow = $true; Rights = 0x1301BF; InheritOnly = $true }, @{ Sid = 'S-1-5-32-544'; Name = 'a'; Allow = $true; Rights = 0x1F01FF; InheritOnly = $false })
    T 'C:\ as Windows ships it (create subfolders only, Modify inherit-only): no one but administrators can create C:\Program.exe' (@(Get-NonAdminWriters $root -OwnerSid 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464').Count -eq 0) ''
    $w = @(Get-NonAdminWriters $root -Mode 'folder')
    T 'the same C:\ when the folder below does not exist yet: Authenticated Users can create it, so they count' ($w.Count -eq 1 -and $w[0] -eq 'NT AUTHORITY\Authenticated Users') ($w -join ',')
    $w = @(Get-NonAdminWriters @(@{ Sid = 'S-1-5-21-1-2-3-1001'; Name = 'PC\bob'; Allow = $true; Rights = 0x1F01FF; InheritOnly = $false }, @{ Sid = 'S-1-5-18'; Name = 'SYSTEM'; Allow = $true; Rights = 0x1F01FF; InheritOnly = $false }))
    T 'a folder one ordinary account may write (bob, with SYSTEM): bob counts, whoever runs the audit' ($w.Count -eq 1 -and $w[0] -eq 'PC\bob') ($w -join ',')
    $w = @(Get-NonAdminWriters @(@{ Sid = 'S-1-5-32-545'; Name = 'BUILTIN\Users'; Allow = $true; Rights = 0x40000; InheritOnly = $false }))
    T 'WRITE_DAC granted to Users counts: they can grant themselves the rest' ($w.Count -eq 1) ($w -join ',')
    $w = @(Get-NonAdminWriters @() -OwnerSid 'S-1-5-21-1-2-3-1001' -OwnerName 'PC\bob')
    T 'a folder OWNED by an ordinary account counts, with no allow entry at all' ($w.Count -eq 1 -and $w[0] -match 'owner PC\\bob') ($w -join ',')
    $w = @(Get-NonAdminWriters @(@{ Sid = 'S-1-1-0'; Name = 'Everyone'; Allow = $false; Rights = 0x2; InheritOnly = $false }))
    T 'a DENY entry grants nothing' ($w.Count -eq 0) ($w -join ',')
    $w = @(Get-NonAdminWriters @(@{ Sid = 'S-1-5-80-123-456'; Name = 'NT SERVICE\AcmeAgent'; Allow = $true; Rights = 0x1F01FF; InheritOnly = $false }))
    T 'a per-service NT SERVICE account is not counted' ($w.Count -eq 0) ($w -join ',')

    # --- the verdict ---
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Open $adminOnly)); $t = $v.Lines -join "`n"
    T 'only administrators can put a program at the open places: INFO with the path, [OK], nothing raised' ((-not ($v.Crit -or $v.Warn -or $v.Gap)) -and $v.State -eq 'uq=info,n=1' -and $t -match '(?m)^\[INFO\] Unquoted service path, not exploitable as installed: service AcmeAgent runs C:\\Program Files\\Acme Agent\\agent\.exe -k run; only administrators can put a program at C:\\Program\.exe, C:\\Program Files\\Acme\.exe' -and $t -match '(?m)^\[OK\] No unquoted service path a non-administrator can exploit') $t
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Open @((Place 'C:\Program.exe'), (Place 'C:\Program Files\Acme.exe' -Writers @('BUILTIN\Users'))))); $t = $v.Lines -join "`n"
    T 'a folder Users can write: the WARNING naming the place and who' ($v.Warn -and $v.State -eq 'uq=warn,n=1' -and $t -match '(?m)^\[WARNING\] Unquoted service path a non-administrator can hijack -- service AcmeAgent' -and $t -match 'C:\\Program Files\\Acme\.exe -- its folder lets BUILTIN\\Users create it' -and $t -notmatch '\[OK\]') $t
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Open @((Place 'C:\Apps\Vendor.exe' -Writers @('NT AUTHORITY\Authenticated Users') -Mode 'folder'))))
    T 'a folder that does not exist yet, under one Authenticated Users may create folders in: the WARNING, said as such' ($v.Warn -and ($v.Lines -join ' ') -match 'does not exist yet') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Planted @(@{ Path = 'C:\Program.exe'; File = 'C:\Program.exe, 4096 bytes, NOT validly signed (NotSigned)' }))); $t = $v.Lines -join "`n"
    T 'a file already at C:\Program.exe: CRITICAL, with the file''s details beneath' ($v.Crit -and $v.State -eq 'uq=crit,n=1' -and $t -match '(?m)^\[CRITICAL\] Unquoted service path: a file already sits where Windows looks first -- service AcmeAgent' -and $t -match 'Windows tries C:\\Program\.exe before C:\\Program Files\\Acme Agent\\agent\.exe' -and $t -match '(?m)^\[INFO\]   that file: C:\\Program\.exe, 4096 bytes') $t
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Open @((Place 'C:\Program.exe' -AclError 'IOException: x'))))
    T 'permissions that could not be read: a raised GAP naming the folder, never a hijack row, never INFO, never [OK]' ($v.Gap -and (-not $v.Warn) -and ($v.Lines -join ' ') -match 'could not be graded: AcmeAgent \(who can write C:\\: IOException' -and ($v.Lines -join ' ') -notmatch '\[OK\]|not exploitable') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Open @((Place 'C:\Program.exe' -AclError 'UnauthorizedAccessException: denied' -Denied $true)))) -IsElevated $false
    T 'permissions refused to a standard-user token: a counted deferral, not a row' ((-not $v.Gap) -and $v.Deferred -eq 1 -and ($v.Lines -join ' ') -match '\[DEFERRED - ADMIN REQUIRED\]') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List @{ State = 'unreadable'; Error = 'SecurityException: denied' } -Services @()
    T 'the Services key could not be listed: a raised gap, never [OK]' ($v.Gap -and $v.State -eq 'uq=gap,n=0' -and ($v.Lines -join ' ') -match '^\[WARNING\] Unquoted service path check NOT performed -- the service registry' -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $den = @{ Name = 'Locked'; State = 'denied'; Error = 'SecurityException: denied' }
    $v = Get-UnquotedVerdict -List $okList -Services @($den) -IsElevated $false
    T 'a service key refused to a standard-user token: a counted deferral, never [OK]' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.State -eq 'uq=deferred,n=0' -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @($den) -IsElevated $true
    T 'the same refusal for an administrator: a raised gap' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Open @((Place 'C:\Program.exe' -Writers @('Everyone')))), @{ Name = 'Broken'; State = 'unreadable'; Error = 'IOException: x' })
    T 'a hijackable service AND an unreadable key: both raised, the gap says "in full"' ($v.Warn -and $v.Gap -and ($v.Lines -join ' ') -match 'NOT performed in full') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @(@{ Name = 'Plain'; State = 'ok'; Graded = $false; Shape = ''; Raw = '"C:\Program Files\A\b.exe"' })
    T 'no unquoted path at all: [OK] naming how many keys were read' ($v.State -eq 'uq=none,n=0' -and ($v.Lines -join ' ') -match '^\[OK\] No service runs from an unquoted path with a space in its program path \(1 service key\(s\) read') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @(@{ Name = 'NtForm'; State = 'ok'; Graded = $false; Shape = 'nt'; Raw = '\??\C:\Program Files\A B\x.exe' })
    T 'a \??\ path is counted as a form not graded, never silent' (($v.Lines -join ' ') -match '1 service\(s\) with an unquoted path in a form this check does not grade.*NtForm') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Name ('x' + [char]13 + [char]10 + '[OK] No unquoted service path') -Open @((Place 'C:\Program.exe' -Writers @('BUILTIN\Users')))))
    T 'a line break inside a service name cannot forge an [OK] line' ($v.Warn -and @($v.Lines | Where-Object { $_ -match '^\[OK\]' }).Count -eq 0) ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -ProgramExists $false -Open @((Place 'C:\Program.exe' -Writers @('BUILTIN\Users')))))
    T 'the program itself missing is said beside the finding' ($v.Warn -and ($v.Lines -join ' ') -match 'the program it names does not exist') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails unquoted_service_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] unquoted_service_check self-test: Windows'' documented search order, a file already in front of the program is CRITICAL, a place a non-administrator can fill is a WARNING, an admin-only place is INFO, and a key or permission that could not be read is a raised gap (or a deferral for a refused standard user), never [OK].'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$list = @{ State = 'ok'; Error = '' }
$services = @()
$base = $null
try {
    $base = Get-Item -LiteralPath $ServicesRoot -ErrorAction Stop
    $names = @($base.GetSubKeyNames())
    $services = @($names | ForEach-Object { Read-ServiceEntry -Base $base -Name $_ })
} catch {
    $list = @{ State = 'unreadable'; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
} finally { if ($base) { try { $base.Close() } catch {} } }
$v = $null
try { $v = Get-UnquotedVerdict -List $list -Services $services -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^uq=(crit|warn|gap|deferred|info|none),n=\d+$') {
    'unquoted_service_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
# Markers first, each one written or the tool stops: a marker that cannot be
# written leaves no state, and the bat raises "produced no verdict". Writing
# the state first would let a saved state stand over a finding that never
# reached the ledger.
try {
    if ($v.Crit) { Write-Marker -Name 'unquoted_crit' -Sev 'CRITICAL' }
    if ($v.Warn) { Write-Marker -Name 'unquoted_warn' -Sev 'WARNING' }
    if ($v.Gap) { Write-Marker -Name 'unquoted_gap' -Sev 'WARNING' }
    if ($v.Deferred -gt 0) { Write-Marker -Name 'unquoted_deferred' -Sev ([string]$v.Deferred) }
    Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop
} catch { ('unquoted_service_check: the verdict above could not be saved for the bat (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
exit 0
