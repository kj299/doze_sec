# unquoted_service_check.ps1 -- can a service be made to run someone else's
# program (T1574.009, path interception by unquoted path)?
#
# A service whose ImagePath is NOT quoted and has a space inside the program's
# own path -- C:\Program Files\Acme Agent\agent.exe -- is started by
# CreateProcess, which cannot tell where the path ends. It tries each
# space-separated prefix in turn, so it runs C:\Program.exe, then
# C:\Program Files\Acme.exe, before the real program. A file at one of those
# places runs as the service's account (often SYSTEM) at its next start.
#
# The check was an inline block that matched any service path containing a
# space anywhere (arguments included), printed a bare table with no severity
# and raised nothing, and printed an unraised [SKIPPED] when the service query
# failed. Win32_Service also leaves out a service whose DACL denies this
# token, so the source is now what Windows itself runs: each service's
# ImagePath in the registry, which a standard user can read.
#
# THE RULE (pure, pinned by -SelfTest; the owner's choice, 2026-11-16):
#   * only services that run as a PROCESS are graded (Type 0x10/0x20, the
#     0x50/0x60 per-user templates, with or without the 0x100 interactive
#     bit). A driver is loaded by exact path and is not searched;
#   * a quoted ImagePath is not graded; a space only in the ARGUMENTS gives no
#     place to intercept and is not graded either;
#   * the places Windows tries first are <prefix>.exe for each space inside
#     the program's path;
#   * CRITICAL: a file already sits at one of them -- the attack is done;
#   * WARNING: a non-administrator may create a file in one of their folders
#     (an allow entry granting CreateFiles to Everyone, Authenticated Users,
#     Users, INTERACTIVE, or -- on a standard-user token -- this account).
#     Deny entries are not subtracted, and a folder whose permissions could
#     not be read is a WARNING stated as not known: "could not check" goes
#     with the risky half;
#   * INFO: only administrators can create a file there -- a careless install
#     that cannot be exploited as it stands. Listed with its path.
#   Note: AppendData on a FOLDER is "create subfolders", not files, which is
#   what Authenticated Users hold on C:\ by default. It is not counted.
#   * the Services key that could not be listed is a raised gap; one service
#     key refused to a standard-user token is a counted deferral, and to an
#     administrator a raised gap. A finding and a gap are both raised.
# Markers: dz_unquoted_crit / dz_unquoted_warn / dz_unquoted_gap /
# dz_unquoted_deferred. State: dz_unquoted_state.txt
#   uq=<crit|warn|info|none|gap|deferred>,n=<graded count>
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
# Everyone, Authenticated Users, Users, INTERACTIVE.
$script:LowPrivSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4')
$script:SidNames = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-32-545' = 'Users'; 'S-1-5-4' = 'INTERACTIVE' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function ConvertTo-PrintableText {
    # Registry text goes into the report: no control characters, capped.
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt 260) { $t = $t.Substring(0, 260) + '...' }
    return $t
}

# Expand the forms a service ImagePath / driver PathName / task action takes
# into a path Test-Path can see: %var%, \??\, \SystemRoot, surrounding quotes.
function Resolve-BinPath {
    param([string]$Raw)
    if (-not $Raw) { return '' }
    $p = [Environment]::ExpandEnvironmentVariables($Raw.Trim().Trim('"'))
    $p = $p -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
    if ($p -match '^"') { $p = $p.Trim('"') }
    return $p
}

# Pull the executable path out of a service ImagePath / scheduled-task action
# so signature checks have something to work with. An UNQUOTED action whose
# path contains spaces ("C:\Program Files\Microsoft OneDrive\<ver>\
# OneDriveLauncher.exe /startInstances") has no delimiter between path and
# arguments; CreateProcess tries each space-separated prefix and runs the
# first file that exists, so the signature check has to find the binary the
# same way. Taking the first token ("C:\Program") found nothing, the
# signature check never ran, and three OneDrive tasks were WARNING for a
# version bump their sibling service (quoted path) read as INFO. -Exists is
# the file probe, injectable so the walk can be pinned without a disk.
function Get-BinPath {
    param([string]$Raw, [scriptblock]$Exists = $null)
    if (-not $Raw) { return '' }
    $s = $Raw.Trim()
    if ($s.StartsWith('"')) {
        $end = $s.IndexOf('"', 1)
        if ($end -gt 1) { return $s.Substring(1, $end - 1) }
    }
    if ($null -eq $Exists) { $Exists = { param([string]$p) Test-Path -LiteralPath $p -PathType Leaf } }
    $tok = @($s -split ' ')
    $max = [Math]::Min($tok.Count, 16)
    for ($i = 1; $i -le $max; $i++) {
        $cand = ($tok[0..($i - 1)] -join ' ')
        if ($cand -notmatch '\.(exe|sys|dll)$') { continue }
        $hit = $false
        try { $hit = [bool](& $Exists (Resolve-BinPath $cand)) } catch { $hit = $false }
        if ($hit) { return $cand }
    }
    $m = [regex]::Match($s, '^[^\s]+\.(exe|sys|dll)', 'IgnoreCase')
    if ($m.Success) { return $m.Value }
    return $s
}

# PURE. The folder a candidate file would be created in, by string, so the
# answer does not depend on the engine's path separator: C:\Program.exe ->
# C:\ (the drive root), C:\Program Files\A.exe -> C:\Program Files.
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

# PURE. The places CreateProcess tries before $Bin, for an UNQUOTED $Bin
# (the program's own path, no arguments): <prefix>.exe for each space inside
# it. 'C:\Program Files\A B\svc.exe' -> C:\Program.exe, C:\Program Files\A.exe.
function Get-InterceptionCandidates {
    param([string]$Bin)
    $out = New-Object System.Collections.ArrayList
    if (-not $Bin -or $Bin.StartsWith('"')) { return @() }
    $tok = @($Bin -split ' ')
    for ($i = 1; $i -lt $tok.Count; $i++) {
        $pre = ($tok[0..($i - 1)] -join ' ')
        if (-not $pre -or $pre.EndsWith('\')) { continue }
        [void]$out.Add($pre + '.exe')
    }
    return @($out.ToArray())
}

# PURE. Who other than an administrator may create a FILE in this folder?
# $Aces: @( @{ Sid; Allow = $true|$false; Rights = <int>; InheritOnly = $bool } ).
# CreateFiles (0x2), GENERIC_WRITE (0x40000000) and GENERIC_ALL (0x10000000)
# count; AppendData (0x4) on a folder is "create subfolders" and does not.
# Returns the names that may, or @() when only administrators may.
function Get-LowPrivWriters {
    param($Aces, [string]$OwnSid = '')
    $who = New-Object System.Collections.ArrayList
    $sids = @($script:LowPrivSids); if ($OwnSid) { $sids += $OwnSid }
    foreach ($a in @($Aces)) {
        if (-not $a.Allow -or $a.InheritOnly) { continue }
        $r = 0; try { $r = [long]$a.Rights } catch { continue }
        if (($r -band 0x2) -eq 0 -and ($r -band 0x40000000) -eq 0 -and ($r -band 0x10000000) -eq 0) { continue }
        $s = [string]$a.Sid
        if ($sids -notcontains $s) { continue }
        $n = $(if ($script:SidNames.ContainsKey($s)) { $script:SidNames[$s] } else { 'this account' })
        if ($who -notcontains $n) { [void]$who.Add($n) }
    }
    return @($who.ToArray())
}

# PURE. $List: @{ State = ok|unreadable; Error }. $Services: @( @{ Name;
# State = ok|denied|unreadable; Error; Graded = $bool; Raw; Bin; BinExists;
# Cands = @( @{ Path; Exists; File = '<facts>'; Writers = @(..); AclError } ) } ).
# Returns @{ Lines; Crit; Warn; Gap; Deferred; State }.
function Get-UnquotedVerdict {
    param($List, $Services, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    if ([string]$List.State -ne 'ok') {
        [void]$out.Add(('[WARNING] Unquoted service path check NOT performed -- the service registry (HKLM\SYSTEM\CurrentControlSet\Services) could not be listed (' + (ConvertTo-PrintableText ([string]$List.Error)) + '), so a service Windows could be tricked into running the wrong program for would go unseen (T1574.009).'))
        return @{ Lines = @($out.ToArray()); Crit = $false; Warn = $false; Gap = $true; Deferred = 0; State = 'uq=gap,n=0' }
    }
    $crit = New-Object System.Collections.ArrayList
    $nCrit = 0
    $warn = New-Object System.Collections.ArrayList
    $info = New-Object System.Collections.ArrayList
    $failed = New-Object System.Collections.ArrayList
    $denied = New-Object System.Collections.ArrayList
    $read = 0
    foreach ($s in @($Services)) {
        $name = ConvertTo-PrintableText ([string]$s.Name)
        $st = [string]$s.State
        if ($st -eq 'denied' -and -not $IsElevated) { [void]$denied.Add($name); continue }
        if ($st -ne 'ok') { [void]$failed.Add(($name + ' (' + (ConvertTo-PrintableText ([string]$s.Error)) + ')')); continue }
        $read++
        if (-not $s.Graded) { continue }
        $img = ConvertTo-PrintableText ([string]$s.Raw)
        $binNote = $(if ($s.BinExists) { '' } else { ' (that program does not exist)' })
        $planted = @($s.Cands | Where-Object { $_.Exists })
        $open = @($s.Cands | Where-Object { -not $_.Exists -and (@($_.Writers).Count -gt 0 -or [string]$_.AclError) })
        if ($planted.Count -gt 0) {
            $p = $planted[0]
            $nCrit++
            [void]$crit.Add(('[CRITICAL] Unquoted service path: a file already sits where Windows looks first -- service ' + $name + ' runs ' + $img + $binNote + ', and Windows tries ' + (ConvertTo-PrintableText ([string]$p.Path)) + ' before the real program; it runs as the service account at the next start (T1574.009).'))
            [void]$crit.Add(('[INFO]   that file: ' + (ConvertTo-PrintableText ([string]$p.File))))
        } elseif ($open.Count -gt 0) {
            $parts = @($open | ForEach-Object {
                $d = ConvertTo-PrintableText (Get-ParentDir ([string]$_.Path))
                if ([string]$_.AclError) { $d + ' (who can write there could not be read: ' + (ConvertTo-PrintableText ([string]$_.AclError)) + ')' }
                else { $d + ' (writable by ' + (@($_.Writers) -join ', ') + ')' }
            })
            [void]$warn.Add(('[WARNING] Unquoted service path a non-administrator can hijack -- service ' + $name + ' runs ' + $img + $binNote + '; Windows tries ' + ((@($open | ForEach-Object { ConvertTo-PrintableText ([string]$_.Path) })) -join ', ') + ' first, and a program placed there would run as the service account. The folder''s permissions grant file creation: ' + ($parts -join '; ') + ' (T1574.009).'))
        } else {
            [void]$info.Add(('[INFO] Unquoted service path, not exploitable as installed: service ' + $name + ' runs ' + $img + $binNote + '; only administrators can create ' + ((@($s.Cands | ForEach-Object { ConvertTo-PrintableText ([string]$_.Path) })) -join ', ') + '. The vendor should quote it.'))
        }
    }
    foreach ($l in $crit) { [void]$out.Add($l) }
    $nw = 0; foreach ($l in $warn) { $nw++; if ($nw -le $script:MaxListed) { [void]$out.Add($l) } }
    if ($warn.Count -gt $script:MaxListed) { [void]$out.Add(('[INFO] ... and ' + ($warn.Count - $script:MaxListed) + ' more hijackable service(s).')) }
    $ni = 0; foreach ($l in $info) { $ni++; if ($ni -le $script:MaxListed) { [void]$out.Add($l) } }
    if ($info.Count -gt $script:MaxListed) { [void]$out.Add(('[INFO] ... and ' + ($info.Count - $script:MaxListed) + ' more unquoted path(s) only administrators can exploit.')) }
    if ($crit.Count -or $warn.Count) {
        [void]$out.Add('[INFO] Verify: (Get-ItemProperty ''HKLM:\SYSTEM\CurrentControlSet\Services\<name>'').ImagePath -- and look at the file or folder named above. A file you do not recognise at one of those places is the attack; quoting the path is the vendor''s fix.')
    }
    $gap = ($failed.Count -gt 0)
    if ($gap) {
        $lead = $(if ($crit.Count -or $warn.Count -or $info.Count) { '[WARNING] Unquoted service path check NOT performed in full -- ' } else { '[WARNING] Unquoted service path check NOT performed -- ' })
        $shown = @($failed | Select-Object -First 10)
        $more = $(if ($failed.Count -gt 10) { '; and ' + ($failed.Count - 10) + ' more' } else { '' })
        [void]$out.Add(($lead + $failed.Count + ' service key(s) could not be read: ' + ($shown -join '; ') + $more + ' (T1574.009).'))
    }
    $deferred = $(if ($denied.Count) { 1 } else { 0 })
    if ($deferred) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] ' + $denied.Count + ' service key(s) were refused to this standard-user token and not graded: ' + ((@($denied | Select-Object -First 10)) -join ', ') + '; an audit run as administrator reads them.'))
    }
    if (-not ($crit.Count -or $warn.Count -or $gap -or $deferred)) {
        $lead = $(if ($info.Count) { '[OK] No unquoted service path a non-administrator can exploit' } else { '[OK] No service runs from an unquoted path with a space in its program path' })
        [void]$out.Add(($lead + ' (' + $read + ' service key(s) read from the registry).'))
    }
    $state = $(if ($crit.Count) { 'crit' } elseif ($warn.Count) { 'warn' } elseif ($gap) { 'gap' } elseif ($deferred) { 'deferred' } elseif ($info.Count) { 'info' } else { 'none' })
    return @{ Lines = @($out.ToArray()); Crit = ($crit.Count -gt 0); Warn = ($warn.Count -gt 0); Gap = $gap; Deferred = $deferred; State = ('uq=' + $state + ',n=' + ($nCrit + $warn.Count + $info.Count)) }
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

# Live. The folder's access entries in the shape Get-LowPrivWriters reads.
function Read-FolderAces {
    param([string]$Dir)
    $acl = Get-Acl -LiteralPath $Dir -ErrorAction Stop
    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    return @($rules | ForEach-Object {
        @{ Sid = [string]$_.IdentityReference.Value; Allow = ([string]$_.AccessControlType -eq 'Allow'); Rights = [long][int]$_.FileSystemRights; InheritOnly = ((([int]$_.PropagationFlags) -band 2) -ne 0) }
    })
}

# Live. One service key.
function Read-ServiceEntry {
    param($Base, [string]$Name, [string]$OwnSid)
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
        $e = @{ Name = $Name; State = 'ok'; Graded = $false; Raw = $raw }
        if (-not (Test-ProcessServiceType $type) -or -not $raw.Trim() -or $raw.Trim().StartsWith('"')) { return $e }
        $exp = [Environment]::ExpandEnvironmentVariables($raw.Trim())
        if ($exp -notmatch '^[A-Za-z]:\\') { return $e }
        $bin = Get-BinPath $exp
        $cands = @(Get-InterceptionCandidates $bin)
        if ($cands.Count -eq 0) { return $e }
        $e.Graded = $true
        $e.Bin = $bin
        $e.BinExists = (Test-Path -LiteralPath $bin -PathType Leaf)
        $e.Cands = @($cands | ForEach-Object {
            $c = @{ Path = $_; Exists = $false; File = ''; Writers = @(); AclError = '' }
            if (Test-Path -LiteralPath $_ -PathType Leaf) { $c.Exists = $true; $c.File = Get-FileFacts $_ }
            else {
                $dir = Get-ParentDir $_
                if ($dir -and (Test-Path -LiteralPath $dir -PathType Container)) {
                    try { $c.Writers = @(Get-LowPrivWriters (Read-FolderAces $dir) $OwnSid) } catch { $c.AclError = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
                }
            }
            $c
        })
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
    function Svc { param([string]$Name = 'AcmeAgent', $Cands, [bool]$BinExists = $true, [string]$Raw = 'C:\Program Files\Acme Agent\agent.exe -k run') @{ Name = $Name; State = 'ok'; Graded = $true; Raw = $Raw; Bin = 'C:\Program Files\Acme Agent\agent.exe'; BinExists = $BinExists; Cands = @($Cands) } }
    function Cand { param([string]$Path, [bool]$Exists = $false, $Writers = @(), [string]$AclError = '') @{ Path = $Path; Exists = $Exists; File = $(if ($Exists) { $Path + ', 4096 bytes, NOT validly signed (NotSigned)' } else { '' }); Writers = @($Writers); AclError = $AclError } }
    $okList = @{ State = 'ok'; Error = '' }
    $adminOnly = @((Cand 'C:\Program.exe'), (Cand 'C:\Program Files\Acme.exe'))

    $c = @(Get-InterceptionCandidates 'C:\Program Files\A B\svc.exe')
    T 'the places Windows tries first: one per space inside the program path' ($c.Count -eq 2 -and $c[0] -eq 'C:\Program.exe' -and $c[1] -eq 'C:\Program Files\A.exe') ($c -join ' | ')
    T 'the folder for C:\Program.exe is the drive root C:\' ((Get-ParentDir 'C:\Program.exe') -eq 'C:\' -and (Get-ParentDir 'C:\Program Files\A.exe') -eq 'C:\Program Files') ((Get-ParentDir 'C:\Program.exe') + ' | ' + (Get-ParentDir 'C:\Program Files\A.exe'))
    $c = @(Get-InterceptionCandidates 'C:\Tools\svc.exe')
    T 'no space in the program path: nowhere to intercept' ($c.Count -eq 0) ($c -join ' | ')
    $c = @(Get-InterceptionCandidates '"C:\Program Files\A\svc.exe"')
    T 'a quoted path: nowhere to intercept' ($c.Count -eq 0) ($c -join ' | ')
    $g = Get-BinPath 'C:\Tools\svc.exe -k netsvcs -p' { param($p) $p -eq 'C:\Tools\svc.exe' }
    T 'a space only in the ARGUMENTS: the program path has none, so it is not graded' ($g -eq 'C:\Tools\svc.exe' -and @(Get-InterceptionCandidates $g).Count -eq 0) $g
    T 'a service Type 0x10 (own process) runs as a process' (Test-ProcessServiceType 16) ''
    T 'a per-user template 0x60 with the interactive bit (0x160) runs as a process' (Test-ProcessServiceType 0x160) ''
    T 'a kernel driver (Type 1) is loaded by exact path and is not graded' (-not (Test-ProcessServiceType 1)) ''

    $w = @(Get-LowPrivWriters @(@{ Sid = 'S-1-5-32-545'; Allow = $true; Rights = 0x2; InheritOnly = $false }))
    T 'Users granted CreateFiles on the folder: Users can write there' ($w.Count -eq 1 -and $w[0] -eq 'Users') ($w -join ',')
    # C:\ as Windows ships it: Authenticated Users may create SUBFOLDERS
    # (AppendData, this folder only) and Modify only on what is below.
    $root = @(@{ Sid = 'S-1-5-11'; Allow = $true; Rights = 0x4; InheritOnly = $false }, @{ Sid = 'S-1-5-11'; Allow = $true; Rights = 0x1301BF; InheritOnly = $true }, @{ Sid = 'S-1-5-32-544'; Allow = $true; Rights = 0x1F01FF; InheritOnly = $false })
    $w = @(Get-LowPrivWriters $root)
    T 'C:\ as Windows ships it (create subfolders only, Modify inherit-only): no non-administrator can create C:\Program.exe' ($w.Count -eq 0) ($w -join ',')
    $w = @(Get-LowPrivWriters @(@{ Sid = 'S-1-5-21-1-2-3-1001'; Allow = $true; Rights = 0x1301BF; InheritOnly = $false }) 'S-1-5-21-1-2-3-1001')
    T 'on a standard-user token, a folder this account may write: this account' ($w.Count -eq 1 -and $w[0] -eq 'this account') ($w -join ',')
    $w = @(Get-LowPrivWriters @(@{ Sid = 'S-1-1-0'; Allow = $false; Rights = 0x2; InheritOnly = $false }))
    T 'a DENY entry grants nothing' ($w.Count -eq 0) ($w -join ',')

    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Cands $adminOnly)); $t = $v.Lines -join "`n"
    T 'only administrators can create the files: INFO with the path, [OK] says none is exploitable, nothing raised' ((-not ($v.Crit -or $v.Warn -or $v.Gap)) -and $v.State -eq 'uq=info,n=1' -and $t -match '(?m)^\[INFO\] Unquoted service path, not exploitable as installed: service AcmeAgent runs C:\\Program Files\\Acme Agent\\agent\.exe -k run' -and $t -match '(?m)^\[OK\] No unquoted service path a non-administrator can exploit') $t
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Cands @((Cand 'C:\Program.exe'), (Cand 'C:\Program Files\Acme.exe' -Writers @('Users'))))); $t = $v.Lines -join "`n"
    T 'a folder Users can write: the WARNING, naming the place and who can write it' ($v.Warn -and (-not $v.Crit) -and $v.State -eq 'uq=warn,n=1' -and $t -match '(?m)^\[WARNING\] Unquoted service path a non-administrator can hijack -- service AcmeAgent' -and $t -match 'C:\\Program Files \(writable by Users\)' -and $t -notmatch '\[OK\]') $t
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Cands @((Cand 'C:\Program.exe' -Exists $true), (Cand 'C:\Program Files\Acme.exe')))); $t = $v.Lines -join "`n"
    T 'a file already at C:\Program.exe: CRITICAL, with the file''s details beneath' ($v.Crit -and $v.State -eq 'uq=crit,n=1' -and $t -match '(?m)^\[CRITICAL\] Unquoted service path: a file already sits where Windows looks first -- service AcmeAgent' -and $t -match 'Windows tries C:\\Program\.exe before the real program' -and $t -match '(?m)^\[INFO\]   that file: C:\\Program\.exe, 4096 bytes') $t
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Cands @((Cand 'C:\Program.exe' -AclError 'UnauthorizedAccessException: denied'))))
    T 'a folder whose permissions could not be read: WARNING stated as not known, never INFO or [OK]' ($v.Warn -and ($v.Lines -join ' ') -match 'who can write there could not be read' -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List @{ State = 'unreadable'; Error = 'SecurityException: denied' } -Services @()
    T 'the Services key could not be listed: a raised gap, never [OK]' ($v.Gap -and $v.State -eq 'uq=gap,n=0' -and ($v.Lines -join ' ') -match '^\[WARNING\] Unquoted service path check NOT performed -- the service registry' -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $den = @{ Name = 'Locked'; State = 'denied'; Error = 'SecurityException: denied' }
    $v = Get-UnquotedVerdict -List $okList -Services @($den) -IsElevated $false
    T 'a service key refused to a standard-user token: a counted deferral, not a row, never [OK]' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.State -eq 'uq=deferred,n=0' -and ($v.Lines -join ' ') -match '\[DEFERRED - ADMIN REQUIRED\] 1 service key' -and ($v.Lines -join ' ') -notmatch '\[OK\]') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @($den) -IsElevated $true
    T 'the same refusal for an administrator: a raised gap' ($v.Gap -and $v.Deferred -eq 0) ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Cands @((Cand 'C:\Program.exe' -Writers @('Everyone')))), @{ Name = 'Broken'; State = 'unreadable'; Error = 'IOException: x' })
    T 'a hijackable service AND an unreadable key: both raised, the gap says "in full"' ($v.Warn -and $v.Gap -and ($v.Lines -join ' ') -match 'NOT performed in full') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @(@{ Name = 'Plain'; State = 'ok'; Graded = $false; Raw = '"C:\Program Files\A\b.exe"' })
    T 'no unquoted path at all: [OK] naming how many keys were read' ($v.State -eq 'uq=none,n=0' -and ($v.Lines -join ' ') -match '^\[OK\] No service runs from an unquoted path with a space in its program path \(1 service key\(s\) read') ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Name ('x' + [char]13 + [char]10 + '[OK] No unquoted service path') -Cands @((Cand 'C:\Program.exe' -Writers @('Users')))))
    T 'a line break inside a service name cannot forge an [OK] line' ($v.Warn -and @($v.Lines | Where-Object { $_ -match '^\[OK\]' }).Count -eq 0) ($v.Lines -join ' | ')
    $v = Get-UnquotedVerdict -List $okList -Services @((Svc -Cands @((Cand 'C:\Program.exe' -Writers @('Users'))) -BinExists $false))
    T 'the program itself missing is said beside the finding' ($v.Warn -and ($v.Lines -join ' ') -match 'that program does not exist') ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails unquoted_service_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] unquoted_service_check self-test: a file already at an interception point is CRITICAL, a folder a non-administrator can write is a WARNING, an admin-only folder is INFO, a space only in the arguments is nothing, and a key that could not be read is a raised gap (or a deferral for a refused standard user), never [OK].'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$ownSid = ''
if ($Elevated -ne 1) { try { $ownSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch {} }
$list = @{ State = 'ok'; Error = '' }
$services = @()
$base = $null
try {
    $base = Get-Item -LiteralPath $ServicesRoot -ErrorAction Stop
    $names = @($base.GetSubKeyNames())
    $services = @($names | ForEach-Object { Read-ServiceEntry -Base $base -Name $_ -OwnSid $ownSid })
} catch {
    $list = @{ State = 'unreadable'; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
} finally { if ($base) { try { $base.Close() } catch {} } }
$v = $null
try { $v = Get-UnquotedVerdict -List $list -Services $services -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^uq=(crit|warn|info|none|gap|deferred),n=\d+$') {
    'unquoted_service_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
# The state first: when it cannot be saved the bat raises "produced no
# verdict", and a marker written before it would raise beside that.
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII -ErrorAction Stop }
catch { ('unquoted_service_check: the verdict above could not be saved (' + (ConvertTo-PrintableText $_.Exception.Message) + ').'); exit 1 }
if ($v.Crit) { Write-Marker -Name 'unquoted_crit' -Sev 'CRITICAL' }
if ($v.Warn) { Write-Marker -Name 'unquoted_warn' -Sev 'WARNING' }
if ($v.Gap) { Write-Marker -Name 'unquoted_gap' -Sev 'WARNING' }
if ($v.Deferred -gt 0) { Write-Marker -Name 'unquoted_deferred' -Sev ([string]$v.Deferred) }
exit 0
