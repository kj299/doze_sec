# make_usb_stick.ps1 -- put doze_sec on a USB stick, and check the stick when
# it comes back. Run it on YOUR OWN laptop, never on the machine being audited.
#
# WHAT IT DOES
#   -Drive E:            copies the tool into E:\doze_sec, reads every file back,
#                        and writes a SHA-256 manifest -- one copy kept on this
#                        laptop, one on the stick.
#   -Drive E: -Verify    after the stick has been to another machine: compares
#                        E:\doze_sec with the manifest kept on this laptop and
#                        lists every file changed, added or removed.
#   -ToFolder D:\x       the same copy into a plain folder (CI, or a copy you
#                        will carry some other way). Verify works the same.
#   -ListCandidates      read-only: every lettered volume and whether this
#                        script would accept it.
#   -Refresh             with -Drive/-ToFolder: replace an earlier copy. It
#                        removes <target>\doze_sec only when that folder's
#                        manifest says this script wrote it.
#
# WHAT IT NEVER DOES
#   It never formats, partitions or writes boot files. There is no
#   Format-Volume, Clear-Disk, Initialize-Disk, New-Partition, diskpart or
#   bcdboot in it, and its self-test fails if one appears. Formatting erases
#   every file on the selected drive, and picking the wrong drive erases the
#   wrong one; a copy cannot. If the stick needs formatting, do it yourself in
#   File Explorer after checking the drive letter is the stick.
#
#   The stick is NOT bootable, on purpose. doze_sec audits the Windows that is
#   running; booting the PC from a stick runs a different Windows, so the audit
#   would describe the stick. Windows' own bootable stick (a recovery drive)
#   has no PowerShell, so the audit could not start there anyway. And booting
#   other media can make a BitLocker PC demand its 48-digit recovery key at the
#   next start -- without it, every file on C: is lost. See README.md.
#
# WHAT GOES ON THE STICK
#   Everything the audit needs, and nothing that changes a machine. Left off,
#   and named when the copy runs: .git, .github, .claude, and the test
#   harness -- tests\manual_ci.ps1 and tests\detection_selftest.ps1 plant fake
#   malware (on a real laptop they once locked the owner out of it),
#   tests\cleanup_selftest.ps1 is that harness's cleanup, and
#   tests\noadmin_smoke.ps1 creates a local user account. None of them belongs
#   on someone else's machine.
#
#   File CONTENTS are copied, not the files' alternate data streams, so Mark of
#   the Web never travels onto the stick: under a Group Policy RemoteSigned
#   execution policy a marked helper would be refused while the rest ran.
#   Batch files are written with CRLF line endings, which cmd.exe needs; a
#   checkout made outside Windows has LF only.
#
# WHY THE MANIFEST LIVES ON THIS LAPTOP
#   The stick visits machines that may be compromised. Whatever is on the stick
#   when it comes back -- including its own copy of the manifest -- may have
#   been rewritten there. -Verify trusts only the copy kept here. A changed
#   tool file on a returned stick is itself worth reporting. And the check is
#   only as trustworthy as this laptop.
#
# Windows PowerShell 5.1 (the Storage module: Windows 8 and later). -SelfTest
# also runs on pwsh 7 on Linux with injected disk objects; the cases that need
# NTFS alternate data streams print [SKIP] there.

[CmdletBinding()]
param(
    [string]$Drive = '',
    [string]$ToFolder = '',
    [switch]$Verify,
    [switch]$Refresh,
    [switch]$ListCandidates,
    [string]$Source = '',
    [string]$ManifestStore = '',
    [string]$Manifest = '',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$script:Version = 'make_usb_stick v1'
$script:OnWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
$script:StickFolder = 'doze_sec'
$script:StickManifestName = 'STICK_MANIFEST.sha256'
# Top-level directories that never go on a stick.
$script:ExcludeDirs = @('.git', '.github', '.claude')
# Files that change a machine. Relative to the repo root, backslash form.
$script:ExcludeFiles = @(
    'tests\manual_ci.ps1',
    'tests\detection_selftest.ps1',
    'tests\cleanup_selftest.ps1',
    'tests\noadmin_smoke.ps1'
)
# Files the audit cannot run without; a copy missing one is refused.
$script:Required = @(
    'doze_sec.bat', 'doze_sec_noAdmin.bat',
    'tools\exec_probe.ps1', 'tests\field_test.ps1', 'tests\benign_corpus.txt',
    'tests\unraised_allowlist.txt', 'ThreatLists\ioc_hashes.txt'
)
# A file that appears at the stick's root with one of these extensions is
# reported by -Verify: it is how a visited machine would try to reach the next.
$script:RootSuspectRx = '\.(inf|lnk|exe|scr|com|pif|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|dll|cpl|msi|url)$'

if (-not $Source) { $Source = Split-Path -Parent $PSScriptRoot }

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

function ConvertTo-BusName {
    # Get-Disk formats BusType as a name; the CIM class holds a number. 7 is USB.
    param($BusType)
    if ($null -eq $BusType) { return '' }
    $s = [string]$BusType
    if ($s -eq '7') { return 'USB' }
    return $s
}

function Get-StickVerdict {
    # PURE. Decides whether a volume may receive the tool.
    #   -Disk    object with BusType, IsBoot, IsSystem, IsOffline, IsReadOnly,
    #            FriendlyName, Size (Get-Disk); $null when it could not be read
    #   -Volume  object with DriveLetter, FileSystem, DriveType, UniqueId,
    #            SizeRemaining (Get-Volume); $null when it could not be read
    #   -Context @{ SystemDrive = 'C'; ProtectedPaths = @(...); LookupError = '' }
    # Returns @{ Ok; Reasons = @(); Info = @() }. Fails closed: anything it
    # cannot establish is a reason to refuse.
    param($Disk, $Volume, [hashtable]$Context)
    $reasons = New-Object System.Collections.Generic.List[string]
    $info = New-Object System.Collections.Generic.List[string]
    if ($Context -and $Context.LookupError) {
        $reasons.Add('could not identify the disk behind this drive: ' + $Context.LookupError + ' -- try an elevated PowerShell')
    }
    if ($null -eq $Disk) {
        if (-not ($Context -and $Context.LookupError)) { $reasons.Add('could not read the disk behind this drive') }
    } else {
        $bus = ConvertTo-BusName $Disk.BusType
        if ($bus -ne 'USB') {
            $seen = if ($bus) { $bus } else { 'nothing' }
            $reasons.Add('the disk is not on the USB bus (Windows reports: ' + $seen + ')')
        }
        if ($Disk.IsBoot)     { $reasons.Add('this is the disk Windows booted from') }
        if ($Disk.IsSystem)   { $reasons.Add('this disk holds the system partition') }
        if ($Disk.IsOffline)  { $reasons.Add('the disk is offline') }
        if ($Disk.IsReadOnly) { $reasons.Add('the disk is read-only (a write-protect switch?) -- turn protection off to make the stick, back on afterwards if you like') }
    }
    if ($null -eq $Volume) {
        if (-not ($Context -and $Context.LookupError)) { $reasons.Add('could not read the volume') }
    } else {
        $letter = ([string]$Volume.DriveLetter).Trim().TrimEnd(':').ToUpper()
        $sys = ''
        if ($Context -and $Context.SystemDrive) { $sys = ([string]$Context.SystemDrive).Trim().TrimEnd(':').ToUpper() }
        if ($letter -and $sys -and $letter -eq $sys) { $reasons.Add('this is the Windows drive (' + $letter + ':)') }
        if ($letter -and $Context -and $Context.ProtectedPaths) {
            foreach ($p in $Context.ProtectedPaths) {
                if (-not $p) { continue }
                $pl = ([string]$p).Trim()
                if ($pl.Length -ge 2 -and $pl[1] -eq ':' -and $pl.Substring(0, 1).ToUpper() -eq $letter) {
                    $reasons.Add('this drive holds ' + $pl)
                }
            }
        }
        $fs = [string]$Volume.FileSystem
        if ($fs -notin @('FAT', 'FAT32', 'exFAT', 'NTFS')) {
            $shown = if ($fs) { $fs } else { 'none' }
            $reasons.Add('the volume is not formatted with FAT32, exFAT or NTFS (file system: ' + $shown + '). To format it: File Explorer, right-click the drive, Format, exFAT. Formatting erases every file on that drive -- check the letter is the stick first.')
        }
        if ([string]$Volume.DriveType -eq 'Fixed') {
            $info.Add('the volume reports drive type Fixed; many USB sticks and USB SSDs do. The bus decides, and it is USB.')
        }
    }
    return @{ Ok = ($reasons.Count -eq 0); Reasons = $reasons.ToArray(); Info = $info.ToArray() }
}

function Get-RelPath {
    param([string]$Root, [string]$Full)
    $r = $Full.Substring($Root.TrimEnd('\', '/').Length).TrimStart('\', '/')
    return ($r -replace '/', '\')
}

function Join-Rel {
    param([string]$Root, [string]$Rel)
    return [IO.Path]::Combine($Root, ($Rel -replace '\\', [string][IO.Path]::DirectorySeparatorChar))
}

function Test-IsReparse {
    param([IO.FileSystemInfo]$Item)
    return (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Test-IsLinkEntry {
    # PURE. Is this reparse point a LINK (symbolic link or junction), which a
    # walk must never follow? OneDrive Files On-Demand marks ordinary synced
    # files and folders as reparse points too (cloud placeholders), and the
    # owner's checkout lives under OneDrive, so "any reparse point" would refuse
    # every real checkout. PowerShell names the link kind in LinkType.
    param($Attributes, $LinkType)
    if (([IO.FileAttributes]$Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { return $false }
    return ([string]$LinkType -in @('SymbolicLink', 'Junction'))
}

function Get-TreeEntries {
    # Walks a tree WITHOUT following links: a link is returned as one entry and
    # never descended into, so a junction cannot lead this script outside the
    # tree. -Strict (used on the stick) treats EVERY reparse point as a link: a
    # stick made by this script holds none, so any reparse point there was
    # added elsewhere. Without -Strict (the source checkout) only symbolic links
    # and junctions count; cloud placeholders are walked like ordinary files.
    # Returns @{ Files = @(FileInfo); Dirs = @(DirectoryInfo); Reparse = @(rel) }.
    param([string]$Root, [switch]$Strict)
    $files = New-Object System.Collections.Generic.List[IO.FileInfo]
    $dirs = New-Object System.Collections.Generic.List[IO.DirectoryInfo]
    $reparse = New-Object System.Collections.Generic.List[string]
    $stack = New-Object System.Collections.Generic.Stack[IO.DirectoryInfo]
    $stack.Push((New-Object IO.DirectoryInfo $Root))
    while ($stack.Count -gt 0) {
        $d = $stack.Pop()
        foreach ($e in $d.GetFileSystemInfos()) {
            $isLink = if ($Strict) { Test-IsReparse $e } else { Test-IsLinkEntry $e.Attributes $e.LinkType }
            if ($isLink) { $reparse.Add((Get-RelPath $Root $e.FullName)); continue }
            if ($e -is [IO.DirectoryInfo]) { $dirs.Add($e); $stack.Push($e) }
            else { $files.Add([IO.FileInfo]$e) }
        }
    }
    return @{ Files = $files.ToArray(); Dirs = $dirs.ToArray(); Reparse = $reparse.ToArray() }
}

function Test-Excluded {
    # Returns the reason a relative path stays off the stick, or ''.
    param([string]$Rel)
    $top = ($Rel -split '\\')[0]
    foreach ($d in $script:ExcludeDirs) { if ($top -ieq $d) { return $d + '\' } }
    foreach ($f in $script:ExcludeFiles) { if ($Rel -ieq $f) { return $f } }
    return ''
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($Bytes)) -replace '-', '').ToLower() }
    finally { $h.Dispose() }
}

function ConvertTo-CrLf {
    # Byte-exact: every LF not already preceded by CR becomes CRLF. Batch files
    # are ASCII, so no character can be split.
    param([byte[]]$Bytes)
    $out = New-Object System.Collections.Generic.List[byte] ($Bytes.Length + 1024)
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        $b = $Bytes[$i]
        if ($b -eq 10 -and ($i -eq 0 -or $Bytes[$i - 1] -ne 13)) { $out.Add(13) }
        $out.Add($b)
    }
    return $out.ToArray()
}

function Get-MotwCount {
    # How many source files carry a Zone.Identifier stream (Mark of the Web).
    param([IO.FileInfo[]]$Files)
    if (-not $script:OnWindows) { return -1 }
    $n = 0
    foreach ($f in $Files) {
        $s = Get-Item -LiteralPath $f.FullName -Stream 'Zone.Identifier' -EA SilentlyContinue
        if ($s) { $n++ }
    }
    return $n
}

function Get-ExtraStreams {
    # Alternate data streams on a file, other than the main one. Windows only.
    param([string]$Path)
    if (-not $script:OnWindows) { return @() }
    $all = @(Get-Item -LiteralPath $Path -Stream * -EA SilentlyContinue)
    return @($all | Where-Object { $_.Stream -ne ':$DATA' } | ForEach-Object { $_.Stream })
}

function Invoke-StickCopy {
    # Copies $Source into $Dest (which must not exist). Returns
    # @{ Entries = ordered rel -> sha256; Excluded = @(); Normalized; Motw; Bytes }.
    # Throws with a plain reason on anything it refuses.
    param([string]$Source, [string]$Dest)
    $srcFull = [IO.Path]::GetFullPath($Source).TrimEnd('\', '/')
    $dstFull = [IO.Path]::GetFullPath($Dest).TrimEnd('\', '/')
    if ($dstFull.StartsWith($srcFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or $dstFull -ieq $srcFull) {
        throw ('the destination ' + $dstFull + ' is inside the source tree')
    }
    if (Test-Path -LiteralPath $dstFull) { throw ($dstFull + ' already exists -- use -Refresh to replace a copy this script made, or remove it yourself') }
    $tree = Get-TreeEntries $srcFull
    $excluded = New-Object System.Collections.Generic.List[string]
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($r in $tree.Reparse) {
        $why = Test-Excluded $r
        if (-not $why) { throw ('the source contains a link or junction (' + $r + '); copy refused -- a link could carry files from outside the tool onto the stick') }
    }
    foreach ($f in $tree.Files) {
        $rel = Get-RelPath $srcFull $f.FullName
        $why = Test-Excluded $rel
        if ($why) { if (-not $excluded.Contains($why)) { $excluded.Add($why) }; continue }
        $plan.Add(@{ Rel = $rel; File = $f })
    }
    foreach ($req in $script:Required) {
        if (-not @($plan | Where-Object { $_.Rel -ieq $req }).Count) { throw ('the source is missing ' + $req + ' -- is -Source the doze_sec folder?') }
    }
    $seen = @{}
    foreach ($p in $plan) {
        $k = $p.Rel.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { throw ('two source files differ only in case (' + $seen[$k] + ', ' + $p.Rel + '); FAT32 and exFAT cannot hold both') }
        $seen[$k] = $p.Rel
    }
    $motw = Get-MotwCount @($plan | ForEach-Object { $_.File })
    $entries = [ordered]@{}
    $normalized = 0
    $bytesTotal = [long]0
    [void][IO.Directory]::CreateDirectory($dstFull)
    foreach ($p in ($plan | Sort-Object { $_.Rel })) {
        $bytes = [IO.File]::ReadAllBytes($p.File.FullName)
        if ($p.Rel -match '\.(bat|cmd)$') {
            $crlf = ConvertTo-CrLf $bytes
            if ($crlf.Length -ne $bytes.Length) { $normalized++ }
            $bytes = $crlf
        }
        $target = Join-Rel $dstFull $p.Rel
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
        # Contents only: no alternate data stream, so no Mark of the Web, can follow.
        [IO.File]::WriteAllBytes($target, $bytes)
        $entries[$p.Rel] = Get-Sha256Hex $bytes
        $bytesTotal += $bytes.Length
    }
    # Read every file back and compare: a copy that did not land is not a copy.
    foreach ($rel in @($entries.Keys)) {
        $back = Get-Sha256Hex ([IO.File]::ReadAllBytes((Join-Rel $dstFull $rel)))
        if ($back -ne $entries[$rel]) { throw ('read-back mismatch on ' + $rel + ' -- the stick did not store what was written; use another stick') }
    }
    return @{ Entries = $entries; Excluded = @($excluded.ToArray() | Sort-Object); Normalized = $normalized; Motw = $motw; Bytes = $bytesTotal }
}

function New-ManifestText {
    param([System.Collections.IDictionary]$Entries, [string]$TargetId, [string]$SourcePath, [string]$Created)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# doze_sec stick manifest -- SHA-256 of every file this script put on the stick')
    $lines.Add('# made-by: ' + $script:Version)
    $lines.Add('# created: ' + $Created)
    $lines.Add('# target: ' + $TargetId)
    $lines.Add('# source: ' + $SourcePath)
    $lines.Add('# files: ' + $Entries.Count)
    foreach ($k in $Entries.Keys) { $lines.Add($Entries[$k] + '  ' + $k) }
    return ($lines -join "`r`n") + "`r`n"
}

function Read-Manifest {
    # Returns @{ Header = @{}; Entries = @{ rel -> sha256 } } or throws.
    param([string]$Path)
    $hdr = @{}
    $ent = @{}
    foreach ($ln in [IO.File]::ReadAllLines($Path)) {
        if ($ln -match '^#\s*([a-z-]+):\s*(.*)$') { $hdr[$matches[1]] = $matches[2].Trim(); continue }
        if ($ln -match '^#' -or -not $ln.Trim()) { continue }
        if ($ln -match '^([0-9a-f]{64})  (.+)$') { $ent[$matches[2]] = $matches[1]; continue }
        throw ('unreadable manifest line in ' + $Path + ': ' + $ln)
    }
    if (-not $hdr.ContainsKey('made-by') -or $hdr['made-by'] -notmatch '^make_usb_stick ') { throw ($Path + ' is not a manifest written by this script') }
    return @{ Header = $hdr; Entries = $ent }
}

function Compare-StickTree {
    # Compares <Root> (the doze_sec folder on the stick) with a manifest's
    # entries. Returns @{ Changed; Added; Removed; Streams; Reparse; RootSuspect }.
    param([string]$Root, [hashtable]$Expected, [string]$OuterRoot = '')
    $changed = New-Object System.Collections.Generic.List[string]
    $added = New-Object System.Collections.Generic.List[string]
    $removed = New-Object System.Collections.Generic.List[string]
    $streams = New-Object System.Collections.Generic.List[string]
    $suspect = New-Object System.Collections.Generic.List[string]
    $tree = Get-TreeEntries $Root -Strict
    $present = @{}
    foreach ($f in $tree.Files) {
        $rel = Get-RelPath $Root $f.FullName
        if ($rel -ieq $script:StickManifestName) { continue }
        $present[$rel] = $true
        # PowerShell hashtables compare keys case-insensitively, as FAT and
        # exFAT compare names.
        if (-not $Expected.ContainsKey($rel)) { $added.Add($rel); continue }
        $exp = $Expected[$rel]
        $h = Get-Sha256Hex ([IO.File]::ReadAllBytes($f.FullName))
        if ($h -ne $exp) { $changed.Add($rel) }
        foreach ($s in (Get-ExtraStreams $f.FullName)) { $streams.Add($rel + ':' + $s) }
    }
    foreach ($k in $Expected.Keys) { if (-not $present.ContainsKey($k)) { $removed.Add($k) } }
    if ($OuterRoot -and (Test-Path -LiteralPath $OuterRoot)) {
        foreach ($e in (New-Object IO.DirectoryInfo $OuterRoot).GetFileSystemInfos()) {
            if ($e -is [IO.FileInfo] -and $e.Name -match $script:RootSuspectRx) { $suspect.Add($e.Name) }
            elseif ((Test-IsReparse $e) -and $e.Name -ine $script:StickFolder) { $suspect.Add($e.Name + ' (link)') }
        }
    }
    return @{ Changed = $changed.ToArray(); Added = $added.ToArray(); Removed = $removed.ToArray(); Streams = $streams.ToArray(); Reparse = $tree.Reparse; RootSuspect = $suspect.ToArray() }
}

function Remove-StickCopy {
    # Removes <Dir> only when it holds a manifest this script wrote and no
    # link or junction anywhere under it. Deletes bottom-up with plain file
    # and empty-directory deletes, so nothing outside <Dir> can be reached.
    param([string]$Dir)
    $mf = Join-Path $Dir $script:StickManifestName
    if (-not (Test-Path -LiteralPath $mf)) { throw ($Dir + ' has no ' + $script:StickManifestName + ' -- not a copy this script made; remove it yourself if you are sure') }
    [void](Read-Manifest $mf)
    $self = New-Object IO.DirectoryInfo $Dir
    if (Test-IsReparse $self) { throw ($Dir + ' is itself a link or junction; refused') }
    $tree = Get-TreeEntries $Dir -Strict
    if ($tree.Reparse.Count) { throw ($Dir + ' contains a link or junction (' + ($tree.Reparse -join ', ') + '); refused -- inspect the stick before reusing it') }
    foreach ($f in $tree.Files) { $f.Attributes = 'Normal'; $f.Delete() }
    foreach ($d in ($tree.Dirs | Sort-Object { $_.FullName.Length } -Descending)) { $d.Delete($false) }
    $self.Delete($false)
}

function Get-ManifestStore {
    if ($ManifestStore) { return $ManifestStore }
    $base = $env:LOCALAPPDATA
    if (-not $base) { $base = [IO.Path]::GetTempPath() }
    return (Join-Path (Join-Path $base 'doze_sec') 'sticks')
}

function Find-TrustedManifest {
    # The newest manifest in the store whose target matches. Never the stick's.
    param([string]$Store, [string]$TargetId)
    if (-not (Test-Path -LiteralPath $Store)) { return $null }
    $best = $null
    foreach ($f in (Get-ChildItem -LiteralPath $Store -Filter '*.sha256' -File | Sort-Object Name -Descending)) {
        try { $m = Read-Manifest $f.FullName } catch { continue }
        if ($m.Header['target'] -ceq $TargetId) { $best = $f.FullName; break }
    }
    return $best
}

function Get-IdTag {
    param([string]$TargetId)
    return (Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($TargetId))).Substring(0, 8)
}

# ---------------------------------------------------------------------------
# Live lookups (Windows only)
# ---------------------------------------------------------------------------

function Get-LiveTarget {
    param([string]$Letter)
    $r = @{ Disk = $null; Volume = $null; Error = '' }
    try {
        $r.Volume = Get-Volume -DriveLetter $Letter -EA Stop
        $r.Disk = Get-Partition -DriveLetter $Letter -EA Stop | Get-Disk -EA Stop
    } catch { $r.Error = $_.Exception.Message }
    return $r
}

function Get-LiveContext {
    param([string]$Err)
    return @{
        SystemDrive    = $env:SystemDrive
        ProtectedPaths = @($env:windir, $env:USERPROFILE, $Source, $PSScriptRoot)
        LookupError    = $Err
    }
}

function ConvertTo-Letter {
    param([string]$D)
    if ($D -notmatch '^\s*([A-Za-z])(:\\?)?\s*$') { throw ('-Drive takes a drive letter such as E: -- got "' + $D + '"') }
    return $matches[1].ToUpper()
}

# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function D { param($Bus = 'USB', [bool]$Boot = $false, [bool]$Sys = $false, [bool]$Off = $false, [bool]$Ro = $false)
        return (New-Object PSObject -Property @{ BusType = $Bus; IsBoot = $Boot; IsSystem = $Sys; IsOffline = $Off; IsReadOnly = $Ro; FriendlyName = 'Test Stick'; Size = 16GB })
    }
    function V { param([string]$L = 'E', [string]$Fs = 'exFAT', [string]$Dt = 'Removable')
        return (New-Object PSObject -Property @{ DriveLetter = $L; FileSystem = $Fs; DriveType = $Dt; UniqueId = '\\?\Volume{test}\'; SizeRemaining = 8GB })
    }
    $ctx = @{ SystemDrive = 'C:'; ProtectedPaths = @('C:\Windows', 'C:\Users\u', 'C:\Users\u\src\doze_sec'); LookupError = '' }

    $v = Get-StickVerdict (D) (V) $ctx
    T 'a USB stick formatted exFAT is accepted' ($v.Ok) ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D -Bus 7) (V -Fs 'FAT32') $ctx
    T 'BusType given as the CIM number 7 is USB' ($v.Ok) ($v.Reasons -join '; ')
    foreach ($bus in @('SATA', 'NVMe', 'SD', 'SCSI', 'RAID', 'Unknown')) {
        $v = Get-StickVerdict (D -Bus $bus) (V) $ctx
        T ("a disk on the {0} bus is refused, naming what was seen" -f $bus) ((-not $v.Ok) -and ($v.Reasons -join ' ') -match [regex]::Escape($bus)) ($v.Reasons -join '; ')
    }
    $v = Get-StickVerdict (D -Bus $null) (V) $ctx
    T 'an unreadable bus fails closed' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'not on the USB bus') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D -Boot $true) (V) $ctx
    T 'the boot disk is refused even on USB' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'booted from') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D -Sys $true) (V) $ctx
    T 'the system disk is refused' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'system partition') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D -Off $true) (V) $ctx
    T 'an offline disk is refused' (-not $v.Ok) ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D -Ro $true) (V) $ctx
    T 'a read-only (write-protected) disk is refused, and says why' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'write-protect') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D) (V -Fs 'RAW') $ctx
    T 'an unformatted volume is refused, with how to format and the erase warning' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'File Explorer' -and ($v.Reasons -join ' ') -match 'erases every file') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D) (V -L 'C') $ctx
    T 'the Windows drive letter is refused whatever the bus says' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'Windows drive') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D) (V -L 'D') @{ SystemDrive = 'C:'; ProtectedPaths = @('D:\src\doze_sec'); LookupError = '' }
    T 'a drive holding the source checkout is refused' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'holds D:\\src') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D) (V -Dt 'Fixed') $ctx
    T 'a USB disk reporting Fixed is accepted, with an INFO line (the bus decides)' ($v.Ok -and ($v.Info -join ' ') -match 'bus decides') (($v.Reasons + $v.Info) -join '; ')
    $v = Get-StickVerdict $null $null @{ SystemDrive = 'C:'; ProtectedPaths = @(); LookupError = 'Access denied' }
    T 'a lookup error refuses and suggests an elevated window' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'elevated') ($v.Reasons -join '; ')

    T 'ConvertTo-Letter accepts E, E: and E:\' ((ConvertTo-Letter 'e') -eq 'E' -and (ConvertTo-Letter 'E:') -eq 'E' -and (ConvertTo-Letter 'E:\') -eq 'E') ''
    $threw = $false; try { [void](ConvertTo-Letter 'E:\stuff') } catch { $threw = $true }
    T 'ConvertTo-Letter refuses a path' $threw ''

    $crlf = ConvertTo-CrLf ([Text.Encoding]::ASCII.GetBytes("a`nb`r`nc`n"))
    T 'LF becomes CRLF and an existing CRLF is left alone' ([Text.Encoding]::ASCII.GetString($crlf) -ceq "a`r`nb`r`nc`r`n") ([Text.Encoding]::ASCII.GetString($crlf))

    $rp = [IO.FileAttributes]::Archive -bor [IO.FileAttributes]::ReparsePoint
    T 'a symbolic link is a link' (Test-IsLinkEntry $rp 'SymbolicLink') ''
    T 'a junction is a link' (Test-IsLinkEntry ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint) 'Junction') ''
    T 'a OneDrive cloud placeholder (reparse point, no link type) is NOT a link -- the owner''s checkout is under OneDrive' (-not (Test-IsLinkEntry $rp $null)) ''
    T 'a hard link is not a link to avoid (it is the file itself)' (-not (Test-IsLinkEntry ([IO.FileAttributes]::Archive) 'HardLink')) ''
    T 'a plain file is not a link' (-not (Test-IsLinkEntry ([IO.FileAttributes]::Archive) $null)) ''

    # The script must never format, partition or write boot files. Checked on
    # the AST, so the comments that explain why are not a match.
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$tok, [ref]$err)
    $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
    $bad = @($cmds | Where-Object { $_ -match '^(Format-Volume|Clear-Disk|Initialize-Disk|New-Partition|Set-Partition|Remove-Partition|Resize-Partition|diskpart(\.exe)?|bcdboot(\.exe)?|bcdedit(\.exe)?|format(\.com)?|Set-Disk)$' })
    T 'the script calls no formatting, partitioning or boot command' ($bad.Count -eq 0) ($bad -join ', ')

    # --- copy, manifest, verify on temp trees ---------------------------------
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_stick_selftest_' + $PID)
    try {
        $src = Join-Path $tmp 'src'
        foreach ($rel in ($script:Required + @('tools\other.ps1', '.git\config', '.github\workflows\x.yml', 'tests\manual_ci.ps1', 'tests\detection_selftest.ps1', 'tests\cleanup_selftest.ps1', 'tests\noadmin_smoke.ps1', 'docs\second-machine.md'))) {
            $p = Join-Rel $src $rel
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p))
            [IO.File]::WriteAllText($p, ("content of " + $rel + "`nline two`n"))
        }
        $store = Join-Path $tmp 'store'
        $ManifestStore = $store
        $dest = Join-Path (Join-Path $tmp 'stick') $script:StickFolder
        $res = Invoke-StickCopy -Source $src -Dest $dest
        T 'the copy holds every required file' (@($script:Required | Where-Object { -not (Test-Path -LiteralPath (Join-Rel $dest $_)) }).Count -eq 0) ''
        T 'no harness file reaches the stick' (@($script:ExcludeFiles | Where-Object { Test-Path -LiteralPath (Join-Rel $dest $_) }).Count -eq 0) ''
        T '.git and .github stay off the stick' (-not (Test-Path -LiteralPath (Join-Path $dest '.git')) -and -not (Test-Path -LiteralPath (Join-Path $dest '.github'))) ''
        T 'every exclusion is reported, none silently' (@($res.Excluded).Count -eq 6) ($res.Excluded -join ', ')
        $batBytes = [IO.File]::ReadAllBytes((Join-Path $dest 'doze_sec.bat'))
        T 'the LF-only bat lands with CRLF line endings' ([Text.Encoding]::ASCII.GetString($batBytes) -match "`r`n" -and $res.Normalized -eq 2) ("normalized=" + $res.Normalized)
        T 'a non-batch file is copied byte for byte' ([IO.File]::ReadAllText((Join-Rel $dest 'tools\other.ps1')) -ceq ("content of tools\other.ps1`nline two`n")) ''

        $tid = 'folder=' + $dest
        $text = New-ManifestText -Entries $res.Entries -TargetId $tid -SourcePath $src -Created '2026-10-09T12:00:00'
        [void][IO.Directory]::CreateDirectory($store)
        [IO.File]::WriteAllText((Join-Path $store ('stick_20261009_120000_' + (Get-IdTag $tid) + '.sha256')), $text)
        [IO.File]::WriteAllText((Join-Path $dest $script:StickManifestName), $text)
        $m = Read-Manifest (Join-Path $dest $script:StickManifestName)
        T 'the manifest round-trips: one entry per copied file' ($m.Entries.Count -eq $res.Entries.Count -and $m.Header['target'] -eq $tid) ("entries=" + $m.Entries.Count)
        T 'the trusted manifest is found in the laptop store by target' ((Find-TrustedManifest $store $tid) -ne $null) ''
        T 'a different target finds no manifest' ((Find-TrustedManifest $store 'folder=elsewhere') -eq $null) ''

        $c = Compare-StickTree -Root $dest -Expected $m.Entries -OuterRoot (Split-Path -Parent $dest)
        T 'an untouched stick verifies identical' (($c.Changed.Count + $c.Added.Count + $c.Removed.Count + $c.RootSuspect.Count) -eq 0) (($c.Changed + $c.Added + $c.Removed + $c.RootSuspect) -join ', ')
        [IO.File]::AppendAllText((Join-Rel $dest 'tools\exec_probe.ps1'), "`n# tampered")
        [IO.File]::WriteAllText((Join-Rel $dest 'tools\extra.ps1'), 'new')
        Remove-Item -LiteralPath (Join-Rel $dest 'tests\benign_corpus.txt')
        [IO.File]::WriteAllText((Join-Path (Split-Path -Parent $dest) 'autorun.inf'), '[autorun]')
        $c = Compare-StickTree -Root $dest -Expected $m.Entries -OuterRoot (Split-Path -Parent $dest)
        T 'a changed tool file is reported' (@($c.Changed) -contains 'tools\exec_probe.ps1') ($c.Changed -join ', ')
        T 'an added file is reported' (@($c.Added) -contains 'tools\extra.ps1') ($c.Added -join ', ')
        T 'a removed file is reported' (@($c.Removed) -contains 'tests\benign_corpus.txt') ($c.Removed -join ', ')
        T 'an autorun.inf at the stick root is reported' (@($c.RootSuspect) -contains 'autorun.inf') ($c.RootSuspect -join ', ')
        $slink = $false
        try { New-Item -ItemType SymbolicLink -Path (Join-Rel $dest 'tools\escape') -Target $src -EA Stop | Out-Null; $slink = $true } catch {}
        if ($slink) {
            $c2 = Compare-StickTree -Root $dest -Expected $m.Entries
            T 'a link planted on the stick is reported and not followed' ((@($c2.Reparse) -contains 'tools\escape') -and -not (@($c2.Added) -match '^tools\\escape\\').Count) (($c2.Reparse + $c2.Added) -join ', ')
            $threw = ''; try { Remove-StickCopy $dest } catch { $threw = $_.Exception.Message }
            T 'refresh refuses a stick copy holding a link, and deletes nothing' ($threw -match 'link or junction' -and (Test-Path -LiteralPath (Join-Rel $dest 'tools\other.ps1'))) $threw
            (Get-Item -LiteralPath (Join-Rel $dest 'tools\escape') -Force).Delete()
        } else { Write-Output '[SKIP] link on the stick: creating a symbolic link needs rights this session lacks' }

        $threw = ''; try { [void](Invoke-StickCopy -Source $src -Dest $dest) } catch { $threw = $_.Exception.Message }
        T 'an existing copy is never overwritten without -Refresh' ($threw -match 'already exists') $threw
        $threw = ''; try { [void](Invoke-StickCopy -Source $src -Dest (Join-Path $src 'inner')) } catch { $threw = $_.Exception.Message }
        T 'a destination inside the source tree is refused' ($threw -match 'inside the source') $threw

        $other = Join-Path $tmp 'other'
        [void][IO.Directory]::CreateDirectory($other)
        [IO.File]::WriteAllText((Join-Path $other 'keep.txt'), 'not ours')
        $threw = ''; try { Remove-StickCopy $other } catch { $threw = $_.Exception.Message }
        T 'refresh refuses a folder this script did not make, and deletes nothing' ($threw -match 'not a copy this script made' -and (Test-Path -LiteralPath (Join-Path $other 'keep.txt'))) $threw
        Remove-StickCopy $dest
        T 'refresh removes a copy this script made' (-not (Test-Path -LiteralPath $dest)) ''

        $miss = Join-Path $tmp 'miss'
        [void][IO.Directory]::CreateDirectory((Join-Path $miss 'tools'))
        [IO.File]::WriteAllText((Join-Path $miss 'doze_sec.bat'), 'x')
        $threw = ''; try { [void](Invoke-StickCopy -Source $miss -Dest (Join-Path $tmp 'miss_out')) } catch { $threw = $_.Exception.Message }
        T 'a source missing a required file is refused, naming it' ($threw -match 'missing') $threw

        $case = Join-Path $tmp 'case'
        foreach ($rel in ($script:Required + @('tools\A.ps1', 'tools\a.ps1'))) {
            $p = Join-Rel $case $rel
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p))
            [IO.File]::WriteAllText($p, 'x')
        }
        if (@(Get-ChildItem -LiteralPath (Join-Path $case 'tools') -File).Count -eq 3) {
            $threw = ''; try { [void](Invoke-StickCopy -Source $case -Dest (Join-Path $tmp 'case_out')) } catch { $threw = $_.Exception.Message }
            T 'two source files differing only in case are refused' ($threw -match 'only in case') $threw
        } else { Write-Output '[SKIP] case-only collision: this file system is case-insensitive, the collision cannot be planted here' }

        $lnk = Join-Path $tmp 'lnk'
        foreach ($rel in $script:Required) {
            $p = Join-Rel $lnk $rel
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p))
            [IO.File]::WriteAllText($p, 'x')
        }
        $planted = $false
        try { New-Item -ItemType SymbolicLink -Path (Join-Path $lnk 'tools\outside') -Target $tmp -EA Stop | Out-Null; $planted = $true } catch {}
        if ($planted) {
            $threw = ''; try { [void](Invoke-StickCopy -Source $lnk -Dest (Join-Path $tmp 'lnk_out')) } catch { $threw = $_.Exception.Message }
            T 'a link inside the source is refused, never followed' ($threw -match 'link or junction') $threw
        } else { Write-Output '[SKIP] link in source: creating a symbolic link needs rights this session lacks' }

        if ($script:OnWindows) {
            $ms = Join-Path $tmp 'motw'
            foreach ($rel in $script:Required) {
                $p = Join-Rel $ms $rel
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p))
                [IO.File]::WriteAllText($p, 'x')
            }
            Set-Content -LiteralPath (Join-Rel $ms 'tools\exec_probe.ps1') -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3"
            $mdest = Join-Path $tmp 'motw_out'
            $mres = Invoke-StickCopy -Source $ms -Dest $mdest
            T 'Mark of the Web on a source file is counted' ($mres.Motw -eq 1) ("motw=" + $mres.Motw)
            T 'Mark of the Web does not travel onto the copy' (@(Get-ExtraStreams (Join-Rel $mdest 'tools\exec_probe.ps1')).Count -eq 0) ''
            Set-Content -LiteralPath (Join-Rel $mdest 'tools\exec_probe.ps1') -Stream 'dz_hidden' -Value 'x'
            $mc = Compare-StickTree -Root $mdest -Expected $mres.Entries
            T 'an alternate data stream added on a visited machine is reported' (@(@($mc.Streams) -match 'dz_hidden').Count -eq 1) ($mc.Streams -join ', ')
        } else {
            Write-Output '[SKIP] Mark of the Web and alternate data streams: NTFS streams exist only on Windows (windows-smoke runs these cases)'
        }

        # The real repo: the stick carries what the audit needs and no harness.
        $real = Join-Path $tmp 'real'
        $rres = Invoke-StickCopy -Source $Source -Dest $real
        T 'a copy of this repo holds the audit and no harness' ((@($script:ExcludeFiles | Where-Object { Test-Path -LiteralPath (Join-Rel $real $_) }).Count -eq 0) -and (Test-Path -LiteralPath (Join-Rel $real 'tools\exec_probe.ps1'))) ''
        T 'every exclusion that applied to this repo was named' (@($rres.Excluded | Where-Object { $_ -like 'tests\*' }).Count -eq 4) ($rres.Excluded -join ', ')
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -EA SilentlyContinue }
    }
    if ($fails -gt 0) { Write-Output "FAILED: $fails"; exit 1 }
    Write-Output '[OK] make_usb_stick self-test: only a USB stick is accepted, nothing is formatted, the harness stays off, and a returned stick is checked against the laptop copy of its manifest.'
    exit 0
}

# ---------------------------------------------------------------------------
# Live modes
# ---------------------------------------------------------------------------

if ($ListCandidates) {
    if (-not $script:OnWindows) { Write-Output '[FAIL] -ListCandidates needs Windows.'; exit 1 }
    Write-Output 'Lettered volumes and whether this script would put the tool on them (read-only; nothing is changed):'
    foreach ($vol in (Get-Volume | Where-Object { $_.DriveLetter } | Sort-Object DriveLetter)) {
        $lt = Get-LiveTarget ([string]$vol.DriveLetter)
        $v = Get-StickVerdict $lt.Disk $lt.Volume (Get-LiveContext $lt.Error)
        $name = if ($lt.Disk) { [string]$lt.Disk.FriendlyName } else { '?' }
        $bus = if ($lt.Disk) { ConvertTo-BusName $lt.Disk.BusType } else { '?' }
        $state = if ($v.Ok) { 'ACCEPTED' } else { 'refused ' }
        Write-Output ('  {0}:  {1}  {2,-8} {3,-6} {4}' -f $vol.DriveLetter, $state, [string]$vol.FileSystem, $bus, $name)
        foreach ($r in $v.Reasons) { Write-Output ('        - ' + $r) }
    }
    exit 0
}

if (($Drive -and $ToFolder) -or (-not $Drive -and -not $ToFolder)) {
    Write-Output 'Usage: make_usb_stick.ps1 -Drive E: [-Verify | -Refresh]   or   -ToFolder <dir> [-Verify | -Refresh]   or   -ListCandidates   or   -SelfTest'
    exit 1
}

$outer = ''
$targetId = ''
if ($Drive) {
    if (-not $script:OnWindows) { Write-Output '[FAIL] -Drive needs Windows.'; exit 1 }
    try { $letter = ConvertTo-Letter $Drive } catch { Write-Output ('[FAIL] ' + $_.Exception.Message); exit 1 }
    $outer = $letter + ':\'
    $lt = Get-LiveTarget $letter
    if ($lt.Volume) { $targetId = 'volume=' + [string]$lt.Volume.UniqueId }
    if (-not $Verify) {
        $v = Get-StickVerdict $lt.Disk $lt.Volume (Get-LiveContext $lt.Error)
        $name = if ($lt.Disk) { [string]$lt.Disk.FriendlyName } else { '?' }
        Write-Output ("Target: {0}:  {1}" -f $letter, $name)
        foreach ($i in $v.Info) { Write-Output ('[INFO] ' + $i) }
        if (-not $v.Ok) {
            foreach ($r in $v.Reasons) { Write-Output ('[FAIL] ' + $r) }
            Write-Output 'Nothing was written. Run -ListCandidates to see which drives this script accepts.'
            exit 1
        }
    }
} else {
    if (-not $Verify) { [void][IO.Directory]::CreateDirectory($ToFolder) }
    $outer = [IO.Path]::GetFullPath($ToFolder)
}
$dest = Join-Path $outer $script:StickFolder
if (-not $targetId) { $targetId = 'folder=' + [IO.Path]::GetFullPath($dest) }
$store = Get-ManifestStore

if ($Verify) {
    $mfPath = $Manifest
    if (-not $mfPath) { $mfPath = Find-TrustedManifest $store $targetId }
    if (-not $mfPath) {
        Write-Output ('[UNVERIFIED] No manifest for this stick in ' + $store + '.')
        Write-Output '  The copy of the manifest ON the stick is not used: a visited machine could have rewritten it along with the files.'
        Write-Output '  Pass -Manifest <file> if you kept it elsewhere; otherwise make the stick again from your checkout.'
        exit 2
    }
    if (-not (Test-Path -LiteralPath $dest)) { Write-Output ('[FAIL] ' + $dest + ' does not exist.'); exit 1 }
    $m = Read-Manifest $mfPath
    $c = Compare-StickTree -Root $dest -Expected $m.Entries -OuterRoot $outer
    Write-Output ('Checking ' + $dest + ' against ' + $mfPath + ' (made ' + $m.Header['created'] + ', ' + $m.Entries.Count + ' files)')
    $n = 0
    foreach ($x in $c.Changed)     { Write-Output ('[CHANGED] ' + $x); $n++ }
    foreach ($x in $c.Added)       { Write-Output ('[ADDED]   ' + $x); $n++ }
    foreach ($x in $c.Removed)     { Write-Output ('[REMOVED] ' + $x); $n++ }
    foreach ($x in $c.Streams)     { Write-Output ('[STREAM]  ' + $x + '  (a hidden data stream that was not there when the stick was made)'); $n++ }
    foreach ($x in $c.Reparse)     { Write-Output ('[LINK]    ' + $x + '  (a link or junction -- not followed)'); $n++ }
    foreach ($x in $c.RootSuspect) { Write-Output ('[ROOT]    ' + $outer + $x + '  (a file at the stick root of a kind that can run or point elsewhere -- do not open it)'); $n++ }
    if ($n -eq 0) {
        Write-Output ('[OK] The tool on the stick is exactly what this laptop put there (' + $m.Entries.Count + ' files).')
        Write-Output '     This check is only as trustworthy as this laptop.'
        exit 0
    }
    Write-Output ('[WARNING] ' + $n + ' difference(s). The tool on the stick was changed after it left this laptop.')
    Write-Output '  Do not run it again. Note which machine it visited -- a changed tool file is itself worth reporting.'
    Write-Output '  Do not open the listed files. Keep this stick exactly as it is -- it is evidence of what that machine'
    Write-Output '  did -- and make a NEW stick for the next machine. -Refresh would erase that evidence.'
    exit 1
}

# --- make --------------------------------------------------------------------
if (Test-Path -LiteralPath $dest) {
    if (-not $Refresh) {
        Write-Output ('[FAIL] ' + $dest + ' already exists. Use -Refresh to replace a copy this script made, or remove it yourself.')
        exit 1
    }
    try { Remove-StickCopy $dest; Write-Output ('[OK] Removed the earlier copy at ' + $dest) }
    catch { Write-Output ('[FAIL] ' + $_.Exception.Message); exit 1 }
}
$srcBytes = [long]0
$srcRoot = [IO.Path]::GetFullPath($Source)
foreach ($f in (Get-TreeEntries $srcRoot).Files) { if (-not (Test-Excluded (Get-RelPath $srcRoot $f.FullName))) { $srcBytes += $f.Length } }
if ($Drive -and $lt.Volume -and $lt.Volume.SizeRemaining -and ([long]$lt.Volume.SizeRemaining -lt [long]($srcBytes * 1.2))) {
    Write-Output ('[FAIL] Not enough free space on ' + $outer + ' (' + [long]$lt.Volume.SizeRemaining + ' bytes free, about ' + [long]($srcBytes * 1.2) + ' needed).')
    exit 1
}
Write-Output ('Copying ' + $Source + ' -> ' + $dest)
try { $res = Invoke-StickCopy -Source $Source -Dest $dest }
catch { Write-Output ('[FAIL] ' + $_.Exception.Message); Write-Output ('  If ' + $dest + ' was partly written, delete it before trying again.'); exit 1 }
foreach ($x in $res.Excluded) { Write-Output ('[INFO] Left off the stick: ' + $x) }
if ($res.Normalized -gt 0) { Write-Output ('[INFO] ' + $res.Normalized + ' batch file(s) had LF-only line endings and were written with CRLF, which cmd.exe needs.') }
if ($res.Motw -gt 0) { Write-Output ('[INFO] ' + $res.Motw + ' source file(s) carried Mark of the Web (downloaded). The stick holds file contents only, so the mark did not travel; the manifest identifies these files from here on.') }
$created = Get-Date -Format 's'
$text = New-ManifestText -Entries $res.Entries -TargetId $targetId -SourcePath ([IO.Path]::GetFullPath($Source)) -Created $created
[void][IO.Directory]::CreateDirectory($store)
$keep = Join-Path $store ('stick_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + (Get-IdTag $targetId) + '.sha256')
# The laptop copy first: a run interrupted after this point leaves a stick
# with no manifest, which -Verify reports as unverified rather than trusted.
[IO.File]::WriteAllText($keep, $text)
[IO.File]::WriteAllText((Join-Path $dest $script:StickManifestName), $text)
Write-Output ('[OK] ' + $res.Entries.Count + ' files copied and read back, ' + $res.Bytes + ' bytes.')
Write-Output ('[OK] Manifest kept on this laptop: ' + $keep)
Write-Output ''
Write-Output 'Next:'
Write-Output '  1. Eject the stick (Safely Remove), plug it back in, and run once:'
Write-Output ('       powershell -NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" ' + $(if ($Drive) { '-Drive ' + $letter + ':' } else { '-ToFolder "' + $ToFolder + '"' }) + ' -Verify')
Write-Output '     It reads the files from the stick itself, not from Windows'' cache, so a stick that lies about its size is caught here.'
Write-Output '  2. If the stick has a write-protect switch, you may turn it on now: the audit never writes into its own folder.'
Write-Output '     (You then need another stick, or the switch off, to bring the results back.)'
Write-Output '  3. On the other machine, follow docs\second-machine.md. When the stick comes back, run -Verify again here.'
exit 0
