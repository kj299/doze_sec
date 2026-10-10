# make_usb_stick.ps1 -- put doze_sec on a USB stick, and check the stick when
# it comes back. Run it on YOUR OWN laptop, from your checkout or from a
# downloaded copy of the repository (GitHub's Download ZIP; git is not needed)
# -- never on the machine being audited, and never the copy of anything that
# is on the stick.
#
# WHAT IT DOES
#   (no drive named)     lists the drives, numbers only the USB sticks this
#                        script accepts (every other drive is shown with the
#                        reason it is not offered), asks which one, and asks
#                        you to type that drive's letter before it writes.
#                        With -Verify or -Refresh it asks the same way.
#   -Drive E:            copies the tool into E:\doze_sec, reads every file back,
#                        and writes a SHA-256 manifest -- one copy kept on this
#                        laptop, one on the stick.
#   -Drive E: -Verify    after the stick has been to another machine: compares
#                        E:\doze_sec with the manifest kept on this laptop and
#                        lists every file changed, added or removed, and any new
#                        file at the stick's root that could run.
#   -ToFolder D:\x       the same copy into a plain folder (CI, or a copy you
#                        will carry some other way). Verify works the same.
#   -ListCandidates      read-only: every lettered volume and whether this
#                        script would accept it.
#   -Refresh             with -Drive/-ToFolder: replace an earlier copy. It
#                        deletes only the files the manifest kept on this laptop
#                        lists, and only when the copy is still exactly what this
#                        laptop wrote -- anything changed or added (your saved
#                        results, or evidence of what a visited machine did) makes
#                        it refuse and list what it found.
#
# WHAT IT NEVER DOES
#   It never formats, partitions or writes boot files. There is no
#   Format-Volume, Clear-Disk, Initialize-Disk, New-Partition, diskpart or
#   bcdboot in it, and its self-test fails if one appears. Formatting erases
#   every file on the selected drive, and picking the wrong drive erases the
#   wrong one; a copy cannot. If the stick needs formatting, do it yourself in
#   File Explorer after checking the drive letter is the stick and that it
#   holds nothing you need.
#
#   It never makes the stick bootable, on purpose. doze_sec audits the Windows
#   that is running; booting the PC from a stick runs a different Windows, so
#   the audit would describe the stick. Windows' own bootable stick (a recovery
#   drive) has no PowerShell, so the audit could not start there anyway. And
#   booting other media can make a BitLocker PC demand its 48-digit recovery
#   key at the next start -- without it, every file on that PC is out of reach.
#   See README.md.
#
# WHAT GOES ON THE STICK
#   Everything the audit needs, and nothing that changes a machine. Left off,
#   and named when the copy runs: .git, .github, .claude, the test harness --
#   tests\manual_ci.ps1 and tests\detection_selftest.ps1 plant fake malware (on
#   a real laptop they once locked the owner out of it), tests\cleanup_selftest.ps1
#   is that harness's cleanup, tests\noadmin_smoke.ps1 creates a local user
#   account -- and THIS script: the stick's checker must not travel with the
#   stick, or a visited machine could rewrite the checker that later vouches
#   for it.
#
#   File CONTENTS are copied, not the files' alternate data streams, so Mark of
#   the Web never travels onto the stick: under a Group Policy RemoteSigned
#   execution policy a marked helper would be refused while the rest ran.
#   Text files are written with CRLF line endings, as a Windows checkout has
#   them and as CI tests them: cmd.exe needs CRLF in a batch file, and
#   findstr's end-of-line anchor needs it in the lists the audit reads. A
#   GitHub ZIP, or a checkout made outside Windows, has LF only.
#
# WHY THE MANIFEST LIVES ON THIS LAPTOP
#   The stick visits machines that may be compromised. Whatever is on the stick
#   when it comes back -- including its own copy of the manifest -- may have
#   been rewritten there. -Verify and -Refresh trust only the copy kept here,
#   and never follow a link or junction found on the stick. A changed tool file
#   on a returned stick is itself worth reporting: keep that stick as it is.
#   And the check is only as trustworthy as this laptop.
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
# Files that change a machine, and the stick's own checker. Relative to the
# repo root, backslash form.
$script:ExcludeFiles = @(
    'tests\manual_ci.ps1',
    'tests\detection_selftest.ps1',
    'tests\cleanup_selftest.ps1',
    'tests\noadmin_smoke.ps1',
    'tools\make_usb_stick.ps1'
)
# Files the audit cannot run without; a copy missing one is refused.
$script:Required = @(
    'doze_sec.bat', 'doze_sec_noAdmin.bat',
    'tools\exec_probe.ps1', 'tests\field_test.ps1', 'tests\benign_corpus.txt',
    'tests\unraised_allowlist.txt', 'ThreatLists\ioc_hashes.txt'
)
# Files at the stick's root of a kind that can run or point elsewhere. They are
# recorded when the stick is made, and -Verify reports any that are new or
# changed: that is how a visited machine would try to reach the next one.
$script:RootSuspectRx = '\.(inf|lnk|exe|scr|com|pif|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|dll|cpl|msi|url)$'
# Root entries that make a stick bootable (an old install or recovery stick).
$script:BootNames = @('bootmgr', 'bootmgr.efi', 'efi', 'boot', 'sources')
# Root folders Windows itself keeps on a removable drive.
$script:SystemRootDirs = @('System Volume Information', '$RECYCLE.BIN')
# A root file larger than this is recorded by size, not hashed.
$script:RootHashLimit = 64MB
# Files written with CRLF line endings on the stick (a file holding a NUL byte
# is left as it is: it may be UTF-16 or binary). Every other file is copied
# byte for byte.
$script:TextRx = '\.(bat|cmd|ps1|psm1|psd1|txt|md|csv|json|xml|html?|css|js|ini|cfg|ya?ml|gitignore)$'

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
    #   -ForReading  the volume will only be read (-Verify): write protection
    #            and the file system are then no reason to refuse
    # Returns @{ Ok; Reasons = @(); Info = @() }. Fails closed: anything it
    # cannot establish is a reason to refuse.
    param($Disk, $Volume, [hashtable]$Context, [switch]$ForReading)
    $reasons = New-Object System.Collections.Generic.List[string]
    $info = New-Object System.Collections.Generic.List[string]
    $busOk = $false
    if ($Context -and $Context.LookupError) {
        $reasons.Add('could not identify the disk behind this drive: ' + $Context.LookupError + ' -- try an elevated PowerShell')
    }
    if ($null -eq $Disk) {
        if (-not ($Context -and $Context.LookupError)) { $reasons.Add('could not read the disk behind this drive') }
    } else {
        $bus = ConvertTo-BusName $Disk.BusType
        $busOk = ($bus -eq 'USB')
        if (-not $busOk) {
            $seen = if ($bus) { $bus } else { 'nothing' }
            $reasons.Add('the disk is not on the USB bus (Windows reports: ' + $seen + ')')
        }
        if ($Disk.IsBoot)     { $reasons.Add('this is the disk Windows booted from') }
        if ($Disk.IsSystem)   { $reasons.Add('this disk holds the system partition') }
        if ($Disk.IsOffline)  { $reasons.Add('the disk is offline') }
        if ($Disk.IsReadOnly -and -not $ForReading) { $reasons.Add('the disk is read-only (a write-protect switch?) -- turn protection off to make the stick, back on afterwards if you like') }
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
        # File-system advice only for a USB disk: for any other disk the bus
        # reason already refuses it, and format advice there is how a person is
        # talked into erasing a data drive.
        if ($busOk -and -not $ForReading) {
            $fs = [string]$Volume.FileSystem
            if ($fs -in @('FAT', 'FAT32', 'exFAT', 'NTFS')) {
                # fine
            } elseif (-not $fs -or $fs -in @('RAW', 'Unknown')) {
                $reasons.Add('Windows cannot read a file system on this volume. It may be locked by BitLocker (unlock it in File Explorer first), formatted on a Mac or under Linux, or brand new. Format it ONLY if you know it holds nothing you need -- formatting erases every file on it (File Explorer, right-click the drive, Format, exFAT).')
            } else {
                $reasons.Add('the volume uses ' + $fs + ', a file system that holds files but that this script does not write to -- use another stick')
            }
        }
        if ([string]$Volume.DriveType -eq 'Fixed') {
            $info.Add('the volume reports drive type Fixed; many USB sticks and USB SSDs do. The bus decides, and it is USB.')
        }
    }
    return @{ Ok = ($reasons.Count -eq 0); Reasons = $reasons.ToArray(); Info = $info.ToArray() }
}

function Test-SelfOnTarget {
    # PURE. Is this script running from the target it is about to make,
    # verify or refresh? The stick's own copy -- if one is there at all, it was
    # put there by someone else -- must never be the one that vouches for it.
    param([string]$ScriptRoot, [string]$Outer)
    if (-not $ScriptRoot -or -not $Outer) { return $false }
    $a = ($ScriptRoot.TrimEnd('\', '/') + '\') -replace '/', '\'
    $b = ($Outer.TrimEnd('\', '/') + '\') -replace '/', '\'
    return $a.StartsWith($b, [StringComparison]::OrdinalIgnoreCase)
}

function Format-Size {
    param($Bytes)
    if ($null -eq $Bytes) { return '?' }
    $b = [double]$Bytes
    if ($b -ge 1GB) { return ('{0:N1} GB' -f ($b / 1GB)) }
    return ('{0:N0} MB' -f ($b / 1MB))
}

function Get-PickerRow {
    # PURE. One lettered volume as the drive picker shows it.
    #   -Mode 'make'    put the tool on it: offered when Get-StickVerdict
    #                   accepts it and it does not already hold doze_sec
    #                   (copying never overwrites a copy)
    #         'refresh' replace a copy there: offered when Get-StickVerdict
    #                   accepts it and it holds doze_sec
    #         'verify'  check the copy there: offered when it holds doze_sec
    #                   and passes the same rule read-only (a write-protected
    #                   stick reads back fine)
    #   -HasTool  something named doze_sec is at its root
    #   -ProbeError  why looking for doze_sec there failed (an unreadable
    #             volume); a reason to refuse it
    # Returns @{ Letter; Offer; Reasons; Name; Bus; FileSystem; Size; Free }.
    param([string]$Letter, $Disk, $Volume, [hashtable]$Context, [string]$Mode = 'make', [bool]$HasTool = $false, [string]$ProbeError = '')
    $v = Get-StickVerdict $Disk $Volume $Context -ForReading:($Mode -eq 'verify')
    $reasons = New-Object System.Collections.Generic.List[string]
    foreach ($r in $v.Reasons) { $reasons.Add($r) }
    if ($Mode -eq 'verify' -and -not $HasTool) { $reasons.Add('it holds no doze_sec folder to check') }
    if ($ProbeError) { $reasons.Add($ProbeError) }
    if ($Mode -eq 'make' -and $HasTool) { $reasons.Add('it already holds doze_sec -- run with -Refresh to replace that copy, or -Verify to check it') }
    if ($Mode -eq 'refresh' -and -not $HasTool) { $reasons.Add('it holds no doze_sec to replace -- run without -Refresh to make one') }
    $size = $null
    if ($Volume -and $Volume.PSObject.Properties['Size']) { $size = $Volume.Size } elseif ($Disk) { $size = $Disk.Size }
    return @{
        Letter     = ([string]$Letter).Trim().TrimEnd(':').ToUpper()
        Offer      = ($reasons.Count -eq 0)
        Reasons    = $reasons.ToArray()
        Name       = $(if ($Disk -and $Disk.FriendlyName) { [string]$Disk.FriendlyName } else { '?' })
        Bus        = $(if ($Disk) { ConvertTo-BusName $Disk.BusType } else { '?' })
        FileSystem = $(if ($Volume -and $Volume.FileSystem) { [string]$Volume.FileSystem } else { '?' })
        Size       = $size
        Free       = $(if ($Volume) { $Volume.SizeRemaining } else { $null })
    }
}

function Invoke-StickPicker {
    # Shows the drives, asks which one, then asks the person to type that
    # drive's letter before anything is written. Returns the letter, or '' when
    # nothing was chosen. Only an offered drive has a number; a refused one is
    # listed with its reason and cannot be picked, by number or by letter.
    # -Ask reads one answer (Read-Host) and -Say prints one line (Write-Host);
    # the self-test injects both. A window that cannot ask (powershell
    # -NonInteractive) returns '' and names the -Drive form to use instead.
    param([object[]]$Rows, [string]$Mode = 'make', [scriptblock]$Ask, [scriptblock]$Say)
    $offer = @($Rows | Where-Object { $_.Offer })
    $refused = @($Rows | Where-Object { -not $_.Offer })
    $what = switch ($Mode) { 'verify' { 'check' } 'refresh' { 'refresh' } default { 'put the tool on' } }
    if ($offer.Count -gt 0) {
        & $Say ('Drives this script can ' + $what + ':')
        for ($i = 0; $i -lt $offer.Count; $i++) {
            $o = $offer[$i]
            & $Say ('  [{0}]  {1}:  {2}  ({3}, {4}, {5}, {6} free)' -f ($i + 1), $o.Letter, $o.Name, $o.Bus, $o.FileSystem, (Format-Size $o.Size), (Format-Size $o.Free))
        }
    }
    if ($refused.Count -gt 0) {
        & $Say 'Not offered:'
        foreach ($r in $refused) {
            & $Say ('        {0}:  {1}  ({2}, {3})' -f $r.Letter, $r.Name, $r.Bus, $r.FileSystem)
            foreach ($x in $r.Reasons) { & $Say ('              - ' + $x) }
        }
    }
    if ($offer.Count -eq 0) {
        & $Say ('No drive this script can ' + $what + ' was found. Nothing was written.')
        & $Say '  Plug the USB stick in (unlock it first if it uses BitLocker) and run this again. If every drive says'
        & $Say '  its disk could not be identified, use PowerShell as administrator.'
        return ''
    }
    $pick = $null
    for ($try = 1; $try -le 3 -and -not $pick; $try++) {
        try { $a = & $Ask ('Type the number of the drive (1-' + $offer.Count + '), or Q to quit') }
        catch {
            & $Say ('This window cannot ask (' + $_.Exception.Message + '). Nothing was written.')
            & $Say ('  Name the drive instead, for example: -Drive ' + $offer[0].Letter + ':')
            return ''
        }
        $a = ([string]$a).Trim()
        if ($a -eq '' -or $a -ieq 'q') { & $Say 'Nothing chosen. Nothing was written.'; return '' }
        $n = 0
        if ([int]::TryParse($a, [ref]$n) -and $n -ge 1 -and $n -le $offer.Count) { $pick = $offer[$n - 1] }
        else { & $Say ('"' + $a + '" is not one of the numbers above.') }
    }
    if (-not $pick) { & $Say 'No drive chosen after 3 tries. Nothing was written.'; return '' }
    $L = $pick.Letter
    & $Say ('You chose {0}:  {1}  ({2}, {3}).' -f $L, $pick.Name, $pick.FileSystem, (Format-Size $pick.Size))
    switch ($Mode) {
        'verify'  { & $Say ('This will check ' + $L + ':\doze_sec against the manifest kept on this laptop. It only reads the drive.') }
        'refresh' { & $Say ('This will replace the copy in ' + $L + ':\doze_sec -- only if it is still exactly what this laptop wrote; anything else stops it, nothing deleted.') }
        default   { & $Say ('This will copy the tool into ' + $L + ':\doze_sec. Nothing on the drive is formatted or erased; the files already on it stay.') }
    }
    try { $c = & $Ask ('Type ' + $L + ' to go ahead, anything else to cancel') }
    catch { & $Say ('This window cannot ask (' + $_.Exception.Message + '). Nothing was written.'); return '' }
    if (([string]$c).Trim().TrimEnd(':') -ine $L) { & $Say 'Cancelled. Nothing was written.'; return '' }
    return $L
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

function Get-EntryState {
    # 'missing' | 'link' | 'dir' | 'file' | 'unreadable' -- read from the entry
    # ITSELF, never from what a link points at. Test-Path and
    # DirectoryInfo.Exists follow links; a junction planted on a stick can point
    # into this laptop. A METHOD call, not FileInfo.Attributes: PowerShell turns
    # an exception thrown by a property getter into $null, so a BitLocker-locked
    # or unrecognised volume read as attributes 0 -- an ordinary file.
    param([string]$Path)
    try { $a = [int][IO.File]::GetAttributes($Path) }
    catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] { return 'missing' }
    catch { return 'unreadable' }
    if (($a -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) { return 'link' }
    if (($a -band [int][IO.FileAttributes]::Directory) -ne 0) { return 'dir' }
    return 'file'
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
    # The ROOT itself is the caller's to check (Get-EntryState) before calling.
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
    # Byte-exact: every LF not already preceded by CR becomes CRLF, and nothing
    # else changes. Latin-1 maps each byte to one character and back, so no
    # byte is altered; UTF-8 never uses the byte 0x0A inside a multi-byte
    # character, so UTF-8 text is safe too. Returns byte[] (the leading comma
    # stops PowerShell unrolling it into an object array).
    param([byte[]]$Bytes)
    $enc = [Text.Encoding]::GetEncoding(28591)
    return ,$enc.GetBytes(($enc.GetString($Bytes) -replace '(?<!\r)\n', "`r`n"))
}

function Test-CanHoldStreams {
    # Only NTFS (and ReFS) store named alternate data streams. On FAT32 and
    # exFAT, Windows PowerShell 5.1's Get-Item -Stream THROWS (FindFirstStreamW
    # fails with ERROR_INVALID_PARAMETER and the 5.1 provider raises it), so
    # asking there would end the run on the most common sticks.
    param([string]$Path)
    if (-not $script:OnWindows) { return $false }
    $fmt = ''
    try { $fmt = (New-Object IO.DriveInfo ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path)))).DriveFormat } catch {}
    return ($fmt -in @('NTFS', 'ReFS'))
}

function Get-MotwCount {
    # How many source files carry a Zone.Identifier stream (Mark of the Web).
    # -1 when the source's file system cannot hold one.
    param([IO.FileInfo[]]$Files, [string]$Root)
    if (-not (Test-CanHoldStreams $Root)) { return -1 }
    $n = 0
    foreach ($f in $Files) {
        try { if (Get-Item -LiteralPath $f.FullName -Stream 'Zone.Identifier' -EA Stop) { $n++ } } catch {}
    }
    return $n
}

function Get-ExtraStreams {
    # Alternate data streams on a file, other than the main one. Returns a
    # '(could not list ...)' entry when they could not be read, so a failed
    # check is reported as a difference, never as a clean result.
    param([string]$Path)
    if (-not (Test-CanHoldStreams $Path)) { return @() }
    try { $all = @(Get-Item -LiteralPath $Path -Stream * -EA Stop) }
    catch { return @('(could not list streams: ' + $_.Exception.Message + ')') }
    return @($all | Where-Object { $_.Stream -ne ':$DATA' } | ForEach-Object { $_.Stream })
}

function Get-RootScan {
    # The stick root, minus doze_sec and Windows' own folders:
    #   Watch  ordered name -> sha256 | 'size:N' | 'link' | 'dir' for every root
    #          entry that can run, point elsewhere or boot (recorded in the
    #          manifest when the stick is made, compared on -Verify)
    #   Boot   names that make the stick bootable (bootmgr, EFI, ...)
    #   Other  any other top-level folder (for example results you copied there)
    param([string]$Outer)
    $watch = [ordered]@{}
    $boot = New-Object System.Collections.Generic.List[string]
    $other = New-Object System.Collections.Generic.List[string]
    if ((Get-EntryState $Outer) -ne 'dir') { return @{ Watch = $watch; Boot = $boot.ToArray(); Other = $other.ToArray() } }
    foreach ($e in (New-Object IO.DirectoryInfo $Outer).GetFileSystemInfos()) {
        $n = $e.Name
        if ($n -ieq $script:StickFolder -and -not (Test-IsReparse $e)) { continue }
        if ($script:SystemRootDirs -contains $n) { continue }
        $isBoot = ($script:BootNames -contains $n.ToLowerInvariant())
        if ($isBoot) { $boot.Add($n) }
        if (Test-IsReparse $e) { $watch[$n] = 'link'; continue }
        if ($e -is [IO.DirectoryInfo]) {
            if ($isBoot) { $watch[$n] = 'dir' } else { $other.Add($n) }
            continue
        }
        if ($isBoot -or $n -match $script:RootSuspectRx) {
            $fi = [IO.FileInfo]$e
            if ($fi.Length -gt $script:RootHashLimit) { $watch[$n] = 'size:' + $fi.Length }
            else {
                try { $watch[$n] = Get-Sha256Hex ([IO.File]::ReadAllBytes($fi.FullName)) }
                catch { $watch[$n] = 'unreadable' }
            }
        }
    }
    return @{ Watch = $watch; Boot = $boot.ToArray(); Other = $other.ToArray() }
}

function Invoke-StickCopy {
    # Copies $Source into $Dest (which must not exist). Returns
    # @{ Entries = ordered rel -> sha256; Excluded = @(); Normalized; Motw; Bytes }.
    # Throws with a plain reason on anything it refuses.
    param([string]$Source, [string]$Dest)
    $srcFull = [IO.Path]::GetFullPath($Source).TrimEnd('\', '/')
    $dstFull = [IO.Path]::GetFullPath($Dest).TrimEnd('\', '/')
    if (Test-SelfOnTarget $dstFull $srcFull) { throw ('the destination ' + $dstFull + ' is inside the source tree') }
    if (Test-SelfOnTarget $srcFull $dstFull) { throw ('the source ' + $srcFull + ' is inside the destination') }
    if ((Get-EntryState $dstFull) -ne 'missing') { throw ($dstFull + ' already exists -- use -Refresh to replace a copy this script made, or remove it yourself') }
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
    $motw = Get-MotwCount @($plan | ForEach-Object { $_.File }) $srcFull
    $entries = [ordered]@{}
    $normalized = 0
    $bytesTotal = [long]0
    [void][IO.Directory]::CreateDirectory($dstFull)
    foreach ($p in ($plan | Sort-Object { $_.Rel })) {
        $bytes = [IO.File]::ReadAllBytes($p.File.FullName)
        if (($p.Rel -match $script:TextRx) -and ([Array]::IndexOf($bytes, [byte]0) -lt 0)) {
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
    param([System.Collections.IDictionary]$Entries, [string]$TargetId, [string]$SourcePath, [string]$Created, [System.Collections.IDictionary]$Root)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# doze_sec stick manifest -- SHA-256 of every file this script put on the stick')
    $lines.Add('# made-by: ' + $script:Version)
    $lines.Add('# created: ' + $Created)
    $lines.Add('# target: ' + $TargetId)
    $lines.Add('# source: ' + $SourcePath)
    $lines.Add('# files: ' + $Entries.Count)
    $lines.Add('# root-scan: v1')
    if ($Root) { foreach ($k in $Root.Keys) { $lines.Add('# root: ' + $Root[$k] + ' ' + $k) } }
    foreach ($k in $Entries.Keys) { $lines.Add($Entries[$k] + '  ' + $k) }
    return ($lines -join "`r`n") + "`r`n"
}

function Read-Manifest {
    # Returns @{ Header = @{}; Entries = @{ rel -> sha256 }; Root = @{ name -> state } or $null }.
    param([string]$Path)
    $hdr = @{}
    $ent = @{}
    $root = @{}
    foreach ($ln in [IO.File]::ReadAllLines($Path)) {
        if ($ln -match '^#\s*root:\s*(\S+)\s+(.+)$') { $root[$matches[2]] = $matches[1]; continue }
        if ($ln -match '^#\s*([a-z-]+):\s*(.*)$') { $hdr[$matches[1]] = $matches[2].Trim(); continue }
        if ($ln -match '^#' -or -not $ln.Trim()) { continue }
        if ($ln -match '^([0-9a-f]{64})  (.+)$') { $ent[$matches[2]] = $matches[1]; continue }
        throw ('unreadable manifest line in ' + $Path + ': ' + $ln)
    }
    if (-not $hdr.ContainsKey('made-by') -or $hdr['made-by'] -notmatch '^make_usb_stick ') { throw ($Path + ' is not a manifest written by this script') }
    $rootOut = $null
    if ($hdr.ContainsKey('root-scan')) { $rootOut = $root }
    return @{ Header = $hdr; Entries = $ent; Root = $rootOut }
}

function Get-FileSha256 {
    # SHA-256 of a file, streamed, so a planted multi-gigabyte file cannot
    # exhaust memory.
    param([string]$Path)
    $h = [Security.Cryptography.SHA256]::Create()
    $fs = $null
    try {
        $fs = [IO.File]::OpenRead($Path)
        return ([BitConverter]::ToString($h.ComputeHash($fs)) -replace '-', '').ToLower()
    } finally {
        if ($fs) { $fs.Dispose() }
        $h.Dispose()
    }
}

function Get-StickState {
    # Reads the copy at <Root>, and the stick root at <OuterRoot>, ONCE: every
    # file's SHA-256 (one larger than RootHashLimit is recorded by size --
    # nothing this script writes is that large), each file's extra streams,
    # every reparse point, the stick's own copy of its manifest, and the root
    # scan. Comparing against several manifests reuses this reading instead of
    # reading the stick again for each. Never follows a link.
    param([string]$Root, [string]$OuterRoot = '')
    $s = @{ State = (Get-EntryState $Root); Files = @{}; Streams = @{}; Reparse = @(); StickManifest = ''; Scan = $null }
    if ($OuterRoot) { $s.Scan = Get-RootScan $OuterRoot }
    if ($s.State -ne 'dir') { return $s }
    $tree = Get-TreeEntries $Root -Strict
    foreach ($f in $tree.Files) {
        $rel = Get-RelPath $Root $f.FullName
        $h = 'unreadable'
        if ($f.Length -gt $script:RootHashLimit) { $h = 'size:' + $f.Length }
        else { try { $h = Get-FileSha256 $f.FullName } catch {} }
        # PowerShell hashtables compare keys case-insensitively, as FAT and
        # exFAT compare names.
        if ($rel -ieq $script:StickManifestName) { $s.StickManifest = $h } else { $s.Files[$rel] = $h }
        $x = @(Get-ExtraStreams $f.FullName)
        if ($x.Count -gt 0) { $s.Streams[$rel] = $x }
    }
    $s.Reparse = $tree.Reparse
    return $s
}

function Compare-StickState {
    # Compares a Get-StickState reading with a trusted manifest: its entries,
    # the stick root against the root it recorded, and -- given -ManifestHash,
    # the SHA-256 of the laptop's manifest file -- the copy of that manifest the
    # stick carries, which this script wrote byte for byte equal to the
    # laptop's. That copy ties the stick to ONE manifest: two sticks made from
    # the same checkout hold the same files but not the same manifest.
    # Returns @{ RootLink; Missing; Changed; Added; Removed; Streams; Reparse;
    #            RootNew; Other }.
    param($State, [hashtable]$Expected, $RootBaseline = $null, [string]$ManifestHash = '')
    $r = @{ RootLink = $false; Missing = $false; Changed = @(); Added = @(); Removed = @(); Streams = @(); Reparse = @(); RootNew = @(); Other = @() }
    if ($State.State -eq 'link') { $r.RootLink = $true; return $r }
    if ($State.State -ne 'dir') { $r.Missing = $true; return $r }
    $changed = New-Object System.Collections.Generic.List[string]
    $added = New-Object System.Collections.Generic.List[string]
    $removed = New-Object System.Collections.Generic.List[string]
    $streams = New-Object System.Collections.Generic.List[string]
    foreach ($rel in @($State.Files.Keys | Sort-Object)) {
        if (-not $Expected.ContainsKey($rel)) { $added.Add($rel); continue }
        if ($State.Files[$rel] -ne $Expected[$rel]) { $changed.Add($rel) }
        if ($State.Streams.ContainsKey($rel)) { foreach ($x in $State.Streams[$rel]) { $streams.Add($rel + ':' + $x) } }
    }
    foreach ($k in @($Expected.Keys | Sort-Object)) { if (-not $State.Files.ContainsKey($k)) { $removed.Add($k) } }
    if ($ManifestHash) {
        if (-not $State.StickManifest) { $removed.Add($script:StickManifestName) }
        elseif ($State.StickManifest -ne $ManifestHash) { $changed.Add($script:StickManifestName) }
        if ($State.Streams.ContainsKey($script:StickManifestName)) { foreach ($x in $State.Streams[$script:StickManifestName]) { $streams.Add($script:StickManifestName + ':' + $x) } }
    }
    $r.Changed = $changed.ToArray()
    $r.Added = $added.ToArray()
    $r.Removed = $removed.ToArray()
    $r.Streams = $streams.ToArray()
    $r.Reparse = $State.Reparse
    if ($State.Scan) {
        $new = New-Object System.Collections.Generic.List[string]
        foreach ($k in $State.Scan.Watch.Keys) {
            if ($null -eq $RootBaseline) { $new.Add($k + ' (the root was not recorded when this stick was made)'); continue }
            if (-not $RootBaseline.ContainsKey($k)) { $new.Add($k); continue }
            if ($RootBaseline[$k] -ne $State.Scan.Watch[$k]) { $new.Add($k + ' (changed)') }
        }
        $r.RootNew = $new.ToArray()
        $r.Other = $State.Scan.Other
    }
    return $r
}

function Compare-StickTree {
    # Get-StickState and Compare-StickState in one call.
    param([string]$Root, [hashtable]$Expected, [string]$OuterRoot = '', $RootBaseline = $null, [string]$ManifestHash = '')
    return (Compare-StickState (Get-StickState $Root $OuterRoot) $Expected $RootBaseline $ManifestHash)
}

function Get-DiffCount {
    param([hashtable]$C)
    return (@($C.Changed).Count + @($C.Added).Count + @($C.Removed).Count + @($C.Streams).Count + @($C.Reparse).Count)
}

function Remove-StickCopy {
    # Removes a copy this laptop made -- and only if it is still exactly that.
    # Compares <Dir> with the TRUSTED manifest's entries first (never the copy
    # on the stick) and refuses, listing what it found, on any file changed,
    # added or removed, any new stream, or any link: an added file may be the
    # owner's saved results, a changed one is evidence of what a visited machine
    # did, and a link could lead the delete off the stick. Then it deletes only
    # the files the manifest lists, the stick's manifest, and folders left
    # empty. Throws with the reason on refusal; deletes nothing in that case.
    param([string]$Dir, [hashtable]$Expected, [string]$ManifestHash = '')
    if ((Get-EntryState $Dir) -eq 'link') { throw ($Dir + ' is itself a link or junction; refused -- nothing behind it was read. Keep the stick as it is: it is evidence.') }
    if ($null -eq $Expected) { throw ('this laptop holds no manifest for ' + $Dir + ', so nothing proves what in it is ours; remove it yourself after looking at what it holds') }
    $c = Compare-StickTree -Root $Dir -Expected $Expected -ManifestHash $ManifestHash
    if ($c.RootLink) { throw ($Dir + ' is itself a link or junction; refused -- inspect the stick before reusing it') }
    if ($c.Missing) { throw ($Dir + ' does not exist') }
    if ((Get-DiffCount $c) -gt 0) {
        $list = @($c.Changed | ForEach-Object { 'changed: ' + $_ }) + @($c.Added | ForEach-Object { 'added: ' + $_ }) +
                @($c.Removed | ForEach-Object { 'removed: ' + $_ }) + @($c.Streams | ForEach-Object { 'stream: ' + $_ }) +
                @($c.Reparse | ForEach-Object { 'link: ' + $_ })
        $shown = @($list | Select-Object -First 12) -join '; '
        if ($list.Count -gt 12) { $shown += ('; and ' + ($list.Count - 12) + ' more') }
        throw ($Dir + ' is no longer exactly what this laptop wrote (' + $shown + '). Nothing was deleted. Run -Verify; move out any files of yours; if the visited machine changed it, keep this stick as evidence and use a new one.')
    }
    foreach ($k in @($Expected.Keys)) {
        $f = New-Object IO.FileInfo (Join-Rel $Dir $k)
        $f.Attributes = 'Normal'
        $f.Delete()
    }
    $mf = New-Object IO.FileInfo (Join-Path $Dir $script:StickManifestName)
    if ($mf.Exists) { $mf.Attributes = 'Normal'; $mf.Delete() }
    $tree = Get-TreeEntries $Dir -Strict
    foreach ($d in ($tree.Dirs | Sort-Object { $_.FullName.Length } -Descending)) {
        try { $d.Delete($false) } catch {}
    }
    (New-Object IO.DirectoryInfo $Dir).Delete($false)
}

function Get-ManifestStore {
    if ($ManifestStore) { return $ManifestStore }
    $base = $env:LOCALAPPDATA
    if (-not $base) { $base = [IO.Path]::GetTempPath() }
    return (Join-Path (Join-Path $base 'doze_sec') 'sticks')
}

function Get-StoreManifests {
    # Every manifest in the laptop store, newest first, each read once:
    # @{ Path; Manifest (or $null); Error }. One that cannot be read is kept
    # with its reason, so a listing names it instead of skipping it in silence.
    param([string]$Store)
    $out = New-Object System.Collections.Generic.List[object]
    if ((Get-EntryState $Store) -ne 'dir') { return ,$out.ToArray() }
    $files = @(Get-ChildItem -LiteralPath $Store -File | Where-Object { $_.Name.EndsWith('.sha256', [StringComparison]::OrdinalIgnoreCase) } | Sort-Object Name -Descending)
    foreach ($f in $files) {
        $m = $null; $e = ''
        try { $m = Read-Manifest $f.FullName } catch { $e = $_.Exception.Message }
        $out.Add(@{ Path = $f.FullName; Manifest = $m; Error = $e })
    }
    return ,$out.ToArray()
}

function Set-ManifestSuperseded {
    # A laptop manifest whose copy -Refresh has replaced must never vouch
    # again. Otherwise a visited machine that put the OLD copy back -- the
    # files and the old manifest copy, saved from an earlier visit -- would
    # read "[OK] ... exactly what this laptop put there": a rollback to an
    # older tool. Renamed, not deleted, so the record stays; the store
    # listing reads *.sha256 only. Returns the new path.
    param([string]$Path)
    $to = $Path + '.superseded'
    if ((Get-EntryState $to) -ne 'missing') { $to = $Path + '.' + (Get-Date -Format 'yyyyMMddHHmmss') + '.superseded' }
    [IO.File]::Move($Path, $to)
    return $to
}

function Resolve-TrustedManifest {
    # Which manifest kept on this laptop vouches for the copy read into
    # <Stick> (Get-StickState). Never the stick's own copy of the manifest.
    #   1. The newest whose recorded target is this one (the volume ID, or the
    #      folder path): How = 'target'.
    #   2. Failing that, the newest that the copy matches EXACTLY -- every file,
    #      and the stick's own copy of that manifest byte for byte: How =
    #      'content'. Windows can give a stick with no serial number a new
    #      volume ID when it goes into another USB port; that changes nothing on
    #      the stick. The manifest copy is what makes this one stick's manifest:
    #      another stick made from the same checkout has the same files and a
    #      different manifest. And -Refresh retires the manifest of the copy it
    #      replaces (Set-ManifestSuperseded), so an older copy put back cannot
    #      match at all.
    #   3. Neither: How = '', and Candidates lists every manifest with its
    #      difference count (or why it was not compared), so the caller can say
    #      UNVERIFIED and point at the closest one instead of guessing.
    # A copy that is a link, a file or unreadable is matched by target only.
    # Returns @{ Path; Manifest; How; Candidates = @(@{ Path; Line }) }.
    param([object[]]$Manifests, [string]$TargetId, $Stick)
    foreach ($e in $Manifests) {
        if ($e.Manifest -and $e.Manifest.Header['target'] -ceq $TargetId) {
            return @{ Path = $e.Path; Manifest = $e.Manifest; How = 'target'; Candidates = @() }
        }
    }
    $cands = New-Object System.Collections.Generic.List[object]
    $pick = $null
    foreach ($e in $Manifests) {
        if (-not $e.Manifest) { $cands.Add(@{ Path = $e.Path; Line = 'could not be read (' + $e.Error + ')' }); continue }
        $m = $e.Manifest
        $head = 'made ' + $m.Header['created'] + ' for ' + $m.Header['target'] + ', ' + $m.Entries.Count + ' files'
        if ($Stick.State -ne 'dir') { $cands.Add(@{ Path = $e.Path; Line = ($head + ': not compared -- the copy is not a folder (' + $Stick.State + ')') }); continue }
        $c = Compare-StickState $Stick $m.Entries $m.Root (Get-FileSha256 $e.Path)
        $d = Get-DiffCount $c
        if ((-not $pick) -and $d -eq 0 -and $m.Entries.Count -gt 0) { $pick = $e }
        $cands.Add(@{ Path = $e.Path; Line = ($head + ': ' + $d + ' difference(s) from this copy') })
    }
    if ($pick) { return @{ Path = $pick.Path; Manifest = $pick.Manifest; How = 'content'; Candidates = @() } }
    return @{ Path = $null; Manifest = $null; How = ''; Candidates = $cands.ToArray() }
}

function Get-IdTag {
    param([string]$TargetId)
    return (Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($TargetId))).Substring(0, 8)
}

function ConvertTo-Hashtable {
    param([System.Collections.IDictionary]$D)
    $h = @{}
    foreach ($k in $D.Keys) { $h[$k] = $D[$k] }
    return $h
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

function Get-LivePickerRows {
    param([string]$Mode)
    $rows = New-Object System.Collections.Generic.List[object]
    # Throws when the drives cannot be listed (a window that is not elevated
    # may be refused); the caller says so and names the -Drive form.
    $vols = @(Get-Volume -EA Stop | Where-Object { $_.DriveLetter } | Sort-Object DriveLetter)
    foreach ($vol in $vols) {
        $l = [string]$vol.DriveLetter
        $lt = Get-LiveTarget $l
        # Anything named doze_sec counts, a link or a file included: -Verify
        # reports those, and a copy never writes over one.
        $st = Get-EntryState ($l + ':\' + $script:StickFolder)
        $probe = ''
        if ($st -eq 'unreadable') { $probe = 'Windows cannot read this drive -- it may be locked by BitLocker (unlock it in File Explorer first) or formatted for a Mac or Linux' }
        $rows.Add((Get-PickerRow -Letter $l -Disk $lt.Disk -Volume $lt.Volume -Context (Get-LiveContext $lt.Error) -Mode $Mode -HasTool ($st -in @('dir', 'link', 'file')) -ProbeError $probe))
    }
    return ,$rows.ToArray()
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
    function New-Tree { param([string]$Root, [string[]]$Rels)
        foreach ($rel in $Rels) {
            $p = Join-Rel $Root $rel
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p))
            [IO.File]::WriteAllText($p, ("content of " + $rel + "`nline two`n"))
        }
    }
    $ctx = @{ SystemDrive = 'C:'; ProtectedPaths = @('C:\Windows', 'C:\Users\u', 'C:\Users\u\src\doze_sec'); LookupError = '' }

    # --- the target rule ---------------------------------------------------
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
    $rj = $v.Reasons -join ' '
    T 'an unreadable volume is never called unformatted: BitLocker or Mac/Linux is named before any format advice, with the erase warning' ((-not $v.Ok) -and $rj -match 'cannot read a file system' -and $rj -match 'BitLocker' -and $rj -match 'Mac' -and $rj -match 'ONLY if you know' -and $rj -match 'erases every file' -and $rj -notmatch 'not formatted') $rj
    $v = Get-StickVerdict (D) (V -Fs '') $ctx
    T 'a volume with no file system name gets the same careful wording' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'BitLocker') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D) (V -Fs 'ReFS') $ctx
    T 'a ReFS volume is named as holding files, with no format advice' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'ReFS' -and ($v.Reasons -join ' ') -notmatch 'Format') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D -Bus 'SATA') (V -Fs 'RAW') $ctx
    T 'a non-USB disk gets no format advice at all (only the bus reason)' ((-not $v.Ok) -and ($v.Reasons -join ' ') -notmatch 'Format' -and ($v.Reasons -join ' ') -notmatch 'erases') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D) (V -L 'C') $ctx
    T 'the Windows drive letter is refused whatever the bus says' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'Windows drive') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D) (V -L 'D') @{ SystemDrive = 'C:'; ProtectedPaths = @('D:\src\doze_sec'); LookupError = '' }
    T 'a drive holding the source checkout is refused' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'holds D:\\src') ($v.Reasons -join '; ')
    $v = Get-StickVerdict (D) (V -Dt 'Fixed') $ctx
    T 'a USB disk reporting Fixed is accepted, with an INFO line (the bus decides)' ($v.Ok -and ($v.Info -join ' ') -match 'bus decides') (($v.Reasons + $v.Info) -join '; ')
    $v = Get-StickVerdict $null $null @{ SystemDrive = 'C:'; ProtectedPaths = @(); LookupError = 'Access denied' }
    T 'a lookup error refuses and suggests an elevated window' ((-not $v.Ok) -and ($v.Reasons -join ' ') -match 'elevated') ($v.Reasons -join '; ')

    # --- the drive picker ------------------------------------------------------
    # Answers come from a script-scoped queue and printed lines go to a
    # script-scoped list (a plain scriptblock sees script scope on 5.1; a
    # closure would not -- see CLAUDE.md on GetNewClosure).
    function Pick { param([object[]]$Rows, [string]$Mode = 'make', [string[]]$Answers)
        $script:PickQ = New-Object System.Collections.Generic.Queue[string]
        foreach ($x in $Answers) { $script:PickQ.Enqueue($x) }
        $script:PickSaid = New-Object System.Collections.Generic.List[string]
        $script:PickAsked = 0
        $letter = Invoke-StickPicker -Rows $Rows -Mode $Mode -Ask { param($p) $script:PickAsked++; if ($script:PickQ.Count -eq 0) { throw 'no more answers' }; $script:PickQ.Dequeue() } -Say { param($l) $script:PickSaid.Add($l) }
        return @{ Letter = $letter; Said = ($script:PickSaid -join "`n"); Asked = $script:PickAsked }
    }
    $rowC = Get-PickerRow -Letter 'C' -Disk (D -Bus 'NVMe' -Boot $true -Sys $true) -Volume (V -L 'C' -Fs 'NTFS' -Dt 'Fixed') -Context $ctx
    $rowE = Get-PickerRow -Letter 'E' -Disk (D) -Volume (V -L 'E') -Context $ctx
    $rowF = Get-PickerRow -Letter 'F' -Disk (D) -Volume (V -L 'F' -Fs 'FAT32') -Context $ctx
    T 'the picker offers a USB stick and refuses the Windows disk, with its reasons' ($rowE.Offer -and -not $rowC.Offer -and ($rowC.Reasons -join ' ') -match 'Windows drive' -and ($rowC.Reasons -join ' ') -match 'NVMe') ($rowC.Reasons -join '; ')
    $r = Pick @($rowC, $rowE) 'make' @('1', 'E')
    T 'one stick: number 1, then its letter, chooses it' ($r.Letter -eq 'E' -and $r.Asked -eq 2) ($r.Letter + ' asked=' + $r.Asked)
    T 'a refused drive is listed with its reason and has no number' ($r.Said -match '(?m)^\s+C:\s' -and $r.Said -match 'Windows drive' -and $r.Said -notmatch '\[\d\]\s+C:') $r.Said
    T 'the confirmation says nothing is formatted or erased' ($r.Said -match 'Nothing on the drive is formatted or erased') $r.Said
    $r = Pick @($rowC, $rowE, $rowF) 'make' @('2', 'f')
    T 'two sticks: the second number and a lower-case letter choose the second' ($r.Letter -eq 'F') $r.Letter
    $r = Pick @($rowC, $rowE) 'make' @('9', 'x', '1', 'E:')
    T 'a wrong number is asked again; the letter may be typed with a colon' ($r.Letter -eq 'E' -and $r.Asked -eq 4 -and $r.Said -match '"9" is not one of the numbers') ($r.Letter + ' asked=' + $r.Asked)
    $r = Pick @($rowC, $rowE) 'make' @('C', '0', '7')
    T 'three wrong answers -- typing a refused drive''s letter is one -- choose nothing' ($r.Letter -eq '' -and $r.Said -match 'after 3 tries' -and $r.Said -match 'Nothing was written') $r.Said
    $r = Pick @($rowE) 'make' @('q')
    T 'Q quits and nothing is written' ($r.Letter -eq '' -and $r.Said -match 'Nothing was written') $r.Said
    $r = Pick @($rowE) 'make' @('')
    T 'an empty answer quits too (an accidental Enter writes nothing)' ($r.Letter -eq '') $r.Letter
    $r = Pick @($rowE, $rowF) 'make' @('1', 'F')
    T 'confirming with a different letter cancels' ($r.Letter -eq '' -and $r.Said -match 'Cancelled') $r.Said
    $r = Pick @($rowC) 'make' @('1', 'C')
    T 'with no acceptable drive nothing is asked at all' ($r.Letter -eq '' -and $r.Asked -eq 0 -and $r.Said -match 'No drive this script can put the tool on was found') ($r.Said)
    $r = Pick @($rowE) 'make' @()
    T 'a window that cannot ask chooses nothing and names the -Drive form' ($r.Letter -eq '' -and $r.Said -match 'cannot ask' -and $r.Said -match '-Drive E:') $r.Said
    $rowHas = Get-PickerRow -Letter 'E' -Disk (D) -Volume (V -L 'E') -Context $ctx -Mode 'make' -HasTool $true
    T 'making: a stick that already holds doze_sec is not offered, and the reason names -Refresh and -Verify' ((-not $rowHas.Offer) -and ($rowHas.Reasons -join ' ') -match '-Refresh' -and ($rowHas.Reasons -join ' ') -match '-Verify') ($rowHas.Reasons -join '; ')
    T 'refreshing: the same stick is offered' ((Get-PickerRow -Letter 'E' -Disk (D) -Volume (V -L 'E') -Context $ctx -Mode 'refresh' -HasTool $true).Offer) ''
    $rf = Get-PickerRow -Letter 'E' -Disk (D) -Volume (V -L 'E') -Context $ctx -Mode 'refresh' -HasTool $false
    T 'refreshing: a stick with no copy to replace is not offered, and the reason says to run without -Refresh' ((-not $rf.Offer) -and ($rf.Reasons -join ' ') -match 'without -Refresh') ($rf.Reasons -join '; ')
    $ur = Get-PickerRow -Letter 'E' -Disk (D) -Volume (V -L 'E') -Context $ctx -Mode 'verify' -HasTool $false -ProbeError 'Windows cannot read this drive -- it may be locked by BitLocker'
    T 'checking: a stick Windows cannot read is refused with that reason, never offered' ((-not $ur.Offer) -and ($ur.Reasons -join ' ') -match 'cannot read') ($ur.Reasons -join '; ')
    $roV = Get-PickerRow -Letter 'E' -Disk (D -Ro $true) -Volume (V -L 'E') -Context $ctx -Mode 'verify' -HasTool $true
    $roM = Get-PickerRow -Letter 'E' -Disk (D -Ro $true) -Volume (V -L 'E') -Context $ctx -Mode 'make'
    T 'checking: a write-protected stick holding doze_sec is offered (reading back is fine); making on it is refused' ($roV.Offer -and -not $roM.Offer) (($roV.Reasons + $roM.Reasons) -join '; ')
    T 'checking: a stick with no doze_sec is not offered' (-not (Get-PickerRow -Letter 'E' -Disk (D) -Volume (V -L 'E') -Context $ctx -Mode 'verify' -HasTool $false).Offer) ''
    T 'checking: the boot disk is refused even when it holds doze_sec' (-not (Get-PickerRow -Letter 'E' -Disk (D -Boot $true) -Volume (V -L 'E') -Context $ctx -Mode 'verify' -HasTool $true).Offer) ''
    $r = Pick @($roV) 'verify' @('1', 'E')
    T 'checking: the confirmation says it only reads the drive' ($r.Letter -eq 'E' -and $r.Said -match 'only reads the drive') $r.Said

    T 'ConvertTo-Letter accepts E, E: and E:\' ((ConvertTo-Letter 'e') -eq 'E' -and (ConvertTo-Letter 'E:') -eq 'E' -and (ConvertTo-Letter 'E:\') -eq 'E') ''
    $threw = $false; try { [void](ConvertTo-Letter 'E:\stuff') } catch { $threw = $true }
    T 'ConvertTo-Letter refuses a path' $threw ''
    T 'the script refuses to vouch for a target it is running from (drive)' (Test-SelfOnTarget 'E:\doze_sec\tools' 'E:\') ''
    T 'the script refuses to vouch for a target it is running from (folder, any case)' (Test-SelfOnTarget 'd:\x\stick\doze_sec\tools' 'D:\x\stick') ''
    T 'a laptop checkout is not on the target' (-not (Test-SelfOnTarget 'C:\Users\u\src\doze_sec\tools' 'E:\')) ''
    T 'a sibling folder with a common prefix is not the target' (-not (Test-SelfOnTarget 'D:\x\stick2\tools' 'D:\x\stick')) ''

    $crlf = ConvertTo-CrLf ([Text.Encoding]::ASCII.GetBytes("a`nb`r`nc`n"))
    T 'LF becomes CRLF and an existing CRLF is left alone' ([Text.Encoding]::ASCII.GetString($crlf) -ceq "a`r`nb`r`nc`r`n") ([Text.Encoding]::ASCII.GetString($crlf))
    T 'the converter returns a byte array, not an unrolled object array' ($crlf -is [byte[]]) ($crlf.GetType().FullName)
    $u8 = ConvertTo-CrLf ([byte[]](0x41, 0xC3, 0xA9, 0x0A, 0xE2, 0x82, 0xAC, 0x0A))
    T 'UTF-8 text keeps every byte of its multi-byte characters' ((($u8 | ForEach-Object { '{0:X2}' -f $_ }) -join ' ') -eq '41 C3 A9 0D 0A E2 82 AC 0D 0A') (($u8 | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
    $hi = ConvertTo-CrLf ([byte[]](0..255))
    T 'every byte value 0-255 survives the conversion (only the LF gains a CR)' ($hi.Length -eq 257 -and $hi[10] -eq 13 -and $hi[11] -eq 10 -and $hi[256] -eq 255 -and $hi[200] -eq 199) ("len=" + $hi.Length)
    T 'an empty file stays empty' ((ConvertTo-CrLf ([byte[]]@())).Length -eq 0) ''

    $rp = [IO.FileAttributes]::Archive -bor [IO.FileAttributes]::ReparsePoint
    T 'a symbolic link is a link' (Test-IsLinkEntry $rp 'SymbolicLink') ''
    T 'a junction is a link' (Test-IsLinkEntry ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint) 'Junction') ''
    T 'a OneDrive cloud placeholder (reparse point, no link type) is NOT a link -- the owner''s checkout is under OneDrive' (-not (Test-IsLinkEntry $rp $null)) ''
    T 'a hard link is not a link to avoid (it is the file itself)' (-not (Test-IsLinkEntry ([IO.FileAttributes]::Archive) 'HardLink')) ''
    T 'a plain file is not a link' (-not (Test-IsLinkEntry ([IO.FileAttributes]::Archive) $null)) ''

    # The script must never format, partition or write boot files, and never
    # delete recursively (a recursive delete follows junctions on 5.1). Checked
    # on the AST, so the comments that explain why are not a match; the
    # self-test's own temp cleanup below is the one allowed Remove-Item.
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$tok, [ref]$err)
    $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
    $bad = @($cmds | Where-Object { $_ -match '^(Format-Volume|Clear-Disk|Initialize-Disk|New-Partition|Set-Partition|Remove-Partition|Resize-Partition|diskpart(\.exe)?|bcdboot(\.exe)?|bcdedit(\.exe)?|format(\.com)?|Set-Disk)$' })
    T 'the script calls no formatting, partitioning or boot command' ($bad.Count -eq 0) ($bad -join ', ')
    $rm = @($cmds | Where-Object { $_ -eq 'Remove-Item' }).Count
    T 'only the self-test''s own temp cleanup uses Remove-Item' ($rm -eq 1) ("Remove-Item calls: " + $rm)

    # --- copy, manifest, verify, refresh on temp trees -----------------------
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_stick_selftest_' + $PID)
    # Every link this self-test plants is removed on its own before the temp
    # tree is: a recursive delete must never meet a link it could follow.
    $links = New-Object System.Collections.Generic.List[string]
    try {
        $src = Join-Path $tmp 'src'
        New-Tree $src ($script:Required + @('tools\other.ps1', '.git\config', '.github\workflows\x.yml', 'tests\manual_ci.ps1', 'tests\detection_selftest.ps1', 'tests\cleanup_selftest.ps1', 'tests\noadmin_smoke.ps1', 'tools\make_usb_stick.ps1', 'docs\second-machine.md'))
        # Line-ending shapes a download or a checkout can hold.
        [IO.File]::WriteAllText((Join-Rel $src 'tools\crlf.ps1'), "already`r`nCRLF`r`n")
        [IO.File]::WriteAllText((Join-Rel $src 'tools\mixed.ps1'), "a`r`nb`nc`r`n")
        [IO.File]::WriteAllBytes((Join-Rel $src 'tests\utf16.txt'), [byte[]](0xFF, 0xFE, 0x61, 0x00, 0x0A, 0x00))
        [IO.File]::WriteAllBytes((Join-Rel $src 'docs\picture.png'), [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0A, 0x1A, 0x0A, 0x00))
        $store = Join-Path $tmp 'store'
        $ManifestStore = $store
        $outer = Join-Path $tmp 'stick'
        [void][IO.Directory]::CreateDirectory($outer)
        [IO.File]::WriteAllText((Join-Path $outer 'autorun.inf'), '[autorun]')   # already there when the stick is made
        $dest = Join-Path $outer $script:StickFolder
        $res = Invoke-StickCopy -Source $src -Dest $dest
        T 'the copy holds every required file' (@($script:Required | Where-Object { -not (Test-Path -LiteralPath (Join-Rel $dest $_)) }).Count -eq 0) ''
        T 'no harness file and not this script reach the stick' (@($script:ExcludeFiles | Where-Object { Test-Path -LiteralPath (Join-Rel $dest $_) }).Count -eq 0) ''
        T '.git and .github stay off the stick' (-not (Test-Path -LiteralPath (Join-Path $dest '.git')) -and -not (Test-Path -LiteralPath (Join-Path $dest '.github'))) ''
        T 'every exclusion is reported, none silently' (@($res.Excluded).Count -eq 7) ($res.Excluded -join ', ')
        $batBytes = [IO.File]::ReadAllBytes((Join-Path $dest 'doze_sec.bat'))
        T 'the LF-only bat lands with CRLF line endings' ([Text.Encoding]::ASCII.GetString($batBytes) -ceq "content of doze_sec.bat`r`nline two`r`n") ([Text.Encoding]::ASCII.GetString($batBytes))
        T 'an LF-only .ps1, .txt and .md land with CRLF, as a Windows checkout has them' (
            [IO.File]::ReadAllText((Join-Rel $dest 'tools\other.ps1')) -ceq "content of tools\other.ps1`r`nline two`r`n" -and
            [IO.File]::ReadAllText((Join-Rel $dest 'tests\benign_corpus.txt')) -ceq "content of tests\benign_corpus.txt`r`nline two`r`n" -and
            [IO.File]::ReadAllText((Join-Rel $dest 'docs\second-machine.md')) -ceq "content of docs\second-machine.md`r`nline two`r`n") ''
        T 'a file already in CRLF is copied unchanged' ([IO.File]::ReadAllText((Join-Rel $dest 'tools\crlf.ps1')) -ceq "already`r`nCRLF`r`n") ''
        T 'a file mixing CRLF and LF becomes CRLF throughout, with no doubled CR' ([IO.File]::ReadAllText((Join-Rel $dest 'tools\mixed.ps1')) -ceq "a`r`nb`r`nc`r`n") ''
        T 'a text file holding a NUL byte (UTF-16) is copied byte for byte' ((([IO.File]::ReadAllBytes((Join-Rel $dest 'tests\utf16.txt'))) -join ',') -eq '255,254,97,0,10,0') ''
        T 'a file of a non-text type is copied byte for byte' ((([IO.File]::ReadAllBytes((Join-Rel $dest 'docs\picture.png'))) -join ',') -eq '137,80,78,71,10,26,10,0') ''
        T 'every text file that gained a CR is counted, and only those' ($res.Normalized -eq 10) ("normalized=" + $res.Normalized)

        $scan0 = Get-RootScan $outer
        T 'the root scan records what was already at the stick root' ($scan0.Watch.Contains('autorun.inf')) (@($scan0.Watch.Keys) -join ', ')
        $tid = 'folder=' + $dest
        $text = New-ManifestText -Entries $res.Entries -TargetId $tid -SourcePath $src -Created '2026-10-09T12:00:00' -Root $scan0.Watch
        [void][IO.Directory]::CreateDirectory($store)
        $keep = Join-Path $store ('stick_20261009_120000_' + (Get-IdTag $tid) + '.sha256')
        [IO.File]::WriteAllText($keep, $text)
        [IO.File]::WriteAllText((Join-Path $dest $script:StickManifestName), $text)
        $m = Read-Manifest $keep
        T 'the manifest round-trips: one entry per copied file, and the root baseline' ($m.Entries.Count -eq $res.Entries.Count -and $m.Header['target'] -eq $tid -and $null -ne $m.Root -and $m.Root.ContainsKey('autorun.inf')) ("entries=" + $m.Entries.Count)
        $r = Resolve-TrustedManifest (Get-StoreManifests $store) $tid (Get-StickState $dest $outer)
        T 'the trusted manifest is found in the laptop store by target' ($r.Path -eq $keep -and $r.How -eq 'target') ($r.How + ' ' + $r.Path)
        $r = Resolve-TrustedManifest (Get-StoreManifests $store) 'volume=\\?\Volume{new-port}\' (Get-StickState $dest $outer)
        T 'a stick whose volume ID changed (another USB port) is matched by content to the manifest this laptop wrote' ($r.Path -eq $keep -and $r.How -eq 'content') ($r.How + ' ' + $r.Path)
        $r = Resolve-TrustedManifest (Get-StoreManifests $store) 'folder=elsewhere' (Get-StickState (Join-Path $tmp 'nowhere') '')
        T 'a missing copy matches no manifest by content, and every manifest is still listed with why it was not compared' ($null -eq $r.Path -and (@($r.Candidates | ForEach-Object { $_.Line }) -join ' ') -match 'not compared') ($r.How + ' ' + $r.Path)
        # Another stick made from the same checkout: the same files, a different
        # manifest (another target, another time, another root). Newer, but the
        # stick's own copy of ITS manifest decides which one it is.
        $sameNoRoot = New-ManifestText -Entries $res.Entries -TargetId 'volume=\\?\Volume{other-stick}\' -SourcePath $src -Created '2026-10-10T12:00:00' -Root ([ordered]@{})
        $newer = Join-Path $store 'stick_20261010_120000_aaaaaaaa.sha256'
        [IO.File]::WriteAllText($newer, $sameNoRoot)
        $r = Resolve-TrustedManifest (Get-StoreManifests $store) 'volume=\\?\Volume{new-port}\' (Get-StickState $dest $outer)
        T 'another stick''s manifest with the same files does not vouch for this one: the stick''s own manifest copy decides' ($r.Path -eq $keep -and $r.How -eq 'content') ($r.How + ' ' + $r.Path)
        [IO.File]::Delete($newer)
        [IO.File]::WriteAllText((Join-Path $store 'stick_20261011_000000_bbbbbbbb.sha256'), 'not a manifest')
        $all = Get-StoreManifests $store
        T 'a manifest that cannot be read is listed with its reason, not skipped in silence' (@($all | Where-Object { -not $_.Manifest -and $_.Error -match 'unreadable manifest line' }).Count -eq 1) ''
        $r = Resolve-TrustedManifest $all $tid (Get-StickState $dest $outer)
        T 'an unreadable manifest does not stop the right one being found' ($r.Path -eq $keep) $r.Path

        $c = Compare-StickTree -Root $dest -Expected $m.Entries -OuterRoot $outer -RootBaseline $m.Root
        T 'an untouched stick verifies identical, and a root file that was there when it was made is not reported' (((Get-DiffCount $c) + @($c.RootNew).Count) -eq 0) ((@($c.Changed) + @($c.Added) + @($c.Removed) + @($c.RootNew)) -join ', ')
        $c = Compare-StickTree -Root $dest -Expected $m.Entries -OuterRoot $outer -RootBaseline $null
        T 'with no root baseline the root entries are reported as not recorded, never as clean' (@($c.RootNew | Where-Object { $_ -match 'not recorded' }).Count -eq 1) ($c.RootNew -join ', ')

        $kh = Get-FileSha256 $keep
        $c = Compare-StickTree -Root $dest -Expected $m.Entries -OuterRoot $outer -RootBaseline $m.Root -ManifestHash $kh
        T 'the stick''s own copy of its manifest is compared byte for byte, and an untouched one is not a difference' ((Get-DiffCount $c) -eq 0) ((@($c.Changed) + @($c.Removed)) -join ', ')
        $smPath = Join-Path $dest $script:StickManifestName
        [IO.File]::WriteAllText($smPath, 'rewritten on a visited machine')
        $c = Compare-StickTree -Root $dest -Expected $m.Entries -ManifestHash $kh
        T 'a rewritten manifest copy on the stick is a difference' (@($c.Changed) -contains $script:StickManifestName) ($c.Changed -join ', ')
        $threw = ''; try { Remove-StickCopy -Dir $dest -Expected $m.Entries -ManifestHash $kh } catch { $threw = $_.Exception.Message }
        T 'refresh refuses a copy whose manifest copy was rewritten, and deletes nothing' ($threw -match 'changed: STICK_MANIFEST' -and (Test-Path -LiteralPath (Join-Rel $dest 'tools\exec_probe.ps1'))) $threw
        $r = Resolve-TrustedManifest (Get-StoreManifests $store) 'volume=\\?\Volume{new-port}\' (Get-StickState $dest $outer)
        T 'a copy whose manifest copy was rewritten is never matched by content' ($null -eq $r.Path) ($r.How + ' ' + $r.Path)
        [IO.File]::WriteAllText($smPath, $text)

        # A user's own results inside doze_sec: -Refresh must refuse and keep them.
        $resultsFile = Join-Rel $dest 'results\PC1\SecurityReport.txt'
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($resultsFile))
        [IO.File]::WriteAllText($resultsFile, 'the owner''s saved report')
        $threw = ''; try { Remove-StickCopy -Dir $dest -Expected $m.Entries } catch { $threw = $_.Exception.Message }
        T 'refresh refuses a copy holding files it did not write, names them, and deletes nothing' ($threw -match 'added: results' -and $threw -match 'Nothing was deleted' -and (Test-Path -LiteralPath $resultsFile) -and (Test-Path -LiteralPath (Join-Rel $dest 'tools\exec_probe.ps1'))) $threw
        [IO.Directory]::Delete((Join-Rel $dest 'results'), $true)

        # Tampering, as a visited machine would.
        [IO.File]::AppendAllText((Join-Rel $dest 'tools\exec_probe.ps1'), "`n# tampered")
        [IO.File]::WriteAllText((Join-Rel $dest 'tools\extra.ps1'), 'new')
        [IO.File]::Delete((Join-Rel $dest 'tests\benign_corpus.txt'))
        [IO.File]::WriteAllText((Join-Path $outer 'setup.exe'), 'MZ')
        [IO.File]::WriteAllText((Join-Path $outer 'autorun.inf'), '[autorun]open=setup.exe')
        [void][IO.Directory]::CreateDirectory((Join-Path $outer 'results'))
        $c = Compare-StickTree -Root $dest -Expected $m.Entries -OuterRoot $outer -RootBaseline $m.Root
        T 'a changed tool file is reported' (@($c.Changed) -contains 'tools\exec_probe.ps1') ($c.Changed -join ', ')
        T 'an added file is reported' (@($c.Added) -contains 'tools\extra.ps1') ($c.Added -join ', ')
        T 'a removed file is reported' (@($c.Removed) -contains 'tests\benign_corpus.txt') ($c.Removed -join ', ')
        T 'a NEW runnable file at the stick root is reported' (@($c.RootNew) -contains 'setup.exe') ($c.RootNew -join ', ')
        T 'a CHANGED root file is reported as changed' (@($c.RootNew) -contains 'autorun.inf (changed)') ($c.RootNew -join ', ')
        T 'other folders at the stick root are listed (results that must not travel on)' (@($c.Other) -contains 'results') ($c.Other -join ', ')
        $r = Resolve-TrustedManifest (Get-StoreManifests $store) 'volume=\\?\Volume{new-port}\' (Get-StickState $dest $outer)
        $lines = @($r.Candidates | ForEach-Object { $_.Line }) -join ' | '
        T 'a CHANGED copy whose ID changed is never matched: unverified, each laptop manifest listed with its difference count' ($null -eq $r.Path -and $lines -match ': 3 difference\(s\) from this copy' -and $lines -match 'could not be read') $lines
        $r = Resolve-TrustedManifest (Get-StoreManifests $store) $tid (Get-StickState $dest $outer)
        T 'a changed copy whose ID still matches is found by target, so the changes are reported' ($r.Path -eq $keep -and $r.How -eq 'target') ($r.How + ' ' + $r.Path)
        $threw = ''; try { Remove-StickCopy -Dir $dest -Expected $m.Entries } catch { $threw = $_.Exception.Message }
        T 'refresh refuses a tampered copy -- it is evidence -- and deletes nothing' ($threw -match 'changed: tools\\exec_probe.ps1' -and (Test-Path -LiteralPath (Join-Rel $dest 'tools\extra.ps1'))) $threw
        $threw = ''; try { Remove-StickCopy -Dir $dest -Expected $null } catch { $threw = $_.Exception.Message }
        T 'refresh with no manifest on this laptop refuses, whatever the stick''s own manifest says' ($threw -match 'no manifest') $threw

        # A link planted on the stick, inside doze_sec and in place of it.
        $slink = $false
        try { New-Item -ItemType SymbolicLink -Path (Join-Rel $dest 'tools\escape') -Target $src -EA Stop | Out-Null; $slink = $true } catch {}
        if ($slink) {
            $c2 = Compare-StickTree -Root $dest -Expected $m.Entries
            T 'a link planted inside the copy is reported and not followed' ((@($c2.Reparse) -contains 'tools\escape') -and -not @(@($c2.Added) | Where-Object { $_ -like 'tools\escape\*' }).Count) ((@($c2.Reparse) + @($c2.Added)) -join ', ')
            (Get-Item -LiteralPath (Join-Rel $dest 'tools\escape') -Force).Delete()
            $outer2 = Join-Path $tmp 'stick2'
            [void][IO.Directory]::CreateDirectory($outer2)
            $laptopDir = Join-Path $tmp 'laptop_files'
            New-Tree $laptopDir @('secret.txt')
            New-Item -ItemType SymbolicLink -Path (Join-Path $outer2 $script:StickFolder) -Target $laptopDir -EA Stop | Out-Null
            $links.Add((Join-Path $outer2 $script:StickFolder))
            $c3 = Compare-StickTree -Root (Join-Path $outer2 $script:StickFolder) -Expected $m.Entries -OuterRoot $outer2 -RootBaseline $m.Root
            T 'a link in place of doze_sec is reported, and nothing behind it is read' ($c3.RootLink -and @($c3.Added).Count -eq 0) ("rootlink=" + $c3.RootLink + " added=" + (@($c3.Added) -join ','))
            $threw = ''; try { Remove-StickCopy -Dir (Join-Path $outer2 $script:StickFolder) -Expected $m.Entries } catch { $threw = $_.Exception.Message }
            T 'refresh refuses a doze_sec that is a link, and the files behind it survive' ($threw -match 'link or junction' -and (Test-Path -LiteralPath (Join-Path $laptopDir 'secret.txt'))) $threw
            $threw = ''; try { Remove-StickCopy -Dir (Join-Path $outer2 $script:StickFolder) -Expected $null } catch { $threw = $_.Exception.Message }
            T 'a link in place of doze_sec is named as a link even when this laptop has no manifest for it' ($threw -match 'link or junction' -and $threw -notmatch 'no manifest') $threw
            $r = Resolve-TrustedManifest (Get-StoreManifests $store) 'volume=\\?\Volume{elsewhere}\' (Get-StickState (Join-Path $outer2 $script:StickFolder) $outer2)
            T 'a link in place of doze_sec is never matched by content, and the store''s manifests are still listed' ($null -eq $r.Path -and (@($r.Candidates | ForEach-Object { $_.Line }) -join ' ') -match 'not compared -- the copy is not a folder \(link\)') (@($r.Candidates | ForEach-Object { $_.Line }) -join ' | ')
        } else { Write-Output '[SKIP] links on the stick: creating a symbolic link needs rights this session lacks' }

        # A clean copy refreshes.
        $dest3 = Join-Path (Join-Path $tmp 'stick3') $script:StickFolder
        $res3 = Invoke-StickCopy -Source $src -Dest $dest3
        Remove-StickCopy -Dir $dest3 -Expected (ConvertTo-Hashtable $res3.Entries)
        T 'refresh removes a copy that is still exactly what this laptop wrote' ((Get-EntryState $dest3) -eq 'missing') ''

        # A rollback: v1 made, -Refresh to v2 (which retires v1's manifest), then
        # a visited machine puts the saved v1 copy back and the stick comes home
        # under a new ID. Nothing may vouch for v1 any more.
        $rbStore = Join-Path $tmp 'rb_store'
        [void][IO.Directory]::CreateDirectory($rbStore)
        $rbOuter = Join-Path $tmp 'rb_stick'
        $rbDest = Join-Path $rbOuter $script:StickFolder
        $rb1 = Invoke-StickCopy -Source $src -Dest $rbDest
        $rbText1 = New-ManifestText -Entries $rb1.Entries -TargetId 'volume=A' -SourcePath $src -Created '2026-10-01T10:00:00' -Root ([ordered]@{})
        $rbM1 = Join-Path $rbStore 'stick_20261001_100000_11111111.sha256'
        [IO.File]::WriteAllText($rbM1, $rbText1)
        [IO.File]::WriteAllText((Join-Path $rbDest $script:StickManifestName), $rbText1)
        $saved = Join-Path $tmp 'rb_saved_v1'
        [void][IO.Directory]::CreateDirectory($saved)
        foreach ($f in (Get-TreeEntries $rbDest -Strict).Files) { $to = Join-Rel $saved (Get-RelPath $rbDest $f.FullName); [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($to)); [IO.File]::Copy($f.FullName, $to) }
        Remove-StickCopy -Dir $rbDest -Expected (Read-Manifest $rbM1).Entries -ManifestHash (Get-FileSha256 $rbM1)
        $src2 = Join-Path $tmp 'src_v2'
        New-Tree $src2 ($script:Required + @('tools\new_in_v2.ps1'))
        $rb2 = Invoke-StickCopy -Source $src2 -Dest $rbDest
        $rbText2 = New-ManifestText -Entries $rb2.Entries -TargetId 'volume=A' -SourcePath $src2 -Created '2026-10-05T10:00:00' -Root ([ordered]@{})
        [IO.File]::WriteAllText((Join-Path $rbStore 'stick_20261005_100000_22222222.sha256'), $rbText2)
        [IO.File]::WriteAllText((Join-Path $rbDest $script:StickManifestName), $rbText2)
        $sup = Set-ManifestSuperseded $rbM1
        T 'a replaced copy''s manifest is retired, not deleted, and the store no longer lists it' ((Get-EntryState $sup) -eq 'file' -and (Get-EntryState $rbM1) -eq 'missing' -and @(Get-StoreManifests $rbStore).Count -eq 1) $sup
        foreach ($f in (Get-TreeEntries $rbDest -Strict).Files) { [IO.File]::Delete($f.FullName) }
        foreach ($f in (Get-TreeEntries $saved -Strict).Files) { $to = Join-Rel $rbDest (Get-RelPath $saved $f.FullName); [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($to)); [IO.File]::Copy($f.FullName, $to) }
        $r = Resolve-TrustedManifest (Get-StoreManifests $rbStore) 'volume=B' (Get-StickState $rbDest $rbOuter)
        T 'a rolled-back copy (the old files and the old manifest copy, put back) is never matched under a new ID' ($null -eq $r.Path) ($r.How + ' ' + $r.Path)
        $r = Resolve-TrustedManifest (Get-StoreManifests $rbStore) 'volume=A' (Get-StickState $rbDest $rbOuter)
        $c = Compare-StickState (Get-StickState $rbDest $rbOuter) $r.Manifest.Entries $r.Manifest.Root (Get-FileSha256 $r.Path)
        T 'under the old ID the newer manifest is used, so the rollback shows as differences' ($r.How -eq 'target' -and (Get-DiffCount $c) -gt 0) ('how=' + $r.How + ' diffs=' + (Get-DiffCount $c))

        $threw = ''; try { [void](Invoke-StickCopy -Source $src -Dest $dest) } catch { $threw = $_.Exception.Message }
        T 'an existing copy is never overwritten without -Refresh' ($threw -match 'already exists') $threw
        $threw = ''; try { [void](Invoke-StickCopy -Source $src -Dest (Join-Path $src 'inner')) } catch { $threw = $_.Exception.Message }
        T 'a destination inside the source tree is refused' ($threw -match 'inside the source') $threw

        $miss = Join-Path $tmp 'miss'
        New-Tree $miss @('doze_sec.bat', 'tools\x.ps1')
        $threw = ''; try { [void](Invoke-StickCopy -Source $miss -Dest (Join-Path $tmp 'miss_out')) } catch { $threw = $_.Exception.Message }
        T 'a source missing a required file is refused, naming it' ($threw -match 'missing') $threw

        $case = Join-Path $tmp 'case'
        New-Tree $case ($script:Required + @('tools\A.ps1', 'tools\a.ps1'))
        if (@(Get-ChildItem -LiteralPath (Join-Path $case 'tools') -File).Count -eq 3) {
            $threw = ''; try { [void](Invoke-StickCopy -Source $case -Dest (Join-Path $tmp 'case_out')) } catch { $threw = $_.Exception.Message }
            T 'two source files differing only in case are refused' ($threw -match 'only in case') $threw
        } else { Write-Output '[SKIP] case-only collision: this file system is case-insensitive, the collision cannot be planted here' }

        $lnk = Join-Path $tmp 'lnk'
        New-Tree $lnk $script:Required
        $planted = $false
        $outside = Join-Path $tmp 'outside_target'
        New-Tree $outside @('x.txt')
        try { New-Item -ItemType SymbolicLink -Path (Join-Path $lnk 'tools\outside') -Target $outside -EA Stop | Out-Null; $planted = $true; $links.Add((Join-Path $lnk 'tools\outside')) } catch {}
        if ($planted) {
            $threw = ''; try { [void](Invoke-StickCopy -Source $lnk -Dest (Join-Path $tmp 'lnk_out')) } catch { $threw = $_.Exception.Message }
            T 'a link inside the source is refused, never followed' ($threw -match 'link or junction') $threw
        } else { Write-Output '[SKIP] link in source: creating a symbolic link needs rights this session lacks' }

        if ($script:OnWindows -and (Test-CanHoldStreams $tmp)) {
            $ms = Join-Path $tmp 'motw'
            New-Tree $ms $script:Required
            Set-Content -LiteralPath (Join-Rel $ms 'tools\exec_probe.ps1') -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3"
            $mdest = Join-Path $tmp 'motw_out'
            $mres = Invoke-StickCopy -Source $ms -Dest $mdest
            T 'Mark of the Web on a source file is counted' ($mres.Motw -eq 1) ("motw=" + $mres.Motw)
            T 'Mark of the Web does not travel onto the copy' (@(Get-ExtraStreams (Join-Rel $mdest 'tools\exec_probe.ps1')).Count -eq 0) ''
            Set-Content -LiteralPath (Join-Rel $mdest 'tools\exec_probe.ps1') -Stream 'dz_hidden' -Value 'x'
            $mc = Compare-StickTree -Root $mdest -Expected (ConvertTo-Hashtable $mres.Entries)
            T 'an alternate data stream added on a visited machine is reported' (@(@($mc.Streams) -match 'dz_hidden').Count -eq 1) ($mc.Streams -join ', ')
        } else {
            Write-Output '[SKIP] Mark of the Web and alternate data streams: NTFS streams exist only on Windows (windows-smoke runs these cases)'
        }

        # The real repo: the stick carries what the audit needs, no harness, not this script.
        $real = Join-Path $tmp 'real'
        $rres = Invoke-StickCopy -Source $Source -Dest $real
        T 'a copy of this repo holds the audit, no harness and not this script' ((@($script:ExcludeFiles | Where-Object { Test-Path -LiteralPath (Join-Rel $real $_) }).Count -eq 0) -and (Test-Path -LiteralPath (Join-Rel $real 'tools\exec_probe.ps1'))) ''
        T 'every exclusion that applied to this repo was named' (@($rres.Excluded | Where-Object { $_ -like 'tests\*' }).Count -eq 4 -and @($rres.Excluded) -contains 'tools\make_usb_stick.ps1') ($rres.Excluded -join ', ')
    } finally {
        foreach ($l in $links) {
            try { $li = Get-Item -LiteralPath $l -Force -EA Stop; $li.Delete() } catch {}
        }
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -EA SilentlyContinue }
    }
    if ($fails -gt 0) { Write-Output "FAILED: $fails"; exit 1 }
    Write-Output '[OK] make_usb_stick self-test: only a USB stick is accepted, nothing is formatted, the harness and this script stay off, and a returned stick is checked against the laptop copy of its manifest.'
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

if (($Drive -and $ToFolder) -or ((-not $Drive) -and (-not $ToFolder) -and (-not $script:OnWindows))) {
    Write-Output 'Usage: make_usb_stick.ps1 [-Drive E:] [-Verify | -Refresh]   or   -ToFolder <dir> [-Verify | -Refresh]   or   -ListCandidates   or   -SelfTest'
    Write-Output '  With no -Drive it lists the drives, numbers the USB sticks it accepts, and asks which one.'
    exit 1
}
if (-not $Drive -and -not $ToFolder) {
    $pmode = if ($Verify) { 'verify' } elseif ($Refresh) { 'refresh' } else { 'make' }
    $rows = $null
    try { $rows = Get-LivePickerRows $pmode }
    catch {
        Write-Output ('[FAIL] Could not list the drives: ' + $_.Exception.Message)
        Write-Output '  Run PowerShell as administrator, or name the drive instead, for example: -Drive E:'
        exit 1
    }
    $picked = Invoke-StickPicker -Rows $rows -Mode $pmode -Ask { param($q) Read-Host $q } -Say { param($l) Write-Host $l }
    if (-not $picked) { exit 1 }
    $Drive = $picked + ':'
}

$outer = ''
$targetId = ''
$letter = ''
$lt = $null
if ($Drive) {
    if (-not $script:OnWindows) { Write-Output '[FAIL] -Drive needs Windows.'; exit 1 }
    try { $letter = ConvertTo-Letter $Drive } catch { Write-Output ('[FAIL] ' + $_.Exception.Message); exit 1 }
    $outer = $letter + ':\'
} else {
    $outer = [IO.Path]::GetFullPath($ToFolder)
}
if (Test-SelfOnTarget $PSScriptRoot $outer) {
    Write-Output ('[FAIL] This copy of make_usb_stick.ps1 is running from ' + $outer + ' -- the target itself.')
    Write-Output '  Run a copy kept on this laptop (your checkout, or the folder you downloaded it to). A checker that travelled on the stick can'
    Write-Output '  have been rewritten by a machine it visited, and could then report anything at all.'
    exit 1
}
if ($ToFolder -and (Get-EntryState $outer) -eq 'link') { Write-Output ('[FAIL] ' + $outer + ' is a link or junction; refused.'); exit 1 }
if ($Drive) {
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
} elseif (-not $Verify) {
    [void][IO.Directory]::CreateDirectory($outer)
}
$dest = Join-Path $outer $script:StickFolder
if (-not $targetId) { $targetId = 'folder=' + [IO.Path]::GetFullPath($dest) }
$store = Get-ManifestStore
$destState = Get-EntryState $dest
# Which laptop manifest vouches for the copy (-Verify, and -Refresh of an
# existing copy). Never the copy on the stick, and never a -Manifest file on
# the stick: the visited machine could have rewritten either.
$found = @{ Path = $null; Manifest = $null; How = ''; Candidates = @() }
$stickState = $null
if ($Verify -or ($Refresh -and $destState -ne 'missing')) {
    $stickState = Get-StickState $dest $outer
    if ($Manifest) {
        $mfull = [IO.Path]::GetFullPath($Manifest)
        if ((Test-SelfOnTarget $mfull $outer) -or (Get-EntryState $mfull) -eq 'link') {
            Write-Output ('[FAIL] -Manifest ' + $mfull + ' is on the target itself (or is a link). Pass the manifest kept on THIS laptop;')
            Write-Output '  the copy on the stick may have been rewritten by a machine it visited, along with the files.'
            exit 1
        }
        try { $found = @{ Path = $mfull; Manifest = (Read-Manifest $mfull); How = 'given'; Candidates = @() } }
        catch { Write-Output ('[FAIL] ' + $_.Exception.Message); exit 1 }
    } else {
        $found = Resolve-TrustedManifest -Manifests (Get-StoreManifests $store) -TargetId $targetId -Stick $stickState
    }
}
function Write-ContentMatchNote {
    param($R)
    if ($R.How -ne 'content') { return }
    Write-Output ('[INFO] No manifest on this laptop names this copy (' + $targetId + '), but it matches, file for file and with its own')
    Write-Output ('       copy of the manifest, the one made ' + $R.Manifest.Header['created'] + ' for ' + $R.Manifest.Header['target'] + ', so that one is used.')
    if ($Drive -and $lt -and $lt.Volume) { Write-Output '       Windows can give a stick a new volume ID when it goes into another USB port; that changes nothing on it.' }
    elseif ($Drive) { Write-Output ('       The volume behind ' + $letter + ': could not be read, so the copy was matched by its files instead.') }
    else { Write-Output '       The folder was moved or renamed since; that changes nothing in it.' }
}
function Write-Candidates {
    param($R)
    if (@($R.Candidates).Count -gt 0) {
        Write-Output ('  Manifests kept on this laptop (' + $store + '), newest first:')
        foreach ($x in $R.Candidates) { Write-Output ('    ' + $x.Path); Write-Output ('      ' + $x.Line) }
        Write-Output '  If one of them is this stick -- Windows can give a stick a new volume ID when it goes into another'
        Write-Output '  USB port -- run this again with -Manifest "<that path>" to list exactly what changed. If none of'
        Write-Output '  them is, this laptop did not make this copy: do not run it.'
    } else {
        Write-Output ('  There are no manifests in ' + $store + '. This laptop cannot vouch for this copy: do not run it.')
        Write-Output '  Make the stick again from your checkout, or pass -Manifest <file> if you kept this laptop''s manifest elsewhere.'
    }
}

if ($Verify) {
    if ($Drive -and -not $lt.Volume) {
        Write-Output ('[INFO] Could not read the volume behind ' + $letter + ': (' + $lt.Error + ').')
    }
    if ($destState -eq 'missing') { Write-Output ('[FAIL] ' + $dest + ' does not exist.'); exit 1 }
    if ($destState -eq 'unreadable') { Write-Output ('[FAIL] Windows cannot read ' + $dest + ' -- unlock the stick (BitLocker) or check it in File Explorer.'); exit 1 }
    if ($destState -in @('link', 'file')) {
        # This script only ever writes a folder there. Whatever put a link or a
        # file in its place, it was not this laptop -- with or without a manifest.
        if ($destState -eq 'link') { Write-Output ('[LINK]    ' + $dest + ' is a link or junction -- not followed, nothing behind it was read.') }
        else { Write-Output ('[CHANGED] ' + $dest + ' is a file, not the folder this script writes.') }
        Write-Output '[WARNING] The tool folder on this stick was replaced. Keep the stick exactly as it is: it is evidence. Do not open anything on it.'
        exit 1
    }
    if (-not $found.Path) {
        Write-Output ('[UNVERIFIED] No manifest on this laptop names this copy (' + $targetId + '), and it matches none of them exactly.')
        Write-Output '  The copy of the manifest ON the stick is not used: a visited machine could have rewritten it along with the files.'
        Write-Candidates $found
        exit 2
    }
    $trusted = $found.Path
    $m = $found.Manifest
    Write-ContentMatchNote $found
    $c = Compare-StickState $stickState $m.Entries $m.Root (Get-FileSha256 $trusted)
    Write-Output ('Checking ' + $dest + ' against ' + $trusted + ' (made ' + $m.Header['created'] + ', ' + $m.Entries.Count + ' files)')
    if ($c.RootLink) {
        Write-Output ('[LINK]    ' + $dest + ' is a link or junction -- not followed, nothing behind it was read.')
        Write-Output '[WARNING] The stick was changed after it left this laptop. Keep it exactly as it is: it is evidence. Do not open anything on it.'
        exit 1
    }
    if ($c.Missing) { Write-Output ('[FAIL] ' + $dest + ' does not exist.'); exit 1 }
    foreach ($x in $c.Changed) { Write-Output ('[CHANGED] ' + $x) }
    foreach ($x in $c.Added)   { Write-Output ('[ADDED]   ' + $x) }
    foreach ($x in $c.Removed) { Write-Output ('[REMOVED] ' + $x) }
    foreach ($x in $c.Streams) { Write-Output ('[STREAM]  ' + $x + '  (a hidden data stream that was not there when the stick was made)') }
    foreach ($x in $c.Reparse) { Write-Output ('[LINK]    ' + $x + '  (a link or junction -- not followed)') }
    foreach ($x in $c.RootNew) { Write-Output ('[ROOT]    ' + $outer + $x + '  (a file at the stick root that can run, point elsewhere or boot, and was not there when the stick was made -- do not open it)') }
    foreach ($x in $c.Other)   { Write-Output ('[INFO]    ' + $outer + $x + '\  is not part of the tool. If it holds reports from a PC you visited, move it to this laptop and delete it from the stick before the stick goes anywhere else -- they are that PC''s private data.') }
    $toolDiff = Get-DiffCount $c
    $rc = 0
    if ($toolDiff -eq 0) {
        Write-Output ('[OK] The tool on the stick is exactly what this laptop put there (' + $m.Entries.Count + ' files). This check is only as trustworthy as this laptop.')
    } else {
        Write-Output ('[WARNING] ' + $toolDiff + ' difference(s) in the tool. It was changed after it left this laptop.')
        Write-Output '  Do not run it again. Note which machine it visited -- a changed tool file is itself worth reporting.'
        Write-Output '  Keep this stick exactly as it is -- it is evidence -- and use a NEW stick for the next machine.'
        $rc = 1
    }
    if (@($c.RootNew).Count -gt 0) {
        Write-Output ('[WARNING] ' + @($c.RootNew).Count + ' new or changed file(s) at the stick root that can run or boot. Do not open them; keep the stick as it is.')
        $rc = 1
    }
    exit $rc
}

# --- make (and -Refresh) -------------------------------------------------------
if ($destState -ne 'missing') {
    if (-not $Refresh) {
        Write-Output ('[FAIL] ' + $dest + ' already exists. Use -Refresh to replace a copy this laptop made, or remove it yourself.')
        exit 1
    }
    $srcFull = [IO.Path]::GetFullPath($Source)
    if ((Test-SelfOnTarget $srcFull $dest) -or (Test-SelfOnTarget $dest $srcFull)) { Write-Output ('[FAIL] ' + $dest + ' overlaps the source ' + $srcFull + '; refused.'); exit 1 }
    $expected = $null
    $mhash = ''
    if ($found.Path) { $expected = $found.Manifest.Entries; $mhash = Get-FileSha256 $found.Path }
    elseif ($destState -eq 'dir' -and @($found.Candidates).Count -gt 0) {
        # The laptop holds manifests, and this copy matches none of them: it
        # changed, or it is not this laptop's. Never delete it on a guess.
        Write-Output ('[FAIL] No manifest on this laptop names this copy (' + $targetId + '), and it matches none of them exactly. Nothing was deleted.')
        Write-Candidates $found
        Write-Output '  Run -Verify first: it lists what changed.'
        exit 1
    }
    Write-ContentMatchNote $found
    try { Remove-StickCopy -Dir $dest -Expected $expected -ManifestHash $mhash; Write-Output ('[OK] Removed the earlier copy at ' + $dest + ' (it was still exactly what this laptop wrote).') }
    catch { Write-Output ('[FAIL] ' + $_.Exception.Message); exit 1 }
}
$srcBytes = [long]0
$srcRoot = [IO.Path]::GetFullPath($Source)
foreach ($f in (Get-TreeEntries $srcRoot).Files) { if (-not (Test-Excluded (Get-RelPath $srcRoot $f.FullName))) { $srcBytes += $f.Length } }
if ($Drive -and $lt.Volume -and $lt.Volume.SizeRemaining -and ([long]$lt.Volume.SizeRemaining -lt [long]($srcBytes * 1.2))) {
    Write-Output ('[FAIL] Not enough free space on ' + $outer + ' (' + [long]$lt.Volume.SizeRemaining + ' bytes free, about ' + [long]($srcBytes * 1.2) + ' needed).')
    exit 1
}
$scan = Get-RootScan $outer
if (@($scan.Boot).Count -gt 0) {
    Write-Output ('[WARNING] The stick already holds boot files (' + ($scan.Boot -join ', ') + ') -- it looks like an old install or recovery stick.')
    Write-Output '  Never leave it in a PC while that PC restarts: a bootable stick there can make a BitLocker PC ask for its'
    Write-Output '  48-digit recovery key, and without the key you cannot get to any file on it. A clean stick is better.'
}
foreach ($k in $scan.Watch.Keys) { if ($scan.Boot -notcontains $k) { Write-Output ('[INFO] Already at the stick root, recorded so -Verify can tell whether it changes: ' + $k) } }
foreach ($x in $scan.Other) { Write-Output ('[INFO] ' + $outer + $x + '\ is on the stick too. If it holds reports from a PC you visited, move it off before this stick travels -- they are that PC''s private data.') }
Write-Output ('Copying ' + $Source + ' -> ' + $dest)
try { $res = Invoke-StickCopy -Source $Source -Dest $dest }
catch { Write-Output ('[FAIL] ' + $_.Exception.Message); Write-Output ('  If ' + $dest + ' was partly written, delete it before trying again.'); exit 1 }
foreach ($x in $res.Excluded) { Write-Output ('[INFO] Left off the stick: ' + $x) }
if ($res.Normalized -gt 0) { Write-Output ('[INFO] ' + $res.Normalized + ' text file(s) had LF line endings and were written with CRLF, as a Windows checkout has them (cmd.exe needs CRLF in a batch file, findstr in the lists).') }
if ($res.Motw -gt 0) { Write-Output ('[INFO] ' + $res.Motw + ' source file(s) carried Mark of the Web (downloaded). The stick holds file contents only, so the mark did not travel. The manifest records these bytes as copied: it proves later that the stick still holds them, not where the download came from.') }
$created = Get-Date -Format 's'
$text = New-ManifestText -Entries $res.Entries -TargetId $targetId -SourcePath $srcRoot -Created $created -Root $scan.Watch
[void][IO.Directory]::CreateDirectory($store)
$keep = Join-Path $store ('stick_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + (Get-IdTag $targetId) + '.sha256')
# The laptop copy first. The stick's own copy is a convenience only: -Verify
# and -Refresh read the laptop's.
[IO.File]::WriteAllText($keep, $text)
[IO.File]::WriteAllText((Join-Path $dest $script:StickManifestName), $text)
Write-Output ('[OK] ' + $res.Entries.Count + ' files copied and read back, ' + $res.Bytes + ' bytes.')
Write-Output ('[OK] Manifest kept on this laptop: ' + $keep)
if ($Refresh -and $found.Path) {
    # The copy that manifest vouched for is gone; it must never vouch again.
    $storeFull = [IO.Path]::GetFullPath($store)
    if (Test-SelfOnTarget ([IO.Path]::GetDirectoryName($found.Path)) $storeFull) {
        $sup = Set-ManifestSuperseded $found.Path
        Write-Output ('[INFO] The manifest of the copy just replaced no longer vouches for anything (kept as ' + $sup + ').')
    } else {
        Write-Output ('[INFO] Delete ' + $found.Path + ' (the -Manifest you passed): the copy it vouched for is gone, and if a')
        Write-Output '       visited machine ever put that old copy back, that file would still call it unchanged.'
    }
}
$againTarget = '-Drive ' + $letter + ':'
if (-not $Drive) {
    $tf = $outer
    if ($tf.EndsWith('\') -or $tf.EndsWith('/')) { $tf = $tf + '.' }
    $againTarget = '-ToFolder "' + $tf + '"'
}
$again = 'powershell -NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" ' + $againTarget + ' -Verify'
if ($ManifestStore) { $again += ' -ManifestStore "' + $ManifestStore + '"' }
Write-Output ''
Write-Output 'Next:'
Write-Output '  1. Eject the stick (Safely Remove), plug it back in, and run this on THIS laptop (it works from any folder):'
Write-Output ('       ' + $again)
Write-Output '     It reads the files back from the stick, so it proves the copy landed intact. (It does not test'
Write-Output '     the stick''s real capacity: a fake-capacity stick can hold these few MB and lose what comes later.)'
Write-Output '  2. If the stick has a write-protect switch, you may turn it on now: the audit never writes into its own folder.'
Write-Output '     (You then need another stick, or the switch off, to bring the results back.)'
Write-Output ('  3. On the other machine, follow the guide ON THE STICK: ' + (Join-Rel $dest 'docs\second-machine.md'))
Write-Output '     (the drive letter may differ there). It matches this copy of the tool; an older checkout can hold an older guide.'
Write-Output ('     Bring the results back OUTSIDE the tool folder, for example ' + (Join-Path $outer 'results') + '\<PC name>\ --')
Write-Output ('     anything added inside ' + $dest + ' reads as tampering when you check the stick.')
Write-Output '     When the stick comes back, run the command in step 1 again here before you open anything on the stick.'
exit 0
