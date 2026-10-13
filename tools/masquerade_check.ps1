# masquerade_check.ps1 -- a system-process NAME running outside its canonical
# directory (T1036, masquerading). Invoked from Section 4 of doze_sec.bat /
# doze_sec_noAdmin.bat against the process snapshot Section 4 already took.
#
# WHY: naming an implant svchost.exe, lsass.exe or explorer.exe and running it
# from AppData, ProgramData, Temp or a vendor directory is the most common
# evasion on a client machine -- Task Manager shows a familiar name and most
# readers stop there. Windows itself never runs those names from anywhere but
# a fixed directory, so the path IS the verdict. The 2026-09 retrospective
# found this the one real detection gap among the manifest techniques with no
# check behind them.
#
# ONE MEASUREMENT: this reads the SAME dump Section 4 grades with
# proc_path_grade.ps1 (`Name  PID  Path`, one bulk Win32_Process query taken
# early in the run). It never enumerates processes itself, so it cannot
# disagree with the section about which processes existed.
#
# THE RULE (pure, in Get-MasqueradeVerdict, pinned by -SelfTest):
#   * a listed system-process name whose directory is not one of its canonical
#     directories is a WARNING ("investigate"), never CRITICAL: the path alone
#     says the file is not the Windows binary, not what it is. The
#     comparison is case-insensitive (the owner's machine spells it
#     C:\WINDOWS\system32\ and C:\WINDOWS\Explorer.EXE) and anchored on both
#     the directory and the file name, so System32x\ and System32\drivers\ are
#     not System32\.
#   * a listed name with NO path is UNVERIFIED, never a finding and never an
#     all-clear: protected processes, and every other user's processes on a
#     non-admin run, come back with an empty ExecutablePath.
#   * any other name is IGNORED here; proc_path_grade grades paths by
#     location and module_inspect grades what is loaded inside.
#
# MARKER: -MarkerFile is written with WARNING when any hit exists; the caller
# raises via :dz_finding. Read-only. Windows PowerShell 5.1 and pwsh.

[CmdletBinding()]
param(
    # NOT Mandatory: a mandatory parameter makes -SelfTest (and the report
    # command probe, which runs the printed Command: line without arguments)
    # sit at an interactive prompt. Validated below, where it is needed.
    [string]$Path,
    [string]$MarkerFile,
    # The process tree proc_snapshot.ps1 wrote from the SAME query as -Path,
    # and the marker the parent rule writes (its own ledger row).
    [string]$TreePath,
    [string]$ParentMarkerFile,
    [string]$SystemRoot = $env:SystemRoot,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'

function Write-MarkerFile {
    # The marker IS the route to the findings ledger: a failed write turns a
    # real finding into a CLEAN section. Create the directory rather than
    # assume it, and no -EA SilentlyContinue -- a swallowed failure here is how
    # a field test lost its finding. Local to each tool, like Write-Marker.
    param([string]$Path, [string]$Value = 'WARNING')
    if (-not $Path) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Value -Encoding ASCII
}

# Canonical directories, relative to the Windows directory unless absolute.
# 'sys32' = <root>\System32, 'wow' = <root>\SysWOW64, 'root' = <root>,
# 'wbem' = <root>\System32\wbem and <root>\SysWOW64\wbem,
# 'defender' = the Defender platform directories (versioned) and Program Files.
$script:Canonical = @{
    'lsass.exe'                 = @('sys32')
    'csrss.exe'                 = @('sys32')
    'smss.exe'                  = @('sys32')
    'wininit.exe'               = @('sys32')
    'services.exe'              = @('sys32')
    'winlogon.exe'              = @('sys32')
    'spoolsv.exe'               = @('sys32')
    'sihost.exe'                = @('sys32')
    'taskhostw.exe'             = @('sys32')
    'dwm.exe'                   = @('sys32')
    'ctfmon.exe'                = @('sys32')
    'fontdrvhost.exe'           = @('sys32')
    'lsaiso.exe'                = @('sys32')
    'logonui.exe'               = @('sys32')
    'userinit.exe'              = @('sys32')
    'searchindexer.exe'         = @('sys32')
    'securityhealthservice.exe' = @('sys32')
    'svchost.exe'               = @('sys32', 'wow')
    'dllhost.exe'               = @('sys32', 'wow')
    'conhost.exe'               = @('sys32', 'wow')
    'runtimebroker.exe'         = @('sys32', 'wow')
    'rundll32.exe'              = @('sys32', 'wow')
    'werfault.exe'              = @('sys32', 'wow')
    'explorer.exe'              = @('root', 'wow')
    'wmiprvse.exe'              = @('wbem')
    'msmpeng.exe'               = @('defender')
    'nissrv.exe'                = @('defender')
}

function Get-CanonicalDirs {
    # The directories a name may live in, as regex fragments anchored at the
    # start of the path. Built from the Windows directory of THIS machine so
    # an install on D:\ or a renamed Windows directory is graded correctly.
    param([string]$Name, [string]$Root)
    $r = [regex]::Escape($Root.TrimEnd('\'))
    $out = @()
    foreach ($k in $script:Canonical[$Name.ToLowerInvariant()]) {
        switch ($k) {
            'sys32'    { $out += ($r + '\\System32\\') }
            'wow'      { $out += ($r + '\\SysWOW64\\') }
            'root'     { $out += ($r + '\\') }
            'wbem'     { $out += ($r + '\\System32\\wbem\\'); $out += ($r + '\\SysWOW64\\wbem\\') }
            'defender' {
                $out += '[A-Za-z]:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\[^\\]+\\'
                $out += '[A-Za-z]:\\Program Files\\Windows Defender\\'
            }
        }
    }
    return $out
}

# PURE: one process, graded. Sev is OK, WARNING, UNVERIFIED or IGNORED.
function Get-MasqueradeVerdict {
    param([string]$Name, [string]$ProcPath, [string]$SystemRoot)
    $n = ([string]$Name).Trim()
    if (-not $n) { return @{ Sev = 'IGNORED'; Why = 'no name' } }
    if (-not $script:Canonical.ContainsKey($n.ToLowerInvariant())) { return @{ Sev = 'IGNORED'; Why = 'not a system-process name' } }
    $p = ([string]$ProcPath).Trim()
    if (-not $p) { return @{ Sev = 'UNVERIFIED'; Why = 'no readable path (protected process, or another user''s process on a non-admin run)' } }
    if (-not $SystemRoot) { return @{ Sev = 'UNVERIFIED'; Why = 'the Windows directory is unknown, so no canonical directory can be built' } }
    $dirs = Get-CanonicalDirs -Name $n -Root $SystemRoot
    $esc = [regex]::Escape($n)
    foreach ($d in $dirs) {
        # Anchored at both ends: the directory, then exactly the file name.
        if ($p -match ('(?i)^' + $d + $esc + '$')) { return @{ Sev = 'OK'; Why = 'canonical directory' } }
    }
    $shown = @()
    foreach ($k in $script:Canonical[$n.ToLowerInvariant()]) {
        switch ($k) {
            'sys32'    { $shown += ($SystemRoot.TrimEnd('\') + '\System32') }
            'wow'      { $shown += ($SystemRoot.TrimEnd('\') + '\SysWOW64') }
            'root'     { $shown += $SystemRoot.TrimEnd('\') }
            'wbem'     { $shown += ($SystemRoot.TrimEnd('\') + '\System32\wbem') }
            'defender' { $shown += 'the Windows Defender platform directory' }
        }
    }
    return @{ Sev = 'WARNING'; Why = ('the genuine ' + $n + ' lives only in ' + ($shown -join ' or ')) }
}

# PURE: a whole snapshot (lines of `Name  PID  Path`) to report lines + marker.
function Get-MasqueradeReport {
    param([string[]]$Lines, [string]$SystemRoot)
    $out = New-Object System.Collections.ArrayList
    $hits = 0; $ok = 0; $unverified = 0; $parsed = 0
    foreach ($ln in @($Lines)) {
        if (-not $ln) { continue }
        # Name, two spaces, PID, two spaces, Path (Path may be empty).
        $m = [regex]::Match($ln, '^(\S.*?)\s{2,}(\d+)\s{0,}(.*)$')
        if (-not $m.Success) { continue }
        $parsed++
        $name = $m.Groups[1].Value; $procId = $m.Groups[2].Value; $p = $m.Groups[3].Value.Trim()
        $v = Get-MasqueradeVerdict -Name $name -ProcPath $p -SystemRoot $SystemRoot
        switch ($v.Sev) {
            'WARNING'    {
                $hits++
                # The directory by string, not Split-Path: on the Linux lint runner
                # Split-Path rewrites backslashes, and the report must show the
                # path as Windows spells it.
                $dir = $p; $cut = $p.LastIndexOf('\'); if ($cut -gt 0) { $dir = $p.Substring(0, $cut) }
                [void]$out.Add(('[WARNING] Process ' + $name + ' (PID ' + $procId + ') runs from ' + $dir + ' -- ' + $v.Why + ' (T1036 masquerading)'))
            }
            'OK'         { $ok++ }
            'UNVERIFIED' { $unverified++ }
        }
    }
    if ($parsed -eq 0) {
        [void]$out.Add('[SKIPPED] the process snapshot held no parseable lines -- masquerading check NOT performed.')
        return @{ Lines = @($out.ToArray()); Marker = $null }
    }
    if ($unverified -gt 0) {
        [void]$out.Add(('[INFO] ' + $unverified + ' system-process name(s) had no readable path (protected, or another user''s on a non-admin run) -- not graded, not cleared.'))
    }
    if ($hits -eq 0) {
        if ($ok -gt 0) {
            [void]$out.Add(('[OK] ' + $ok + ' system-process name(s) run from their canonical directories -- no masquerading by name.'))
        } else {
            # Nothing could be graded. That is not an all-clear, and it must
            # not read like one.
            [void]$out.Add('[SKIPPED] no system-process path could be graded -- masquerading by name NOT verified.')
        }
        return @{ Lines = @($out.ToArray()); Marker = $null }
    }
    return @{ Lines = @($out.ToArray()); Marker = 'WARNING' }
}

# ---- Masquerading by PARENT ------------------------------------------------
# A copy of an implant named svchost.exe can sit in System32 and pass the
# path rule above. Windows starts each of these names from one parent, so the
# parent is the second signal. A PID is reused once its owner exits, and
# Microsoft documents how to tell (Win32_Process, ParentProcessId): the parent
# "may not refer to a running process", or may "incorrectly [refer] to a
# process that reuses a process identifier"; CreationDate shows whether the
# listed parent was created after the child. So a parent created AFTER the
# child is not the parent: the real one has exited.
#
# Whether an exited parent matters depends on the parent. System, smss.exe,
# wininit.exe and services.exe are critical processes: Windows stops with a
# bug check if one exits (Bug check 0xEF; "Critical System Services"), so a
# child of theirs whose parent is gone was not started by them. A session's
# smss.exe exits by design once it has started csrss, wininit and winlogon; a
# service host can restart; a session's winlogon ends with the session. Those
# are counted, never graded.
#
# Not in the table, on purpose: explorer.exe (userinit, winlogon, Task
# Manager and explorer itself all start it), conhost, rundll32, werfault and
# ctfmon (their parents vary by design).
#
# Out of reach: parent PID spoofing (an implant started with a forged parent
# looks like a child of services.exe; THREAT_MODEL names it as a gap).
# Process-isolated Windows containers run their own smss, csrss and services
# trees on the host.
$script:ParentRule = @{
    'smss.exe'                  = @{ Parents = @('system', 'smss.exe');       Show = 'System';                         Lifetime = $true }
    'csrss.exe'                 = @{ Parents = @('smss.exe');                 Show = 'smss.exe';                       Lifetime = $false }
    'wininit.exe'               = @{ Parents = @('smss.exe');                 Show = 'smss.exe';                       Lifetime = $false }
    'winlogon.exe'              = @{ Parents = @('smss.exe');                 Show = 'smss.exe';                       Lifetime = $false }
    'services.exe'              = @{ Parents = @('wininit.exe');              Show = 'wininit.exe';                    Lifetime = $true }
    'lsass.exe'                 = @{ Parents = @('wininit.exe');              Show = 'wininit.exe';                    Lifetime = $true }
    'lsaiso.exe'                = @{ Parents = @('wininit.exe');              Show = 'wininit.exe';                    Lifetime = $true }
    'svchost.exe'               = @{ Parents = @('services.exe');             Show = 'services.exe';                   Lifetime = $true }
    'spoolsv.exe'               = @{ Parents = @('services.exe');             Show = 'services.exe';                   Lifetime = $true }
    'searchindexer.exe'         = @{ Parents = @('services.exe');             Show = 'services.exe';                   Lifetime = $true }
    'securityhealthservice.exe' = @{ Parents = @('services.exe');             Show = 'services.exe';                   Lifetime = $true }
    'msmpeng.exe'               = @{ Parents = @('services.exe');             Show = 'services.exe';                   Lifetime = $true }
    'nissrv.exe'                = @{ Parents = @('services.exe');             Show = 'services.exe';                   Lifetime = $true }
    'dwm.exe'                   = @{ Parents = @('winlogon.exe');             Show = 'winlogon.exe';                   Lifetime = $false }
    'logonui.exe'               = @{ Parents = @('winlogon.exe');             Show = 'winlogon.exe';                   Lifetime = $false }
    'userinit.exe'              = @{ Parents = @('winlogon.exe');             Show = 'winlogon.exe';                   Lifetime = $false }
    'fontdrvhost.exe'           = @{ Parents = @('wininit.exe', 'winlogon.exe'); Show = 'wininit.exe or winlogon.exe'; Lifetime = $false }
    'sihost.exe'                = @{ Parents = @('svchost.exe');              Show = 'svchost.exe';                    Lifetime = $false }
    'taskhostw.exe'             = @{ Parents = @('svchost.exe');              Show = 'svchost.exe';                    Lifetime = $false }
    'runtimebroker.exe'         = @{ Parents = @('svchost.exe');              Show = 'svchost.exe';                    Lifetime = $false }
    'dllhost.exe'               = @{ Parents = @('svchost.exe');              Show = 'svchost.exe';                    Lifetime = $false }
    'wmiprvse.exe'              = @{ Parents = @('svchost.exe');              Show = 'svchost.exe';                    Lifetime = $false }
}

function ConvertTo-PrintableText {
    # A process name or path goes into the report as text: no control
    # characters, so nothing a process calls itself can break a line.
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

function Format-UtcTicks {
    param($Ticks)
    if ($null -eq $Ticks) { return 'at an unknown time' }
    return ([datetime]::new([long]$Ticks, [DateTimeKind]::Utc).ToString('yyyy-MM-dd HH:mm:ss') + 'Z')
}

# PURE: one process, graded by its parent. Sev is OK, WARNING, EXITED,
# UNVERIFIED or IGNORED. ChildTicks: the child's creation time (UTC ticks) or
# $null. Parent: $null when no process holds the parent PID, else
# @{ Pid; Name; Ticks }.
function Get-ParentVerdict {
    param([string]$Name, $ChildTicks, $Parent)
    $n = ([string]$Name).Trim().ToLowerInvariant()
    if (-not $script:ParentRule.ContainsKey($n)) { return @{ Sev = 'IGNORED' } }
    $rule = $script:ParentRule[$n]
    if ($null -eq $ChildTicks) { return @{ Sev = 'UNVERIFIED'; Why = 'no creation time for the process' } }
    $gone = $false; $reused = $false
    if ($null -eq $Parent) {
        $gone = $true
    } elseif ([int]$Parent.Pid -eq 4 -and [string]$Parent.Name -eq 'System') {
        # PID 4 is always System, and System has no creation time to compare.
    } elseif ($null -eq $Parent.Ticks) {
        return @{ Sev = 'UNVERIFIED'; Why = 'no creation time for the parent' }
    } elseif ([long]$Parent.Ticks -gt [long]$ChildTicks) {
        # Created after the child: a later process holds the PID, so the
        # process that started this one has exited.
        $gone = $true; $reused = $true
    }
    if ($gone) {
        if ($rule.Lifetime) {
            return @{ Sev = 'WARNING'; Kind = 'gone'; Reused = $reused; Why = ('Windows starts ' + $n + ' only from ' + $rule.Show + ', which runs until shutdown') }
        }
        return @{ Sev = 'EXITED'; Reused = $reused }
    }
    if ($rule.Parents -contains ([string]$Parent.Name).Trim().ToLowerInvariant()) { return @{ Sev = 'OK' } }
    return @{ Sev = 'WARNING'; Kind = 'wrong'; Reused = $false; Why = ('Windows starts ' + $n + ' only from ' + $rule.Show) }
}

# PURE: the tree (`PID|PPID|CreatedUtcTicks|Name`, from proc_snapshot.ps1) and
# the dump (`Name  PID  Path`, for the paths) to report lines + marker.
function Get-ParentReport {
    param([string[]]$Tree, [string[]]$Dump)
    $out = New-Object System.Collections.ArrayList
    $procs = @{}
    $order = New-Object System.Collections.ArrayList
    foreach ($ln in @($Tree)) {
        if (-not $ln) { continue }
        $m = [regex]::Match($ln, '^(\d+)\|(\d+)\|(\d*)\|(.+)$')
        if (-not $m.Success) { continue }
        $t = $null
        if ($m.Groups[3].Value) { $t = [long]$m.Groups[3].Value }
        $rec = @{ Pid = [int]$m.Groups[1].Value; PPid = [int]$m.Groups[2].Value; Ticks = $t; Name = $m.Groups[4].Value.Trim() }
        $procs[$rec.Pid] = $rec
        [void]$order.Add($rec)
    }
    if ($order.Count -eq 0) {
        [void]$out.Add('[SKIPPED] the process tree snapshot held no parseable lines -- masquerading by parent NOT verified.')
        return @{ Lines = @($out.ToArray()); Marker = $null }
    }
    $paths = @{}
    foreach ($ln in @($Dump)) {
        if (-not $ln) { continue }
        $m = [regex]::Match($ln, '^(\S.*?)\s{2,}(\d+)\s{0,}(.*)$')
        if ($m.Success) { $paths[[int]$m.Groups[2].Value] = $m.Groups[3].Value.Trim() }
    }
    function Show-Path([int]$ProcessId) {
        $p = $paths[$ProcessId]
        if ($p) { return (ConvertTo-PrintableText $p) }
        return '(path not readable)'
    }
    $hits = 0; $ok = 0; $exited = 0; $unverified = 0
    foreach ($rec in $order) {
        $parent = $null
        if ($procs.ContainsKey($rec.PPid) -and $rec.PPid -ne $rec.Pid) { $parent = $procs[$rec.PPid] }
        $v = Get-ParentVerdict -Name $rec.Name -ChildTicks $rec.Ticks -Parent $parent
        switch ($v.Sev) {
            'OK'         { $ok++ }
            'EXITED'     { $exited++ }
            'UNVERIFIED' { $unverified++ }
            'WARNING'    {
                $hits++
                $nm = ConvertTo-PrintableText $rec.Name
                if ($v.Kind -eq 'wrong') {
                    [void]$out.Add(('[WARNING] Process ' + $nm + ' (PID ' + $rec.Pid + ') has the wrong parent: ' + (ConvertTo-PrintableText $parent.Name) + ' (PID ' + $parent.Pid + ') -- ' + $v.Why + ' (T1036 masquerading by parent)'))
                } else {
                    [void]$out.Add(('[WARNING] Process ' + $nm + ' (PID ' + $rec.Pid + ') has the wrong parent: the process that started it (PID ' + $rec.PPid + ') is no longer running -- ' + $v.Why + ' (T1036 masquerading by parent)'))
                }
                [void]$out.Add(('    child:  ' + (Show-Path $rec.Pid) + ', started ' + (Format-UtcTicks $rec.Ticks)))
                if ($v.Kind -eq 'wrong') {
                    [void]$out.Add(('    parent: ' + (ConvertTo-PrintableText $parent.Name) + ' (PID ' + $parent.Pid + ') ' + (Show-Path $parent.Pid) + ', started ' + (Format-UtcTicks $parent.Ticks)))
                } elseif ($v.Reused) {
                    [void]$out.Add(('    parent: PID ' + $rec.PPid + ' now belongs to ' + (ConvertTo-PrintableText $parent.Name) + ', started ' + (Format-UtcTicks $parent.Ticks) + ', after this process -- so the process that started it is no longer running'))
                } else {
                    [void]$out.Add(('    parent: PID ' + $rec.PPid + ' is no longer running'))
                }
            }
        }
    }
    if ($exited -gt 0) {
        [void]$out.Add(('[INFO] ' + $exited + ' system-process name(s) whose parent is no longer running, as it may be by design (a session''s smss.exe exits once it has started csrss, wininit and winlogon; a service host can restart) -- not graded by parent.'))
    }
    if ($unverified -gt 0) {
        [void]$out.Add(('[INFO] ' + $unverified + ' system-process name(s) had no creation time for themselves or their parent -- not graded by parent, not cleared.'))
    }
    if ($hits -eq 0) {
        if ($ok -gt 0) {
            [void]$out.Add(('[OK] ' + $ok + ' system-process name(s) were started by the parent Windows uses -- no masquerading by parent.'))
        } else {
            [void]$out.Add('[SKIPPED] no system-process parent could be graded -- masquerading by parent NOT verified.')
        }
        return @{ Lines = @($out.ToArray()); Marker = $null }
    }
    return @{ Lines = @($out.ToArray()); Marker = 'WARNING' }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $root = 'C:\WINDOWS'
    function V { param([string]$n, [string]$p, [string]$r = $root) (Get-MasqueradeVerdict -Name $n -ProcPath $p -SystemRoot $r).Sev }

    # The owner's machine spells its paths C:\WINDOWS\system32\ and
    # C:\WINDOWS\Explorer.EXE. Case must never be the difference.
    T 'svchost.exe at C:\WINDOWS\system32\svchost.exe (the owner''s casing) is canonical' ((V 'svchost.exe' 'C:\WINDOWS\system32\svchost.exe') -eq 'OK') (V 'svchost.exe' 'C:\WINDOWS\system32\svchost.exe')
    T 'Explorer.EXE at C:\WINDOWS\Explorer.EXE (the owner''s casing) is canonical' ((V 'explorer.exe' 'C:\WINDOWS\Explorer.EXE') -eq 'OK') (V 'explorer.exe' 'C:\WINDOWS\Explorer.EXE')
    T 'lsass.exe under System32 is canonical' ((V 'lsass.exe' 'C:\Windows\System32\lsass.exe') -eq 'OK') ''
    T 'a 32-bit svchost.exe under SysWOW64 is canonical' ((V 'svchost.exe' 'C:\Windows\SysWOW64\svchost.exe') -eq 'OK') ''
    T 'a 32-bit dllhost.exe under SysWOW64 is canonical' ((V 'dllhost.exe' 'C:\Windows\SysWOW64\dllhost.exe') -eq 'OK') ''
    T 'conhost.exe under SysWOW64 is canonical' ((V 'conhost.exe' 'C:\Windows\SysWOW64\conhost.exe') -eq 'OK') ''
    T 'WmiPrvSE.exe lives under System32\wbem, not System32' ((V 'WmiPrvSE.exe' 'C:\WINDOWS\system32\wbem\WmiPrvSE.exe') -eq 'OK') ''
    T 'MsMpEng.exe under the versioned Defender platform directory is canonical' ((V 'MsMpEng.exe' 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MsMpEng.exe') -eq 'OK') ''
    T 'MsMpEng.exe under Program Files\Windows Defender is canonical too' ((V 'MsMpEng.exe' 'C:\Program Files\Windows Defender\MsMpEng.exe') -eq 'OK') ''
    T 'a Windows installed on D:\Win is graded against D:\Win, not C:\Windows' ((V 'lsass.exe' 'D:\Win\System32\lsass.exe' 'D:\Win') -eq 'OK' -and (V 'lsass.exe' 'C:\Windows\System32\lsass.exe' 'D:\Win') -eq 'WARNING') ''
    T 'a trailing backslash on the Windows directory changes nothing' ((V 'svchost.exe' 'C:\Windows\System32\svchost.exe' 'C:\Windows\') -eq 'OK') ''
    T 'a system name with NO path is UNVERIFIED, not a finding' ((V 'csrss.exe' '') -eq 'UNVERIFIED') (V 'csrss.exe' '')
    T 'a system name with an unknown Windows directory is UNVERIFIED' ((V 'csrss.exe' 'C:\Windows\System32\csrss.exe' '') -eq 'UNVERIFIED') ''
    T 'chrome.exe anywhere is not this check''s business' ((V 'chrome.exe' 'C:\Users\u\AppData\Local\Google\Chrome\Application\chrome.exe') -eq 'IGNORED') ''
    T 'an empty name is ignored' ((V '' 'C:\x.exe') -eq 'IGNORED') ''

    # Must raise.
    T 'svchost.exe from AppData\Roaming is WARNING' ((V 'svchost.exe' 'C:\Users\u\AppData\Roaming\svchost.exe') -eq 'WARNING') ''
    T 'lsass.exe from Windows\Temp is WARNING' ((V 'lsass.exe' 'C:\Windows\Temp\lsass.exe') -eq 'WARNING') ''
    T 'csrss.exe from ProgramData is WARNING' ((V 'csrss.exe' 'C:\ProgramData\csrss.exe') -eq 'WARNING') ''
    T 'svchost.exe from System32\drivers (a SUBdirectory) is WARNING' ((V 'svchost.exe' 'C:\Windows\System32\drivers\svchost.exe') -eq 'WARNING') ''
    T 'svchost.exe from System32x (a prefix trick) is WARNING' ((V 'svchost.exe' 'C:\Windows\System32x\svchost.exe') -eq 'WARNING') ''
    T 'explorer.exe from C:\Intel is WARNING' ((V 'explorer.exe' 'C:\Intel\explorer.exe') -eq 'WARNING') ''
    T 'explorer.exe from System32 is WARNING (the real one lives in the Windows root)' ((V 'explorer.exe' 'C:\Windows\System32\explorer.exe') -eq 'WARNING') ''
    T 'lsass.exe from SysWOW64 is WARNING (no 32-bit lsass exists)' ((V 'lsass.exe' 'C:\Windows\SysWOW64\lsass.exe') -eq 'WARNING') ''
    T 'WmiPrvSE.exe directly in System32 is WARNING (it lives in wbem)' ((V 'WmiPrvSE.exe' 'C:\Windows\System32\WmiPrvSE.exe') -eq 'WARNING') ''
    T 'MsMpEng.exe from Users\Public is WARNING' ((V 'MsMpEng.exe' 'C:\Users\Public\MsMpEng.exe') -eq 'WARNING') ''
    T 'a name spelled SVCHOST.EXE from Downloads is still graded (case-insensitive lookup)' ((V 'SVCHOST.EXE' 'C:\Users\u\Downloads\SVCHOST.EXE') -eq 'WARNING') ''
    $w = Get-MasqueradeVerdict -Name 'svchost.exe' -ProcPath 'C:\Users\u\AppData\Roaming\svchost.exe' -SystemRoot $root
    T 'the WARNING names where the genuine binary lives' ($w.Why -match 'lives only in C:\\WINDOWS\\System32 or C:\\WINDOWS\\SysWOW64') $w.Why

    # The snapshot as Section 4 writes it: `Name  PID  Path`, path optional.
    $dump = @(
        'svchost.exe  1234  C:\WINDOWS\system32\svchost.exe',
        'Explorer.EXE  5678  C:\WINDOWS\Explorer.EXE',
        'brave.exe  25976  C:\Users\khali\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe',
        'csrss.exe  700  ',
        'System  4  ',
        'svchost.exe  9999  C:\Users\Public\dz_selftest_masq\svchost.exe'
    )
    $r = Get-MasqueradeReport -Lines $dump -SystemRoot $root
    T 'a snapshot with one masquerading svchost.exe raises exactly one WARNING and the marker' ($r.Marker -eq 'WARNING' -and @($r.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 1) ($r.Lines -join ' | ')
    T 'the WARNING line carries the name, the PID and the directory' (($r.Lines -join "`n") -match '\[WARNING\] Process svchost\.exe \(PID 9999\) runs from C:\\Users\\Public\\dz_selftest_masq --') ($r.Lines -join ' | ')
    T 'the pathless csrss.exe is counted as not graded, and said so' (($r.Lines -join "`n") -match '\[INFO\] 1 system-process name\(s\) had no readable path') ($r.Lines -join ' | ')
    $clean = Get-MasqueradeReport -Lines ($dump | Select-Object -First 5) -SystemRoot $root
    T 'the same snapshot without the impostor is OK with no marker' ($null -eq $clean.Marker -and (($clean.Lines -join "`n") -match '\[OK\] 2 system-process name\(s\) run from their canonical directories')) ($clean.Lines -join ' | ')
    $none = Get-MasqueradeReport -Lines @('', '   ') -SystemRoot $root
    T 'an empty snapshot is SKIPPED, never OK' ($null -eq $none.Marker -and (($none.Lines -join "`n") -match '^\[SKIPPED\]')) ($none.Lines -join ' | ')
    $noroot = Get-MasqueradeReport -Lines $dump -SystemRoot ''
    T 'no Windows directory: every system name is unverified, nothing is cleared, and the block says SKIPPED' ($null -eq $noroot.Marker -and (($noroot.Lines -join "`n") -notmatch '\[OK\]') -and (($noroot.Lines -join "`n") -match '\[INFO\] 4 system-process name') -and (($noroot.Lines -join "`n") -match '\[SKIPPED\] no system-process path could be graded')) ($noroot.Lines -join ' | ')

    # ---- by parent ----
    function PV { param([string]$n, $ct, $par) Get-ParentVerdict -Name $n -ChildTicks $ct -Parent $par }
    function Par { param([int]$procId, [string]$n, $t) @{ Pid = $procId; Name = $n; Ticks = $t } }
    # Rightful parents, alive and created before the child: OK.
    T 'svchost.exe started by services.exe is OK' ((PV 'svchost.exe' 1300 (Par 900 'services.exe' 1200)).Sev -eq 'OK') ''
    T 'lsass.exe and services.exe started by wininit.exe are OK' ((PV 'lsass.exe' 1210 (Par 780 'wininit.exe' 1011)).Sev -eq 'OK' -and (PV 'services.exe' 1200 (Par 780 'wininit.exe' 1011)).Sev -eq 'OK') ''
    T 'LsaIso.exe (Credential Guard) started by wininit.exe is OK' ((PV 'LsaIso.exe' 1220 (Par 780 'wininit.exe' 1011)).Sev -eq 'OK') ''
    T 'smss.exe started by System (PID 4, no creation time) is OK' ((PV 'smss.exe' 1002 (Par 4 'System' $null)).Sev -eq 'OK') ''
    T 'csrss.exe started by a living smss.exe is OK' ((PV 'csrss.exe' 1010 (Par 612 'smss.exe' 1005)).Sev -eq 'OK') ''
    T 'dwm.exe started by winlogon.exe is OK' ((PV 'dwm.exe' 1040 (Par 860 'winlogon.exe' 1013)).Sev -eq 'OK') ''
    T 'fontdrvhost.exe started by wininit.exe or by winlogon.exe is OK' ((PV 'fontdrvhost.exe' 1031 (Par 780 'wininit.exe' 1011)).Sev -eq 'OK' -and (PV 'fontdrvhost.exe' 1032 (Par 860 'winlogon.exe' 1013)).Sev -eq 'OK') ''
    T 'RuntimeBroker.exe and WmiPrvSE.exe started by svchost.exe are OK' ((PV 'RuntimeBroker.exe' 2000 (Par 1000 'svchost.exe' 1030)).Sev -eq 'OK' -and (PV 'WmiPrvSE.exe' 2100 (Par 1000 'svchost.exe' 1030)).Sev -eq 'OK') ''
    $svc = $true
    foreach ($n in 'spoolsv.exe', 'SearchIndexer.exe', 'SecurityHealthService.exe', 'MsMpEng.exe', 'NisSrv.exe') { if ((PV $n 1300 (Par 900 'services.exe' 1200)).Sev -ne 'OK') { $svc = $false } }
    T 'every service-started name in the table is OK under services.exe' $svc ''
    T 'names compare case-insensitively (SVCHOST.EXE under Services.exe)' ((PV 'SVCHOST.EXE' 1300 (Par 900 'Services.exe' 1200)).Sev -eq 'OK') ''
    # A parent that exited by design is counted, never graded.
    T 'csrss.exe whose session smss.exe has exited is EXITED, not a finding' ((PV 'csrss.exe' 1010 $null).Sev -eq 'EXITED') ''
    T 'winlogon.exe whose parent PID now belongs to a LATER process is EXITED (PID reuse), not a finding' ((PV 'winlogon.exe' 1013 (Par 770 'chrome.exe' 5000)).Sev -eq 'EXITED') ''
    T 'RuntimeBroker.exe whose service host has exited is EXITED, not a finding' ((PV 'RuntimeBroker.exe' 2000 $null).Sev -eq 'EXITED') ''
    # Must raise.
    $w = PV 'svchost.exe' 1300 (Par 3000 'explorer.exe' 1250)
    T 'svchost.exe started by explorer.exe is WARNING, and names services.exe' ($w.Sev -eq 'WARNING' -and $w.Kind -eq 'wrong' -and $w.Why -match 'only from services\.exe') ($w.Why)
    T 'lsass.exe started by cmd.exe is WARNING' ((PV 'lsass.exe' 1300 (Par 2500 'cmd.exe' 1250)).Sev -eq 'WARNING') ''
    T 'services.exe started by explorer.exe is WARNING' ((PV 'services.exe' 1300 (Par 3000 'explorer.exe' 1250)).Sev -eq 'WARNING') ''
    T 'csrss.exe started by a living cmd.exe is WARNING (an exited smss is fine, a wrong living parent is not)' ((PV 'csrss.exe' 1300 (Par 2500 'cmd.exe' 1250)).Sev -eq 'WARNING') ''
    $g = PV 'svchost.exe' 1300 $null
    T 'svchost.exe whose parent is no longer running is WARNING: services.exe runs until shutdown' ($g.Sev -eq 'WARNING' -and $g.Kind -eq 'gone' -and $g.Why -match 'runs until shutdown') ($g.Why)
    $r2 = PV 'svchost.exe' 1300 (Par 900 'services.exe' 9000)
    T 'svchost.exe whose parent PID belongs to a process created AFTER it is WARNING (PID reuse: the real parent exited), even when the new owner is named services.exe' ($r2.Sev -eq 'WARNING' -and $r2.Kind -eq 'gone' -and $r2.Reused) ''
    T 'smss.exe started by cmd.exe, or whose parent is gone, is WARNING' ((PV 'smss.exe' 1300 (Par 2500 'cmd.exe' 1250)).Sev -eq 'WARNING' -and (PV 'smss.exe' 1300 $null).Sev -eq 'WARNING') ''
    T 'svchost.exe started by System (PID 4) is WARNING: System is not services.exe' ((PV 'svchost.exe' 1300 (Par 4 'System' $null)).Sev -eq 'WARNING') ''
    # Cannot tell.
    T 'no creation time for the child is UNVERIFIED' ((PV 'svchost.exe' $null (Par 900 'services.exe' 1200)).Sev -eq 'UNVERIFIED') ''
    T 'no creation time for a living parent is UNVERIFIED' ((PV 'svchost.exe' 1300 (Par 900 'services.exe' $null)).Sev -eq 'UNVERIFIED') ''
    $ign = $true
    foreach ($n in 'explorer.exe', 'conhost.exe', 'rundll32.exe', 'WerFault.exe', 'ctfmon.exe', 'chrome.exe') { if ((PV $n 1300 (Par 2500 'cmd.exe' 1250)).Sev -ne 'IGNORED') { $ign = $false } }
    T 'names whose parent varies by design (explorer, conhost, rundll32, werfault, ctfmon) are not graded by parent' $ign ''

    # The report, on a Windows 11-shaped tree: session smss instances gone
    # (612, 770), winlogon's parent PID reused by a later chrome.exe, and
    # explorer.exe whose userinit has exited.
    $tree = @(
        '0|0||System Idle Process', '4|0||System', '128|4|1001|Registry', '520|4|1002|smss.exe',
        '700|612|1010|csrss.exe', '780|612|1011|wininit.exe', '790|770|1012|csrss.exe', '860|770|1013|winlogon.exe',
        '900|780|1020|services.exe', '920|780|1021|lsass.exe', '930|780|1022|LsaIso.exe',
        '1000|900|1030|svchost.exe', '1010|780|1031|fontdrvhost.exe', '1020|860|1032|fontdrvhost.exe', '1100|860|1040|dwm.exe',
        '1500|900|1050|spoolsv.exe', '1600|900|1060|MsMpEng.exe', '2000|1000|1100|RuntimeBroker.exe', '2100|1000|1110|WmiPrvSE.exe',
        '2200|1000|1120|taskhostw.exe', '2300|1000|1130|sihost.exe', '3000|2900|1200|explorer.exe', '3100|3000|1300|ctfmon.exe',
        '770|3000|5000|chrome.exe'
    )
    $pdump = @('svchost.exe  1000  C:\Windows\System32\svchost.exe', 'explorer.exe  3000  C:\Windows\explorer.exe', 'csrss.exe  700  ')
    $pr = Get-ParentReport -Tree $tree -Dump $pdump
    $pt = $pr.Lines -join "`n"
    T 'a real-shaped Windows tree raises nothing and prints the OK line' ($null -eq $pr.Marker -and $pt -match '\[OK\] \d+ system-process name\(s\) were started by the parent Windows uses' -and $pt -notmatch '\[WARNING\]') $pt
    T 'the parents that exited by design (two csrss, wininit, winlogon) are counted, not graded' ($pt -match '\[INFO\] 4 system-process name\(s\) whose parent is no longer running') $pt
    $bad = $tree + @('4242|3000|6000|svchost.exe', '4243|5555|6001|svchost.exe', '4244|770|1500|svchost.exe')
    $bd = $pdump + @('svchost.exe  4242  C:\Windows\System32\svchost.exe', 'svchost.exe  4243  C:\Users\Public\x\svchost.exe')
    $pr = Get-ParentReport -Tree $bad -Dump $bd
    $pt = $pr.Lines -join "`n"
    T 'three impostors: three WARNINGs and the marker' ($pr.Marker -eq 'WARNING' -and @($pr.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 3) $pt
    T 'a canonical-path svchost.exe started by explorer.exe is named, with both processes beneath it' ($pt -match '\[WARNING\] Process svchost\.exe \(PID 4242\) has the wrong parent: explorer\.exe \(PID 3000\) -- Windows starts svchost\.exe only from services\.exe \(T1036 masquerading by parent\)' -and $pt -match '(?m)^    child:  C:\\Windows\\System32\\svchost\.exe, started ' -and $pt -match '(?m)^    parent: explorer\.exe \(PID 3000\) C:\\Windows\\explorer\.exe, started ') $pt
    T 'an svchost.exe whose parent is gone says so' ($pt -match '\[WARNING\] Process svchost\.exe \(PID 4243\) has the wrong parent: the process that started it \(PID 5555\) is no longer running -- Windows starts svchost\.exe only from services\.exe, which runs until shutdown' -and $pt -match '(?m)^    parent: PID 5555 is no longer running$') $pt
    T 'an svchost.exe whose parent PID was reused names the new owner and why it is not the parent' ($pt -match '(?m)^    parent: PID 770 now belongs to chrome\.exe, started [^,]+, after this process') $pt
    T 'the times are shown in UTC' ($pt -match 'started \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z') $pt
    $pr = Get-ParentReport -Tree @('', 'garbage') -Dump $pdump
    T 'an empty or unparseable tree is SKIPPED, never OK' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '^\[SKIPPED\] the process tree snapshot held no parseable lines') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree @('900|780||services.exe', '1000|900||svchost.exe') -Dump @()
    T 'a tree with no creation times grades nothing and says SKIPPED, never OK' ($null -eq $pr.Marker -and ($pr.Lines -join "`n") -match '\[SKIPPED\] no system-process parent could be graded' -and ($pr.Lines -join "`n") -notmatch '\[OK\]') ($pr.Lines -join ' | ')
    $pr = Get-ParentReport -Tree @('900|780|1020|services.exe', ('1000|3000|1300|svchost.exe'), ('3000|1|1250|evil' + [char]7 + 'name.exe')) -Dump @()
    T 'a control character in a parent name is not printed' ((($pr.Lines -join "`n") -notmatch [char]7) -and (($pr.Lines -join "`n") -match 'evil\?name\.exe')) ($pr.Lines -join ' | ')

    if ($fails) { Write-Output "[FAIL] $fails masquerade_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] masquerade_check self-test: canonical directories in any casing are clean, a system name anywhere else is a WARNING, and a name with no path is stated as unverified; by parent, the parent Windows uses is clean, a wrong parent or a lifetime parent that is gone is a WARNING, a reused PID is told apart by creation time, and a parent that exits by design is counted.'
    exit 0
}

'--- [T1036] System-process name masquerading (a system name running outside its directory) ---'
if (-not $Path) {
    '[SKIPPED] masquerade_check: -Path <process snapshot> required -- the audit passes the Section 4 dump; masquerading check NOT performed.'
    exit 0
}
if (-not (Test-Path -LiteralPath $Path)) {
    "[SKIPPED] masquerade_check: snapshot '$Path' not found -- masquerading check NOT performed."
    exit 0
}
$lines = @()
try { $lines = @(Get-Content -LiteralPath $Path -EA Stop) } catch {
    "[SKIPPED] masquerade_check: snapshot unreadable ($($_.Exception.Message)) -- masquerading check NOT performed."
    exit 0
}
$report = Get-MasqueradeReport -Lines $lines -SystemRoot $SystemRoot
foreach ($l in $report.Lines) { $l }
if ($report.Marker) { Write-MarkerFile -Path $MarkerFile -Value $report.Marker }

'--- [T1036] System-process name masquerading by parent (a system name started by a parent Windows never uses) ---'
if (-not $TreePath) {
    '[SKIPPED] masquerade_check: -TreePath <process tree> not given -- masquerading by parent NOT verified.'
    exit 0
}
if (-not (Test-Path -LiteralPath $TreePath)) {
    "[SKIPPED] masquerade_check: process tree '$TreePath' not found -- masquerading by parent NOT verified."
    exit 0
}
$tree = @()
try { $tree = @(Get-Content -LiteralPath $TreePath -EA Stop) } catch {
    "[SKIPPED] masquerade_check: process tree unreadable ($($_.Exception.Message)) -- masquerading by parent NOT verified."
    exit 0
}
$parentReport = Get-ParentReport -Tree $tree -Dump $lines
foreach ($l in $parentReport.Lines) { $l }
if ($parentReport.Marker) { Write-MarkerFile -Path $ParentMarkerFile -Value $parentReport.Marker }
