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

    if ($fails) { Write-Output "[FAIL] $fails masquerade_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] masquerade_check self-test: canonical directories in any casing are clean, a system name anywhere else is a WARNING, and a name with no path is stated as unverified.'
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
