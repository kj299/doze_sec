# proc_snapshot.ps1 -- the Section 4 process snapshot, from ONE Win32_Process
# query: the `Name  PID  Path` lines every Section 4 check reads, and the
# process tree the masquerade check's parent rule reads.
#
# WHY ONE QUERY: a second enumeration minutes later is a second opinion, not
# the same snapshot (CLAUDE.md, "a tile that re-measures"): a parent could
# exit, or a PID be reused, between the two. Both outputs come from the same
# objects, so the tree and the lines always describe the same processes.
#
# STDOUT is exactly what the bats' one-liner printed before:
#   $_.Name + '  ' + $_.ProcessId + '  ' + $_.ExecutablePath
# The bat redirects it into dz_proc4.tmp, so every consumer (select_lines,
# proc_path_grade, masquerade_check) reads the same bytes as before.
#
# -TreePath writes `PID|PPID|CreatedUtcTicks|SessionId|Path|Name`, one process
# per line. CreationDate is what Microsoft documents for telling a real parent
# from a PID reused after the parent exited (Win32_Process, ParentProcessId);
# the standard-user CI job measures that a standard user reads it for every
# process. An empty field means Windows gave no value. The path is carried
# here, from the same object, so the parent rule never re-reads the dump.
# The name is last (it may hold spaces); control characters and '|' in a name
# or path become '?', so no process can split or forge a line.
#
# Read-only. Windows PowerShell 5.1 and pwsh. Pure ASCII.

[CmdletBinding()]
param(
    [string]$TreePath = '',
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'

function ConvertTo-TreeField {
    param($Value)
    return (([string]$Value) -replace '[\x00-\x1F\x7F|]', '?')
}

function Format-TreeLine {
    # Pure. One process object to `PID|PPID|CreatedUtcTicks|SessionId|Path|Name`.
    param($Process)
    $ticks = ''
    if ($null -ne $Process.CreationDate) {
        try { $ticks = [string]([datetime]$Process.CreationDate).ToUniversalTime().Ticks } catch { $ticks = '' }
    }
    $session = ''
    if ($null -ne $Process.SessionId) { $session = [string]$Process.SessionId }
    return ([string]$Process.ProcessId + '|' + [string]$Process.ParentProcessId + '|' + $ticks + '|' + $session + '|' +
            (ConvertTo-TreeField $Process.ExecutablePath) + '|' + (ConvertTo-TreeField $Process.Name))
}

function Format-DumpLine {
    # Pure. Exactly the bats' former one-liner.
    param($Process)
    return ($Process.Name + '  ' + $Process.ProcessId + '  ' + $Process.ExecutablePath)
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $d = New-Object DateTime 2026, 10, 12, 9, 30, 0
    $p = [pscustomobject]@{ Name = 'svchost.exe'; ProcessId = 1234; ParentProcessId = 700; CreationDate = $d; SessionId = 0; ExecutablePath = 'C:\Windows\System32\svchost.exe' }
    $t = Format-TreeLine $p
    T 'the tree line is PID|PPID|CreatedUtcTicks|SessionId|Path|Name' ($t -ceq ('1234|700|' + $d.ToUniversalTime().Ticks + '|0|C:\Windows\System32\svchost.exe|svchost.exe')) $t
    $q = [pscustomobject]@{ Name = 'System Idle Process'; ProcessId = 0; ParentProcessId = 0; CreationDate = $null; SessionId = $null; ExecutablePath = $null }
    $t = Format-TreeLine $q
    T 'no creation time, session or path leaves those fields empty, never a made-up value' ($t -ceq '0|0||||System Idle Process') $t
    T 'a name with spaces survives (the name is the last field)' ((Format-TreeLine $q).Split('|', 6)[5] -ceq 'System Idle Process') ''
    $e = [pscustomobject]@{ Name = ('evil' + [char]10 + '9|0|1|0||services.exe'); ProcessId = 66; ParentProcessId = 5; CreationDate = $d; SessionId = 1; ExecutablePath = ('C:\x|y' + [char]13 + '.exe') }
    $t = Format-TreeLine $e
    T 'a newline or | in a name or path cannot split or forge a tree line' (($t -split "`n").Count -eq 1 -and $t.Split('|').Count -eq 6 -and $t -match '\|C:\\x\?y\?\.exe\|evil\?9\?0\?1\?0\?\?services\.exe$') $t
    $l = Format-DumpLine $p
    T 'the stdout line is exactly the former one-liner: Name, two spaces, PID, two spaces, Path' ($l -ceq 'svchost.exe  1234  C:\Windows\System32\svchost.exe') $l
    $l = Format-DumpLine ([pscustomobject]@{ Name = 'csrss.exe'; ProcessId = 700; ParentProcessId = 600; CreationDate = $d; ExecutablePath = $null })
    T 'a process with no readable path keeps its trailing two spaces, as before' ($l -ceq 'csrss.exe  700  ') ("[" + $l + "]")
    if ($fails) { Write-Output "[FAIL] $fails proc_snapshot self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] proc_snapshot self-test: the tree line carries the creation time or an empty field, and the stdout line is the former one-liner exactly.'
    exit 0
}

$ps = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
if ($TreePath) {
    $tree = @(foreach ($p in $ps) { Format-TreeLine $p })
    try { Set-Content -LiteralPath $TreePath -Value $tree -Encoding ASCII -ErrorAction Stop } catch { }
}
foreach ($p in $ps) { Format-DumpLine $p }
