# ioc_proc_snapshot.ps1 -- the running-process snapshot Sections 18a and 18g match
# their IOC lists against, and a statement of what it could not see.
#
# It was an inline one-liner,
#   Get-CimInstance Win32_Process -EA SilentlyContinue | ForEach-Object { ... }
# and the sections then printed "[OK] No process IOC matches." or "[OK] No
# LOLBin abuse patterns in running processes." over every process. But a
# standard-user token is not shown the ExecutablePath or CommandLine of any
# process another account or an elevated token runs -- on a typical PC that is
# most of them, and every one an attacker running as SYSTEM would own -- and
# even an administrator is not shown them for protected processes. The line
# was matched on the process name alone and nothing said so.
#
# THE RULE (pure, in Get-ProcScope, pinned by -SelfTest):
#   * every process is still written, as before: "Name  PID  <field>";
#   * the scope line says how many processes exposed no <field>:
#       - none: "[INFO] All N process(es) were matched by name and <field>.";
#       - elevated: an [INFO] count -- the token does not explain it, Windows
#         shows no administrator those (protected and system processes);
#       - standard user: [DEFERRED - ADMIN REQUIRED], counted through
#         -DeferredFile: the token is the whole explanation;
#   * the query FAILED -> nothing is written and the exit code is 2, so the
#     bat's existing "could not be listed" gap is raised. It is asked with
#     -ErrorAction Stop; a silenced failure used to read as an empty list.
#
# Usage:
#   powershell -File tools\ioc_proc_snapshot.ps1 -Field <ExecutablePath|CommandLine> -OutFile <f> -ScopeFile <f> [-DeferredFile <f>] [-Elevated 0|1]
#   powershell -File tools\ioc_proc_snapshot.ps1 -SelfTest   (lists no process)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only, except the files
# it is told to write.

[CmdletBinding()]
param(
    [ValidateSet('ExecutablePath', 'CommandLine')]
    [string]$Field,
    [string]$OutFile,
    [string]$ScopeFile,
    [string]$DeferredFile,
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# PURE. Returns @{ Line; Deferred }.
function Get-ProcScope {
    param([int]$Total, [int]$Blank, [bool]$IsElevated, [string]$Field)
    $what = if ($Field -eq 'CommandLine') { 'command line' } else { 'executable path' }
    if ($Blank -le 0) {
        return @{ Line = ('[INFO] All ' + $Total + ' process(es) were matched by name and ' + $what + '.'); Deferred = 0 }
    }
    if ($IsElevated) {
        return @{ Line = ('[INFO] ' + $Blank + ' of ' + $Total + ' process(es) expose no ' + $what + ' even to an administrator (protected and system processes such as System, Registry and csrss); they were matched by name only.'); Deferred = 0 }
    }
    return @{ Line = ('[DEFERRED - ADMIN REQUIRED] ' + $Blank + ' of ' + $Total + ' process(es) run under another account or elevated, so this token cannot read their ' + $what + '; they were matched by name only -- re-run as administrator to match those another account runs.'); Deferred = 1 }
}

# PURE. One snapshot line, as the bats always wrote it. A newline in a field
# cannot forge a second line.
function Format-ProcLine {
    param([string]$Name, $ProcessId, [string]$Value)
    return (([string]$Name + '  ' + [string]$ProcessId + '  ' + [string]$Value) -replace '[\r\n]+', ' ')
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $v = Get-ProcScope -Total 120 -Blank 0 -IsElevated $true -Field 'CommandLine'
    T 'every process exposed its command line: an [INFO] count, no deferral' ($v.Deferred -eq 0 -and $v.Line -eq '[INFO] All 120 process(es) were matched by name and command line.') $v.Line
    $v = Get-ProcScope -Total 120 -Blank 6 -IsElevated $true -Field 'CommandLine'
    T 'an administrator shown no command line for protected processes: an [INFO] count, never a deferral' ($v.Deferred -eq 0 -and $v.Line -match '^\[INFO\] 6 of 120 process\(es\) expose no command line even to an administrator') $v.Line
    $v = Get-ProcScope -Total 120 -Blank 80 -IsElevated $false -Field 'CommandLine'
    T 'a standard-user token shown no command line for 80 processes: a counted deferral that says how many' ($v.Deferred -eq 1 -and $v.Line -match '^\[DEFERRED - ADMIN REQUIRED\] 80 of 120 process\(es\) run under another account or elevated, so this token cannot read their command line;') $v.Line
    $v = Get-ProcScope -Total 120 -Blank 80 -IsElevated $false -Field 'ExecutablePath'
    T 'the 18a wording names the executable path' ($v.Line -match 'cannot read their executable path;') $v.Line
    $v = Get-ProcScope -Total 120 -Blank 80 -IsElevated $false -Field 'CommandLine'
    T 'no scope line ever says [OK]: what was not seen is never an all-clear' ($v.Line -notmatch '\[OK\]') $v.Line
    $l = Format-ProcLine 'svchost.exe' 1234 ('C:\x.exe' + [char]13 + [char]10 + '[OK] fine')
    T 'a field cannot forge a second snapshot line' ($l -notmatch "[`r`n]" -and $l -like 'svchost.exe  1234  C:\x.exe *') $l
    T 'the snapshot line keeps the shape the bats matched against' ((Format-ProcLine 'a.exe' 7 'C:\a.exe') -eq 'a.exe  7  C:\a.exe') ''
    if ($fails) { Write-Output "[FAIL] $fails ioc_proc_snapshot self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] ioc_proc_snapshot self-test: every process is written as before, and what this token could not see is counted -- an [INFO] for an administrator, a counted deferral for a standard user, never an all-clear.'
    exit 0
}

if (-not $Field -or -not $OutFile -or -not $ScopeFile) { 'ioc_proc_snapshot: -Field, -OutFile and -ScopeFile are required.'; exit 2 }
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
foreach ($f in @($OutFile, $ScopeFile, $DeferredFile)) { if ($f) { Remove-Item -LiteralPath $f -Force -EA SilentlyContinue } }
$procs = $null
try { $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop) }
catch { exit 2 }
if ($procs.Count -eq 0) { exit 2 }
$lines = New-Object System.Collections.ArrayList
$blank = 0
foreach ($p in $procs) {
    $val = [string]$p.$Field
    if (-not $val.Trim()) { $blank++ }
    [void]$lines.Add((Format-ProcLine $p.Name $p.ProcessId $val))
}
try {
    [IO.File]::WriteAllLines($OutFile, [string[]]$lines.ToArray(), (New-Object Text.UTF8Encoding($false)))
    $s = Get-ProcScope -Total $procs.Count -Blank $blank -IsElevated ($Elevated -eq 1) -Field $Field
    Set-Content -LiteralPath $ScopeFile -Value $s.Line -Encoding ASCII
    if ($s.Deferred -gt 0 -and $DeferredFile) { Set-Content -LiteralPath $DeferredFile -Value ([string]$s.Deferred) -Encoding ASCII }
} catch { exit 2 }
exit 0
