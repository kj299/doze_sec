# scheduled_tasks_full.ps1 -- Scheduled-task inventory without "Task To Run" truncation
#
# Invoked from Section 6 of doze_sec.bat and doze_sec_noAdmin.bat in three modes:
#
#   -Mode Inventory   Default. Replaces `schtasks /query /fo LIST /v` for the full
#                     inventory. Emits "Field: Value" record blocks mirroring the
#                     LIST format but pulls Execute / Arguments / WorkingDirectory
#                     from .Actions, which are not truncated. (schtasks LIST cuts
#                     "Task To Run" at ~261 chars; CSV cuts it too -- only the
#                     CIM-backed Get-ScheduledTask preserves the full string.)
#
#   -Mode Suspicious  Tasks whose Execute or Arguments contain a path under
#                     Temp / AppData / Downloads / Users\Public / ProgramData\update.
#                     Replaces the prior `schtasks /query /fo CSV /v | Format-Table`
#                     suspicious-path check which truncated user-profile paths
#                     and Format-Table column-truncated again at console width.
#
#   -Mode System      Tasks running as SYSTEM (or NT AUTHORITY\SYSTEM). Replaces
#                     the prior `schtasks /query /fo CSV /v | findstr "SYSTEM"`
#                     which truncated the action.
#
# Multi-action tasks emit Execute[N] / Arguments[N] / WorkingDirectory[N].
#
# A TASK LIST THAT WAS NOT READ IS NOT A CLEAN ONE (2026-11-21). -Mode
# Suspicious used to print "[INFO] Get-ScheduledTask unavailable" or "No
# scheduled tasks returned", write no marker, and the dashboard tile then read
# PASS. Now, in -Mode Suspicious (Get-EnumVerdict holds the rule, -SelfTest
# pins it):
#   * the query failed -> a raised gap, [WARNING] ... NOT performed;
#   * the query was REFUSED on a standard-user token -> a counted deferral
#     ([DEFERRED - ADMIN REQUIRED]); the token explains a refusal, nothing else;
#   * the query answered with no task at all -> a raised gap: Windows registers
#     dozens of its own, so an empty list is a list that was not read.
# Markers (in -MarkerDir): dz_susptask_crit.txt (the count of flagged tasks,
# as before), dz_susptask_gap.txt, dz_susptask_deferred.txt (a count).
# State file: dz_susptask_state.txt  tasks=<ok|crit|gap|deferred>,n=<count>;
# the dashboard tile states it and never re-measures. Inventory and System
# are listings and are unchanged.
#
# Usage:
#   powershell -File tools\scheduled_tasks_full.ps1 [-Mode Inventory]
#   powershell -File tools\scheduled_tasks_full.ps1 -Mode Suspicious [-MarkerDir <dir>] [-Elevated 0|1]
#   powershell -File tools\scheduled_tasks_full.ps1 -Mode System
#   powershell -File tools\scheduled_tasks_full.ps1 -SelfTest   (reads nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

param(
    [ValidateSet('Inventory','Suspicious','System')]
    [string]$Mode = 'Inventory',
    [string]$MarkerDir = $env:TEMP,
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# A refusal is the token's doing only when an exception in the chain says so:
# an access denial (.NET), or the CIM layer's own access-denied answer.
function Test-RefusedError {
    param($Exception)
    $x = $Exception
    $depth = 0
    while ($null -ne $x -and $depth -lt 8) {
        if ($x -is [System.Security.SecurityException] -or $x -is [System.UnauthorizedAccessException]) { return $true }
        if ([int]$x.HResult -eq -2147024891) { return $true }   # 0x80070005 E_ACCESSDENIED
        if ($x.GetType().FullName -eq 'Microsoft.Management.Infrastructure.CimException') {
            $nec = ''
            try { $nec = [string]$x.NativeErrorCode } catch {}
            if ($nec -eq 'AccessDenied') { return $true }
        }
        $x = $x.InnerException
        $depth++
    }
    return $false
}

function ConvertTo-OneLine {
    param([string]$Text)
    $t = ([string]$Text) -replace '[\r\n\t]+', ' '
    if ($t.Length -gt 200) { $t = $t.Substring(0, 200) + '...' }
    return $t.Trim()
}

# PURE. Whether the task list was read, and what to say when it was not.
# Returns @{ State = ok|gap|deferred; Line }.
function Get-EnumVerdict {
    param([int]$Count, [string]$ErrorText, [bool]$Refused, [bool]$IsElevated)
    $miss = 'so a task launching a binary from Temp, Downloads or Public, or an unsigned one under AppData, would go unseen (T1053.005).'
    if ($ErrorText) {
        if ($Refused -and -not $IsElevated) {
            return @{ State = 'deferred'; Line = ('[DEFERRED - ADMIN REQUIRED] Scheduled-task check: this token was refused the task list (' + (ConvertTo-OneLine $ErrorText) + ').') }
        }
        return @{ State = 'gap'; Line = ('[WARNING] Scheduled-task check NOT performed -- the task list could not be read (' + (ConvertTo-OneLine $ErrorText) + '), ' + $miss) }
    }
    if ($Count -lt 1) {
        return @{ State = 'gap'; Line = ('[WARNING] Scheduled-task check NOT performed -- the task list came back empty, and Windows registers dozens of its own tasks, ' + $miss) }
    }
    return @{ State = 'ok'; Line = '' }
}

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) { New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got) if ($Ok) { "[OK]   $Name" } else { "[FAIL] $Name -- got: $Got"; $script:fails++ } }
    $v = Get-EnumVerdict -Count 120 -ErrorText '' -Refused $false -IsElevated $true
    T 'a task list that answered is graded' ($v.State -eq 'ok' -and -not $v.Line) $v.Line
    $v = Get-EnumVerdict -Count 0 -ErrorText 'The RPC server is unavailable.' -Refused $false -IsElevated $true
    T 'a failed query is a raised gap that names the error, never an [INFO]' ($v.State -eq 'gap' -and $v.Line -match '^\[WARNING\] Scheduled-task check NOT performed -- the task list could not be read \(The RPC server is unavailable\.\)') $v.Line
    $v = Get-EnumVerdict -Count 0 -ErrorText 'Access denied' -Refused $true -IsElevated $false
    T 'a refusal on a standard-user token is a deferral, never a row' ($v.State -eq 'deferred' -and $v.Line -match '^\[DEFERRED - ADMIN REQUIRED\]') $v.Line
    $v = Get-EnumVerdict -Count 0 -ErrorText 'Access denied' -Refused $true -IsElevated $true
    T 'a refusal to an administrator is a gap: the token does not explain it' ($v.State -eq 'gap') $v.Line
    $v = Get-EnumVerdict -Count 0 -ErrorText 'The RPC server is unavailable.' -Refused $false -IsElevated $false
    T 'a failure that is not a refusal stays a gap on a standard-user token' ($v.State -eq 'gap') $v.Line
    $v = Get-EnumVerdict -Count 0 -ErrorText '' -Refused $false -IsElevated $true
    T 'an empty answer is a gap, never "[OK] No scheduled-task actions in ..."' ($v.State -eq 'gap' -and $v.Line -match 'came back empty' -and $v.Line -notmatch '\[OK\]') $v.Line
    $v = Get-EnumVerdict -Count 0 -ErrorText ("a`r`nb" + ('x' * 400)) -Refused $false -IsElevated $true
    T 'an error message is one line and capped' ($v.Line -notmatch "[`r`n]" -and $v.Line.Length -lt 420) $v.Line
    $deny = New-Object System.UnauthorizedAccessException 'x'
    T 'Test-RefusedError: an access denial, wrapped or not, is a refusal; an RPC failure and nothing are not' ((Test-RefusedError $deny) -and (Test-RefusedError (New-Object System.Management.Automation.RuntimeException 'outer', $deny)) -and -not (Test-RefusedError (New-Object System.Runtime.InteropServices.COMException 'The RPC server is unavailable.', -2147023174)) -and -not (Test-RefusedError $null)) ''
    $e5 = New-Object System.Runtime.InteropServices.COMException 'Access is denied.', -2147024891
    T 'Test-RefusedError: HRESULT 0x80070005 is a refusal' (Test-RefusedError $e5) ''
    if ($fails) { "[FAIL] scheduled_tasks_full self-test: $fails case(s) failed"; exit 1 }
    '[OK] scheduled_tasks_full self-test: a failed, refused or empty task list is a gap or a deferral, never PASS.'
    exit 0
}

if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}

$tasks = @()
$enumError = ''
$enumRefused = $false
try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) } catch {
    $enumError = [string]$_.Exception.Message
    if (-not $enumError) { $enumError = 'no message' }
    $enumRefused = Test-RefusedError $_.Exception
}

if ($Mode -ne 'Suspicious') {
    # Listings: nothing is graded from them.
    if ($enumError) { Write-Output ('[INFO] Get-ScheduledTask unavailable -- ' + (ConvertTo-OneLine $enumError)); return }
    if ($tasks.Count -eq 0) { Write-Output '[INFO] No scheduled tasks returned.'; return }
} else {
    $stateFile = Join-Path $MarkerDir 'dz_susptask_state.txt'
    foreach ($n in 'crit', 'gap', 'deferred', 'state') { Remove-Item -LiteralPath (Join-Path $MarkerDir ("dz_susptask_{0}.txt" -f $n)) -Force -EA SilentlyContinue }
    $ev = Get-EnumVerdict -Count $tasks.Count -ErrorText $enumError -Refused $enumRefused -IsElevated ($Elevated -eq 1)
    if ($ev.State -ne 'ok') {
        Write-Output $ev.Line
        if ($ev.State -eq 'deferred') { Write-Marker -Name 'susptask_deferred' -Sev '1' } else { Write-Marker -Name 'susptask_gap' -Sev 'WARNING' }
        Write-Marker -Name 'susptask_state' -Sev ('tasks=' + $ev.State + ',n=0')
        return
    }
}

function Format-TaskBlock {
    param($t, $info, $actions, $triggers)

    $taskPath = $t.TaskPath
    $taskName = $t.TaskName
    $fullName = ($taskPath.TrimEnd('\') + '\' + $taskName)

    $principal = $t.Principal
    $runAs     = if ($principal) { $principal.UserId } else { '' }
    $logonType = if ($principal) { $principal.LogonType } else { '' }
    $runLevel  = if ($principal) { $principal.RunLevel } else { '' }

    Write-Output ('HostName:                             ' + $env:COMPUTERNAME)
    Write-Output ('TaskName:                             ' + $fullName)
    Write-Output ('TaskPath:                             ' + $taskPath)
    Write-Output ('State:                                ' + $t.State)
    Write-Output ('Author:                               ' + $t.Author)
    Write-Output ('Description:                          ' + $t.Description)
    Write-Output ('Run As User:                          ' + $runAs)
    Write-Output ('Logon Type:                           ' + $logonType)
    Write-Output ('Run Level:                            ' + $runLevel)

    if ($info) {
        Write-Output ('Last Run Time:                        ' + $info.LastRunTime)
        Write-Output ('Last Result:                          ' + $info.LastTaskResult)
        Write-Output ('Next Run Time:                        ' + $info.NextRunTime)
        Write-Output ('Number Of Missed Runs:                ' + $info.NumberOfMissedRuns)
    }

    if ($actions.Count -eq 0) {
        Write-Output 'Actions:                              (none)'
    } else {
        $i = 0
        foreach ($a in $actions) {
            $i++
            $sfx = if ($actions.Count -gt 1) { "[$i]" } else { '' }
            $exec = $null; $argv = $null; $wdir = $null
            try { $exec = $a.Execute } catch {}
            try { $argv = $a.Arguments } catch {}
            try { $wdir = $a.WorkingDirectory } catch {}
            if ($null -ne $exec) { Write-Output ("Execute$sfx" + ':' + (' ' * [Math]::Max(1, 38 - ("Execute$sfx".Length))) + $exec) }
            if ($null -ne $argv -and $argv -ne '') { Write-Output ("Arguments$sfx" + ':' + (' ' * [Math]::Max(1, 38 - ("Arguments$sfx".Length))) + $argv) }
            if ($null -ne $wdir -and $wdir -ne '') { Write-Output ("WorkingDirectory$sfx" + ':' + (' ' * [Math]::Max(1, 38 - ("WorkingDirectory$sfx".Length))) + $wdir) }
        }
    }

    if ($triggers.Count -eq 0) {
        Write-Output 'Triggers:                             (none)'
    } else {
        $i = 0
        foreach ($tr in $triggers) {
            $i++
            $sfx = if ($triggers.Count -gt 1) { "[$i]" } else { '' }
            $cls = $tr.CimClass.CimClassName
            $enabled = $tr.Enabled
            $start = $tr.StartBoundary
            Write-Output ("Trigger$sfx" + ':' + (' ' * [Math]::Max(1, 38 - ("Trigger$sfx".Length))) + "$cls Enabled=$enabled Start=$start")
        }
    }
}

# Suspicious-path regex: matches Execute or Arguments under a high-risk location.
# Mirrors the original CMD-block pattern so semantics don't drift between modes.
$susPattern = '\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\|\\ProgramData\\update'

if ($Mode -eq 'Inventory') {
    foreach ($t in $tasks) {
        $info = $null
        try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch { }
        $actions = @($t.Actions)
        $triggers = @($t.Triggers)
        Format-TaskBlock $t $info $actions $triggers
        Write-Output ''
    }
    return
}

if ($Mode -eq 'Suspicious') {
    # Hard-suspicious locations: no legitimate reason for a persistent task to
    # launch a binary from here, so flag CRITICAL regardless of signature.
    $hardPattern = '\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\ProgramData\\update'
    # %AppData% (Local/Roaming) is where legitimate per-user app updaters live
    # (Brave, Chrome, Zoom, Teams). Flag CRITICAL only when the binary there is
    # NOT validly Authenticode-signed; validly-signed ones are downgraded to
    # [INFO] to avoid burying real findings under known-good updater noise.
    $appDataPattern = '\\AppData\\'

    $crit = @()   # unsigned/untrusted, or any hard-suspicious path
    $info = @()   # validly-signed binary under %AppData% (legit per-user updater)

    foreach ($t in $tasks) {
        $matchedExec = $null
        $isHard = $false
        $isAppData = $false
        foreach ($a in @($t.Actions)) {
            $exec = $null; $argv = $null
            try { $exec = $a.Execute } catch {}
            try { $argv = $a.Arguments } catch {}
            $blob = "$exec $argv"
            if ($blob -match $hardPattern) { $isHard = $true; if ($exec) { $matchedExec = $exec }; break }
            if ($blob -match $appDataPattern) { $isAppData = $true; if ($exec) { $matchedExec = $exec } }
        }
        if (-not ($isHard -or $isAppData)) { continue }
        if ($isHard) { $crit += $t; continue }

        # AppData-only match: signature-gate the executable.
        $signed = $false; $signer = ''
        if ($matchedExec) {
            $clean = [Environment]::ExpandEnvironmentVariables($matchedExec.Trim('"'))
            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $clean -ErrorAction Stop
                if ($sig.Status -eq 'Valid') {
                    $signed = $true
                    if ($sig.SignerCertificate) { $signer = ((($sig.SignerCertificate.Subject -split ',')[0]) -replace '^CN=','').Trim() }
                }
            } catch {}
        }
        if ($signed) { $info += [pscustomobject]@{ Task = $t; Signer = $signer } }
        else { $crit += $t }
    }

    $marker = Join-Path $MarkerDir 'dz_susptask_crit.txt'
    Write-Marker -Name 'susptask_state' -Sev ('tasks=' + $(if ($crit.Count -gt 0) { 'crit' } else { 'ok' }) + ',n=' + [string]$crit.Count)

    if ($crit.Count -eq 0 -and $info.Count -eq 0) {
        Write-Output ('[OK] No scheduled-task actions in Temp/AppData/Downloads/Public/ProgramData\update (' + [string]$tasks.Count + ' tasks read).')
        return
    }

    if ($crit.Count -gt 0) {
        $cnames = @($crit | ForEach-Object { $_.TaskName } | Sort-Object -Unique)
        Write-Output ('[CRITICAL] ' + $crit.Count + ' scheduled task(s) with actions in suspicious locations (unsigned, or under Temp/Downloads/Public): ' + ($cnames -join '; '))
        # Marker so the live-summary dashboard reports the SAME count/verdict
        # instead of re-deriving it with different (looser) logic.
        try { Set-Content -LiteralPath $marker -Value ([string]$crit.Count) -Encoding ASCII -ErrorAction SilentlyContinue } catch {}
        Write-Output ''
        foreach ($t in $crit) {
            $info2 = $null
            try { $info2 = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}
            Format-TaskBlock $t $info2 @($t.Actions) @($t.Triggers)
            Write-Output ''
        }
    }

    if ($info.Count -gt 0) {
        $inames = @($info | ForEach-Object { $_.Task.TaskName } | Sort-Object -Unique)
        Write-Output ('[INFO] ' + $info.Count + ' validly-signed task(s) under %AppData% (legitimate per-user updaters; not flagged): ' + ($inames -join '; '))
        foreach ($e in $info) {
            Write-Output ('        - ' + ($e.Task.TaskPath.TrimEnd('\') + '\' + $e.Task.TaskName) + '  [signer: ' + $e.Signer + ']')
        }
        Write-Output ''
    }
    return
}

if ($Mode -eq 'System') {
    $hits = @()
    foreach ($t in $tasks) {
        $uid = ''
        try { $uid = $t.Principal.UserId } catch {}
        if ($uid -match '(?i)(^|\\)SYSTEM$') { $hits += $t }
    }
    if ($hits.Count -eq 0) {
        Write-Output '[INFO] No SYSTEM-context scheduled tasks found.'
        return
    }
    Write-Output ('[INFO] ' + $hits.Count + ' scheduled task(s) running as SYSTEM:')
    Write-Output ''
    foreach ($t in $hits) {
        $info = $null
        try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}
        Format-TaskBlock $t $info @($t.Actions) @($t.Triggers)
        Write-Output ''
    }
    return
}
