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
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File scheduled_tasks_full.ps1
#   pwsh -NoProfile -ExecutionPolicy Bypass -File scheduled_tasks_full.ps1 -Mode Suspicious
#   pwsh -NoProfile -ExecutionPolicy Bypass -File scheduled_tasks_full.ps1 -Mode System

param(
    [ValidateSet('Inventory','Suspicious','System')]
    [string]$Mode = 'Inventory'
)

$ErrorActionPreference = 'Continue'

$tasks = $null
try { $tasks = Get-ScheduledTask -ErrorAction Stop } catch {
    Write-Output "[INFO] Get-ScheduledTask unavailable -- $($_.Exception.Message)"
    return
}
if (-not $tasks) {
    Write-Output '[INFO] No scheduled tasks returned.'
    return
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

    $marker = Join-Path $env:TEMP 'dz_susptask_crit.txt'
    if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force -EA SilentlyContinue }

    if ($crit.Count -eq 0 -and $info.Count -eq 0) {
        Write-Output '[OK] No scheduled-task actions in Temp/AppData/Downloads/Public/ProgramData\update.'
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
