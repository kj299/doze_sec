# scheduled_tasks_full.ps1 -- Full scheduled-task inventory without "Task To Run" truncation
#
# Replaces `schtasks /query /fo LIST /v` for the Section 6 "Full Task Listing"
# block. The LIST format truncates the "Task To Run" field at ~261 characters,
# which silently cuts off PowerShell -EncodedCommand actions, multi-arg installer
# wrappers, and other long command lines that an inventory must capture in full.
#
# Get-ScheduledTask returns CIM objects whose .Actions[].Execute / .Arguments /
# .WorkingDirectory fields are not truncated. We emit one "Field: Value" record
# block per task, mirroring the LIST format so the report layout is unchanged.
#
# If a task has multiple Actions (multi-step task), each action is printed as
# Execute[N] / Arguments[N] / WorkingDirectory[N].
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File scheduled_tasks_full.ps1

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

foreach ($t in $tasks) {
    $info = $null
    try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch { }

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

    $actions = @($t.Actions)
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

    $triggers = @($t.Triggers)
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

    Write-Output ''
}
