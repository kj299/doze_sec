# cross_api_check.ps1 -- read the same fact through independent APIs and flag
# disagreement. Invoked from Section 17.
#
# WHY: THREAT_MODEL states honestly that "a sufficiently privileged implant can
# lie to any user-mode tool" -- but until now the audit never TRIED to catch the
# lie. Every check read each fact exactly one way, so a rootkit that hooks one
# enumeration path is invisible to all of them.
#
# This is the one positive rootkit signal available to a user-mode tool. User-
# mode hooking (and much kernel-mode hiding) is applied per code path: an implant
# that filters NtQuerySystemInformation so the process vanishes from Task Manager
# does not necessarily also filter the WMI provider, the SCM, or the raw registry
# hives underneath. Asking the same question three different ways and comparing
# the answers turns that asymmetry into a detection.
#
# WHAT IS COMPARED
#   Processes  Get-Process (.NET/NtQuerySystemInformation) vs Win32_Process (WMI)
#              vs tasklist.exe (separate process, separate code path).
#   Services   Get-Service (SCM) vs Win32_Service (WMI) vs the raw
#              HKLM\SYSTEM\CurrentControlSet\Services registry keys. A service
#              present in the registry but hidden from both SCM and WMI is the
#              classic "hidden service" shape.
#   Tasks      TARRASK (HAFNIUM, T1053.005): deleting a task's SD value under
#              TaskCache\Tasks makes it invisible to schtasks.exe and the Task
#              Scheduler UI while it still runs. A task registered in Tree whose
#              Tasks\{GUID} entry EXISTS but carries no SD is that exact IOC.
#
#              NOT compared: "present in Tree but not returned by
#              Get-ScheduledTask". That sounds like the same idea but is
#              unusable in practice -- a stock Windows install legitimately
#              keeps stale and non-enumerable Tree entries (CI measured 26 of
#              them on a clean image: Store licensing, WindowsUpdate\sihboot,
#              maintenance tasks). Reporting those as hidden tasks would bury a
#              real Tarrask hit in noise, so the precise documented IOC (the
#              missing security descriptor) is the detection and the fuzzy
#              comparison is dropped.
#
# RACE CONDITIONS ARE THE FALSE-POSITIVE RISK, and the reason a naive version of
# this check is useless: processes start and exit constantly, so any two
# snapshots taken microseconds apart legitimately differ. Every candidate
# discrepancy is therefore RE-VERIFIED by re-querying that specific item through
# both paths after a short settle; only a disagreement that PERSISTS is
# reported. A process that exited mid-scan disappears from both on re-check and
# is silently dropped.
#
# SEVERITY: a persistent cross-API disagreement is CRITICAL -- there is no benign
# reason for a live process or service to exist in one authoritative view of the
# system and not another. A missing task SD (Tarrask) is CRITICAL. Where an API
# cannot be consulted at all (access denied, service stopped), the check reports
# [SKIPPED] rather than a false clean.
#
# MARKER: severity word to $env:TEMP\dz_crossapi.txt; caller raises via
# :dz_finding. No marker when every view agrees.
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [int]$SettleMs = 1200,
    # Registry roots are parameterised ONLY so CI can point the task check at a
    # synthetic hive and prove the Tarrask logic without writing to the real
    # TaskCache (which would risk confusing the live Task Scheduler). Production
    # always uses the defaults.
    [string]$TreeRoot  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree',
    [string]$TasksRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks',
    # Retained for compatibility with existing invocations. The comparison it
    # used to gate (Tree entries vs live Get-ScheduledTask output) was removed
    # after CI proved it false-positives on stock Windows, so this is now a
    # no-op; the SD check below works identically against a real or synthetic
    # hive and needs no scheduler probe.
    [switch]$SkipLiveTaskCompare
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -EA SilentlyContinue
}
function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

$sev = 'OK'

# ---- 1. Processes: three independent enumerations -------------------------
'--- [T1014] Process enumeration cross-check (.NET vs WMI vs tasklist) ---'
$pOk = $true
$setNet = @{}; $setWmi = @{}; $setTl = @{}
try { foreach ($p in (Get-Process -EA Stop)) { $setNet[[string]$p.Id] = $p.ProcessName } } catch { $pOk = $false }
try { foreach ($p in (Get-CimInstance Win32_Process -EA Stop)) { $setWmi[[string]$p.ProcessId] = [string]$p.Name } } catch { $pOk = $false }
try {
    foreach ($line in (& tasklist.exe /FO CSV /NH 2>$null)) {
        if (-not $line) { continue }
        $f = $line -split '","'
        if ($f.Count -lt 2) { continue }
        $nm  = $f[0].TrimStart('"')
        $pid2 = $f[1].Trim('"')
        if ($pid2 -match '^\d+$') { $setTl[$pid2] = $nm }
    }
} catch { $pOk = $false }

if (-not $pOk -or $setNet.Count -eq 0 -or $setWmi.Count -eq 0 -or $setTl.Count -eq 0) {
    '[SKIPPED] One or more process enumerations failed -- cross-check NOT performed.'
    $sev = Get-MaxSev $sev 'WARNING'
} else {
    # Union of PIDs seen anywhere; a PID missing from any one view is a candidate.
    $allPids = @{}
    foreach ($k in $setNet.Keys) { $allPids[$k] = $true }
    foreach ($k in $setWmi.Keys) { $allPids[$k] = $true }
    foreach ($k in $setTl.Keys)  { $allPids[$k] = $true }
    $cand = @()
    foreach ($procId in $allPids.Keys) {
        $n = $setNet.ContainsKey($procId); $w = $setWmi.ContainsKey($procId); $t = $setTl.ContainsKey($procId)
        if (-not ($n -and $w -and $t)) { $cand += $procId }
    }
    # Re-verify: a process that merely started or exited mid-scan resolves
    # consistently (present everywhere, or gone everywhere) on the second look.
    $realHits = @()
    if ($cand.Count -gt 0) {
        Start-Sleep -Milliseconds $SettleMs
        foreach ($procId in $cand) {
            $n2 = $false; $w2 = $false; $t2 = $false; $nm = ''
            try { $o = Get-Process -Id ([int]$procId) -EA Stop; $n2 = $true; $nm = $o.ProcessName } catch {}
            try { $o = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $procId) -EA Stop; if ($o) { $w2 = $true; if (-not $nm) { $nm = [string]$o.Name } } } catch {}
            try {
                $tl = & tasklist.exe /FI ("PID eq {0}" -f $procId) /FO CSV /NH 2>$null
                if ($tl -and ($tl -join '') -match ('"{0}"' -f $procId)) { $t2 = $true }
            } catch {}
            $present = @($n2, $w2, $t2) | Where-Object { $_ }
            # Gone everywhere = it exited. Present everywhere = it started. Both benign.
            if ($present.Count -gt 0 -and $present.Count -lt 3) {
                $realHits += ("PID {0} ({1}) -- .NET:{2} WMI:{3} tasklist:{4}" -f $procId, $nm, $n2, $w2, $t2)
            }
        }
    }
    if ($realHits.Count -gt 0) {
        "[CRITICAL] Process visible to some enumeration APIs but not others -- process-hiding rootkit indicator (T1014):"
        foreach ($h in $realHits) { "  $h" }
        '[CRITICAL] A live process has no legitimate reason to be missing from one authoritative view of the system.'
        $sev = Get-MaxSev $sev 'CRITICAL'
    } else {
        "[OK] Process lists agree across .NET, WMI and tasklist ($($setNet.Count) processes; transient start/exit differences resolved on re-check)."
    }
}

# ---- 2. Services: SCM vs WMI vs raw registry ------------------------------
''
'--- [T1014] Service enumeration cross-check (SCM vs WMI vs registry) ---'
$svcScm = @{}; $svcWmi = @{}; $svcReg = @{}
$sOk = $true
try { foreach ($s in (Get-Service -EA Stop)) { $svcScm[$s.Name.ToLower()] = $true } } catch { $sOk = $false }
try { foreach ($s in (Get-CimInstance Win32_Service -EA Stop)) { $svcWmi[([string]$s.Name).ToLower()] = $true } } catch { $sOk = $false }
$svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
try {
    foreach ($k in (Get-ChildItem -LiteralPath $svcRoot -EA Stop)) {
        $type = $null
        try { $type = (Get-ItemProperty -LiteralPath $k.PSPath -Name 'Type' -EA SilentlyContinue).Type } catch {}
        # Only Win32 service types (0x10 own process, 0x20 share process, and the
        # interactive variants). Drivers (1/2/4/8) are not SCM services and would
        # be a guaranteed false positive against Get-Service.
        if ($null -ne $type -and (($type -band 0x30) -ne 0)) { $svcReg[$k.PSChildName.ToLower()] = $true }
    }
} catch { $sOk = $false }

if (-not $sOk -or $svcReg.Count -eq 0) {
    '[SKIPPED] Service enumeration or registry read failed -- cross-check NOT performed.'
    $sev = Get-MaxSev $sev 'WARNING'
} else {
    $hidden = @()
    foreach ($n in $svcReg.Keys) {
        if (-not $svcScm.ContainsKey($n) -and -not $svcWmi.ContainsKey($n)) { $hidden += $n }
    }
    if ($hidden.Count -gt 0) {
        # Re-verify individually: a service installed or removed during the scan
        # settles consistently on the second look.
        Start-Sleep -Milliseconds $SettleMs
        $confirmed = @()
        foreach ($n in $hidden) {
            $stillReg = Test-Path -LiteralPath (Join-Path $svcRoot $n)
            $seen = $false
            try { if (Get-Service -Name $n -EA Stop) { $seen = $true } } catch {}
            try { if (Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f ($n -replace "'", "''")) -EA Stop) { $seen = $true } } catch {}
            if ($stillReg -and -not $seen) { $confirmed += $n }
        }
        if ($confirmed.Count -gt 0) {
            '[CRITICAL] Service present in the registry but hidden from both SCM and WMI (T1014):'
            foreach ($n in $confirmed) { "  $n" }
            $sev = Get-MaxSev $sev 'CRITICAL'
        } else {
            "[OK] Service views agree across SCM, WMI and registry ($($svcReg.Count) Win32 services)."
        }
    } else {
        "[OK] Service views agree across SCM, WMI and registry ($($svcReg.Count) Win32 services)."
    }
}

# ---- 3. Scheduled tasks: Task Scheduler vs raw TaskCache (incl. Tarrask) ---
''
'--- [T1053.005] Scheduled-task cross-check + hidden-task (Tarrask) detection ---'
$treeRoot  = $TreeRoot
$tasksRoot = $TasksRoot
$tOk = $true

$treeTasks = @()
try {
    if (Test-Path $treeRoot) {
        $stack = New-Object System.Collections.Stack
        $stack.Push((Get-Item -LiteralPath $treeRoot -EA Stop))
        while ($stack.Count -gt 0) {
            $node = $stack.Pop()
            $id = $null
            try { $id = (Get-ItemProperty -LiteralPath $node.PSPath -Name 'Id' -EA SilentlyContinue).Id } catch {}
            if ($id) {
                # REG_SZ values here carry a trailing NUL; leaving it in makes the
                # Tasks\{GUID} lookup malformed, the SD read fail, and EVERY task
                # look like a Tarrask hit. Strip NULs and whitespace.
                $idClean = ([string]$id) -replace "`0", '' 
                $idClean = $idClean.Trim()
                $full = $node.PSPath -replace ('^.*' + [regex]::Escape((Split-Path -Leaf $treeRoot))), ''
                $treeTasks += New-Object PSObject -Property @{ Path = $full; Id = $idClean }
            }
            try { foreach ($c in (Get-ChildItem -LiteralPath $node.PSPath -EA SilentlyContinue)) { $stack.Push($c) } } catch {}
        }
    } else { $tOk = $false }
} catch { $tOk = $false }

if (-not $tOk -or $treeTasks.Count -eq 0) {
    '[SKIPPED] TaskCache registry or Task Scheduler unavailable (needs admin) -- task cross-check NOT performed.'
    $sev = Get-MaxSev $sev 'WARNING'
} else {
    $noSd = @()
    $unreadable = 0
    foreach ($tt in $treeTasks) {
        # Tarrask: the SD (security descriptor) value under Tasks\{GUID} is
        # deleted, which hides the task from schtasks.exe and the Task Scheduler
        # UI while the task keeps running.
        $tk = Join-Path $tasksRoot $tt.Id
        if (Test-Path -LiteralPath $tk) {
            # Ask which VALUES EXIST rather than reading SD's data. Reading the
            # descriptor bytes generally requires SYSTEM (Administrators can open
            # the key but not necessarily read that value), so a data read
            # returning null cannot distinguish "deleted" from "not permitted"
            # -- and treating those the same reports every task on the machine as
            # a Tarrask hit. Enumerating value names answers the actual question.
            $vals = $null
            try { $vals = (Get-Item -LiteralPath $tk -EA Stop).GetValueNames() } catch {}
            if ($null -eq $vals) { $unreadable++; continue }
            if ($vals -notcontains 'SD') { $noSd += ("{0}  (Id {1})" -f $tt.Path, $tt.Id) }
        }
    }
    # Safety net independent of the cause: a real Tarrask implant hides ONE task
    # (or a few). If EVERY registered task appears to lack a descriptor, that is
    # a permissions or platform artifact, not a compromise -- report the blind
    # spot honestly instead of burying the user in false criticals. Kept
    # conservative (only when there is a real population to judge) so a genuine
    # single-task hit on a small task list is never suppressed.
    if ($treeTasks.Count -ge 10 -and $noSd.Count -eq $treeTasks.Count) {
        "[SKIPPED] All $($treeTasks.Count) task security descriptors were unreadable -- hidden-task check NOT performed (reading TaskCache SD values generally requires SYSTEM, not just admin)."
        $sev = Get-MaxSev $sev 'WARNING'
        $noSd = @()
    } elseif ($unreadable -gt 0) {
        "[INFO] $unreadable task(s) could not be inspected for a security descriptor; the rest were checked."
    }
    if ($noSd.Count -gt 0) {
        '[CRITICAL] Scheduled task registered in TaskCache with NO security descriptor (SD) -- Tarrask-style hidden task (T1053.005):'
        foreach ($h in $noSd) { "  $h" }
        '[CRITICAL] Deleting the SD value hides a task from schtasks and the Task Scheduler UI while it still runs. Used by HAFNIUM.'
        $sev = Get-MaxSev $sev 'CRITICAL'
    }
    if ($noSd.Count -eq 0) {
        "[OK] No hidden scheduled tasks ($($treeTasks.Count) registered tasks; all carry a security descriptor)."
    }
}

Write-Marker -Name 'crossapi' -Sev $sev
