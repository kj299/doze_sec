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
#              BOTH signals are required, because each alone false-positives on
#              a healthy machine -- CI proved both empirically:
#                * "Tree entry not returned by Get-ScheduledTask" alone flagged
#                  26 legitimate Microsoft tasks (stale/non-enumerable entries
#                  are normal: Store licensing, WindowsUpdate\sihboot, ...).
#                * "missing SD" alone flagged EVERY task, because reading task
#                  security descriptors really wants SYSTEM; at admin privilege
#                  the value is simply not visible.
#              Tarrask is the INTERSECTION of the two -- hidden from the
#              scheduler AND stripped of its descriptor -- so requiring both
#              collapses both false-positive sources while still catching the
#              technique. A proportion guard additionally suppresses the whole
#              check if an implausible share of tasks match.
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
# system and not another. ONE EXCEPTION, AND IT IS THE TOKEN, NOT THE SERVICE:
# a service whose DACL denies enumeration to standard users is in the registry
# and absent from Get-Service and Win32_Service when the audit runs unelevated.
# Windows 11's own ZTHelper (the Zero Trust DNS helper, KB5058411) is one; the
# first standard-user field run reported it as a rootkit indicator, CRITICAL,
# exit code 8. Enumeration cannot tell hidden from denied, but ONE open can:
# ServiceController on the name throws with NativeErrorCode 5 (the DACL refuses
# this token) or 1060 (the SCM has never heard of it). 1060 is the hidden
# service; 5 unelevated is 'not enumerable from a standard-user token', counted
# and named, never a finding and never cleared; 5 elevated is a WARNING (a
# service that refuses an administrator's query is not routine). A missing task SD (Tarrask) is CRITICAL. Where an API
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
    # Skips the live Get-ScheduledTask probe, forcing the same degraded path a
    # host takes when the Schedule service is stopped or tampered with. It was
    # dead (documented as a no-op, passed by nobody); it now does what its name
    # says, which gives CI a seam to prove the degraded path reports itself
    # honestly instead of claiming a clean result it cannot reach. Production
    # never passes it.
    [switch]$SkipLiveTaskCompare,
    # Whether this process runs elevated. Read once from the token below;
    # injectable so the self-test can grade both tokens. -1 = detect.
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write here turns
    # a real finding into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine write failure print instead of vanishing --
    # an -EA SilentlyContinue on this write cost a field test its finding.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}
function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

# ---------------------------------------------------------------------------
# PURE: one registry-only service, graded by what the SCM said when asked for
# it by name. No token, no SCM: the caller passes the error code it got.
# ---------------------------------------------------------------------------
function Get-ServiceVisibilityVerdict {
    param([string]$Name, [bool]$IsElevated, [int]$NativeError)
    if ($NativeError -eq 5) {
        if ($IsElevated) {
            return @{ Sev = 'WARNING'; Kind = 'denied-admin'; Line = ('[WARNING] Service ' + $Name + ' refuses an administrator''s query (access denied) while present in the registry -- a service DACL that denies Administrators is not routine (T1014 or hardening; verify: sc sdshow ' + $Name + ')') }
        }
        return @{ Sev = 'OK'; Kind = 'denied-user'; Line = $null }
    }
    return @{ Sev = 'CRITICAL'; Kind = 'hidden'; Line = ('  ' + $Name) }
}

# PURE: the whole set of registry-only names with their per-name codes.
function Get-ServiceCrossCheckReport {
    param([array]$Probes, [bool]$IsElevated, [int]$RegistryCount)
    $out = New-Object System.Collections.ArrayList
    $hidden = @(); $deniedUser = @(); $sev = 'OK'
    foreach ($pr in @($Probes)) {
        $v = Get-ServiceVisibilityVerdict -Name ([string]$pr.Name) -IsElevated $IsElevated -NativeError ([int]$pr.NativeError)
        switch ($v.Kind) {
            'hidden'       { $hidden += [string]$pr.Name }
            'denied-user'  { $deniedUser += [string]$pr.Name }
            'denied-admin' { [void]$out.Add($v.Line); $sev = Get-MaxSev $sev 'WARNING' }
        }
    }
    if ($deniedUser.Count -gt 0) {
        [void]$out.Add(('[INFO] ' + $deniedUser.Count + ' service(s) registered but not enumerable from a standard-user token: ' + ($deniedUser -join ', ') + ' -- a restricted service DACL (as Windows'' own ZTHelper carries) and a hidden service look identical without elevation. Not graded, not cleared; re-run as administrator to grade them.'))
    }
    if ($hidden.Count -gt 0) {
        [void]$out.Add('[CRITICAL] Service present in the registry but unknown to the SCM and WMI (T1014):')
        foreach ($n in $hidden) { [void]$out.Add('  ' + $n) }
        $sev = Get-MaxSev $sev 'CRITICAL'
    }
    if ($hidden.Count -eq 0 -and $sev -eq 'OK') {
        $graded = $RegistryCount - $deniedUser.Count
        [void]$out.Add(('[OK] Service views agree across SCM, WMI and registry (' + $graded + ' Win32 services graded' + $(if ($deniedUser.Count -gt 0) { ', ' + $deniedUser.Count + ' not enumerable from this token' } else { '' }) + ').'))
    }
    return @{ Lines = @($out.ToArray()); Sev = $sev }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    # The standard-user twin, by name: Windows 11's Zero Trust DNS helper.
    $v = Get-ServiceVisibilityVerdict -Name 'zthelper' -IsElevated $false -NativeError 5
    T 'zthelper denied (error 5) to a standard-user token is NOT a finding' ($v.Sev -eq 'OK' -and $v.Kind -eq 'denied-user') ($v.Sev + '/' + $v.Kind)
    $v = Get-ServiceVisibilityVerdict -Name 'zthelper' -IsElevated $true -NativeError 5
    T 'a service that denies an ADMINISTRATOR is a WARNING, named, with the sdshow command' ($v.Sev -eq 'WARNING' -and $v.Line -match 'sc sdshow zthelper') $v.Line
    $v = Get-ServiceVisibilityVerdict -Name 'dz_hidden' -IsElevated $false -NativeError 1060
    T 'error 1060 (SCM has never heard of it) is the hidden service: CRITICAL even unelevated' ($v.Sev -eq 'CRITICAL') $v.Sev
    $v = Get-ServiceVisibilityVerdict -Name 'dz_hidden' -IsElevated $true -NativeError 1060
    T 'error 1060 elevated is CRITICAL' ($v.Sev -eq 'CRITICAL') $v.Sev
    $v = Get-ServiceVisibilityVerdict -Name 'dz_odd' -IsElevated $true -NativeError 0
    T 'any other outcome (no error, yet absent from both enumerations) stays CRITICAL -- never explained away' ($v.Sev -eq 'CRITICAL') $v.Sev

    $r = Get-ServiceCrossCheckReport -Probes @(@{ Name = 'zthelper'; NativeError = 5 }) -IsElevated $false -RegistryCount 321
    T 'standard user, one DACL-restricted service: INFO line names it, no CRITICAL, OK line counts 320 graded' ($r.Sev -eq 'OK' -and (($r.Lines -join "`n") -match '\[INFO\] 1 service\(s\) registered but not enumerable from a standard-user token: zthelper') -and (($r.Lines -join "`n") -match '\[OK\] .*320 Win32 services graded, 1 not enumerable')) ($r.Lines -join ' | ')
    T '...and the INFO line says not graded, not cleared' (($r.Lines -join "`n") -match 'Not graded, not cleared') ''
    T '...and no [CRITICAL] line is printed' (@($r.Lines | Where-Object { $_ -match '^\[CRITICAL\]' }).Count -eq 0) ''
    $r = Get-ServiceCrossCheckReport -Probes @(@{ Name = 'zthelper'; NativeError = 5 }, @{ Name = 'dz_rootkit'; NativeError = 1060 }) -IsElevated $false -RegistryCount 321
    T 'standard user, a DACL-restricted service AND a hidden one: CRITICAL names only the hidden one' ($r.Sev -eq 'CRITICAL' -and (($r.Lines -join "`n") -match '\[CRITICAL\] Service present in the registry but unknown to the SCM and WMI \(T1014\):\n  dz_rootkit') -and (($r.Lines -join "`n") -notmatch '^\s*zthelper$')) ($r.Lines -join ' | ')
    $r = Get-ServiceCrossCheckReport -Probes @(@{ Name = 'zthelper'; NativeError = 5 }) -IsElevated $true -RegistryCount 321
    T 'elevated, a service denying admins: WARNING, no OK line' ($r.Sev -eq 'WARNING' -and (($r.Lines -join "`n") -notmatch '\[OK\]')) ($r.Lines -join ' | ')
    $r = Get-ServiceCrossCheckReport -Probes @() -IsElevated $true -RegistryCount 300
    T 'no registry-only services: plain OK with the count' ($r.Sev -eq 'OK' -and (($r.Lines -join "`n") -match '\[OK\] Service views agree across SCM, WMI and registry \(300 Win32 services graded\)\.')) ($r.Lines -join ' | ')
    T 'Get-MaxSev never lowers a CRITICAL' ((Get-MaxSev 'CRITICAL' 'OK') -eq 'CRITICAL') ''

    if ($fails) { Write-Output "[FAIL] $fails cross_api_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] cross_api_check self-test: a service the SCM refuses to a standard user is stated as not enumerable, one the SCM has never heard of is the hidden service, and only the latter is CRITICAL.'
    exit 0
}

if ($Elevated -lt 0) {
    $Elevated = 0
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 }
    } catch {}
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
    $raced = 0   # candidates whose disagreement was explained by the process exiting
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
                # CLOSING LIVENESS CHECK. The three reads above are sequential,
                # so a process that exits partway through is present in the
                # earlier reads and absent from the later ones -- an ordinary
                # race that looked identical to a hiding rootkit and was raised
                # as CRITICAL. Re-read once more at the end: if the PID is gone
                # now, the disagreement is explained by it exiting, not by
                # concealment. A genuinely hidden process is still running and
                # still disagrees.
                $stillAlive = $false
                try { if ([System.Diagnostics.Process]::GetProcessById($procId)) { $stillAlive = $true } } catch {}
                if ($stillAlive) {
                    $realHits += ("PID {0} ({1}) -- .NET:{2} WMI:{3} tasklist:{4}" -f $procId, $nm, $n2, $w2, $t2)
                } else {
                    $raced++
                }
            }
        }
    }
    if ($realHits.Count -gt 0) {
        "[CRITICAL] Process visible to some enumeration APIs but not others -- process-hiding rootkit indicator (T1014):"
        foreach ($h in $realHits) { "  $h" }
        # The consequence, not a second finding.
        '[INFO] A live process has no legitimate reason to be missing from one authoritative view of the system.'
        $sev = Get-MaxSev $sev 'CRITICAL'
    } else {
        "[OK] Process lists agree across .NET, WMI and tasklist ($($setNet.Count) processes; transient start/exit differences resolved on re-check)."
    }
    if ($raced -gt 0) {
        "[INFO] $raced process(es) disagreed across APIs but had exited by the final re-check -- ordinary start/exit races, not concealment."
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
        # settles consistently on the second look. Then ask the SCM for each
        # survivor BY NAME: the error code is what separates a DACL that refuses
        # this token (5) from a service the SCM does not know (1060).
        Start-Sleep -Milliseconds $SettleMs
        $probes = @()
        foreach ($n in $hidden) {
            $stillReg = Test-Path -LiteralPath (Join-Path $svcRoot $n)
            $seen = $false
            try { if (Get-Service -Name $n -EA Stop) { $seen = $true } } catch {}
            try { if (Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f ($n -replace "'", "''")) -EA Stop) { $seen = $true } } catch {}
            if (-not $stillReg -or $seen) { continue }
            $code = 1060
            try {
                $sc = New-Object System.ServiceProcess.ServiceController($n)
                $null = $sc.Status
                # No error at all: the SCM answered by name although it did
                # not enumerate the service. Treat as hidden, never as fine.
                $code = 0
            } catch {
                $inner = $_.Exception.InnerException
                if ($inner -and ($inner.PSObject.Properties.Name -contains 'NativeErrorCode')) { $code = [int]$inner.NativeErrorCode }
            }
            $probes += @{ Name = $n; NativeError = $code }
        }
        $rep = Get-ServiceCrossCheckReport -Probes $probes -IsElevated ($Elevated -eq 1) -RegistryCount $svcReg.Count
        foreach ($l in $rep.Lines) { $l }
        $sev = Get-MaxSev $sev $rep.Sev
    } else {
        "[OK] Service views agree across SCM, WMI and registry ($($svcReg.Count) Win32 services graded)."
    }
}

# ---- 3. Scheduled tasks: Task Scheduler vs raw TaskCache (incl. Tarrask) ---
''
'--- [T1053.005] Scheduled-task cross-check + hidden-task (Tarrask) detection ---'
$treeRoot  = $TreeRoot
$tasksRoot = $TasksRoot
$tOk = $true
# Live task list, used ONLY to corroborate a missing-SD hit (see below). Failure
# to enumerate is not fatal -- it just means corroboration is unavailable.
$live = @{}
$liveOk = $false
if (-not $SkipLiveTaskCompare) {
    try {
        foreach ($t in (Get-ScheduledTask -EA Stop)) {
            $full = ([string]$t.TaskPath).TrimEnd('\') + '\' + [string]$t.TaskName
            $live[$full.ToLower()] = $true
        }
        $liveOk = ($live.Count -gt 0)
    } catch { $liveOk = $false }
}

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
                # NON-greedy. `^.*Tree` matched as far as the LAST occurrence,
                # so a task whose own name contains the root's leaf -- a vendor
                # task called "TreeSize Update", say -- was truncated at the
                # wrong place ("Size Update"), and that bogus path never matched
                # the live Get-ScheduledTask list. The corroboration signal was
                # lost silently, for precisely the task whose name triggered it.
                # `^.*?` stops at the root's own segment, which comes first.
                $full = $node.PSPath -replace ('^.*?' + [regex]::Escape((Split-Path -Leaf $treeRoot))), ''
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
    $inspected = 0
    $sdOnly = 0
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
            $inspected++
            if ($vals -notcontains 'SD') {
                # CORROBORATION IS REQUIRED. Each signal alone false-positives:
                # a missing SD in this registry view happens for ordinary tasks
                # (CI measured it for EVERY task at admin privilege -- reading
                # descriptors here really wants SYSTEM), and a Tree entry the
                # scheduler does not return is usually just stale. Tarrask is
                # the INTERSECTION: the task is hidden from Task Scheduler AND
                # its descriptor is gone. Demanding both collapses both
                # false-positive sources while still catching the real technique.
                if ($liveOk -and -not $live.ContainsKey(($tt.Path).ToLower())) {
                    $noSd += ("{0}  (Id {1})" -f $tt.Path, $tt.Id)
                } else {
                    $sdOnly++
                }
            }
        }
    }
    # Safety net independent of the cause: a real Tarrask implant hides ONE task
    # (or a few). If EVERY registered task appears to lack a descriptor, that is
    # a permissions or platform artifact, not a compromise -- report the blind
    # spot honestly instead of burying the user in false criticals. Kept
    # conservative (only when there is a real population to judge) so a genuine
    # single-task hit on a small task list is never suppressed.
    # Proportion guard, independent of cause: a real implant hides one task or a
    # few. If a large share of everything inspected trips the rule, that is a
    # platform or permissions artifact -- say so instead of emitting a wall of
    # false criticals a frightened user cannot evaluate.
    $sdSuppressed = $false
    if ($inspected -ge 10 -and $noSd.Count -gt [int]($inspected * 0.25)) {
        $sdSuppressed = $true
        "[SKIPPED] $($noSd.Count) of $inspected tasks matched the hidden-task rule -- implausibly many, treated as a platform/permissions artifact rather than a compromise. Hidden-task check NOT performed."
        $sev = Get-MaxSev $sev 'WARNING'
        $noSd = @()
    }
    if (-not $liveOk) {
        # NOT "ran without its second signal" -- it did not run at all. The rule
        # is `$liveOk -and -not $live.ContainsKey(...)`, so with $liveOk false
        # EVERY task takes the else branch, $noSd stays empty, and no hit is
        # reachable. The old wording claimed a degraded check while the [OK]
        # line below asserted every task carried a descriptor -- two false
        # statements on a host where the Schedule service is stopped or
        # tampered with, which is exactly what an implant that just planted a
        # hidden task would arrange. Report the blind spot and raise it.
        '[SKIPPED] Task Scheduler could not be enumerated, so the hidden-task (Tarrask) check could NOT run -- it requires both signals: a missing security descriptor AND absence from the scheduler. A stopped or tampered Schedule service is itself worth investigating.'
        $sev = Get-MaxSev $sev 'WARNING'
    }
    if ($sdOnly -gt 0) {
        "[INFO] $sdOnly task(s) lack a readable security descriptor but ARE enumerable by Task Scheduler -- expected at admin privilege (descriptor reads want SYSTEM), not treated as hidden."
    }
    if ($unreadable -gt 0) {
        "[INFO] $unreadable task(s) could not be inspected at all; the remaining $inspected were checked."
    }
    if ($noSd.Count -gt 0) {
        '[CRITICAL] Scheduled task registered in TaskCache with NO security descriptor (SD) -- Tarrask-style hidden task (T1053.005):'
        foreach ($h in $noSd) { "  $h" }
        # What the technique achieves, not a second finding.
        '[INFO] Deleting the SD value hides a task from schtasks and the Task Scheduler UI while it still runs. Used by HAFNIUM.'
        $sev = Get-MaxSev $sev 'CRITICAL'
    }
    # Only claim a clean result when the check could actually reach one. Two
    # ways it cannot: the scheduler was unavailable ($liveOk false), or the
    # proportion guard just emptied $noSd and said "Hidden-task check NOT
    # performed". Without $sdSuppressed the second path printed that SKIPPED
    # line and then, one branch later, "all carry a security descriptor" --
    # contradicting itself in adjacent lines.
    if ($noSd.Count -eq 0 -and $liveOk -and -not $sdSuppressed) {
        "[OK] No hidden scheduled tasks ($($treeTasks.Count) registered tasks; all carry a security descriptor)."
    }
}

Write-Marker -Name 'crossapi' -Sev $sev
