# pending_reboot_check.ps1 -- Section 1: is a reboot pending, WHAT is queued,
# and was the flag written before or after the last boot?
#
# Extracted from the staged block that lived inline in both bats. That block
# tested only that PendingFileRenameOperations EXISTS and told the reader to
# "Reboot the system then re-run the audit". On the owner's laptop the flag was
# still set after a boot the System log proved (WinInit Event 12, 2026-10-02
# 09:09), so every run exited 4 with advice that could not work, and the report
# never said which files were queued or by whom. Two more defects rode along:
# the registry read sat in `try{...}catch{}`, so an unreadable key printed
# `[OK] No pending reboot detected` (a false clean), and the WU line's wording
# never matched the analyst note written for it.
#
# WHAT WINDOWS RECORDS (Microsoft Learn, MoveFileEx / MOVEFILE_DELAY_UNTIL_REBOOT):
#   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations
#   is a REG_MULTI_SZ of PAIRS `src\0dst\0`; an empty dst means "delete src at
#   restart". Session Manager performs the operations at the next restart, in
#   order, and removes the value. Sysinternals PendMoves prints the same list.
#   PendingFileRenameOperations2 is the same shape (used by some servicing
#   paths). Windows Update's RebootRequired key and Component Based Servicing's
#   RebootPending key are the other two flags the audit reads.
#
# THE RULE. Every flag that is present is PRINTED with what it holds and WHEN
# it was written (the key's RegQueryInfoKey last-write time), compared with the
# kernel's last boot time:
#   * written AFTER the last boot  -> fresh: a Restart will apply it.
#   * written BEFORE the last boot -> stale: it survived a restart. Either a
#     component re-created it (Defender platform updates and MSI installers
#     do, after every update) or it was never processed -- Fast Startup's
#     "Shut down" hibernates the kernel, LastBootUpTime does not move and the
#     queue is not run; only Restart does. Rebooting again is unlikely to
#     clear it, and the report says so instead of repeating the advice.
#   * no boot time or no key time  -> unknown, stated; never guessed.
#   The Session Manager time is the KEY's: any value under that key moves it,
#   so it is an upper bound on when the queue was written. Said in the line.
# One [WARNING] line names every flag present and ends with ':' so the queued
# operations beneath it travel into the TOP FINDINGS block; the operations are
# printed indented and tag-free (a path can never start a report line with a
# severity tag). A registry read that fails is a declared gap -- its own
# marker and its own ledger row -- never an all-clear.
#
# MARKERS: dz_reboot.txt = WARNING when a reboot is pending (the bat raises the
# REBOOT row and exit code 4); dz_reboot_gap.txt = WARNING when a flag could not
# be read. STATE (one line, every field always present, for the bat's advice):
#   <pending 0/1>|<age fresh|stale|mixed|unknown>|<queued ops N>|<wu 0/1>|<cbs 0/1>|<faststartup 0/1/unknown>
#
# Usage:
#   powershell -File tools\pending_reboot_check.ps1 [-MarkerDir <dir>] [-StateFile <path>]
#   powershell -File tools\pending_reboot_check.ps1 -SelfTest   (no registry, no CIM, no Add-Type)
#
# Read-only. Works from a standard-user token (Session Manager and the two
# flag keys are readable by Users). Windows PowerShell 5.1 compatible; pure ASCII.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_reboot_state.txt' }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write here turns
    # a real finding into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine write failure print instead of vanishing.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

function Get-MaxSev {
    param([string]$A, [string]$B)
    $rank = @{ 'OK' = 0; 'WARNING' = 1; 'CRITICAL' = 2 }
    if ($rank[$B] -gt $rank[$A]) { return $B }
    return $A
}

# Registry key last-write time. PowerShell's registry provider does NOT expose
# it -- Get-Item on a key returns a RegistryKey with no LastWriteTime -- so it
# has to come from RegQueryInfoKey. The type is defined once per process and
# every failure path degrades to $null, which the report states as "unknown"
# rather than inventing a date. Same function as tools\logon_persistence.ps1.
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

function Format-When {
    param($Time)
    if ($null -eq $Time) { return 'unknown' }
    try { return ([datetime]$Time).ToString('yyyy-MM-ddTHH:mm:ss') } catch { return 'unknown' }
}

# A path as it will be printed: control characters and the record separator
# stripped, the NT object prefix removed, long values cut. The line it goes on
# starts with 'delete:' / 'rename:' after the indent, so no path can ever
# start a report line with a severity tag.
function ConvertTo-PrintablePath {
    param([string]$Path)
    if ($null -eq $Path) { return '' }
    $s = $Path -replace '^\\\?\?\\', ''
    $s = ($s -replace '[\x00-\x1F|]', ' ').Trim()
    if ($s.Length -gt 240) { $s = $s.Substring(0, 240) + '...' }
    return $s
}

# PURE. The REG_MULTI_SZ entries, two at a time: src then dst; an empty dst is
# a delete. A dangling last src (odd length -- .NET drops the final terminator
# of `src\0\0`) is a delete too. -Exists is the source-file probe, injectable.
function ConvertTo-PendingOperations {
    param([string[]]$Entries = @(), [scriptblock]$Exists = $null)
    if ($null -eq $Exists) { $Exists = { param([string]$p) Test-Path -LiteralPath $p -PathType Any } }
    $ops = New-Object System.Collections.Generic.List[string]
    $e = @($Entries | ForEach-Object { if ($null -eq $_) { '' } else { [string]$_ } })
    $i = 0
    while ($i -lt $e.Count) {
        $src = $e[$i]
        if (-not $src.Trim()) { $i++; continue }
        $dst = ''
        if (($i + 1) -lt $e.Count) { $dst = $e[$i + 1] }
        $i += 2
        $srcP = ConvertTo-PrintablePath $src
        $missing = ''
        $probe = $false
        try { $probe = [bool](& $Exists ($src -replace '^\\\?\?\\', '')) } catch { $probe = $false }
        if (-not $probe) { $missing = ' (source missing)' }
        if ($dst.Trim()) {
            [void]$ops.Add(('rename: {0} -> {1}{2}' -f $srcP, (ConvertTo-PrintablePath $dst), $missing))
        } else {
            [void]$ops.Add(('delete: {0}{1}' -f $srcP, $missing))
        }
    }
    return @($ops.ToArray())
}

# PURE. fresh = written after the last boot; stale = before it; unknown when
# either time is missing. A small tolerance absorbs clock skew between the
# kernel's boot stamp and the registry's.
function Get-FlagAge {
    param($When, $BootTime)
    if ($null -eq $When -or $null -eq $BootTime) { return 'unknown' }
    try {
        if (([datetime]$When) -ge ([datetime]$BootTime).AddMinutes(-2)) { return 'fresh' }
        return 'stale'
    } catch { return 'unknown' }
}

function Get-OverallAge {
    param([string[]]$Ages)
    $a = @($Ages | Where-Object { $_ })
    if ($a.Count -eq 0) { return 'unknown' }
    if (@($a | Where-Object { $_ -eq 'unknown' }).Count) { return 'unknown' }
    $fresh = @($a | Where-Object { $_ -eq 'fresh' }).Count
    $stale = @($a | Where-Object { $_ -eq 'stale' }).Count
    if ($stale -eq $a.Count) { return 'stale' }
    if ($fresh -eq $a.Count) { return 'fresh' }
    return 'mixed'
}

function Get-AgeClause {
    param([string]$Age, [string]$Verb)
    switch ($Age) {
        'fresh' { return ('written AFTER the last boot: a Restart will {0} it.' -f $Verb) }
        'stale' { return 'written BEFORE the last boot: it survived a restart (re-created by a component after the boot, or never processed -- see Fast Startup below); restarting again is unlikely to clear it.' }
        default { return 'could not be compared with the last boot (a time is unknown).' }
    }
}

# PURE. Every input is injectable so the self-test can drive every row of the
# rule above without a registry, CIM or Add-Type.
function Get-PendingRebootReport {
    param(
        [bool]$WuPending = $false, $WuWhen = $null,
        [bool]$CbsPending = $false, $CbsWhen = $null,
        [string[]]$Renames = @(),
        $KeyWhen = $null,
        $BootTime = $null,
        [int]$FastStartup = -1,
        [scriptblock]$Exists = $null,
        [string[]]$ReadErrors = @(),
        [int]$MaxOps = 25
    )
    $out = New-Object System.Collections.Generic.List[string]
    $sev = 'OK'; $gapSev = 'OK'
    $ops = @()
    if ($Renames -and @($Renames).Count) { $ops = @(ConvertTo-PendingOperations -Entries $Renames -Exists $Exists) }
    $pfro = ($ops.Count -gt 0)
    $pending = ($WuPending -or $CbsPending -or $pfro)
    $ages = @()

    if ($pending) {
        $flags = @()
        if ($pfro) { $flags += ('PendingFileRenameOperations is set ({0} queued file operation(s))' -f $ops.Count) }
        if ($WuPending) { $flags += 'Windows Update requires a reboot' }
        if ($CbsPending) { $flags += 'Component Based Servicing has a reboot queued' }
        # ONE finding line, ending with ':' so top_findings carries the detail
        # beneath it. The detail lines are tag-free and indented.
        [void]$out.Add('[WARNING] Reboot pending: ' + ($flags -join '; ') + ' -- audit results may be incomplete:')
        $sev = 'WARNING'
        $n = 0
        foreach ($o in $ops) {
            $n++
            if ($n -le $MaxOps) { [void]$out.Add('    ' + $o) }
        }
        if ($ops.Count -gt $MaxOps) { [void]$out.Add(('    ...and {0} more queued operation(s) not listed.' -f ($ops.Count - $MaxOps))) }
        if ($WuPending)  { [void]$out.Add(('    flag: Windows Update RebootRequired key (written {0})' -f (Format-When $WuWhen))) }
        if ($CbsPending) { [void]$out.Add(('    flag: Component Based Servicing RebootPending key (written {0})' -f (Format-When $CbsWhen))) }
        $bootText = Format-When $BootTime
        if ($pfro) {
            $age = Get-FlagAge -When $KeyWhen -BootTime $BootTime; $ages += $age
            [void]$out.Add(('[INFO] PendingFileRenameOperations: Session Manager key last written {0}, last boot {1} -- {2} (the key time is an upper bound: any value under that key moves it)' -f (Format-When $KeyWhen), $bootText, (Get-AgeClause -Age $age -Verb 'run')))
        }
        if ($WuPending) {
            $age = Get-FlagAge -When $WuWhen -BootTime $BootTime; $ages += $age
            [void]$out.Add(('[INFO] Windows Update RebootRequired: key written {0}, last boot {1} -- {2}' -f (Format-When $WuWhen), $bootText, (Get-AgeClause -Age $age -Verb 'clear')))
        }
        if ($CbsPending) {
            $age = Get-FlagAge -When $CbsWhen -BootTime $BootTime; $ages += $age
            [void]$out.Add(('[INFO] Component Based Servicing RebootPending: key written {0}, last boot {1} -- {2}' -f (Format-When $CbsWhen), $bootText, (Get-AgeClause -Age $age -Verb 'clear')))
        }
        if ($FastStartup -eq 1) {
            [void]$out.Add('[INFO] Fast Startup is ON (HiberbootEnabled=1): "Shut down" hibernates the kernel and does not process this queue; use Restart.')
        }
    }
    if ($ReadErrors -and @($ReadErrors).Count) {
        # A flag that could not be read is a gap: its own marker, its own row,
        # and no all-clear line. What WAS readable is still reported above.
        [void]$out.Add('[WARNING] Pending-reboot state NOT determined -- could not read: ' + ((@($ReadErrors) | ForEach-Object { ($_ -replace '[\r\n|]', ' ').Trim() }) -join '; '))
        $gapSev = 'WARNING'
    } elseif (-not $pending) {
        [void]$out.Add('[OK] No pending reboot detected.')
    }
    $overall = Get-OverallAge -Ages $ages
    $fs = 'unknown'
    if ($FastStartup -eq 1) { $fs = '1' } elseif ($FastStartup -eq 0) { $fs = '0' }
    # Six fields, every one always present: cmd's for /f leaves the literal
    # token text in a variable when a field is missing.
    $state = ('{0}|{1}|{2}|{3}|{4}|{5}' -f $(if ($pending) { '1' } else { '0' }), $overall, $ops.Count, $(if ($WuPending) { '1' } else { '0' }), $(if ($CbsPending) { '1' } else { '0' }), $fs)
    return @{ Pending = $pending; Age = $overall; Sev = $sev; GapSev = $gapSev; Lines = @($out.ToArray()); State = $state; Operations = $ops }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $boot = Get-Date '2026-10-02 09:09:31'
    $after = $boot.AddHours(5)
    $before = $boot.AddDays(-1)
    $none = { param([string]$p) $false }
    $all  = { param([string]$p) $true }
    $j = { param($r) ($r.Lines -join "`n") }

    # Pair parsing.
    $ops = @(ConvertTo-PendingOperations -Entries @('\??\C:\Config.Msi\3ec7bbbf.rbf', '') -Exists $none)
    T 'a src/empty pair is a delete, the NT prefix is stripped, a missing source is said' ($ops.Count -eq 1 -and $ops[0] -eq 'delete: C:\Config.Msi\3ec7bbbf.rbf (source missing)') ($ops -join ' / ')
    $ops = @(ConvertTo-PendingOperations -Entries @('\??\C:\Windows\Temp\new.dll', '\??\C:\Windows\System32\old.dll') -Exists $all)
    T 'a src/dst pair is a rename, both paths printed' ($ops.Count -eq 1 -and $ops[0] -eq 'rename: C:\Windows\Temp\new.dll -> C:\Windows\System32\old.dll') ($ops -join ' / ')
    $ops = @(ConvertTo-PendingOperations -Entries @('\??\C:\a.tmp', '', '\??\C:\b.tmp', '\??\C:\c.tmp', '\??\C:\d.tmp') -Exists $all)
    T 'a dangling last entry (odd length: .NET drops the final terminator) is a delete; pairs stay aligned' ($ops.Count -eq 3 -and $ops[0] -eq 'delete: C:\a.tmp' -and $ops[1] -eq 'rename: C:\b.tmp -> C:\c.tmp' -and $ops[2] -eq 'delete: C:\d.tmp') ($ops -join ' / ')
    $ops = @(ConvertTo-PendingOperations -Entries @('', '\??\C:\x.tmp', '') -Exists $all)
    T 'a leading empty entry is skipped and the pairs re-synchronise' ($ops.Count -eq 1 -and $ops[0] -eq 'delete: C:\x.tmp') ($ops -join ' / ')
    $ops = @(ConvertTo-PendingOperations -Entries @("[CRITICAL] evil`t|.exe", '') -Exists $all)
    T 'a path can never start a report line with a tag, and control characters and | are stripped' ($ops[0] -match '^delete: \[CRITICAL\] evil  \.exe$') ($ops -join ' / ')
    $ops = @(ConvertTo-PendingOperations -Entries @() -Exists $all)
    T 'no entries, no operations' ($ops.Count -eq 0) ''

    # The report: PendingFileRenameOperations present.
    $r = Get-PendingRebootReport -Renames @('\??\C:\dz_ci_pending_rename.tmp', '') -KeyWhen $after -BootTime $boot -FastStartup 0 -Exists $none
    $t = & $j $r
    T 'PFRO set: ONE [WARNING] line naming the flag with the count, ending with a colon, the CI phrase present' ($r.Sev -eq 'WARNING' -and $r.Pending -and @($r.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 1 -and $r.Lines[0] -eq '[WARNING] Reboot pending: PendingFileRenameOperations is set (1 queued file operation(s)) -- audit results may be incomplete:') $t
    T 'the queued operation follows the finding line DIRECTLY, indented and tag-free (top_findings carries it)' ($r.Lines[1] -eq '    delete: C:\dz_ci_pending_rename.tmp (source missing)') $t
    T 'written after the boot: fresh, the INFO line says a Restart will run it and names both times' ($r.Age -eq 'fresh' -and $t -match '\[INFO\] PendingFileRenameOperations: Session Manager key last written 2026-10-02T14:09:31, last boot 2026-10-02T09:09:31 -- written AFTER the last boot: a Restart will run it') $t
    T 'state line: 1|fresh|1|0|0|0' ($r.State -eq '1|fresh|1|0|0|0') $r.State
    T 'no gap, no OK line when something is pending' ($r.GapSev -eq 'OK' -and $t -notmatch '\[OK\]') $t
    $r = Get-PendingRebootReport -Renames @('\??\C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\x.dll', '') -KeyWhen $before -BootTime $boot -FastStartup 1 -Exists $all
    $t = & $j $r
    T 'written before the boot: STALE, the line says it survived a restart and that restarting again is unlikely to clear it' ($r.Age -eq 'stale' -and $t -match 'written BEFORE the last boot: it survived a restart' -and $t -match 'restarting again is unlikely to clear it') $t
    T 'Fast Startup ON is named with the Restart advice' ($t -match '\[INFO\] Fast Startup is ON \(HiberbootEnabled=1\): "Shut down" hibernates the kernel and does not process this queue; use Restart\.') $t
    T 'state line carries stale and Fast Startup: 1|stale|1|0|0|1' ($r.State -eq '1|stale|1|0|0|1') $r.State
    $r = Get-PendingRebootReport -Renames @('\??\C:\x.tmp', '') -KeyWhen $null -BootTime $boot -Exists $all
    T 'no key time: age unknown, said, never guessed' ($r.Age -eq 'unknown' -and (& $j $r) -match 'key last written unknown' -and (& $j $r) -match 'could not be compared with the last boot') (& $j $r)
    $r = Get-PendingRebootReport -Renames @('\??\C:\x.tmp', '') -KeyWhen $after -BootTime $null -Exists $all
    T 'no boot time: age unknown' ($r.Age -eq 'unknown' -and $r.State -eq '1|unknown|1|0|0|unknown') ($r.Age + ' / ' + $r.State)

    # The other two flags.
    $r = Get-PendingRebootReport -WuPending $true -WuWhen $before -BootTime $boot -FastStartup 0
    $t = & $j $r
    T 'Windows Update flag only, written before the boot: the finding line names it (the top_findings key), a flag: detail line, stale' ($r.Lines[0] -eq '[WARNING] Reboot pending: Windows Update requires a reboot -- audit results may be incomplete:' -and $r.Lines[1] -eq '    flag: Windows Update RebootRequired key (written 2026-10-01T09:09:31)' -and $r.Age -eq 'stale' -and $r.State -eq '1|stale|0|1|0|0') $t
    $r = Get-PendingRebootReport -WuPending $true -WuWhen $after -CbsPending $true -CbsWhen $before -Renames @('\??\C:\x.tmp', '') -KeyWhen $after -BootTime $boot -FastStartup 0 -Exists $all
    $t = & $j $r
    T 'all three flags: one finding line names all three in order, age MIXED (one stale, two fresh)' ($r.Lines[0] -eq '[WARNING] Reboot pending: PendingFileRenameOperations is set (1 queued file operation(s)); Windows Update requires a reboot; Component Based Servicing has a reboot queued -- audit results may be incomplete:' -and $r.Age -eq 'mixed' -and $r.State -eq '1|mixed|1|1|1|0') $t
    T 'a single WARNING line even with three flags (the row count equals the line count)' (@($r.Lines | Where-Object { $_ -match '^\[WARNING\]' }).Count -eq 1) $t
    $r = Get-PendingRebootReport -WuPending $true -WuWhen $before -CbsPending $true -CbsWhen $before -BootTime $boot
    T 'every flag before the boot: STALE overall' ($r.Age -eq 'stale') $r.Age
    $r = Get-PendingRebootReport -WuPending $true -WuWhen $after -CbsPending $true -CbsWhen $null -BootTime $boot
    T 'one flag with no time: overall UNKNOWN, not fresh' ($r.Age -eq 'unknown') $r.Age

    # Nothing pending; the cap; the gap.
    $r = Get-PendingRebootReport -BootTime $boot -FastStartup 1
    T 'nothing pending: the OK line, Sev OK, state 0|unknown|0|0|0|1, no Fast Startup line' ($r.Sev -eq 'OK' -and (-not $r.Pending) -and $r.Lines.Count -eq 1 -and $r.Lines[0] -eq '[OK] No pending reboot detected.' -and $r.State -eq '0|unknown|0|0|0|1') ((& $j $r) + ' / ' + $r.State)
    $many = @(); for ($k = 1; $k -le 30; $k++) { $many += ('\??\C:\t\f{0}.tmp' -f $k); $many += '' }
    $r = Get-PendingRebootReport -Renames $many -KeyWhen $after -BootTime $boot -Exists $all -MaxOps 25
    T '30 queued operations: 25 listed, the remainder counted, the finding line says 30' ($r.Lines[0] -match '\(30 queued file operation\(s\)\)' -and @($r.Lines | Where-Object { $_ -match '^    (delete|rename): ' }).Count -eq 25 -and (& $j $r) -match '    \.\.\.and 5 more queued operation\(s\) not listed\.') (& $j $r)
    $r = Get-PendingRebootReport -ReadErrors @('Session Manager: Requested registry access is not allowed') -BootTime $boot
    $t = & $j $r
    T 'a registry read failure is a declared gap: [WARNING] ... NOT determined, GapSev WARNING, Sev OK, no finding, NO [OK] line' ($r.GapSev -eq 'WARNING' -and $r.Sev -eq 'OK' -and (-not $r.Pending) -and $t -match '^\[WARNING\] Pending-reboot state NOT determined -- could not read: Session Manager: Requested registry access is not allowed$' -and $t -notmatch '\[OK\]') $t
    $r = Get-PendingRebootReport -WuPending $true -WuWhen $after -BootTime $boot -ReadErrors @('Session Manager: denied')
    T 'a readable flag is still reported beside the gap for the unreadable one' ($r.Sev -eq 'WARNING' -and $r.GapSev -eq 'WARNING' -and (& $j $r) -match 'Windows Update requires a reboot' -and (& $j $r) -match 'NOT determined') (& $j $r)
    T 'Get-FlagAge tolerates two minutes of clock skew around the boot' ((Get-FlagAge -When $boot.AddSeconds(-30) -BootTime $boot) -eq 'fresh' -and (Get-FlagAge -When $boot.AddMinutes(-3) -BootTime $boot) -eq 'stale') ''
    T 'Get-MaxSev never lowers a WARNING' ((Get-MaxSev 'WARNING' 'OK') -eq 'WARNING') ''

    if ($fails) { Write-Output "[FAIL] $fails pending_reboot_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] pending_reboot_check self-test: a pending reboot names what is queued and whether the flag predates the last boot; an unreadable flag is a declared gap, never an all-clear.'
    exit 0
}

# ---- Live ----------------------------------------------------------------
$errs = @()
$smKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$wuKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$cbsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'

$wu = $false; $wuWhen = $null
try {
    $wu = [bool](Test-Path -LiteralPath $wuKey -EA Stop)
    if ($wu) { $wuWhen = Get-RegKeyLastWrite $wuKey }
} catch { $errs += ('Windows Update RebootRequired: ' + $_.Exception.Message) }

$cbs = $false; $cbsWhen = $null
try {
    $cbs = [bool](Test-Path -LiteralPath $cbsKey -EA Stop)
    if ($cbs) { $cbsWhen = Get-RegKeyLastWrite $cbsKey }
} catch { $errs += ('Component Based Servicing RebootPending: ' + $_.Exception.Message) }

$ren = @(); $keyWhen = $null
try {
    if (-not (Test-Path -LiteralPath $smKey -EA Stop)) {
        $errs += 'Session Manager: key not found or not readable from this token'
    } else {
        $props = Get-ItemProperty -LiteralPath $smKey -EA Stop
        foreach ($name in 'PendingFileRenameOperations', 'PendingFileRenameOperations2') {
            $v = $null
            try { $v = $props.$name } catch { $v = $null }
            if ($null -ne $v) { $ren += @($v | ForEach-Object { [string]$_ }) }
        }
        if ($ren.Count) { $keyWhen = Get-RegKeyLastWrite $smKey }
    }
} catch { $errs += ('Session Manager: ' + $_.Exception.Message) }

$boot = $null
try { $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { $boot = $null }

$fastStartup = -1
try {
    $hb = (Get-ItemProperty -LiteralPath ($smKey + '\Power') -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled
    if ($null -ne $hb) { $fastStartup = $(if ([int]$hb -ne 0) { 1 } else { 0 }) }
} catch { $fastStartup = -1 }

$rep = $null
try {
    $rep = Get-PendingRebootReport -WuPending $wu -WuWhen $wuWhen -CbsPending $cbs -CbsWhen $cbsWhen -Renames $ren -KeyWhen $keyWhen -BootTime $boot -FastStartup $fastStartup -ReadErrors $errs
} catch { $rep = $null }
if ($null -eq $rep) {
    $rep = @{ Pending = $false; Age = 'unknown'; Sev = 'OK'; GapSev = 'WARNING'; State = '0|unknown|0|0|0|unknown'; Lines = @('[WARNING] Pending-reboot state NOT determined -- the check itself failed; re-run tools\pending_reboot_check.ps1 by hand to see the error.') }
}
$rep.Lines
Write-Marker -Name 'reboot' -Sev $rep.Sev
# A gap is its own row: a flag this token could not read never reads as "no
# pending reboot"; the bat raises dz_reboot_gap.txt with gap wording.
if ($rep.GapSev -ne 'OK') { Write-Marker -Name 'reboot_gap' -Sev $rep.GapSev }
try {
    $d = Split-Path -Parent $StateFile
    if ($d -and -not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath $StateFile -Value $rep.State -Encoding ASCII
} catch {
    '[INFO] Could not write the pending-reboot state file; the exit-4 advice will read as if the flag age were unknown.'
}
