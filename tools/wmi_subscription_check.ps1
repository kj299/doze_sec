# wmi_subscription_check.ps1 -- Section 17: WMI permanent event subscriptions
# (T1546.003): non-default __EventFilter instances, CommandLineEventConsumer
# and ActiveScriptEventConsumer, in root\subscription.
#
# Extracted from three inline blocks in both bats, after two defects were
# found by reading:
#   * a query that FAILED printed "[SKIPPED] ... NOT performed" through
#     :dz_ps_scan, and [SKIPPED] never raises -- so a WMI repository an
#     intruder had broken (a known way to hide a subscription) reached neither
#     the ledger, the section verdict nor the exit code. Retagging it
#     [WARNING] inside :dz_ps_scan would have been worse: the row would read
#     "Non-default WMI EventFilter - stealthy persistence" for a query that
#     found nothing. The gap needs its own marker.
#   * the dashboard tile re-ran the EventFilter query with -EA SilentlyContinue
#     and printed PASS "No non-default WMI permanent EventFilter subscriptions"
#     when it failed, and graded a hit CRIT where the section raised WARNING.
#     A tile that re-measures is a second opinion.
#
# THE RULE (pure, in Get-WmiSubscriptionVerdict, pinned by -SelfTest):
#   * found     -> WARNING with the same lines and tables as before, and a hit
#                  marker per class (dz_wmi_filter_hit / _cmd_hit / _script_hit);
#   * none      -> [OK], the same wording as before;
#   * query failed:
#       - elevated token -> "[WARNING] ... NOT performed", marker dz_wmisub_gap;
#       - standard user  -> [DEFERRED - ADMIN REQUIRED], dz_wmisub_deferred.
# The default Microsoft filters stay allowlisted exactly as before. State line
# for the dashboard (a comma, never a pipe):
#   filter=<n|gap|deferred>,cmd=<n|gap|deferred>,script=<n|gap|deferred>
#
# Usage:
#   powershell -File tools\wmi_subscription_check.ps1 [-MarkerDir <dir>] [-StateFile <path>] [-Elevated 0|1] [-Namespace <ns>]
#   powershell -File tools\wmi_subscription_check.ps1 -SelfTest   (queries nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$StateFile,
    [int]$Elevated = -1,
    # The namespace to query. Only CI changes it, to one that does not exist, so
    # the could-not-query path runs through the real reader.
    [string]$Namespace = 'root\subscription',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }
if (-not $StateFile) { $StateFile = Join-Path $MarkerDir 'dz_wmisub_state.txt' }

function Write-Marker {
    param([string]$Name, [string]$Value)
    if (-not $Value) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Value -Encoding ASCII
}

function ConvertTo-PrintableText {
    param([string]$s)
    return (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
}

function Test-DefaultFilter {
    # PURE. The default Microsoft filters, allowlisted exactly as the inline
    # check did: the SCM event-log filter by name AND query, and three names.
    param($Filter)
    $n = [string]$Filter.Name
    if ($n -eq 'SCM Event Log Filter' -and ([string]$Filter.Query) -like '*MSFT_SCMEventLogEvent*') { return $true }
    return ($n -in @('BVTConsumer', 'BVTFilter', 'RmAssistEventLog'))
}

function Format-Table200 {
    # The same table the inline check printed, as text lines.
    param($Rows, [string[]]$Props, [switch]$List)
    if ($List) { $s = ($Rows | Select-Object -Property $Props | Format-List | Out-String -Width 200) }
    else { $s = ($Rows | Select-Object -Property $Props | Format-Table -AutoSize | Out-String -Width 200) }
    return @(($s -split "`r?`n") | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -ne '' } | ForEach-Object { ConvertTo-PrintableText $_ })
}

# PURE. $Q maps 'filter'/'cmd'/'script' to @{ Items; Error }: Items the WMI
# instances (any objects with the properties), Error '' when the query ran.
# Returns @{ Lines; Hits; Gap; Deferred; State }.
function Get-WmiSubscriptionVerdict {
    param([hashtable]$Q, [bool]$IsElevated = $true)
    $out = New-Object System.Collections.ArrayList
    $hits = New-Object System.Collections.ArrayList
    $gap = $false; $deferred = 0
    $state = New-Object System.Collections.ArrayList
    $spec = @(
        @{ Key = 'filter'; Class = 'EventFilter'; Hit = 'wmi_filter_hit' },
        @{ Key = 'cmd'; Class = 'CommandLineEventConsumer'; Hit = 'wmi_cmd_hit' },
        @{ Key = 'script'; Class = 'ActiveScriptEventConsumer'; Hit = 'wmi_script_hit' }
    )
    foreach ($s in $spec) {
        $r = $Q[$s.Key]
        if ($null -eq $r) { $r = @{ Items = @(); Error = 'no result was produced' } }
        if ($r.Error) {
            if ($IsElevated) {
                $gap = $true
                [void]$state.Add($s.Key + '=gap')
                [void]$out.Add(('[WARNING] WMI ' + $s.Class + ' check NOT performed -- root\subscription could not be queried (' + (ConvertTo-PrintableText $r.Error) + '). A broken WMI repository is also a way to hide a subscription.'))
            } else {
                $deferred++
                [void]$state.Add($s.Key + '=deferred')
                [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] WMI ' + $s.Class + ' check: this token cannot query root\subscription -- re-run as administrator to check it.'))
            }
            continue
        }
        $items = @($r.Items | Where-Object { $null -ne $_ })
        if ($s.Key -eq 'filter') { $items = @($items | Where-Object { -not (Test-DefaultFilter $_) }) }
        [void]$state.Add($s.Key + '=' + $items.Count)
        if ($items.Count -eq 0) {
            switch ($s.Key) {
                'filter' { [void]$out.Add('[OK] No non-default WMI EventFilter subscriptions (default Microsoft filters allowlisted).') }
                'cmd'    { [void]$out.Add('[OK] No WMI CommandLineEventConsumer.') }
                'script' { [void]$out.Add('[OK] No WMI ActiveScriptEventConsumer.') }
            }
            continue
        }
        [void]$hits.Add($s.Hit)
        switch ($s.Key) {
            'filter' {
                [void]$out.Add('[WARNING] Non-default WMI EventFilters found:')
                foreach ($l in (Format-Table200 -Rows $items -Props @('Name', 'Query'))) { [void]$out.Add($l) }
            }
            'cmd' {
                [void]$out.Add('[WARNING] WMI CommandLine Consumers found:')
                foreach ($l in (Format-Table200 -Rows $items -Props @('Name', 'CommandLineTemplate'))) { [void]$out.Add($l) }
            }
            'script' {
                [void]$out.Add('[WARNING] WMI ActiveScript (VBScript/JScript) Consumers found:')
                $rows = @($items | ForEach-Object {
                    $txt = [string]$_.ScriptText
                    if ($txt.Length -gt 200) { $txt = $txt.Substring(0, 200) + '...[truncated]' }
                    New-Object PSObject -Property @{ Name = [string]$_.Name; ScriptingEngine = [string]$_.ScriptingEngine; ScriptText = $txt }
                })
                foreach ($l in (Format-Table200 -Rows $rows -Props @('Name', 'ScriptingEngine', 'ScriptText') -List)) { [void]$out.Add($l) }
            }
        }
    }
    return @{ Lines = @($out.ToArray()); Hits = @($hits.ToArray()); Gap = $gap; Deferred = $deferred; State = (@($state.ToArray()) -join ',') }
}

# Live: one class from root\subscription, and why it could not be queried.
function Read-WmiClass {
    param([string]$Class)
    try { return @{ Items = @(Get-WmiObject -Namespace $Namespace -Class $Class -ErrorAction Stop); Error = '' } }
    catch { return @{ Items = @(); Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) } }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function Obj { param([hashtable]$h) New-Object PSObject -Property $h }
    $none = @{ Items = @(); Error = '' }
    $scm = Obj @{ Name = 'SCM Event Log Filter'; Query = 'select * from MSFT_SCMEventLogEvent' }
    $v = Get-WmiSubscriptionVerdict -Q @{ filter = @{ Items = @($scm, (Obj @{ Name = 'BVTFilter'; Query = 'q' })); Error = '' }; cmd = $none; script = $none }
    $t = $v.Lines -join "`n"
    T 'only the default Microsoft filters: all [OK], nothing raised, the old wording kept' ($v.Hits.Count -eq 0 -and -not $v.Gap -and $v.State -eq 'filter=0,cmd=0,script=0' -and $t -match '(?m)^\[OK\] No non-default WMI EventFilter subscriptions \(default Microsoft filters allowlisted\)\.$' -and $t -match '(?m)^\[OK\] No WMI CommandLineEventConsumer\.$' -and $t -match '(?m)^\[OK\] No WMI ActiveScriptEventConsumer\.$') $t
    $v = Get-WmiSubscriptionVerdict -Q @{ filter = @{ Items = @((Obj @{ Name = 'SCM Event Log Filter'; Query = 'select * from __InstanceModificationEvent' })); Error = '' }; cmd = $none; script = $none }
    T 'a filter NAMED like the SCM default but with another query is not allowlisted' (($v.Hits -join ',') -eq 'wmi_filter_hit' -and $v.State -eq 'filter=1,cmd=0,script=0') ($v.Lines -join ' | ')
    $evil = Obj @{ Name = 'Updater'; Query = 'SELECT * FROM __InstanceModificationEvent WITHIN 60' }
    $cl = Obj @{ Name = 'UpdaterC'; CommandLineTemplate = 'powershell -enc AAAA' }
    $as = Obj @{ Name = 'UpdaterS'; ScriptingEngine = 'VBScript'; ScriptText = ('x' * 300) }
    $v = Get-WmiSubscriptionVerdict -Q @{ filter = @{ Items = @($scm, $evil); Error = '' }; cmd = @{ Items = @($cl); Error = '' }; script = @{ Items = @($as); Error = '' } }
    $t = $v.Lines -join "`n"
    T 'a planted subscription: all three WARNING with their tables and hit markers' (($v.Hits -join ',') -eq 'wmi_filter_hit,wmi_cmd_hit,wmi_script_hit' -and $v.State -eq 'filter=1,cmd=1,script=1' -and $t -match '(?m)^\[WARNING\] Non-default WMI EventFilters found:$' -and $t -match 'Updater +SELECT' -and $t -match 'powershell -enc AAAA' -and $t -match '\.\.\.\[truncated\]' -and $t -notmatch 'SCM Event Log Filter') $t
    $v = Get-WmiSubscriptionVerdict -Q @{ filter = @{ Items = @(); Error = 'COMException: Invalid namespace' }; cmd = @{ Items = @(); Error = 'COMException: Invalid namespace' }; script = @{ Items = @(); Error = 'COMException: Invalid namespace' } } -IsElevated $true
    $t = $v.Lines -join "`n"
    T 'a query that failed on an administrator token is a raised gap, never [OK] and never [SKIPPED]' ($v.Gap -and $v.Hits.Count -eq 0 -and $v.State -eq 'filter=gap,cmd=gap,script=gap' -and $t -match '(?m)^\[WARNING\] WMI EventFilter check NOT performed' -and $t -notmatch '\[OK\]' -and $t -notmatch '\[SKIPPED\]') $t
    $v = Get-WmiSubscriptionVerdict -Q @{ filter = @{ Items = @(); Error = 'UnauthorizedAccessException: denied' }; cmd = $none; script = $none } -IsElevated $false
    T 'a standard-user token that cannot query is a deferral, not a gap row' ((-not $v.Gap) -and $v.Deferred -eq 1 -and $v.State -eq 'filter=deferred,cmd=0,script=0' -and ($v.Lines -join "`n") -match '\[DEFERRED - ADMIN REQUIRED\] WMI EventFilter check') ($v.Lines -join ' | ')
    $v = Get-WmiSubscriptionVerdict -Q @{ filter = @{ Items = @($evil); Error = '' }; cmd = @{ Items = @(); Error = 'x' }; script = $none } -IsElevated $true
    T 'a finding in one class and a failed query in another: both raised, each under its own marker' (($v.Hits -join ',') -eq 'wmi_filter_hit' -and $v.Gap -and $v.State -eq 'filter=1,cmd=gap,script=0') ($v.Lines -join ' | ')
    $v = Get-WmiSubscriptionVerdict -Q @{ filter = $none } -IsElevated $true
    T 'a class that produced no result is a gap, never an [OK]' ($v.Gap -and $v.State -eq 'filter=0,cmd=gap,script=gap') ($v.Lines -join ' | ')
    $v = Get-WmiSubscriptionVerdict -Q @{ filter = @{ Items = @((Obj @{ Name = ('E' + [char]10 + '[OK] fine'); Query = 'q' })); Error = '' }; cmd = $none; script = $none }
    T 'a control character in a WMI name cannot start a report line' (@($v.Lines | Where-Object { $_ -match '^\[OK\] fine' }).Count -eq 0) ($v.Lines -join ' | ')
    if ($fails) { Write-Output "[FAIL] $fails wmi_subscription_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] wmi_subscription_check self-test: a non-default subscription is WARNING, the defaults stay allowlisted, and a query that failed is a raised gap (administrator) or a deferral (standard user), never [OK] or an unraised [SKIPPED].'
    exit 0
}

# --- live ---------------------------------------------------------------------
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 } } catch {}
}
$q = @{
    filter = (Read-WmiClass -Class '__EventFilter')
    cmd    = (Read-WmiClass -Class 'CommandLineEventConsumer')
    script = (Read-WmiClass -Class 'ActiveScriptEventConsumer')
}
$v = $null
try { $v = Get-WmiSubscriptionVerdict -Q $q -IsElevated ($Elevated -eq 1) } catch { $v = $null }
if ($null -eq $v -or [string]$v.State -notmatch '^filter=(\d+|gap|deferred),cmd=(\d+|gap|deferred),script=(\d+|gap|deferred)$') {
    'wmi_subscription_check: the grading step failed; no verdict was written.'
    exit 1
}
foreach ($l in $v.Lines) { $l }
foreach ($h in $v.Hits) { Write-Marker -Name $h -Value 'WARNING' }
if ($v.Gap) { Write-Marker -Name 'wmisub_gap' -Value 'WARNING' }
if ($v.Deferred -gt 0) { Write-Marker -Name 'wmisub_deferred' -Value ([string]$v.Deferred) }
try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII } catch {}
exit 0
