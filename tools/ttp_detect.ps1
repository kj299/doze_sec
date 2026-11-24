# ttp_detect.ps1 -- one CTI-AUTO detection, as written into
# ThreatLists\ttp_generated_checks.bat by tools\ttp_merge.ps1 and run in
# Section 18 through `call "%TTP_BLOCKS%"`.
#
# The blocks ttp_merge used to write were cmd and PowerShell one-liners:
#   file path    if exist "<v>" (echo [SEV] ...) else (echo [OK] ... check clear.)
#   named pipe   Get-ChildItem \\.\pipe\ -EA SilentlyContinue ... else '[OK] ... clear.'
#   wmi query    Get-CimInstance -Query ... -EA SilentlyContinue ... else '[OK] ... clear.'
#   registry key reg query "<v>" (no verdict at all)
#   event id     wevtutil ... | findstr "TimeCreated" "Account Name" (no verdict;
#                English labels)
#   process name Get-CimInstance ... -EA SilentlyContinue | Format-Table (no verdict)
# So a query that FAILED read "[OK] ... check clear.", a folder that refused
# us read as "the file is not there", and a hit printed [SEV] into the report
# while raising nothing: the generated file cannot reach the parent bat's
# :dz_finding, and no line wrote a marker.
#
# THE RULE (pure, in Get-TtpVerdict, pinned by -SelfTest). Each detection is
# asked with -ErrorAction Stop, and the probe says one of:
#   hit     -> [SEV] <name> ...: <what was found>, and a SEV row;
#   clear   -> [OK] <name> check clear. (it answered: nothing there);
#   unread  -> [WARNING] <name> check NOT performed -- <why>, a WARNING row;
#   denied  -> on a standard-user token, [DEFERRED - ADMIN REQUIRED], a
#              DEFERRED row the bat counts; elevated, the same as unread;
#   listed  -> event id only: the recent records are listed, [INFO], no row
#              (an event ID is a pattern to review, not an indicator).
# Rows go to -RowsFile, one per line: SEV|technique|message. The bat reads it
# after the generated file returns and raises each row in Section 18.
#
# Usage (as the generated file calls it):
#   powershell -File tools\ttp_detect.ps1 -Method "<method>" -Value "<value>" -Severity <CRITICAL|WARNING> -Id <MITRE id> -Name "<name>" -RowsFile <file>
#   powershell -File tools\ttp_detect.ps1 -SelfTest   (queries nothing)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only, except -RowsFile.

[CmdletBinding()]
param(
    [string]$Method = '',
    [string]$Value = '',
    [string]$Severity = 'WARNING',
    [string]$Id = '',
    [string]$Name = '',
    [string]$RowsFile = '',
    [int]$Elevated = -1,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# PURE. Text that goes into a report line, or a ledger row cmd parses: no
# control characters, no '|' (the row separator), no '!' or '%' (cmd
# expansion), no quotes.
function ConvertTo-SafeText {
    param([string]$s, [int]$Max = 200)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]+', ' ' -replace '[|!%"^]', '_').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

function Get-TtpTechnique {
    param([string]$Id)
    if ($Id -match '^T\d{4}(\.\d{3})?$') { return $Id }
    return 'CTIAUTO'
}

# PURE. $Probe: @{ State = hit|clear|unread|denied|listed; Detail; Error;
# Listing }. Returns @{ Lines; Row } (Row is '' when nothing is raised).
function Get-TtpVerdict {
    param([string]$Method, [string]$Name, [string]$Severity, [string]$Id, $Probe, [bool]$IsElevated = $true)
    $sev = if ($Severity -match '^(?i)critical$') { 'CRITICAL' } else { 'WARNING' }
    $nm = ConvertTo-SafeText $Name 120
    if (-not $nm) { $nm = 'CTI-AUTO ' + (ConvertTo-SafeText $Method 40) }
    $tech = Get-TtpTechnique $Id
    $st = if ($null -eq $Probe) { '' } else { [string]$Probe.State }
    $why = ConvertTo-SafeText ([string]$Probe.Error)
    switch ($st) {
        'hit' {
            return @{ Lines = @(('[' + $sev + '] ' + $nm + ' IOC found: ' + (ConvertTo-SafeText ([string]$Probe.Detail) 300))); Row = ($sev + '|' + $tech + '|' + $nm + ' - CTI-AUTO IOC match') }
        }
        'clear' {
            return @{ Lines = @(('[OK] ' + $nm + ' check clear.')); Row = '' }
        }
        'context' {
            return @{ Lines = @(('[INFO] ' + $nm + ': ' + (ConvertTo-SafeText ([string]$Probe.Detail) 300))); Row = '' }
        }
        'listed' {
            $ls = @($Probe.Listing | ForEach-Object { '  ' + (ConvertTo-SafeText ([string]$_) 200) })
            $head = if ($ls.Count) { '[INFO] ' + $nm + ': the newest ' + $ls.Count + ' matching event(s), listed for review:' } else { '[INFO] ' + $nm + ': no matching events in the log.' }
            return @{ Lines = @(@($head) + $ls); Row = '' }
        }
        'denied' {
            if (-not $IsElevated) {
                return @{ Lines = @(('[DEFERRED - ADMIN REQUIRED] ' + $nm + ' check: ' + $why + ' -- re-run as administrator to check it.')); Row = ('DEFERRED|' + $tech + '|' + $nm) }
            }
        }
    }
    if (-not $why) { $why = 'no result' }
    return @{ Lines = @(('[WARNING] ' + $nm + ' check NOT performed -- ' + $why + '.')); Row = ('WARNING|' + $tech + '|' + $nm + ' check NOT performed - the query did not answer') }
}

function Test-Denied {
    param($Err)
    $x = $Err.Exception
    while ($x) {
        if ($x -is [System.UnauthorizedAccessException] -or $x -is [System.Security.SecurityException] -or [int]$x.HResult -eq -2147024891) { return $true }
        $x = $x.InnerException
    }
    return $false
}

function Get-ErrText {
    param($Err)
    $x = $Err.Exception; if ($x.InnerException) { $x = $x.InnerException }
    return ($x.GetType().Name + ': ' + $x.Message)
}

# Keys that exist, with entries, on every Windows. A feed row naming one of
# them bare is a pattern to review, never an indicator by itself: it would
# raise on every PC. Listed by their tail, matched case-insensitively.
$script:StockKeyTails = @(
    '\Microsoft\Windows\CurrentVersion\Run', '\Microsoft\Windows\CurrentVersion\RunOnce',
    '\Microsoft\Windows\CurrentVersion\Policies\Explorer', '\Microsoft\Windows\CurrentVersion\Policies\System',
    '\Microsoft\Windows NT\CurrentVersion\Winlogon', '\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    '\Microsoft\Windows NT\CurrentVersion\Windows', '\CurrentControlSet\Services', '\CurrentControlSet\Control\Lsa',
    '\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders', '\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
    '\Microsoft\Windows\CurrentVersion\Uninstall', '\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree')

# PURE. Whether a key path is one of the stock keys above.
function Test-StockKey {
    param([string]$Path)
    $p = ([string]$Path).TrimEnd('\')
    foreach ($t in $script:StockKeyTails) { if ($p.EndsWith($t, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

# Live. One probe per method. Never throws.
function Invoke-TtpProbe {
    param([string]$Method, [string]$Value)
    $v = [Environment]::ExpandEnvironmentVariables(([string]$Value).Trim())
    switch -Regex ($Method.Trim().ToLower()) {
        '^registry key$' {
            $p = $v -replace '^(?i)HKEY_LOCAL_MACHINE\\', 'HKLM:\' -replace '^(?i)HKLM\\', 'HKLM:\' -replace '^(?i)HKEY_CURRENT_USER\\', 'HKCU:\' -replace '^(?i)HKCU\\', 'HKCU:\'
            if ($p -notmatch '^(HKLM|HKCU):\\') { return @{ State = 'unread'; Error = ('the key must start HKLM\ or HKCU\: ' + $v) } }
            try { $k = Get-Item -LiteralPath $p -ErrorAction Stop }
            catch {
                if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { return @{ State = 'clear' } }
                return @{ State = $(if (Test-Denied $_) { 'denied' } else { 'unread' }); Error = (Get-ErrText $_) }
            }
            # An empty key is what Windows leaves behind once its values are
            # gone (the PortProxy lesson): it is not the indicator.
            $n = [int]$k.ValueCount + [int]$k.SubKeyCount
            if ($n -le 0) { return @{ State = 'clear' } }
            if (Test-StockKey $p) { return @{ State = 'context'; Detail = ($v + ' is a key every Windows has (' + $n + ' entr(ies)); naming it bare says nothing about this PC -- its entries are graded elsewhere in the audit') } }
            return @{ State = 'hit'; Detail = ($v + ' exists, ' + $n + ' entr(ies)') }
        }
        '^process name$' {
            try { $ps = @(Get-CimInstance Win32_Process -Filter ("Name='" + $v + "'") -ErrorAction Stop) }
            catch { return @{ State = 'unread'; Error = (Get-ErrText $_) } }
            # The audit's own processes are not an indicator: a feed row naming
            # powershell.exe or cmd.exe would otherwise match the audit itself.
            $own = @($PID)
            try { $pp = (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $PID) -ErrorAction Stop).ParentProcessId; for ($i = 0; $i -lt 6 -and $pp; $i++) { $own += $pp; $pp = (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $pp) -ErrorAction Stop).ParentProcessId } } catch {}
            $ps = @($ps | Where-Object { $own -notcontains [int]$_.ProcessId })
            if (-not $ps.Count) { return @{ State = 'clear' } }
            # A Windows program running from the Windows folder under its own
            # name says nothing by its name alone; it is listed as context.
            $win = @(); $other = @()
            foreach ($q in $ps) {
                $ep = [string]$q.ExecutablePath; $isWin = $false
                if ($ep -and $env:SystemRoot -and $ep.StartsWith(($env:SystemRoot.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
                    try { $sg = Get-AuthenticodeSignature -LiteralPath $ep -ErrorAction Stop; $isWin = ($sg.Status -eq 'Valid' -and [string]$sg.SignerCertificate.Subject -match 'O=Microsoft Corporation') } catch {}
                }
                if ($isWin) { $win += $q } else { $other += $q }
            }
            $fmt = { param($q) [string]$q.Name + ' PID ' + [string]$q.ProcessId + $(if ($q.ExecutablePath) { ' ' + [string]$q.ExecutablePath } else { ' (path not visible to this token)' }) }
            if ($other.Count) { return @{ State = 'hit'; Detail = ((@($other | Select-Object -First 5 | ForEach-Object { & $fmt $_ })) -join '; ') } }
            return @{ State = 'context'; Detail = ([string]$win.Count + ' Microsoft-signed Windows process(es) by that name, running from the Windows folder -- a name alone is not an indicator: ' + ((@($win | Select-Object -First 3 | ForEach-Object { & $fmt $_ })) -join '; ')) }
        }
        '^file path$' {
            $why = ''
            try { $null = [IO.File]::GetAttributes($v); return @{ State = 'hit'; Detail = $v } } catch { $why = (Get-ErrText $_) }
            $dir = [IO.Path]::GetDirectoryName($v); $leaf = [IO.Path]::GetFileName($v)
            if (-not $dir -or -not $leaf) { return @{ State = 'unread'; Error = ('not a full path: ' + $v) } }
            try { $names = @([IO.Directory]::GetFileSystemEntries($dir) | ForEach-Object { [IO.Path]::GetFileName($_) }) }
            catch [System.IO.DirectoryNotFoundException] { return @{ State = 'clear' } }
            catch { return @{ State = $(if (Test-Denied $_) { 'denied' } else { 'unread' }); Error = ($dir + ' could not be listed: ' + (Get-ErrText $_)) } }
            if ($names -contains $leaf) { return @{ State = 'hit'; Detail = ($v + ' (its folder lists it, but it could not be opened by name: ' + $why + ')') } }
            return @{ State = 'clear' }
        }
        '^named pipe$' {
            # Get-ChildItem degrades per entry; [IO.Directory]::GetFiles fails
            # the whole list on one pipe name .NET does not accept.
            $pe = $null
            $pipes = @(Get-ChildItem -LiteralPath '\\.\pipe\' -EA SilentlyContinue -ErrorVariable pe | ForEach-Object { [string]$_.Name })
            if (-not $pipes.Count -and $pe) { return @{ State = 'unread'; Error = ('the named-pipe list could not be read: ' + (Get-ErrText $pe[0])) } }
            if ($pipes.Count -eq 0) { return @{ State = 'unread'; Error = 'the named-pipe list came back empty, and Windows always has some' } }
            $m = @()
            try { $m = @($pipes | Where-Object { $_ -match $v }) } catch { $m = @($pipes | Where-Object { $_.IndexOf($v, [StringComparison]::OrdinalIgnoreCase) -ge 0 }) }
            if ($m.Count) { return @{ State = 'hit'; Detail = ((@($m | Select-Object -First 10)) -join ', ') } }
            return @{ State = 'clear' }
        }
        '^wmi query$' {
            try { $r = @(Get-CimInstance -Query $v -ErrorAction Stop) }
            catch { return @{ State = 'unread'; Error = (Get-ErrText $_) } }
            if ($r.Count) { return @{ State = 'hit'; Detail = ([string]$r.Count + ' instance(s): ' + ((@($r | Select-Object -First 3 | ForEach-Object { ($_ | Out-String).Trim() -replace '\s+', ' ' })) -join ' / ')) } }
            return @{ State = 'clear' }
        }
        '^event id$' {
            $eid = 0
            if (-not [int]::TryParse($v, [ref]$eid)) { return @{ State = 'unread'; Error = ('not an event ID: ' + $v) } }
            # Opened by name first: a log this token may not read answers the
            # filtered query with "no matching events" (account_events_check).
            try { $null = Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop }
            catch {
                if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { return @{ State = $(if (Test-Denied $_) { 'denied' } else { 'unread' }); Error = ('the Security log could not be read: ' + (Get-ErrText $_)) } }
            }
            try { $evts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $eid } -MaxEvents 10 -ErrorAction Stop) }
            catch {
                if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { return @{ State = 'listed'; Listing = @() } }
                return @{ State = $(if (Test-Denied $_) { 'denied' } else { 'unread' }); Error = ('the Security log could not be read: ' + (Get-ErrText $_)) }
            }
            $ls = @($evts | ForEach-Object { $msg = ''; try { $msg = (([string]$_.Message) -split "`n")[0] } catch {}; $_.TimeCreated.ToString('s') + '  ' + $msg })
            return @{ State = 'listed'; Listing = $ls }
        }
    }
    return @{ State = 'unread'; Error = ('unknown detection method: ' + $Method) }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$N, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $N" } else { Write-Output "[FAIL] $N$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    function V { param($P, [string]$Sev = 'CRITICAL', [bool]$Adm = $true, [string]$Id = 'T1055')
        $v = Get-TtpVerdict -Method 'file path' -Name 'Evil Loader' -Severity $Sev -Id $Id -Probe $P -IsElevated $Adm; @{ V = $v; T = ($v.Lines -join "`n") } }
    $x = V @{ State = 'hit'; Detail = 'C:\ProgramData\evil.dll' }
    T 'a hit prints its severity and raises a row at that severity' ($x.T -eq '[CRITICAL] Evil Loader IOC found: C:\ProgramData\evil.dll' -and $x.V.Row -eq 'CRITICAL|T1055|Evil Loader - CTI-AUTO IOC match') $x.T
    $x = V @{ State = 'clear' }
    T 'an answer of nothing there is the [OK] the blocks always printed, and no row' ($x.T -eq '[OK] Evil Loader check clear.' -and -not $x.V.Row) $x.T
    $x = V @{ State = 'unread'; Error = 'UnauthorizedAccessException: Access to the path is denied.' }
    T 'a query that did not answer is a raised gap, never "check clear" (the defect)' ($x.T -match '^\[WARNING\] Evil Loader check NOT performed -- UnauthorizedAccessException' -and $x.T -notmatch '\[OK\]' -and $x.V.Row -like 'WARNING|T1055|*NOT performed*') $x.T
    $x = V @{ State = 'denied'; Error = 'denied' } 'CRITICAL' $false
    T 'refused on a standard-user token: a counted deferral, not a row' ($x.T -match '^\[DEFERRED - ADMIN REQUIRED\] ' -and $x.V.Row -like 'DEFERRED|*') $x.T
    $x = V @{ State = 'denied'; Error = 'denied' } 'CRITICAL' $true
    T 'refused to an administrator: a gap, the token does not explain it' ($x.V.Row -like 'WARNING|*') $x.T
    $x = V @{ State = 'hit'; Detail = 'x' } 'bogus'
    T 'a severity the feed spelled oddly is WARNING, never an empty tag' ($x.T -like '`[WARNING`]*' -and $x.V.Row -like 'WARNING|*') $x.T
    $x = V @{ State = 'hit'; Detail = 'x' } 'WARNING' $true 'not-an-id'
    T 'an ID that is not a technique ID files under CTIAUTO' ($x.V.Row -like 'WARNING|CTIAUTO|*') $x.V.Row
    $v = Get-TtpVerdict -Method 'file path' -Name ('bad|"name!' + [char]10 + '[OK] x') -Severity 'WARNING' -Id 'T1' -Probe @{ State = 'hit'; Detail = 'd' }
    T 'a name cannot break the row (|) or cmd (! % quotes) or forge a line' (($v.Row -split '\|').Count -eq 3 -and $v.Row -notmatch '[!"%]' -and ($v.Lines -join "`n") -notmatch '(?m)^\[OK\] x') $v.Row
    $v = Get-TtpVerdict -Method 'event id' -Name 'Log cleared' -Severity 'CRITICAL' -Id 'T1070.001' -Probe @{ State = 'listed'; Listing = @('2026-11-24T01:00:00  The audit log was cleared.') }
    T 'event ID records are listed for review, never raised' ((-not $v.Row) -and ($v.Lines -join ' ') -match '^\[INFO\] Log cleared: the newest 1 matching event') ($v.Lines -join ' | ')
    $v = Get-TtpVerdict -Method 'event id' -Name 'Log cleared' -Severity 'CRITICAL' -Id 'T1070.001' -Probe @{ State = 'unread'; Error = 'EventLogException' }
    T 'an event log that could not be read is a gap' ($v.Row -like 'WARNING|T1070.001|*') ($v.Lines -join ' | ')
    $v = Get-TtpVerdict -Method 'process name' -Name 'Shell' -Severity 'CRITICAL' -Id 'T1059' -Probe @{ State = 'context'; Detail = '3 Microsoft-signed Windows process(es) by that name' }
    T 'a Windows program running under its own name is context, never a CRITICAL on every PC' ((-not $v.Row) -and ($v.Lines -join ' ') -match '^\[INFO\] Shell: ') ($v.Lines -join ' | ')
    T 'a feed row naming a stock key (Run) is context, not an indicator' ((Test-StockKey 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run') -and (Test-StockKey 'HKLM:\SYSTEM\CurrentControlSet\Services\')) ''
    T 'a key that is not a stock key is graded' (-not (Test-StockKey 'HKCU:\Software\EvilCorp\Loader')) ''
    T 'a key BELOW a stock key is graded (a Run subkey an attacker made is not the stock key)' (-not (Test-StockKey 'HKLM:\SYSTEM\CurrentControlSet\Services\EvilSvc')) ''
    $p = Invoke-TtpProbe -Method 'carrier pigeon' -Value 'x'
    T 'an unknown method is a gap, never a silent pass' ($p.State -eq 'unread') ([string]$p.Error)
    $p = Invoke-TtpProbe -Method 'registry key' -Value 'HKU\.DEFAULT\x'
    T 'a registry key outside HKLM and HKCU is said, never skipped' ($p.State -eq 'unread' -and $p.Error -match 'must start HKLM') ([string]$p.Error)
    $p = Invoke-TtpProbe -Method 'event id' -Value 'abc'
    T 'an event ID that is not a number is a gap' ($p.State -eq 'unread') ([string]$p.Error)
    if ($fails) { Write-Output "[FAIL] $fails ttp_detect self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] ttp_detect self-test: a hit is raised at its severity, nothing there is [OK], and a query that did not answer is a raised gap (or a counted deferral on a standard-user token), never "check clear".'
    exit 0
}

if (-not $Method) { 'ttp_detect: -Method is required.'; exit 1 }
if ($Elevated -lt 0) {
    $Elevated = 0
    try { if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.SecurityIdentifier]'S-1-5-32-544')) { $Elevated = 1 } } catch {}
}
$probe = $null
try { $probe = Invoke-TtpProbe -Method $Method -Value $Value } catch { $probe = @{ State = 'unread'; Error = ('the probe failed: ' + $_.Exception.Message) } }
$v = Get-TtpVerdict -Method $Method -Name $Name -Severity $Severity -Id $Id -Probe $probe -IsElevated ($Elevated -eq 1)
foreach ($l in $v.Lines) { $l }
if ($v.Row -and $RowsFile) {
    try { Add-Content -LiteralPath $RowsFile -Value $v.Row -Encoding ASCII -ErrorAction Stop }
    catch { ('[WARNING] ' + (ConvertTo-SafeText $Name 120) + ': this result could not be recorded for the findings ledger (' + $_.Exception.Message + ').') }
}
exit 0
