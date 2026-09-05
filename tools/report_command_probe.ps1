# report_command_probe.ps1 -- RUN the commands the report tells a reader to run.
#
# WHY: tools/lint_report_echo.ps1 proves every printed `Command:` line PARSES.
# Parsing is not running. This project has already paid for that distinction
# once: two remediation commands parsed cleanly and could never execute
# (`\$false` reached disk as `\False`; a `$_`/`$ms` block became a parse error
# that voided the whole file). #195 then rewrote 22 `Command:` lines per bat
# against what each check actually does, verified only with ParseInput. The
# strongest honest claim was "syntactically valid PowerShell". This closes that.
#
# WHAT IT IS NOT: this proves a printed command is WELL-FORMED AND INVOCABLE.
# It does not prove the machine has the data the command looks for. Finding
# nothing is success -- "no Defender exclusions configured" is the healthy
# answer -- and a missing path, absent service, absent log or absent optional
# module is machine state, not a defect in the printed line. Read that boundary
# before trusting a green run for more than it says.
#
# SAFETY: this executes text extracted from a generated report. It is safe
# because of an ALLOWLIST, never because the text is trusted. A deny-list
# misses what it has not seen, and that is the wrong shape for the one part of
# this tool that can touch a machine. Six printed lines across the two bats are
# genuinely not read-only -- the RunOnce `reg add`, the `ping`, and the
# self-update `Invoke-WebRequest`, all of which honestly document the audit's
# own INIT actions and are already gated by `-readonly`. Those are skipped by
# name. Anything this probe cannot PROVE is read-only is never executed.
#
# A line it cannot classify at all is a FAILURE, not a skip: silence there
# would be exactly the vacuous pass this repo keeps building gates against.
#
# Windows PowerShell 5.1 and pwsh. Output goes to the SUCCESS stream so CI can
# assert on it (Write-Host would be invisible to `$out = (...)`).

[CmdletBinding()]
param(
    [string]$Report,
    [int]$TimeoutSeconds = 8,
    [int]$BudgetSeconds = 420,
    [int]$MinProbed = 120,   # the real run executes 136; see readonly-field-test
    [switch]$ClassifyOnly,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

# --- Read-only allowlists -------------------------------------------------
# Every PowerShell command name the printed payloads may invoke. Derived by
# walking the AST of all 126 printed payloads, then vetted by hand: each is a
# pure query. A name absent here is never executed.
$script:OkCmdlets = @(
    'Confirm-SecureBootUEFI','ConvertFrom-Csv','ForEach-Object','Format-List','Format-Table',
    'Get-AuthenticodeSignature','Get-BitLockerVolume','Get-ChildItem','Get-CimInstance',
    'Get-Content','Get-Date','Get-ExecutionPolicy','Get-HotFix','Get-Item','Get-ItemProperty',
    'Get-LocalUser','Get-MpComputerStatus','Get-MpPreference','Get-MpThreatDetection',
    'Get-NetFirewallProfile','Get-PhysicalDisk','Get-Process','Get-Service',
    'Get-SmbServerConfiguration','Get-WindowsOptionalFeature','Get-WinEvent','Get-WMIObject',
    'Join-Path','Measure-Object','Select-Object','Sort-Object','Test-Path','Where-Object','Write-Output'
)
# New-Object can construct anything, so it is allowed only for the exact COM
# object the update-history check reads.
$script:OkComObjects = @('Microsoft.Update.AutoUpdate')
# Native filters that legitimately appear inside a printed PowerShell pipeline.
$script:OkNativeInPipeline = @('findstr','sort','more','select_lines.ps1','schtasks')

# Native programs, allowed only with a read-only verb.
$script:OkNative = @{
    'reg'      = @('query')
    'sc'       = @('query','qc')
    'sc.exe'   = @('query','qc')
    'net'      = @('user','localgroup','share','accounts','session')
    'netsh'    = @('advfirewall','interface','wlan')      # further gated on 'show' below
    'wevtutil' = @('qe','el','gli')
    'schtasks' = @('/query')
    'bcdedit'  = @('/enum')
    'netstat'  = @()
    'ipconfig' = @()
    'arp'      = @()
    'route'    = @('print')
    'type'     = @()
    'dir'      = @()
    'findstr'  = @()
    'whoami'   = @()
    'forfiles' = @()                                       # gated on its /c payload below
}
# Printed lines that honestly document a change the audit itself makes. Never
# executed. Each must match something, or the entry is stale and this fails.
$script:KnownMutating = @(
    @{ Match = 'reg add';          Why = 'the RunOnce resume key the audit writes at INIT 8 (gated by -readonly)' },
    @{ Match = 'ping -n';          Why = 'the INIT 9 connectivity probe (gated by -readonly)' },
    @{ Match = 'Invoke-WebRequest';Why = 'the INIT 10 self-update check (gated by -readonly)' }
)
# Printed lines that describe a check rather than invoke it. Legitimate prose;
# each must match something, or the entry is stale and this fails.
$script:KnownDescriptive = @(
    @{ Match = 'powershell evaluates';        Why = 'prose: names the two cmdlets the Defender block evaluates' },
    @{ Match = 'powershell reads VBAWarnings';Why = 'prose: names the values read per Office application' },
    @{ Match = 'select_lines.ps1';            Why = 'abbreviated pipeline: the printed pattern list ends in an ellipsis' },
    @{ Match = 'findstr /i vpn-client-names'; Why = 'abbreviated: stands in for the generated VPN name list' }
)
# Repo helper scripts. Read-only, but executed by the helpers-ps51 job against
# real WMI/CIM already; re-running them here would duplicate that at cost.
$script:HelperPattern = '(?i)(^|\s)(powershell[^"]*\s)?-?-?File?\s*tools\\[a-z0-9_]+\.ps1|(?i)^tools\\[a-z0-9_]+\.ps1'

# Runtime output that means the PRINTED LINE is malformed. Missing commands,
# paths, services, logs and modules are machine state and are tolerated.
$script:MalformedSignals = @(
    'A parameter cannot be found that matches parameter name',
    'Cannot bind parameter',
    'Missing an argument for parameter',
    'Unexpected token',
    'Missing closing',
    'The string is missing the terminator',
    'The specified query is invalid',
    'Failed to process query',
    'The syntax of this command is',
    'Invalid syntax',
    'ERROR: Invalid'
)

function Get-ReportCommands {
    param([string]$Path)
    $out = @()
    $n = 0
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $n++
        $m = [regex]::Match($line, '^\s*Command:\s*(\S.*?)\s*$')
        if ($m.Success) { $out += [pscustomobject]@{ Line = $n; Text = $m.Groups[1].Value } }
    }
    return $out
}

function Get-Classification {
    # -> @{ Action = 'exec-ps'|'exec-native'|'skip'|'fail'; Payload; Reason }
    param([string]$Text)

    # A trailing "   [note]" is documentation appended to the printed line, not
    # part of the command. The powershell form already tolerated it in its
    # regex; a native line did not, so `reg query "...\Attachments" /v X
    # [also the HKLM twin]` handed reg the note as arguments and it answered
    # "ERROR: Invalid syntax." Strip it once, here, for every form.
    $Text = [regex]::Replace($Text, '\s{2,}\[[^\]]*\]\s*$', '')

    # An elided command cannot be run as printed. Catching this statically
    # matters because the runtime signal is not reliable: `reg query
    # "...\Policies\Attachments"` has no hive and reports "Invalid key name"
    # (malformed), while `reg query "HKLM\...\Explorer"` parses `...` as a real
    # subkey name and reports "unable to find the specified registry key",
    # which is correctly tolerated as machine state. Same defect, different
    # wording -- so the ellipsis itself is the test, not the error text.
    if ($Text -match '\.\.\.') {
        $described = $false
        foreach ($k in $script:KnownDescriptive) {
            if ($Text -like ('*' + $k.Match + '*')) { $k.Hit = $true; $described = $true; break }
        }
        if (-not $described) {
            return @{ Action = 'fail'; Reason = "elided with '...' -- the reader cannot run this as printed; print the real path, or add it to `$KnownDescriptive if it is deliberately abbreviated prose" }
        }
        return @{ Action = 'skip'; Reason = 'not an invocation -- deliberately abbreviated, and catalogued as such' }
    }

    foreach ($k in $script:KnownMutating) {
        if ($Text -like ('*' + $k.Match + '*')) {
            $k.Hit = $true
            return @{ Action = 'skip'; Reason = "not read-only -- $($k.Why)" }
        }
    }
    foreach ($k in $script:KnownDescriptive) {
        if ($Text -like ('*' + $k.Match + '*')) {
            $k.Hit = $true
            return @{ Action = 'skip'; Reason = "not an invocation -- $($k.Why)" }
        }
    }
    if ($Text -match $script:HelperPattern) {
        return @{ Action = 'skip'; Reason = 'repo helper script -- executed by the helpers-ps51 job against real WMI/CIM' }
    }

    # smartctl, invoked by absolute path, read-only flags only.
    if ($Text -match '(?i)^"?[^"]*smartctl\.exe"?\s') {
        if ($Text -match '(?i)\s(--scan|-H|--health|-i|--info|-A)\b') { return @{ Action = 'exec-native'; Payload = $Text } }
        return @{ Action = 'fail'; Reason = 'smartctl invoked with a flag outside the read-only set' }
    }

    # powershell -Command "<payload>"   [optional bracketed note], or a bare
    # `powershell <expr>` whose output cmd then pipes onward.
    $pm = [regex]::Match($Text, '^powershell(?:\.exe)?(?:\s+-Command)?\s+"(.*)"(?:\s{2,}\[.*\])?$')
    if (-not $pm.Success) {
        $um = [regex]::Match($Text, '^powershell(?:\.exe)?\s+([A-Z][a-zA-Z]+-[A-Za-z]+\s.*)$')
        if ($um.Success) { $pm = $um }
    }
    if ($pm.Success) {
        $payload = $pm.Groups[1].Value
        $errs = $null; $toks = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($payload, [ref]$toks, [ref]$errs)
        if ($errs -and $errs.Count) {
            return @{ Action = 'fail'; Reason = "printed payload does not parse -- $($errs[0].Message)" }
        }
        foreach ($c in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $name = $c.GetCommandName()
            if (-not $name) { continue }
            if ($name -eq 'New-Object') {
                $txt = $c.Extent.Text
                $okCom = $false
                foreach ($com in $script:OkComObjects) { if ($txt -like ("*-ComObject*" + $com + "*")) { $okCom = $true } }
                if (-not $okCom) {
                    return @{ Action = 'fail'; Reason = "New-Object constructing something outside the vetted COM allowlist -- $txt" }
                }
                continue
            }
            if ($script:OkNativeInPipeline -contains $name) { continue }
            if ($script:OkCmdlets -notcontains $name) {
                return @{ Action = 'fail'; Reason = "'$name' is not in the read-only allowlist -- either the printed line is wrong, or add it to `$OkCmdlets after checking what it does" }
            }
        }
        return @{ Action = 'exec-ps'; Payload = $payload }
    }

    # native program
    $tokens = $Text -split '\s+'
    $head = ($tokens[0] -replace '^"|"$', '').ToLowerInvariant()
    if ($script:OkNative.ContainsKey($head)) {
        $verbs = $script:OkNative[$head]
        if ($verbs.Count -gt 0) {
            $verb = if ($tokens.Count -gt 1) { $tokens[1].ToLowerInvariant() } else { '' }
            if ($verbs -notcontains $verb) {
                return @{ Action = 'fail'; Reason = "'$head $verb' is not a read-only verb for $head" }
            }
        }
        if ($head -eq 'netsh' -and $Text -notmatch '(?i)\sshow\s') {
            return @{ Action = 'fail'; Reason = 'netsh without a "show" verb cannot be proven read-only' }
        }
        if ($head -eq 'forfiles' -and $Text -notmatch '(?i)/c\s+"cmd /c echo') {
            return @{ Action = 'fail'; Reason = 'forfiles /c runs an arbitrary command; only "cmd /c echo ..." is allowed' }
        }
        return @{ Action = 'exec-native'; Payload = $Text }
    }

    return @{ Action = 'fail'; Reason = "unrecognised command '$head' -- if this line is prose it should not be labelled Command:, otherwise teach the allowlist what it is" }
}

function Invoke-Probe {
    param([string]$Kind, [string]$Payload, [int]$Timeout)
    # Defence in depth. The caller decides what may run; if a control-flow slip
    # ever routes a refused line here, it must die loudly rather than execute.
    # This is not hypothetical: `continue` inside a PowerShell `switch` leaves
    # the switch, NOT the enclosing loop, so an earlier version fell through
    # after deciding to SKIP the RunOnce `reg add` and tried to run it.
    if ($Kind -ne 'exec-ps' -and $Kind -ne 'exec-native') {
        throw "Invoke-Probe refused kind '$Kind' -- only a classified execute decision may run"
    }
    $psExe = if ($IsLinux -or $IsMacOS) { 'pwsh' } else { 'powershell' }
    # GetTempFileName() creates the file it names, so appending an extension
    # would strand the original on every probe -- hundreds of them over a run.
    $stem = Join-Path ([System.IO.Path]::GetTempPath()) ('dz_probe_' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    if ($Kind -eq 'exec-ps') {
        $file = "$stem.ps1"
        Set-Content -LiteralPath $file -Value $Payload
        $exe = $psExe; $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $file)
    } else {
        $file = "$stem.cmd"
        Set-Content -LiteralPath $file -Value "@echo off`r`n$Payload"
        $exe = $env:ComSpec; if (-not $exe) { $exe = 'cmd.exe' }
        $argList = @('/c', $file)
    }
    $so = "$stem.out"; $se = "$stem.err"
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $argList -NoNewWindow -PassThru `
                           -RedirectStandardOutput $so -RedirectStandardError $se
        if (-not $p.WaitForExit($Timeout * 1000)) {
            try { $p.Kill() } catch { }
            return @{ Status = 'slow'; Detail = "no result within ${Timeout}s" }
        }
        $text = ((Get-Content -LiteralPath $so -Raw -EA SilentlyContinue) + "`n" +
                 (Get-Content -LiteralPath $se -Raw -EA SilentlyContinue))
        foreach ($sig in $script:MalformedSignals) {
            if ($text -like ('*' + $sig + '*')) {
                $line = @($text -split "`n" | Where-Object { $_ -like ('*' + $sig + '*') })[0]
                return @{ Status = 'fail'; Detail = $line.Trim() }
            }
        }
        return @{ Status = 'ok'; Detail = '' }
    } finally {
        Remove-Item -LiteralPath $file, $so, $se -Force -EA SilentlyContinue
    }
}

function Invoke-ProbeRun {
    # -Classify runs the allowlist gate WITHOUT executing anything. It answers
    # "is every printed line something this probe can account for", which is
    # the half that works off Windows; it is never a substitute for the run.
    #
    # $Budget caps total wall-clock. Per-command timeouts alone are not enough:
    # a run that went from 3 slow commands to 29 on an identical tree took the
    # probe from 2.5 to 8.7 minutes, and the worst case would blow the job's
    # own timeout and look like a hang. On exhaustion the remaining commands
    # are DECLARED un-probed and counted, never silently dropped.
    param([string]$ReportPath, [int]$Timeout, [int]$Floor, [int]$Budget = 0, [switch]$Classify)
    $clock = [System.Diagnostics.Stopwatch]::StartNew()

    $cmds = @(Get-ReportCommands -Path $ReportPath)
    $bad = @(); $nExec = 0; $nSkip = 0; $nSlow = 0; $nUnprobed = 0
    foreach ($c in $cmds) {
        $cls = Get-Classification -Text $c.Text
        # if/continue, never `switch`/`continue`: see the note in Invoke-Probe.
        if ($cls.Action -eq 'skip') { $nSkip++; continue }
        if ($cls.Action -eq 'fail') {
            $bad += "report line $($c.Line): $($cls.Reason) -- from: $($c.Text)"
            Write-Output ("[FAIL ] line {0}: {1}" -f $c.Line, $cls.Reason)
            continue
        }
        if ($Classify) { $nExec++; continue }
        if ($Budget -gt 0 -and $clock.Elapsed.TotalSeconds -gt $Budget) { $nUnprobed++; continue }
        $r = Invoke-Probe -Kind $cls.Action -Payload $cls.Payload -Timeout $Timeout
        if ($r.Status -eq 'ok')   { $nExec++ }
        if ($r.Status -eq 'slow') { $nSlow++; $nExec++; Write-Output ("[SLOW ] line {0}: {1}" -f $c.Line, $r.Detail) }
        if ($r.Status -eq 'fail') {
            $bad += "report line $($c.Line): $($r.Detail) -- from: $($c.Text)"
            Write-Output ("[FAIL ] line {0}: {1}" -f $c.Line, $r.Detail)
            Write-Output ("         printed as: {0}" -f $c.Text)
        }
    }

    foreach ($k in ($script:KnownMutating + $script:KnownDescriptive)) {
        if (-not $k.Hit) { $bad += "stale exemption '$($k.Match)' matched nothing -- remove it or fix the line it was written for" }
        else { Write-Output ("[SKIP ] {0} -- {1}" -f $k.Match, $k.Why) }
    }
    if ($cmds.Count -eq 0) { $bad += "no 'Command:' lines found in $ReportPath -- the extractor is broken, not the report" }
    if ($nUnprobed -gt 0) {
        Write-Output ("[BUDGET] {0} command(s) NOT probed -- the {1}s wall-clock budget ran out. This is missing coverage, not a pass." -f $nUnprobed, $Budget)
    }
    if ($nExec -lt $Floor) { $bad += "only $nExec command(s) actually executed (floor $Floor) -- a clean result means nothing" }

    return @{ Bad = $bad; Total = $cmds.Count; Exec = $nExec; Skip = $nSkip; Slow = $nSlow; Unprobed = $nUnprobed }
}

if ($SelfTest) {
    # A probe that cannot fail is not a probe. Every case must land where stated.
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('dz_probe_fixture_' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '.txt')
    $fixture = @(
        ' Command: powershell -Command "Get-Date | Select-Object -First 1"',
        ' Command: powershell -Command "Get-Date -NoSuchSwitchZZ"',
        ' Command: powershell -Command "Remove-Item C:\important"',
        ' Command: reg add "HKCU\Software\Zzz" /v x /t REG_SZ /d y /f',
        ' Command: powershell evaluates Get-MpComputerStatus + Get-MpPreference',
        ' Command: powershell reads VBAWarnings + blockcontentexecutionfrominternet per Office app',
        ' Command: Get-CimInstance Win32_Process | select_lines.ps1 mshta ...',
        ' Command: Get-CimInstance Win32_Process | findstr /i vpn-client-names',
        ' Command: ping -n 1 -w 2000 8.8.8.8',
        ' Command: Invoke-WebRequest http://example.invalid/version.txt',
        ' Command: frobnicate --all',
        ' Command: reg query "...\Policies\Attachments" /v SaveZoneInformation',
        ' Command: reg query "HKLM\...\Explorer" /v SmartScreenEnabled',
        ' Command: powershell -Command "Get-Date -NoSuchSwitchYY"   [a bracket note must not become an argument]'
    )
    Set-Content -LiteralPath $tmp -Value $fixture
    foreach ($k in ($script:KnownMutating + $script:KnownDescriptive)) { $k.Remove('Hit') | Out-Null }
    $r = Invoke-ProbeRun -ReportPath $tmp -Timeout 20 -Floor 1
    Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue

    $expect = @(
        @{ Need = 'Get-Date -NoSuchSwitchZZ|parameter cannot be found|Cannot bind|Missing an argument'; Why = 'a malformed switch must FAIL at runtime' },
        @{ Need = "'Remove-Item' is not in the read-only allowlist";                                    Why = 'a mutating cmdlet must be refused, never executed' },
        @{ Need = "unrecognised command 'frobnicate'";                                                 Why = 'an unclassifiable line must FAIL, not skip silently' },
        @{ Need = "elided with.*Policies.Attachments";                                                 Why = 'an elided path reg reports as "Invalid key name" must FAIL' },
        @{ Need = "elided with.*HKLM.*Explorer";                                                       Why = 'an elided path reg only reports as "key not found" must FAIL too' },
        @{ Need = "NoSuchSwitchYY|parameter cannot be found|Cannot bind|Missing an argument";                  Why = 'a line with a trailing [note] still runs the command, and its own defect is caught' }
    )
    $fail = 0
    foreach ($e in $expect) {
        if (@($r.Bad | Where-Object { $_ -match $e.Need }).Count -gt 0) {
            Write-Output "[OK]   caught: $($e.Why)"
        } else {
            Write-Output "[FAIL] NOT caught: $($e.Why)"; $fail++
        }
    }
    # The mutating and descriptive lines must have been skipped, not run.
    if ($r.Skip -lt 6) { Write-Output "[FAIL] expected >= 6 skips (mutating + descriptive); got $($r.Skip)"; $fail++ }
    else { Write-Output "[OK]   $($r.Skip) line(s) skipped without execution (mutating + descriptive)" }
    if ($r.Exec -lt 1) { Write-Output "[FAIL] the good command never executed -- the probe is vacuous"; $fail++ }
    else { Write-Output "[OK]   $($r.Exec) command(s) actually executed" }

    # Pin the defence-in-depth guard directly. A `continue` inside a PowerShell
    # `switch` leaves the switch, not the loop, and an earlier version of this
    # file fell through after deciding to SKIP the RunOnce `reg add` and tried
    # to execute it. On Linux that died for want of cmd.exe; on Windows it
    # would have written the key. Nothing refused may ever reach Invoke-Probe.
    $threw = $false
    try { Invoke-Probe -Kind 'skip' -Payload 'reg add HKCU\Software\Zzz /f' -Timeout 5 | Out-Null }
    catch { $threw = $true }
    if ($threw) { Write-Output "[OK]   Invoke-Probe refuses a non-execute decision outright" }
    else { Write-Output "[FAIL] Invoke-Probe accepted a refused line -- a skip could still execute"; $fail++ }

    if ($fail) { Write-Output "[FAIL] $fail self-test expectation(s) unmet"; exit 1 }
    Write-Output "[OK] report_command_probe self-test: malformed FAILS, mutating is refused, unclassifiable FAILS, good runs."
    exit 0
}

if (-not $Report) { Write-Output '[FAIL] -Report <path> is required (or -SelfTest)'; exit 1 }
if (-not (Test-Path -LiteralPath $Report)) { Write-Output "[FAIL] report not found: $Report"; exit 1 }

$res = Invoke-ProbeRun -ReportPath $Report -Timeout $TimeoutSeconds -Floor $MinProbed -Budget $BudgetSeconds -Classify:$ClassifyOnly
$verb = if ($ClassifyOnly) { 'classified as runnable' } else { 'executed' }
Write-Output ("-- {0} 'Command:' line(s): {1} {2}, {3} skipped, {4} slow, {5} not probed" -f $res.Total, $res.Exec, $verb, $res.Skip, $res.Slow, $res.Unprobed)
if (-not $ClassifyOnly -and $res.Slow -gt 0) {
    Write-Output ("   ({0} counted as executed: argument binding and syntax errors surface in the first moments, so a command still working at {1}s has already shown it is well-formed.)" -f $res.Slow, $TimeoutSeconds)
}
if ($res.Bad.Count) {
    Write-Output ("[FAIL] {0} printed command(s) the reader could not run:" -f $res.Bad.Count)
    $res.Bad | ForEach-Object { Write-Output ("  - " + $_) }
    exit 1
}
if ($ClassifyOnly) {
    Write-Output ("[OK] every printed command is accounted for: {0} provably read-only, {1} skipped by name. NOTHING WAS EXECUTED -- this is the gate, not the run." -f $res.Exec, $res.Skip)
    exit 0
}
Write-Output ("[OK] every printed command this probe could prove read-only actually runs: {0} executed, {1} skipped by name, {2} slow." -f $res.Exec, $res.Skip, $res.Slow)
exit 0
