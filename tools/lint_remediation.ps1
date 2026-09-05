# lint_remediation.ps1 -- the remediation script is the only artifact this tool
# hands a person to RUN ELEVATED on their own machine. It must be sound.
#
# WHY: a field run produced a remediation script containing
#   Set-MpPreference -DisableRealtimeMonitoring \False
# and
#   =@('SCM Event Log Filter',...) ... Where-Object { .Name -notin  } ^| Remove-CimInstance
# Both are generated from `addfix 'tag' "command"` lines echoed into %PSRUN%.
# The command is a DOUBLE-QUOTED PowerShell string, so every $var in it expands
# while the script is being WRITTEN rather than when the user RUNS it. The first
# fails at runtime; the second is a parse error, and a parse error anywhere in a
# .ps1 stops the whole file -- so it silently voided every other queued fix. Both
# fire only when something is genuinely wrong (Defender off; a WMI implant), so
# the two fixes most needed in an incident were the two that did not work.
#
# WHAT THIS DOES: it reproduces the real pipeline -- cmd un-escaping, then the
# PowerShell string expansion that `addfix` performs -- and parses what would
# actually land in Remediation_<ts>.ps1. Static reading cannot see these bugs;
# only running the expansion can.
#
#   -SelfTest   reintroduce each bug into a copy and prove the lint fails.
#
# Windows PowerShell 5.1 compatible; runs on any platform.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$bats = @('doze_sec.bat', 'doze_sec_noAdmin.bat')

function Expand-CmdEscapes {
    # cmd consumes ^ as an escape ONLY outside double quotes; inside quotes a
    # caret is literal. Getting this backwards is what put a literal ^| into a
    # generated command and ate the ^ anchors out of the fix-counter regex.
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    $inQ = $false
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($c -eq '"') { $inQ = -not $inQ; [void]$sb.Append($c); continue }
        if ($c -eq '^' -and -not $inQ -and $i + 1 -lt $Text.Length) { [void]$sb.Append($Text[$i + 1]); $i++; continue }
        [void]$sb.Append($c)
    }
    return $sb.ToString()
}

function Get-BareCmdOperators {
    # cmd splits a command line on | < > & BEFORE anything else, and it honours
    # DOUBLE quotes only -- PowerShell single quotes mean nothing to it. So a
    # payload written as 'Get-CimInstance ... | Where-Object ...' makes cmd try
    # to pipe the echo, and the audit dies with "| was unexpected at this time"
    # in the middle of the run. Every such operator must be ^-escaped.
    param([string]$Text)
    $hits = @(); $inQ = $false
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($c -eq '"') { $inQ = -not $inQ; continue }
        if ($c -eq '^' -and -not $inQ) { $i++; continue }
        if (-not $inQ -and '|<>&'.Contains([string]$c)) { $hits += [string]$c }
    }
    return $hits
}

function Get-EmittedCommands {
    param([string]$BatPath, [ref]$RuleCount)
    $emitted = @()
    $lines = [IO.File]::ReadAllLines($BatPath)
    $rules = @()
    foreach ($ln in $lines) {
        $t = $ln.TrimStart()
        if (-not $t.StartsWith('echo ')) { continue }
        if ($t -notmatch '\baddfix\b') { continue }
        # The line that DEFINES addfix also contains the word; it is not a rule.
        if ($t -match 'function\s+addfix') { continue }
        $t = $t.Substring(5)
        $t = [regex]::Replace($t, '\s*>>\s*"%PSRUN%"\s*$', '')
        $t = Expand-CmdEscapes $t
        # strip the trigger so every rule is exercised
        $t = [regex]::Replace($t, '^if\(\$joined -match .*?\)\{', '')
        $t = [regex]::Replace($t, '\}\s*$', '')
        $rules += $t.Trim()
    }
    $RuleCount.Value = $rules.Count
    # Run the real addfix in a child PowerShell so the SAME expansion happens.
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("dz_remlint_{0}" -f [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        $out = Join-Path $tmp 'out.ps1'
        $runner = Join-Path $tmp 'run.ps1'
        $body = @()
        $body += ('$rem = ' + ("'" + $out.Replace("'", "''") + "'"))
        $body += 'function addfix($tag,$cmd){ Add-Content -LiteralPath $rem -Value (''# ''+$tag); Add-Content -LiteralPath $rem -Value $cmd; Add-Content -LiteralPath $rem -Value '''' }'
        $body += $rules
        [IO.File]::WriteAllLines($runner, $body)
        $exe = (Get-Process -Id $PID).Path
        & $exe -NoProfile -File $runner *>&1 | Out-Null
        if (Test-Path -LiteralPath $out) { $emitted = @([IO.File]::ReadAllLines($out)) }
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -EA SilentlyContinue }
    return $emitted
}

function Invoke-Check {
    param([string]$R)
    $fail = @()
    $allCounts = @()
    $sig = @{}
    foreach ($b in $bats) {
        $path = Join-Path $R $b
        if (-not (Test-Path -LiteralPath $path)) { return @(("missing: {0}" -f $b)) }
        $n = 0
        $emitted = Get-EmittedCommands -BatPath $path -RuleCount ([ref]$n)
        $allCounts += $n
        $src = [IO.File]::ReadAllText($path)

        # 0. Before anything else: the generator line must survive cmd itself.
        foreach ($ln in [IO.File]::ReadAllLines($path)) {
            $t = $ln.TrimStart()
            if (-not $t.StartsWith('echo ')) { continue }
            if ($t -notmatch '\baddfix\b' -and $t -notmatch 'Add-Content -LiteralPath \$rem -Value') { continue }
            if ($t -match 'function\s+addfix') { continue }
            $payload = [regex]::Replace($t, '\s*>>\s*"%PSRUN%"\s*$', '')
            # PowerShell escapes with a backtick; a backslash-quote is a literal
            # backslash followed by a quote and is a parse error in the file the
            # user runs. (I shipped exactly this bug into this lint's own source.)
            if ($payload -match '\\"') {
                $fail += ("{0}: addfix line contains a backslash-escaped quote -- PowerShell escapes with a backtick, so this lands as a literal \\ in the generated script: {1}" -f $b, $t.Substring(0, [Math]::Min(120, $t.Length)))
            }
            $bare = Get-BareCmdOperators $payload
            if ($bare.Count) {
                $fail += ("{0}: addfix line has {1} UNESCAPED cmd operator(s) [{2}] outside double quotes -- cmd would split the line and abort the audit mid-run. Escape them as ^{2}: {3}" -f $b, $bare.Count, ($bare -join ''), $t.Substring(0, [Math]::Min(120, $t.Length)))
            }
        }

        if ($n -lt 15) { $fail += ("{0}: only {1} addfix rule(s) found -- this lint is broken, not the code" -f $b, $n) }
        if ($emitted.Count -eq 0) { $fail += ("{0}: the generator produced NO commands -- expansion failed entirely" -f $b); continue }

        $cmds = @($emitted | Where-Object { $_ -and -not $_.StartsWith('# ') })
        if ($cmds.Count -lt 15) { $fail += ("{0}: only {1} command(s) emitted from {2} rules" -f $b, $cmds.Count, $n) }
        $sig[$b] = ($cmds -join "`n")

        foreach ($c in $cmds) {
            # 1. It must parse. A parse error voids the ENTIRE remediation file.
            $e = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($c, [ref]$null, [ref]$e)
            if ($e -and $e.Count) {
                $fail += ("{0}: emitted command does NOT parse ({1}) -- this voids every other queued fix: {2}" -f $b, $e[0].Message, $c)
                continue
            }
            # 2. Fingerprints of a variable that expanded at generation time.
            if ($c -match '^\s*=') { $fail += ("{0}: emitted command starts with '=' -- a variable was consumed by generation-time expansion: {1}" -f $b, $c) }
            if ($c -match '\\(False|True)\b') { $fail += ("{0}: emitted command contains \{1} -- a backslash was used to escape `$; PowerShell escapes with a backtick: {2}" -f $b, $matches[1], $c) }
            if ($c -match '\^\|') { $fail += ("{0}: emitted command contains a literal ^| -- a caret inside cmd double quotes is NOT an escape: {1}" -f $b, $c) }
            if ($c -match '-notin\s*$' -or $c -match '\{\s*\.\w') { $fail += ("{0}: emitted command lost an operand to expansion: {1}" -f $b, $c) }
        }

        # 3. The generated script's own safety envelope.
        if ($src -notmatch 'IsInRole\(\[Security\.Principal\.WindowsBuiltInRole\]::Administrator') {
            $fail += ("{0}: the generated remediation script has no elevation assert -- run non-elevated it would apply only the per-user change and leave the machine half-fixed" -f $b)
        }
        if ($src -match "remove the 'exit 1'") {
            $fail += ("{0}: the generated script still tells the user to remove its own safety guard" -f $b)
        }
        if ($src -match "Write-Host '\[ABORT\][^']*'\s*-Fore") {
            $fail += ("{0}: the abort guard depends on colour; colour is stripped by redirection, transcripts and high-contrast themes" -f $b)
        }
        # 4. The fix counter must be anchored. cmd eats ^ outside double quotes,
        #    which silently turned '^netsh' into a substring match on the tag comment.
        if ($src -match "match '\^Set-") {
            $fail += ("{0}: the fix-count regex uses ^ anchors that cmd will eat -- use \A" -f $b)
        }
    }
    if ($sig.Count -eq 2 -and $sig[$bats[0]] -ne $sig[$bats[1]]) {
        $fail += 'the two bats emit DIFFERENT remediation commands -- they must stay mirrored'
    }
    return @{ Fail = $fail; Rules = ($allCounts | Select-Object -First 1) }
}

if ($SelfTest) {
    $mutations = @(
        @{ Name = 'a backslash-escaped $false (the Defender bug)'
           Find = '-DisableRealtimeMonitoring `\$false'; Repl = '-DisableRealtimeMonitoring \$false'
           Expect = 'PowerShell escapes with a backtick' },
        @{ Name = 'a $ variable inside a double-quoted command (the WMI bug)'
           Find = [regex]::Escape("addfix 'Harden NTLM to NTLMv2-only' `"Set-ItemProperty")
           Repl = "addfix 'Harden NTLM to NTLMv2-only' `"`$ms=@('a'); Set-ItemProperty"
           Expect = 'expansion' },
        @{ Name = 'a bare pipe in an addfix payload (cmd would split the line)'
           Find = [regex]::Escape('addfix ''Update Defender signatures'' "Update-MpSignature"')
           Repl = 'addfix ''Update Defender signatures'' ''Update-MpSignature | Out-Null'''
           Expect = 'UNESCAPED cmd operator' },
        @{ Name = 'the elevation assert removed'
           Find = '(?m)^echo if\(-not \(New-Object Security\.Principal\.WindowsPrincipal[^\r\n]*\r?\n'; Repl = ''
           Expect = 'no elevation assert' },
        @{ Name = 'caret anchors back in the fix counter'
           Find = "match '\\ASet-"; Repl = "match '^Set-"
           Expect = 'cmd will eat' }
    )
    $tmpBase = Join-Path ([IO.Path]::GetTempPath()) ("dz_remlint_st_{0}" -f [guid]::NewGuid().ToString('N'))
    $bad = @(); $ran = 0
    try {
        foreach ($m in $mutations) {
            $dir = Join-Path $tmpBase ("m{0}" -f $ran)
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            foreach ($b in $bats) { Copy-Item -LiteralPath (Join-Path $Root $b) -Destination $dir -Force }
            $target = Join-Path $dir 'doze_sec.bat'
            $src = [IO.File]::ReadAllText($target)
            $mut = [regex]::Replace($src, $m.Find, $m.Repl, 1)
            if ($mut -eq $src) { $bad += ("{0}: the mutation did not apply -- the self-test is broken, not the code" -f $m.Name); $ran++; continue }
            [IO.File]::WriteAllText($target, $mut)
            $r = Invoke-Check -R $dir
            $msg = ($r.Fail -join "`n")
            if ($r.Fail.Count -eq 0) { $bad += ("{0}: the lint PASSED on the mutated generator" -f $m.Name) }
            elseif ($msg -notmatch [regex]::Escape($m.Expect)) { $bad += ("{0}: failed, but not for the expected reason ('{1}' absent):`n{2}" -f $m.Name, $m.Expect, $msg) }
            else { Write-Host ("  [OK] fails as it must: {0}" -f $m.Name) }
            $ran++
        }
    } finally { Remove-Item -LiteralPath $tmpBase -Recurse -Force -EA SilentlyContinue }
    if ($ran -lt $mutations.Count) { $bad += 'not every mutation ran' }
    if ($bad.Count) { Write-Host ("[FAIL] lint_remediation self-test: {0} problem(s):" -f $bad.Count); $bad | ForEach-Object { Write-Host ("  - " + $_) }; exit 1 }
    Write-Host ("[OK] lint_remediation self-test: all {0} mutations fail the lint, each for the right reason." -f $ran)
    exit 0
}

$res = Invoke-Check -R $Root
if ($res.Fail.Count) {
    Write-Host ("[FAIL] {0} problem(s) in the remediation script the user is told to run elevated:" -f $res.Fail.Count)
    $res.Fail | ForEach-Object { Write-Host ("  - " + $_) }
    exit 1
}
Write-Host ("[OK] remediation generator: {0} rules; every emitted command parses, no generation-time expansion damage, both scripts mirrored, elevation asserted, guard legible without colour." -f $res.Rules)
exit 0
