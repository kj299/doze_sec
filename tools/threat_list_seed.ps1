# threat_list_seed.ps1 -- seed the RUNTIME ThreatLists directory from the
# release baseline, and reconcile a runtime copy that has fallen behind it.
#
# WHY: doze_sec reads its IOC lists from a runtime directory (C:\SecurityAudit\
# ThreatLists elevated, %USERPROFILE%\SecurityAudit\ThreatLists as a standard
# user) so that -updateTTP can append to a copy rather than to the git
# checkout. The seed step copied a file only when it was MISSING, so a runtime
# copy made from an older release was never reconciled with a newer one. The
# first standard-user field run read a per-user copy of ioc_registry.txt that
# predated the |BadValue column, and the parser's fallback for a row with no
# BadValue is "fire when the value exists": it reported EnableLUA = 1 and
# RunAsPPL = 1 -- UAC ON and LSASS PPL ON, the secure values -- as suspicious
# registry IOCs. A runtime copy of a shipped list is a fork; this is the merge.
#
# THE RULE (pure, in Get-SeedVerdict, pinned by -SelfTest):
#   * runtime copy missing                       -> copy (seed)
#   * identical content                          -> keep (nothing to say)
#   * runtime '# Last verified by doze_sec:' date STRICTLY newer than the
#     shipped one                                -> keep: -updateTTP wrote it
#                                                   after this release
#   * otherwise (older, equal, or no header)     -> replace with the shipped
#                                                   file, and SAY SO in the
#                                                   report: ties go to the
#                                                   release, because a copy
#                                                   with the same date and
#                                                   different content is a
#                                                   fork nobody chose.
#
# ttp_generated_checks.bat, which -updateTTP appends to and Section 18 calls,
# is reconciled too: a PowerShell launch line an earlier release wrote without
# -NonInteractive gets it (every PowerShell the bats start runs it, so a
# question fails at once instead of waiting where nobody sees it). Rewritten
# byte for byte apart from the inserted flag, and the report says how many.
# The -updateTTP path runs this tool once early with its output discarded;
# that call passes -SkipGeneratedChecks, so the rewrite happens in the INIT
# call whose output reaches the report.
#
# Prints one line per file it changed, and a one-line summary. Read-only apart
# from the runtime directory. Windows PowerShell 5.1 and pwsh.

[CmdletBinding()]
param(
    [string]$ShippedDir,
    [string]$RuntimeDir,
    [switch]$SkipGeneratedChecks,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'

$script:Files = @('ioc_processes.txt', 'ioc_named_pipes.txt', 'ioc_services.txt', 'ioc_registry.txt',
                  'ioc_file_paths.txt', 'ioc_scheduled_tasks.txt', 'ioc_domains.txt', 'ioc_hashes.txt',
                  'ioc_lolbins.txt', 'ttp_manifest.txt')

# A launch line as every release of ttp_merge.ps1 has written it: the program
# at the start of the line, then -NoProfile. Anchored, so text elsewhere on a
# line (a CTI name, a path) is never edited.
$script:GenLaunchRx = '(?i)^(\s*)("%PWSH%"|%PWSH%)(\s+-NoProfile)\b(?!\s+-NonInteractive\b)'

function ConvertTo-NonInteractiveLaunch {
    # Pure. A launch line without -NonInteractive gets it straight after
    # -NoProfile, before -File or -Command. An echo, rem or :: line is text,
    # never a launch.
    param([string[]]$Lines)
    $out = @(); $changed = 0
    foreach ($l in $Lines) {
        if ($l -notmatch '(?i)^\s*@?(echo|rem\s|::)' -and $l -match $script:GenLaunchRx) {
            $l = [regex]::Replace($l, $script:GenLaunchRx, '$1$2$3 -NonInteractive')
            $changed++
        }
        $out += $l
    }
    return @{ Lines = $out; Changed = $changed }
}

function Update-GeneratedChecks {
    # The file -updateTTP appends to. Read and written through Latin-1 so every
    # byte (encoding, line endings) stays as it was except the inserted flag.
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $enc = [Text.Encoding]::GetEncoding(28591)
    $text = $enc.GetString([IO.File]::ReadAllBytes($Path))
    $parts = [regex]::Split($text, '(\r?\n)')
    $n = 0
    for ($i = 0; $i -lt $parts.Count; $i += 2) {
        $c = ConvertTo-NonInteractiveLaunch @($parts[$i])
        if ($c.Changed -gt 0) { $parts[$i] = $c.Lines[0]; $n++ }
    }
    if ($n -gt 0) {
        # Written beside it, then swapped in: a failed write (a full disk, a
        # scanner's lock) leaves the original whole, never a truncated batch
        # file that Section 18 would call.
        $tmp = $Path + '.dz_tmp'
        try {
            [IO.File]::WriteAllBytes($tmp, $enc.GetBytes(($parts -join '')))
            # A rename on the same volume, replacing the target: the file is
            # either the old one or the new one, never half of either.
            Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop
        } catch {
            Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue
            throw
        }
    }
    return $n
}

# The date threat_list_sync.ps1 writes on -updateTTP; $null when absent.
function Get-VerifiedDate {
    param([string[]]$Lines)
    foreach ($l in @($Lines)) {
        $m = [regex]::Match([string]$l, '^\s*#\s*Last verified by doze_sec:\s*(\d{4}-\d{2}-\d{2})(?:\s+(\d{2}:\d{2}:\d{2}))?')
        if ($m.Success) {
            $txt = $m.Groups[1].Value + $(if ($m.Groups[2].Success) { ' ' + $m.Groups[2].Value } else { ' 00:00:00' })
            try { return [datetime]::ParseExact($txt, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } catch { return $null }
        }
    }
    return $null
}

# PURE: shipped text and runtime text (or $null when the copy is missing) in,
# an action out: Seed, Keep, Replace -- with the reason.
function Get-SeedVerdict {
    param([string[]]$ShippedLines, [string[]]$RuntimeLines)
    if ($null -eq $RuntimeLines) { return @{ Action = 'Seed'; Why = 'no runtime copy' } }
    $a = (@($ShippedLines) -join "`n"); $b = (@($RuntimeLines) -join "`n")
    if ($a -eq $b) { return @{ Action = 'Keep'; Why = 'identical' } }
    $ds = Get-VerifiedDate -Lines $ShippedLines
    $dr = Get-VerifiedDate -Lines $RuntimeLines
    if ($null -ne $dr -and $null -ne $ds -and $dr -gt $ds) {
        return @{ Action = 'Keep'; Why = ('runtime copy verified ' + $dr.ToString('yyyy-MM-dd') + ', newer than the release (' + $ds.ToString('yyyy-MM-dd') + ')') }
    }
    if ($null -ne $dr -and $null -eq $ds) {
        # A runtime copy with a date beats a release file with none only if
        # the release file is malformed; the release always carries one.
        return @{ Action = 'Replace'; Why = 'the release file carries no verified date -- the release baseline wins' }
    }
    $whyR = if ($null -eq $dr) { 'no verified date' } else { 'verified ' + $dr.ToString('yyyy-MM-dd') }
    $whyS = if ($null -eq $ds) { 'no verified date' } else { 'release ' + $ds.ToString('yyyy-MM-dd') }
    return @{ Action = 'Replace'; Why = ('runtime copy ' + $whyR + ', ' + $whyS + ' -- content differs and the copy is not newer') }
}

# Defined BEFORE the self-test that calls it: PowerShell binds functions in
# script order, and a self-test that reached this function first got a
# CommandNotFoundException that terminated its try block -- five directory-pass
# cases never ran and the summary still read [OK]. CI's by-name grep caught it.
function Invoke-Seed {
    param([string]$Shipped, [string]$Runtime, [switch]$SkipGenerated)
    $lines = @()
    $seeded = 0; $replaced = 0; $kept = 0
    if (-not (Test-Path -LiteralPath $Runtime)) { New-Item -ItemType Directory -Path $Runtime -Force -EA SilentlyContinue | Out-Null }
    foreach ($f in $script:Files) {
        $src = Join-Path $Shipped $f
        $dst = Join-Path $Runtime $f
        if (-not (Test-Path -LiteralPath $src)) { continue }
        $shippedLines = @(Get-Content -LiteralPath $src -EA SilentlyContinue)
        $runtimeLines = $null
        if (Test-Path -LiteralPath $dst) { $runtimeLines = @(Get-Content -LiteralPath $dst -EA SilentlyContinue) }
        $v = Get-SeedVerdict -ShippedLines $shippedLines -RuntimeLines $runtimeLines
        switch ($v.Action) {
            'Seed'    { Copy-Item -LiteralPath $src -Destination $dst -Force; $seeded++;   $lines += ('[INFO] ThreatLists\' + $f + ': seeded from the release baseline.') }
            'Replace' { Copy-Item -LiteralPath $src -Destination $dst -Force; $replaced++; $lines += ('[INFO] ThreatLists\' + $f + ': runtime copy replaced by the release baseline (' + $v.Why + ').') }
            default   { $kept++ }
        }
    }
    $lines += ('[INFO] ThreatLists: ' + $seeded + ' seeded, ' + $replaced + ' replaced from the release baseline, ' + $kept + ' kept.')
    $gen = $null
    if (-not $SkipGenerated) {
    try { $gen = Update-GeneratedChecks (Join-Path $Runtime 'ttp_generated_checks.bat') }
    catch { $lines += ('[INFO] ThreatLists\ttp_generated_checks.bat could not be checked for -NonInteractive: ' + $_.Exception.Message) }
    }
    if ($gen -gt 0) { $lines += ('[INFO] ThreatLists\ttp_generated_checks.bat: ' + $gen + ' PowerShell launch line(s) written by an earlier -updateTTP now run -NonInteractive.') }
    return $lines
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    # The release file as shipped today, and the stale per-user copy the field
    # run read: same header shape, no BadValue column.
    $shipped = @('# Last verified by doze_sec: 2026-06-06 10:20:38', '# Format: HIVE\KEY\PATH|ValueName|BadValue',
                 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA|0')
    $stale   = @('# Last verified by doze_sec: 2026-05-01 09:00:00', '# Format: HIVE\KEY\PATH|ValueName',
                 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA')
    $v = Get-SeedVerdict -ShippedLines $shipped -RuntimeLines $stale
    T 'a runtime copy OLDER than the release, different content: Replace' ($v.Action -eq 'Replace') ($v.Action + ': ' + $v.Why)
    T '...and the reason names both dates' ($v.Why -match 'verified 2026-05-01' -and $v.Why -match 'release 2026-06-06') $v.Why
    $v = Get-SeedVerdict -ShippedLines $shipped -RuntimeLines $null
    T 'no runtime copy: Seed' ($v.Action -eq 'Seed') $v.Action
    $v = Get-SeedVerdict -ShippedLines $shipped -RuntimeLines $shipped
    T 'identical content: Keep, nothing to say' ($v.Action -eq 'Keep' -and $v.Why -eq 'identical') ($v.Action + ': ' + $v.Why)
    $updated = @('# Last verified by doze_sec: 2026-09-20 12:00:00', '# Format: HIVE\KEY\PATH|ValueName|BadValue',
                 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA|0',
                 'HKLM\SOFTWARE\Example|Added|1')
    $v = Get-SeedVerdict -ShippedLines $shipped -RuntimeLines $updated
    T 'a runtime copy -updateTTP wrote AFTER the release (newer date, more rows): Keep' ($v.Action -eq 'Keep' -and $v.Why -match 'newer than the release') ($v.Action + ': ' + $v.Why)
    $same = @('# Last verified by doze_sec: 2026-06-06 10:20:38', 'HKLM\SOFTWARE\Example|Edited|1')
    $v = Get-SeedVerdict -ShippedLines $shipped -RuntimeLines $same
    T 'same date, different content (a fork nobody chose): Replace -- ties go to the release' ($v.Action -eq 'Replace') ($v.Action + ': ' + $v.Why)
    $noHdr = @('# SENTINEL-X CTI', 'HKLM\SOFTWARE\Example|Old')
    $v = Get-SeedVerdict -ShippedLines $shipped -RuntimeLines $noHdr
    T 'a runtime copy with no verified header at all: Replace' ($v.Action -eq 'Replace' -and $v.Why -match 'no verified date') ($v.Action + ': ' + $v.Why)
    $v = Get-SeedVerdict -ShippedLines @('# no header here', 'x|y') -RuntimeLines @('# Last verified by doze_sec: 2026-09-20', 'x|z')
    T 'a release file with no header still wins over a dated runtime copy' ($v.Action -eq 'Replace') ($v.Action + ': ' + $v.Why)
    T 'the header date parses with and without a time' ((Get-VerifiedDate -Lines @('# Last verified by doze_sec: 2026-09-20')) -ne $null -and (Get-VerifiedDate -Lines @('# Last verified by doze_sec: 2026-09-20 12:34:56')).Hour -eq 12) ''
    T 'a malformed date is treated as no date' ($null -eq (Get-VerifiedDate -Lines @('# Last verified by doze_sec: yesterday'))) ''
    # Whole-directory pass on temp copies: the stale file is replaced, the
    # updated one kept, and the lines say which.
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('dz_seed_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $sd = Join-Path $tmp 'shipped'; $rd = Join-Path $tmp 'runtime'
    New-Item -ItemType Directory -Path $sd, $rd -Force | Out-Null
    try {
        Set-Content -LiteralPath (Join-Path $sd 'ioc_registry.txt') -Value $shipped -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $rd 'ioc_registry.txt') -Value $stale -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $sd 'ioc_domains.txt') -Value $shipped -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $rd 'ioc_domains.txt') -Value $updated -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $sd 'ioc_hashes.txt') -Value $shipped -Encoding ASCII
        $out = @(Invoke-Seed -Shipped $sd -Runtime $rd)
        T 'directory pass: the stale registry list is replaced and the line names the file and both dates' (($out -join "`n") -match '\[INFO\] ThreatLists\\ioc_registry\.txt: runtime copy replaced by the release baseline \(runtime copy verified 2026-05-01, release 2026-06-06') ($out -join ' | ')
        T 'directory pass: the updated domains list is kept and NOT mentioned as replaced' (($out -join "`n") -notmatch 'ioc_domains\.txt: runtime copy replaced') ($out -join ' | ')
        T 'directory pass: the missing hashes list is seeded' ((Test-Path (Join-Path $rd 'ioc_hashes.txt')) -and (($out -join "`n") -match 'ioc_hashes\.txt: seeded from the release baseline')) ($out -join ' | ')
        T 'directory pass: the replaced file now equals the release file' (((Get-Content (Join-Path $rd 'ioc_registry.txt')) -join "`n") -eq ($shipped -join "`n")) ''
        T 'directory pass: the summary counts 1 seeded, 1 replaced, 1 kept' (($out -join "`n") -match '\[INFO\] ThreatLists: 1 seeded, 1 replaced from the release baseline, 1 kept') ($out -join ' | ')
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -EA SilentlyContinue }

    # The generated CTI checks: an old launch line gets the flag, an echo line
    # and a flagged line do not, the bytes around it survive, and a second
    # pass changes nothing.
    $echoL = 'echo  Command: "%PWSH%" -NoProfile -File x>> "%REPORT%"'
    $remL = 'rem "%PWSH%" -NoProfile -File x'
    $nameL = 'if exist "C:\x" (echo [WARNING] %PWSH% -NoProfile in a name>> "%REPORT%")'
    $c = ConvertTo-NonInteractiveLaunch @(
        '"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1',
        $echoL, $remL, $nameL,
        '"%PWSH%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1',
        '"%PWSH%" -NoProfileX -File x')
    T 'an old generated launch gets -NonInteractive before -File' ($c.Changed -eq 1 -and $c.Lines[0] -ceq '"%PWSH%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%PSRUN%">> "%REPORT%" 2>&1') ($c.Lines -join ' | ')
    T 'echo and rem lines carrying the launch text are left alone' ($c.Lines[1] -ceq $echoL -and $c.Lines[2] -ceq $remL) ($c.Lines -join ' | ')
    T 'launch text inside a line that is not a launch (a CTI name) is left alone' ($c.Lines[3] -ceq $nameL) $c.Lines[3]
    T 'an already-flagged launch and -NoProfileX are left alone' ($c.Lines[4] -cmatch '^"%PWSH%" -NoProfile -NonInteractive -ExecutionPolicy' -and $c.Lines[5] -ceq '"%PWSH%" -NoProfileX -File x') ($c.Lines -join ' | ')
    $gtmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_seed_gen_{0}' -f $PID)
    New-Item -ItemType Directory -Path $gtmp -Force | Out-Null
    try {
        $g = Join-Path $gtmp 'ttp_generated_checks.bat'
        # A non-ASCII byte (0xE9), an LF-only line and a last line with no
        # newline: a text-mode rewrite would change at least one of them.
        $L1 = [Text.Encoding]::GetEncoding(28591)
        $orig = ":: --- block Caf" + [char]0xE9 + " ---`r`necho x > `"%PSRUN%`"`n`"%PWSH%`" -NoProfile -ExecutionPolicy Bypass -File `"%PSRUN%`">> `"%REPORT%`" 2>&1`r`n`"%PWSH%`" -NoProfile -ExecutionPolicy Bypass -File `"%PSRUN%`""
        [IO.File]::WriteAllBytes($g, $L1.GetBytes($orig))
        $n1 = Update-GeneratedChecks $g
        $want = $L1.GetBytes(($orig -creplace '-NoProfile -ExecutionPolicy', '-NoProfile -NonInteractive -ExecutionPolicy'))
        $got = [IO.File]::ReadAllBytes($g)
        T 'the file: both launches flagged, every other byte kept (0xE9, LF-only, no final newline)' ($n1 -eq 2 -and ([Convert]::ToBase64String($got) -ceq [Convert]::ToBase64String($want))) ("n=$n1")
        T 'the swap leaves no temporary file behind' (-not (Test-Path -LiteralPath ($g + '.dz_tmp')))
        $n2 = Update-GeneratedChecks $g
        T 'a second pass changes nothing' ($n2 -eq 0) ("n=$n2")
        T 'no generated checks file: nothing to do' ($null -eq (Update-GeneratedChecks (Join-Path $gtmp 'absent.bat')))
        # -SkipGeneratedChecks (the -updateTTP path's early, unreported call)
        # leaves the file for the INIT call, whose output reaches the report.
        [IO.File]::WriteAllBytes($g, $L1.GetBytes($orig))
        $sk = @(Invoke-Seed -Shipped $gtmp -Runtime $gtmp -SkipGenerated)
        T '-SkipGeneratedChecks leaves the generated checks alone' ((([Convert]::ToBase64String([IO.File]::ReadAllBytes($g))) -ceq [Convert]::ToBase64String($L1.GetBytes($orig))) -and -not (($sk -join ' ') -match 'ttp_generated_checks')) ($sk -join ' | ')
        $rp = @(Invoke-Seed -Shipped $gtmp -Runtime $gtmp)
        T 'without it the same file is flagged and the report line says so' (($rp -join ' ') -match 'ttp_generated_checks\.bat: 2 PowerShell launch line\(s\)') ($rp -join ' | ')
    } finally { Remove-Item -LiteralPath $gtmp -Recurse -Force -EA SilentlyContinue }

    if ($fails) { Write-Output "[FAIL] $fails threat_list_seed self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] threat_list_seed self-test: a runtime list older than or forked from the release is replaced and reported; one -updateTTP refreshed after the release is kept.'
    exit 0
}

if (-not $ShippedDir -or -not $RuntimeDir) {
    '[SKIPPED] threat_list_seed: -ShippedDir and -RuntimeDir are required -- runtime ThreatLists NOT reconciled with the release baseline.'
    exit 0
}
foreach ($l in (Invoke-Seed -Shipped $ShippedDir -Runtime $RuntimeDir -SkipGenerated:$SkipGeneratedChecks)) { $l }
