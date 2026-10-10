# count_gaps.ps1 -- how many checks in one part of the report said they could
# not run.
#
# Section 18's summary printed "[OK] No threat indicator matches found across
# all IOC categories" and the dashboard a PASS tile with the same words, while
# a category above them printed "NOT performed" or "[SKIPPED]": the claim
# covered checks that never ran. The summary now asks this tool how many such
# lines the section printed, from the byte offset the bat noted when the
# section began, and says "not an all-clear" when the count is above zero.
#
#   -Report     the report file
#   -FromByte   where the part to count begins (the report's size when the
#               bat noted it)
#   -StateFile  receives the count, or -1 when the report could not be read
#               (the caller then claims nothing)
#
# A line counts once when it says NOT performed (any case) or begins with
# [SKIPPED] or [DEFERRED. Windows PowerShell 5.1 and pwsh 7; pure ASCII.

[CmdletBinding()]
param(
    [string]$Report = '',
    [long]$FromByte = 0,
    [string]$StateFile = '',
    [switch]$SelfTest
)

function Get-GapCount {
    # PURE. The number of gap lines in $Text.
    param([string]$Text)
    $n = 0
    foreach ($l in ($Text -split "`r?`n")) {
        if ($l -match '(?i)\bNOT performed\b' -or $l -match '^\s*\[(SKIPPED|DEFERRED)') { $n++ }
    }
    return $n
}

function Read-ReportTail {
    # The report from byte $From on, decoded as the ANSI code page cmd writes.
    param([string]$Path, [long]$From)
    $b = [IO.File]::ReadAllBytes($Path)
    if ($From -lt 0) { $From = 0 }
    if ($From -ge $b.Length) { return '' }
    return [Text.Encoding]::Default.GetString($b, [int]$From, [int]($b.Length - $From))
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ': ' + $Got })"; $script:fails++ }
    }
    $sample = "--- [18a] Process IOC Match ---`r`n[OK] No process IOC matches.`r`n--- [18f] DNS Cache C2 Domain Match ---`r`n[WARNING] C2 domain IOC match NOT performed -- ioc_domains.txt could not be read`r`n--- [18b] ---`r`n[SKIPPED] ioc_named_pipes.txt missing or empty -- named pipe IOC match NOT performed.`r`n  [DEFERRED - ADMIN REQUIRED] something`r`n[OK] fine`r`n"
    T 'a NOT-performed line, a [SKIPPED] line and a [DEFERRED] line count once each' ((Get-GapCount $sample) -eq 3) ([string](Get-GapCount $sample))
    T 'a section with no gap counts 0' ((Get-GapCount "[OK] a`n[INFO] b`n[WARNING] c`n") -eq 0) ''
    T 'the phrase is matched as words, in any case' ((Get-GapCount "x not performed y`nCANNOTperformed`n") -eq 1) ''
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_count_gaps_' + $PID + '.txt')
    $out = $tmp + '.state'
    try {
        $head = "[SKIPPED] in Section 17, before the offset -- NOT performed`r`n"
        [IO.File]::WriteAllText($tmp, $head + $sample, [Text.Encoding]::ASCII)
        $from = [Text.Encoding]::ASCII.GetByteCount($head)
        & $PSCommandPath -Report $tmp -FromByte $from -StateFile $out
        T 'only the part after -FromByte is counted' (([IO.File]::ReadAllText($out)).Trim() -eq '3') ([IO.File]::ReadAllText($out))
        & $PSCommandPath -Report $tmp -FromByte 0 -StateFile $out
        T 'from byte 0 the whole report is counted' (([IO.File]::ReadAllText($out)).Trim() -eq '4') ([IO.File]::ReadAllText($out))
        & $PSCommandPath -Report ($tmp + '.missing') -FromByte 0 -StateFile $out
        T 'an unreadable report writes -1, never 0' (([IO.File]::ReadAllText($out)).Trim() -eq '-1') ([IO.File]::ReadAllText($out))
        & $PSCommandPath -Report $tmp -FromByte 999999 -StateFile $out
        T 'an offset past the end counts 0' (([IO.File]::ReadAllText($out)).Trim() -eq '0') ([IO.File]::ReadAllText($out))
    } finally {
        foreach ($f in $tmp, $out) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -EA SilentlyContinue } }
    }
    if ($fails -gt 0) { Write-Output "FAILED: $fails"; exit 1 }
    Write-Output '[OK] count_gaps self-test: NOT-performed, [SKIPPED] and [DEFERRED] lines are counted after the offset, and an unreadable report is -1, not 0.'
    exit 0
}

$count = -1
try { $count = Get-GapCount (Read-ReportTail $Report $FromByte) } catch { $count = -1 }
if ($StateFile) { Set-Content -LiteralPath $StateFile -Value ([string]$count) -Encoding ASCII } else { Write-Output $count }
exit 0
