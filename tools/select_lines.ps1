# select_lines.ps1 -- findstr-replacement that handles arbitrarily long lines.
#
# findstr's input-line buffer aborts with "FINDSTR: Line N is too long" when a
# single input line exceeds ~8KB, AND silently drops the match on that line.
# wevtutil event-log XML and `wmic process get CommandLine` output regularly
# produce >8KB lines (Chrome with extension args, Java classpaths, Defender
# scan commands, etc.), so any pipeline like
#   wevtutil qe Security ... ^| findstr /c:"Command Line"
# misses matches AND pollutes the report.
#
# This helper reads -Path via .NET StreamReader.ReadLine which has no fixed-size
# line buffer, so the same patterns against the same input always return every
# match without errors.
#
# Patterns are matched as literal substrings (mirroring `findstr /c:"..."`),
# not regex. Case-insensitive by default; pass -CaseSensitive to disable.
# -Invert mirrors `findstr /v` (emit non-matching lines).
#
# Usage:
#   pwsh -NoProfile -File select_lines.ps1 -Path "%TEMP%\dz_pipe.tmp" "TimeCreated" "Account Name"
#   pwsh -NoProfile -File select_lines.ps1 -Path "..." -CaseSensitive -Invert "drop me"
#   pwsh -NoProfile -File select_lines.ps1 -Path "..." -PatternFile "ioc_lolbins.txt"
#
# Callers should write the upstream command's output to a temp file first
# (e.g. `wevtutil qe ... > "%TEMP%\dz_pipe.tmp"`) and then invoke this helper
# with -Path. Stdin is intentionally not supported because powershell.exe -File
# does not reliably forward piped stdin to the script.
#
# Notes:
# - Patterns are taken from trailing positional args (ValueFromRemainingArguments).
#   This avoids the "powershell -File ... -Pattern a,b" array-splatting quirk
#   where comma-separated values don't round-trip cleanly through CMD into
#   the script's [string[]] parameter.
# - The input-file parameter is -Path, not -File, because powershell.exe's own
#   -File switch would otherwise consume the value before the script sees it.

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)] [string]$Path = '',
    [Parameter(Mandatory=$false)] [string]$PatternFile = '',
    [Parameter(Mandatory=$false)] [switch]$CaseSensitive,
    [Parameter(Mandatory=$false)] [switch]$Invert,
    [Parameter(Position=0, ValueFromRemainingArguments=$true)] [string[]]$Pattern
)

# Load patterns from -PatternFile (mirrors `findstr /g:file`). Blank lines and
# lines starting with `#` are ignored, matching the threat-list convention used
# under ThreatLists/.
if ($PatternFile -ne '') {
    if (Test-Path -LiteralPath $PatternFile) {
        $fromFile = @(Get-Content -LiteralPath $PatternFile -EA SilentlyContinue |
            Where-Object { $_ -and -not ($_ -match '^\s*#') } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne '' })
        if ($Pattern) { $Pattern = @($Pattern) + $fromFile } else { $Pattern = $fromFile }
    }
}

if (-not $Pattern -or $Pattern.Count -eq 0) {
    Write-Error "select_lines.ps1: at least one pattern is required (pass as trailing positional args, or via -PatternFile <file>)."
    exit 2
}

$ErrorActionPreference = 'Continue'

# Pre-lowercase the patterns once when case-insensitive to avoid per-line work.
$needles = if ($CaseSensitive) { $Pattern } else { @($Pattern | ForEach-Object { $_.ToLowerInvariant() }) }

function Test-Hit {
    param([string]$Line)
    if ($null -eq $Line) { return $false }
    $hay = if ($CaseSensitive) { $Line } else { $Line.ToLowerInvariant() }
    foreach ($n in $needles) {
        if ($hay.Contains($n)) { return $true }
    }
    return $false
}

# Footgun guard: if -Path was omitted but the first positional pattern looks
# like a file path that exists on disk, the caller likely forgot the -Path
# flag and the file would silently be treated as a literal pattern. Fail loud.
# (Mandatory=$true on -Path is NOT used because powershell -File hangs waiting
# for stdin when a mandatory parameter is missing, instead of erroring cleanly.)
if ($Path -eq '' -and $Pattern -and $Pattern.Count -gt 0 -and (Test-Path -LiteralPath $Pattern[0] -EA SilentlyContinue)) {
    Write-Error "select_lines.ps1: -Path was omitted but the first positional argument '$($Pattern[0])' looks like an existing file. Did you forget the -Path flag?"
    exit 2
}

if ($Path -eq '') {
    Write-Error "select_lines.ps1: -Path <file> is required."
    exit 2
}

if (-not (Test-Path -LiteralPath $Path)) { exit 1 }

# Mirror findstr's exit code: 0 = at least one line emitted, 1 = none emitted.
# Callers (e.g. doze_sec.bat) gate WARN/CRITICAL blocks on `if errorlevel 0`.
$emitted = 0
$reader = $null
try {
    $reader = [System.IO.StreamReader]::new($Path)
    while ($null -ne ($line = $reader.ReadLine())) {
        $hit = Test-Hit $line
        if ($hit -xor $Invert) {
            Write-Output $line
            $emitted++
        }
    }
} finally {
    if ($reader) { $reader.Dispose() }
}
if ($emitted -gt 0) { exit 0 } else { exit 1 }
