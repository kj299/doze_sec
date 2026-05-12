# report_format.ps1 -- Post-process the audit report for unambiguous section boundaries
#
# Walks the report top-to-bottom. Every time it sees a MAIN section header
# (the `=====` box containing a [N/18] or [INIT N/14] title line), if the
# prior section had content, it inserts a horizontal-rule terminator line
# (68 dashes) so the preceding content is visually anchored to its own
# main section.
#
# Sub-section dividers (single-line `--- Title ---`) are NOT treated as
# section boundaries -- they are individual checks WITHIN a main section
# and don't need their own terminators (which would produce 50-100 rules
# per report instead of ~18).
#
# Detection: a main section opens when we encounter `=====` line N
# followed by `[N/18] TITLE` line N+1 followed by another `=====` line.
# The terminator is inserted before line N (the opening `=====`).
#
# Output preserves the original line-ending convention by re-checking the
# input bytes for CRLF vs LF and writing accordingly. Without this guard
# WriteAllLines would silently downgrade Windows CRLF reports to LF.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File report_format.ps1 -Report <path>

param(
    [Parameter(Mandatory=$true)]
    [string]$Report
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path -LiteralPath $Report)) { return }

# Detect line-ending style from the raw bytes BEFORE Get-Content strips \r.
$rawBytes = [System.IO.File]::ReadAllBytes($Report)
$rawText = [System.Text.Encoding]::UTF8.GetString($rawBytes)
$useCRLF = ($rawText -match "`r`n")
$nl = if ($useCRLF) { "`r`n" } else { "`n" }

$lines = $rawText -split "`r?`n"
if (-not $lines -or $lines.Count -eq 0) { return }

$rule = '-' * 68
$out = New-Object System.Collections.Generic.List[string]
$inMainSection = $false
$sectionHadContent = $false

for ($i = 0; $i -lt $lines.Count; $i++) {
    $L = $lines[$i]

    # A MAIN section opener is "=====" followed on the very next line by
    # "[N/18] TITLE" or "[INIT N/14] TITLE". We detect by looking AHEAD
    # one line when we see an "=====" line.
    $isMainOpener = $false
    if ($L -match '^={5,}\s*$' -and ($i + 1) -lt $lines.Count) {
        $next = $lines[$i + 1]
        if ($next -match '^\s*\[(\d+/18|INIT \d+/14)\]') {
            $isMainOpener = $true
        }
    }

    if ($isMainOpener -and $inMainSection -and $sectionHadContent) {
        # Close the previous main section: trim trailing blanks, add rule.
        while ($out.Count -gt 0 -and $out[$out.Count - 1] -match '^\s*$') {
            $out.RemoveAt($out.Count - 1)
        }
        $out.Add($rule)
        $out.Add('')
    }

    $out.Add($L)
    if ($isMainOpener) {
        $inMainSection = $true
        $sectionHadContent = $false
    } elseif ($L -notmatch '^\s*$') {
        $sectionHadContent = $true
    }
}

# Close the final main section
if ($inMainSection -and $sectionHadContent) {
    while ($out.Count -gt 0 -and $out[$out.Count - 1] -match '^\s*$') {
        $out.RemoveAt($out.Count - 1)
    }
    $out.Add($rule)
}

# Write back with the original line-ending convention preserved.
$bytes = [System.Text.Encoding]::UTF8.GetBytes(($out -join $nl) + $nl)
[System.IO.File]::WriteAllBytes($Report, $bytes)
