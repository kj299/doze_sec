# report_format.ps1 -- Post-process the audit report for unambiguous section boundaries
#
# Walks the report top-to-bottom. Every time it sees a section header
# (a line matching `^--- ... ---$`), if the prior section had content,
# it inserts a horizontal-rule terminator line (68 dashes) so the
# preceding content is visually anchored to its own section header.
#
# Before:                            After:
#   --- Section A ---                  --- Section A ---
#   output                             output
#   [WARNING] issue                    [WARNING] issue
#                                      --------------------------------------------------------------------
#   --- Section B ---
#   output                             --- Section B ---
#                                      output
#
# Without the terminator, an analyst skimming the report cannot tell
# whether `[WARNING] issue` belongs to Section A (above) or Section B
# (below). The horizontal rule unambiguously closes Section A.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File report_format.ps1 -Report <path>

param(
    [Parameter(Mandatory=$true)]
    [string]$Report
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path -LiteralPath $Report)) {
    Write-Output "[INFO] Report formatter: $Report not found, skipping."
    return
}

$lines = Get-Content -LiteralPath $Report
if (-not $lines -or $lines.Count -eq 0) {
    return
}

$rule = '-' * 68
$out = New-Object System.Collections.Generic.List[string]
$inSection = $false
$sectionHadContent = $false

foreach ($L in $lines) {
    $isHeader = $L -match '^---\s.+---\s*$'
    if ($isHeader -and $inSection -and $sectionHadContent) {
        # Trim trailing blank lines from $out
        while ($out.Count -gt 0 -and $out[$out.Count - 1] -match '^\s*$') {
            $out.RemoveAt($out.Count - 1)
        }
        $out.Add($rule)
        $out.Add('')
    }
    $out.Add($L)
    if ($isHeader) {
        $inSection = $true
        $sectionHadContent = $false
    } elseif ($L -notmatch '^\s*$') {
        $sectionHadContent = $true
    }
}

# Close the final section
if ($inSection -and $sectionHadContent) {
    while ($out.Count -gt 0 -and $out[$out.Count - 1] -match '^\s*$') {
        $out.RemoveAt($out.Count - 1)
    }
    $out.Add($rule)
}

[System.IO.File]::WriteAllLines($Report, $out.ToArray(), (New-Object System.Text.UTF8Encoding $false))
