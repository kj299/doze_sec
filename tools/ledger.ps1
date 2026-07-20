# ledger.ps1 -- the single finding record for the audit (finding #4, Option B).
#
# WHY: severity today is split across three disagreeing channels -- the cmd
# FINDINGS counter (section verdicts + "FINDINGS COUNTED"), the summary
# dashboard's ck tally (exit code), and an end-of-run [CRITICAL] report scrape.
# They are computed from different populations of checks and contradict each
# other (see docs/design/finding-model.md). This module is the foundation of
# the fix: one append-only ledger that every finding writes to, and from which
# the section verdicts, the findings count, and the exit code all derive.
#
# RECORD FORMAT (one finding per line): SEVERITY|SECTION|CODE|MESSAGE
#   SEVERITY : CRITICAL | WARNING   (the two severities that count as findings)
#   SECTION  : section id the finding belongs to (e.g. 9, 13, 17, INIT)
#   CODE     : optional short tag (MITRE id or check id); may be empty
#   MESSAGE  : human-readable text (separator/newline chars are sanitized out)
#
# This module NEVER evaluates a security condition -- callers evaluate and
# append; this only records and summarizes. That separation is the whole point:
# one place computes the rollup, so the channels cannot diverge.
#
# MODES:
#   Append    -Path <ledger> -Severity CRITICAL|WARNING -Section <id>
#             [-Code <tag>] -Message <text>
#               Append one finding line (creating the file if needed).
#   Summarize -Path <ledger>
#               Emit KEY=VALUE lines: TOTAL, CRITICAL, WARNING, MAXSEV
#               (MAXSEV = CRITICAL if any critical, else WARNING, else NONE).
#   Section   -Path <ledger> -Section <id>
#               Emit the finding count for one section (0 = clean).
#
# Windows PowerShell 5.1 compatible. Exercised by the helpers-ps51 CI job.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Append', 'Summarize', 'Section')][string]$Mode,
    [Parameter(Mandatory = $true)][string]$Path,
    [ValidateSet('CRITICAL', 'WARNING')][string]$Severity,
    [string]$Section,
    [string]$Code = '',
    [string]$Message
)

$ErrorActionPreference = 'Stop'

function Read-LedgerLines {
    param([string]$p)
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    @(Get-Content -LiteralPath $p -EA SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' })
}

switch ($Mode) {
    'Append' {
        if (-not $Severity) { throw 'Append requires -Severity' }
        if (-not $Section)  { throw 'Append requires -Section' }
        # Strip field separators and newlines from free text so one finding
        # stays exactly one parseable line.
        $sev = $Severity
        $sec = ($Section -replace '[|\r\n]', ' ').Trim()
        $cod = ($Code    -replace '[|\r\n]', ' ').Trim()
        $msg = ($Message -replace '[|\r\n]', ' ').Trim()
        Add-Content -LiteralPath $Path -Value ('{0}|{1}|{2}|{3}' -f $sev, $sec, $cod, $msg) -Encoding ASCII
    }
    'Summarize' {
        $lines = Read-LedgerLines $Path
        $crit = @($lines | Where-Object { $_ -like 'CRITICAL|*' }).Count
        $warn = @($lines | Where-Object { $_ -like 'WARNING|*' }).Count
        $max = if ($crit -gt 0) { 'CRITICAL' } elseif ($warn -gt 0) { 'WARNING' } else { 'NONE' }
        "TOTAL=$($lines.Count)"
        "CRITICAL=$crit"
        "WARNING=$warn"
        "MAXSEV=$max"
    }
    'Section' {
        if (-not $Section) { throw 'Section requires -Section' }
        # Explicit iteration with String.Split (not the -split operator inside a
        # Where-Object block, which mis-scoped $Section and always counted 0).
        $want = [string]$Section
        $n = 0
        foreach ($ln in (Read-LedgerLines $Path)) {
            $f = $ln.Split('|')
            if ($f.Length -ge 2 -and $f[1] -eq $want) { $n++ }
        }
        $n
    }
}
