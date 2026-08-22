# block_sev.ps1 -- read the captured output of one audit block and print the
# highest severity that block actually reported: CRITICAL, WARNING, or OK.
#
# WHY THIS EXISTS. A large class of checks in doze_sec.bat printed
# '[CRITICAL] ...' or '[WARNING] ...' straight into the report and never called
# :dz_finding. The line was visible to a human reading the report, but invisible
# to the findings ledger -- so the section verdict said CLEAN, FINDINGS COUNTED
# did not count it, and the exit code stayed 0. A machine with a Cobalt Strike
# named pipe, a WMI event-subscription implant, an IFEO accessibility hijack or
# ransomware-extension files could be told "no issues detected". That is the
# exact false-clean failure this tool exists to prevent, so the raise is no
# longer left to per-check hand-wiring: :dz_ps_scan runs the block, appends its
# output to the report, asks this script what the block reported, and raises.
#
# PARSING RULES. Severity is taken from the tag that OPENS a line, so
# explanatory prose ("Review [WARNING] entries above") and the negative form
# ("[OK] No AMSI bypass patterns") can never inflate a block's severity:
#   * leading '[CRITICAL]' / '[WARNING]', optionally followed by a bracketed
#     technique tag ('[WARNING][T1574.001] ...') -- counted.
#   * a line opening with [OK], [INFO] or [SKIPPED] -- never counted, whatever
#     it says afterwards.
#   * a severity tag appearing mid-line after other text -- counted only when
#     the line has no other opening tag, because several checks render as
#     'Word 2016: [WARNING] blockcontentexecutionfrominternet=0'.
# Indentation is ignored (blocks indent continuation lines).
#
# Prints exactly one word so a cmd `for /f` can capture it. Never throws: an
# unreadable file prints OK, because a scan that cannot read its input must not
# invent a finding -- the block's own [SKIPPED] line reports the degradation.
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path
)

$ErrorActionPreference = 'Continue'

$sev = 'OK'
if (Test-Path -LiteralPath $Path) {
    try {
        foreach ($ln in (Get-Content -LiteralPath $Path -EA Stop)) {
            $t = $ln.TrimStart()
            if (-not $t) { continue }
            # A line that opens with a non-severity tag is descriptive, not a
            # finding, no matter what it mentions later.
            if ($t -match '^\[(OK|INFO|SKIPPED)\]') { continue }
            if ($t -match '^\[CRITICAL\]') { $sev = 'CRITICAL'; break }
            if ($t -match '^\[WARNING\]')  { $sev = 'WARNING'; continue }
            # Mid-line form: 'Word 2016: [WARNING] ...'. Only trusted on a line
            # that did not open with a tag of its own.
            if ($t -notmatch '^\[') {
                if ($t -match '\[CRITICAL\]') { $sev = 'CRITICAL'; break }
                if ($t -match '\[WARNING\]')  { $sev = 'WARNING' }
            }
        }
    } catch { $sev = 'OK' }
}

$sev
exit 0
