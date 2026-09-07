# assert_header_matches_ledger.ps1 -- the summary header must agree with
# FINDINGS COUNTED, on a report a real audit just produced.
#
# WHY. A field report (2026-09-06) headed
#
#   REVIEW RECOMMENDED  --  0 CRITICAL  /  3 WARNING  /  30 PASSED
#
# and ended
#
#   FINDINGS COUNTED: 7
#
# The header counted dashboard TILES, which are a curated highlights view, so
# the two numbers described different things. The divergence ran BOTH ways: one
# tile WARNING (Sticky Keys) was not a counted finding at all, and five counted
# findings had no tile. A reader cannot act on a tool whose first line disagrees
# with its last one.
#
# The header now derives from the findings ledger. Nothing else asserts that, so
# without this it would drift back the moment someone reintroduced a tile
# counter -- and the drift is invisible in a green run, because every other gate
# is satisfied by a report whose two halves simply disagree.
#
# Read-only: parses one report file. Windows PowerShell 5.1 compatible.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Report
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Report)) {
    "[FAIL] report not found: $Report"
    exit 1
}
$lines = @(Get-Content -LiteralPath $Report)

# FINDINGS COUNTED is the ledger total the exit code derives from.
$counted = $null
foreach ($l in $lines) {
    $m = [regex]::Match($l, '^\s*FINDINGS COUNTED:\s*(\d+)\s*$')
    if ($m.Success) { $counted = [int]$m.Groups[1].Value }
}
if ($null -eq $counted) {
    "[FAIL] no 'FINDINGS COUNTED:' line in the report -- cannot compare the header against anything."
    exit 1
}

# The header, in any of its three shapes.
$hdr = $null
foreach ($l in $lines) {
    if ($l -match 'ACTION REQUIRED|REVIEW RECOMMENDED|NO FINDINGS COUNTED') { $hdr = $l }
}
if ($null -eq $hdr) {
    "[FAIL] no summary header line in the report -- the summary block did not run."
    exit 1
}

$hc = 0; $hw = 0
$mc = [regex]::Match($hdr, '(\d+)\s+CRITICAL')
if ($mc.Success) { $hc = [int]$mc.Groups[1].Value }
$mw = [regex]::Match($hdr, '(\d+)\s+WARNING')
if ($mw.Success) { $hw = [int]$mw.Groups[1].Value }
$total = $hc + $hw

# The header must not report a tile count as a finding count.
if ($hdr -match '\d+\s+PASSED' -and $hdr -notmatch 'DASHBOARD CHECKS PASSED') {
    "[FAIL] the header's third number is labelled 'PASSED', which reads as findings. It is a DASHBOARD TILE count and must say so."
    exit 1
}

if ($total -ne $counted) {
    "[FAIL] the summary header and FINDINGS COUNTED disagree -- a reader cannot act on a tool whose first line contradicts its last."
    "       header:           $($hdr.Trim())"
    "       header total:     $total ($hc CRITICAL + $hw WARNING)"
    "       FINDINGS COUNTED: $counted"
    "       The header must derive from the findings ledger, not from the dashboard tile counters."
    exit 1
}

"[OK] summary header agrees with FINDINGS COUNTED (${total}: $hc CRITICAL + $hw WARNING), and the tile count is labelled as one."
exit 0
