# assert_report_complete.ps1 -- did the audit run to the end, and is the
# report file what the exit handler left?
#
# The full-run job used to assert this with two cmd findstr lines
# (`EXIT CODE:` present, `[18/18]` present). On 2026-10-03 the second one
# failed on a run whose console showed every section, the summary and exit
# code 8, and the artifact could not be fetched to see why; a cmd findstr
# verdict carries no diagnostics. This script asserts the same two facts and,
# when either fails, prints what the file actually is -- size, line count,
# longest line, NUL count, a BOM/UTF-16 sniff, the first and last lines --
# so a failure names its cause instead of its symptom.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\assert_report_complete.ps1 -Report <path>
# Exit 0 when complete, 1 otherwise. Pure ASCII; Windows PowerShell 5.1.
param([Parameter(Mandatory = $true)][string]$Report)
$ErrorActionPreference = 'Continue'
if (-not (Test-Path -LiteralPath $Report)) { Write-Output "FAIL: report not found: $Report"; exit 1 }
$bytes = [System.IO.File]::ReadAllBytes($Report)
$text  = [System.Text.Encoding]::UTF8.GetString($bytes)
$lines = @($text -split "`r?`n")
$fail = @()
if ($text -notmatch '(?m)^\s*EXIT CODE:') { $fail += 'no "EXIT CODE:" line -- the audit did not reach its exit handler (early exit or crash)' }
if ($text -notmatch '\[18/18\]')          { $fail += 'no "[18/18]" banner -- the audit did not reach Section 18, or the report was rewritten without it' }
if ($fail.Count -eq 0) {
    $longest = 0; foreach ($l in $lines) { if ($l.Length -gt $longest) { $longest = $l.Length } }
    Write-Output ("OK: report complete -- {0} bytes, {1} lines, longest line {2} chars" -f $bytes.Length, $lines.Count, $longest)
    exit 0
}
foreach ($f in $fail) { Write-Output ("FAIL: " + $f) }
$nul = 0; foreach ($b in $bytes) { if ($b -eq 0) { $nul++ } }
$longest = 0; $longestAt = 0
for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].Length -gt $longest) { $longest = $lines[$i].Length; $longestAt = $i + 1 } }
$head = ''
if ($bytes.Length -ge 2) { $head = ('{0:X2} {1:X2}' -f $bytes[0], $bytes[1]) }
Write-Output ("  bytes={0} lines={1} longest={2} (line {3}) NUL bytes={4} first two bytes={5} (FF FE = UTF-16 LE, EF BB = UTF-8 BOM)" -f $bytes.Length, $lines.Count, $longest, $longestAt, $nul, $head)
Write-Output ("  lines containing '[18/18]': {0}; lines containing 'EXIT CODE': {1}; lines containing 'Section: [': {2}" -f @($lines | Where-Object { $_ -like '*[[]18/18]*' }).Count, @($lines | Where-Object { $_ -like '*EXIT CODE*' }).Count, @($lines | Where-Object { $_ -like '*Section: [[]*' }).Count)
Write-Output '  ---- first 40 lines ----'
$lines | Select-Object -First 40 | ForEach-Object { Write-Output ('  | ' + $_) }
Write-Output '  ---- last 30 lines ----'
$lines | Select-Object -Last 30 | ForEach-Object { Write-Output ('  | ' + $_) }
exit 1
