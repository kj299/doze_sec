# CI ONLY -- run by .github/workflows/windows-smoke.yml on a throwaway runner,
# from the step named:
#   report_html.ps1 surfaces a Findings Index with section links
# It may plant test state on the machine it runs on; do not run it on a
# machine you use. It lives in .github/ so it never reaches a USB stick
# (make_usb_stick.ps1 excludes the directory), and outside the workflow file
# because GitHub refuses to run a workflow file over its size limit --
# silently: the jobs simply never appear. The body below is the step's own,
# moved unchanged.
$ErrorActionPreference = 'Stop'
$r = Join-Path $env:TEMP 'dz_ci_html_report.txt'
$h = Join-Path $env:TEMP 'dz_ci_html_report.html'
$lines = @(
  '===================================================================='
  ' [18/18] CTI-DRIVEN IOC SWEEP'
  '===================================================================='
  '[CRITICAL] Known malware staging files found: C:\x\evil.exe'
  '######################################################################'
  '##  SECURITY AUDIT SUMMARY  --  CITEST'
  '##  ACTION REQUIRED  --  1 CRITICAL  /  2 WARNING  --  5 DASHBOARD CHECKS PASSED'
  '######################################################################'
  '  --- CTI IOC SWEEP  (Section 18 - SENTINEL-X) -----------------------'
  '  [!! CRITICAL !!]  CTI IOC sweep: 1 category matches found'
  '                     Fix: Review Section 18 for specific IOC matches.'
  '  --- SYSTEM HARDENING  (Section 13) ---------------------------------'
  '  [  WARNING   ]  BitLocker OFF for C:'
  '  [    OK      ]  UAC on with prompt'
  '  NEXT STEPS -- CRITICAL issues found:'
)
$lines | Set-Content -LiteralPath $r -Encoding UTF8
.\tools\report_html.ps1 -Report $r -HtmlPath $h
if (-not (Test-Path $h)) { Write-Host 'report_html produced no HTML'; exit 1 }
$html = Get-Content -LiteralPath $h -Raw
if ($html -notmatch 'Findings Index') { Write-Host 'no Findings Index panel'; exit 1 }
if ($html -notmatch 'CTI IOC sweep: 1 category matches found') { Write-Host 'critical finding not surfaced'; exit 1 }
if ($html -notmatch 'href="#sec18"') { Write-Host 'critical not linked to its section'; exit 1 }
if ($html -notmatch '<div class="card card-crit"><h3>1</h3>') { Write-Host 'dashboard crit count not taken from verdict line'; exit 1 }
# EVERY dashboard card must carry the report's own numbers, not just
# the CRITICAL one. report_html builds them by matching the verdict
# line, and when that regex stops matching the cards do not go stale
# -- they render 0/0/0. A machine with real CRITICAL findings showed a
# dashboard of zero after the header gained ledger-derived counts and
# its separator changed from '/' to ' -- '. Nothing caught it because
# THIS FIXTURE STILL USED THE OLD FORMAT: a test whose input has
# drifted from what the tool emits proves nothing. The fixture above
# is now the current shape, and all three counts are asserted.
if ($html -notmatch '<div class="card card-warn"><h3>2</h3>') { Write-Host 'dashboard WARNING count not taken from verdict line'; exit 1 }
if ($html -notmatch '<div class="card card-ok"><h3>5</h3>')   { Write-Host 'dashboard PASSED count not taken from verdict line'; exit 1 }
# The clean-machine header carries no CRITICAL/WARNING numbers at all.
# Leaving it unmatched put a 0 in the PASSED card on exactly the runs
# where that count is the reassuring part.
$rc = Join-Path $env:TEMP 'dz_ci_html_clean.txt'
$hc = Join-Path $env:TEMP 'dz_ci_html_clean.html'
@(
  '######################################################################'
  '##  SECURITY AUDIT SUMMARY  --  CITEST'
  '##  NO FINDINGS COUNTED  --  42 DASHBOARD CHECKS PASSED  --  not a statement that the system is clean'
  '######################################################################'
  '  --- SYSTEM HARDENING  (Section 13) ---------------------------------'
  '  [    OK      ]  UAC on with prompt'
  '  NEXT STEPS -- nothing to do'
) | Set-Content -LiteralPath $rc -Encoding UTF8
.\tools\report_html.ps1 -Report $rc -HtmlPath $hc
$htmlc = Get-Content -LiteralPath $hc -Raw
if ($htmlc -notmatch '<div class="card card-ok"><h3>42</h3>') { Write-Host 'clean-machine PASSED count not taken from verdict line'; exit 1 }
Remove-Item $rc, $hc -Force -EA SilentlyContinue

# The HTML page is what doze_sec.bat opens in the browser. It used to
# drop every line before the first section banner -- the report
# header, the whole Tier 0 READ THIS FIRST block, and the table of
# contents -- because $inPre starts false and the preamble is pure
# prose. Findings told the reader to "read the READ THIS FIRST
# section at the top of this report" before remediating (it can alert
# an abusive partner and destroys evidence) and that section was not
# there. Assert the real preamble survives, and that it is NOT buried
# in a collapsed <details>.
$r2 = Join-Path $env:TEMP 'dz_ci_html_preamble.txt'
$h2 = Join-Path $env:TEMP 'dz_ci_html_preamble.html'
$pre = .\tools\report_safety.ps1 -Mode Preamble
$pre + @(
  '  TABLE OF CONTENTS'
  '===================================================================='
  ' [13/18] SYSTEM HARDENING'
  '===================================================================='
  '[OK] placeholder'
) | Set-Content -LiteralPath $r2 -Encoding UTF8
.\tools\report_html.ps1 -Report $r2 -HtmlPath $h2
$html2 = Get-Content -LiteralPath $h2 -Raw
foreach ($must in @('READ THIS FIRST', 'accessnow.org/help', 'stopstalkerware.org', 'PRESERVE EVIDENCE', 'TABLE OF CONTENTS')) {
  if ($html2 -notmatch [regex]::Escape($must)) { Write-Host "preamble content missing from HTML: $must"; exit 1 }
}
if ($html2 -notmatch 'id="readfirst"') { Write-Host 'no readfirst panel in the HTML'; exit 1 }
# The panel must be reachable without expanding anything: everything
# from the panel open tag to its close must contain no <details>.
$panel = [regex]::Match($html2, 'id="readfirst"[\s\S]*?</div>')
if (-not $panel.Success) { Write-Host 'readfirst panel not delimited'; exit 1 }
if ($panel.Value -match '<details') { Write-Host 'READ THIS FIRST is hidden inside a <details> -- it must be visible without interaction'; exit 1 }
Remove-Item $r2, $h2 -Force -EA SilentlyContinue
Write-Host 'report_html OK (Findings Index, section link, verdict-based counts, visible READ THIS FIRST)'
exit 0
