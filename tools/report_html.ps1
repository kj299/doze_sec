# report_html.ps1 -- render the audit text report as a navigable HTML report.
#
# Extracted from doze_sec.bat's inline generator so it is (a) testable -- the
# windows-smoke helpers-ps51 job runs it on a sample report -- and (b) free of
# cmd.exe escaping, which made the inline version fragile and impossible to
# validate on CI.
#
# Clarity features (closes the "which findings are critical / what section?"
# confusion):
#   - A "Findings Index" panel at the very top lists every CRITICAL and WARNING
#     finding, each linking to the section it belongs to.
#   - The computed live-summary block is rendered as a color-coded panel
#     instead of being buried as plain text inside Section 18.
#   - Dashboard counts come from the report's own verdict line
#     ("N CRITICAL / M WARNING / P PASSED") so they always match the text
#     report. The old naive substring counting over-counted incidental
#     "[CRITICAL]" mentions in descriptive text (e.g. 30 WARNING vs a real 4).
#
# Windows PowerShell 5.1 compatible (no pwsh-7-only syntax).
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File report_html.ps1 `
#       -Report <txt> -HtmlPath <html> [-RemediationPath <ps1>]

param(
    [Parameter(Mandatory=$true)] [string]$Report,
    [Parameter(Mandatory=$true)] [string]$HtmlPath,
    [Parameter(Mandatory=$false)][string]$RemediationPath = ''
)

$ErrorActionPreference = 'Continue'
if (-not (Test-Path -LiteralPath $Report)) { return }

Add-Type -AssemblyName System.Web
$lines = Get-Content -LiteralPath $Report -Encoding UTF8

function Enc([string]$s) { [System.Web.HttpUtility]::HtmlEncode($s) }

$nav      = [System.Text.StringBuilder]::new()
$body     = [System.Text.StringBuilder]::new()
$summary  = [System.Text.StringBuilder]::new()
$critList = New-Object System.Collections.Generic.List[string]
$warnList = New-Object System.Collections.Generic.List[string]

$secNum = 0
$inPre = $false
$inSummary = $false
$haveSummary = $false
$sumAnchor = ''
$sumCat = ''
$vCrit = $null; $vWarn = $null; $vPass = $null
$okCount = 0; $warnCount = 0; $critCount = 0; $infoCount = 0

foreach ($line in $lines) {
    $esc = Enc $line
    $t = $line.Trim()

    # ---- Enter the computed live-summary block ----
    if (-not $inSummary -and $t -match 'SECURITY AUDIT SUMMARY') {
        if ($inPre) { [void]$body.AppendLine('</pre></details>'); $inPre = $false }
        if ($secNum -ne 0) { [void]$body.AppendLine('</div>') }  # close the last section div
        $inSummary = $true
        $haveSummary = $true
        [void]$summary.AppendLine('<div class="section" id="summary"><h2>Live Security Summary</h2>')
        continue
    }
    # ---- Exit the summary block at the next major banner ----
    if ($inSummary -and ($t -match '^NEXT STEPS' -or $t -match 'REMEDIATION SCRIPT' -or $t -match 'AUDIT COMPLETE')) {
        [void]$summary.AppendLine('</div>')
        $inSummary = $false
        continue
    }

    if ($inSummary) {
        # Verdict line: "N CRITICAL / M WARNING / P PASSED"
        if ($t -match '(\d+)\s+CRITICAL\s*/\s*(\d+)\s+WARNING\s*/\s*(\d+)\s+PASSED') {
            $vCrit = [int]$Matches[1]; $vWarn = [int]$Matches[2]; $vPass = [int]$Matches[3]
            continue
        }
        # Category subheader: --- TITLE (Section N) ---
        if ($t -match '^---\s*(.+?)\s*-{2,}\s*$') {
            $cat = $Matches[1].Trim()
            if ($cat -match '\(Section (\d+)') { $sumAnchor = 'sec' + $Matches[1] } else { $sumAnchor = '' }
            $sumCat = $cat
            [void]$summary.AppendLine('<h3 class="sub">' + (Enc $cat) + '</h3>')
            continue
        }
        # CRITICAL finding (icon "[!! CRITICAL !!]" or plain "[CRITICAL]")
        if ($t -match '^\[\s*!*\s*CRITICAL\s*!*\s*\]\s*(.*)$') {
            $msg = $Matches[1]
            $jump = ''
            $where = Enc $sumCat
            if ($sumAnchor) {
                $jump = ' <a class="jump" href="#' + $sumAnchor + '">(go to section)</a>'
                $where = '<a href="#' + $sumAnchor + '">' + (Enc $sumCat) + '</a>'
            }
            [void]$summary.AppendLine('<div class="crit">[CRITICAL] ' + (Enc $msg) + $jump + '</div>')
            $critList.Add('<li><span class="badge badge-crit">CRITICAL</span> ' + (Enc $msg) + ' <span class="where">&mdash; ' + $where + '</span></li>')
            continue
        }
        # WARNING finding
        if ($t -match '^\[\s*WARNING\s*\]\s*(.*)$') {
            $msg = $Matches[1]
            $jump = ''
            $where = Enc $sumCat
            if ($sumAnchor) {
                $jump = ' <a class="jump" href="#' + $sumAnchor + '">(go to section)</a>'
                $where = '<a href="#' + $sumAnchor + '">' + (Enc $sumCat) + '</a>'
            }
            [void]$summary.AppendLine('<div class="warn">[WARNING] ' + (Enc $msg) + $jump + '</div>')
            $warnList.Add('<li><span class="badge badge-warn">WARNING</span> ' + (Enc $msg) + ' <span class="where">&mdash; ' + $where + '</span></li>')
            continue
        }
        if ($t -match '^\[\s*OK\s*\]\s*(.*)$')   { [void]$summary.AppendLine('<div class="ok">[OK] '   + (Enc $Matches[1]) + '</div>'); continue }
        if ($t -match '^\[\s*INFO\s*\]\s*(.*)$') { [void]$summary.AppendLine('<div class="info">[INFO] ' + (Enc $Matches[1]) + '</div>'); continue }
        if ($t -match '^Fix:\s*(.*)$')           { [void]$summary.AppendLine('<div class="fix">' + (Enc $t) + '</div>'); continue }
        # banner / blank lines inside the summary block -> skip
        continue
    }

    # ---- Normal per-section rendering ----
    # Severity tokens are anchored to the start of the line so incidental
    # "[CRITICAL]" mentions in descriptive text are not mis-colored/counted.
    if ($line -match '^\s*\[(\d+)/18\]\s+(.+)$') {
        if ($inPre) { [void]$body.AppendLine('</pre></details>'); $inPre = $false }
        $secNum = $Matches[1]; $secTitle = $Matches[2].Trim()
        [void]$nav.AppendLine('<a href="#sec' + $secNum + '">' + $secNum + '. ' + (Enc $secTitle) + '</a>')
        [void]$body.AppendLine('</div><div class="section" id="sec' + $secNum + '"><h2>[' + $secNum + '/18] ' + (Enc $secTitle) + '</h2>')
        [void]$body.AppendLine('<details open><summary>Section output</summary><pre>')
        $inPre = $true
    }
    elseif ($line -match '^\s*\[OK\]') {
        $okCount++
        if ($inPre) { [void]$body.AppendLine('</pre></details>'); $inPre = $false }
        [void]$body.AppendLine('<div class="ok">' + $esc + '</div>')
        [void]$body.AppendLine('<details><summary>Details</summary><pre>'); $inPre = $true
    }
    elseif ($line -match '^\s*\[(WARNING|WARN)\]') {
        $warnCount++
        if ($inPre) { [void]$body.AppendLine('</pre></details>'); $inPre = $false }
        [void]$body.AppendLine('<div class="warn">' + $esc + '</div>')
        [void]$body.AppendLine('<details><summary>Details</summary><pre>'); $inPre = $true
    }
    elseif ($line -match '^\s*\[(CRITICAL|CRIT)\]') {
        $critCount++
        if ($inPre) { [void]$body.AppendLine('</pre></details>'); $inPre = $false }
        [void]$body.AppendLine('<div class="crit">' + $esc + '</div>')
        [void]$body.AppendLine('<details><summary>Details</summary><pre>'); $inPre = $true
    }
    elseif ($line -match '^\s*\[INFO\]') {
        $infoCount++
        if ($inPre) { [void]$body.AppendLine('</pre></details>'); $inPre = $false }
        [void]$body.AppendLine('<div class="info">' + $esc + '</div>')
        [void]$body.AppendLine('<details><summary>Details</summary><pre>'); $inPre = $true
    }
    elseif ($line -match '^-{60,}\s*$') {
        # section terminator from report_format.ps1; HTML delimits via <details>
    }
    else {
        if ($inPre) { [void]$body.AppendLine($esc) }
    }
}
if ($inPre) { [void]$body.AppendLine('</pre></details></div>') }

# Dashboard counts: prefer the authoritative verdict line; fall back to the
# anchored per-section tallies if the summary block was not found.
$cCrit = if ($vCrit -ne $null) { $vCrit } else { $critCount }
$cWarn = if ($vWarn -ne $null) { $vWarn } else { $warnCount }
$cPass = if ($vPass -ne $null) { $vPass } else { $okCount }

# Findings Index panel
$index = ''
if ($critList.Count -gt 0 -or $warnList.Count -gt 0) {
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<div class="section" id="findings"><h2>Findings Index</h2>')
    if ($critList.Count -gt 0) {
        [void]$sb.AppendLine('<h3 class="crit-h">Critical (' + $critList.Count + ')</h3><ul class="findings">')
        foreach ($li in $critList) { [void]$sb.AppendLine($li) }
        [void]$sb.AppendLine('</ul>')
    }
    if ($warnList.Count -gt 0) {
        [void]$sb.AppendLine('<h3 class="warn-h">Warnings (' + $warnList.Count + ')</h3><ul class="findings">')
        foreach ($li in $warnList) { [void]$sb.AppendLine($li) }
        [void]$sb.AppendLine('</ul>')
    }
    [void]$sb.AppendLine('</div>')
    $index = $sb.ToString()
}

# ---- Assemble the document ----
$html = [System.Text.StringBuilder]::new()
[void]$html.AppendLine('<!DOCTYPE html>')
[void]$html.AppendLine('<html lang="en"><head><meta charset="UTF-8">')
[void]$html.AppendLine('<title>Security Audit Report</title>')
[void]$html.AppendLine('<style>')
[void]$html.AppendLine('body{font-family:Consolas,monospace;margin:0;background:#1a1a2e;color:#e0e0e0}')
[void]$html.AppendLine('.wrap{display:flex}')
[void]$html.AppendLine('nav{position:fixed;top:0;left:0;width:260px;height:100vh;overflow-y:auto;background:#16213e;padding:16px;box-sizing:border-box;border-right:2px solid #0f3460}')
[void]$html.AppendLine('nav h2{color:#56cfe1;font-size:14px;margin:0 0 12px}')
[void]$html.AppendLine('nav a{display:block;color:#a8b2d1;text-decoration:none;padding:4px 0;font-size:12px}')
[void]$html.AppendLine('nav a:hover{color:#56cfe1}')
[void]$html.AppendLine('main{margin-left:270px;padding:20px;max-width:1100px}')
[void]$html.AppendLine('.section{margin-bottom:24px;border:1px solid #0f3460;border-radius:6px;padding:16px;background:#16213e}')
[void]$html.AppendLine('.section h2{color:#56cfe1;margin-top:0;font-size:16px;border-bottom:1px solid #0f3460;padding-bottom:8px}')
[void]$html.AppendLine('.ok{color:#00d26a;font-weight:bold;overflow-wrap:anywhere}')
[void]$html.AppendLine('.warn{color:#ffc107;font-weight:bold;overflow-wrap:anywhere}')
[void]$html.AppendLine('.crit{color:#ff4444;font-weight:bold;background:#3a0000;padding:4px 8px;border-radius:3px;overflow-wrap:anywhere;margin:3px 0}')
[void]$html.AppendLine('.info{color:#17a2b8;overflow-wrap:anywhere}')
[void]$html.AppendLine('.fix{color:#9aa7c7;font-size:12px;margin:0 0 6px 18px;overflow-wrap:anywhere}')
[void]$html.AppendLine('h3.sub{color:#56cfe1;font-size:13px;margin:14px 0 6px;border-bottom:1px solid #0f3460;padding-bottom:4px}')
[void]$html.AppendLine('h3.crit-h{color:#ff4444;font-size:14px;margin:6px 0}')
[void]$html.AppendLine('h3.warn-h{color:#ffc107;font-size:14px;margin:14px 0 6px}')
[void]$html.AppendLine('ul.findings{list-style:none;padding-left:0;margin:0}')
[void]$html.AppendLine('ul.findings li{padding:8px 10px;margin-bottom:6px;background:#0f3460;border-radius:4px;overflow-wrap:anywhere}')
[void]$html.AppendLine('.badge{display:inline-block;font-size:10px;font-weight:bold;padding:2px 6px;border-radius:3px;margin-right:6px}')
[void]$html.AppendLine('.badge-crit{background:#ff4444;color:#1a1a2e}')
[void]$html.AppendLine('.badge-warn{background:#ffc107;color:#1a1a2e}')
[void]$html.AppendLine('.where{color:#a8b2d1;font-size:12px}')
[void]$html.AppendLine('.jump{color:#ff8888;font-size:11px;text-decoration:none}')
[void]$html.AppendLine('.where a,.jump:hover{color:#56cfe1}')
[void]$html.AppendLine('details{margin:8px 0}')
[void]$html.AppendLine('summary{cursor:pointer;color:#a8b2d1;font-size:13px}')
[void]$html.AppendLine('summary:hover{color:#56cfe1}')
[void]$html.AppendLine('pre{background:#0a0a1a;padding:12px;border-radius:4px;font-size:12px;line-height:1.4;color:#c8c8c8;max-height:400px;overflow-x:auto;overflow-y:auto;white-space:pre-wrap;overflow-wrap:anywhere}')
[void]$html.AppendLine('.dashboard{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}')
[void]$html.AppendLine('.card{padding:16px;border-radius:6px;text-align:center}')
[void]$html.AppendLine('.card h3{margin:0;font-size:28px}')
[void]$html.AppendLine('.card p{margin:4px 0 0;font-size:12px}')
[void]$html.AppendLine('.card-ok{background:#0a3d0a;border:1px solid #00d26a}')
[void]$html.AppendLine('.card-warn{background:#3d3a0a;border:1px solid #ffc107}')
[void]$html.AppendLine('.card-crit{background:#3d0a0a;border:1px solid #ff4444}')
[void]$html.AppendLine('.card-info{background:#0a2a3d;border:1px solid #17a2b8}')
[void]$html.AppendLine('</style></head><body>')
[void]$html.AppendLine('<div class="wrap"><nav><h2>DOZE_SEC AUDIT</h2>')
[void]$html.AppendLine('<a href="#dashboard">Dashboard</a>')
if ($index -ne '') { [void]$html.AppendLine('<a href="#findings" style="color:#ff8888">Findings Index</a>') }
if ($haveSummary)  { [void]$html.AppendLine('<a href="#summary">Live Summary</a>') }
[void]$html.AppendLine($nav.ToString())
[void]$html.AppendLine('<a href="#remediation" style="color:#ffc107">Rollback Script</a>')
[void]$html.AppendLine('</nav><main>')
[void]$html.AppendLine('<div id="dashboard"><h1 style="color:#56cfe1;margin-top:0">Security Audit Report</h1>')
[void]$html.AppendLine('<div class="dashboard">')
[void]$html.AppendLine('<div class="card card-crit"><h3>' + $cCrit + '</h3><p>CRITICAL</p></div>')
[void]$html.AppendLine('<div class="card card-warn"><h3>' + $cWarn + '</h3><p>WARNING</p></div>')
[void]$html.AppendLine('<div class="card card-ok"><h3>' + $cPass + '</h3><p>PASSED</p></div>')
[void]$html.AppendLine('<div class="card card-info"><h3>' + $infoCount + '</h3><p>INFO</p></div>')
[void]$html.AppendLine('</div></div>')
if ($index -ne '') { [void]$html.AppendLine($index) }
if ($haveSummary)  { [void]$html.AppendLine($summary.ToString()) }
[void]$html.AppendLine('<div class="section">')
[void]$html.AppendLine($body.ToString())

# ---- Rollback / Remediation panel ----
if ($RemediationPath -and (Test-Path -LiteralPath $RemediationPath)) {
    $remLines = Get-Content -LiteralPath $RemediationPath -Encoding UTF8
    $fixes = @()
    for ($i = 0; $i -lt $remLines.Count - 1; $i++) {
        $l = $remLines[$i]; $n = $remLines[$i+1]
        if ($l.StartsWith('# ') -and $n -match '^(Set-|Disable-|Enable-|netsh|bcdedit|Update-|Stop-|sfc|New-|Get-|Remove-|Write-Host)') {
            $fixes += [PSCustomObject]@{ Desc = $l.Substring(2).Trim(); Cmd = $n.Trim() }
        }
    }
    [void]$html.AppendLine('<div class="section" id="remediation" style="border-color:#ffc107"><h2 style="color:#ffc107;border-bottom-color:#ffc107">Rollback Script: Proposed Fixes</h2>')
    [void]$html.AppendLine('<p><strong>Location:</strong> <code>' + (Enc $RemediationPath) + '</code></p>')
    [void]$html.AppendLine('<p>This script reverts risky configurations detected above back to safe defaults. <strong>Review every command before running.</strong></p>')
    if ($fixes.Count -gt 0) {
        [void]$html.AppendLine('<p><strong>' + $fixes.Count + ' auto-fix command(s) queued:</strong></p>')
        [void]$html.AppendLine('<ul style="list-style:none;padding-left:0">')
        foreach ($f in $fixes) {
            [void]$html.AppendLine('<li style="margin-bottom:10px;padding:10px;background:#0f3460;border-radius:4px;border-left:3px solid #ffc107">')
            [void]$html.AppendLine('<div style="color:#ffc107;font-weight:bold;margin-bottom:4px">' + (Enc $f.Desc) + '</div>')
            [void]$html.AppendLine('<code style="display:block;color:#a8b2d1;font-size:11px;word-break:break-all">' + (Enc $f.Cmd) + '</code></li>')
        }
        [void]$html.AppendLine('</ul>')
    } else {
        [void]$html.AppendLine('<p><em>No auto-fixable findings detected. Remediation file contains the safety header only.</em></p>')
    }
    [void]$html.AppendLine('<h3 style="color:#56cfe1;margin-top:16px;font-size:14px">To Apply</h3>')
    [void]$html.AppendLine('<ol><li>Open the script and review every command.</li>')
    [void]$html.AppendLine('<li>Change <code>$IReadAndUnderstand=$false</code> to <code>$true</code>.</li>')
    [void]$html.AppendLine('<li>Run from elevated PowerShell: <code>powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Enc $RemediationPath) + '"</code></li></ol>')
    [void]$html.AppendLine('<details><summary>Full script contents</summary><pre>' + (Enc ($remLines -join "`n")) + '</pre></details>')
    [void]$html.AppendLine('</div>')
}
[void]$html.AppendLine('</main></div></body></html>')

$html.ToString() | Out-File -LiteralPath $HtmlPath -Encoding UTF8
