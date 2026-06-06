# ttp_merge.ps1 -- Process a sanitized CTI TTP feed into detection blocks,
# IOC-file merges, and ttp_manifest.txt rows. Invoked by doze_sec.bat from
# the -updateTTP / -importTTP handler.
#
# The previous inline-bat implementation handled three things in two nested
# CMD `for /f` loops with `if !errorlevel!` checks inside multiple levels of
# parenthesized blocks. That worked for the original three Detection_Method
# branches but reliably broke when extended -- CMDs block-boundary scanner
# counts every paren in a for-body (including those in echo args), errorlevel
# propagation through delayed-expansion-vs-immediate-expansion is fragile,
# and findstr inside the loop emits stray "system cannot find" errors as
# soon as a fourth merge branch is added. PR #80 fixed the most user-visible
# crash via paren-escaping, but the loop is still the wrong tool for the job.
# This helper replaces it with one PowerShell pass.
#
# What it does:
#   1. Read TTP_OUTPUT (pipe-delimited, 6 fields per row, already sanitized
#      by the CMD-side PS one-liner against shell metacharacters and the
#      Detection_Method allowlist).
#   2. For each row, emit a detection command into BlocksFile (append) using
#      the same template the inline bat used. Detection_Method routing:
#        registry key   -> reg query
#        event ID       -> wevtutil qe Security
#        process name   -> Get-CimInstance Win32_Process via PSRUN
#        file path      -> if exist
#        named pipe     -> Get-ChildItem \\.\pipe\ via PSRUN
#        wmi query      -> Get-CimInstance -Query via PSRUN
#   3. Merge new IOC values into the appropriate ThreatLists/ioc_*.txt file
#      (skip if the literal value already appears). Mapping (closes #78):
#        process name   -> ioc_processes.txt
#        named pipe     -> ioc_named_pipes.txt
#        file path      -> ioc_file_paths.txt
#        registry key   -> ioc_registry.txt    (NEW)
#        event ID, wmi query -> no IOC file (inline-only)
#   4. Append a row to ttp_manifest.txt for each unique MITRE_ID not already
#      present (closes #79). The CTI schema has no Tactic column, so we
#      write "CTI-AUTO" in the tactic slot; the MITRE_ID itself is enough
#      for analysts to look up the real tactic.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File ttp_merge.ps1 `
#       -TtpOutput   "<path to sanitized feed>" `
#       -BlocksFile  "<path to ttp_generated_checks.bat>" `
#       -ThreatListsDir "<path to ThreatLists/>"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$TtpOutput,
    [Parameter(Mandatory=$true)] [string]$BlocksFile,
    [Parameter(Mandatory=$true)] [string]$ThreatListsDir
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path -LiteralPath $TtpOutput)) {
    Write-Error "ttp_merge.ps1: TTP feed not found: $TtpOutput"
    exit 2
}

$rows = @(Get-Content -LiteralPath $TtpOutput -EA SilentlyContinue |
    Where-Object { $_ -and $_.Trim() -ne '' })

if ($rows.Count -eq 0) {
    Write-Output "  [INFO] No TTP rows to merge."
    exit 0
}

$today = Get-Date -Format 'ddd MM/dd/yyyy'

# --- Detection-block emitter --------------------------------------------------
# Each branch builds the literal bat lines that get appended to BlocksFile.
# Output strings use the same shapes the inline-bat handlers used in
# doze_sec.bat lines 454-488, so existing TTP_BLOCKS files stay compatible.

function Get-DetectionBlock {
    param([string]$Id, [string]$Name, [string]$Method, [string]$Value,
          [string]$Severity, [string]$Actor)
    $header = "echo --- [CTI-AUTO][$Id] $Name ($Actor) --->> `"%REPORT%`""
    switch ($Method.ToLower()) {
        'registry key' {
            return @(
                $header,
                "reg query `"$Value`">> `"%REPORT%`" 2>&1"
            )
        }
        'event id' {
            return @(
                $header,
                "wevtutil qe Security /q:`"*[System[(EventID=$Value)]]`" /c:10 /rd:true /f:text | findstr /c:`"TimeCreated`" /c:`"Account Name`">> `"%REPORT%`" 2>&1"
            )
        }
        'process name' {
            return @(
                $header,
                "echo Get-CimInstance Win32_Process -Filter `"name='$Value'`" -EA SilentlyContinue | Select-Object Name,ProcessId,ExecutablePath | Format-Table -AutoSize > `"%PSRUN%`"",
                "`"%PWSH%`" -NoProfile -ExecutionPolicy Bypass -File `"%PSRUN%`">> `"%REPORT%`" 2>&1"
            )
        }
        'file path' {
            return @(
                $header,
                "if exist `"$Value`" (echo [$Severity] $Name IOC found: $Value>> `"%REPORT%`") else (echo [OK] $Name check clear.>> `"%REPORT%`")"
            )
        }
        'named pipe' {
            return @(
                $header,
                "echo try{`$p=Get-ChildItem \\.\pipe\ -EA SilentlyContinue | Where-Object {`$_.Name -match '$Value'}; if(`$p){'[$Severity] $Name pipe detected: '+(`$p.Name -join ', ')}else{'[OK] $Name pipe check clear.'}}catch{'[INFO] Pipe check unavailable.'} > `"%PSRUN%`"",
                "`"%PWSH%`" -NoProfile -ExecutionPolicy Bypass -File `"%PSRUN%`">> `"%REPORT%`" 2>&1"
            )
        }
        'wmi query' {
            return @(
                $header,
                "echo try{`$r=Get-CimInstance -Query '$Value' -EA SilentlyContinue; if(`$r){'[$Severity] $Name WMI hit: '+(`$r | Out-String).Trim()}else{'[OK] $Name WMI check clear.'}}catch{'[INFO] WMI query failed: '+`$_.Exception.Message} > `"%PSRUN%`"",
                "`"%PWSH%`" -NoProfile -ExecutionPolicy Bypass -File `"%PSRUN%`">> `"%REPORT%`" 2>&1"
            )
        }
    }
    return @()
}

# --- IOC merge ----------------------------------------------------------------
# Detection_Method -> ioc_*.txt mapping. event ID / wmi query intentionally
# absent: those are inline event-pattern matches, no persistent IOC list.

$iocFileMap = @{
    'process name' = 'ioc_processes.txt'
    'named pipe'   = 'ioc_named_pipes.txt'
    'file path'    = 'ioc_file_paths.txt'
    'registry key' = 'ioc_registry.txt'    # closes #78
}

function Add-IocEntry {
    param([string]$Id, [string]$Actor, [string]$Method, [string]$Value)
    $rel = $iocFileMap[$Method.ToLower()]
    if (-not $rel) { return $false }
    $path = Join-Path $ThreatListsDir $rel
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    # Skip if the literal value already appears anywhere in the file (mirrors
    # the inline bat's `findstr /x /c:"<value>"` exact-line check).
    $existing = Get-Content -LiteralPath $path -EA SilentlyContinue
    if ($existing -contains $Value) { return $false }
    Add-Content -LiteralPath $path -Value "# CTI-AUTO $today [$Id] $Actor"
    Add-Content -LiteralPath $path -Value $Value
    return $true
}

# --- Manifest append ---------------------------------------------------------
# closes #79. Append per-MITRE_ID rows to ttp_manifest.txt so the master
# coverage map reflects what -updateTTP actually pulled. Skip MITRE_IDs that
# are already present (by line-start match on "<id>|").

$manifestPath = Join-Path $ThreatListsDir 'ttp_manifest.txt'
$manifestSeenIds = @{}
if (Test-Path -LiteralPath $manifestPath) {
    foreach ($line in Get-Content -LiteralPath $manifestPath -EA SilentlyContinue) {
        if ($line -match '^([A-Za-z0-9_.+\-]+)\|') {
            $manifestSeenIds[$Matches[1]] = $true
        }
    }
}

function Add-ManifestRow {
    param([string]$Id, [string]$Name, [string]$Actor)
    if (-not (Test-Path -LiteralPath $manifestPath)) { return $false }
    if ($manifestSeenIds.ContainsKey($Id)) { return $false }
    Add-Content -LiteralPath $manifestPath -Value "# CTI-AUTO $today [from -updateTTP]"
    Add-Content -LiteralPath $manifestPath -Value "$Id|CTI-AUTO|$Name|$Actor|Sec 18 CTI-auto via -updateTTP"
    $manifestSeenIds[$Id] = $true
    return $true
}

# --- Main loop ---------------------------------------------------------------

$blockLines = New-Object System.Collections.Generic.List[string]
$iocsAdded     = 0
$blocksWritten = 0
$manifestAdded = 0

foreach ($row in $rows) {
    $parts = $row -split '\|'
    if ($parts.Count -ne 6) { continue }
    $id       = $parts[0].Trim()
    $name     = $parts[1].Trim()
    $method   = $parts[2].Trim()
    $value    = $parts[3].Trim()
    $severity = $parts[4].Trim()
    $actor    = $parts[5].Trim()

    $block = Get-DetectionBlock -Id $id -Name $name -Method $method -Value $value -Severity $severity -Actor $actor
    if ($block.Count -gt 0) {
        foreach ($l in $block) { $blockLines.Add($l) }
        $blocksWritten++
    }

    if (Add-IocEntry -Id $id -Actor $actor -Method $method -Value $value) {
        $iocsAdded++
    }

    if (Add-ManifestRow -Id $id -Name $name -Actor $actor) {
        $manifestAdded++
    }
}

# Append all block lines to BlocksFile in one shot (cheaper than per-line Add).
if ($blockLines.Count -gt 0) {
    Add-Content -LiteralPath $BlocksFile -Value $blockLines
}

Write-Output ("  [OK] ttp_merge: $blocksWritten detection block(s) written, $iocsAdded IOC entry/entries merged, $manifestAdded ttp_manifest row(s) added")
exit 0
