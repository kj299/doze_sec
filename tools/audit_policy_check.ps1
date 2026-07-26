# audit_policy_check.ps1 -- verify the host is actually GENERATING the events
# the audit's event-log checks depend on. Invoked from Section 16.
#
# WHY THIS EXISTS (a whole class of false-cleans): the audit reads Security
# events -- 4688 process creation, 4624/4625 logon, 4720 account creation,
# 1102 log-clear -- and reports "[OK] no suspicious ..." when it finds none.
# But stock Windows does NOT audit process creation, and NEVER records process
# command lines without an explicit policy. So on a default box "no suspicious
# process-creation events" almost always means "process creation is not being
# audited" -- reported to the user as clean. For someone deciding whether their
# device is safe, that silent blindness is the most dangerous kind of result.
#
# This check makes the blindness VISIBLE: it reports which high-value audit
# subcategories are off, so a downstream "clean" event check is understood as
# "clean, AND the events were actually being recorded" rather than "clean
# because nothing was watching."
#
# LOCALE SAFETY: subcategories are addressed by their locale-independent GUIDs
# (the display names auditpol prints are localized -- the same trap that made
# the old netsh firewall scrape misreport on non-English Windows). The
# command-line-inclusion signal is read straight from the registry, which is
# fully locale-independent. The auditpol Inclusion-Setting text ("Success" /
# "No Auditing") IS localized; that parse is best-effort and its result is
# clearly labelled, while the registry cmdline signal is definitive everywhere.
#
# SEVERITY: WARNING (never CRITICAL). Auditing being off is the DEFAULT on a
# fresh install, not proof of tampering -- but it does mean the event-based
# detections cannot be trusted as clean, which the user must know. If auditpol
# itself cannot run, the check reports [SKIPPED] rather than a false [OK].
#
# MARKER: writes the severity word to $env:TEMP\dz_auditpol.txt; the caller
# reads it and raises via :dz_finding. No marker when everything is enabled.
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -EA SilentlyContinue
}

'--- [T1562.002/DS0026] Audit-policy visibility (are the events even being logged?) ---'
$sev = 'OK'

# Subcategories whose absence blinds a detection the audit actually performs.
# GUIDs are locale-independent; names are for the report only.
$subs = @(
    @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Process Creation (4688)';         Feeds = 'suspicious-process, service-install and LOLBin event checks' },
    @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon (4624/4625)';                Feeds = 'logon / failed-logon and lateral-movement checks' },
    @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management (4720/4732)'; Feeds = 'new-account and admin-group-change checks' },
    @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change (4719)';        Feeds = 'detection of auditing being turned off by an attacker' }
)

$apOk = $true
$rows = @{}
try {
    $guidList = ($subs | ForEach-Object { $_.Guid }) -join ','
    $csv = & auditpol /get ("/subcategory:$guidList") /r 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $csv) { $apOk = $false }
    else {
        foreach ($line in ($csv | ConvertFrom-Csv)) {
            $g = [string]$line.'Subcategory GUID'
            if ($g) { $rows[$g.Trim().ToLower()] = [string]$line.'Inclusion Setting' }
        }
    }
} catch { $apOk = $false }

if (-not $apOk) {
    '[SKIPPED] auditpol could not be queried -- audit-policy visibility NOT verified (needs admin).'
    $sev = 'WARNING'
} else {
    foreach ($s in $subs) {
        $set = $rows[$s.Guid.ToLower()]
        # "Success" present => the success events this feeds are being recorded.
        # Empty or "No Auditing" => blind. (Localized text may read otherwise on
        # non-English Windows; the cmdline registry signal below is definitive.)
        if ($set -and $set -match 'Success') {
            "[OK] $($s.Name) auditing is ON -- feeds $($s.Feeds)."
        } else {
            $shown = if ($set) { $set } else { '(not set)' }
            "[WARNING] $($s.Name) auditing is OFF [$shown] -- a clean result for the $($s.Feeds) may only mean these events are not being recorded (T1562.002)."
            $sev = 'WARNING'
        }
    }
}

# Command-line inclusion in 4688 -- locale-independent registry signal. Without
# it, even when 4688 is on, the events carry no command line, so any check that
# inspects a process command line from the log is blind to the payload.
$cmdKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$cmd = $null
try { $cmd = (Get-ItemProperty -Path $cmdKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -EA SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled } catch {}
if ($cmd -eq 1) {
    '[OK] Process-creation command-line logging is ENABLED (4688 events include the command line).'
} else {
    '[WARNING] Process-creation command-line logging is DISABLED -- even audited 4688 events omit the command line, hiding the actual payload of a malicious launch (T1562.002).'
    $sev = 'WARNING'
}

Write-Marker -Name 'auditpol' -Sev $sev
