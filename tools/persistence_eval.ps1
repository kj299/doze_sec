# persistence_eval.ps1 -- evaluate Run/RunOnce autoruns and IFEO Debugger
# hijacks for known-malicious indicators. Invoked from Section 5 of
# doze_sec.bat / doze_sec_noAdmin.bat.
#
# WHY: Section 5 raw-dumps the Run keys and printed a bare "[IFEO HIT]" for
# Debugger values, but never evaluated either -- an encoded-PowerShell Run
# key or an IFEO Debugger on a non-accessibility binary scrolled past with no
# verdict (code-review gaps, issue #138). This adds high-signal, low-false-
# positive evaluation:
#
#   Run/RunOnce  -- flags autorun commands whose CONTENT is a strong backdoor
#                   indicator: encoded PowerShell (-enc / -EncodedCommand /
#                   FromBase64String), hidden-window launchers, LOLBin
#                   download-and-exec (iex/DownloadString/mshta/certutil
#                   -urlcache/bitsadmin /transfer/regsvr32 /i:http/rundll32
#                   javascript), or execution from an unusual autorun location
#                   (\Temp\, \Downloads\, \Public\). Common legit autorun
#                   paths (\AppData\, \ProgramData\) are deliberately NOT
#                   flagged on path alone -- Slack/Discord/Teams/Spotify live
#                   there -- so this does not reintroduce false alarms.
#
#   IFEO         -- ANY Debugger value under Image File Execution Options is a
#                   hijack technique (the debugger runs instead of the target
#                   binary). Section 13 escalates the accessibility binaries
#                   to CRITICAL separately; here every IFEO Debugger, on any
#                   binary, is surfaced as a WARNING so non-accessibility
#                   targets (e.g. notepad.exe) are no longer silent.
#
# A finding writes -MarkerFile so the caller raises the exit code / findings
# count. CRITICAL is intentionally not emitted here (these are high-but-not-
# certain indicators); the caller treats a hit as a WARNING.
#
# Windows PowerShell 5.1 compatible. Read-only (registry reads + one marker
# file write). Executed by the helpers-ps51 CI job.

[CmdletBinding()]
param(
    [string]$MarkerFile
)

$ErrorActionPreference = 'Continue'

# Command-content backdoor indicators (case-insensitive -match patterns).
$suspContent = @(
    '-enc(odedcommand)?\b',
    '-e[ncw]*\s+[A-Za-z0-9+/=]{16,}',
    'frombase64string',
    '-w(indowstyle)?\s+hidden',
    'hidden\b.*\benc',
    '\biex\b', 'invoke-expression', 'downloadstring', 'downloadfile', 'invoke-webrequest',
    'mshta\s+https?:', 'mshta\s+javascript', 'mshtml,runhtmlapplication',
    'certutil.*-urlcache', 'certutil.*-decode', 'bitsadmin.*/transfer',
    'regsvr32.*/i:http', 'regsvr32.*scrobj', 'rundll32.*javascript'
)
# Unusual autorun LOCATIONS (path-only signal; kept narrow to avoid FPs).
$suspPath = @('\\Temp\\', '\\Downloads\\', '\\Public\\', '\\Users\\Public\\')

$runKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)

$found = $false

foreach ($k in $runKeys) {
    if (-not (Test-Path $k)) { continue }
    $props = Get-ItemProperty -Path $k -EA SilentlyContinue
    if (-not $props) { continue }
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -match '^PS') { continue }
        $val = [string]$p.Value
        if (-not $val) { continue }

        $why = $null
        foreach ($s in $suspContent) { if ($val -match $s) { $why = "command content ($s)"; break } }
        if (-not $why) { foreach ($s in $suspPath) { if ($val -match $s) { $why = "unusual autorun path ($s)"; break } } }

        if ($why) {
            $found = $true
            # Value NAME on the [WARNING] line so it is greppable per-entry.
            "[WARNING] Suspicious Run-key autorun [$($k)\$($p.Name)]: $val"
            "  indicator: $why"
        }
    }
}

$ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$ifeoOk = $true
$subs = $null
try { $subs = Get-ChildItem -Path $ifeoBase -EA Stop } catch { $ifeoOk = $false }
if (-not $ifeoOk) {
    '[SKIPPED] IFEO enumeration failed -- Debugger-hijack evaluation NOT performed.'
} else {
    foreach ($sub in $subs) {
        $d = Get-ItemProperty -Path $sub.PSPath -Name Debugger -EA SilentlyContinue
        if ($d -and $d.Debugger) {
            $found = $true
            "[WARNING] IFEO Debugger hijack: $($sub.PSChildName) => $($d.Debugger)"
        }
    }
}

if (-not $found) {
    '[OK] No suspicious Run-key autoruns or IFEO Debugger hijacks.'
} elseif ($MarkerFile) {
    Set-Content -LiteralPath $MarkerFile -Value 'hit' -EA SilentlyContinue
}
