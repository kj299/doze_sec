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
#                   FromBase64String / -e <base64>), or LOLBin download-and-exec
#                   (DownloadString/DownloadFile, iwr|curl|wget to http, piped
#                   or invoked iex, mshta http/javascript, certutil
#                   -urlcache/-decode, bitsadmin /transfer, regsvr32 /i:http or
#                   scrobj, rundll32 javascript); or execution from an unusual
#                   autorun location (\Temp\, \Downloads\, \Public\).
#                   A hidden-window launcher (-w hidden) is common in
#                   legitimate updaters, so it is flagged ONLY when it
#                   co-occurs with a download/encode indicator -- never on its
#                   own. Common legit autorun paths (\AppData\, \ProgramData\)
#                   are deliberately NOT flagged on path alone --
#                   Slack/Discord/Teams/Spotify live there -- so this does not
#                   reintroduce false alarms.
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

# PowerShell adds these note-properties to every Get-ItemProperty result; they
# are not registry values. Matched by EXACT name -- a '^PS' prefix match would
# also swallow real values whose names start with "PS".
$psNoteProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

# STRONG command-content indicators -- fire on their own (unambiguous):
# encoded PowerShell, base64 decode, and LOLBin download-and-exec.
$strongContent = @(
    '-enc(odedcommand)?\b',
    '-e\s+[A-Za-z0-9+/=]{24,}',
    'frombase64string',
    'downloadstring', 'downloadfile',
    '(invoke-webrequest|\biwr\b|\bcurl\b|\bwget\b)[^\r\n]*https?:',
    '(iex|invoke-expression)\s*[\(\$]', '\|\s*(iex|invoke-expression)\b',
    'mshta\s+https?:', 'mshta\s+javascript', 'mshtml,runhtmlapplication',
    'certutil[^\r\n]*-urlcache', 'certutil[^\r\n]*-decode', 'bitsadmin[^\r\n]*/transfer',
    'regsvr32[^\r\n]*/i:http', 'regsvr32[^\r\n]*scrobj', 'rundll32[^\r\n]*javascript'
)
# A hidden-window launcher (-w hidden) ALONE is common in legitimate updaters,
# so flag it only when it co-occurs with a download/encode indicator.
$hiddenLauncher = '-w(indowstyle)?\s+hidden'
$hiddenCombine  = @('-enc', 'frombase64', 'downloadstring', 'downloadfile',
                    'https?:', '(iex|invoke-expression)\b', '-e\s+[A-Za-z0-9+/=]{24,}')
# Unusual autorun LOCATIONS (path-only signal; kept narrow to avoid FPs).
# (\Users\Public\ is intentionally omitted -- it is already subsumed by \Public\.)
$suspPath = @('\\Temp\\', '\\Downloads\\', '\\Public\\')

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
        # Skip PowerShell's synthetic note-properties by EXACT name.
        #
        # This test used to be `-match '^PS'` -- a case-insensitive PREFIX
        # match. It skipped PSPath/PSChildName/... as intended, but it also
        # skipped every REAL registry value whose name merely began with "PS".
        # Naming a Run-key autorun "PSUpdater" or "psnotify" therefore hid it
        # from this evaluator completely: no verdict, no finding, no ledger
        # entry. That is a one-word evasion of the tool's most important
        # persistence check, and "PS" is a natural prefix for anything
        # PowerShell-flavoured, so it could also happen by accident.
        if ($psNoteProps -contains $p.Name) { continue }
        $val = [string]$p.Value
        if (-not $val) { continue }

        $why = $null
        foreach ($s in $strongContent) { if ($val -match $s) { $why = "command content ($s)"; break } }
        if (-not $why -and $val -match $hiddenLauncher) {
            foreach ($s in $hiddenCombine) { if ($val -match $s) { $why = "hidden-window launcher + $s"; break } }
        }
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
