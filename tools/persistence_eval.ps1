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

function Write-MarkerFile {
    # The marker IS the route to the findings ledger: a failed write turns a
    # real finding into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine failure print instead of vanishing -- the
    # bare `Set-Content -EA SilentlyContinue` this replaces is the exact
    # pattern that cost a field test its finding across twelve tools, and it
    # survived here because tests/marker_selftest.ps1 only discovered tools
    # that define a Write-Marker FUNCTION.
    param([string]$Path, [string]$Value = 'hit')
    if (-not $Path) { return }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Value -Encoding ASCII
}

# Registry key last-write time. PowerShell's registry provider does NOT expose
# it -- Get-Item on a key returns a RegistryKey with no LastWriteTime -- so it
# has to come from RegQueryInfoKey. The type is defined once per process and
# every failure path degrades to $null, which simply omits the registry half of
# the "when:" line rather than inventing a date.
function Get-RegKeyLastWrite {
    param([string]$KeyPath)
    if (-not $KeyPath) { return $null }
    try {
        if (-not ([System.Management.Automation.PSTypeName]'DozeSec.RegTime').Type) {
            Add-Type -ErrorAction Stop -Namespace DozeSec -Name RegTime -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int RegQueryInfoKey(IntPtr hKey, System.Text.StringBuilder lpClass,
    IntPtr lpcchClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen,
    IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen,
    IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
'@
        }
    } catch { return $null }
    $key = $null
    try {
        # Accept both provider paths (HKLM:\...) and PSPath forms.
        $p = $KeyPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
        $p = $p -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM:\' -replace '^HKEY_CURRENT_USER\\', 'HKCU:\'
        $key = Get-Item -LiteralPath $p -EA Stop
        $ft = [long]0
        $rc = [DozeSec.RegTime]::RegQueryInfoKey($key.Handle.DangerousGetHandle(),
            $null, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [IntPtr]::Zero, [ref]$ft)
        if ($rc -ne 0 -or $ft -le 0) { return $null }
        return [datetime]::FromFileTime($ft)
    } catch { return $null }
}

# Timestamps on a persistence finding: WHEN did this appear? For someone working
# out whether an implant predates a relationship, a job, or a break-in, that is
# the question the finding itself never answered. Both halves are optional --
# whichever is unavailable is simply omitted.
#
# TWO LIMITS, STATED IN THE REPORT TOO, because a timestamp presented without
# them is worse than none:
#   * Registry last-write is per KEY, not per value. Changing ANY value in a Run
#     key updates the whole key, so this is an upper bound on when THIS entry
#     appeared, not a precise date for it.
#   * File times are trivially forged (timestomping, T1070.006). An attacker who
#     cares sets them to whatever they like.
function Get-WhenLine {
    param([string]$KeyPath = '', [string]$FilePath = '')
    $parts = @()
    if ($KeyPath) {
        $lw = Get-RegKeyLastWrite $KeyPath
        if ($null -ne $lw) { $parts += ("registry key last modified {0}" -f $lw.ToString('yyyy-MM-dd HH:mm:ss')) }
    }
    if ($FilePath) {
        try {
            $f = Get-Item -LiteralPath $FilePath -EA Stop
            $parts += ("file written {0}" -f $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
            # Creation AFTER last-write is the classic timestomp tell, so show
            # creation whenever the two disagree in either direction.
            if ($f.CreationTime -and $f.CreationTime -ne $f.LastWriteTime) {
                $parts += ("created {0}" -f $f.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))
            }
        } catch {}
    }
    if ($parts.Count -eq 0) { return $null }
    return ("  when: {0}" -f ($parts -join '  |  '))
}

# Pull the executable out of an autorun command line so its file times can be
# read: strip a quoted path, or take everything up to the first argument, then
# expand environment variables. Returns '' when nothing file-like is found (a
# pure `powershell -enc <blob>` autorun has no interesting file of its own --
# the registry timestamp is the signal there).
function Get-AutorunBinary {
    param([string]$Command)
    if (-not $Command) { return '' }
    $c = $Command.Trim()
    $path = ''
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { $path = $c.Substring(1, $end - 1) }
    } else {
        $m = [regex]::Match($c, '^([^\s]+\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js|com))\b')
        if ($m.Success) { $path = $m.Groups[1].Value }
        else { $path = ($c -split '\s+')[0] }
    }
    if (-not $path) { return '' }
    try { $path = [Environment]::ExpandEnvironmentVariables($path) } catch {}
    if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    return ''
}

# Emitted once, immediately before the first timestamped finding in this tool's
# output, so the numbers are never read as more precise than they are.
$script:whenCaveatShown = $false
function Write-WhenCaveat {
    if ($script:whenCaveatShown) { return }
    $script:whenCaveatShown = $true
    '  note: registry times are per KEY (any value change updates them) and file times can be forged (timestomping, T1070.006) -- treat them as leads, not proof.'
}

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
            Write-WhenCaveat
            $w = Get-WhenLine -KeyPath $k -FilePath (Get-AutorunBinary $val)
            if ($w) { $w }
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
            Write-WhenCaveat
            $w = Get-WhenLine -KeyPath $sub.PSPath -FilePath (Get-AutorunBinary ([string]$d.Debugger))
            if ($w) { $w }
        }
    }
}

if (-not $found) {
    '[OK] No suspicious Run-key autoruns or IFEO Debugger hijacks.'
} elseif ($MarkerFile) {
    Write-MarkerFile -Path $MarkerFile -Value 'hit'
}
