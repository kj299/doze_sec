# baseline_diff.ps1 -- baseline capture and differential analysis.
#
# WHY THIS IS THE MOST IMPORTANT DETECTION IN THE TOOL: every other check asks
# "does this match something we already know is bad?" That question cannot be
# answered for a bespoke implant built for one target -- which is exactly what a
# capable or state-level actor deploys. This check asks a different question:
# "is anything DIFFERENT from how this machine used to be?" A new kernel driver,
# a new service, a new admin, a new listening port, or a new persistence value
# that was not here last week is suspicious regardless of whether anyone has
# ever written a signature for it. Change detection is how you catch tooling
# nobody has catalogued.
#
# HONEST LIMITATION -- STATED IN THE OUTPUT, NOT JUST HERE: a baseline captured
# on an ALREADY-COMPROMISED machine records the implant as "normal", and it will
# never be reported again. This is a change detector from the moment of capture
# forward, NOT a clean-room reference. Capture it as early as possible in a
# device's life, ideally right after a clean install. The report says so plainly
# so nobody mistakes a quiet diff for proof of health.
#
# MODES
#   -Mode Save -Path <file>   Capture the current state to a snapshot file.
#   -Mode Diff -Path <file>   Compare current state to the snapshot and report
#                             NEW / CHANGED / REMOVED. No baseline yet => an
#                             [INFO] line telling the user how to create one
#                             (never a failure, never a fake clean).
#
# SNAPSHOT FORMAT: one record per line, `CATEGORY|KEY|DETAIL`, sorted, so the
# file is deterministic and diffable by eye or by tool. KEY is the stable
# identity (what makes two records "the same thing"); DETAIL is what may change.
# Privacy-conscious: paths, names, hashes and signer CNs only -- never file
# contents, never user documents, no network or telemetry of any kind.
#
# CATEGORIES: DRV (loaded kernel drivers, hashed -- bounded and highest value),
# SVC (services), TASK (scheduled tasks), RUN (autorun/persistence registry
# values), PORT (listening ports), ADMIN (local administrators), CERT (root CA
# certificates -- a new root CA is how TLS interception is installed).
#
# FALSE-POSITIVE CONTROL -- a change detector has to know what changes BY
# DESIGN, or it teaches its reader to ignore it:
#   * Windows Update adds and REPLACES drivers, services and tasks every month.
#     A NEW or CHANGED item whose current binary is validly MICROSOFT-signed and
#     whose arguments carry nothing suspicious is reported [INFO], not raised.
#     A hash change to an unsigned or non-Microsoft binary is WARNING -- that is
#     the shape of a replaced binary. (CHANGED used to be WARNING always, which
#     meant every Patch Tuesday raised dozens of driver findings.)
#   * The RPC endpoint mapper hands out dynamic listening ports (49152-65535)
#     to svchost/lsass/wininit/services on every boot, so those move without
#     anyone touching the machine. A NEW listener in that range owned by one
#     of those system processes is [INFO]; any other new listener is WARNING.
#   * A NEW autorun whose binary is validly Microsoft-signed with clean
#     arguments is [INFO] (OneDrive setup, SecurityHealth). A signed LOLBin host
#     with a suspicious argument stays WARNING: the arguments are graded first.
#   * Any NEW admin or root CA is WARNING -- those are never routine.
#   * REMOVED items are reported [INFO]: uninstalls are normal.
# Get-AddedVerdict / Get-ChangedVerdict hold these rules; -SelfTest pins them.
#
# MARKER: writes the severity word to $env:TEMP\dz_baseline.txt; the caller
# raises via :dz_finding. No marker when nothing noteworthy changed.
#
# Windows PowerShell 5.1 compatible. Read-only apart from writing the snapshot
# and the marker. Executed by the helpers-ps51 CI job (save/diff round-trip).

[CmdletBinding()]
param(
    [ValidateSet('Save', 'Diff')][string]$Mode = 'Diff',
    [string]$Path = '',
    [string]$MarkerDir = $env:TEMP,
    [int]$MaxReport = 40,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

# PowerShell adds these note-properties to every Get-ItemProperty result; they
# are not registry values. Matched by EXACT name -- a '^PS' prefix match would
# also swallow real values whose names start with "PS".
$psNoteProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write here turns
    # a real finding into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine write failure print instead of vanishing --
    # an -EA SilentlyContinue on this write cost a field test its finding.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}
function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}
# Field separators and newlines must never appear inside a record field, or one
# record stops being one parseable line (same rule as the findings ledger).
function CleanField {
    param([string]$s)
    if ($null -eq $s) { return '' }
    return (($s -replace '[|\r\n]', ' ').Trim())
}

# Is this binary validly signed by Microsoft? Used to keep Windows Update noise
# out of the NEW-item findings without silencing third-party additions.
function Test-MsSigned {
    param([string]$FilePath)
    if (-not $FilePath) { return $false }
    $p = [Environment]::ExpandEnvironmentVariables($FilePath.Trim().Trim('"'))
    $p = $p -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
    if ($p -match '^"') { $p = $p.Trim('"') }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $false }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $p -EA Stop } catch {}
    if (-not $sig -or $sig.Status -ne 'Valid') { return $false }
    return ($sig.SignerCertificate.Subject -match '\bMicrosoft\b|\bWindows\b')
}

# Pull the first plausible executable path out of a service ImagePath /
# scheduled-task action so signature checks have something to work with.
function Get-BinPath {
    param([string]$Raw)
    if (-not $Raw) { return '' }
    $s = $Raw.Trim()
    if ($s.StartsWith('"')) {
        $end = $s.IndexOf('"', 1)
        if ($end -gt 1) { return $s.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($s, '^[^\s]+\.(exe|sys|dll)', 'IgnoreCase')
    if ($m.Success) { return $m.Value }
    return $s
}

# Argument-content test for signed LOLBin hosts. Patterns are deliberately the
# same ones persistence_eval.ps1 uses to judge Run-key values, so a command line
# that would be flagged as an autorun is flagged here too.
$script:LolbinHosts   = 'rundll32|regsvr32|mshta|powershell|pwsh|wscript|cscript|cmd|msiexec|installutil|certutil|bitsadmin|curl|wget|conhost|forfiles|mftrace'
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
$script:HiddenLauncher = '-w(indowstyle)?\s+hidden'
$script:SuspPath       = @('\\Temp\\', '\\Downloads\\', '\\Users\\Public\\', '\\ProgramData\\', '\\AppData\\')
function Test-SuspiciousArgs {
    param([string]$Detail)
    if (-not $Detail) { return $false }
    foreach ($p in $script:StrongContent) { if ($Detail -match $p) { return $true } }
    if ($Detail -match $script:HiddenLauncher) { return $true }
    # A signed LOLBin host pointed at a user-writable staging directory is the
    # shape of the technique even when no single argument token is damning.
    if ($Detail -match $script:LolbinHosts) {
        foreach ($p in $script:SuspPath) { if ($Detail -match $p) { return $true } }
    }
    return $false
}


# ---------------------------------------------------------------------------
# PURE VERDICTS. A record's category, identity and detail in, a severity out.
# No CIM, no disk, no signature check: the caller says whether the binary is
# Microsoft-signed, so every rule here can be pinned against real records.
# ---------------------------------------------------------------------------
$script:CatLabel = @{
    'DRV' = 'kernel driver'; 'SVC' = 'service'; 'TASK' = 'scheduled task'
    'RUN' = 'autorun/persistence value'; 'PORT' = 'listening port'
    'ADMIN' = 'local administrator'; 'CERT' = 'root CA certificate'
}
$script:BinaryCats       = @('DRV', 'SVC', 'TASK', 'RUN')
# The processes the RPC endpoint mapper and the OS itself give dynamic-range
# listeners to on every boot.
$script:DynamicPortOwner = '^(svchost|lsass|wininit|services|spoolsv|System|Idle)$'
$script:DynamicPortFloor = 49152
# A binary living in a staging directory is a finding whatever its signature
# says (the proc_path_grade rule): a Microsoft-signed file COPIED to
# Users\Public and registered as a service is the relocation, not the update.
$script:StagingRx = '\\Temp\\|\\Downloads\\|\\Users\\Public\\'

function Get-CatLabel { param([string]$Cat) $l = $script:CatLabel[$Cat]; if ($l) { return $l }; return $Cat }

# A record present now and absent from the baseline.
function Get-AddedVerdict {
    param([string]$Cat, [string]$Id, [string]$Detail, [bool]$MsSigned)
    if ($script:BinaryCats -contains $Cat) {
        # The arguments are graded FIRST: a Microsoft signature on the host
        # binary is not a clean bill of health (rundll32 <staging>\x.dll).
        if (Test-SuspiciousArgs $Detail) { return @{ Sev = 'WARNING'; Why = 'suspicious arguments' } }
        if ($Detail -match $script:StagingRx) { return @{ Sev = 'WARNING'; Why = 'runs from a staging path' } }
        if ($MsSigned) { return @{ Sev = 'INFO'; Why = 'Microsoft-signed, likely a Windows update' } }
        return @{ Sev = 'WARNING'; Why = 'not validly Microsoft-signed' }
    }
    if ($Cat -eq 'PORT') {
        $port = 0
        if ($Id -match '^tcp/(\d+)$') { $port = [int]$Matches[1] }
        if ($port -ge $script:DynamicPortFloor -and $Detail -match $script:DynamicPortOwner) {
            return @{ Sev = 'INFO'; Why = 'dynamic RPC range, system-owned -- reassigned on every boot' }
        }
        return @{ Sev = 'WARNING'; Why = 'new listener' }
    }
    return @{ Sev = 'WARNING'; Why = 'never routine' }
}

# A record present in both, with different detail.
function Get-ChangedVerdict {
    param([string]$Cat, [string]$Id, [string]$Old, [string]$New, [bool]$MsSignedNow)
    if ($script:BinaryCats -contains $Cat) {
        if (Test-SuspiciousArgs $New) { return @{ Sev = 'WARNING'; Why = 'suspicious arguments' } }
        if ($New -match $script:StagingRx) { return @{ Sev = 'WARNING'; Why = 'now runs from a staging path' } }
        if ($Cat -ne 'RUN' -and $MsSignedNow) { return @{ Sev = 'INFO'; Why = 'Microsoft-signed, likely a Windows update' } }
        return @{ Sev = 'WARNING'; Why = 'binary or command changed' }
    }
    if ($Cat -eq 'PORT') {
        # Same port, different owner: only quiet when the new owner is still a
        # system process in the dynamic range (svchost -> lsass on reboot).
        $port = 0
        if ($Id -match '^tcp/(\d+)$') { $port = [int]$Matches[1] }
        if ($port -ge $script:DynamicPortFloor -and $New -match $script:DynamicPortOwner) {
            return @{ Sev = 'INFO'; Why = 'dynamic RPC range, system-owned' }
        }
        return @{ Sev = 'WARNING'; Why = 'listener owner changed' }
    }
    return @{ Sev = 'WARNING'; Why = 'never routine' }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    # Patch Tuesday: a Microsoft-signed driver's hash changes.
    $v = Get-ChangedVerdict -Cat 'DRV' -Id 'tcpip' -Old 'C:\Windows\System32\drivers\tcpip.sys sha256=AAAA' -New 'C:\Windows\System32\drivers\tcpip.sys sha256=BBBB' -MsSignedNow $true
    T 'CHANGED Microsoft-signed driver (Windows Update replaced it) is INFO' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'DRV' -Id 'gdrv' -Old 'C:\Windows\System32\drivers\gdrv.sys sha256=AAAA' -New 'C:\Windows\System32\drivers\gdrv.sys sha256=BBBB' -MsSignedNow $false
    T 'CHANGED driver whose new binary is NOT Microsoft-signed is WARNING (a replaced binary)' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'SVC' -Id 'Spooler' -Old 'C:\Windows\System32\spoolsv.exe start=Auto' -New 'C:\Users\Public\spoolsv.exe start=Auto' -MsSignedNow $true
    T 'CHANGED service repointed at Users\Public is WARNING even with a signed host' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'SVC' -Id 'WinDefend' -Old 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe start=Auto' -New 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MsMpEng.exe start=Auto' -MsSignedNow $true
    T 'CHANGED Defender platform path (monthly platform update, signed) is INFO' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'RUN' -Id 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth' -Old '%windir%\system32\SecurityHealthSystray.exe' -New '%windir%\system32\SecurityHealthSystray.exe -x' -MsSignedNow $true
    T 'CHANGED autorun value stays WARNING even when signed (persistence content changed)' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'ADMIN' -Id 'Z4NEE52\khali' -Old 'Local' -New 'MicrosoftAccount' -MsSignedNow $false
    T 'CHANGED admin record is WARNING' ($v.Sev -eq 'WARNING') ''
    $v = Get-ChangedVerdict -Cat 'PORT' -Id 'tcp/49668' -Old 'svchost' -New 'lsass' -MsSignedNow $false
    T 'CHANGED dynamic port owner svchost -> lsass (reboot reshuffle) is INFO' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'PORT' -Id 'tcp/49668' -Old 'svchost' -New 'evil' -MsSignedNow $false
    T 'CHANGED dynamic port owner to a non-system process is WARNING' ($v.Sev -eq 'WARNING') ''

    # New items.
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/49668' -Detail 'svchost' -MsSigned $false
    T 'NEW dynamic-range listener owned by svchost is INFO (RPC reassigns these every boot)' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/49670' -Detail 'lsass' -MsSigned $false
    T 'NEW dynamic-range listener owned by lsass is INFO' ($v.Sev -eq 'INFO') ''
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/49668' -Detail 'evil' -MsSigned $false
    T 'NEW dynamic-range listener owned by an unknown process is WARNING' ($v.Sev -eq 'WARNING') ''
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/4444' -Detail 'svchost' -MsSigned $false
    T 'NEW listener BELOW the dynamic range is WARNING even for svchost' ($v.Sev -eq 'WARNING') ''
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/49152' -Detail 'services' -MsSigned $false
    T 'the dynamic range starts at 49152 inclusive' ($v.Sev -eq 'INFO') ''
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/49151' -Detail 'services' -MsSigned $false
    T '49151 is below the range: WARNING' ($v.Sev -eq 'WARNING') ''
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/50000' -Detail 'pid=1234' -MsSigned $false
    T 'the netstat fallback (pid=N, no name) cannot prove a system owner: WARNING' ($v.Sev -eq 'WARNING') ''
    $v = Get-AddedVerdict -Cat 'DRV' -Id 'newdrv' -Detail 'C:\Windows\System32\drivers\newdrv.sys sha256=AAAA' -MsSigned $true
    T 'NEW Microsoft-signed driver is INFO' ($v.Sev -eq 'INFO') ''
    $v = Get-AddedVerdict -Cat 'DRV' -Id 'newdrv' -Detail 'C:\Windows\System32\drivers\newdrv.sys sha256=AAAA' -MsSigned $false
    T 'NEW unsigned driver is WARNING' ($v.Sev -eq 'WARNING') ''
    $v = Get-AddedVerdict -Cat 'SVC' -Id 'helper' -Detail 'C:\Users\Public\helper.exe start=Auto' -MsSigned $true
    T 'NEW service whose Microsoft-signed binary sits in Users\Public is WARNING (relocation, not update)' ($v.Sev -eq 'WARNING' -and $v.Why -match 'staging') ($v.Sev + '/' + $v.Why)
    $v = Get-AddedVerdict -Cat 'SVC' -Id 'dz_selftest_ci_lolbin' -Detail 'C:\Windows\System32\rundll32.exe C:\ProgramData\dz_selftest_ci_stage\x.dll,Run start=Demand' -MsSigned $true
    T 'NEW service hosted by signed rundll32 pointed at ProgramData is WARNING (the CI case)' ($v.Sev -eq 'WARNING' -and $v.Why -eq 'suspicious arguments') ("sev=" + $v.Sev)
    $v = Get-AddedVerdict -Cat 'RUN' -Id 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth' -Detail '%windir%\system32\SecurityHealthSystray.exe' -MsSigned $true
    T 'NEW autorun of a Microsoft-signed binary with clean arguments is INFO' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    $v = Get-AddedVerdict -Cat 'RUN' -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater' -Detail 'powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' -MsSigned $true
    T 'NEW autorun of signed powershell with -enc is WARNING (arguments graded first)' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-AddedVerdict -Cat 'RUN' -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\X' -Detail 'C:\Users\u\AppData\Local\Vendor\app.exe' -MsSigned $false
    T 'NEW autorun of an unsigned third-party binary is WARNING' ($v.Sev -eq 'WARNING') ''
    $v = Get-AddedVerdict -Cat 'ADMIN' -Id 'Z4NEE52\helper' -Detail 'Local' -MsSigned $false
    T 'NEW local administrator is WARNING' ($v.Sev -eq 'WARNING') ''
    $v = Get-AddedVerdict -Cat 'CERT' -Id 'ABCDEF0123456789' -Detail 'CN=Corp Proxy Root' -MsSigned $false
    T 'NEW root CA is WARNING' ($v.Sev -eq 'WARNING') ''
    $v = Get-AddedVerdict -Cat 'TASK' -Id '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan' -Detail '%systemroot%\system32\usoclient.exe StartScan' -MsSigned $true
    T 'NEW Microsoft-signed scheduled task with clean arguments is INFO' ($v.Sev -eq 'INFO') ''

    # The argument grader on the owner's real autoruns: nothing suspicious.
    $real = @(
        '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background',
        '"C:\Users\khali\AppData\Local\BraveSoftware\Update\1.3.361.151\BraveUpdateCore.exe"',
        'C:\Users\khali\AppData\Local\Programs\signal-desktop\Signal.exe --start-in-tray',
        '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start',
        '"C:\WINDOWS\System32\DriverStore\FileRepository\wavesapo12de.inf_amd64_7705ab85ca3fc744\WavesSvc64.exe" -Jack',
        '"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\153.0.4234.48\Installer\setup.exe" --msedgewebview --delete-old-versions --system-level --verbose-logging'
    )
    foreach ($r in $real) { T ("owner's real autorun has no suspicious arguments: " + $r.Substring(0, [Math]::Min(60, $r.Length))) (-not (Test-SuspiciousArgs $r)) '' }
    T 'a hidden-window launcher IS suspicious here (baseline records have no updater exemption)' (Test-SuspiciousArgs 'powershell -w hidden -File x.ps1') ''

    if ($fails) { Write-Output "[FAIL] $fails baseline_diff self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] baseline_diff self-test: update churn (signed replacements, dynamic RPC ports) is context; replaced unsigned binaries, new admins, new roots and suspicious arguments are findings.'
    exit 0
}

if (-not $Path) {
    '[SKIPPED] baseline_diff: -Path is required for -Mode Save and -Mode Diff.'
    exit 2
}

# ---- Collect the current state ------------------------------------------
function Get-Snapshot {
    $recs = New-Object System.Collections.Generic.List[string]
    $sysroot = $env:SystemRoot

    # DRV -- loaded kernel drivers, hashed. Bounded set, highest value: a new or
    # swapped kernel driver is the single most consequential change on a host.
    try {
        foreach ($d in (Get-CimInstance Win32_SystemDriver -EA Stop)) {
            $pn = [string]$d.PathName
            if (-not $pn) { continue }
            $pn = $pn -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $sysroot
            $pn = [Environment]::ExpandEnvironmentVariables($pn.Trim('"'))
            $h = ''
            try { if (Test-Path -LiteralPath $pn -PathType Leaf) { $h = (Get-FileHash -LiteralPath $pn -Algorithm SHA256 -EA Stop).Hash } } catch {}
            $recs.Add(('DRV|{0}|{1} sha256={2}' -f (CleanField $d.Name), (CleanField $pn), $h))
        }
    } catch {}

    # SVC -- services by name; DETAIL carries the image path and start mode, so a
    # service repointed at a new binary shows up as CHANGED.
    try {
        foreach ($s in (Get-CimInstance Win32_Service -EA Stop)) {
            $recs.Add(('SVC|{0}|{1} start={2}' -f (CleanField $s.Name), (CleanField $s.PathName), (CleanField $s.StartMode)))
        }
    } catch {}

    # TASK -- scheduled tasks by full path; DETAIL carries the action.
    try {
        foreach ($t in (Get-ScheduledTask -EA Stop)) {
            $act = ''
            try { $act = (($t.Actions | ForEach-Object { [string]$_.Execute + ' ' + [string]$_.Arguments }) -join ' ; ') } catch {}
            $recs.Add(('TASK|{0}{1}|{2}' -f (CleanField $t.TaskPath), (CleanField $t.TaskName), (CleanField $act)))
        }
    } catch {}

    # RUN -- autorun / persistence registry values. The classic locations plus
    # the subsystem load points audited elsewhere in Section 5.
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls',
        'HKLM:\SOFTWARE\Microsoft\Netsh'
    )
    foreach ($k in $runKeys) {
        try {
            if (-not (Test-Path $k)) { continue }
            $props = Get-ItemProperty -Path $k -EA Stop
            foreach ($p in $props.PSObject.Properties) {
                # Exact-name skip, not a '^PS' prefix match (see
                # persistence_eval.ps1). A "PS"-named autorun was excluded from
                # the snapshot too, so the diff could not report it as NEW
                # either -- both the direct check and change detection missed it.
                if ($psNoteProps -contains $p.Name) { continue }
                $recs.Add(('RUN|{0}\{1}|{2}' -f (CleanField $k), (CleanField $p.Name), (CleanField ([string]$p.Value))))
            }
        } catch {}
    }

    # PORT -- listening sockets. A new listener is how an implant takes calls.
    try {
        foreach ($c in (Get-NetTCPConnection -State Listen -EA Stop)) {
            $pname = ''
            try { $pname = (Get-Process -Id $c.OwningProcess -EA Stop).ProcessName } catch {}
            $recs.Add(('PORT|tcp/{0}|{1}' -f (CleanField ([string]$c.LocalPort)), (CleanField $pname)))
        }
    } catch {
        # Get-NetTCPConnection is absent on very old builds -- fall back to netstat
        # rather than silently recording no listeners (a false clean).
        try {
            foreach ($line in (& netstat -ano 2>$null)) {
                if ($line -notmatch '^\s*TCP\s') { continue }
                if ($line -notmatch 'LISTENING') { continue }
                $f = ($line -split '\s+') | Where-Object { $_ }
                if ($f.Count -lt 5) { continue }
                $lp = ($f[1] -split ':')[-1]
                $recs.Add(('PORT|tcp/{0}|pid={1}' -f (CleanField $lp), (CleanField $f[4])))
            }
        } catch {}
    }

    # ADMIN -- local Administrators membership. A new admin is a takeover.
    try {
        foreach ($m in (Get-LocalGroupMember -Group 'Administrators' -EA Stop)) {
            $recs.Add(('ADMIN|{0}|{1}' -f (CleanField ([string]$m.Name)), (CleanField ([string]$m.PrincipalSource))))
        }
    } catch {
        try {
            $out = & net localgroup Administrators 2>$null
            $on = $false
            foreach ($line in $out) {
                if ($line -match '^-+$') { $on = $true; continue }
                if ($line -match '^The command completed') { $on = $false; continue }
                if ($on -and $line.Trim()) { $recs.Add(('ADMIN|{0}|net' -f (CleanField $line))) }
            }
        } catch {}
    }

    # CERT -- machine root CAs. A new root CA is how TLS interception is planted.
    try {
        foreach ($c in (Get-ChildItem Cert:\LocalMachine\Root -EA Stop)) {
            $recs.Add(('CERT|{0}|{1}' -f (CleanField $c.Thumbprint), (CleanField $c.Subject)))
        }
    } catch {}

    return ($recs | Sort-Object -Unique)
}

$snapshot = Get-Snapshot

if ($Mode -eq 'Save') {
    $header = @(
        '# doze_sec baseline snapshot -- CATEGORY|KEY|DETAIL, sorted.',
        '# Captured: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        '# NOTE: a baseline taken on an already-compromised machine records the',
        '# implant as normal. This is a change detector from now forward, not a',
        '# clean-room reference. Capture as early in the device life as possible.'
    )
    try {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        # UTF8, not ASCII. -Encoding ASCII replaces every non-ASCII character
        # with '?', so any record containing one -- a service display name, a
        # task path, or a certificate subject with an accented or non-Latin
        # character -- was stored mangled. It could then never match the live
        # value again, producing a permanent false WARNING on every subsequent
        # run: the diff would report the same item as CHANGED forever, which is
        # precisely the noise that makes a change-detection feature unusable.
        Set-Content -LiteralPath $Path -Value ($header + $snapshot) -Encoding UTF8 -EA Stop
        '--- Baseline Snapshot (saved) ---'
        "[OK] Baseline saved: $Path"
        "[OK] $($snapshot.Count) state record(s) captured (drivers, services, tasks, autoruns, ports, admins, root CAs)."
        '[INFO] A baseline captured on an already-compromised machine records the implant as normal.'
        '[INFO] It detects CHANGE from this moment forward -- it is not proof the current state is clean.'
    } catch {
        "[SKIPPED] Could not write baseline to ${Path}: $($_.Exception.Message)"
    }
    return
}

# ---- Diff mode -----------------------------------------------------------
'--- [BASELINE] Differential analysis vs saved baseline ---'
if (-not (Test-Path -LiteralPath $Path)) {
    "[INFO] No baseline found at $Path -- differential analysis not performed."
    '[INFO] Create one with:  doze_sec.bat -baseline save'
    '[INFO] Change detection is the strongest signal this tool has against a'
    '[INFO] targeted implant that matches no known signature. Capturing a'
    '[INFO] baseline early -- ideally on a freshly installed device -- is the'
    '[INFO] single most useful thing you can do to make future runs meaningful.'
    Write-Marker -Name 'baseline' -Sev 'OK'
    return
}

$old = @{}
try {
    foreach ($ln in (Get-Content -LiteralPath $Path -Encoding UTF8 -EA Stop)) {
        $t = $ln.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $f = $t.Split('|')
        if ($f.Length -lt 2) { continue }
        $key = $f[0] + '|' + $f[1]
        $detail = ''
        if ($f.Length -ge 3) { $detail = ($f[2..($f.Length - 1)] -join '|') }
        $old[$key] = $detail
    }
} catch {
    "[SKIPPED] Baseline unreadable: $($_.Exception.Message)"
    Write-Marker -Name 'baseline' -Sev 'WARNING'
    return
}

$new = @{}
foreach ($ln in $snapshot) {
    $f = $ln.Split('|')
    if ($f.Length -lt 2) { continue }
    $key = $f[0] + '|' + $f[1]
    $detail = ''
    if ($f.Length -ge 3) { $detail = ($f[2..($f.Length - 1)] -join '|') }
    $new[$key] = $detail
}

# NEW items that are validly Microsoft-signed are almost always Windows Update
# doing its job -- reported for the record, but not raised.
$sev = 'OK'
$added = @(); $changed = @(); $removed = @()

foreach ($k in $new.Keys) {
    if ($old.ContainsKey($k)) {
        if ($old[$k] -ne $new[$k]) { $changed += $k }
    } else {
        $added += $k
    }
}
foreach ($k in $old.Keys) { if (-not $new.ContainsKey($k)) { $removed += $k } }

# Evaluate every added item FIRST, then print raised findings before benign
# ones. Printing in raw sorted order with a single shared cap is a real
# detection-quality bug: category names sort ADMIN < CERT < DRV < PORT < RUN,
# so on a stale or foreign baseline a few dozen benign new certificates and
# drivers would exhaust the budget and silently push an actual malicious new
# autorun off the end of the report. Severity decides who gets printed, never
# alphabetical luck.
# Helper: is the binary behind a record's detail validly Microsoft-signed?
function Test-RecordMsSigned {
    param([string]$Cat, [string]$Detail)
    if ($script:BinaryCats -notcontains $Cat) { return $false }
    $bin = Get-BinPath ($Detail -replace ' sha256=[0-9A-Fa-f]*$', '' -replace ' start=\w+$', '')
    return (Test-MsSigned $bin)
}

$addEval = @()
foreach ($k in ($added | Sort-Object)) {
    $cat = $k.Split('|')[0]
    $id  = $k.Substring($cat.Length + 1)
    $lbl = Get-CatLabel $cat
    $detail = $new[$k]
    $v = Get-AddedVerdict -Cat $cat -Id $id -Detail $detail -MsSigned (Test-RecordMsSigned -Cat $cat -Detail $detail)
    if ($v.Sev -eq 'WARNING') { $sev = Get-MaxSev $sev 'WARNING' }
    $addEval += New-Object PSObject -Property @{ Lbl = $lbl; Id = $id; Detail = $detail; Sev = $v.Sev; Why = $v.Why }
}
$warnAdds = @($addEval | Where-Object { $_.Sev -eq 'WARNING' })
$infoAdds = @($addEval | Where-Object { $_.Sev -ne 'WARNING' })
$n = 0
foreach ($a in $warnAdds) {
    $n++
    if ($n -le $MaxReport) { "[WARNING] NEW $($a.Lbl) since baseline: $($a.Id)  =>  $($a.Detail)" }
}
if ($warnAdds.Count -gt $MaxReport) { "[INFO] ...and $($warnAdds.Count - $MaxReport) more new item(s) needing review, not listed (report cap $MaxReport)." }
$n = 0
foreach ($a in $infoAdds) {
    $n++
    # Print the detail on INFO items too. Omitting it is how a signed LOLBin
    # host with a malicious command line stayed invisible even to someone
    # reading the report line by line.
    if ($n -le $MaxReport) { "[INFO] NEW $($a.Lbl) since baseline ($($a.Why)): $($a.Id)  =>  $($a.Detail)" }
}
if ($infoAdds.Count -gt $MaxReport) { "[INFO] ...and $($infoAdds.Count - $MaxReport) more routine new item(s) not listed (report cap $MaxReport)." }

$chEval = @()
foreach ($k in ($changed | Sort-Object)) {
    $cat = $k.Split('|')[0]
    $id  = $k.Substring($cat.Length + 1)
    $v = Get-ChangedVerdict -Cat $cat -Id $id -Old $old[$k] -New $new[$k] -MsSignedNow (Test-RecordMsSigned -Cat $cat -Detail $new[$k])
    if ($v.Sev -eq 'WARNING') { $sev = Get-MaxSev $sev 'WARNING' }
    $chEval += New-Object PSObject -Property @{ Lbl = (Get-CatLabel $cat); Id = $id; Key = $k; Sev = $v.Sev; Why = $v.Why }
}
$warnCh = @($chEval | Where-Object { $_.Sev -eq 'WARNING' })
$infoCh = @($chEval | Where-Object { $_.Sev -ne 'WARNING' })
$chShown = 0
foreach ($c in $warnCh) {
    $chShown++
    if ($chShown -le $MaxReport) {
        "[WARNING] CHANGED $($c.Lbl) since baseline: $($c.Id)"
        "          was: $($old[$c.Key])"
        "          now: $($new[$c.Key])"
    }
}
if ($chShown -gt $MaxReport) { "[INFO] ...and $($chShown - $MaxReport) more changed item(s) needing review, not listed (report cap $MaxReport)." }
$n = 0
foreach ($c in $infoCh) {
    $n++
    if ($n -le $MaxReport) {
        "[INFO] CHANGED $($c.Lbl) since baseline ($($c.Why)): $($c.Id)"
        "          was: $($old[$c.Key])"
        "          now: $($new[$c.Key])"
    }
}
if ($infoCh.Count -gt $MaxReport) { "[INFO] ...and $($infoCh.Count - $MaxReport) more routine changed item(s) not listed (report cap $MaxReport)." }

$rmShown = 0
foreach ($k in ($removed | Sort-Object)) {
    $cat = $k.Split('|')[0]
    $id  = $k.Substring($cat.Length + 1)
    $lbl = Get-CatLabel $cat
    $rmShown++
    # Removals are reported but not raised: uninstalls and update churn are
    # normal, and burying a real NEW finding under removal noise helps nobody.
    if ($rmShown -le $MaxReport) { "[INFO] REMOVED $lbl since baseline: $id" }
}
if ($rmShown -gt $MaxReport) { "[INFO] ...and $($rmShown - $MaxReport) more removed item(s) not listed (report cap $MaxReport)." }

if ($added.Count -eq 0 -and $changed.Count -eq 0 -and $removed.Count -eq 0) {
    "[OK] No change from the saved baseline across $($new.Count) tracked state record(s)."
} else {
    "[INFO] Baseline diff summary: $($added.Count) new, $($changed.Count) changed, $($removed.Count) removed (of $($new.Count) tracked records)."
}
'[INFO] A quiet diff means nothing changed since the baseline was taken -- not that the baseline itself was clean.'

Write-Marker -Name 'baseline' -Sev $sev
