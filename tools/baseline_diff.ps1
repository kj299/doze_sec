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
#   * Five more classes, every one taken verbatim from a real report (2026-10-03)
#     that raised ten WARNING lines of updates and installs:
#     - a CHANGED binary validly signed by a NON-Microsoft publisher whose
#       record differs only in a version-shaped path segment (Chrome's
#       elevation service, an MSIX package directory) is [INFO] naming the
#       signer -- a version bump. A changed start mode, argument, directory or
#       hash is not a bump and stays WARNING, with the signer named.
#     - a NEW task/service/driver/autorun validly signed by a non-Microsoft
#       publisher, clean arguments, no staging path, is [INFO] naming the
#       signer: a new install, which the owner is told to confirm.
#     - a NEW task with NO executable action is a COM-handler task: [INFO]
#       under the Windows-owned task paths (\Microsoft\Windows\, \SoftLanding\),
#       WARNING anywhere else (inspect its CLSID).
#     - a NEW listener bound to loopback only (127.0.0.1 / ::1) is [INFO]
#       whatever the owner or range: it is unreachable from the network. The
#       snapshot now records the bind address; a listener that MOVES from
#       loopback to a network-reachable address is WARNING.
#     - the Winlogon logon/logoff perf counters are rewritten at every logon
#       and are not persistence values: excluded from the snapshot by name,
#       declared once when the snapshot is saved.
#     An unquoted task action with spaces in its path ("C:\Program Files\...\x.exe
#     /arg") used to defeat the signature check entirely (Get-BinPath took the
#     first token); it now walks the space-separated prefixes the way
#     CreateProcess does and sign-checks the first file that exists.
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

# Expand the forms a service ImagePath / driver PathName / task action takes
# into a path Test-Path can see: %var%, \??\, \SystemRoot, surrounding quotes.
function Resolve-BinPath {
    param([string]$Raw)
    if (-not $Raw) { return '' }
    $p = [Environment]::ExpandEnvironmentVariables($Raw.Trim().Trim('"'))
    $p = $p -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
    if ($p -match '^"') { $p = $p.Trim('"') }
    return $p
}

# The common name out of a certificate subject ('CN=Google LLC, O=Google LLC,
# L=Mountain View, ...' -> 'Google LLC'). Falls back to the whole subject.
function Get-SubjectCN {
    param([string]$Subject)
    if (-not $Subject) { return '' }
    if ($Subject -match '(?:^|,\s*)CN=(.+?)(?:,\s*[A-Za-z]+=|$)') { return (CleanField ($Matches[1].Trim().Trim('"'))) }
    return (CleanField $Subject)
}

# Signature facts for one binary. Valid: the Authenticode chain verifies.
# CN: the signer's common name, '' when the file is unsigned, absent or
# unreadable -- "could not check" belongs with unsigned (the proc_path_grade
# rule). Microsoft: Valid and the subject names Microsoft/Windows.
function Get-SignerInfo {
    param([string]$FilePath)
    $r = @{ Valid = $false; Subject = ''; CN = ''; Microsoft = $false }
    if (-not $FilePath) { return $r }
    $p = Resolve-BinPath $FilePath
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return $r }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $p -EA Stop } catch {}
    if (-not $sig -or $sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { return $r }
    $r.Valid = $true
    $r.Subject = [string]$sig.SignerCertificate.Subject
    $r.CN = Get-SubjectCN $r.Subject
    $r.Microsoft = ($r.Subject -match '\bMicrosoft\b|\bWindows\b')
    return $r
}

# Is this binary validly signed by Microsoft? Used to keep Windows Update noise
# out of the NEW-item findings without silencing third-party additions.
function Test-MsSigned {
    param([string]$FilePath)
    return [bool](Get-SignerInfo $FilePath).Microsoft
}

# Pull the executable path out of a service ImagePath / scheduled-task action
# so signature checks have something to work with. An UNQUOTED action whose
# path contains spaces ("C:\Program Files\Microsoft OneDrive\<ver>\
# OneDriveLauncher.exe /startInstances") has no delimiter between path and
# arguments; CreateProcess tries each space-separated prefix and runs the
# first file that exists, so the signature check has to find the binary the
# same way. Taking the first token ("C:\Program") found nothing, the
# signature check never ran, and three OneDrive tasks were WARNING for a
# version bump their sibling service (quoted path) read as INFO. -Exists is
# the file probe, injectable so the walk can be pinned without a disk.
function Get-BinPath {
    param([string]$Raw, [scriptblock]$Exists = $null)
    if (-not $Raw) { return '' }
    $s = $Raw.Trim()
    if ($s.StartsWith('"')) {
        $end = $s.IndexOf('"', 1)
        if ($end -gt 1) { return $s.Substring(1, $end - 1) }
    }
    if ($null -eq $Exists) { $Exists = { param([string]$p) Test-Path -LiteralPath $p -PathType Leaf } }
    $tok = @($s -split ' ')
    $max = [Math]::Min($tok.Count, 16)
    for ($i = 1; $i -le $max; $i++) {
        $cand = ($tok[0..($i - 1)] -join ' ')
        if ($cand -notmatch '\.(exe|sys|dll)$') { continue }
        $hit = $false
        try { $hit = [bool](& $Exists (Resolve-BinPath $cand)) } catch { $hit = $false }
        if ($hit) { return $cand }
    }
    $m = [regex]::Match($s, '^[^\s]+\.(exe|sys|dll)', 'IgnoreCase')
    if ($m.Success) { return $m.Value }
    return $s
}

# Does the record differ from its baseline only in a version-shaped segment?
# A version is digits-dot-digits (2 to 4 parts) sitting inside a path segment
# -- between backslashes or underscores, or after a 'v', as in
# \Chrome\Application\154.0.8037.98\, \OneDrive\26.173.0906.0008\,
# OpenAI.Codex_26.930.2377.0_x64__<id>, Platform\4.18.25070.5-0\. A number
# that is an ARGUMENT (-server 10.0.0.2) sits after a space and is not masked,
# so a changed argument is never read as a version bump; neither is a changed
# start mode, directory or hash.
$script:VersionRx = '(?<=[\\_v-])\d+(\.\d+){1,3}(?=[\\_-])'
function Test-VersionBumpOnly {
    param([string]$Old, [string]$New)
    if ($Old -eq $New) { return $false }
    $a = $Old -replace $script:VersionRx, '<v>'
    $b = $New -replace $script:VersionRx, '<v>'
    return ($a -eq $b)
}

# Winlogon values that Windows rewrites at every logon and logoff. They are
# counters, not persistence, and snapshotting them made every run after a
# logoff report a CHANGED autorun. Exact names under the Winlogon key only.
$script:ExcludedRunValues = @('LastLogOffEndTimePerfCounter', 'LastLogOnEndTimePerfCounter')
function Test-ExcludedRunValue {
    param([string]$Key, [string]$Name)
    if ($Key -notmatch '\\Winlogon$') { return $false }
    return ($script:ExcludedRunValues -contains $Name)
}

# doze_sec's own RunOnce resume entry (INIT 8). A baseline saved by a run that
# created it records it, and every later diff then reports it -- and once its
# path was corrected, a non-read-only run would have reported it CHANGED, as an
# unsigned .bat autorun. Excluded by MARKER, never by name: the value name alone
# is attacker-choosable, so the data must also point at one of our own bats.
function Test-OwnResumeEntry {
    param([string]$Key, [string]$Name, [string]$Value)
    if ($Key -notmatch '\\RunOnce$') { return $false }
    if ($Name -notmatch '^\*.+_resume$') { return $false }
    return ($Value -match '\\doze_sec(_noAdmin)?\.bat"?\s+-resume"?\s*$')
}

# A record the diff must not compare at all. Applied to the OLD snapshot as well
# as the live one, so a baseline saved before an exclusion existed stops
# reporting the excluded value as REMOVED on every run.
function Test-ExcludedRecord {
    param([string]$Cat, [string]$Id, [string]$Detail)
    if ($Cat -ne 'RUN') { return $false }
    $i = $Id.LastIndexOf('\')
    if ($i -lt 0) { return $false }
    $k = $Id.Substring(0, $i); $n = $Id.Substring($i + 1)
    if (Test-ExcludedRunValue -Key $k -Name $n) { return $true }
    return (Test-OwnResumeEntry -Key $k -Name $n -Value $Detail)
}

# Per-user services. Windows creates an instance of every per-user service
# template for each logon session, named <template>_<LUID suffix> (Microsoft
# Learn, "Per-user services in Windows"), so a new logon renamed all of them: a
# field report carried 24 NEW and 24 REMOVED lines for AarSvc_*, cbdhsvc_*,
# CDPUserSvc_* and the rest. They are compared under one key per template --
# but only when a real template of that name exists (Type has
# SERVICE_USER_SERVICE 0x40, not SERVICE_USERSERVICE_INSTANCE 0x80) AND the
# instance runs the template's own image. A name that merely looks per-user, or
# an instance repointed at another binary, keeps its own key and stays visible.
$script:PerUserSvcRx = '^(.+)_([0-9a-f]{4,8})$'
function ConvertTo-ImageKey {
    param([string]$Image)
    return ([Environment]::ExpandEnvironmentVariables([string]$Image) -replace '"', '').Trim().ToLower()
}
function Get-RecordKey {
    param([string]$Cat, [string]$Id, [string]$Detail, [hashtable]$Templates)
    if ($Cat -eq 'SVC' -and $Templates -and $Id -match $script:PerUserSvcRx) {
        $tn = $Matches[1]
        $tk = $tn.ToLower()
        if ($Templates.ContainsKey($tk)) {
            $img = $Detail -replace ' start=\w+$', ''
            if ((ConvertTo-ImageKey $img) -eq (ConvertTo-ImageKey $Templates[$tk])) { return ('SVC|' + $tn + '_<per-user>') }
        }
    }
    return ($Cat + '|' + $Id)
}
function Get-UserServiceTemplates {
    $t = @{}
    try {
        foreach ($k in (Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA Stop)) {
            try {
                $pr = Get-ItemProperty -LiteralPath $k.PSPath -EA Stop
                $ty = 0
                if ($null -ne $pr.Type) { $ty = [int]$pr.Type }
                if (($ty -band 0x40) -and -not ($ty -band 0x80) -and $pr.ImagePath) { $t[$k.PSChildName.ToLower()] = [string]$pr.ImagePath }
            } catch {}
        }
    } catch {}
    return $t
}

# PORT detail is '<owner> bind=<local address>'. The bind address is recorded
# so a loopback-only listener can be told from one reachable over the network;
# the owner alone decides whether two records are "the same" so a baseline
# saved before the bind field existed does not report every port as CHANGED.
$script:LoopbackRx = '^(127\.0\.0\.1|::1|\[::1\])$'
function Get-PortBind  { param([string]$Detail) if ($Detail -match '(?:^|\s)bind=(\S+)') { return $Matches[1] }; return '' }
function Get-PortOwner { param([string]$Detail) return (($Detail -replace '(?:^|\s)bind=\S+', '').Trim()) }
# Is a record CHANGED? Everything but PORT compares the whole detail. PORT
# compares the owner, and the bind address only when BOTH sides carry one
# (a listener that moved from loopback to 0.0.0.0 is a change worth seeing).
function Test-RecordChanged {
    param([string]$Cat, [string]$Old, [string]$New)
    if ($Cat -ne 'PORT') { return ($Old -ne $New) }
    if ((Get-PortOwner $Old) -ne (Get-PortOwner $New)) { return $true }
    $ob = Get-PortBind $Old; $nb = Get-PortBind $New
    return ([bool]($ob -and $nb -and $ob -ne $nb))
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

# The task folders Windows itself populates with COM-handler tasks (no
# executable action; the handler is a CLSID). SoftLanding is the Windows
# feature-promotion scheduler, which creates per-user Deferral/Trigger tasks.
$script:WindowsTaskPathRx = '^\\(Microsoft\\Windows|SoftLanding)\\'

# A record present now and absent from the baseline. -Signer is the common
# name the binary is validly signed with ('' = unsigned, absent, unreadable);
# -MsSigned says that signer is Microsoft.
function Get-AddedVerdict {
    param([string]$Cat, [string]$Id, [string]$Detail, [bool]$MsSigned, [string]$Signer = '')
    if ($script:BinaryCats -contains $Cat) {
        # The arguments are graded FIRST: a Microsoft signature on the host
        # binary is not a clean bill of health (rundll32 <staging>\x.dll).
        if (Test-SuspiciousArgs $Detail) { return @{ Sev = 'WARNING'; Why = 'suspicious arguments' } }
        if ($Detail -match $script:StagingRx) { return @{ Sev = 'WARNING'; Why = 'runs from a staging path' } }
        if ($Cat -eq 'TASK' -and -not $Detail.Trim()) {
            # No executable to grade: a COM-handler task. Routine only where
            # Windows creates them; anywhere else the CLSID is the thing to read.
            if ($Id -match $script:WindowsTaskPathRx) { return @{ Sev = 'INFO'; Why = 'COM-handler task, no executable action, under a Windows-owned task path' } }
            return @{ Sev = 'WARNING'; Why = 'COM-handler task outside the Windows task paths -- inspect its CLSID' }
        }
        if ($MsSigned) { return @{ Sev = 'INFO'; Why = 'Microsoft-signed, likely a Windows update' } }
        if ($Signer) { return @{ Sev = 'INFO'; Why = ('validly signed by {0} -- a new install, not an update; confirm it is one you made' -f $Signer) } }
        return @{ Sev = 'WARNING'; Why = 'not validly signed' }
    }
    if ($Cat -eq 'PORT') {
        $port = 0
        if ($Id -match '^tcp/(\d+)$') { $port = [int]$Matches[1] }
        # Loopback only: nothing off the machine can reach it, whoever owns it
        # (jhi_service on [::1] in the dynamic range was a WARNING).
        if ((Get-PortBind $Detail) -match $script:LoopbackRx) {
            return @{ Sev = 'INFO'; Why = 'loopback-only listener, unreachable from the network' }
        }
        if ($port -ge $script:DynamicPortFloor -and (Get-PortOwner $Detail) -match $script:DynamicPortOwner) {
            return @{ Sev = 'INFO'; Why = 'dynamic RPC range, system-owned -- reassigned on every boot' }
        }
        return @{ Sev = 'WARNING'; Why = 'new listener' }
    }
    return @{ Sev = 'WARNING'; Why = 'never routine' }
}

# A record present in both, with different detail. -SignerNow is the common
# name the CURRENT binary is validly signed with ('' = unsigned, absent,
# unreadable); the old binary is gone, so the old signer cannot be known.
function Get-ChangedVerdict {
    param([string]$Cat, [string]$Id, [string]$Old, [string]$New, [bool]$MsSignedNow, [string]$SignerNow = '')
    if ($script:BinaryCats -contains $Cat) {
        if (Test-SuspiciousArgs $New) { return @{ Sev = 'WARNING'; Why = 'suspicious arguments' } }
        if ($New -match $script:StagingRx) { return @{ Sev = 'WARNING'; Why = 'now runs from a staging path' } }
        if ($Cat -ne 'RUN') {
            if ($MsSignedNow) { return @{ Sev = 'INFO'; Why = 'Microsoft-signed, likely a Windows update' } }
            if ($SignerNow) {
                # A non-Microsoft publisher's update moves the binary to a new
                # version directory and changes nothing else. Anything else
                # that differs -- start mode, arguments, directory, hash -- is
                # not a bump, and the signer is named so the reader can judge.
                if (Test-VersionBumpOnly -Old $Old -New $New) { return @{ Sev = 'INFO'; Why = ('validly signed by {0} -- version bump' -f $SignerNow) } }
                return @{ Sev = 'WARNING'; Why = ('binary or command changed (now signed by {0})' -f $SignerNow) }
            }
        }
        return @{ Sev = 'WARNING'; Why = 'binary or command changed' }
    }
    if ($Cat -eq 'PORT') {
        $port = 0
        if ($Id -match '^tcp/(\d+)$') { $port = [int]$Matches[1] }
        $nb = Get-PortBind $New
        if ((Get-PortOwner $Old) -eq (Get-PortOwner $New)) {
            # Same owner: the bind address moved.
            if ($nb -match $script:LoopbackRx) { return @{ Sev = 'INFO'; Why = 'listener now bound to loopback only' } }
            return @{ Sev = 'WARNING'; Why = 'listener moved from loopback to a network-reachable address' }
        }
        if ($nb -match $script:LoopbackRx) { return @{ Sev = 'INFO'; Why = 'loopback-only listener, unreachable from the network' } }
        # Same port, different owner: only quiet when the new owner is still a
        # system process in the dynamic range (svchost -> lsass on reboot).
        if ($port -ge $script:DynamicPortFloor -and (Get-PortOwner $New) -match $script:DynamicPortOwner) {
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

    # ---- what changes by design: the ten lines of the 2026-10-03 report ----
    # Get-BinPath on an UNQUOTED path with spaces (the OneDrive task action).
    $od  = 'C:\Program Files\Microsoft OneDrive\26.173.0906.0008\OneDriveLauncher.exe'
    $odOld = 'C:\Program Files\Microsoft OneDrive\26.163.0823.0004\OneDriveLauncher.exe /startInstances'
    $odNew = $od + ' /startInstances'
    # The probe reads a script-scoped value (no GetNewClosure -- see CLAUDE.md).
    $script:dzProbeHit = $od
    $probe = { param([string]$p) $p -eq $script:dzProbeHit }
    $got = Get-BinPath -Raw $odNew -Exists $probe
    T 'Get-BinPath walks an unquoted path with spaces to the first file that exists (OneDrive task action, verbatim)' ($got -eq $od) ("got=" + $got)
    $got = Get-BinPath -Raw 'C:\Windows\System32\x.exe /a /b' -Exists { param([string]$p) $false }
    T 'Get-BinPath keeps the first-token behaviour when no prefix exists' ($got -eq 'C:\Windows\System32\x.exe') ("got=" + $got)
    $got = Get-BinPath -Raw ('"' + $od + '" /startInstances') -Exists { param([string]$p) $false }
    T 'Get-BinPath takes a quoted path whole without probing' ($got -eq $od) ("got=" + $got)
    $got = Get-BinPath -Raw 'C:\Program Files\Vendor\tool.exe -server 10.0.0.1 -log C:\Program Files\Vendor\x.dll' -Exists { param([string]$p) $p -eq 'C:\Program Files\Vendor\tool.exe' }
    T 'Get-BinPath stops at the first existing prefix, not a later .dll argument' ($got -eq 'C:\Program Files\Vendor\tool.exe') ("got=" + $got)
    T 'Get-SubjectCN takes the common name out of a full subject' ((Get-SubjectCN 'CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US') -eq 'Google LLC') (Get-SubjectCN 'CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US')
    T 'Get-SubjectCN keeps a comma inside a quoted CN' ((Get-SubjectCN 'CN="Zoom Video Communications, Inc.", O="Zoom Video Communications, Inc.", C=US') -eq 'Zoom Video Communications, Inc.') (Get-SubjectCN 'CN="Zoom Video Communications, Inc.", O="Zoom Video Communications, Inc.", C=US')

    # CHANGED: version bumps of validly signed non-Microsoft binaries (verbatim).
    $v = Get-ChangedVerdict -Cat 'TASK' -Id '\OneDrive Startup Task-S-1-5-21-3734314744-1054637183-1240667225-1001' -Old $odOld -New $odNew -MsSignedNow $true -SignerNow 'Microsoft Corporation'
    T 'CHANGED OneDrive startup task (unquoted path, Microsoft-signed once found) is INFO' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    $chOld = '"C:\Program Files\Google\Chrome\Application\154.0.8037.58\elevation_service.exe" start=Manual'
    $chNew = '"C:\Program Files\Google\Chrome\Application\154.0.8037.98\elevation_service.exe" start=Manual'
    $v = Get-ChangedVerdict -Cat 'SVC' -Id 'GoogleChromeElevationService' -Old $chOld -New $chNew -MsSignedNow $false -SignerNow 'Google LLC'
    T 'CHANGED service validly signed by a non-Microsoft publisher, version segment only, is INFO naming the signer (Chrome elevation service, verbatim)' ($v.Sev -eq 'INFO' -and $v.Why -match 'Google LLC' -and $v.Why -match 'version bump') ($v.Sev + '/' + $v.Why)
    $cxOld = '"C:\Program Files\WindowsApps\OpenAI.Codex_26.924.2738.0_x64__2p2nqsd0c76g0\app\resources\codex-windows-sandbox-service.exe" start=Auto'
    $cxNew = '"C:\Program Files\WindowsApps\OpenAI.Codex_26.930.2377.0_x64__2p2nqsd0c76g0\app\resources\codex-windows-sandbox-service.exe" start=Auto'
    $v = Get-ChangedVerdict -Cat 'SVC' -Id 'CodexSandboxService.OpenAI.Codex' -Old $cxOld -New $cxNew -MsSignedNow $false -SignerNow 'OpenAI OpCo, LLC'
    T 'CHANGED MSIX package directory version (signed, non-Microsoft) is INFO (Codex sandbox service, verbatim)' ($v.Sev -eq 'INFO' -and $v.Why -match 'version bump') ($v.Sev + '/' + $v.Why)
    $v = Get-ChangedVerdict -Cat 'SVC' -Id 'GoogleChromeElevationService' -Old $chOld -New $chNew -MsSignedNow $false -SignerNow ''
    T 'CHANGED service version bump whose new binary is NOT validly signed stays WARNING' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'SVC' -Id 'GoogleChromeElevationService' -Old $chOld -New '"C:\Users\u\AppData\Local\Vendor\elevation_service.exe" start=Manual' -MsSignedNow $false -SignerNow 'Google LLC'
    T 'CHANGED service whose signed binary moved to a different directory is WARNING naming the signer' ($v.Sev -eq 'WARNING' -and $v.Why -match 'Google LLC') ($v.Sev + '/' + $v.Why)
    $v = Get-ChangedVerdict -Cat 'SVC' -Id 'GoogleChromeElevationService' -Old $chOld -New ($chNew -replace 'start=Manual$', 'start=Auto') -MsSignedNow $false -SignerNow 'Google LLC'
    T 'CHANGED service with a version bump AND a start-mode change is WARNING (not a bump)' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'TASK' -Id '\Vendor\Agent' -Old '"C:\Program Files\Vendor\agent.exe" -server 10.0.0.1' -New '"C:\Program Files\Vendor\agent.exe" -server 10.0.0.2' -MsSignedNow $false -SignerNow 'Vendor Inc'
    T 'CHANGED signed task whose ARGUMENT changed (an address, not a path version) is WARNING' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'DRV' -Id 'vendrv' -Old 'C:\Windows\System32\drivers\vendrv.sys sha256=AAAA' -New 'C:\Windows\System32\drivers\vendrv.sys sha256=BBBB' -MsSignedNow $false -SignerNow 'Vendor Inc'
    T 'CHANGED non-Microsoft driver hash (same path) is WARNING naming the signer -- a hash is not a version bump' ($v.Sev -eq 'WARNING' -and $v.Why -match 'Vendor Inc') ($v.Sev + '/' + $v.Why)
    $v = Get-ChangedVerdict -Cat 'RUN' -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\BraveUpdate' -Old '"C:\Users\u\AppData\Local\BraveSoftware\Update\1.3.361.151\BraveUpdateCore.exe"' -New '"C:\Users\u\AppData\Local\BraveSoftware\Update\1.3.370.12\BraveUpdateCore.exe"' -MsSignedNow $false -SignerNow 'Brave Software, Inc.'
    T 'CHANGED autorun value stays WARNING for a signed version bump (persistence content changed)' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    T 'Test-VersionBumpOnly: identical records are not a bump' (-not (Test-VersionBumpOnly -Old $chOld -New $chOld)) ''
    T 'Test-VersionBumpOnly: Defender platform directory (4.18.24090.11-0 -> 4.18.25070.5-0)' (Test-VersionBumpOnly -Old 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe start=Auto' -New 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MsMpEng.exe start=Auto') ''

    # NEW: signed installs, COM-handler tasks, loopback listeners (verbatim).
    $v = Get-AddedVerdict -Cat 'TASK' -Id '\ZoomVDIMGMTTaskUser' -Detail '"C:\Program Files\ZoomVDIPluginManagement\ZoomVDIPluginManagement.exe" -BackendMode' -MsSigned $false -Signer 'Zoom Video Communications, Inc.'
    T 'NEW task validly signed by a non-Microsoft publisher is INFO naming the signer (Zoom VDI, verbatim)' ($v.Sev -eq 'INFO' -and $v.Why -match 'Zoom Video Communications' -and $v.Why -match 'confirm') ($v.Sev + '/' + $v.Why)
    $v = Get-AddedVerdict -Cat 'TASK' -Id '\ZoomVDIMGMTTaskUser' -Detail '"C:\Program Files\ZoomVDIPluginManagement\ZoomVDIPluginManagement.exe" -BackendMode' -MsSigned $false -Signer ''
    T 'NEW task whose binary is not validly signed is WARNING' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-AddedVerdict -Cat 'SVC' -Id 'helper' -Detail 'C:\Users\Public\helper.exe start=Auto' -MsSigned $false -Signer 'Vendor Inc'
    T 'NEW signed non-Microsoft service in a staging path is still WARNING (the signer does not rescue the path)' ($v.Sev -eq 'WARNING' -and $v.Why -match 'staging') ($v.Sev + '/' + $v.Why)
    $v = Get-AddedVerdict -Cat 'TASK' -Id '\SoftLanding\S-1-5-21-3734314744-1054637183-1240667225-1001\SoftLandingDeferralTask-{fd0dce8d-c5fe-4ec7-b115-c0ed19f2d8f1}' -Detail '' -MsSigned $false
    T 'NEW SoftLanding task with no executable action is INFO (COM-handler task, Windows-owned path, verbatim)' ($v.Sev -eq 'INFO' -and $v.Why -match 'COM-handler') ($v.Sev + '/' + $v.Why)
    $v = Get-AddedVerdict -Cat 'TASK' -Id '\Microsoft\Windows\WindowsUpdate\Scheduled Start' -Detail '' -MsSigned $false
    T 'NEW \Microsoft\Windows\ task with no executable action is INFO' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    $v = Get-AddedVerdict -Cat 'TASK' -Id '\Updater' -Detail '' -MsSigned $false
    T 'NEW COM-handler task OUTSIDE the Windows task paths is WARNING (inspect its CLSID)' ($v.Sev -eq 'WARNING' -and $v.Why -match 'CLSID') ($v.Sev + '/' + $v.Why)
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/49670' -Detail 'jhi_service bind=::1' -MsSigned $false
    T 'NEW listener bound to [::1] only is INFO whatever the owner (jhi_service, verbatim)' ($v.Sev -eq 'INFO' -and $v.Why -match 'loopback') ($v.Sev + '/' + $v.Why)
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/4444' -Detail 'evil bind=127.0.0.1' -MsSigned $false
    T 'NEW listener bound to 127.0.0.1 below the dynamic range is INFO (unreachable from the network)' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/49670' -Detail 'jhi_service bind=0.0.0.0' -MsSigned $false
    T 'NEW non-system listener in the dynamic range bound to 0.0.0.0 is WARNING' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/49670' -Detail 'evil bind=::' -MsSigned $false
    T 'NEW listener bound to :: (every address) is WARNING' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/49670' -Detail 'svchost bind=::' -MsSigned $false
    T 'the system-owner rule still reads the owner with a bind field present' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    $v = Get-AddedVerdict -Cat 'PORT' -Id 'tcp/50000' -Detail 'pid=1234 bind=0.0.0.0' -MsSigned $false
    T 'the netstat fallback with a network-reachable bind is WARNING' ($v.Sev -eq 'WARNING') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'PORT' -Id 'tcp/8080' -Old 'agent bind=127.0.0.1' -New 'agent bind=0.0.0.0' -MsSignedNow $false
    T 'CHANGED listener that moved from loopback to 0.0.0.0 is WARNING' ($v.Sev -eq 'WARNING' -and $v.Why -match 'network-reachable') ($v.Sev + '/' + $v.Why)
    $v = Get-ChangedVerdict -Cat 'PORT' -Id 'tcp/8080' -Old 'agent bind=0.0.0.0' -New 'agent bind=127.0.0.1' -MsSignedNow $false
    T 'CHANGED listener that moved to loopback only is INFO' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    $v = Get-ChangedVerdict -Cat 'PORT' -Id 'tcp/49669' -Old 'jhi_service bind=::1' -New 'evil bind=::1' -MsSignedNow $false
    T 'CHANGED owner of a loopback-only listener is INFO' ($v.Sev -eq 'INFO') ("sev=" + $v.Sev)
    T 'a baseline saved before the bind field existed does not read every port as CHANGED' (-not (Test-RecordChanged -Cat 'PORT' -Old 'svchost' -New 'svchost bind=0.0.0.0')) ''
    T 'a PORT whose owner changed is CHANGED' (Test-RecordChanged -Cat 'PORT' -Old 'svchost bind=::' -New 'lsass bind=::') ''
    T 'a PORT whose bind moved (both sides recorded) is CHANGED' (Test-RecordChanged -Cat 'PORT' -Old 'agent bind=127.0.0.1' -New 'agent bind=0.0.0.0') ''
    T 'a non-PORT record compares its whole detail' (Test-RecordChanged -Cat 'SVC' -Old 'a start=Auto' -New 'a start=Manual') ''

    # RUN capture: the Winlogon counters are excluded by exact name.
    T 'Winlogon LastLogOffEndTimePerfCounter is excluded from the snapshot' (Test-ExcludedRunValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'LastLogOffEndTimePerfCounter') ''
    T 'Winlogon LastLogOnEndTimePerfCounter is excluded from the snapshot' (Test-ExcludedRunValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'LastLogOnEndTimePerfCounter') ''
    T 'Winlogon Shell / Userinit are NOT excluded' (-not (Test-ExcludedRunValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Shell')) ''
    T 'the same value name under a Run key is NOT excluded (the exclusion is key-scoped)' (-not (Test-ExcludedRunValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'LastLogOffEndTimePerfCounter')) ''

    # --- Per-user service instances, pinned from the 2026-10-03 22:49 report ---
    $tpl = @{
        'aarsvc'     = 'C:\WINDOWS\system32\svchost.exe -k AarSvcGroup -p'
        'cbdhsvc'    = 'C:\WINDOWS\system32\svchost.exe -k ClipboardSvcGroup -p'
        'cdpusersvc' = 'C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup'
        'credentialenrollmentmanagerusersvc' = 'C:\WINDOWS\system32\CredentialEnrollmentManager.exe'
    }
    $kOld = Get-RecordKey -Cat 'SVC' -Id 'AarSvc_fdf7a'   -Detail 'C:\WINDOWS\system32\svchost.exe -k AarSvcGroup -p start=Manual' -Templates $tpl
    $kNew = Get-RecordKey -Cat 'SVC' -Id 'AarSvc_4c42911' -Detail 'C:\WINDOWS\system32\svchost.exe -k AarSvcGroup -p start=Manual' -Templates $tpl
    T 'a per-user service renamed by a new logon keeps one key (AarSvc_fdf7a == AarSvc_4c42911)' ($kOld -eq $kNew -and $kNew -eq 'SVC|AarSvc_<per-user>') "$kOld / $kNew"
    $k1 = Get-RecordKey -Cat 'SVC' -Id 'cbdhsvc_4c42911' -Detail 'C:\WINDOWS\system32\svchost.exe -k ClipboardSvcGroup -p start=Auto' -Templates $tpl
    $k2 = Get-RecordKey -Cat 'SVC' -Id 'CredentialEnrollmentManagerUserSvc_fdf7a' -Detail 'C:\WINDOWS\system32\CredentialEnrollmentManager.exe start=Manual' -Templates $tpl
    T 'cbdhsvc and CredentialEnrollmentManagerUserSvc instances key by template' ($k1 -eq 'SVC|cbdhsvc_<per-user>' -and $k2 -eq 'SVC|CredentialEnrollmentManagerUserSvc_<per-user>') "$k1 / $k2"
    $k3 = Get-RecordKey -Cat 'SVC' -Id 'CDPUserSvc_4c42911' -Detail '"C:\Windows\System32\svchost.exe" -k UnistackSvcGroup start=Auto' -Templates $tpl
    T 'the image comparison ignores case and quotes' ($k3 -eq 'SVC|CDPUserSvc_<per-user>') $k3
    $k4 = Get-RecordKey -Cat 'SVC' -Id 'evil_abc12' -Detail 'C:\Users\Public\evil.exe start=Auto' -Templates $tpl
    T 'a per-user-LOOKING name with no template keeps its own key (stays visible as NEW)' ($k4 -eq 'SVC|evil_abc12') $k4
    $k5 = Get-RecordKey -Cat 'SVC' -Id 'AarSvc_4c42911' -Detail 'C:\Users\Public\svchost.exe -k AarSvcGroup -p start=Manual' -Templates $tpl
    T 'an instance repointed at another image keeps its own key (stays visible)' ($k5 -eq 'SVC|AarSvc_4c42911') $k5
    $k6 = Get-RecordKey -Cat 'TASK' -Id '\AarSvc_4c42911' -Detail 'x' -Templates $tpl
    T 'only services are keyed by template' ($k6 -eq 'TASK|\AarSvc_4c42911') $k6
    $k7 = Get-RecordKey -Cat 'SVC' -Id 'AarSvc_4c42911' -Detail 'C:\WINDOWS\system32\svchost.exe -k AarSvcGroup -p start=Manual' -Templates @{}
    T 'with no template map (registry unreadable) nothing is collapsed' ($k7 -eq 'SVC|AarSvc_4c42911') $k7

    # --- Old-snapshot exclusions -------------------------------------------
    T 'an OLD Winlogon counter record is excluded from the diff' `
      (Test-ExcludedRecord -Cat 'RUN' -Id 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LastLogOffEndTimePerfCounter' -Detail '1804345906204') ''
    T 'our own RunOnce resume entry (data names doze_sec.bat) is excluded' `
      (Test-ExcludedRecord -Cat 'RUN' -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*WIN11_SecurityAudit_resume' -Detail '"C:\Users\u\src\doze_sec\doze_sec.bat" -resume') ''
    T 'the noAdmin bat resume entry is excluded too' `
      (Test-ExcludedRecord -Cat 'RUN' -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*WIN11_SecurityAudit_resume' -Detail '"C:\x\doze_sec_noAdmin.bat" -resume') ''
    T 'the resume NAME with someone else''s data is NOT excluded (marker, never name)' `
      (-not (Test-ExcludedRecord -Cat 'RUN' -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*WIN11_SecurityAudit_resume' -Detail 'C:\Users\Public\evil.exe -resume')) ''
    T 'the resume shape under a Run key (not RunOnce) is NOT excluded' `
      (-not (Test-ExcludedRecord -Cat 'RUN' -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*WIN11_SecurityAudit_resume' -Detail '"C:\x\doze_sec.bat" -resume')) ''
    T 'a SVC record is never excluded by the RUN rules' `
      (-not (Test-ExcludedRecord -Cat 'SVC' -Id 'LastLogOffEndTimePerfCounter' -Detail 'x')) ''

    if ($fails) { Write-Output "[FAIL] $fails baseline_diff self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] baseline_diff self-test: update churn (signed replacements and version bumps, dynamic RPC ports, loopback listeners, COM-handler tasks, logon counters) is context; replaced unsigned binaries, moved listeners, new admins, new roots and suspicious arguments are findings.'
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
                if (Test-ExcludedRunValue -Key $k -Name $p.Name) { continue }
                if (Test-OwnResumeEntry -Key $k -Name $p.Name -Value ([string]$p.Value)) { continue }
                $recs.Add(('RUN|{0}\{1}|{2}' -f (CleanField $k), (CleanField $p.Name), (CleanField ([string]$p.Value))))
            }
        } catch {}
    }

    # PORT -- listening sockets. A new listener is how an implant takes calls.
    try {
        foreach ($c in (Get-NetTCPConnection -State Listen -EA Stop)) {
            $pname = ''
            try { $pname = (Get-Process -Id $c.OwningProcess -EA Stop).ProcessName } catch {}
            $bind = CleanField ([string]$c.LocalAddress)
            $recs.Add(('PORT|tcp/{0}|{1} bind={2}' -f (CleanField ([string]$c.LocalPort)), (CleanField $pname), ($bind -replace '\s', '')))
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
                $bind = ''
                if ($f[1].Length -gt $lp.Length + 1) { $bind = $f[1].Substring(0, $f[1].Length - $lp.Length - 1).Trim('[', ']') }
                $recs.Add(('PORT|tcp/{0}|pid={1} bind={2}' -f (CleanField $lp), (CleanField $f[4]), (CleanField $bind -replace '\s', '')))
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
        "[INFO] Excluded by design: Winlogon $($script:ExcludedRunValues -join ' and ') -- Windows rewrites these counters at every logon and logoff; they are not persistence values."
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
$oldExcluded = 0
$perUserOld = 0
$perUserNew = 0
$userSvcTemplates = Get-UserServiceTemplates
try {
    foreach ($ln in (Get-Content -LiteralPath $Path -Encoding UTF8 -EA Stop)) {
        $t = $ln.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $f = $t.Split('|')
        if ($f.Length -lt 2) { continue }
        $detail = ''
        if ($f.Length -ge 3) { $detail = ($f[2..($f.Length - 1)] -join '|') }
        if (Test-ExcludedRecord -Cat $f[0] -Id $f[1] -Detail $detail) { $oldExcluded++; continue }
        $key = Get-RecordKey -Cat $f[0] -Id $f[1] -Detail $detail -Templates $userSvcTemplates
        if ($key -ne ($f[0] + '|' + $f[1])) { $perUserOld++ }
        $old[$key] = $detail
    }
} catch {
    "[WARNING] Baseline unreadable: $($_.Exception.Message) -- baseline comparison NOT performed."
    # A gap, not a changed-state finding: its own marker and its own ledger row.
    Write-Marker -Name 'baseline_gap' -Sev 'WARNING'
    return
}

$new = @{}
foreach ($ln in $snapshot) {
    $f = $ln.Split('|')
    if ($f.Length -lt 2) { continue }
    $detail = ''
    if ($f.Length -ge 3) { $detail = ($f[2..($f.Length - 1)] -join '|') }
    $key = Get-RecordKey -Cat $f[0] -Id $f[1] -Detail $detail -Templates $userSvcTemplates
    if ($key -ne ($f[0] + '|' + $f[1])) { $perUserNew++ }
    $new[$key] = $detail
}
# Declared, never silent: what was compared differently, and why.
if ($perUserOld -gt 0 -or $perUserNew -gt 0) {
    "[INFO] Per-user service instances compared by template ($perUserOld in the baseline, $perUserNew now): Windows renames them <template>_<suffix> at every logon. An instance whose image differs from its template's is still compared by its own name."
}
if ($oldExcluded -gt 0) {
    "[INFO] Excluded by design: $oldExcluded value(s) in the saved baseline (Winlogon logon/logoff counters, or doze_sec's own RunOnce resume entry) -- not compared."
}

# NEW items that are validly Microsoft-signed are almost always Windows Update
# doing its job -- reported for the record, but not raised.
$sev = 'OK'
$added = @(); $changed = @(); $removed = @()

foreach ($k in $new.Keys) {
    if ($old.ContainsKey($k)) {
        if (Test-RecordChanged -Cat ($k.Split('|')[0]) -Old $old[$k] -New $new[$k]) { $changed += $k }
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
# Helper: who validly signed the binary behind a record's detail? Signer is
# the common name ('' when unsigned, absent or unreadable); MsSigned says it
# is Microsoft. Non-binary categories carry no signer.
function Get-RecordSigner {
    param([string]$Cat, [string]$Detail)
    $r = @{ MsSigned = $false; Signer = '' }
    if ($script:BinaryCats -notcontains $Cat) { return $r }
    $bin = Get-BinPath ($Detail -replace ' sha256=[0-9A-Fa-f]*$', '' -replace ' start=\w+$', '')
    $si = Get-SignerInfo $bin
    $r.MsSigned = [bool]$si.Microsoft
    if ($si.Valid) { $r.Signer = [string]$si.CN }
    return $r
}

$addEval = @()
foreach ($k in ($added | Sort-Object)) {
    $cat = $k.Split('|')[0]
    $id  = $k.Substring($cat.Length + 1)
    $lbl = Get-CatLabel $cat
    $detail = $new[$k]
    $sg = Get-RecordSigner -Cat $cat -Detail $detail
    $v = Get-AddedVerdict -Cat $cat -Id $id -Detail $detail -MsSigned $sg.MsSigned -Signer $sg.Signer
    if ($v.Sev -eq 'WARNING') { $sev = Get-MaxSev $sev 'WARNING' }
    $addEval += New-Object PSObject -Property @{ Lbl = $lbl; Id = $id; Detail = $detail; Sev = $v.Sev; Why = $v.Why }
}
$warnAdds = @($addEval | Where-Object { $_.Sev -eq 'WARNING' })
$infoAdds = @($addEval | Where-Object { $_.Sev -ne 'WARNING' })
$n = 0
foreach ($a in $warnAdds) {
    $n++
    # The reason is printed on WARNING lines too, so a reader sees WHY this
    # one was not forgiven (unsigned, staging path, suspicious argument).
    if ($n -le $MaxReport) { "[WARNING] NEW $($a.Lbl) since baseline ($($a.Why)): $($a.Id)  =>  $($a.Detail)" }
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
    $sg = Get-RecordSigner -Cat $cat -Detail $new[$k]
    $v = Get-ChangedVerdict -Cat $cat -Id $id -Old $old[$k] -New $new[$k] -MsSignedNow $sg.MsSigned -SignerNow $sg.Signer
    if ($v.Sev -eq 'WARNING') { $sev = Get-MaxSev $sev 'WARNING' }
    $chEval += New-Object PSObject -Property @{ Lbl = (Get-CatLabel $cat); Id = $id; Key = $k; Sev = $v.Sev; Why = $v.Why }
}
$warnCh = @($chEval | Where-Object { $_.Sev -eq 'WARNING' })
$infoCh = @($chEval | Where-Object { $_.Sev -ne 'WARNING' })
$chShown = 0
foreach ($c in $warnCh) {
    $chShown++
    if ($chShown -le $MaxReport) {
        "[WARNING] CHANGED $($c.Lbl) since baseline ($($c.Why)): $($c.Id)"
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
