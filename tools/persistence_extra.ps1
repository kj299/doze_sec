# persistence_extra.ps1 -- the long tail of autostart/persistence points that
# the other Section 5 evaluators do not own. Invoked from Section 5 of
# doze_sec.bat / doze_sec_noAdmin.bat.
#
# The Section 5 persistence evaluators, by domain:
#   persistence_eval.ps1   Run/RunOnce keys, IFEO debuggers          (issue #138)
#   startup_eval.ps1       Startup folders, AppCert DLLs             (T1547.001/.009)
#   logon_persistence.ps1  Winlogon Notify, Credential/Network Providers,
#                          LSA packages, screensaver, logon scripts  (logon/unlock)
#   persistence_extra.ps1  THIS FILE -- netsh helpers, print processors, port
#                          monitors, BITS jobs, PowerShell profiles, time
#                          providers.
#
# WHY THESE SIX: each is a documented ATT&CK persistence technique where some
# Windows subsystem loads an attacker-chosen DLL or runs an attacker-chosen
# command, and none of them was audited at all. They are individually less
# common than a Run key, which is exactly why they are attractive: an operator
# who expects the obvious locations to be checked moves to these.
#
#   Netsh helper DLLs      T1546.007  HKLM\SOFTWARE\Microsoft\Netsh -- every
#                                     DLL here loads whenever netsh.exe runs,
#                                     and netsh runs constantly on a managed
#                                     host (scripts, GPO, admins).
#   Print processors       T1547.012  ...\Control\Print\Environments\*\Print
#                                     Processors\*\Driver -- loaded by
#                                     spoolsv.exe, which runs as SYSTEM and
#                                     starts at boot.
#   Port monitors          T1547.010  ...\Control\Print\Monitors\*\Driver --
#                                     same SYSTEM spooler load, at boot.
#   BITS jobs              T1197      A job whose notify command line runs on
#                          + T1048    completion survives reboots and is owned
#                                     by the service, not a startup key. A job
#                                     whose TransferType is Upload is the other
#                                     direction: a file queued to LEAVE this
#                                     machine over HTTP, by a Windows service,
#                                     under the owner's account.
#   PowerShell profiles    T1546.013  profile.ps1 runs on every interactive
#                                     PowerShell start -- a favourite because
#                                     it looks like developer config.
#   Time providers         T1547.003  W32Time\TimeProviders\*\DllName -- loaded
#                                     by the time service as SYSTEM.
#
# FALSE POSITIVES ARE THE WHOLE DESIGN PROBLEM HERE. Real machines legitimately
# extend three of these: printer vendors (HP, Canon, Xerox) install port
# monitors and print processors, some VPN/network products add netsh helpers,
# and developers keep PowerShell profiles. So:
#   - DLL-backed points (netsh, print processors, port monitors, time providers)
#     are judged by Authenticode, not by name allowlist. Judging by signature
#     also closes the obvious bypass: an attacker who overwrites the DLL behind
#     a DEFAULT entry name (winprint.dll, w32time.dll) would sail past any
#     name allowlist, but not past a signature check.
#       CRITICAL -- unsigned / invalid signature / missing file / staging path
#       WARNING  -- validly signed, but not by Microsoft (the vendor case)
#       OK       -- validly Microsoft-signed (every stock Windows entry)
#   - PowerShell profiles: EXISTENCE IS NOT A FINDING. Only profile CONTENT is
#     judged -- download cradles, encoded commands, staging paths.
#   - BITS: a job existing is not a finding either (Windows Update uses BITS).
#     A notify command line is the persistence mechanism, so that is what is
#     flagged; long-lived jobs are surfaced separately because the default max
#     job lifetime is 90 days and malware parks jobs there. An UPLOAD job is
#     reported on its own terms and at its own severity, because the benign
#     cause is narrow (a management agent sending diagnostics to a collector it
#     owns) and the malign one is the last step of an intrusion.
#
# MARKERS: writes the severity word (CRITICAL/WARNING) to
# $env:TEMP\dz_netsh.txt, dz_printproc.txt, dz_portmon.txt, dz_bits.txt,
# dz_bitsupload.txt, dz_psprofile.txt, dz_timeprov.txt. The caller reads each
# and raises via :dz_finding. No marker is written when clean.
#
# Windows PowerShell 5.1 compatible. Read-only (registry/filesystem/BITS reads
# plus marker writes under TEMP). Executed by the helpers-ps51 CI job.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [int]$BitsAgeDays  = 30,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

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

$trusted   = '\bMicrosoft\b|\bWindows\b'
$badPathRx = '\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\ProgramData\\update'
# Strong command-content indicators, kept in sync with persistence_eval.ps1
# and startup_eval.ps1.
$strongContent = @(
    '-enc(odedcommand)?\b',
    '-e\s+[A-Za-z0-9+/=]{24,}',
    'frombase64string',
    'downloadstring', 'downloadfile',
    '(invoke-webrequest|\biwr\b|\bcurl\b|\bwget\b)[^\r\n]*https?:',
    '(iex|invoke-expression)\s*[\(\$]', '\|\s*(iex|invoke-expression)\b',
    'mshta\s+https?:', 'mshta\s+javascript',
    'certutil[^\r\n]*-urlcache', 'certutil[^\r\n]*-decode',
    'bitsadmin[^\r\n]*/transfer',
    'regsvr32[^\r\n]*/i:http', 'regsvr32[^\r\n]*scrobj', 'rundll32[^\r\n]*javascript'
) -join '|'

function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

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

# Resolve a registry-held DLL reference to a full path. These keys routinely
# hold a bare filename (winprint.dll, w32time.dll) that the loading service
# resolves against its own search path, so a bare name is looked up in the
# caller-supplied directories before being reported missing.
function Resolve-DllPath {
    param([string]$Raw, [string[]]$SearchDirs)
    if (-not $Raw) { return '' }
    $p = [Environment]::ExpandEnvironmentVariables($Raw.Trim().Trim('"'))
    if ($p -match '^\\\?\?\\') { $p = $p.Substring(4) }
    if ($p -match '[\\/]') { return $p }
    foreach ($d in $SearchDirs) {
        if (-not $d) { continue }
        $c = Join-Path $d $p
        if (Test-Path -LiteralPath $c -PathType Leaf) { return $c }
    }
    if ($SearchDirs -and $SearchDirs[0]) { return (Join-Path $SearchDirs[0] $p) }
    return $p
}

# Authenticode gate for subsystem-loaded DLLs. Stricter than the Startup-folder
# gate: every stock entry in these keys is Microsoft-signed, so a validly-signed
# third party is worth a WARNING rather than a clean pass.
function Get-DllVerdict {
    param([string]$Path)
    if (-not $Path) { return @{ Sev = 'CRITICAL'; Why = 'no DLL path recorded' } }
    if ($Path -match $badPathRx) { return @{ Sev = 'CRITICAL'; Why = "staging path: $Path" } }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @{ Sev = 'CRITICAL'; Why = "DLL not found: $Path" } }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $Path -EA Stop } catch {}
    if (-not $sig -or $sig.Status -ne 'Valid') { return @{ Sev = 'CRITICAL'; Why = "unsigned or invalid signature: $Path" } }
    if ($sig.SignerCertificate.Subject -notmatch $trusted) {
        $cn = (($sig.SignerCertificate.Subject -split ',')[0]) -replace '^CN=', ''
        return @{ Sev = 'WARNING'; Why = "signed by $cn (not Microsoft): $Path" }
    }
    return @{ Sev = 'OK'; Why = "Microsoft-signed: $Path" }
}

# ---------------------------------------------------------------------------
# BITS grading (T1197), as a PURE function.
#
# Every input is a plain value -- no CIM, no clock, no BITS module -- so the
# whole rule is exercisable by -SelfTest on any platform. The BITS arm had no
# seam at all, and that is exactly why the false positive recorded below had
# to be caught by hand on the owner's machine instead of by a test.
# ---------------------------------------------------------------------------

# A bare IP literal as the destination host...
#
# ...of which the private and non-routable ranges are NOT a signal. An
# on-premises WSUS server, an SCCM distribution point and a Microsoft
# Connected Cache node are all routinely reached by bare LAN address, and
# BITS is the transport all three use. A bare PUBLIC address has no such
# routine cause and still raises. 172.32.x is deliberately outside this --
# the private block ends at 172.31.
# IPv6 literals count too, in both rules. A bare `http://[2001:db8::7]/u` is as
# nameless as a bare IPv4 address -- and before this was added it fell through
# to the reassuring half of the upload wording, which told the reader that the
# owner account and the collector are what tell a management agent apart while
# the collector was an address with no name at all.
$script:BareIpRx = '^\s*https?://((\d{1,3}\.){3}\d{1,3}|\[[0-9A-Fa-f:.]+\])([:/]|$)'
$script:PrivateIpRx = '^\s*https?://(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|\[(::1\]|[fF][eE]80:|[fF][cCdD][0-9A-Fa-f]{2}:))'

# A value read off a job goes straight into a report line, so a crafted file
# name must not be able to start a line with a severity tag of its own. Same
# rule driver_audit applies to a driver path.
function Format-BitsField {
    param([string]$Raw)
    if ($null -eq $Raw) { return '' }
    $s = ($Raw -replace '[\x00-\x1F\x7F]', ' ').Trim()
    if ($s.Length -gt 240) { $s = $s.Substring(0, 240) + '...' }
    return $s
}

# ...and a value that lands INSIDE a single-quoted PowerShell string in a line
# the report tells the reader to paste needs its apostrophes doubled as well.
# A BITS display name is an arbitrary string the job's creator chooses, so
# without this the `verify:` line below is a command an attacker writes for a
# person who has just been told their data is leaving: a name of
# `ok'; Start-Process calc; 'x` closes the comparison and appends a statement.
# The benign half is the same bug this repo already paid for elsewhere: a job
# honestly named `O'Brien backup` printed a line that could not run.
function Format-BitsQuoted {
    param([string]$Raw)
    return ((Format-BitsField $Raw) -replace "'", "''")
}

# WHAT IS LEAVING decides the severity of an upload, as a PURE classifier.
#
# An upload job names the local file in its FileList, so the audit can say what
# would leave rather than only that something would. These classes are the
# person's own data and the credential stores: nothing on a healthy machine
# queues them for an HTTP upload.
#
# Deliberately NOT here: an archive outside the user's own folders. A real
# management agent does collect diagnostics into a .cab under a temp folder and
# upload it, so an archive alone is reported at WARNING with the file named,
# not asserted to be staged loot. An archive INSIDE the profile's own folders
# is covered by the profile rule below, which is where the person's documents
# actually live.
# EVERY reason that applies is returned, not the first one. A copy of
# ntds.dit taken out of a shadow copy is both a credential database and a
# shadow-copy read, and the reader needs both halves: the first says what was
# taken, the second how. Returning only the first match would also make the
# wording depend on the order of the tests below, which is not a property
# anyone should have to reason about.
function Get-UploadSourceReason {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return @() }
    # Trim first: these classes are `$`-anchored and NTFS allows a trailing
    # space in a name, so `ntds.dit ` would otherwise read as ordinary.
    $p = ([string]$Path).Trim()
    $out = @()
    $notes = @()
    # `Public`, `Default`, `Default User` and `All Users` sit beside the real
    # profiles under \Users\ and are NOT "the signed-in user's own folders":
    # C:\Users\Public\Documents is a shared location vendors write logs into,
    # and saying otherwise would be a false sentence in a CRITICAL finding.
    # (The repo has paid for a path regex that matched a name it did not mean
    # before: `\\Public\\` matched node_modules\...\public\binaries\.)
    # OneDrive is matched with a suffix because the business client's folder is
    # always `OneDrive - <TenantName>` -- the commercial case, which is exactly
    # the machine that also has a management agent on it.
    if ($p -match '(?i)\\Users\\(?!Public\\|Default\\|Default User\\|All Users\\)[^\\]+\\(Documents|Desktop|Downloads|Pictures|Videos|Music|OneDrive[^\\]*)\\') {
        $out += "it is a file from the signed-in user's own folders"
    }
    if ($p -match '(?i)\\AppData\\(Local|Roaming)\\(Google\\Chrome|Microsoft\\Edge|Mozilla\\Firefox|BraveSoftware|Opera Software|Vivaldi)\\') {
        $out += 'it is a file from a browser profile, where saved passwords, cookies and session tokens live'
    }
    if ($p -match '(?i)(\.(pst|ost|kdbx|kdb|ppk|pfx|p12|key)$|\\id_rsa$)') {
        $out += 'it is a mail store, a password database or a private key'
    }
    # A .pem is as often a PUBLIC certificate or a CA bundle as a private key,
    # and an agent's diagnostics bundle plausibly carries one, so it does not
    # escalate on the extension alone -- it is named instead, and the upload is
    # still reported.
    if ($p -match '(?i)\.(pem|crt|cer|der)$') {
        $notes += 'the file is a certificate file; a .pem or .crt may be a public certificate rather than a private key, so read it before deciding'
    }
    # Anchored to the directory that actually holds the live hives, plus the
    # extensions a COPY of one carries. `(\.\w+)?$` used to be the tail here,
    # which made every `...\config\system.json` -- one of the commonest
    # application-config shapes there is -- read as a copy of a registry hive,
    # CRITICAL, with advice to treat the machine as compromised.
    if ($p -match '(?i)(\\ntds\.dit$|\\Windows\\System32\\config\\(SAM|SYSTEM|SECURITY)(\.(sav|bak|old|log\d?))?$|\\(SAM|SYSTEM|SECURITY)\.(sav|bak|hive|old)$)') {
        $out += 'it is a copy of a registry hive or of the directory database, which holds credentials'
    }
    if ($p -match '(?i)\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy') {
        $out += 'it is read out of a volume shadow copy, the usual way a locked credential file is taken'
    }
    return @{ Reasons = $out; Notes = $notes }
}

# The per-run summary lines, as a PURE function. The all-clear sentence is the
# single most dangerous line this file prints -- it is what a reader takes as
# "nothing is leaving" -- and whether it is printed depended on three counters
# in the middle of a live loop, where no test could reach it. One of those
# counters was missing: a job whose direction could not be read was declared as
# a gap AND covered by the all-clear in the same report.
function Get-BitsSummaryLines {
    param(
        [int]$JobCount,
        [int]$Flagged = 0,
        [int]$UpFlagged = 0,
        [int]$Aged = 0,
        [int]$Unread = 0,
        [int]$TypeUnread = 0,
        [bool]$AllUsers = $true
    )
    $out = @()
    if ($Flagged -eq 0 -and $UpFlagged -eq 0 -and $TypeUnread -eq 0) {
        $scope = 'BITS job(s) queued'
        if (-not $AllUsers) { $scope = 'BITS job(s) queued for this user' }
        $out += "[OK] $JobCount $scope, none with a notify command line, an unreadable file list, a questionable destination, or a file queued to leave this machine."
    } elseif ($Flagged -eq 0 -and $UpFlagged -eq 0) {
        $out += "[INFO] $($JobCount - $TypeUnread) of $JobCount BITS job(s) were graded and none of them raised anything; the direction of the other $TypeUnread could not be read and is declared below, not cleared."
    }
    if (-not $AllUsers) {
        $out += '[INFO] BITS jobs were enumerated for THIS USER only -- Get-BitsTransfer -AllUsers needs administrator rights, so a job owned by another account, including one queued to upload, is not visible from this token. Re-run as administrator to cover the machine.'
    }
    if ($Aged -gt 0) { $out += "[INFO] $Aged long-lived BITS job(s) listed above are reported as context only -- see the destination on each line." }
    if ($Unread -gt 0) { $out += "[WARNING] $Unread BITS job(s) did not expose a NotifyCmdLine property and were NOT checked for command-line persistence." }
    if ($TypeUnread -gt 0) { $out += "[WARNING] $TypeUnread BITS job(s) did not report a readable transfer direction and were NOT checked for it -- whether they upload a file off this machine is unknown, not cleared." }
    return $out
}

function Get-BitsVerdict {
    param(
        [string]$Name,
        [string]$Owner,
        [object]$Created,                 # [datetime], or $null when unreadable
        [string]$NotifyCmdLine = '',
        [bool]$NotifyKnown = $true,
        [string[]]$Remotes = @(),
        [string[]]$Locals  = @(),
        [bool]$DestKnown = $true,
        [bool]$FileListEmpty = $false,
        [string]$TransferType = '',       # download | upload | uploadreply
        [bool]$TypeKnown = $true,
        [string]$JobState = '',
        [bool]$AllUsers = $true,
        [int]$AgeDays = 30,
        [datetime]$Now = (Get-Date)
    )
    $r = @{ Lines = @(); Sev = 'OK'; UpSev = 'OK'; UpGap = 'OK'; Flagged = 0; Aged = 0
            Unread = 0; UpFlagged = 0; TypeUnread = 0 }
    # EVERY value that came off the job is normalised once, here, before any arm
    # can print it. A BITS display name and a file name may both contain CR and
    # LF, and a line of the report is identified by the tag it starts with: an
    # unfiltered name carrying a newline and `[OK] this machine is fine` forges
    # a line that block_sev, verdict_audit and top_findings all grade. Only the
    # upload arm filtered its own values before; the arms below interpolated
    # these raw, and moving the destination signal out from behind the age gate
    # is what made that reachable for a job created minutes ago.
    $Name          = Format-BitsField $Name
    $Owner         = Format-BitsField $Owner
    $NotifyCmdLine = Format-BitsField $NotifyCmdLine
    if (-not $NotifyKnown) { $r.Unread = 1 }
    # An engine that does not surface the direction has not been asked the
    # question. Counted and declared by the caller, never read as a download --
    # defaulting an unknown to the harmless value is the mistake this repo has
    # paid for in block_sev, DZ_BLKSEV and the service probe. A value that IS
    # there but is none of the three documented types is the same situation:
    # an engine that starts surfacing the type as a number, or a type added
    # later, must not be read as "download" because that is the harmless one.
    $tt = ''
    if ($TransferType) { $tt = ([string]$TransferType).Trim().ToLower() }
    if (-not $TypeKnown) {
        $r.TypeUnread = 1
    } elseif ($tt -ne 'download' -and $tt -ne 'upload' -and $tt -ne 'uploadreply') {
        $r.TypeUnread = 1
    }

    if (-not [string]::IsNullOrWhiteSpace($NotifyCmdLine)) {
        $sev = 'WARNING'
        if ($NotifyCmdLine -match $strongContent -or $NotifyCmdLine -match $badPathRx) { $sev = 'CRITICAL' }
        $r.Lines += "[$sev] BITS job '$Name' (owner $Owner) has a notify command line: $NotifyCmdLine"
        $r.Sev = Get-MaxSev $r.Sev $sev
        $r.Flagged++
    }

    # AGE ALONE IS NOT A FINDING. This rule used to raise a WARNING on any job
    # older than $AgeDays, and on the owner's machine 2026-09-13 it fired for
    # 'Edge Component Updater' -- Microsoft Edge's own updater, created
    # 2026-08-09, with NO notify command line. It had been 29 days old during
    # the previous run and 35 during this one: the finding reported a birthday,
    # not a behaviour, and nothing on the machine had changed.
    #
    # T1197 persistence executes through the NOTIFY COMMAND LINE, handled
    # above and independently. What a long-parked job with no notify command
    # can still do is move bytes, so the honest discriminator is the
    # DESTINATION, not the calendar. Deliberately NOT a list of known-good job
    # names: this repo already records that excluding by NAME lets an attacker
    # pick the name.
    #
    # THE AGE GATE USED TO SIT HERE, ABOVE THE DESTINATION RULE, AND THAT HID
    # THE ONLY SHAPE THAT MOVES QUICKLY. A `return` for any job younger than
    # $AgeDays (30 by default) meant a job created minutes ago was never graded
    # at all: not its destination, not the direction of transfer, not what file
    # it carries. An exfiltration job is minutes old, and so is the ingress job
    # that fetches the next stage. The calendar now gates only the INFO context
    # line at the bottom, which is the one thing age really is about; every
    # signal below is reached whatever the job's age.

    # PLAIN HTTP IS NOT A SIGNAL, AND USED TO BE ONE HERE.
    #
    # The destination rule replaced the age rule above, and shipped with a
    # branch that raised on any http:// remote. On 2026-09-19 it flagged the
    # SAME 'Edge Component Updater', for the third time through a third rule:
    #
    #   [WARNING] ... it fetches over plain HTTP, not HTTPS
    #   (http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/...)
    #
    # Microsoft documents *.dl.delivery.mp.microsoft.com as HTTP on port 80 for
    # Edge content delivery, and states: "Be sure not to use HTTPS for those
    # endpoints that specify HTTP, and vice versa. The connection will fail."
    # Plain HTTP there is REQUIRED -- the payloads are signed and hash-verified
    # separately -- so the rule flagged the single most common BITS job class
    # on Windows. The CI case used http://localhost and proved the rule FIRED;
    # it never asked whether firing was correct. The mechanism was tested and
    # the judgement was not.
    #
    # Do not re-add it. If a destination needs grading, grade WHO is at the
    # other end, not which scheme reaches them.
    $pubIps = @()
    $lan = @()
    foreach ($rn in @($Remotes)) {
        if ($rn -notmatch $script:BareIpRx) { continue }
        if ($rn -match $script:PrivateIpRx) { $lan += $rn; continue }
        $pubIps += $rn
    }
    $why = @()
    foreach ($ip in @($pubIps)) { $why += "fetches from a bare public IP address ($ip)" }
    # NOT $badPathRx here, though every other arm in this file uses it. It
    # contains \Temp\, and a BITS job writing into the temp folder is what a
    # downloader DOES -- Edge's own updater included. An autostart folder is
    # different: nothing legitimate streams a file straight into Startup.
    foreach ($l in @($Locals)) {
        if ($l -match '(?i)\\Start Menu\\Programs\\Startup\\') { $why += "writes directly into an autostart folder ($l)" }
    }

    # ---- THE DIRECTION OF TRANSFER (T1048) --------------------------------
    #
    # Microsoft documents three job types -- Download (the default), Upload and
    # UploadReply -- and, for an upload, that the job's SOURCE is the local file
    # and its DESTINATION is the HTTP URL. Every rule above and below reads a
    # job the other way round, so before this arm existed an upload job's local
    # file (the data leaving) was examined only for autostart writes, and the
    # collector receiving it was printed as "an ordinary destination".
    #
    # An upload job is reported whatever its age and whatever its state: the
    # job names the file and the collector whether or not the transfer ever
    # succeeds, and a queued-but-never-completed upload is still the owner's
    # evidence that something tried. Uploading to an arbitrary server needs
    # either the IIS BITS Server Extension enabled on the receiving virtual
    # directory, or a non-GET method (-HttpMethod, which Microsoft documents as
    # forcing foreground priority) -- so a failing upload job is as interesting
    # as a working one and is never discounted for it.
    if ($tt -eq 'upload' -or $tt -eq 'uploadreply') {
        # A job with NO files added yet is not a file queued to leave: it is
        # also exactly what the moment between creating a job and adding a file
        # looks like, and the download arm below refuses to grade that same
        # transient for that reason. Reported as context, raising nothing.
        if ($FileListEmpty) {
            $r.Lines += "[INFO] BITS job '$Name' (owner $Owner) is an UPLOAD job with no files added yet, so nothing is queued to leave this machine. A job in this state is also what the moment between creating a job and adding a file to it looks like; it is reported so a reader can look again rather than counted as a finding."
            return $r
        }
        $sev = 'WARNING'
        $srcReasons = @()
        $srcNotes   = @()
        foreach ($l in @($Locals)) {
            $cls = Get-UploadSourceReason -Path $l
            foreach ($rsn in @($cls.Reasons)) { $srcReasons += ($rsn + ' (' + (Format-BitsField $l) + ')') }
            foreach ($nte in @($cls.Notes))   { $srcNotes   += ($nte + ' (' + (Format-BitsField $l) + ')') }
        }
        if (@($srcReasons).Count -gt 0 -or @($pubIps).Count -gt 0) { $sev = 'CRITICAL' }

        $head = "[$sev] BITS job '$Name' (owner $Owner) is queued to UPLOAD a file off this machine (T1048)"
        if ($tt -eq 'uploadreply') { $head += ', and to receive a reply file back' }
        $r.Lines += ($head + ':')
        if (-not $DestKnown) {
            $r.Lines += '    file:   NOT READABLE -- the job exists and its file list could not be read, so WHAT is leaving could not be identified'
        } else {
            foreach ($l in @($Locals)) { $r.Lines += ("    file:   " + (Format-BitsField $l)) }
            foreach ($rn in @($Remotes)) { $r.Lines += ("    to:     " + (Format-BitsField $rn)) }
        }
        $shownWhy = 0
        foreach ($s in @($srcReasons)) {
            if ($shownWhy -ge 6) { break }
            $r.Lines += ("    why:    " + $s)
            $shownWhy++
        }
        if (@($srcReasons).Count -gt $shownWhy) {
            $r.Lines += ("    why:    ...and " + (@($srcReasons).Count - $shownWhy) + " more file(s) in the classes above")
        }
        if (@($pubIps).Count -gt 0) {
            $r.Lines += ("    why:    the collector is a bare public IP address with no name behind it (" + (Format-BitsField (@($pubIps)[0])) + ')')
        }
        if (@($lan).Count -gt 0) {
            $r.Lines += '    note:   the collector is a private LAN address -- a ConfigMgr management point receives client uploads this way over BITS. Confirm that address is one your organisation runs.'
        }
        foreach ($nte in @($srcNotes)) { $r.Lines += ("    note:   " + $nte) }
        if (@($srcReasons).Count -eq 0 -and @($pubIps).Count -eq 0) {
            $where = 'the owner account and the collector above are what tell the two apart'
            if (-not $DestKnown) { $where = 'the owner account below is all there is to go on, since the file list could not be read' }
            $r.Lines += ("    note:   a management agent may upload diagnostics legitimately; " + $where + '.')
        }
        if ($JobState) { $r.Lines += ("    state:  " + (Format-BitsField $JobState)) }
        if ($null -ne $Created) { $r.Lines += ("    created: " + ([datetime]$Created).ToString('yyyy-MM-dd HH:mm:ss')) }
        # -AllUsers needs administrator rights, so the printed line must match
        # the token the reader has: handing a standard user a command they
        # cannot run is the same defect as printing one that does not parse.
        $allSw = ' -AllUsers'
        if (-not $AllUsers) { $allSw = '' }
        $r.Lines += "    verify: Get-BitsTransfer$allSw | Where-Object DisplayName -eq '$(Format-BitsQuoted $Name)' | Select-Object TransferType,JobState,OwnerAccount -ExpandProperty FileList"
        $r.UpSev = Get-MaxSev $r.UpSev $sev
        $r.UpFlagged++
        return $r
    }

    # ---- downloads: the destination signal, now age-independent -----------
    if (@($why).Count -gt 0) {
        $when = 'creation time unreadable'
        $tail = 'A background transfer that moves bytes somewhere questionable is the T1197 shape whatever its age.'
        if ($null -ne $Created) {
            [datetime]$cw = $Created
            $agew = [int]($Now - $cw).TotalDays
            $when = "created $($cw.ToString('yyyy-MM-dd')), $agew days old"
            # Only say "parked near the maximum" when it is true of this job:
            # at the default AgeDays of 30, a 31-day-old job was being
            # described as near a 90-day maximum.
            if ($cw -lt $Now.AddDays(-60)) {
                $tail = 'A job parked near the 90-day maximum that also moves bytes somewhere questionable is the T1197 shape.'
            } elseif ($cw -lt $Now.AddDays(-$AgeDays)) {
                $tail = 'A long-lived job that also moves bytes somewhere questionable is the T1197 shape; BITS allows a job to sit for 90 days.'
            }
        }
        $r.Lines += "[WARNING] BITS job '$Name' (owner $Owner) $when, and it $([string]::Join('; ', $why)). $tail"
        $r.Sev = Get-MaxSev $r.Sev 'WARNING'
        $r.Flagged++
        return $r
    }

    # The remaining two arms are about AGE, so they keep the age gate. An
    # unreadable file list is left age-gated on purpose: a job caught during
    # creation has no files added yet, and Windows Update creates jobs while an
    # audit is reading them -- that transient must not become a finding.
    if ($null -eq $Created) { return $r }
    [datetime]$c = $Created
    if ($c -ge $Now.AddDays(-$AgeDays)) { return $r }
    $age = [int]($Now - $c).TotalDays

    if (-not $DestKnown) {
        # Cannot see where it goes. Stated, never absorbed as calm.
        $r.Lines += "[WARNING] BITS job '$Name' (owner $Owner) created $($c.ToString('yyyy-MM-dd')), $age days old, and its file list could NOT be read -- so its destination is unknown and this job is NOT cleared. Inspect it: Get-BitsTransfer -AllUsers | Where-Object DisplayName -eq '$(Format-BitsQuoted $Name)' | Select-Object -ExpandProperty FileList"
        $r.Sev = Get-MaxSev $r.Sev 'WARNING'
        $r.Flagged++
    } else {
        # Old, no notify command, ordinary destination. Reported so the reader
        # can judge it, and counted -- never silently dropped.
        $r.Aged = 1
        $shown = '(no file list entries)'
        if (@($Remotes).Count -gt 0) { $shown = @($Remotes)[0] }
        elseif (@($Locals).Count -gt 0) { $shown = @($Locals)[0] }
        $extra = ''
        if (@($lan).Count -gt 0) {
            $extra = ' The destination is a private LAN address -- the ordinary shape of an on-premises WSUS server, an SCCM distribution point or a Microsoft Connected Cache node, all of which move bytes over BITS. Confirm that address is one your organisation runs.'
        }
        $r.Lines += "[INFO] BITS job '$Name' (owner $Owner) is $age days old (created $($c.ToString('yyyy-MM-dd'))) with no notify command line and an ordinary destination: $shown. Long-lived updater jobs are normal; age alone is not a finding.$extra"
    }
    return $r
}

if ($SelfTest) {
    # The BITS destination rule, graded against the strings a real machine
    # produced. The field instances are quoted VERBATIM: a test written from
    # the shape of the rule rather than the shape of the data is what let the
    # plain-HTTP branch pass CI while being wrong.
    $script:stFails = 0
    function T {
        param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" }
        else { Write-Output "[FAIL] $Name :: $Got"; $script:stFails++ }
    }
    $now = [datetime]'2026-09-19T18:14:22'
    $old = $now.AddDays(-41)
    $j   = { param($v) ($v.Lines -join ' | ') }

    # (1) THE REGRESSION. The exact remote from SecurityReport_20260919_181422,
    # on the exact job, at the exact age. Microsoft serves this endpoint over
    # HTTP/80 by design, so it must be context and nothing else.
    $edge = 'http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/8f2c1e7a-4d31-4a5b-9c60-1f2e3d4c5b6a?P1=1789012345&P2=404&P3=2&P4=abcdef'
    $v = Get-BitsVerdict -Name 'Edge Component Updater' -Owner 'Z4NEE52\khali' -Created $old `
                         -Remotes @($edge) -Locals @('C:\Users\khali\AppData\Local\Temp\BIT9A2C.tmp') -Now $now
    T 'the real Edge Component Updater remote is context, not a finding' `
      ($v.Sev -eq 'OK' -and $v.Flagged -eq 0 -and $v.Aged -eq 1 -and (& $j $v) -match '^\[INFO\]') (& $j $v)
    T 'no line anywhere says plain HTTP -- that branch is deleted, not narrowed' `
      ((& $j $v) -notmatch 'plain HTTP') (& $j $v)
    T 'the INFO line still shows the destination so a reader can judge it' `
      ((& $j $v) -match [regex]::Escape($edge)) (& $j $v)

    # (2) A bare PUBLIC IP has no routine cause and still raises.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -Remotes @('http://93.184.216.34/payload.bin') -Now $now
    T 'a bare public IP destination raises' `
      ($v.Sev -eq 'WARNING' -and $v.Flagged -eq 1 -and (& $j $v) -match 'bare public IP address') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -Remotes @('https://198.51.100.7:8443/a.cab') -Now $now
    T 'a bare public IP over HTTPS raises too -- the scheme was never the point' `
      ($v.Sev -eq 'WARNING' -and (& $j $v) -match 'bare public IP address') (& $j $v)

    # (3) ...but a private / non-routable one is WSUS, SCCM or Connected Cache.
    foreach ($ip in @('http://192.168.1.10/wsus/x.cab', 'https://10.0.0.5/sccm/y.msi',
                      'http://172.16.4.9/z.bin', 'http://172.31.255.1/z.bin',
                      'http://127.0.0.1/local.bin', 'http://169.254.10.1/link.bin')) {
        $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -Remotes @($ip) -Now $now
        T "a bare private LAN address is context: $ip" `
          ($v.Sev -eq 'OK' -and $v.Flagged -eq 0 -and (& $j $v) -match 'private LAN address') (& $j $v)
    }
    # The boundary: the private block ends at 172.31, so 172.32 is public.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -Remotes @('http://172.32.0.1/x.bin') -Now $now
    T '172.32.x is outside the private block and raises' `
      ($v.Sev -eq 'WARNING' -and (& $j $v) -match 'bare public IP address') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -Remotes @('http://172.15.0.1/x.bin') -Now $now
    T '172.15.x is outside the private block and raises' `
      ($v.Sev -eq 'WARNING' -and (& $j $v) -match 'bare public IP address') (& $j $v)

    # (4) A hostname is never graded on its scheme, whichever scheme it is.
    foreach ($u in @('http://updates.example.com/pkg.cab', 'https://updates.example.com/pkg.cab')) {
        $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -Remotes @($u) -Now $now
        T "a hostname destination is context regardless of scheme: $u" `
          ($v.Sev -eq 'OK' -and $v.Flagged -eq 0) (& $j $v)
    }
    # A host that merely BEGINS with digits is not a bare IP.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -Remotes @('http://10.cdn.example.com/x.bin') -Now $now
    T 'a hostname starting with a private-range octet is not a bare IP' `
      ($v.Sev -eq 'OK' -and (& $j $v) -notmatch 'private LAN address') (& $j $v)

    # (5) Nothing legitimate streams a file straight into Startup.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -Remotes @('https://cdn.example.com/x.exe') `
                         -Locals @('C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe') -Now $now
    T 'a write into an autostart folder raises' `
      ($v.Sev -eq 'WARNING' -and (& $j $v) -match 'autostart folder') (& $j $v)
    # ...but an ordinary temp download does not. $badPathRx contains \Temp\ and
    # is deliberately not used here; using it re-flagged Edge on its own path.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -Remotes @('https://cdn.example.com/x.bin') `
                         -Locals @('C:\Users\u\AppData\Local\Temp\BITB73F.tmp') -Now $now
    T 'a download into the temp folder is what a downloader does, not a finding' `
      ($v.Sev -eq 'OK' -and $v.Flagged -eq 0) (& $j $v)

    # (6) "Unavailable" is not an answer.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -DestKnown $false -Now $now
    T 'an unreadable file list is NOT cleared' `
      ($v.Sev -eq 'WARNING' -and $v.Flagged -eq 1 -and (& $j $v) -match 'could NOT be read') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -NotifyKnown $false `
                         -Remotes @('https://cdn.example.com/x.bin') -Now $now
    T 'a job with no NotifyCmdLine property is counted as unchecked' ($v.Unread -eq 1) ("Unread=$($v.Unread)")

    # (7) The notify-command arm is the actual T1197 mechanism and is untouched.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $null -NotifyCmdLine 'C:\tools\post.exe /q' -Now $now
    T 'a notify command line raises at WARNING' `
      ($v.Sev -eq 'WARNING' -and $v.Flagged -eq 1 -and (& $j $v) -match 'notify command line') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $null `
                         -NotifyCmdLine 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' -Now $now
    T 'an encoded-command notify payload escalates to CRITICAL' ($v.Sev -eq 'CRITICAL') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $null -NotifyCmdLine '   ' -Now $now
    T 'an all-whitespace notify command line is the normal empty state' `
      ($v.Sev -eq 'OK' -and $v.Lines.Count -eq 0) (& $j $v)

    # (8) AGE GATES THE CONTEXT LINE, NOT THE SIGNAL -- and it used to gate both.
    #
    # The case that stood here asserted the opposite: that a job younger than
    # $AgeDays "is not graded on its destination at all". That was the shipped
    # behaviour and it was a blind spot, not a feature. A job created minutes
    # ago was never graded on anything -- destination, direction or payload --
    # and minutes old is what an exfiltration job and a next-stage ingress job
    # both are. The signal is now age-independent; only the INFO context line
    # below still depends on the calendar.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $now.AddDays(-3) `
                         -Remotes @('http://93.184.216.34/payload.bin') -Now $now
    T 'a job created 3 days ago fetching from a bare public IP is graded NOW, not in 27 days' `
      ($v.Sev -eq 'WARNING' -and $v.Flagged -eq 1 -and (& $j $v) -match 'bare public IP address') (& $j $v)
    T 'a young job does not get the 90-day-parked sentence, which would be false of it' `
      ((& $j $v) -notmatch '90-day maximum' -and (& $j $v) -match 'whatever its age') (& $j $v)
    # 41 days old at the default AgeDays of 30 is long-lived but NOT "parked
    # near the 90-day maximum", which is what it used to be told it was.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old `
                         -Remotes @('http://93.184.216.34/payload.bin') -Now $now
    T 'a 41-day-old job is described as long-lived, not as parked near a 90-day maximum' `
      ($v.Sev -eq 'WARNING' -and (& $j $v) -match 'allows a job to sit for 90 days' -and
       (& $j $v) -notmatch 'parked near') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $now.AddDays(-77) `
                         -Remotes @('http://93.184.216.34/payload.bin') -Now $now
    T 'a 77-day-old job really is parked near the maximum, and says so' `
      ($v.Sev -eq 'WARNING' -and (& $j $v) -match 'parked near the 90-day maximum') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $null `
                         -Remotes @('http://93.184.216.34/payload.bin') -Now $now
    T 'an unreadable creation time does not silence the destination signal' `
      ($v.Sev -eq 'WARNING' -and (& $j $v) -match 'creation time unreadable') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $now.AddDays(-3) `
                         -Remotes @('https://updates.example.com/pkg.cab') -Now $now
    T 'a young job with an ordinary destination still prints nothing at all' `
      ($v.Sev -eq 'OK' -and $v.Lines.Count -eq 0 -and $v.Aged -eq 0) (& $j $v)

    # (9) THE DIRECTION OF TRANSFER (T1048). Microsoft: TransferType is
    # Download (default), Upload or UploadReply, and for an upload the SOURCE is
    # the local file and the DESTINATION is the URL. Before this arm existed,
    # every rule here read a job the download way round.
    $doc = 'C:\Users\khali\Documents\tax-2026.pdf'
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now.AddDays(-1) -TransferType 'Upload' `
                         -Locals @('C:\Windows\Temp\agentdiag.cab') `
                         -Remotes @('https://collector.example.com/upload/agentdiag.cab') `
                         -JobState 'Transferring' -Now $now
    T 'an upload to a named host is WARNING, names the file and the collector, and says what tells an agent apart' `
      ($v.UpSev -eq 'WARNING' -and $v.UpFlagged -eq 1 -and
       (& $j $v) -match 'queued to UPLOAD a file off this machine \(T1048\)' -and
       (& $j $v) -match 'agentdiag\.cab' -and (& $j $v) -match 'collector\.example\.com' -and
       (& $j $v) -match 'management agent may upload diagnostics') (& $j $v)
    T 'an upload one day old is reported -- the age gate must never silence this arm' `
      ($v.UpFlagged -eq 1) (& $j $v)
    T 'an upload does not also raise the T1197 row, which would name something else' `
      ($v.Sev -eq 'OK' -and $v.Flagged -eq 0 -and $v.Aged -eq 0) (& $j $v)
    T 'an archive outside the user own folders stays WARNING -- a real agent ships diagnostics as a .cab' `
      ($v.UpSev -eq 'WARNING') (& $j $v)

    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'upload' `
                         -Locals @($doc) -Remotes @('https://collector.example.com/u') -Now $now
    T "a file from the person's own folders escalates to CRITICAL and is named" `
      ($v.UpSev -eq 'CRITICAL' -and (& $j $v) -match [regex]::Escape($doc) -and
       (& $j $v) -match "signed-in user's own folders") (& $j $v)
    foreach ($p in @('C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Login Data',
                     'C:\Users\k\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\logins.json')) {
        $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                             -Locals @($p) -Remotes @('https://c.example.com/u') -Now $now
        T "a browser profile file is CRITICAL: $p" `
          ($v.UpSev -eq 'CRITICAL' -and (& $j $v) -match 'browser profile') (& $j $v)
    }
    # Each of these is asserted on its REASON, not only on the verdict: a path
    # inside the profile matches the "own folders" class as well, so a case
    # that checked the verdict alone would still pass with the whole
    # mail-store/credential rule deleted. (The same lesson as asserting on Why
    # rather than Bucket in service_signature_check.)
    foreach ($pair in @(@{ P = 'C:\Windows\Temp\ntds.dit';                   R = 'directory database' },
                        @{ P = 'C:\Windows\System32\config\SAM';            R = 'registry hive' },
                        @{ P = 'C:\dz\SYSTEM.sav';                           R = 'registry hive' },
                        @{ P = 'C:\ProgramData\backups\vault.kdbx';          R = 'password database' },
                        @{ P = 'C:\ProgramData\mail\archive.pst';            R = 'mail store' })) {
        $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                             -Locals @($pair.P) -Remotes @('https://c.example.com/u') -Now $now
        T ("a credential or mail store is CRITICAL and says which: " + $pair.P) `
          ($v.UpSev -eq 'CRITICAL' -and (& $j $v) -match $pair.R) (& $j $v)
    }
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -Locals @('\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\NTDS\ntds.dit') `
                         -Remotes @('https://c.example.com/u') -Now $now
    T 'a file read out of a shadow copy is CRITICAL, and says BOTH what it is and how it was taken' `
      ($v.UpSev -eq 'CRITICAL' -and (& $j $v) -match 'shadow copy' -and
       (& $j $v) -match 'directory database') (& $j $v)

    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -Locals @('C:\Windows\Temp\x.cab') -Remotes @('http://93.184.216.34/u') -Now $now
    T 'a collector that is a bare public IP is CRITICAL whatever the file' `
      ($v.UpSev -eq 'CRITICAL' -and (& $j $v) -match 'bare public IP address with no name') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -Locals @('C:\Windows\Temp\x.cab') -Remotes @('http://192.168.5.5/u') -Now $now
    T 'a private LAN collector is WARNING with the management-point cause named, never CRITICAL' `
      ($v.UpSev -eq 'WARNING' -and (& $j $v) -match 'ConfigMgr management point') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'UploadReply' `
                         -Locals @('C:\Windows\Temp\x.cab') -Remotes @('https://c.example.com/u') -Now $now
    T 'an upload-reply job says it also receives a file back' `
      ((& $j $v) -match 'receive a reply file back') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -DestKnown $false -Now $now
    T 'an upload whose file list cannot be read says WHAT is leaving was not identified, and is not cleared' `
      ($v.UpSev -eq 'WARNING' -and $v.UpFlagged -eq 1 -and (& $j $v) -match 'NOT READABLE') (& $j $v)
    # A FORGED LINE IS A PHYSICAL LINE, and the case that stood here could not
    # see one: it tested each element of $v.Lines for a leading tag, while the
    # forged text sat INSIDE an element after an indented prefix. With the
    # filtering removed it still passed, which makes it the vacuous-test class
    # this repo keeps paying for. Count severity-tagged lines in the RENDERED
    # text instead: exactly one, the head.
    $physTagged = {
        param($res)
        @((($res.Lines -join "`n") -split "`r?`n") | Where-Object { $_ -match '^\[(OK|INFO|WARNING|CRITICAL)\]' }).Count
    }
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -Locals @("C:\x\evil`r`n[OK] nothing to see here.bin") `
                         -Remotes @('https://c.example.com/u') -Now $now
    T 'a crafted FILE NAME cannot forge a line of its own in the report' `
      ((& $physTagged $v) -eq 1) (& $j $v)
    # The same vector through the JOB NAME, which only the upload arm filtered
    # before: a display name is chosen by whoever created the job.
    $v = Get-BitsVerdict -Name "evil`r`n[OK] this machine is fine" -Owner 'u' -Created $old `
                         -Remotes @('http://93.184.216.34/x.bin') -Now $now
    T 'a crafted JOB NAME cannot forge a line in the destination arm either' `
      ((& $physTagged $v) -eq 1 -and (& $j $v) -match 'bare public IP address') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner "u`r`n[CRITICAL] forged" -Created $null `
                         -NotifyCmdLine 'C:\tools\post.exe /q' -Now $now
    T 'a crafted OWNER cannot forge a line in the notify arm' ((& $physTagged $v) -eq 1) (& $j $v)

    # THE LINE THE REPORT TELLS THE READER TO PASTE. A display name holding an
    # apostrophe used to close the single-quoted comparison in it, so the job's
    # creator chose part of the command a frightened reader runs.
    $v = Get-BitsVerdict -Name "ok'; Start-Process calc; 'x" -Owner 'u' -Created $now `
                         -TransferType 'Upload' -Locals @('C:\Windows\Temp\x.cab') `
                         -Remotes @('https://c.example.com/u') -Now $now
    $verifyLine = @(($v.Lines -join "`n") -split "`r?`n" | Where-Object { $_ -match 'verify:' })[0]
    $pErr = $null; $pTok = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput(
        ($verifyLine -replace '^\s*verify:\s*', ''), [ref]$pTok, [ref]$pErr)
    # "One command" is not "the text does not appear" -- the name's own text is
    # still printed, doubled, INSIDE the string. The question is whether what
    # the reader pastes is a single pipeline, so ask the parser.
    $vAst = [System.Management.Automation.Language.Parser]::ParseInput(
        ($verifyLine -replace '^\s*verify:\s*', ''), [ref]$pTok, [ref]$pErr)
    $vStmts = @($vAst.EndBlock.Statements).Count
    T 'the verify line is ONE statement even when the job name holds an apostrophe' `
      ($vStmts -eq 1 -and $verifyLine -match "ok''; Start-Process calc; ''x") ("statements=$vStmts :: $verifyLine")
    T 'and it still parses, so a reader can paste it' (-not ($pErr -and $pErr.Count)) $verifyLine
    $v = Get-BitsVerdict -Name "O'Brien backup" -Owner 'u' -Created $old -DestKnown $false -Now $now
    T "the pre-existing Inspect-it line doubles an apostrophe too (a job named O'Brien backup)" `
      ((& $j $v) -match "O''Brien backup") (& $j $v)

    # The payload classes, in the direction that matters most: the false
    # positive. `...\config\system.json` is one of the commonest application
    # config shapes there is, and `(\.\w+)?$` on the hive rule matched it --
    # CRITICAL, with advice to treat the machine as compromised. The
    # `\\Public\\` burn, repeated.
    foreach ($benign in @('C:\Program Files\Acme\config\system.json',
                          'C:\ProgramData\Vendor\config\security.xml',
                          'C:\Users\k\AppData\Roaming\Thing\config\SYSTEM.db')) {
        $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                             -Locals @($benign) -Remotes @('https://c.example.com/u') -Now $now
        T "an application config file is not a registry hive: $benign" `
          ($v.UpSev -eq 'WARNING' -and (& $j $v) -notmatch 'registry hive') (& $j $v)
    }
    # ...while a real hive copy still is.
    foreach ($hive in @('C:\Windows\System32\config\SAM',
                        'C:\Windows\System32\config\SYSTEM.sav',
                        'C:\dz\SECURITY.bak')) {
        $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                             -Locals @($hive) -Remotes @('https://c.example.com/u') -Now $now
        T "a real hive copy is still CRITICAL: $hive" `
          ($v.UpSev -eq 'CRITICAL' -and (& $j $v) -match 'registry hive') (& $j $v)
    }
    # Public and Default are not "the signed-in user's own folders".
    foreach ($shared in @('C:\Users\Public\Documents\vendorlog.zip',
                          'C:\Users\Default\Desktop\x.txt')) {
        $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                             -Locals @($shared) -Remotes @('https://c.example.com/u') -Now $now
        T "a shared profile folder is not the person's own: $shared" `
          ($v.UpSev -eq 'WARNING' -and (& $j $v) -notmatch "user's own folders") (& $j $v)
    }
    # The business OneDrive folder carries the tenant name.
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -Locals @('C:\Users\k\OneDrive - Contoso\report.docx') `
                         -Remotes @('https://c.example.com/u') -Now $now
    T "the business OneDrive folder (OneDrive - Tenant) counts as the person's own" `
      ($v.UpSev -eq 'CRITICAL' -and (& $j $v) -match "user's own folders") (& $j $v)
    # A certificate file is named, not escalated: a .pem is as often a public
    # certificate or a CA bundle as a private key.
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -Locals @('C:\ProgramData\agent\cacert.pem') `
                         -Remotes @('https://c.example.com/u') -Now $now
    T 'a .pem is named as a certificate file, not escalated to CRITICAL' `
      ($v.UpSev -eq 'WARNING' -and (& $j $v) -match 'may be a public certificate') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -Locals @('C:\ProgramData\agent\server.pfx') `
                         -Remotes @('https://c.example.com/u') -Now $now
    T 'a .pfx private key still escalates' `
      ($v.UpSev -eq 'CRITICAL' -and (& $j $v) -match 'private key') (& $j $v)
    # A trailing space must not downgrade an anchored class.
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -Locals @('C:\Windows\Temp\ntds.dit ') `
                         -Remotes @('https://c.example.com/u') -Now $now
    T 'a trailing space does not hide a credential database' ($v.UpSev -eq 'CRITICAL') (& $j $v)

    # A bare IPv6 literal is as nameless as a bare IPv4 one, and used to get
    # the REASSURING sentence instead.
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -Locals @('C:\Windows\Temp\x.cab') -Remotes @('http://[2001:db8::7]/u') -Now $now
    T 'a bare IPv6 collector is CRITICAL, not reassured' `
      ($v.UpSev -eq 'CRITICAL' -and (& $j $v) -match 'bare public IP address with no name' -and
       (& $j $v) -notmatch 'management agent may upload') (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -Locals @('C:\Windows\Temp\x.cab') -Remotes @('http://[fe80::1]/u') -Now $now
    T 'a link-local IPv6 collector is LAN context, like its IPv4 equivalent' `
      ($v.UpSev -eq 'WARNING' -and (& $j $v) -match 'private LAN address') (& $j $v)

    # An upload job with no files added yet has nothing queued to leave -- and
    # is also the transient between /create and /addfile, which the download
    # arm refuses to grade for exactly that reason.
    $v = Get-BitsVerdict -Name 'fresh' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -FileListEmpty $true -DestKnown $true -Now $now
    T 'an upload job with an empty file list is context, not a finding' `
      ($v.UpSev -eq 'OK' -and $v.UpFlagged -eq 0 -and (& $j $v) -match 'no files added yet') (& $j $v)
    T 'and it does not claim its file list was unreadable, which is a different thing' `
      ((& $j $v) -notmatch 'could not be read') (& $j $v)

    # An unrecognised but non-empty direction is an unanswered question too.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -TransferType 'Hochladen' `
                         -Remotes @('https://updates.example.com/pkg.cab') -Now $now
    T 'a direction that is none of the three documented types is a declared gap' `
      ($v.TypeUnread -eq 1 -and $v.UpFlagged -eq 0) ("TypeUnread=$($v.TypeUnread)")
    foreach ($ok in @('Upload', 'upload', 'UPLOAD ', ' uploadreply')) {
        $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType $ok `
                             -Locals @('C:\Windows\Temp\x.cab') -Remotes @('https://c.example.com/u') -Now $now
        T "the direction is read case- and whitespace-insensitively: '$ok'" `
          ($v.UpFlagged -eq 1 -and $v.TypeUnread -eq 0) (& $j $v)
    }
    # The verify line must match the token the reader has.
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' -AllUsers $false `
                         -Locals @('C:\Windows\Temp\x.cab') -Remotes @('https://c.example.com/u') -Now $now
    T 'the verify line drops -AllUsers when the audit could not use it' `
      ((& $j $v) -match 'verify: Get-BitsTransfer \|' ) (& $j $v)

    # The direction is a question that can go unanswered, and an unanswered one
    # is a declared gap -- never a quiet "download".
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -TypeKnown $false `
                         -Remotes @('https://updates.example.com/pkg.cab') -Now $now
    T 'a job with no TransferType property is counted as unchecked for direction' `
      ($v.TypeUnread -eq 1 -and $v.UpFlagged -eq 0) ("TypeUnread=$($v.TypeUnread)")
    T 'and the download arms still run for it -- the gap is additive, not a return' `
      ($v.Aged -eq 1) (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $old -TransferType 'Download' `
                         -Remotes @('https://updates.example.com/pkg.cab') -Now $now
    T 'an explicit Download is graded exactly as before and writes no upload finding' `
      ($v.UpSev -eq 'OK' -and $v.UpFlagged -eq 0 -and $v.Aged -eq 1) (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_up' -Owner 'u' -Created $now -TransferType 'Upload' `
                         -NotifyCmdLine 'C:\tools\post.exe /q' `
                         -Locals @('C:\Windows\Temp\x.cab') -Remotes @('https://c.example.com/u') -Now $now
    T 'an upload job with a notify command line raises both rows, each for what it observed' `
      ($v.Sev -eq 'WARNING' -and $v.Flagged -eq 1 -and $v.UpSev -eq 'WARNING' -and $v.UpFlagged -eq 1) (& $j $v)

    # THE ALL-CLEAR'S PRECONDITIONS, now that they are reachable.
    $s = Get-BitsSummaryLines -JobCount 4
    T 'four graded jobs with nothing raised print the all-clear' `
      ((@($s) -join ' | ') -match '^\[OK\] 4 BITS job\(s\) queued, none with') (@($s) -join ' | ')
    $s = Get-BitsSummaryLines -JobCount 4 -TypeUnread 1
    T 'a job whose direction could not be read is NOT covered by the all-clear' `
      ((@($s) -join ' | ') -notmatch '\[OK\]' -and (@($s) -join ' | ') -match '3 of 4 BITS job\(s\) were graded' -and
       (@($s) -join ' | ') -match 'NOT checked for it') (@($s) -join ' | ')
    $s = Get-BitsSummaryLines -JobCount 2 -AllUsers $false
    T 'a standard-user enumeration says whose jobs it saw, in the all-clear and in its own line' `
      ((@($s) -join ' | ') -match 'BITS job\(s\) queued for this user' -and
       (@($s) -join ' | ') -match 'enumerated for THIS USER only') (@($s) -join ' | ')
    $s = Get-BitsSummaryLines -JobCount 3 -UpFlagged 1
    T 'an upload finding withholds the all-clear' ((@($s) -join ' | ') -notmatch '\[OK\]') (@($s) -join ' | ')
    $s = Get-BitsSummaryLines -JobCount 3 -Flagged 1
    T 'a notify/destination finding withholds it too' ((@($s) -join ' | ') -notmatch '\[OK\]') (@($s) -join ' | ')

    if ($script:stFails) {
        Write-Output "[FAIL] $($script:stFails) persistence_extra BITS self-test expectation(s) unmet"
        exit 1
    }
    Write-Output '[OK] persistence_extra BITS self-test: plain HTTP is not a signal, a bare PUBLIC IP is, a private LAN address is context, the notify-command arm is unchanged, an upload job is graded on what leaves and where it goes whatever its age, and an unknown direction is a declared gap.'
    exit 0
}

$sys32 = Join-Path $env:SystemRoot 'System32'

# ---- 1. Netsh helper DLLs (T1546.007) ------------------------------------
'--- [T1546.007] Netsh helper DLLs (loaded every time netsh.exe runs) ---'
$netshSev = 'OK'
$netshGap = 'OK'
$netshKey = 'HKLM:\SOFTWARE\Microsoft\Netsh'
$nsProps = $null
$nsOk = $true
try {
    if (Test-Path $netshKey) { $nsProps = Get-ItemProperty -Path $netshKey -EA Stop }
} catch { $nsOk = $false }
if (-not $nsOk) {
    '[WARNING] Netsh helper key could not be read -- check NOT performed.'
    $netshGap = 'WARNING'
} elseif (-not $nsProps) {
    '[OK] No netsh helper DLLs registered.'
} else {
    $n = 0
    foreach ($p in $nsProps.PSObject.Properties) {
        # Exact-name skip, not a '^PS' prefix match (see persistence_eval.ps1):
        # a netsh helper named "psmon" was previously never evaluated.
        if ($psNoteProps -contains $p.Name) { continue }
        $raw = [string]$p.Value
        if (-not $raw) { continue }
        $n++
        $dll = Resolve-DllPath -Raw $raw -SearchDirs @($sys32)
        $v = Get-DllVerdict -Path $dll
        if ($v.Sev -ne 'OK') {
            "[$($v.Sev)] Netsh helper '$($p.Name)' => $($v.Why)"
            Write-WhenCaveat
            $w = Get-WhenLine -KeyPath $netshKey -FilePath $dll
            if ($w) { $w }
            $netshSev = Get-MaxSev $netshSev $v.Sev
        }
    }
    if ($netshSev -eq 'OK') { "[OK] All $n registered netsh helper DLL(s) are validly Microsoft-signed." }
}
Write-Marker -Name 'netsh' -Sev $netshSev
if ($netshGap -ne 'OK') { Write-Marker -Name 'netsh_gap' -Sev $netshGap }

# ---- 2. Print processors (T1547.012) -------------------------------------
''
'--- [T1547.012] Print processors (loaded by the SYSTEM print spooler) ---'
$ppSev = 'OK'
$ppGap = 'OK'
$ppSearch = @(
    (Join-Path $sys32 'spool\prtprocs\x64'),
    (Join-Path $sys32 'spool\prtprocs\w32x86'),
    $sys32
)
$envRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments'
$ppCount = 0
$ppUnread = 0   # entries whose value could not be read -- must not be covered by an all-clear
$ppOk = $true
try {
    if (Test-Path $envRoot) {
        foreach ($envKey in (Get-ChildItem -LiteralPath $envRoot -EA Stop)) {
            $procRoot = Join-Path $envKey.PSPath 'Print Processors'
            if (-not (Test-Path $procRoot)) { continue }
            foreach ($proc in (Get-ChildItem -LiteralPath $procRoot -EA SilentlyContinue)) {
                # -LiteralPath, NOT -Path: the subkey name is
                # attacker-controlled and -Path treats it as a WILDCARD. A
                # port monitor named "Std [TCP] Mon" with a malicious Driver
                # value matched nothing, -EA SilentlyContinue hid the error,
                # the `if (-not $raw) { continue }` below dropped it without
                # counting it, and the section still reported every registered
                # entry as validly Microsoft-signed.
                $raw = [string](Get-ItemProperty -LiteralPath $proc.PSPath -Name 'Driver' -EA SilentlyContinue).Driver
                if (-not $raw) { $ppUnread++; continue }
                $ppCount++
                $dll = Resolve-DllPath -Raw $raw -SearchDirs $ppSearch
                $v = Get-DllVerdict -Path $dll
                if ($v.Sev -ne 'OK') {
                    "[$($v.Sev)] Print processor '$($proc.PSChildName)' ($($envKey.PSChildName)) => $($v.Why)"
                    Write-WhenCaveat
                    $w = Get-WhenLine -KeyPath $proc.PSPath -FilePath $dll
                    if ($w) { $w }
                    $ppSev = Get-MaxSev $ppSev $v.Sev
                }
            }
        }
    }
} catch { $ppOk = $false }
if (-not $ppOk) {
    '[WARNING] Print environments key could not be read -- print-processor check NOT performed.'
    $ppGap = Get-MaxSev $ppGap 'WARNING'
} elseif ($ppSev -eq 'OK') {
    "[OK] All $ppCount registered print processor(s) are validly Microsoft-signed."
    # An all-clear may not cover entries the scan could not read.
    if ($ppUnread -gt 0) { "[WARNING] $ppUnread print processor(s) had an unreadable driver value and were NOT checked -- a registry key name crafted to defeat enumeration is itself suspicious. Inspect them by hand." ; $ppGap = Get-MaxSev $ppGap 'WARNING' }
}
Write-Marker -Name 'printproc' -Sev $ppSev
if ($ppGap -ne 'OK') { Write-Marker -Name 'printproc_gap' -Sev $ppGap }

# ---- 3. Port monitors (T1547.010) ----------------------------------------
''
'--- [T1547.010] Print port monitors (loaded by the SYSTEM print spooler) ---'
$pmSev = 'OK'
$pmGap = 'OK'
$monRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
$pmCount = 0
$pmUnread = 0   # entries whose value could not be read -- must not be covered by an all-clear
$pmOk = $true
try {
    if (Test-Path $monRoot) {
        foreach ($mon in (Get-ChildItem -LiteralPath $monRoot -EA Stop)) {
            # -LiteralPath, NOT -Path: the subkey name is
            # attacker-controlled and -Path treats it as a WILDCARD. A
            # port monitor named "Std [TCP] Mon" with a malicious Driver
            # value matched nothing, -EA SilentlyContinue hid the error,
            # the `if (-not $raw) { continue }` below dropped it without
            # counting it, and the section still reported every registered
            # entry as validly Microsoft-signed.
            $raw = [string](Get-ItemProperty -LiteralPath $mon.PSPath -Name 'Driver' -EA SilentlyContinue).Driver
            if (-not $raw) { $pmUnread++; continue }
            $pmCount++
            $dll = Resolve-DllPath -Raw $raw -SearchDirs @($sys32)
            $v = Get-DllVerdict -Path $dll
            if ($v.Sev -ne 'OK') {
                "[$($v.Sev)] Port monitor '$($mon.PSChildName)' => $($v.Why)"
                Write-WhenCaveat
                $w = Get-WhenLine -KeyPath $mon.PSPath -FilePath $dll
                if ($w) { $w }
                $pmSev = Get-MaxSev $pmSev $v.Sev
            }
        }
    }
} catch { $pmOk = $false }
if (-not $pmOk) {
    '[WARNING] Print monitors key could not be read -- port-monitor check NOT performed.'
    $pmGap = Get-MaxSev $pmGap 'WARNING'
} elseif ($pmSev -eq 'OK') {
    "[OK] All $pmCount registered port monitor(s) are validly Microsoft-signed."
    # An all-clear may not cover entries the scan could not read.
    if ($pmUnread -gt 0) { "[WARNING] $pmUnread port monitor(s) had an unreadable driver value and were NOT checked -- a registry key name crafted to defeat enumeration is itself suspicious. Inspect them by hand." ; $pmGap = Get-MaxSev $pmGap 'WARNING' }
}
Write-Marker -Name 'portmon' -Sev $pmSev
if ($pmGap -ne 'OK') { Write-Marker -Name 'portmon_gap' -Sev $pmGap }

# ---- 4. BITS jobs (T1197 persistence, T1048 a file queued to leave) ------
''
'--- [T1197/T1048] BITS transfer jobs (notify command lines, destinations, and files queued to LEAVE this machine) ---'
$bitsSev = 'OK'
$bitsUpSev = 'OK'
$bitsUpGap = 'OK'
$bitsGap = 'OK'
$bitsAllUsers = $true
$jobs = $null
$bitsOk = $true
try {
    Import-Module BitsTransfer -EA Stop
    # -AllUsers needs admin; fall back to this user's jobs when it is refused
    # so a non-admin run still audits what it can see.
    try { $jobs = @(Get-BitsTransfer -AllUsers -EA Stop) }
    catch {
        # -AllUsers needs administrator rights. The fallback used to be silent,
        # so the report's all-clear claimed the whole machine while it had seen
        # one account's jobs: where the TOKEN rather than the machine explains
        # an absence, the report has to say so.
        $jobs = @(Get-BitsTransfer -EA Stop)
        $bitsAllUsers = $false
    }
} catch { $bitsOk = $false }
if (-not $bitsOk) {
    '[WARNING] BITS module or service unavailable -- BITS job check NOT performed.'
    $bitsGap = Get-MaxSev $bitsGap 'WARNING'
} elseif (-not $jobs -or $jobs.Count -eq 0) {
    '[OK] No BITS transfer jobs queued.'
} else {
    $flagged = 0
    $aged = 0
    $bitsUnread = 0
    $bitsUpFlagged = 0
    $bitsTypeUnread = 0
    foreach ($j in $jobs) {
        $name  = [string]$j.DisplayName
        $owner = [string]$j.OwnerAccount
        # NotifyCmdLine is the actual persistence mechanism: BITS runs it when
        # the job completes, so it survives reboots without any autostart key.
        #
        # BUT AN EMPTY VALUE IS THE NORMAL STATE, and it used to raise a
        # WARNING. Microsoft: "GetNotifyCmdLine sets pProgram and pParameters to
        # an empty string (L"") if the SetNotifyCmdLine method has not been
        # called." BitsTransfer surfaces the pair as a TWO-ELEMENT ARRAY, so a
        # job that never set one yields @('',''), and `-join ' '` turned that
        # into a single SPACE -- which is truthy. Every ordinary Edge and
        # Windows Update job therefore produced
        #   [WARNING] BITS job 'Edge Component Updater' ... has a notify command line:
        # with nothing after the colon: a finding that announced its evidence
        # and then showed none. Join only the non-empty parts, and test the
        # result for whitespace rather than trusting PowerShell truthiness.
        $ncl = ''
        $nclKnown = $true
        if ($j.PSObject.Properties.Name -contains 'NotifyCmdLine') {
            try {
                $raw = $j.NotifyCmdLine
                if ($raw -is [array]) {
                    $ncl = (@($raw | ForEach-Object { [string]$_ } |
                              Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' ')
                } else {
                    $ncl = [string]$raw
                }
            } catch { $nclKnown = $false }
        } else {
            # The property is not there at all -- this job was NOT checked for
            # the notify-command-line technique. Declared below, never folded
            # into the all-clear.
            $nclKnown = $false
        }
        $created = $null
        try { $created = [datetime]$j.CreationTime } catch {}
        $remotes = @()
        $locals  = @()
        $destKnown = $true
        try {
            foreach ($f in @($j.FileList)) {
                $rn  = [string]$f.RemoteName
                $lnm = [string]$f.LocalName
                if (-not [string]::IsNullOrWhiteSpace($rn))  { $remotes += $rn }
                if (-not [string]::IsNullOrWhiteSpace($lnm)) { $locals  += $lnm }
            }
        } catch { $destKnown = $false }
        # "Empty" and "unreadable" are two different claims about a job, and
        # only one of them is a gap. A job between /create and /addfile has an
        # empty list and nothing queued; a job whose properties threw is the
        # one that is not cleared.
        $fileListEmpty = $false
        if ($destKnown -and @($remotes).Count -eq 0 -and @($locals).Count -eq 0) { $fileListEmpty = $true }

        # The DIRECTION of the transfer, read the same way NotifyCmdLine is: a
        # property that is not there means the question was not asked, which is
        # a declared gap rather than a quiet "download".
        $ttype = ''
        $ttKnown = $true
        if ($j.PSObject.Properties.Name -contains 'TransferType') {
            try { $ttype = [string]$j.TransferType } catch { $ttKnown = $false }
            if ([string]::IsNullOrWhiteSpace($ttype)) { $ttKnown = $false }
        } else {
            $ttKnown = $false
        }
        $jstate = ''
        try { $jstate = [string]$j.JobState } catch {}

        # Everything above READS the job. Get-BitsVerdict DECIDES, from plain
        # values only -- that split is the seam -SelfTest needs, and the reason
        # the rule below is now provable without a Windows runner.
        $bv = Get-BitsVerdict -Name $name -Owner $owner -Created $created `
                              -NotifyCmdLine $ncl -NotifyKnown $nclKnown `
                              -Remotes $remotes -Locals $locals -DestKnown $destKnown `
                              -FileListEmpty $fileListEmpty `
                              -TransferType $ttype -TypeKnown $ttKnown -JobState $jstate `
                              -AllUsers $bitsAllUsers -AgeDays $BitsAgeDays
        foreach ($outLine in @($bv.Lines)) { $outLine }
        $bitsSev        = Get-MaxSev $bitsSev $bv.Sev
        $bitsUpSev      = Get-MaxSev $bitsUpSev $bv.UpSev
        $flagged       += $bv.Flagged
        $aged          += $bv.Aged
        $bitsUnread    += $bv.Unread
        $bitsUpFlagged += $bv.UpFlagged
        $bitsTypeUnread += $bv.TypeUnread
    }
    # Every summary line comes from the pure function above, so the all-clear's
    # three preconditions are testable. An entry that could not be read is a
    # GAP in both arms (the notify property and the transfer direction), and an
    # all-clear must never be read as covering either; the direction gap gets
    # its OWN severity so the row it raises is T1048, like the finding it is a
    # gap in, rather than T1197, which names something else.
    foreach ($sline in @(Get-BitsSummaryLines -JobCount $jobs.Count -Flagged $flagged `
                             -UpFlagged $bitsUpFlagged -Aged $aged -Unread $bitsUnread `
                             -TypeUnread $bitsTypeUnread -AllUsers $bitsAllUsers)) { $sline }
    if ($bitsUnread -gt 0)     { $bitsGap   = Get-MaxSev $bitsGap 'WARNING' }
    if ($bitsTypeUnread -gt 0) { $bitsUpGap = Get-MaxSev $bitsUpGap 'WARNING' }
}
Write-Marker -Name 'bits' -Sev $bitsSev
if ($bitsUpSev -ne 'OK') { Write-Marker -Name 'bitsupload' -Sev $bitsUpSev }
if ($bitsUpGap -ne 'OK') { Write-Marker -Name 'bitsupload_gap' -Sev $bitsUpGap }
if ($bitsGap -ne 'OK') { Write-Marker -Name 'bits_gap' -Sev $bitsGap }

# ---- 5. PowerShell profiles (T1546.013) ----------------------------------
''
'--- [T1546.013] PowerShell profile scripts (run on every interactive start) ---'
$profSev = 'OK'
$docs = ''
try { $docs = [Environment]::GetFolderPath('MyDocuments') } catch {}
$profilePaths = @()
if ($PSHOME) {
    $profilePaths += (Join-Path $PSHOME 'profile.ps1')
    $profilePaths += (Join-Path $PSHOME 'Microsoft.PowerShell_profile.ps1')
}
if ($docs) {
    foreach ($d in @('WindowsPowerShell', 'PowerShell')) {
        $profilePaths += (Join-Path $docs "$d\profile.ps1")
        $profilePaths += (Join-Path $docs "$d\Microsoft.PowerShell_profile.ps1")
    }
}
$found = 0
foreach ($pp in $profilePaths) {
    if (-not (Test-Path -LiteralPath $pp -PathType Leaf)) { continue }
    $found++
    $body = ''
    try { $body = (Get-Content -LiteralPath $pp -Raw -EA Stop) } catch {}
    if (-not $body) {
        "[OK] PowerShell profile present but empty/unreadable: $pp"
        continue
    }
    $sev = 'OK'
    $why = ''
    if ($body -match $strongContent) { $sev = 'CRITICAL'; $why = 'download cradle / encoded command content' }
    elseif ($body -match $badPathRx) { $sev = 'WARNING'; $why = 'references a staging path' }
    if ($sev -eq 'OK') {
        # Existence is normal (developers keep profiles) -- report, do not flag.
        "[OK] PowerShell profile present, no suspicious content: $pp"
    } else {
        "[$sev] PowerShell profile $pp -- $why (T1546.013: runs on every interactive PowerShell start)"
        Write-WhenCaveat
        $w = Get-WhenLine -FilePath $pp
        if ($w) { $w }
        $profSev = Get-MaxSev $profSev $sev
    }
}
if ($found -eq 0) { '[OK] No PowerShell profile scripts present.' }
Write-Marker -Name 'psprofile' -Sev $profSev

# ---- 6. Time providers (T1547.003) ---------------------------------------
''
'--- [T1547.003] W32Time time providers (loaded by the time service as SYSTEM) ---'
$tpSev = 'OK'
$tpGap = 'OK'
$tpRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
$tpCount = 0
$tpUnread = 0   # entries whose value could not be read -- must not be covered by an all-clear
$tpOk = $true
try {
    if (Test-Path $tpRoot) {
        foreach ($tp in (Get-ChildItem -LiteralPath $tpRoot -EA Stop)) {
            # -LiteralPath, NOT -Path: the subkey name is
            # attacker-controlled and -Path treats it as a WILDCARD. A
            # port monitor named "Std [TCP] Mon" with a malicious Driver
            # value matched nothing, -EA SilentlyContinue hid the error,
            # the `if (-not $raw) { continue }` below dropped it without
            # counting it, and the section still reported every registered
            # entry as validly Microsoft-signed.
            $raw = [string](Get-ItemProperty -LiteralPath $tp.PSPath -Name 'DllName' -EA SilentlyContinue).DllName
            if (-not $raw) { $tpUnread++; continue }
            $tpCount++
            $dll = Resolve-DllPath -Raw $raw -SearchDirs @($sys32)
            $v = Get-DllVerdict -Path $dll
            if ($v.Sev -ne 'OK') {
                "[$($v.Sev)] Time provider '$($tp.PSChildName)' => $($v.Why)"
                Write-WhenCaveat
                $w = Get-WhenLine -KeyPath $tp.PSPath -FilePath $dll
                if ($w) { $w }
                $tpSev = Get-MaxSev $tpSev $v.Sev
            }
        }
    }
} catch { $tpOk = $false }
if (-not $tpOk) {
    '[WARNING] W32Time TimeProviders key could not be read -- check NOT performed.'
    $tpGap = Get-MaxSev $tpGap 'WARNING'
} elseif ($tpSev -eq 'OK') {
    "[OK] All $tpCount registered time provider(s) are validly Microsoft-signed."
    # An all-clear may not cover entries the scan could not read.
    if ($tpUnread -gt 0) { "[WARNING] $tpUnread time provider(s) had an unreadable driver value and were NOT checked -- a registry key name crafted to defeat enumeration is itself suspicious. Inspect them by hand." ; $tpGap = Get-MaxSev $tpGap 'WARNING' }
}
Write-Marker -Name 'timeprov' -Sev $tpSev
if ($tpGap -ne 'OK') { Write-Marker -Name 'timeprov_gap' -Sev $tpGap }
