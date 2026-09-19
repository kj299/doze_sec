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
#                                     completion survives reboots and is owned
#                                     by the service, not a startup key.
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
#     job lifetime is 90 days and malware parks jobs there.
#
# MARKERS: writes the severity word (CRITICAL/WARNING) to
# $env:TEMP\dz_netsh.txt, dz_printproc.txt, dz_portmon.txt, dz_bits.txt,
# dz_psprofile.txt, dz_timeprov.txt. The caller reads each and raises via
# :dz_finding. No marker is written when clean.
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
$badPathRx = '\\Temp\\|\\Downloads\\|\\Public\\|\\ProgramData\\update'
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

# A bare IPv4 literal as the destination host.
$script:BareIpRx = '^\s*https?://(\d{1,3}\.){3}\d{1,3}([:/]|$)'

# ...of which the private and non-routable ranges are NOT a signal. An
# on-premises WSUS server, an SCCM distribution point and a Microsoft
# Connected Cache node are all routinely reached by bare LAN address, and
# BITS is the transport all three use. A bare PUBLIC address has no such
# routine cause and still raises. 172.32.x is deliberately outside this --
# the private block ends at 172.31.
$script:PrivateIpRx = '^\s*https?://(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'

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
        [int]$AgeDays = 30,
        [datetime]$Now = (Get-Date)
    )
    $r = @{ Lines = @(); Sev = 'OK'; Flagged = 0; Aged = 0; Unread = 0 }
    if (-not $NotifyKnown) { $r.Unread = 1 }

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
    if ($null -eq $Created) { return $r }
    [datetime]$c = $Created
    if ($c -ge $Now.AddDays(-$AgeDays)) { return $r }
    $age = [int]($Now - $c).TotalDays

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
    $why = @()
    $lan = @()
    foreach ($rn in @($Remotes)) {
        if ($rn -notmatch $script:BareIpRx) { continue }
        if ($rn -match $script:PrivateIpRx) { $lan += $rn; continue }
        $why += "fetches from a bare public IP address ($rn)"
    }
    # NOT $badPathRx here, though every other arm in this file uses it. It
    # contains \Temp\, and a BITS job writing into the temp folder is what a
    # downloader DOES -- Edge's own updater included. An autostart folder is
    # different: nothing legitimate streams a file straight into Startup.
    foreach ($l in @($Locals)) {
        if ($l -match '(?i)\\Start Menu\\Programs\\Startup\\') { $why += "writes directly into an autostart folder ($l)" }
    }

    if (-not $DestKnown) {
        # Cannot see where it goes. Stated, never absorbed as calm.
        $r.Lines += "[WARNING] BITS job '$Name' (owner $Owner) created $($c.ToString('yyyy-MM-dd')), $age days old, and its file list could NOT be read -- so its destination is unknown and this job is NOT cleared. Inspect it: Get-BitsTransfer -AllUsers | Where-Object DisplayName -eq '$Name' | Select-Object -ExpandProperty FileList"
        $r.Sev = Get-MaxSev $r.Sev 'WARNING'
        $r.Flagged++
    } elseif (@($why).Count -gt 0) {
        $r.Lines += "[WARNING] BITS job '$Name' (owner $Owner) created $($c.ToString('yyyy-MM-dd')), $age days old, and it $([string]::Join('; ', $why)). A job parked near the 90-day maximum that also moves bytes somewhere questionable is the T1197 shape."
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

    # (8) Age is the gate on the destination arm, and nothing else.
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $now.AddDays(-3) `
                         -Remotes @('http://93.184.216.34/payload.bin') -Now $now
    T 'a young job is not graded on its destination at all' `
      ($v.Sev -eq 'OK' -and $v.Lines.Count -eq 0 -and $v.Aged -eq 0) (& $j $v)
    $v = Get-BitsVerdict -Name 'dz_t' -Owner 'u' -Created $now.AddDays(-3) `
                         -Remotes @('http://93.184.216.34/payload.bin') -AgeDays 0 -Now $now
    T '-AgeDays 0 brings the same job into scope, so both directions are reachable' `
      ($v.Sev -eq 'WARNING' -and (& $j $v) -match 'bare public IP address') (& $j $v)

    if ($script:stFails) {
        Write-Output "[FAIL] $($script:stFails) persistence_extra BITS self-test expectation(s) unmet"
        exit 1
    }
    Write-Output '[OK] persistence_extra BITS self-test: plain HTTP is not a signal, a bare PUBLIC IP is, a private LAN address is context, and the notify-command arm is unchanged.'
    exit 0
}

$sys32 = Join-Path $env:SystemRoot 'System32'

# ---- 1. Netsh helper DLLs (T1546.007) ------------------------------------
'--- [T1546.007] Netsh helper DLLs (loaded every time netsh.exe runs) ---'
$netshSev = 'OK'
$netshKey = 'HKLM:\SOFTWARE\Microsoft\Netsh'
$nsProps = $null
$nsOk = $true
try {
    if (Test-Path $netshKey) { $nsProps = Get-ItemProperty -Path $netshKey -EA Stop }
} catch { $nsOk = $false }
if (-not $nsOk) {
    '[SKIPPED] Netsh helper key could not be read -- check NOT performed.'
    $netshSev = 'WARNING'
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

# ---- 2. Print processors (T1547.012) -------------------------------------
''
'--- [T1547.012] Print processors (loaded by the SYSTEM print spooler) ---'
$ppSev = 'OK'
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
    '[SKIPPED] Print environments key could not be read -- print-processor check NOT performed.'
    $ppSev = Get-MaxSev $ppSev 'WARNING'
} elseif ($ppSev -eq 'OK') {
    "[OK] All $ppCount registered print processor(s) are validly Microsoft-signed."
    # An all-clear may not cover entries the scan could not read.
    if ($ppUnread -gt 0) { "[WARNING] $ppUnread print processor(s) had an unreadable driver value and were NOT checked -- a registry key name crafted to defeat enumeration is itself suspicious. Inspect them by hand." ; $ppSev = Get-MaxSev $ppSev 'WARNING' }
}
Write-Marker -Name 'printproc' -Sev $ppSev

# ---- 3. Port monitors (T1547.010) ----------------------------------------
''
'--- [T1547.010] Print port monitors (loaded by the SYSTEM print spooler) ---'
$pmSev = 'OK'
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
    '[SKIPPED] Print monitors key could not be read -- port-monitor check NOT performed.'
    $pmSev = Get-MaxSev $pmSev 'WARNING'
} elseif ($pmSev -eq 'OK') {
    "[OK] All $pmCount registered port monitor(s) are validly Microsoft-signed."
    # An all-clear may not cover entries the scan could not read.
    if ($pmUnread -gt 0) { "[WARNING] $pmUnread port monitor(s) had an unreadable driver value and were NOT checked -- a registry key name crafted to defeat enumeration is itself suspicious. Inspect them by hand." ; $pmSev = Get-MaxSev $pmSev 'WARNING' }
}
Write-Marker -Name 'portmon' -Sev $pmSev

# ---- 4. BITS jobs (T1197) ------------------------------------------------
''
'--- [T1197] BITS transfer jobs (notify command lines and long-lived jobs) ---'
$bitsSev = 'OK'
$jobs = $null
$bitsOk = $true
try {
    Import-Module BitsTransfer -EA Stop
    # -AllUsers needs admin; fall back to this user's jobs when it is refused
    # so a non-admin run still audits what it can see.
    try { $jobs = @(Get-BitsTransfer -AllUsers -EA Stop) }
    catch { $jobs = @(Get-BitsTransfer -EA Stop) }
} catch { $bitsOk = $false }
if (-not $bitsOk) {
    '[SKIPPED] BITS module or service unavailable -- BITS job check NOT performed.'
    $bitsSev = Get-MaxSev $bitsSev 'WARNING'
} elseif (-not $jobs -or $jobs.Count -eq 0) {
    '[OK] No BITS transfer jobs queued.'
} else {
    $flagged = 0
    $aged = 0
    $bitsUnread = 0
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
        if (@($remotes).Count -eq 0 -and @($locals).Count -eq 0) { $destKnown = $false }

        # Everything above READS the job. Get-BitsVerdict DECIDES, from plain
        # values only -- that split is the seam -SelfTest needs, and the reason
        # the rule below is now provable without a Windows runner.
        $bv = Get-BitsVerdict -Name $name -Owner $owner -Created $created `
                              -NotifyCmdLine $ncl -NotifyKnown $nclKnown `
                              -Remotes $remotes -Locals $locals -DestKnown $destKnown `
                              -AgeDays $BitsAgeDays
        foreach ($outLine in @($bv.Lines)) { $outLine }
        $bitsSev     = Get-MaxSev $bitsSev $bv.Sev
        $flagged    += $bv.Flagged
        $aged       += $bv.Aged
        $bitsUnread += $bv.Unread
    }
    if ($flagged -eq 0) { "[OK] $($jobs.Count) BITS job(s) queued, none with a notify command line, an unreadable file list, or a questionable destination." }
    if ($aged -gt 0) { "[INFO] $aged long-lived BITS job(s) listed above are reported as context only -- see the destination on each line." }
    if ($bitsUnread -gt 0) {
        # Same contract as the port-monitor / print-processor / time-provider
        # arms above: an entry that could not be read is a GAP, and an all-clear
        # must never be read as covering it.
        "[WARNING] $bitsUnread BITS job(s) did not expose a NotifyCmdLine property and were NOT checked for command-line persistence."
        $bitsSev = Get-MaxSev $bitsSev 'WARNING'
    }
}
Write-Marker -Name 'bits' -Sev $bitsSev

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
    '[SKIPPED] W32Time TimeProviders key could not be read -- check NOT performed.'
    $tpSev = Get-MaxSev $tpSev 'WARNING'
} elseif ($tpSev -eq 'OK') {
    "[OK] All $tpCount registered time provider(s) are validly Microsoft-signed."
    # An all-clear may not cover entries the scan could not read.
    if ($tpUnread -gt 0) { "[WARNING] $tpUnread time provider(s) had an unreadable driver value and were NOT checked -- a registry key name crafted to defeat enumeration is itself suspicious. Inspect them by hand." ; $tpSev = Get-MaxSev $tpSev 'WARNING' }
}
Write-Marker -Name 'timeprov' -Sev $tpSev
