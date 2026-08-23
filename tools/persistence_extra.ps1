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
    [int]$BitsAgeDays  = 30
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
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -EA SilentlyContinue
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
    foreach ($j in $jobs) {
        $name  = [string]$j.DisplayName
        $owner = [string]$j.OwnerAccount
        # NotifyCmdLine is the actual persistence mechanism: BITS runs it when
        # the job completes, so it survives reboots without any autostart key.
        $ncl = ''
        if ($j.PSObject.Properties.Name -contains 'NotifyCmdLine') {
            $raw = $j.NotifyCmdLine
            if ($raw -is [array]) { $ncl = ($raw -join ' ') } else { $ncl = [string]$raw }
        }
        if ($ncl) {
            $sev = 'WARNING'
            if ($ncl -match $strongContent -or $ncl -match $badPathRx) { $sev = 'CRITICAL' }
            "[$sev] BITS job '$name' (owner $owner) has a notify command line: $ncl"
            $bitsSev = Get-MaxSev $bitsSev $sev
            $flagged++
        }
        $created = $null
        try { $created = [datetime]$j.CreationTime } catch {}
        if ($created -and $created -lt (Get-Date).AddDays(-$BitsAgeDays)) {
            "[WARNING] BITS job '$name' (owner $owner) created $($created.ToString('yyyy-MM-dd')) -- older than $BitsAgeDays days; malware parks jobs near the 90-day max lifetime."
            $bitsSev = Get-MaxSev $bitsSev 'WARNING'
            $flagged++
        }
    }
    if ($flagged -eq 0) { "[OK] $($jobs.Count) BITS job(s) queued, none with a notify command line or older than $BitsAgeDays days." }
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
