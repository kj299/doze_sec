# logon_persistence.ps1 -- detect registry persistence/credential-capture on the
# Windows logon and UNLOCK path. Invoked from Section 5 of doze_sec*.bat.
#
# WHY: LogonUI renders both the logon AND unlock screens, and several registry
# vectors fire there -- so malware that triggers "when you unlock" lives here.
# doze_sec already covers Winlogon Userinit/Shell, AppInit, IFEO. This adds the
# three highest-value gaps (Tier 1):
#
#   1. Winlogon Notify packages (T1547.004)
#        HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*
#        Notify handlers subscribe to logon/logoff/lock/UNLOCK/screensaver
#        events. Deprecated after XP/2003, so ANY subkey on a modern host is
#        anomalous; a non-Microsoft/unsigned DllName escalates to CRITICAL.
#
#   2. Network Provider DLL (T1556.008 -- "NPPSPY")
#        HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order\ProviderOrder
#        + HKLM\SYSTEM\CurrentControlSet\Services\<name>\NetworkProvider\ProviderPath
#        A rogue network provider captures CLEARTEXT credentials at every logon.
#        Default order is RDPNP,LanmanWorkstation,webclient; other providers
#        whose DLL is Microsoft-signed under System32 (WSL's P9NP being the
#        common case) are reported as [INFO] context, per the tiering below.
#
#   3. Credential Providers / Filters (LogonUI, logon + unlock)
#        HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\
#          Credential Providers\{GUID}  and  Credential Provider Filters\{GUID}
#        Each GUID -> CLSID InprocServer32 DLL loaded by LogonUI. A rogue one
#        harvests the password at every logon/unlock.
#
# SEVERITY TIERING (avoids false positives on legit third-party MFA/VPN
# providers, which are vendor-signed rather than Microsoft-signed):
#   CRITICAL -- DLL missing, unsigned, invalid signature, or under a staging
#               path (Temp/AppData/Downloads/Public)
#   WARNING  -- validly signed but NOT by Microsoft (verify: could be Duo/
#               Okta/YubiKey/Citrix/a VPN), or (for Notify) any subkey present
#   (Microsoft-signed under System32 is treated as clean.)
#
# On a finding, writes the marker file "$env:TEMP\dz_logon_<type>.txt" whose
# single line is the severity word, so the caller raises via :dz_finding.
#
# A KEY THAT COULD NOT BE READ IS NOT A CLEAN ONE (2026-11-23). Four checks
# printed an unraised "[SKIPPED] ... NOT performed"; the others read with
# -EA SilentlyContinue, so a Notify, network-provider, credential-provider,
# screensaver or logon-script key that could not be read printed the same
# [OK] as one that held nothing -- and a credential provider whose COM
# registration could not be read was skipped as "stale". Now every key is
# asked with -ErrorAction Stop: a key that does not exist is the ordinary
# answer, one that could not be read is named in "[WARNING] ... NOT
# performed", and any such line writes dz_logon_gap.txt, which the caller
# raises as its own row. dz_logon_done.txt is written last.
#
# Windows PowerShell 5.1 compatible. Read-only except the marker files.
# Executed by the helpers-ps51 CI job.

[CmdletBinding()]
param(
    # Where the severity markers go. The bat calls this with no arguments, so
    # the default is the previous hardcoded behavior; the parameter exists so
    # the marker contract can be tested without writing into the real TEMP.
    [string]$MarkerDir = $env:TEMP,
    # Only CI changes these: throwaway registry roots standing in for HKLM:
    # and HKCU:, so a key that cannot be read runs through the real readers
    # without touching the runner's own logon keys.
    [string]$KeyRoot = 'HKLM:',
    [string]$UserRoot = 'HKCU:',
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

$trusted    = '\bMicrosoft\b|\bWindows\b'
$badPathRx  = '\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\'

# Classify a DLL path: returns 'CRITICAL' | 'WARNING' | 'OK' plus a reason.
function Get-DllVerdict {
    param([string]$Path)
    if (-not $Path) { return @{ Sev = 'CRITICAL'; Why = 'no DLL path'; Path = '' } }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if ($p -match '^\\\?\?\\') { $p = $p.Substring(4) }
    # A BARE module name is not a missing DLL. Winlogon Notify DllName is by
    # design just a module name (sclgntfy.dll), which the loader resolves
    # against System32. Test-Path on the raw value resolved it against the
    # PowerShell working directory instead, failed, and returned
    # CRITICAL "DLL not found" -- a critical finding and a non-zero exit on a
    # healthy machine carrying a legitimate signed Notify handler. The LSA
    # branch further down already resolves its bare package names with
    # Join-Path $sys; do the same here so every caller benefits.
    if ($p -notmatch '[\\/]') {
        $sys32 = [Environment]::GetFolderPath('System')
        $cand  = Join-Path $sys32 $p
        if (Test-Path -LiteralPath $cand -PathType Leaf) { $p = $cand }
    }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ Sev = 'CRITICAL'; Why = "DLL not found: $p"; Path = '' } }
    if ($p -match $badPathRx) { return @{ Sev = 'CRITICAL'; Why = "DLL under staging path: $p"; Path = $p } }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $p -EA Stop } catch {}
    if (-not $sig -or $sig.Status -ne 'Valid') { return @{ Sev = 'CRITICAL'; Why = "unsigned/invalid signature: $p"; Path = $p } }
    if ($sig.SignerCertificate.Subject -notmatch $trusted) { return @{ Sev = 'WARNING'; Why = "non-Microsoft signer ($p) -- verify (MFA/VPN?)"; Path = $p } }
    return @{ Sev = 'OK'; Why = "Microsoft-signed: $p"; Path = $p }
}

# Escalate a running severity ('OK' < 'WARNING' < 'CRITICAL').
function Get-MaxSev { param($a, $b); if ($a -eq 'CRITICAL' -or $b -eq 'CRITICAL') { 'CRITICAL' } elseif ($a -eq 'WARNING' -or $b -eq 'WARNING') { 'WARNING' } else { 'OK' } }

# PURE. Whether a failed Get-Item said "this key does not exist".
function Test-KeyMissing {
    param($Err)
    if ($null -eq $Err) { return $false }
    $x = $Err.Exception
    $d = 0
    while ($null -ne $x -and $d -lt 6) { if ($x -is [System.Management.Automation.ItemNotFoundException]) { return $true }; $x = $x.InnerException; $d++ }
    return ([string]$Err.FullyQualifiedErrorId -like 'PathNotFound*')
}

# PURE. A named property of a Get-ItemProperty result, or $null (a key with
# no values gives back nothing at all).
function Get-PropValue {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    $pp = $Obj.PSObject.Properties[$Name]
    if ($null -eq $pp) { return $null }
    return $pp.Value
}

function ConvertTo-OneLine {
    param($Err)
    $m = ''
    if ($Err -is [System.Management.Automation.ErrorRecord]) { $m = [string]$Err.Exception.Message } elseif ($Err -is [Exception]) { $m = [string]$Err.Message } else { $m = [string]$Err }
    $m = ($m -replace '[\r\n\t]+', ' ').Trim()
    if (-not $m) { $m = 'no message' }
    if ($m.Length -gt 160) { $m = $m.Substring(0, 160) + '...' }
    return $m
}

# Read a key's values. State: ok (Values set) | missing | unreadable (Error).
function Read-KeyValues {
    param([string]$Path)
    try { $null = Get-Item -LiteralPath $Path -ErrorAction Stop }
    catch {
        if (Test-KeyMissing $_) { return @{ State = 'missing'; Values = $null; Error = '' } }
        return @{ State = 'unreadable'; Values = $null; Error = (ConvertTo-OneLine $_) }
    }
    try { return @{ State = 'ok'; Values = (Get-ItemProperty -LiteralPath $Path -ErrorAction Stop); Error = '' } }
    catch { return @{ State = 'unreadable'; Values = $null; Error = (ConvertTo-OneLine $_) } }
}

# Child keys of a key that opened: what was listed, and each child that could
# not be opened NAMED.
function Get-ChildKeys {
    param([string]$Path)
    $errs = $null
    $kids = @(Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue -ErrorVariable errs)
    $bad = @()
    foreach ($e in @($errs)) {
        if ($null -eq $e) { continue }
        $t = [string]$e.TargetObject
        if (-not $t) { $t = $Path }
        $bad += ((Split-Path -Leaf $t) + ': ' + (ConvertTo-OneLine $e))
    }
    return @{ Kids = $kids; Bad = $bad }
}

# PURE. The line for a check whose keys could not all be read.
function Get-GapLine {
    param([string]$What, [string[]]$Unread, [string]$Miss)
    $u = @($Unread | Where-Object { $_ })
    if ($u.Count -eq 0) { return '' }
    $names = (@($u | Select-Object -First 3) -join '; ') + $(if ($u.Count -gt 3) { '; and ' + ($u.Count - 3) + ' more' } else { '' })
    return ('[WARNING] ' + $What + ' NOT performed in full -- ' + $u.Count + ' key(s) could not be read (' + $names + '), so ' + $Miss + '.')
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got) if ($Ok) { "[OK]   $Name" } else { "[FAIL] $Name -- got: $Got"; $script:fails++ } }
    $l = Get-GapLine -What 'Winlogon Notify check' -Unread @('Notify: Requested registry access is not allowed.') -Miss 'a Notify package there would go unseen'
    T 'a key that could not be read is a [WARNING] ... NOT performed line that names it' ($l -match '^\[WARNING\] Winlogon Notify check NOT performed in full -- 1 key\(s\) could not be read \(Notify: Requested registry access') $l
    T 'every key read: no gap line' ((Get-GapLine -What 'x' -Unread @() -Miss 'y') -eq '') ''
    $l = Get-GapLine -What 'x' -Unread @('a', 'b', 'c', 'd', 'e') -Miss 'y'
    T 'more than three unread keys: three named and the rest counted' ($l -match '\(a; b; c; and 2 more\)') $l
    T 'a key with no values reads as no value, never an error' (($null -eq (Get-PropValue $null 'DllName')) -and ((Get-PropValue ([pscustomobject]@{ DllName = 'x.dll' }) 'DllName') -eq 'x.dll') -and ($null -eq (Get-PropValue ([pscustomobject]@{ Other = 1 }) 'DllName'))) ''
    $missErr = $null; try { $null = Get-Item -LiteralPath (Join-Path ([IO.Path]::GetTempPath()) 'dz_no_such_item_lp_7f3a') -ErrorAction Stop } catch { $missErr = $_ }
    T 'an item that does not exist is MISSING, never unreadable' (Test-KeyMissing $missErr) ([string]$missErr.FullyQualifiedErrorId)
    T 'an access denial is not "missing"' (-not (Test-KeyMissing (New-Object System.Management.Automation.ErrorRecord ((New-Object System.Security.SecurityException 'Requested registry access is not allowed.')), 'System.Security.SecurityException,Microsoft.PowerShell.Commands.GetItemCommand', 'PermissionDenied', $null))) ''
    if ($fails) { "[FAIL] logon_persistence self-test: $fails case(s) failed"; exit 1 }
    '[OK] logon_persistence self-test: a key that could not be read is a named NOT-performed line, a missing key is the ordinary answer, and a key with no values is not an error.'
    exit 0
}

$gaps = 0

function Write-Marker {
    # -Name writes dz_<Name>.txt exactly (the gap marker); -Type keeps the
    # dz_logon_<Type>.txt names every finding marker has always used.
    param([string]$Type, [string]$Sev, [string]$Name = '')
    # The marker IS the route to the findings ledger: a failed write here turns
    # a real finding into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine write failure print instead of vanishing --
    # an -EA SilentlyContinue on this write cost a field test its finding.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    $file = $(if ($Name) { "dz_{0}.txt" -f $Name } else { "dz_logon_{0}.txt" -f $Type })
    Set-Content -LiteralPath (Join-Path $MarkerDir $file) -Value $Sev -Encoding ASCII
}

# ---- 1. Winlogon Notify --------------------------------------------------
'--- [T1547.004] Winlogon Notify packages (fire on logon/lock/UNLOCK) ---'
$notifyBase = "$KeyRoot\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
$unread = @()
$k = Read-KeyValues $notifyBase
$subs = @()
if ($k.State -eq 'unreadable') { $unread += ('Winlogon\Notify: ' + $k.Error) }
elseif ($k.State -eq 'ok') { $ck = Get-ChildKeys $notifyBase; $subs = $ck.Kids; $unread += $ck.Bad }
$sev = 'OK'
foreach ($sub in $subs) {
    $sk = Read-KeyValues $sub.PSPath
    if ($sk.State -eq 'unreadable') { $unread += ($sub.PSChildName + ': ' + $sk.Error); continue }
    if ($sev -eq 'OK') { $sev = 'WARNING' }
    $dll = [string](Get-PropValue $sk.Values 'DllName')
    $v = Get-DllVerdict -Path $dll
    $sev = Get-MaxSev $sev $v.Sev
    ("[{0}] Winlogon Notify subkey '{1}' -> {2} ({3})" -f (@{CRITICAL='CRITICAL';WARNING='WARNING';OK='WARNING'}[$v.Sev]), $sub.PSChildName, $dll, $v.Why)
    Write-WhenCaveat
    $w = Get-WhenLine -KeyPath $sub.PSPath -FilePath $v.Path
    if ($w) { $w }
}
if ($sev -ne 'OK') { Write-Marker 'notify' $sev }
$gl = Get-GapLine -What 'Winlogon Notify check' -Unread $unread -Miss 'a Notify package there, which runs at every logon, lock and unlock, would go unseen (T1547.004)'
if ($gl) { $gl; $gaps++ } elseif ($sev -eq 'OK') { '[OK] No Winlogon Notify packages (expected on modern Windows).' }

# ---- 2. Network Provider DLL (NPPSPY) ------------------------------------
''
'--- [T1556.008] Network Provider DLLs (cleartext credential capture at logon) ---'
$allowedNp = @('RDPNP', 'LanmanWorkstation', 'webclient')
$unread = @()
$order = $null
$k = Read-KeyValues "$KeyRoot\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order"
if ($k.State -eq 'ok') { $order = [string](Get-PropValue $k.Values 'ProviderOrder') }
# The Order key and its ProviderOrder value exist on every Windows: not
# finding them is a read that did not answer, never "no providers".
if ($k.State -ne 'ok') { $unread += ('NetworkProvider\Order: ' + $(if ($k.State -eq 'missing') { 'the key was not found' } else { $k.Error })) }
elseif (-not $order) { $unread += 'NetworkProvider\Order: ProviderOrder is empty or absent' }
$sev = 'OK'; $any = $false
foreach ($np in @(([string]$order) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    if ($allowedNp -contains $np) { continue }
    $pk = Read-KeyValues ("$KeyRoot\SYSTEM\CurrentControlSet\Services\{0}\NetworkProvider" -f $np)
    # A provider whose key could not be read is not graded at all -- never the
    # CRITICAL "no DLL path" an empty path would earn below.
    if ($pk.State -eq 'unreadable') { $unread += ($np + ': ' + $pk.Error); continue }
    $any = $true
    $pp = [string](Get-PropValue $pk.Values 'ProviderPath')
    $v = Get-DllVerdict -Path $pp
    if ($v.Sev -eq 'OK') {
        # Microsoft-signed under System32 is clean, exactly as the tiering
        # header promises. This branch used to upgrade OK verdicts to
        # WARNING to keep its pre-WSL three-name allowlist authoritative --
        # and a field test then flagged WSL's own P9NP (p9np.dll, shipped
        # by Windows on every WSL machine) as credential capture. Surface
        # the provider as context, not as a finding.
        ("[INFO] Non-default network provider '{0}' -> {1} ({2}) -- Microsoft-signed system DLL; WSL's P9NP is the common case." -f $np, $pp, $v.Why)
    } else {
        $sev = Get-MaxSev $sev $v.Sev
        ("[{0}] Non-default network provider '{1}' -> {2} ({3})" -f $v.Sev, $np, $pp, $v.Why)
    }
}
if ($sev -ne 'OK') { Write-Marker 'netprov' $sev }
$gl = Get-GapLine -What 'Network provider check' -Unread $unread -Miss 'a rogue network provider there, which captures the password at every logon, would go unseen (T1556.008)'
if ($gl) { $gl; $gaps++ } elseif ($sev -eq 'OK' -and -not $any) { '[OK] Only default network providers present (RDPNP, LanmanWorkstation, webclient).' }

# ---- 3. Credential Providers / Filters -----------------------------------
''
'--- [T1547] Credential Providers/Filters (LogonUI, logon + UNLOCK) ---'
$cpBases = @(
    "$KeyRoot\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers",
    "$KeyRoot\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters"
)
$unread = @(); $flagged = $false; $sev = 'OK'; $stale = 0
foreach ($base in $cpBases) {
    $k = Read-KeyValues $base
    if ($k.State -eq 'missing') { continue }
    if ($k.State -eq 'unreadable') { $unread += ((Split-Path -Leaf $base) + ': ' + $k.Error); continue }
    $ck = Get-ChildKeys $base
    $unread += $ck.Bad
    foreach ($g in $ck.Kids) {
        $guid = $g.PSChildName
        $ip = "$KeyRoot\SOFTWARE\Classes\CLSID\$guid\InprocServer32"
        $ik = Read-KeyValues $ip
        # No COM registration at all is a stale entry (it cannot load); a
        # registration that could not be READ is not graded and is named.
        if ($ik.State -eq 'missing') { $stale++; continue }
        if ($ik.State -eq 'unreadable') { $unread += ($guid + ': ' + $ik.Error); continue }
        $dll = [string](Get-PropValue $ik.Values '(default)')
        if (-not $dll) { $stale++; continue }
        $v = Get-DllVerdict -Path $dll
        if ($v.Sev -eq 'OK') { continue }
        $flagged = $true; $sev = Get-MaxSev $sev $v.Sev
        ("[{0}] Credential provider {1} -> {2} ({3})" -f $v.Sev, $guid, $dll, $v.Why)
        Write-WhenCaveat
        $w = Get-WhenLine -KeyPath $ip -FilePath $v.Path
        if ($w) { $w }
    }
}
if ($stale -gt 0) { ('[INFO] ' + $stale + ' registered credential provider(s) have no COM registration, so they cannot load -- a leftover of uninstalled software, not graded.') }
if ($flagged) { Write-Marker 'credprov' $sev }
$gl = Get-GapLine -What 'Credential provider check' -Unread $unread -Miss 'a rogue credential provider there, which LogonUI loads at every logon and unlock, would go unseen (T1547)'
if ($gl) { $gl; $gaps++ } elseif (-not $flagged) { '[OK] All registered credential providers are Microsoft-signed system DLLs.' }

# ---- 4. LSA Notification / Authentication packages (Tier 2) --------------
# Loaded by lsass at boot/logon; a rogue package (e.g. a password-filter DLL)
# captures cleartext credentials at logon/password change. The signature IS the
# allowlist -- legit MS packages (scecli/msv1_0/rassfm) are Microsoft-signed
# System32 DLLs and pass; a planted non-MS/unsigned/missing one is flagged.
''
'--- [T1556.002/T1547.002] LSA Notification & Authentication packages (lsass, SYSTEM) ---'
$sys = [Environment]::GetFolderPath('System')
$lsaFlagged = $false; $lsaSev = 'OK'
$k = Read-KeyValues "$KeyRoot\SYSTEM\CurrentControlSet\Control\Lsa"
if ($k.State -eq 'ok') {
    foreach ($setName in 'Notification Packages', 'Authentication Packages') {
        foreach ($pkg in @((Get-PropValue $k.Values $setName) | Where-Object { $_ })) {
            $dllp = Join-Path $sys ($pkg + '.dll')
            $v = Get-DllVerdict -Path $dllp
            if ($v.Sev -eq 'OK') { continue }
            $lsaFlagged = $true; $lsaSev = Get-MaxSev $lsaSev $v.Sev
            ("[{0}] LSA {1} package '{2}' -> {3} ({4})" -f $v.Sev, $setName, $pkg, $dllp, $v.Why)
            Write-WhenCaveat
            $w = Get-WhenLine -KeyPath "$KeyRoot\SYSTEM\CurrentControlSet\Control\Lsa" -FilePath $v.Path
            if ($w) { $w }
        }
    }
}
if ($lsaFlagged) { Write-Marker 'lsa' $lsaSev }
# The Lsa key exists on every Windows: missing is a read that did not answer.
$gl = Get-GapLine -What 'LSA package check' -Unread $(if ($k.State -ne 'ok') { @('Control\Lsa: ' + $(if ($k.State -eq 'missing') { 'the key was not found' } else { $k.Error })) } else { @() }) -Miss 'a rogue LSA package, which lsass loads to see every password, would go unseen (T1556.002)'
if ($gl) { $gl; $gaps++ } elseif (-not $lsaFlagged) { '[OK] LSA Notification/Authentication packages are Microsoft-signed system DLLs.' }

# ---- 5. Screensaver hijack (Tier 2) -- runs on idle -> lock --------------
''
'--- [T1546.002] Screensaver (executes on user inactivity / lock) ---'
$desk = "$UserRoot\Control Panel\Desktop"
$k = Read-KeyValues $desk
$scr = $null; $scrSecure = $null
if ($k.State -eq 'ok') { $scr = [string](Get-PropValue $k.Values 'SCRNSAVE.EXE'); $scrSecure = Get-PropValue $k.Values 'ScreenSaverIsSecure' }
$scrFlagged = $false; $scrSev = 'OK'
if ($k.State -eq 'unreadable') {
    $gl = Get-GapLine -What 'Screensaver check' -Unread @('Control Panel\Desktop: ' + $k.Error) -Miss 'a screensaver swapped for a program, which runs whenever this PC sits idle, would go unseen (T1546.002)'
    $gl; $gaps++
} elseif ($scr) {
    $v = Get-DllVerdict -Path $scr
    if ($v.Sev -ne 'OK') {
        $scrFlagged = $true; $scrSev = Get-MaxSev $scrSev $v.Sev
        ("[{0}] Screensaver SCRNSAVE.EXE -> {1} ({2})" -f $v.Sev, $scr, $v.Why)
        Write-WhenCaveat
        $w = Get-WhenLine -KeyPath $desk -FilePath $v.Path
        if ($w) { $w }
    }
    else { "[OK] Screensaver is a Microsoft-signed system binary: $scr" }
    # INFO, not WARNING. ScreenSaverIsSecure=0 is what Windows leaves behind
    # whenever someone picks a screensaver and does not tick "On resume,
    # display logon screen" -- i.e. the default. Raising it put a finding in
    # the persistence section and a non-zero exit code on ordinary machines
    # with nothing wrong with them. It is a real local-access weakness and the
    # advice stays, but it is a user preference, not a compromise indicator,
    # and the same call was already made for ADFS / Azure AD Connect.
    if ("$scrSecure" -eq '0') { '[INFO] ScreenSaverIsSecure=0 -- the screensaver does not require a password to resume, so an unattended machine stays unlocked. This is the Windows default and not a compromise indicator; tick "On resume, display logon screen" in Screen Saver Settings to harden it.' }
} else {
    '[OK] No custom screensaver configured.'
}
if ($scrFlagged) { Write-Marker 'scr' $scrSev }

# ---- 6. UserInitMprLogonScript (Tier 2) ----------------------------------
''
'--- [T1037.001] Logon script (UserInitMprLogonScript) ---'
$k = Read-KeyValues "$UserRoot\Environment"
$lsn = $null
if ($k.State -eq 'ok') { $lsn = [string](Get-PropValue $k.Values 'UserInitMprLogonScript') }
if ($k.State -eq 'unreadable') {
    $gl = Get-GapLine -What 'Logon script check' -Unread @('Environment: ' + $k.Error) -Miss 'a script set to run at every logon would go unseen (T1037.001)'
    $gl; $gaps++
} elseif ($lsn) {
    ("[WARNING] UserInitMprLogonScript is set -- runs a script at every logon: {0}" -f $lsn)
    Write-Marker 'logonscript' 'WARNING'
} else {
    '[OK] No UserInitMprLogonScript logon script.'
}
if ($gaps -gt 0) { Write-Marker -Name 'logon_gap' -Sev 'WARNING' }
# Written last: the caller raises "produced no verdict" when it is absent.
Write-Marker 'done' 'done'
