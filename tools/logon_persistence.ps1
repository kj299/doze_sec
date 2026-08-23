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
#        Legit order is only RDPNP,LanmanWorkstation,webclient.
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
# Enumeration failures emit [SKIPPED] (fail-closed, not silent-clean).
#
# Windows PowerShell 5.1 compatible. Read-only except the marker files.
# Executed by the helpers-ps51 CI job.

[CmdletBinding()]
param()

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
$badPathRx  = '\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\'

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

function Write-Marker { param([string]$Type, [string]$Sev); Set-Content -LiteralPath (Join-Path $env:TEMP ("dz_logon_{0}.txt" -f $Type)) -Value $Sev -Encoding ASCII -EA SilentlyContinue }

# ---- 1. Winlogon Notify --------------------------------------------------
'--- [T1547.004] Winlogon Notify packages (fire on logon/lock/UNLOCK) ---'
$notifyBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
$ok = $true; $subs = $null
try { if (Test-Path $notifyBase) { $subs = Get-ChildItem -Path $notifyBase -EA Stop } } catch { $ok = $false }
if (-not $ok) {
    '[SKIPPED] Winlogon\Notify enumeration failed -- check NOT performed.'
} elseif (-not $subs) {
    '[OK] No Winlogon Notify packages (expected on modern Windows).'
} else {
    $sev = 'WARNING'
    foreach ($s in $subs) {
        $dll = (Get-ItemProperty -Path $s.PSPath -Name DllName -EA SilentlyContinue).DllName
        $v = Get-DllVerdict -Path $dll
        $sev = Get-MaxSev $sev $v.Sev
        ("[{0}] Winlogon Notify subkey '{1}' -> {2} ({3})" -f (@{CRITICAL='CRITICAL';WARNING='WARNING';OK='WARNING'}[$v.Sev]), $s.PSChildName, $dll, $v.Why)
        Write-WhenCaveat
        $w = Get-WhenLine -KeyPath $s.PSPath -FilePath $v.Path
        if ($w) { $w }
    }
    Write-Marker 'notify' $sev
}

# ---- 2. Network Provider DLL (NPPSPY) ------------------------------------
''
'--- [T1556.008] Network Provider DLLs (cleartext credential capture at logon) ---'
$allowedNp = @('RDPNP', 'LanmanWorkstation', 'webclient')
$ok = $true; $order = $null
try { $order = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order' -Name ProviderOrder -EA Stop).ProviderOrder } catch { $ok = $false }
if (-not $ok) {
    '[SKIPPED] NetworkProvider order unavailable -- check NOT performed.'
} else {
    $sev = 'OK'; $any = $false
    foreach ($np in @($order -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if ($allowedNp -contains $np) { continue }
        $any = $true
        $pp = (Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}\NetworkProvider" -f $np) -Name ProviderPath -EA SilentlyContinue).ProviderPath
        $v = Get-DllVerdict -Path $pp
        $sev = Get-MaxSev $sev $v.Sev
        ("[{0}] Non-default network provider '{1}' -> {2} ({3})" -f (@{CRITICAL='CRITICAL';WARNING='WARNING';OK='WARNING'}[$v.Sev]), $np, $pp, $v.Why)
    }
    if ($any) { if ($sev -eq 'OK') { $sev = 'WARNING' }; Write-Marker 'netprov' $sev }
    else { '[OK] Only default network providers present (RDPNP, LanmanWorkstation, webclient).' }
}

# ---- 3. Credential Providers / Filters -----------------------------------
''
'--- [T1547] Credential Providers/Filters (LogonUI, logon + UNLOCK) ---'
$cpBases = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters'
)
$ok = $true; $flagged = $false; $sev = 'OK'
try {
    foreach ($base in $cpBases) {
        if (-not (Test-Path $base)) { continue }
        foreach ($g in (Get-ChildItem -Path $base -EA Stop)) {
            $guid = $g.PSChildName
            $dll = (Get-ItemProperty -Path ("HKLM:\SOFTWARE\Classes\CLSID\{0}\InprocServer32" -f $guid) -Name '(default)' -EA SilentlyContinue).'(default)'
            if (-not $dll) { continue }   # GUID with no COM registration -> skip (stale)
            $v = Get-DllVerdict -Path $dll
            if ($v.Sev -eq 'OK') { continue }
            $flagged = $true; $sev = Get-MaxSev $sev $v.Sev
            ("[{0}] Credential provider {1} -> {2} ({3})" -f $v.Sev, $guid, $dll, $v.Why)
            Write-WhenCaveat
            $w = Get-WhenLine -KeyPath ("HKLM:\SOFTWARE\Classes\CLSID\{0}\InprocServer32" -f $guid) -FilePath $v.Path
            if ($w) { $w }
        }
    }
} catch { $ok = $false }
if (-not $ok) { '[SKIPPED] Credential Provider enumeration failed -- check NOT performed.' }
elseif (-not $flagged) { '[OK] All registered credential providers are Microsoft-signed system DLLs.' }
else { Write-Marker 'credprov' $sev }

# ---- 4. LSA Notification / Authentication packages (Tier 2) --------------
# Loaded by lsass at boot/logon; a rogue package (e.g. a password-filter DLL)
# captures cleartext credentials at logon/password change. The signature IS the
# allowlist -- legit MS packages (scecli/msv1_0/rassfm) are Microsoft-signed
# System32 DLLs and pass; a planted non-MS/unsigned/missing one is flagged.
''
'--- [T1556.002/T1547.002] LSA Notification & Authentication packages (lsass, SYSTEM) ---'
$sys = [Environment]::GetFolderPath('System')
$lsaOk = $true; $lsaFlagged = $false; $lsaSev = 'OK'
try {
    $lp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA Stop
    foreach ($setName in 'Notification Packages', 'Authentication Packages') {
        foreach ($pkg in @($lp.$setName | Where-Object { $_ })) {
            $dllp = Join-Path $sys ($pkg + '.dll')
            $v = Get-DllVerdict -Path $dllp
            if ($v.Sev -eq 'OK') { continue }
            $lsaFlagged = $true; $lsaSev = Get-MaxSev $lsaSev $v.Sev
            ("[{0}] LSA {1} package '{2}' -> {3} ({4})" -f $v.Sev, $setName, $pkg, $dllp, $v.Why)
            Write-WhenCaveat
            $w = Get-WhenLine -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -FilePath $v.Path
            if ($w) { $w }
        }
    }
} catch { $lsaOk = $false }
if (-not $lsaOk) { '[SKIPPED] LSA package enumeration failed -- check NOT performed.' }
elseif (-not $lsaFlagged) { '[OK] LSA Notification/Authentication packages are Microsoft-signed system DLLs.' }
else { Write-Marker 'lsa' $lsaSev }

# ---- 5. Screensaver hijack (Tier 2) -- runs on idle -> lock --------------
''
'--- [T1546.002] Screensaver (executes on user inactivity / lock) ---'
$desk = 'HKCU:\Control Panel\Desktop'
$scr = (Get-ItemProperty -Path $desk -Name 'SCRNSAVE.EXE' -EA SilentlyContinue).'SCRNSAVE.EXE'
$scrSecure = (Get-ItemProperty -Path $desk -Name 'ScreenSaverIsSecure' -EA SilentlyContinue).ScreenSaverIsSecure
$scrFlagged = $false; $scrSev = 'OK'
if ($scr) {
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
$lsn = (Get-ItemProperty -Path 'HKCU:\Environment' -Name UserInitMprLogonScript -EA SilentlyContinue).UserInitMprLogonScript
if ($lsn) {
    ("[WARNING] UserInitMprLogonScript is set -- runs a script at every logon: {0}" -f $lsn)
    Write-Marker 'logonscript' 'WARNING'
} else {
    '[OK] No UserInitMprLogonScript logon script.'
}
