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

$trusted    = '\bMicrosoft\b|\bWindows\b'
$badPathRx  = '\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\'

# Classify a DLL path: returns 'CRITICAL' | 'WARNING' | 'OK' plus a reason.
function Get-DllVerdict {
    param([string]$Path)
    if (-not $Path) { return @{ Sev = 'CRITICAL'; Why = 'no DLL path' } }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if ($p -match '^\\\?\?\\') { $p = $p.Substring(4) }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ Sev = 'CRITICAL'; Why = "DLL not found: $p" } }
    if ($p -match $badPathRx) { return @{ Sev = 'CRITICAL'; Why = "DLL under staging path: $p" } }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $p -EA Stop } catch {}
    if (-not $sig -or $sig.Status -ne 'Valid') { return @{ Sev = 'CRITICAL'; Why = "unsigned/invalid signature: $p" } }
    if ($sig.SignerCertificate.Subject -notmatch $trusted) { return @{ Sev = 'WARNING'; Why = "non-Microsoft signer ($p) -- verify (MFA/VPN?)" } }
    return @{ Sev = 'OK'; Why = "Microsoft-signed: $p" }
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
        }
    }
} catch { $ok = $false }
if (-not $ok) { '[SKIPPED] Credential Provider enumeration failed -- check NOT performed.' }
elseif (-not $flagged) { '[OK] All registered credential providers are Microsoft-signed system DLLs.' }
else { Write-Marker 'credprov' $sev }
