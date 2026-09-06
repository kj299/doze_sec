# com_clsid_check.ps1 -- HKCU COM CLSID InprocServer32 overrides (T1546.015).
# Invoked from Section 18.
#
# A per-user CLSID whose InprocServer32 points at a DLL outside System32 is
# userland COM hijacking: the next process to instantiate that class loads the
# attacker's DLL, with no file dropped in a startup folder and no registry Run
# key. This check enumerates them and grades each one.
#
# EXTRACTED FROM THE BATS (was 33 echo lines into %PSRUN% in each). CLAUDE.md's
# rule -- a block with if/elseif nesting belongs in a tools/*.ps1 -- applies
# sharply here: the admin copy left `)` bare while the noAdmin copy escaped
# every one as `^)`, so the same logic had to be hand-maintained twice with
# different escaping, around a `$why =` assignment containing a nested
# if/elseif chain. Here there is no cmd escaping and the whole rule is
# self-testable.
#
# WHAT CHANGED, AND WHY -- "the file is missing" is not "you are compromised".
#
# A field report (2026-09-06) raised
#   [WARNING][T1546.015] Suspicious COM CLSID overrides (3):
#     {06B74C04-...} -> ...\AppData\Local\BraveSoftware\Update\1.3.361.151\psuser_64.dll   [no-file]
# on a clean machine. Brave's updater (Omaha, as used by Chrome and Edge too)
# registers these CLSIDs and leaves the registration behind when it rolls to a
# new version directory. The DLL is gone; the key is not.
#
# The check already had a vendor tier -- the same report shows
# "[INFO][T1546.015] Vendor-registered user CLSID overrides (1, expected)" for
# an Adobe DLL -- and Brave is in the $trusted signer list. But that list is
# consulted only on the Authenticode SIGNER, and a file that does not exist has
# no signer, so the vendor tier was unreachable for exactly the entries that
# needed it. Absence of evidence was read as evidence.
#
# So a registration whose file is genuinely missing now goes to its own bucket:
#
#   missing file, path under \Temp\ \Downloads\ \Users\Public\   WARNING (unchanged)
#   missing file, anywhere else                                  INFO, itemised
#
# That asymmetry is the same one proc_path_grade uses, and it is what keeps the
# detection harness honest: its plant is C:\Users\Public\dz_selftest_evil_com.dll,
# which the plant deliberately never creates -- so it is graded through this
# very branch and MUST stay WARNING because \Users\Public\ is a staging path.
#
# The INFO line still says what it means. A dangling registration cannot load
# anything as it stands, but it would become live the moment a file appeared at
# that path, and a reader deserves to know it is there.
#
# ALSO FIXED: "[no-file]" used to mean only "Get-AuthenticodeSignature threw",
# which is equally true of a quoted value, an unexpanded %SystemRoot%, an NT
# \??\ prefix, or a bare module name. logon_persistence.ps1 and
# service_signature_check.ps1 both carry header comments recording that exact
# false alarm in sibling checks. The path is now normalised the same way and
# existence is tested explicitly, so "no-file" means what it says.
#
# MARKER: severity word to $MarkerDir\dz_com.txt; caller raises via
# :dz_finding. Vendor and stale entries write no marker.
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [int]$MaxReport = 15,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Sev)
    if ($Sev -eq 'OK') { return }
    # The marker IS the route to the findings ledger: a failed write here turns
    # a real finding into a CLEAN section. Create the directory rather than
    # assume it -- an -EA SilentlyContinue on this write cost a field test its
    # finding.
    if (-not (Test-Path -LiteralPath $MarkerDir)) {
        New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $MarkerDir 'dz_com.txt') -Value $Sev -Encoding ASCII
}

# Ported verbatim from the bat block.
$script:Trusted = '\bMicrosoft\b|\bAdobe\b|\bBrave\b|\bGoogle\b|\bMozilla\b|\bWinSCP\b|\bCisco\b|\bCitrix\b|\bLogitech\b|\bVMware\b|\bDropbox\b|\bZoom\b|\bApple\b|\bNVIDIA\b|\bIntel\b|\bRealtek\b|\bLenovo\b|\bHP Inc\b|\bDell\b'
$script:BadPathRx = '\\Temp\\|\\Downloads\\|\\Public\\'
$script:SkipPathRx = 'Microsoft|Windows|System32'

# Script-scope so the self-test can set it: GetFolderPath('System') is empty on
# a non-Windows host, which would make the bare-module-name case untestable
# anywhere but Windows.
$script:System32 = [Environment]::GetFolderPath('System')
if (-not $script:System32 -and $env:SystemRoot) { $script:System32 = $env:SystemRoot.TrimEnd('\') + '\System32' }

function Resolve-DllPath {
    # Normalise before judging. Without this, a perfectly good quoted or
    # env-var path reads as "no-file".
    param([string]$Raw)
    if (-not $Raw) { return '' }
    $p = [Environment]::ExpandEnvironmentVariables($Raw.Trim().Trim('"'))
    if ($p -match '^\\\?\?\\') { $p = $p.Substring(4) }
    if ($p -match '^\\SystemRoot\\' -and $env:SystemRoot) { $p = $env:SystemRoot.TrimEnd('\') + '\' + $p.Substring(12) }
    # A bare module name is resolved by the loader against System32, not
    # against the audit's working directory. Resolving it against the working
    # directory is what made a legitimate signed handler read as "not found" in
    # a sibling check (logon_persistence.ps1).
    if ($p -and $p -notmatch '[\\/]' -and $script:System32) {
        $p = $script:System32.TrimEnd('\') + '\' + $p
    }
    return $p
}

# Injectable so the self-test needs no registry, no files and no certificates.
$script:ExistsProbe = { param($p) Test-Path -LiteralPath $p -PathType Leaf }
$script:SigProbe    = { param($p) $s = $null; try { $s = Get-AuthenticodeSignature -FilePath $p -EA Stop } catch {}; return $s }
$script:CertProbe   = { param($c) try { return [bool](Test-Certificate -Cert $c -EA Stop) } catch { return $true } }

function Get-ClsidVerdict {
    # Returns @{ Bucket = 'vendor'|'stale'|'flagged'; Label = <string> }.
    param([string]$Guid, [string]$RawPath)
    $path = Resolve-DllPath -Raw $RawPath
    $bad  = ($path -match $script:BadPathRx) -or ($RawPath -match $script:BadPathRx)

    if (-not (& $script:ExistsProbe $path)) {
        # THE BRAVE CASE. A registration pointing at a file that is not there
        # cannot load anything -- unless the path is somewhere an attacker
        # stages payloads, in which case a dangling registration is exactly
        # what pre-staging looks like and it keeps its WARNING.
        if ($bad) { return @{ Bucket = 'flagged'; Label = 'no-file bad-path' } }
        return @{ Bucket = 'stale'; Label = 'no-file' }
    }

    $sig = & $script:SigProbe $path
    $certIssue = ''
    if ($sig -and $sig.SignerCertificate) {
        if (-not (& $script:CertProbe $sig.SignerCertificate)) { $certIssue = 'cert-invalid' }
        if ($certIssue -eq '' -and $sig.SignerCertificate.NotAfter -lt (Get-Date) -and -not $sig.TimeStamperCertificate) {
            $certIssue = 'cert-expired'
        }
    }
    $valid   = ($sig -and $sig.Status -eq 'Valid')
    $trusted = ($valid -and $sig.SignerCertificate.Subject -match $script:Trusted)

    if ($valid -and $trusted -and -not $bad -and $certIssue -eq '') {
        $cn = (($sig.SignerCertificate.Subject -split ',')[0]) -replace '^CN=', ''
        return @{ Bucket = 'vendor'; Label = ('signed: ' + $cn) }
    }
    $why = ''
    if ($certIssue) { $why = if ($trusted) { 'trusted-but-' + $certIssue } else { $certIssue } }
    elseif ($valid) { $why = if ($trusted) { 'trusted-signer' } else { 'unexpected-signer' } }
    elseif ($sig -and $sig.Status -eq 'NotSigned') { $why = 'unsigned' }
    elseif ($sig) { $why = [string]$sig.Status }
    else { $why = 'unreadable' }
    if ($bad) { $why = $why + ' bad-path' }
    return @{ Bucket = 'flagged'; Label = $why }
}

function Get-ClsidOverrides {
    # Emits @{ Guid; Raw } for each HKCU CLSID carrying an InprocServer32
    # default value outside the Windows/System32 tree. Written straight to the
    # pipeline: `return $out` on an empty array yields $null and the caller's
    # @($null) is a one-element array holding null (see hosts_check.ps1 and
    # module_inspect.ps1 #201 for what that costs).
    param([string]$Root = 'HKCU:\Software\Classes\CLSID')
    if (-not (Test-Path $Root)) { return }
    foreach ($k in (Get-ChildItem $Root -EA SilentlyContinue)) {
        $sv = Get-ItemProperty ("$($k.PSPath)\InprocServer32") -Name '(default)' -EA SilentlyContinue
        if (-not $sv) { continue }
        $dll = [string]$sv.'(default)'
        if (-not $dll) { continue }
        if ($dll -match $script:SkipPathRx) { continue }
        New-Object PSObject -Property @{ Guid = $k.PSChildName; Raw = $dll }
    }
}

# ---------------------------------------------------------------------------
if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    function FakeSig {
        param([string]$Status, [string]$Subject, [datetime]$NotAfter = ([datetime]'2099-01-01'), $Stamp = $null)
        $cert = New-Object PSObject -Property @{ Subject = $Subject; NotAfter = $NotAfter }
        return (New-Object PSObject -Property @{ Status = $Status; SignerCertificate = $cert; TimeStamperCertificate = $Stamp })
    }
    $script:CertProbe = { param($c) $true }

    # --- THE FIELD FALSE POSITIVE -----------------------------------------
    $script:ExistsProbe = { param($p) $false }
    $script:SigProbe    = { param($p) $null }
    $v = Get-ClsidVerdict -Guid '{06B74C04}' -RawPath 'C:\Users\khali\AppData\Local\BraveSoftware\Update\1.3.361.151\psuser_64.dll'
    T "Brave's stale updater CLSID is context, not a finding" `
      ($v.Bucket -eq 'stale' -and $v.Label -eq 'no-file') "$($v.Bucket)/$($v.Label)"

    # --- ...and the harness plant, which must NOT be downgraded with it ----
    $v = Get-ClsidVerdict -Guid '{dead1111}' -RawPath 'C:\Users\Public\dz_selftest_evil_com.dll'
    T 'the harness plant under \Users\Public\ stays a WARNING' `
      ($v.Bucket -eq 'flagged' -and $v.Label -eq 'no-file bad-path') "$($v.Bucket)/$($v.Label)"
    foreach ($p in @('C:\Windows\Temp\x.dll', 'C:\Users\u\Downloads\x.dll')) {
        $v = Get-ClsidVerdict -Guid '{g}' -RawPath $p
        T "a missing DLL under $(Split-Path -Parent $p) stays a WARNING" ($v.Bucket -eq 'flagged') "$($v.Bucket)/$($v.Label)"
    }

    # --- present files keep every existing verdict -------------------------
    $script:ExistsProbe = { param($p) $true }
    $script:SigProbe = { param($p) FakeSig -Status 'Valid' -Subject 'CN=Adobe Inc., O=Adobe' }
    $v = Get-ClsidVerdict -Guid '{a}' -RawPath 'C:\Program Files (x86)\Adobe\x.dll'
    T 'a present, validly-signed trusted vendor DLL is the INFO vendor tier' `
      ($v.Bucket -eq 'vendor' -and $v.Label -eq 'signed: Adobe Inc.') "$($v.Bucket)/$($v.Label)"

    $script:SigProbe = { param($p) FakeSig -Status 'NotSigned' -Subject '' }
    $v = Get-ClsidVerdict -Guid '{b}' -RawPath 'C:\ProgramData\app\x.dll'
    T 'a present unsigned DLL is still flagged' ($v.Bucket -eq 'flagged' -and $v.Label -eq 'unsigned') "$($v.Bucket)/$($v.Label)"

    $script:SigProbe = { param($p) FakeSig -Status 'Valid' -Subject 'CN=Totally Legit Ltd' }
    $v = Get-ClsidVerdict -Guid '{c}' -RawPath 'C:\ProgramData\app\x.dll'
    T 'a present DLL signed by an untrusted signer is flagged' `
      ($v.Bucket -eq 'flagged' -and $v.Label -eq 'unexpected-signer') "$($v.Bucket)/$($v.Label)"

    $script:SigProbe = { param($p) FakeSig -Status 'Valid' -Subject 'CN=Adobe Inc.' }
    $v = Get-ClsidVerdict -Guid '{d}' -RawPath 'C:\Users\Public\x.dll'
    T 'a trusted signer in a staging path is still flagged' `
      ($v.Bucket -eq 'flagged' -and $v.Label -eq 'trusted-signer bad-path') "$($v.Bucket)/$($v.Label)"

    $script:SigProbe = { param($p) FakeSig -Status 'Valid' -Subject 'CN=Adobe Inc.' -NotAfter ([datetime]'2001-01-01') }
    $v = Get-ClsidVerdict -Guid '{e}' -RawPath 'C:\ProgramData\app\x.dll'
    T 'an expired certificate with no timestamp is flagged, label preserved' `
      ($v.Bucket -eq 'flagged' -and $v.Label -eq 'trusted-but-cert-expired') "$($v.Bucket)/$($v.Label)"

    $script:SigProbe  = { param($p) FakeSig -Status 'Valid' -Subject 'CN=Adobe Inc.' }
    $script:CertProbe = { param($c) $false }
    $v = Get-ClsidVerdict -Guid '{f}' -RawPath 'C:\ProgramData\app\x.dll'
    T 'a revoked certificate is flagged, label preserved' `
      ($v.Bucket -eq 'flagged' -and $v.Label -eq 'trusted-but-cert-invalid') "$($v.Bucket)/$($v.Label)"
    $script:CertProbe = { param($c) $true }

    # --- path normalisation: these must NOT read as no-file ----------------
    $seen = @()
    $script:ExistsProbe = { param($p) $script:probed = $p; $true }
    $script:SigProbe    = { param($p) FakeSig -Status 'Valid' -Subject 'CN=Adobe Inc.' }
    $null = Get-ClsidVerdict -Guid '{g}' -RawPath '"C:\Program Files\App\x.dll"'
    T 'a quoted registry value is unquoted before it is tested' `
      ($script:probed -eq 'C:\Program Files\App\x.dll') "probed=$($script:probed)"
    $null = Get-ClsidVerdict -Guid '{h}' -RawPath '\??\C:\App\x.dll'
    T 'an NT \??\ prefix is stripped' ($script:probed -eq 'C:\App\x.dll') "probed=$($script:probed)"
    $script:System32 = 'C:\Windows\System32'
    $null = Get-ClsidVerdict -Guid '{i}' -RawPath 'somemodule.dll'
    T 'a bare module name resolves against System32, not the working directory' `
      ($script:probed -eq 'C:\Windows\System32\somemodule.dll') "probed=$($script:probed)"

    # --- a staging path must be caught even before normalisation -----------
    $script:ExistsProbe = { param($p) $false }
    $v = Get-ClsidVerdict -Guid '{j}' -RawPath '%PUBLIC%\..\Public\evil.dll'
    T 'a staging path expressed via an env var is still flagged' ($v.Bucket -eq 'flagged') "$($v.Bucket)/$($v.Label)"

    # --- enumeration must not invent an entry from an empty registry -------
    T 'an absent CLSID root yields zero entries under @()' `
      (@(Get-ClsidOverrides -Root 'HKCU:\Software\Classes\NoSuchKeyForSelfTest').Count -eq 0) ''

    if ($fails) { Write-Output "[FAIL] $fails com_clsid_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] com_clsid_check self-test: a dangling vendor registration is context, a dangling one in a staging path is not, and every present-file verdict is unchanged.'
    exit 0
}

# ---------------------------------------------------------------------------
$vendor  = @()
$stale   = @()
$flagged = @()

foreach ($e in @(Get-ClsidOverrides)) {
    if ($null -eq $e) { continue }
    $entry = $e.Guid + ' -> ' + $e.Raw
    $v = Get-ClsidVerdict -Guid $e.Guid -RawPath $e.Raw
    $line = $entry + '   [' + $v.Label + ']'
    switch ($v.Bucket) {
        'vendor'  { $vendor  += $line }
        'stale'   { $stale   += $line }
        default   { $flagged += $line }
    }
}

$sev = 'OK'
if ($flagged.Count -gt 0) {
    $sev = 'WARNING'
    "[WARNING][T1546.015] Suspicious COM CLSID overrides ($($flagged.Count)):"
    $flagged | Select-Object -First $MaxReport | ForEach-Object { '  ' + $_ }
    if ($flagged.Count -gt $MaxReport) { "  ...and $($flagged.Count - $MaxReport) more not listed (report cap $MaxReport)." }
}
if ($stale.Count -gt 0) {
    "[INFO][T1546.015] $($stale.Count) user CLSID override(s) point at a file that is not present -- they cannot load as-is. Common when an updater (Brave, Chrome, Edge and other Omaha-based updaters) rolls to a new version directory and leaves the registration behind. Would become live if a file appeared at that path:"
    $stale | Select-Object -First $MaxReport | ForEach-Object { '  ' + $_ }
    if ($stale.Count -gt $MaxReport) { "  ...and $($stale.Count - $MaxReport) more not listed (report cap $MaxReport)." }
}
if ($vendor.Count -gt 0) {
    "[INFO][T1546.015] Vendor-registered user CLSID overrides ($($vendor.Count), expected):"
    $vendor | Select-Object -First $MaxReport | ForEach-Object { '  ' + $_ }
    if ($vendor.Count -gt $MaxReport) { "  ...and $($vendor.Count - $MaxReport) more not listed (report cap $MaxReport)." }
}
if ($flagged.Count -eq 0 -and $stale.Count -eq 0 -and $vendor.Count -eq 0) {
    '[OK] No user-level COM CLSID overrides.'
}

Write-Marker -Sev $sev
