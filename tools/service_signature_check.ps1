# service_signature_check.ps1 -- Authenticode signature gating for Win32 services
#
# Invoked from doze_sec.bat / doze_sec_noAdmin.bat Section 7.
# Replaces the path-substring allowlist (which an attacker bypassed
# by installing a service binary anywhere under "Program Files")
# with per-binary Authenticode signature evaluation, plus cert
# revocation (Test-Certificate) and cert expiry checks. Mirrors
# the COM hijack signature gating in Section 17 ([CTI][T1546.015]).
#
# A service is RAISED as a WARNING only if at least one of these holds:
#   - The signature is not Valid (NotSigned, UnknownError, etc.)
#   - The cert chain fails Test-Certificate (revocation or chain build)
#   - The cert is past NotAfter and there is no countersigning timestamp
#   - The binary lives under \Temp\, \AppData\, \Downloads\, \Public\
#     (whatever the signature says), or is MISSING from such a path
#
# TWO THINGS THAT USED TO BE WARNINGS AND ARE NOW CONTEXT.
#
# 1. "no-file" MEANT ONLY "Get-AuthenticodeSignature THREW". There was no
#    Test-Path anywhere in this file, so one label covered three unrelated
#    states. A field report (2026-09-06) raised nine services on a clean
#    machine, four of them this way:
#      GoogleUpdaterService141.0.7340.0 -> ...\GoogleUpdater\141.0.7340.0\updater.exe
#      CoworkVMService                  -> ...\WindowsApps\Claude_1.11737.2.0_x64__...\cowork-svc.exe
#    The first is genuinely absent -- Google's Omaha updater rolled to a new
#    version directory and left the service registration behind, byte-for-byte
#    the Brave pattern fixed for COM CLSIDs in #201. The second almost
#    certainly EXISTS: \Program Files\WindowsApps\ is ACL'd to
#    TrustedInstaller, so the read fails and the file is called missing. The
#    label was simply wrong.
#
#    Existence is now tested explicitly and the three states are named:
#      absent, in a staging path      -> WARNING  (pre-staging looks like this)
#      absent, anywhere else          -> INFO     stale-registration
#      present, signature unreadable  -> INFO     unreadable, DECLARED as a gap
#    The third follows CLAUDE.md's "'Unavailable' is not an answer": an
#    inability must be visible as one, never folded into "fine" or "finding".
#
# 2. "unexpected-signer" ON A VALIDLY SIGNED BINARY. The same report flagged
#    Docker Inc. and DoD-PKE InstallRoot -- both validly signed, both simply
#    absent from a 19-name allowlist. That list cannot enumerate the legitimate
#    software industry, so "not on my list" carries almost no signal while
#    firing on every real machine. A valid signature in a normal install
#    location is now an INFO inventory line naming the signer. It is still a
#    WARNING when the path is a staging directory, the cert is expired or
#    revoked, or the binary is unsigned.
#
# Trusted-vendor allowlist uses \b...\b word-boundary anchors so short
# tokens like Dell / Intel / Apple do not substring-match unrelated
# subjects (e.g. "Mandell Inc"). Same regex as Section 17 COM hijack.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File service_signature_check.ps1 [-MarkerFile <path>]
#
# -MarkerFile: if any service is flagged, write this file so the caller can
# raise the exit code / findings count (the report [WARNING] alone was never
# wired into Section 7's verdict, so a flagged service used to read CLEAN).

[CmdletBinding()]
param([string]$MarkerFile, [switch]$SelfTest)

$ErrorActionPreference = 'Continue'

$trusted = '\bMicrosoft\b|\bAdobe\b|\bBrave\b|\bGoogle\b|\bMozilla\b|\bWinSCP\b|\bCisco\b|\bCitrix\b|\bLogitech\b|\bVMware\b|\bDropbox\b|\bZoom\b|\bApple\b|\bNVIDIA\b|\bIntel\b|\bRealtek\b|\bLenovo\b|\bHP Inc\b|\bDell\b|\bWindows\b'

function Get-ServiceBinaryPath {
    param([string]$PathName)
    if (-not $PathName) { return $null }
    # ImagePath forms seen in the wild: quoted, unquoted with arguments,
    # %SystemRoot%-style env vars (REG_EXPAND_SZ), and NT-native \??\ /
    # \SystemRoot\ prefixes. Normalize before parsing, or a legitimate
    # service gets misread and flagged 'no-file' (false alarm).
    $p = [Environment]::ExpandEnvironmentVariables($PathName.Trim())
    if ($p -match '^\\\?\?\\') { $p = $p.Substring(4) }
    if ($p -match '^\\SystemRoot\\') { $p = Join-Path $env:SystemRoot $p.Substring(12) }
    if ($p.StartsWith('"')) {
        $endQuote = $p.IndexOf('"', 1)
        if ($endQuote -gt 0) { return $p.Substring(1, $endQuote - 1) }
        return $p.Substring(1)
    }
    # Unquoted path, possibly with arguments AND spaces in the path itself
    # (the classic unquoted-service-path case: C:\Program Files\App\svc.exe
    # -flag). Resolve the way the SCM does: try each space-delimited prefix,
    # first existing file wins, also with an implied .exe extension.
    # Splitting at the first space misparsed these as "C:\Program" and
    # flagged signed vendor services as 'no-file'.
    $candidate = $null
    foreach ($t in ($p -split ' ')) {
        $candidate = if ($null -eq $candidate) { $t } else { "$candidate $t" }
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        if ($candidate -notmatch '\.[Ee][Xx][Ee]$' -and
            (Test-Path -LiteralPath ($candidate + '.exe') -PathType Leaf)) { return $candidate + '.exe' }
    }
    return ($p -split '\s+', 2)[0]
}

# Injectable so the self-test needs no services, no files and no certificates.
$script:ExistsProbe = { param($p) Test-Path -LiteralPath $p -PathType Leaf }
$script:SigProbe    = { param($p) $sig = $null; try { $sig = Get-AuthenticodeSignature -FilePath $p -EA Stop } catch {}; return $sig }
$script:CertProbe   = { param($c) try { return [bool](Test-Certificate -Cert $c -EA Stop) } catch { return $true } }
# A service's MSIX package is provisioned for SYSTEM, not for the auditing
# user, so -AllUsers (which needs admin) is tried first; the per-user query is
# the fallback so a non-elevated run still answers what it can.
# Memoised by package full name. Get-AppxPackage -AllUsers enumerates every
# package for every user and can take seconds; without this it runs once per
# unsigned WindowsApps service binary. This repo has already paid once for a
# slow check blowing a timeout, and module_inspect.ps1 caches its signature
# lookups for the same reason.
$script:AppxCache = @{}
$script:AppxProbe = {
    param($full)
    try { $r = Get-AppxPackage -AllUsers -EA Stop | Where-Object { $_.PackageFullName -eq $full }; if ($r) { return $r } } catch {}
    try { return (Get-AppxPackage -EA Stop | Where-Object { $_.PackageFullName -eq $full }) } catch {}
    return $null
}

$script:BadPathRx = '\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\'

function Get-MsixPackageSignature {
    # MSIX/AppX packages are CATALOG-signed: the package carries the signature,
    # not each inner file, so Get-AuthenticodeSignature on the inner .exe
    # correctly returns NotSigned. Field false positive 2026-09-06:
    #   IntelGraphicsSoftwareService (Running, Auto) ->
    #   C:\Program Files\WindowsApps\AppUp.IntelArcSoftware_26.26.2459.0_x64__8j3eq9eme6ctt
    #     \VFS\ProgramFilesX64\Intel\...\IntelGraphicsSoftware.Service.exe
    #
    # The package full name is the path segment straight after WindowsApps\.
    # Returns $null when the path is not in a package at all -- the caller then
    # grades exactly as before.
    param([string]$Path)
    if (-not $Path) { return $null }
    # ANCHORED to the real package root. Matching any directory merely NAMED
    # WindowsApps let a path like C:\Users\Public\WindowsApps\<real package
    # full name>\evil.exe resolve against a genuinely installed package and be
    # graded as Store-signed. Installed MSIX packages only ever live under
    # %ProgramFiles%\WindowsApps.
    $m = [regex]::Match($Path, '(?i)^[A-Za-z]:\\Program Files\\WindowsApps\\([^\\]+)')
    if (-not $m.Success) { return $null }
    $full = $m.Groups[1].Value
    if ($script:AppxCache.ContainsKey($full)) {
        $pkg = $script:AppxCache[$full]
    } else {
        $pkg = & $script:AppxProbe $full
        $script:AppxCache[$full] = $pkg
    }
    if (-not $pkg) { return @{ Kind = ''; FullName = $full; Resolved = $false } }
    if ($pkg -is [array]) { $pkg = $pkg[0] }
    return @{ Kind = [string]$pkg.SignatureKind; FullName = $full; Resolved = $true }
}

function Get-ServiceVerdict {
    # Returns @{ Bucket = 'clean'|'inventory'|'stale'|'unreadable'|'flagged'; Why = <label> }.
    # 'clean' is not reported at all; the middle three are INFO context; only
    # 'flagged' becomes a WARNING and writes the marker.
    param([string]$Binary)
    $bad = ($Binary -match $script:BadPathRx)

    if (-not (& $script:ExistsProbe $Binary)) {
        # A registration whose binary is gone cannot start. In a staging path
        # that is what pre-staging looks like and it keeps its WARNING;
        # anywhere else it is an updater that moved on.
        if ($bad) { return @{ Bucket = 'flagged'; Why = 'no-file bad-path' } }
        return @{ Bucket = 'stale'; Why = 'stale-registration' }
    }

    $sig = & $script:SigProbe $Binary
    if ($null -eq $sig) {
        # The file IS there and the signature could not be read -- typically
        # WindowsApps, ACL'd to TrustedInstaller. Declared, never absorbed.
        if ($bad) { return @{ Bucket = 'flagged'; Why = 'unreadable bad-path' } }
        return @{ Bucket = 'unreadable'; Why = 'unreadable' }
    }

    $certIssue = ''
    if ($sig.SignerCertificate) {
        if (-not (& $script:CertProbe $sig.SignerCertificate)) { $certIssue = 'cert-invalid' }
        if ($certIssue -eq '' -and $sig.SignerCertificate.NotAfter -lt (Get-Date) -and -not $sig.TimeStamperCertificate) {
            $certIssue = 'cert-expired'
        }
    }
    $valid     = ($sig.Status -eq 'Valid')
    $isTrusted = ($valid -and $sig.SignerCertificate.Subject -match $trusted)

    if ($valid -and $certIssue -eq '' -and -not $bad) {
        if ($isTrusted) { return @{ Bucket = 'clean'; Why = '' } }
        # Validly signed by someone not on a 19-name list. Inventory, not a
        # finding -- that list can never enumerate the software industry.
        $cn = (($sig.SignerCertificate.Subject -split ',')[0]) -replace '^CN=', ''
        return @{ Bucket = 'inventory'; Why = ('signed: ' + $cn) }
    }

    $why = ''
    if ($certIssue)   { $why = if ($isTrusted) { 'trusted-but-' + $certIssue } else { $certIssue } }
    elseif ($valid)   { $why = if ($isTrusted) { 'trusted-signer' } else { 'unexpected-signer' } }
    elseif ($sig.Status -eq 'NotSigned') {
        # BEFORE calling it unsigned, ask whether it lives inside an MSIX
        # package. Microsoft documents the guarantee that makes SignatureKind
        # usable here: "Any value other than None indicates that the package is
        # signed with a trusted certificate, since it is not possible to
        # install a package that is signed with an untrusted or otherwise
        # invalid certificate."
        #
        # None is the Visual-Studio-F5 / dev-layout case and keeps its WARNING,
        # so this cannot go wrong in the direction that matters. Developer and
        # Enterprise are signed but NOT store-vetted -- an attacker-signed MSIX
        # lands there -- so they stay findings with an accurate label. An
        # unresolvable package fails CLOSED.
        # $bad wins outright: the staging-path rule is not something a
        # package signature may override. Two independent guards, because
        # either alone would leave the bypass open.
        $msix = $null
        if (-not $bad) { $msix = Get-MsixPackageSignature -Path $Binary }
        if ($null -ne $msix) {
            if (-not $msix.Resolved) { $why = 'unsigned; msix package did not resolve' }
            elseif ($msix.Kind -eq 'Store' -or $msix.Kind -eq 'System') {
                return @{ Bucket = 'inventory'; Why = ('msix: signed by ' + $msix.Kind + ' (' + $msix.FullName + ')') }
            }
            elseif ($msix.Kind -and $msix.Kind -ne 'None') { $why = 'msix: ' + $msix.Kind + '-signed, not store-vetted' }
            else { $why = 'unsigned' }
        } else { $why = 'unsigned' }
    }
    else { $why = [string]$sig.Status }
    if ($bad) { $why = $why + ' bad-path' }
    return @{ Bucket = 'flagged'; Why = $why }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    function FakeSig {
        param([string]$Status, [string]$Subject, [datetime]$NotAfter = ([datetime]'2099-01-01'), $Stamp = $null)
        $c = New-Object PSObject -Property @{ Subject = $Subject; NotAfter = $NotAfter }
        return (New-Object PSObject -Property @{ Status = $Status; SignerCertificate = $c; TimeStamperCertificate = $Stamp })
    }
    $script:CertProbe = { param($c) $true }

    # --- the owner's four false positives, verbatim paths ------------------
    $script:ExistsProbe = { param($p) $false }
    $v = Get-ServiceVerdict -Binary 'C:\Program Files (x86)\Google\GoogleUpdater\141.0.7340.0\updater.exe'
    T "Google's stale versioned updater registration is context" `
      ($v.Bucket -eq 'stale') "$($v.Bucket)/$($v.Why)"

    $script:ExistsProbe = { param($p) $true }
    $script:SigProbe    = { param($p) $null }
    $v = Get-ServiceVerdict -Binary 'C:\Program Files\WindowsApps\Claude_1.11737.2.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe'
    T 'a present WindowsApps binary whose signature cannot be read is declared unreadable, not missing' `
      ($v.Bucket -eq 'unreadable' -and $v.Why -eq 'unreadable') "$($v.Bucket)/$($v.Why)"

    $script:SigProbe = { param($p) FakeSig -Status 'Valid' -Subject 'CN=Docker Inc., O=Docker' }
    $v = Get-ServiceVerdict -Binary 'C:\Program Files\Docker\Docker\com.docker.service'
    T 'a validly signed unlisted vendor is inventory, not a finding' `
      ($v.Bucket -eq 'inventory' -and $v.Why -eq 'signed: Docker Inc.') "$($v.Bucket)/$($v.Why)"

    $script:SigProbe = { param($p) FakeSig -Status 'Valid' -Subject 'CN=U.S. Government DoD PKE' }
    $v = Get-ServiceVerdict -Binary 'C:\Program Files\DoD-PKE\InstallRoot\InstallRootService.exe'
    T 'the DoD-PKE service is inventory too' ($v.Bucket -eq 'inventory') "$($v.Bucket)/$($v.Why)"

    # --- and none of that may swallow a real finding -----------------------
    $script:ExistsProbe = { param($p) $false }
    $v = Get-ServiceVerdict -Binary 'C:\Users\Public\evil.exe'
    T 'a MISSING binary in a staging path stays a WARNING' `
      ($v.Bucket -eq 'flagged' -and $v.Why -eq 'no-file bad-path') "$($v.Bucket)/$($v.Why)"
    $script:ExistsProbe = { param($p) $true }
    $script:SigProbe    = { param($p) $null }
    $v = Get-ServiceVerdict -Binary 'C:\Users\u\AppData\Local\Temp\x.exe'
    T 'an unreadable binary in a staging path stays a WARNING' ($v.Bucket -eq 'flagged') "$($v.Bucket)/$($v.Why)"

    $script:SigProbe = { param($p) FakeSig -Status 'NotSigned' -Subject '' }
    $v = Get-ServiceVerdict -Binary 'C:\Program Files\App\svc.exe'
    T 'an unsigned service binary is still a WARNING' `
      ($v.Bucket -eq 'flagged' -and $v.Why -eq 'unsigned') "$($v.Bucket)/$($v.Why)"

    # --- MSIX catalog signing: the owner's two remaining rows --------------
    # An MSIX package is signed as a PACKAGE, so the inner .exe is correctly
    # NotSigned. SignatureKind is the oracle; None still means unsigned.
    $intel = 'C:\Program Files\WindowsApps\AppUp.IntelArcSoftware_26.26.2459.0_x64__8j3eq9eme6ctt\VFS\ProgramFilesX64\Intel\Intel Graphics Software\IntelGraphicsSoftware.Service.exe'
    function FakePkg { param([string]$Kind, [string]$Full)
        return (New-Object PSObject -Property @{ SignatureKind = $Kind; PackageFullName = $Full })
    }
    $script:AppxCache = @{}; $script:AppxProbe = { param($f) FakePkg -Kind 'Store' -Full $f }
    $v = Get-ServiceVerdict -Binary $intel
    T "the owner's Store-signed MSIX service is inventory, not a finding" `
      ($v.Bucket -eq 'inventory' -and $v.Why -match '^msix: signed by Store \(AppUp\.IntelArcSoftware_') "$($v.Bucket)/$($v.Why)"

    $script:AppxCache = @{}; $script:AppxProbe = { param($f) FakePkg -Kind 'System' -Full $f }
    $v = Get-ServiceVerdict -Binary $intel
    T 'a System-signed MSIX service is inventory' ($v.Bucket -eq 'inventory') "$($v.Bucket)/$($v.Why)"

    # ...and every other SignatureKind stays a finding.
    #
    # The kind travels in a SCRIPT-SCOPED variable, not a closure. This loop
    # was written `{ ... $k ... }.GetNewClosure()` and it failed on real 5.1
    # with CommandNotFoundException: FakePkg. GetNewClosure builds a new
    # DYNAMIC MODULE and copies the caller VARIABLES into it -- not its
    # functions -- and module code runs in its own scope hierarchy with its
    # own root, so a script-scope function is not on the lookup chain.
    # pwsh 7 resolves it anyway; 5.1 does not. Both cases then failed for the
    # WRONG REASON -- the probe threw, the package "did not resolve", and the
    # fail-closed path returned flagged/unsigned. They still read as flagged,
    # so only the assertion on Why (not just Bucket) caught it.
    # A plain scriptblock is bound to the script session state and sees both.
    foreach ($k in @('Developer','Enterprise')) {
        $script:fakeKind = $k
        $script:AppxCache = @{}; $script:AppxProbe = { param($f) FakePkg -Kind $script:fakeKind -Full $f }
        $v = Get-ServiceVerdict -Binary $intel
        T "an MSIX package signed '$k' is NOT store-vetted and stays a WARNING" `
          ($v.Bucket -eq 'flagged' -and $v.Why -match 'not store-vetted') "$($v.Bucket)/$($v.Why)"
    }
    $script:AppxCache = @{}; $script:AppxProbe = { param($f) FakePkg -Kind 'None' -Full $f }
    $v = Get-ServiceVerdict -Binary $intel
    T "SignatureKind 'None' is a genuinely unsigned package and stays a WARNING" `
      ($v.Bucket -eq 'flagged' -and $v.Why -eq 'unsigned') "$($v.Bucket)/$($v.Why)"

    # Fails CLOSED: an unresolvable package must never read as signed.
    $script:AppxCache = @{}; $script:AppxProbe = { param($f) $null }
    $v = Get-ServiceVerdict -Binary $intel
    T 'an MSIX package that does not resolve fails CLOSED' `
      ($v.Bucket -eq 'flagged' -and $v.Why -match 'did not resolve') "$($v.Bucket)/$($v.Why)"

    # THE OTHER ROW: not an MSIX path, so the MSIX logic must not touch it.
    $script:AppxCache = @{}; $script:AppxProbe = { param($f) FakePkg -Kind 'Store' -Full $f }
    $v = Get-ServiceVerdict -Binary 'C:\Program Files\WiFiman Desktop\wifiman-desktopd.exe'
    T "the owner's non-MSIX unsigned service is still a WARNING" `
      ($v.Bucket -eq 'flagged' -and $v.Why -eq 'unsigned') "$($v.Bucket)/$($v.Why)"

    # An MSIX binary in a staging path keeps bad-path precedence.
    $v = Get-ServiceVerdict -Binary 'C:\Users\Public\WindowsApps\Pkg_1.0_x64__abc\x.exe'
    T 'an MSIX-looking path under \Users\Public\ is still flagged' ($v.Bucket -eq 'flagged') "$($v.Bucket)/$($v.Why)"
    # ...and the resolver itself refuses it, so neither guard is load-bearing alone.
    T 'a directory merely NAMED WindowsApps is not a package root' `
      ($null -eq (Get-MsixPackageSignature -Path 'C:\Users\Public\WindowsApps\Pkg_1.0_x64__abc\x.exe')) ''
    T 'only %ProgramFiles%\WindowsApps counts as a package root' `
      ($null -ne (Get-MsixPackageSignature -Path 'C:\Program Files\WindowsApps\Pkg_1.0_x64__abc\x.exe')) ''
    # The second guard, proven separately: a staging segment INSIDE a real
    # package root. The anchored regex accepts this path, so only the bad-path
    # check keeps it flagged -- without that case the guard was untested.
    $script:AppxCache = @{}; $script:AppxProbe = { param($f) FakePkg -Kind 'Store' -Full $f }
    $v = Get-ServiceVerdict -Binary 'C:\Program Files\WindowsApps\Pkg_1.0_x64__abc\VFS\Temp\x.exe'
    T 'a staging segment inside a real package root still wins over the signature' `
      ($v.Bucket -eq 'flagged') "$($v.Bucket)/$($v.Why)"

    T 'a non-WindowsApps path yields no MSIX lookup at all' `
      ($null -eq (Get-MsixPackageSignature -Path 'C:\Program Files\App\svc.exe')) ''
    $r = Get-MsixPackageSignature -Path $intel
    T 'the package full name is taken from the segment after WindowsApps' `
      ($r.FullName -eq 'AppUp.IntelArcSoftware_26.26.2459.0_x64__8j3eq9eme6ctt') "$($r.FullName)"

    # The lookup is memoised: Get-AppxPackage -AllUsers is expensive and would
    # otherwise run once per unsigned WindowsApps binary.
    $script:AppxCache = @{}
    $script:probeCalls = 0
    $script:AppxCache = @{}; $script:AppxProbe = { param($f) $script:probeCalls++; FakePkg -Kind 'Store' -Full $f }
    $null = Get-MsixPackageSignature -Path $intel
    $null = Get-MsixPackageSignature -Path $intel
    T 'the Appx lookup is cached (one probe call for two lookups)' `
      ($script:probeCalls -eq 1) "probe calls=$($script:probeCalls)"
    $null = Get-MsixPackageSignature -Path 'C:\Program Files\WindowsApps\Other_1.0_x64__zzz\x.exe'
    T 'the cache does not leak across packages' ($script:probeCalls -eq 2) "probe calls=$($script:probeCalls)"
    $script:AppxCache = @{}
    $script:AppxCache = @{}; $script:AppxProbe = { param($f) $null }

    $script:SigProbe = { param($p) FakeSig -Status 'HashMismatch' -Subject 'CN=Microsoft Corporation' }
    $v = Get-ServiceVerdict -Binary 'C:\Program Files\App\svc.exe'
    T 'a tampered binary (HashMismatch) is still a WARNING, label preserved' `
      ($v.Bucket -eq 'flagged' -and $v.Why -eq 'HashMismatch') "$($v.Bucket)/$($v.Why)"

    $script:SigProbe = { param($p) FakeSig -Status 'Valid' -Subject 'CN=Microsoft Corporation' -NotAfter ([datetime]'2001-01-01') }
    $v = Get-ServiceVerdict -Binary 'C:\Program Files\App\svc.exe'
    T 'an expired cert with no timestamp is still a WARNING, label preserved' `
      ($v.Bucket -eq 'flagged' -and $v.Why -eq 'trusted-but-cert-expired') "$($v.Bucket)/$($v.Why)"

    $script:SigProbe  = { param($p) FakeSig -Status 'Valid' -Subject 'CN=Docker Inc.' }
    $script:CertProbe = { param($c) $false }
    $v = Get-ServiceVerdict -Binary 'C:\Program Files\Docker\Docker\com.docker.service'
    T 'a REVOKED cert is a WARNING even for an unlisted vendor' `
      ($v.Bucket -eq 'flagged' -and $v.Why -eq 'cert-invalid') "$($v.Bucket)/$($v.Why)"
    $script:CertProbe = { param($c) $true }

    $script:SigProbe = { param($p) FakeSig -Status 'Valid' -Subject 'CN=Microsoft Corporation' }
    $v = Get-ServiceVerdict -Binary 'C:\Users\Public\svc.exe'
    T 'a trusted signer running from a staging path is still a WARNING' `
      ($v.Bucket -eq 'flagged' -and $v.Why -eq 'trusted-signer bad-path') "$($v.Bucket)/$($v.Why)"

    $v = Get-ServiceVerdict -Binary 'C:\Windows\System32\svchost.exe'
    T 'an ordinary Microsoft-signed service is clean and reported nowhere' `
      ($v.Bucket -eq 'clean') "$($v.Bucket)/$($v.Why)"

    if ($fails) { Write-Output "[FAIL] $fails service_signature_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] service_signature_check self-test: absent / unreadable / unlisted-but-signed are context; staging paths, unsigned and bad certs stay findings.'
    exit 0
}

$services = Get-CimInstance Win32_Service -EA SilentlyContinue
if (-not $services) {
    '[INFO] Service enumeration unavailable.'
    return
}

$flagged    = @()
$inventory  = @()
$stale      = @()
$unreadable = @()
$totalChecked = 0

foreach ($s in $services) {
    if (-not $s.PathName) { continue }
    $bin = Get-ServiceBinaryPath -PathName $s.PathName
    if (-not $bin) { continue }
    $totalChecked++
    $v = Get-ServiceVerdict -Binary $bin
    if ($v.Bucket -eq 'clean') { continue }
    $row = [pscustomobject]@{
        Name = $s.Name; State = $s.State; StartMode = $s.StartMode; Why = $v.Why; Binary = $bin
    }
    switch ($v.Bucket) {
        'flagged'    { $flagged    += $row }
        'inventory'  { $inventory  += $row }
        'stale'      { $stale      += $row }
        'unreadable' { $unreadable += $row }
    }
}

function Write-MarkerFile {
    param([string]$Path)
    if (-not $Path) { return }
    # The marker IS the route to the findings ledger: a failed write turns a
    # real finding into a CLEAN section. Create the directory rather than
    # assume it, and let a genuine failure print instead of vanishing -- the
    # bare `Set-Content -EA SilentlyContinue` that used to be here is the exact
    # pattern that cost a field test its finding across twelve tools.
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
    }
    Set-Content -LiteralPath $Path -Value 'hit' -Encoding ASCII
}

if ($flagged.Count -gt 0) {
    "[WARNING] $($flagged.Count) service(s) failed Authenticode gating (out of $totalChecked checked):"
    $flagged | Format-Table Name,State,StartMode,Why,Binary -AutoSize -Wrap
    "[INFO] 'unsigned' = binary has no Authenticode signature."
    "[INFO] 'unexpected-signer' / 'trusted-signer' with 'bad-path' = the binary runs from Temp/AppData/Downloads/Public."
    "[INFO] 'no-file bad-path' = registration points at a missing file in a staging path -- what pre-staging looks like."
    "[INFO] 'cert-invalid' = chain build / revocation check failed for the signing cert."
    "[INFO] 'cert-expired' = cert past NotAfter and no countersigning timestamp."
    Write-MarkerFile -Path $MarkerFile
} else {
    "[OK] All $totalChecked services with binary paths pass Authenticode gating + path check."
}

# CONTEXT, NOT FINDINGS. Each of these was a WARNING until 2026-09-06, and each
# fired on a clean machine. They are still printed, itemised, because a reader
# adjudicating an intrusion needs to see them -- they are simply not raised.
if ($stale.Count -gt 0) {
    "[INFO] $($stale.Count) service(s) point at a binary that is not on disk, outside any staging path -- the registration cannot start. Common when an updater (Google, Brave, Edge and other Omaha-based updaters) rolls to a new version directory and leaves the service behind:"
    $stale | Format-Table Name,State,StartMode,Binary -AutoSize -Wrap
}
if ($unreadable.Count -gt 0) {
    "[INFO] $($unreadable.Count) service binary(ies) EXIST but their signature could not be read, so they were NOT verified -- this is a gap, not a clean result. Usual cause is \Program Files\WindowsApps\, which is ACL'd to TrustedInstaller. Verify one by hand with: Get-AuthenticodeSignature -FilePath '<binary>'"
    $unreadable | Format-Table Name,State,StartMode,Binary -AutoSize -Wrap
}
if ($inventory.Count -gt 0) {
    "[INFO] $($inventory.Count) service(s) are validly signed by a vendor outside this tool's short allowlist, in a normal install location. That is inventory, not evidence -- no allowlist can enumerate every legitimate software vendor. Listed so you can confirm you recognise each one:"
    $inventory | Format-Table Name,State,StartMode,Why,Binary -AutoSize -Wrap
}
