# service_signature_check.ps1 -- Authenticode signature gating for Win32 services
#
# Invoked from doze_sec.bat / doze_sec_noAdmin.bat Section 7.
# Replaces the path-substring allowlist (which an attacker bypassed
# by installing a service binary anywhere under "Program Files")
# with per-binary Authenticode signature evaluation, plus cert
# revocation (Test-Certificate) and cert expiry checks. Mirrors
# the COM hijack signature gating in Section 17 ([CTI][T1546.015]).
#
# A service is REPORTED only if at least one of these holds:
#   - The binary cannot be located on disk
#   - The signature is not Valid (NotSigned, UnknownError, etc.)
#   - The signer is not on the trusted vendor allowlist
#   - The cert chain fails Test-Certificate (revocation or chain build)
#   - The cert is past NotAfter and there is no countersigning timestamp
#   - The binary lives under \Temp\, \AppData\, \Downloads\, \Public\
#
# Trusted-vendor allowlist uses \b...\b word-boundary anchors so short
# tokens like Dell / Intel / Apple do not substring-match unrelated
# subjects (e.g. "Mandell Inc"). Same regex as Section 17 COM hijack.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File service_signature_check.ps1

$ErrorActionPreference = 'Continue'

$trusted = '\bMicrosoft\b|\bAdobe\b|\bBrave\b|\bGoogle\b|\bMozilla\b|\bWinSCP\b|\bCisco\b|\bCitrix\b|\bLogitech\b|\bVMware\b|\bDropbox\b|\bZoom\b|\bApple\b|\bNVIDIA\b|\bIntel\b|\bRealtek\b|\bLenovo\b|\bHP Inc\b|\bDell\b|\bWindows\b'

function Get-ServiceBinaryPath {
    param([string]$PathName)
    if (-not $PathName) { return $null }
    $p = $PathName.Trim()
    if ($p.StartsWith('"')) {
        $endQuote = $p.IndexOf('"', 1)
        if ($endQuote -gt 0) { return $p.Substring(1, $endQuote - 1) }
        return $p.Substring(1)
    }
    return ($p -split '\s+', 2)[0]
}

$services = Get-CimInstance Win32_Service -EA SilentlyContinue
if (-not $services) {
    '[INFO] Service enumeration unavailable.'
    return
}

$flagged = @()
$totalChecked = 0

foreach ($s in $services) {
    if (-not $s.PathName) { continue }
    $bin = Get-ServiceBinaryPath -PathName $s.PathName
    if (-not $bin) { continue }
    $totalChecked++

    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $bin -EA Stop } catch {}

    $bad = ($bin -match '\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\')

    $certIssue = ''
    if ($sig -and $sig.SignerCertificate) {
        try { if (-not (Test-Certificate -Cert $sig.SignerCertificate -EA Stop)) { $certIssue = 'cert-invalid' } } catch {}
        if (-not $certIssue -and $sig.SignerCertificate.NotAfter -lt (Get-Date) -and -not $sig.TimeStamperCertificate) {
            $certIssue = 'cert-expired'
        }
    }

    # Allowlist gate: trusted vendor + valid sig + good path + good cert -> skip
    if ($sig -and $sig.Status -eq 'Valid' -and `
        $sig.SignerCertificate.Subject -match $trusted -and `
        -not $bad -and `
        -not $certIssue) {
        continue
    }

    # Build classification label
    $why = ''
    if ($null -eq $sig) {
        $why = 'no-file'
    } elseif ($certIssue) {
        $why = if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match $trusted) {
            'trusted-but-' + $certIssue
        } else {
            $certIssue
        }
    } elseif ($sig.Status -eq 'Valid') {
        $why = if ($sig.SignerCertificate.Subject -match $trusted) { 'trusted-signer' } else { 'unexpected-signer' }
    } elseif ($sig.Status -eq 'NotSigned') {
        $why = 'unsigned'
    } else {
        $why = [string]$sig.Status
    }
    if ($bad) { $why = $why + ' bad-path' }

    $flagged += [pscustomobject]@{
        Name      = $s.Name
        State     = $s.State
        StartMode = $s.StartMode
        Why       = $why
        Binary    = $bin
    }
}

if ($flagged.Count -gt 0) {
    "[WARNING] $($flagged.Count) service(s) failed Authenticode gating (out of $totalChecked checked):"
    $flagged | Format-Table Name,State,StartMode,Why,Binary -AutoSize -Wrap
    "[INFO] 'no-file' = service binary path doesn't exist on disk (likely stale)."
    "[INFO] 'trusted-signer' = signer is on vendor allowlist but path is under Temp/AppData/Downloads/Public."
    "[INFO] 'unexpected-signer' = valid sig but signer is not on the vendor allowlist."
    "[INFO] 'unsigned' = binary has no Authenticode signature."
    "[INFO] 'cert-invalid' = chain build / revocation check failed for the signing cert."
    "[INFO] 'cert-expired' = cert past NotAfter and no countersigning timestamp."
} else {
    "[OK] All $totalChecked services with binary paths pass Authenticode gating + path check."
}
