# driver_catalog_probe.ps1 -- why does ONE machine call a Microsoft inbox
# driver unsigned when a clean Windows install does not?
#
# READ-ONLY. Opens files for reading, queries services and the catalog
# database, and prints. It writes nothing, changes nothing, installs nothing
# and makes no network connection. Safe to run on a live machine, elevated or
# not. It needs no admin, but it REPORTS whether it had it, because that is
# one of the candidate explanations.
#
# BACKGROUND
#   tools/driver_audit.ps1 grades a kernel driver with Get-AuthenticodeSignature
#   and raises "[WARNING] Driver ... unsigned or invalid Authenticode signature
#   (NotSigned) on a kernel driver" when the status is not Valid. On the
#   owner's machine that fired for C:\WINDOWS\system32\drivers\bthmodem.sys,
#   a Microsoft inbox Bluetooth driver, and it was catalogued in
#   tests/benign_corpus.txt as a known false positive on the theory that the
#   cmdlet cannot read driver-store CATALOG signatures.
#
#   MEASURED 2026-09-07 on windows-latest (Windows Server 2025 26100,
#   PowerShell 5.1.26100): that theory is WRONG. All 457 drivers reported
#   Status=Valid, and SignatureType came back Catalog for every one sampled.
#   Get-AuthenticodeSignature on 5.1 already resolves driver catalogs. The
#   false positive did not reproduce on a clean machine at all.
#
#   So the interesting question is no longer "how do we read catalogs" -- the
#   cmdlet does. It is "what is different about the machine where the lookup
#   FAILED", and whether that difference is itself worth reporting. A catalog
#   lookup that stops working is not automatically benign: the catalog store
#   and the service that reads it are exactly what tampering would target.
#
# WHAT THIS SEPARATES
#   1. Not elevated                 -> catalog access denied for some files.
#   2. CryptSvc not running/healthy -> every catalog lookup fails.
#   3. Catalog store unreadable     -> same, and worth a finding of its own.
#   4. This ONE driver is genuinely uncovered (its package was removed and
#      the .sys was left behind) -> the warning is arguably CORRECT.
#   5. Something else -- in which case the per-file dump below says what.
[CmdletBinding()]
param(
    # Focus on one file. Default: audit the whole drivers directory the way
    # driver_audit.ps1 does, so we learn whether this is one driver or many.
    [string]$Path = '',
    # The full scan calls Get-AuthenticodeSignature ~450 times; that measured
    # 55 s on a runner. Skip it if you only care about -Path.
    [switch]$SkipFullScan
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

function Line { param([string]$s) Write-Output $s }

Line '=== ENVIRONMENT ==='
Line "PSVersion    : $($PSVersionTable.PSVersion)"
Line "LanguageMode : $($ExecutionContext.SessionState.LanguageMode)"
Line "OS build     : $([Environment]::OSVersion.Version)"
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    $elev = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $elev = 'unknown' }
Line "Elevated     : $elev"

Line ''
Line '=== CANDIDATE 2/3: the catalog subsystem itself ==='
# Get-AuthenticodeSignature's catalog lookup goes through Cryptographic
# Services. If CryptSvc is stopped or unhealthy EVERY catalog-signed file
# reports NotSigned -- which would make this a whole-machine condition, not a
# per-driver one, and a security-relevant finding in its own right.
foreach ($svc in @('CryptSvc', 'CryptoSvc')) {
    try {
        $s = Get-Service -Name $svc -EA Stop
        Line "Service $svc : Status=$($s.Status) StartType=$($s.StartType)"
    } catch { }
}
$catRoot = Join-Path (Join-Path $env:SystemRoot 'System32') 'CatRoot'
$drvCatDir = Join-Path $catRoot '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
foreach ($d in @($catRoot, $drvCatDir)) {
    if (Test-Path -LiteralPath $d) {
        $n = -1
        try { $n = @(Get-ChildItem -LiteralPath $d -Filter *.cat -File -EA Stop).Count } catch { $n = "UNREADABLE ($($_.Exception.Message))" }
        Line "CatRoot $d : $n .cat file(s)"
    } else {
        Line "CatRoot $d : MISSING"
    }
}

Line ''
Line '=== P/Invoke availability (the lock-down question) ==='
$catOk = $false
try {
    Add-Type -ErrorAction Stop -Namespace DozeSec -Name CatSig -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct CATALOG_INFO {
    public uint cbStruct;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)]
    public string wszCatalogFile;
}
[DllImport("wintrust.dll", SetLastError=true)]
public static extern bool CryptCATAdminAcquireContext(ref IntPtr phCatAdmin, ref Guid pgSubsystem, uint dwFlags);
[DllImport("wintrust.dll", SetLastError=true, EntryPoint="CryptCATAdminAcquireContext")]
public static extern bool CryptCATAdminAcquireContextNull(ref IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);
[DllImport("wintrust.dll", SetLastError=true)]
public static extern bool CryptCATAdminAcquireContext2(ref IntPtr phCatAdmin, ref Guid pgSubsystem, [MarshalAs(UnmanagedType.LPWStr)] string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);
[DllImport("wintrust.dll", SetLastError=true, EntryPoint="CryptCATAdminAcquireContext2")]
public static extern bool CryptCATAdminAcquireContext2Null(ref IntPtr phCatAdmin, IntPtr pgSubsystem, [MarshalAs(UnmanagedType.LPWStr)] string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);
[DllImport("wintrust.dll", SetLastError=true)]
public static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);
[DllImport("wintrust.dll", SetLastError=true)]
public static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);
[DllImport("wintrust.dll", SetLastError=true)]
public static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);
[DllImport("wintrust.dll", SetLastError=true)]
public static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);
[DllImport("wintrust.dll", SetLastError=true)]
public static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);
[DllImport("wintrust.dll", SetLastError=true)]
public static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
'@
    $catOk = $true
} catch {
    Line "Add-Type FAILED: $($_.Exception.Message)"
    Line '  (Constrained Language Mode, WDAC or an AppLocker rule over %TEMP% blocks this.)'
}
Line "Add-Type compiled : $catOk"

function Find-Catalog {
    param([string]$File, [string]$Which, [string]$Alg)
    $res = @{ Found = $false; Catalog = ''; Err = '' }
    if (-not $catOk) { $res.Err = 'no P/Invoke'; return $res }
    $hCat = [IntPtr]::Zero
    $drvGuid = [Guid]'F750E6C3-38EE-11D1-85E5-00C04FC295EE'
    try {
        $ok = $false
        if ($Alg -eq 'SHA1') {
            if ($Which -eq 'driver') { $ok = [DozeSec.CatSig]::CryptCATAdminAcquireContext([ref]$hCat, [ref]$drvGuid, 0) }
            else { $ok = [DozeSec.CatSig]::CryptCATAdminAcquireContextNull([ref]$hCat, [IntPtr]::Zero, 0) }
        } else {
            if ($Which -eq 'driver') { $ok = [DozeSec.CatSig]::CryptCATAdminAcquireContext2([ref]$hCat, [ref]$drvGuid, $Alg, [IntPtr]::Zero, 0) }
            else { $ok = [DozeSec.CatSig]::CryptCATAdminAcquireContext2Null([ref]$hCat, [IntPtr]::Zero, $Alg, [IntPtr]::Zero, 0) }
        }
        if (-not $ok) {
            $res.Err = "AcquireContext failed (LastError $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
            return $res
        }
        $fs = [IO.File]::Open($File, 'Open', 'Read', 'ReadWrite')
        try {
            $h = $fs.SafeFileHandle.DangerousGetHandle()
            $sz = 0
            if ($Alg -eq 'SHA1') { [void][DozeSec.CatSig]::CryptCATAdminCalcHashFromFileHandle($h, [ref]$sz, $null, 0) }
            else { [void][DozeSec.CatSig]::CryptCATAdminCalcHashFromFileHandle2($hCat, $h, [ref]$sz, $null, 0) }
            if ($sz -le 0) { $res.Err = 'hash size 0'; return $res }
            $buf = New-Object byte[] $sz
            $ok2 = $false
            if ($Alg -eq 'SHA1') { $ok2 = [DozeSec.CatSig]::CryptCATAdminCalcHashFromFileHandle($h, [ref]$sz, $buf, 0) }
            else { $ok2 = [DozeSec.CatSig]::CryptCATAdminCalcHashFromFileHandle2($hCat, $h, [ref]$sz, $buf, 0) }
            if (-not $ok2) { $res.Err = 'CalcHash failed'; return $res }
            $prev = [IntPtr]::Zero
            $ctx = [DozeSec.CatSig]::CryptCATAdminEnumCatalogFromHash($hCat, $buf, $sz, 0, [ref]$prev)
            if ($ctx -ne [IntPtr]::Zero) {
                $ci = New-Object DozeSec.CatSig+CATALOG_INFO
                $ci.cbStruct = [uint32][Runtime.InteropServices.Marshal]::SizeOf($ci)
                if ([DozeSec.CatSig]::CryptCATCatalogInfoFromContext($ctx, [ref]$ci, 0)) {
                    $res.Found = $true
                    $res.Catalog = $ci.wszCatalogFile
                } else { $res.Err = 'CatalogInfoFromContext failed' }
                [void][DozeSec.CatSig]::CryptCATAdminReleaseCatalogContext($hCat, $ctx, 0)
            } else { $res.Err = 'no catalog covers this file' }
        } finally { $fs.Close() }
    } catch { $res.Err = $_.Exception.Message }
    finally { if ($hCat -ne [IntPtr]::Zero) { [void][DozeSec.CatSig]::CryptCATAdminReleaseContext($hCat, 0) } }
    return $res
}

function Dump-File {
    param([string]$File)
    Line "--- $File"
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { Line '    NOT ON DISK'; return }
    $fi = Get-Item -LiteralPath $File -EA SilentlyContinue
    if ($fi) { Line "    size=$($fi.Length)  modified=$($fi.LastWriteTimeUtc.ToString('u'))" }
    $s = $null
    try { $s = Get-AuthenticodeSignature -LiteralPath $File -EA Stop } catch { Line "    Get-AuthenticodeSignature THREW: $($_.Exception.Message)" }
    if ($s) {
        Line "    Status        : $($s.Status)"
        Line "    StatusMessage : $($s.StatusMessage)"
        Line "    SignatureType : $($s.SignatureType)"
        Line "    IsOSBinary    : $($s.IsOSBinary)"
        Line "    Signer        : $($s.SignerCertificate.Subject)"
    }
    foreach ($combo in @(@('driver', 'SHA256'), @('default', 'SHA256'), @('driver', 'SHA1'))) {
        $r = Find-Catalog -File $File -Which $combo[0] -Alg $combo[1]
        $tail = if ($r.Found) { [IO.Path]::GetFileName($r.Catalog) } else { $r.Err }
        Line "    catalog[$($combo[0])/$($combo[1])] : found=$($r.Found) $tail"
        if ($r.Found) {
            $cs = $null
            try { $cs = Get-AuthenticodeSignature -LiteralPath $r.Catalog -EA Stop } catch {}
            if ($cs) { Line "      -> catalog signature Status=$($cs.Status) Signer=$($cs.SignerCertificate.Subject)" }
        }
    }
}

if ($Path) {
    Line ''
    Line '=== FOCUSED FILE ==='
    Dump-File -File $Path
}

if (-not $SkipFullScan) {
    Line ''
    Line '=== FULL SCAN of System32\drivers (this takes about a minute) ==='
    $drv = Join-Path (Join-Path $env:SystemRoot 'System32') 'drivers'
    $all = @(Get-ChildItem -LiteralPath $drv -Filter *.sys -File -EA SilentlyContinue)
    Line "Total .sys: $($all.Count)"
    $byStatus = @{}
    $notValid = @()
    foreach ($f in $all) {
        $s = $null
        try { $s = Get-AuthenticodeSignature -LiteralPath $f.FullName -EA Stop } catch {}
        $st = if ($s) { "$($s.Status)/$($s.SignatureType)" } else { 'threw/-' }
        if (-not $byStatus.ContainsKey($st)) { $byStatus[$st] = 0 }
        $byStatus[$st]++
        if (-not ($s -and $s.Status -eq 'Valid')) { $notValid += $f.FullName }
    }
    Line 'Status/SignatureType spread:'
    foreach ($k in ($byStatus.Keys | Sort-Object)) { Line "   $k = $($byStatus[$k])" }
    Line ''
    Line "NOT Valid -- the drivers driver_audit.ps1 warns about: $($notValid.Count)"
    # THIS is the number that decides between the candidates. One file means a
    # single uncovered driver; many means the catalog subsystem is the problem.
    foreach ($p in ($notValid | Select-Object -First 20)) { Dump-File -File $p }
    if ($notValid.Count -gt 20) { Line "... and $($notValid.Count - 20) more not shown" }
}

Line ''
Line '=== DONE -- send this whole output back ==='
