# TEMPORARY diagnostic -- DELETE with .github/workflows/driver-catalog-probe.yml
# once it has answered.
#
# Question: WHY does Get-AuthenticodeSignature report a Microsoft inbox driver
# (bthmodem.sys on the owner's machine) as NotSigned, and which IN-BOX
# mechanism reports it correctly? Nothing may be installed on the target
# machine, so every candidate here ships with Windows.
#
# Microsoft's Get-AuthenticodeSignature docs say catalog signatures ARE used.
# The SignTool docs say there are TWO catalog databases -- /ad (default) and
# /as (system component / driver), the latter keyed by DRIVER_ACTION_VERIFY
# {F750E6C3-38EE-11D1-85E5-00C04FC295EE}. Hypothesis: the cmdlet consults only
# the default database, so driver catalogs are missed.
#
# That is a HYPOTHESIS. This measures it on a real runner before any code is
# built on it -- the same A/B technique that broke the :dz_ps_scan deadlock.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

'=== ENV ==='
"PSVersion     : $($PSVersionTable.PSVersion)"
"LanguageMode  : $($ExecutionContext.SessionState.LanguageMode)"
"OS            : $([Environment]::OSVersion.Version)"

'=== M0: does Add-Type compile at all? (the lock-down question) ==='
$swAdd = [Diagnostics.Stopwatch]::StartNew()
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
    "Add-Type FAILED: $($_.Exception.Message)"
}
$swAdd.Stop()
"Add-Type compiled : $catOk  ($($swAdd.ElapsedMilliseconds) ms)"

# Find the catalog holding a file, in a NAMED database.
#   Which = 'driver'  -> DRIVER_ACTION_VERIFY subsystem GUID
#   Which = 'default' -> NULL subsystem (the default catalog database)
function Find-Catalog {
    param([string]$Path, [string]$Which, [string]$Alg)
    $res = @{ Found = $false; Catalog = ''; Err = '' }
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
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
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
            } else { $res.Err = 'no catalog for hash' }
        } finally { $fs.Close() }
    } catch { $res.Err = $_.Exception.Message }
    finally { if ($hCat -ne [IntPtr]::Zero) { [void][DozeSec.CatSig]::CryptCATAdminReleaseContext($hCat, 0) } }
    return $res
}

'=== M5: Win32_PnPSignedDriver coverage ==='
try {
    $pnp = @(Get-CimInstance Win32_PnPSignedDriver -EA Stop)
    "Win32_PnPSignedDriver rows: $($pnp.Count)"
    "  signed rows: $(@($pnp | Where-Object { $_.IsSigned }).Count)"
} catch { "Win32_PnPSignedDriver FAILED: $($_.Exception.Message)" }

'=== M6: driverquery /si ==='
try { & driverquery.exe /si /fo csv 2>&1 | Select-Object -First 4 | ForEach-Object { "  $_" } }
catch { "driverquery FAILED: $($_.Exception.Message)" }

'=== SCAN: drivers\*.sys that Get-AuthenticodeSignature does NOT call Valid ==='
$drv = Join-Path (Join-Path $env:SystemRoot 'System32') 'drivers'
$all = @(Get-ChildItem -LiteralPath $drv -Filter *.sys -File -EA SilentlyContinue)
"Total .sys in drivers dir: $($all.Count)"
$swSig = [Diagnostics.Stopwatch]::StartNew()
$notValid = @()
foreach ($f in $all) {
    $s = $null
    try { $s = Get-AuthenticodeSignature -LiteralPath $f.FullName -EA Stop } catch {}
    if (-not ($s -and $s.Status -eq 'Valid')) { $notValid += [pscustomobject]@{ File = $f; Sig = $s } }
}
$swSig.Stop()
"Get-AuthenticodeSignature over all: $($swSig.ElapsedMilliseconds) ms"
"NOT Valid (today's false-positive set): $($notValid.Count)"

'=== M2: does the 5.1 Signature object expose SignatureType / IsOSBinary? ==='
$probeSig = Get-AuthenticodeSignature -LiteralPath $all[0].FullName
$props = @($probeSig | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)
"Signature properties: $($props -join ', ')"
"Has SignatureType : $($props -contains 'SignatureType')"
"Has IsOSBinary    : $($props -contains 'IsOSBinary')"
if ($props -contains 'SignatureType') {
    $spread = @($all | Select-Object -First 40 | ForEach-Object {
        [string](Get-AuthenticodeSignature -LiteralPath $_.FullName).SignatureType
    }) | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }
    "SignatureType spread over first 40: $($spread -join ' ')"
}

'=== PER-FILE: every mechanism, on the files that fail today ==='
if ($notValid.Count -eq 0) {
    '!! No NotSigned drivers on this runner -- the false positive does not reproduce here.'
}
$swCat = [Diagnostics.Stopwatch]::StartNew()
$tally = @{ drvSha256 = 0; drvSha1 = 0; defSha256 = 0; catValid = 0 }
foreach ($e in ($notValid | Select-Object -First 25)) {
    $p = $e.File.FullName
    $st = if ($e.Sig) { [string]$e.Sig.Status } else { 'unreadable' }
    "--- $($e.File.Name)  [M1 Status=$st]"
    if ($props -contains 'SignatureType') {
        "    M2 SignatureType=$($e.Sig.SignatureType) IsOSBinary=$($e.Sig.IsOSBinary)"
    }
    if (-not $catOk) { continue }
    $r3 = Find-Catalog -Path $p -Which 'driver'  -Alg 'SHA256'
    $r4 = Find-Catalog -Path $p -Which 'default' -Alg 'SHA256'
    $r5 = Find-Catalog -Path $p -Which 'driver'  -Alg 'SHA1'
    "    M3 driver/SHA256 : found=$($r3.Found) $(if($r3.Found){[IO.Path]::GetFileName($r3.Catalog)}else{$r3.Err})"
    "    M4 default/SHA256: found=$($r4.Found) $(if($r4.Found){[IO.Path]::GetFileName($r4.Catalog)}else{$r4.Err})"
    "    M3 driver/SHA1   : found=$($r5.Found) $(if($r5.Found){[IO.Path]::GetFileName($r5.Catalog)}else{$r5.Err})"
    if ($r3.Found) {
        $tally.drvSha256++
        $cs = Get-AuthenticodeSignature -LiteralPath $r3.Catalog
        "    -> catalog signature: Status=$($cs.Status) Signer=$($cs.SignerCertificate.Subject)"
        if ($cs.Status -eq 'Valid') { $tally.catValid++ }
    }
    if ($r5.Found) { $tally.drvSha1++ }
    if ($r4.Found) { $tally.defSha256++ }
}
$swCat.Stop()

'=== TALLY (over the probed subset) ==='
"driver DB / SHA256 resolved  : $($tally.drvSha256)"
"  of those, catalog is Valid : $($tally.catValid)"
"driver DB / SHA1   resolved  : $($tally.drvSha1)"
"default DB / SHA256 resolved : $($tally.defSha256)"
"catalog lookup wall clock    : $($swCat.ElapsedMilliseconds) ms"
