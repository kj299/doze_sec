# driver_audit.ps1 -- kernel driver audit for BYOVD and unsigned kernel code
# (T1562.001 / T1068). Invoked from Section 17. Replaces the old 12-filename
# Test-Path scan that any attacker defeated by renaming the file.
#
# WHAT THE OLD CHECK DID WRONG
#   $byovd = @('RTCore64.sys', ...12 names...)
#   if (Test-Path "$drivers\$name") { hit }
# Three fatal weaknesses: (1) matched by FILENAME, so `copy RTCore64.sys
# a.sys` was invisible; (2) looked only in System32\drivers, so a driver
# loaded from anywhere else was invisible; (3) twelve names against a known
# universe of ~1500 vulnerable drivers -- effectively zero coverage.
#
# WHAT THIS DOES
#   Enumerates BOTH loaded drivers (Win32_SystemDriver PathName) AND on-disk
#   .sys files under the drivers tree and the common drop locations, then
#   judges each THREE independent ways so no single rename/move/resign evades
#   all of them:
#     1. SHA256 vs the known-bad hash list (ThreatLists\ioc_hashes.txt, which
#        already carries BYOVD driver hashes). Hash identity survives any
#        rename or relocation -- the direct fix for weakness (1)/(2).  CRITICAL.
#     2. Filename vs an expanded known-vulnerable-driver name set. Catches a
#        known driver whose hash is a variant not yet in the list.  CRITICAL.
#     3. Authenticode. A kernel driver that is unsigned or has an invalid /
#        unverifiable signature is inherently suspicious regardless of name --
#        this is the catch-all that a renamed, not-yet-listed malicious driver
#        cannot escape.  WARNING (validly-signed third-party drivers -- GPU,
#        audio, VPN, AV -- are normal and stay OK).
#
# WHY NOT the full Microsoft vulnerable-driver blocklist (~1500 entries): it is
# not shippable offline as data here and changes often. Hash matching against
# the maintained ioc_hashes.txt list (refreshable with -updateTTP) plus the
# signature catch-all covers the same ground for the drivers that are actually
# present, and degrades honestly (a hash not in the list still trips the
# signature check if the driver is unsigned).
#
# MARKER: writes the max severity word to $env:TEMP\dz_driver.txt; the caller
# raises via :dz_finding. No marker when clean.
#
# Windows PowerShell 5.1 compatible. Read-only (enumeration + hashing of files
# already on disk; never downloads or executes anything). helpers-ps51 CI runs
# the clean-runner path; the detection harness plants a fake unsigned driver.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [string]$HashList  = ''
)

$ErrorActionPreference = 'Continue'

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
function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

'--- [T1562.001/T1068] Kernel driver audit (BYOVD by hash, unsigned by signature) ---'
$sev = 'OK'
$sys32 = Join-Path $env:SystemRoot 'System32'

# Expanded known-vulnerable-driver filename set (superset of the old 12). Names
# are a fallback signal; the hash and signature checks are the primary ones.
$badNames = @(
    'rtcore64.sys','dbutil_2_3.sys','dbutildrv2.sys','gdrv.sys','gdrv2.sys',
    'cpuz141.sys','cpuz.sys','asio.sys','asio64.sys','asio2.sys','asio3.sys',
    'hw64.sys','winio64.sys','winio.sys','winring0x64.sys','winring0.sys',
    'iqvw64e.sys','iqvw64.sys','kprocesshacker.sys','procexp152.sys','procexp.sys',
    'zemana.sys','viragt64.sys','viragt.sys','mhyprot2.sys','mhyprot3.sys',
    'aswarpot.sys','truesight.sys','pcdsrvc.sys','pcdsrvc_x64.sys','nscm.sys',
    'atillk64.sys','elrawdsk.sys','ene.sys','enetechio64.sys','glckio2.sys',
    'msio64.sys','physmem.sys','rtkiow8x64.sys','rtkiow10x64.sys','speedfan.sys',
    'segwindrvx64.sys','vboxdrv.sys','wcpu.sys','ucorew64.sys','amifldrv64.sys'
) | ForEach-Object { $_.ToLower() }

# Known-bad SHA256 set from the maintained hash list (default location resolved
# relative to this script so it works from any CWD).
if (-not $HashList) {
    $HashList = Join-Path (Split-Path -Parent $PSCommandPath) '..\ThreatLists\ioc_hashes.txt'
}
$badHashes = @{}
$malformedHashes = @()
if (Test-Path -LiteralPath $HashList) {
    foreach ($ln in (Get-Content -LiteralPath $HashList -EA SilentlyContinue)) {
        $t = $ln.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $h = ($t -split '\|')[0].Trim().ToLower()
        # A malformed hash must never fail SILENTLY: an entry that does not load
        # is a detection this tool claims to have and does not. Count and report
        # them -- a 65-char DBUtil_2_3.sys hash sat unnoticed in this list until a
        # retrospective found it, meaning that BYOVD driver was never matched by
        # hash at all (the filename rule still covered it, but the hash path --
        # the one that survives renaming -- was dead).
        if ($h -match '^[0-9a-f]{64}$') { $badHashes[$h] = $true }
        elseif ($h -match '^[0-9a-fA-F]{8,}$') { $malformedHashes += $h }
    }
}
if ($malformedHashes.Count -gt 0) {
    "[WARNING] $($malformedHashes.Count) entr(y/ies) in the known-bad hash list are not valid SHA256 values and were NOT loaded -- those drivers are not covered by hash matching. Fix the list: $((@($malformedHashes | ForEach-Object { $_.Substring(0, [Math]::Min(12, $_.Length)) + '...' })) -join ', ')"
    $sev = Get-MaxSev $sev 'WARNING'
}

# Build the candidate set: loaded drivers (authoritative -- these are running in
# the kernel right now) plus on-disk .sys under the drivers tree and the drop
# locations malware favours. Deduplicated by full path.
$paths = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
try {
    foreach ($d in (Get-CimInstance Win32_SystemDriver -EA Stop)) {
        $pn = [string]$d.PathName
        if ($pn) {
            $pn = $pn -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
            [void]$paths.Add([Environment]::ExpandEnvironmentVariables($pn))
        }
    }
} catch {
    '[SKIPPED] Win32_SystemDriver enumeration failed -- loaded-driver set not audited.'
    $sev = Get-MaxSev $sev 'WARNING'
}
# The loaded set above is the authoritative one (a BYOVD has to be loaded to
# kill EDR). On-disk scanning targets where a driver is STAGED before loading:
# the flat drivers dir (drivers live directly here, not in its subtrees) is
# enumerated shallowly, and the temp/public drop locations recursively -- both
# bounded, so this never turns into a multi-thousand-file DriverStore hash walk
# that would blow the CI time budget.
$shallowDirs = @( (Join-Path $sys32 'drivers') )
$dropDirs    = @( $env:TEMP, (Join-Path $env:SystemRoot 'Temp'), 'C:\Users\Public' )
foreach ($dir in $shallowDirs) {
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter '*.sys' -File -EA SilentlyContinue)) {
            if ($f.Extension -ieq '.sys') { [void]$paths.Add($f.FullName) }
        }
    } catch {}
}
foreach ($dir in $dropDirs) {
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    try {
        # -Filter, NOT -Include: with -LiteralPath -Recurse, -Include is silently
        # ignored and EVERY file is returned (then Authenticode-checked as a bogus
        # "driver"). -Filter is applied by the provider and actually restricts to
        # .sys. Belt-and-braces: re-check the extension in PS too.
        foreach ($f in (Get-ChildItem -LiteralPath $dir -Recurse -Filter '*.sys' -File -EA SilentlyContinue)) {
            if ($f.Extension -ieq '.sys') { [void]$paths.Add($f.FullName) }
        }
    } catch {}
}

# A driver is "staged" when it sits somewhere a legitimate kernel driver never
# lives. Presence there turns an abusable-but-signed driver into the actual
# BYOVD pattern.
$stagedRx = '\\Temp\\|\\Tmp\\|\\Downloads\\|\\Users\\Public\\|\\ProgramData\\|\\AppData\\'
$sys32drv = Join-Path (Join-Path $env:SystemRoot 'System32') 'drivers'

$checked = 0
$missing = 0
foreach ($p in $paths) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        # A LOADED driver whose file is gone is not a non-event -- it is the
        # load-then-delete BYOVD pattern: create the service, start the driver
        # (the image stays mapped in the kernel), delete the .sys so there is
        # nothing left to hash. Win32_SystemDriver still enumerates it, so it
        # reaches this loop and used to be dropped by a bare `continue` -- no
        # counter, no output -- after which the all-clear below was printed
        # unqualified. The absence IS the finding.
        $missing++
        "[WARNING] Driver $p is registered/loaded but its file is NOT on disk -- the load-then-delete pattern used to stage a vulnerable driver and then remove the evidence (T1562.001). It cannot be hashed or signature-checked; investigate the owning service."
        $sev = Get-MaxSev $sev 'WARNING'
        continue
    }
    $checked++
    $name = [System.IO.Path]::GetFileName($p).ToLower()
    $why = @()
    $itemSev = 'OK'

    # -LiteralPath everywhere: -FilePath wildcard-expands, so a driver at
    # C:\Users\Public\vgk[1].sys (the duplicate-download form browsers produce,
    # and one an attacker can choose deliberately) matched no file and was
    # misreported as unsigned.
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $p -EA Stop } catch {}
    $sigValid = ($sig -and $sig.Status -eq 'Valid')
    $staged = ($p -match $stagedRx) -or -not ($p -like (Join-Path $sys32drv '*'))

    $hash = $null
    try { $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -EA Stop).Hash.ToLower() } catch {}
    if ($hash -and $badHashes.ContainsKey($hash)) {
        $why += "SHA256 matches a known-bad driver hash"
        $itemSev = 'CRITICAL'
    }
    if ($badNames -contains $name) {
        # These names ARE genuinely BYOVD-abusable -- but several of them ship
        # with software people deliberately install (vboxdrv.sys with
        # VirtualBox, procexp152.sys with Process Explorer, cpuz141.sys,
        # gdrv.sys, asio64.sys). The old rule set CRITICAL on the name alone
        # and then SKIPPED the signature check entirely, so a validly
        # vendor-signed driver in its normal location produced "CRITICAL
        # findings present -- review NOW" and exit code 8 on a healthy
        # developer machine. A tool that cries wolf there is not believed the
        # day it is right. So: attack surface and evidence of compromise are
        # reported differently, as they already are for ADFS / Azure AD Connect.
        if ($sigValid -and -not $staged) {
            $why += "known BYOVD-abusable driver, but validly signed and in the normal drivers directory -- most likely installed by legitimate software. A local attacker can still abuse it to load unsigned kernel code; remove it if you do not need the software that installed it"
            $itemSev = Get-MaxSev $itemSev 'WARNING'
        } else {
            $why += "filename is a known vulnerable/abused driver, and it is unsigned, invalidly signed, or staged outside the drivers directory -- the BYOVD staging pattern"
            $itemSev = 'CRITICAL'
        }
    }
    if ($itemSev -ne 'CRITICAL' -and -not $sigValid) {
        $st = if ($sig) { [string]$sig.Status } else { 'unreadable' }
        $why += "unsigned or invalid Authenticode signature ($st) on a kernel driver"
        $itemSev = Get-MaxSev $itemSev 'WARNING'
    }

    if ($itemSev -ne 'OK') {
        $hs = if ($hash) { $hash.Substring(0,16) + '...' } else { '(unhashable)' }
        "[$itemSev] Driver $p [$hs] -- $($why -join '; ')"
        $sev = Get-MaxSev $sev $itemSev
    }
}

if ($sev -eq 'OK') {
    "[OK] $checked kernel driver(s) audited -- none known-bad, all validly signed."
} elseif ($missing -gt 0) {
    "[INFO] $missing driver(s) could not be examined because their files are absent; $checked were fully audited."
}
Write-Marker -Name 'driver' -Sev $sev
