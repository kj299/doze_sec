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
    [string]$HashList  = '',
    [switch]$SelfTest
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

if (-not $SelfTest) {
    '--- [T1562.001/T1068] Kernel driver audit (BYOVD by hash, unsigned by signature) ---'
}
$sev = 'OK'
# Defaulted rather than read straight from the environment so -SelfTest runs on
# a box with no %SystemRoot% at all; the self-test overrides both anyway.
$script:WinDir   = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
$sys32           = $script:WinDir.TrimEnd('\') + '\System32'
$script:Sys32Drv = $sys32 + '\drivers'
# A driver is "staged" when it sits somewhere a legitimate kernel driver never
# lives. Presence there turns an abusable-but-signed driver into the actual
# BYOVD pattern.
$script:StagedRx = '\\Temp\\|\\Tmp\\|\\Downloads\\|\\Users\\Public\\|\\ProgramData\\|\\AppData\\'

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
$script:BadNames = $badNames
# Populated from the hash list below; declared here so Get-DriverVerdict can be
# defined (and self-tested) before the list is read.
$script:BadHashes = @{}

# Injectable so the self-test needs no drivers, no files and no certificates.
# There was NO injection point here before -- the signature read was inline in
# the scan loop -- so the one rule most likely to be wrong was also the one
# rule that could not be exercised by a test. The catalog false positive lived
# in exactly that blind spot.
$script:SigProbe  = {
    param($p)
    # -LiteralPath everywhere: -FilePath wildcard-expands, so a driver at
    # C:\Users\Public\vgk[1].sys (the duplicate-download form browsers produce,
    # and one an attacker can choose deliberately) matched no file and was
    # misreported as unsigned.
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $p -EA Stop } catch {}
    return $sig
}
$script:HashProbe = {
    param($p)
    try { return (Get-FileHash -LiteralPath $p -Algorithm SHA256 -EA Stop).Hash.ToLower() } catch { return $null }
}

function Get-DriverVerdict {
    # Returns @{ Sev = 'OK'|'WARNING'|'CRITICAL'; Why = @(...) }.
    #
    # Pure: every input is a parameter or a $script: variable the self-test can
    # set, so the entire grade is exercisable with no machine state at all.
    param([string]$Path, [string]$Hash, $Sig)
    $why  = @()
    $sev  = 'OK'
    # Split on both separators rather than [IO.Path]::GetFileName: that method
    # is platform-dependent -- off Windows it does not treat '\' as a
    # separator, so it returns the ENTIRE path and every known-bad NAME rule
    # silently stops matching. The self-test caught exactly that.
    $name = (($Path -split '[\\/]')[-1]).ToLower()
    $sigValid = ($Sig -and $Sig.Status -eq 'Valid')
    # Concatenate rather than Join-Path: Join-Path resolves the drive and
    # throws when it does not exist, which is machine state this pure grading
    # function must not depend on.
    $staged   = ($Path -match $script:StagedRx) -or -not ($Path -like ($script:Sys32Drv.TrimEnd('\') + '\*'))

    if ($Hash -and $script:BadHashes.ContainsKey($Hash)) {
        $why += "SHA256 matches a known-bad driver hash"
        $sev = 'CRITICAL'
    }
    if ($script:BadNames -contains $name) {
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
            $sev = Get-MaxSev $sev 'WARNING'
        } else {
            $why += "filename is a known vulnerable/abused driver, and it is unsigned, invalidly signed, or staged outside the drivers directory -- the BYOVD staging pattern"
            $sev = 'CRITICAL'
        }
    }
    if ($sev -ne 'CRITICAL' -and -not $sigValid) {
        $st = if ($Sig) { [string]$Sig.Status } else { 'unreadable' }
        $why += "unsigned or invalid Authenticode signature ($st) on a kernel driver"
        $sev = Get-MaxSev $sev 'WARNING'
    }
    return @{ Sev = $sev; Why = $why }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    function FakeSig { param([string]$Status)
        return (New-Object PSObject -Property @{ Status = $Status })
    }
    # Fixed roots so the grade does not depend on the host running the test.
    $script:Sys32Drv  = 'C:\Windows\System32\drivers'
    $script:BadHashes = @{ 'dead00000000000000000000000000000000000000000000000000000000beef' = $true }
    $normal = 'C:\Windows\System32\drivers\bthmodem.sys'
    $public = 'C:\Users\Public\dz_selftest_evil.sys'

    $v = Get-DriverVerdict -Path $normal -Hash 'aa' -Sig (FakeSig 'Valid')
    T 'a validly signed driver in the drivers directory is not a finding' `
      ($v.Sev -eq 'OK') "$($v.Sev)"

    # The shipped negative direction: an unsigned .sys must stay a finding.
    # Whatever is done about the catalog case, THIS must never stop firing --
    # being wrong here means calling a genuinely unsigned kernel driver fine.
    $v = Get-DriverVerdict -Path $public -Hash 'aa' -Sig (FakeSig 'NotSigned')
    T 'an unsigned driver in a drop location is still a WARNING' `
      ($v.Sev -eq 'WARNING') "$($v.Sev)"

    $v = Get-DriverVerdict -Path $normal -Hash 'aa' -Sig (FakeSig 'NotSigned')
    T 'an unsigned driver in the drivers directory is a WARNING' `
      ($v.Sev -eq 'WARNING') "$($v.Sev)"
    $msg = ($v.Why -join '; ')
    # tests/benign_corpus.txt [driver-catalog-signed-inbox] keys on this exact
    # wording. Reword the message and the corpus entry silently stops matching
    # -- the corpus note says so in as many words. This asserts the contract.
    $corpusRx = 'unsigned or invalid Authenticode signature \(NotSigned\) on a kernel driver'
    T 'the emitted message still matches the benign_corpus signature regex' `
      ($msg -match $corpusRx) $msg

    $v = Get-DriverVerdict -Path $normal -Hash 'aa' -Sig $null
    T 'an unreadable signature is a WARNING and says unreadable' `
      ($v.Sev -eq 'WARNING' -and ($v.Why -join '; ') -match '\(unreadable\)') "$($v.Sev): $($v.Why -join '; ')"

    $v = Get-DriverVerdict -Path $normal -Hash 'dead00000000000000000000000000000000000000000000000000000000beef' -Sig (FakeSig 'Valid')
    T 'a known-bad hash is CRITICAL even with a valid signature' `
      ($v.Sev -eq 'CRITICAL') "$($v.Sev)"

    $v = Get-DriverVerdict -Path 'C:\Windows\System32\drivers\vboxdrv.sys' -Hash 'aa' -Sig (FakeSig 'Valid')
    T 'a signed BYOVD-abusable name in the normal directory is WARNING, not CRITICAL' `
      ($v.Sev -eq 'WARNING') "$($v.Sev)"

    $v = Get-DriverVerdict -Path 'C:\Users\Public\vboxdrv.sys' -Hash 'aa' -Sig (FakeSig 'Valid')
    T 'the same name staged in a drop location is CRITICAL' `
      ($v.Sev -eq 'CRITICAL') "$($v.Sev)"

    if ($fails -gt 0) { Write-Output "FAILED: $fails"; exit 1 }
    Write-Output 'driver_audit self-test: all cases passed'
    exit 0
}

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
$script:BadHashes = $badHashes
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
    $sig  = & $script:SigProbe  $p
    $hash = & $script:HashProbe $p
    $v = Get-DriverVerdict -Path $p -Hash $hash -Sig $sig

    if ($v.Sev -ne 'OK') {
        $hs = if ($hash) { $hash.Substring(0,16) + '...' } else { '(unhashable)' }
        "[$($v.Sev)] Driver $p [$hs] -- $($v.Why -join '; ')"
        $sev = Get-MaxSev $sev $v.Sev
    }
}

if ($sev -eq 'OK') {
    "[OK] $checked kernel driver(s) audited -- none known-bad, all validly signed."
} elseif ($missing -gt 0) {
    "[INFO] $missing driver(s) could not be examined because their files are absent; $checked were fully audited."
}
Write-Marker -Name 'driver' -Sev $sev
