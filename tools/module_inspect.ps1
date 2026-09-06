# module_inspect.ps1 -- inspect the DLLs actually loaded inside running
# processes (T1055 process injection / T1574 DLL hijacking). Invoked from
# Section 4.
#
# WHY: every persistence check in this audit reads a registry key or a file on
# disk. An implant that lives only inside another process's address space --
# reflectively loaded, injected into a signed host, or side-loaded next to a
# legitimate EXE -- touches none of those. Section 4 previously enumerated
# process NAMES and PATHS but never looked at what those processes had LOADED,
# so a signed, trusted-looking svchost.exe hosting a malicious DLL passed clean.
# This closes the fileless/injection blind spot from the on-host side.
#
# WHAT IS FLAGGED
#   CRITICAL  A module loaded from a staging path (\Temp\, \Downloads\,
#             \Public\, \ProgramData\update) -- legitimate software does not
#             load its DLLs from there.
#   CRITICAL  An unsigned or invalid-signature module inside a CORE SECURITY
#             process (lsass, winlogon, services, csrss, smss, wininit). A
#             non-Microsoft DLL in lsass is the classic credential-theft shape
#             (password filter, injected stealer).
#   WARNING   A validly-signed NON-Microsoft module inside a core security
#             process (legitimate for some EDR/smartcard/MFA vendors, so it is
#             reported for review rather than raised to critical).
#   COUNTED   Unsigned modules elsewhere. NOT itemised: plenty of legitimate
#             software ships unsigned DLLs, and CI alone produced a screenful
#             from the build agent's own binaries. A report listing hundreds of
#             them is one nobody can triage, and it buries the findings that
#             matter -- so they are summarised as a count the user can act on if
#             they have other reason for concern.
#
# NOT FLAGGED -- deliberately:
#   * A process's OWN executable (Modules[0]). A process running from a
#     suspicious path is a real finding, but it is a DIFFERENT finding that
#     Section 4 already makes; calling it an injected module double-reports it
#     and is a category error.
#   * .NET NGEN native images (\Windows\assembly\NativeImages_*), which are
#     compiled locally from already-validated assemblies and are unsigned by
#     design.
#
# APPLICATION VIRTUALIZATION -- "not on disk" is not the same as "unbacked".
# The first field run with Microsoft Word open produced FOURTEEN warnings of the
# form "Module C:\Program Files\Common Files\Microsoft Shared\Office16\mso.dll
# -- module is mapped into the process but its file is NOT on disk -- reflective
# or unbacked load ... (T1055)". The tool was telling its owner that Word was
# running fourteen in-memory-injected modules on a clean machine. A false "you
# are compromised" is the most harmful output this tool can produce.
#
# Office Click-to-Run executes in a virtual application environment: the
# products have PRIVATE COPIES of their files, and the real file lives under
# <install>\root\VFS\ProgramFilesCommonX64\Microsoft Shared\Office16\. WINWORD
# reports the VIRTUAL path, which exists only inside the process's own view, so
# a bare Test-Path from outside says "not on disk" for a perfectly ordinary
# Microsoft DLL. MSIX/WindowsApps packages use the same VFS layout.
#
# So, before declaring a module absent, the reported path is retried under the
# Click-to-Run VFS root (discovered from the registry -- never a hard-coded
# path) using Microsoft's documented folder mapping. If it resolves there, it is
# backed: its signature is verified AT THE REAL PATH and it is graded normally.
#
# When it still does not resolve, the wording stops overclaiming. A module with
# a plausible SYSTEM path that is simply not visible from outside is not the
# same finding as one with no backing file anywhere, and the two causes --
# virtualization, or a file deleted after loading -- are indistinguishable from
# here. The full T1055 "reflective or unbacked load" wording is reserved for the
# latter shape. The downgrade is deliberately asymmetric, as in psv2_check: a
# module under a staging path keeps its CRITICAL, and a module under a
# non-system path keeps the full T1055 treatment. Only the "plausible system
# path, not visible from outside" case is downgraded -- and it is downgraded to
# STATED UNCERTAINTY, not to silence.
#
# LSASS AND PPL: when LSA Protection (RunAsPPL) is enabled, lsass module
# enumeration is denied to everything -- including this tool. That is the
# protection WORKING, not a coverage gap, so it is reported as [OK] with the
# reason rather than as a failure. When PPL is OFF and enumeration still fails,
# it is reported [SKIPPED] so the blindness is visible.
#
# PERFORMANCE: the same DLL is loaded by dozens of processes, so module paths
# are DEDUPLICATED and each unique file is Authenticode-checked exactly once,
# cached by path. Without that this would take many minutes on a normal desktop.
# The number of unique files checked is capped (-MaxModules) and the cap is
# reported if hit -- a silent truncation would read as "all clear".
#
# MARKER: severity word to $env:TEMP\dz_module.txt; caller raises via
# :dz_finding. No marker when clean.
#
# Windows PowerShell 5.1 compatible. Read-only (enumeration + Authenticode of
# files already on disk). Executed by the helpers-ps51 CI job.

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
    [int]$MaxModules = 2500,
    [int]$MaxReport = 25,
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

$badPathRx = '\\Temp\\|\\Downloads\\|\\Public\\|\\ProgramData\\update'
$coreProcs = @('lsass', 'winlogon', 'services', 'csrss', 'smss', 'wininit')

# Paths where a MISSING file is ambiguous rather than damning: the locations an
# application-virtualization layer redirects. A module claiming to live here and
# not being visible is exactly what Office C2R and MSIX produce.
$script:SystemishRx = '^[A-Za-z]:\\Program Files|\\WindowsApps\\|^[A-Za-z]:\\Windows\\'

# ---------------------------------------------------------------------------
# Application virtualization (Office Click-to-Run, MSIX): resolving a virtual
# path to the real file. Microsoft's documented VFS mapping -- FOLDERID_* to a
# folder name under <package_root>\VFS.
# ---------------------------------------------------------------------------

function New-VfsMap {
    # Built from the environment, never hard-coded: the drive and the
    # "Program Files" folder name are both localisable/relocatable.
    param([hashtable]$EnvMap)
    $pairs = @(
        @{ K = 'CommonProgramW6432';     F = 'ProgramFilesCommonX64' },
        @{ K = 'CommonProgramFiles';     F = 'ProgramFilesCommonX64' },
        @{ K = 'CommonProgramFiles(x86)'; F = 'ProgramFilesCommonX86' },
        @{ K = 'ProgramW6432';           F = 'ProgramFilesX64' },
        @{ K = 'ProgramFiles';           F = 'ProgramFilesX64' },
        @{ K = 'ProgramFiles(x86)';      F = 'ProgramFilesX86' }
    )
    $map = @()
    foreach ($p in $pairs) {
        $v = $EnvMap[$p.K]
        if ($v) { $map += @{ Prefix = $v.TrimEnd('\'); Folder = $p.F } }
    }
    $win = $EnvMap['SystemRoot']
    if ($win) {
        $win = $win.TrimEnd('\')
        $map += @{ Prefix = ($win + '\System32'); Folder = 'SystemX64' }
        $map += @{ Prefix = ($win + '\SysWOW64'); Folder = 'SystemX86' }
        $map += @{ Prefix = $win;                 Folder = 'Windows' }
    }
    # A 32-bit host reports the same value under two names; keep one entry per
    # prefix so a path does not produce duplicate candidates.
    $seen = @{}
    $uniq = @()
    foreach ($m in $map) {
        $k = $m.Prefix.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $uniq += $m
    }
    # LONGEST PREFIX FIRST. "Common Files" must win over "Program Files", and
    # System32 over Windows -- matched in the wrong order, mso.dll maps to
    # VFS\ProgramFilesX64\Common Files\..., which does not exist, and the
    # false positive survives.
    return @($uniq | Sort-Object @{ Expression = { $_.Prefix.Length }; Descending = $true })
}

function Get-VfsCandidates {
    param([string]$Path, $Map, [string[]]$Roots)
    $out = @()
    if (-not $Path -or -not $Map -or -not $Roots -or @($Roots).Count -eq 0) { return $out }
    foreach ($m in $Map) {
        if (-not $Path.StartsWith(($m.Prefix + '\'), [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $rest = $Path.Substring($m.Prefix.Length).TrimStart('\')
        foreach ($r in $Roots) {
            if (-not $r) { continue }
            $out += ($r.TrimEnd('\') + '\' + $m.Folder + '\' + $rest)
        }
        break
    }
    return $out
}

function Resolve-VfsPath {
    param([string]$Path, $Map, [string[]]$Roots, [scriptblock]$Exists)
    if (-not $Exists) { $Exists = { param($p) Test-Path -LiteralPath $p -PathType Leaf } }
    foreach ($c in (Get-VfsCandidates -Path $Path -Map $Map -Roots $Roots)) {
        if (& $Exists $c) { return $c }
    }
    return $null
}

$script:VfsRoots = $null
function Get-VfsRoots {
    if ($null -ne $script:VfsRoots) { return $script:VfsRoots }
    $roots = New-Object System.Collections.Generic.List[string]
    # Discovered from the registry -- the install location is configurable and a
    # hard-coded C:\Program Files\Microsoft Office would be wrong on any machine
    # that moved it, which is precisely the machine whose Office DLLs would then
    # be reported as injected.
    $sources = @(
        @{ Key = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun';               Name = 'InstallPath' },
        @{ Key = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'; Name = 'InstallationPath' },
        @{ Key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun';   Name = 'InstallPath' }
    )
    foreach ($s in $sources) {
        $ip = $null
        try { $ip = (Get-ItemProperty -LiteralPath $s.Key -Name $s.Name -EA SilentlyContinue).($s.Name) } catch {}
        if (-not $ip) { continue }
        $ip = ([string]$ip).TrimEnd('\')
        foreach ($cand in @(($ip + '\root\VFS'), ($ip + '\VFS'))) {
            if ((Test-Path -LiteralPath $cand -PathType Container) -and -not $roots.Contains($cand)) { $roots.Add($cand) }
        }
    }
    $script:VfsRoots = @($roots.ToArray())
    # `return @()` from a PowerShell function yields $NULL, not an empty array
    # -- the pipeline unrolls it. The caller then does @($null), which is a
    # ONE-element array containing null, and the loop body runs on a null. On
    # every machine WITHOUT Office (most of them, and every CI runner) that
    # threw twice per process into the audit report. The comma operator
    # suppresses the unroll.
    return ,$script:VfsRoots
}

function Get-HostVfsRoot {
    # Find a package root from the LOADING PROCESS's own image path, with no
    # product name and no registry: an application-virtualization package puts
    # its redirected tree in a "VFS" folder at the package root, so the first
    # ancestor of the executable that has a VFS subdirectory IS the package
    # root. Office C2R (<install>\root\Office16\WINWORD.EXE -> <install>\root\VFS)
    # and MSIX both follow it.
    #
    # This is the primary discovery path precisely because it does not depend on
    # HKLM:\SOFTWARE\Microsoft\Office\ClickToRun being readable or present. If
    # it did, a machine where that key is missing would get its Office DLLs
    # reported as injected -- the exact failure being fixed.
    param([string]$ImagePath, [scriptblock]$DirExists)
    if (-not $ImagePath) { return $null }
    if (-not $DirExists) { $DirExists = { param($p) Test-Path -LiteralPath $p -PathType Container } }
    $d = $ImagePath
    for ($i = 0; $i -lt 8; $i++) {
        $cut = $d.LastIndexOf('\')
        if ($cut -lt 3) { break }
        $d = $d.Substring(0, $cut)
        $cand = $d + '\VFS'
        if (& $DirExists $cand) { return $cand }
    }
    return $null
}

function Add-VfsRoot {
    param([string]$Root)
    if (-not $Root) { return }
    if ($null -eq $script:VfsRoots) { $script:VfsRoots = @() }
    foreach ($r in $script:VfsRoots) { if ($r -ieq $Root) { return } }
    $script:VfsRoots = @($script:VfsRoots + $Root)
}

function Test-VirtualizedHost {
    # Is the LOADING process itself running out of a virtualized package? If it
    # is, a virtual module path from it is expected, not an anomaly.
    param([string]$ImagePath, [string[]]$Roots)
    if (-not $ImagePath) { return $false }
    if ($ImagePath -match '\\WindowsApps\\') { return $true }
    foreach ($r in @($Roots)) {
        if (-not $r) { continue }
        # The VFS root is <package>\VFS; the package's own binaries sit under
        # <package>, its parent.
        $pkg = ($r.TrimEnd('\'))
        $pkg = $pkg.Substring(0, [Math]::Max(0, $pkg.LastIndexOf('\')))
        if ($pkg -and $ImagePath.StartsWith(($pkg + '\'), [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-UnbackedVerdict {
    # The classification the 14 WINWORD warnings got wrong. Returns the severity
    # and the sentence for a module whose file could not be found -- INFO means
    # printed as context and NOT raised.
    param([string]$Path, [bool]$AllOwnersVirtualized)
    if ($AllOwnersVirtualized) {
        return @{
            Sev = 'INFO'
            Reason = 'reported path is not visible on disk, and every process that loaded it runs from a virtualized package (Office Click-to-Run / MSIX). Those packages keep private copies of their files under <package>\VFS\, so the path a process reports exists only inside its own view. Context, not an injection signal -- confirm with: (Get-ItemProperty ''HKLM:\SOFTWARE\Microsoft\Office\ClickToRun'').InstallPath'
        }
    }
    if ($Path -match $script:SystemishRx) {
        return @{
            Sev = 'WARNING'
            Reason = 'mapped into the process but not visible on disk at that path. Two causes look identical from outside: application virtualization (Office Click-to-Run, MSIX/WindowsApps) redirecting a system path, or a module whose file was deleted after loading. NOT asserted to be an injection -- check whether the loading process runs from a virtualized package before treating it as one'
        }
    }
    return @{
        Sev = 'WARNING'
        Reason = 'module is mapped into the process but its file is NOT on disk -- reflective or unbacked load, the standard in-memory injection pattern (T1055)'
    }
}

$sigCache = @{}

# Injectable probes. The two filesystem touches this tool makes go through
# these so the self-test can exercise Get-SigVerdict ITSELF -- the function that
# shipped the fourteen WINWORD warnings -- rather than only the helper it now
# calls. A self-test that proves the helper works while the caller still runs a
# bare Test-Path proves nothing about the bug.
$script:ExistsProbe = { param($p) Test-Path -LiteralPath $p -PathType Leaf }
$script:SigProbe    = { param($p) Get-FileSigVerdict -FilePath $p }

function Get-FileSigVerdict {
    param([string]$FilePath)
    $r = @{ Valid = $false; MsSigned = $false; Why = 'unreadable' }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $FilePath -EA Stop } catch {}
    if ($sig -and $sig.Status -eq 'Valid') {
        $r.Valid = $true
        $r.MsSigned = ($sig.SignerCertificate.Subject -match '\bMicrosoft\b|\bWindows\b')
        $cn = (($sig.SignerCertificate.Subject -split ',')[0]) -replace '^CN=', ''
        $r.Why = "signed by $cn"
    } else {
        $st = 'NotSigned'
        if ($sig) { $st = [string]$sig.Status }
        $r.Why = "unsigned or invalid signature ($st)"
    }
    return $r
}

function Get-SigVerdict {
    param([string]$FilePath)
    if ($sigCache.ContainsKey($FilePath)) { return $sigCache[$FilePath] }
    if (& $script:ExistsProbe $FilePath) {
        $r = & $script:SigProbe $FilePath
    } else {
        # Before calling a module absent, try to resolve it through the
        # virtualization layer. A file that resolves there IS backed, and is
        # graded on the signature of the real file.
        $real = Resolve-VfsPath -Path $FilePath -Map $script:VfsMap -Roots (Get-VfsRoots) -Exists $script:ExistsProbe
        if ($real) {
            $r = & $script:SigProbe $real
            $r.Why = $r.Why + ' (resolved through the Click-to-Run/MSIX virtual file system)'
        } else {
            $r = @{ Valid = $false; MsSigned = $false; Why = 'module file not found on disk (possible reflective/unbacked load)' }
        }
    }
    $sigCache[$FilePath] = $r
    return $r
}

# ---------------------------------------------------------------------------
# Self-test. Pure string/logic assertions with the file-existence probe
# injected, so it runs anywhere -- there is no Office on a CI runner and the
# owner's machine is the only place the real path can be proven.
# ---------------------------------------------------------------------------
if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    $fakeEnv = @{
        'ProgramFiles'            = 'C:\Program Files'
        'ProgramFiles(x86)'       = 'C:\Program Files (x86)'
        'CommonProgramFiles'      = 'C:\Program Files\Common Files'
        'CommonProgramFiles(x86)' = 'C:\Program Files (x86)\Common Files'
        'SystemRoot'              = 'C:\Windows'
    }
    $map = New-VfsMap -EnvMap $fakeEnv
    $roots = @('C:\Program Files\Microsoft Office\root\VFS')
    $mso = 'C:\Program Files\Common Files\Microsoft Shared\Office16\mso.dll'

    # The map must come back LONGEST PREFIX FIRST. Today the insertion order
    # happens to be right, so a lost sort would not change any mapping result --
    # and a reordering of the pairs table later would silently reintroduce the
    # false positive. Assert the property, not its accidental consequence.
    $lens = @($map | ForEach-Object { $_.Prefix.Length })
    $sorted = $true
    for ($n = 1; $n -lt $lens.Count; $n++) { if ($lens[$n] -gt $lens[$n-1]) { $sorted = $false } }
    T 'the VFS prefix table is ordered longest-first' $sorted ($lens -join ',')

    $c = @(Get-VfsCandidates -Path $mso -Map $map -Roots $roots)
    T 'the real WINWORD module path maps into VFS\ProgramFilesCommonX64' `
      ($c.Count -eq 1 -and $c[0] -eq 'C:\Program Files\Microsoft Office\root\VFS\ProgramFilesCommonX64\Microsoft Shared\Office16\mso.dll') `
      ($c -join ' | ')

    # Longest prefix first, or Common Files maps under ProgramFilesX64 and
    # nothing resolves -- the false positive survives silently.
    T 'Common Files wins over Program Files (longest prefix first)' `
      ($c.Count -eq 1 -and $c[0] -notmatch 'ProgramFilesX64') ($c -join ' | ')

    $c2 = @(Get-VfsCandidates -Path 'C:\Windows\System32\foo.dll' -Map $map -Roots $roots)
    T 'System32 maps to SystemX64, not Windows\System32' `
      ($c2.Count -eq 1 -and $c2[0] -eq 'C:\Program Files\Microsoft Office\root\VFS\SystemX64\foo.dll') ($c2 -join ' | ')

    $c3 = @(Get-VfsCandidates -Path 'C:\Program Files (x86)\Common Files\Microsoft Shared\VBA\VBA7.1\VBE7.DLL' -Map $map -Roots $roots)
    T 'the x86 Common Files tree maps to ProgramFilesCommonX86' `
      ($c3.Count -eq 1 -and $c3[0] -match '\\VFS\\ProgramFilesCommonX86\\Microsoft Shared\\VBA\\') ($c3 -join ' | ')

    $c4 = @(Get-VfsCandidates -Path 'C:\Users\u\AppData\Local\Evil\x.dll' -Map $map -Roots $roots)
    T 'a user-profile path has no VFS mapping at all' ($c4.Count -eq 0) ($c4 -join ' | ')

    $c5 = @(Get-VfsCandidates -Path $mso -Map $map -Roots @())
    T 'with no Click-to-Run installed nothing is resolved' ($c5.Count -eq 0) ($c5 -join ' | ')

    $hit = Resolve-VfsPath -Path $mso -Map $map -Roots $roots -Exists { param($p) $p -match 'ProgramFilesCommonX64' }
    T 'a module that exists under VFS resolves to the real file' ($null -ne $hit) ([string]$hit)
    $miss = Resolve-VfsPath -Path $mso -Map $map -Roots $roots -Exists { param($p) $false }
    T 'a module that exists nowhere does NOT resolve' ($null -eq $miss) ([string]$miss)

    $dirs = @{ 'C:\Program Files\Microsoft Office\root\VFS' = $true }
    $hr = Get-HostVfsRoot -ImagePath 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE' -DirExists { param($p) $dirs.ContainsKey($p) }
    T 'the package root is found from WINWORD.EXE alone, with no registry' `
      ($hr -eq 'C:\Program Files\Microsoft Office\root\VFS') ([string]$hr)
    $hr2 = Get-HostVfsRoot -ImagePath 'C:\Windows\System32\svchost.exe' -DirExists { param($p) $dirs.ContainsKey($p) }
    T 'an ordinary system process yields no package root' ($null -eq $hr2) ([string]$hr2)

    T 'a WindowsApps process counts as a virtualized host' `
      (Test-VirtualizedHost -ImagePath 'C:\Program Files\WindowsApps\Pkg_1.0_x64__8wekyb3d8bbwe\app.exe' -Roots @()) ''
    T 'a Click-to-Run process counts as a virtualized host' `
      (Test-VirtualizedHost -ImagePath 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE' -Roots $roots) ''
    T 'svchost.exe is NOT a virtualized host' `
      (-not (Test-VirtualizedHost -ImagePath 'C:\Windows\System32\svchost.exe' -Roots $roots)) ''

    # The 14 WINWORD warnings, pinned.
    $v1 = Get-UnbackedVerdict -Path $mso -AllOwnersVirtualized $true
    T 'an Office C2R module is context, not a finding' `
      ($v1.Sev -eq 'INFO' -and $v1.Reason -notmatch 'T1055|reflective') "$($v1.Sev): $($v1.Reason)"

    $v2 = Get-UnbackedVerdict -Path $mso -AllOwnersVirtualized $false
    T 'an unresolved SYSTEM path states uncertainty instead of asserting injection' `
      ($v2.Sev -eq 'WARNING' -and $v2.Reason -match 'virtualization' -and $v2.Reason -notmatch 'T1055') "$($v2.Sev): $($v2.Reason)"

    # ...and the downgrade must not swallow the real thing.
    $v3 = Get-UnbackedVerdict -Path 'C:\Users\u\AppData\Local\Evil\x.dll' -AllOwnersVirtualized $false
    T 'a non-system unbacked module keeps the full T1055 finding' `
      ($v3.Sev -eq 'WARNING' -and $v3.Reason -match 'reflective or unbacked load') "$($v3.Sev): $($v3.Reason)"

    $v4 = Get-UnbackedVerdict -Path 'C:\Users\Public\x.dll' -AllOwnersVirtualized $false
    T 'a Users\Public unbacked module keeps the full T1055 finding' `
      ($v4.Reason -match 'reflective or unbacked load') "$($v4.Reason)"

    # END TO END through Get-SigVerdict -- the function that produced the
    # fourteen warnings. Probes injected; no Office is needed, and none exists
    # on a CI runner.
    $script:VfsMap = $map
    $script:VfsRoots = $roots
    $script:SigProbe = { param($p) @{ Valid = $true; MsSigned = $true; Why = 'signed by Microsoft Corporation' } }
    $script:ExistsProbe = { param($p) $p -like '*\VFS\ProgramFilesCommonX64\*' }
    $sigCache.Clear()
    $g = Get-SigVerdict $mso
    T 'Get-SigVerdict resolves the virtual path and grades the REAL file' `
      ($g.Valid -and $g.Why -match 'virtual file system') "$($g.Valid): $($g.Why)"

    $script:ExistsProbe = { param($p) $false }
    $sigCache.Clear()
    $g2 = Get-SigVerdict $mso
    T 'a module that resolves nowhere is still reported as not on disk' `
      ((-not $g2.Valid) -and $g2.Why -match 'not found on disk') "$($g2.Valid): $($g2.Why)"

    # THE COMMON CASE: no Office at all. This must be silent and false, not a
    # method call on a null. It was not -- Get-VfsRoots returned $null for an
    # empty result and every caller threw. Every earlier case here passed a
    # NON-empty roots array, so the machine state that 99% of users have was
    # the one shape never exercised.
    $errBefore = $Error.Count
    $noOffice = $false
    try {
        $noOffice = (Test-VirtualizedHost -ImagePath 'C:\Windows\System32\svchost.exe' -Roots $null)
        $null = @(Get-VfsCandidates -Path $mso -Map $map -Roots $null)
        $null = @(Get-VfsCandidates -Path $mso -Map $map -Roots @($null))
        $null = (Test-VirtualizedHost -ImagePath 'C:\Windows\System32\svchost.exe' -Roots @($null))
    } catch { }
    T 'a machine with no Office resolves nothing and raises no error' `
      ((-not $noOffice) -and $Error.Count -eq $errBefore) ("errors raised: " + ($Error.Count - $errBefore))

    # ...and Get-VfsRoots must hand back an ARRAY when it found nothing, never
    # $null: that is the difference between the two behaviours above.
    $script:VfsRoots = $null
    $saveEnv = $env:SystemRoot
    $emptyRoots = Get-VfsRoots
    T 'Get-VfsRoots returns an empty ARRAY, not $null, when nothing is installed' `
      ($null -ne $emptyRoots -and @($emptyRoots).Count -eq 0) ("null=" + ($null -eq $emptyRoots) + " count=" + @($emptyRoots).Count)
    $script:VfsRoots = $null

    if ($fails) { Write-Output "[FAIL] $fails module_inspect self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] module_inspect self-test: Click-to-Run/MSIX virtual paths resolve or are stated as uncertain; a genuinely unbacked module still raises T1055.'
    exit 0
}

$script:VfsMap = New-VfsMap -EnvMap @{
    'ProgramFiles'            = $env:ProgramFiles
    'ProgramFiles(x86)'       = ${env:ProgramFiles(x86)}
    'ProgramW6432'            = $env:ProgramW6432
    'CommonProgramFiles'      = $env:CommonProgramFiles
    'CommonProgramFiles(x86)' = ${env:CommonProgramFiles(x86)}
    'CommonProgramW6432'      = $env:CommonProgramW6432
    'SystemRoot'              = $env:SystemRoot
}

'--- [T1055/T1574] Loaded-module inspection (what is running INSIDE processes) ---'

$sev = 'OK'
$modOwners = @{}     # module path -> list of process names that loaded it
$modAllVirt = @{}    # module path -> every loading process is virtualization-hosted
$denied = 0
$procCount = 0
$lsassDenied = $false
$imgVirt = @{}       # process image path -> is it running from a virtualized package
[void](Get-VfsRoots)  # prime the registry-derived roots; the walk appends any it discovers

foreach ($p in (Get-Process -EA SilentlyContinue)) {
    $procCount++
    $pname = $p.ProcessName
    $mods = $null
    try { $mods = $p.Modules } catch {
        $denied++
        if ($pname -ieq 'lsass') { $lsassDenied = $true }
        continue
    }
    if (-not $mods) { continue }
    $first = $true
    $procVirt = $false
    foreach ($m in $mods) {
        $fn = $null
        try { $fn = [string]$m.FileName } catch {}
        if (-not $fn) { continue }
        # Modules[0] is the process's OWN executable. Flagging that as an
        # injected module is a category error -- a process running from a
        # suspicious path is a different finding, and Section 4 already reports
        # it. Record it so it can be excluded, or every process launched from
        # Temp gets double-reported here as an injection.
        if ($first) {
            $first = $false
            if ($imgVirt.ContainsKey($fn)) {
                $procVirt = [bool]$imgVirt[$fn]
            } else {
                # Ask the process where its own package root is before falling
                # back to the registry-derived list -- the image path answers
                # even when the Click-to-Run key does not.
                $hostRoot = Get-HostVfsRoot -ImagePath $fn
                if ($hostRoot) { Add-VfsRoot -Root $hostRoot; $procVirt = $true }
                else { $procVirt = Test-VirtualizedHost -ImagePath $fn -Roots (Get-VfsRoots) }
                $imgVirt[$fn] = $procVirt
            }
            continue
        }
        if (-not $modOwners.ContainsKey($fn)) { $modOwners[$fn] = New-Object System.Collections.Generic.List[string] }
        if (-not $modOwners[$fn].Contains($pname)) { $modOwners[$fn].Add($pname) }
        # "Every owner is virtualized" -- one ordinary process loading the same
        # module is enough to make the virtualization explanation insufficient.
        if (-not $procVirt) { $modAllVirt[$fn] = $false }
        elseif (-not $modAllVirt.ContainsKey($fn)) { $modAllVirt[$fn] = $true }
    }
}

if ($modOwners.Count -eq 0) {
    '[SKIPPED] No process modules could be enumerated -- injection check NOT performed.'
    Write-Marker -Name 'module' -Sev 'WARNING'
    return
}

# LSA Protection makes lsass modules unreadable BY DESIGN. Distinguish that from
# a genuine failure so the report never implies a gap where a defence is working.
$ppl = $null
try { $ppl = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -EA SilentlyContinue).RunAsPPL } catch {}
if ($lsassDenied) {
    if ($ppl -eq 1) {
        '[OK] lsass modules not enumerable -- consistent with LSA Protection (RunAsPPL) being enabled. The protection is working.'
    } else {
        '[SKIPPED] lsass module enumeration denied while LSA Protection is OFF -- lsass injection NOT checked.'
        $sev = Get-MaxSev $sev 'WARNING'
    }
}

$findings = @()
$checked = 0
$unsignedOther = 0
$capped = $false
# INSPECT THE SUSPICIOUS PATHS FIRST. Plain `Sort-Object` is alphabetical, so
# C:\Windows\Temp\... and C:\Users\<u>\AppData\... sort near the END -- and on a
# busy workstation (Chrome + Teams + Office + an IDE easily exceed the 2500-file
# cap) the cap dropped exactly the modules this check exists to find, while the
# report still said no module came from a staging path. Ordering staged paths
# ahead of everything else means the cap can only ever discard the least
# interesting candidates.
$ordered = @($modOwners.Keys | Sort-Object @{Expression = { if ($_ -match $badPathRx) { 0 } else { 1 } }}, @{Expression = { $_ }})
foreach ($path in $ordered) {
    $owners = $modOwners[$path]
    $inCore = $false
    foreach ($o in $owners) { if ($coreProcs -contains $o.ToLower()) { $inCore = $true; break } }
    $staged = ($path -match $badPathRx)

    # .NET NGEN native images are compiled ON THIS MACHINE from assemblies that
    # were already validated, and are unsigned by design -- they are not a
    # signal, on a runner or on a user's PC.
    if ($path -match '\\Windows\\assembly\\NativeImages_') { continue }
    if ($checked -ge $MaxModules) { $capped = $true; break }
    $checked++
    $v = Get-SigVerdict $path

    $itemSev = ''
    $reason = ''
    if ($staged) {
        $itemSev = 'CRITICAL'
        $reason = 'loaded from a staging path'
    } elseif (-not $v.Valid) {
        if ($inCore) {
            $itemSev = 'CRITICAL'; $reason = $v.Why + ' inside a core security process'
        } elseif ($v.Why -match 'not found on disk') {
            # A module mapped into a process whose FILE DOES NOT EXIST is not
            # the same thing as an unsigned vendor DLL, and folding it into
            # $unsignedOther meant the classic in-memory injection signal was
            # counted and then explained away as "common for legitimate
            # third-party software". Reflectively-loaded and unbacked modules
            # are exactly what this check exists to surface, so they are raised
            # on their own rather than absorbed into a benign tally.
            #
            # It reaches here only after the Click-to-Run/MSIX virtual file
            # system failed to resolve it; Get-UnbackedVerdict then decides how
            # much this actually proves. Fourteen ordinary Office DLLs were
            # reported as in-memory injection before it did.
            $allVirt = $false
            if ($modAllVirt.ContainsKey($path)) { $allVirt = [bool]$modAllVirt[$path] }
            $u = Get-UnbackedVerdict -Path $path -AllOwnersVirtualized $allVirt
            $itemSev = $u.Sev
            $reason = $u.Reason
        } else {
            # Unsigned DLLs outside the core security processes are ordinary on
            # real machines -- plenty of legitimate software ships unsigned
            # binaries, and CI alone showed .NET NGEN native images plus every
            # app DLL of the build agent. Itemising them produces a report of
            # hundreds of entries that nobody can triage, which buries the
            # findings that matter. Counted and summarised instead of raised.
            $unsignedOther++
        }
    } elseif ($inCore -and -not $v.MsSigned) {
        $itemSev = 'WARNING'
        $reason = $v.Why + ' (non-Microsoft) inside a core security process'
    }

    if ($itemSev) {
        $findings += New-Object PSObject -Property @{
            Sev = $itemSev; Path = $path; Reason = $reason; Owners = (($owners | Select-Object -First 6) -join ', ')
        }
        # INFO items are context lines, printed but never raised -- Get-MaxSev
        # returns OK for anything that is not CRITICAL/WARNING, so this is
        # already correct, but the intent is worth stating.
        $sev = Get-MaxSev $sev $itemSev
    }
}

# Print CRITICAL before WARNING, each capped, so a raised finding is never
# crowded out of the report by lower-severity noise.
$crit = @($findings | Where-Object { $_.Sev -eq 'CRITICAL' })
$warn = @($findings | Where-Object { $_.Sev -eq 'WARNING' })
$note = @($findings | Where-Object { $_.Sev -eq 'INFO' })
$i = 0
foreach ($f in $crit) {
    $i++
    if ($i -le $MaxReport) { "[CRITICAL] Module $($f.Path) -- $($f.Reason)  [loaded by: $($f.Owners)]" }
}
if ($crit.Count -gt $MaxReport) { "[INFO] ...and $($crit.Count - $MaxReport) more critical module finding(s) not listed (report cap $MaxReport)." }
$i = 0
foreach ($f in $warn) {
    $i++
    if ($i -le $MaxReport) { "[WARNING] Module $($f.Path) -- $($f.Reason)  [loaded by: $($f.Owners)]" }
}
if ($warn.Count -gt $MaxReport) { "[INFO] ...and $($warn.Count - $MaxReport) more module finding(s) not listed (report cap $MaxReport)." }
# Virtualized modules are SUMMARISED, not itemised: Word alone contributes
# fourteen, and a screenful of context lines is how a reader learns to skip the
# section. One line, with an example, so the state is visible and adjudicable.
if ($note.Count -gt 0) {
    "[INFO] $($note.Count) module(s) report a path that is not visible on disk while every process loading them runs from a virtualized package (Office Click-to-Run / MSIX). Those packages keep private copies of their files under <package>\VFS\, so the reported path exists only inside the process. Context, not an injection signal."
    "[INFO]   example: $($note[0].Path)  [loaded by: $($note[0].Owners)]"
}

if ($findings.Count -eq 0) {
    # Qualify the all-clear when the cap truncated the walk: "none from a
    # staging path" must not be read as covering modules that were never
    # examined. (Staged paths are inspected first, so a cap hit now means the
    # unchecked remainder is the least interesting part of the list -- but the
    # sentence still has to say what it actually covers.)
    if ($capped) {
        "[OK] $checked unique loaded module(s) inspected across $procCount process(es) -- none of THOSE came from a staging path or were unsigned inside a core security process. The walk stopped at the $MaxModules-file cap; see the coverage note below."
    } else {
        "[OK] $checked unique loaded module(s) across $procCount process(es) -- none from a staging path, none unsigned inside a core security process."
    }
}
if ($unsignedOther -gt 0) {
    "[INFO] $unsignedOther unique unsigned module(s) loaded outside the core security processes -- common for legitimate third-party software, so counted rather than flagged. Reviewed individually only if you have other reason for concern."
}
if ($capped) {
    "[INFO] Module inspection stopped at the $MaxModules-file cap; $($modOwners.Count - $checked) unique module(s) were NOT checked."
}
if ($denied -gt 0) {
    "[INFO] $denied process(es) refused module enumeration (protected or cross-architecture) -- normal on Windows, but those processes were not inspected."
}

Write-Marker -Name 'module' -Sev $sev
