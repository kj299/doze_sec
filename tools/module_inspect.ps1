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
    [int]$MaxReport = 25
)

$ErrorActionPreference = 'Continue'

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if ($Sev -eq 'OK') { return }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII -EA SilentlyContinue
}
function Get-MaxSev {
    param([string]$A, [string]$B)
    if ($A -eq 'CRITICAL' -or $B -eq 'CRITICAL') { return 'CRITICAL' }
    if ($A -eq 'WARNING'  -or $B -eq 'WARNING')  { return 'WARNING' }
    return 'OK'
}

$badPathRx = '\\Temp\\|\\Downloads\\|\\Public\\|\\ProgramData\\update'
$coreProcs = @('lsass', 'winlogon', 'services', 'csrss', 'smss', 'wininit')

'--- [T1055/T1574] Loaded-module inspection (what is running INSIDE processes) ---'

$sev = 'OK'
$sigCache = @{}
$modOwners = @{}     # module path -> list of process names that loaded it
$denied = 0
$procCount = 0
$lsassDenied = $false

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
    foreach ($m in $mods) {
        $fn = $null
        try { $fn = [string]$m.FileName } catch {}
        if (-not $fn) { continue }
        # Modules[0] is the process's OWN executable. Flagging that as an
        # injected module is a category error -- a process running from a
        # suspicious path is a different finding, and Section 4 already reports
        # it. Record it so it can be excluded, or every process launched from
        # Temp gets double-reported here as an injection.
        if ($first) { $first = $false; continue }
        if (-not $modOwners.ContainsKey($fn)) { $modOwners[$fn] = New-Object System.Collections.Generic.List[string] }
        if (-not $modOwners[$fn].Contains($pname)) { $modOwners[$fn].Add($pname) }
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

function Get-SigVerdict {
    param([string]$FilePath)
    if ($sigCache.ContainsKey($FilePath)) { return $sigCache[$FilePath] }
    $r = @{ Valid = $false; MsSigned = $false; Why = 'unreadable' }
    if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
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
    } else {
        $r.Why = 'module file not found on disk (possible reflective/unbacked load)'
    }
    $sigCache[$FilePath] = $r
    return $r
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
        $sev = Get-MaxSev $sev $itemSev
    }
}

# Print CRITICAL before WARNING, each capped, so a raised finding is never
# crowded out of the report by lower-severity noise.
$crit = @($findings | Where-Object { $_.Sev -eq 'CRITICAL' })
$warn = @($findings | Where-Object { $_.Sev -eq 'WARNING' })
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
