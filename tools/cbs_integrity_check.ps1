# cbs_integrity_check.ps1 -- Windows' OWN record of corrupted system binaries
# (T1554 Compromise Host Software Binary). Invoked from Section 13.
#
# WHY THIS EXISTS
#   The Windows servicing stack (Component Based Servicing) writes to
#   %WINDIR%\Logs\CBS\CBS.log every time it finds a protected system binary
#   whose bytes are not what the component store says they should be. That is a
#   FIRST-PARTY integrity oracle, and this tool did not read it.
#
#   The cost of not reading it, measured: on 2026-09-07 the driver audit flagged
#   C:\WINDOWS\system32\drivers\bthmodem.sys as unsigned. Establishing why took
#   five rounds of hand-written diagnostics against the owner's machine. The
#   answer was already in CBS.log:
#
#     DEPLOY [Pnp] Corrupt file:  C:\WINDOWS\system32\drivers\bthmodem.sys  (x6)
#     DEPLOY [Pnp] Repaired file: C:\WINDOWS\System32\drivers\bthmodem.sys
#
#   Corruption of a system binary is in scope whatever the cause -- a bad block
#   and an adversary produce the same log line, and the reader needs to know.
#
# THE FALSE POSITIVE THIS IS DESIGNED AROUND, BEFORE ANYTHING ELSE
#   Microsoft KB 954402 documents that
#       [SR] Cannot repair member file [l:18{9}]"img11.jpg" of
#       Microsoft-Windows-Shell-Wallpaper-Common, ... hash mismatch
#   appears ROUTINELY AND BENIGNLY for static files that Windows Resource
#   Protection does not protect -- their own example is a wallpaper .jpg, logged
#   even when sfc reports overall success. A naive grep for "Cannot repair
#   member file" reports wallpaper as system compromise. So the markers below
#   carry three different meanings and are never counted together.
#
# THE LOG IS HISTORY, SO THE PRESENT IS VERIFIED
#   CBS entries persist indefinitely. Reporting a long-since-repaired file as
#   current corruption is the same defect as reporting an EMPTY PortProxy key
#   as an IOC, or reading "not visible on disk" as "injected" -- both already
#   fixed in this repo. An unrepaired log entry is therefore a LEAD, not a
#   verdict: the file's signature is checked NOW, and only a file that both was
#   logged corrupt and still fails verification becomes a finding.
#
# MARKER: max severity word to $env:TEMP\dz_cbs.txt; the caller raises via
# :dz_finding. No marker when nothing is currently corrupt.
#
# Windows PowerShell 5.1 compatible. Read-only -- it opens log files for
# reading and verifies signatures; it repairs nothing and runs no sfc/DISM.
# Executed by helpers-ps51 CI.

[CmdletBinding()]
param(
    # Point at a fixture instead of the real log. The self-test needs no
    # filesystem at all, but a fixture path lets CI drive the real reader.
    [string]$Path = '',
    [string]$MarkerDir = $env:TEMP,
    [int]$MaxReport = 15,
    # A CBS.log can be tens of megabytes and there can be many rotated
    # CbsPersist_*.log beside it. Exhausting this budget is DECLARED, never
    # reported as clean.
    [int]$BudgetSeconds = 20,
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

# Executable payloads are the ones Windows Resource Protection really protects
# and the ones an attacker would want to alter. KB 954402's benign class is
# precisely the non-executable static files, so this extension test is the
# discriminator that keeps wallpaper out of the findings.
$script:ExeRx = '\.(sys|dll|exe|ocx|drv|cpl|efi|scr|mui)$'

# Injectable so the self-test needs no files and no certificates, mirroring
# tools/service_signature_check.ps1 and tools/driver_audit.ps1.
$script:ExistsProbe = { param($p) Test-Path -LiteralPath $p -PathType Leaf }
$script:SigProbe    = {
    param($p)
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $p -EA Stop } catch {}
    return $sig
}

function Get-CbsEntries {
    # PURE. Parses CBS log lines into events. No I/O, so CI proves the parser
    # over known inputs -- including Microsoft's own documented benign example.
    #
    # Three markers, three meanings:
    #   Corrupt      DEPLOY [Pnp] Corrupt file: <full path>
    #   Repaired     DEPLOY [Pnp] Repaired file: <full path>
    #   CannotRepair [SR] Cannot repair member file [l:N{M}]"<name>" of <component>
    #
    # The [SR] form names a component MEMBER, not a full path, so it can never
    # be signature-verified the way a [Pnp] path can. That asymmetry is real and
    # is carried through to the verdict rather than papered over.
    param([string[]]$Lines)
    $out = @()
    if (-not $Lines) { return $out }
    foreach ($ln in $Lines) {
        if ($null -eq $ln) { continue }
        $stamp = ''
        $m = [regex]::Match($ln, '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
        if ($m.Success) { $stamp = $m.Groups[1].Value }

        $m = [regex]::Match($ln, '\[Pnp\]\s+Corrupt file:\s*(\S.*?)\s*$')
        if ($m.Success) {
            $out += @{ Kind = 'Corrupt'; Path = $m.Groups[1].Value; Name = ''; Component = ''; Stamp = $stamp }
            continue
        }
        $m = [regex]::Match($ln, '\[Pnp\]\s+Repaired file:\s*(\S.*?)\s*$')
        if ($m.Success) {
            $out += @{ Kind = 'Repaired'; Path = $m.Groups[1].Value; Name = ''; Component = ''; Stamp = $stamp }
            continue
        }
        $m = [regex]::Match($ln, '\[SR\]\s+Cannot repair member file\s+\[[^\]]*\]"([^"]+)"(?:\s+of\s+([^,]+))?')
        if ($m.Success) {
            $comp = ''
            if ($m.Groups.Count -gt 2 -and $m.Groups[2].Success) { $comp = $m.Groups[2].Value.Trim() }
            $out += @{ Kind = 'CannotRepair'; Path = ''; Name = $m.Groups[1].Value; Component = $comp; Stamp = $stamp }
            continue
        }
    }
    return $out
}

function Get-CbsVerdict {
    # PURE given its probes. Returns @{ Sev; Findings = @(); Context = @() }.
    #
    # Findings are lines that become the severity. Context is printed but never
    # raises -- resolved corruption, vanished paths, and KB 954402's benign
    # class all belong there, WITH a count, never silently dropped.
    param($Entries)
    $res = @{ Sev = 'OK'; Findings = @(); Context = @() }
    if (-not $Entries) { return $res }

    # Logs are append-only, so "a repair for this path appears anywhere" is a
    # sound pairing: a later corruption would be followed by its own repair or
    # by the file failing verification below, which is what actually decides.
    $repaired = @{}
    foreach ($e in $Entries) {
        if ($e.Kind -eq 'Repaired' -and $e.Path) { $repaired[$e.Path.ToLower()] = $true }
    }

    $seen = @{}
    $nResolved = 0
    $nGone = 0
    foreach ($e in $Entries) {
        if ($e.Kind -ne 'Corrupt' -or -not $e.Path) { continue }
        $key = $e.Path.ToLower()
        if ($seen.ContainsKey($key)) { continue }   # the same file is logged repeatedly
        $seen[$key] = $true

        if ($repaired.ContainsKey($key)) {
            $nResolved++
            continue
        }
        if (-not (& $script:ExistsProbe $e.Path)) {
            # Named as corrupt and no longer on disk. Not a current finding, and
            # not silence either: it is stated and counted.
            $nGone++
            continue
        }
        $sig = & $script:SigProbe $e.Path
        if ($sig -and $sig.Status -eq 'Valid') {
            # Logged corrupt, verifies now -- repaired by some path that did not
            # log a matching Repaired line, or replaced by servicing. This is
            # exactly the bthmodem.sys case and it must NOT be a finding.
            $nResolved++
            continue
        }
        $st = if ($sig) { [string]$sig.Status } else { 'unreadable' }
        if ($e.Path -notmatch $script:ExeRx) {
            $res.Context += "[INFO] CBS logged $($e.Path) as corrupt with no repair, but it is not an executable system binary -- see KB 954402, Windows Resource Protection reports unprotected static files this way routinely."
            continue
        }
        $res.Findings += "[WARNING] Windows servicing logged $($e.Path) as CORRUPT with no matching repair, and it still does not verify (signature: $st). A protected system binary whose bytes are not what the component store expects (T1554). Cause is not determined by this check: disk corruption and deliberate modification produce the same record. Repair with: sfc /scannow"
        $res.Sev = Get-MaxSev $res.Sev 'WARNING'
    }

    # The [SR] class. Microsoft documents the non-executable case as benign, so
    # it is context; an EXECUTABLE member that the store cannot repair is not,
    # and is reported with the uncertainty it deserves -- there is no path here
    # to verify, so this can never be confirmed the way a [Pnp] entry can.
    $srSeen = @{}
    foreach ($e in $Entries) {
        if ($e.Kind -ne 'CannotRepair' -or -not $e.Name) { continue }
        $k = ($e.Name + '|' + $e.Component).ToLower()
        if ($srSeen.ContainsKey($k)) { continue }
        $srSeen[$k] = $true
        $where = if ($e.Component) { " of $($e.Component)" } else { '' }
        if ($e.Name -match $script:ExeRx) {
            $res.Findings += "[WARNING] Windows servicing could not repair the component member '$($e.Name)'$where (hash mismatch). It is an executable, so this is not the benign static-file case Microsoft documents in KB 954402. CBS names a component member rather than a path, so this check cannot verify it directly -- confirm with: sfc /scannow"
            $res.Sev = Get-MaxSev $res.Sev 'WARNING'
        } else {
            $res.Context += "[INFO] Windows servicing could not repair '$($e.Name)'$where -- a non-executable static file. Microsoft KB 954402 documents these as reported routinely and benignly, even when sfc reports success."
        }
    }

    if ($nResolved -gt 0) {
        $res.Context += "[INFO] $nResolved file(s) recorded as corrupt in CBS were repaired, or verify correctly now. Windows detected and fixed them; no action needed."
    }
    if ($nGone -gt 0) {
        $res.Context += "[INFO] $nGone file(s) recorded as corrupt are no longer on disk -- nothing left to verify."
    }
    return $res
}

if ($SelfTest) {
    '--- cbs_integrity_check self-test (parser + verdict over fixed inputs) ---'
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if($Got){": $Got"})"; $script:fails++ }
    }
    function FakeSig { param([string]$Status) return (New-Object PSObject -Property @{ Status = $Status }) }
    function V { param([string[]]$Lines) return (Get-CbsVerdict -Entries (Get-CbsEntries -Lines $Lines)) }

    # THE REAL CASE, VERBATIM from the owner's machine 2026-09-07 (recorded in
    # docs/design/backlog.md). Corrupt six times, then repaired. This must
    # produce NO finding: it is history, and Windows already fixed it. Kept as a
    # permanent regression case the way log_gap_check keeps its false positive.
    $bthmodem = @(
        '2026-09-07 15:24:17, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\system32\drivers\bthmodem.sys',
        '2026-09-07 15:27:11, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\System32\drivers\bthmodem.sys',
        '2026-09-07 16:03:08, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\system32\drivers\bthmodem.sys',
        '2026-09-07 16:04:37, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\system32\drivers\bthmodem.sys',
        '2026-09-07 16:16:26, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\System32\drivers\bthmodem.sys',
        '2026-09-07 16:17:40, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\System32\drivers\bthmodem.sys',
        '2026-09-07 16:17:40, Info                  DEPLOY [Pnp] Repaired file: C:\WINDOWS\System32\drivers\bthmodem.sys'
    )
    $e = Get-CbsEntries -Lines $bthmodem
    T 'the real bthmodem lines parse to 6 Corrupt + 1 Repaired' `
      ((@($e | Where-Object { $_.Kind -eq 'Corrupt' }).Count -eq 6) -and (@($e | Where-Object { $_.Kind -eq 'Repaired' }).Count -eq 1)) `
      ("parsed $($e.Count) entries")

    # Both spellings of the path appear in the real log (system32 / System32).
    # Pairing must be case-insensitive or the repair is missed and a fixed file
    # is reported as live corruption.
    $script:ExistsProbe = { param($p) $true }
    $script:SigProbe    = { param($p) FakeSig 'NotSigned' }
    $r = V $bthmodem
    T 'corrupt-then-repaired raises NOTHING even while the file reads NotSigned' `
      ($r.Sev -eq 'OK' -and $r.Findings.Count -eq 0) `
      ("sev=$($r.Sev) findings=$($r.Findings.Count)")
    T 'and the repair is reported as context rather than dropped' `
      (($r.Context -join ' ') -match 'were repaired, or verify correctly now') `
      (($r.Context -join ' | '))

    # KB 954402, Microsoft's own documented benign example.
    $wallpaper = @('2026-01-01 00:00:00, Info                  CSI 00000145 [SR] Cannot repair member file [l:18{9}]"img11.jpg" of Microsoft-Windows-Shell-Wallpaper-Common, Version = 6.0.5720.0, pA = PROCESSOR_ARCHITECTURE_INTEL (0), Culture neutral, VersionScope = 1 nonSxS in the store, hash mismatch')
    $r = V $wallpaper
    T 'KB 954402 wallpaper hash mismatch is context, never a finding' `
      ($r.Sev -eq 'OK' -and $r.Findings.Count -eq 0 -and ($r.Context -join ' ') -match 'KB 954402') `
      ("sev=$($r.Sev) findings=$($r.Findings.Count)")

    # An unrepairable EXECUTABLE member is not that benign class.
    $sysMember = @('2026-01-01 00:00:00, Info                  CSI 00000145 [SR] Cannot repair member file [l:24{12}]"tcpip.sys" of Microsoft-Windows-TCPIP, Version = 10.0.26100.1, Culture neutral in the store, hash mismatch')
    $r = V $sysMember
    T 'an unrepairable EXECUTABLE member is a WARNING' `
      ($r.Sev -eq 'WARNING' -and $r.Findings.Count -eq 1) `
      ("sev=$($r.Sev) findings=$($r.Findings.Count)")

    # The finding case: logged corrupt, never repaired, still fails to verify.
    $open = @('2026-01-01 00:00:00, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\system32\drivers\evil.sys')
    $script:ExistsProbe = { param($p) $true }
    $script:SigProbe    = { param($p) FakeSig 'NotSigned' }
    $r = V $open
    T 'unrepaired AND still unverifiable is a WARNING' `
      ($r.Sev -eq 'WARNING' -and $r.Findings.Count -eq 1) `
      ("sev=$($r.Sev) findings=$($r.Findings.Count)")
    T 'the finding states that the cause is not determined' `
      (($r.Findings -join ' ') -match 'Cause is not determined') `
      (($r.Findings -join ' '))

    # THE LOG IS HISTORY. Same unrepaired entry, but the file verifies now.
    $script:SigProbe = { param($p) FakeSig 'Valid' }
    $r = V $open
    T 'unrepaired but verifying NOW is resolved context, not a finding' `
      ($r.Sev -eq 'OK' -and $r.Findings.Count -eq 0) `
      ("sev=$($r.Sev) findings=$($r.Findings.Count)")

    # A path that has since been deleted cannot be verified either way.
    $script:ExistsProbe = { param($p) $false }
    $script:SigProbe    = { param($p) $null }
    $r = V $open
    T 'a corrupt path no longer on disk is counted context, not a finding' `
      ($r.Sev -eq 'OK' -and ($r.Context -join ' ') -match 'no longer on disk') `
      ("sev=$($r.Sev) ctx=$($r.Context -join ' | ')")

    # Non-executable [Pnp] path, unrepaired: still the KB 954402 shape.
    $script:ExistsProbe = { param($p) $true }
    $script:SigProbe    = { param($p) FakeSig 'NotSigned' }
    $r = V @('2026-01-01 00:00:00, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\Web\Wallpaper\img0.jpg')
    T 'an unrepaired NON-executable path is context, not a finding' `
      ($r.Sev -eq 'OK' -and $r.Findings.Count -eq 0) `
      ("sev=$($r.Sev) findings=$($r.Findings.Count)")

    # A clean log must be silent, or every audit gains a permanent noise line.
    $r = V @('2026-01-01 00:00:00, Info                  CBS    Starting TrustedInstaller initialization.', '2026-01-01 00:00:01, Info                  CSI 00000001 [SR] Verify complete')
    T 'an ordinary servicing log raises nothing and adds no context' `
      ($r.Sev -eq 'OK' -and $r.Findings.Count -eq 0 -and $r.Context.Count -eq 0) `
      ("sev=$($r.Sev) findings=$($r.Findings.Count) ctx=$($r.Context.Count)")

    if ($fails -gt 0) { Write-Output "[CRITICAL] $fails self-test case(s) failed."; exit 2 }
    Write-Output '[OK] cbs_integrity_check self-test: all cases passed.'
    exit 0
}

# ---- live run -------------------------------------------------------------

'--- [T1554] System-file integrity per Windows'' own servicing log (CBS) ---'

$logs = @()
if ($Path) {
    $logs = @($Path)
} else {
    # Concatenated, not Join-Path: Join-Path resolves the drive and throws when
    # it does not exist, which makes the whole tool unrunnable off Windows and
    # so untestable without a Windows box. driver_audit.ps1 carries the same
    # fix for the same reason.
    $winDir = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
    $cbsDir = $winDir.TrimEnd('\') + '\Logs\CBS'
    if (Test-Path -LiteralPath $cbsDir) {
        # CBS.log first (current), then rotated persist logs newest-first, so a
        # budget that runs out loses the OLDEST history rather than the newest.
        $main = $cbsDir + '\CBS.log'
        if (Test-Path -LiteralPath $main) { $logs += $main }
        try {
            $logs += @(Get-ChildItem -LiteralPath $cbsDir -Filter 'CbsPersist_*.log' -File -EA SilentlyContinue |
                Sort-Object LastWriteTimeUtc -Descending | ForEach-Object { $_.FullName })
        } catch {}
    }
}

if ($logs.Count -eq 0) {
    # Not an answer, and said so. A missing CBS directory on Windows is itself
    # unusual; treating it as clean would be the reassurance this repo bans.
    '[SKIPPED] No CBS log found under %SystemRoot%\Logs\CBS -- system-file integrity NOT checked. Reading it needs administrator rights on most builds.'
    Write-Marker -Name 'cbs' -Sev 'WARNING'
    return
}

$clock = [System.Diagnostics.Stopwatch]::StartNew()
$lines = New-Object System.Collections.Generic.List[string]
$read = 0
$unread = 0
$denied = 0
foreach ($lg in $logs) {
    if ($clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { $unread++; continue }
    $reader = $null
    try {
        # Share ReadWrite: TrustedInstaller holds CBS.log open while servicing.
        $fs = [System.IO.File]::Open($lg, 'Open', 'Read', 'ReadWrite')
        $reader = New-Object System.IO.StreamReader($fs)
        while ($null -ne ($ln = $reader.ReadLine())) {
            # Cheap pre-filter before any regex: these logs are mostly noise.
            if ($ln.IndexOf('Corrupt file', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                $ln.IndexOf('Repaired file', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                $ln.IndexOf('Cannot repair member file', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                [void]$lines.Add($ln)
            }
            if ($clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { $unread++; break }
        }
        $read++
    } catch [System.UnauthorizedAccessException] {
        $denied++
    } catch {
        $unread++
    } finally {
        if ($reader) { $reader.Dispose() }
    }
}
$clock.Stop()

if ($read -eq 0) {
    if ($denied -gt 0) {
        '[SKIPPED] CBS log(s) could not be read (access denied) -- system-file integrity NOT checked. Reading %SystemRoot%\Logs\CBS needs administrator rights.'
    } else {
        '[SKIPPED] CBS log(s) could not be read -- system-file integrity NOT checked.'
    }
    Write-Marker -Name 'cbs' -Sev 'WARNING'
    return
}

$v = Get-CbsVerdict -Entries (Get-CbsEntries -Lines $lines)

# Findings before context, always. Printing in arrival order with one shared
# cap is a real detection-quality bug: benign context would crowd out a real
# finding, exactly as baseline_diff.ps1 records for its own categories.
$shown = 0
foreach ($f in $v.Findings) {
    if ($shown -ge $MaxReport) { break }
    $f
    $shown++
}
if ($v.Findings.Count -gt $shown) {
    "[INFO] $($v.Findings.Count - $shown) further corrupt-file finding(s) not shown (report cap $MaxReport)."
}
foreach ($c in $v.Context) { $c }

if ($denied -gt 0) {
    "[INFO] $denied CBS log file(s) could not be read (access denied); $read were read."
}
if ($unread -gt 0) {
    # Budget exhaustion is missing coverage, and is declared as such. A clean
    # verdict over a partially read log would be a claim this run cannot make.
    "[BUDGET] $unread CBS log file(s) NOT fully read -- the ${BudgetSeconds}s wall-clock budget ran out. This is missing coverage, not a pass."
    $v.Sev = Get-MaxSev $v.Sev 'WARNING'
}

if ($v.Sev -eq 'OK' -and $v.Findings.Count -eq 0 -and $v.Context.Count -eq 0) {
    "[OK] $read CBS log file(s) read -- Windows servicing has recorded no corrupt system files."
}
Write-Marker -Name 'cbs' -Sev $v.Sev
