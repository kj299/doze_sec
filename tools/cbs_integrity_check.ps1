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
    [string[]]$Path = @(),
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

# Reads one CBS log and returns the lines worth parsing. It scans in .NET-sized
# chunks, never one line at a time: WIN11-02 (2026-10-24 and -25) ran out of
# the 20 s budget on BOTH runs with the old per-line PowerShell loop, whose
# per-iteration cost, not the disk, set the speed (a 150 MB log took 11 s
# under pwsh 7 and longer on 5.1). The budget is checked once per chunk
# through -OutOfTime, so a test can drive the cut-short path with a fake clock.
# Hits go straight into -Into as each chunk is scanned, so a read that fails
# part-way (a bad sector -- the very thing this check reports on) keeps the
# corrupt-file lines it had already found. Returns @{ FirstStamp; Complete;
# Bytes }.
# The three phrases the old per-line filter used, matched the same way
# (ordinal, ignoring case). Each is found with String.IndexOf -- native and
# fast on 5.1's .NET Framework, where a case-insensitive regex walks the text
# one character at a time -- and each hit is then widened to its line. An
# anchored '^[^\r\n]*(?:...)' regex was tried first: it backtracked across
# every noise line and was barely faster than the loop it replaced.
$script:CbsPhrases = @('Corrupt file', 'Repaired file', 'Cannot repair member file')
function Get-CbsHitLines {
    # PURE. Every line of $Text holding one of the phrases, once each and in
    # file order, without its line ending. A line ends at CR or LF, as
    # ReadLine splits it.
    param([string]$Text, [System.Collections.Generic.List[string]]$Into)
    $eol = [char[]]@([char]13, [char]10)
    $starts = New-Object 'System.Collections.Generic.SortedDictionary[int,int]'
    foreach ($ph in $script:CbsPhrases) {
        $at = 0
        while ($at -lt $Text.Length) {
            $k = $Text.IndexOf($ph, $at, [System.StringComparison]::OrdinalIgnoreCase)
            if ($k -lt 0) { break }
            $start = $Text.LastIndexOfAny($eol, $k) + 1
            $end = $Text.IndexOfAny($eol, $k)
            if ($end -lt 0) { $end = $Text.Length }
            $starts[$start] = $end
            $at = $end + 1
        }
    }
    foreach ($kv in $starts.GetEnumerator()) { $Into.Add($Text.Substring($kv.Key, $kv.Value - $kv.Key)) }
}
function Read-CbsLog {
    param([string]$Path, [System.Collections.Generic.List[string]]$Into, [int]$ChunkChars = 4194304, [scriptblock]$OutOfTime = { $false })
    $first = $null; $complete = $false; $bytes = [long]0
    $eol = [char[]]@([char]13, [char]10)
    $reader = $null
    try {
        # Share ReadWrite: TrustedInstaller holds CBS.log open while servicing.
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $reader = New-Object System.IO.StreamReader($fs)
        $buf = New-Object char[] $ChunkChars
        $carry = ''
        $firstDone = $false
        while ($true) {
            $n = $reader.ReadBlock($buf, 0, $ChunkChars)
            if ($n -le 0) { break }
            $bytes = $fs.Position
            $text = $carry + (New-Object string($buf, 0, $n))
            if (-not $firstDone) {
                # The first line's timestamp is the start of the window this
                # file covers. A typed [ref]: with an untyped one TryParse threw
                # and sent a readable log into the catch.
                $nl = $text.IndexOfAny($eol)
                if ($nl -ge 0 -or $reader.EndOfStream) {
                    $firstLine = if ($nl -ge 0) { $text.Substring(0, $nl) } else { $text }
                    $m = [regex]::Match($firstLine, '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
                    if ($m.Success) {
                        [datetime]$t = [datetime]::MinValue
                        if ([datetime]::TryParse($m.Groups[1].Value, [ref]$t)) { $first = $t }
                    }
                    $firstDone = $true
                }
            }
            $cut = $text.LastIndexOfAny($eol)
            if ($cut -lt 0 -and $text.Length -lt (4 * $ChunkChars)) {
                # No line end yet: carry it -- but a file with no line ends at
                # all (a crash's NUL run) must not grow without bound, and the
                # budget is checked either way.
                $carry = $text
                if (& $OutOfTime) { break }
                continue
            }
            if ($cut -lt 0) { $cut = $text.Length - 1 }
            Get-CbsHitLines -Text $text.Substring(0, $cut + 1) -Into $Into
            $carry = $text.Substring($cut + 1)
            if (& $OutOfTime) { break }
        }
        # Reaching EOF is the only thing that counts as fully read; then the
        # last line, with or without a newline, is scanned too.
        if ($reader.EndOfStream) {
            if ($carry) { Get-CbsHitLines -Text $carry -Into $Into }
            $complete = $true
        }
    } finally {
        if ($reader) { $reader.Dispose() }
    }
    return @{ FirstStamp = $first; Complete = $complete; Bytes = $bytes }
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

    # THE READER, through real files: it scans in chunks, so a hit may straddle
    # a chunk edge, a file may end without a newline, and a budget may expire
    # mid-file. ChunkChars 64 forces many edges; a fake clock drives the cut.
    $tdir = Join-Path ([IO.Path]::GetTempPath()) ("dz_cbs_st_{0}" -f $PID)
    New-Item -ItemType Directory -Path $tdir -Force | Out-Null
    try {
        $hitA = '2026-10-18 05:21:07, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\System32\drivers\x.sys'
        $hitB = '2026-10-18 05:22:07, Info                  DEPLOY [Pnp] Repaired file: C:\WINDOWS\System32\drivers\x.sys'
        $hitC = '2026-10-18 05:23:07, Info                  CSI    00000002 [SR] Cannot repair member file [l:9]"y.dll" of Comp'
        $noise = '2026-10-18 05:21:00, Info                  CSI    00000001 ordinary servicing noise line'
        $body = @('2026-10-18 05:21:00, Info                  CBS    Starting TrustedInstaller initialization.') + (@($noise) * 40) + @($hitA) + (@($noise) * 7) + @($hitB.ToUpper()) + @($noise) + @($hitC)
        $fCrlf = Join-Path $tdir 'crlf.log'; [IO.File]::WriteAllText($fCrlf, (($body -join "`r`n") + "`r`n"))
        $fLf = Join-Path $tdir 'lf.log'; [IO.File]::WriteAllText($fLf, ($body -join "`n"))
        function RL { param($p, [int]$c = 64, $ot = { $false }) $l = New-Object System.Collections.Generic.List[string]; $x = Read-CbsLog -Path $p -Into $l -ChunkChars $c -OutOfTime $ot; $x.Lines = $l; $x }
        $r1 = RL $fCrlf
        $r2 = RL $fLf
        T 'the chunked reader finds all three phrases once each, across chunk edges, in any case' `
          ($r1.Complete -and $r1.Lines.Count -eq 3 -and $r1.Lines[0] -eq $hitA -and $r1.Lines[1] -eq $hitB.ToUpper() -and $r1.Lines[2] -eq $hitC) `
          ("complete=$($r1.Complete) n=$($r1.Lines.Count) :: $($r1.Lines -join ' || ')")
        T 'LF-only and CRLF files read the same, and a last line with no newline is still scanned' `
          ($r2.Complete -and $r2.Lines.Count -eq 3 -and $r2.Lines[2] -eq $hitC -and ($r2.Lines -join '|') -eq ($r1.Lines -join '|')) `
          ("n=$($r2.Lines.Count) :: $($r2.Lines -join ' || ')")
        T 'the reader takes the window start from the first line' `
          ($null -ne $r1.FirstStamp -and $r1.FirstStamp -eq [datetime]'2026-10-18 05:21:00') ([string]$r1.FirstStamp)
        $script:dzTicks = 0
        $r3 = RL $fCrlf 64 { $script:dzTicks++; $script:dzTicks -ge 2 }
        T 'a budget that expires mid-file leaves the file NOT complete (the cut-short path)' `
          ((-not $r3.Complete) -and $r3.Bytes -lt (Get-Item -LiteralPath $fCrlf).Length) ("complete=$($r3.Complete) bytes=$($r3.Bytes)")
        # A read that FAILS part-way keeps what it already found: a bad sector
        # is the very thing this check reports on, and dropping the hits
        # before it would turn a corruption finding into a gap.
        $kept = New-Object System.Collections.Generic.List[string]
        $script:dzTicks = 0
        $threw = $false
        try { $null = Read-CbsLog -Path $fCrlf -Into $kept -ChunkChars 65536 -OutOfTime { $script:dzTicks++; if ($script:dzTicks -ge 1) { throw 'simulated read failure' }; $false } } catch { $threw = $true }
        T 'hits found before a read failure are kept, not thrown away with it' ($threw -and $kept.Count -eq 3) ("threw=$threw kept=$($kept.Count)")
        # CR-only line ends split like ReadLine splits them.
        $fCr = Join-Path $tdir 'cr.log'; [IO.File]::WriteAllText($fCr, ($body -join "`r"))
        $r5 = RL $fCr
        T 'a CR-only log splits into lines as ReadLine did, each hit its own line' ($r5.Complete -and $r5.Lines.Count -eq 3 -and $r5.Lines[0] -eq $hitA) ("n=$($r5.Lines.Count) :: $($r5.Lines -join ' || ')")
        # A file with no line ends at all is still read to the end, bounded.
        $fNl = Join-Path $tdir 'noeol.log'; [IO.File]::WriteAllText($fNl, ('x' * 2000) + 'Corrupt file: C:\a.sys')
        $r6 = RL $fNl 64
        T 'a log with no line ends at all is still read to the end and its hit found' ($r6.Complete -and $r6.Lines.Count -ge 1) ("complete=$($r6.Complete) n=$($r6.Lines.Count)")
        $fClean = Join-Path $tdir 'clean.log'; [IO.File]::WriteAllText($fClean, ((@($noise) * 10) -join "`r`n"))
        $r4 = RL $fClean
        T 'a clean log yields no lines and reads complete' ($r4.Complete -and $r4.Lines.Count -eq 0) ("complete=$($r4.Complete) n=$($r4.Lines.Count)")
    } finally { Remove-Item -LiteralPath $tdir -Recurse -Force -EA SilentlyContinue }

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
    '[WARNING] No CBS log found under %SystemRoot%\Logs\CBS -- system-file integrity NOT checked. Reading it needs administrator rights on most builds.'
    Write-Marker -Name 'cbs_gap' -Sev 'WARNING'
    return
}

$clock = [System.Diagnostics.Stopwatch]::StartNew()
$lines = New-Object System.Collections.Generic.List[string]
# Counted separately because they mean different things to a reader. A file
# cut short by the budget was NOT fully examined, and the earlier version
# incremented both $unread and $read for it -- so the number describing
# coverage was wrong in exactly the situation where coverage had shrunk.
$read    = 0   # opened and read to the end
$partial = 0   # opened, budget expired part-way through
$skipped = 0   # never opened, budget already gone
$denied  = 0   # access denied (needs admin)
$failed  = 0   # any other read error
# How far back the logs actually reach. CBS rotates, and on a busy machine the
# window can be under a week -- measured on the owner's machine 2026-09-13,
# where records from 2026-09-07 had already aged out entirely. Without this the
# all-clear below would claim more than it can possibly know.
$oldest = $null
$scanned = [long]0   # bytes scanned, for the measured-speed line
foreach ($lg in $logs) {
    if ($clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { $skipped++; continue }
    try {
        $r = Read-CbsLog -Path $lg -Into $lines -OutOfTime { $clock.Elapsed.TotalSeconds -gt $BudgetSeconds }
        $scanned += $r.Bytes
        if ($null -ne $r.FirstStamp -and ($null -eq $oldest -or $r.FirstStamp -lt $oldest)) { $oldest = $r.FirstStamp }
        if ($r.Complete) { $read++ } else { $partial++ }
    } catch [System.UnauthorizedAccessException] {
        $denied++
    } catch {
        $failed++
    }
}
$clock.Stop()

# MEASURED on every path, so a gap run carries the timing that explains it.
$scanLine = "[INFO] Scanned {0:N1} MB of CBS log in {1:N1} s (budget {2} s)." -f ($scanned / 1MB), $clock.Elapsed.TotalSeconds, $BudgetSeconds
if (($read + $partial) -eq 0) {
    if ($skipped -gt 0 -and ($denied + $failed) -eq 0) {
        "[WARNING] System-file integrity check NOT performed -- the ${BudgetSeconds}s wall-clock budget ran out before any of $skipped CBS log file(s) was opened. This is missing coverage, not a pass."
    } elseif ($denied -gt 0) {
        '[WARNING] CBS log(s) could not be read (access denied) -- system-file integrity NOT checked. Reading %SystemRoot%\Logs\CBS needs administrator rights.'
    } else {
        '[WARNING] CBS log(s) could not be read -- system-file integrity NOT checked.'
    }
    if ($skipped -gt 0 -and ($denied + $failed) -gt 0) { "[INFO] $skipped further CBS log file(s) were never opened: the ${BudgetSeconds}s wall-clock budget ran out." }
    Write-Marker -Name 'cbs_gap' -Sev 'WARNING'
    $scanLine
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

if (($denied + $failed) -gt 0) {
    # A file that could not be opened is part of the window NOT examined: a
    # gap, raised, and it withholds the all-clear like a budget cut does.
    "[WARNING] System-file integrity check NOT performed in full -- $denied CBS log file(s) denied and $failed unreadable for another reason were NOT examined; $read were read in full."
    Write-Marker -Name 'cbs_gap' -Sev 'WARNING'
}
$cutShort = (($partial + $skipped + $denied + $failed) -gt 0)
if (($partial + $skipped) -gt 0) {
    # Budget exhaustion is missing coverage, and is declared as such. A clean
    # verdict over a partially read log would be a claim this run cannot make.
    # It is a GAP, raised through the gap marker: it used to raise the
    # FINDING severity, and the bat then filed it as "Windows servicing
    # recorded a corrupt system binary" -- WIN11-02, 2026-10-24, where the
    # tool had found no corrupt file at all.
    "[WARNING] System-file integrity check NOT performed in full -- $partial CBS log file(s) cut short and $skipped never opened: the ${BudgetSeconds}s wall-clock budget ran out. This is missing coverage, not a pass."
    Write-Marker -Name 'cbs_gap' -Sev 'WARNING'
}

# STATE THE WINDOW, ALWAYS. CBS logs rotate, so "nothing corrupt" is only ever
# a claim about the retained window -- and that window is short. Measured on
# the owner's machine 2026-09-13: a corrupt-file record from 2026-09-07 had
# already rotated away entirely, six days later. Without this line a reader
# takes the all-clear for far more than it is.
$window = if ($oldest) { "back to $($oldest.ToString('yyyy-MM-dd HH:mm'))" } else { 'an undetermined period' }
if ($v.Sev -eq 'OK' -and $v.Findings.Count -eq 0 -and $v.Context.Count -eq 0 -and -not $cutShort) {
    "[OK] $read CBS log file(s) read, covering $window -- Windows servicing recorded no corrupt system files in that window."
    '[INFO] CBS logs rotate and can cover less than a week on a busy machine. Corruption older than the window above is not visible to this check, whether or not it happened.'
} else {
    "[INFO] $read CBS log file(s) read in full, covering $window. CBS logs rotate, so anything older is not visible here."
}
# MEASURED, so the next field run says whether the budget fits this machine.
$scanLine
Write-Marker -Name 'cbs' -Sev $v.Sev
