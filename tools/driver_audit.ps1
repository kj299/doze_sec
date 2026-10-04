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
$gapSev = 'OK'
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
# Memory Integrity state, for CONTEXT on a signature finding -- never for the
# grade. Returns 'on' | 'off' | 'unknown', and 'unknown' is a real answer here:
# this tool is NOT admin-gated in doze_sec_noAdmin.bat (boot_chain_check is),
# so it can run unelevated where this query may not answer.
#
# Deliberately duplicated rather than shared with boot_chain_check.ps1: there
# is no tool-to-tool state channel in this repo and no module import in
# tools/, and every tool queries the machine independently. Write-Marker is
# copy-pasted into a dozen tools for the same reason.
$script:HvciProbe = {
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -EA Stop
        # A NULL SecurityServicesRunning is 'unknown', NOT 'off'. Some editions
        # return nothing here, and reading that as "Memory Integrity is off"
        # would state a fact this tool did not establish.
        if ($null -eq $dg -or $null -eq $dg.SecurityServicesRunning) { return 'unknown' }
        if (@($dg.SecurityServicesRunning) -contains 2) { return 'on' }
        return 'off'
    } catch { return 'unknown' }
}

function Get-HvciNote {
    # PURE. The line printed beside a signature finding.
    #
    # It states what was MEASURED and the established meaning of the mechanism.
    # It does NOT say "this driver cannot load": that is a guarantee about a
    # specific binary, and claiming it would be the same overreach as the
    # findings this tool exists to keep honest -- just pointed at reassurance
    # instead of alarm.
    #
    # Every state returns a non-empty line. Silence on 'unknown' is exactly the
    # failure this is designed against.
    param([string]$State)
    switch ($State) {
        'on'  { return '[INFO] Memory Integrity (HVCI) is running on this machine, so kernel code integrity is hypervisor-enforced. The finding above still stands -- the file is what it is, and Memory Integrity can be turned off. Section 13 has the full boot-chain state.' }
        'off' { return '[INFO] Memory Integrity (HVCI) is not running, so kernel code integrity is not hypervisor-enforced. Section 13 has the full boot-chain state.' }
        default { return '[INFO] Memory Integrity (HVCI) state could not be determined -- this check may be running without elevation. The finding above is reported at face value, with no assumption either way.' }
    }
}

function Get-DriverVerdict {
    # Returns @{ Sev = 'OK'|'WARNING'|'CRITICAL'; Why = @(...) }.
    #
    # Pure: every input is a parameter or a $script: variable the self-test can
    # set, so the entire grade is exercisable with no machine state at all.
    param([string]$Path, [string]$Hash, $Sig)
    $why = @()
    # NOT named $sev: the script-level $sev is the running maximum across all
    # drivers, and a same-named local here would shadow it. It happens to be
    # safe (the local is assigned before any read) but that is too subtle a
    # thing to leave load-bearing in the function that decides whether a
    # kernel driver is trustworthy.
    $itemSev = 'OK'
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
        $itemSev = 'CRITICAL'
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
            $itemSev = Get-MaxSev $itemSev 'WARNING'
        } else {
            $why += "filename is a known vulnerable/abused driver, and it is unsigned, invalidly signed, or staged outside the drivers directory -- the BYOVD staging pattern"
            $itemSev = 'CRITICAL'
        }
    }
    # Unsigned records whether the SIGNATURE rule fired, so the caller knows
    # whether the Memory Integrity context line is warranted. It never affects
    # the grade -- see Get-HvciNote.
    $unsigned = $false
    if ($itemSev -ne 'CRITICAL' -and -not $sigValid) {
        $st = if ($Sig) { [string]$Sig.Status } else { 'unreadable' }
        $why += "unsigned or invalid Authenticode signature ($st) on a kernel driver"
        $itemSev = Get-MaxSev $itemSev 'WARNING'
        $unsigned = $true
    }
    return @{ Sev = $itemSev; Why = $why; Unsigned = $unsigned }
}

function ConvertTo-EvidenceText {
    # A file name, service name or certificate subject is attacker-chosen text
    # that lands at the start of a report line's value. Strip control
    # characters (a CR/LF would start a new line) and cap the length.
    param([string]$Text, [int]$Max = 200)
    if ($null -eq $Text) { return '' }
    $t = ($Text -replace '[\x00-\x1f\x7f]', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

function Get-SignerCN {
    param([string]$Subject)
    if (-not $Subject) { return '' }
    if ($Subject -match '(?:^|,\s*)CN=("[^"]+"|[^,]+)') { return $Matches[1].Trim('"') }
    return $Subject
}

function Get-DriverEvidenceLines {
    # PURE. The facts a reader needs to triage a flagged driver, printed as
    # indented, tag-free lines directly under the finding (top_findings carries
    # up to six of them beside the finding).
    #
    # A field report printed "PROCEXP152.SYS [ff9b3fc49bb3cd9a...]" and nothing
    # else; the owner then needed three commands and a second opinion to learn
    # what this tool already held: that the driver was on disk with no service
    # and not loaded, and which hash it was -- and the truncated hash could not
    # be looked up anywhere. Every line below is either a fact the tool read or
    # an explicit "not read", never a guess.
    #
    #   -Svc          @{ Service; State; StartMode } when a Win32_SystemDriver
    #                 record points at this file, else $null
    #   -FileInfo     @{ Created; Modified } (DateTime) or $null
    #   -InstallEvent @{ Time; Service } for a matching Event 7045, or $null
    #   -InstallState 'read' | 'unread'; -InstallReason why it was not read
    #   -LogOldest    DateTime of the oldest System record, or $null
    param([string]$Path, [string]$Hash, $Sig, $FileInfo, $Svc,
          $InstallEvent, [string]$InstallState = 'read', [string]$InstallReason = '',
          $LogOldest)
    $fmt = 'yyyy-MM-ddTHH:mm:ss'
    $lines = New-Object System.Collections.Generic.List[string]
    if ($Hash) { $lines.Add('    sha256: ' + $Hash.ToLower() + '  (look it up at loldrivers.io or VirusTotal)') }
    else       { $lines.Add('    sha256: not computed (the file could not be read)') }
    $st = if ($Sig) { [string]$Sig.Status } else { 'unreadable' }
    $cn = ''
    if ($Sig -and $Sig.SignerCertificate) { $cn = Get-SignerCN ([string]$Sig.SignerCertificate.Subject) }
    if ($cn) { $lines.Add('    signer: ' + (ConvertTo-EvidenceText $cn) + ' (Authenticode ' + $st + ')') }
    else     { $lines.Add('    signer: none read (Authenticode ' + $st + ')') }
    if ($FileInfo -and $FileInfo.Created -and $FileInfo.Modified) {
        $lines.Add('    file: created ' + ([datetime]$FileInfo.Created).ToString($fmt) + ', modified ' + ([datetime]$FileInfo.Modified).ToString($fmt))
    } else {
        $lines.Add('    file: times not read')
    }
    if ($Svc -and $Svc.Service) {
        $sn = ConvertTo-EvidenceText ([string]$Svc.Service) 64
        if ([string]$Svc.State -eq 'Running') {
            $lines.Add('    kernel: LOADED -- service ' + $sn + ', state Running, start ' + [string]$Svc.StartMode)
        } else {
            $lines.Add('    kernel: registered, not running -- service ' + $sn + ', state ' + [string]$Svc.State + ', start ' + [string]$Svc.StartMode)
        }
    } else {
        $sn = ''
        $lines.Add('    kernel: on disk only -- no driver service references this file; not loaded')
    }
    if ($InstallState -ne 'read') {
        $lines.Add('    install: Event 7045 not read (' + (ConvertTo-EvidenceText $InstallReason 120) + ')')
    } elseif ($InstallEvent) {
        $lines.Add('    install: Event 7045 at ' + ([datetime]$InstallEvent.Time).ToString($fmt) + ' installed service ' + (ConvertTo-EvidenceText ([string]$InstallEvent.Service) 64))
    } elseif ($LogOldest) {
        $lines.Add('    install: no Event 7045 for this file in the System log (oldest record ' + ([datetime]$LogOldest).ToString($fmt) + ')')
    } else {
        $lines.Add('    install: no Event 7045 for this file in the System log')
    }
    $q = "'" + ((ConvertTo-EvidenceText $Path 400) -replace "'", "''") + "'"
    $verify = '    verify: Get-FileHash -Algorithm SHA256 ' + $q + '; Get-AuthenticodeSignature ' + $q
    if ($sn) { $verify += '; sc query ' + $sn }
    $lines.Add($verify)
    return ,$lines.ToArray()
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
    # A benign_corpus entry keys on a regex matched against report lines, so
    # rewording what this tool emits silently decouples the entry -- the corpus
    # header says as much. The FIRST version of this case hard-coded the regex,
    # which made it stale the moment the entry it named was removed: it went on
    # passing while its stated reason had become false. So read the regex OUT of
    # the corpus at test time. Now renaming, rewording or removing the entry
    # fails here loudly instead of leaving a test guarding nothing.
    $corpusFile = Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) 'tests/benign_corpus.txt'
    $corpusRx = ''
    if (Test-Path -LiteralPath $corpusFile) {
        $inEntry = $false
        foreach ($ln in (Get-Content -LiteralPath $corpusFile)) {
            if ($ln -match '^\s*\[([^\]]+)\]') { $inEntry = ($Matches[1] -eq 'driver-signed-byovd-name'); continue }
            if ($inEntry -and $ln -match '^\s*signature\s*=\s*(.+?)\s*$') { $corpusRx = $Matches[1]; break }
        }
    }
    # Missing file or missing entry is a FAILURE, never a skip: a contract test
    # that quietly passes when it cannot find its contract is worse than absent.
    T 'the [driver-signed-byovd-name] corpus entry and its signature regex exist' `
      ([bool]$corpusRx) "corpusFile=$corpusFile"
    $vb = Get-DriverVerdict -Path 'C:\Windows\System32\drivers\vboxdrv.sys' -Hash 'aa' -Sig (FakeSig 'Valid')
    $bmsg = ($vb.Why -join '; ')
    T 'the emitted message still matches that corpus signature regex' `
      ($corpusRx -and ($bmsg -match $corpusRx)) "rx=[$corpusRx] msg=[$bmsg]"

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

    # --- Memory Integrity context -----------------------------------------
    # The probe is NEVER called here: this self-test runs on ubuntu-latest in
    # lint.yml, where the DeviceGuard CIM namespace does not exist. That is why
    # the note is a pure function taking a state.
    $onNote  = Get-HvciNote -State 'on'
    $offNote = Get-HvciNote -State 'off'
    $unkNote = Get-HvciNote -State 'unknown'
    T 'the HVCI note says running when Memory Integrity is on' `
      ($onNote -match 'is running' -and $onNote -match 'hypervisor-enforced') $onNote
    T 'the HVCI note says NOT running when Memory Integrity is off' `
      ($offNote -match 'is not running') $offNote
    # Silence on 'unknown' is the failure mode this was designed against: the
    # tool is not admin-gated in the non-admin bat, so unelevated runs are real.
    T 'an UNKNOWN Memory Integrity state still produces a line, and says so' `
      ($unkNote -match 'could not be determined') $unkNote
    T 'every HVCI state produces a non-empty [INFO] line' `
      ((@($onNote, $offNote, $unkNote) | Where-Object { $_ -notmatch '^\[INFO\] \S' }).Count -eq 0) `
      "on=[$onNote] off=[$offNote] unknown=[$unkNote]"
    # The context must never be mistaken for a verdict downgrade.
    T 'the HVCI-on note states the finding still stands' `
      ($onNote -match 'still stands') $onNote

    # Unsigned tells the caller whether the context line is warranted. It must
    # follow the SIGNATURE rule, not the severity: a known-bad hash is CRITICAL
    # without the signature rule firing at all.
    $v = Get-DriverVerdict -Path $normal -Hash 'aa' -Sig (FakeSig 'NotSigned')
    T 'Unsigned is true when the signature rule fires' ($v.Unsigned -eq $true) "$($v.Unsigned)"
    $v = Get-DriverVerdict -Path $normal -Hash 'aa' -Sig $null
    T 'Unsigned is true when the signature is unreadable' ($v.Unsigned -eq $true) "$($v.Unsigned)"
    $v = Get-DriverVerdict -Path $normal -Hash 'aa' -Sig (FakeSig 'Valid')
    T 'Unsigned is false for a validly signed driver' ($v.Unsigned -eq $false) "$($v.Unsigned)"
    $v = Get-DriverVerdict -Path $normal -Hash 'dead00000000000000000000000000000000000000000000000000000000beef' -Sig (FakeSig 'Valid')
    T 'Unsigned is false for a known-bad hash that is validly signed' `
      ($v.Unsigned -eq $false -and $v.Sev -eq 'CRITICAL') "unsigned=$($v.Unsigned) sev=$($v.Sev)"

    # --- Evidence beside a finding ------------------------------------------
    # Pinned from the field report that motivated it: PROCEXP152.SYS, signed by
    # Sysinternals, on disk with no service, no install event retained.
    $full = 'ff9b3fc49bb3cd9a' + ('0' * 48)
    $sigP = New-Object PSObject -Property @{ Status = 'Valid'; SignerCertificate = (New-Object PSObject -Property @{ Subject = 'CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' }) }
    $fiP  = @{ Created = [datetime]'2026-09-12T10:01:02'; Modified = [datetime]'2024-03-01T08:00:00' }
    $pp   = 'C:\WINDOWS\System32\drivers\PROCEXP152.SYS'
    $ev = Get-DriverEvidenceLines -Path $pp -Hash $full.ToUpper() -Sig $sigP -FileInfo $fiP -Svc $null -InstallEvent $null -InstallState 'read' -LogOldest ([datetime]'2026-08-01T00:00:00')
    $evj = $ev -join "`n"
    T 'evidence: the FULL sha256 is printed, lower-case, never truncated' `
      (($evj -match ('sha256: ' + $full + '\b')) -and ($evj -notmatch [regex]::Escape('ff9b3fc49bb3cd9a...'))) $evj
    T 'evidence: the signer CN and Authenticode status are named' `
      ($evj -match 'signer: Microsoft Windows Hardware Compatibility Publisher \(Authenticode Valid\)') $evj
    T 'evidence: file creation and modification times are printed' `
      ($evj -match 'file: created 2026-09-12T10:01:02, modified 2024-03-01T08:00:00') $evj
    T 'evidence: a file no driver service references reads on disk only, not loaded' `
      ($evj -match 'kernel: on disk only -- no driver service references this file; not loaded') $evj
    T 'evidence: no matching install event names how far back the log reaches' `
      ($evj -match 'install: no Event 7045 for this file in the System log \(oldest record 2026-08-01T00:00:00\)') $evj
    T 'evidence: the verify line quotes the path and has no sc query without a service' `
      (($evj -match [regex]::Escape("verify: Get-FileHash -Algorithm SHA256 '$pp'; Get-AuthenticodeSignature '$pp'")) -and ($evj -notmatch 'sc query')) $evj
    T 'evidence: every line is indented and carries no severity tag' `
      ((@($ev | Where-Object { $_ -notmatch '^    [a-z0-9]+: ' -or $_ -match '\[(CRITICAL|WARNING|OK|INFO|SKIPPED)\]' })).Count -eq 0) $evj

    $ev = Get-DriverEvidenceLines -Path $pp -Hash $full -Sig $sigP -FileInfo $fiP -Svc @{ Service = 'PROCEXP152'; State = 'Running'; StartMode = 'Manual' } -InstallEvent @{ Time = [datetime]'2026-09-12T10:01:03'; Service = 'PROCEXP152' } -InstallState 'read'
    $evj = $ev -join "`n"
    T 'evidence: a running driver service reads LOADED with its name, state and start mode' `
      ($evj -match 'kernel: LOADED -- service PROCEXP152, state Running, start Manual') $evj
    T 'evidence: a matching Event 7045 gives the install time and service' `
      ($evj -match 'install: Event 7045 at 2026-09-12T10:01:03 installed service PROCEXP152') $evj
    T 'evidence: with a service, the verify line adds sc query <service>' ($evj -match 'sc query PROCEXP152$') $evj

    $ev = Get-DriverEvidenceLines -Path $pp -Hash $full -Sig $sigP -FileInfo $fiP -Svc @{ Service = 'PROCEXP152'; State = 'Stopped'; StartMode = 'Demand' } -InstallState 'unread' -InstallReason 'Attempted to perform an unauthorized operation.'
    $evj = $ev -join "`n"
    T 'evidence: a stopped driver service reads registered, not running' `
      ($evj -match 'kernel: registered, not running -- service PROCEXP152, state Stopped, start Demand') $evj
    T 'evidence: an unreadable System log says not read and why, never "no event"' `
      (($evj -match 'install: Event 7045 not read \(Attempted to perform an unauthorized operation\.\)') -and ($evj -notmatch 'no Event 7045')) $evj

    $ev = Get-DriverEvidenceLines -Path 'C:\Users\Public\x.sys' -Hash $null -Sig $null -FileInfo $null -Svc $null -InstallState 'read'
    $evj = $ev -join "`n"
    T 'evidence: unhashable, unsigned and unreadable times each say so' `
      (($evj -match 'sha256: not computed') -and ($evj -match 'signer: none read \(Authenticode unreadable\)') -and ($evj -match 'file: times not read')) $evj

    $evil = "C:\Users\Public\a`r`n[CRITICAL] fake.sys"
    $ev = Get-DriverEvidenceLines -Path $evil -Hash $full -Sig (FakeSig 'NotSigned') -FileInfo $null -Svc @{ Service = "s`n[OK] x"; State = 'Running'; StartMode = 'Auto' } -InstallState 'read'
    T 'evidence: a crafted path or service name cannot start a new line' `
      ((@($ev | Where-Object { $_ -match "[`r`n]" })).Count -eq 0 -and (@($ev | Where-Object { $_ -match '^\[' })).Count -eq 0) ($ev -join ' | ')

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
# Which driver service (if any) points at each file, and whether it is running:
# the first thing a reader asks about a flagged driver is whether it is in the
# kernel right now or just sitting on disk.
$svcByPath = @{}
try {
    foreach ($d in (Get-CimInstance Win32_SystemDriver -EA Stop)) {
        $pn = [string]$d.PathName
        if ($pn) {
            $pn = $pn -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
            $pn = [Environment]::ExpandEnvironmentVariables($pn)
            [void]$paths.Add($pn)
            $svcByPath[$pn.ToLower()] = @{ Service = [string]$d.Name; State = [string]$d.State; StartMode = [string]$d.StartMode }
        }
    }
} catch {
    '[WARNING] Win32_SystemDriver enumeration failed -- loaded-driver set not audited.'
    $gapSev = Get-MaxSev $gapSev 'WARNING'
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

# Event 7045 (service installed), read once and only when something is flagged:
# the install time is the timeline answer -- a driver extracted by a tool the
# owner ran, or one staged at an hour nobody was at the machine.
$installEvents = $null
function Get-DriverInstallEvents {
    $r = @{ State = 'read'; Reason = ''; Events = @(); Oldest = $null }
    try {
        $r.Events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045 } -MaxEvents 500 -EA Stop |
            ForEach-Object { @{ Time = $_.TimeCreated; Service = [string]$_.Properties[0].Value; Image = [string]$_.Properties[1].Value } })
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            $r.State = 'unread'; $r.Reason = $_.Exception.Message
            return $r
        }
    }
    try { $r.Oldest = (Get-WinEvent -LogName System -MaxEvents 1 -Oldest -EA Stop).TimeCreated } catch {}
    return $r
}

$checked = 0
$missing = 0
$anyUnsigned = $false
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
    if ($v.Unsigned) { $anyUnsigned = $true }

    if ($v.Sev -ne 'OK') {
        # The finding line ends with ':' and the evidence follows it, indented
        # and untagged, so it reads as one finding and top_findings carries it.
        "[$($v.Sev)] Driver $(ConvertTo-EvidenceText $p 400) -- $($v.Why -join '; '):"
        $fi = $null
        try { $it = Get-Item -LiteralPath $p -EA Stop; $fi = @{ Created = $it.CreationTime; Modified = $it.LastWriteTime } } catch {}
        if ($null -eq $installEvents) { $installEvents = Get-DriverInstallEvents }
        $ie = $null
        $leaf = (($p -split '[\\/]')[-1]).ToLower()
        foreach ($e in $installEvents.Events) {
            if ((([string]$e.Image -split '[\\/]')[-1]).ToLower() -eq $leaf) { $ie = $e; break }
        }
        # Emit each line on its own: the function returns one array object, and
        # a caller that joins this tool's output would otherwise print it as
        # 'System.String[]'.
        $evLines = Get-DriverEvidenceLines -Path $p -Hash $hash -Sig $sig -FileInfo $fi -Svc $svcByPath[$p.ToLower()] `
            -InstallEvent $ie -InstallState $installEvents.State -InstallReason $installEvents.Reason -LogOldest $installEvents.Oldest
        foreach ($el in $evLines) { $el }
        $sev = Get-MaxSev $sev $v.Sev
    }
}

# ONE line, after the drivers, and only when a signature finding exists.
# Per-driver would repeat it; on a clean machine it would be noise. It is
# [INFO] and never touches $sev: an unsigned kernel driver is a finding whether
# or not Memory Integrity is running. Downgrading a real finding because a
# mitigating control happens to be present is the false reassurance this repo
# treats as its worst failure -- and the mitigation can be switched off while
# the file stays wrong.
if ($anyUnsigned) {
    Get-HvciNote -State (& $script:HvciProbe)
}

if ($sev -eq 'OK' -and $gapSev -eq 'OK') {
    "[OK] $checked kernel driver(s) audited -- none known-bad, all validly signed."
} elseif ($missing -gt 0) {
    "[INFO] $missing driver(s) could not be examined because their files are absent; $checked were fully audited."
}
Write-Marker -Name 'driver' -Sev $sev
if ($gapSev -ne 'OK') { Write-Marker -Name 'driver_gap' -Sev $gapSev }
