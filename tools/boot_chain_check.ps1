# boot_chain_check.ps1 -- audit the boot chain's CONFIGURATION and known-bad
# indicators (T1542 Pre-OS Boot). Invoked from Section 13.
#
# THE CEILING, STATED FIRST BECAUSE IT MATTERS MOST: this is a user-mode tool.
# It audits what the OS and firmware EXPOSE about the boot chain -- boot-loader
# integrity flags, Secure Boot state and its revocation list, memory-integrity
# status. It CANNOT scan the firmware image, cannot read SPI flash, and cannot
# trust that firmware is telling it the truth. A bootkit that has already
# subverted the boot chain (BlackLotus, CosmicStrand) can lie to every query
# here. So this is "is the boot chain CONFIGURED to resist a bootkit, and are
# the known revocations in place" -- not "is the firmware clean". Findings and
# the report say so, so a clean result is never mistaken for a firmware scan.
# (This is the honest framing recorded in docs/design/backlog.md before it was
# built; overclaiming here would be the exact false-safety failure Tier 0
# exists to prevent.)
#
# WHAT IS CHECKED
#   Boot-loader integrity (bcdedit -- works on any machine incl. a VM):
#     nointegritychecks = Yes  -> CRITICAL. Kernel-mode code-signing enforcement
#                                 is OFF. Unsigned/tampered drivers load freely;
#                                 this is a direct bootkit/rootkit enabler and,
#                                 unlike testsigning, is rarely set for any
#                                 legitimate reason. (testsigning is already
#                                 raised by the dedicated Section 13 check, so it
#                                 is deliberately NOT re-raised here.)
#     bootdebug / debug = On   -> WARNING. A boot or kernel debugger can inspect
#                                 and modify the kernel and bypass driver-signing
#                                 -- no ordinary reason on a user's PC.
#   Secure Boot depth (real UEFI only; [SKIPPED] on legacy BIOS or a VM without
#   the vars):
#     SetupMode = 1            -> WARNING. Secure Boot is in setup mode: its keys
#                                 can be replaced without validation, the
#                                 precursor to enrolling a malicious boot chain.
#     dbx essentially empty    -> WARNING. The UEFI revocation list (dbx) blocks
#                                 known-bad bootloaders. A near-empty dbx means
#                                 known bootkit loaders are NOT revoked; refresh
#                                 via Windows Update / the DBX update.
#   Memory integrity (informational context, never raised):
#     VBS / HVCI running state via Win32_DeviceGuard.
#
# MARKER: max severity word to $env:TEMP\dz_bootchain.txt; caller raises via
# :dz_finding. No marker when the boot chain is configured soundly (or when
# every deep check was skipped for lack of real UEFI).
#
# Windows PowerShell 5.1 compatible. Read-only. Executed by helpers-ps51 CI
# (where the Secure Boot depth checks will [SKIPPED] on the VM runner, which is
# the correct, honest degradation -- the bcdedit checks still run).

[CmdletBinding()]
param(
    [string]$MarkerDir = $env:TEMP,
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


# ---------------------------------------------------------------------------
# The three grading rules of this check, as PURE functions: text and bytes in,
# lines and a severity out. No bcdedit, no UEFI variables, no CIM -- so the
# whole thing is exercisable by -SelfTest on any platform.
#
# The benign half is what needed covering. Secure Boot in setup mode and a
# bare dbx are rare; a legacy BIOS, a VM with no UEFI variables, and VBS/HVCI
# switched off are the ORDINARY state of consumer hardware, and this check
# must not read any of them as a compromise.
# ---------------------------------------------------------------------------

function Get-BcdVerdict {
    # $BcdText is bcdedit's output, or '' when it produced none.
    param([string]$BcdText)
    $r = @{ Lines = @(); Sev = 'OK' }
    if (-not $BcdText) {
        # "Unavailable" is not an answer: declared as a gap, never absorbed.
        $r.Lines += '[SKIPPED] bcdedit produced no output -- boot-loader integrity flags NOT checked (needs admin).'
        $r.Sev = 'WARNING'
        return $r
    }
    if ($BcdText -match '(?im)^\s*nointegritychecks\s+Yes\b') {
        $r.Lines += '[CRITICAL] Boot config: nointegritychecks = Yes (T1542.003) -- kernel driver-signature enforcement is OFF; unsigned or tampered kernel code can load. Fix: bcdedit /set nointegritychecks off'
        $r.Sev = Get-MaxSev $r.Sev 'CRITICAL'
    } else {
        $r.Lines += '[OK] Boot config: kernel integrity checks are enforced (nointegritychecks not set).'
    }
    if ($BcdText -match '(?im)^\s*bootdebug\s+Yes\b') {
        $r.Lines += '[WARNING] Boot config: bootdebug = Yes (T1542.003) -- a boot debugger is enabled and can subvert early boot. Fix: bcdedit /bootdebug off'
        $r.Sev = Get-MaxSev $r.Sev 'WARNING'
    }
    if ($BcdText -match '(?im)^\s*debug\s+Yes\b') {
        $r.Lines += '[WARNING] Boot config: kernel debug = Yes (T1542.003) -- a kernel debugger can read/modify kernel memory and bypass driver signing. Fix: bcdedit /debug off'
        $r.Sev = Get-MaxSev $r.Sev 'WARNING'
    }
    if (($BcdText -notmatch '(?im)^\s*bootdebug\s+Yes\b') -and ($BcdText -notmatch '(?im)^\s*debug\s+Yes\b')) {
        $r.Lines += '[OK] Boot config: no boot or kernel debugger enabled.'
    }
    return $r
}

function Get-SecureBootVerdict {
    # $SetupMode and $Dbx are the raw UEFI variable bytes, or $null when the
    # variable could not be read. $Readable is $false on legacy BIOS or a VM
    # without the variables -- the ordinary case, and NOT a finding.
    param([byte[]]$SetupMode, [byte[]]$Dbx, [bool]$Readable = $true)
    $r = @{ Lines = @(); Sev = 'OK' }
    if (-not $Readable -or $null -eq $SetupMode -or $SetupMode.Length -eq 0) {
        # Legacy BIOS and VMs are not compromised machines. Declared as not
        # checked, at OK -- this is the single most common state this function
        # will ever see and it must never raise.
        $r.Lines += '[SKIPPED] Secure Boot UEFI variables not readable -- legacy BIOS, a VM without them, or no privilege. Secure Boot depth NOT checked (Secure Boot on/off is reported separately in this section).'
        return $r
    }
    if ($SetupMode[0] -eq 1) {
        $r.Lines += '[WARNING] Secure Boot is in SETUP MODE (T1542.001) -- platform keys can be replaced without validation, the precursor to enrolling a malicious boot chain. Complete Secure Boot setup / restore factory keys in firmware.'
        $r.Sev = Get-MaxSev $r.Sev 'WARNING'
    } else {
        $r.Lines += '[OK] Secure Boot is in user mode (keys are locked; not in setup mode).'
    }
    if ($null -ne $Dbx) {
        $len = $Dbx.Length
        # A maintained dbx is many KB. The threshold is deliberately low so
        # only a genuinely bare list is flagged.
        if ($len -lt 512) {
            $r.Lines += "[WARNING] Secure Boot revocation list (dbx) is only $len bytes (T1542) -- known-bad bootloader revocations appear ABSENT, so a known bootkit loader may not be blocked. Refresh via Windows Update / the DBX update (KB4535680)."
            $r.Sev = Get-MaxSev $r.Sev 'WARNING'
        } else {
            $r.Lines += "[OK] Secure Boot revocation list (dbx) is populated ($len bytes) -- known bootloader revocations are present."
        }
    }
    return $r
}

function Get-DeviceGuardNote {
    # VBS and HVCI are CONTEXT, never a finding: most consumer hardware has
    # them off. $null means the query could not answer, which must read as
    # "could not be determined" and never as "not running" -- stating
    # hardening as absent when it merely could not be read is the false
    # reassurance this project treats as its worst failure, inverted.
    param($VbsStatus, $SecurityServicesRunning, [bool]$Available = $true)
    $lines = @()
    if (-not $Available) {
        $lines += '[INFO] DeviceGuard status not available on this edition/platform.'
        return $lines
    }
    if ($null -eq $VbsStatus)      { $lines += '[INFO] Virtualization-Based Security state could not be determined on this edition/platform.' }
    elseif ($VbsStatus -eq 2)      { $lines += '[INFO] Virtualization-Based Security is running.' }
    else                           { $lines += '[INFO] Virtualization-Based Security is not running (optional hardening; not a compromise indicator).' }
    if ($null -eq $SecurityServicesRunning)          { $lines += '[INFO] HVCI / Memory Integrity state could not be determined on this edition/platform.' }
    elseif (@($SecurityServicesRunning) -contains 2) { $lines += '[INFO] HVCI / Memory Integrity is running -- kernel code-integrity is hypervisor-enforced.' }
    else                                             { $lines += '[INFO] HVCI / Memory Integrity is not running -- enabling it strongly raises the bar against kernel/bootkit tampering (Settings > Core isolation).' }
    return $lines
}

if ($SelfTest) {
    $script:stFails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name :: $Got"; $script:stFails++ } }
    $J = { param($v) ($v.Lines -join ' | ') }
    $W = { param($v) @($v.Lines | Where-Object { $_ -match '^\[(WARNING|CRITICAL)\]' }).Count }

    # An ordinary Windows 11 boot entry, as bcdedit prints it. This is the
    # shape the check sees on virtually every machine it will ever run on,
    # and it must produce nothing but [OK].
    $cleanBcd = @'
Windows Boot Manager
--------------------
identifier              {bootmgr}
device                  partition=\Device\HarddiskVolume1
description             Windows Boot Manager
locale                  en-US
inherit                 {globalsettings}
default                 {current}
resumeobject            {7619dcc9-0000-0000-0000-000000000000}
displayorder            {current}
toolsdisplayorder       {memdiag}
timeout                 30

Windows Boot Loader
-------------------
identifier              {current}
device                  partition=C:
path                    \WINDOWS\system32\winload.efi
description             Windows 11
locale                  en-US
inherit                 {bootloadersettings}
recoverysequence        {7619dccb-0000-0000-0000-000000000000}
displaymessageoverride  Recovery
recoveryenabled         Yes
allowedinmemorysettings 0x15000075
osdevice                partition=C:
systemroot              \WINDOWS
resumeobject            {7619dcc9-0000-0000-0000-000000000000}
nx                      OptIn
bootmenupolicy          Standard
'@
    $v = Get-BcdVerdict -BcdText $cleanBcd
    T 'an ordinary Windows 11 boot entry raises nothing' ($v.Sev -eq 'OK' -and (& $W $v) -eq 0) (& $J $v)
    # 'recoveryenabled Yes' is present in that dump. A regex not anchored to
    # the start of the line would match 'enabled Yes' and fire on every PC.
    T 'recoveryenabled Yes is not read as a debugger' ((& $J $v) -notmatch '\[WARNING\][^|]*debug') (& $J $v)
    T 'the clean entry states both things it checked' `
      ((& $J $v) -match 'integrity checks are enforced' -and (& $J $v) -match 'no boot or kernel debugger') (& $J $v)

    # The true-positive direction.
    T 'nointegritychecks Yes is CRITICAL' `
      ((Get-BcdVerdict -BcdText "identifier {current}`nnointegritychecks Yes").Sev -eq 'CRITICAL') 'not raised'
    T 'bootdebug Yes is WARNING' `
      ((Get-BcdVerdict -BcdText "identifier {current}`nbootdebug Yes").Sev -eq 'WARNING') 'not raised'
    T 'debug Yes is WARNING' `
      ((Get-BcdVerdict -BcdText "identifier {current}`ndebug Yes").Sev -eq 'WARNING') 'not raised'
    T 'the flags are matched case-insensitively' `
      ((Get-BcdVerdict -BcdText "NOINTEGRITYCHECKS YES").Sev -eq 'CRITICAL') 'case-sensitive'
    # ...and the negative forms must not fire.
    foreach ($off in @('nointegritychecks No', 'bootdebug No', 'debug No')) {
        T "'$off' is the normal state and raises nothing" ((Get-BcdVerdict -BcdText $off).Sev -eq 'OK') 'raised'
    }
    T 'no bcdedit output is declared as a GAP, not as clean' `
      ((Get-BcdVerdict -BcdText '').Sev -eq 'WARNING' -and (Get-BcdVerdict -BcdText '').Lines[0] -match '^\[SKIPPED\]') 'absorbed as calm'

    # Secure Boot. The unreadable case is legacy BIOS and every VM -- by far
    # the most common state, and it must never raise.
    $v = Get-SecureBootVerdict -SetupMode $null -Dbx $null -Readable $false
    T 'legacy BIOS / a VM without UEFI variables is NOT a finding' ($v.Sev -eq 'OK' -and (& $W $v) -eq 0) (& $J $v)
    T 'and it says the depth check did not run' ((& $J $v) -match '^\[SKIPPED\].*NOT checked') (& $J $v)
    $v = Get-SecureBootVerdict -SetupMode ([byte[]]@(0)) -Dbx (New-Object 'byte[]' 4096)
    T 'user mode with a populated dbx is the healthy shape and raises nothing' ($v.Sev -eq 'OK' -and (& $W $v) -eq 0) (& $J $v)
    $v = Get-SecureBootVerdict -SetupMode ([byte[]]@(1)) -Dbx (New-Object 'byte[]' 4096)
    T 'SetupMode=1 raises WARNING' ($v.Sev -eq 'WARNING' -and (& $J $v) -match 'SETUP MODE') (& $J $v)
    $v = Get-SecureBootVerdict -SetupMode ([byte[]]@(0)) -Dbx (New-Object 'byte[]' 16)
    T 'a bare dbx raises WARNING' ($v.Sev -eq 'WARNING' -and (& $J $v) -match 'dbx\) is only 16 bytes') (& $J $v)
    $v = Get-SecureBootVerdict -SetupMode ([byte[]]@(0)) -Dbx (New-Object 'byte[]' 512)
    T 'a dbx exactly at the 512-byte threshold is populated, not bare' ($v.Sev -eq 'OK') (& $J $v)
    $v = Get-SecureBootVerdict -SetupMode ([byte[]]@(0)) -Dbx $null
    T 'an unreadable dbx alongside a readable SetupMode says nothing about dbx' `
      ($v.Sev -eq 'OK' -and (& $J $v) -notmatch 'dbx') (& $J $v)

    # DeviceGuard is CONTEXT. Most consumer hardware has VBS and HVCI off,
    # and tests/benign_corpus.txt carries [vbs-off] for exactly that.
    foreach ($case in @(
        @{ Vbs = $null; Hvci = $null; Want = 'could not be determined' },
        @{ Vbs = 0;     Hvci = @();   Want = 'is not running' },
        @{ Vbs = 2;     Hvci = @(2);  Want = 'is running' })) {
        $l = (Get-DeviceGuardNote -VbsStatus $case.Vbs -SecurityServicesRunning $case.Hvci) -join ' | '
        T ("DeviceGuard state '{0}' is [INFO] only, never a finding" -f $case.Want) `
          (@($l -split ' \| ' | Where-Object { $_ -notmatch '^\[INFO\]' }).Count -eq 0 -and $l -match [regex]::Escape($case.Want)) $l
    }
    # The #210 fix: a $null must read as unknown, never as "not running".
    $l = (Get-DeviceGuardNote -VbsStatus $null -SecurityServicesRunning $null) -join ' | '
    T 'a null DeviceGuard reading is never reported as "not running"' ($l -notmatch 'is not running') $l
    $l = (Get-DeviceGuardNote -VbsStatus 0 -SecurityServicesRunning @() -Available $false) -join ' | '
    T 'no DeviceGuard class at all is stated, not guessed' ($l -match 'not available on this edition') $l

    if ($script:stFails) { Write-Output "[FAIL] $($script:stFails) boot_chain_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] boot_chain_check self-test: an ordinary boot entry, a legacy BIOS and VBS/HVCI switched off all raise nothing, while nointegritychecks, a debugger, setup mode and a bare dbx still do.'
    exit 0
}

$sev = 'OK'
'--- [T1542] Boot-chain configuration audit (config + known-bad indicators, NOT a firmware scan) ---'

# ---- 1. Boot-loader integrity flags (bcdedit) -----------------------------
$bcd = ''
try { $bcd = (& bcdedit /enum ALL 2>$null | Out-String) } catch {}
if (-not $bcd) {
    try { $bcd = (& bcdedit /enum '{current}' 2>$null | Out-String) } catch {}
}
# Reading is above; Get-BcdVerdict decides, from the text alone.
$bv = Get-BcdVerdict -BcdText $bcd
foreach ($l in $bv.Lines) { $l }
$sev = Get-MaxSev $sev $bv.Sev

# ---- 2. Secure Boot depth (real UEFI only) --------------------------------
# SetupMode: keys replaceable without validation.
$smOk = $true
$sm = $null
try { $sm = (Get-SecureBootUEFI -Name SetupMode -EA Stop).Bytes } catch { $smOk = $false }
$dbx = $null
if ($smOk) { try { $dbx = (Get-SecureBootUEFI -Name dbx -EA Stop).Bytes } catch {} }
$sbv = Get-SecureBootVerdict -SetupMode $sm -Dbx $dbx -Readable $smOk
foreach ($l in $sbv.Lines) { $l }
$sev = Get-MaxSev $sev $sbv.Sev

# ---- 3. Memory integrity (informational context, never raised) ------------
# A NULL property is UNKNOWN, not "off". Some editions return the instance
# with nothing in these fields, and an earlier version read that as
# "Virtualization-Based Security is not running" / "HVCI is not running" --
# stating a fact it had not established. Reporting hardening as absent when it
# merely could not be read is the same error as reporting a check clean when
# it never ran, and tools/driver_audit.ps1 now cites this state beside a
# signature finding, so the distinction has to be real. The rule lives in
# Get-DeviceGuardNote so the self-test covers all three states; this runner is
# Linux in lint.yml, where the DeviceGuard namespace does not exist.
$dg = $null
$dgAvailable = $true
try { $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -EA Stop } catch { $dgAvailable = $false }
if ($dgAvailable -and $null -eq $dg) { $dgAvailable = $false }
$vbs = $null; $ssr = $null
if ($dgAvailable) { $vbs = $dg.VirtualizationBasedSecurityStatus; $ssr = $dg.SecurityServicesRunning }
foreach ($l in (Get-DeviceGuardNote -VbsStatus $vbs -SecurityServicesRunning $ssr -Available $dgAvailable)) { $l }

Write-Marker -Name 'bootchain' -Sev $sev
