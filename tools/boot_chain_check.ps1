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
    [string]$MarkerDir = $env:TEMP
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

$sev = 'OK'
'--- [T1542] Boot-chain configuration audit (config + known-bad indicators, NOT a firmware scan) ---'

# ---- 1. Boot-loader integrity flags (bcdedit) -----------------------------
$bcd = ''
try { $bcd = (& bcdedit /enum ALL 2>$null | Out-String) } catch {}
if (-not $bcd) {
    try { $bcd = (& bcdedit /enum '{current}' 2>$null | Out-String) } catch {}
}
if (-not $bcd) {
    '[SKIPPED] bcdedit produced no output -- boot-loader integrity flags NOT checked (needs admin).'
    $sev = Get-MaxSev $sev 'WARNING'
} else {
    # nointegritychecks Yes -> kernel code-signing enforcement disabled.
    if ($bcd -match '(?im)^\s*nointegritychecks\s+Yes\b') {
        '[CRITICAL] Boot config: nointegritychecks = Yes (T1542.003) -- kernel driver-signature enforcement is OFF; unsigned or tampered kernel code can load. Fix: bcdedit /set nointegritychecks off'
        $sev = Get-MaxSev $sev 'CRITICAL'
    } else {
        '[OK] Boot config: kernel integrity checks are enforced (nointegritychecks not set).'
    }
    # bootdebug / kernel debug attached.
    if ($bcd -match '(?im)^\s*bootdebug\s+Yes\b') {
        '[WARNING] Boot config: bootdebug = Yes (T1542.003) -- a boot debugger is enabled and can subvert early boot. Fix: bcdedit /bootdebug off'
        $sev = Get-MaxSev $sev 'WARNING'
    }
    if ($bcd -match '(?im)^\s*debug\s+Yes\b') {
        '[WARNING] Boot config: kernel debug = Yes (T1542.003) -- a kernel debugger can read/modify kernel memory and bypass driver signing. Fix: bcdedit /debug off'
        $sev = Get-MaxSev $sev 'WARNING'
    }
    if (($bcd -notmatch '(?im)^\s*bootdebug\s+Yes\b') -and ($bcd -notmatch '(?im)^\s*debug\s+Yes\b')) {
        '[OK] Boot config: no boot or kernel debugger enabled.'
    }
}

# ---- 2. Secure Boot depth (real UEFI only) --------------------------------
# SetupMode: keys replaceable without validation.
$smOk = $true
$sm = $null
try { $sm = (Get-SecureBootUEFI -Name SetupMode -EA Stop).Bytes } catch { $smOk = $false }
if (-not $smOk -or $null -eq $sm) {
    '[SKIPPED] Secure Boot UEFI variables not readable -- legacy BIOS, a VM without them, or no privilege. Secure Boot depth NOT checked (Secure Boot on/off is reported separately in this section).'
} else {
    if ($sm[0] -eq 1) {
        '[WARNING] Secure Boot is in SETUP MODE (T1542.001) -- platform keys can be replaced without validation, the precursor to enrolling a malicious boot chain. Complete Secure Boot setup / restore factory keys in firmware.'
        $sev = Get-MaxSev $sev 'WARNING'
    } else {
        '[OK] Secure Boot is in user mode (keys are locked; not in setup mode).'
    }
    # dbx revocation list population.
    $dbx = $null
    try { $dbx = (Get-SecureBootUEFI -Name dbx -EA Stop).Bytes } catch {}
    if ($null -ne $dbx) {
        $len = $dbx.Length
        # A maintained dbx is many KB (Microsoft has revoked a long list of
        # vulnerable loaders). An essentially-empty dbx means those revocations
        # are absent -- known bootkit loaders would not be blocked. Threshold is
        # deliberately low so only a genuinely bare dbx is flagged.
        if ($len -lt 512) {
            "[WARNING] Secure Boot revocation list (dbx) is only $len bytes (T1542) -- known-bad bootloader revocations appear ABSENT, so a known bootkit loader may not be blocked. Refresh via Windows Update / the DBX update (KB4535680)."
            $sev = Get-MaxSev $sev 'WARNING'
        } else {
            "[OK] Secure Boot revocation list (dbx) is populated ($len bytes) -- known bootloader revocations are present."
        }
    }
}

# ---- 3. Memory integrity (informational context, never raised) ------------
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -EA Stop
    $running = @($dg.SecurityServicesRunning)
    $hvci = ($running -contains 2)
    $vbs = ($dg.VirtualizationBasedSecurityStatus -eq 2)
    if ($vbs) { '[INFO] Virtualization-Based Security is running.' } else { '[INFO] Virtualization-Based Security is not running (optional hardening; not a compromise indicator).' }
    if ($hvci) { '[INFO] HVCI / Memory Integrity is running -- kernel code-integrity is hypervisor-enforced.' } else { '[INFO] HVCI / Memory Integrity is not running -- enabling it strongly raises the bar against kernel/bootkit tampering (Settings > Core isolation).' }
} catch {
    '[INFO] DeviceGuard status not available on this edition/platform.'
}

Write-Marker -Name 'bootchain' -Sev $sev
