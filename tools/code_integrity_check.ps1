# code_integrity_check.ps1 -- Section 13: can unsigned kernel drivers load on
# this boot? Asked of the RUNNING KERNEL, not of the boot configuration text.
#
# The check it replaces was
#   bcdedit /enum | findstr /i /c:"testsigning Yes"   ...   else [OK]
# and the dashboard tile re-ran the same bcdedit read. Three ways it printed
# "[OK] Driver signature enforcement active." having looked at nothing:
#   * bcdedit prints its values in the system language ("Ja", "Oui", "Si"),
#     so on a non-English Windows "testsigning Yes" never matched;
#   * bcdedit needs administrator: on a standard-user token it prints "Access
#     is denied", findstr finds nothing, and the no-admin bat deferred the
#     whole check instead;
#   * a bcdedit that failed for any other reason read the same as a clean one.
# And a boot-configuration value is only the INTENT (it takes effect at the
# next restart). CLAUDE.md: "A registry value is the intent; the boot event is
# the fact."
#
# THE FACT: NtQuerySystemInformation(SystemCodeIntegrityInformation) returns
# the options Code Integrity is enforcing right now (Microsoft documents the
# structure and every flag on the NtQuerySystemInformation page, winternl.h):
#   0x01 CODEINTEGRITY_OPTION_ENABLED            kernel-mode CI enforced
#   0x02 CODEINTEGRITY_OPTION_TESTSIGN           test-signed content allowed
#   0x80 CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED  a kernel debugger is attached
#                                                and CI may allow unsigned code
#   0x400 CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED memory integrity (context)
# A number, the same in every language, and readable by a standard user.
#
# THE RULE (pure, in Get-CodeIntegrityVerdict, pinned by -SelfTest):
#   * ENABLED off       -> CRITICAL: kernel code integrity is not enforced;
#   * TESTSIGN on       -> WARNING (the wording the bats always printed);
#   * DEBUGMODE on      -> WARNING;
#   * none of those     -> [OK], and the options are printed in hex;
#   * the kernel did not answer -> [WARNING] ... NOT performed, a raised gap,
#     never [OK]. There is no fallback to bcdedit's text: it is the localized
#     reading this tool exists to stop trusting.
#
# Markers (in -MarkerDir): dz_codeint_crit.txt, dz_codeint_testsign.txt,
# dz_codeint_debug.txt, dz_codeint_gap.txt, and dz_codeint_done.txt written
# last. -StateFile gets one word list the dashboard tile states, never
# re-measures: ok | gap | nointegrity,testsign,debug (any of the three).
#
# Usage:
#   powershell -File tools\code_integrity_check.ps1 [-MarkerDir <dir>] [-StateFile <f>]
#   powershell -File tools\code_integrity_check.ps1 -SelfTest   (asks no kernel)
#
# Windows PowerShell 5.1 compatible; pure ASCII. Read-only.

[CmdletBinding()]
param(
    [string]$MarkerDir = '',
    [string]$StateFile = '',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
if (-not $MarkerDir) { $MarkerDir = [IO.Path]::GetTempPath() }

function Write-Marker {
    param([string]$Name, [string]$Sev)
    if (-not $Sev) { return }
    if (-not (Test-Path -LiteralPath $MarkerDir)) { New-Item -ItemType Directory -Path $MarkerDir -Force -EA SilentlyContinue | Out-Null }
    Set-Content -LiteralPath (Join-Path $MarkerDir ("dz_{0}.txt" -f $Name)) -Value $Sev -Encoding ASCII
}

$script:CI_ENABLED = 0x01
$script:CI_TESTSIGN = 0x02
$script:CI_DEBUGMODE = 0x80
$script:CI_HVCI = 0x400

# PURE. $Options: the kernel's CodeIntegrityOptions, or -1 when it did not
# answer ($ErrorText then says why). Returns @{ Lines; State; Crit; TestSign;
# Debug; Gap }.
function Get-CodeIntegrityVerdict {
    param([long]$Options, [string]$ErrorText = '')
    $out = New-Object System.Collections.ArrayList
    $v = @{ Lines = @(); State = ''; Crit = $false; TestSign = $false; Debug = $false; Gap = $false }
    if ($Options -lt 0) {
        $why = (([string]$ErrorText) -replace '[\r\n]+', ' ').Trim()
        if (-not $why) { $why = 'no answer' }
        [void]$out.Add(('[WARNING] Driver signature enforcement check NOT performed -- the running kernel did not report its code-integrity options (' + $why + '), so test signing or disabled integrity checks would go unseen (T1553.006).'))
        $v.Lines = @($out.ToArray()); $v.State = 'gap'; $v.Gap = $true
        return $v
    }
    $st = @()
    if (-not ($Options -band $script:CI_ENABLED)) {
        [void]$out.Add('[CRITICAL] Kernel code integrity is NOT enforced -- the running kernel reports CODEINTEGRITY_OPTION_ENABLED off (nointegritychecks, or an equivalent), so unsigned kernel drivers can load (T1553.006).')
        $v.Crit = $true; $st += 'nointegrity'
    }
    if ($Options -band $script:CI_TESTSIGN) {
        [void]$out.Add('[WARNING] testsigning enabled. Unsigned kernel drivers can load.')
        [void]$out.Add('[INFO] Reported by the running kernel (CODEINTEGRITY_OPTION_TESTSIGN): any certificate can sign a kernel driver on this boot, and Windows shows "Test Mode" on the desktop. Fix: bcdedit /set testsigning off, then restart.')
        $v.TestSign = $true; $st += 'testsign'
    }
    if ($Options -band $script:CI_DEBUGMODE) {
        [void]$out.Add('[WARNING] A kernel debugger is attached, and code integrity may let unsigned kernel code load on this boot (CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED, T1553.006).')
        $v.Debug = $true; $st += 'debug'
    }
    if ($st.Count -eq 0) {
        [void]$out.Add('[OK] Driver signature enforcement active (the running kernel reports code integrity enforced, test signing off, no kernel debugger attached).')
        $st = @('ok')
    }
    [void]$out.Add(('[INFO] Code-integrity options reported by the running kernel: 0x{0:X8}{1}. This is what is enforced on THIS boot; a boot-configuration change takes effect at the next restart (Boot-Chain Configuration below reads the settings).' -f $Options, $(if ($Options -band $script:CI_HVCI) { ', memory integrity (HVCI) on' } else { '' })))
    $v.Lines = @($out.ToArray()); $v.State = ($st -join ',')
    return $v
}

# Live. Returns @{ Options; Error }.
function Read-CodeIntegrity {
    try {
        if (-not ('DzCodeIntegrity' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DzCodeIntegrity {
    [StructLayout(LayoutKind.Sequential)]
    public struct Info { public uint Length; public uint CodeIntegrityOptions; }
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(int infoClass, ref Info info, int length, out int returned);
}
'@
        }
        $i = New-Object DzCodeIntegrity+Info
        $i.Length = 8
        $ret = 0
        # 103 = SystemCodeIntegrityInformation.
        $st = [DzCodeIntegrity]::NtQuerySystemInformation(103, [ref]$i, 8, [ref]$ret)
        if ($st -ne 0) { return @{ Options = -1; Error = ('NTSTATUS 0x{0:X8}' -f $st) } }
        return @{ Options = [long]$i.CodeIntegrityOptions; Error = '' }
    } catch {
        $x = $_.Exception; if ($x.InnerException) { $x = $x.InnerException }
        return @{ Options = -1; Error = ($x.GetType().Name + ': ' + $x.Message) }
    }
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    # An ordinary Windows 11 PC with memory integrity on: ENABLED | HVCI.
    $v = Get-CodeIntegrityVerdict -Options 0x401; $t = $v.Lines -join "`n"
    T 'an ordinary PC (enforced, HVCI on): [OK], state ok, nothing raised' ($v.State -eq 'ok' -and -not ($v.Crit -or $v.TestSign -or $v.Debug -or $v.Gap) -and $t -match '(?m)^\[OK\] Driver signature enforcement active' -and $t -match '0x00000401, memory integrity \(HVCI\) on') $t
    $v = Get-CodeIntegrityVerdict -Options 0x01
    T 'enforced with HVCI off is still [OK]: memory integrity is context, not this finding' ($v.State -eq 'ok' -and ($v.Lines -join ' ') -notmatch 'memory integrity \(HVCI\) on') ($v.Lines -join ' | ')
    $v = Get-CodeIntegrityVerdict -Options 0x03; $t = $v.Lines -join "`n"
    T 'test signing on: the WARNING wording the bats always printed, state testsign, never [OK]' ($v.TestSign -and $v.State -eq 'testsign' -and $t -match '(?m)^\[WARNING\] testsigning enabled\. Unsigned kernel drivers can load\.$' -and $t -notmatch '\[OK\]') $t
    $v = Get-CodeIntegrityVerdict -Options 0x00; $t = $v.Lines -join "`n"
    T 'enforcement off (nointegritychecks): CRITICAL, state nointegrity' ($v.Crit -and $v.State -eq 'nointegrity' -and $t -match '(?m)^\[CRITICAL\] Kernel code integrity is NOT enforced' -and $t -notmatch '\[OK\]') $t
    $v = Get-CodeIntegrityVerdict -Options 0x81
    T 'a kernel debugger attached: WARNING, state debug' ($v.Debug -and $v.State -eq 'debug' -and -not $v.Crit) ($v.Lines -join ' | ')
    $v = Get-CodeIntegrityVerdict -Options 0x82
    T 'every bad bit at once: all three are raised and named in the state' ($v.Crit -and $v.TestSign -and $v.Debug -and $v.State -eq 'nointegrity,testsign,debug') $v.State
    $v = Get-CodeIntegrityVerdict -Options -1 -ErrorText ('DllNotFoundException: ntdll' + [char]10 + '[OK] fine'); $t = $v.Lines -join "`n"
    T 'the kernel did not answer: a raised gap, never [OK], and the error cannot forge a line' ($v.Gap -and $v.State -eq 'gap' -and $t -match '(?m)^\[WARNING\] Driver signature enforcement check NOT performed -- ' -and $t -notmatch '(?m)^\[OK\]') $t
    # The defect this replaces: a localized bcdedit ("testsigning Ja") is not
    # an input at all here; the same bits grade the same in every language.
    $v1 = Get-CodeIntegrityVerdict -Options 0x03
    T 'no text is read: the verdict depends on the bits alone (the localized-bcdedit defect cannot recur)' ((Get-Command Get-CodeIntegrityVerdict).Parameters.Keys -notcontains 'BcdText' -and $v1.TestSign) ''
    if ($fails) { Write-Output "[FAIL] $fails code_integrity_check self-test expectation(s) unmet"; exit 1 }
    Write-Output '[OK] code_integrity_check self-test: the running kernel''s code-integrity bits decide -- test signing, enforcement off and an attached debugger are raised, an ordinary PC is [OK], and a kernel that did not answer is a raised gap.'
    exit 0
}

foreach ($n in 'crit', 'testsign', 'debug', 'gap', 'done') { Remove-Item -LiteralPath (Join-Path $MarkerDir ("dz_codeint_{0}.txt" -f $n)) -Force -EA SilentlyContinue }
$r = Read-CodeIntegrity
$v = Get-CodeIntegrityVerdict -Options $r.Options -ErrorText $r.Error
foreach ($l in $v.Lines) { $l }
# Marker names are written out, not built: lint_unraised_findings reads them.
if ($v.Crit) { Write-Marker -Name 'codeint_crit' -Sev 'CRITICAL' }
if ($v.TestSign) { Write-Marker -Name 'codeint_testsign' -Sev 'WARNING' }
if ($v.Debug) { Write-Marker -Name 'codeint_debug' -Sev 'WARNING' }
if ($v.Gap) { Write-Marker -Name 'codeint_gap' -Sev 'WARNING' }
if ($StateFile) { try { Set-Content -LiteralPath $StateFile -Value $v.State -Encoding ASCII } catch {} }
Write-Marker -Name 'codeint_done' -Sev 'done'
exit 0
