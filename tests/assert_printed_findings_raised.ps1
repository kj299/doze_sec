# assert_printed_findings_raised.ps1 -- a printed finding must reach the ledger
# under ITS OWN technique, not merely under its section's.
#
# WHY THIS EXISTS SEPARATELY FROM verdict_audit.ps1. That tool asks "did this
# SECTION raise anything at all", which is the right question for it and the
# wrong one here. Section 13 of the owner's 2026-09-06 21:59 report printed
#
#   [WARNING] Sticky Keys shortcut ENABLED (Shift x5 activates at login screen)
#
# and the section did have a ledger row -- for BitLocker, T1486. So verdict_audit
# said [OK] while the Sticky Keys finding reached neither FINDINGS COUNTED, the
# exit code, nor the remediation script. It cannot be widened to compare
# printed-vs-raised COUNTS, because :dz_ps_scan deliberately raises ONCE for a
# block that prints several severity lines.
#
# So this asserts the narrow thing verdict_audit cannot: a curated list of
# findings that must each reach the ledger under a specific SECTION+TECHNIQUE.
# Curated, not inferred, precisely so it cannot produce false positives on the
# aggregate blocks -- every entry is a case someone has confirmed by hand.
#
# ADDING AN ENTRY IS THE POINT. When a check is fixed to raise properly, add it
# here so it cannot silently stop.
#
# Read-only: parses one report and one ledger. Windows PowerShell 5.1 compatible.

[CmdletBinding()]
param(
    # NOT Mandatory: -SelfTest alone must run without prompting. A mandatory
    # parameter turns the self-test into an interactive hang, which in CI is a
    # job timeout rather than a verdict. Checked explicitly below instead.
    [string]$Report,
    [string]$Ledger,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

# Signature = a regex matching the line the check PRINTS into the report.
# Section/Technique = the ledger coordinates it must then appear under.
$script:Contracts = @(
    # Section 1's pending-reboot check, extracted to tools\pending_reboot_check.ps1
    # (marker idiom). The full-run job plants PendingFileRenameOperations, so
    # it exercises this on the real path.
    @{ Name      = 'Reboot pending (a flag is set; the queued operations are listed)'
       Signature = '^\s*\[WARNING\] Reboot pending:'
       Section   = '1'
       Technique = 'REBOOT' },
    @{ Name      = 'Sticky Keys shortcut at the logon screen'
       Signature = '^\s*\[WARNING\].*Sticky Keys shortcut ENABLED'
       Section   = '13'
       Technique = 'T1546.008' },
    @{ Name      = 'System-process name outside its canonical directory'
       Signature = '^\s*\[WARNING\] Process \S+ \(PID \d+\) runs from .*\(T1036 masquerading\)'
       Section   = '4'
       Technique = 'T1036' },
    # Section 9's Defender core block, extracted to tools\defender_core_check.ps1
    # (marker idiom). The runner image ships with real-time protection off, so
    # the full-run job exercises this on the real path.
    @{ Name      = 'Defender real-time protection off with no other antivirus in control'
       Signature = '^\s*\[CRITICAL\] Defender real-time protection is OFF \(T1562.001\)'
       Section   = '9'
       Technique = 'T1562.001' },
    # Section 9's exclusion check, extracted to tools\defender_exclusions_check.ps1
    # (marker idiom). The harness plants C:\dz_selftest_excl_dir, so the
    # regression job exercises this on the real path.
    @{ Name      = 'Defender exclusion configured'
       Signature = '^\s*\[WARNING\] Exclusion (paths|processes|extensions) found'
       Section   = '9'
       Technique = 'T1562.001' },
    # Section 12's LSA Protection verdict, measured in Section 4 by
    # tools\lsa_protection_check.ps1 and printed/raised in Section 12 (marker
    # idiom). The runner has LSASS unprotected, so the full-run job exercises
    # this on the real path.
    @{ Name      = 'LSASS not running as a protected process'
       Signature = '^\s*\[WARNING\] (LSASS PPL not enabled|RunAsPPL=\S+ is set but LSASS did NOT start protected|LSA Protection state could NOT be determined)'
       Section   = '12'
       Technique = 'T1003.001' }
    # Sections 18a, 18f and 18g (direct echo + :dz_finding). The plant harness
    # fires 18a and 18f; on an unplanted runner neither prints, so here these
    # guard the raise if a runner ever does. The NOT-performed lines are the
    # gap rows: same section and technique, gap-worded.
    @{ Name      = 'Running process on ioc_processes.txt, or the match not performed'
       Signature = '^\s*\[WARNING\] Process IOC (matches found above|match NOT performed)'
       Section   = '18'
       Technique = 'T1057' }
    @{ Name      = 'C2 domain from ioc_domains.txt in the DNS cache, or the match not performed'
       Signature = '^\s*\[WARNING\] C2 domain IOC (matches found in DNS cache|match NOT performed)'
       Section   = '18'
       Technique = 'T1071.004' }
    @{ Name      = 'LOLBin command-line match not performed'
       Signature = '^\s*\[WARNING\] LOLBin pattern match NOT performed'
       Section   = '18'
       Technique = 'T1059' }
    # Sections 18b-18e, 18h and 18k (marker idiom). A match raises the finding;
    # a list that is missing or holds no entries, or a listing Windows would
    # not give, prints NOT performed and raises a gap row under the same
    # section and technique. None prints on an unplanted runner; these guard
    # the raise on any report that does print one.
    @{ Name      = 'Named pipe on ioc_named_pipes.txt, or the match not performed'
       Signature = '^\s*\[WARNING\] Named pipe IOC (matches found|match NOT performed)'
       Section   = '18'
       Technique = 'T1071' }
    @{ Name      = 'Service on ioc_services.txt, or the match not performed'
       Signature = '^\s*\[WARNING\] Service IOC (matches found|match NOT performed)'
       Section   = '18'
       Technique = 'T1543' }
    @{ Name      = 'Known malware staging file on disk, or the match not performed'
       Signature = '^\s*(\[CRITICAL\] Known malware staging files found|\[WARNING\] Staging file IOC match NOT performed)'
       Section   = '18'
       Technique = 'T1074' }
    @{ Name      = 'Scheduled task on ioc_scheduled_tasks.txt, or the match not performed'
       Signature = '^\s*\[WARNING\] Scheduled task IOC (matches found|match NOT performed)'
       Section   = '18'
       Technique = 'T1053' }
    @{ Name      = 'Registry IOC from ioc_registry.txt, or the match not performed'
       Signature = '^\s*\[WARNING\] (Suspicious registry IOCs found|Registry IOC match NOT performed)'
       Section   = '18'
       Technique = 'T1112' }
    @{ Name      = 'File with a known-bad SHA256 from ioc_hashes.txt, or the match not performed'
       Signature = '^\s*(\[CRITICAL\] Local hash IOC:|\[WARNING\] File hash IOC match NOT performed)'
       Section   = '18'
       Technique = 'T1105' }
    @{ Name      = 'No ThreatLists folder, so the whole file-based IOC sweep was not performed'
       Signature = '^\s*\[WARNING\] IOC sweep NOT performed'
       Section   = '18'
       Technique = 'IOCSWEEP' }
)

function Get-UnraisedContracts {
    param([string[]]$ReportLines, [string[]]$LedgerLines)
    $out = @()
    foreach ($c in $script:Contracts) {
        $printed = $false
        foreach ($l in $ReportLines) { if ($l -match $c.Signature) { $printed = $true; break } }
        if (-not $printed) { continue }
        $raised = $false
        foreach ($l in $LedgerLines) {
            $f = $l.Split('|')
            if ($f.Length -ge 3 -and $f[1] -eq $c.Section -and $f[2] -eq $c.Technique) { $raised = $true; break }
        }
        if (-not $raised) {
            $out += New-Object PSObject -Property @{
                Name = $c.Name; Section = $c.Section; Technique = $c.Technique
            }
        }
    }
    # Emitted to the pipeline: `return $out` on an empty array yields $null, and
    # the caller's @($null) is a ONE-element array holding null.
    $out
}

if ($SelfTest) {
    $fail = 0
    function T { param([string]$n, [bool]$ok, [string]$d)
        if ($ok) { "[OK]   $n" } else { $script:fail++; "[FAIL] $n" + $(if ($d) { ": $d" }) } }

    $printedLine = '[WARNING] Sticky Keys shortcut ENABLED (Shift x5 activates at login screen)'
    $goodLedger  = @('WARNING|13|T1486|System drive not encrypted with BitLocker',
                     'WARNING|13|T1546.008|Sticky Keys shortcut enabled - Shift x5 triggers sethc.exe at the logon screen')
    $ownersLedger = @('WARNING|13|T1486|System drive not encrypted with BitLocker')

    T 'the reported bug is caught: printed, section raised, technique not' `
      (@(Get-UnraisedContracts -ReportLines @($printedLine) -LedgerLines $ownersLedger).Count -eq 1) ''
    T 'a correctly raised finding passes' `
      (@(Get-UnraisedContracts -ReportLines @($printedLine) -LedgerLines $goodLedger).Count -eq 0) ''
    T 'a machine where the check did not fire is not a failure' `
      (@(Get-UnraisedContracts -ReportLines @('[OK] Sticky Keys shortcut disabled') -LedgerLines @()).Count -eq 0) ''
    T 'an indented printed line still counts' `
      (@(Get-UnraisedContracts -ReportLines @('   ' + $printedLine) -LedgerLines $ownersLedger).Count -eq 1) ''
    # The section-only match is exactly what verdict_audit accepts and this must not.
    T 'a row for the right section but the wrong technique does NOT satisfy it' `
      (@(Get-UnraisedContracts -ReportLines @($printedLine) -LedgerLines @('WARNING|13|T9999|other')).Count -eq 1) ''
    T 'a row for the right technique but the wrong section does NOT satisfy it' `
      (@(Get-UnraisedContracts -ReportLines @($printedLine) -LedgerLines @('WARNING|9|T1546.008|other')).Count -eq 1) ''
    T 'an empty parse yields zero under @()' `
      (@(Get-UnraisedContracts -ReportLines @() -LedgerLines @()).Count -eq 0) ''
    T 'the contract list is not empty (a vacuous pass is not a pass)' `
      ($script:Contracts.Count -ge 1) ''

    if ($fail -gt 0) { "[FAIL] $fail assert_printed_findings_raised self-test expectation(s) unmet"; exit 1 }
    '[OK] assert_printed_findings_raised self-test: a printed finding must reach the ledger under its own section AND technique.'
    exit 0
}

if (-not $Report) { "[FAIL] -Report is required (or pass -SelfTest)."; exit 1 }
if (-not (Test-Path -LiteralPath $Report)) { "[FAIL] report not found: $Report"; exit 1 }
if (-not $Ledger) {
    $Ledger = [System.IO.Path]::ChangeExtension($Report, '.ledger')
}
if (-not (Test-Path -LiteralPath $Ledger)) {
    # No ledger is not a pass. It is the state in which nothing can be checked.
    "[FAIL] ledger not found: $Ledger -- nothing could be verified, which is not the same as nothing being wrong."
    exit 1
}

$rep = @(Get-Content -LiteralPath $Report)
$led = @(Get-Content -LiteralPath $Ledger)
$bad = @(Get-UnraisedContracts -ReportLines $rep -LedgerLines $led)

if ($bad.Count -gt 0) {
    "[FAIL] {0} check(s) printed a finding that never reached the findings ledger under their own technique." -f $bad.Count
    foreach ($b in $bad) {
        "       {0}: printed, but no ledger row for section {1} / {2}." -f $b.Name, $b.Section, $b.Technique
    }
    "       These findings are NOT in FINDINGS COUNTED, NOT in the exit code, and NOT in the remediation script."
    "       This is a defect in the audit, not in this machine."
    exit 1
}

"[OK] every curated check that printed a finding raised it under its own section and technique ({0} contract(s))." -f $script:Contracts.Count
exit 0
