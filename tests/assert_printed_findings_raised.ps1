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
    @{ Name      = 'Sticky Keys shortcut at the logon screen'
       Signature = '^\s*\[WARNING\].*Sticky Keys shortcut ENABLED'
       Section   = '13'
       Technique = 'T1546.008' }
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
