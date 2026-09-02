# lint_orphan_else.ps1 -- an 'else' that parsed as a COMMAND is a runtime bomb.
#
# WHY: an edit inserted four lines between an `if (...) { ... }` and its own
# `else { ... }`. The file still parsed -- an orphaned `else` is syntactically
# just a command named "else" -- so "parses clean" was a vacuous claim, and on
# a real Windows runner the harness died with "The term 'else' is not
# recognized" AFTER printing its OK lines. Static parsing cannot see this;
# the AST can: a genuine else clause never becomes a CommandAst.
#
# Scans tools/*.ps1 and tests/*.ps1. Runs on any platform. Refuses a vacuous
# pass (fewer than 10 files scanned = the scanner is broken, not the code).

[CmdletBinding()]
param([string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)))

$ErrorActionPreference = 'Stop'
$files = @()
foreach ($d in @('tools', 'tests')) {
    $dir = Join-Path $Root $d
    if (Test-Path -LiteralPath $dir) { $files += Get-ChildItem -LiteralPath $dir -Filter '*.ps1' }
}
if ($files.Count -lt 10) { Write-Host ("[FAIL] only {0} script(s) found -- this lint is broken, not the code" -f $files.Count); exit 1 }

$bad = @()
foreach ($f in $files) {
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
    if ($errs -and $errs.Count) { $bad += ("{0}: does not parse ({1})" -f $f.Name, $errs[0].Message); continue }
    $orphans = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.CommandAst] -and
        ($n.GetCommandName() -in @('else', 'elseif'))
    }, $true)
    foreach ($o in $orphans) {
        $bad += ("{0}:{1}: '{2}' is not attached to an if -- it would run as a command and abort the script" -f $f.Name, $o.Extent.StartLineNumber, $o.GetCommandName())
    }
}
if ($bad.Count) {
    Write-Host ("[FAIL] {0} orphaned else/elseif clause(s):" -f $bad.Count)
    $bad | ForEach-Object { Write-Host ("  - " + $_) }
    exit 1
}
Write-Host ("[OK] {0} script(s) scanned; no else/elseif clause is detached from its if." -f $files.Count)
exit 0
