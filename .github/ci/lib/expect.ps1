# CI ONLY -- a helper, not a step body: dot-sourced by .github/ci/*.ps1
#     . .\.github\ci\lib\expect.ps1
# (.github/ci/lib/ holds helpers; lint.yml requires each to be dot-sourced by
# at least one step body, as it requires each body to be called by one step.)
#
# WHY: a step that throws at its first failed assertion shows ONE problem per
# Windows round. PR #317 paid for that: its first run failed on the runner's
# Active Setup entries, the fix was pushed, and the second run failed on an
# assertion two lines further down -- about a value that was already printed
# in the first run's log. With every expectation checked and reported
# together, one round would have shown both.
#
# Expect records a failure and carries on; Complete-Expectations throws once,
# at the end, listing every unmet expectation. Clean-up still belongs in a
# `finally`, and Complete-Expectations goes AFTER it.
$script:ExpectFailures = New-Object System.Collections.Generic.List[string]

function Expect {
    param([bool]$Ok, [string]$What, [string]$Show = '')
    if ($Ok) { Write-Host "[ok]   $What"; return }
    Write-Host "[FAIL] $What"
    if ($Show) {
        Write-Host '---- what was seen ----'
        Write-Host $Show
        Write-Host '-----------------------'
    }
    $script:ExpectFailures.Add($What)
}

function Complete-Expectations {
    param([string]$Step = 'this step')
    if ($script:ExpectFailures.Count) {
        throw ("{0} unmet expectation(s) in {1}:`n - {2}" -f $script:ExpectFailures.Count, $Step, ($script:ExpectFailures -join "`n - "))
    }
    Write-Host "[OK] every expectation of $Step was met."
}
