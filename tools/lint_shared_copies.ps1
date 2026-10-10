# lint_shared_copies.ps1 -- copies of a shared helper must stay identical.
#
# WHY: every tools\*.ps1 is self-contained on purpose -- no module imports, no
# tool-to-tool channel -- so a helper that several tools need is COPIED into
# each of them (driver_audit.ps1's header explains the choice). A shared file
# the tools load would add a failure mode to scripts that run elevated on a
# machine a person depends on. The price of copying is drift: a fix made in
# one copy and not the others leaves two tools answering the same question
# differently, and nothing would notice. pending_reboot_check.ps1's copy of
# Get-RegKeyLastWrite had already lost a line when this lint was written.
#
# The test scripts copy helpers too: the cold cleanup (tests\cleanup_selftest.ps1)
# must run standalone, so it carries the harness's HOSTS cleanup rather than
# loading it. tests\*.ps1 is scanned beside tools\*.ps1 for that reason.
#
# RULE: for each function named in $script:Pinned, every definition of that
# name across tools\*.ps1 and tests\*.ps1 must be the same text (line endings normalised,
# comments included -- a comment is part of what was copied). The most common
# text is the reference; every other copy is reported with its file, line and
# first differing line. When no text is shared by most copies (two copies that
# differ), the lint cannot know which one drifted and names every copy. A pinned name with fewer than two copies fails too: a
# manifest entry that guards nothing is a promise, not a check.
#
# When a helper is copied into a second script, add its name here.
#
# -SelfTest works on temp copies of the real tools: unchanged passes, a
# changed token or a dropped comment line in one copy fails naming that file,
# and a CRLF-only difference passes.
#
# Windows PowerShell 5.1 and pwsh 7 (Linux CI) -- no dependencies.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

$script:Pinned = @('Get-RegKeyLastWrite', 'Get-WhenLine', 'Write-WhenCaveat', 'Remove-HostsMarkerLines', 'Expand-CmdEscapes')
$script:ScanDirs = @('tools', 'tests')

function Join-Rel {
    # 'tools\x.ps1' under $Base, on either platform's separator.
    param([string]$Base, [string]$Rel)
    $p = $Base
    foreach ($part in ($Rel -split '\\')) { $p = Join-Path $p $part }
    return $p
}

function Get-PinnedCopies {
    # Returns @{ <name> = @( @{ File; Line; Text }, ... ) } for every pinned
    # name, over every .ps1 in the scanned folders under $Base. File is the
    # path relative to $Base, as 'tools\x.ps1'.
    param([string]$Base)
    $out = @{}
    foreach ($n in $script:Pinned) { $out[$n] = @() }
    foreach ($sub in $script:ScanDirs) {
        $dir = Join-Path $Base $sub
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter '*.ps1' -File | Sort-Object Name)) {
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            $defs = $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
            foreach ($d in $defs) {
                if ($script:Pinned -notcontains $d.Name) { continue }
                $out[$d.Name] += @{ File = ('{0}\{1}' -f $sub, $f.Name); Line = $d.Extent.StartLineNumber; Text = ($d.Extent.Text -replace "`r`n", "`n") }
            }
        }
    }
    return $out
}

function Get-CopyDefects {
    param([hashtable]$Copies)
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($n in $script:Pinned) {
        $c = @($Copies[$n])
        if ($c.Count -lt 2) {
            $bad.Add(("{0}: {1} copy(ies) -- a pinned helper must exist in at least two tools; remove it from the manifest or restore the copies" -f $n, $c.Count))
            continue
        }
        $groups = @($c | Group-Object -CaseSensitive { $_.Text } | Sort-Object Count -Descending)
        if ($groups.Count -gt 1 -and $groups[0].Count -eq $groups[1].Count) {
            # No text is shared by most copies (two copies that differ, or a
            # 2-2 split), so nothing says which one drifted: name them all.
            $a = $groups[0].Name -split "`n"; $b = $groups[1].Name -split "`n"
            $i = 0
            while ($i -lt $a.Count -and $i -lt $b.Count -and $a[$i] -ceq $b[$i]) { $i++ }
            $one   = if ($i -lt $a.Count) { $a[$i].Trim() } else { '(end of function)' }
            $other = if ($i -lt $b.Count) { $b[$i].Trim() } else { '(end of function)' }
            $where = @($c | ForEach-Object { '{0}:{1}' -f $_.File, $_.Line }) -join ', '
            $bad.Add(("{0}: its {1} copies disagree and no text is shared by most of them ({2}); they first differ at the function's line {3}`n      one:      {4}`n      another:  {5}" -f $n, $c.Count, $where, ($i + 1), $one, $other))
            continue
        }
        $ref = $groups[0].Name
        foreach ($x in $c) {
            if ($x.Text -ceq $ref) { continue }
            $a = $ref -split "`n"; $b = $x.Text -split "`n"
            $i = 0
            while ($i -lt $a.Count -and $i -lt $b.Count -and $a[$i] -ceq $b[$i]) { $i++ }
            $want = if ($i -lt $a.Count) { $a[$i].Trim() } else { '(end of function)' }
            $got  = if ($i -lt $b.Count) { $b[$i].Trim() } else { '(end of function)' }
            $bad.Add(("{0}:{1}: {2} differs from the other copies at its line {3}`n      expected: {4}`n      found:    {5}" -f $x.File, ($x.Line + $i), $n, ($i + 1), $want, $got))
        }
    }
    return ,$bad.ToArray()
}

if ($SelfTest) {
    $fails = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Got)
        if ($Ok) { Write-Output "[OK]   $Name" } else { Write-Output "[FAIL] $Name$(if ($Got) { ": $Got" })"; $script:fails++ }
    }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('dz_lint_shared_{0}' -f $PID)
    try {
        foreach ($sub in $script:ScanDirs) { New-Item -ItemType Directory -Path (Join-Path $tmp $sub) -Force | Out-Null }
        $c0 = Get-PinnedCopies -Base $Root
        $files = @($script:Pinned | ForEach-Object { $c0[$_] } | ForEach-Object { $_.File } | Sort-Object -Unique)
        T 'every pinned helper has at least two copies' (@($script:Pinned | Where-Object { @($c0[$_]).Count -lt 2 }).Count -eq 0) ''
        T 'the HOSTS cleanup is pinned in the harness AND the cold cleanup' ((@($c0['Remove-HostsMarkerLines'] | ForEach-Object { $_.File }) -join ',') -eq 'tests\cleanup_selftest.ps1,tests\detection_selftest.ps1') (@($c0['Remove-HostsMarkerLines'] | ForEach-Object { $_.File }) -join ',')

        function Reset-Tmp { foreach ($f in $files) { Copy-Item -LiteralPath (Join-Rel $Root $f) -Destination (Join-Rel $tmp $f) -Force } }
        Reset-Tmp
        $d = Get-CopyDefects (Get-PinnedCopies -Base $tmp)
        T 'the shipped copies are identical' ($d.Count -eq 0) ($d -join ' | ')

        foreach ($n in $script:Pinned) {
            Reset-Tmp
            $victim = @($c0[$n])[-1].File
            $p = Join-Rel $tmp $victim
            $text = [IO.File]::ReadAllText($p)
            # Change one token inside this function only: its first 'return'.
            $start = $text.IndexOf("function $n")
            $at = $text.IndexOf('return', $start)
            $text = $text.Substring(0, $at) + 'return  ' + $text.Substring($at + 6)
            [IO.File]::WriteAllText($p, $text)
            $d = Get-CopyDefects (Get-PinnedCopies -Base $tmp)
            T ("a changed token in one copy of {0} fails, naming {1}" -f $n, $victim) ($d.Count -eq 1 -and $d[0] -match [regex]::Escape($victim)) ($d -join ' | ')
        }

        Reset-Tmp
        $victim = @($c0['Get-RegKeyLastWrite'])[0].File
        $p = Join-Rel $tmp $victim
        $lines = [IO.File]::ReadAllLines($p)
        $fnAt = [array]::IndexOf(@($lines | ForEach-Object { $_ -match '^\s*function Get-RegKeyLastWrite\b' }), $true)
        $cAt = -1
        for ($i = $fnAt; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*#') { $cAt = $i; break } }
        T 'the self-test found a comment line inside a Get-RegKeyLastWrite copy to drop' ($cAt -ge 0) "file=$victim"
        if ($cAt -ge 0) {
            $kept = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($i -ne $cAt) { $lines[$i] } })
            [IO.File]::WriteAllLines($p, $kept)
            $d = Get-CopyDefects (Get-PinnedCopies -Base $tmp)
            T 'a dropped comment line fails (comments are part of the copy)' ($d.Count -eq 1 -and $d[0] -match [regex]::Escape($victim)) ($d -join ' | ')
        }

        Reset-Tmp
        $victim = @($c0['Get-WhenLine'])[0].File
        $p = Join-Rel $tmp $victim
        $lf = [IO.File]::ReadAllText($p) -replace "`r`n", "`n"
        [IO.File]::WriteAllText($p, ($lf -replace "`n", "`r`n"))
        $d = Get-CopyDefects (Get-PinnedCopies -Base $tmp)
        T 'a CRLF-only difference passes' ($d.Count -eq 0) ($d -join ' | ')

        $saved = $script:Pinned
        $script:Pinned = @('Get-NoSuchHelperZZ')
        $d = Get-CopyDefects (Get-PinnedCopies -Base $tmp)
        T 'a pinned name with no copies fails' ($d.Count -eq 1 -and $d[0] -match 'at least two') ($d -join ' | ')
        $script:Pinned = $saved
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -EA SilentlyContinue
    }
    if ($fails -gt 0) { Write-Output "FAILED: $fails"; exit 1 }
    Write-Output '[OK] lint_shared_copies self-test: a drifted copy fails naming its file, a CRLF-only difference does not.'
    exit 0
}

$copies = Get-PinnedCopies -Base $Root
$defects = Get-CopyDefects $copies
if ($defects.Count -gt 0) {
    foreach ($x in $defects) { Write-Output ("[FAIL] " + $x) }
    Write-Output ("FAIL: {0} shared-helper copy(ies) drifted. Make every copy identical (the reference is the text most copies share)." -f $defects.Count)
    exit 1
}
$summary = @($script:Pinned | ForEach-Object { '{0} x{1}' -f $_, @($copies[$_]).Count }) -join ', '
Write-Output ("[OK] lint_shared_copies: every copy of a pinned helper is identical ({0})." -f $summary)
exit 0
