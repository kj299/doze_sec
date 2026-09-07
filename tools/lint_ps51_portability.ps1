# lint_ps51_portability.ps1 -- catch source that PARSES on Windows PowerShell 5.1
# but MEANS something different there than it does on pwsh 7.
#
# WHY THIS IS ITS OWN LINT. The helpers-ps51 CI job already parses every
# tools/*.ps1 with the 5.1 parser, and lint.yml runs the tools under pwsh 7.
# Neither can see this class, because there is no parse error to see: 5.1
# accepts the text and quietly produces a different string. The defect stays
# invisible until a case that depends on it runs on real 5.1 -- and a case can
# only do that if it was not itself written in the same broken way.
#
# It has already cost the project a real detection gap. tools/hosts_check.ps1
# stripped a UTF-8 BOM from the first HOSTS line with two -replace patterns: the
# mojibake form (written "^\xEF\xBB\xBF", pure ASCII, fine) and a second meant
# to catch a real U+FEFF -- written as the three raw UTF-8 BOM bytes typed into
# a BOM-LESS .ps1. Windows PowerShell 5.1 decodes a BOM-less script as ANSI, so
# those bytes became U+00EF U+00BB U+00BF and the line compiled to an exact
# DUPLICATE of the one above it. On the only engine this tool ships to, a real
# U+FEFF was never stripped, the first HOSTS entry then failed the address test,
# and it was dropped with no error -- a blackholed windowsupdate.microsoft.com
# on line 1 of a UTF-8 HOSTS file would have been INVISIBLE. That is a false
# negative, the worse error in a security tool.
#
# The test that should have caught it was written with the PowerShell 6+ escape
# `u{FEFF}. 5.1 has no such escape: it drops the backtick and hands you the
# literal text, so the case asserted against the string "u{FEFF}127.0.0.1" and
# could not fail for its own reason. It passed on pwsh 7 across four merges.
# Real-Windows CI is what finally caught it.
#
# TWO RULES:
#
#   1. No non-ASCII byte in any .ps1, anywhere in the file. A BOM-less file is
#      decoded as ANSI by 5.1 and as UTF-8 by 7, so any such byte is two
#      different characters depending on the engine. In a comment that is only
#      cosmetic -- but a lint that has to tell a comment from a regex is a lint
#      with an exception list to rot, and the cosmetic case is not harmless
#      either: the one other occurrence in this repo was a comment explaining a
#      Japanese auditpol header, which rendered as mojibake to exactly the
#      reader it was written for. Build the character from its code point
#      instead ([char]0xFEFF), or in a regex use the .NET escape \uFEFF, which
#      is ASCII in the source.
#
#   2. No PowerShell 6+ escape sequence (`u{...}, `e) INSIDE A DOUBLE-QUOTED
#      STRING. These are the escapes 5.1 does not merely reject -- it accepts
#      them, drops the backtick, and leaves the literal text.
#
#      Scoped by AST, not by regex over the file. A backtick only escapes inside
#      a double-quoted or here-string; in a comment it is ordinary text, and
#      this repo's comments quote identifiers markdown-style (`else`, `echo`,
#      `event ID`), which a naive file-wide scan reported as six defects across
#      four files. A lint people learn to work around is worse than no lint.
#      Single-quoted strings process no escapes at all and are exempt likewise.
#
# Read-only. Windows PowerShell 5.1 compatible; runs under pwsh on CI.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

# Built from char codes so this file does not trip its own rule 2, and so the
# needles stay correct whatever encoding reads this script.
$script:BT = [string][char]0x60
$script:Ps6Escapes = @(
    @{ Needle = ($script:BT + 'u{'); Name = 'backtick-u{...}' },
    @{ Needle = ($script:BT + 'e');  Name = 'backtick-e' }
)

function Get-PortabilityDefects {
    # Emits one object per defect: File, Line, Rule, Detail.
    param([string]$Path)

    $out = @()
    $bytes = [System.IO.File]::ReadAllBytes($Path)

    # --- Rule 1: non-ASCII bytes -------------------------------------------
    # Work on BYTES, not on a decoded string: the decoding is the thing that
    # differs between engines, so decoding first would erase the evidence.
    # A leading UTF-8 BOM is the one unambiguous sequence (both engines detect
    # and consume it), so it is tolerated -- not blessed; no file here has one.
    $start = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
    $line = 1
    $seen = @{}
    for ($i = $start; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 0x0A) { $line++; continue }
        # One report per LINE, not per byte: one character is several bytes, and
        # a defect list nobody can read is a defect list nobody acts on.
        if ($bytes[$i] -ge 0x80 -and -not $seen.ContainsKey($line)) {
            $seen[$line] = $true
            $out += New-Object PSObject -Property @{
                File   = $Path
                Line   = $line
                Rule   = 'non-ascii'
                Detail = ('byte 0x{0:X2} -- ANSI to 5.1, UTF-8 to 7. Build it from its code point ([char]0xFEFF), or use the ASCII regex escape \uFEFF.' -f $bytes[$i])
            }
        }
    }

    # --- Rule 2: PowerShell 6+ escapes, inside double-quoted strings only ---
    # Decode as ASCII so a rule-1 byte cannot perturb this scan; those bytes are
    # already reported above and would only produce a duplicate finding here.
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    $errs = $null
    $tok  = $null
    $ast  = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tok, [ref]$errs)
    if ($errs -and $errs.Count -gt 0) {
        # A file that will not parse is DECLARED, never quietly skipped: silence
        # here is indistinguishable from having checked.
        $out += New-Object PSObject -Property @{
            File   = $Path
            Line   = $errs[0].Extent.StartLineNumber
            Rule   = 'unparseable'
            Detail = ('cannot be parsed, so its strings could not be checked: {0}' -f $errs[0].Message)
        }
        return $out
    }

    $strings = @($ast.FindAll({
        param($n)
        ($n -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) -or
        (($n -is [System.Management.Automation.Language.StringConstantExpressionAst]) -and
         ($n.StringConstantType -eq 'DoubleQuoted' -or $n.StringConstantType -eq 'DoubleQuotedHereString'))
    }, $true))

    foreach ($s in $strings) {
        # The RAW source span. $s.Value has already had the escape processed --
        # differently by each engine, which is the whole point.
        $raw = $s.Extent.Text
        foreach ($e in $script:Ps6Escapes) {
            $idx = 0
            while (($idx = $raw.IndexOf($e.Needle, $idx, [StringComparison]::Ordinal)) -ge 0) {
                # An escaped backtick (two of them) yields a LITERAL backtick in
                # the output, not an escape sequence -- do not report it.
                $bts = 0
                $j = $idx - 1
                while ($j -ge 0 -and $raw[$j] -eq [char]0x60) { $bts++; $j-- }
                if (($bts % 2) -eq 0) {
                    $before = $raw.Substring(0, $idx)
                    $ln = $s.Extent.StartLineNumber + (@($before -split "`n").Count - 1)
                    $out += New-Object PSObject -Property @{
                        File   = $Path
                        Line   = $ln
                        Rule   = 'ps6-escape'
                        Detail = ('{0} in a double-quoted string is PowerShell 6+ only. 5.1 drops the backtick and leaves the literal text, so this parses and silently means something else.' -f $e.Name)
                    }
                }
                $idx += $e.Needle.Length
            }
        }
    }

    # --- Rule 3: GetNewClosure() --------------------------------------------
    # It builds a new DYNAMIC MODULE and copies the caller VARIABLES into it --
    # not its functions -- and module code runs in its own scope hierarchy with
    # its own root, so a script-scope function is not on the lookup chain.
    # pwsh 7 resolves such a call anyway; Windows PowerShell 5.1 raises
    # CommandNotFoundException. Same shape as the rules above: both engines
    # accept the source and mean something different by it.
    #
    # It cost this repo two self-test cases that then failed for the WRONG
    # REASON -- the probe threw, the package "did not resolve", and the
    # fail-closed path returned the flagged bucket the cases were asserting on.
    # Only an assertion on the REASON, not just the verdict, caught it.
    #
    # Matched on the AST, so the sequence can be named freely in prose. Pass the
    # value in a script-scoped variable instead: a plain scriptblock is bound to
    # the script session state and sees both the variable and the function.
    foreach ($m in @($ast.FindAll({
        param($n)
        ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and
        ($n.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) -and
        ($n.Member.Value -eq 'GetNewClosure')
    }, $true))) {
        $out += New-Object PSObject -Property @{
            File   = $Path
            Line   = $m.Extent.StartLineNumber
            Rule   = 'getnewclosure'
            Detail = 'GetNewClosure() runs the block in a new dynamic module whose scope chain does not include this script, so a script-scope FUNCTION is not visible to it on 5.1 (pwsh 7 resolves it). Pass the value in a script-scoped variable and use a plain scriptblock.'
        }
    }

    # Emitted straight to the pipeline. `return $out` on an empty array yields
    # $null, and the caller's @($null) is a ONE-element array holding null.
    $out
}

if ($SelfTest) {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('dz_p51_{0}' -f $PID)
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    $script:fail = 0
    function T { param([string]$Name, [bool]$Ok, [string]$Detail)
        if ($Ok) { "[OK]   $Name" } else { $script:fail++; "[FAIL] $Name" + $(if ($Detail) { ": $Detail" }) } }

    function W { param([string]$Name, [string]$Body)
        $p = Join-Path $tmp $Name
        [System.IO.File]::WriteAllBytes($p, [System.Text.Encoding]::ASCII.GetBytes($Body))
        $p }
    function WB { param([string]$Name, [string]$Pre, [byte[]]$Mid, [string]$Post)
        $p = Join-Path $tmp $Name
        $l = New-Object System.Collections.Generic.List[byte]
        $l.AddRange([System.Text.Encoding]::ASCII.GetBytes($Pre))
        $l.AddRange($Mid)
        $l.AddRange([System.Text.Encoding]::ASCII.GetBytes($Post))
        [System.IO.File]::WriteAllBytes($p, $l.ToArray())
        $p }
    function N { param([string]$Path) @(Get-PortabilityDefects -Path $Path).Count }

    $BOMB = [byte[]]@(0xEF, 0xBB, 0xBF)
    $NL   = "`r`n"
    $Q    = [string][char]0x22
    # Fixtures are built from these, so this file never itself contains the
    # sequences it hunts for -- the lint must be able to lint itself.
    $BQU = $script:BT + 'u{'
    $BQE = $script:BT + 'e'

    # --- clean ---
    $a = W 'clean.ps1' ('$l = $raw -replace ' + $Q + '^\uFEFF' + $Q + ', ' + $Q + $Q + $NL +
                        '$bom = [string][char]0xFEFF' + $NL)
    T 'ASCII source using the \uFEFF escape and [char]0xFEFF is clean' ((N $a) -eq 0) ('count=' + (N $a))

    # --- rule 1: the exact bug that shipped ---
    $b = WB 'bom.ps1' ('# ok' + $NL + '$l = $l -replace ' + $Q + '^') $BOMB ($Q + ', ' + $Q + $Q + $NL)
    $d = @(Get-PortabilityDefects -Path $b)
    T 'raw BOM bytes inside a pattern are a defect' `
      ($d.Count -eq 1 -and $d[0].Rule -eq 'non-ascii' -and $d[0].Line -eq 2) `
      ("count=$($d.Count) rule=$(if($d.Count){$d[0].Rule}) line=$(if($d.Count){$d[0].Line})")

    $c = WB 'comment.ps1' '# the header reads ' ([byte[]]@(0xE3, 0x82, 0xAB)) $NL
    $d = @(Get-PortabilityDefects -Path $c)
    T 'non-ASCII in a COMMENT is a defect too (no exception list)' `
      ($d.Count -eq 1 -and $d[0].Rule -eq 'non-ascii') ("count=$($d.Count)")
    T 'a multi-byte character reports once, not once per byte' ($d.Count -eq 1) ("count=$($d.Count)")

    $g = WB 'bomfile.ps1' '' $BOMB ('$x = 1' + $NL)
    T 'a leading UTF-8 BOM on the FILE itself is not a defect' ((N $g) -eq 0) ('count=' + (N $g))

    # --- rule 2 ---
    $e = W 'esc.ps1' ('$s = ' + $Q + $BQU + 'FEFF}127.0.0.1 localhost' + $Q + $NL)
    $d = @(Get-PortabilityDefects -Path $e)
    T 'backtick-u{...} in a double-quoted string is a defect' `
      ($d.Count -eq 1 -and $d[0].Rule -eq 'ps6-escape' -and $d[0].Line -eq 1) `
      ("count=$($d.Count) rule=$(if($d.Count){$d[0].Rule}) line=$(if($d.Count){$d[0].Line})")

    $f = W 'esc2.ps1' ('Write-Host ' + $Q + $BQE + '[31mred' + $Q + $NL)
    $d = @(Get-PortabilityDefects -Path $f)
    T 'backtick-e in a double-quoted string is a defect' `
      ($d.Count -eq 1 -and $d[0].Rule -eq 'ps6-escape') ("count=$($d.Count)")

    # The false positives a naive file-wide regex produced against this repo.
    $h = W 'prose.ps1' ('# an orphaned ' + $BQE + 'lse` is still a parse hazard' + $NL +
                        '#   2. An ' + $BQE + 'cho [CRITICAL]` with no raise nearby' + $NL +
                        '# the ' + $BQE + 'vent ID` column is localized' + $NL + '$x = 1' + $NL)
    T 'markdown-quoted prose in a comment is NOT a defect' ((N $h) -eq 0) ('count=' + (N $h))

    $i = W 'single.ps1' ('$s = ''' + $BQU + 'FEFF}''' + $NL)
    T 'a SINGLE-quoted string processes no escapes and is not a defect' ((N $i) -eq 0) ('count=' + (N $i))

    $j = W 'dblbt.ps1' ('$s = ' + $Q + $script:BT + $script:BT + 'u{FEFF} is how you write it' + $Q + $NL)
    T 'an escaped backtick is a literal backtick, not an escape' ((N $j) -eq 0) ('count=' + (N $j))

    $k = W 'here.ps1' ('$s = @' + $Q + $NL + $BQE + '[31m' + $NL + $Q + '@' + $NL)
    T 'a double-quoted HERE-string is checked too' ((N $k) -eq 1) ('count=' + (N $k))

    # --- rule 3 ---
    $m = W 'closure.ps1' ('function FakePkg { param($Kind) $Kind }' + $NL +
                          '$k = ' + $Q + 'Developer' + $Q + $NL +
                          '$p = { FakePkg -Kind $k }.GetNewClosure()' + $NL)
    $d = @(Get-PortabilityDefects -Path $m)
    T 'GetNewClosure() is a defect' `
      ($d.Count -eq 1 -and $d[0].Rule -eq 'getnewclosure' -and $d[0].Line -eq 3) `
      ("count=$($d.Count) rule=$(if($d.Count){$d[0].Rule}) line=$(if($d.Count){$d[0].Line})")

    $n = W 'closureprose.ps1' ('# GetNewClosure() copies variables, not functions.' + $NL +
                               '$s = ' + $Q + 'do not call GetNewClosure() here' + $Q + $NL)
    T 'GetNewClosure named in prose or a string is NOT a defect (AST-matched)' `
      ((N $n) -eq 0) ('count=' + (N $n))

    $o = W 'closurefix.ps1' ('function FakePkg { param($Kind) $Kind }' + $NL +
                             '$script:k = ' + $Q + 'Developer' + $Q + $NL +
                             '$p = { FakePkg -Kind $script:k }' + $NL)
    T 'the script-scoped-variable replacement is clean' ((N $o) -eq 0) ('count=' + (N $o))

    # --- a file that will not parse is declared, never silently skipped ---
    $l = W 'broken.ps1' ('function f { if ($x) {' + $NL)
    $d = @(Get-PortabilityDefects -Path $l)
    T 'an unparseable file is reported, not silently skipped' `
      ($d.Count -ge 1 -and $d[0].Rule -eq 'unparseable') `
      ("count=$($d.Count) rule=$(if($d.Count){$d[0].Rule})")

    T 'the scanner is not vacuous' ((N $b) -gt 0 -and (N $a) -eq 0) ''

    Remove-Item $tmp -Recurse -Force -EA SilentlyContinue
    if ($script:fail -gt 0) { "[FAIL] $script:fail lint_ps51_portability self-test expectation(s) unmet"; exit 1 }
    '[OK] lint_ps51_portability self-test: source that parses on 5.1 but means something else there is caught, and markdown-quoted prose is not.'
    exit 0
}

$files = @(Get-ChildItem -Path $Root -Recurse -Include '*.ps1' -File |
           Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
           Sort-Object FullName)
if ($files.Count -eq 0) {
    "[FAIL] lint_ps51_portability scanned no .ps1 under $Root -- a vacuous pass is not a pass."
    exit 1
}

$defects = @()
foreach ($f in $files) { $defects += @(Get-PortabilityDefects -Path $f.FullName) }

if ($defects.Count -gt 0) {
    foreach ($d in ($defects | Sort-Object File, Line)) {
        $rel = $d.File
        if ($rel.StartsWith($Root)) { $rel = $rel.Substring($Root.Length).TrimStart([char]0x5C, [char]0x2F) }
        '[FAIL] {0}:{1} [{2}] {3}' -f $rel, $d.Line, $d.Rule, $d.Detail
    }
    ''
    '[FAIL] {0} portability defect(s) in {1} file(s). These PARSE on Windows PowerShell 5.1 and mean something else there.' -f $defects.Count, @($defects | Group-Object File).Count
    exit 1
}

'[OK] lint_ps51_portability: {0} .ps1 file(s) are pure ASCII, use no PowerShell 6+ escape in a double-quoted string, and no GetNewClosure().' -f $files.Count
exit 0
